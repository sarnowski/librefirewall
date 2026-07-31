//! The one thing an established connection on the management port does today:
//! send back what it was sent.
//!
//! # What this is and what replaces it
//!
//! It is a stand-in for the HTTP server that belongs here, and it is deliberately
//! a *complete* one rather than a stub: it carries a byte stream in both
//! directions, holds its own unacknowledged bytes for as long as the transport may
//! ask for them again, and closes when its peer does. That is what gives the
//! end-to-end gate a whole TCP exchange to assert — a handshake, a payload
//! compared byte for byte, and a clean close — which is the only way to know the
//! transport works at all.
//!
//! It is replaced *wholesale* when HTTP lands, not extended: nothing here is a
//! layer HTTP would sit on. There is no compatibility path to keep (ENG-6).
//!
//! # Why the application holds the bytes
//!
//! `lfw_tcp` owns no buffers, so an unacknowledged range is one its caller must
//! be able to supply again. This is that caller. Each connection's slot holds the
//! bytes it has been handed and has not yet seen acknowledged, and answers
//! `lfw_tcp::Timeout::Retransmit` out of them. A send buffer belongs with the
//! application that produced the bytes, and this is what that costs — a fixed
//! array per connection, and no copy anywhere else.
//!
//! # Why the advertised window is this buffer's free space
//!
//! One rule removes the only lossy case a receiver with no reassembly queue would
//! have. The window this endpoint advertises is kept equal to the room left in
//! the slot, so a peer cannot put more into the connection than the slot can
//! hold: data is never acknowledged and then dropped. That is what RFC 793 says a
//! window is, and treating it as a constant is what would make it a lie.
//!
//! # Adversary
//!
//! CONCEPT §7.1's untrusted network traffic and its management-plane attacker,
//! through `lfw_tcp`. Every byte here was chosen by the party on the port, and
//! every length is derived from a slice rather than from a number that party
//! sent — so the copies below are bounded by this crate's own array and by
//! nothing on the wire (ENG-4).

use lfw_clock::Monotonic;
use lfw_tcp::{Connection, ConnectionId, SeqNumber, TcpStack, Timeout};

/// Bytes one connection may hold, and so the window this endpoint advertises on
/// an idle connection.
///
/// It is the whole of the flow control: a peer is told it may send this much and
/// no more. 1 KiB is a management request and a comfortable multiple of the
/// smallest segment size RFC 1122 admits, and eight of them is what a protection
/// domain's own memory holds beside two frame buffers.
pub const ECHO_CAPACITY: usize = 1024;

/// One connection's held bytes.
///
/// `sent` is a prefix of `bytes[..len]`, and it is a prefix rather than a range
/// because only one segment is ever in flight at a time: the next is not composed
/// until the transport reports the last acknowledged. That keeps the sequence
/// arithmetic here to one number, which is the whole reason for the restriction —
/// a second in-flight segment would buy latency this endpoint has no use for and
/// cost a send queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    connection: Option<ConnectionId>,
    bytes: [u8; ECHO_CAPACITY],
    /// Bytes held, sent or not.
    len: usize,
    /// The prefix handed to the transport and not yet acknowledged.
    sent: usize,
    /// Where `bytes[0]` sits in the connection's send sequence space, once
    /// anything has been sent.
    sequence: SeqNumber,
    /// The peer has closed its half, so this end closes once it has nothing left
    /// to send.
    peer_closed: bool,
    /// This end has closed, so it must not close twice.
    closed: bool,
}

impl Slot {
    const EMPTY: Self = Self {
        connection: None,
        bytes: [0; ECHO_CAPACITY],
        len: 0,
        sent: 0,
        sequence: SeqNumber::new(0),
        peer_closed: false,
        closed: false,
    };

    /// The room left, which is the window the connection advertises.
    fn room(&self) -> usize {
        ECHO_CAPACITY.saturating_sub(self.len)
    }
}

/// What the echo has done, in the shape the metrics endpoint (CONCEPT §11) will
/// scrape. Saturating and never reset, on `lfw_tcp::TcpCounters`' terms.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EchoCounters {
    /// Bytes taken from connections and held to be sent back.
    pub bytes_taken: u64,
    /// Bytes handed to the transport.
    pub bytes_echoed: u64,
    /// Bytes a connection delivered that no slot had room for. Expected to read
    /// zero forever: the advertised window is the room, so a peer that reaches
    /// this sent more than it was told it could — and the count is what makes
    /// that visible rather than silent.
    pub bytes_overrun: u64,
    /// Connections the echo had no slot for, so nothing was echoed on them. The
    /// slot table is the same size as the connection table, so this too reads
    /// zero unless the two are configured apart.
    pub slots_exhausted: u64,
    /// Closes this end sent because its peer had closed and it had nothing left.
    pub closes: u64,
    /// Ranges the transport asked for again and this endpoint supplied.
    pub retransmits_served: u64,
    /// Ranges the transport asked for that no slot held. A caller and a transport
    /// disagreeing about what is outstanding, which is **ours** rather than the
    /// peer's.
    pub retransmits_unavailable: u64,
}

impl EchoCounters {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes_taken: 0,
            bytes_echoed: 0,
            bytes_overrun: 0,
            slots_exhausted: 0,
            closes: 0,
            retransmits_served: 0,
            retransmits_unavailable: 0,
        }
    }
}

/// The echo application over one stack's connections.
///
/// `SLOTS` is the connection table's size: one slot per connection, so a
/// connection that exists always has somewhere to hold its bytes.
#[derive(Clone, Debug)]
pub struct Echo<const SLOTS: usize> {
    slots: [Slot; SLOTS],
    counters: EchoCounters,
}

impl<const SLOTS: usize> Echo<SLOTS> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; SLOTS],
            counters: EchoCounters::new(),
        }
    }

    #[must_use]
    pub const fn counters(&self) -> EchoCounters {
        self.counters
    }

    /// Take bytes a connection delivered, holding them to be sent back.
    ///
    /// Bounded by the slot, which is what the connection's advertised window is
    /// kept equal to: a peer that honours the window cannot overrun it, and one
    /// that does not has the excess counted and dropped rather than written past
    /// the array.
    pub fn take(&mut self, connection: ConnectionId, data: &[u8]) {
        let Some(slot) = self.slot_for(connection) else {
            bump(&mut self.counters.slots_exhausted);
            return;
        };
        let room = slot.room();
        let taken = room.min(data.len());
        // Bounded by `room`, so both slices are inside the array.
        let held = slot.len;
        for (target, byte) in slot
            .bytes
            .iter_mut()
            .skip(held)
            .zip(data.iter().take(taken))
        {
            *target = *byte;
        }
        slot.len = held.saturating_add(taken);
        add(&mut self.counters.bytes_taken, taken as u64);
        add(
            &mut self.counters.bytes_overrun,
            (data.len() - taken) as u64,
        );
    }

    /// Note that the peer has closed its half, so this end closes once it has
    /// nothing left to send.
    pub fn note_peer_closed(&mut self, connection: ConnectionId) {
        if let Some(slot) = self.slot_for(connection) {
            slot.peer_closed = true;
        }
    }

    /// Do whatever this connection now owes: send the next chunk, or close.
    ///
    /// Answers the length of a segment written into `out`, or `None` where there
    /// was nothing to do. One segment per call, because `out` holds one: a data
    /// segment carries the acknowledgement a bare one would have, so replacing
    /// the transport's own answer with this loses nothing.
    pub fn drive<const CONNECTIONS: usize>(
        &mut self,
        stack: &mut TcpStack<CONNECTIONS>,
        now: Monotonic,
        connection: ConnectionId,
        out: &mut [u8],
    ) -> Option<usize> {
        let index = self.index_of(connection)?;
        let slot = self.slots.get_mut(index)?;

        // Everything sent has been acknowledged, so the held prefix is free and
        // the window re-opens by that much.
        if slot.sent > 0 && stack.outstanding(connection) == 0 {
            // Shifted a byte at a time through `get`, so no index can leave the
            // array whatever the two lengths are: `copy_within` would carry a
            // panicking precondition onto a path a peer's acknowledgement
            // reaches (ENG-5).
            let shift = slot.sent;
            let mut index = 0usize;
            while index.saturating_add(shift) < slot.len {
                let byte = slot
                    .bytes
                    .get(index.saturating_add(shift))
                    .copied()
                    .unwrap_or(0);
                if let Some(target) = slot.bytes.get_mut(index) {
                    *target = byte;
                }
                index = index.saturating_add(1);
            }
            slot.len = slot.len.saturating_sub(shift);
            slot.sent = 0;
        }

        // Before anything is composed, because the segment composed below carries
        // the window: a window set afterwards would be one segment out of date,
        // and the peer would be told it may send bytes this endpoint is still
        // holding.
        //
        // Lossless: `room` is bounded by `ECHO_CAPACITY`.
        stack.set_receive_window(connection, slot.room() as u32);

        let unsent = slot.len.saturating_sub(slot.sent);
        if unsent > 0 && slot.sent == 0 {
            let payload = slot.bytes.get(..slot.len).unwrap_or_default();
            match stack.send(now, connection, payload, out) {
                Ok(sent) => {
                    slot.sent = sent.bytes;
                    slot.sequence = stack
                        .connection(connection)
                        .and_then(Connection::oldest_range)
                        .map_or(slot.sequence, |(sequence, _)| sequence);
                    add(&mut self.counters.bytes_echoed, sent.bytes as u64);
                    Some(sent.len)
                }
                // A window with no room, a record table that is full, or storage
                // too small: all three are answered by holding the bytes and
                // trying again on the next wakeup, which is what the buffer is
                // for.
                Err(_) => None,
            }
        } else if slot.peer_closed && slot.len == 0 && !slot.closed {
            match stack.close(now, connection, out) {
                Ok(len) => {
                    slot.closed = true;
                    bump(&mut self.counters.closes);
                    Some(len)
                }
                Err(_) => None,
            }
        } else {
            None
        }
    }

    /// Answer one of the transport's timeouts.
    ///
    /// Only [`Timeout::Retransmit`] asks anything of this endpoint: the rest are
    /// segments the transport composed itself, or connections it has given up on.
    /// A slot whose connection is gone is released here, which is where a closed
    /// connection's bytes are forgotten.
    pub fn answer<const CONNECTIONS: usize>(
        &mut self,
        stack: &mut TcpStack<CONNECTIONS>,
        now: Monotonic,
        timeout: Timeout,
        out: &mut [u8],
    ) -> Option<usize> {
        match timeout {
            Timeout::Retransmit {
                connection,
                sequence,
                len,
            } => self.serve(stack, now, connection, sequence, len, out),
            Timeout::Resent { len, .. } => Some(len),
            Timeout::Abandoned { connection, len } => {
                self.release(connection);
                Some(len)
            }
            Timeout::Reaped { connection } => {
                self.release(connection);
                None
            }
        }
    }

    /// Supply a range the transport asked for again.
    fn serve<const CONNECTIONS: usize>(
        &mut self,
        stack: &mut TcpStack<CONNECTIONS>,
        now: Monotonic,
        connection: ConnectionId,
        sequence: SeqNumber,
        len: u16,
        out: &mut [u8],
    ) -> Option<usize> {
        let index = self.index_of(connection)?;
        let slot = self.slots.get(index)?;
        // The range must be the one prefix this slot holds: the echo keeps a
        // single segment in flight, so any other range is a disagreement between
        // this endpoint and the transport rather than a range to look up.
        let holds = slot.sequence == sequence && slot.sent == usize::from(len);
        let payload = holds
            .then(|| slot.bytes.get(..slot.sent))
            .flatten()
            .unwrap_or_default();
        if payload.is_empty() {
            bump(&mut self.counters.retransmits_unavailable);
            return None;
        }
        match stack.retransmit(now, connection, sequence, payload, out) {
            Ok(written) => {
                bump(&mut self.counters.retransmits_served);
                Some(written)
            }
            Err(_) => {
                bump(&mut self.counters.retransmits_unavailable);
                None
            }
        }
    }

    /// Give a slot back, forgetting whatever it held.
    ///
    /// Called where a connection has gone — reaped, abandoned, reset or closed —
    /// which is the only place bytes are forgotten: a slot is otherwise held for
    /// as long as the transport may ask for its range again.
    pub fn release(&mut self, connection: ConnectionId) {
        if let Some(index) = self.index_of(connection)
            && let Some(slot) = self.slots.get_mut(index)
        {
            *slot = Slot::EMPTY;
        }
    }

    /// The slot this connection already has, or a free one bound to it.
    fn slot_for(&mut self, connection: ConnectionId) -> Option<&mut Slot> {
        let index = match self.index_of(connection) {
            Some(index) => index,
            None => self
                .slots
                .iter()
                .position(|slot| slot.connection.is_none())?,
        };
        let slot = self.slots.get_mut(index)?;
        if slot.connection != Some(connection) {
            *slot = Slot {
                connection: Some(connection),
                ..Slot::EMPTY
            };
        }
        Some(slot)
    }

    fn index_of(&self, connection: ConnectionId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.connection == Some(connection))
    }
}

impl<const SLOTS: usize> Default for Echo<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

fn bump(count: &mut u64) {
    *count = count.saturating_add(1);
}

fn add(total: &mut u64, amount: u64) {
    *total = total.saturating_add(amount);
}
