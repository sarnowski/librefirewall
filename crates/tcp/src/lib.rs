//! The appliance's TCP: a passive-open transport that never owns a byte of the
//! streams it carries.
//!
//! # What this is for
//!
//! It is the stack the management endpoint answers on today and the one the
//! proxy dataplane will run on. That second use is what fixes every constraint
//! below, so none of them is a management-endpoint economy: a proxy terminating
//! traffic at 10 Gbit/s per port pair (CONCEPT §5) cannot afford a copy, cannot
//! afford a lock, and cannot afford an allocator.
//!
//! # Adversary
//!
//! Two of CONCEPT §7.1's five, and both reach every byte here.
//!
//! * **Untrusted network traffic.** A segment is bytes a peer chose: its ports,
//!   its sequence numbers, its window, its options and its length. Nothing is
//!   believed — the checksum is verified over the pseudo-header before a field is
//!   read, the sequence space is checked against the window before a byte is
//!   delivered, and every refusal is a typed error with a counter.
//! * **The management-plane attacker.** The port this runs on is the management
//!   port (CONCEPT §9.1), so the party on it is the one that will hold a session
//!   with the appliance. Two consequences shape the code: initial sequence
//!   numbers are unpredictable (RFC 6528, `isn`), because a predictable one lets
//!   that attacker inject into a connection it cannot see; and the connection
//!   table is bounded and reapable from both ends, because a flood of half-open
//!   connections is the cheapest attack there is against a listener.
//!
//! # It owns no buffers, and that is the whole design
//!
//! A received segment arrives as `&[u8]` — the caller's slice, which in the
//! appliance is a pool buffer a NIC wrote into — and the in-order payload comes
//! back out as a subslice of it. A segment to send is composed into a `&mut [u8]`
//! the caller supplies. There is no socket buffer anywhere in this crate, so
//! there is no copy through one.
//!
//! What that costs is a real obligation and it is stated in the type system
//! rather than in prose: [`Timeout::Retransmit`] names a sequence range the
//! caller must supply the bytes of again ([`TcpStack::retransmit`]), because this
//! crate did not keep them. A caller therefore holds its unacknowledged bytes
//! until [`TcpStack::outstanding`] falls to zero. That is where a send buffer
//! belongs — with the application that produced the bytes — and it is the exact
//! obligation smoltcp's `RingBuffer` takes on for its user and pays for with a
//! copy at every send. Ours is the other side of that trade, taken deliberately.
//!
//! # State is per shard, and nothing is shared
//!
//! A [`TcpStack`] owns its whole connection table and reaches nothing outside
//! itself: no `static`, no lock, no cell, no atomic. Several instances therefore
//! run on several cores with no coordination at all (ENG-2), and that is
//! structural — every method takes `&mut self`, so the compiler refuses two
//! concurrent users of one shard and needs no runtime check to do it. The
//! capacity is a const generic, so a shard's memory is fixed at compile time and
//! sized by the caller rather than by this crate.
//!
//! # Scope: passive open, and what is deliberately outside it
//!
//! Each of the following is a decision with a reason, not an unfinished edge.
//!
//! * **No active open.** Nothing in the appliance originates a connection yet, so
//!   `SYN_SENT` and the simultaneous-open path have no caller. They arrive with
//!   the proxy, which is what will first need to *make* a connection rather than
//!   accept one; adding them is a state and a transition, not a restructuring.
//! * **No selective acknowledgement.** SACK's value is retransmitting only the
//!   holes in a reassembly queue, and there is no reassembly queue here — that
//!   would be a buffer this crate owns. `crate::segment` reads and records the
//!   SACK-permitted option anyway, so SACK becomes a change to the state machine
//!   rather than to the parser.
//! * **No reassembly, and so no out-of-order data.** In-window payload ahead of
//!   the next byte expected is dropped and re-requested by the acknowledgement
//!   that follows, counted as `refused_out_of_order`. Holding it would mean
//!   owning it. On a lossless, in-order link — which is what a management port
//!   and a same-host proxy hop are — the case does not arise; on a reordering
//!   path it costs a round trip per reorder, and that is the price of the copy
//!   that is not made.
//! * **No congestion control.** A response that fits the initial window needs
//!   none, and a wrong one is worse than none. The structural place for it is
//!   [`Connection::sendable`](connection::Connection::sendable), which today
//!   returns the flow-control window and would return the minimum of that and a
//!   congestion window.
//! * **No delayed acknowledgement and no Nagle.** Both trade latency for fewer
//!   segments, and both need a timer this stack is not driven by: it is woken by
//!   a frame, so a delayed acknowledgement would be delayed until the next
//!   unrelated one. An acknowledgement therefore leaves immediately, and a caller
//!   that has data to send replaces it with a segment carrying the same
//!   acknowledgement number.
//! * **The urgent pointer is ignored.** `URG` data is delivered in band and
//!   counted (`urgent_ignored`). Nothing in a management protocol or an HTTP
//!   proxy uses it, and reinterpreting a byte's position out of band is worse
//!   than not.
//!
//! # Time comes from the caller
//!
//! Every timer is stated against [`lfw_clock::Monotonic`], which the caller
//! reads. This crate holds no clock: reading one is a capability a protection
//! domain is granted, and a crate that reached for it could not be driven by a
//! host test at all. What follows is that the timers advance when the caller
//! polls them — [`TcpStack::poll_timeouts`] — and a caller woken only by traffic
//! reaps a `TIME_WAIT` on the next frame rather than at its deadline. That is
//! bounded rather than unbounded: the table is also reaped under pressure, so a
//! quiet node holds dead state and never runs out of it.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod connection;
pub mod counters;
pub mod isn;
pub mod rto;
pub mod segment;
pub mod seq;

use lfw_clock::Monotonic;
use net_headers::Ipv4Address;

pub use connection::{
    Connection, IDLE_TIMEOUT, MAX_RETRANSMITS, MAX_UNACKED, Refusal, State, TIME_WAIT_DURATION,
};
pub use counters::TcpCounters;
pub use isn::{IsnGenerator, IsnSecret};
pub use rto::{INITIAL_RTO, MAX_RTO, MIN_RTO, RetransmissionTimer};
pub use segment::{
    Flags, MAX_TCP_HEADER_LEN, MAX_WINDOW_SCALE, Options, Outgoing, Segment, SegmentError,
    TCP_HEADER_LEN, WriteError,
};
pub use seq::SeqNumber;

use connection::Reply;

/// Which connection a caller means.
///
/// A slot index alone would be a handle that silently addresses whatever
/// connection took the slot over — a stale reference to a closed connection
/// would deliver bytes into a new one on a different 4-tuple. The generation
/// makes that unrepresentable rather than merely unlikely: the table refuses a
/// handle whose generation is not the one it issued, so a stale handle is a typed
/// error and never a wrong connection (DOC-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    slot: usize,
    generation: u32,
}

/// What one received segment did.
///
/// Held together rather than returned as a tuple because the three parts are
/// read together: what happened, what it delivered, and what leaves in answer.
#[derive(Debug, PartialEq, Eq)]
pub struct Received<'a> {
    pub outcome: Outcome,
    /// In-order payload this segment contributed, a subslice of the segment
    /// handed in. Empty unless the segment carried data that was next.
    pub data: &'a [u8],
    /// The connection `data` belongs to, and the one a caller answers on.
    pub connection: Option<ConnectionId>,
    /// Bytes of `out` now holding a segment to put on the wire.
    pub emitted: usize,
    /// The peer has closed its half. A caller with nothing more to send answers
    /// with [`TcpStack::close`].
    pub peer_closed: bool,
}

/// What became of one segment. Every variant is counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A `SYN` opened a connection; a `SYN-ACK` was written.
    Accepted,
    /// An existing connection processed the segment.
    Advanced,
    /// The segment was refused. Every variant of [`Rejection`] names a cause a
    /// counter has a field for.
    Rejected(Rejection),
}

/// Why a segment was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// Not a TCP segment, or not one whose checksum verifies.
    Malformed(SegmentError),
    /// A port this stack does not listen on. Dropped in silence; see
    /// `connection`'s header on why RFC 793's `RST` is not sent.
    NotListening { port: u16 },
    /// A segment for a 4-tuple with no connection.
    NoConnection,
    /// A `SYN` with no room in the table and nothing in it reapable.
    TableFull,
    /// An existing connection refused it. See [`Refusal`].
    Connection(Refusal),
    /// This stack decided to send something and the caller's storage could not
    /// hold it. **Ours**, not the peer's.
    WriteRefused(WriteError),
}

/// What a caller must do, or what was done, when a timer expired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timeout {
    /// A control segment — a `SYN-ACK` or a `FIN` — was re-composed into `out`.
    /// Nothing is asked of the caller but to send it.
    Resent {
        connection: ConnectionId,
        len: usize,
    },
    /// Data must be re-sent and this crate does not hold it. The caller supplies
    /// exactly `len` bytes starting at `sequence` to [`TcpStack::retransmit`].
    Retransmit {
        connection: ConnectionId,
        sequence: SeqNumber,
        len: u16,
    },
    /// The retransmission limit was reached: the connection is gone and a `RST`
    /// may have been written into `out`.
    Abandoned {
        connection: ConnectionId,
        len: usize,
    },
    /// A `TIME_WAIT` elapsed, or a connection sat idle past its limit. Its slot
    /// is free.
    Reaped { connection: ConnectionId },
}

/// Why a caller's send, close or retransmission was refused.
///
/// Every variant is about the *caller* — a handle that names nothing, a
/// connection in a state that cannot do what was asked, storage too small, bytes
/// that do not match the range they were asked for. A peer's misbehaviour is
/// never one of these; it is an [`Outcome::Rejected`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// The handle names no connection, or names a slot that has been reused.
    UnknownConnection,
    /// The connection cannot carry data or cannot be closed from its state.
    WrongState(State),
    /// The peer's window is closed, or every record slot is taken, so nothing
    /// may be sent right now. The caller retries when an acknowledgement has
    /// arrived.
    WouldBlock,
    /// Storage too small, or a payload no datagram can carry.
    Write(WriteError),
    /// The bytes offered are not the range the timeout asked for.
    WrongRange { expected: SeqNumber, len: u16 },
    /// Nothing is outstanding, so there is nothing to retransmit.
    NothingOutstanding,
}

/// What one send accepted and produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sent {
    /// Payload bytes taken from the caller's slice. Fewer than offered where the
    /// peer's window or the negotiated segment size allowed less; the caller
    /// sends the rest later.
    pub bytes: usize,
    /// Bytes of `out` now holding a segment.
    pub len: usize,
}

/// One shard: a listener on one address and port, and the connections it holds.
///
/// `CONNECTIONS` is the caller's, not this crate's: it fixes the table's memory
/// at compile time, and it is the bound a connection flood is answered by.
#[derive(Clone, Debug)]
pub struct TcpStack<const CONNECTIONS: usize> {
    address: Ipv4Address,
    port: u16,
    /// The largest payload this end will put in one segment, and the clamp a
    /// peer's offered segment size is held to.
    mss_limit: u16,
    /// The window this end advertises. A constant because every accepted byte is
    /// handed to the caller inside the same call, so there is no queue that could
    /// fill (see the crate header).
    receive_window: u32,
    isn: IsnGenerator,
    slots: [Option<Connection>; CONNECTIONS],
    /// Bumped every time a slot is filled, so a handle to a closed connection
    /// cannot address the one that replaced it.
    generations: [u32; CONNECTIONS],
    counters: TcpCounters,
}

impl<const CONNECTIONS: usize> TcpStack<CONNECTIONS> {
    /// A stack listening on `port` at `address`.
    ///
    /// `mss_limit` is the largest payload this end will compose, which the
    /// caller derives from the storage it will offer; `receive_window` is what it
    /// can absorb. Both are bounds the peer does not choose (ENG-4).
    #[must_use]
    pub fn new(
        address: Ipv4Address,
        port: u16,
        mss_limit: u16,
        receive_window: u32,
        secret: IsnSecret,
    ) -> Self {
        Self {
            address,
            port,
            mss_limit,
            receive_window,
            isn: IsnGenerator::new(secret),
            slots: [const { None }; CONNECTIONS],
            generations: [0; CONNECTIONS],
            counters: TcpCounters::new(),
        }
    }

    #[must_use]
    pub const fn address(&self) -> Ipv4Address {
        self.address
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub const fn counters(&self) -> TcpCounters {
        self.counters
    }

    /// How many connections the table holds, in any state.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// One connection, for a caller reporting on what it holds.
    #[must_use]
    pub fn connection(&self, id: ConnectionId) -> Option<&Connection> {
        self.resolve(id)
    }

    /// How many unacknowledged ranges a connection has, and so how many the
    /// caller must still hold the bytes of.
    #[must_use]
    pub fn outstanding(&self, id: ConnectionId) -> usize {
        self.resolve(id).map_or(0, Connection::outstanding)
    }

    /// Set the window a connection advertises to the room its caller now has.
    ///
    /// Answering `false` for a handle that names nothing, which is the only way
    /// this can fail: a window is a number and every number is a legal one, held
    /// to what the negotiated shift can express.
    ///
    /// A caller that keeps this equal to its own free space is one no peer can
    /// send more than it can take — see
    /// [`Connection::set_receive_window`](connection::Connection::set_receive_window).
    pub fn set_receive_window(&mut self, id: ConnectionId, bytes: u32) -> bool {
        match self.resolve_mut(id) {
            Some(connection) => {
                connection.set_receive_window(bytes);
                true
            }
            None => false,
        }
    }

    /// Process one received segment.
    ///
    /// `source` is the IPv4 source address the segment arrived under, which the
    /// checksum's pseudo-header is verified over: a caller that passed a
    /// different address than the datagram carried would refuse every segment.
    /// `out` receives whatever answer the segment provokes.
    pub fn receive<'a>(
        &mut self,
        now: Monotonic,
        source: Ipv4Address,
        segment: &'a [u8],
        out: &mut [u8],
    ) -> Received<'a> {
        TcpCounters::bump(&mut self.counters.segments_received);
        let parsed = match Segment::parse(source, self.address, segment) {
            Ok(parsed) => parsed,
            Err(error) => {
                let count = match error {
                    SegmentError::ChecksumInvalid { .. } => &mut self.counters.refused_bad_checksum,
                    SegmentError::TooShort { .. }
                    | SegmentError::DataOffsetTooSmall { .. }
                    | SegmentError::DataOffsetExceedsSegment { .. }
                    | SegmentError::OptionTruncated { .. }
                    | SegmentError::OptionLengthInvalid { .. } => {
                        &mut self.counters.refused_malformed
                    }
                };
                TcpCounters::bump(count);
                return self.rejected(Rejection::Malformed(error));
            }
        };
        if parsed.destination_port != self.port {
            TcpCounters::bump(&mut self.counters.refused_not_listening);
            return self.rejected(Rejection::NotListening {
                port: parsed.destination_port,
            });
        }
        match self.find(source, parsed.source_port) {
            Some(slot) => self.advance(now, slot, source, &parsed, out),
            None => self.open(now, source, &parsed, out),
        }
    }

    /// Send up to `data.len()` bytes on a connection.
    ///
    /// Takes as much as the peer's window and the negotiated segment size allow
    /// and reports how much that was; the caller sends the rest on a later call.
    ///
    /// The range is recorded before the segment is composed, so a
    /// [`SendError::Write`] leaves it outstanding: the caller keeps the bytes
    /// until the range is acknowledged in any case, and
    /// [`poll_timeouts`](Self::poll_timeouts) will ask for them with storage the
    /// next poll offers. Losing the record instead would leave a sequence number
    /// consumed that nothing would ever re-send.
    ///
    /// # Errors
    /// [`SendError`], for a handle that names nothing, a connection that cannot
    /// send from its state, a window with no room, or storage too small.
    pub fn send(
        &mut self,
        now: Monotonic,
        id: ConnectionId,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<Sent, SendError> {
        // Read before the table is borrowed: `resolve_mut` takes the whole of
        // `self`, and these two are what the segment is addressed from.
        let (local, local_port) = (self.address, self.port);
        let Some(connection) = self.resolve_mut(id) else {
            return Err(SendError::UnknownConnection);
        };
        match connection.state() {
            State::Established | State::CloseWait => {}
            other => return Err(SendError::WrongState(other)),
        }
        let allowed = connection.sendable().min(data.len());
        if allowed == 0 {
            return Err(SendError::WouldBlock);
        }
        // Lossless: `allowed` is bounded by the segment size, a `u16`.
        let accepted = allowed as u16;
        let sequence = connection.snd_nxt();
        // Recorded before anything is composed, so a full record table is
        // refused without a segment having been written — see
        // `Connection::record`. The consequence where the *write* then fails is
        // stated in this method's own documentation.
        if !connection.record(now, sequence, accepted, false, false) {
            return Err(SendError::WouldBlock);
        }
        connection.advance_send(u32::from(accepted));
        // Bounded by the `min` above; `unwrap_or_default` is what keeps it total
        // rather than adding a refusal the bound makes unreachable.
        let payload = data.get(..allowed).unwrap_or_default();
        let outgoing = Outgoing {
            source_port: local_port,
            destination_port: connection.peer_port(),
            sequence,
            acknowledgement: connection.rcv_nxt(),
            flags: Flags::ACK.with(Flags::PSH),
            window: connection.advertised_window(),
            mss: None,
            window_scale: None,
            payload,
        };
        let peer = connection.peer_address();
        let len = match outgoing.write(local, peer, out) {
            Ok(len) => len,
            Err(error) => {
                TcpCounters::bump(&mut self.counters.write_refused);
                return Err(SendError::Write(error));
            }
        };
        TcpCounters::bump(&mut self.counters.segments_sent);
        TcpCounters::add(&mut self.counters.bytes_sent, u64::from(accepted));
        Ok(Sent {
            bytes: allowed,
            len,
        })
    }

    /// Close this end of a connection: send a `FIN` and move on.
    ///
    /// # Errors
    /// [`SendError`], for a handle that names nothing, a connection this end has
    /// already closed, or storage too small.
    pub fn close(
        &mut self,
        now: Monotonic,
        id: ConnectionId,
        out: &mut [u8],
    ) -> Result<usize, SendError> {
        let Some(connection) = self.resolve_mut(id) else {
            return Err(SendError::UnknownConnection);
        };
        let state = connection.state();
        let Some(reply) = connection.close(now) else {
            return Err(SendError::WrongState(state));
        };
        let peer = connection.peer_address();
        let port = connection.peer_port();
        let window = connection.advertised_window();
        self.emit(peer, port, window, &reply, out)
            .map_err(SendError::Write)
    }

    /// Re-send the oldest unacknowledged range of a connection, with the bytes
    /// the caller still holds for it.
    ///
    /// The retransmission timer is not touched: [`poll_timeouts`](Self::poll_timeouts)
    /// noted the expiry when it asked, so the timeout has already doubled and the
    /// deadline already moved.
    ///
    /// # Errors
    /// [`SendError`], and [`SendError::WrongRange`] where the bytes offered are
    /// not the range [`Timeout::Retransmit`] named — which is the check that
    /// keeps a caller's bookkeeping mistake from putting the wrong bytes into a
    /// stream (DOC-7: this is the enforcer that obligation names, held to it by
    /// `tests::retransmitting_the_wrong_range_is_refused`).
    pub fn retransmit(
        &mut self,
        now: Monotonic,
        id: ConnectionId,
        sequence: SeqNumber,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, SendError> {
        let (local, local_port) = (self.address, self.port);
        let Some(connection) = self.resolve_mut(id) else {
            return Err(SendError::UnknownConnection);
        };
        let Some(oldest) = connection.oldest_unacked() else {
            return Err(SendError::NothingOutstanding);
        };
        if oldest.sequence != sequence || data.len() != usize::from(oldest.len) {
            return Err(SendError::WrongRange {
                expected: oldest.sequence,
                len: oldest.len,
            });
        }
        let outgoing = Outgoing {
            source_port: local_port,
            destination_port: connection.peer_port(),
            sequence,
            acknowledgement: connection.rcv_nxt(),
            // A record with a payload is never a `SYN` or a `FIN`: only
            // `TcpStack::send` produces one, and only with those flags clear. So
            // it carries no options and needs none.
            flags: Flags::ACK.with(Flags::PSH),
            window: connection.advertised_window(),
            mss: None,
            window_scale: None,
            payload: data,
        };
        let peer = connection.peer_address();
        let len = match outgoing.write(local, peer, out) {
            Ok(len) => len,
            Err(error) => {
                TcpCounters::bump(&mut self.counters.write_refused);
                return Err(SendError::Write(error));
            }
        };
        // Re-resolved because the write borrowed nothing of the table and the
        // counter bump above borrows all of it.
        if let Some(connection) = self.resolve_mut(id) {
            connection.note_activity(now);
        }
        TcpCounters::bump(&mut self.counters.segments_sent);
        TcpCounters::bump(&mut self.counters.retransmits);
        TcpCounters::add(&mut self.counters.bytes_retransmitted, data.len() as u64);
        Ok(len)
    }

    /// Take one expired timer, or `None` when nothing is due.
    ///
    /// Called in a loop until it answers `None`. Each answer either frees a slot
    /// or re-arms the timer it fired, so a loop over it terminates: no timer can
    /// be reported twice at one instant (ENG-4).
    pub fn poll_timeouts(&mut self, now: Monotonic, out: &mut [u8]) -> Option<Timeout> {
        // Reaping first, so a table under pressure recovers its slots before it
        // spends work re-sending on connections that are already dead.
        for slot in 0..CONNECTIONS {
            let expired = self
                .slots
                .get(slot)
                .and_then(Option::as_ref)
                .is_some_and(|connection| connection.expired(now));
            if expired {
                let id = self.id_of(slot);
                self.free(slot);
                TcpCounters::bump(&mut self.counters.connections_reaped);
                return Some(Timeout::Reaped { connection: id });
            }
        }
        for slot in 0..CONNECTIONS {
            // Everything the answer needs, read in one borrow of the table so
            // the mutation below is the only other one — and so a slot that is
            // empty or has nothing due is the only refusal here.
            let plan = self
                .slots
                .get(slot)
                .and_then(Option::as_ref)
                .and_then(|connection| {
                    connection.due(now).map(|range| Expiry {
                        range,
                        backoff: connection.backoff(),
                        peer: connection.peer_address(),
                        port: connection.peer_port(),
                        window: connection.advertised_window(),
                        scale: connection.window_scale(),
                        acknowledgement: connection.rcv_nxt(),
                    })
                });
            let Some(plan) = plan else { continue };
            let id = self.id_of(slot);
            if plan.backoff >= MAX_RETRANSMITS {
                return Some(self.abandon(slot, id, out));
            }
            // Noted before either answer below: the timeout doubles once per
            // loss, and the deadline moves so one instant cannot report the same
            // range twice — which is also what backs a caller that never answers
            // towards being abandoned.
            if let Some(connection) = self.slots.get_mut(slot).and_then(Option::as_mut) {
                connection.note_expiry(now);
            }
            if plan.range.len > 0 {
                // The bytes are the caller's; ask for them.
                return Some(Timeout::Retransmit {
                    connection: id,
                    sequence: plan.range.sequence,
                    len: plan.range.len,
                });
            }
            let reply = Reply {
                flags: control_flags(&plan.range),
                sequence: plan.range.sequence,
                acknowledgement: plan.acknowledgement,
                with_options: plan.range.syn,
            };
            let len = match self.write(plan.peer, plan.port, plan.window, plan.scale, &reply, out) {
                Ok(len) => len,
                Err(_) => {
                    TcpCounters::bump(&mut self.counters.write_refused);
                    0
                }
            };
            TcpCounters::bump(&mut self.counters.retransmits);
            return Some(Timeout::Resent {
                connection: id,
                len,
            });
        }
        None
    }

    /// Abandon a connection whose retransmissions are exhausted, telling the
    /// peer with a `RST` in case it is still listening.
    fn abandon(&mut self, slot: usize, id: ConnectionId, out: &mut [u8]) -> Timeout {
        let composed = self
            .slots
            .get(slot)
            .and_then(Option::as_ref)
            .map(|connection| {
                (
                    connection.peer_address(),
                    connection.peer_port(),
                    connection.advertised_window(),
                    connection.reset(),
                )
            });
        // The zero is unreachable — the caller found the slot occupied to reach
        // here — and is a value rather than an assertion, ENG-5 admitting none on
        // a path a peer's traffic reaches.
        let len = composed.map_or(0, |(peer, port, window, reply)| {
            self.send_reset(peer, port, window, &reply, out)
        });
        self.free(slot);
        TcpCounters::bump(&mut self.counters.connections_abandoned);
        Timeout::Abandoned {
            connection: id,
            len,
        }
    }

    /// A `SYN` for a 4-tuple with no connection, or something else that names
    /// none.
    fn open<'a>(
        &mut self,
        now: Monotonic,
        source: Ipv4Address,
        segment: &Segment<'a>,
        out: &mut [u8],
    ) -> Received<'a> {
        if segment.flags.contains(Flags::RST) {
            // RFC 793 §3.4: a `RST` for a connection that does not exist is
            // dropped, and never answered with another.
            TcpCounters::bump(&mut self.counters.refused_no_connection);
            return self.rejected(Rejection::NoConnection);
        }
        if !segment.flags.contains(Flags::SYN) || segment.flags.contains(Flags::ACK) {
            // RFC 793 §3.4's "reset generation": a segment that is not a fresh
            // `SYN` names a connection the peer believes in and this end does
            // not, so it is told. The sequence numbers are the ones that section
            // prescribes — the peer's acknowledgement where it carried one, so
            // the `RST` is acceptable to it.
            let reply = if segment.flags.contains(Flags::ACK) {
                Reply {
                    flags: Flags::RST,
                    sequence: segment.acknowledgement,
                    acknowledgement: SeqNumber::new(0),
                    with_options: false,
                }
            } else {
                Reply {
                    flags: Flags::RST.with(Flags::ACK),
                    sequence: SeqNumber::new(0),
                    acknowledgement: segment.sequence.add(segment.sequence_length()),
                    with_options: false,
                }
            };
            TcpCounters::bump(&mut self.counters.refused_no_connection);
            let emitted = self.send_reset(source, segment.source_port, 0, &reply, out);
            return Received {
                outcome: Outcome::Rejected(Rejection::NoConnection),
                data: &[],
                connection: None,
                emitted,
                peer_closed: false,
            };
        }

        let Some(slot) = self.free_slot(now) else {
            // Nothing in the table may be taken back. Dropped in silence rather
            // than answered: a listener under a `SYN` flood that replies to
            // every refusal is a listener spending its port on the flood.
            TcpCounters::bump(&mut self.counters.refused_table_full);
            return self.rejected(Rejection::TableFull);
        };
        let iss =
            self.isn
                .initial_sequence(now, self.address, self.port, source, segment.source_port);
        let connection = Connection::accept(
            now,
            segment,
            source,
            iss,
            self.mss_limit,
            self.receive_window,
        );
        let reply = connection.syn_ack();
        let window = connection.advertised_window();
        let scale = connection.window_scale();
        let port = connection.peer_port();
        if let Some(cell) = self.slots.get_mut(slot) {
            *cell = Some(connection);
        }
        if let Some(generation) = self.generations.get_mut(slot) {
            *generation = generation.wrapping_add(1);
        }
        let id = Some(self.id_of(slot));
        TcpCounters::bump(&mut self.counters.connections_accepted);
        let emitted = match self.write(source, port, window, scale, &reply, out) {
            Ok(len) => {
                TcpCounters::bump(&mut self.counters.segments_sent);
                len
            }
            Err(error) => {
                // The `SYN-ACK` could not be composed, which is this stack's
                // fault and not the peer's. The connection stays: its own
                // retransmission timer will try again with whatever storage the
                // next poll offers.
                TcpCounters::bump(&mut self.counters.write_refused);
                return Received {
                    outcome: Outcome::Rejected(Rejection::WriteRefused(error)),
                    data: &[],
                    connection: id,
                    emitted: 0,
                    peer_closed: false,
                };
            }
        };
        Received {
            outcome: Outcome::Accepted,
            data: &[],
            connection: id,
            emitted,
            peer_closed: false,
        }
    }

    /// A segment for a connection the table holds.
    fn advance<'a>(
        &mut self,
        now: Monotonic,
        slot: usize,
        source: Ipv4Address,
        segment: &Segment<'a>,
        out: &mut [u8],
    ) -> Received<'a> {
        let id = Some(self.id_of(slot));
        let Some(connection) = self.slots.get_mut(slot).and_then(Option::as_mut) else {
            return self.rejected(Rejection::NoConnection);
        };
        let reset = segment.flags.contains(Flags::RST);
        let processed = connection.receive(now, segment);
        let port = connection.peer_port();
        let window = connection.advertised_window();
        let scale = connection.window_scale();
        let state = connection.state();

        if processed.urgent {
            TcpCounters::bump(&mut self.counters.urgent_ignored);
        }
        if processed.established {
            TcpCounters::bump(&mut self.counters.connections_established);
        }
        TcpCounters::add(
            &mut self.counters.bytes_received,
            processed.data.len() as u64,
        );
        if let Some(refusal) = processed.refusal {
            let count = match refusal {
                Refusal::OutOfWindow => &mut self.counters.refused_out_of_window,
                Refusal::UnvalidatedReset | Refusal::UnexpectedSyn => {
                    &mut self.counters.challenge_acks
                }
                Refusal::UnacceptableAck => &mut self.counters.refused_unacceptable_ack,
                Refusal::OutOfOrder => &mut self.counters.refused_out_of_order,
                Refusal::NoAcknowledgement => &mut self.counters.refused_no_acknowledgement,
            };
            TcpCounters::bump(count);
        }
        if reset && processed.refusal.is_none() {
            TcpCounters::bump(&mut self.counters.resets_received);
        }
        if matches!(state, State::Closed) && processed.finished {
            TcpCounters::bump(&mut self.counters.connections_closed);
        }

        let emitted = match processed.reply {
            Some(reply) => match self.write(source, port, window, scale, &reply, out) {
                Ok(len) => {
                    TcpCounters::bump(&mut self.counters.segments_sent);
                    if reply.flags.contains(Flags::RST) {
                        TcpCounters::bump(&mut self.counters.resets_sent);
                    }
                    len
                }
                Err(_) => {
                    TcpCounters::bump(&mut self.counters.write_refused);
                    0
                }
            },
            None => 0,
        };
        if processed.finished {
            self.free(slot);
        }
        let outcome = match processed.refusal {
            Some(refusal) => Outcome::Rejected(Rejection::Connection(refusal)),
            None => Outcome::Advanced,
        };
        Received {
            outcome,
            data: processed.data,
            connection: id,
            emitted,
            peer_closed: processed.peer_closed,
        }
    }

    /// Write a `RST` that belongs to no connection, counting what it was.
    fn send_reset(
        &mut self,
        peer: Ipv4Address,
        port: u16,
        window: u16,
        reply: &Reply,
        out: &mut [u8],
    ) -> usize {
        match self.emit(peer, port, window, reply, out) {
            Ok(len) => {
                TcpCounters::bump(&mut self.counters.resets_sent);
                len
            }
            Err(_) => {
                TcpCounters::bump(&mut self.counters.write_refused);
                0
            }
        }
    }

    /// Compose one reply with no options and count it as sent.
    fn emit(
        &mut self,
        peer: Ipv4Address,
        port: u16,
        window: u16,
        reply: &Reply,
        out: &mut [u8],
    ) -> Result<usize, WriteError> {
        let len = self.write(peer, port, window, None, reply, out)?;
        TcpCounters::bump(&mut self.counters.segments_sent);
        Ok(len)
    }

    /// Turn a reply into bytes.
    fn write(
        &self,
        peer: Ipv4Address,
        port: u16,
        window: u16,
        scale: Option<u8>,
        reply: &Reply,
        out: &mut [u8],
    ) -> Result<usize, WriteError> {
        Outgoing {
            source_port: self.port,
            destination_port: port,
            sequence: reply.sequence,
            acknowledgement: reply.acknowledgement,
            flags: reply.flags,
            window,
            mss: reply.with_options.then_some(self.mss_limit),
            window_scale: reply.with_options.then_some(scale).flatten(),
            payload: &[],
        }
        .write(self.address, peer, out)
    }

    /// A rejection that produced no answer.
    fn rejected<'a>(&self, rejection: Rejection) -> Received<'a> {
        Received {
            outcome: Outcome::Rejected(rejection),
            data: &[],
            connection: None,
            emitted: 0,
            peer_closed: false,
        }
    }

    /// The slot holding the connection this 4-tuple names.
    fn find(&self, source: Ipv4Address, port: u16) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|connection| connection.matches(source, port))
        })
    }

    /// A slot for a new connection: an empty one, else the oldest evictable one.
    fn free_slot(&mut self, now: Monotonic) -> Option<usize> {
        if let Some(slot) = self.slots.iter().position(Option::is_none) {
            return Some(slot);
        }
        // Expired first — a slot whose connection is over is not an eviction —
        // and then the least recently active evictable one, which under a `SYN`
        // flood is the oldest half-open connection.
        let victim = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(slot, held)| held.as_ref().map(|connection| (slot, connection)))
            .filter(|(_, connection)| connection.expired(now) || connection.evictable())
            .reduce(|oldest, candidate| {
                if candidate.1.last_activity() < oldest.1.last_activity() {
                    candidate
                } else {
                    oldest
                }
            })
            .map(|(slot, connection)| (slot, connection.expired(now)))?;
        let (victim, was_expired) = victim;
        self.free(victim);
        // An expired connection taken back is a reaping that happened to be
        // triggered by pressure rather than by a poll; an evictable one that is
        // *not* expired is a real eviction, and the two accuse different things.
        let count = if was_expired {
            &mut self.counters.connections_reaped
        } else {
            &mut self.counters.connections_evicted
        };
        TcpCounters::bump(count);
        Some(victim)
    }

    /// Empty a slot.
    fn free(&mut self, slot: usize) {
        if let Some(cell) = self.slots.get_mut(slot) {
            *cell = None;
        }
    }

    /// The handle for a slot as it stands. Total: a slot past the table has no
    /// generation and cannot be occupied, so the handle it yields resolves to
    /// nothing.
    fn id_of(&self, slot: usize) -> ConnectionId {
        ConnectionId {
            slot,
            generation: self.generations.get(slot).copied().unwrap_or(0),
        }
    }

    /// The connection a handle names, or `None` where its slot is empty or has
    /// been reused.
    fn resolve(&self, id: ConnectionId) -> Option<&Connection> {
        let held = self.slots.get(id.slot)?.as_ref()?;
        (self.generations.get(id.slot) == Some(&id.generation)).then_some(held)
    }

    /// As [`resolve`](Self::resolve), for the three calls that change one.
    fn resolve_mut(&mut self, id: ConnectionId) -> Option<&mut Connection> {
        if self.generations.get(id.slot) != Some(&id.generation) {
            return None;
        }
        self.slots.get_mut(id.slot)?.as_mut()
    }
}

/// What one expired timer needs to be answered, read out of its connection in
/// one borrow so the answer below needs only one more.
struct Expiry {
    range: connection::Unacked,
    backoff: u32,
    peer: Ipv4Address,
    port: u16,
    window: u16,
    scale: Option<u8>,
    acknowledgement: SeqNumber,
}

/// The flags a re-sent control segment carries, from what its record says it was.
///
/// Only a record with no payload reaches this — `TcpStack::poll_timeouts` sends
/// a caller's data back to the caller instead — so there is no `PSH` case.
fn control_flags(record: &connection::Unacked) -> Flags {
    let mut flags = Flags::ACK;
    if record.syn {
        flags = flags.with(Flags::SYN);
    }
    if record.fin {
        flags = flags.with(Flags::FIN);
    }
    flags
}

#[cfg(test)]
mod tests;
