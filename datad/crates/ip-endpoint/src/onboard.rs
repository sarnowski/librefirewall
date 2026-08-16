//! The onboarding port: a **byte stream** rather than a request and a response.
//!
//! It is the **only** port of this endpoint that listens: the management port
//! beside it dials and accepts nothing. This one serves no protocol of its own
//! either. It accepts a connection, hands whatever arrives to a consumer above
//! it, puts whatever that consumer answers with on the wire, and closes when
//! either end says the session is over. It does not know what the bytes are: it
//! is the transport half of a session another domain terminates, and the whole
//! of what it may do with a byte is move it.
//!
//! # Adversary
//!
//! **The management-plane attacker, unauthenticated.** Every byte here was
//! chosen by whoever reached the port, and there is no authentication in front
//! of it — that is the point of the port, which exists so an administrator can
//! present themselves to an appliance that has never met them. So nothing here
//! interprets a byte, every buffer is a fixed array with a first-party bound,
//! and every quantity a peer can drive is counted and saturating.
//!
//! # One connection, and why the number is one rather than a policy
//!
//! The transport this stream runs on holds [`ONBOARD_CONNECTIONS`] connections,
//! which is one. A second peer's `SYN` while a session is live finds no slot and
//! nothing evictable — an established connection is neither — so it is dropped
//! in silence by the transport itself, and this crate has no case to handle. A
//! `SYN` arriving after a clean close *does* find a slot, because a connection
//! in `TIME_WAIT` is evictable: an administrator who reconnects immediately is
//! served rather than told to wait out somebody else's timer.
//!
//! One is not an economy. The consumer above is a session that cannot be named
//! twice, and a transport that could accept two connections would leave this
//! crate deciding which of them the consumer meant.
//!
//! # What it holds, and what it refuses to hold
//!
//! Two fixed arrays and nothing else. [`INBOUND_CAPACITY`] bytes of what
//! arrived and has not been taken, because a consumer is driven on a wakeup and
//! bytes arrive on a frame; and [`OUTBOUND_CAPACITY`] bytes of what the consumer
//! answered, because the transport owns no copy of a range it may ask for again.
//! Neither grows and neither is sized by anything a peer sends: what does not
//! fit is **counted and refused**, never dropped silently and never allowed to
//! displace what came before it.
//!
//! The receive window is kept equal to the room actually left, so a peer that
//! keeps to the window cannot overflow the inbound array at all; the overflow
//! count is what a peer that does not keep to it produces.

use lfw_clock::Monotonic;
use lfw_tcp::{Connection, ConnectionId, SendError, SeqNumber, TcpStack, Timeout};
use net_headers::{Ipv4Address, MacAddress};

/// The port this stream listens on.
///
/// A first-party constant, and deliberately **not** the management port beside
/// it: that port carries the channel this appliance dials out of and answers
/// nothing, and this one is where a session an administrator authenticates is
/// terminated. Two ports rather than one, because they are two different
/// transports serving two different things, and because the number a peer may
/// open a connection on is then not the number this appliance composes one
/// from.
pub const ONBOARDING_PORT: u16 = 4443;

/// Connections the onboarding transport holds at once. See the module header on
/// why one is structural rather than thrifty.
pub const ONBOARD_CONNECTIONS: usize = 1;

/// Bytes read off the peer and held until the consumer takes them.
///
/// Sized so the room left is always a window worth advertising and never so
/// large that a peer can make this endpoint hold a page of its choosing: it is
/// the staging area between one frame and one wakeup, not a reassembly buffer.
/// The consumer reassembles, being the end that knows what the bytes are.
pub const INBOUND_CAPACITY: usize = 4096;

/// Bytes the consumer has answered with and the transport has not finished
/// with.
///
/// It must outlast the send, not the answer: the transport keeps no copy of a
/// range it may ask for again, so these bytes are held until the peer has
/// acknowledged them. [`INBOUND_CAPACITY`]'s size, the two directions of one
/// session having no reason to differ.
pub const OUTBOUND_CAPACITY: usize = 4096;

/// What the onboarding port has done, one field per decision.
///
/// Saturating and never reset, on `EndpointCounters`' terms: a peer chooses the
/// rate, so a wrapped total would turn a sustained flood back into a small
/// number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamCounters {
    /// Connections accepted on this port, whatever became of them.
    pub accepted: u64,
    /// Bytes taken off a peer and held for the consumer.
    pub received: u64,
    /// Bytes a peer sent past the room left, refused. Unreachable while the
    /// window is honoured, which is why a number here is a peer that ignored
    /// it rather than an endpoint that ran out.
    pub overflowed: u64,
    /// Bytes the consumer answered with and the transport took.
    pub sent: u64,
    /// Bytes the consumer answered with that there was no room for. **Ours**,
    /// not the peer's: the consumer is another domain, and this is the count
    /// that says its answer outgrew the room this end keeps for one.
    pub refused: u64,
    /// Sessions the peer ended by closing its half.
    pub closed_by_peer: u64,
    /// Sessions the consumer ended.
    pub closed_by_consumer: u64,
    /// Connections the transport stopped holding while a session was running on
    /// them: a reset, an eviction, a reaping. Distinct from either close above,
    /// because a session that ended without either end saying so is a different
    /// thing to go and look at.
    pub forgotten: u64,
}

impl StreamCounters {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            accepted: 0,
            received: 0,
            overflowed: 0,
            sent: 0,
            refused: 0,
            closed_by_peer: 0,
            closed_by_consumer: 0,
            forgotten: 0,
        }
    }

    fn bump(count: &mut u64) {
        *count = count.saturating_add(1);
    }

    fn add(count: &mut u64, by: usize) {
        *count = count.saturating_add(by as u64);
    }
}

/// Which end ended a session, for a consumer reporting what became of one.
///
/// Three answers rather than a `bool`, because they are three different things
/// for an operator to read: a peer that hung up, a consumer that decided the
/// session was over, and a connection that stopped existing while neither had
/// said anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The peer closed its half.
    ByPeer,
    /// The consumer said the session was over.
    ByConsumer,
    /// The transport stopped holding the connection: a reset, an eviction, or a
    /// reaping. Neither end of the session said anything.
    Forgotten,
}

impl Ended {
    /// A stable short name, for a report line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ByPeer => "peer",
            Self::ByConsumer => "consumer",
            Self::Forgotten => "forgotten",
        }
    }
}

/// One onboarding session: the connection it runs on, the bytes each way, and
/// which end has finished.
///
/// Not `Copy`, and not by omission: it holds the bytes the transport may ask for
/// again, so a copy would be a second account of one conversation with its own
/// idea of what had been sent.
#[derive(Clone, Debug)]
pub struct Stream {
    connection: Option<ConnectionId>,
    /// Where this connection's frames come from, learned from the frame that
    /// opened it and forgotten with it. It is the only pair a segment this end
    /// originates on the connection can be addressed to.
    peer: Option<(MacAddress, Ipv4Address)>,
    inbound: [u8; INBOUND_CAPACITY],
    inbound_len: usize,
    outbound: [u8; OUTBOUND_CAPACITY],
    outbound_len: usize,
    /// How much of `outbound` the transport has taken. A window smaller than
    /// the answer is why this is a position rather than a flag.
    sent: usize,
    /// The sequence number the answer's first byte occupies, learned from the
    /// transport once it has taken one. Without it a range the transport asks
    /// for again would be a guess, and a guess would put the wrong bytes on the
    /// wire under a number the peer would accept them at.
    base: Option<SeqNumber>,
    peer_closed: bool,
    /// The consumer has said the session is over. The close waits on the
    /// outbound bytes: a `FIN` composed in front of them would end the session
    /// before the last thing it had to say.
    consumer_closed: bool,
    /// **Which end said so first**, recorded once. Derived afterwards from the
    /// two flags above it would be wrong in the ordinary case: a peer that hangs
    /// up is answered by the consumer ending the session, so by the time anybody
    /// reads them both are set and the order is the only thing that says who
    /// finished it.
    ended: Option<Ended>,
    /// How the session before this one ended, waiting to be taken. It is here
    /// rather than answered live because the transport frees a connection on its
    /// own: a consumer that asked afterwards would find the session gone and
    /// read every ending as `Forgotten`.
    last_ended: Option<Ended>,
    /// A `FIN` has been composed, so nothing more is owed on this connection.
    closing: bool,
    counters: StreamCounters,
}

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}

impl Stream {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            connection: None,
            peer: None,
            inbound: [0; INBOUND_CAPACITY],
            inbound_len: 0,
            outbound: [0; OUTBOUND_CAPACITY],
            outbound_len: 0,
            sent: 0,
            base: None,
            peer_closed: false,
            consumer_closed: false,
            ended: None,
            last_ended: None,
            closing: false,
            counters: StreamCounters::new(),
        }
    }

    #[must_use]
    pub const fn counters(&self) -> StreamCounters {
        self.counters
    }

    /// The connection a session is running on, or `None` where there is none.
    ///
    /// It is what a consumer tells one session from the next by: the handle
    /// carries the slot's generation, so a fresh connection never reads as the
    /// one it replaced.
    #[must_use]
    pub const fn connection(&self) -> Option<ConnectionId> {
        self.connection
    }

    /// Where this session's frames are addressed, for the endpoint composing
    /// one.
    #[must_use]
    pub const fn peer(&self) -> Option<(MacAddress, Ipv4Address)> {
        self.peer
    }

    /// Bytes the peer sent that the consumer has not taken.
    #[must_use]
    pub fn received(&self) -> &[u8] {
        self.inbound.get(..self.inbound_len).unwrap_or(&[])
    }

    /// The room left for what the peer sends next, which is the window this end
    /// advertises.
    #[must_use]
    pub const fn room(&self) -> usize {
        INBOUND_CAPACITY.saturating_sub(self.inbound_len)
    }

    /// Whether the peer has closed its half.
    #[must_use]
    pub const fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// Whether the consumer has ended the session.
    #[must_use]
    pub const fn consumer_closed(&self) -> bool {
        self.consumer_closed
    }

    /// Whether anything the consumer answered with is still waiting for the
    /// transport.
    #[must_use]
    pub const fn owes_bytes(&self) -> bool {
        self.sent < self.outbound_len
    }

    /// Take a session that has just been accepted, or leave the one running.
    ///
    /// A handle that is not the one held is a **new** session: the transport
    /// holds one connection at a time on this port, so a different handle means
    /// the one before it is gone. Everything the old session held goes with it,
    /// which is what keeps one peer's bytes from reaching another's consumer.
    pub fn accepted(
        &mut self,
        connection: ConnectionId,
        mac: MacAddress,
        address: Ipv4Address,
    ) -> bool {
        if self.connection == Some(connection) {
            return false;
        }
        self.forget();
        self.connection = Some(connection);
        self.peer = Some((mac, address));
        StreamCounters::bump(&mut self.counters.accepted);
        true
    }

    /// Keep what the peer sent, refusing what there is no room for.
    ///
    /// Refused rather than truncated-and-forgotten: the count is what says a
    /// peer sent past the window it was given, and the bytes that did fit are
    /// the ones that arrived first, so the consumer reads a prefix of the stream
    /// rather than a hole in the middle of one.
    pub fn take(&mut self, data: &[u8]) {
        let held = self.inbound_len;
        let Some(room) = self.inbound.get_mut(held..) else {
            StreamCounters::add(&mut self.counters.overflowed, data.len());
            return;
        };
        let mut kept = 0usize;
        for (cell, byte) in room.iter_mut().zip(data) {
            *cell = *byte;
            kept = kept.saturating_add(1);
        }
        self.inbound_len = held.saturating_add(kept);
        StreamCounters::add(&mut self.counters.received, kept);
        StreamCounters::add(
            &mut self.counters.overflowed,
            data.len().saturating_sub(kept),
        );
    }

    /// Drop the first `bytes` the consumer has taken, keeping the rest.
    ///
    /// A copy inside one fixed array and bounded by it: the alternative is a
    /// read position that grows until the array is full of bytes nobody wants,
    /// which is the same overflow with a longer fuse.
    pub fn consumed(&mut self, bytes: usize) {
        let taken = bytes.min(self.inbound_len);
        let left = self.inbound_len.saturating_sub(taken);
        self.inbound.copy_within(taken..self.inbound_len, 0);
        self.inbound_len = left;
    }

    pub fn note_peer_closed(&mut self) {
        if !self.peer_closed {
            self.peer_closed = true;
            StreamCounters::bump(&mut self.counters.closed_by_peer);
        }
        self.ended.get_or_insert(Ended::ByPeer);
    }

    /// Put `bytes` on the wire, answering how many there was room for.
    ///
    /// Fewer than offered is a refusal this end owns and counts: the caller
    /// decides what to do about it, and every caller in this workspace ends the
    /// session, a stream missing a run of its middle being no stream at all.
    pub fn push(&mut self, bytes: &[u8]) -> usize {
        let held = self.outbound_len;
        let Some(room) = self.outbound.get_mut(held..) else {
            StreamCounters::add(&mut self.counters.refused, bytes.len());
            return 0;
        };
        let mut kept = 0usize;
        for (cell, byte) in room.iter_mut().zip(bytes) {
            *cell = *byte;
            kept = kept.saturating_add(1);
        }
        self.outbound_len = held.saturating_add(kept);
        StreamCounters::add(&mut self.counters.refused, bytes.len().saturating_sub(kept));
        kept
    }

    /// The consumer has finished with the session **on `connection`**. The close
    /// goes out once everything it answered with has.
    ///
    /// A close names the session it belongs to, and a name this stream no longer
    /// holds ends nothing: the consumer decides on one wakeup and this end may
    /// have taken a different connection by the next, so a close that named no
    /// session would end whichever one happened to be running. That is a peer's
    /// lever rather than a race — resetting and reconnecting between two passes
    /// is one segment and a handshake — and the identity is the transport's own
    /// handle, whose generation makes a fresh connection unequal to the one it
    /// replaced.
    ///
    /// Answers whether it ended the session named. `false` is a consumer whose
    /// close arrived after the session it was about was gone, which the caller
    /// reads as nothing left to do rather than as a failure.
    pub fn end_session(&mut self, connection: ConnectionId) -> bool {
        if self.connection != Some(connection) {
            return false;
        }
        if !self.consumer_closed {
            self.consumer_closed = true;
            StreamCounters::bump(&mut self.counters.closed_by_consumer);
        }
        self.ended.get_or_insert(Ended::ByConsumer);
        true
    }

    /// Send whatever this session owes, or close it.
    ///
    /// One segment per call, because `out` holds one. `None` where there is
    /// nothing to do or the transport would not take it, which is answered by
    /// trying again on the next wakeup.
    pub fn drive(
        &mut self,
        stack: &mut TcpStack<ONBOARD_CONNECTIONS>,
        now: Monotonic,
        out: &mut [u8],
    ) -> Option<usize> {
        let connection = self.connection?;
        // Before anything is composed, because the segment below carries the
        // window: one set afterwards would tell the peer it may send bytes this
        // end is still holding.
        //
        // Lossless: bounded by `INBOUND_CAPACITY`.
        stack.set_receive_window(connection, self.room() as u32);
        if self.owes_bytes() {
            return self.send_next(stack, now, connection, out);
        }
        if self.closing || !self.consumer_closed {
            return None;
        }
        // A `FIN` and not a `RST`: this session ended because one of its two
        // ends said so, which is exactly what a `FIN` means. Nothing here is
        // ever cut short of a length it announced, there being no length to
        // announce on a byte stream.
        match stack.close(now, connection, out) {
            Ok(written) => {
                self.closing = true;
                Some(written)
            }
            // A window with no room, a full record table, or storage too small.
            Err(_) => None,
        }
    }

    fn send_next(
        &mut self,
        stack: &mut TcpStack<ONBOARD_CONNECTIONS>,
        now: Monotonic,
        connection: ConnectionId,
        out: &mut [u8],
    ) -> Option<usize> {
        let payload = self.outbound.get(self.sent..self.outbound_len)?;
        // The transport records the range and advances its sequence *before* it
        // composes, so a refused write leaves those bytes outstanding and asks
        // for them again on the retransmission timer. This end advances over
        // exactly what it committed either way: not doing so leaves a range
        // `range` can never find.
        let (bytes, len) = match stack.send(now, connection, payload, out) {
            Ok(written) => (written.bytes, Some(written.len)),
            Err(SendError::Write { committed, .. }) => (committed, None),
            Err(_) => return None,
        };
        if self.base.is_none() {
            // The first range out is the oldest unacknowledged one, and this
            // stream sends nothing else, so this is where its byte zero sits.
            self.base = stack
                .connection(connection)
                .and_then(Connection::oldest_range)
                .map(|(sequence, _)| sequence);
        }
        self.sent = self.sent.saturating_add(bytes);
        StreamCounters::add(&mut self.counters.sent, bytes);
        len
    }

    /// Answer one of this connection's own timers.
    ///
    /// The range a retransmission asks for is supplied out of the bytes held
    /// here, which is the obligation the transport states in return for owning
    /// no copy of them.
    pub fn answer(
        &mut self,
        stack: &mut TcpStack<ONBOARD_CONNECTIONS>,
        now: Monotonic,
        timeout: Timeout,
        out: &mut [u8],
    ) -> Option<usize> {
        match timeout {
            Timeout::Retransmit {
                connection,
                sequence,
                len,
            } => {
                let payload = self.range(sequence, len)?;
                stack
                    .retransmit(now, connection, sequence, payload, out)
                    .ok()
            }
            Timeout::Resent { len, .. } | Timeout::Abandoned { len, .. } => {
                (len > 0).then_some(len)
            }
            Timeout::Reaped { .. } => None,
        }
    }

    /// The `len` bytes at `sequence`, or `None` for a range this stream never
    /// sent — which is what a number outside the answer, or one past what has
    /// gone out, is.
    fn range(&self, sequence: SeqNumber, len: u16) -> Option<&[u8]> {
        let base = self.base?;
        let at = sequence.distance_from(base) as usize;
        let end = at.checked_add(usize::from(len))?;
        if end > self.sent {
            return None;
        }
        self.outbound.get(at..end)
    }

    /// Give up everything held for a connection the transport no longer holds.
    ///
    /// Reconciliation rather than a notification per release, on the server
    /// beside this one's terms: the transport takes a slot back for reasons
    /// that produce no event at all — an eviction under table pressure is a
    /// `SYN` answered, not a timeout — and a session nobody was told about
    /// would hold this port's one slot for the life of the domain.
    pub fn reconcile(&mut self, stack: &TcpStack<ONBOARD_CONNECTIONS>) {
        let Some(connection) = self.connection else {
            return;
        };
        if stack.connection(connection).is_some() {
            return;
        }
        // A session neither end finished is a connection that stopped existing:
        // a reset, an eviction, a reaping. Counted apart from both closes,
        // because it is a different thing to go and look at.
        if !self.peer_closed && !self.consumer_closed {
            StreamCounters::bump(&mut self.counters.forgotten);
        }
        self.forget();
    }

    /// How the session running now would end if it ended at this instant.
    #[must_use]
    pub const fn ending(&self) -> Ended {
        match self.ended {
            Some(ended) => ended,
            None => Ended::Forgotten,
        }
    }

    /// How the **last** session ended, answered once.
    ///
    /// Taken rather than read, so a consumer reports each session exactly once:
    /// a second ask before the next session ends answers `None`, which is a
    /// consumer with nothing to report rather than one reporting a session
    /// twice.
    pub fn take_ending(&mut self) -> Option<Ended> {
        self.last_ended.take()
    }

    /// Drop the session's whole state. The arrays are left as they are and the
    /// lengths reset, which is what makes this a bounded operation: the next
    /// session writes over them from byte zero and can read nothing before its
    /// own write.
    fn forget(&mut self) {
        if self.connection.is_some() {
            self.last_ended = Some(self.ending());
        }
        self.connection = None;
        self.peer = None;
        self.inbound_len = 0;
        self.outbound_len = 0;
        self.sent = 0;
        self.base = None;
        self.peer_closed = false;
        self.consumer_closed = false;
        self.ended = None;
        self.closing = false;
    }
}
