//! The management HTTP server: what an established connection on the management
//! port now does.
//!
//! It answers exactly one target — `GET /metrics`, with the Prometheus
//! exposition its caller renders — and every other request with a status. It
//! replaced the byte echo wholesale rather than being layered on it (ENG-6):
//! nothing of that stand-in survives, and there is no path back to it.
//!
//! # Adversary
//!
//! CONCEPT §7.1's **management-plane attacker**, one layer above `lfw_http`.
//! That crate refuses a malformed head; this one decides what a well-formed one
//! gets, and holds the state a connection accumulates while it does. Both
//! dimensions of that state are fixed arrays: [`REQUEST_CAPACITY`] per
//! connection for the head being read, and one [`RESPONSE_CAPACITY`] buffer for
//! the one exposition that may be in flight (ENG-4).
//!
//! # One exposition at a time, and what a second connection gets
//!
//! An exposition is [`RESPONSE_CAPACITY`] bytes — about 28 KiB — and a buffer
//! per connection would be eight of them in a protection domain's own memory.
//! There is therefore **one**, claimed by the connection whose request completed
//! and released as soon as its response can no longer be *asked for* again, and
//! a second request for `/metrics` arriving in between is answered
//! `503 Service Unavailable`.
//!
//! That is a real limit and it is stated rather than hidden: two concurrent
//! scrapers refuse each other. Every other status needs no body at all, so it is
//! composed in the connection's own slot and is never refused for want of the
//! shared one.
//!
//! "No longer asked for" is [`Server::sweep`]: this end closed and the transport
//! holds none of its ranges. Waiting for the connection's *slot* would hold it
//! through `TIME_WAIT` — a minute — and refuse every scrape made in it.
//!
//! # Why the application holds the response bytes
//!
//! `lfw_tcp` owns no buffers, so an unacknowledged range is one its caller must
//! be able to supply again — and a response that spans twenty segments has up to
//! `lfw_tcp::MAX_UNACKED` of them outstanding at once. The whole response
//! therefore stays here until the connection is done with it, and
//! [`Server::answer`] serves a retransmission out of it by offset from the
//! sequence number its first byte took.
//!
//! # The body is asked for, not fetched
//!
//! A completed `GET /metrics` claims the staging buffer and stops at
//! [`Phase::AwaitingBody`]: the caller then asks [`Server::pending_body`] and
//! renders through [`Server::supply`]. Two steps rather than a renderer this
//! crate calls, and the reason is freshness rather than layering. The caller is
//! the protection domain whose *own* counters the exposition carries, and it can
//! only publish them once the request has been counted — which happens as the
//! head completes. Rendering inside the parse would put a scrape's own request
//! one publish in the future, so a node that had just answered a scrape would
//! report having answered none.
//!
//! # Why the advertised window is the request buffer's free space
//!
//! A peer is told it may send what this end can still hold, so a legitimate
//! request is never acknowledged and then dropped. Once a head is complete the
//! window is whatever is left, which is how a client that keeps sending is
//! slowed rather than answered.
//!
//! **The value is one segment stale, and that is stated rather than hidden.**
//! The transport composes an arriving segment's acknowledgement before this
//! server has taken its bytes, so that acknowledgement carries the window as of
//! the *previous* segment; the next thing this end composes carries the current
//! one. What the slack can buy a peer is up to one segment past the bound, which
//! [`take`](Server::take) counts as an overrun and answers
//! [`Status::HeadersTooLarge`] — the same answer a head that long gets in any
//! case, so no legitimate request loses a byte.

use lfw_clock::Monotonic;
use lfw_http::{
    MAX_HEAD_LEN, MAX_REQUEST_BYTES, METRICS_CONTENT_TYPE, Parsed, Status, parse, write_head,
};
use lfw_tcp::{Connection, ConnectionId, SeqNumber, TcpStack, Timeout};

/// Bytes of request head one connection may accumulate, which is also the
/// window it is offered. `lfw_http`'s own bound, because the two are one
/// decision: the parser's limits are stated against a head this size.
pub const REQUEST_CAPACITY: usize = MAX_REQUEST_BYTES;

/// The one target this server answers with a body.
pub const METRICS_TARGET: &str = "/metrics";

/// Bytes the shared response buffer holds: the longest head this server can
/// write, in front of the longest exposition the metric catalogue can produce.
///
/// Derived rather than chosen, which is what makes a new metric unable to
/// silently truncate an operator's scrape — a family added to `lfw_metrics`
/// moves this number and the array with it (ENG-12).
pub const RESPONSE_CAPACITY: usize = MAX_HEAD_LEN + lfw_metrics::MAX_EXPOSITION_LEN;

// The bound the whole streaming design rests on, stated where both halves are
// visible: the worst-case exposition and the head in front of it fit the buffer
// they are composed into, so a scrape is never answered short (TEST-5). Both are
// stated as numbers, so a new family moves this reservation in a diff.
const _: () = {
    assert!(RESPONSE_CAPACITY >= MAX_HEAD_LEN + lfw_metrics::MAX_EXPOSITION_LEN);
    assert!(RESPONSE_CAPACITY > MAX_HEAD_LEN);

    assert!(lfw_metrics::MAX_EXPOSITION_LEN == 30_632);
    assert!(RESPONSE_CAPACITY == 30_793);
};

/// What the server has done, in the shape the metrics endpoint scrapes.
/// Saturating and never reset, on `lfw_tcp::TcpCounters`' terms.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HttpCounters {
    /// Heads read to their end and decided on, whatever the decision.
    pub requests: u64,
    /// Responses composed, one slot per [`Status::ALL`] entry.
    pub responses: [u64; Status::ALL.len()],
    /// Response bytes handed to the transport, heads included.
    pub response_bytes: u64,
    /// Requests whose head outgrew [`REQUEST_CAPACITY`], answered 431.
    pub overflowed: u64,
    /// Expositions the renderer would not fit. **Ours**, and unreachable while
    /// [`RESPONSE_CAPACITY`] is derived from the renderer's own bound.
    pub expositions_refused: u64,
    /// Ranges the transport asked for again that no response buffer held. A
    /// caller and a transport disagreeing about what is outstanding, which is
    /// **ours**.
    pub retransmits_unavailable: u64,
    /// Connections the server had no slot for. **Ours**: the slot table is the
    /// connection table's size, so this reads zero unless the two are
    /// configured apart.
    pub slots_exhausted: u64,
}

/// Where one connection's conversation has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Accumulating a request head.
    Reading,
    /// The head is read and the staging buffer is this connection's; the caller
    /// owes the body. Deliberately not [`Phase::Responding`]: nothing may be
    /// sent until there is something to send.
    AwaitingBody,
    /// A response is composed and being handed to the transport.
    Responding,
    /// Everything is out and this end has closed. The slot is kept so a
    /// retransmission can still be served out of it.
    Closed,
}

/// One connection's state.
struct Slot {
    connection: Option<ConnectionId>,
    request: [u8; REQUEST_CAPACITY],
    received: usize,
    /// A response with no body, composed here rather than in the shared buffer.
    head: [u8; MAX_HEAD_LEN],
    phase: Phase,
    /// True while this connection holds the shared response buffer.
    shared: bool,
    /// Bytes of response, wherever they live.
    len: usize,
    /// How many of them the transport has taken.
    sent: usize,
    /// Where response byte 0 sits in this connection's send sequence space,
    /// learned from the transport when the first range went out.
    base: Option<SeqNumber>,
}

impl Slot {
    const fn empty() -> Self {
        Self {
            connection: None,
            request: [0; REQUEST_CAPACITY],
            received: 0,
            head: [0; MAX_HEAD_LEN],
            phase: Phase::Reading,
            shared: false,
            len: 0,
            sent: 0,
            base: None,
        }
    }

    /// The room left in the request buffer, which is the window this connection
    /// advertises.
    const fn room(&self) -> usize {
        REQUEST_CAPACITY.saturating_sub(self.received)
    }
}

/// The one exposition that may be in flight.
struct Shared {
    owner: Option<ConnectionId>,
    bytes: [u8; RESPONSE_CAPACITY],
    /// Where the head begins. The body is rendered at [`MAX_HEAD_LEN`] and the
    /// head written backwards from there, so the two are contiguous and the
    /// body is never moved.
    start: usize,
}

/// The management server over one stack's connections.
///
/// `SLOTS` is the connection table's size: one slot per connection, so a
/// connection that exists always has somewhere to hold its request.
pub struct Server<const SLOTS: usize> {
    slots: [Slot; SLOTS],
    shared: Shared,
    counters: HttpCounters,
}

impl<const SLOTS: usize> Server<SLOTS> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [const { Slot::empty() }; SLOTS],
            shared: Shared {
                owner: None,
                bytes: [0; RESPONSE_CAPACITY],
                start: MAX_HEAD_LEN,
            },
            counters: HttpCounters {
                requests: 0,
                responses: [0; Status::ALL.len()],
                response_bytes: 0,
                overflowed: 0,
                expositions_refused: 0,
                retransmits_unavailable: 0,
                slots_exhausted: 0,
            },
        }
    }

    #[must_use]
    pub const fn counters(&self) -> HttpCounters {
        self.counters
    }

    /// Take request bytes a connection delivered, and decide on the head once it
    /// has arrived whole.
    ///
    /// Bounded by the slot, which the advertised window is kept equal to: a peer
    /// that honours the window cannot overrun it, and one that does not has the
    /// excess counted and dropped rather than written past the array.
    pub fn take(&mut self, connection: ConnectionId, data: &[u8]) {
        let Some(index) = self.slot_for(connection) else {
            bump(&mut self.counters.slots_exhausted);
            return;
        };
        let overran = {
            let Some(slot) = self.slots.get_mut(index) else {
                return;
            };
            let room = slot.room();
            let taken = room.min(data.len());
            let held = slot.received;
            for (target, byte) in slot
                .request
                .iter_mut()
                .skip(held)
                .zip(data.iter().take(taken))
            {
                *target = *byte;
            }
            slot.received = held.saturating_add(taken);
            slot.phase == Phase::Reading && taken < data.len()
        };
        if self
            .slots
            .get(index)
            .is_none_or(|slot| slot.phase != Phase::Reading)
        {
            // A connection that has already been answered goes on being read so
            // its window accounting stays honest, and nothing further is parsed:
            // this server answers one request per connection and closes.
            return;
        }
        if overran {
            bump(&mut self.counters.overflowed);
            self.respond_without_body(index, Status::HeadersTooLarge);
            return;
        }
        self.decide(index, connection);
    }

    /// Parse whatever has accumulated and answer if the head is whole.
    fn decide(&mut self, index: usize, connection: ConnectionId) {
        let status = {
            let Some(slot) = self.slots.get(index) else {
                return;
            };
            let head = slot.request.get(..slot.received).unwrap_or_default();
            match parse(head) {
                Ok(Parsed::NeedMore) => {
                    // Not yet, and a buffer that is now full will never hold
                    // one: answered here rather than waited on.
                    if slot.room() == 0 {
                        bump(&mut self.counters.overflowed);
                        self.respond_without_body(index, Status::HeadersTooLarge);
                    }
                    return;
                }
                Ok(Parsed::Complete { request, .. }) => {
                    bump(&mut self.counters.requests);
                    if !request.is_get() {
                        Status::MethodNotAllowed
                    } else if path_of(request.target()) == METRICS_TARGET {
                        Status::Ok
                    } else {
                        Status::NotFound
                    }
                }
                Err(error) => {
                    bump(&mut self.counters.requests);
                    error.status()
                }
            }
        };
        if status == Status::Ok {
            self.claim_buffer(index, connection);
        } else {
            self.respond_without_body(index, status);
        }
    }

    /// Claim the staging buffer, or answer 503 where a response is *still* going
    /// out on it.
    ///
    /// A closed owner's claim is taken rather than waited out. Waiting for the
    /// transport to hold none of its ranges — what [`Server::sweep`] waits for —
    /// would make the next scrape depend on the previous peer's last
    /// acknowledgement arriving first: `curl` twice in a row is answered
    /// `200, 200` on the debug kernel and `200, 503` on the release one, and a
    /// periodic scraper's second scrape may not be decided by timing. The price is
    /// a retransmit to an already-closed connection, refused rather than answered
    /// wrongly and counted as `http_retransmits_unavailable`.
    fn claim_buffer(&mut self, index: usize, connection: ConnectionId) {
        if !self.reclaim_if_finished() {
            self.respond_without_body(index, Status::ServiceUnavailable);
            return;
        }
        self.shared.owner = Some(connection);
        self.shared.start = MAX_HEAD_LEN;
        if let Some(slot) = self.slots.get_mut(index) {
            slot.phase = Phase::AwaitingBody;
            slot.shared = true;
            slot.len = 0;
            slot.sent = 0;
            slot.base = None;
        }
    }

    /// Whether the buffer may be claimed now, releasing a finished owner's hold.
    /// Free where nobody owns it, where the owner has no slot left, or where that
    /// slot has closed; held only while a response is still going out.
    fn reclaim_if_finished(&mut self) -> bool {
        let Some(owner) = self.shared.owner else {
            return true;
        };
        let index = self.index_of(owner);
        if index.is_some_and(|index| {
            self.slots
                .get(index)
                .is_some_and(|slot| slot.phase != Phase::Closed)
        }) {
            return false;
        }
        self.shared.owner = None;
        self.shared.start = MAX_HEAD_LEN;
        if let Some(slot) = index.and_then(|index| self.slots.get_mut(index)) {
            slot.shared = false;
            slot.base = None;
        }
        true
    }

    /// The connection whose body the caller owes, if any.
    #[must_use]
    pub fn pending_body(&self) -> Option<ConnectionId> {
        self.slots
            .iter()
            .find(|slot| slot.phase == Phase::AwaitingBody)
            .and_then(|slot| slot.connection)
    }

    /// Render that connection's body with `render` and put a head in front of
    /// it.
    ///
    /// `render` writes into the staging buffer and answers the body's length, or
    /// `None` where it does not fit — which is **ours** rather than the client's,
    /// [`RESPONSE_CAPACITY`] being derived from the renderer's own worst case, so
    /// a caller sized by it can never provoke one.
    pub fn supply(&mut self, render: impl FnOnce(&mut [u8]) -> Option<usize>) {
        let Some(connection) = self.pending_body() else {
            return;
        };
        let Some(index) = self.index_of(connection) else {
            return;
        };
        let composed = self
            .shared
            .bytes
            .get_mut(MAX_HEAD_LEN..)
            .and_then(render)
            .and_then(|body| {
                let mut head = [0u8; MAX_HEAD_LEN];
                let len =
                    write_head(Status::Ok, Some(METRICS_CONTENT_TYPE), body, &mut head).ok()?;
                let start = MAX_HEAD_LEN.checked_sub(len)?;
                self.shared
                    .bytes
                    .get_mut(start..MAX_HEAD_LEN)?
                    .copy_from_slice(head.get(..len)?);
                self.shared.start = start;
                Some(len.saturating_add(body))
            });
        let Some(len) = composed else {
            // Counted rather than asserted so a divergence surfaces as a refused
            // scrape with a number attached (ENG-12). The buffer is released
            // here: the refusal has no body to keep it for.
            bump(&mut self.counters.expositions_refused);
            self.shared.owner = None;
            self.shared.start = MAX_HEAD_LEN;
            if let Some(slot) = self.slots.get_mut(index) {
                slot.shared = false;
            }
            self.respond_without_body(index, Status::ServiceUnavailable);
            return;
        };
        if let Some(slot) = self.slots.get_mut(index) {
            slot.phase = Phase::Responding;
            slot.len = len;
        }
        self.record(Status::Ok);
    }

    /// A status with no body, composed in the connection's own slot so it can
    /// never be refused for want of the shared buffer.
    fn respond_without_body(&mut self, index: usize, status: Status) {
        if let Some(slot) = self.slots.get_mut(index) {
            let len = write_head(status, None, 0, &mut slot.head).map_or(0, |len| len);
            slot.phase = Phase::Responding;
            slot.shared = false;
            slot.len = len;
            slot.sent = 0;
            slot.base = None;
        }
        self.record(status);
    }

    fn record(&mut self, status: Status) {
        if let Some(count) = self.counters.responses.get_mut(status.slot()) {
            *count = count.saturating_add(1);
        }
    }

    /// Note that the peer has closed its half.
    ///
    /// A connection that closed before its request head ended will never send
    /// one, so this end has nothing to answer and closes too rather than holding
    /// the slot until an idle timer reaps it. A connection already being answered
    /// is unaffected: a half-close is the client saying it has finished asking,
    /// not that it has stopped listening.
    pub fn note_peer_closed(&mut self, connection: ConnectionId) {
        let Some(index) = self.index_of(connection) else {
            return;
        };
        if let Some(slot) = self.slots.get_mut(index)
            && matches!(slot.phase, Phase::Reading | Phase::AwaitingBody)
        {
            slot.phase = Phase::Responding;
            slot.shared = false;
            slot.len = 0;
            slot.sent = 0;
            slot.base = None;
        }
    }

    /// A connection with something left to send, if any.
    #[must_use]
    pub fn pending(&self) -> Option<ConnectionId> {
        self.slots
            .iter()
            .find(|slot| slot.phase == Phase::Responding)
            .and_then(|slot| slot.connection)
    }

    /// Do whatever this connection now owes: send the next chunk of its
    /// response, or close.
    ///
    /// Answers the length of a segment written into `out`, or `None` where there
    /// was nothing to do or the transport would not take it. One segment per
    /// call, because `out` holds one.
    pub fn drive<const CONNECTIONS: usize>(
        &mut self,
        stack: &mut TcpStack<CONNECTIONS>,
        now: Monotonic,
        connection: ConnectionId,
        out: &mut [u8],
    ) -> Option<usize> {
        let index = self.index_of(connection)?;
        // Before anything is composed, because the segment below carries the
        // window: one set afterwards would be a segment out of date, and the
        // peer would be told it may send bytes this end is still holding.
        //
        // Lossless: `room` is bounded by `REQUEST_CAPACITY`.
        let room = self.slots.get(index)?.room();
        stack.set_receive_window(connection, room as u32);

        if self.slots.get(index)?.phase != Phase::Responding {
            return None;
        }
        let (sent, len) = {
            let slot = self.slots.get(index)?;
            (slot.sent, slot.len)
        };
        if sent < len {
            return self.send_next(stack, now, connection, index, out);
        }
        match stack.close(now, connection, out) {
            Ok(written) => {
                let slot = self.slots.get_mut(index)?;
                slot.phase = Phase::Closed;
                Some(written)
            }
            // A window with no room, a full record table, or storage too small:
            // all three are answered by trying again on the next wakeup.
            Err(_) => None,
        }
    }

    fn send_next<const CONNECTIONS: usize>(
        &mut self,
        stack: &mut TcpStack<CONNECTIONS>,
        now: Monotonic,
        connection: ConnectionId,
        index: usize,
        out: &mut [u8],
    ) -> Option<usize> {
        let (sent, len, shared, start) = {
            let slot = self.slots.get(index)?;
            (slot.sent, slot.len, slot.shared, self.shared.start)
        };
        let payload = if shared {
            self.shared
                .bytes
                .get(start.saturating_add(sent)..start.saturating_add(len))?
        } else {
            self.slots.get(index)?.head.get(sent..len)?
        };
        let written = stack.send(now, connection, payload, out).ok()?;
        let base = stack
            .connection(connection)
            .and_then(Connection::oldest_range)
            .map(|(sequence, _)| sequence);
        let slot = self.slots.get_mut(index)?;
        if slot.base.is_none() {
            // The first range out is the oldest unacknowledged one, and the
            // response is all this end sends, so this is where byte 0 sits.
            slot.base = base;
        }
        slot.sent = slot.sent.saturating_add(written.bytes);
        self.counters.response_bytes = self
            .counters
            .response_bytes
            .saturating_add(written.bytes as u64);
        Some(written.len)
    }

    /// Answer one of the transport's timeouts.
    ///
    /// Only [`Timeout::Retransmit`] asks anything of this server: the rest are
    /// segments the transport composed itself, or connections it has given up
    /// on. A slot whose connection is gone is released here.
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

    /// Supply a range the transport asked for again, out of the response this
    /// connection is still holding.
    fn serve<const CONNECTIONS: usize>(
        &mut self,
        stack: &mut TcpStack<CONNECTIONS>,
        now: Monotonic,
        connection: ConnectionId,
        sequence: SeqNumber,
        len: u16,
        out: &mut [u8],
    ) -> Option<usize> {
        let payload = self.range(connection, sequence, len);
        let Some(payload) = payload else {
            bump(&mut self.counters.retransmits_unavailable);
            return None;
        };
        match stack.retransmit(now, connection, sequence, payload, out) {
            Ok(written) => Some(written),
            Err(_) => {
                bump(&mut self.counters.retransmits_unavailable);
                None
            }
        }
    }

    /// The `len` response bytes at `sequence`, or `None` where this connection
    /// never sent them.
    fn range(&self, connection: ConnectionId, sequence: SeqNumber, len: u16) -> Option<&[u8]> {
        let index = self.index_of(connection)?;
        let slot = self.slots.get(index)?;
        let base = slot.base?;
        // `distance_from` is modulo-2^32 and so is defined for every pair; a
        // sequence outside the response answers an offset past `sent`, which the
        // bound below refuses.
        let offset = sequence.distance_from(base) as usize;
        let end = offset.checked_add(usize::from(len))?;
        if end > slot.sent {
            return None;
        }
        if slot.shared {
            let start = self.shared.start;
            self.shared
                .bytes
                .get(start.saturating_add(offset)..start.saturating_add(end))
        } else {
            slot.head.get(offset..end)
        }
    }

    /// Release the staging buffer as soon as its response can no longer be asked
    /// for again: this end has closed and the transport holds none of its ranges
    /// outstanding.
    ///
    /// Waiting for the connection's slot instead would hold the buffer through
    /// `TIME_WAIT` — a minute — and refuse every scrape made in it.
    pub fn sweep<const CONNECTIONS: usize>(&mut self, stack: &TcpStack<CONNECTIONS>) {
        let Some(owner) = self.shared.owner else {
            return;
        };
        let Some(index) = self.index_of(owner) else {
            return;
        };
        let closed = self
            .slots
            .get(index)
            .is_some_and(|slot| slot.phase == Phase::Closed);
        if !closed || stack.outstanding(owner) > 0 {
            return;
        }
        self.shared.owner = None;
        self.shared.start = MAX_HEAD_LEN;
        if let Some(slot) = self.slots.get_mut(index) {
            // Nothing may be served out of it, and nothing will ask.
            slot.shared = false;
            slot.base = None;
        }
    }

    /// Give a slot back, forgetting whatever it held and releasing the shared
    /// buffer where this connection owned it.
    ///
    /// Called where a connection has gone — reaped, abandoned, reset or closed —
    /// which is the only place a response is forgotten: it is otherwise held for
    /// as long as the transport may ask for a range of it again.
    pub fn release(&mut self, connection: ConnectionId) {
        if self.shared.owner == Some(connection) {
            self.shared.owner = None;
            self.shared.start = MAX_HEAD_LEN;
        }
        if let Some(index) = self.index_of(connection)
            && let Some(slot) = self.slots.get_mut(index)
        {
            slot.connection = None;
            slot.received = 0;
            slot.phase = Phase::Reading;
            slot.shared = false;
            slot.len = 0;
            slot.sent = 0;
            slot.base = None;
        }
    }

    /// The slot this connection already has, or a free one bound to it.
    fn slot_for(&mut self, connection: ConnectionId) -> Option<usize> {
        if let Some(index) = self.index_of(connection) {
            return Some(index);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| slot.connection.is_none())?;
        let slot = self.slots.get_mut(index)?;
        slot.connection = Some(connection);
        slot.received = 0;
        slot.phase = Phase::Reading;
        slot.shared = false;
        slot.len = 0;
        slot.sent = 0;
        slot.base = None;
        Some(index)
    }

    fn index_of(&self, connection: ConnectionId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.connection == Some(connection))
    }
}

impl<const SLOTS: usize> Default for Server<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

/// The path half of a request target, so `/metrics?foo=1` reaches the same
/// handler `/metrics` does. Nothing here interprets the query: this server takes
/// no parameters, and one it silently ignored would be one a caller believed in.
fn path_of(target: &str) -> &str {
    match target.split_once('?') {
        Some((path, _)) => path,
        None => target,
    }
}

fn bump(count: &mut u64) {
    *count = count.saturating_add(1);
}
