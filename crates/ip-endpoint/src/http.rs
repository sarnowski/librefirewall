//! The management HTTP server: what an established connection on the management
//! port now does.
//!
//! It answers `GET /metrics` with the Prometheus exposition its caller renders,
//! a target its owner registered through [`Server::serve_stream_at`] by
//! streaming a body that owner produces a window at a time, and everything else
//! with a status. It replaced the byte echo wholesale rather than being layered
//! on it (ENG-6): nothing of that stand-in survives.
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
//! An exposition is [`RESPONSE_CAPACITY`] bytes — about 39 KiB — and a buffer
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
//! # A body no array can hold, and the window that answers it
//!
//! That paragraph is also why a recording off a block device *cannot* be composed
//! whole. A second shape shares the one array — [`Body`] keeps the two exclusive
//! — stating its length up front ([`Server::supply_stream`] writes an exact
//! `Content-Length`; nothing here is chunked) and taking the body [`WINDOW_LEN`]
//! bytes at a time ([`Server::supply_window`]). A window is not simply the next
//! bytes to send, because a range the transport re-asks for must still be in the
//! array: it begins [`RETRANSMIT_SPAN`] *behind* that byte, with [`WINDOW_LEN`]
//! twice that span to leave room in front, under a `const` assertion so a wider
//! transport window moves this in a diff. Not holding one is an answer rather
//! than a stall: **nothing** goes out that pass, [`Server::window_wanted`] names
//! what is needed, and [`Server::pending`] prefers a connection that can send.
//! Where a window cannot be produced at all, [`Server::abandon_stream`] closes
//! short of the announced length — invented bytes being worse than truncation.
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
use lfw_tcp::{Connection, ConnectionId, MAX_UNACKED, SeqNumber, TcpStack, Timeout};

use crate::TCP_MSS;

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

/// The tail a window keeps behind the byte being sent: everything the transport
/// can re-ask for and owns no copy of, so a window slid past one of those ranges
/// would refuse the retransmission and stall the transfer.
pub const RETRANSMIT_SPAN: usize = MAX_UNACKED * TCP_MSS as usize;

/// Bytes of body the sliding window holds, and so the size of every window
/// [`Server::supply_window`] is handed.
pub const WINDOW_LEN: usize = 16 * 1024;

/// The longest body this server will stream. A range is found by its offset from
/// the sequence number the first byte took and `distance_from` is modulo 2^32,
/// so past half that space two offsets look alike and a retransmission would
/// carry the wrong bytes. A longer recording is refused, never truncated.
pub const MAX_STREAM_LEN: u64 = 1 << 31;

/// Targets an owner may register as streamed: several, CONCEPT §11's management
/// surface naming several, and bounded because each is compared against every
/// request target (ENG-4).
pub const MAX_STREAM_TARGETS: usize = 4;

// The bound the whole streaming design rests on, stated where both halves are
// visible: the worst-case exposition and the head in front of it fit the buffer
// they are composed into, so a scrape is never answered short (TEST-5). Both are
// stated as numbers, so a new family moves this reservation in a diff.
const _: () = {
    assert!(RESPONSE_CAPACITY >= MAX_HEAD_LEN + lfw_metrics::MAX_EXPOSITION_LEN);
    assert!(RESPONSE_CAPACITY > MAX_HEAD_LEN);

    assert!(lfw_metrics::MAX_EXPOSITION_LEN == 39_018);
    assert!(RESPONSE_CAPACITY == 39_179);
};

// And the bound the windowed shape rests on, held to the transport's own
// numbers: a wider `MAX_UNACKED` or `TCP_MSS` fails the build here rather than
// producing an appliance whose downloads stall on the first lost segment. In
// order: advance by more than a window's own tail, fit behind the head, and stay
// inside what an `as u64` widening below can carry.
const _: () = {
    assert!(WINDOW_LEN >= 2 * RETRANSMIT_SPAN);
    assert!(MAX_HEAD_LEN + WINDOW_LEN <= RESPONSE_CAPACITY);
    assert!(WINDOW_LEN as u64 <= MAX_STREAM_LEN);
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
    /// Responses committed to by window: one per [`Server::supply_stream`] taken.
    pub streams_started: u64,
    /// Windows a caller handed over and this server took.
    pub windows_supplied: u64,
    /// Passes that sent nothing for want of the window: how often a download
    /// stalls on its supplier, and **ours**.
    pub window_misses: u64,
    /// Windows offered at another `start` or length: a caller and this server
    /// disagreeing about a body's place, which is **ours**.
    pub windows_refused: u64,
    /// Windowed responses given up on: a supplier that cannot keep up.
    pub streams_abandoned: u64,
}

/// What a caller owes a connection whose head has been read, and so which body
/// shape was decided on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Want {
    Exposition,
    /// A decision on this target: [`Server::supply_stream`] or an abandon.
    Stream(&'static str),
}

/// Where one connection's conversation has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Accumulating a request head.
    Reading,
    /// The head is read and the staging buffer is this connection's; the caller
    /// owes what [`Want`] names. Deliberately not [`Phase::Responding`]: nothing
    /// may be sent until there is something to send.
    AwaitingBody(Want),
    /// A response is composed and being handed to the transport.
    Responding,
    /// Everything is out and this end has closed. The slot is kept so a
    /// retransmission can still be served out of it.
    Closed,
}

/// Where a windowed response has got to, and which slice of its body the array
/// holds. Offsets are of the *response*: what a retransmission asks by.
#[derive(Clone, Copy, Debug)]
struct Window {
    /// The body's whole length, already announced: a caller that finds it has
    /// fewer bytes abandons rather than revising it.
    total: u64,
    at: u64,
    /// Bytes of the window supplied; short of [`WINDOW_LEN`] on the last one.
    filled: usize,
    /// Response bytes handed to the transport, the head included.
    sent: u64,
}

impl Window {
    fn len(&self, head: usize) -> u64 {
        // Lossless: a head is at most `MAX_HEAD_LEN` bytes.
        (head as u64).saturating_add(self.total)
    }

    fn sent_body(&self, head: usize) -> u64 {
        self.sent.saturating_sub(head as u64)
    }

    /// The response offsets the array can answer now, half-open, and where the
    /// first sits. While the window begins at body byte 0 the head in front is
    /// part of that run and one segment carries both; after a slide it is out of
    /// reach, being past [`RETRANSMIT_SPAN`] anyway.
    fn servable(&self, head: usize) -> (u64, u64, usize) {
        // Lossless: `filled` is at most `WINDOW_LEN` and `head` at most
        // `MAX_HEAD_LEN`.
        let filled = self.filled as u64;
        if self.at == 0 {
            let hi = (head as u64).saturating_add(filled);
            return (0, hi, MAX_HEAD_LEN.saturating_sub(head));
        }
        let lo = (head as u64).saturating_add(self.at);
        (lo, lo.saturating_add(filled), MAX_HEAD_LEN)
    }

    /// The body byte a window must begin at, or `None` where the one held will do
    /// or the body is out. A *start*, not the byte to send: see the header.
    fn wanted(&self, head: usize) -> Option<u64> {
        let body = self.sent_body(head);
        if body >= self.total {
            return None;
        }
        // Lossless: `filled` is at most `WINDOW_LEN`.
        if body < self.at.saturating_add(self.filled as u64) {
            return None;
        }
        Some(body.saturating_sub(RETRANSMIT_SPAN as u64))
    }

    /// Bytes the window at `start` owes: a whole [`WINDOW_LEN`], or the rest.
    fn expected(&self, start: u64) -> u64 {
        // Lossless: `WINDOW_LEN` is a compile-time constant well under 2^32.
        self.total.saturating_sub(start).min(WINDOW_LEN as u64)
    }
}

/// Where one connection's response bytes are, and in what shape. One value
/// rather than a flag beside a cursor: the variants are exclusive by
/// construction, which makes a buffered and a windowed response owning the one
/// staging array at once unrepresentable (DOC-9).
#[derive(Clone, Copy, Debug)]
enum Body {
    /// A status with no body, in the slot's own [`Slot::head`].
    Own,
    /// Head and body together in the staging array, composed once.
    Staged,
    /// A head in the staging array, and a sliding window of the body behind it.
    Windowed(Window),
    /// Given up on: nothing more goes out and no range serves again.
    Abandoned,
}

/// One connection's state.
struct Slot {
    connection: Option<ConnectionId>,
    request: [u8; REQUEST_CAPACITY],
    received: usize,
    /// A response with no body, composed here rather than in the shared buffer.
    head: [u8; MAX_HEAD_LEN],
    phase: Phase,
    /// Where this connection's response bytes are.
    body: Body,
    /// Bytes of a [`Body::Own`] or [`Body::Staged`] response; a windowed one
    /// carries its own in `u64`.
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
            body: Body::Own,
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

    /// Whether the transport has yet to be handed everything. An abandoned
    /// response owes nothing whatever it announced, which turns the next drive
    /// into the close.
    fn owes(&self, head: usize) -> bool {
        match self.body {
            Body::Own | Body::Staged => self.sent < self.len,
            Body::Windowed(window) => window.sent < window.len(head),
            Body::Abandoned => false,
        }
    }

    fn window(&self) -> Option<Window> {
        match self.body {
            Body::Windowed(window) => Some(window),
            _ => None,
        }
    }
}

/// What a completed head resolved to: two answers rather than a status compared
/// against `200`, which shape was claimed not being readable off that code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    Refuse(Status),
    Claim(Want),
}

/// Where the next unsent bytes are, as a span not a borrow: counting a miss
/// needs the counters mutably, and the borrow would still be live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Chunk {
    Own {
        start: usize,
        end: usize,
    },
    Staged {
        start: usize,
        end: usize,
    },
    /// Outside the window held: nothing goes out until one is supplied.
    Missing,
}

/// The one response that may be in flight, in either of its two shapes.
struct Shared {
    owner: Option<ConnectionId>,
    bytes: [u8; RESPONSE_CAPACITY],
    /// Where the head begins. A staged body is rendered at [`MAX_HEAD_LEN`] and a
    /// window filled from there, the head written backwards from that point in
    /// both cases, so the two are contiguous and the body never moves.
    start: usize,
}

impl Shared {
    /// Bytes of head in front of the body, derived rather than stored so the two
    /// cannot disagree (DOC-9).
    const fn head_len(&self) -> usize {
        MAX_HEAD_LEN.saturating_sub(self.start)
    }
}

/// The management server over one stack's connections.
///
/// `SLOTS` is the connection table's size: one slot per connection, so a
/// connection that exists always has somewhere to hold its request.
pub struct Server<const SLOTS: usize> {
    slots: [Slot; SLOTS],
    shared: Shared,
    /// The targets an owner registered as streamed: a fixed table this server
    /// only compares against, which keeps recordings and block devices out of it.
    targets: [Option<&'static str>; MAX_STREAM_TARGETS],
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
            targets: [None; MAX_STREAM_TARGETS],
            counters: HttpCounters {
                requests: 0,
                responses: [0; Status::ALL.len()],
                response_bytes: 0,
                overflowed: 0,
                expositions_refused: 0,
                retransmits_unavailable: 0,
                slots_exhausted: 0,
                streams_started: 0,
                windows_supplied: 0,
                window_misses: 0,
                windows_refused: 0,
                streams_abandoned: 0,
            },
        }
    }

    #[must_use]
    pub const fn counters(&self) -> HttpCounters {
        self.counters
    }

    /// Register `target` as one this server answers by streaming; an unregistered
    /// one stays `404`, which keeps this table the whole of the routing. `false`
    /// for a full table, one already registered, or [`METRICS_TARGET`], which
    /// would put two answers on one target.
    pub fn serve_stream_at(&mut self, target: &'static str) -> bool {
        if target == METRICS_TARGET || self.registered(target).is_some() {
            return false;
        }
        let Some(slot) = self.targets.iter_mut().find(|slot| slot.is_none()) else {
            return false;
        };
        *slot = Some(target);
        true
    }

    fn registered(&self, path: &str) -> Option<&'static str> {
        self.targets
            .iter()
            .flatten()
            .copied()
            .find(|target| *target == path)
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
        // Copied out before the slot is borrowed: four words against a borrow of
        // the whole server across the parse.
        let targets = self.targets;
        let decision = {
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
                    let path = path_of(request.target());
                    if !request.is_get() {
                        Decision::Refuse(Status::MethodNotAllowed)
                    } else if path == METRICS_TARGET {
                        Decision::Claim(Want::Exposition)
                    } else if let Some(target) =
                        targets.iter().flatten().copied().find(|it| *it == path)
                    {
                        Decision::Claim(Want::Stream(target))
                    } else {
                        Decision::Refuse(Status::NotFound)
                    }
                }
                Err(error) => {
                    bump(&mut self.counters.requests);
                    Decision::Refuse(error.status())
                }
            }
        };
        match decision {
            Decision::Claim(want) => self.claim_buffer(index, connection, want),
            Decision::Refuse(status) => self.respond_without_body(index, status),
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
    fn claim_buffer(&mut self, index: usize, connection: ConnectionId, want: Want) {
        if !self.reclaim_if_finished() {
            self.respond_without_body(index, Status::ServiceUnavailable);
            return;
        }
        self.shared.owner = Some(connection);
        self.shared.start = MAX_HEAD_LEN;
        if let Some(slot) = self.slots.get_mut(index) {
            slot.phase = Phase::AwaitingBody(want);
            // The shape is whichever of `supply` and `supply_stream` answers.
            slot.body = Body::Own;
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
            slot.body = Body::Own;
            slot.base = None;
        }
        true
    }

    /// Give the staging array back, leaving the response where a bodiless status
    /// is composed.
    fn release_shared(&mut self, index: usize) {
        self.shared.owner = None;
        self.shared.start = MAX_HEAD_LEN;
        if let Some(slot) = self.slots.get_mut(index) {
            slot.body = Body::Own;
        }
    }

    /// The connection whose exposition the caller owes, if any — never one
    /// waiting on a *stream* decision, which would answer one target with
    /// another's body.
    #[must_use]
    pub fn pending_body(&self) -> Option<ConnectionId> {
        self.slots
            .iter()
            .find(|slot| slot.phase == Phase::AwaitingBody(Want::Exposition))
            .and_then(|slot| slot.connection)
    }

    /// The connection whose registered stream target the caller must decide on,
    /// and which it asked for. Leaving one unanswered holds the staging array and
    /// refuses every scrape meanwhile, as a caller that never supplies an
    /// exposition already can.
    #[must_use]
    pub fn pending_stream(&self) -> Option<(ConnectionId, &'static str)> {
        self.slots.iter().find_map(|slot| match slot.phase {
            Phase::AwaitingBody(Want::Stream(target)) => Some((slot.connection?, target)),
            _ => None,
        })
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
                // Lossless: an exposition is at most `MAX_EXPOSITION_LEN` bytes.
                let len = write_head(
                    Status::Ok,
                    Some(METRICS_CONTENT_TYPE),
                    body as u64,
                    &mut head,
                )
                .ok()?;
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
            self.release_shared(index);
            self.respond_without_body(index, Status::ServiceUnavailable);
            return;
        };
        if let Some(slot) = self.slots.get_mut(index) {
            slot.phase = Phase::Responding;
            slot.body = Body::Staged;
            slot.len = len;
        }
        self.record(Status::Ok);
    }

    /// Commit to answering the pending stream target with a body of `total`
    /// bytes, written into the head now as an exact `Content-Length`: a caller
    /// that cannot then produce exactly that many has no way back but
    /// [`abandon_stream`](Self::abandon_stream) — which is also what it owes the
    /// request where this answers `false`, changing nothing.
    pub fn supply_stream(&mut self, total: u64, content_type: &str) -> bool {
        let Some((connection, _)) = self.pending_stream() else {
            return false;
        };
        let Some(index) = self.index_of(connection) else {
            return false;
        };
        // Lossless: a head is at most `MAX_HEAD_LEN` bytes, and the response is
        // the head and the body together.
        if total > MAX_STREAM_LEN.saturating_sub(MAX_HEAD_LEN as u64) {
            return false;
        }
        if self.write_stream_head(total, content_type).is_none() {
            return false;
        }
        if let Some(slot) = self.slots.get_mut(index) {
            slot.phase = Phase::Responding;
            slot.body = Body::Windowed(Window {
                total,
                at: 0,
                filled: 0,
                sent: 0,
            });
            slot.len = 0;
            slot.sent = 0;
            slot.base = None;
        }
        bump(&mut self.counters.streams_started);
        self.record(Status::Ok);
        true
    }

    /// Write the head backwards from [`MAX_HEAD_LEN`], so a window filled from
    /// there begins where it ends. `None` for a content type past that bound.
    fn write_stream_head(&mut self, total: u64, content_type: &str) -> Option<()> {
        let mut head = [0u8; MAX_HEAD_LEN];
        let len = write_head(Status::Ok, Some(content_type), total, &mut head).ok()?;
        let start = MAX_HEAD_LEN.checked_sub(len)?;
        self.shared
            .bytes
            .get_mut(start..MAX_HEAD_LEN)?
            .copy_from_slice(head.get(..len)?);
        self.shared.start = start;
        Some(())
    }

    /// The body byte a window must begin at, and the connection waiting on it: a
    /// window *start*, not the next byte to send (see [`Window::wanted`]).
    #[must_use]
    pub fn window_wanted(&self) -> Option<(ConnectionId, u64)> {
        let head = self.shared.head_len();
        self.slots
            .iter()
            .find_map(|slot| Some((slot.connection?, slot.window()?.wanted(head)?)))
    }

    /// Hand the server the window beginning at body byte `start`: the `start`
    /// [`window_wanted`](Self::window_wanted) named, and a whole [`WINDOW_LEN`]
    /// unless the body ends first. Anything else is refused and counted — it would
    /// put a recording's bytes where no client could tell they did not belong.
    pub fn supply_window(&mut self, start: u64, bytes: &[u8]) -> bool {
        if self.take_window(start, bytes) {
            bump(&mut self.counters.windows_supplied);
            return true;
        }
        bump(&mut self.counters.windows_refused);
        false
    }

    fn take_window(&mut self, start: u64, bytes: &[u8]) -> bool {
        let head = self.shared.head_len();
        let found = self
            .slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| Some((index, slot.window()?)));
        let Some((index, window)) = found else {
            return false;
        };
        // Lossless: a slice length is a `usize`.
        if window.wanted(head) != Some(start) || bytes.len() as u64 != window.expected(start) {
            return false;
        }
        // `bytes` is at most `WINDOW_LEN`, which the module's assertion holds to
        // fit behind the head, so the zip copies all of it. An iteration rather
        // than a slice leaves no bound to refuse at runtime (ENG-5).
        for (target, byte) in self
            .shared
            .bytes
            .iter_mut()
            .skip(MAX_HEAD_LEN)
            .zip(bytes.iter())
        {
            *target = *byte;
        }
        if let Some(slot) = self.slots.get_mut(index)
            && let Body::Windowed(window) = &mut slot.body
        {
            window.at = start;
            window.filled = bytes.len();
        }
        true
    }

    /// Give up on the windowed response, wherever it has got to. Before the head
    /// is written nothing is on the wire, so the request is answered `503`: the
    /// owner registered the target and could not produce it. After it, the
    /// connection closes short of the announced length.
    pub fn abandon_stream(&mut self) {
        if let Some((connection, _)) = self.pending_stream()
            && let Some(index) = self.index_of(connection)
        {
            self.release_shared(index);
            bump(&mut self.counters.streams_abandoned);
            self.respond_without_body(index, Status::ServiceUnavailable);
            return;
        }
        let windowed = self
            .slots
            .iter()
            .position(|slot| slot.window().is_some())
            .and_then(|index| self.slots.get_mut(index));
        if let Some(slot) = windowed {
            slot.body = Body::Abandoned;
            bump(&mut self.counters.streams_abandoned);
        }
    }

    /// A status with no body, composed in the connection's own slot so it can
    /// never be refused for want of the shared buffer.
    fn respond_without_body(&mut self, index: usize, status: Status) {
        if let Some(slot) = self.slots.get_mut(index) {
            let len = write_head(status, None, 0, &mut slot.head).map_or(0, |len| len);
            slot.phase = Phase::Responding;
            slot.body = Body::Own;
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
            && matches!(slot.phase, Phase::Reading | Phase::AwaitingBody(_))
        {
            slot.phase = Phase::Responding;
            slot.body = Body::Own;
            slot.len = 0;
            slot.sent = 0;
            slot.base = None;
        }
    }

    /// A connection with something left to send. One waiting on a window is taken
    /// **last**, so an absent supplier holds up nobody else — but it is taken,
    /// because that is where the miss is counted.
    #[must_use]
    pub fn pending(&self) -> Option<ConnectionId> {
        self.responding(false).or_else(|| self.responding(true))
    }

    fn responding(&self, stalled: bool) -> Option<ConnectionId> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            (slot.phase == Phase::Responding && self.stalled(index) == stalled)
                .then_some(slot.connection)
                .flatten()
        })
    }

    /// Waiting on a window: the one state a response cannot be driven out of.
    fn stalled(&self, index: usize) -> bool {
        self.chunk_for(index) == Some(Chunk::Missing)
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
        let head = self.shared.head_len();
        if self.slots.get(index)?.owes(head) {
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
        let payload = match self.chunk_for(index)? {
            Chunk::Missing => {
                // Inventing bytes would put data in a recording that was never
                // recorded, so the miss is counted and the place kept (ENG-12).
                bump(&mut self.counters.window_misses);
                return None;
            }
            Chunk::Own { start, end } => self.slots.get(index)?.head.get(start..end)?,
            Chunk::Staged { start, end } => self.shared.bytes.get(start..end)?,
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
        if let Body::Windowed(window) = &mut slot.body {
            // Lossless: a count of bytes taken out of one segment.
            window.sent = window.sent.saturating_add(written.bytes as u64);
        } else {
            slot.sent = slot.sent.saturating_add(written.bytes);
        }
        self.counters.response_bytes = self
            .counters
            .response_bytes
            .saturating_add(written.bytes as u64);
        Some(written.len)
    }

    /// Where the next unsent bytes are, or `None` where the response owes none.
    fn chunk_for(&self, index: usize) -> Option<Chunk> {
        let slot = self.slots.get(index)?;
        match slot.body {
            Body::Abandoned => None,
            Body::Own => (slot.sent < slot.len).then_some(Chunk::Own {
                start: slot.sent,
                end: slot.len,
            }),
            Body::Staged => (slot.sent < slot.len).then(|| Chunk::Staged {
                start: self.shared.start.saturating_add(slot.sent),
                end: self.shared.start.saturating_add(slot.len),
            }),
            Body::Windowed(window) => {
                let head = self.shared.head_len();
                if window.sent >= window.len(head) {
                    return None;
                }
                let (lo, hi, at) = window.servable(head);
                if window.sent < lo || window.sent >= hi {
                    return Some(Chunk::Missing);
                }
                // Lossless: both are bounded by the head plus `WINDOW_LEN`,
                // which the module's assertion holds to `RESPONSE_CAPACITY`.
                Some(Chunk::Staged {
                    start: at.saturating_add((window.sent - lo) as usize),
                    end: at.saturating_add((hi - lo) as usize),
                })
            }
        }
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
    /// never sent them, or the window moved past them ([`RETRANSMIT_SPAN`] keeps
    /// that unreachable).
    fn range(&self, connection: ConnectionId, sequence: SeqNumber, len: u16) -> Option<&[u8]> {
        let index = self.index_of(connection)?;
        let slot = self.slots.get(index)?;
        let base = slot.base?;
        // `distance_from` is modulo-2^32 and so is defined for every pair; a
        // sequence outside the response answers an offset past `sent`, which the
        // bounds below refuse. `MAX_STREAM_LEN` keeps a windowed response inside
        // half that space, so no two of its offsets look alike.
        let offset = sequence.distance_from(base);
        match slot.body {
            Body::Abandoned => None,
            Body::Windowed(window) => {
                let head = self.shared.head_len();
                let offset = u64::from(offset);
                let end = offset.checked_add(u64::from(len))?;
                if end > window.sent {
                    return None;
                }
                let (lo, hi, at) = window.servable(head);
                if offset < lo || end > hi {
                    // Unreachable while the module's assertion holds; refused
                    // rather than asserted, for `expositions_refused`'s reason.
                    return None;
                }
                // Lossless: as `chunk_for`.
                self.shared.bytes.get(
                    at.saturating_add((offset - lo) as usize)
                        ..at.saturating_add((end - lo) as usize),
                )
            }
            Body::Own | Body::Staged => {
                let offset = offset as usize;
                let end = offset.checked_add(usize::from(len))?;
                if end > slot.sent {
                    return None;
                }
                if matches!(slot.body, Body::Staged) {
                    let start = self.shared.start;
                    self.shared
                        .bytes
                        .get(start.saturating_add(offset)..start.saturating_add(end))
                } else {
                    slot.head.get(offset..end)
                }
            }
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
            slot.body = Body::Own;
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
            slot.body = Body::Own;
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
        slot.body = Body::Own;
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
