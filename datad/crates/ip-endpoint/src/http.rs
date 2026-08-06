//! The management HTTP server: what an established connection on the management
//! port now does.
//!
//! It answers three shapes of request and everything else with a status:
//!
//! * a `GET` of a target registered through [`Server::serve_rendered_at`] —
//!   `/metrics` among them — with a body its owner renders into the one staging
//!   array;
//! * a `GET` of a target registered through [`Server::serve_stream_at`] by
//!   streaming a body that owner produces a window at a time;
//! * a `POST` to a target registered through [`Server::serve_body_at`] by
//!   **accumulating** the request body into that same staging array and handing it
//!   to the owner to decide on.
//!
//! # The request body lives in the response buffer, and that is the whole design
//!
//! There is one staging array ([`RESPONSE_CAPACITY`]) and it is claimed by one
//! connection at a time. A submitted body claims it exactly as an exposition
//! does, is accumulated in it, and is then overwritten by the response composed
//! for the same connection — so a `POST` costs no second buffer anywhere, which
//! matters because the alternative is [`MAX_BODY_LEN`] per connection slot in a
//! protection domain's own memory.
//!
//! Two consequences, both stated rather than hidden. A `POST` in progress makes a
//! concurrent scrape `503`, on exactly the terms two concurrent scrapes already
//! refuse each other. And the owner **must read the body before it answers**:
//! [`Server::submission`] borrows out of the array that [`Server::supply`] then
//! writes into, which the borrow checker enforces at the call site rather than
//! this paragraph enforcing by asking.
//!
//! # A body that never finishes, and why it needs a deadline of its own
//!
//! Because that refusal is what one connection can do to every other, the
//! accumulation is bounded in *time* as well as in bytes. A peer that declares a
//! body and then trickles it holds the array while it does, and the transport's
//! idle timeout cannot end that: the timer is refreshed by each arriving byte, so
//! one byte every few minutes keeps a connection alive indefinitely and the array
//! with it. [`BODY_TIMEOUT`] is the bound that closes it —
//! [`Server::expire`] answers a body that misses it `408`, gives the array back,
//! and **resets** the connection rather than closing it, a close leaving the
//! peer's half open for it to go on refreshing that same timer from.
//!
//! An operator tool killed mid-`POST` reaches this too, which is why it is not
//! only an attacker's concern: without it, the surfaces an operator would use to
//! find out what happened are the ones that stop answering.
//!
//! # Adversary
//!
//! The **management-plane attacker**, one layer above `lfw_http`.
//! That crate refuses a malformed head; this one decides what a well-formed one
//! gets, and holds the state a connection accumulates while it does. Both
//! dimensions of that state are fixed arrays: [`REQUEST_CAPACITY`] per
//! connection for the head being read, and one [`RESPONSE_CAPACITY`] buffer for
//! the one body — response or request — that may be in flight.
//!
//! This server authenticates nobody and there is no TLS below it, so **a `POST` to
//! a body-taking target is an unauthenticated write from whoever reached the
//! port.** Nothing here can close that; what it does instead is bound it — one
//! framing for a body, a length refused at the head, an accumulation the array
//! itself limits, and a decision it hands upward rather than makes.
//!
//! # One exposition at a time, and what a second connection gets
//!
//! An exposition is [`RESPONSE_CAPACITY`] bytes — about 86 KiB, most of it the
//! one series per filter rule the configuration ABI admits — and a buffer
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
//! `Content-Length`; nothing here is chunked) and taking the body at most
//! [`WINDOW_LEN`] bytes at a time ([`Server::supply_window`]). A window is not
//! simply the next bytes to send, because a range the transport re-asks for must
//! still be in the array: it begins [`RETRANSMIT_SPAN`] *behind* that byte, with
//! [`WINDOW_LEN`] twice that span to leave room in front, under a `const`
//! assertion so a wider transport window moves this in a diff.
//!
//! [`Server::window_wanted`] names both where the next bytes begin and **how
//! many** the array will take, and a supplier that hands over fewer than that
//! advances the stream rather than ending it: the next call asks for the
//! remainder at the byte after what arrived, so the window is completed in place
//! and the span behind it is never given up. A supplier reading a segmented ring
//! legitimately runs short at every segment boundary, so a short window is
//! ordinary rather than exceptional. Not holding one at all is an answer rather
//! than a stall: **nothing** goes out that pass, and [`Server::pending`] prefers
//! a connection that can send. Where a window cannot be produced at all,
//! [`Server::abandon_stream`] gives up short of the announced length — invented
//! bytes being worse than truncation — and the connection is **reset** rather
//! than closed, because a `FIN` under an exact `Content-Length` presents a
//! truncated message to an intermediary as a complete one.
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

use lfw_clock::{Duration, Monotonic};
use lfw_http::{ContentType, MAX_HEAD_LEN, MAX_REQUEST_BYTES, Parsed, Status, parse, write_head};
use lfw_tcp::{Connection, ConnectionId, MAX_UNACKED, SendError, SeqNumber, TcpStack, Timeout};

use crate::TCP_MSS;

/// Bytes of request head one connection may accumulate, which is also the
/// window it is offered. `lfw_http`'s own bound, because the two are one
/// decision: the parser's limits are stated against a head this size.
pub const REQUEST_CAPACITY: usize = MAX_REQUEST_BYTES;

/// The exposition's own target, registered by this server rather than by an
/// owner: the metric surface is what the crate above it exists to serve, and a
/// build that forgot to register it would answer an operator's scraper `404`.
pub const METRICS_TARGET: &str = "/metrics";

/// Bytes of request body this server will accumulate, and so the bound a
/// `Content-Length` is refused against with `413` before a byte is taken.
///
/// The configuration document bound: the one body this appliance accepts is a
/// configuration, and the domain that reads it refuses a longer one in any case.
/// A caller crossing a protection-domain boundary with it asserts the two agree
/// (`pd_runtime::configuration`), so a region that could not carry a body this
/// server took is a build failure rather than a submission that vanishes.
pub const MAX_BODY_LEN: usize = 64 * 1024;

/// Bytes the shared staging array holds: the longest head this server can write,
/// in front of the longest body that array ever carries — an exposition the metric
/// catalogue can produce, or a request body [`MAX_BODY_LEN`] admits.
///
/// Derived rather than chosen, which is what makes a new metric unable to
/// silently truncate an operator's scrape — a family added to `lfw_metrics`
/// moves this number and the array with it — and what makes a larger body bound
/// move it too rather than overrun the array quietly.
pub const RESPONSE_CAPACITY: usize = MAX_HEAD_LEN + longest_body();

const fn longest_body() -> usize {
    if lfw_metrics::MAX_EXPOSITION_LEN > MAX_BODY_LEN {
        lfw_metrics::MAX_EXPOSITION_LEN
    } else {
        MAX_BODY_LEN
    }
}

/// The tail a window keeps behind the byte being sent: everything the transport
/// can re-ask for and owns no copy of, so a window slid past one of those ranges
/// would refuse the retransmission and stall the transfer.
pub const RETRANSMIT_SPAN: usize = MAX_UNACKED * TCP_MSS as usize;

/// Bytes of body the sliding window holds, and so the most
/// [`Server::supply_window`] will take at once.
///
/// A supplier crossing a protection-domain boundary has a reply region of its
/// own, and the two numbers must agree: this is the smaller of the pair, so the
/// domain that fetches a window clamps its request to it under a compile-time
/// assertion of its own rather than discovering the mismatch as a download that
/// answers `200` and an empty body.
pub const WINDOW_LEN: usize = 16 * 1024;

/// The longest body this server will stream. A range is found by its offset from
/// the sequence number the first byte took and `distance_from` is modulo 2^32,
/// so past half that space two offsets look alike and a retransmission would
/// carry the wrong bytes. A longer recording is refused, never truncated.
pub const MAX_STREAM_LEN: u64 = 1 << 31;

/// Targets an owner may register as streamed: several, the management
/// surface naming several, and bounded because each is compared against every
/// request target.
pub const MAX_STREAM_TARGETS: usize = 4;

/// Targets answered on `GET` with a body the owner renders whole, [`METRICS_TARGET`]
/// among them. Bounded on [`MAX_STREAM_TARGETS`]' terms.
pub const MAX_RENDERED_TARGETS: usize = 4;

/// Targets that accept a request body on `POST`. One today — the configuration —
/// and a table rather than a constant because the routing is one comparison
/// either way and a second body-taking surface must not be a special case
/// somewhere else.
pub const MAX_BODY_TARGETS: usize = 2;

/// How long a request body may take to arrive whole before the request is
/// answered [`Status::RequestTimeout`] and the connection reset.
///
/// Deliberately not derived from anything the peer states: a span computed from a
/// declared `Content-Length` would let the peer choose how long it may hold the
/// array by declaring a larger body. Thirty seconds is the whole of
/// [`MAX_BODY_LEN`] at about 2 KiB/s — two orders below what a management link
/// carries — and a tenth of `lfw_tcp::IDLE_TIMEOUT`, so this is the deadline that
/// binds rather than a second copy of that one.
pub const BODY_TIMEOUT: Duration = Duration::from_millis(30_000);

// The bound the whole streaming design rests on, stated where both halves are
// visible: the worst-case exposition and the head in front of it fit the buffer
// they are composed into, so a scrape is never answered short. Both are
// stated as numbers, so a new family moves this reservation in a diff.
const _: () = {
    assert!(RESPONSE_CAPACITY >= MAX_HEAD_LEN + lfw_metrics::MAX_EXPOSITION_LEN);
    assert!(RESPONSE_CAPACITY >= MAX_HEAD_LEN + MAX_BODY_LEN);
    assert!(RESPONSE_CAPACITY > MAX_HEAD_LEN);

    assert!(lfw_metrics::MAX_EXPOSITION_LEN == 89_263);
    assert!(MAX_BODY_LEN == 65_536);
    assert!(RESPONSE_CAPACITY == 89_424);
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
    /// Bodies a caller's renderer would not fit. **Ours**, and unreachable while
    /// [`RESPONSE_CAPACITY`] is derived from every renderer's own bound.
    pub bodies_refused: u64,
    /// Request-body bytes a peer sent past the length it declared, dropped. The
    /// peer's, and the one dimension of a body a `Content-Length` does not bound
    /// on its own: the declared length is a claim, and what arrives is refused
    /// against it rather than believed.
    pub bodies_overrun: u64,
    /// Request bodies accumulated whole and handed to the caller.
    pub bodies_taken: u64,
    /// Request bodies given up on for taking longer than [`BODY_TIMEOUT`] to
    /// arrive, answered 408 and reset. The peer's, and every one of them is a
    /// stretch in which the other body-bearing surfaces answered 503.
    pub bodies_timed_out: u64,
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
    /// Windows offered at another `start`, carrying nothing, or longer than the
    /// length asked for: a caller and this server disagreeing about a body's
    /// place, which is **ours**. A window merely *shorter* than what was asked
    /// for is not one of these — it is taken and the remainder asked for again.
    pub windows_refused: u64,
    /// Windowed responses given up on: a supplier that cannot keep up.
    pub streams_abandoned: u64,
}

/// What a caller owes a connection whose head has been read, and so which body
/// shape was decided on.
///
/// Each carries the target it is about, because the owner of one target is not
/// the owner of another: the domain that renders an exposition and the one that
/// states a configuration are different halves of the same protection domain, and
/// each must be able to tell whether the request waiting is its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Want {
    /// A body the caller renders whole into the staging array.
    Rendered(&'static str),
    /// A decision on this target: [`Server::supply_stream`] or an abandon.
    Stream(&'static str),
    /// A request body has arrived whole in the staging array and the caller owes
    /// a decision on it: read it with [`Server::submission`], then answer with
    /// [`Server::supply`].
    Submitted(&'static str),
}

/// Where one connection's conversation has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Accumulating a request head.
    Reading,
    /// The head is read, it declared a body, and the staging array is this
    /// connection's to accumulate that body into. `received` counts body bytes and
    /// is what the advertised window is derived from, so a peer is told to send
    /// exactly what is still owed.
    ///
    /// `deadline` is when the accumulation gives up. Fixed when the phase is
    /// entered and never moved by an arriving byte: a deadline each byte refreshed
    /// would be the transport's idle timer again, which a peer sending one byte a
    /// minute already defeats.
    Receiving {
        target: &'static str,
        total: usize,
        received: usize,
        deadline: Monotonic,
    },
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

impl Phase {
    /// Whether a request head is still being accumulated, which is the one phase
    /// [`Server::decide`] parses in.
    const fn is_reading(self) -> bool {
        matches!(self, Self::Reading)
    }
}

/// What the array needs next: where in the body those bytes begin, how many it
/// will take, and how much of the window they follow.
///
/// `behind` is what distinguishes completing the window held from replacing it.
/// Zero means the window slides and the array is filled from its front; anything
/// else means the bytes land behind what is already there, which is how a short
/// supply is finished without giving up the span the transport may still re-ask
/// for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Need {
    start: u64,
    len: usize,
    behind: usize,
}

/// Where a windowed response has got to, and which slice of its body the array
/// holds. Offsets are of the *response*: what a retransmission asks by.
#[derive(Clone, Copy, Debug)]
struct Window {
    /// The body's whole length, already announced: a caller that finds it has
    /// fewer bytes abandons rather than revising it.
    total: u64,
    at: u64,
    /// Bytes of the window supplied; below [`WINDOW_LEN`] where the body ended
    /// first or a supplier ran short of it.
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

    /// The body bytes the array needs next, or `None` where the window it holds
    /// can still be sent from or the body is out.
    ///
    /// A *start*, not the byte to send: see the module header. Where the window
    /// is not yet full the need is the byte after what it holds, so a supplier
    /// that ran short completes it and the span behind the send point stays
    /// servable; where it is full and spent, the window slides and the span is
    /// re-fetched with it.
    fn wanted(&self, head: usize) -> Option<Need> {
        let body = self.sent_body(head);
        if body >= self.total {
            return None;
        }
        // Lossless: `filled` is at most `WINDOW_LEN`.
        let held_end = self.at.saturating_add(self.filled as u64);
        if body < held_end {
            return None;
        }
        let (start, behind) = if self.filled < WINDOW_LEN {
            (held_end, self.filled)
        } else {
            (body.saturating_sub(RETRANSMIT_SPAN as u64), 0)
        };
        let room = WINDOW_LEN.saturating_sub(behind);
        // Lossless: bounded by `room`, itself at most `WINDOW_LEN`.
        let len = self.total.saturating_sub(start).min(room as u64) as usize;
        (len > 0).then_some(Need { start, len, behind })
    }
}

/// Where one connection's response bytes are, and in what shape. One value
/// rather than a flag beside a cursor: the variants are exclusive by
/// construction, which makes a buffered and a windowed response owning the one
/// staging array at once unrepresentable.
#[derive(Clone, Copy, Debug)]
enum Body {
    /// A status with no body, in the slot's own [`Slot::head`].
    Own,
    /// Head and body together in the staging array, composed once.
    Staged,
    /// A head in the staging array, and a sliding window of the body behind it.
    Windowed(Window),
    /// Given up on: nothing more goes out, no range serves again, and the next
    /// drive resets the connection rather than closing it.
    Abandoned,
}

/// How this end finishes with a connection once its response is out.
///
/// A value rather than a `bool`, because the two differ in what they say to the
/// peer rather than in degree, and the difference is the whole reason the second
/// exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ending {
    /// A `FIN`: the exchange finished and the peer owes nothing more.
    Close,
    /// A `RST`: this end gave up on a message the peer is still sending. A `FIN`
    /// would leave the peer's own half open, and each byte it went on sending
    /// would refresh the transport's idle timer — holding the connection's slot
    /// for as long as the peer kept sending, which is the thing the deadline
    /// above it exists to bound.
    Reset,
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
    /// How the connection is finished with once its response is out.
    ending: Ending,
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
            ending: Ending::Close,
        }
    }

    /// The window this connection advertises: what this end can still hold of
    /// whatever it is now reading.
    ///
    /// Two answers, because a connection reads two things. While a head is being
    /// accumulated it is the room left in the slot; while a body is, it is what
    /// that body still owes — so a peer is asked for exactly the remainder and a
    /// window that stayed at the head's leftover room would stall every submission
    /// longer than a request buffer.
    const fn room(&self) -> usize {
        match self.phase {
            Phase::Receiving {
                total, received, ..
            } => total.saturating_sub(received),
            _ => REQUEST_CAPACITY.saturating_sub(self.received),
        }
    }

    /// Whether the transport has yet to be handed everything. An abandoned
    /// response owes nothing whatever it announced, which turns the next drive
    /// into the reset that says so.
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

/// What a completed head resolved to: three answers rather than a status compared
/// against `200`, which shape was claimed not being readable off that code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    Refuse(Status),
    Claim(Want),
    /// A body-taking target with a body to take: how many bytes were declared, and
    /// where in the connection's own buffer the ones already delivered begin.
    Receive {
        target: &'static str,
        total: usize,
        head_len: usize,
    },
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
    /// cannot disagree.
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
    /// The `GET` targets answered with a body the owner renders whole.
    /// [`METRICS_TARGET`] is here from the start, this crate being what serves it.
    rendered: [Option<&'static str>; MAX_RENDERED_TARGETS],
    /// The targets an owner registered as streamed: a fixed table this server
    /// only compares against, which keeps recordings and block devices out of it.
    targets: [Option<&'static str>; MAX_STREAM_TARGETS],
    /// The `POST` targets that accept a request body. A table of its own rather
    /// than a flag on the two above, because the routing key is the method and the
    /// target together: one path may be a `GET` that states something and a `POST`
    /// that changes it, and each is refused `405` under the other's method.
    bodies: [Option<&'static str>; MAX_BODY_TARGETS],
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
            rendered: {
                let mut table = [None; MAX_RENDERED_TARGETS];
                table[0] = Some(METRICS_TARGET);
                table
            },
            targets: [None; MAX_STREAM_TARGETS],
            bodies: [None; MAX_BODY_TARGETS],
            counters: HttpCounters {
                requests: 0,
                responses: [0; Status::ALL.len()],
                response_bytes: 0,
                overflowed: 0,
                bodies_refused: 0,
                bodies_overrun: 0,
                bodies_taken: 0,
                bodies_timed_out: 0,
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
    /// one stays `404`, which keeps these tables the whole of the routing. `false`
    /// for a full table or a target already answered on `GET`, either of which
    /// would put two answers on one target.
    pub fn serve_stream_at(&mut self, target: &'static str) -> bool {
        if self.answers_get(target) {
            return false;
        }
        Self::register(&mut self.targets, target)
    }

    /// Register `target` as one this server answers on `GET` with a body the
    /// caller renders whole. `false` on the same terms as
    /// [`serve_stream_at`](Self::serve_stream_at).
    pub fn serve_rendered_at(&mut self, target: &'static str) -> bool {
        if self.answers_get(target) {
            return false;
        }
        Self::register(&mut self.rendered, target)
    }

    /// Register `target` as one this server accepts a request body on. `false` for
    /// a full table or one already registered — and deliberately **not** for a
    /// target answered on `GET`: one path that states a thing and changes it is
    /// the shape this exists for, the two being told apart by method.
    pub fn serve_body_at(&mut self, target: &'static str) -> bool {
        if Self::holds(&self.bodies, target).is_some() {
            return false;
        }
        Self::register(&mut self.bodies, target)
    }

    /// Whether some `GET` answer already claims this target, which is what makes
    /// the two `GET` tables one namespace.
    fn answers_get(&self, target: &str) -> bool {
        Self::holds(&self.rendered, target).is_some()
            || Self::holds(&self.targets, target).is_some()
    }

    fn register<const N: usize>(
        table: &mut [Option<&'static str>; N],
        target: &'static str,
    ) -> bool {
        if Self::holds(table, target).is_some() {
            return false;
        }
        let Some(slot) = table.iter_mut().find(|slot| slot.is_none()) else {
            return false;
        };
        *slot = Some(target);
        true
    }

    fn holds<const N: usize>(
        table: &[Option<&'static str>; N],
        path: &str,
    ) -> Option<&'static str> {
        table
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
    pub fn take(&mut self, now: Monotonic, connection: ConnectionId, data: &[u8]) {
        let Some(index) = self.slot_for(connection) else {
            bump(&mut self.counters.slots_exhausted);
            return;
        };
        let receiving = self
            .slots
            .get(index)
            .is_some_and(|slot| matches!(slot.phase, Phase::Receiving { .. }));
        if receiving {
            self.take_body(index, data);
            return;
        }
        let overran = {
            let Some(slot) = self.slots.get_mut(index) else {
                return;
            };
            let room = REQUEST_CAPACITY.saturating_sub(slot.received);
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
            slot.phase.is_reading() && taken < data.len()
        };
        if self
            .slots
            .get(index)
            .is_none_or(|slot| !slot.phase.is_reading())
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
        self.decide(now, index, connection);
    }

    /// Take body bytes for a connection whose head declared a length, appending
    /// them into the staging array behind the room the head reservation holds.
    ///
    /// Bounded twice over and by two different things: by the declared length,
    /// which is the protocol bound and what the excess is counted against, and by
    /// the array itself, which is the memory one — `MAX_BODY_LEN` having already
    /// refused a declaration the array could not hold, so the second is
    /// unreachable and is a `zip` rather than a check.
    fn take_body(&mut self, index: usize, data: &[u8]) {
        let overrun = {
            let Some(slot) = self.slots.get_mut(index) else {
                return;
            };
            let Phase::Receiving {
                target,
                total,
                received,
                deadline,
            } = slot.phase
            else {
                return;
            };
            let taken = total.saturating_sub(received).min(data.len());
            for (cell, byte) in self
                .shared
                .bytes
                .iter_mut()
                .skip(MAX_HEAD_LEN.saturating_add(received))
                .zip(data.iter().take(taken))
            {
                *cell = *byte;
            }
            let received = received.saturating_add(taken);
            slot.phase = Phase::Receiving {
                target,
                total,
                received,
                deadline,
            };
            if received >= total {
                slot.phase = Phase::AwaitingBody(Want::Submitted(target));
                slot.len = total;
            }
            data.len().saturating_sub(taken)
        };
        if overrun > 0 {
            // A peer that sent more than it announced. Counted rather than
            // answered: the request it belongs to is complete, and the bytes past
            // it belong to no message this server will read.
            self.counters.bodies_overrun =
                self.counters.bodies_overrun.saturating_add(overrun as u64);
        }
        if self
            .slots
            .get(index)
            .is_some_and(|slot| matches!(slot.phase, Phase::AwaitingBody(Want::Submitted(_))))
        {
            bump(&mut self.counters.bodies_taken);
        }
    }

    /// Parse whatever has accumulated and answer if the head is whole.
    fn decide(&mut self, now: Monotonic, index: usize, connection: ConnectionId) {
        // Copied out before the slot is borrowed: three small tables against a
        // borrow of the whole server across the parse.
        let rendered = self.rendered;
        let streams = self.targets;
        let bodies = self.bodies;
        let decision = {
            let Some(slot) = self.slots.get(index) else {
                return;
            };
            let head = slot.request.get(..slot.received).unwrap_or_default();
            match parse(head, MAX_BODY_LEN) {
                Ok(Parsed::NeedMore) => {
                    // Not yet, and a buffer that is now full will never hold
                    // one: answered here rather than waited on.
                    if slot.room() == 0 {
                        bump(&mut self.counters.overflowed);
                        self.respond_without_body(index, Status::HeadersTooLarge);
                    }
                    return;
                }
                Ok(Parsed::Complete { request, consumed }) => {
                    bump(&mut self.counters.requests);
                    let path = path_of(request.target());
                    let claims_get = |table: &[Option<&'static str>]| -> Option<&'static str> {
                        table.iter().flatten().copied().find(|it| *it == path)
                    };
                    if request.is_get() {
                        if let Some(target) = claims_get(&rendered) {
                            Decision::Claim(Want::Rendered(target))
                        } else if let Some(target) = claims_get(&streams) {
                            Decision::Claim(Want::Stream(target))
                        } else if claims_get(&bodies).is_some() {
                            // A target that exists and takes a body rather than
                            // stating one: `405` says so, where `404` would say
                            // the resource is absent.
                            Decision::Refuse(Status::MethodNotAllowed)
                        } else {
                            Decision::Refuse(Status::NotFound)
                        }
                    } else if request.is_post() {
                        match claims_get(&bodies) {
                            Some(target) => Decision::Receive {
                                target,
                                total: request.body_len(),
                                head_len: consumed,
                            },
                            None if claims_get(&rendered).is_some()
                                || claims_get(&streams).is_some() =>
                            {
                                Decision::Refuse(Status::MethodNotAllowed)
                            }
                            None => Decision::Refuse(Status::NotFound),
                        }
                    } else {
                        Decision::Refuse(Status::MethodNotAllowed)
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
            Decision::Receive {
                target,
                total,
                head_len,
            } => self.begin_receiving(now, index, connection, target, total, head_len),
        }
    }

    /// Claim the staging array for a request body and move into it whatever of that
    /// body arrived in the same segment as the head.
    ///
    /// A `POST` with no body at all — `Content-Length: 0`, or none — is complete the
    /// moment its head is, so it goes straight to the caller's decision rather than
    /// waiting for a byte that will never come.
    fn begin_receiving(
        &mut self,
        now: Monotonic,
        index: usize,
        connection: ConnectionId,
        target: &'static str,
        total: usize,
        head_len: usize,
    ) {
        if !self.reclaim_if_finished() {
            self.respond_without_body(index, Status::ServiceUnavailable);
            return;
        }
        self.shared.owner = Some(connection);
        self.shared.start = MAX_HEAD_LEN;
        if let Some(slot) = self.slots.get_mut(index) {
            slot.phase = Phase::Receiving {
                target,
                total,
                received: 0,
                deadline: now.saturating_add(BODY_TIMEOUT),
            };
            slot.body = Body::Own;
            slot.len = 0;
            slot.sent = 0;
            slot.base = None;
        }
        // What the same segment already delivered behind the head, which for a
        // small document is the whole body.
        let delivered = {
            let Some(slot) = self.slots.get(index) else {
                return;
            };
            let end = slot.received;
            let mut carried = [0u8; REQUEST_CAPACITY];
            let mut len = 0usize;
            for (cell, byte) in carried.iter_mut().zip(
                slot.request
                    .iter()
                    .skip(head_len)
                    .take(end.saturating_sub(head_len)),
            ) {
                *cell = *byte;
                len = len.saturating_add(1);
            }
            (carried, len)
        };
        let (carried, len) = delivered;
        if len > 0 {
            self.take_body(index, carried.get(..len).unwrap_or_default());
        }
        if total == 0
            && let Some(slot) = self.slots.get_mut(index)
            && matches!(slot.phase, Phase::Receiving { .. })
        {
            slot.phase = Phase::AwaitingBody(Want::Submitted(target));
            slot.len = 0;
            bump(&mut self.counters.bodies_taken);
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

    /// The connection whose rendered body the caller owes and the target it asked
    /// for — never one waiting on a *stream* decision or on a submission, which
    /// would answer one target with another's body.
    #[must_use]
    pub fn pending_render(&self) -> Option<(ConnectionId, &'static str)> {
        self.awaiting(|want| match want {
            Want::Rendered(target) => Some(target),
            Want::Stream(_) | Want::Submitted(_) => None,
        })
    }

    /// The connection whose submitted body the caller owes a decision on, and the
    /// target it was submitted to.
    ///
    /// Read the body with [`submission`](Self::submission) and answer with
    /// [`supply`](Self::supply). Leaving one unanswered holds the staging array
    /// and refuses every scrape meanwhile, exactly as an unsupplied exposition
    /// already can.
    #[must_use]
    pub fn pending_submission(&self) -> Option<(ConnectionId, &'static str)> {
        self.awaiting(|want| match want {
            Want::Submitted(target) => Some(target),
            Want::Rendered(_) | Want::Stream(_) => None,
        })
    }

    /// The body a submission delivered, borrowed out of the staging array.
    ///
    /// The borrow is the enforcement: [`supply`](Self::supply) needs `&mut self`
    /// and writes into this same array, so a caller cannot answer while still
    /// holding the bytes it is answering about. `None` where nothing is waiting.
    #[must_use]
    pub fn submission(&self) -> Option<&[u8]> {
        let (connection, _) = self.pending_submission()?;
        let index = self.index_of(connection)?;
        let len = self.slots.get(index)?.len;
        self.shared
            .bytes
            .get(MAX_HEAD_LEN..MAX_HEAD_LEN.saturating_add(len))
    }

    fn awaiting(
        &self,
        of: impl Fn(Want) -> Option<&'static str>,
    ) -> Option<(ConnectionId, &'static str)> {
        self.slots.iter().find_map(|slot| match slot.phase {
            Phase::AwaitingBody(want) => Some((slot.connection?, of(want)?)),
            _ => None,
        })
    }

    /// The connection whose registered stream target the caller must decide on,
    /// and which it asked for. Leaving one unanswered holds the staging array and
    /// refuses every scrape meanwhile, as a caller that never supplies an
    /// exposition already can.
    #[must_use]
    pub fn pending_stream(&self) -> Option<(ConnectionId, &'static str)> {
        self.awaiting(|want| match want {
            Want::Stream(target) => Some(target),
            Want::Rendered(_) | Want::Submitted(_) => None,
        })
    }

    /// Answer the request waiting on a whole body — a rendered `GET` or a decided
    /// submission — with `status` and whatever `render` writes.
    ///
    /// `render` writes into the staging buffer and answers the body's length, or
    /// `None` where it does not fit — which is **ours** rather than the client's,
    /// [`RESPONSE_CAPACITY`] being derived from every renderer's own worst case, so
    /// a caller sized by it can never provoke one. A caller with nothing to say
    /// answers a length of zero and no content type.
    ///
    /// One call for both shapes, because both are the same act: the owner of a
    /// target puts a body in the array and this puts a head in front of it. What
    /// differs is the status and the type, and those are the parameters. For a
    /// submission the bytes written **overwrite the body that was submitted**,
    /// which is why [`submission`](Self::submission) borrows and this does not.
    pub fn supply(
        &mut self,
        status: Status,
        content_type: Option<ContentType>,
        render: impl FnOnce(&mut [u8]) -> Option<usize>,
    ) {
        let waiting = self
            .pending_render()
            .or_else(|| self.pending_submission())
            .map(|(connection, _)| connection);
        let Some(connection) = waiting else {
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
                // Lossless: a body is at most `longest_body()` bytes, which the
                // module's assertion holds inside the array.
                let len = write_head(status, content_type, body as u64, &mut head).ok()?;
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
            // request with a number attached. The buffer is released
            // here: the refusal has no body to keep it for.
            bump(&mut self.counters.bodies_refused);
            self.release_shared(index);
            self.respond_without_body(index, Status::ServiceUnavailable);
            return;
        };
        if let Some(slot) = self.slots.get_mut(index) {
            slot.phase = Phase::Responding;
            slot.body = Body::Staged;
            slot.len = len;
        }
        self.record(status);
    }

    /// Commit to answering the pending stream target with a body of `total`
    /// bytes, written into the head now as an exact `Content-Length`: a caller
    /// that cannot then produce exactly that many has no way back but
    /// [`abandon_stream`](Self::abandon_stream) — which is also what it owes the
    /// request where this answers `false`, changing nothing.
    pub fn supply_stream(&mut self, total: u64, content_type: ContentType) -> bool {
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
    /// there begins where it ends.
    ///
    /// `None` only where the length will not fit, which
    /// [`supply_stream`](Self::supply_stream) has already refused: the content
    /// type is one [`MAX_HEAD_LEN`] was derived from, so no value of it can
    /// overrun the reservation.
    fn write_stream_head(&mut self, total: u64, content_type: ContentType) -> Option<()> {
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

    /// The body byte the next window bytes begin at, how many of them the array
    /// will take, and the connection waiting on them.
    ///
    /// A window *start*, not the next byte to send (see [`Window::wanted`]). The
    /// length is the bound a supplier is held to and never a demand: fewer bytes
    /// are taken and the remainder asked for again, which is what a supplier
    /// reading a segmented medium hands over at every boundary.
    #[must_use]
    pub fn window_wanted(&self) -> Option<(ConnectionId, u64, usize)> {
        let head = self.shared.head_len();
        self.slots.iter().find_map(|slot| {
            let need = slot.window()?.wanted(head)?;
            Some((slot.connection?, need.start, need.len))
        })
    }

    /// Hand the server the window beginning at body byte `start`: the `start`
    /// [`window_wanted`](Self::window_wanted) named, and between one byte and the
    /// length it named. Anything else is refused and counted — it would put a
    /// recording's bytes where no client could tell they did not belong.
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
        let Some(need) = window.wanted(head) else {
            return false;
        };
        if start != need.start || bytes.is_empty() || bytes.len() > need.len {
            return false;
        }
        // The window begins at `MAX_HEAD_LEN` and these bytes land behind
        // whatever of it is already there. `behind + need.len` is at most
        // `WINDOW_LEN`, which the module's assertion holds to fit behind the
        // head, so the zip copies all of `bytes`. An iteration rather than a
        // slice leaves no bound to refuse at runtime.
        for (target, byte) in self
            .shared
            .bytes
            .iter_mut()
            .skip(MAX_HEAD_LEN.saturating_add(need.behind))
            .zip(bytes.iter())
        {
            *target = *byte;
        }
        if let Some(slot) = self.slots.get_mut(index)
            && let Body::Windowed(window) = &mut slot.body
        {
            // Lossless: `behind` is at most `WINDOW_LEN`.
            window.at = need.start.saturating_sub(need.behind as u64);
            window.filled = need.behind.saturating_add(bytes.len());
        }
        true
    }

    /// Give up on the windowed response, wherever it has got to. Before the head
    /// is written nothing is on the wire, so the request is answered `503`: the
    /// owner registered the target and could not produce it. After it, the
    /// connection is **reset** short of the announced length, which is the one
    /// unambiguous way to say a message is incomplete.
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

    /// Give up on any body whose deadline has passed, releasing the staging array
    /// so the surfaces that share it answer again.
    ///
    /// Answered [`Status::RequestTimeout`] out of the slot's own buffer, so the
    /// array is handed back before a byte of the answer is composed and the next
    /// request for it is served rather than refused.
    ///
    /// There is no timer to run this on: a wakeup is the only thing that happens,
    /// so a deadline is only ever *checked* on one. That is sufficient rather than
    /// a compromise — a held array denies only the requests that arrive, and each
    /// arrival is a wakeup — so what a quiet stretch delays is the reclamation of
    /// an array nothing is asking for.
    ///
    pub fn expire(&mut self, now: Monotonic) {
        let expired = (0..SLOTS).find(|index| {
            self.slots.get(*index).is_some_and(
                |slot| matches!(slot.phase, Phase::Receiving { deadline, .. } if now >= deadline),
            )
        });
        let Some(index) = expired else {
            return;
        };
        bump(&mut self.counters.bodies_timed_out);
        self.release_shared(index);
        self.respond_without_body(index, Status::RequestTimeout);
        if let Some(slot) = self.slots.get_mut(index) {
            slot.ending = Ending::Reset;
        }
    }

    /// Note that the peer has closed its half.
    ///
    /// A connection that closed before its request head ended will never send
    /// one, so this end has nothing to answer and closes too rather than holding
    /// the slot until an idle timer reaps it. A connection already being answered
    /// is unaffected: a half-close is the client saying it has finished asking,
    /// not that it has stopped listening.
    ///
    /// A slot is *taken* for a connection that never had one — one that delivered
    /// no byte at all, which is a bare `SYN` followed by a `FIN` — because it is
    /// the close this end owes that needs recording. Without it nothing ever
    /// asks the transport to close, and the connection sits in `CLOSE_WAIT`,
    /// which the transport deliberately will not evict, for the whole idle
    /// timeout: a handful of packets would then deny the port.
    pub fn note_peer_closed(&mut self, connection: ConnectionId) {
        let Some(index) = self.slot_for(connection) else {
            bump(&mut self.counters.slots_exhausted);
            return;
        };
        if let Some(slot) = self.slots.get_mut(index)
            && matches!(
                slot.phase,
                Phase::Reading | Phase::Receiving { .. } | Phase::AwaitingBody(_)
            )
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
        // A response given up on part way is short of the length its head
        // announced, so it ends with a `RST`: a `FIN` would say the message
        // ended where it ended, and every intermediary on the path would read a
        // truncated recording as a complete one.
        let slot = self.slots.get(index)?;
        let ended = match (slot.body, slot.ending) {
            (Body::Abandoned, _) | (_, Ending::Reset) => stack.abort(connection, out),
            (Body::Own | Body::Staged | Body::Windowed(_), Ending::Close) => {
                stack.close(now, connection, out)
            }
        };
        match ended {
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
                // recorded, so the miss is counted and the place kept.
                bump(&mut self.counters.window_misses);
                return None;
            }
            Chunk::Own { start, end } => self.slots.get(index)?.head.get(start..end)?,
            Chunk::Staged { start, end } => self.shared.bytes.get(start..end)?,
        };
        // The transport records the range and advances its sequence *before* it
        // composes, so a refused write leaves those bytes outstanding and asks
        // for them again on the retransmission timer. This end therefore
        // advances over exactly what it committed either way: not doing so
        // leaves a range `range` can never find, and every retransmission of it
        // counted as unavailable for the life of the connection.
        let (bytes, len) = match stack.send(now, connection, payload, out) {
            Ok(written) => (written.bytes, Some(written.len)),
            Err(SendError::Write { committed, .. }) => (committed, None),
            Err(_) => return None,
        };
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
            window.sent = window.sent.saturating_add(bytes as u64);
        } else {
            slot.sent = slot.sent.saturating_add(bytes);
        }
        self.counters.response_bytes = self.counters.response_bytes.saturating_add(bytes as u64);
        len
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

    /// Give back every slot whose connection the transport no longer holds.
    ///
    /// The transport frees a connection on its own — evicting one under table
    /// pressure, taking a reset, finishing a close — and the only thing it says
    /// about it is that the handle stops resolving. Reconciling against that
    /// covers every such release at once, including the ones a future
    /// transport adds; a notification per release would be one more thing a
    /// caller must not forget, and a slot forgotten here is a slot no
    /// connection can ever have again.
    pub fn reconcile<const CONNECTIONS: usize>(&mut self, stack: &TcpStack<CONNECTIONS>) {
        for index in 0..SLOTS {
            let held = self.slots.get(index).and_then(|slot| slot.connection);
            let Some(connection) = held else { continue };
            if stack.connection(connection).is_none() {
                self.release(connection);
            }
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
            slot.ending = Ending::Close;
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
        slot.ending = Ending::Close;
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
