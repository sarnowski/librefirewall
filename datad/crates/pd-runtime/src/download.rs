//! The management domain's side of a recording download: turning a `GET` of a
//! recording into windows of a body it reads out of the recorder, one round
//! trip at a time.
//!
//! # Adversary
//!
//! A **management-plane attacker** in front and a **byzantine
//! neighbour protection domain** behind. The attacker chooses when and how often to
//! ask; nothing here allocates, waits or retries on their account, and a pass
//! with no window yet does nothing and comes back. The recorder chooses every
//! byte of the answer: `wire::download` refuses a reply that is not this
//! request's, longer than the window, or longer than what was asked for, and
//! what survives that is a byte range handed to the transport unread. Nothing
//! in this crate parses a recording.
//!
//! # Two readers, and which of them yields
//!
//! The same channel also feeds the management channel, which ships ring bytes
//! upstream from a cursor of its own. They share one window because the recorder
//! has one staging area and one outstanding request, so the question is not how
//! to run both but which waits — and **the download wins**. It is bounded, an
//! operator is waiting on it, and the staging it pins is single-tenant; the
//! channel's cursor is unbounded and loses nothing by standing still, because
//! the position it will ask for next is the same position either way.
//!
//! The two coordinates are not interchangeable and `wire::DownloadReader` is what
//! keeps them apart: a download offset is resolved against an origin the recorder
//! recomputes at each boot, and a cursor a management server holds across one
//! could not survive that.
//!
//! # Why a body is a window and not a buffer
//!
//! A recording is megabytes and the domain that serves it has kilobytes. The
//! transport therefore asks for the range it is about to send
//! (`EndpointStage::stream_wanted`), this module asks the recorder for exactly
//! that range, and the answer is copied straight into the transport's sliding
//! window. Nothing here holds a second copy of the body, and nothing holds any
//! of it between passes.

use lfw_clock::{Duration, Monotonic};
use lfw_ip_endpoint::{ContentType, http::WINDOW_LEN};
use wire::{
    DOWNLOAD_WINDOW_LEN, DownloadFault, DownloadPoll, DownloadReader, DownloadRefusal,
    DownloadReply, DownloadRequest, DownloadRequester, DownloadSink, PendingDownload, RangeOutcome,
    RangeWant,
};

use crate::range::RANGE_ANSWER_BYTES;
use crate::{endpoint::EndpointStage, relay::SHIPPED_RING_BYTES, relay::Upstream};
use wire::Acknowledged;

// The two window lengths this module sits between, tied together where both are
// visible: the transport's sliding window is what a reply must fit into, so a
// channel that could not carry one would answer every download past the first
// window with a body the endpoint refuses — an exact `Content-Length` and no
// bytes behind it. Either constant moving apart from the other fails the build
// here rather than on an appliance.
const _: () = {
    assert!(WINDOW_LEN <= DOWNLOAD_WINDOW_LEN);
    assert!(WINDOW_LEN > 0);
    // And the channel's own, for the same reason in the other direction: a
    // shipment is asked for out of this window, so one that could not fit in it
    // would be a frame this domain asked for and could not carry.
    assert!(SHIPPED_RING_BYTES <= DOWNLOAD_WINDOW_LEN);
};

/// The streamed-response half of an HTTP endpoint, as a download needs it.
///
/// A trait rather than the concrete stage for [`crate::tap::Tap`]'s reason in
/// reverse: driving a real endpoint to the point of a pending stream is a TCP
/// handshake and a parsed request, so the interesting states — a transport that
/// asks for a range out of order, one that refuses the window it asked for, one
/// that has no stream at all — are hours of protocol away there and one call
/// away against a fake. The connection identity is deliberately absent: a
/// recording is the same bytes whoever asked, and the endpoint holds one stream
/// at a time.
pub trait Stream {
    /// The target a request is awaiting a decision on.
    fn pending_stream(&self) -> Option<&'static str>;
    /// Commit to a body of `total` bytes. `false` where the endpoint would not
    /// begin one.
    fn begin_stream(&mut self, total: u64, content_type: ContentType) -> bool;
    /// The body offset the transport is waiting for, and the most it will take
    /// there. Fewer bytes than that are accepted and the remainder asked for
    /// again.
    fn stream_wanted(&self) -> Option<(u64, usize)>;
    /// Hand over the window starting at `start`. `false` where the endpoint
    /// would not take it.
    fn supply_window(&mut self, start: u64, bytes: &[u8]) -> bool;
    /// Give up on the response in progress.
    fn abandon_stream(&mut self);
    /// Take this module's counters, so the domain's shard carries them without
    /// the protection domain having to route a second value into it.
    fn note_downloads(&mut self, counters: DownloadCounters);
}

impl Stream for EndpointStage<'_> {
    fn pending_stream(&self) -> Option<&'static str> {
        Self::pending_stream(self).map(|(_, target)| target)
    }

    fn begin_stream(&mut self, total: u64, content_type: ContentType) -> bool {
        Self::begin_stream(self, total, content_type)
    }

    fn stream_wanted(&self) -> Option<(u64, usize)> {
        Self::stream_wanted(self).map(|(_, offset, len)| (offset, len))
    }

    fn supply_window(&mut self, start: u64, bytes: &[u8]) -> bool {
        Self::supply_window(self, start, bytes)
    }

    fn abandon_stream(&mut self) {
        Self::abandon_stream(self);
    }

    fn note_downloads(&mut self, counters: DownloadCounters) {
        Self::note_downloads(self, counters);
    }
}

/// The request target of each recording, as a client asks for it.
///
/// A `&'static str` pair rather than a lookup table, because
/// `EndpointStage::serve_stream_at` takes exactly this and a target registered
/// under one name and matched under another would answer 404 to the only two
/// paths this appliance serves.
pub const LOG_TARGET: &str = "/logs.pcapng";
pub const CAPTURE_TARGET: &str = "/capture.pcapng";

/// What a recording is served as. pcapng has no registered media type, and a
/// browser that guessed at one would render an evidence artifact as text.
const CONTENT_TYPE: ContentType = ContentType::OctetStream;

/// Saturating, monotone counts for the operator-facing metrics contract.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DownloadCounters {
    /// Streams begun — one per `GET` of a recording that the recorder answered.
    pub started: u64,
    /// Windows handed to the transport.
    pub windows: u64,
    /// Body bytes those windows carried.
    pub bytes: u64,
    /// Streams given up on, by whatever ended them: a refusal, a reply that
    /// could not be believed, or a transport that would not take the window.
    pub abandoned: u64,
}

/// Which recording a target names, or `None` for a target that is not one.
#[must_use]
pub fn sink_for(target: &str) -> Option<DownloadSink> {
    match target {
        LOG_TARGET => Some(DownloadSink::Log),
        CAPTURE_TARGET => Some(DownloadSink::Capture),
        _ => None,
    }
}

/// How long the recorder may take to answer one window before the download is
/// given up on.
///
/// The same shape of bound the configuration exchange carries: a response committed
/// to by length holds the endpoint's staging array until it completes, and the slot
/// for an outstanding request here is single.
///
/// Ten seconds rather than the configuration's five, because the work behind it is
/// a block device rather than a table build: a window is a read of up to
/// [`WINDOW_LEN`] bytes off storage that may be retrying.
const REPLY_TIMEOUT: Duration = Duration::from_millis(10_000);

/// The recordings, in the order this module indexes its per-ring state by.
const RINGS: [DownloadSink; 2] = [DownloadSink::Log, DownloadSink::Capture];

/// Which slot of that state a recording is.
const fn ring_index(recording: DownloadSink) -> usize {
    match recording {
        DownloadSink::Log => 0,
        DownloadSink::Capture => 1,
    }
}

/// How long a ring whose cursor has caught up is left alone before it is asked
/// again.
///
/// The channel's contract is that unsent ring bytes go up at least once a
/// second, so a cursor with nothing to send need be asked no more often than
/// that — and a caught-up reader that asked on every wakeup would be a round
/// trip to the recorder for an empty answer at whatever rate the management
/// port happens to be woken.
const RING_HOLDOFF: Duration = Duration::from_millis(1_000);

/// How often where the channel stands reaches the console while it is moving.
///
/// The channel's own batching period, so a healthy appliance leaves one line a
/// batch and an operator reading two consecutive lines is reading two batches.
/// Shorter would be a line per shipment, which under load is a line per wakeup;
/// longer would leave a reader unable to tell a channel that is working from one
/// that has stopped, which is the whole reason the record exists.
const SHIPPING_REPORT_PERIOD: Duration = Duration::from_millis(1_000);

/// How long durable bytes may stand behind a cursor that is not moving, on a
/// session that could carry them, before the appliance says so.
///
/// Ten batching periods: long enough that a slow round trip, a full wire or a
/// recorder busy with an operator's download is not reported as a fault, and
/// short enough that an appliance which has stopped shipping says so while the
/// session it stopped on is still open. A constant of this file, so no peer can
/// lengthen the silence.
const SHIPPING_STALL_WINDOW: Duration = Duration::from_millis(10_000);

/// Reports the reader has for the console and the domain has not taken.
///
/// Seven, and total by construction: one pass claims at most one answer, so it
/// raises at most one resynchronisation **or** one range-read report — the two
/// come off the same claim and never both — and beside that it raises at most one
/// line about where the channel stands, one stall per recording, and — on the
/// single pass that agrees a greeting — one clamped resume point per recording.
/// The seventh slot is the range report's, counted separately rather than shared
/// with the resynchronisation's so the sum stays a sum of the shapes a pass can
/// have rather than of the ones it happens to. The domain drains the queue on
/// every pass, so nothing accumulates in it.
const SHIPPING_REPORTS: usize = 7;

/// One recording's place in the channel, as a report carries it.
///
/// The pair rather than the position alone: a position says how far this
/// appliance has got, and only what is behind it says whether that is keeping up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Place {
    /// Where the cursor stands, in the ring's own append space — the coordinate
    /// the server's own resume cursors are in.
    pub position: u64,
    /// Durable bytes behind it, which this appliance still owes the server.
    pub pending: u64,
}

/// What the reader has to say about the recordings it ships and the extents it
/// reads.
///
/// One variant per thing an operator does something different about: a channel
/// working; history this appliance can no longer ship, and so a gap in what the
/// server will hold; a node that has records to send and is not sending them; and
/// the three ways a read for a range answer does not produce the extent asked for.
///
/// The last three exist because the wire cannot carry the cause: a range answer
/// has three statuses and the recorder has six refusals, so the mapping is lossy
/// by construction and the console is where the cause that was lost is put.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shipped {
    /// Where both recordings stand. Both in one report rather than one each,
    /// because the question an operator asks is about the channel, and a
    /// recording that never moves is read off the line that carries the other.
    Shipping { log: Place, capture: Place },
    /// The ring had overwritten the position the cursor stood at, and the reader
    /// carried on from the oldest byte still on the medium. The two positions are
    /// what say how much history went with it.
    Resynchronised {
        recording: DownloadSink,
        lost_from: u64,
        resumed_at: u64,
    },
    /// Durable bytes have stood behind the cursor for [`SHIPPING_STALL_WINDOW`]
    /// with a session up to carry them, and the cursor has not moved.
    Stalled {
        recording: DownloadSink,
        place: Place,
    },
    /// A session opened naming a resume point past the durable end of the
    /// recording, and the reader started from that end instead. Not a
    /// resynchronisation: that is history lost, this is bytes nothing wrote.
    ResumeClamped {
        recording: DownloadSink,
        claimed: u64,
        durable: u64,
    },
    /// The recorder refused a read for a range answer, saying why, at this
    /// position. Carried whole rather than mapped: which recording it was is in
    /// the answer's own ring byte, while the cause is only here.
    RangeRefused {
        reason: DownloadRefusal,
        offset: u64,
    },
    /// The recorder answered with a reply this reader could not believe. Its own
    /// line: an operator reading a fault as a refusal would go looking at the
    /// medium instead of at the domain in front of it.
    RangeFaulted { offset: u64 },
    /// The recorder did not answer a read for a range answer inside
    /// [`REPLY_TIMEOUT`]. Distinct from a refusal for the same reason: a recorder
    /// that said nothing and one that said no are different faults.
    RangeUnanswered { offset: u64 },
}

/// The range-answer status a recorder's refusal amounts to.
///
/// **Lossy on purpose, and the loss is recorded elsewhere.** The wire has an
/// overrun and a medium refusal and nothing else, so the four that are neither
/// take the honest catch-all rather than a status invented here — each reaching
/// the console under its own name on the line beside this mapping.
const fn range_outcome(reason: DownloadRefusal) -> RangeOutcome {
    match reason {
        // The ring rolled past the extent. The one refusal the wire has a word of
        // its own for, and the one an operator acts on differently: those bytes
        // are gone rather than momentarily unavailable.
        DownloadRefusal::Overrun => RangeOutcome::Overwritten,
        DownloadRefusal::DeviceError
        | DownloadRefusal::NotReady
        | DownloadRefusal::OutOfRange
        | DownloadRefusal::NoSuchSink
        | DownloadRefusal::NoSuchReader => RangeOutcome::MediumRefused,
    }
}

/// A request out to the recorder, and what its answer is for.
struct Outstanding {
    pending: PendingDownload,
    /// Which reader asked, so the answer is read in the coordinate it was asked
    /// in and handed to the half that wanted it.
    reader: DownloadReader,
    /// For a ring request, which recording — the reader's own state is per
    /// recording, and the demand is the only thing that says which.
    recording: DownloadSink,
    offset: u64,
    /// True for the offset-zero request that opens a response: its answer
    /// carries the length the response commits to, so it is the only one that
    /// may begin the stream.
    opening: bool,
    /// What this read is for. Both readers of a ring ask in the same coordinate,
    /// so the coordinate cannot say which of them asked — and answering a range
    /// request into the shipment buffer would put an operator's extent on the wire
    /// under a shipping cursor.
    purpose: Fetching,
    /// When this request is given up on, or `None` on a node whose clock has not
    /// been published yet — a state no client can reach, the endpoint refusing
    /// every TCP segment until a calibration has arrived, and carried rather than
    /// asserted away.
    deadline: Option<Monotonic>,
}

/// Which of the reader's three jobs one outstanding read belongs to.
///
/// A value rather than a flag beside the coordinate, because the coordinate is
/// already taken: an operator's download reads a snapshot, and both the shipping
/// cursor and a range answer read the ring's own append space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fetching {
    /// An operator's `GET`, in snapshot coordinates.
    Snapshot,
    /// The shipping cursor, whose answer moves that cursor.
    Ship,
    /// One frame of a range answer, whose answer moves no cursor at all.
    Range,
}

/// One frame of a range answer, waiting for the relay's next free item.
///
/// The shipment's shape for the other direction, with the outcome in place of the
/// recording: the ring a range answer names is the asking end's, so this side
/// never states one.
#[derive(Clone, Copy)]
struct RangeFrame {
    outcome: RangeOutcome,
    position: u64,
    len: usize,
}

/// The download half of the management endpoint.
pub struct Downloads<'chan> {
    requester: DownloadRequester<'chan>,
    outstanding: Option<Outstanding>,
    /// The recording the stream in progress is being read out of. Held because
    /// `EndpointStage::stream_wanted` answers an offset and not a target: the
    /// target was decided when the stream began.
    serving: Option<DownloadSink>,
    /// The window a reply is copied into before the transport takes it. A field
    /// rather than a local because it is the channel's whole window and a
    /// protection domain's stack is not where that belongs. Sized by the channel
    /// rather than by the transport's window, because `DownloadRequester::poll`
    /// copies into the whole of it.
    window: [u8; DOWNLOAD_WINDOW_LEN],
    /// The ring bytes read for the channel and not yet shipped.
    ///
    /// A buffer of its own rather than a claim on [`Self::window`], because the
    /// download wins: an operator's `GET` may arrive at any moment and would
    /// otherwise overwrite a shipment mid-flight, which is the one way the two
    /// readers could corrupt each other rather than merely wait for each other.
    shipment: [u8; SHIPPED_RING_BYTES],
    /// How much of it is a shipment, and where in its ring it came from.
    held: Option<Shipment>,
    /// Each recording's place in the channel, in [`RINGS`] order.
    rings: [RingCursor; 2],
    /// When the last line about where the channel stands went out, which is what
    /// holds the channel to one per [`SHIPPING_REPORT_PERIOD`].
    reported_at: Option<Monotonic>,
    /// What the domain has not taken yet.
    reports: [Option<Shipped>; SHIPPING_REPORTS],
    /// The extent a range answer still owes, as the composing domain last stated
    /// it. **Told and never remembered across it**: that domain holds the answer's
    /// state and shrinks this as frames go, so what stands here is always the
    /// remainder rather than a copy this reader keeps in step.
    range: Option<RangeWant>,
    /// The extent bytes read for a range answer and not yet sent. Its own buffer
    /// for the reason the shipment has one: the other two readers take the shared
    /// window whenever they want it.
    answer: [u8; RANGE_ANSWER_BYTES],
    /// How much of it is a frame, and how that read went.
    held_range: Option<RangeFrame>,
    /// Which medium turn is next, so no one of the three starves the others.
    next: usize,
    counters: DownloadCounters,
}

/// Turns the medium is shared out in: one per ring, and one for a range answer.
///
/// **This is where shipping and range answers are made fair to each other.** The
/// relay puts a shipment in hand ahead of an answer frame in hand, which settles
/// only which of two composed frames goes first; what decides how much of the
/// medium each gets is this rotation. Two of every three reads are a ring's, so an
/// answer advances by a frame every third read — neither a peer starving the
/// channel's own purpose, nor the traffic starving an operator's request.
const MEDIUM_TURNS: usize = RINGS.len() + 1;

/// The turn a range answer takes, after the rings.
const RANGE_TURN: usize = RINGS.len();

const _: () = {
    assert!(MEDIUM_TURNS == 3);
    assert!(RANGE_TURN < MEDIUM_TURNS);
    // One answer frame is read in one request, so the window the channel offers
    // must hold a whole one.
    assert!(RANGE_ANSWER_BYTES <= DOWNLOAD_WINDOW_LEN);
};

/// One recording's place in the channel, as the reader keeps it.
///
/// One value rather than a field per array, because every number in it is read
/// against the others: a position without the durable end beside it cannot say
/// whether anything is waiting, and neither can say whether the channel is
/// moving without the instants that bound the two questions.
#[derive(Clone, Copy)]
struct RingCursor {
    /// Where the cursor stands. It starts at the beginning of the ring and moves
    /// only on a shipment the far end answered, so nothing this domain forgets
    /// can skip a byte.
    ///
    /// Zero is where it *starts* and not where every ring *begins*: a recorder
    /// that resumed a medium serves nothing before the segment this boot opened.
    /// The recorder answers its own first position on every reply and the reader
    /// takes it, which is the whole of how a cursor and a ring that disagree are
    /// brought back together — and the reason a cursor is never simply given up
    /// on.
    position: u64,
    /// One past the last durable byte, as of this ring's last answer. What the
    /// cursor is behind, and so the only thing this domain can say about whether
    /// it has anything to ship.
    durable: u64,
    /// Whether the recorder has answered this ring at all. Until it has, a
    /// durable end of zero is *unknown* rather than *nothing behind the cursor*,
    /// and reporting the second would put a caught-up channel on the console
    /// before a byte of either recording had been asked for.
    answered: bool,
    /// When this ring may be asked again after an answer that carried nothing.
    holdoff: Option<Monotonic>,
    /// The position last reported, so a line is owed only where one has moved.
    reported: u64,
    /// The position as of the last pass, so a move is noticed where the clock is
    /// read: the cursor moves on a relay answer, which carries no instant.
    seen: u64,
    /// When the cursor last moved on a session that could carry it, or `None`
    /// while there is no such session. The instant [`SHIPPING_STALL_WINDOW`] is
    /// measured from.
    moving_since: Option<Monotonic>,
    /// Whether a stall has already been reported, so it is said once and
    /// re-armed only by the cursor moving.
    stalled: bool,
    /// How far the management server says it has durably taken this recording.
    ///
    /// **Never moved backward**: this becomes a reader cursor on the medium, so
    /// a peer that could walk it back could make a reboot re-ship history the
    /// server already holds. Distinct from [`Self::position`], which is where
    /// the *reader* stands — the two disagreeing is the ordinary state of a
    /// channel with bytes in flight.
    acked: u64,
}

impl RingCursor {
    const fn new() -> Self {
        Self {
            position: 0,
            durable: 0,
            answered: false,
            holdoff: None,
            reported: 0,
            seen: 0,
            moving_since: None,
            stalled: false,
            acked: 0,
        }
    }

    /// Durable bytes behind the cursor: what this recording still owes the
    /// server.
    const fn pending(&self) -> u64 {
        self.durable.saturating_sub(self.position)
    }
}

/// Ring bytes waiting for the relay's next free item.
#[derive(Clone, Copy)]
struct Shipment {
    recording: DownloadSink,
    position: u64,
    len: usize,
}

impl<'chan> Downloads<'chan> {
    /// Take the asking side of the channel — once per domain; a second would
    /// restart at sequence zero and reuse numbers the first has outstanding
    /// (`wire::DownloadRequest::requester`).
    #[must_use]
    pub const fn attach(request: &'chan DownloadRequest, reply: &'chan DownloadReply) -> Self {
        Self {
            requester: request.requester(reply),
            outstanding: None,
            serving: None,
            window: [0; DOWNLOAD_WINDOW_LEN],
            shipment: [0; SHIPPED_RING_BYTES],
            held: None,
            rings: [RingCursor::new(), RingCursor::new()],
            reported_at: None,
            reports: [None; SHIPPING_REPORTS],
            range: None,
            answer: [0; RANGE_ANSWER_BYTES],
            held_range: None,
            next: 0,
            counters: DownloadCounters {
                started: 0,
                windows: 0,
                bytes: 0,
                abandoned: 0,
            },
        }
    }

    /// Register both recordings as streamed targets, so a `GET` of either is a
    /// body this domain produces rather than a 404.
    ///
    /// Answers whether both were taken; a `false` means the endpoint's target
    /// table is full, which is a build fact rather than a run-time condition.
    pub fn register(&self, stage: &mut EndpointStage<'_>) -> bool {
        stage.serve_stream_at(LOG_TARGET) && stage.serve_stream_at(CAPTURE_TARGET)
    }

    #[must_use]
    pub const fn counters(&self) -> DownloadCounters {
        self.counters
    }

    /// One bounded pass: claim a reply if one has arrived, and ask for the next
    /// window if the transport is waiting on one.
    ///
    /// Never blocks and never spins. A pass with nothing to do returns having
    /// done nothing, which is the whole of the contract with the event loop:
    /// the recorder notifies this domain when a reply lands.
    /// One bounded pass, `shipping` saying whether there is a channel to ship
    /// ring bytes up.
    ///
    /// A parameter and not a thing this module works out, for the reason the
    /// relay's own half is told rather than deduced: only the domain holding the
    /// relay knows whether the session up now is the dialled one and whether its
    /// greeting has been agreed, and a reader that guessed would read the medium
    /// on behalf of a channel that is not there.
    pub fn poll(&mut self, now: Option<Monotonic>, stage: &mut impl Stream, shipping: bool) {
        if !shipping {
            // No session to carry an answer, so nothing is owed one. Cleared here
            // rather than waited for: a want is retired by the next relay answer,
            // and a session that has gone will not produce one — which would
            // leave this reader spending medium turns on an extent nobody is
            // waiting for.
            self.range = None;
            self.held_range = None;
        }
        self.claim(now, stage);
        self.ask(now, stage, shipping);
        self.judge(now, shipping);
        stage.note_downloads(self.counters);
    }

    /// What the reader has to say about the recordings it ships, one at a time.
    ///
    /// Taken by the domain rather than counted here, because what an operator
    /// needs is the console: a recording whose place in the channel is moving is
    /// the only evidence a node without a shell gives that it is shipping at all,
    /// and one that has stopped moving with bytes behind it is the fault this
    /// surface exists for.
    pub fn take_shipped(&mut self) -> Option<Shipped> {
        let at = self.reports.iter().position(Option::is_some)?;
        self.reports.get_mut(at)?.take()
    }

    /// Put one report in the first free slot, or drop it.
    ///
    /// Dropped rather than panicking, no fault being admissible on a path a peer
    /// paces — and unreachable while the domain drains the queue every pass, the
    /// bound being what one pass can raise ([`SHIPPING_REPORTS`]).
    fn report(&mut self, shipped: Shipped) {
        if let Some(slot) = self.reports.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(shipped);
        }
    }

    /// Say where the channel stands, and whether either recording is stuck.
    ///
    /// Both halves are read off the two numbers this domain holds per recording
    /// — where the cursor stands and where the recorder said the durable bytes
    /// end — so nothing here asks the recorder anything, and nothing a peer sends
    /// can change how often it speaks.
    ///
    /// The stall clock runs only while a session is up to carry the bytes: an
    /// appliance whose channel is down has a channel to report and not a reader
    /// to, and the window would otherwise arm on every dial that never came up.
    fn judge(&mut self, now: Option<Monotonic>, shipping: bool) {
        let mut stalled = [false; RINGS.len()];
        let mut moved = false;
        for (at, ring) in self.rings.iter_mut().enumerate() {
            if ring.position != ring.seen {
                ring.seen = ring.position;
                ring.moving_since = now;
                ring.stalled = false;
            }
            moved |= ring.position != ring.reported;
            if !shipping {
                // Nothing to be stuck on. The window restarts when a session
                // comes up rather than carrying a quiet node's silence into it.
                ring.moving_since = None;
                continue;
            }
            let overdue = match (now, ring.moving_since) {
                (Some(now), Some(since)) => now >= since.saturating_add(SHIPPING_STALL_WINDOW),
                // Nothing has been observed to move on this session yet, so the
                // window starts here rather than at an instant nobody read.
                (Some(now), None) => {
                    ring.moving_since = Some(now);
                    false
                }
                // A pass with no reading of the clock judges no deadline, which
                // is the direction that cannot report a healthy node as stuck.
                (None, _) => false,
            };
            if ring.pending() > 0 && overdue && !ring.stalled {
                ring.stalled = true;
                if let Some(slot) = stalled.get_mut(at) {
                    *slot = true;
                }
            }
        }
        // And only once every recording has been asked at least once: a line
        // written before that would state a backlog of zero for a ring whose end
        // nobody has said yet, which reads as caught up.
        let known = self.rings.iter().all(|ring| ring.answered);
        if moved && known && due(now, self.reported_at) {
            self.reported_at = now;
            let [log, capture] = self.places();
            for ring in &mut self.rings {
                ring.reported = ring.position;
            }
            self.report(Shipped::Shipping { log, capture });
        }
        for at in 0..RINGS.len() {
            if !stalled.get(at).copied().unwrap_or(false) {
                continue;
            }
            let (Some(recording), Some(place)) =
                (RINGS.get(at).copied(), self.places().get(at).copied())
            else {
                continue;
            };
            self.report(Shipped::Stalled { recording, place });
        }
    }

    /// What this reader has taken delivery of, as the recorder is told it.
    /// Composed from the per-recording cursors rather than kept beside them, so
    /// each number has one home.
    fn acknowledgement(&self) -> Acknowledged {
        let mut acked = Acknowledged::NONE;
        for (at, recording) in RINGS.iter().enumerate() {
            let Some(ring) = self.rings.get(at) else {
                continue;
            };
            match recording {
                DownloadSink::Log => acked.log = ring.acked,
                DownloadSink::Capture => acked.capture = ring.acked,
            }
        }
        acked
    }

    /// Both recordings' places, in [`RINGS`] order.
    fn places(&self) -> [Place; RINGS.len()] {
        let mut places = [Place {
            position: 0,
            pending: 0,
        }; RINGS.len()];
        for (slot, ring) in places.iter_mut().zip(&self.rings) {
            *slot = Place {
                position: ring.position,
                pending: ring.pending(),
            };
        }
        places
    }

    /// Look once for the answer to the outstanding request, giving up on one that
    /// has outlived [`REPLY_TIMEOUT`].
    fn claim(&mut self, now: Option<Monotonic>, stage: &mut impl Stream) {
        let Some(Outstanding {
            pending,
            reader,
            recording,
            offset,
            opening,
            purpose,
            deadline,
        }) = self.outstanding.take()
        else {
            return;
        };
        match purpose {
            Fetching::Ship => {
                self.claim_ring(now, pending, recording, offset, deadline);
                return;
            }
            Fetching::Range => {
                self.claim_range(now, pending, recording, offset, deadline);
                return;
            }
            Fetching::Snapshot => {}
        }
        match self.requester.poll(pending, &mut self.window) {
            DownloadPoll::Outstanding(pending) => {
                if expired(now, deadline) {
                    // Given up on exactly as a refusal is: the handle is dropped
                    // rather than re-parked, which frees this module's one slot,
                    // and a reply landing afterwards answers a sequence no request
                    // is held against — which `DownloadRequester::poll` reads as no
                    // answer at all. A client sees a truncated body rather than a
                    // stalled one.
                    self.abandon(stage);
                    return;
                }
                self.outstanding = Some(Outstanding {
                    pending,
                    reader,
                    recording,
                    offset,
                    opening,
                    purpose,
                    deadline,
                });
            }
            DownloadPoll::Delivered {
                bytes, total_len, ..
            } => {
                // The length is committed to before a byte of body is offered,
                // so a response that could not state its own length is never
                // begun rather than begun and truncated.
                if opening && !stage.begin_stream(total_len, CONTENT_TYPE) {
                    self.abandon(stage);
                    return;
                }
                if opening {
                    self.counters.started = self.counters.started.saturating_add(1);
                }
                if bytes.is_empty() {
                    // The end of the body. `supply_window` of nothing would
                    // tell the transport nothing, and the stream completes on
                    // the length it was begun with.
                    return;
                }
                if stage.supply_window(offset, bytes) {
                    self.counters.windows = self.counters.windows.saturating_add(1);
                    self.counters.bytes = self.counters.bytes.saturating_add(bytes.len() as u64);
                } else {
                    // The transport asked for a range and would not take it:
                    // the two have come apart, and a stream that cannot be
                    // completed is given up rather than left half-sent.
                    self.abandon(stage);
                }
            }
            // Every one of these ends the response. `Overrun` is a reader the
            // traffic outran, `DeviceError` a medium that refused, and the
            // others a recorder that has nothing to serve — none is a state a
            // retry improves, and a client sees a truncated body rather than a
            // wrong one.
            DownloadPoll::Refused { reason, .. } => {
                let _: DownloadRefusal = reason;
                self.abandon(stage);
            }
            DownloadPoll::Faulted(fault) => {
                let _: DownloadFault = fault;
                self.abandon(stage);
            }
        }
    }

    /// Claim the answer to a ring request, and hold whatever it brought.
    ///
    /// A refusal, a fault and a deadline all leave the cursor where it was: each
    /// is an answer this reader can come back from by asking for the same
    /// position again. An **overrun** is the one that cannot — those bytes are
    /// gone — and it is not the end of the recording either: the reply says
    /// where the medium now begins, and the reader carries on from there and
    /// says what it skipped. A cursor abandoned instead would be an appliance
    /// that stops shipping a recording for the rest of its boot, which is a
    /// silence no operator can act on and no reconnection clears.
    fn claim_ring(
        &mut self,
        now: Option<Monotonic>,
        pending: PendingDownload,
        recording: DownloadSink,
        offset: u64,
        deadline: Option<Monotonic>,
    ) {
        let at = ring_index(recording);
        match self.requester.poll(pending, &mut self.window) {
            DownloadPoll::Outstanding(pending) => {
                if expired(now, deadline) {
                    return;
                }
                self.outstanding = Some(Outstanding {
                    pending,
                    reader: DownloadReader::Ring,
                    recording,
                    offset,
                    opening: false,
                    purpose: Fetching::Ship,
                    deadline,
                });
            }
            DownloadPoll::Delivered {
                bytes, total_len, ..
            } => {
                // The durable end is taken after the window has been read and
                // not before it: `bytes` borrows the very field a store through
                // `self` would touch, so the two are ordered rather than nested.
                if bytes.is_empty() {
                    self.note_durable(at, total_len);
                    // Caught up with what the medium has taken. Left alone until
                    // the hold-off is out rather than asked again on the next
                    // wakeup, which would be a round trip per wakeup for an
                    // answer that is empty by construction.
                    self.hold_off(at, now);
                    return;
                }
                // Copied out of the shared window, which the other reader may
                // overwrite at any moment: an operator's download takes this
                // channel whenever it wants it, and a shipment left pointing
                // into the window would be that download's bytes shipped under
                // a ring position.
                let mut taken = 0_usize;
                for (slot, byte) in self.shipment.iter_mut().zip(bytes) {
                    *slot = *byte;
                    taken = taken.saturating_add(1);
                }
                self.held = Some(Shipment {
                    recording,
                    position: offset,
                    len: taken,
                });
                self.note_durable(at, total_len);
            }
            DownloadPoll::Refused {
                reason,
                total_len,
                first,
            } => {
                self.note_durable(at, total_len);
                if matches!(reason, DownloadRefusal::Overrun) {
                    self.resynchronise(at, recording, offset, first);
                }
                // Every refusal, the overrun included: a recorder answering the
                // same refusal is asked again at this domain's own rate rather
                // than at whatever rate the management port is woken.
                self.hold_off(at, now);
            }
            DownloadPoll::Faulted(fault) => {
                let _: DownloadFault = fault;
                self.hold_off(at, now);
            }
        }
    }

    /// Take the recorder's word for where this ring's durable bytes end.
    ///
    /// Kept at the larger rather than believed outright: the end of a recording
    /// only grows, so a smaller number is a recorder contradicting itself — and
    /// one that could walk this backwards could hide a backlog from the stall
    /// window below.
    fn note_durable(&mut self, at: usize, total_len: u64) {
        if let Some(ring) = self.rings.get_mut(at) {
            ring.durable = ring.durable.max(total_len);
            ring.answered = true;
        }
    }

    /// Leave this ring alone for [`RING_HOLDOFF`].
    fn hold_off(&mut self, at: usize, now: Option<Monotonic>) {
        if let Some(ring) = self.rings.get_mut(at) {
            ring.holdoff = now.map(|now| now.saturating_add(RING_HOLDOFF));
        }
    }

    /// Move a cursor the ring has outrun to the oldest byte still on the medium.
    ///
    /// **Only ever forward.** The position comes from the recorder, which is a
    /// byzantine neighbour: one that answered a smaller number would have this
    /// reader ship the same bytes again forever, so a resume point that is not
    /// past the position just refused moves nothing at all. The ring then stays
    /// where it is, and the stall window is what says so.
    fn resynchronise(&mut self, at: usize, recording: DownloadSink, offset: u64, first: u64) {
        if first <= offset {
            return;
        }
        if let Some(ring) = self.rings.get_mut(at) {
            ring.position = first;
        }
        self.report(Shipped::Resynchronised {
            recording,
            lost_from: offset,
            resumed_at: first,
        });
    }

    /// Ask for whatever the transport is waiting on, if nothing is out.
    fn ask(&mut self, now: Option<Monotonic>, stage: &mut impl Stream, shipping: bool) {
        if self.outstanding.is_some() {
            return;
        }
        if let Some(target) = stage.pending_stream() {
            let Some(sink) = sink_for(target) else {
                // A target registered as streamed that this module has no
                // recording for: a build inconsistency, answered rather than
                // left hanging.
                self.abandon(stage);
                return;
            };
            self.serving = Some(sink);
            // The opening request is made before the endpoint has committed to
            // anything, so there is no window to ask against yet: a whole one,
            // which is the most the endpoint will ever take.
            self.request(now, sink, 0, WINDOW_LEN, true);
            return;
        }
        let Some((offset, len)) = stage.stream_wanted() else {
            // Nothing an operator is waiting for, so the channel may have the
            // window. This is the whole of the fairness between an operator
            // physically downloading a recording and everything the channel does:
            // a download in progress is asked for above and returns, and the
            // medium's own rotation is only ever reached on a pass where none is.
            self.ask_medium(now, shipping);
            return;
        };
        let Some(sink) = self.serving else {
            // A window wanted for a stream this module did not begin. Nothing
            // can serve it, so the response is ended rather than stalled.
            self.abandon(stage);
            return;
        };
        self.request(now, sink, offset, len, false);
    }

    /// Ask for at most `len` bytes at `offset`.
    ///
    /// `len` is what the endpoint said it would take, clamped to what the
    /// channel can carry. Asking for more than the endpoint's own window would
    /// have the reply refused and the download abandoned; asking for more than
    /// the channel's is clamped by the requester in any case, and the assertion
    /// at the top of this module keeps the two from drifting apart silently.
    fn request(
        &mut self,
        now: Option<Monotonic>,
        sink: DownloadSink,
        offset: u64,
        len: usize,
        opening: bool,
    ) {
        let pending = self.requester.request(
            DownloadReader::Snapshot,
            sink,
            offset,
            len.min(DOWNLOAD_WINDOW_LEN),
        );
        self.outstanding = Some(Outstanding {
            pending,
            reader: DownloadReader::Snapshot,
            recording: sink,
            offset,
            opening,
            purpose: Fetching::Snapshot,
            deadline: now.map(|now| now.saturating_add(REPLY_TIMEOUT)),
        });
    }

    /// Share the medium out between the two rings and one range answer, one read
    /// per pass and each participant taken in turn.
    ///
    /// **The rotation is the fairness.** A ring the traffic keeps busy cannot hold
    /// the window against the other ring, and neither can hold it against an
    /// answer an operator is waiting for; equally, a peer asking for extent after
    /// extent takes one read in three and never the channel's own purpose. A
    /// participant with nothing to do is stepped over rather than costing its
    /// turn, so an idle range answer does not slow shipping down at all.
    fn ask_medium(&mut self, now: Option<Monotonic>, shipping: bool) {
        if !shipping {
            return;
        }
        for step in 0..MEDIUM_TURNS {
            let at = self.next.saturating_add(step) % MEDIUM_TURNS;
            if at == RANGE_TURN {
                if self.ask_range(now) {
                    self.next = at.saturating_add(1) % MEDIUM_TURNS;
                    return;
                }
                continue;
            }
            if self.held.is_some() {
                continue;
            }
            let Some(recording) = RINGS.get(at) else {
                continue;
            };
            let Some(ring) = self.rings.get(at) else {
                continue;
            };
            if held_off(now, ring.holdoff) {
                continue;
            }
            let offset = ring.position;
            let pending = self.requester.request(
                DownloadReader::Ring,
                *recording,
                offset,
                SHIPPED_RING_BYTES,
            );
            self.outstanding = Some(Outstanding {
                pending,
                reader: DownloadReader::Ring,
                recording: *recording,
                offset,
                opening: false,
                purpose: Fetching::Ship,
                deadline: now.map(|now| now.saturating_add(REPLY_TIMEOUT)),
            });
            self.next = at.saturating_add(1) % MEDIUM_TURNS;
            return;
        }
    }

    /// Ask for the next frame's worth of the extent a range answer owes.
    ///
    /// Answers whether a read was issued. Nothing is asked while a frame is held —
    /// there is one answer buffer — and the length is cut to what one frame
    /// carries, a constant of this crate and not the number on the wire.
    fn ask_range(&mut self, now: Option<Monotonic>) -> bool {
        if self.held_range.is_some() {
            return false;
        }
        let Some(want) = self.range else {
            return false;
        };
        // Both bounds in one step, and both this crate's: one frame's room, and
        // what is actually still owed. The peer's own length reached the composing
        // domain's bound before it ever became a want.
        let len = usize::try_from(want.length)
            .unwrap_or(RANGE_ANSWER_BYTES)
            .min(RANGE_ANSWER_BYTES);
        if len == 0 {
            return false;
        }
        let pending = self
            .requester
            .request(DownloadReader::Ring, want.recording, want.start, len);
        self.outstanding = Some(Outstanding {
            pending,
            reader: DownloadReader::Ring,
            recording: want.recording,
            offset: want.start,
            opening: false,
            purpose: Fetching::Range,
            deadline: now.map(|now| now.saturating_add(REPLY_TIMEOUT)),
        });
        true
    }

    /// Claim the answer to a range read and hold the one frame it produced.
    ///
    /// **Every path produces a frame**, which is what keeps a requester from
    /// waiting forever. None of them touches a shipping cursor or a ring's durable
    /// end: a range read is an operator's question and must not move where the
    /// channel stands.
    fn claim_range(
        &mut self,
        now: Option<Monotonic>,
        pending: PendingDownload,
        recording: DownloadSink,
        offset: u64,
        deadline: Option<Monotonic>,
    ) {
        // Held only to re-park the item under the same identity it was issued
        // with; nothing about a range answer's outcome depends on it, the ring
        // being the asking end's.
        let _ = recording;
        match self.requester.poll(pending, &mut self.window) {
            DownloadPoll::Outstanding(pending) => {
                if expired(now, deadline) {
                    // Given up on rather than re-parked, which frees this
                    // module's one slot. The answer ends saying the medium would
                    // not serve it, which is what a recorder that never replied
                    // amounts to from here.
                    self.hold_range(RangeOutcome::MediumRefused, offset, 0);
                    self.report(Shipped::RangeUnanswered { offset });
                    return;
                }
                self.outstanding = Some(Outstanding {
                    pending,
                    reader: DownloadReader::Ring,
                    recording,
                    offset,
                    opening: false,
                    purpose: Fetching::Range,
                    deadline,
                });
            }
            DownloadPoll::Delivered { bytes, .. } => {
                // Copied out of the shared window on the shipment's terms: the
                // other two readers take it whenever they want it.
                let mut taken = 0_usize;
                for (slot, byte) in self.answer.iter_mut().zip(bytes) {
                    *slot = *byte;
                    taken = taken.saturating_add(1);
                }
                // An empty delivery is handed on as a data frame of no bytes, and
                // the composing domain's own rule ends the answer on it. One place
                // decides what a read that advanced nothing means.
                self.hold_range(RangeOutcome::Data, offset, taken);
            }
            DownloadPoll::Refused { reason, .. } => {
                self.hold_range(range_outcome(reason), offset, 0);
                // The wire has three statuses and the recorder has six refusals,
                // so the mapping loses the cause — which is put on the console
                // here, where a node with no shell is diagnosed.
                self.report(Shipped::RangeRefused { reason, offset });
            }
            DownloadPoll::Faulted(fault) => {
                let _: DownloadFault = fault;
                self.hold_range(RangeOutcome::MediumRefused, offset, 0);
                self.report(Shipped::RangeFaulted { offset });
            }
        }
    }

    /// Hold one answer frame for the relay's next free item.
    fn hold_range(&mut self, outcome: RangeOutcome, position: u64, len: usize) {
        self.held_range = Some(RangeFrame {
            outcome,
            position,
            len,
        });
    }

    fn abandon(&mut self, stage: &mut impl Stream) {
        self.counters.abandoned = self.counters.abandoned.saturating_add(1);
        self.serving = None;
        self.outstanding = None;
        stage.abandon_stream();
    }
}

/// Whether a deadline has passed at `now`.
///
/// False for either absence, and the two are different facts rather than one
/// default: an unarmed request has no deadline to miss, and a pass with no reading
/// of the clock cannot judge one. Both mean *not yet*, which is the direction that
/// cannot truncate a download that was going to complete.
fn expired(now: Option<Monotonic>, deadline: Option<Monotonic>) -> bool {
    match (now, deadline) {
        (Some(now), Some(deadline)) => now >= deadline,
        _ => false,
    }
}

/// Whether a ring is still inside its hold-off at `now`.
///
/// A ring with no hold-off armed is free, and so is one on a node whose clock
/// has published nothing: a reader that treated an unreadable clock as a
/// hold-off would stop shipping on exactly the node that cannot tell it to
/// start again.
fn held_off(now: Option<Monotonic>, until: Option<Monotonic>) -> bool {
    match (now, until) {
        (Some(now), Some(until)) => now < until,
        _ => false,
    }
}

/// Whether a recording's line is due again at `now`, `last` being when one went
/// out.
///
/// A ring that has never been reported is due, which is what puts the first
/// shipment of a session on the console rather than one period into it. A pass
/// with no reading of the clock is not: a console line is worth less than a
/// record rate nothing bounds.
fn due(now: Option<Monotonic>, last: Option<Monotonic>) -> bool {
    match (now, last) {
        (Some(_), None) => true,
        (Some(now), Some(last)) => now >= last.saturating_add(SHIPPING_REPORT_PERIOD),
        (None, _) => false,
    }
}

impl Upstream for Downloads<'_> {
    /// Place both readers where the session that just opened says to read from.
    ///
    /// **The whole of honouring a resume point.** Where a reader stood is where
    /// the *last* session got to; where this one starts is what the server that
    /// will ingest the bytes needs, and the two differ whenever a session ended
    /// with frames in flight. Moving backwards costs nothing, every frame
    /// carrying its own position.
    ///
    /// The one bound is the recording's own durable end, applied only where the
    /// recorder has said where that is. A resume point past it names bytes
    /// nothing wrote, and a reader placed there would ask forever for a position
    /// answered as past the end. Clamped and said out loud rather than refused,
    /// the session still being worth carrying.
    fn resume_from(&mut self, acked: Acknowledged) {
        let mut clamped = [None; RINGS.len()];
        for (at, recording) in RINGS.iter().enumerate() {
            let claimed = acked.of(*recording);
            let Some(ring) = self.rings.get_mut(at) else {
                continue;
            };
            // Unanswered is *unknown* and not *nothing*, on `note_durable`'s
            // terms: clamping against an unstated durable end would place every
            // reader at zero, which is what the resume point replaces.
            if ring.answered && claimed > ring.durable {
                if let Some(slot) = clamped.get_mut(at) {
                    *slot = Some((claimed, ring.durable));
                }
                ring.position = ring.durable;
            } else {
                ring.position = claimed;
            }
            // Moved by something other than a shipment, so the stall window
            // starts afresh rather than counting against a new session.
            ring.seen = ring.position;
            ring.moving_since = None;
            ring.stalled = false;
        }
        for (at, report) in clamped.into_iter().enumerate() {
            let (Some((claimed, durable)), Some(recording)) = (report, RINGS.get(at).copied())
            else {
                continue;
            };
            self.report(Shipped::ResumeClamped {
                recording,
                claimed,
                durable,
            });
        }
    }

    /// Take how far the far end says it has durably taken each recording, and
    /// state it to the recorder so a reboot resumes from it.
    ///
    /// **Forward only.** The claim was bounded by what this appliance sent at
    /// the end that composes the frames; what is left here is that no session
    /// undoes what an earlier one established — a server greeting with a smaller
    /// number wants those bytes again, which `resume_from` gives it, and is not
    /// saying the older ones were never delivered. The pair rides the next
    /// request to the recorder, whatever that request is for.
    fn acknowledged(&mut self, acked: Acknowledged) {
        for (at, recording) in RINGS.iter().enumerate() {
            let claimed = acked.of(*recording);
            if let Some(ring) = self.rings.get_mut(at) {
                ring.acked = ring.acked.max(claimed);
            }
        }
        self.requester.acknowledge(self.acknowledgement());
    }

    fn waiting(&self) -> Option<(DownloadSink, u64, &[u8])> {
        let Shipment {
            recording,
            position,
            len,
        } = self.held?;
        Some((recording, position, self.shipment.get(..len)?))
    }

    fn shipped(&mut self) {
        let Some(Shipment {
            recording,
            position,
            len,
        }) = self.held.take()
        else {
            return;
        };
        let at = ring_index(recording);
        if let Some(ring) = self.rings.get_mut(at) {
            // From the position that was shipped rather than from wherever the
            // cursor happens to stand: the two are the same on every path that
            // reaches here, and taking the shipment's own is what keeps them so.
            ring.position = position.saturating_add(len as u64);
        }
    }

    /// Take what extent the composing domain says it still owes.
    ///
    /// Assigned rather than merged, and that is the whole of how an answer ends:
    /// the domain states `None` once it is complete, so this reader stops asking
    /// without holding a rule about when to.
    fn wants(&mut self, wanted: Option<RangeWant>) {
        self.range = wanted;
    }

    fn range_waiting(&self) -> Option<(RangeOutcome, u64, &[u8])> {
        let RangeFrame {
            outcome,
            position,
            len,
        } = self.held_range?;
        // An outcome that ends the answer carries nothing whatever was read, so
        // the length is taken from the outcome rather than from the read.
        let bytes = if outcome.ends_the_answer() {
            &[][..]
        } else {
            self.answer.get(..len)?
        };
        Some((outcome, position, bytes))
    }

    fn range_answered(&mut self) {
        // No cursor moves: where the answer stands next is the composing domain's,
        // and it states it as the next want. This reader keeps nothing about an
        // answer between frames, which is what makes the two accounts one.
        self.held_range = None;
    }
}

#[cfg(test)]
mod tests;
