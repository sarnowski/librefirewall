//! The management domain's reader of the recorder's rings: the cursor that
//! ships a recording up the management channel, and the reads that answer an
//! operator's range request over the same channel.
//!
//! # Adversary
//!
//! A **management-plane attacker** in front and a **byzantine neighbour
//! protection domain** behind. The attacker chooses when and how often to ask
//! for an extent; nothing here allocates, waits or retries on their account.
//! The recorder chooses every byte of the answer: `wire::download` refuses a
//! reply that is not this request's, longer than the window, or longer than what
//! was asked for, and what survives that is a byte range handed on unread.
//! Nothing in this crate parses a recording.
//!
//! # Two readers of one ring, and how they are kept apart
//!
//! A recording is read for two purposes over one request channel: the shipping
//! cursor, which walks the ring forward and is what the management server
//! ingests, and a range answer, which reads wherever a peer asked and moves no
//! cursor at all. Both ask in the ring's own append space, so the coordinate
//! cannot say which of them asked — `Fetching` is what does, and answering a
//! range read into the shipment buffer would put an operator's extent on the
//! wire under a shipping position. Neither may starve the other and neither is
//! preferred: the recorder has one staging area and one outstanding request, so
//! the medium is shared by a rotation ([`MEDIUM_TURNS`]) rather than a priority.
//!
//! A recording is megabytes and the domain reading it has kilobytes, so every
//! read is bounded by what the frame it feeds can carry — a shipment by
//! [`SHIPPED_RING_BYTES`], an answer frame by [`RANGE_ANSWER_BYTES`] — and
//! nothing is held between passes beyond the one frame waiting for the relay.

use lfw_clock::{Duration, Monotonic};
use wire::{
    DOWNLOAD_WINDOW_LEN, DownloadFault, DownloadPoll, DownloadReader, DownloadRefusal,
    DownloadReply, DownloadRequest, DownloadRequester, DownloadSink, PendingDownload, RangeOutcome,
    RangeWant,
};

use crate::range::RANGE_ANSWER_BYTES;
use crate::relay::{SHIPPED_RING_BYTES, Upstream};
use wire::Acknowledged;

// The channel's own window against the recorder's, tied together where both are
// visible: a shipment is asked for out of this window, so one that could not fit
// would be a frame this domain asked for and could not carry.
const _: () = {
    assert!(SHIPPED_RING_BYTES <= DOWNLOAD_WINDOW_LEN);
    assert!(SHIPPED_RING_BYTES > 0);
};

/// How long the recorder may take to answer one read before it is given up on.
///
/// The slot for an outstanding request is single, so a recorder that never
/// answered would otherwise stop this reader for the rest of the boot. Ten
/// seconds rather than the configuration exchange's five, because the work
/// behind it is a block device that may be retrying rather than a table build.
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
/// second, so a caught-up cursor need be asked no more often — and one asked on
/// every wakeup would be a round trip to the recorder for an empty answer at
/// whatever rate the management port happens to be woken.
const RING_HOLDOFF: Duration = Duration::from_millis(1_000);

/// How often where the channel stands reaches the console while it is moving.
///
/// The channel's own batching period, so a healthy appliance leaves one line a
/// batch. Shorter would be a line per wakeup under load; longer would leave a
/// reader unable to tell a working channel from a stopped one, which is the
/// whole reason the record exists.
const SHIPPING_REPORT_PERIOD: Duration = Duration::from_millis(1_000);

/// How long durable bytes may stand behind a cursor that is not moving, on a
/// session that could carry them, before the appliance says so.
///
/// Ten batching periods: long enough that a slow round trip, a full wire or a
/// recorder busy with an operator's range read is not reported as a fault, and
/// short enough that an appliance which has stopped shipping says so while the
/// session it stopped on is still open. A constant of this file, so no peer can
/// lengthen the silence.
const SHIPPING_STALL_WINDOW: Duration = Duration::from_millis(10_000);

/// Reports the reader has for the console and the domain has not taken.
///
/// Seven, and total by construction: one pass claims at most one answer, so it
/// raises at most one resynchronisation **or** one range-read report, and beside
/// that at most one line about where the channel stands, one stall per recording,
/// and — on the single pass that agrees a greeting — one clamped resume point per
/// recording. The seventh slot is the range report's, counted separately so the
/// sum stays a sum of the shapes a pass can have rather than the ones it happens
/// to. The domain drains the queue every pass, so nothing accumulates.
const SHIPPING_REPORTS: usize = 7;

/// One recording's place in the channel, as a report carries it.
///
/// The pair rather than the position alone: a position says how far this
/// appliance has got, and only what is behind it says whether that keeps up.
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
/// the three ways a read for a range answer does not produce the extent asked
/// for. The last three exist because the wire cannot carry the cause: a range
/// answer has three statuses and the recorder has six refusals, so the mapping is
/// lossy and the console is where the cause that was lost is put.
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
        // The ring rolled past the extent: the one refusal the wire has a word
        // for, and the one an operator acts on differently — those bytes are
        // gone rather than momentarily unavailable.
        DownloadRefusal::Overrun => RangeOutcome::Overwritten,
        DownloadRefusal::DeviceError
        | DownloadRefusal::NotReady
        | DownloadRefusal::OutOfRange
        | DownloadRefusal::NoSuchSink
        | DownloadRefusal::NoSuchReader => RangeOutcome::MediumRefused,
    }
}

/// A request out to the recorder, and what its answer is for.
///
/// Every read this module issues is a [`DownloadReader::Ring`] one, so the
/// coordinate is not carried.
struct Outstanding {
    pending: PendingDownload,
    /// Which recording — the reader's own state is per recording, and the demand
    /// is the only thing that says which.
    recording: DownloadSink,
    /// What this read is for. Both readers of a ring ask in the same coordinate,
    /// so the coordinate cannot say which of them asked — and answering a range
    /// request into the shipment buffer would put an operator's extent on the wire
    /// under a shipping cursor.
    purpose: Fetching,
    offset: u64,
    /// When this request is given up on, or `None` on a node whose clock has not
    /// been published yet — a state carried rather than asserted away.
    deadline: Option<Monotonic>,
}

/// Which of the reader's two jobs one outstanding read belongs to.
///
/// A value rather than a flag beside the coordinate, because the coordinate is
/// already taken: the shipping cursor and a range answer both read the ring's
/// own append space, so nothing about the request says which of them asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fetching {
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

/// The management domain's reader of the recorder's rings.
pub struct Downloads<'chan> {
    requester: DownloadRequester<'chan>,
    outstanding: Option<Outstanding>,
    /// The window a reply is copied into before this reader takes what it wanted
    /// out of it. A field rather than a local because it is the channel's whole
    /// window and a protection domain's stack is not where that belongs. Sized by
    /// the channel rather than by any one frame, because
    /// `DownloadRequester::poll` copies into the whole of it.
    window: [u8; DOWNLOAD_WINDOW_LEN],
    /// The ring bytes read for the channel and not yet shipped.
    ///
    /// A buffer of its own rather than a claim on [`Self::window`], because the
    /// window is shared: the next read a rotation reaches would otherwise
    /// overwrite a shipment mid-flight, which is the one way the two readers
    /// could corrupt each other rather than merely wait for each other.
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
    /// it. **Told and never remembered across it**: that domain holds the
    /// answer's state and shrinks this as frames go, so what stands here is the
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
}

/// Turns the medium is shared out in: one per ring, and one for a range answer.
///
/// **This is where shipping and range answers are made fair to each other.** The
/// relay settles only which of two composed frames goes first; what decides how
/// much of the medium each gets is this rotation. Two of every three reads are a
/// ring's, so an answer advances by a frame every third read — neither a peer
/// starving the channel's purpose, nor the traffic starving an operator.
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
/// whether anything is waiting, and neither says whether the channel is moving
/// without the instants that bound the two questions.
#[derive(Clone, Copy)]
struct RingCursor {
    /// Where the cursor stands. It starts at the beginning of the ring and moves
    /// only on a shipment the far end answered, so nothing this domain forgets
    /// can skip a byte.
    ///
    /// Zero is where it *starts* and not where every ring *begins*: a recorder
    /// that resumed a medium serves nothing before the segment this boot opened.
    /// The recorder answers its own first position on every reply and the reader
    /// takes it, which is how a cursor and a ring that disagree are brought back
    /// together — and why a cursor is never simply given up on.
    position: u64,
    /// One past the last durable byte, as of this ring's last answer. What the
    /// cursor is behind, and so the only thing this domain can say about whether
    /// it has anything to ship.
    durable: u64,
    /// Whether the recorder has answered this ring at all. Until it has, a
    /// durable end of zero is *unknown* rather than *nothing behind the cursor*:
    /// reporting the second puts a caught-up channel on the console before a byte
    /// of either recording has been asked for.
    answered: bool,
    /// When this ring may be asked again after an answer that carried nothing.
    holdoff: Option<Monotonic>,
    /// The position last reported, so a line is owed only where one has moved.
    reported: u64,
    /// The position as of the last pass, so a move is noticed where the clock is
    /// read — the cursor moves on a relay answer, which carries no instant.
    seen: u64,
    /// When the cursor last moved on a session that could carry it, or `None`
    /// while there is none: the instant [`SHIPPING_STALL_WINDOW`] is measured
    /// from.
    moving_since: Option<Monotonic>,
    /// Whether a stall has already been reported, so it is said once and
    /// re-armed only by the cursor moving.
    stalled: bool,
    /// How far the management server says it has durably taken this recording.
    ///
    /// **Never moved backward**: this becomes a reader cursor on the medium, so
    /// a peer that could walk it back could make a reboot re-ship history the
    /// server already holds. Distinct from [`Self::position`], where the *reader*
    /// stands — the two disagreeing is ordinary on a channel with bytes in
    /// flight.
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
        }
    }

    /// One bounded pass, `shipping` saying whether there is a channel to ship
    /// ring bytes up.
    ///
    /// Never blocks and never spins. A pass with nothing to do returns having
    /// done nothing, which is the whole of the contract with the event loop:
    /// the recorder notifies this domain when a reply lands.
    ///
    /// `shipping` is a parameter and not a thing this module works out, for the
    /// reason the relay's own half is told rather than deduced: only the domain
    /// holding the relay knows whether the session up now is the dialled one and
    /// whether its greeting has been agreed, and a reader that guessed would read
    /// the medium on behalf of a channel that is not there.
    pub fn poll(&mut self, now: Option<Monotonic>, shipping: bool) {
        if !shipping {
            // No session to carry an answer, so nothing is owed one. Cleared
            // rather than waited for: a want is retired by the next relay answer,
            // which a session that has gone will never produce.
            self.range = None;
            self.held_range = None;
        }
        self.claim(now);
        self.ask(now, shipping);
        self.judge(now, shipping);
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
                // A pass with no reading of the clock judges no deadline,
                // which cannot report a healthy node as stuck.
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
        // written before that states a backlog of zero for a ring whose end
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
    fn claim(&mut self, now: Option<Monotonic>) {
        let Some(Outstanding {
            pending,
            recording,
            offset,
            purpose,
            deadline,
        }) = self.outstanding.take()
        else {
            return;
        };
        match purpose {
            Fetching::Ship => self.claim_ring(now, pending, recording, offset, deadline),
            Fetching::Range => self.claim_range(now, pending, recording, offset, deadline),
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
                    recording,
                    purpose: Fetching::Ship,
                    offset,
                    deadline,
                });
            }
            DownloadPoll::Delivered {
                bytes, total_len, ..
            } => {
                // The durable end is taken after the window has been read:
                // `bytes` borrows the very field a store through `self` would
                // touch, so the two are ordered rather than nested.
                if bytes.is_empty() {
                    self.note_durable(at, total_len);
                    // Caught up with what the medium has taken. Left alone until
                    // the hold-off is out: asking again on the next wakeup would
                    // be a round trip for an answer empty by construction.
                    self.hold_off(at, now);
                    return;
                }
                // Copied out of the shared window, which the next read the
                // rotation reaches overwrites: a shipment left pointing into it
                // would be an answer frame's bytes shipped under a ring
                // position.
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

    /// Ask for the next read this reader owes, if nothing is out.
    fn ask(&mut self, now: Option<Monotonic>, shipping: bool) {
        if self.outstanding.is_some() {
            return;
        }
        self.ask_medium(now, shipping);
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
                recording: *recording,
                purpose: Fetching::Ship,
                offset,
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
            recording: want.recording,
            purpose: Fetching::Range,
            offset: want.start,
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
                    recording,
                    purpose: Fetching::Range,
                    offset,
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

    fn hold_range(&mut self, outcome: RangeOutcome, position: u64, len: usize) {
        self.held_range = Some(RangeFrame {
            outcome,
            position,
            len,
        });
    }
}

/// Whether a deadline has passed at `now`.
///
/// False for either absence, and the two are different facts rather than one
/// default: an unarmed request has no deadline to miss, and a pass with no
/// reading of the clock cannot judge one. Both mean *not yet*.
fn expired(now: Option<Monotonic>, deadline: Option<Monotonic>) -> bool {
    match (now, deadline) {
        (Some(now), Some(deadline)) => now >= deadline,
        _ => false,
    }
}

/// Whether a ring is still inside its hold-off at `now`.
///
/// A ring with no hold-off armed is free, and so is one on a node whose clock has
/// published nothing: treating an unreadable clock as a hold-off would stop
/// shipping on exactly the node that cannot tell it to start again.
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
