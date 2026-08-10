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
    DownloadReply, DownloadRequest, DownloadRequester, DownloadSink, PendingDownload,
};

use crate::{endpoint::EndpointStage, relay::SHIPPED_RING_BYTES, relay::Upstream};

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
    /// When this request is given up on, or `None` on a node whose clock has not
    /// been published yet — a state no client can reach, the endpoint refusing
    /// every TCP segment until a calibration has arrived, and carried rather than
    /// asserted away.
    deadline: Option<Monotonic>,
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
    /// Where the channel's cursor stands in each ring, in [`RINGS`] order. It
    /// starts at the beginning of the ring and moves only on a shipment the far
    /// end answered, so nothing this domain forgets can skip a byte.
    cursors: [u64; 2],
    /// Which rings the ring wrapped past, in [`RINGS`] order. Latched: nothing
    /// this build has resynchronises a lost cursor, so the honest answer is to
    /// stop shipping that ring rather than to ship bytes from somewhere else,
    /// and to say so once.
    lost: [bool; 2],
    /// Lost rings this domain has not yet reported.
    unreported: [bool; 2],
    /// When each ring may be asked again after catching up, in [`RINGS`] order.
    holdoff: [Option<Monotonic>; 2],
    /// Which ring the next ring request is for, so neither starves the other.
    next: usize,
    counters: DownloadCounters,
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
            cursors: [0; 2],
            lost: [false; 2],
            unreported: [false; 2],
            holdoff: [None; 2],
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
        self.claim(now, stage);
        self.ask(now, stage, shipping);
        stage.note_downloads(self.counters);
    }

    /// A ring the channel has lost its place in, reported once each.
    ///
    /// Taken by the domain rather than counted here, because what an operator
    /// needs is the console: a cursor the traffic outran means this appliance
    /// has stopped shipping that recording, and nothing in this build starts it
    /// again.
    pub fn take_lost(&mut self) -> Option<DownloadSink> {
        let at = self.unreported.iter().position(|lost| *lost)?;
        let recording = *RINGS.get(at)?;
        if let Some(slot) = self.unreported.get_mut(at) {
            *slot = false;
        }
        Some(recording)
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
            deadline,
        }) = self.outstanding.take()
        else {
            return;
        };
        if matches!(reader, DownloadReader::Ring) {
            self.claim_ring(now, pending, recording, offset, deadline);
            return;
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
                    deadline,
                });
            }
            DownloadPoll::Delivered { bytes, total_len } => {
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
    /// Every ending here leaves the cursor alone. A refusal, a fault and a
    /// deadline are all answers this reader can come back from by asking for the
    /// same position again, and an overrun is the one that cannot — the bytes
    /// are gone, and continuing from anywhere else would be shipping a
    /// recording's contents under a position that is not theirs.
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
                    deadline,
                });
            }
            DownloadPoll::Delivered { bytes, .. } => {
                if bytes.is_empty() {
                    // Caught up with what the medium has taken. Left alone until
                    // the hold-off is out rather than asked again on the next
                    // wakeup, which would be a round trip per wakeup for an
                    // answer that is empty by construction.
                    if let Some(slot) = self.holdoff.get_mut(at) {
                        *slot = now.map(|now| now.saturating_add(RING_HOLDOFF));
                    }
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
            }
            DownloadPoll::Refused { reason, .. } => {
                if matches!(reason, DownloadRefusal::Overrun) {
                    if let Some(slot) = self.lost.get_mut(at) {
                        *slot = true;
                    }
                    if let Some(slot) = self.unreported.get_mut(at) {
                        *slot = true;
                    }
                }
            }
            DownloadPoll::Faulted(fault) => {
                let _: DownloadFault = fault;
            }
        }
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
            // window. This is the whole of the fairness between the two readers:
            // a download in progress is asked for above and returns, and the
            // ring is only ever reached on a pass where none is.
            self.ask_ring(now, shipping);
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
            deadline: now.map(|now| now.saturating_add(REPLY_TIMEOUT)),
        });
    }

    /// Ask one ring for the bytes at its cursor.
    ///
    /// One recording per pass and the two taken in turn, so a ring the traffic
    /// keeps busy cannot hold the window against the other. A ring that is lost,
    /// held off, or already holding a shipment is skipped: there is one shipment
    /// buffer, and reading a second over it would drop the first.
    fn ask_ring(&mut self, now: Option<Monotonic>, shipping: bool) {
        if !shipping || self.held.is_some() {
            return;
        }
        for step in 0..RINGS.len() {
            let at = self.next.saturating_add(step) % RINGS.len();
            let Some(recording) = RINGS.get(at) else {
                continue;
            };
            if self.lost.get(at).copied().unwrap_or(true) {
                continue;
            }
            if held_off(now, self.holdoff.get(at).copied().flatten()) {
                continue;
            }
            let offset = self.cursors.get(at).copied().unwrap_or_default();
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
                deadline: now.map(|now| now.saturating_add(REPLY_TIMEOUT)),
            });
            self.next = at.saturating_add(1) % RINGS.len();
            return;
        }
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

impl Upstream for Downloads<'_> {
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
        if let Some(cursor) = self.cursors.get_mut(at) {
            // From the position that was shipped rather than from wherever the
            // cursor happens to stand: the two are the same on every path that
            // reaches here, and taking the shipment's own is what keeps them so.
            *cursor = position.saturating_add(len as u64);
        }
    }
}

#[cfg(test)]
mod tests;
