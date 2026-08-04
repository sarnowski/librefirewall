//! Both recordings on one block device: where each lives, what the staging
//! window is carved into, and the whole of the pass a protection domain runs —
//! completions, tap records, flushes and downloads.
//!
//! # The adversary
//!
//! Two adversaries at once. The **byzantine neighbour** is on both
//! handovers: the tap ring's annotations arrive already checked by `wire::tap`,
//! and a download's sink, offset and length are the management domain's claims,
//! bounded here and nowhere else — only this side knows how long a snapshot is.
//! The **hostile or malfunctioning device** is behind [`Medium`]: a completion
//! may answer a job nothing is waiting on, may report failure, and may never
//! arrive at all. None costs more than a counted refusal, and every bound here
//! is a constant or a validated `Geometry` rather than a number either party
//! chose.
//!
//! # Why the pass is here and not in the protection domain
//!
//! Every interesting state of a recording — a segment rolling while the device
//! is backpressured, a download the writer wrapped past mid-read, a completion
//! for a flush already acknowledged — is hours of traffic away on real hardware
//! and one call away against a fake [`Medium`]. So the domain holding the
//! device capability implements that trait and nothing else.
//!
//! # A record a sink cannot take yet is held, never dropped
//!
//! `wire::TapReader` consumes a slot irrevocably, so a record one recording
//! refused for want of staging has nowhere else to live. [`Pending`] holds it
//! and the pass stops draining until every recording that selected it has taken
//! it; dropping it would be silent omission from an artifact whose whole value is
//! that it states its own losses in-band. A recording that did not *select* the
//! record is owed nothing by it, so the log skipping a packet is never a reason
//! the tap stops draining.

use lfw_clock::{Calibration, Ticks};

use lfw_capture_ring::{
    Geometry, GeometryError, SECTOR_SIZE, SUPERBLOCK_BYTES, SUPERBLOCK_COPY_BYTES,
};
use wire::{
    CheckedTap, DOWNLOAD_WINDOW_LEN, DownloadDemand, DownloadRefusal, DownloadSink, TAP_SNAP_LEN,
    TapReader,
};

use crate::{
    Flush, InterfaceName, Locate, MAX_INTERFACES, Recorded, Sink, SinkConfig, SinkCounters,
    SinkError, Snapshot,
};

/// Sectors at the front of the device neither recording may touch.
///
/// 1 MiB, and not a guess: the harness seeds and judges sectors here
/// (`xtask::data_disk`), a partition table would live here on real hardware,
/// and a recording starting at sector zero would make the first unprovable and
/// the second impossible.
pub const RESERVED_SECTORS: u64 = 2048;

/// Bytes of one segment, in both recordings. A segment is what a wrap replaces
/// whole and what a reader resynchronises on, so the number trades history
/// granularity against per-segment prologue cost: 1 MiB gives the log ring
/// fifteen payload segments and the capture ring thirty-one, one of each
/// extent's going to the superblock.
pub const SEGMENT_BYTES: usize = 1024 * 1024;

/// Where the event recording lives: 16 MiB starting at the reserved front.
pub const LOG_START_SECTOR: u64 = RESERVED_SECTORS;
pub const LOG_SECTORS: u64 = 32768;
/// Bytes of each causing frame an event record keeps.
///
/// The whole L2–L4 header chain and nothing of the payload. That bound is not a
/// round number: the largest chain this appliance ever reaches a decision on is
/// an Ethernet header (14), an 802.1Q tag (4), an IPv4 header with no options
/// (20) and a TCP header with a full option area (60) — 98 bytes. A frame that
/// is not IPv4 produces no decision and so no observation at all, and one whose
/// IPv4 header carries options is refused by the parser rather than decided on,
/// so nothing longer can reach a record. `xtask::recording_contract` holds this
/// number to those constants.
///
/// The payload stays out because an event record is evidence about a *decision*.
/// Carrying traffic is the capture recording's job, and widening the payload
/// exception past it would be a design change rather than a constant.
pub const LOG_SNAP_LEN: u32 = 128;

/// Where the full-content recording lives: 32 MiB starting at the log's end.
pub const CAPTURE_START_SECTOR: u64 = LOG_START_SECTOR + LOG_SECTORS;
pub const CAPTURE_SECTORS: u64 = 65536;
/// Whole frames, matching `wire::TAP_SNAP_LEN`, so a capture keeps everything
/// the tap could carry and truncates nothing a second time.
pub const CAPTURE_SNAP_LEN: u32 = TAP_SNAP_LEN as u32;

const SEGMENT_SECTORS: u64 = (SEGMENT_BYTES / SECTOR_SIZE) as u64;

const _: () = {
    assert!(LOG_START_SECTOR >= RESERVED_SECTORS);
    // Adjacent and disjoint, as one comparison, so a change to either extent
    // that overlapped the other fails the build.
    assert!(LOG_START_SECTOR + LOG_SECTORS <= CAPTURE_START_SECTOR);
    assert!(CAPTURE_SNAP_LEN as usize <= TAP_SNAP_LEN);
    assert!(SEGMENT_BYTES.is_multiple_of(SECTOR_SIZE));
    assert!(LOG_SECTORS.is_multiple_of(SEGMENT_SECTORS));
    assert!(CAPTURE_SECTORS.is_multiple_of(SEGMENT_SECTORS));
};

/// One area of the block-I/O staging window.
///
/// The window is carved once, here, and every transfer names an area rather
/// than an offset — so no arithmetic a caller performs can put one recording's
/// bytes in another's buffer, or a download's read over a pending write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Area {
    Log,
    Capture,
    Download,
    Superblock,
}

pub const LOG_STAGING_OFFSET: usize = 0;
pub const LOG_STAGING_BYTES: usize = 64 * 1024;
pub const CAPTURE_STAGING_OFFSET: usize = LOG_STAGING_OFFSET + LOG_STAGING_BYTES;
pub const CAPTURE_STAGING_BYTES: usize = 128 * 1024;
pub const DOWNLOAD_STAGING_OFFSET: usize = CAPTURE_STAGING_OFFSET + CAPTURE_STAGING_BYTES;
/// A window's worth plus one sector: a snapshot offset need not be
/// sector-aligned, so the read covers the bytes in front of the answer too.
pub const DOWNLOAD_STAGING_BYTES: usize = DOWNLOAD_WINDOW_LEN + SECTOR_SIZE;
pub const SUPERBLOCK_STAGING_OFFSET: usize = DOWNLOAD_STAGING_OFFSET + DOWNLOAD_STAGING_BYTES;
pub const SUPERBLOCK_STAGING_BYTES: usize = SUPERBLOCK_BYTES;
/// One past the last byte any area uses.
pub const STAGING_END: usize = SUPERBLOCK_STAGING_OFFSET + SUPERBLOCK_STAGING_BYTES;

const _: () = {
    // Every area starts and ends on a sector: each is the source or the
    // destination of a whole-sector transfer.
    assert!(LOG_STAGING_OFFSET.is_multiple_of(SECTOR_SIZE));
    assert!(LOG_STAGING_BYTES.is_multiple_of(SECTOR_SIZE));
    assert!(CAPTURE_STAGING_OFFSET.is_multiple_of(SECTOR_SIZE));
    assert!(CAPTURE_STAGING_BYTES.is_multiple_of(SECTOR_SIZE));
    assert!(DOWNLOAD_STAGING_OFFSET.is_multiple_of(SECTOR_SIZE));
    assert!(DOWNLOAD_STAGING_BYTES.is_multiple_of(SECTOR_SIZE));
    assert!(SUPERBLOCK_STAGING_OFFSET.is_multiple_of(SECTOR_SIZE));
    assert!(SUPERBLOCK_STAGING_BYTES.is_multiple_of(SECTOR_SIZE));
    // A staging buffer must hold a prologue, one record and the tail reserve at
    // once, or its recording could never place anything.
    assert!(LOG_STAGING_BYTES > crate::TAIL_RESERVE + LOG_SNAP_LEN as usize);
    assert!(CAPTURE_STAGING_BYTES > crate::TAIL_RESERVE + CAPTURE_SNAP_LEN as usize);
    // A closed segment's padding is composed in the staging buffer, and the
    // most that can be left is one record's claim short of the tail reserve.
    assert!(LOG_STAGING_BYTES > 2 * crate::TAIL_RESERVE);
    assert!(CAPTURE_STAGING_BYTES > 2 * crate::TAIL_RESERVE);
};

impl Area {
    /// This area's offset and length within the staging window.
    #[must_use]
    pub const fn extent(self) -> (usize, usize) {
        match self {
            Self::Log => (LOG_STAGING_OFFSET, LOG_STAGING_BYTES),
            Self::Capture => (CAPTURE_STAGING_OFFSET, CAPTURE_STAGING_BYTES),
            Self::Download => (DOWNLOAD_STAGING_OFFSET, DOWNLOAD_STAGING_BYTES),
            Self::Superblock => (SUPERBLOCK_STAGING_OFFSET, SUPERBLOCK_STAGING_BYTES),
        }
    }
}

/// The interface table a recording's prologue names, sized by
/// `wire::MAX_INTERFACES`.
pub type InterfaceNames = [InterfaceName; MAX_INTERFACES];

/// Which of the two recordings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    Log,
    Capture,
}

impl Which {
    /// Both, in the order [`RecorderCounters::sinks`] holds them.
    pub const ALL: [Self; 2] = [Self::Log, Self::Capture];

    #[must_use]
    pub const fn area(self) -> Area {
        match self {
            Self::Log => Area::Log,
            Self::Capture => Area::Capture,
        }
    }

    /// The recording the download channel's own name refers to.
    #[must_use]
    pub const fn named(sink: DownloadSink) -> Self {
        match sink {
            DownloadSink::Log => Self::Log,
            DownloadSink::Capture => Self::Capture,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Log => 0,
            Self::Capture => 1,
        }
    }

    const fn geometry(self, capacity_sectors: u64) -> Result<Geometry, GeometryError> {
        let (start, sectors) = match self {
            Self::Log => (LOG_START_SECTOR, LOG_SECTORS),
            Self::Capture => (CAPTURE_START_SECTOR, CAPTURE_SECTORS),
        };
        Geometry::new(start, sectors, SEGMENT_BYTES, capacity_sectors)
    }

    const fn snap_len(self) -> u32 {
        match self {
            Self::Log => LOG_SNAP_LEN,
            Self::Capture => CAPTURE_SNAP_LEN,
        }
    }

    /// Whether this recording takes the observation at all — **what the two
    /// recordings differ by**, the snap length being a consequence of it.
    ///
    /// The log takes an observation carrying a lifecycle or policy event and
    /// nothing else, so its rate is bounded by how fast conversations are
    /// admitted and refused rather than by the packet rate. That is what keeps a
    /// connection history usable under the conditions it is wanted in: a flood
    /// recorded per packet evicts the whole history in seconds.
    ///
    /// The capture takes every observation **of a frame**, which is every one but
    /// the revocation: a capture is the frames themselves with the verdict on
    /// each, and a flow the appliance ended of its own accord was on no wire. That
    /// record belongs to the connection history alone, where the conversation it
    /// ends was opened.
    const fn records(self, tap: &CheckedTap) -> bool {
        match self {
            Self::Log => tap.event.is_some(),
            Self::Capture => tap.outcome.observes_a_frame(),
        }
    }
}

/// What one submitted transfer is for, so a completion is attributed to a
/// decision this side took rather than to anything the device said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Job {
    /// A recording's staged sectors going to the medium.
    Flush(Which),
    /// A checkpoint superblock going to a recording's extent.
    Checkpoint(Which),
    /// A download's sectors coming back.
    Fetch,
}

/// One transfer, as the medium is asked for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub area: Area,
    /// Byte offset within the area, a whole number of sectors. Non-zero only
    /// for a superblock, which rewrites one of its two copies and must leave
    /// the other — the one the medium is currently relying on — alone.
    pub at: usize,
    /// The first device sector, produced by the recording's own `Geometry`.
    pub sector: u64,
    /// A whole number of sectors, never more than the area holds past `at`.
    pub len: usize,
    pub write: bool,
}

/// How a transfer ended, as the domain owning the device reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The medium performed it and moved `delivered` data bytes — carried because
    /// a device may complete a read `Ok` having moved less, leaving the shortfall
    /// holding an earlier transfer's bytes.
    Ok { delivered: usize },
    /// The medium refused it, or answered something the driver could not
    /// decode.
    Failed,
}

/// One completion: the job it answers, and how it ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub job: Job,
    pub ended: Ended,
}

/// What one poll of the medium produced. An unattributable completion is its own
/// answer and never `None`, which is how a caller learns the device has nothing
/// more to say: reporting one as the other lets a device replaying its used ring
/// end the drain on every pass while every fault surface reads clean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polled {
    Settled(Completion),
    /// Counted, and the drain goes on.
    Unattributed,
}

/// The medium would not take a transfer now — no free slot, no room in the
/// queue, or a range it refused. Backpressure, never a lost record: the caller
/// offers it again on a later pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused;

/// The block device, as a recording needs it.
///
/// Three methods and no state machine: submission is asynchronous because the
/// device is, and hiding that behind a blocking call would put an unbounded
/// wait on the one domain that must keep draining a tap.
pub trait Medium {
    /// The bytes of one staging area — the source or destination of a transfer
    /// naming it. Always exactly `area.extent().1` bytes long.
    fn staging(&mut self, area: Area) -> &mut [u8];

    /// Publish one transfer, answered later by [`poll`](Self::poll) under
    /// `job`.
    ///
    /// # Errors
    /// [`Refused`] when the device cannot take it now; nothing is published.
    fn submit(&mut self, job: Job, transfer: Transfer) -> Result<(), Refused>;

    /// Take one completion, or `None` once the device has nothing more. One per
    /// call, so the caller bounds its own drain and a device flooding its used
    /// ring cannot park the domain inside a single call.
    fn poll(&mut self) -> Option<Polled>;
}

/// Completions one pass settles. A device answering faster than this leaves the
/// rest for the next pass, which is what keeps the tap drained.
pub const COMPLETION_BUDGET: usize = 8;

/// Tap records one pass drains, bounded independently of the ring's own
/// capacity so a producer that keeps it full cannot hold the pass inside the
/// drain.
pub const TAP_BUDGET: usize = 16;

/// Saturating, monotone counts for the operator-facing metrics contract.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecorderCounters {
    /// Per recording, in [`Which::ALL`] order.
    pub sinks: [SinkCounters; 2],
    /// Tap records drained and offered to the recordings that select them.
    pub tap_records: u64,
    /// Tap annotations the reader would not decode.
    pub tap_refused: u64,
    /// Drops the forwarder claims the ring cost it — its statement about
    /// itself, published beside this side's rather than instead of it.
    pub tap_dropped_by_writer: u64,
    /// Download windows answered with bytes.
    pub downloads_served: u64,
    /// Download windows answered with a refusal.
    pub downloads_refused: u64,
    /// Records placed before any calibration was published. A recording states
    /// 1970 for these rather than a counter reading dressed as a time.
    pub records_unclocked: u64,
    /// Transfers the medium would not take when one was ready.
    pub medium_refusals: u64,
    /// Transfers the medium answered with a failure.
    pub medium_failures: u64,
    /// Completions answering a job nothing was waiting on: a device replaying
    /// its used ring, or a wiring defect. Expected to stay zero.
    pub completions_unexpected: u64,
}

/// Why the recordings could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeckError {
    /// An extent is not a ring on this device — usually a device smaller than
    /// the recording configured for it.
    Extent { which: Which, error: GeometryError },
    /// A sink refused its configuration, or its opening prologue did not fit
    /// the staging area.
    Sink { which: Which, error: SinkError },
}

/// One recording and everything outstanding against it.
struct Recording {
    which: Which,
    sink: Sink,
    /// The flush the medium was handed, or is about to be. Held because a
    /// [`Flush`] is the caller's single obligation to write those bytes and
    /// `Sink::acknowledge` consumes it, so it cannot be dropped on a
    /// refused submit and re-derived later.
    in_flight: Option<Flush>,
    /// Whether that flush has actually reached the medium. A refused submit
    /// leaves it false and the next pass offers the same bytes again.
    submitted: bool,
    /// Set when the open segment has been closed and its bytes must reach the
    /// medium before the next segment's prologue may overwrite the staging
    /// buffer. This is the whole reason a roll spans passes.
    rolling: bool,
    /// Set when the ring's state has changed enough to be worth a superblock.
    checkpoint_due: bool,
}

impl Recording {
    fn new(
        which: Which,
        capacity_sectors: u64,
        interfaces: InterfaceNames,
        interface_count: usize,
        staging: &mut [u8],
    ) -> Result<Self, DeckError> {
        let geometry = which
            .geometry(capacity_sectors)
            .map_err(|error| DeckError::Extent { which, error })?;
        let sink = Sink::new(
            SinkConfig {
                geometry,
                snap_len: which.snap_len(),
                interfaces,
                interface_count,
            },
            staging,
        )
        .map_err(|error| DeckError::Sink { which, error })?;
        Ok(Self {
            which,
            sink,
            in_flight: None,
            submitted: false,
            rolling: false,
            // The extent identifies itself on the medium from the first pass,
            // so a reader that finds the disk knows what the bytes past it are.
            checkpoint_due: true,
        })
    }
}

/// A tap record one or both recordings have not taken yet.
struct Pending {
    tap: CheckedTap,
    bytes: [u8; TAP_SNAP_LEN],
    len: usize,
    /// Which recordings still owe this record a place, in [`Which::ALL`] order.
    owed: [bool; 2],
}

/// Where a download stands. One at a time, which the channel already enforces:
/// `wire::download` admits exactly one outstanding request.
enum Download {
    Idle,
    /// A new snapshot was asked for: the recording is being sealed so what a
    /// reader is promised is what the medium actually holds.
    Sealing {
        demand: DownloadDemand,
        which: Which,
        sealed: bool,
    },
    /// A read of the answer's sectors, out or waiting to go out; its bytes land
    /// in the download staging area.
    Fetching {
        demand: DownloadDemand,
        total_len: u64,
        /// Bytes of the first sector that are in front of the answer.
        skip: usize,
        len: usize,
        sector: u64,
        sectors: u64,
        /// Whether the medium has taken it. A refused submit leaves it false
        /// and the next pass offers the same read again.
        submitted: bool,
    },
    /// That read landed, and the answer is in the staging area.
    Fetched {
        demand: DownloadDemand,
        total_len: u64,
        skip: usize,
        len: usize,
    },
    /// An answer that carries no bytes, waiting to be handed over.
    Answered {
        demand: DownloadDemand,
        reason: Option<DownloadRefusal>,
        total_len: u64,
    },
}

/// What the caller must put on the download channel.
///
/// Both shapes consume the demand, which is what makes one demand exactly one
/// reply — `wire::DownloadResponder` takes it by value for the same reason.
pub enum Served<'window> {
    /// Answer with these bytes. Empty is a legitimate answer: it is what the
    /// end of a snapshot looks like, under a `total_len` the reader compares
    /// its own progress against.
    Deliver {
        demand: DownloadDemand,
        bytes: &'window [u8],
        total_len: u64,
    },
    /// Answer with a refusal, and why.
    Refuse {
        demand: DownloadDemand,
        reason: DownloadRefusal,
        total_len: u64,
    },
}

/// Both recordings, and the pass that drives them.
pub struct Deck {
    recordings: [Recording; 2],
    pending: Option<Pending>,
    /// The snapshot a download is answered out of, pinned when the requester
    /// asks for offset 0 and kept until it asks for one again.
    pinned: Option<(Which, Snapshot)>,
    download: Download,
    /// The calibration the last pass was given, or `None` while the clock
    /// domain has published nothing this side would use.
    clock: Option<Calibration>,
    /// The recording whose checkpoint the medium is carrying. One at a time,
    /// because both share one staging area.
    checkpointing: Option<Which>,
    counters: RecorderCounters,
}

impl Deck {
    /// Build both recordings over a device of `capacity_sectors` and compose
    /// their opening prologues into the staging window.
    ///
    /// # Errors
    /// [`DeckError`], naming the recording and what it refused.
    pub fn new(
        capacity_sectors: u64,
        interfaces: InterfaceNames,
        interface_count: usize,
        medium: &mut impl Medium,
    ) -> Result<Self, DeckError> {
        let log = Recording::new(
            Which::Log,
            capacity_sectors,
            interfaces,
            interface_count,
            medium.staging(Area::Log),
        )?;
        let capture = Recording::new(
            Which::Capture,
            capacity_sectors,
            interfaces,
            interface_count,
            medium.staging(Area::Capture),
        )?;
        Ok(Self {
            recordings: [log, capture],
            pending: None,
            pinned: None,
            download: Download::Idle,
            clock: None,
            checkpointing: None,
            counters: RecorderCounters::default(),
        })
    }

    /// Both extents as `(start_sector, sectors)`, for the record a boot owes an
    /// operator.
    #[must_use]
    pub const fn extents() -> [(u64, u64); 2] {
        [
            (LOG_START_SECTOR, LOG_SECTORS),
            (CAPTURE_START_SECTOR, CAPTURE_SECTORS),
        ]
    }

    #[must_use]
    pub fn counters(&self) -> RecorderCounters {
        let mut counters = self.counters;
        for (slot, recording) in counters.sinks.iter_mut().zip(&self.recordings) {
            *slot = recording.sink.counters();
        }
        counters
    }

    /// One bounded pass: settle what the medium answered, take what the tap
    /// offers, and give the medium whatever is ready.
    ///
    /// Every step has a bound that is this crate's own rather than a peer's, so
    /// no pass can be held open by a device that keeps completing or a producer
    /// that keeps publishing.
    pub fn poll(
        &mut self,
        medium: &mut impl Medium,
        tap: &mut TapReader<'_>,
        scratch: &mut [u8; TAP_SNAP_LEN],
        clock: Option<Calibration>,
    ) {
        self.clock = clock;
        for _ in 0..COMPLETION_BUDGET {
            if !self.settle(medium) {
                break;
            }
        }
        self.drain_tap(medium, tap, scratch);
        self.advance_download(medium);
        for index in 0..self.recordings.len() {
            self.advance(index, medium);
        }
        self.checkpoint(medium);
    }

    /// Bytes the transfer answering `job` asked for, or `None` holding none.
    fn asked(&self, job: Job) -> Option<usize> {
        match job {
            Job::Flush(which) => self
                .recordings
                .get(which.index())
                .filter(|recording| recording.submitted)
                .and_then(|recording| recording.in_flight.as_ref())
                .map(Flush::len),
            // The smaller length a `SuperblockWrite` names, so both copies
            // replaced and one moved still reads as short.
            Job::Checkpoint(which) => {
                (self.checkpointing == Some(which)).then_some(SUPERBLOCK_COPY_BYTES)
            }
            Job::Fetch => match self.download {
                Download::Fetching {
                    sectors,
                    submitted: true,
                    ..
                } => Some((sectors as usize).saturating_mul(SECTOR_SIZE)),
                _ => None,
            },
        }
    }

    /// Take one completion and settle it, reporting whether there was one.
    fn settle(&mut self, medium: &mut impl Medium) -> bool {
        let Some(polled) = medium.poll() else {
            return false;
        };
        let Polled::Settled(Completion { job, ended }) = polled else {
            self.counters.completions_unexpected =
                self.counters.completions_unexpected.saturating_add(1);
            return true;
        };
        // Short is a failure however it reports itself.
        let short = match ended {
            Ended::Ok { delivered } => self.asked(job).is_some_and(|asked| delivered < asked),
            Ended::Failed => false,
        };
        let failed = ended == Ended::Failed || short;
        if failed {
            self.counters.medium_failures = self.counters.medium_failures.saturating_add(1);
        }
        match job {
            Job::Flush(which) => {
                let index = which.index();
                let staging = medium.staging(which.area());
                let Some(recording) = self.recordings.get_mut(index) else {
                    return true;
                };
                match recording.in_flight.take() {
                    // Acknowledged even where the medium failed. The bytes are
                    // lost and counted as `medium_failures`; refusing to
                    // advance would stall every later record behind a fault
                    // retrying cannot clear, which is a worse recording than
                    // one with a stated gap.
                    Some(flush) if recording.submitted => {
                        recording.submitted = false;
                        recording.sink.acknowledge(flush, staging);
                        // The durable cursor just moved, and the superblock is
                        // the medium's only statement of where it is. Rolling a
                        // segment is far too coarse a trigger for that: it would
                        // leave the extent claiming nothing durable for as long
                        // as a recording stays inside its first segment, which
                        // is the whole of a short run.
                        recording.checkpoint_due = true;
                    }
                    // A completion for a flush that was never handed over, or
                    // for one already settled: the device's, and counted.
                    other => {
                        recording.in_flight = other;
                        self.counters.completions_unexpected =
                            self.counters.completions_unexpected.saturating_add(1);
                    }
                }
            }
            Job::Checkpoint(which) => {
                if self.checkpointing == Some(which) {
                    self.checkpointing = None;
                    if !failed && let Some(recording) = self.recordings.get_mut(which.index()) {
                        recording.sink.acknowledge_checkpoint();
                    }
                } else {
                    self.counters.completions_unexpected =
                        self.counters.completions_unexpected.saturating_add(1);
                }
            }
            Job::Fetch => match core::mem::replace(&mut self.download, Download::Idle) {
                Download::Fetching {
                    demand,
                    total_len,
                    skip,
                    len,
                    submitted: true,
                    ..
                } => {
                    self.download = if failed {
                        // Answered rather than left waiting: a requester cannot
                        // tell a refusal from a hang (`wire::download`). A short
                        // read arrives here too, so the area's older bytes are
                        // never handed out as this window's.
                        Download::Answered {
                            demand,
                            reason: Some(DownloadRefusal::DeviceError),
                            total_len,
                        }
                    } else {
                        Download::Fetched {
                            demand,
                            total_len,
                            skip,
                            len,
                        }
                    };
                }
                other => {
                    self.download = other;
                    self.counters.completions_unexpected =
                        self.counters.completions_unexpected.saturating_add(1);
                }
            },
        }
        true
    }

    /// Offer the tap's records to both recordings, stopping the moment one is
    /// still owed a place.
    fn drain_tap(
        &mut self,
        medium: &mut impl Medium,
        tap: &mut TapReader<'_>,
        scratch: &mut [u8; TAP_SNAP_LEN],
    ) {
        // The rise since the last pass is the loss the next record's
        // `epb_dropcount` states, so a recording says what it did not see.
        let dropped = u64::from(tap.dropped_by_writer());
        let unattributed = dropped.saturating_sub(self.counters.tap_dropped_by_writer);
        if unattributed > 0 {
            for recording in &mut self.recordings {
                recording.sink.note_drops(unattributed);
            }
        }
        self.counters.tap_dropped_by_writer = dropped;
        for _ in 0..TAP_BUDGET {
            if !self.settle_pending(medium) {
                return;
            }
            let Some(read) = tap.read(scratch) else {
                return;
            };
            match read {
                Ok((checked, bytes)) => {
                    self.counters.tap_records = self.counters.tap_records.saturating_add(1);
                    let checked = self.stamped(checked);
                    self.offer(checked, bytes, medium);
                }
                Err(_) => {
                    self.counters.tap_refused = self.counters.tap_refused.saturating_add(1);
                }
            }
        }
    }

    /// Try again to place the held record, answering whether the way is clear
    /// for a new one.
    fn settle_pending(&mut self, medium: &mut impl Medium) -> bool {
        let Some(mut held) = self.pending.take() else {
            return true;
        };
        // The held length is this crate's own, recorded from the slice the
        // reader filled, so the slice is the record; an empty one settles
        // rather than looping, and no path here can panic.
        let bytes = held.bytes.get(..held.len).unwrap_or_default();
        let mut still_owed = false;
        for which in Which::ALL {
            let index = which.index();
            let owed = held.owed.get(index).copied().unwrap_or(false);
            if owed && !place(&mut self.recordings, which, &held.tap, bytes, medium) {
                still_owed = true;
            } else if let Some(slot) = held.owed.get_mut(index) {
                *slot = false;
            }
        }
        if still_owed {
            self.pending = Some(held);
            return false;
        }
        true
    }

    /// The observation with its counter reading converted to the microseconds a
    /// recording states — here rather than on the dataplane, which would have
    /// to re-read another domain's region per frame. With no calibration the
    /// instant is zero rather than the raw reading, so a recording never
    /// dresses a counter value as a wall-clock time.
    fn stamped(&mut self, mut tap: CheckedTap) -> CheckedTap {
        match self.clock {
            Some(calibration) => {
                tap.timestamp = calibration.utc(Ticks(tap.timestamp)).as_nanos() / 1_000;
            }
            None => {
                tap.timestamp = 0;
                self.counters.records_unclocked = self.counters.records_unclocked.saturating_add(1);
            }
        }
        tap
    }

    /// Offer one record to the recordings that take it, holding it where one
    /// could not.
    ///
    /// A recording that does not select the observation is owed nothing by it, so
    /// a record the log does not carry never becomes a reason to stop draining
    /// the tap.
    fn offer(&mut self, tap: CheckedTap, bytes: &[u8], medium: &mut impl Medium) {
        let mut owed = [false; 2];
        let mut any = false;
        for which in Which::ALL.into_iter().filter(|which| which.records(&tap)) {
            if !place(&mut self.recordings, which, &tap, bytes, medium) {
                if let Some(slot) = owed.get_mut(which.index()) {
                    *slot = true;
                }
                any = true;
            }
        }
        if !any {
            return;
        }
        let mut held = Pending {
            tap,
            bytes: [0; TAP_SNAP_LEN],
            // Bounded by the destination, so a length is never larger than what
            // was actually copied.
            len: bytes.len().min(TAP_SNAP_LEN),
            owed,
        };
        for (slot, byte) in held.bytes.iter_mut().zip(bytes) {
            *slot = *byte;
        }
        self.pending = Some(held);
    }

    /// Give the medium whatever recording `index` has ready, and reopen a
    /// segment whose close has reached the medium.
    fn advance(&mut self, index: usize, medium: &mut impl Medium) {
        let Some(recording) = self.recordings.get_mut(index) else {
            return;
        };
        let which = recording.which;
        let staging = medium.staging(which.area());
        if recording.rolling && recording.in_flight.is_none() && recording.sink.staged() == 0 {
            // The closed segment is on the medium, so the buffer may be reused
            // for the next segment's prologue.
            if recording.sink.begin_segment(staging).is_ok() {
                recording.rolling = false;
                recording.checkpoint_due = true;
            }
        }
        if recording.in_flight.is_none() {
            recording.in_flight = recording.sink.take_flush();
            recording.submitted = false;
        }
        let Some(flush) = recording.in_flight.as_ref() else {
            return;
        };
        if recording.submitted {
            return;
        }
        let transfer = Transfer {
            area: which.area(),
            at: 0,
            sector: flush.sector(),
            len: flush.len(),
            write: true,
        };
        match medium.submit(Job::Flush(which), transfer) {
            Ok(()) => recording.submitted = true,
            Err(Refused) => {
                self.counters.medium_refusals = self.counters.medium_refusals.saturating_add(1);
            }
        }
    }

    /// Compose and submit one checkpoint superblock, if one is due and the
    /// shared staging area is free.
    fn checkpoint(&mut self, medium: &mut impl Medium) {
        if self.checkpointing.is_some() {
            return;
        }
        let Some((which, sector)) = self
            .recordings
            .iter()
            .find(|recording| recording.checkpoint_due)
            .map(|recording| (recording.which, recording.sink.superblock_sector()))
        else {
            return;
        };
        let staging = medium.staging(Area::Superblock);
        let Some(image) = staging.get_mut(..SUPERBLOCK_BYTES) else {
            return;
        };
        let Ok(image) = <&mut [u8; SUPERBLOCK_BYTES]>::try_from(image) else {
            return;
        };
        let Some(recording) = self.recordings.get_mut(which.index()) else {
            return;
        };
        let Ok(write) = recording.sink.superblock(image) else {
            // A cursor no superblock can carry: the recording keeps going and
            // the checkpoint is simply not written, which is what an
            // unidentified extent already looks like to a reader.
            recording.checkpoint_due = false;
            return;
        };
        let transfer = Transfer {
            area: Area::Superblock,
            at: write.at,
            sector: sector.saturating_add((write.at / SECTOR_SIZE) as u64),
            len: write.len,
            write: true,
        };
        match medium.submit(Job::Checkpoint(which), transfer) {
            Ok(()) => {
                self.checkpointing = Some(which);
                if let Some(recording) = self.recordings.get_mut(which.index()) {
                    recording.checkpoint_due = false;
                }
            }
            Err(Refused) => {
                self.counters.medium_refusals = self.counters.medium_refusals.saturating_add(1);
            }
        }
    }

    /// Take one demand off the channel. Answered on this pass or a later one,
    /// never both.
    ///
    /// A demand arriving while another is being served replaces it: the channel
    /// admits one outstanding request, so the old one is a request the
    /// requester has already abandoned.
    pub fn demand(&mut self, demand: DownloadDemand) {
        let Some(sink) = demand.sink() else {
            self.download = Download::Answered {
                demand,
                reason: Some(DownloadRefusal::NoSuchSink),
                total_len: 0,
            };
            return;
        };
        let which = Which::named(sink);
        if demand.offset() == 0 {
            self.download = Download::Sealing {
                demand,
                which,
                sealed: false,
            };
            return;
        }
        match self.pinned {
            Some((pinned, snapshot)) if pinned == which => {
                self.locate(demand, which, snapshot);
            }
            // A later offset with nothing pinned, or pinned against the other
            // recording: the requester never started this download, or started
            // a different one. Refused rather than begun afresh, which would
            // answer bytes from a snapshot it never asked about.
            _ => {
                self.download = Download::Answered {
                    demand,
                    reason: Some(DownloadRefusal::NotReady),
                    total_len: 0,
                };
            }
        }
    }

    /// Whether a demand is being worked on, so a caller does not take a second
    /// off the channel while the first is unanswered.
    #[must_use]
    pub const fn serving(&self) -> bool {
        !matches!(self.download, Download::Idle)
    }

    /// The answer a demand is owed, once there is one.
    pub fn answer<'window, M: Medium>(
        &mut self,
        medium: &'window mut M,
    ) -> Option<Served<'window>> {
        match core::mem::replace(&mut self.download, Download::Idle) {
            Download::Answered {
                demand,
                reason,
                total_len,
            } => Some(match reason {
                Some(reason) => {
                    self.counters.downloads_refused =
                        self.counters.downloads_refused.saturating_add(1);
                    Served::Refuse {
                        demand,
                        reason,
                        total_len,
                    }
                }
                None => {
                    self.counters.downloads_served =
                        self.counters.downloads_served.saturating_add(1);
                    Served::Deliver {
                        demand,
                        bytes: &[],
                        total_len,
                    }
                }
            }),
            Download::Fetched {
                demand,
                total_len,
                skip,
                len,
            } => {
                self.counters.downloads_served = self.counters.downloads_served.saturating_add(1);
                let staging = medium.staging(Area::Download);
                // Both bounds are this crate's own: `skip` is below a sector
                // and `len` below the window, and the slicing that produces the
                // answer is what enforces them, with no panic possible.
                let bytes = staging
                    .get(skip..)
                    .and_then(|tail| tail.get(..len))
                    .unwrap_or_default();
                Some(Served::Deliver {
                    demand,
                    bytes,
                    total_len,
                })
            }
            other => {
                self.download = other;
                None
            }
        }
    }

    /// Move a sealing download along, and submit a read whose sectors are
    /// known.
    fn advance_download(&mut self, medium: &mut impl Medium) {
        // Taken out rather than borrowed: a `DownloadDemand` is not `Copy`,
        // because one demand may produce exactly one reply (`wire::download`).
        if matches!(self.download, Download::Sealing { .. }) {
            let Download::Sealing {
                demand,
                which,
                sealed,
            } = core::mem::replace(&mut self.download, Download::Idle)
            else {
                return;
            };
            let staging = medium.staging(which.area());
            let Some(recording) = self.recordings.get_mut(which.index()) else {
                // The demand was taken out of the state to be moved, so returning
                // would consume it and answer nothing.
                self.download = Download::Answered {
                    demand,
                    reason: Some(DownloadRefusal::NotReady),
                    total_len: 0,
                };
                return;
            };
            // A seal that will not fit waits for a flush to make room; nothing
            // is lost by trying again next pass.
            let sealed = sealed || recording.sink.seal(staging).is_ok();
            if !sealed || recording.in_flight.is_some() || recording.sink.staged() != 0 {
                self.download = Download::Sealing {
                    demand,
                    which,
                    sealed,
                };
                return;
            }
            let snapshot = recording.sink.snapshot();
            self.pinned = Some((which, snapshot));
            self.locate(demand, which, snapshot);
        }
        if let Download::Fetching {
            sector,
            sectors,
            submitted,
            ..
        } = &mut self.download
        {
            if *submitted {
                return;
            }
            let transfer = Transfer {
                area: Area::Download,
                at: 0,
                sector: *sector,
                // Bounded by the read's own sector count, which
                // `DOWNLOAD_STAGING_BYTES` is sized to hold: a window plus the
                // one sector an unaligned offset skips into.
                len: (*sectors as usize).saturating_mul(SECTOR_SIZE),
                write: false,
            };
            match medium.submit(Job::Fetch, transfer) {
                Ok(()) => *submitted = true,
                Err(Refused) => {
                    self.counters.medium_refusals = self.counters.medium_refusals.saturating_add(1);
                }
            }
        }
    }

    /// Resolve one offset against a pinned snapshot and either answer it or put
    /// a read out for it.
    fn locate(&mut self, demand: DownloadDemand, which: Which, snapshot: Snapshot) {
        let total_len = snapshot.total_len();
        let Some(recording) = self.recordings.get_mut(which.index()) else {
            self.download = Download::Answered {
                demand,
                reason: Some(DownloadRefusal::NotReady),
                total_len,
            };
            return;
        };
        match recording.sink.locate(&snapshot, demand.offset()) {
            Locate::PastEnd => {
                self.download = Download::Answered {
                    demand,
                    reason: None,
                    total_len,
                };
            }
            Locate::Overrun => {
                self.download = Download::Answered {
                    demand,
                    reason: Some(DownloadRefusal::Overrun),
                    total_len,
                };
            }
            Locate::Live(span) => {
                let len = span.len().min(demand.len());
                if len == 0 {
                    self.download = Download::Answered {
                        demand,
                        reason: None,
                        total_len,
                    };
                    return;
                }
                self.download = Download::Fetching {
                    demand,
                    total_len,
                    skip: span.skip(),
                    len,
                    sector: span.sector(),
                    // `skip` is below a sector and `len` at most a window, so
                    // the sum is at most `DOWNLOAD_STAGING_BYTES`.
                    sectors: (span.skip().saturating_add(len)).div_ceil(SECTOR_SIZE) as u64,
                    submitted: false,
                };
            }
        }
    }
}

/// Offer one record to one recording, answering whether it is settled — placed,
/// or dropped for a reason retrying cannot fix.
fn place(
    recordings: &mut [Recording; 2],
    which: Which,
    tap: &CheckedTap,
    bytes: &[u8],
    medium: &mut impl Medium,
) -> bool {
    let staging = medium.staging(which.area());
    let Some(recording) = recordings.get_mut(which.index()) else {
        return true;
    };
    match recording.sink.record(tap, bytes, staging) {
        // The two drops are terminal and already counted by the sink: no flush
        // and no roll makes an oversized or unencodable record placeable.
        Recorded::Placed { .. } | Recorded::Oversized { .. } | Recorded::Refused(_) => true,
        Recorded::SegmentFull => {
            if !recording.rolling && recording.sink.close_segment(staging).is_ok() {
                recording.rolling = true;
            }
            false
        }
        Recorded::StagingFull { .. } => false,
    }
}

#[cfg(test)]
mod tests;
