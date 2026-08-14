//! Both recordings on one block device: where each lives, what the staging
//! window is carved into, and the whole of the pass a protection domain runs —
//! completions, tap records, flushes and downloads.
//!
//! # A superblock never becomes visible before the payload it describes
//!
//! A device is free to commit writes in any order and to hold earlier ones in a
//! cache, so a power cut can leave a superblock whose durable cursor points into
//! payload bytes that never reached the medium — and a reader holding the disk
//! follows that cursor. A [`Job::Barrier`] between the two removes the
//! reordering; the [`Checkpointing`] states remove the remembering.
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
    Geometry, GeometryError, RingState, RingStateError, SECTOR_SIZE, SUPERBLOCK_BYTES,
    SUPERBLOCK_COPY_BYTES,
};
use lfw_metrics::{SNAPSHOT_BYTES, SNAPSHOT_SLOTS, encode_snapshot};
use wire::{
    Acknowledged, BATCH_BYTES, CheckedTap, DOWNLOAD_WINDOW_LEN, DownloadDemand, DownloadReader,
    DownloadRefusal, DownloadSink, LogRelayReader, RELAY_LINE_BYTES, StatsRelay, TAP_SNAP_LEN,
    TRANSCRIPT_MAX_ENTRIES, TapReader, TranscriptBatch, TranscriptEntry,
};

use lfw_pcapng::MIN_CUSTOM_BLOCK_LEN;

use crate::{
    Flush, InterfaceName, Locate, MAX_INTERFACES, Recorded, Sink, SinkConfig, SinkCounters,
    SinkError, Snapshot, TAIL_RESERVE,
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

    #[must_use]
    pub const fn sink(self) -> DownloadSink {
        match self {
            Self::Log => DownloadSink::Log,
            Self::Capture => DownloadSink::Capture,
        }
    }

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

    #[must_use]
    pub const fn extent(self) -> (u64, u64) {
        match self {
            Self::Log => (LOG_START_SECTOR, LOG_SECTORS),
            Self::Capture => (CAPTURE_START_SECTOR, CAPTURE_SECTORS),
        }
    }

    pub(crate) const fn geometry(self, capacity_sectors: u64) -> Result<Geometry, GeometryError> {
        let (start, sectors) = self.extent();
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
    /// A recording's superblock coming back at boot, naming its recording for
    /// [`Self::Barrier`]'s reason: the two reads share one staging area.
    Preload(Which),
    /// A recording's staged sectors going to the medium.
    Flush(Which),
    /// A device barrier between a recording's payload reaching the medium and the
    /// superblock that claims it. It names its recording, so a completion cannot
    /// release the other one's superblock.
    Barrier(Which),
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
/// No state machine: submission is asynchronous because the device is, and
/// hiding that behind a blocking call would put an unbounded wait on the one
/// domain that must keep draining a tap.
///
/// [`barrier`](Self::barrier) is a method rather than a fifth field of a
/// [`Transfer`], because a barrier addresses no range: as a transfer it would
/// need a sector and a length nothing reads, which every fake here asserts
/// containment on.
pub trait Medium {
    /// The bytes of one staging area — the source or destination of a transfer
    /// naming it. Always exactly `area.extent().1` bytes long.
    fn staging(&mut self, area: Area) -> &mut [u8];

    /// Whether the device honours a barrier.
    ///
    /// Where it does not, a checkpoint is written **without** one and durability
    /// is the device's to decide — a weaker recording, not a refusal, these rings
    /// being deliberately temporary. Waiting for a barrier such a device never
    /// completes would leave every extent claiming nothing durable forever, which
    /// is worse than an unordered checkpoint.
    fn orders_writes(&self) -> bool;

    /// Publish one transfer, answered later by [`poll`](Self::poll) under
    /// `job`.
    ///
    /// # Errors
    /// [`Refused`] when the device cannot take it now; nothing is published.
    fn submit(&mut self, job: Job, transfer: Transfer) -> Result<(), Refused>;

    /// Publish a barrier, answered later by [`poll`](Self::poll) under `job`. It
    /// completes only once everything already written is on the medium.
    ///
    /// # Errors
    /// [`Refused`] when the device cannot take it now; nothing is published.
    fn barrier(&mut self, job: Job) -> Result<(), Refused>;

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
    /// Metric readings framed into the log recording.
    pub snapshots_written: u64,
    /// Readings the publisher had moved on from before a settled one could be
    /// taken — a torn read, bounded and reported rather than retried.
    pub snapshots_missed: u64,
    /// Readings no recording could hold, which the assertion below proves none.
    pub snapshots_dropped: u64,
    /// Batches of console transcript lines framed into the log recording, batches
    /// no recording could hold — the assertion below proves none — and their lines.
    pub transcripts_written: u64,
    pub transcripts_dropped: u64,
    pub transcript_lines: u64,
}

/// How one recording's extent was opened at boot — a fresh ring looking exactly
/// like a continued one on every surface a node with no shell has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opened {
    /// A superblock a previous boot left. `generation`/`sequence` are the medium's;
    /// `offset` is where in that segment this boot picked the recording up.
    Resumed {
        generation: u64,
        sequence: u64,
        offset: u64,
    },
    /// Neither copy decoded: an unwritten extent, or one beyond use.
    FreshMedium,
    /// A superblock describing some other ring: the extent was rebound, or this is
    /// not the device it was. Recorded fresh **over it** and loudly.
    Rebound(RingStateError),
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
    /// Build one recording, continuing `stored` where it describes this ring. A
    /// state describing a *different* ring is not an error: the sink is built fresh
    /// over it — overwriting *both* copies — and the disagreement is returned.
    fn new(
        which: Which,
        capacity_sectors: u64,
        stored: Option<RingState>,
        interfaces: InterfaceNames,
        interface_count: usize,
        staging: &mut [u8],
    ) -> Result<(Self, Opened), DeckError> {
        let geometry = which
            .geometry(capacity_sectors)
            .map_err(|error| DeckError::Extent { which, error })?;
        let config = SinkConfig {
            geometry,
            snap_len: which.snap_len(),
            interfaces,
            interface_count,
        };
        let (sink, opened) = match stored {
            None => (Sink::new(config, staging), Opened::FreshMedium),
            Some(state) => match Sink::resume(config, &state, staging) {
                Ok(sink) => {
                    let resumed = state.writer();
                    (
                        Ok(sink),
                        Opened::Resumed {
                            generation: state.write_generation(),
                            sequence: resumed.sequence,
                            offset: resumed.offset as u64,
                        },
                    )
                }
                // Only a geometry disagreement survives.
                Err(SinkError::State(error)) => {
                    (Sink::new(config, staging), Opened::Rebound(error))
                }
                Err(error) => (Err(error), Opened::FreshMedium),
            },
        };
        let sink = sink.map_err(|error| DeckError::Sink { which, error })?;
        Ok((
            Self {
                which,
                sink,
                in_flight: None,
                submitted: false,
                rolling: false,
                // The extent identifies itself on the medium from the first
                // pass, so a reader that finds the disk knows what the bytes
                // past it are.
                checkpoint_due: true,
            },
            opened,
        ))
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
        first: u64,
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
        first: u64,
        skip: usize,
        len: usize,
    },
    /// An answer that carries no bytes, waiting to be handed over.
    Answered {
        demand: DownloadDemand,
        reason: Option<DownloadRefusal>,
        total_len: u64,
        first: u64,
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
        /// The oldest position of the named recording still on the medium, so a
        /// reader whose cursor the ring outran is told where to carry on from
        /// rather than merely that it cannot.
        first: u64,
    },
    /// Answer with a refusal, and why.
    Refuse {
        demand: DownloadDemand,
        reason: DownloadRefusal,
        total_len: u64,
        first: u64,
    },
}

/// The relay this domain drains console lines out of, and the storage one batch of
/// them is composed in. The protection domain owns it rather than [`Deck`], for
/// the reason the tap's scratch buffer is: a batch is a page that exists only
/// during a pass, and a [`Deck`] carrying it would move that page every time one
/// is returned.
pub struct Transcript<'region> {
    reader: LogRelayReader<'region>,
    batch: [u8; BATCH_BYTES],
    line: [u8; RELAY_LINE_BYTES],
}

/// What one composed batch was worth: bytes, and relay slots accounted for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Composed {
    bytes: usize,
    lines: u32,
}

impl<'region> Transcript<'region> {
    /// Hold a relay reader and the storage a batch is composed in.
    #[must_use]
    pub const fn new(reader: LogRelayReader<'region>) -> Self {
        Self {
            reader,
            batch: [0; BATCH_BYTES],
            line: [0; RELAY_LINE_BYTES],
        }
    }

    /// What the console says it dropped for want of a slot: its own claim, passed
    /// on rather than decided under.
    #[must_use]
    pub fn dropped_by_console(&self) -> u32 {
        self.reader.dropped_by_writer()
    }

    /// Compose one batch out of whatever the relay holds, without consuming it,
    /// or `None` where it holds nothing. Bounded by the relay's slot count and by
    /// the entries a batch may carry, both build constants and neither the
    /// console's — so a console that keeps publishing cannot extend a pass. One
    /// entry at a time because one line at a time is all this holds.
    fn compose(&mut self) -> Option<Composed> {
        let queued = self.reader.queued().min(TRANSCRIPT_MAX_ENTRIES as u32);
        if queued == 0 {
            return None;
        }
        let mut batch = TranscriptBatch::new(&mut self.batch);
        for at in 0..queued {
            let Some(read) = self.reader.peek(at, &mut self.line) else {
                break;
            };
            let Some(text) = self.line.get(..read.len) else {
                break;
            };
            let taken = batch.push(&TranscriptEntry {
                origin: read.origin,
                unix_nanos: read.stamp(),
                line: text,
            });
            if !taken {
                break;
            }
        }
        let lines = u32::from(batch.entries());
        let bytes = batch.finish();
        if lines == 0 {
            return None;
        }
        Some(Composed { bytes, lines })
    }
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
    /// How far the one checkpoint in progress has got. One at a time, because
    /// both recordings share one staging area.
    checkpointing: Checkpointing,
    /// The relay generation the last framed reading came from. A reading is
    /// written when this has moved, so the recording's snapshot rate is the
    /// publisher's; and it advances only once one is *placed*, so a deferred
    /// reading is retried against whatever the publisher holds by then.
    framed_generation: u32,
    counters: RecorderCounters,
}

/// Where the checkpoint being taken has reached.
///
/// What the states buy is that a superblock is submitted only from
/// [`Checkpointing::Ordered`], which nothing but a settled barrier — or a device
/// that negotiated none — reaches. The ordering is therefore unskippable rather
/// than remembered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Checkpointing {
    /// Nothing in progress; a recording with one due arms the next.
    Idle,
    /// A barrier is outstanding, so the payload a superblock would claim is not
    /// yet known to be on the medium.
    Barrier(Which),
    /// The payload is ordered against what follows it, so the superblock may go.
    Ordered(Which),
    /// The superblock itself is outstanding.
    Written(Which),
}

impl Deck {
    /// Build both recordings over a device of `capacity_sectors` and compose
    /// their opening prologues into the staging window.
    ///
    /// `stored` is what the medium said about each recording, in [`Which::ALL`]
    /// order. How each went is the second half of the return, nothing else on the
    /// node being able to supply that fact.
    ///
    /// # Errors
    /// [`DeckError`], naming the recording and what it refused.
    pub fn new(
        capacity_sectors: u64,
        stored: [Option<RingState>; 2],
        interfaces: InterfaceNames,
        interface_count: usize,
        medium: &mut impl Medium,
    ) -> Result<(Self, [Opened; 2]), DeckError> {
        let [log_state, capture_state] = stored;
        let (log, log_opened) = Recording::new(
            Which::Log,
            capacity_sectors,
            log_state,
            interfaces,
            interface_count,
            medium.staging(Area::Log),
        )?;
        let (capture, capture_opened) = Recording::new(
            Which::Capture,
            capacity_sectors,
            capture_state,
            interfaces,
            interface_count,
            medium.staging(Area::Capture),
        )?;
        Ok((
            Self {
                recordings: [log, capture],
                pending: None,
                pinned: None,
                download: Download::Idle,
                clock: None,
                checkpointing: Checkpointing::Idle,
                framed_generation: 0,
                counters: RecorderCounters::default(),
            },
            [log_opened, capture_opened],
        ))
    }

    /// Both extents as `(start_sector, sectors)`, for the record a boot owes an
    /// operator.
    #[must_use]
    pub const fn extents() -> [(u64, u64); 2] {
        [Which::Log.extent(), Which::Capture.extent()]
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
        relay: Option<&StatsRelay>,
        transcript: Option<&mut Transcript<'_>>,
    ) {
        self.clock = clock;
        for _ in 0..COMPLETION_BUDGET {
            if !self.settle(medium) {
                break;
            }
        }
        self.drain_tap(medium, tap, scratch);
        self.frame_snapshot(medium, relay);
        self.frame_transcript(medium, transcript);
        self.advance_download(medium);
        for index in 0..self.recordings.len() {
            self.advance(index, medium);
        }
        self.checkpoint(medium);
    }

    /// Take whatever reading the publisher has settled and frame it into the log
    /// recording, if it is newer than the last that went in; at most one per
    /// pass. **The log and not the capture**, the two rings differing by three
    /// to four orders of magnitude in rate.
    fn frame_snapshot(&mut self, medium: &mut impl Medium, relay: Option<&StatsRelay>) {
        let Some(relay) = relay else {
            return;
        };
        let Some((generation, image)) = relay.load(SNAPSHOT_SLOTS) else {
            // Nothing published yet, or every attempt lost to a publisher
            // mid-write; the next pass asks again.
            self.counters.snapshots_missed = self.counters.snapshots_missed.saturating_add(1);
            return;
        };
        if generation == self.framed_generation {
            return;
        }
        let mut body = [0u8; SNAPSHOT_BYTES];
        // Unreachable at the encoder's own length; a value, not an assertion.
        if encode_snapshot(&mut body, image.unix_nanos, image.values()).is_err() {
            self.counters.snapshots_dropped = self.counters.snapshots_dropped.saturating_add(1);
            self.framed_generation = generation;
            return;
        }
        let which = Which::Log;
        let staging = medium.staging(which.area());
        let Some(recording) = self.recordings.get_mut(which.index()) else {
            return;
        };
        match recording.sink.block(&body, staging) {
            Recorded::Placed { .. } => {
                // And complete the sector behind it: a reading is the largest
                // block written here and the only one written when nothing else
                // is happening, so without this the durable prefix a superblock
                // names would routinely end inside one — and a reader following
                // that cursor meets a block whose closing length never reached
                // the medium, a truncated file rather than a shorter one.
                let _ = recording.sink.seal(staging);
                self.counters.snapshots_written = self.counters.snapshots_written.saturating_add(1);
                self.framed_generation = generation;
            }
            // "Not now": the segment rolls or the staging drains, and the next
            // pass offers a fresher reading, the generation not being consumed.
            Recorded::SegmentFull => {
                if !recording.rolling && recording.sink.close_segment(staging).is_ok() {
                    recording.rolling = true;
                }
            }
            Recorded::StagingFull { .. } => {}
            // Neither is reachable for a reading: the assertion at the foot of
            // this module holds its length under a segment's. Counted rather
            // than asserted, nothing about a metric may fault this domain.
            Recorded::Oversized { .. } | Recorded::Refused(_) => {
                self.counters.snapshots_dropped = self.counters.snapshots_dropped.saturating_add(1);
                self.framed_generation = generation;
            }
        }
    }

    /// Take whatever console lines the relay holds and frame them into the log
    /// recording as one batch; at most one per pass. **The log and not the
    /// capture**, for the reason a reading goes there: the two rings differ by
    /// three to four orders of magnitude in rate.
    ///
    /// They are **peeked and not consumed** until the block is placed, so a
    /// rolling segment or a draining staging buffer is a "not now" and not a
    /// loss. The only loss on this path is the console's, when the relay filled
    /// because this domain was not draining it fast enough, and that is counted
    /// where it happens.
    fn frame_transcript(
        &mut self,
        medium: &mut impl Medium,
        transcript: Option<&mut Transcript<'_>>,
    ) {
        let Some(transcript) = transcript else {
            return;
        };
        let Some(taken) = transcript.compose() else {
            return;
        };
        let which = Which::Log;
        let staging = medium.staging(which.area());
        let Some(recording) = self.recordings.get_mut(which.index()) else {
            return;
        };
        let body = transcript.batch.get(..taken.bytes).unwrap_or_default();
        match recording.sink.block(body, staging) {
            Recorded::Placed { .. } => {
                // And complete the sector behind it, for the reason
                // `frame_snapshot` does: this too is a block written when
                // nothing else may be happening.
                let _ = recording.sink.seal(staging);
                transcript.reader.consume(taken.lines);
                self.counters.transcripts_written =
                    self.counters.transcripts_written.saturating_add(1);
                self.counters.transcript_lines = self
                    .counters
                    .transcript_lines
                    .saturating_add(u64::from(taken.lines));
            }
            // "Not now", with nothing consumed.
            Recorded::SegmentFull => {
                if !recording.rolling && recording.sink.close_segment(staging).is_ok() {
                    recording.rolling = true;
                }
            }
            Recorded::StagingFull { .. } => {}
            // Neither is reachable for a batch: the assertion at the foot of this
            // module holds the largest one's length under a segment's. The lines
            // are consumed rather than offered again — a batch refused on its
            // shape is refused for ever, and a relay never drained would then
            // stop carrying the transcript at all. Counted rather than asserted,
            // nothing about a transcript line may fault this domain.
            Recorded::Oversized { .. } | Recorded::Refused(_) => {
                transcript.reader.consume(taken.lines);
                self.counters.transcripts_dropped =
                    self.counters.transcripts_dropped.saturating_add(1);
            }
        }
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
            // A barrier moves no bytes, so there is no length to fall short of.
            Job::Barrier(_) => None,
            Job::Preload(_) => None,
            // The smaller length a `SuperblockWrite` names, so both copies
            // replaced and one moved still reads as short.
            Job::Checkpoint(which) => (self.checkpointing == Checkpointing::Written(which))
                .then_some(SUPERBLOCK_COPY_BYTES),
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
            Job::Preload(_) => {
                self.counters.completions_unexpected =
                    self.counters.completions_unexpected.saturating_add(1);
            }
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
            Job::Barrier(which) => {
                if self.checkpointing == Checkpointing::Barrier(which) {
                    // A failed barrier writes no superblock: an extent claiming
                    // bytes the device may not hold is worse than one claiming
                    // none. The next data flush arms `checkpoint_due` again,
                    // which bounds the retries to actual progress.
                    self.checkpointing = if failed {
                        Checkpointing::Idle
                    } else {
                        Checkpointing::Ordered(which)
                    };
                } else {
                    self.counters.completions_unexpected =
                        self.counters.completions_unexpected.saturating_add(1);
                }
            }
            Job::Checkpoint(which) => {
                if self.checkpointing == Checkpointing::Written(which) {
                    self.checkpointing = Checkpointing::Idle;
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
                    first,
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
                            first,
                        }
                    } else {
                        Download::Fetched {
                            demand,
                            total_len,
                            first,
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
            recording.in_flight = recording.sink.take_flush(staging);
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

    /// Advance the one checkpoint in progress by a step, or arm one where a
    /// recording has one due and the shared staging area is free.
    fn checkpoint(&mut self, medium: &mut impl Medium) {
        match self.checkpointing {
            Checkpointing::Idle => self.order_checkpoint(medium),
            Checkpointing::Ordered(which) => self.write_superblock(which, medium),
            // Outstanding at the device: the pass has nothing to add until a
            // completion moves it on.
            Checkpointing::Barrier(_) | Checkpointing::Written(_) => {}
        }
    }

    /// Take the barrier one recording's due checkpoint has to sit behind.
    fn order_checkpoint(&mut self, medium: &mut impl Medium) {
        let Some(which) = self
            .recordings
            .iter()
            .find(|recording| recording.checkpoint_due)
            .map(|recording| recording.which)
        else {
            return;
        };
        if !medium.orders_writes() {
            // Straight through rather than a pass later: a device with no flush
            // must not also be one whose extents checkpoint half as often.
            self.checkpointing = Checkpointing::Ordered(which);
            self.write_superblock(which, medium);
            return;
        }
        match medium.barrier(Job::Barrier(which)) {
            Ok(()) => {
                self.checkpointing = Checkpointing::Barrier(which);
                if let Some(recording) = self.recordings.get_mut(which.index()) {
                    recording.checkpoint_due = false;
                }
            }
            Err(Refused) => {
                self.counters.medium_refusals = self.counters.medium_refusals.saturating_add(1);
            }
        }
    }

    /// Compose and submit `which`'s checkpoint superblock, the payload it
    /// describes already ordered against it.
    fn write_superblock(&mut self, which: Which, medium: &mut impl Medium) {
        let Some(sector) = self
            .recordings
            .get(which.index())
            .map(|recording| recording.sink.superblock_sector())
        else {
            self.checkpointing = Checkpointing::Idle;
            return;
        };
        let staging = medium.staging(Area::Superblock);
        // The three below are unreachable — the window holds every area the
        // layout names and a `Which` indexes both recordings — and each abandons
        // the checkpoint: a state left `Ordered` would stop the deck
        // checkpointing at all.
        let Some(image) = staging.get_mut(..SUPERBLOCK_BYTES) else {
            self.checkpointing = Checkpointing::Idle;
            return;
        };
        let Ok(image) = <&mut [u8; SUPERBLOCK_BYTES]>::try_from(image) else {
            self.checkpointing = Checkpointing::Idle;
            return;
        };
        let Some(recording) = self.recordings.get_mut(which.index()) else {
            self.checkpointing = Checkpointing::Idle;
            return;
        };
        let Ok(write) = recording.sink.superblock(image) else {
            // A cursor no superblock can carry: the recording keeps going and
            // the checkpoint is simply not written, which is what an
            // unidentified extent already looks like to a reader.
            recording.checkpoint_due = false;
            self.checkpointing = Checkpointing::Idle;
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
                self.checkpointing = Checkpointing::Written(which);
                if let Some(recording) = self.recordings.get_mut(which.index()) {
                    recording.checkpoint_due = false;
                }
            }
            // Left `Ordered`, so the next pass offers the same superblock behind
            // the barrier already taken rather than ordering those bytes twice.
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
        // Before what the demand *asks* for is decided: the pair rides every
        // request, refused ones included.
        self.acknowledge(demand.acknowledged());
        let Some(sink) = demand.sink() else {
            self.download = Download::Answered {
                demand,
                reason: Some(DownloadRefusal::NoSuchSink),
                total_len: 0,
                first: 0,
            };
            return;
        };
        let Some(reader) = demand.reader() else {
            self.download = Download::Answered {
                demand,
                reason: Some(DownloadRefusal::NoSuchReader),
                total_len: 0,
                first: 0,
            };
            return;
        };
        let which = Which::named(sink);
        if matches!(reader, DownloadReader::Ring) {
            self.find(demand, which);
            return;
        }
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
                    first: 0,
                };
            }
        }
    }

    /// Give both recordings the positions the management server says it has
    /// durably taken, and arm a checkpoint for each whose cursor moved.
    ///
    /// Every bound on the claim is the sink's. Armed rather than written, so it
    /// rides the checkpoint the payload's barrier already orders — it needs none
    /// of its own, a cursor persisted early naming bytes already on the medium.
    fn acknowledge(&mut self, acked: Acknowledged) {
        for recording in &mut self.recordings {
            if recording
                .sink
                .acknowledge_reader(acked.of(recording.which.sink()))
            {
                recording.checkpoint_due = true;
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
                first,
            } => Some(match reason {
                Some(reason) => {
                    self.counters.downloads_refused =
                        self.counters.downloads_refused.saturating_add(1);
                    Served::Refuse {
                        demand,
                        reason,
                        total_len,
                        first,
                    }
                }
                None => {
                    self.counters.downloads_served =
                        self.counters.downloads_served.saturating_add(1);
                    Served::Deliver {
                        demand,
                        bytes: &[],
                        total_len,
                        first,
                    }
                }
            }),
            Download::Fetched {
                demand,
                total_len,
                first,
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
                    first,
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
                    first: 0,
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

    /// Resolve one absolute ring position and either answer it or put a read out
    /// for it.
    ///
    /// Nothing is sealed and nothing is pinned. A seal pads the open sector so
    /// that what a download promises is a whole file, and it is a **write** to
    /// the recording — performed on the reader's account, and bounded only by
    /// how often that reader asks. The channel reads whatever the medium has
    /// already taken instead, so a ring cursor costs the recording nothing; what
    /// it gives up is that a frame may end mid-block, which the wire does not
    /// care about because what travels is a byte stream and not a block.
    fn find(&mut self, demand: DownloadDemand, which: Which) {
        let Some(recording) = self.recordings.get_mut(which.index()) else {
            self.download = Download::Answered {
                demand,
                reason: Some(DownloadRefusal::NotReady),
                total_len: 0,
                first: 0,
            };
            return;
        };
        let total_len = recording.sink.durable_position();
        // Answered on every outcome, the refusal included, and that is what makes
        // an overrun something a reader carries on from: the position it asked
        // for is gone and this is the oldest one that is not.
        let first = recording.sink.first_position();
        match recording.sink.find(demand.offset()) {
            Locate::PastEnd => {
                self.download = Download::Answered {
                    demand,
                    reason: None,
                    total_len,
                    first,
                };
            }
            // Counted by the reader that lost its place rather than here: this
            // side knows a position went missing, and the domain holding the
            // cursor is the one that knows which reader it belonged to.
            Locate::Overrun => {
                self.download = Download::Answered {
                    demand,
                    reason: Some(DownloadRefusal::Overrun),
                    total_len,
                    first,
                };
            }
            Locate::Live(span) => {
                let len = span.len().min(demand.len());
                if len == 0 {
                    self.download = Download::Answered {
                        demand,
                        reason: None,
                        total_len,
                        first,
                    };
                    return;
                }
                self.download = Download::Fetching {
                    demand,
                    total_len,
                    first,
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

    /// Resolve one offset against a pinned snapshot and either answer it or put
    /// a read out for it.
    fn locate(&mut self, demand: DownloadDemand, which: Which, snapshot: Snapshot) {
        let total_len = snapshot.total_len();
        let Some(recording) = self.recordings.get_mut(which.index()) else {
            self.download = Download::Answered {
                demand,
                reason: Some(DownloadRefusal::NotReady),
                total_len,
                first: 0,
            };
            return;
        };
        // The recording's own oldest position, which is what the word means
        // whichever reader asked. A snapshot reader counts its offsets from a
        // pinned origin instead and does not read it; publishing it anyway is
        // what keeps one reply shape rather than two.
        let first = recording.sink.first_position();
        match recording.sink.locate(&snapshot, demand.offset()) {
            Locate::PastEnd => {
                self.download = Download::Answered {
                    demand,
                    reason: None,
                    total_len,
                    first,
                };
            }
            Locate::Overrun => {
                self.download = Download::Answered {
                    demand,
                    reason: Some(DownloadRefusal::Overrun),
                    total_len,
                    first,
                };
            }
            Locate::Live(span) => {
                let len = span.len().min(demand.len());
                if len == 0 {
                    self.download = Download::Answered {
                        demand,
                        reason: None,
                        total_len,
                        first,
                    };
                    return;
                }
                self.download = Download::Fetching {
                    demand,
                    total_len,
                    first,
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

// A metric reading always fits the recording it is framed into, both lengths
// being build constants — the catalogue decides one and `SEGMENT_BYTES` the
// other — which is what makes `Sink::block`'s two terminal answers unreachable
// above. The framing sits in front of the reading and the reserve behind it.
const _: () = {
    assert!(SNAPSHOT_BYTES + MIN_CUSTOM_BLOCK_LEN + TAIL_RESERVE < SEGMENT_BYTES);
    // And a batch of console transcript lines, by the same arithmetic: the
    // relay's slot count and slot width are build constants, so the largest batch
    // is one too — which is what makes `Sink::block`'s two terminal answers
    // unreachable for a batch as well. The staging buffer must hold one beside
    // the reserve, a batch being composed elsewhere and copied in.
    assert!(BATCH_BYTES + MIN_CUSTOM_BLOCK_LEN + TAIL_RESERVE < SEGMENT_BYTES);
    assert!(LOG_STAGING_BYTES > BATCH_BYTES + MIN_CUSTOM_BLOCK_LEN + TAIL_RESERVE);
};

#[cfg(test)]
mod tests;
