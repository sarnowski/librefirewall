#![no_main]
#![no_std]

//! The recorder protection domain: it owns the appliance's block device (QEMU
//! q35, virtio-blk 1.0 PCI), is the only domain that can put a byte on
//! persistent storage, and turns the forwarder's observations into two pcapng
//! recordings an operator can download.
//!
//! # Adversary
//!
//! Three adversaries. A hostile or malfunctioning **block device**: this
//! domain maps the device's configuration space, the MMIO window its BAR is
//! relocated to, the DMA region holding the request virtqueue, and the staging
//! window payload crosses in, so the capacity it claims, the completions it
//! publishes, the status bytes it DMAs and the sector contents it answers a
//! read with are all untrusted. DMA is unconfined — this platform has no
//! IOMMU — so an address handed to the device is an address it may
//! write. A **byzantine neighbour** on both handovers: the forwarder writes the
//! tap ring's annotations, and the management domain writes the download
//! request's sink, offset and length. And **untrusted network traffic**, one
//! remove behind the tap: a recorded payload is bytes off a wire, written out
//! and never parsed here.
//!
//! # What is decided elsewhere
//!
//! Nearly all of it, in host-testable crates. Which devices are acceptable and how the handshake
//! runs live in `lfw_blk::bringup`; which byte of the staging window a request
//! may name lives in `lfw_blk::io`; the boot-time proof that the path reaches a
//! medium lives in `lfw_blk::smoke`; and the whole recording pass — where each
//! recording lives, how a segment rolls, how a download is pinned, located and
//! answered — lives in `lfw_recorder::deck`, against a fake medium that
//! refuses, fails and forges. What is left here is the [`Medium`]
//! implementation: it moves bytes and attributes completions, and it is the
//! layering residue this package's coverage exclusion records.
//!
//! # Everything this domain touches is patched in at build time
//!
//! Hardware topology is static, fixed at build time, so this driver performs no PCI
//! enumeration: it holds capabilities for exactly one function's ECAM page.
//! Each symbol comes from `systems/qemu-x86_64/librefirewall.system`:
//!
//! | symbol | what it names |
//! |---|---|
//! | `ecam_vaddr` | the 4 KiB ECAM page of the pinned PCI function 00:05.0 |
//! | `bar_vaddr` | the `lfw_blk::BAR_WINDOW_SIZE` MMIO window the BAR is relocated to |
//! | `dma_vaddr` | the zeroed `lfw_blk::DMA_REGION_SIZE` region holding the request virtqueue |
//! | `io_vaddr` | the `lfw_blk::BLK_IO_REGION_SIZE` staging window payload crosses in |
//! | `tap_vaddr`, `tap_consume_vaddr` | the capture tap, read-only and its cursor read-write |
//! | `dl_request_vaddr`, `dl_reply_vaddr` | the download handover, the reverse way round |
//! | `bar_paddr`, `dma_paddr`, `io_paddr` | those physical bases, for the device |
//!
//! Unlike a NIC driver there is no region here that is an address and nothing
//! more: this domain both composes and reads everything its device transfers,
//! so it maps all three of the regions it hands over physical addresses for.
//!
//! # Scheduling: it busy-loops at the drivers' priority
//!
//! Microkit has no periodic wakeup and this driver takes no interrupt (no
//! MSI-X, no INTx) by design, so it polls by never returning from `init`. The
//! system description fixes what follows: **priority 1**, shared with the three
//! NIC drivers and the console, so mutual progress rests on seL4's round-robin
//! between equal-priority threads. That is why no wait here may be unbounded —
//! every step of a pass is bounded by a constant of `lfw_recorder`'s or
//! `lfw_blk`'s and never by anything a peer or the device controls.
//!
//! # The console is a domain, not a print statement
//!
//! A record is a typed `Event` put into this domain's own log ring, which the
//! console domain renders. `debug_println!` compiles to a kernel debug syscall
//! the release kernel does not implement, so a domain that failed bring-up
//! would park silently in exactly the profile that ships.
//!
//! # Channel 0 sends and never receives
//!
//! This domain's end of the download channel carries `notify="true"` and the
//! management domain's carries `notify="false"`, so it holds a send capability
//! and no peer holds one on it. It notifies management whenever a reply lands;
//! the entrypoint below satisfies `sel4_microkit::Handler` and is unreachable
//! by capability rather than by control flow, exactly as a driver's is.

use lfw_blk::bringup::{self, BringUpError, Live, MappedBlkDevice};
use lfw_blk::io::{IoRegion, IoRegionUnusable, IoSpan};
use lfw_blk::request::{Completed, Operation, Outcome, Requests, SLOTS, SubmitError, Token};
use lfw_blk::smoke::{self, Report, SmokeError};
use lfw_blk::{
    BLK_IO_REGION_SIZE, BlkVirtqueue, Refusal as BlkRefusal, RefusalDetail as BlkRefusalDetail,
    SECTOR_SIZE,
};
use lfw_log::{Domain, DomainDetail, DomainState, Event, Refusal, RefusalDetail, RingSink, Sink};
use lfw_metrics::StatsShard;
use lfw_recorder::deck::{
    Area, Completion, Deck, DeckError, Ended, InterfaceNames, Job, Medium, Opened, Polled,
    RESERVED_SECTORS, Refused, STAGING_END, Served, Transcript, Transfer, Which,
};
use lfw_recorder::preload::{self, PreloadError};
use lfw_recorder::{InterfaceName, MAX_INTERFACES};
use pd_runtime::{BlockCounters, PdClock, attach_region, log_sample, recorder_sample};
use sel4_microkit::{Channel, memory_region_symbol, protection_domain, var};
use virtio::pci::PciConfig;
use wire::{
    ClockCalibration, DownloadReply, DownloadRequest, DownloadResponder, LogConsume, LogRecords,
    LogRelay, LogRelayConsume, StatsRelay, TAP_SNAP_LEN, TapConsume, TapRecords,
};

/// The management domain, which is told whenever a reply lands.
const MANAGEMENT: Channel = Channel::new(0);

// The staging layout is `lfw_recorder`'s and the region is `lfw_blk`'s, so this
// is the one place both are visible and the only place the two can be held to
// each other.
const _: () = assert!(
    STAGING_END <= BLK_IO_REGION_SIZE,
    "the recording layout does not fit the blk_io grant"
);

// Likewise the boot proof's witness sector: it writes before any superblock has
// been read, so the sector must be one this layout claims.
const _: () = assert!(
    smoke::WITNESS_SECTOR < RESERVED_SECTORS,
    "the boot proof writes outside the front the recordings reserve"
);

/// Why this domain could not start.
enum StartupError {
    /// The staging region's patched physical address cannot be a DMA base. Its
    /// own variant rather than a `BringUpError`, because it is refused before
    /// the device is touched at all and names a different artifact: the
    /// `io_paddr` setvar rather than anything the device said.
    StagingUnusable(IoRegionUnusable),
    /// The device refused bring-up, or build data it is programmed with was
    /// rejected.
    Device(BringUpError),
    /// The device came up and the path to the medium did not work.
    Proof(SmokeError),
    /// A recording's superblock could not be read back, so this boot cannot say
    /// whether the extent holds an earlier run of its ring. Refused rather than
    /// recorded fresh: the boot proof has already moved a sector each way by
    /// then, so a device that will not answer here has stopped answering, and
    /// overwriting evidence on the strength of a read that failed is the one
    /// thing a recording appliance must not do.
    Preload(PreloadError),
    /// The device came up and is too small — or otherwise unfit — for the
    /// recordings this build is configured with.
    Recordings(DeckError),
}

impl From<BringUpError> for StartupError {
    fn from(error: BringUpError) -> Self {
        Self::Device(error)
    }
}

impl From<SmokeError> for StartupError {
    fn from(error: SmokeError) -> Self {
        Self::Proof(error)
    }
}

impl From<DeckError> for StartupError {
    fn from(error: DeckError) -> Self {
        Self::Recordings(error)
    }
}

impl From<PreloadError> for StartupError {
    fn from(error: PreloadError) -> Self {
        Self::Preload(error)
    }
}

impl StartupError {
    /// This refusal as the console record of it.
    fn refusal(&self) -> Refusal {
        match self {
            Self::StagingUnusable(IoRegionUnusable { paddr }) => Refusal {
                cause: "staging-region-dma-base",
                detail: RefusalDetail::One(*paddr),
                // Refused before `PciConfig::new`, so no configuration-space
                // access has happened: the BAR is unplaced, bus mastering is
                // still off, and there is nothing to have signalled through.
                signalled: false,
            },
            Self::Device(error) => convert(error.refusal()),
            Self::Proof(error) => convert(error.refusal()),
            Self::Preload(error) => preload_refusal(*error),
            Self::Recordings(error) => recordings_refusal(*error),
        }
    }
}

/// A block driver's refusal in the console's vocabulary.
///
/// Field for field because `lfw_blk::Refusal` is a structural copy of
/// `lfw_log::Refusal`, declared so that a device-class crate need not depend on
/// the log vocabulary (`lfw_blk`'s crate header).
fn convert(refusal: BlkRefusal) -> Refusal {
    Refusal {
        cause: refusal.cause,
        detail: match refusal.detail {
            BlkRefusalDetail::None => RefusalDetail::None,
            BlkRefusalDetail::One(value) => RefusalDetail::One(value),
            BlkRefusalDetail::Two(first, second) => RefusalDetail::Two(first, second),
        },
        signalled: refusal.signalled,
    }
}

/// A superblock that could not be read back, in the same vocabulary.
///
/// **The first number is always the extent's first sector**, which is what says
/// which of the two recordings the read was for — the tokens name the failure
/// and the recordings share them, exactly as the two virtio bring-up trees share
/// theirs and `domain=` tells them apart.
///
/// An extent that is not a ring is reported with the token
/// [`recordings_refusal`] already gives it: it is the same fact, found earlier
/// only because the superblock's address comes from the same geometry, and a
/// second token for it would ask an operator to learn one condition twice.
fn preload_refusal(error: PreloadError) -> Refusal {
    let (start_sector, _) = error.which().extent();
    let (cause, detail) = match error {
        PreloadError::Extent { error, .. } => ("recording-extent-unusable", extent_detail(error)),
        PreloadError::Refused { .. } => (
            "recording-superblock-refused",
            RefusalDetail::One(start_sector),
        ),
        PreloadError::Silent { .. } => (
            "recording-superblock-silent",
            RefusalDetail::Two(start_sector, u64::from(preload::POLL_BUDGET)),
        ),
        PreloadError::Misattributed { .. } => (
            "recording-superblock-misattributed",
            RefusalDetail::One(start_sector),
        ),
        PreloadError::Failed { .. } => (
            "recording-superblock-failed",
            RefusalDetail::One(start_sector),
        ),
        PreloadError::Short { delivered, .. } => (
            "recording-superblock-short",
            RefusalDetail::Two(start_sector, delivered as u64),
        ),
        PreloadError::Unstaged { len, .. } => (
            "recording-superblock-unstaged",
            RefusalDetail::Two(start_sector, len as u64),
        ),
    };
    Refusal {
        cause,
        detail,
        // The device is live by then — the boot proof moved a sector each way
        // through it — and nothing here writes `STATUS_FAILED` to it.
        signalled: true,
    }
}

/// The extent this boot recorded **over**: a superblock that decoded and
/// described some other ring.
///
/// Not a start-up refusal — the domain goes on recording, which is the whole
/// decision — so it is announced on a `Ready` record like the store domain's
/// refused package. It is loud because it has to be: what was overwritten was
/// somebody's evidence, and the two numbers are what disagreed.
fn rebound_refusal(start_sector: u64, error: lfw_capture_ring::RingStateError) -> Refusal {
    Refusal {
        cause: "recording-extent-rebound",
        detail: match error {
            lfw_capture_ring::RingStateError::StartSectorMismatch { stored, .. }
            | lfw_capture_ring::RingStateError::SectorsMismatch { stored, .. } => {
                RefusalDetail::Two(start_sector, stored)
            }
            lfw_capture_ring::RingStateError::SegmentBytesMismatch { stored, .. } => {
                RefusalDetail::Two(start_sector, stored as u64)
            }
            // `RingState::check` compares the three fields above and nothing
            // else, so a variant here is one added upstream: it reaches the
            // console as its cause and this extent's sector, which is a smaller
            // loss than a second number that means nothing.
            _ => RefusalDetail::One(start_sector),
        },
        signalled: true,
    }
}

/// A recording this device cannot hold, in the same vocabulary. The device is
/// live by then, so `signalled` is true: it has been told to run and this
/// domain is about to stop feeding it.
fn recordings_refusal(error: DeckError) -> Refusal {
    Refusal {
        cause: match error {
            DeckError::Extent { .. } => "recording-extent-unusable",
            _ => "recording-sink-unusable",
        },
        detail: deck_detail(error),
        signalled: true,
    }
}

/// The two numbers an extent refusal turns on, where its variant carries them.
fn extent_detail(error: lfw_capture_ring::GeometryError) -> RefusalDetail {
    match error {
        lfw_capture_ring::GeometryError::ExtentOutsideDevice {
            start, capacity, ..
        } => RefusalDetail::Two(start, capacity),
        lfw_capture_ring::GeometryError::SegmentNotSectorMultiple { bytes }
        | lfw_capture_ring::GeometryError::SegmentTooSmall { bytes } => {
            RefusalDetail::One(bytes as u64)
        }
        lfw_capture_ring::GeometryError::ExtentNotSegmentMultiple {
            sectors,
            segment_sectors,
        } => RefusalDetail::Two(sectors, segment_sectors),
        lfw_capture_ring::GeometryError::TooFewSegments { segments } => {
            RefusalDetail::One(segments)
        }
        lfw_capture_ring::GeometryError::ExtentExceedsByteAddressing { sectors } => {
            RefusalDetail::One(sectors)
        }
        // Every variant this build's constants can reach names its numbers
        // above; a variant added upstream reaches the console as its cause and
        // no numbers, which is a smaller loss than a wrong pair.
        _ => RefusalDetail::None,
    }
}

/// The recordings' side of a start-up refusal, as two console numbers.
fn deck_detail(error: DeckError) -> RefusalDetail {
    match error {
        DeckError::Extent { error, .. } => extent_detail(error),
        // A sink refusal names an encoder or an interface count, neither of
        // which is a pair a console line reads usefully; the cause is the whole
        // of it.
        _ => RefusalDetail::None,
    }
}

fn announce(sink: &dyn Sink, state: DomainState, detail: DomainDetail) {
    sink.emit(&Event::Domain {
        domain: Domain::Recorder,
        state,
        detail,
    });
}

/// The interface names a recording's prologue carries.
///
/// Compiled in rather than read from `cfg`: this domain maps no configuration
/// region at all, because a grant it cannot reach is authority for nothing.
/// Reading the document is a later change, and the grant returns with the code
/// that attaches it. Two names, matching the build's two dataplane ports, so a
/// reader sees the ports rather than bare indices.
fn interface_names() -> (InterfaceNames, usize) {
    let mut names = [InterfaceName::new(""); MAX_INTERFACES];
    if let Some(slot) = names.get_mut(0) {
        *slot = InterfaceName::new("port0");
    }
    if let Some(slot) = names.get_mut(1) {
        *slot = InterfaceName::new("port1");
    }
    (names, 2)
}

#[protection_domain]
fn init() -> Recorder {
    // Before anything else that could have something to say. The region is
    // zeroed by the kernel, so it is a valid empty ring the moment it is
    // mapped, and the console domain drains it whenever it comes up — which is
    // what lets a record written here survive to be printed.
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let stats: &'static StatsShard = attach_region!(stats_vaddr: StatsShard);
    let clock: &'static ClockCalibration = attach_region!(clock_vaddr: ClockCalibration);
    let tap: &'static TapRecords = attach_region!(tap_vaddr: TapRecords);
    let tap_consume: &'static TapConsume = attach_region!(tap_consume_vaddr: TapConsume);
    let request: &'static DownloadRequest = attach_region!(dl_request_vaddr: DownloadRequest);
    let reply: &'static DownloadReply = attach_region!(dl_reply_vaddr: DownloadReply);
    let relay: &'static StatsRelay = attach_region!(stats_relay_vaddr: StatsRelay);
    let transcript: &'static LogRelay = attach_region!(log_relay_vaddr: LogRelay);
    let transcript_consume: &'static LogRelayConsume =
        attach_region!(log_relay_consume_vaddr: LogRelayConsume);
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(clock));

    announce(&sink, DomainState::Starting, DomainDetail::None);
    match bring_up(&sink) {
        Ok(Started {
            report,
            mut device,
            blocks,
        }) => {
            let (names, count) = interface_names();
            match open_recordings(report.capacity_sectors, names, count, &mut device) {
                Ok((deck, opened)) => {
                    announce(
                        &sink,
                        DomainState::Ready,
                        DomainDetail::Medium {
                            capacity_sectors: report.capacity_sectors,
                            leading_word: report.probe_word,
                        },
                    );
                    // Where each recording is, so an operator with the disk can
                    // find it — and, beside it, whether this boot continued what
                    // was already there. There is no other way to learn either:
                    // the node has no shell and no CLI, and an appliance that
                    // silently started fresh over a customer's evidence looks
                    // exactly like one that carried it on.
                    for (which, opened) in Which::ALL.into_iter().zip(opened) {
                        announce_recording(&sink, which, opened);
                    }
                    run(
                        Loop {
                            deck,
                            device,
                            tap: tap_consume.reader(tap),
                            responder: reply.responder(request),
                            stats,
                            relay,
                            // Taken once and kept, which is what the relay asks
                            // of a reader: a second handle restarts at slot zero
                            // and re-frames every line the first consumed.
                            transcript: Transcript::new(transcript_consume.reader(transcript)),
                            clock: PdClock::new(clock),
                            blocks,
                        },
                        &sink,
                    )
                }
                Err(error) => refuse(&sink, error),
            }
        }
        Err(error) => refuse(&sink, error),
    }
}

/// Read what the medium already says about each recording, then build both over
/// it.
///
/// The read comes first because its answer is what decides whether a ring is
/// continued or written over, and it is synchronous because there is nothing
/// yet to interleave with: `init` has not returned, no tap is being drained, and
/// the boot proof has just done the same thing one sector at a time. Every wait
/// inside it is bounded by a constant of `lfw_recorder`'s.
fn open_recordings(
    capacity_sectors: u64,
    names: InterfaceNames,
    count: usize,
    device: &mut BlockMedium<'_>,
) -> Result<(Deck, [Opened; 2]), StartupError> {
    let stored = preload::read_superblocks(capacity_sectors, device)?;
    Ok(Deck::new(capacity_sectors, stored, names, count, device)?)
}

/// One recording's extent and how this boot opened it, as the two — or three —
/// records an operator gets.
fn announce_recording(sink: &dyn Sink, which: Which, opened: Opened) {
    let (start_sector, sectors) = which.extent();
    announce(
        sink,
        DomainState::Ready,
        DomainDetail::Extent {
            start_sector,
            sectors,
        },
    );
    let detail = match opened {
        Opened::Resumed {
            generation,
            sequence,
            opened,
        } => DomainDetail::RecordingResumed {
            start_sector,
            generation,
            sequence,
            opened,
        },
        Opened::FreshMedium => DomainDetail::RecordingFresh {
            start_sector,
            rebound: false,
        },
        Opened::Rebound(_) => DomainDetail::RecordingFresh {
            start_sector,
            rebound: true,
        },
    };
    announce(sink, DomainState::Ready, detail);
    if let Opened::Rebound(error) = opened {
        announce(
            sink,
            DomainState::Ready,
            DomainDetail::Refusal(rebound_refusal(start_sector, error)),
        );
    }
}

/// Record the whole reason and park. With no shell and no CLI on the node
/// this record is all an operator gets.
fn refuse(sink: &dyn Sink, error: StartupError) -> Recorder {
    announce(
        sink,
        DomainState::Refused,
        DomainDetail::Refusal(error.refusal()),
    );
    Recorder
}

/// Everything the poll loop holds for the domain's life.
///
/// The reader and the responder are held by value because each *is* this
/// domain's position in its channel: a second would restart at slot zero and
/// re-deliver, or reuse a sequence number the first has outstanding.
struct Loop<'region> {
    deck: Deck,
    device: BlockMedium<'region>,
    tap: wire::TapReader<'region>,
    responder: DownloadResponder<'region>,
    stats: &'region StatsShard,
    /// The whole metric reading the management domain publishes, read-only here
    /// and the only way this domain learns any counter but its own.
    relay: &'region StatsRelay,
    /// The console lines the console domain publishes, read-only here, and the
    /// only way this domain learns what any other domain has said about itself.
    /// It maps no other domain's log ring and this is not one: it carries lines
    /// the console has already printed rather than records a peer wrote.
    transcript: Transcript<'region>,
    clock: PdClock<'region>,
    blocks: BlockCounters,
}

/// The poll loop, entered once and never left.
fn run(mut held: Loop<'_>, sink: &RingSink<'_, PdClock<'_>>) -> ! {
    let Loop {
        deck,
        device,
        tap,
        responder,
        stats,
        relay,
        transcript,
        clock,
        blocks,
    } = &mut held;
    let mut scratch = [0u8; TAP_SNAP_LEN];
    loop {
        // Read afresh each pass: a cached triple would be a stopped clock that
        // no longer says so.
        deck.poll(
            device,
            tap,
            &mut scratch,
            clock.calibration(),
            Some(relay),
            Some(transcript),
        );
        // One demand at a time, which is all the channel admits: taking a
        // second while the first is unanswered would leave the requester
        // waiting on a sequence nothing will publish.
        if !deck.serving()
            && let Some(demand) = responder.take()
        {
            deck.demand(demand);
        }
        if let Some(served) = deck.answer(device) {
            match served {
                Served::Deliver {
                    demand,
                    bytes,
                    total_len,
                    first,
                } => {
                    responder.deliver(demand, bytes, total_len, first);
                }
                Served::Refuse {
                    demand,
                    reason,
                    total_len,
                    first,
                } => responder.refuse(demand, reason, total_len, first),
            }
            // The management domain is `notified`-driven, so a reply nobody is
            // told about waits for whatever wakes that domain next.
            MANAGEMENT.notify();
        }
        *blocks = device.take_blocks(*blocks);
        stats.publish(
            &recorder_sample(
                device.capacity_sectors(),
                *blocks,
                device.faults(),
                deck.counters(),
                log_sample(sink.dropped(), sink.refused()),
            )
            .values(),
        );
    }
}

/// What a successful bring-up established.
struct Started<'region> {
    report: Report,
    device: BlockMedium<'region>,
    blocks: BlockCounters,
}

/// Map this domain's device regions, bring the device up, and prove the path to
/// the medium.
fn bring_up(sink: &dyn Sink) -> Result<Started<'static>, StartupError> {
    let ecam = memory_region_symbol!(ecam_vaddr: *mut u8).as_ptr();
    let bar = memory_region_symbol!(bar_vaddr: *mut u8).as_ptr();
    let dma = memory_region_symbol!(dma_vaddr: *mut u8).as_ptr();
    let io_base = memory_region_symbol!(io_vaddr: *mut u8).as_ptr();
    let bar_paddr = *var!(bar_paddr: usize = 0);
    let dma_paddr = *var!(dma_paddr: usize = 0) as u64;
    let io_paddr = *var!(io_paddr: usize = 0) as u64;

    // SAFETY: `io_base` is the mapped `blk_io` region of
    // `systems/qemu-x86_64/librefirewall.system`, which maps it at `io_vaddr`
    // into this PD alone, at `lfw_blk::BLK_IO_REGION_SIZE` bytes — held equal to
    // that constant by `xtask::sysdesc`'s rule for the region — and holds the
    // mapping for the PD's whole life. That is exactly `IoRegion::attach`'s
    // contract; the address it is paired with is checked rather than trusted,
    // which is why this is the one region whose base can be refused here.
    let mut io =
        unsafe { IoRegion::attach(io_base, io_paddr) }.map_err(StartupError::StagingUnusable)?;

    // SAFETY: `ecam` is the mapped 4 KiB ECAM page of the pinned PCI function,
    // guaranteed by `systems/qemu-x86_64/librefirewall.system`, which maps
    // `ecam3` at `ecam_vaddr` into this PD alone and holds the mapping for the
    // PD's whole life — exactly `PciConfig::new`'s contract.
    let config = unsafe { PciConfig::new(ecam) };

    let placed = bringup::identify(&config)?.place_bar(&config, bar_paddr)?;
    // SAFETY: `bar` is the `bar3` region of
    // `systems/qemu-x86_64/librefirewall.system`, guaranteeing
    // `lfw_blk::BAR_WINDOW_SIZE` bytes — the constant `xtask::sysdesc` holds
    // that region's `size` equal to — page-aligned (so far beyond the eight
    // bytes `capacity` needs) and mapped for the PD's whole life, at the
    // physical address `place_bar` just programmed: `PlacedBar::map`'s
    // contract. Nothing is required of the device's own offsets — `identify`
    // bounded them against the same constant.
    let negotiated = unsafe { placed.map(bar) }
        .acknowledge()?
        .negotiate_features()?;
    announce(
        sink,
        DomainState::Negotiated,
        DomainDetail::Features(negotiated.features()),
    );
    let capacity_sectors = negotiated.capacity_sectors();
    let live: Live<MappedBlkDevice> = negotiated.configure_queue(dma_paddr)?.go_live();

    // SAFETY: `dma` is the `blk_dma` region of
    // `systems/qemu-x86_64/librefirewall.system`, guaranteeing a zeroed,
    // page-aligned (so 16-byte-aligned) mapping of `lfw_blk::DMA_REGION_SIZE`
    // bytes shared with this device alone; `lfw_blk`'s layout assertions prove
    // the queue fits below `HEADER_AREA_OFFSET`, which is where the per-slot
    // headers start — `SplitVirtqueue::new`'s contract.
    let queue = unsafe { BlkVirtqueue::new(dma) };
    // SAFETY: the same region and the address `configure_queue` just programmed
    // the device with — and refused had it been zero, misaligned or wrapping,
    // which is the enforcer `Requests::attach` names for it. The queue
    // passed in was built over this very pointer one statement ago, and
    // `xtask::sysdesc` holds the region's `size` equal to `DMA_REGION_SIZE`.
    let mut requests = unsafe { Requests::attach(dma, dma_paddr, queue, capacity_sectors) };

    let report = smoke::prove(&mut requests, &mut io, &live)?;

    // The proof is two successful requests of one sector each, counted here
    // rather than inside the proof so `lfw_blk` stays free of the metric
    // vocabulary — the same split `lfw_metrics` rests on everywhere.
    let mut blocks = BlockCounters::default();
    blocks.completed(Operation::Read, SECTOR_SIZE as u32);
    blocks.completed(Operation::Write, SECTOR_SIZE as u32);
    Ok(Started {
        report,
        device: BlockMedium::new(requests, io, live),
        blocks,
    })
}

/// One submitted transfer, kept outside the DMA region so no part of the
/// attribution is a value the device can rewrite.
struct Outstanding {
    token: Token,
    job: Job,
    operation: Operation,
}

/// The block device as `lfw_recorder` needs it: staging bytes, submission, and
/// completions attributed to the job that produced them.
///
/// This is the whole of what the recording pass could not decide for itself,
/// and it decides nothing: which sector, which area and which job are all its
/// caller's, and what comes back is reported rather than judged.
pub struct BlockMedium<'region> {
    requests: Requests<'region>,
    io: IoRegion<'region>,
    live: Live<MappedBlkDevice>,
    /// One entry per driver slot, which is the most that can be in flight.
    outstanding: [Option<Outstanding>; SLOTS],
    completed: BlockCounters,
}

impl<'region> BlockMedium<'region> {
    fn new(
        requests: Requests<'region>,
        io: IoRegion<'region>,
        live: Live<MappedBlkDevice>,
    ) -> Self {
        Self {
            requests,
            io,
            live,
            outstanding: [const { None }; SLOTS],
            completed: BlockCounters::default(),
        }
    }

    fn capacity_sectors(&self) -> u64 {
        self.requests.capacity_sectors()
    }

    fn faults(&self) -> lfw_blk::request::RequestFaults {
        self.requests.faults()
    }

    /// Fold what the device has moved since the last call into `blocks`.
    fn take_blocks(&mut self, blocks: BlockCounters) -> BlockCounters {
        let mut total = blocks;
        total.reads = total.reads.saturating_add(self.completed.reads);
        total.read_bytes = total.read_bytes.saturating_add(self.completed.read_bytes);
        total.writes = total.writes.saturating_add(self.completed.writes);
        total.write_bytes = total.write_bytes.saturating_add(self.completed.write_bytes);
        self.completed = BlockCounters::default();
        total
    }
}

/// One staging area as a bounded span of the block-I/O window. `None` is unreachable
/// and a value rather than a panic, the layout assertions and `STAGING_END` between
/// them putting every area on a sector inside the region.
fn area_span(area: Area) -> Option<IoSpan> {
    let (offset, len) = area.extent();
    IoSpan::at_offset(offset, u32::try_from(len).ok()?)
}

impl Medium for BlockMedium<'_> {
    fn staging(&mut self, area: Area) -> &mut [u8] {
        match area_span(area) {
            Some(span) => self.io.staging(span),
            None => Default::default(),
        }
    }

    /// Whether `VIRTIO_BLK_F_FLUSH` was negotiated with this device. The
    /// question is the driver's to answer and not this domain's to assume: a
    /// flush submitted to a device that never negotiated one is a request
    /// virtio does not define.
    fn orders_writes(&self) -> bool {
        self.live.flush_supported()
    }

    fn barrier(&mut self, job: Job) -> Result<(), Refused> {
        let Some(slot) = self.outstanding.iter().position(Option::is_none) else {
            return Err(Refused);
        };
        // A flush addresses no range and carries no data segment, so the sector,
        // address and length below are not part of the request and are not read
        // (`lfw_blk::request::Operation::Flush`). Zero rather than a plausible
        // number, so a driver that started reading them would fail visibly.
        let token = match self.requests.submit(Operation::Flush, 0, 0, 0) {
            Ok(token) => token,
            Err(_) => return Err(Refused),
        };
        if let Some(entry) = self.outstanding.get_mut(slot) {
            *entry = Some(Outstanding {
                token,
                job,
                operation: Operation::Flush,
            });
        }
        self.live.ring();
        Ok(())
    }

    fn submit(&mut self, job: Job, transfer: Transfer) -> Result<(), Refused> {
        let Some(slot) = self.outstanding.iter().position(Option::is_none) else {
            return Err(Refused);
        };
        let operation = if transfer.write {
            Operation::Write
        } else {
            Operation::Read
        };
        let (offset, _) = transfer.area.extent();
        let at = offset.saturating_add(transfer.at);
        let Ok(len) = u32::try_from(transfer.len) else {
            return Err(Refused);
        };
        // The data segment as one `IoSpan`, the whole of what bounds its far end:
        // `Requests::submit` weighs the sector range against the medium's capacity
        // and the address against its alignment, knowing nothing of this region.
        let Some(span) = IoSpan::at_offset(at, len) else {
            return Err(Refused);
        };
        let token = match self.requests.submit(
            operation,
            transfer.sector,
            self.io.span_paddr(span),
            span.bytes(),
        ) {
            Ok(token) => token,
            // Every refusal is backpressure or a range this driver will not
            // name; the caller offers it again, so none is lost silently.
            Err(SubmitError::NoFreeSlot | SubmitError::QueueFull) => return Err(Refused),
            Err(_) => return Err(Refused),
        };
        if let Some(entry) = self.outstanding.get_mut(slot) {
            *entry = Some(Outstanding {
                token,
                job,
                operation,
            });
        }
        // One doorbell per request rather than one per pass: a recording moves
        // a handful of transfers per pass, so batching would save a store and
        // cost a scheduling round of latency on a download.
        self.live.ring();
        Ok(())
    }

    fn poll(&mut self) -> Option<Polled> {
        let Completed {
            token,
            operation,
            outcome,
            bytes,
        } = self.requests.poll()?;
        let Some(entry) = self
            .outstanding
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|held| held.token == token))
            .and_then(Option::take)
        else {
            // A chain this table holds no job for. Not `None`, which says the device
            // is idle and would let a replayed entry end the pass's drain unseen.
            return Some(Polled::Unattributed);
        };
        if outcome == Outcome::Ok {
            self.completed.completed(entry.operation, bytes);
        }
        let _ = operation;
        Some(Polled::Settled(Completion {
            job: entry.job,
            ended: if outcome == Outcome::Ok {
                // The request layer's own count, clamped to what was asked for.
                Ended::Ok {
                    delivered: bytes as usize,
                }
            } else {
                Ended::Failed
            },
        }))
    }
}

/// Returned only by a rejected start, where returning parks the domain in the
/// Microkit event loop with the poll loop never entered: idle and harmless
/// rather than faulted.
struct Recorder;

impl sel4_microkit::Handler for Recorder {
    type Error = sel4_microkit::Infallible;

    /// Unreachable; see the crate header on channel 0.
    fn notified(&mut self, _channels: sel4_microkit::ChannelSet) -> Result<(), Self::Error> {
        Ok(())
    }
}
