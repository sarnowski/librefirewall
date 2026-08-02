#![no_main]
#![no_std]

//! The recorder protection domain: it owns the appliance's block device (QEMU
//! q35, virtio-blk 1.0 PCI), is the only domain that can put a byte on
//! persistent storage, and turns the forwarder's observations into two pcapng
//! recordings an operator can download.
//!
//! # Adversary
//!
//! Three of CONCEPT §7.1's. A hostile or malfunctioning **block device**: this
//! domain maps the device's configuration space, the MMIO window its BAR is
//! relocated to, the DMA region holding the request virtqueue, and the staging
//! window payload crosses in, so the capacity it claims, the completions it
//! publishes, the status bytes it DMAs and the sector contents it answers a
//! read with are all untrusted. DMA is unconfined — no IOMMU on this platform
//! (CONCEPT §7.2) — so an address handed to the device is an address it may
//! write. A **byzantine neighbour** on both handovers: the forwarder writes the
//! tap ring's annotations, and the management domain writes the download
//! request's sink, offset and length. And **untrusted network traffic**, one
//! remove behind the tap: a recorded payload is bytes off a wire, written out
//! and never parsed here.
//!
//! # What is decided elsewhere
//!
//! Nearly all of it (LAY-2). Which devices are acceptable and how the handshake
//! runs live in `lfw_blk::bringup`; which byte of the staging window a request
//! may name lives in `lfw_blk::io`; the boot-time proof that the path reaches a
//! medium lives in `lfw_blk::smoke`; and the whole recording pass — where each
//! recording lives, how a segment rolls, how a download is pinned, located and
//! answered — lives in `lfw_recorder::deck`, against a fake medium that
//! refuses, fails and forges. What is left here is the [`Medium`]
//! implementation: it moves bytes and attributes completions, and it is the
//! LAY-2 residue this package's coverage exclusion records.
//!
//! # Everything this domain touches is patched in at build time
//!
//! Hardware topology is static (CONCEPT §12.3), so this driver performs no PCI
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
//! `lfw_blk`'s and never by anything a peer or the device controls (ENG-4).
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
use lfw_blk::io::{IoRegion, IoRegionUnusable};
use lfw_blk::request::{Completed, Operation, Outcome, Requests, SLOTS, SubmitError, Token};
use lfw_blk::smoke::{self, Report, SmokeError};
use lfw_blk::{
    BLK_IO_REGION_SIZE, BlkVirtqueue, Refusal as BlkRefusal, RefusalDetail as BlkRefusalDetail,
    SECTOR_SIZE,
};
use lfw_log::{Domain, DomainDetail, DomainState, Event, Refusal, RefusalDetail, RingSink, Sink};
use lfw_metrics::StatsShard;
use lfw_recorder::deck::{
    Area, Completion, Deck, DeckError, Ended, InterfaceNames, Job, Medium, Refused, STAGING_END,
    Served, Transfer,
};
use lfw_recorder::{InterfaceName, MAX_INTERFACES};
use pd_runtime::{BlockCounters, PdClock, attach_region, log_sample, recorder_sample};
use sel4_microkit::{Channel, memory_region_symbol, protection_domain, var};
use virtio::pci::PciConfig;
use wire::{
    ClockCalibration, DownloadReply, DownloadRequest, DownloadResponder, LogConsume, LogRecords,
    TAP_SNAP_LEN, TapConsume, TapRecords,
};

/// The management domain, which is told whenever a reply lands.
const MANAGEMENT: Channel = Channel::new(0);

// The staging layout is `lfw_recorder`'s and the region is `lfw_blk`'s, so this
// is the one place both are visible and the only place the two can be held to
// each other (DOC-7).
const _: () = assert!(
    STAGING_END <= BLK_IO_REGION_SIZE,
    "the recording layout does not fit the blk_io grant"
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
/// Compiled in rather than read from `cfg`: the configuration document is
/// mapped read-only here and reading it is a later change (see the system
/// description beside that row). Two names, matching the build's two dataplane
/// ports, so a reader sees the ports rather than bare indices.
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
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(clock));

    announce(&sink, DomainState::Starting, DomainDetail::None);
    match bring_up(&sink) {
        Ok(Started {
            report,
            mut device,
            blocks,
        }) => {
            let (names, count) = interface_names();
            match Deck::new(report.capacity_sectors, names, count, &mut device) {
                Ok(deck) => {
                    announce(
                        &sink,
                        DomainState::Ready,
                        DomainDetail::Medium {
                            capacity_sectors: report.capacity_sectors,
                            leading_word: report.probe_word,
                        },
                    );
                    // Where each recording is, so an operator with the disk can
                    // find it. There is no other way to learn it: no shell, no
                    // CLI (CONCEPT §11).
                    for (start_sector, sectors) in Deck::extents() {
                        announce(
                            &sink,
                            DomainState::Ready,
                            DomainDetail::Extent {
                                start_sector,
                                sectors,
                            },
                        );
                    }
                    run(
                        Loop {
                            deck,
                            device,
                            tap: tap_consume.reader(tap),
                            responder: reply.responder(request),
                            stats,
                            clock: PdClock::new(clock),
                            blocks,
                        },
                        &sink,
                    )
                }
                Err(error) => refuse(&sink, StartupError::from(error)),
            }
        }
        Err(error) => refuse(&sink, error),
    }
}

/// Record the whole reason and park. With no shell and no CLI (CONCEPT §11)
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
        clock,
        blocks,
    } = &mut held;
    let mut scratch = [0u8; TAP_SNAP_LEN];
    loop {
        // Read afresh each pass: a cached triple would be a stopped clock that
        // no longer says so.
        deck.poll(device, tap, &mut scratch, clock.calibration());
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
                } => {
                    responder.deliver(demand, bytes, total_len);
                }
                Served::Refuse {
                    demand,
                    reason,
                    total_len,
                } => responder.refuse(demand, reason, total_len),
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
    // which is the enforcer `Requests::attach` names for it (DOC-7). The queue
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

impl Medium for BlockMedium<'_> {
    fn staging(&mut self, area: Area) -> &mut [u8] {
        let (offset, len) = area.extent();
        // The layout is `lfw_recorder`'s and the assertion above holds it
        // inside the region, so the fallback is unreachable and is a value
        // rather than a panic (ENG-5).
        self.io
            .staging()
            .get_mut(offset..)
            .and_then(|tail| tail.get_mut(..len))
            .unwrap_or_default()
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
        // The area's own sector, which `IoSector::new` bounds by the window: a
        // layout that did not fit is refused here rather than handed to a
        // device that would DMA outside the region.
        let Some(sector) = lfw_blk::io::IoSector::new(at / SECTOR_SIZE) else {
            return Err(Refused);
        };
        let Ok(len) = u32::try_from(transfer.len) else {
            return Err(Refused);
        };
        let token = match self.requests.submit(
            operation,
            transfer.sector,
            self.io.sector_paddr(sector),
            len,
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

    fn poll(&mut self) -> Option<Completion> {
        let Completed {
            token,
            operation,
            outcome,
            bytes,
        } = self.requests.poll()?;
        let entry = self
            .outstanding
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|held| held.token == token))?
            .take()?;
        if outcome == Outcome::Ok {
            self.completed.completed(entry.operation, bytes);
        }
        let _ = operation;
        Some(Completion {
            job: entry.job,
            ended: if outcome == Outcome::Ok {
                Ended::Ok
            } else {
                Ended::Failed
            },
        })
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
