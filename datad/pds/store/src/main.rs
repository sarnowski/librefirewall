#![no_main]
#![no_std]

//! The store protection domain: it owns the appliance's **store medium** (QEMU
//! q35, virtio-blk 1.0 PCI at function 00:06.0), is the only domain that can
//! read or write a byte of the appliance's own persistent state, and establishes
//! the one thing a reboot must not change — which appliance this is.
//!
//! On a fresh medium it mints an identity: a 128-bit name, a P-256 keypair, a
//! self-signed onboarding certificate binding the two, and the fingerprint an
//! administrator authenticates the node by. It writes all of that durably and
//! reports the name and the fingerprint on the console. On every later boot it
//! loads the same record, holds it to itself, and reports that the same
//! appliance returned and how far its state has advanced. Then it parks.
//!
//! # It also gives that identity up
//!
//! One sector of the medium is a **factory-reset request**, and it is the only way
//! into an appliance with no shell and no input path. Finding it, this domain
//! clears the request and waits for the flush behind it, overwrites every sector
//! the layout claims, reports what it destroyed, and mints afresh — a reset node is
//! immediately onboardable, which is what unowned means.
//!
//! Two things about that sequence are decisions rather than consequences. The
//! request is answered **before** the record is judged, because a record this build
//! refuses is exactly the state a reset is the remedy for. And the request is
//! cleared **first**: a power cut in that order leaves a node an operator
//! re-onboards, and in the opposite order one that resets on every boot forever,
//! which nobody can onboard at all. One outcome is recoverable and the other is a
//! brick.
//!
//! # Adversary
//!
//! Two, and the second is the reason this domain exists at all.
//!
//! A hostile or malfunctioning **block device**: this domain maps the device's
//! configuration space, the MMIO window its BAR is relocated to, the DMA region
//! holding the request virtqueue, and the staging window the record crosses in,
//! so the capacity it claims, the completions it publishes, the status bytes it
//! DMAs and the sector contents it answers a read with are all untrusted. DMA is
//! unconfined — this platform has no IOMMU — so an address handed to the device
//! is an address it may write.
//!
//! And **a physical attacker who wrote the medium at leisure**. Every byte of
//! the state record is external input: a sector the device mis-addressed, a
//! record composed offline, a whole store carried over from another deployment.
//! Nothing off this medium is acted on until it has carried the magic, the
//! version, a digest over itself, lengths inside their bounds and zero in every
//! byte the layout does not name (`lfw_store`'s decode), has been checked
//! against the layout *this build* compiles against (`lfw_store::StateImage::check`),
//! and has been held to itself as an identity (`lfw_store::verify`). Every
//! refusal is a typed cause token on the console and a parked domain — never a
//! repaired record, because an appliance that signs under a key whose
//! certificate names a different one cannot be authenticated and does not know
//! it.
//!
//! There is no third adversary, and that is a property of the system
//! description rather than of this file: this domain holds no network region, no
//! configuration region and no channel to any other domain, so no packet has a
//! path to these bytes whatever a compromise reaches.
//!
//! # This domain seeds its own generator, and that is the point
//!
//! The device key descends from a generator this domain seeds from `RDRAND`
//! itself. Taking the seed — or the key — over a channel would let the domain at
//! the other end reproduce it, which for a device identity is the whole of what
//! custody means. `RDRAND` and `CPUID` are unprivileged instructions carried by
//! no capability, so a domain seeding itself is granted nothing here; the draw,
//! its health check and the generator are `lfw_crypto`'s, so the *rules* are
//! shared even though the generator is not.
//!
//! # What is decided elsewhere
//!
//! Nearly all of it, in host-testable crates. Which devices are acceptable and
//! how the handshake runs live in `lfw_blk::bringup`; which byte of the staging
//! window a request may name lives in `lfw_blk::io`; what the bytes on the medium
//! *mean* lives in `lfw_store`, and so does minting and verifying an identity,
//! against a generator a test can fix; the hardware draw, its health check and
//! the generator it seeds are `lfw_crypto`'s. What is left here is the device,
//! the `unsafe` that maps it, the transfers and the wiring, and it is the
//! layering residue this package's coverage exclusion records.
//!
//! # Everything this domain touches is patched in at build time
//!
//! Hardware topology is static, fixed at build time, so this driver performs no
//! PCI enumeration: it holds capabilities for exactly one function's ECAM page.
//! Each symbol comes from `systems/qemu-x86_64/librefirewall.system`:
//!
//! | symbol | what it names |
//! |---|---|
//! | `ecam_vaddr` | the 4 KiB ECAM page of the pinned PCI function 00:06.0 |
//! | `bar_vaddr` | the `lfw_blk::BAR_WINDOW_SIZE` MMIO window the BAR is relocated to |
//! | `dma_vaddr` | the zeroed `lfw_blk::DMA_REGION_SIZE` region holding the request virtqueue |
//! | `io_vaddr` | the `lfw_blk::BLK_IO_REGION_SIZE` staging window the record crosses in |
//! | `bar_paddr`, `dma_paddr`, `io_paddr` | those physical bases, for the device |
//!
//! # It runs once and parks
//!
//! Unlike the recorder there is no poll loop: establishing an identity is a
//! thing that happens once, and this domain has no peer to serve. It runs to
//! completion in `init` and parks where nothing can reach it — no channel in
//! either direction — exactly as the clock, hardware-probe and cryptography
//! domains do. What it waits on inside that run is bounded by `lfw_blk`'s own
//! poll budget and by nothing the device controls.
//!
//! # No key material reaches any surface
//!
//! The private scalar is drawn, folded into a certificate and written to the
//! medium, and that is the whole of where it goes. No console record, no metric
//! and no `Debug` in this file names it; the two records this domain emits carry
//! a public name and a public-key digest. The medium's copy is plaintext there
//! deliberately and for want of anywhere to keep a wrapping key, which is why
//! physical possession of the store *is* identity theft and why that boundary is
//! the one the ownership model rests on.

use lfw_blk::bringup::{self, BringUpError, Live, MappedBlkDevice};
use lfw_blk::io::{IoRegion, IoRegionUnusable, IoSpan};
use lfw_blk::request::{Completed, Operation, Outcome, Requests, SubmitError, Token};
use lfw_blk::{
    BLK_IO_REGION_SIZE, BlkVirtqueue, Refusal as BlkRefusal, RefusalDetail as BlkRefusalDetail,
    SECTOR_SIZE,
};
use lfw_crypto::{Drbg, EntropyError, NodeEntropy, SEED_MATERIAL_LEN, hardware_seed, zeroize};
use lfw_log::{Domain, DomainDetail, DomainState, Event, Refusal, RefusalDetail, RingSink, Sink};
use lfw_metrics::StatsShard;
use lfw_store::{
    CheckedState, Cleared, Copies, IdentityError, Onboarding, RESET_REQUEST_BYTES,
    RESET_REQUEST_SECTOR, ResetRequest, STATE_A_SECTOR, STATE_COPY_BYTES, STORE_SECTORS, State,
    StateError, StateWrite, decode_state, encode_state, mint, verify,
};
use pd_runtime::{
    BlockCounters, PdClock, StoreIdentity, attach_region, log_sample, read_timestamp_counter,
    store_sample,
};
use sel4_microkit::{
    ChannelSet, Handler, Infallible, memory_region_symbol, protection_domain, var,
};
use virtio::pci::PciConfig;
use wire::{ClockCalibration, LogConsume, LogRecords};

/// Bytes both copies of the state record occupy, and so the one transfer this
/// domain ever makes.
const BOTH_COPIES: usize = 2 * STATE_COPY_BYTES;

// The record crosses the staging window whole, in one transfer, so the window
// must hold it. Asserted here because this is the one place `lfw_store`'s layout
// and `lfw_blk`'s grant are both visible, and neither crate promises the other's
// number.
const _: () = assert!(
    BOTH_COPIES <= BLK_IO_REGION_SIZE,
    "the state record does not fit the staging window"
);

// The device is polled for one completion at a time, so the driver's slot table
// is never contended and a `submit` refusal is a device fault rather than
// backpressure. Stated as the assertion it is: a table of one would make the
// barrier's own submission fail while the write it orders was still outstanding.
const _: () = assert!(lfw_blk::request::SLOTS >= 2);

/// Sectors one overwrite transfer covers: the whole staging window, so a factory
/// reset erases the layout in the fewest transfers the grant allows. Three of
/// them, for a store of [`STORE_SECTORS`].
const OVERWRITE_SECTORS: u64 = (BLK_IO_REGION_SIZE / SECTOR_SIZE) as u64;

/// Poll iterations one completion is waited for.
///
/// `lfw_blk::smoke`'s budget, reused rather than re-chosen: it is the same
/// question — how long a working device may take to answer one single-sector
/// request — and a second number would be a second thing to justify. Reaching it
/// is a device that has stopped answering, which is a refusal and not a retry.
const POLL_BUDGET: u32 = lfw_blk::smoke::POLL_BUDGET;

/// Why this domain could not establish the appliance's identity.
enum StartupError {
    /// The staging region's patched physical address cannot be a DMA base. Its
    /// own variant rather than a `BringUpError`, because it is refused before
    /// the device is touched at all and names a different artifact: the
    /// `io_paddr` setvar rather than anything the device said.
    StagingUnusable(IoRegionUnusable),
    /// The device refused bring-up, or build data it is programmed with was
    /// rejected.
    Device(BringUpError),
    /// The device came up and claims fewer sectors than this build's store
    /// layout occupies, so a slot this layout names would be a sector the device
    /// does not have.
    TooSmall { capacity: u64, needed: u64 },
    /// The medium carries a record, and it is not one this build may act on.
    Record(StateError),
    /// The medium carries a record this build may act on, and it does not
    /// describe one coherent identity.
    Identity(IdentityError),
    /// The generator this node's key would descend from cannot be seeded.
    Entropy(EntropyError),
    /// The generator was seeded and did not advance between two draws, which no
    /// published vector can catch: a vector fixes the seed and reads one draw.
    GeneratorStalled,
}

/// Why one transfer of the record did not happen.
#[derive(Clone, Copy)]
enum TransferError {
    /// The driver would not take the request. Every reason it gives is a range
    /// this driver will not name or a slot table that is full, and neither is
    /// reachable here: one request is outstanding at a time and every range is a
    /// compile-time constant of the layout.
    Refused,
    /// The device answered a completion for something else, which is a device
    /// that has lost track of its own queue.
    Misattributed,
    /// The device answered, and the answer was a failure.
    Failed,
    /// The device answered fewer bytes than were asked for. A short answer on a
    /// record read whole is a record with a hole in it, and continuing would
    /// decode whatever the staging window held before.
    Short { bytes: u32 },
    /// The device did not answer within [`POLL_BUDGET`].
    Silent,
}

/// Which transfer refused, so a cause token names the step rather than the class.
#[derive(Clone, Copy)]
enum Step {
    Read,
    Write,
    Barrier,
    /// Reading the factory-reset request sector.
    ResetRead,
    /// Clearing that request, which every irreversible step of a reset sits
    /// behind.
    ResetClear,
    /// Overwriting what the medium held.
    Overwrite,
}

impl Step {
    const fn cause(self, error: TransferError) -> &'static str {
        match (self, error) {
            (Self::Read, TransferError::Refused) => "state-read-refused",
            (Self::Read, TransferError::Misattributed) => "state-read-misattributed",
            (Self::Read, TransferError::Failed) => "state-read-failed",
            (Self::Read, TransferError::Short { .. }) => "state-read-short",
            (Self::Read, TransferError::Silent) => "state-read-unanswered",
            (Self::Write, TransferError::Refused) => "state-write-refused",
            (Self::Write, TransferError::Misattributed) => "state-write-misattributed",
            (Self::Write, TransferError::Failed) => "state-write-failed",
            (Self::Write, TransferError::Short { .. }) => "state-write-short",
            (Self::Write, TransferError::Silent) => "state-write-unanswered",
            (Self::Barrier, TransferError::Refused) => "state-barrier-refused",
            (Self::Barrier, TransferError::Misattributed) => "state-barrier-misattributed",
            (Self::Barrier, TransferError::Failed) => "state-barrier-failed",
            // A flush addresses no range and carries no data segment, so a
            // length it reports is not a length of anything. It cannot be
            // short and the variant is answered rather than asserted.
            (Self::Barrier, TransferError::Short { .. }) => "state-barrier-short",
            (Self::Barrier, TransferError::Silent) => "state-barrier-unanswered",
            (Self::ResetRead, TransferError::Refused) => "reset-read-refused",
            (Self::ResetRead, TransferError::Misattributed) => "reset-read-misattributed",
            (Self::ResetRead, TransferError::Failed) => "reset-read-failed",
            (Self::ResetRead, TransferError::Short { .. }) => "reset-read-short",
            (Self::ResetRead, TransferError::Silent) => "reset-read-unanswered",
            (Self::ResetClear, TransferError::Refused) => "reset-clear-refused",
            (Self::ResetClear, TransferError::Misattributed) => "reset-clear-misattributed",
            (Self::ResetClear, TransferError::Failed) => "reset-clear-failed",
            (Self::ResetClear, TransferError::Short { .. }) => "reset-clear-short",
            (Self::ResetClear, TransferError::Silent) => "reset-clear-unanswered",
            (Self::Overwrite, TransferError::Refused) => "reset-overwrite-refused",
            (Self::Overwrite, TransferError::Misattributed) => "reset-overwrite-misattributed",
            (Self::Overwrite, TransferError::Failed) => "reset-overwrite-failed",
            (Self::Overwrite, TransferError::Short { .. }) => "reset-overwrite-short",
            (Self::Overwrite, TransferError::Silent) => "reset-overwrite-unanswered",
        }
    }
}

impl From<BringUpError> for StartupError {
    fn from(error: BringUpError) -> Self {
        Self::Device(error)
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
            Self::TooSmall { capacity, needed } => Refusal {
                cause: "store-medium-too-small",
                detail: RefusalDetail::Two(*capacity, *needed),
                signalled: true,
            },
            Self::Record(error) => Refusal {
                cause: record_cause(*error),
                detail: record_detail(*error),
                signalled: true,
            },
            Self::Identity(error) => Refusal {
                cause: error.cause(),
                detail: RefusalDetail::None,
                signalled: true,
            },
            Self::Entropy(error) => match error {
                EntropyError::NotSupported { feature_word } => Refusal {
                    cause: "rdrand-not-supported",
                    detail: RefusalDetail::One(u64::from(*feature_word)),
                    signalled: true,
                },
                EntropyError::Exhausted { word } => Refusal {
                    cause: "rdrand-exhausted",
                    detail: RefusalDetail::One(*word as u64),
                    signalled: true,
                },
                EntropyError::Stuck { word } => Refusal {
                    cause: "rdrand-output-stuck",
                    detail: RefusalDetail::One(*word as u64),
                    signalled: true,
                },
            },
            Self::GeneratorStalled => Refusal {
                cause: "generator-repeated-a-draw",
                detail: RefusalDetail::None,
                signalled: true,
            },
        }
    }
}

/// A block driver's refusal in the console's vocabulary.
///
/// Field for field because `lfw_blk::Refusal` is a structural copy of
/// `lfw_log::Refusal`, declared so that a device-class crate need not depend on
/// the log vocabulary.
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

/// One transfer's refusal, named by the step it happened at.
fn transfer_refusal(step: Step, error: TransferError) -> Refusal {
    Refusal {
        cause: step.cause(error),
        detail: match error {
            TransferError::Short { bytes } => RefusalDetail::One(u64::from(bytes)),
            _ => RefusalDetail::None,
        },
        // The device is live by then: it has been told to run and this domain is
        // about to stop feeding it.
        signalled: true,
    }
}

/// The token a record this build will not act on is refused with.
///
/// One per variant rather than one for the class, because each names a different
/// thing to go and look at: a record from another build's layout is a store
/// carried over, and a slot table that disagrees with itself is a record nothing
/// this appliance runs wrote.
const fn record_cause(error: StateError) -> &'static str {
    match error {
        StateError::CertificateTooLong { .. } => "stored-certificate-too-long",
        StateError::DocumentTooLong { .. } => "stored-document-too-long",
        StateError::SlotNamedTwice { .. } => "stored-slot-named-twice",
        StateError::SlotOutsideArray { .. } => "stored-slot-outside-array",
        StateError::NamedSlotEmpty { .. } => "stored-named-slot-empty",
        StateError::LayoutMismatch { .. } => "stored-layout-mismatch",
        // A variant added upstream reaches the console as this token and no
        // numbers, which is a smaller loss than a wrong one.
        _ => "stored-record-unusable",
    }
}

/// The numbers a record refusal turns on, where its variant carries them.
const fn record_detail(error: StateError) -> RefusalDetail {
    match error {
        StateError::CertificateTooLong { len } | StateError::DocumentTooLong { len } => {
            RefusalDetail::One(len as u64)
        }
        StateError::SlotNamedTwice { slot } | StateError::NamedSlotEmpty { slot } => {
            RefusalDetail::One(slot as u64)
        }
        StateError::SlotOutsideArray { slot } => RefusalDetail::One(slot as u64),
        StateError::LayoutMismatch {
            stored_slots,
            stored_slot_sectors,
        } => RefusalDetail::Two(stored_slots as u64, stored_slot_sectors as u64),
        _ => RefusalDetail::None,
    }
}

fn announce(sink: &dyn Sink, state: DomainState, detail: DomainDetail) {
    sink.emit(&Event::Domain {
        domain: Domain::Store,
        state,
        detail,
    });
}

/// Seconds since the Unix epoch, as this node believes them.
///
/// From the clock domain's published calibration where there is one, and from a
/// compile-time floor where there is not: the onboarding certificate needs a
/// validity window, and a node whose clock never published would otherwise write
/// one nothing accepts. The floor is not a security control and is not treated
/// as one — the appliance's time is an unauthenticated real-time-clock reading
/// either way, which is enough to bound a certificate and not enough to judge an
/// adversary by.
fn wall_seconds(clock: &PdClock<'_>) -> i64 {
    /// Seconds at the start of 2026, which is before any image carrying this
    /// code was built and after every year a `UTCTime` cannot name.
    const FLOOR: u64 = 1_767_225_600;
    let seconds = clock
        .calibration()
        .map_or(FLOOR, |calibration| {
            calibration.utc(read_timestamp_counter()).as_nanos() / 1_000_000_000
        })
        .max(FLOOR);
    // Saturating: the profile takes a signed instant, and a reading past the
    // signed range is a clock nobody believes rather than a reason to wrap into
    // a date before the epoch.
    i64::try_from(seconds).unwrap_or(i64::MAX)
}

/// What one boot established, whatever the verdict: the counters go to the shard
/// on both paths, so a refused run still reports how far it got.
struct BootOutcome {
    verdict: Result<Established, Refusal>,
    capacity_sectors: u64,
    blocks: BlockCounters,
    faults: lfw_blk::request::RequestFaults,
}

/// The identity this boot established, and how it came by it.
struct Established {
    device: u128,
    fingerprint: [u8; 32],
    generation: u64,
    onboarding: Onboarding,
    /// Whether this boot is the one that minted it. The difference an operator
    /// cares about: a node reporting `minted` after a boot that did not has lost
    /// its identity.
    minted: bool,
    /// What a factory reset destroyed on the way here, where this boot honoured
    /// one. `Some` and `minted` always travel together — a reset leaves an
    /// unowned medium and the next thing that happens is a mint — and they are
    /// kept apart anyway, because a mint on a *first* boot is the same event with
    /// an entirely different cause.
    reset: Option<Cleared>,
}

#[protection_domain]
fn init() -> Store {
    // Before anything else that could have something to say. The region is
    // zeroed by the kernel, so it is a valid empty ring the moment it is mapped,
    // and the console domain drains it whenever it comes up — which is what lets
    // a record written here survive to be printed.
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let stats: &'static StatsShard = attach_region!(stats_vaddr: StatsShard);
    let calibration: &'static ClockCalibration = attach_region!(clock_vaddr: ClockCalibration);
    let clock = PdClock::new(calibration);
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(calibration));

    announce(&sink, DomainState::Starting, DomainDetail::None);
    let outcome = bring_up(&sink, wall_seconds(&clock));
    let identity = match &outcome.verdict {
        Ok(established) => {
            // What was given up, before what replaced it: a reset is the one
            // event on this surface that destroys rather than establishes, and an
            // operator reading the identity below has to know whether it is the
            // appliance that was here or the one that took its place.
            if let Some(cleared) = established.reset {
                announce(
                    &sink,
                    DomainState::Negotiated,
                    DomainDetail::Reset {
                        generation: cleared.generation,
                        documents: cleared.documents as u64,
                        was_owned: cleared.was_owned,
                    },
                );
            }
            // Which appliance this is, then, because it is what every other
            // record on this boot is about.
            announce(
                &sink,
                DomainState::Ready,
                DomainDetail::Identity {
                    device: established.device,
                    generation: established.generation,
                    onboarded: matches!(established.onboarding, Onboarding::Onboarded),
                },
            );
            // And the key, as the one thing an administrator compares against
            // another rendering of it. There is no other way to learn it: the
            // node has no shell and no CLI.
            announce(
                &sink,
                DomainState::Ready,
                DomainDetail::Fingerprint(established.fingerprint),
            );
            StoreIdentity {
                established: true,
                minted: established.minted,
                generation: established.generation,
                onboarded: matches!(established.onboarding, Onboarding::Onboarded),
                reset: established.reset.is_some(),
            }
        }
        Err(cause) => {
            // The whole reason, not a summary: with no shell and no CLI on the
            // appliance, this record is all an operator gets.
            announce(&sink, DomainState::Refused, DomainDetail::Refusal(*cause));
            StoreIdentity::default()
        }
    };
    // Last, and once: this domain runs to completion and parks with no channel
    // to wake it, so its shard is written here and never moves again.
    stats.publish(
        &store_sample(
            identity,
            outcome.capacity_sectors,
            outcome.blocks,
            outcome.faults,
            log_sample(sink.dropped(), sink.refused()),
        )
        .values(),
    );
    Store
}

/// Map this domain's device regions, bring the device up, and establish the
/// appliance's identity on the medium behind it.
fn bring_up(sink: &dyn Sink, now: i64) -> BootOutcome {
    // A refusal before the device is up carries no counters, because there is no
    // device to have counted anything: the capacity is the device's own claim and
    // is not known until bring-up asked for it.
    let mut medium = match attach(sink) {
        Ok(medium) => medium,
        Err(error) => {
            return BootOutcome {
                verdict: Err(error.refusal()),
                capacity_sectors: 0,
                blocks: BlockCounters::default(),
                faults: lfw_blk::request::RequestFaults::default(),
            };
        }
    };
    let verdict = establish(&mut medium, now);
    BootOutcome {
        verdict: verdict.map_err(|error| match error {
            EstablishError::Step(step, transfer) => transfer_refusal(step, transfer),
            EstablishError::Other(error) => error.refusal(),
        }),
        capacity_sectors: medium.requests.capacity_sectors(),
        blocks: medium.completed,
        faults: medium.requests.faults(),
    }
}

/// Why establishing an identity failed, with the step where a transfer is what
/// failed.
///
/// A step is carried beside the error rather than inside [`StartupError`]
/// because the same transfer failure means three different things depending on
/// which transfer it was, and a console token that said only "a transfer failed"
/// would send an operator to look at all three.
enum EstablishError {
    Step(Step, TransferError),
    Other(StartupError),
}

impl From<StartupError> for EstablishError {
    fn from(error: StartupError) -> Self {
        Self::Other(error)
    }
}

/// Read the record; honour a factory-reset request where one is there, mint an
/// identity where there is none, verify the one there is, and answer what the
/// appliance is.
fn establish(medium: &mut Medium<'_>, now: i64) -> Result<Established, EstablishError> {
    let needed = STORE_SECTORS;
    let capacity = medium.requests.capacity_sectors();
    if capacity < needed {
        return Err(StartupError::TooSmall { capacity, needed }.into());
    }

    let mut region = [0_u8; BOTH_COPIES];
    medium.read_state(&mut region)?;

    // The request is answered *before* the record is judged, and that ordering is
    // the decision rather than a consequence of one: a record this build refuses
    // is exactly the state an operator reaches for a reset to fix, so an
    // appliance that demanded a coherent identity before it would give one up
    // could never be recovered. What the record is used for here is the report,
    // and a record beyond use reports zeroes.
    if medium.read_reset()?.is_requested() {
        let cleared = medium.factory_reset(&mut region)?;
        let mut minted = medium.mint_identity(&mut region, now)?;
        minted.reset = Some(cleared);
        return Ok(minted);
    }

    match decode_state(&region) {
        // The medium already carries a record. It is checked against this
        // build's layout and then held to itself as an identity, and only then
        // is it this appliance.
        Some(image) => {
            let state = image
                .check()
                .map_err(|error| EstablishError::Other(StartupError::Record(error)))?;
            let identity = verify(state.get())
                .map_err(|error| EstablishError::Other(StartupError::Identity(error)))?;
            Ok(Established {
                device: device_word(state.get().device_id()),
                fingerprint: identity.fingerprint,
                generation: state.get().generation(),
                onboarding: state.get().onboarding(),
                minted: false,
                reset: None,
            })
        }
        // A fresh medium — or one whose record is beyond use. Both are the same
        // thing to this domain: there is no identity to preserve, so one is
        // minted. That is deliberately not a repair of a damaged record: a
        // record that half-decoded is refused above, and only "neither copy is a
        // record at all" reaches here.
        None => medium.mint_identity(&mut region, now),
    }
}

/// A device identifier as the one number a console record carries it in.
///
/// The bytes are read most significant first, which is the order the rendering
/// prints them in — so the record's number and the certificate's subject name
/// are two renderings of one value rather than two values. Total over the array:
/// sixteen bytes shifted into a 128-bit word is exactly its width.
fn device_word(bytes: [u8; lfw_store::DEVICE_ID_BYTES]) -> u128 {
    let mut word = 0_u128;
    for byte in bytes {
        word = (word << 8) | u128::from(byte);
    }
    word
}

/// The device, the staging window and the generator this domain established.
struct Medium<'region> {
    requests: Requests<'region>,
    io: IoRegion<'region>,
    live: Live<MappedBlkDevice>,
    completed: BlockCounters,
    /// Seeded on first use rather than at bring-up: a boot that reloads an
    /// existing identity needs no randomness at all, and drawing 2048 bits it
    /// will not use would make a healthy generator a precondition for a node
    /// that has nothing to generate.
    entropy: Option<NodeEntropy>,
}

impl<'region> Medium<'region> {
    /// The node's generator, seeded from hardware the first time it is asked
    /// for.
    ///
    /// The seed material is cleared before this function returns, through a
    /// volatile write so the compiler cannot remove a store to a value nothing
    /// reads again. What survives is the generator's own state.
    fn entropy_or_seed(&mut self) -> Result<&NodeEntropy, StartupError> {
        if self.entropy.is_none() {
            let mut raw = [0_u8; SEED_MATERIAL_LEN];
            let drawn = hardware_seed(&mut raw);
            let seeded = drawn.map_err(StartupError::Entropy).and_then(|()| {
                let mut generator = Drbg::from_entropy(&raw);
                let mut first = [0_u8; 32];
                let mut second = [0_u8; 32];
                generator.fill(&mut first);
                generator.fill(&mut second);
                // Two draws that came out identical would mean the generator
                // never advanced, which no vector can catch because a vector
                // fixes the seed and reads one draw. Neither value leaves this
                // frame.
                if first == second {
                    return Err(StartupError::GeneratorStalled);
                }
                Ok(generator)
            });
            // The seed does not outlive this frame in readable form. Through
            // `lfw_crypto`, which is the one place in the appliance that clears
            // key material: doing it by hand here would be a volatile write, and
            // an `unsafe` block for a thing an adopted crate already does.
            zeroize(&mut raw);
            self.entropy = Some(NodeEntropy::new(seeded?));
        }
        // Unreachable: the branch above either set it or returned. Answered
        // rather than asserted, because nothing about establishing an identity
        // may fault this domain.
        self.entropy.as_ref().ok_or(StartupError::GeneratorStalled)
    }

    /// Mint an identity onto a medium that carries none of this appliance's.
    ///
    /// Both copies, because there is no copy of *this* appliance's state to
    /// preserve and one left behind would be another appliance's. The barrier
    /// behind it is what makes the write durable rather than merely submitted.
    ///
    /// `region` is the caller's — the same storage the record was read into, which
    /// by here holds nothing this appliance needs. One buffer rather than two: it
    /// is 4 KiB a copy and this domain's stack is not sized for holding the
    /// record twice at once.
    fn mint_identity(
        &mut self,
        region: &mut [u8; BOTH_COPIES],
        now: i64,
    ) -> Result<Established, EstablishError> {
        let minted = mint(self.entropy_or_seed()?, now)
            .map_err(|error| EstablishError::Other(StartupError::Identity(error)))?;
        self.commit(region, &minted.state, Copies::Both)?;
        Ok(Established {
            device: device_word(minted.state.device_id()),
            fingerprint: minted.identity.fingerprint,
            generation: minted.state.generation(),
            onboarding: minted.state.onboarding(),
            minted: true,
            reset: None,
        })
    }

    /// Read the factory-reset request sector.
    ///
    /// A sector of the medium, so every byte is a physical attacker's — and there
    /// is nothing here to parse: the answer is a comparison against one constant
    /// pattern, which `lfw_store` owns. An absent request is the ordinary state of
    /// this sector and is not an error.
    fn read_reset(&mut self) -> Result<ResetRequest, EstablishError> {
        let Some(span) = IoSpan::at_offset(0, RESET_REQUEST_BYTES as u32) else {
            return Err(EstablishError::Step(
                Step::ResetRead,
                TransferError::Refused,
            ));
        };
        self.transfer(Step::ResetRead, Operation::Read, RESET_REQUEST_SECTOR, span)?;
        // Out of the staging window and into this domain's own storage, on
        // `read_state`'s terms: a device that answered and kept writing must not
        // be able to change the sector between the comparison and its answer.
        let mut sector = [0_u8; RESET_REQUEST_BYTES];
        let staged = self.io.staging(span);
        for (slot, byte) in sector.iter_mut().zip(staged.iter()) {
            *slot = *byte;
        }
        Ok(ResetRequest::read(&sector))
    }

    /// Honour a factory reset: clear the request, then destroy what the medium
    /// held, and answer what that was.
    ///
    /// **The order is the whole of the decision.** The request is cleared and made
    /// durable *first*: a power cut between the two steps then leaves an appliance
    /// whose identity is partly gone and which will not reset again, which is a
    /// node an operator re-onboards. The opposite order leaves one that resets on
    /// every boot forever, which is a node nobody can onboard at all. One outcome
    /// is recoverable and the other is a brick, so the flush behind the clear is
    /// waited for rather than left to the next transfer to imply.
    ///
    /// `region` is this domain's copy of the record and is cleared here too: the
    /// scalar it holds has no reason to outlive the medium's.
    fn factory_reset(&mut self, region: &mut [u8; BOTH_COPIES]) -> Result<Cleared, EstablishError> {
        // Read before anything is destroyed, because the report is about the
        // appliance being given up. A record this build cannot read reports
        // nothing rather than refusing the reset.
        let checked = decode_state(region).and_then(|image| image.check().ok());
        let cleared = Cleared::of(checked.as_ref().map(CheckedState::get));
        self.clear_reset()?;
        self.overwrite_store()?;
        zeroize(region);
        Ok(cleared)
    }

    /// Write zeroes over the request sector and wait for the flush behind them.
    fn clear_reset(&mut self) -> Result<(), EstablishError> {
        let Some(span) = IoSpan::at_offset(0, RESET_REQUEST_BYTES as u32) else {
            return Err(EstablishError::Step(
                Step::ResetClear,
                TransferError::Refused,
            ));
        };
        for byte in self.io.staging(span).iter_mut() {
            *byte = 0;
        }
        self.transfer(
            Step::ResetClear,
            Operation::Write,
            RESET_REQUEST_SECTOR,
            span,
        )?;
        self.barrier()
    }

    /// Overwrite every sector this build's layout claims, and wait for the flush
    /// behind it.
    ///
    /// **Overwritten, not marked free.** The medium holds the private scalar in
    /// plaintext, so a sector released rather than written is a kept secret; and
    /// the whole layout rather than the fields that hold one, because the answer
    /// to "which sectors are the secret ones" would then come from the record this
    /// step exists to destroy.
    ///
    /// It runs before the mint and is made durable on its own rather than left to
    /// the mint's commit, which is not redundant: a boot whose generator turns out
    /// broken refuses and parks *after* this point, and an appliance that kept a
    /// readable key through a reset it reported would be the one failure this
    /// whole step exists to prevent.
    fn overwrite_store(&mut self) -> Result<(), EstablishError> {
        // Zeroes across the whole window once, so every transfer below names a
        // span of a window that already holds nothing.
        let Some(whole) = IoSpan::at_offset(0, BLK_IO_REGION_SIZE as u32) else {
            return Err(EstablishError::Step(
                Step::Overwrite,
                TransferError::Refused,
            ));
        };
        for byte in self.io.staging(whole).iter_mut() {
            *byte = 0;
        }
        let mut sector = 0;
        while sector < STORE_SECTORS {
            let sectors = STORE_SECTORS.saturating_sub(sector).min(OVERWRITE_SECTORS);
            let Some(span) = IoSpan::at_offset(0, sectors_bytes(sectors)) else {
                return Err(EstablishError::Step(
                    Step::Overwrite,
                    TransferError::Refused,
                ));
            };
            self.transfer(Step::Overwrite, Operation::Write, sector, span)?;
            sector = sector.saturating_add(sectors);
        }
        self.barrier()
    }

    /// Read both copies of the record into `region`.
    fn read_state(&mut self, region: &mut [u8; BOTH_COPIES]) -> Result<(), EstablishError> {
        let span = self.whole_record();
        self.transfer(Step::Read, Operation::Read, STATE_A_SECTOR, span)?;
        // Out of the staging window and into this domain's own storage, so what
        // is decoded is a snapshot the device cannot rewrite underneath the
        // decode. A view into the window would let a device that answered and
        // then kept writing change the record between its digest check and its
        // fields being read.
        let staged = self.io.staging(span);
        for (slot, byte) in region.iter_mut().zip(staged.iter()) {
            *slot = *byte;
        }
        Ok(())
    }

    /// Compose `state` into the copies `copies` names, write them, and order the
    /// write behind a device barrier.
    ///
    /// The barrier is the whole difference between a state that is written and
    /// one that is *durable*: a completion says the device took the bytes, and a
    /// flush says they will survive the power going away. Everything a later boot
    /// believes about this appliance rests on it, so it is issued here and waited
    /// for rather than left to the next transfer to imply.
    ///
    /// `image` is the caller's storage and is composed into rather than allocated
    /// here — see [`Self::mint_identity`] on why the record crosses in one buffer
    /// and not two. Only the copies `copies` names are written to the medium, so
    /// bytes the compose leaves untouched reach no sector.
    fn commit(
        &mut self,
        image: &mut [u8; BOTH_COPIES],
        state: &State,
        copies: Copies,
    ) -> Result<(), EstablishError> {
        let StateWrite { sector, sectors } = encode_state(image, state, copies);
        // The staging window is written from this domain's own storage rather
        // than composed in place, so a device reading the window mid-compose
        // sees a whole record or the previous contents and never a half-written
        // one.
        let span = self.whole_record();
        let staged = self.io.staging(span);
        for (slot, byte) in staged.iter_mut().zip(image.iter()) {
            *slot = *byte;
        }
        // Exactly the copies `encode_state` wrote, at the sector it named: the
        // transfer follows that decision rather than restating it.
        let Some(span) = IoSpan::at_offset(0, sectors_bytes(sectors)) else {
            return Err(EstablishError::Step(Step::Write, TransferError::Refused));
        };
        self.transfer(Step::Write, Operation::Write, sector, span)?;
        self.barrier()
    }

    /// Both copies as one span of the staging window, at its front.
    ///
    /// The fallback is unreachable and is a value rather than an assertion: the
    /// length is a compile-time constant the assertion at the head of this file
    /// places inside the window, and one sector is the narrowest span there is.
    fn whole_record(&self) -> IoSpan {
        IoSpan::at_offset(0, BOTH_COPIES as u32).unwrap_or(ONE_SECTOR)
    }

    /// Submit one transfer and wait for the completion that answers it.
    fn transfer(
        &mut self,
        step: Step,
        operation: Operation,
        sector: u64,
        span: IoSpan,
    ) -> Result<(), EstablishError> {
        let token = self
            .requests
            .submit(operation, sector, self.io.span_paddr(span), span.bytes())
            .map_err(|error| {
                // Every refusal is a range this driver will not name or a slot
                // table that is full, and neither is reachable here: one request
                // is outstanding at a time and every range is a constant of the
                // layout, bounded against the capacity above. So the whole set
                // is one cause.
                let _: SubmitError = error;
                EstablishError::Step(step, TransferError::Refused)
            })?;
        self.live.ring();
        let completed = self.await_completion(step)?;
        self.judge(step, operation, &token, &completed, span.bytes())
    }

    /// Order everything submitted so far behind a device flush.
    fn barrier(&mut self) -> Result<(), EstablishError> {
        // A device that never negotiated `VIRTIO_BLK_F_FLUSH` is one this build
        // does not accept: `lfw_blk::ACCEPTED_FEATURES` names the bit and
        // `negotiate_features` refuses a device that does not offer it, so
        // bring-up has already answered this question. Asking again here would
        // be a second policy for the same fact.
        let token = self
            .requests
            .submit(Operation::Flush, 0, 0, 0)
            .map_err(|_| EstablishError::Step(Step::Barrier, TransferError::Refused))?;
        self.live.ring();
        let completed = self.await_completion(Step::Barrier)?;
        // A flush moves no bytes, so the length it reports is not a length of
        // anything and is not compared.
        if completed.token != token || completed.operation != Operation::Flush {
            return Err(EstablishError::Step(
                Step::Barrier,
                TransferError::Misattributed,
            ));
        }
        if completed.outcome != Outcome::Ok {
            return Err(EstablishError::Step(Step::Barrier, TransferError::Failed));
        }
        Ok(())
    }

    /// Poll until the device answers, or until the budget is spent.
    fn await_completion(&mut self, step: Step) -> Result<Completed, EstablishError> {
        for _ in 0..POLL_BUDGET {
            if let Some(completed) = self.requests.poll() {
                return Ok(completed);
            }
            core::hint::spin_loop();
        }
        Err(EstablishError::Step(step, TransferError::Silent))
    }

    /// What one completion says about the transfer that was submitted.
    fn judge(
        &mut self,
        step: Step,
        operation: Operation,
        token: &Token,
        completed: &Completed,
        asked: u32,
    ) -> Result<(), EstablishError> {
        if completed.token != *token || completed.operation != operation {
            return Err(EstablishError::Step(step, TransferError::Misattributed));
        }
        if completed.outcome != Outcome::Ok {
            return Err(EstablishError::Step(step, TransferError::Failed));
        }
        if completed.bytes != asked {
            return Err(EstablishError::Step(
                step,
                TransferError::Short {
                    bytes: completed.bytes,
                },
            ));
        }
        self.completed.completed(operation, completed.bytes);
        Ok(())
    }
}

/// The narrowest span of the staging window, as the unreachable fallback above's
/// value. `IoSpan::new` refuses only a length past the window, and one sector is
/// not one.
const ONE_SECTOR: IoSpan = match IoSpan::new(lfw_blk::io::IoSector::FIRST, SECTOR_SIZE as u32) {
    Some(span) => span,
    None => panic!("one sector is inside the staging window"),
};

/// A whole number of sectors as bytes, saturating rather than wrapping: the
/// release profile checks overflow, and a width the layout cannot produce must
/// yield a length the driver refuses rather than a fault an operator must decode.
fn sectors_bytes(sectors: u64) -> u32 {
    u32::try_from(sectors.saturating_mul(SECTOR_SIZE as u64)).unwrap_or(u32::MAX)
}

/// Map this domain's four device regions and bring the device up.
fn attach(sink: &dyn Sink) -> Result<Medium<'static>, StartupError> {
    let ecam = memory_region_symbol!(ecam_vaddr: *mut u8).as_ptr();
    let bar = memory_region_symbol!(bar_vaddr: *mut u8).as_ptr();
    let dma = memory_region_symbol!(dma_vaddr: *mut u8).as_ptr();
    let io_base = memory_region_symbol!(io_vaddr: *mut u8).as_ptr();
    let bar_paddr = *var!(bar_paddr: usize = 0);
    let dma_paddr = *var!(dma_paddr: usize = 0) as u64;
    let io_paddr = *var!(io_paddr: usize = 0) as u64;

    // SAFETY: `io_base` is the mapped `blk2_io` region of
    // `systems/qemu-x86_64/librefirewall.system`, which maps it at `io_vaddr`
    // into this PD alone, at `lfw_blk::BLK_IO_REGION_SIZE` bytes — held equal to
    // that constant by `xtask::sysdesc`'s rule for the region — and holds the
    // mapping for the PD's whole life. That is exactly `IoRegion::attach`'s
    // contract; the address it is paired with is checked rather than trusted,
    // which is why this is the one region whose base can be refused here.
    let io =
        unsafe { IoRegion::attach(io_base, io_paddr) }.map_err(StartupError::StagingUnusable)?;

    // SAFETY: `ecam` is the mapped 4 KiB ECAM page of the pinned PCI function,
    // guaranteed by `systems/qemu-x86_64/librefirewall.system`, which maps
    // `ecam4` at `ecam_vaddr` into this PD alone and holds the mapping for the
    // PD's whole life — exactly `PciConfig::new`'s contract.
    let config = unsafe { PciConfig::new(ecam) };

    let placed = bringup::identify(&config)?.place_bar(&config, bar_paddr)?;
    // SAFETY: `bar` is the `bar4` region of
    // `systems/qemu-x86_64/librefirewall.system`, guaranteeing
    // `lfw_blk::BAR_WINDOW_SIZE` bytes — the constant `xtask::sysdesc` holds
    // that region's `size` equal to — page-aligned and mapped for the PD's whole
    // life, at the physical address `place_bar` just programmed:
    // `PlacedBar::map`'s contract. Nothing is required of the device's own
    // offsets — `identify` bounded them against the same constant.
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

    // SAFETY: `dma` is the `blk2_dma` region of
    // `systems/qemu-x86_64/librefirewall.system`, guaranteeing a zeroed,
    // page-aligned (so 16-byte-aligned) mapping of `lfw_blk::DMA_REGION_SIZE`
    // bytes shared with this device alone; `lfw_blk`'s layout assertions prove
    // the queue fits below `HEADER_AREA_OFFSET`, which is where the per-slot
    // headers start — `SplitVirtqueue::new`'s contract.
    let queue = unsafe { BlkVirtqueue::new(dma) };
    // SAFETY: the same region and the address `configure_queue` just programmed
    // the device with — and refused had it been zero, misaligned or wrapping,
    // which is the enforcer `Requests::attach` names for it. The queue passed in
    // was built over this very pointer one statement ago, and `xtask::sysdesc`
    // holds the region's `size` equal to `DMA_REGION_SIZE`.
    let requests = unsafe { Requests::attach(dma, dma_paddr, queue, capacity_sectors) };

    Ok(Medium {
        requests,
        io,
        live,
        completed: BlockCounters::default(),
        entropy: None,
    })
}

/// Returned by `init` in every case: this domain runs once and then parks in the
/// Microkit event loop, whether it established an identity or refused to.
struct Store;

impl Handler for Store {
    type Error = Infallible;

    /// Unreachable by capability: nothing in this system holds a notification
    /// capability on this domain, so the event loop it parks in has no sender.
    /// It exists because [`Handler`] requires it.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        Ok(())
    }
}
