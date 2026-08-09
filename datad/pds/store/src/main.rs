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
//! appliance returned and how far its state has advanced.
//!
//! # And then it signs, which is why it no longer parks alone
//!
//! The domain that terminates a mutually-authenticated session needs a signature
//! under this key on every handshake, and must never hold the key: a key in two
//! domains is a key whose custody nobody can state. So this domain keeps the
//! keypair after establishing it and answers a **signing delegation** — sign
//! these bytes, tell me which key you hold, or hand me the certificate over it —
//! over the two shared regions `wire::signing` defines. It parks in the Microkit
//! event loop rather than beyond reach, and a notification from the asking domain
//! wakes it.
//!
//! The certificate is answered here rather than reissued there because **this is
//! the identity domain**: the certificate is half of the identity this domain
//! minted and made durable, and a domain that wrote an equivalent one for itself
//! would leave the appliance with two certificates over one key and nobody able to
//! say which one a peer saw. It is a public artifact, so handing it over gives away
//! nothing — the statement it carries is the one every peer is shown.
//!
//! **The key still cannot cross, and that is a property of two things at once.**
//! The ABI has no field for a scalar in either direction, so there is nothing to
//! put one in; and the reply region is this domain's to write and the asker's to
//! read only, so a compromised asker cannot even name a byte of it. Neither
//! property alone would do — an ABI that could carry a key would carry it
//! through correct grants, and grants alone would leave a domain free to write
//! one into a region it shares.
//!
//! What it answers is bounded by construction rather than by trust in the peer.
//! `wire::SignResponder::take` yields **at most one demand per change of the
//! requester's sequence**, so a peer rewriting that word as fast as it likes
//! costs one reply each; [`DEMANDS_PER_WAKEUP`] bounds one wakeup regardless,
//! and a wakeup that spends it returns to the event loop rather than looping. A
//! request this domain cannot serve is answered with a typed refusal — never
//! ignored, because a requester left waiting cannot tell a refusal from a hang.
//!
//! A refused **signature** reaches the metrics shard and not the console,
//! deliberately. This domain's log ring is single-producer and bounded, so a
//! console record per refusal would let the asking domain choose the rate at
//! which the records an operator actually needs — the identity and the
//! fingerprint — are pushed out of it. A count is the surface that a hostile peer
//! cannot use to hide anything, and the domain that asked is the one that reports
//! what it made of the answer.
//!
//! A refused **install** does reach the console, and the difference is not a
//! relaxation of that rule but the reason it exists. A signature is one of many
//! in a session and its meaning belongs to the domain that asked; an install is
//! the appliance changing hands, and the rule that stopped one is the thing an
//! administrator standing in front of a node with no shell has to be told. What
//! keeps the ring safe is that the number of such records a boot can produce is a
//! constant of this file rather than a peer's choice.
//!
//! # And it takes ownership, which is the second thing that writes this medium
//!
//! An administrator uploads an onboarding package to the port the cryptography
//! domain terminates, and that domain places the archive in a **staging region**
//! it writes and this domain reads. A fourth delegation operation asks this
//! domain to install it; the request states how many bytes of the region hold
//! the archive, and the answer is a status word — installed, or refused.
//!
//! **The region is snapshotted before a rule is applied to it.** Its writer is
//! the domain an unauthenticated peer talks to and can write it again at any
//! instant, so a package validated through a borrow of it would be a package
//! whose bytes were somebody else's by the time they reached a sector. The copy
//! goes into the upper half of this domain's own staging window — the state
//! record's span is at the front and is untouched — and everything after that
//! reads the copy.
//!
//! **The check here is the second reading of those bytes and is deliberately
//! narrower than the first.** The domain that terminated the upload reads them
//! against the certificate validator this appliance adopted; this domain
//! re-applies every structural rule, compares the device certificate against the
//! point in **its own state record** rather than against anything a peer
//! offered, and verifies one signature under one profile. What it adds is that
//! the domain about to write the medium has read what it is writing. What it
//! does not add is a second general chain policy, which is the thing this
//! appliance declines to have in the domain holding the private key — so two
//! checks that disagree mean the bytes changed between them, not that one of
//! them has a better opinion.
//!
//! Every refusal here reaches the console by name, unlike a refused signature. A
//! signature is one of many in a session and what it means belongs to the domain
//! that asked; an install is the appliance changing hands, and the rule that
//! stopped one is what an administrator standing in front of the node has to be
//! told. What keeps that bounded is [`INSTALLS_PER_BOOT`] rather than the peer's
//! restraint — it bounds the console records and the work alike, an install
//! costing a copy, an archive walk and a signature verification.
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
//! And a **byzantine neighbour protection domain** on the delegation channel,
//! which is new and is the whole of what this domain gained: every word of the
//! request region is the asking domain's, so the sequence, the operation and the
//! length are claims. `wire::signing` is what ranges them — an operation outside
//! its set is refused by name rather than coerced, and a stated length past what
//! a request can carry yields no message at all rather than a short one this
//! domain would happily sign.
//!
//! There is still no path from a packet to these bytes, and that remains a
//! property of the system description rather than of this file: this domain holds
//! no network region and no configuration region, and its one channel goes to the
//! cryptography domain, which holds none either. A compromise would have to
//! traverse a domain that no frame reaches to arrive at a channel whose ABI has
//! no field for a key.
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
//! # It establishes once and then serves
//!
//! There is still no poll loop: establishing an identity is a thing that happens
//! once, and it happens to completion in `init`. What follows is not polling
//! either — the domain blocks in the Microkit event loop and does work only when
//! woken.
//!
//! **Two of the three things it serves wait on nothing**: a signature and a
//! certificate are a demand taken, answered and published in one pass. **An
//! install waits**, because it reads the record and writes it back, so it spends
//! device transfers and the flush behind them — every one of them bounded by
//! `lfw_blk`'s own poll budget and by nothing the device controls, exactly as the
//! establishing run is. What that costs the domain below this one is bounded
//! twice over: by that budget per transfer, and by [`INSTALLS_PER_BOOT`] over the
//! boot.
//!
//! # No key material reaches any surface
//!
//! The private scalar is drawn, folded into a certificate, written to the medium,
//! and kept in this domain's own memory to sign with. That is the whole of where
//! it goes. No console record, no metric, no `Debug` in this file and **no field
//! of the delegation ABI** names it; the two records this domain emits carry a
//! public name and a public-key digest, and what it publishes to the asking
//! domain is a public point, a public name, a certificate and signatures — four
//! things a peer of this appliance is shown anyway. The medium's copy is
//! plaintext there deliberately and for want of anywhere to keep a wrapping key,
//! which is why physical possession of the store *is* identity theft and why that
//! boundary is the one the ownership model rests on.

use lfw_blk::bringup::{self, BringUpError, Live, MappedBlkDevice};
use lfw_blk::io::{IoRegion, IoRegionUnusable, IoSpan};
use lfw_blk::request::{Completed, Operation, Outcome, Requests, SubmitError, Token};
use lfw_blk::{
    BLK_IO_REGION_SIZE, BlkVirtqueue, Refusal as BlkRefusal, RefusalDetail as BlkRefusalDetail,
    SECTOR_SIZE,
};
use lfw_crypto::{
    DIGEST_LEN, Drbg, EntropyError, NodeEntropy, P256SecretKey, SEED_MATERIAL_LEN, hardware_seed,
    zeroize,
};
use lfw_log::{
    Domain, DomainDetail, DomainState, Event, Ipv4Address, Refusal, RefusalDetail, RingSink, Sink,
};
use lfw_metrics::StatsShard;
use lfw_package::{Operands, PackageError};
use lfw_store::{
    ChainFault, CheckedState, Cleared, Copies, IdentityError, InstallError, Onboarding,
    RESET_REQUEST_BYTES, RESET_REQUEST_SECTOR, ResetRequest, STATE_A_SECTOR, STATE_COPY_BYTES,
    STORE_SECTORS, State, StateError, StateWrite, StoredEndpoint, decode_state, encode_state, mint,
    read_package, verify,
};
use pd_runtime::{
    BlockCounters, PdClock, StoreIdentity, StoreSigning, attach_region, log_sample,
    read_timestamp_counter, store_sample,
};
use sel4_microkit::{
    ChannelSet, Handler, Infallible, memory_region_symbol, protection_domain, var,
};
use virtio::pci::PciConfig;
use wire::{
    ApplianceOwnership, ClockCalibration, DeviceIdentity, InstallStaging, LogConsume, LogRecords,
    MAX_CERTIFICATE_LEN, MAX_INSTALL_ARCHIVE, MAX_SIGN_MESSAGE, MAX_SIGNATURE_LEN, SignDemand,
    SignOperation, SignRefusal, SignReply, SignRequest, SignResponder, StagedArchive,
};

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

/// Where an uploaded archive is snapshotted inside this domain's staging window.
///
/// The upper half, so the record's own span at the front of the window is
/// untouched by it — the two are the only things this domain ever puts there,
/// and an install stages both. What keeps the *order* right is not this constant
/// but the borrow: the snapshot is held while the package is validated, and the
/// record cannot be composed into the window until that borrow ends, so
/// "validated, then written" is something the compiler holds rather than
/// something this file remembers.
const SNAPSHOT_AT: usize = BLK_IO_REGION_SIZE - MAX_INSTALL_ARCHIVE;

// And the two really do not overlap, which the borrow alone would not say: a
// snapshot placed over the record's span would be a transfer of the archive to
// the medium's first sectors.
const _: () = assert!(
    BOTH_COPIES <= SNAPSHOT_AT,
    "the snapshot of an uploaded archive overlaps the state record's own span"
);

// The staging region's width and the archive bound the reader applies are two
// crates' numbers for one thing, held equal here because this is the one place
// both are visible. `wire::install` declines to depend on the reader for an
// integer and names the domain that sees both; this is it.
const _: () = assert!(MAX_INSTALL_ARCHIVE == lfw_package::ARCHIVE_BOUND);

/// Installs one boot serves, and so the console records one can produce.
///
/// Eight, which is generous for the thing it is really for: an administrator
/// whose package was refused corrects it and uploads again, and a handful of
/// those in one boot is ordinary. What it bounds is two things at once — an
/// install costs this domain a 128 KiB copy, a whole archive walk and one
/// signature verification, all of them paced by a peer; and every one of them
/// can put records on a bounded single-producer ring the console drains. A
/// budget makes both a first-party number rather than a peer's choice, and going
/// past it is answered by name rather than ignored.
const INSTALLS_PER_BOOT: u32 = 8;

/// Poll iterations one completion is waited for.
///
/// `lfw_blk::smoke`'s budget, reused rather than re-chosen: it is the same
/// question — how long a working device may take to answer one single-sector
/// request — and a second number would be a second thing to justify. Reaching it
/// is a device that has stopped answering, which is a refusal and not a retry.
const POLL_BUDGET: u32 = lfw_blk::smoke::POLL_BUDGET;

/// Demands one wakeup answers before returning to the event loop.
///
/// The protocol admits one outstanding request, so a peer keeping to it produces
/// exactly one demand per wakeup and this bound is never reached. It is here for
/// the peer that does not: `wire::SignResponder::take` already costs one reply
/// per change of the requester's sequence rather than one per read, so a request
/// storm cannot loop this domain — and this makes the *number* of replies one
/// wakeup can be made to write a first-party constant rather than a consequence
/// of how fast the peer writes. Exhausting it is not a refusal and not an error:
/// the domain returns to the event loop, and the notification the peer sends for
/// its next request brings it straight back.
///
/// Four rather than one, because Microkit coalesces notifications: two requests
/// issued either side of one wakeup are one signal, and a bound of one would
/// leave the second waiting for a third.
const DEMANDS_PER_WAKEUP: u32 = 4;

// The signature buffer this domain writes into and the channel's own field are
// two crates' numbers for one thing, held equal here because this is the one
// place both are visible. `wire::signing` declines to depend on the cryptography
// for an integer and says so; this is the domain it names.
const _: () = assert!(
    MAX_SIGNATURE_LEN == lfw_crypto::P256_MAX_SIGNATURE_LEN,
    "the reply region cannot hold the longest signature this profile produces"
);

// The same, for the public point: a reply that could not carry the whole of it
// would publish a truncated key a peer would then fail every handshake under.
const _: () = assert!(wire::PUBLIC_KEY_LEN == lfw_crypto::P256_PUBLIC_LEN);
const _: () = assert!(wire::DEVICE_ID_LEN == lfw_store::DEVICE_ID_BYTES);

// And for the certificate, which is the widest thing the channel carries: a reply
// region narrower than the record would hand over a truncated certificate, and
// every peer would then reject the appliance for an encoding error rather than for
// anything true about it. `wire::signing` declines to depend on the store for an
// integer and names the domain that sees both; this is it.
const _: () = assert!(MAX_CERTIFICATE_LEN == lfw_store::MAX_STORED_CERTIFICATE);

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

/// The token an install refusal is named by, and the numbers that place it.
///
/// The rules of the package name themselves: `PackageError::cause` is the one
/// catalogue for them, so every domain that reads a package reads the same
/// tokens out of it and none of them can drift. What is added here is what only
/// this domain can refuse — it owns the medium, the staging region and the
/// appliance's key. The residual arms cover the two vocabularies this domain
/// matches from outside the crate that declares them: a variant added upstream
/// reaches the console as a token saying so rather than as another rule's name.
fn install_refusal(error: InstallError) -> Refusal {
    let (cause, detail) = match error {
        InstallError::AlreadyOwned => ("install-already-owned", RefusalDetail::None),
        InstallError::ArchivePastRegion { len, staged } => (
            "install-archive-past-region",
            RefusalDetail::Two(u64::from(len), staged as u64),
        ),
        InstallError::ApplianceKey(_) => ("install-appliance-key-unencodable", RefusalDetail::None),
        InstallError::Storage(error) => (
            match error {
                StateError::CertificateTooLong { .. } => "install-certificate-too-long",
                _ => "install-record-refused-the-package",
            },
            record_detail(error),
        ),
        InstallError::Chain(fault) => (chain_cause(fault), RefusalDetail::None),
        InstallError::Package(error) => (error.cause(), package_detail(error)),
        _ => ("install-unusable", RefusalDetail::None),
    };
    Refusal {
        cause,
        detail,
        // The device is live and stays live: an install refusal changes nothing
        // about the medium and this domain goes on serving.
        signalled: true,
    }
}

/// Why the one signature this appliance verifies for itself did not hold.
const fn chain_cause(fault: ChainFault) -> &'static str {
    match fault {
        ChainFault::MalformedCertificate => "install-certificate-malformed",
        ChainFault::MalformedSignatureAlgorithm => "install-signature-algorithm-malformed",
        ChainFault::MalformedSignature => "install-signature-malformed",
        ChainFault::MalformedAnchorKey => "install-anchor-key-malformed",
        ChainFault::SignatureAlgorithmNotEcdsaSha256 => "install-signature-not-ecdsa-sha256",
        ChainFault::SignatureAlgorithmsDisagree => "install-signature-algorithms-disagree",
        ChainFault::AnchorKeyNotP256 => "install-anchor-key-not-p256",
        ChainFault::NotAuthentic => "install-signature-not-authentic",
    }
}

/// The numbers a package refusal turns on, where its variant carries them.
/// The numbers a package refusal turns on, as this domain's record carries
/// them.
///
/// Shaped by `lfw_package` and only *written* here: the two domains that read a
/// package would otherwise each carry a hand-written mapping from the same
/// variants to the same numbers, and the one that fell behind would place a
/// fault wrongly. What stays this domain's is the record — a count of numbers is
/// not a console type.
const fn package_detail(error: PackageError) -> RefusalDetail {
    match error.operands() {
        Operands::None => RefusalDetail::None,
        Operands::One(value) => RefusalDetail::One(value),
        Operands::Two(first, second) => RefusalDetail::Two(first, second),
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
    /// The device, kept rather than dropped at the end of the boot.
    ///
    /// It used to go away with the establishing run, because establishing an
    /// identity is the only thing that happened. Taking ownership is the second
    /// thing that writes this medium, and it happens when a peer asks — so the
    /// device, its queue and its staging window are held for the domain's whole
    /// life. `None` is a boot that never brought one up, which is the same boot
    /// that has no identity to install anything onto.
    medium: Option<Medium<'static>>,
}

/// The keypair this domain holds after establishing an identity, and the two
/// public values a delegation answers with.
///
/// One struct rather than three fields on the handler, because they are one
/// answer and must never come apart: a public point paired with another
/// appliance's name, or with a scalar it does not derive, is an identity no peer
/// can use and no operator can diagnose. `verify` and `mint` are what establish
/// that they belong together; this carries the result.
///
/// **No `Debug`, and that is deliberate**: the whole point of the type is that
/// the scalar inside it has no rendering anywhere in this domain.
struct DeviceKey {
    key: P256SecretKey,
    public_key: [u8; wire::PUBLIC_KEY_LEN],
    device_id: [u8; wire::DEVICE_ID_LEN],
    /// The appliance's own certificate over that point, and the bytes of it that
    /// are certificate rather than padding. Held here rather than reread from the
    /// medium on every request: the record is this domain's already, and a second
    /// read would put a device transfer on a path that must not wait.
    certificate: [u8; MAX_CERTIFICATE_LEN],
    certificate_len: usize,
}

impl DeviceKey {
    /// Read the identity out of a state record this domain has already held to
    /// itself.
    ///
    /// The scalar is read into this frame, turned into a key, and cleared before
    /// the frame ends — through `lfw_crypto`, the one place in the appliance that
    /// clears key material. What survives is the key, which is what this domain
    /// signs with, and the certificate, which is what a peer validates that key
    /// out of.
    ///
    /// `None` where the scalar is not a private key **or the record carries no
    /// certificate**, because an identity is not a keypair: it is a keypair with a
    /// certificate binding it, and half of one is nothing this domain can let
    /// another authenticate under. Both are unreachable on the reload path,
    /// `verify` having answered exactly those questions, and answered rather than
    /// asserted because nothing about establishing an identity may fault this
    /// domain.
    fn of(state: &State) -> Option<Self> {
        let mut scalar = state.secret_scalar();
        let key = P256SecretKey::from_scalar(&scalar);
        zeroize(&mut scalar);
        let key = key.ok()?;
        let stored = state.device_certificate();
        if stored.is_empty() {
            return None;
        }
        let mut certificate = [0_u8; MAX_CERTIFICATE_LEN];
        let mut certificate_len = 0_usize;
        // `zip` walks the shorter of the two, so no index is taken. The two lengths
        // are held equal at build time below, which is what makes the truncation
        // this would otherwise admit unreachable.
        for (slot, byte) in certificate.iter_mut().zip(stored.as_bytes()) {
            *slot = *byte;
            certificate_len += 1;
        }
        Some(Self {
            public_key: key.public_key(),
            key,
            device_id: state.device_id(),
            certificate,
            certificate_len,
        })
    }

    /// The public values a `SignOperation::PublicKey` request is answered with.
    /// `Copy`, so a caller holds no borrow of the key while it publishes them.
    ///
    /// `owned` is not the key's and is passed in: the keypair is the same
    /// whether or not a management plane has adopted this appliance, and the
    /// ownership is a fact about the record — which this domain reads once at
    /// start-up and moves exactly where it writes a new one.
    const fn identity(&self, owned: bool) -> DeviceIdentity {
        DeviceIdentity {
            public_key: self.public_key,
            device_id: self.device_id,
            owned,
        }
    }

    /// The certificate a `SignOperation::Certificate` request is answered with,
    /// bounded by what was actually stored rather than by the array.
    fn certificate(&self) -> &[u8] {
        self.certificate.get(..self.certificate_len).unwrap_or(&[])
    }
}

/// The identity this boot established, and how it came by it.
struct Established {
    device: u128,
    fingerprint: [u8; 32],
    generation: u64,
    onboarding: Onboarding,
    /// The keypair, kept for the delegation to sign with. `None` where the record
    /// held to itself and the scalar then would not rebuild — a state `verify`
    /// makes unreachable, carried rather than asserted away, and one that leaves
    /// the domain answering every signing request with a typed refusal instead of
    /// faulting.
    key: Option<DeviceKey>,
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
    // The delegation's two regions, and the direction of each is the system
    // description's: the request is the asking domain's to write and this
    // domain's to read, and the reply is the reverse. Nothing here restates that
    // — the handles `wire::signing` hands back reach the other side only through
    // a view with no store on it.
    let request: &'static SignRequest = attach_region!(sign_request_vaddr: SignRequest);
    let reply: &'static SignReply = attach_region!(sign_reply_vaddr: SignReply);
    // And the region an uploaded archive crosses in, which this domain maps
    // READ-ONLY: it is the asking domain's to fill and this domain's to read,
    // and the handle taken here has no store on it.
    let staging: &'static InstallStaging = attach_region!(install_staging_vaddr: InstallStaging);
    let owner: &'static ApplianceOwnership = attach_region!(owner_vaddr: ApplianceOwnership);

    announce(&sink, DomainState::Starting, DomainDetail::None);
    let outcome = bring_up(&sink, wall_seconds(&clock));
    let BootOutcome {
        verdict,
        capacity_sectors,
        blocks,
        faults,
        medium,
    } = outcome;
    // The keypair is moved out of the verdict rather than borrowed from it: what
    // signs after this function returns is the handler's, and a copy left behind
    // would be a second holder of the scalar inside this domain.
    let (identity, key) = match verdict {
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
            (
                StoreIdentity {
                    established: true,
                    minted: established.minted,
                    generation: established.generation,
                    onboarded: matches!(established.onboarding, Onboarding::Onboarded),
                    reset: established.reset.is_some(),
                },
                established.key,
            )
        }
        Err(cause) => {
            // The whole reason, not a summary: with no shell and no CLI on the
            // appliance, this record is all an operator gets.
            announce(&sink, DomainState::Refused, DomainDetail::Refusal(cause));
            // No key, so the delegation is answered with `NoIdentity` rather than
            // being unreachable: a domain waiting on a signature it will never get
            // cannot tell that from a domain that is merely slow.
            (StoreIdentity::default(), None)
        }
    };
    let store = Store {
        sink,
        stats,
        responder: reply.responder(request),
        staging: staging.staged(),
        medium,
        key,
        identity,
        capacity_sectors,
        blocks,
        faults,
        signing: StoreSigning::default(),
        installs: 0,
        owner,
    };
    // The one fact the dataplane needs off this medium, published before the
    // shard and before a peer can ask for anything: the forwarding domain
    // forwards nothing until it reads an owner here, so a boot that established
    // an owned identity and did not say so would be a node that silently
    // carried no traffic. A boot that established none publishes the negative,
    // which is what the zeroed region already says and is stated anyway — the
    // region's own reading and this domain's must not differ by an omission.
    store.publish_ownership();
    // The shard as this boot established it, before a signature has been asked
    // for. It moves again on every wakeup that serves one, which is the change
    // this delegation makes to a shard that used to be written once.
    store.publish();
    store
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
                medium: None,
            };
        }
    };
    let verdict = establish(&mut medium, now);
    BootOutcome {
        verdict: verdict.map_err(establish_refusal),
        capacity_sectors: medium.requests.capacity_sectors(),
        blocks: medium.completed,
        faults: medium.requests.faults(),
        medium: Some(medium),
    }
}

/// One establishing step's refusal as the console record of it.
fn establish_refusal(error: EstablishError) -> Refusal {
    match error {
        EstablishError::Step(step, transfer) => transfer_refusal(step, transfer),
        EstablishError::Other(error) => error.refusal(),
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
                key: DeviceKey::of(state.get()),
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
        // After the commit, so a record that could not be made durable leaves this
        // domain with nothing to sign under: an appliance signing under a key no
        // later boot can reload would authenticate once and never again, and
        // nobody would learn that from a handshake.
        Ok(Established {
            device: device_word(minted.state.device_id()),
            fingerprint: minted.identity.fingerprint,
            generation: minted.state.generation(),
            onboarding: minted.state.onboarding(),
            key: DeviceKey::of(&minted.state),
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

/// The snapshot's span of the staging window: the upper half, whole.
///
/// A constant rather than a value computed per install, because both ends of it
/// are compile-time numbers the assertion at the head of this file places inside
/// the window — so a span that could not be placed is a build failure rather than
/// a refusal an operator could never provoke and would have to be told about.
const SNAPSHOT_SPAN: IoSpan = match IoSpan::at_offset(SNAPSHOT_AT, MAX_INSTALL_ARCHIVE as u32) {
    Some(span) => span,
    None => panic!("the archive snapshot is inside the staging window"),
};

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

/// Returned by `init` in every case: what this domain holds after establishing
/// an identity, and what it answers a signing delegation out of.
///
/// It carries the boot's counters unchanged — the device is finished with by the
/// time this exists, so a capacity and a block tally are settled facts — and the
/// two that are not: the signatures produced and the requests refused, which move
/// on every wakeup.
struct Store {
    sink: RingSink<'static, PdClock<'static>>,
    stats: &'static StatsShard,
    responder: SignResponder<'static>,
    /// The region an uploaded archive arrives in, as a handle with no store on
    /// it: this domain reads what the asking domain wrote and can write none of
    /// it back.
    staging: StagedArchive<'static>,
    /// The device this domain owns, or `None` on a boot that brought none up.
    /// Held past `init` because taking ownership writes the medium and happens
    /// when a peer asks rather than while the domain is starting.
    medium: Option<Medium<'static>>,
    /// The keypair, or `None` on a boot that established no identity. The one
    /// field of this struct with no rendering anywhere: see [`DeviceKey`].
    key: Option<DeviceKey>,
    identity: StoreIdentity,
    capacity_sectors: u64,
    blocks: BlockCounters,
    faults: lfw_blk::request::RequestFaults,
    signing: StoreSigning,
    /// Installs served this boot, against [`INSTALLS_PER_BOOT`]. Saturating, so
    /// the equality that emits the one exhausted record holds exactly once.
    installs: u32,
    /// The one region this domain writes that no request of a peer's is behind:
    /// whether this appliance has an owner, which the forwarding domain maps
    /// read-only and refuses every frame against until it says so.
    owner: &'static ApplianceOwnership,
}

/// What one accepted package changed, as the two records an operator reads.
struct Installed {
    endpoint: StoredEndpoint,
    anchor_fingerprint: [u8; DIGEST_LEN],
    /// The generation the record carrying the ownership stands at, which is what
    /// says the commit landed rather than that one was attempted.
    generation: u64,
}

impl Store {
    /// State on the ownership region what this domain's own record says.
    ///
    /// Called at bring-up and again the instant an install commits, and nowhere
    /// else: the two are the only moments the answer can change, an appliance
    /// losing an owner only by a factory reset, which takes effect on the boot
    /// after the one that asks for it.
    fn publish_ownership(&self) {
        self.owner.publish(self.identity.onboarded);
    }

    /// Answer one demand, and exactly one: every path below consumes it, because
    /// a demand taken and dropped leaves the requester polling a sequence nothing
    /// will publish.
    fn answer(&mut self, demand: SignDemand) {
        match demand.operation() {
            // The word named an operation this build has none of. Refused by name
            // rather than ignored, on the channel's own terms.
            None => self.refuse(demand, SignRefusal::NoSuchOperation),
            // The public half, the name and whether this appliance has an owner,
            // copied out before the reply is written so no borrow of the key is
            // live across the publish. The ownership fact is this domain's own
            // record rather than the key's — read off the medium at start-up and
            // moved by the one thing that changes it, which is an install this
            // domain itself committed.
            Some(SignOperation::PublicKey) => {
                let owned = self.identity.onboarded;
                match self.key.as_ref().map(|key| key.identity(owned)) {
                    Some(identity) => self.responder.identity(demand, &identity),
                    None => self.refuse(demand, SignRefusal::NoIdentity),
                }
            }
            Some(SignOperation::Certificate) => self.certificate(demand),
            Some(SignOperation::Sign) => self.sign(demand),
            Some(SignOperation::Install) => self.install(demand),
        }
    }

    /// Hand over the certificate this domain wrote and made durable, or say why
    /// not.
    ///
    /// **A public artifact leaving a domain that holds a private one.** The
    /// certificate is the statement every peer of this appliance is given, so what
    /// crosses here is nothing an adversary could not obtain by connecting — and it
    /// is emitted only into the reply region, never to a console record or a
    /// metric. The refusal is `NoIdentity` for the reason it is on the public point:
    /// an identity is a keypair *with* a certificate binding it, so a node with
    /// neither half to give has none.
    fn certificate(&mut self, demand: SignDemand) {
        if self.key.is_none() {
            self.refuse(demand, SignRefusal::NoIdentity);
            return;
        }
        // Read out of one field and published through another. Destructured so that
        // is visible rather than argued: the two borrows are disjoint, so the bytes
        // go from this domain's own memory straight into the reply region with no
        // copy of the certificate in between.
        let Self { key, responder, .. } = self;
        // `None` is the state ruled out above. An empty answer would be read by the
        // requester as no certificate at all — a typed fault on its side rather
        // than anything that could fault this domain — which is the correct reading
        // of a holder that has none and is why this answers rather than asserts.
        let certificate = key.as_ref().map_or(&[][..], DeviceKey::certificate);
        responder.certificate(demand, certificate);
    }

    /// Sign what the request carries, or say why not.
    fn sign(&mut self, demand: SignDemand) {
        // Out of the shared region and into this domain's own storage in one
        // statement, so what is signed is a snapshot the peer cannot rewrite
        // between the length being checked and the bytes being hashed. `None` is
        // the stated length being past what a request can hold, which is a
        // request to refuse and not one to shorten.
        let mut message = [0_u8; MAX_SIGN_MESSAGE];
        let Some(len) = demand
            .message(&self.responder, &mut message)
            .map(<[u8]>::len)
        else {
            self.refuse(demand, SignRefusal::MessageTooLong);
            return;
        };
        if self.key.is_none() {
            self.refuse(demand, SignRefusal::NoIdentity);
            return;
        }
        let mut signature = [0_u8; MAX_SIGNATURE_LEN];
        // The borrow of the key ends with this statement, which is what lets the
        // reply be published — or refused — below.
        let produced = self.key.as_ref().and_then(|holder| {
            holder
                .key
                .sign(message.get(..len).unwrap_or_default(), &mut signature)
                .ok()
        });
        match produced {
            Some(bytes) => {
                self.responder
                    .signed(demand, signature.get(..bytes).unwrap_or_default());
                self.signing.signatures = self.signing.signatures.saturating_add(1);
            }
            // The signing itself failed, which a usable key does not reach. Its
            // own refusal rather than `NoIdentity`, because an operator acts on
            // the two differently: one is a node still coming up, the other a node
            // that cannot use the key it has.
            None => self.refuse(demand, SignRefusal::SigningFailed),
        }
    }

    /// Take ownership of this appliance out of the staged package, or say which
    /// rule refused it.
    ///
    /// **This is the second reading of those bytes and it is deliberately not
    /// the first one repeated.** The domain that terminated the upload read them
    /// against an adopted certificate validator; this domain reads them against
    /// its own record — the key it compares the device certificate to is the
    /// point in that record, never one a peer offered — and verifies exactly one
    /// signature under one profile. What it adds is that the domain about to
    /// *write* the medium has read what it is writing; what it does not add is a
    /// second general chain policy, which is the thing this appliance declines
    /// to have in the domain holding the private key.
    ///
    /// Every refusal reaches the console by name, unlike a refused signature: a
    /// signature is one of many in a session and its meaning belongs to the
    /// domain that asked, while an install is the appliance changing hands and
    /// the rule that stopped it is a thing an administrator standing in front of
    /// the node has to be told. What keeps that bounded is [`INSTALLS_PER_BOOT`]
    /// rather than the peer's restraint.
    fn install(&mut self, demand: SignDemand) {
        if self.installs >= INSTALLS_PER_BOOT {
            // Exactly one record, on the attempt that first goes past: every
            // later one is a count and nothing else, so a peer cannot choose how
            // many lines this domain writes.
            if self.installs == INSTALLS_PER_BOOT {
                self.report(Refusal {
                    cause: "installs-exhausted",
                    detail: RefusalDetail::One(u64::from(INSTALLS_PER_BOOT)),
                    signalled: true,
                });
            }
            self.installs = self.installs.saturating_add(1);
            self.refuse(demand, SignRefusal::InstallRefused);
            return;
        }
        // A boot that brought up no device has no record to own and no medium to
        // write one to. That is the same state a signing request meets, so it is
        // answered the same way rather than as a package refusal: nothing about
        // the package was wrong.
        if self.medium.is_none() {
            self.refuse(demand, SignRefusal::NoIdentity);
            return;
        }
        self.installs = self.installs.saturating_add(1);
        match self.take_ownership(demand.stated_len()) {
            Ok(installed) => {
                // The authority first, then where the appliance will answer: an
                // administrator compares the fingerprint against what the
                // management server showed them, and the endpoint is what the
                // node does about it.
                announce(
                    &self.sink,
                    DomainState::Ready,
                    DomainDetail::AnchorFingerprint(installed.anchor_fingerprint),
                );
                announce(
                    &self.sink,
                    DomainState::Ready,
                    DomainDetail::Adopted {
                        destination: Ipv4Address::from_octets(installed.endpoint.address),
                        port: installed.endpoint.port,
                        generation: installed.generation,
                    },
                );
                self.identity.onboarded = true;
                self.identity.generation = installed.generation;
                // After the record is durable and before the requester is told,
                // so nothing can observe an appliance that has been told it is
                // owned while the dataplane still refuses every frame.
                self.publish_ownership();
                self.responder.installed(demand);
            }
            Err(refusal) => {
                self.report(refusal);
                self.refuse(demand, SignRefusal::InstallRefused);
            }
        }
        self.recount();
    }

    /// Read the record, hold the package to every rule, and commit the ownership
    /// behind a barrier.
    ///
    /// The record is read back off the medium rather than kept from the boot:
    /// what is about to be rewritten is what is on the disk now, and the state
    /// this domain established at start-up is a value that has since had a
    /// device under it. It is held to itself again for the same reason — a
    /// record that no longer verifies is not one to write an owner into.
    fn take_ownership(&mut self, stated_len: u32) -> Result<Installed, Refusal> {
        let Self {
            medium, staging, ..
        } = self;
        // Checked by the caller, and answered rather than asserted because
        // nothing a peer asks for may fault this domain.
        let Some(medium) = medium.as_mut() else {
            return Err(Refusal {
                cause: "install-no-medium",
                detail: RefusalDetail::None,
                signalled: false,
            });
        };

        let mut region = [0_u8; BOTH_COPIES];
        medium.read_state(&mut region).map_err(establish_refusal)?;
        let image = decode_state(&region).ok_or(Refusal {
            cause: "install-record-absent",
            detail: RefusalDetail::None,
            signalled: true,
        })?;
        let checked = image.check().map_err(|error| Refusal {
            cause: record_cause(error),
            detail: record_detail(error),
            signalled: true,
        })?;
        verify(checked.get()).map_err(|error| Refusal {
            cause: error.cause(),
            detail: RefusalDetail::None,
            signalled: true,
        })?;
        let mut state = checked.into_inner();

        // The snapshot, and the whole reason there is one: the region is the
        // asking domain's to write and it can write it again at any instant, so
        // a package validated through a borrow of it would be a package whose
        // bytes were somebody else's by the time they reached a sector. What is
        // read from here on is this domain's own copy.
        let snapshot = medium.io.staging(SNAPSHOT_SPAN);
        staging.copy(snapshot);
        let adoption = read_package(stated_len, snapshot, &state).map_err(install_refusal)?;

        let endpoint = adoption.endpoint();
        let anchor_fingerprint = adoption.anchor_fingerprint();
        adoption.take_ownership(&mut state);
        // The copy the generation's parity selects, so the record the appliance
        // is currently relying on is not the one being written; the barrier
        // inside is what makes the new one durable rather than merely submitted.
        medium
            .commit(&mut region, &state, Copies::Parity)
            .map_err(establish_refusal)?;
        let generation = state.generation();
        // The record carries the private scalar, and this domain's copy of it
        // has no reason to outlive the write.
        zeroize(&mut region);
        Ok(Installed {
            endpoint,
            anchor_fingerprint,
            generation,
        })
    }

    /// Take the block counters the medium has moved since they were last read.
    ///
    /// An install is the one thing after start-up that submits transfers, so a
    /// shard republished without this would report the boot's numbers forever
    /// and an operator would read an install as having moved nothing.
    fn recount(&mut self) {
        if let Some(medium) = self.medium.as_ref() {
            self.blocks = medium.completed;
            self.faults = medium.requests.faults();
        }
    }

    /// Put a refusal on the console.
    ///
    /// `DomainState::Ready` and not `Refused`: this domain came up, and an
    /// install it would not take changes nothing about that. A `refused` record
    /// here would read as a node that never started.
    fn report(&self, cause: Refusal) {
        announce(&self.sink, DomainState::Ready, DomainDetail::Refusal(cause));
    }

    /// Answer a demand with nothing, saying why, and count it.
    ///
    /// The count is the surface and there is no console record here, deliberately:
    /// this domain's log ring is single-producer and bounded, so a record per
    /// refusal would let the asking domain choose the rate at which the identity
    /// and fingerprint records an operator needs are pushed out of it. What a
    /// refusal means is decided by the domain that asked, which is the one that
    /// knows what it wanted the signature for.
    fn refuse(&mut self, demand: SignDemand, reason: SignRefusal) {
        self.responder.refuse(demand, reason);
        self.signing.refusals = self.signing.refusals.saturating_add(1);
    }

    /// Publish this domain's shard.
    ///
    /// Called at the end of `init` and after every wakeup that served something.
    /// The counters other than the two signing ones are settled by then and are
    /// republished unchanged, because a shard is a whole snapshot rather than a
    /// set of independently writable slots.
    fn publish(&self) {
        self.stats.publish(
            &store_sample(
                self.identity,
                self.signing,
                self.capacity_sectors,
                self.blocks,
                self.faults,
                log_sample(self.sink.dropped(), self.sink.refused()),
            )
            .values(),
        );
    }
}

impl Handler for Store {
    type Error = Infallible;

    /// The asking domain has issued a signing request.
    ///
    /// Microkit coalesces notifications and a wakeup names no request, so the
    /// question is asked of the region rather than of the wakeup — and asked at
    /// most [`DEMANDS_PER_WAKEUP`] times, which is what makes the work one signal
    /// can provoke a constant of this file. `take` answering `None` ends the pass:
    /// there is nothing outstanding, which is the ordinary state of a channel
    /// whose peer is between requests.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        let mut served = 0;
        while served < DEMANDS_PER_WAKEUP {
            let Some(demand) = self.responder.take() else {
                break;
            };
            self.answer(demand);
            served += 1;
        }
        // Only where something happened: a wakeup that found nothing has nothing
        // new to say, and republishing an unchanged shard would put a writer on
        // the region for every spurious signal a peer chooses to send.
        if served > 0 {
            self.publish();
        }
        Ok(())
    }
}
