//! Host-testable virtio 1.0 bring-up: PCI identification, BAR placement, the
//! device-initialization handshake, and virtqueue configuration.
//!
//! # The adversary
//!
//! Every byte this module reads is written by CONCEPT §7.1's **hostile or
//! malfunctioning device**: the configuration-space ids, the capability chain,
//! the BAR type bits, the feature bitmap, the `device_status` readback, the
//! queue count, and each queue's `queue_notify_off`. A merely broken device
//! produces the same bytes as a malicious one, so both are answered the same
//! way — **every rejection is a typed [`BringUpError`] naming the specific
//! cause, and no rejection panics.** A driver protection domain that cannot
//! bring its device up parks; it never faults.
//!
//! What is checked and where is `virtio::pci`'s business, and this module does
//! not re-check it: it composes those checks in the one order the virtio 1.0
//! specification permits, which is the thing `virtio::pci` cannot express.
//!
//! # The handshake ordering is a typestate, not a comment
//!
//! virtio 1.0 §3.1.1 fixes the initialization order, and getting it wrong is
//! silent: a device whose features are written before `DRIVER` is set, or which
//! is told `DRIVER_OK` before its virtqueues carry addresses, misbehaves in
//! ways that surface as a dead link rather than as an error. The order is
//! therefore carried by distinct types, each transition consuming the previous
//! state:
//!
//! ```text
//! identify ──▶ Identified ──place_bar──▶ PlacedBar ──map──▶ Offered
//!    │                                                         │
//!    │                                                    acknowledge
//!    │                                                         ▼
//!    │        Live ◀──go_live── Configured ◀─configure_queues─ Negotiated
//!    │                                                         ▲
//!    └── every step returns Err(BringUpError) instead    negotiate_features
//!        of panicking; nothing continues past a rejection.     │
//!                                                         Acknowledged
//! ```
//!
//! There is no constructor for any state but [`Identified`], and no transition
//! that skips one, so a caller cannot write the sequence in the wrong order,
//! repeat a step, or reach a later step without the earlier one having
//! succeeded. Concretely: `set_driver_features` is reachable only from
//! [`Acknowledged`], which only [`Offered::acknowledge`] produces after the
//! reset and the `ACKNOWLEDGE | DRIVER` writes; and a ringable doorbell exists
//! only inside [`Live`], which only [`Configured::go_live`] produces after
//! `DRIVER_OK` — so **the driver cannot notify a device it has not yet
//! declared itself ready to**, which was previously a comment.
//!
//! # Failure is signalled to the device where the device can hear it
//!
//! `STATUS_FAILED` lives in the common-configuration structure, inside the BAR.
//! Before [`PlacedBar::map`] that BAR has not been placed, so a rejection in
//! [`identify`] or [`Identified::place_bar`] **cannot** be signalled at all and
//! the device is left decoding nothing. From [`Offered`] onward the register is
//! reachable and every rejection writes `STATUS_FAILED` before returning, so
//! the device is told to stop rather than left mid-handshake with a driver that
//! walked away. Which of the two happened is not left to the caller's memory:
//! [`BringUpError::signalled_to_device`] answers it per variant, and
//! `status_failed_is_signalled_once_the_device_is_reachable` proves the two
//! agree.
//!
//! # The region constants are this crate's, not the caller's
//!
//! [`BAR_WINDOW_SIZE`], [`VQ_REGION_SIZE`], [`TX_VQ_OFFSET`] and
//! [`QUEUE_SIZE`] were duplicated in the driver protection domain, where the
//! bound a device offset is checked against and the window actually mapped were
//! two independently editable numbers. They are defined here once; the PD maps
//! the window these constants describe and passes only pointers. The remaining
//! cross-check — that `BAR_WINDOW_SIZE` and `VQ_REGION_SIZE` equal the `size=`
//! attributes of the `bar*` and `vq*` memory regions in
//! `systems/qemu-x86_64/librefirewall.system` — has **no enforcer on this
//! side** and is stated as such on each constant (DOC-7).

use pd_runtime::MAPPING_ALIGN;
use virtio::net::features;
use virtio::pci::{
    self, BarError, CapError, CommonCfg, Doorbell, NotifyError, PciConfig, QueueSetupError,
    ResetError, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FAILED,
    STATUS_FEATURES_OK, VIRTIO_NET_DEVICE_ID, VIRTIO_VENDOR_ID, VirtioCaps,
};
use virtio::queue::{QueueLayout, SplitVirtqueue};

/// virtio-net virtqueue index that receives.
pub const RX_QUEUE: u16 = 0;
/// virtio-net virtqueue index that transmits.
pub const TX_QUEUE: u16 = 1;

/// Descriptors per virtqueue: how many buffers may be at the device at once in
/// one direction. Also the per-call bound on every device-driven loop in this
/// crate, which is why it is a driver-owned constant and never a device value.
pub const QUEUE_SIZE: usize = 16;

/// Byte offset of the transmit virtqueue within the virtqueue DMA region; the
/// receive virtqueue sits at offset 0.
pub const TX_VQ_OFFSET: usize = 0x800;

/// Size of the virtqueue DMA region a driver protection domain maps.
///
/// **Unenforced cross-check (DOC-7):** this must equal the `size` attribute of
/// the `vq0`/`vq1` memory regions in
/// `systems/qemu-x86_64/librefirewall.system`. Nothing in this workspace
/// compares the two — the system description is XML consumed by the Microkit
/// tool, and no build step reads it back into Rust. The const assertions below
/// bound the virtqueue layout against *this* number, so an inconsistency here
/// is caught; an inconsistency against the `.system` file is not, and would
/// surface as the transmit virtqueue lying outside the mapping.
pub const VQ_REGION_SIZE: usize = 0x1000;

/// Size of the device MMIO BAR window a driver protection domain maps, and the
/// bound every device-supplied BAR offset is checked against.
///
/// **Unenforced cross-check (DOC-7):** as [`VQ_REGION_SIZE`], this must equal
/// the `size` attribute of the `bar0`/`bar1` memory regions in
/// `systems/qemu-x86_64/librefirewall.system`, and nothing compares them. It is
/// also the alignment [`Identified::place_bar`] requires of the physical
/// address the BAR is relocated to, so the mapped window and the programmed
/// window describe the same bytes.
pub const BAR_WINDOW_SIZE: usize = 0x4000;

/// The virtqueue this driver programs into its device, in both directions. The
/// layout the device is told about and the layout the driver walks are the same
/// type, so they cannot disagree.
pub type DriverVirtqueue = SplitVirtqueue<QUEUE_SIZE>;

/// The feature bits this driver will accept if the device offers them.
///
/// Negotiating a feature changes what the device is *permitted to produce*, so
/// accepting one no code handles would licence buffers this driver cannot
/// service — merged receive buffers spanning descriptors, or a header whose
/// offload fields must be acted on (`virtio::net`). The mask is therefore the
/// set this driver implements, not the set it recognises, and virtio 1.0 is the
/// only member.
pub const ACCEPTED_FEATURES: u64 = features::VIRTIO_F_VERSION_1;

// Both virtqueues must fit the DMA region with the transmit queue's 16-byte
// descriptor-table alignment preserved, and both mapped regions must be whole
// pages, since Microkit maps at page granularity.
const _: () = assert!(DriverVirtqueue::LAYOUT.total_bytes <= TX_VQ_OFFSET);
const _: () = assert!(TX_VQ_OFFSET.is_multiple_of(16));
const _: () = assert!(TX_VQ_OFFSET + DriverVirtqueue::LAYOUT.total_bytes <= VQ_REGION_SIZE);
const _: () = assert!(VQ_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
const _: () = assert!(BAR_WINDOW_SIZE.is_multiple_of(MAPPING_ALIGN));
// The common-configuration structure is the one thing the BAR window must be
// able to hold whatever offset the device names, or `within` can never pass.
const _: () = assert!(pci::COMMON_CFG_MIN_LEN <= BAR_WINDOW_SIZE);

/// Why bring-up refused to continue.
///
/// Every variant carries the value that caused the rejection, because an
/// operator with no shell (CONCEPT §11) can only tell a device that exposes no
/// capability list from one whose capability chain loops if the two produce
/// different console lines. A single "bring-up failed" would make the two
/// indistinguishable, which is the failure mode ENG-12 names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BringUpError {
    /// The function at the pinned BDF is not a modern virtio-net device. The
    /// driver is built for one specific device (see the protection domain's
    /// header) and binds nothing else.
    NotVirtioNet {
        /// PCI vendor id read from configuration space.
        vendor: u16,
        /// PCI device id read from configuration space.
        device: u16,
    },
    /// The virtio PCI capability chain could not be resolved. The inner
    /// [`CapError`] distinguishes an absent capability list from a looped
    /// chain, an invalid BAR index, structures split across BARs, and a missing
    /// required structure.
    Capabilities(CapError),
    /// A virtio structure's offset, or its extent, lies outside the BAR window
    /// this driver mapped. The offsets are the device's own claim, so this is a
    /// malformed device rather than a driver error.
    StructuresOutsideBar {
        /// The offsets the device claimed.
        caps: VirtioCaps,
        /// The window the driver mapped, i.e. [`BAR_WINDOW_SIZE`].
        bar_window: usize,
    },
    /// The device claimed a common-configuration offset that is not
    /// [`pci::COMMON_CFG_ALIGN`]-aligned.
    ///
    /// Distinct from [`StructuresOutsideBar`](Self::StructuresOutsideBar)
    /// because it is a different fault with the same shape: the structure fits
    /// the mapped window perfectly and is still unusable, since its registers
    /// are reached as `u16` and `u32` volatile accesses and the offset decides
    /// their alignment. Refused here so no `CommonCfg` is ever built on it.
    CommonCfgMisaligned {
        /// The offset the device claimed for its common-configuration
        /// structure.
        offset: u32,
        /// The alignment that structure's registers require, i.e.
        /// [`pci::COMMON_CFG_ALIGN`].
        required: usize,
    },
    /// The BAR holding the virtio structures is not the 64-bit memory BAR this
    /// transport relocates.
    BarNotSixtyFourBit {
        /// The BAR index the capability chain named.
        bar: u8,
    },
    /// A BAR operation refused the index the capability chain named; see
    /// [`BarError`].
    BarIndexRefused(BarError),
    /// The physical address the build patched in as the BAR relocation target
    /// is unusable: zero, above 4 GiB, or not [`BAR_WINDOW_SIZE`]-aligned. Not
    /// device input — this is the `bar_paddr` setvar from the system
    /// description, and a wrong value here means the mapped window and the
    /// programmed window would describe different bytes.
    BarTargetUnusable {
        /// The address the build supplied.
        paddr: usize,
    },
    /// The device did not acknowledge the reset within the transport's poll
    /// bound; see [`ResetError`].
    ResetRefused(ResetError),
    /// The device does not offer virtio 1.0, so the modern layout this driver
    /// programs does not apply to it.
    NoVirtio1 {
        /// The full feature bitmap the device offered.
        offered: u64,
    },
    /// The device cleared `FEATURES_OK` on readback, refusing the negotiated
    /// feature set. virtio 1.0 §3.1.1 requires initialization to stop here.
    FeaturesRejected {
        /// The `device_status` byte read back.
        status: u8,
    },
    /// The device offers too few virtqueues to carry both directions.
    TransmitQueueAbsent {
        /// How many virtqueues the device reports.
        offered: u16,
        /// How many this driver needs, i.e. `TX_QUEUE + 1`.
        required: u16,
    },
    /// The physical address the build patched in for the virtqueue DMA region
    /// is unusable: zero, not page-aligned, or so high that the region would
    /// wrap. Like [`BarTargetUnusable`](Self::BarTargetUnusable) this is build
    /// data, checked because the value is programmed into a device that will
    /// DMA to it.
    VirtqueueRegionUnusable {
        /// The address the build supplied.
        paddr: u64,
    },
    /// The device refused to have a virtqueue programmed; see
    /// [`QueueSetupError`] for whether the queue is absent or too small.
    QueueSetupRefused {
        /// Which virtqueue was being programmed.
        index: u16,
        /// The transport's reason.
        error: QueueSetupError,
    },
    /// The device named a doorbell slot that does not lie within the mapped BAR
    /// window, or one at an odd offset; see [`NotifyError`].
    DoorbellRefused {
        /// Which virtqueue's doorbell was being placed.
        index: u16,
        /// The transport's reason.
        error: NotifyError,
    },
}

impl BringUpError {
    /// Whether `STATUS_FAILED` was written to the device before this error was
    /// returned.
    ///
    /// False for every rejection raised before [`PlacedBar::map`], because the
    /// status register lives in a BAR that has not been placed and there is
    /// nothing to write it through — the device is simply left decoding
    /// nothing. True from [`Offered::acknowledge`] onward. A caller reports
    /// this rather than deciding it, so the console line says which of the two
    /// states the device was left in.
    #[must_use]
    pub fn signalled_to_device(&self) -> bool {
        match self {
            Self::NotVirtioNet { .. }
            | Self::Capabilities(_)
            | Self::StructuresOutsideBar { .. }
            | Self::CommonCfgMisaligned { .. }
            | Self::BarNotSixtyFourBit { .. }
            | Self::BarIndexRefused(_)
            | Self::BarTargetUnusable { .. } => false,
            Self::ResetRefused(_)
            | Self::NoVirtio1 { .. }
            | Self::FeaturesRejected { .. }
            | Self::TransmitQueueAbsent { .. }
            | Self::VirtqueueRegionUnusable { .. }
            | Self::QueueSetupRefused { .. }
            | Self::DoorbellRefused { .. } => true,
        }
    }
}

/// One virtqueue's doorbell: writing it tells the device to examine that queue.
///
/// Abstracted from `virtio::pci::Doorbell` so the bring-up sequence and the
/// poll loop can be driven against a recording stand-in on the host. A doorbell
/// write is a two-byte MMIO store into a device BAR, which no host test can
/// observe *in order* relative to the status writes around it — and that order
/// is precisely what [`Configured::go_live`] exists to get right.
pub trait QueueDoorbell {
    /// Tell the device to examine `queue`.
    fn ring(&self, queue: u16);
}

impl QueueDoorbell for Doorbell {
    fn ring(&self, queue: u16) {
        Doorbell::ring(self, queue);
    }
}

/// Everything bring-up does to a virtio device once its BAR is placed: the
/// common-configuration registers, and turning a queue's `queue_notify_off`
/// into a doorbell.
///
/// The one shipped implementation is [`MappedDevice`], which is the device's
/// real MMIO. The trait exists for the same reason `virtio::pci`'s
/// `poll_status_cleared` is a closure rather than a method: the interesting
/// device behaviours — refusing a reset, clearing `FEATURES_OK` on readback,
/// reporting one virtqueue — are *disagreements* between what the driver wrote
/// and what it reads back, and a `CommonCfg` mapped over plain host memory
/// reads back exactly what was written, so none of them can be modelled through
/// it. Without this seam those branches would be unreachable on the host and
/// the QEMU device would be their only test, which it is not, because QEMU's
/// virtio-net conforms.
pub trait VirtioDevice {
    /// The doorbell this device hands out; see [`place_doorbell`](Self::place_doorbell).
    type Doorbell: QueueDoorbell;

    /// Reset the device and wait, bounded, for it to acknowledge.
    ///
    /// # Errors
    /// [`ResetError`] when the device does not acknowledge within the bound.
    fn reset(&self) -> Result<(), ResetError>;

    /// Read the `device_status` byte back.
    fn status(&self) -> u8;

    /// Overwrite the `device_status` byte.
    fn set_status(&self, value: u8);

    /// The device's 64-bit feature bitmap.
    fn device_features(&self) -> u64;

    /// Write the feature bitmap the driver accepts.
    fn set_driver_features(&self, features: u64);

    /// How many virtqueues the device offers.
    fn num_queues(&self) -> u16;

    /// Program one virtqueue's ring addresses and enable it, returning the
    /// device's `queue_notify_off` for it — raw device output, bounded by
    /// nothing, which is why it is only ever consumed by
    /// [`place_doorbell`](Self::place_doorbell).
    ///
    /// # Errors
    /// [`QueueSetupError`] when the device says the queue does not exist or is
    /// smaller than `layout` requires.
    fn setup_queue(
        &self,
        index: u16,
        layout: &QueueLayout,
        ring_paddr: u64,
    ) -> Result<u16, QueueSetupError>;

    /// Turn a `queue_notify_off` into a doorbell, bounding it against the
    /// window the device's BAR is mapped into.
    ///
    /// # Errors
    /// [`NotifyError`] when the slot the device names lies outside that window
    /// or at an odd offset.
    fn place_doorbell(&self, notify_off: u16) -> Result<Self::Doorbell, NotifyError>;
}

/// A virtio device reached through its mapped MMIO BAR.
///
/// It has no public constructor on purpose. The only way to obtain one is
/// [`PlacedBar::map`], which is reachable only from [`identify`] — so
/// `self.caps` has provably passed both `VirtioCaps::within(BAR_WINDOW_SIZE)`
/// and `VirtioCaps::common_is_aligned`, and those two together are exactly what
/// make the common-configuration pointer and every doorbell placement below
/// sound. Handing the type a public `new` would put unvalidated capability
/// offsets one call away from a raw pointer.
pub struct MappedDevice {
    common: CommonCfg,
    bar_base: *mut u8,
    caps: VirtioCaps,
}

impl VirtioDevice for MappedDevice {
    type Doorbell = Doorbell;

    fn reset(&self) -> Result<(), ResetError> {
        self.common.reset()
    }

    fn status(&self) -> u8 {
        self.common.status()
    }

    fn set_status(&self, value: u8) {
        self.common.set_status(value);
    }

    fn device_features(&self) -> u64 {
        self.common.device_features()
    }

    fn set_driver_features(&self, features: u64) {
        self.common.set_driver_features(features);
    }

    fn num_queues(&self) -> u16 {
        self.common.num_queues()
    }

    fn setup_queue(
        &self,
        index: u16,
        layout: &QueueLayout,
        ring_paddr: u64,
    ) -> Result<u16, QueueSetupError> {
        self.common.setup_queue(index, layout, ring_paddr)
    }

    fn place_doorbell(&self, notify_off: u16) -> Result<Doorbell, NotifyError> {
        // SAFETY: `PlacedBar::map` is this type's only constructor and its
        // contract is that `bar_base` names a live, `COMMON_CFG_ALIGN`-aligned
        // mapping of `BAR_WINDOW_SIZE` bytes outliving this value — which
        // discharges `Doorbell::new`'s contract, whose alignment requirement is
        // two bytes and so is subsumed by the four. The device-supplied
        // `notify_off` needs nothing from this side: `Doorbell::new` is the
        // component that bounds and aligns it, proved by `virtio::pci`'s
        // `doorbell_rejects_a_slot_outside_the_bar`.
        unsafe { Doorbell::new(self.bar_base, BAR_WINDOW_SIZE, &self.caps, notify_off) }
    }
}

/// Identify the device at the pinned function and validate everything about it
/// that can be checked before its BAR is placed.
///
/// In order: the (vendor, device) id pair must be modern virtio-net; the virtio
/// capability chain must resolve; every structure offset must fit
/// [`BAR_WINDOW_SIZE`]; the common-configuration offset must additionally be
/// [`pci::COMMON_CFG_ALIGN`]-aligned; and the BAR holding them must be the
/// 64-bit memory BAR this transport relocates.
///
/// **This function is the enforcer the rest of the chain names.** Both offset
/// checks are made here and nowhere else, and every later state is reachable
/// only through the [`Identified`] this returns, so what a `CommonCfg` pointer
/// rests on is established before the value that could form one exists rather
/// than delegated onward to a caller (DOC-7). The extent and the alignment are
/// separate faults with separate errors, because an offset that fits the window
/// can still misalign every register behind it.
///
/// # Errors
/// The corresponding [`BringUpError`] for whichever of those the device fails.
/// None of them is signalled to the device — see the module header.
pub fn identify(config: &PciConfig) -> Result<Identified, BringUpError> {
    let (vendor, device) = config.ids();
    if vendor != VIRTIO_VENDOR_ID || device != VIRTIO_NET_DEVICE_ID {
        return Err(BringUpError::NotVirtioNet { vendor, device });
    }
    let caps = pci::find_virtio_caps(config).map_err(BringUpError::Capabilities)?;
    if !caps.within(BAR_WINDOW_SIZE) {
        return Err(BringUpError::StructuresOutsideBar {
            caps,
            bar_window: BAR_WINDOW_SIZE,
        });
    }
    if !caps.common_is_aligned() {
        return Err(BringUpError::CommonCfgMisaligned {
            offset: caps.common,
            required: pci::COMMON_CFG_ALIGN,
        });
    }
    match config.bar_is_64bit(caps.bar) {
        Ok(true) => Ok(Identified { caps }),
        Ok(false) => Err(BringUpError::BarNotSixtyFourBit { bar: caps.bar }),
        Err(error) => Err(BringUpError::BarIndexRefused(error)),
    }
}

/// A device that is the one this driver is built for, whose virtio structures
/// fit the window the driver mapped and whose common-configuration offset is
/// aligned for the registers behind it. Produced only by [`identify`], so both
/// facts hold of every value of this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identified {
    caps: VirtioCaps,
}

impl Identified {
    /// Where the device says its virtio structures are, already bounded against
    /// [`BAR_WINDOW_SIZE`] and checked for common-configuration alignment by
    /// [`identify`].
    #[must_use]
    pub fn caps(&self) -> VirtioCaps {
        self.caps
    }

    /// Relocate the device's BAR to `bar_paddr` and re-enable memory decoding
    /// and bus mastering.
    ///
    /// `bar_paddr` is build data — the `bar_paddr` setvar the Microkit tool
    /// patches from the system description — and is validated rather than
    /// trusted, because it is the address the driver *also* mapped: a value
    /// that is not [`BAR_WINDOW_SIZE`]-aligned would leave the mapped window
    /// and the decoded window describing different bytes, and every subsequent
    /// bound would be checked against the wrong region.
    ///
    /// # Errors
    /// [`BringUpError::BarTargetUnusable`] when `bar_paddr` is zero, above
    /// 4 GiB, or misaligned, and [`BringUpError::BarIndexRefused`] when the BAR
    /// index cannot be the low half of a 64-bit pair. Nothing is written to the
    /// device in either case.
    pub fn place_bar(
        self,
        config: &PciConfig,
        bar_paddr: usize,
    ) -> Result<PlacedBar, BringUpError> {
        let unusable = BringUpError::BarTargetUnusable { paddr: bar_paddr };
        if bar_paddr == 0 || !bar_paddr.is_multiple_of(BAR_WINDOW_SIZE) {
            return Err(unusable);
        }
        // A 64-bit BAR pair is programmed with a zero high half here, so the
        // target must be representable in the low register on its own.
        let Ok(address) = u32::try_from(bar_paddr) else {
            return Err(unusable);
        };
        config
            .reprogram_bar64(self.caps.bar, address)
            .map_err(BringUpError::BarIndexRefused)?;
        config.enable_memory_and_bus_master();
        Ok(PlacedBar { caps: self.caps })
    }
}

/// A device whose BAR now decodes at the address the driver mapped. Produced
/// only by [`Identified::place_bar`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacedBar {
    caps: VirtioCaps,
}

impl PlacedBar {
    /// Attach to the mapped BAR window, yielding the first handshake state.
    ///
    /// # Safety
    /// `bar_base` must point to a live mapping of exactly [`BAR_WINDOW_SIZE`]
    /// bytes of the BAR just relocated, at least
    /// [`pci::COMMON_CFG_ALIGN`]-aligned (a Microkit mapping is page-aligned,
    /// so this is free), and it must stay mapped for as long as the returned
    /// value or anything derived from it is used.
    ///
    /// Four bytes of alignment, not two: the common-configuration registers are
    /// reached as `u32` volatiles, and the alignment of `bar_base + caps.common`
    /// is what makes them aligned, so the window has to carry at least what
    /// those accesses need. It subsumes the two bytes `Doorbell::new` asks for.
    ///
    /// Nothing is required of the caller about the *device's* offsets.
    /// [`identify`] checked both halves of `CommonCfg::new`'s contract before
    /// this type could exist — `caps.within(BAR_WINDOW_SIZE)` for the extent and
    /// `caps.common_is_aligned()` for the alignment — and `Doorbell::new` bounds
    /// and aligns the notify slot in [`MappedDevice::place_doorbell`]. Those are
    /// enforcements, not assumptions:
    /// `a_structure_outside_the_mapped_window_is_refused_before_any_dereference`
    /// and `a_misaligned_common_configuration_offset_is_refused_before_any_dereference`
    /// prove the first two, `virtio::pci`'s `doorbell_rejects_a_misaligned_slot`
    /// the third (DOC-7).
    #[must_use]
    pub unsafe fn map(self, bar_base: *mut u8) -> Offered<MappedDevice> {
        // SAFETY: `caps` reached this value through `identify`, which checked
        // `caps.within(BAR_WINDOW_SIZE)` — bounding
        // `caps.common + COMMON_CFG_MIN_LEN` against the window size — and
        // `caps.common_is_aligned()`, bounding `caps.common` modulo
        // `COMMON_CFG_ALIGN`. Nothing outside this module can produce a
        // `PlacedBar` any other way, its field being private, and this module's
        // own tests assert both predicates at each literal construction. The
        // caller guarantees `bar_base` names a live, `COMMON_CFG_ALIGN`-aligned
        // mapping of exactly `BAR_WINDOW_SIZE` bytes, so `bar_base +
        // caps.common` is itself `COMMON_CFG_ALIGN`-aligned and starts at least
        // `COMMON_CFG_MIN_LEN` readable and writable bytes inside it —
        // `CommonCfg::new`'s contract in both of its halves.
        let common = unsafe { CommonCfg::new(bar_base.add(self.caps.common as usize)) };
        Offered {
            device: MappedDevice {
                common,
                bar_base,
                caps: self.caps,
            },
        }
    }
}

/// A reachable device that has not been touched by the handshake yet.
pub struct Offered<D> {
    device: D,
}

/// Wrap an already-reachable device in the first handshake state.
///
/// Test-only, and deliberately not a public constructor: on a real device
/// "reachable" means the BAR has been relocated and mapped, which is what
/// [`PlacedBar::map`] establishes and nothing else can. A stand-in device needs
/// none of that, and this is how the sibling modules' tests get one.
#[cfg(test)]
pub(crate) fn offered<D: VirtioDevice>(device: D) -> Offered<D> {
    Offered { device }
}

impl<D: VirtioDevice> Offered<D> {
    /// Reset the device, then tell it the driver has noticed it and knows how
    /// to drive it (`ACKNOWLEDGE`, then `ACKNOWLEDGE | DRIVER`).
    ///
    /// Both writes are cumulative ORs of the bits set so far, as virtio 1.0
    /// §3.1.1 requires: the device latches the status byte as written, so
    /// setting `DRIVER` alone would retract `ACKNOWLEDGE`.
    ///
    /// # Errors
    /// [`BringUpError::ResetRefused`] when the device never acknowledges the
    /// reset. `STATUS_FAILED` is written first.
    pub fn acknowledge(self) -> Result<Acknowledged<D>, BringUpError> {
        if let Err(error) = self.device.reset() {
            self.device.set_status(STATUS_FAILED);
            return Err(BringUpError::ResetRefused(error));
        }
        self.device.set_status(STATUS_ACKNOWLEDGE);
        self.device.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        Ok(Acknowledged {
            device: self.device,
        })
    }
}

/// A device that has been reset and told the driver is present. Produced only
/// by [`Offered::acknowledge`], which is what makes the feature write below
/// reachable only after `DRIVER` is set.
pub struct Acknowledged<D> {
    device: D,
}

impl<D: VirtioDevice> Acknowledged<D> {
    /// Negotiate features and confirm the device can carry both directions.
    ///
    /// Reads the offered bitmap, masks it to [`ACCEPTED_FEATURES`], writes the
    /// result back, sets `FEATURES_OK`, and **re-reads the status byte** — a
    /// virtio 1.0 device may clear that bit to refuse the set, and a driver
    /// that does not read it back proceeds against a device that has already
    /// said no. Finally the virtqueue count is checked, because a device
    /// offering one queue cannot transmit.
    ///
    /// # Errors
    /// [`BringUpError::NoVirtio1`] when the device does not offer virtio 1.0,
    /// [`BringUpError::FeaturesRejected`] when it clears `FEATURES_OK`, and
    /// [`BringUpError::TransmitQueueAbsent`] when it offers too few queues.
    /// Each writes `STATUS_FAILED` before returning.
    pub fn negotiate_features(self) -> Result<Negotiated<D>, BringUpError> {
        let offered = self.device.device_features();
        let negotiated = offered & ACCEPTED_FEATURES;
        if negotiated & features::VIRTIO_F_VERSION_1 == 0 {
            self.device.set_status(STATUS_FAILED);
            return Err(BringUpError::NoVirtio1 { offered });
        }
        self.device.set_driver_features(negotiated);
        self.device
            .set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
        let status = self.device.status();
        if status & STATUS_FEATURES_OK == 0 {
            self.device.set_status(STATUS_FAILED);
            return Err(BringUpError::FeaturesRejected { status });
        }
        let queues = self.device.num_queues();
        if queues <= TX_QUEUE {
            self.device.set_status(STATUS_FAILED);
            return Err(BringUpError::TransmitQueueAbsent {
                offered: queues,
                required: TX_QUEUE + 1,
            });
        }
        Ok(Negotiated {
            device: self.device,
            features: negotiated,
        })
    }
}

/// A device that has accepted this driver's feature set and offers both
/// virtqueues. Produced only by [`Acknowledged::negotiate_features`].
pub struct Negotiated<D> {
    device: D,
    features: u64,
}

impl<D: VirtioDevice> Negotiated<D> {
    /// The feature bits actually negotiated — the offered set masked to
    /// [`ACCEPTED_FEATURES`], never the device's raw offer.
    #[must_use]
    pub fn features(&self) -> u64 {
        self.features
    }

    /// Program both virtqueues into the device and place their doorbells.
    ///
    /// The receive queue is programmed at `vq_region_paddr` and the transmit
    /// queue at `vq_region_paddr + TX_VQ_OFFSET`, matching the single DMA
    /// region the driver maps. `vq_region_paddr` is build data, checked for the
    /// same reason `bar_paddr` is: it is handed to a device that will DMA to
    /// it, so a zero, misaligned, or wrapping value must fail visibly rather
    /// than point the hardware at whatever lies there.
    ///
    /// The doorbells are placed here rather than returned as offsets, so a
    /// `queue_notify_off` never leaves this module as a bare number: it is
    /// either bounded into a [`QueueDoorbell`] or it is an error.
    ///
    /// # Errors
    /// [`BringUpError::VirtqueueRegionUnusable`] for a bad region address,
    /// [`BringUpError::QueueSetupRefused`] when the device refuses a queue, and
    /// [`BringUpError::DoorbellRefused`] when it names an unusable doorbell
    /// slot. Each writes `STATUS_FAILED` before returning.
    pub fn configure_queues(self, vq_region_paddr: u64) -> Result<Configured<D>, BringUpError> {
        // The whole region must be addressable, because the transmit queue's
        // address is derived by adding into it below.
        let region_addressable = vq_region_paddr.checked_add(VQ_REGION_SIZE as u64).is_some();
        if !region_addressable
            || vq_region_paddr == 0
            || !vq_region_paddr.is_multiple_of(MAPPING_ALIGN as u64)
        {
            self.device.set_status(STATUS_FAILED);
            return Err(BringUpError::VirtqueueRegionUnusable {
                paddr: vq_region_paddr,
            });
        }

        let layout = &DriverVirtqueue::LAYOUT;
        let receive = self.program(RX_QUEUE, layout, vq_region_paddr)?;
        // Cannot overflow: `TX_VQ_OFFSET < VQ_REGION_SIZE` (const-asserted
        // above) and `vq_region_paddr + VQ_REGION_SIZE` was just checked.
        let transmit = self.program(TX_QUEUE, layout, vq_region_paddr + TX_VQ_OFFSET as u64)?;
        Ok(Configured {
            device: self.device,
            receive,
            transmit,
        })
    }

    /// Program one virtqueue and bound its doorbell, signalling `STATUS_FAILED`
    /// on either refusal. Shared by both directions so the failure handling is
    /// written once.
    fn program(
        &self,
        index: u16,
        layout: &QueueLayout,
        ring_paddr: u64,
    ) -> Result<D::Doorbell, BringUpError> {
        let notify_off = match self.device.setup_queue(index, layout, ring_paddr) {
            Ok(notify_off) => notify_off,
            Err(error) => {
                self.device.set_status(STATUS_FAILED);
                return Err(BringUpError::QueueSetupRefused { index, error });
            }
        };
        self.device.place_doorbell(notify_off).map_err(|error| {
            self.device.set_status(STATUS_FAILED);
            BringUpError::DoorbellRefused { index, error }
        })
    }
}

/// A device whose virtqueues are programmed and whose doorbells are placed, but
/// which has not been told the driver is ready.
///
/// This is the state in which a driver fills the receive virtqueue with
/// buffers: the descriptors are published, and the device is not yet permitted
/// to act on a notification. The doorbells are held privately here and become
/// ringable only in [`Live`], so the "`DRIVER_OK` before the first doorbell"
/// rule is a property of the types rather than of a comment.
pub struct Configured<D: VirtioDevice> {
    device: D,
    receive: D::Doorbell,
    transmit: D::Doorbell,
}

impl<D: VirtioDevice> Configured<D> {
    /// Set `DRIVER_OK` and then ring the receive doorbell, in that order.
    ///
    /// The order is the whole point and is not the caller's to get right: a
    /// virtio device need not act on a notification before the driver has
    /// declared itself ready, so ringing first can lose every buffer already
    /// posted and leave the link dead with no error anywhere. Because the only
    /// [`QueueDoorbell`] in existence is the one this call moves into [`Live`],
    /// there is no earlier ring to write.
    #[must_use]
    pub fn go_live(self) -> Live<D> {
        self.device
            .set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
        let live = Live {
            receive: self.receive,
            transmit: self.transmit,
        };
        live.ring_receive();
        live
    }
}

/// A live device: the only state from which a doorbell can be rung.
///
/// The device handle itself is dropped at [`Configured::go_live`]: past
/// `DRIVER_OK` the steady-state driver touches no common-configuration
/// register, only the two doorbells and the virtqueues in the DMA region, so
/// keeping the MMIO handle would be reach this domain does not need.
pub struct Live<D: VirtioDevice> {
    receive: D::Doorbell,
    transmit: D::Doorbell,
}

impl<D: VirtioDevice> Live<D> {
    /// Tell the device to examine the receive virtqueue.
    pub fn ring_receive(&self) {
        self.receive.ring(RX_QUEUE);
    }

    /// Tell the device to examine the transmit virtqueue.
    pub fn ring_transmit(&self) {
        self.transmit.ring(TX_QUEUE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_device::{Event, FakeDevice, Log};
    use proptest::prelude::*;
    use std::boxed::Box;
    use std::vec;

    /// A buffer carrying the alignment a Microkit mapping supplies, used for
    /// both fixture regions below.
    ///
    /// `[u8; N]` has `align_of == 1`, so a fixture handing one to
    /// `PciConfig::new` or `PlacedBar::map` would under-deliver on the very
    /// contract under test and manufacture its own misalignment — which it
    /// could then not tell apart from the device's. Page alignment is what the
    /// real mappings have, so it is what the fixtures have.
    #[repr(C, align(4096))]
    struct MappedRegion<const N: usize>([u8; N]);

    impl<const N: usize> core::ops::Deref for MappedRegion<N> {
        type Target = [u8; N];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<const N: usize> core::ops::DerefMut for MappedRegion<N> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    // A synthetic 4 KiB configuration space with a virtio capability chain, so
    // `identify` and `place_bar` run against real `PciConfig` accessors over
    // plain memory — the same pattern `virtio::pci`'s own tests use.
    struct FakeConfig {
        bytes: Box<MappedRegion<4096>>,
    }

    // Configuration-space offsets the fixture writes. Private to `virtio::pci`,
    // restated here because a test that cannot address the registers cannot
    // model a malformed device at all.
    const CFG_VENDOR: usize = 0x00;
    const CFG_DEVICE: usize = 0x02;
    const CFG_STATUS: usize = 0x06;
    const CFG_CAP_PTR: usize = 0x34;
    const CFG_BAR0: usize = 0x10;
    const CAP_LIST_BIT: u16 = 1 << 4;
    const CAP_ID_VNDR: u8 = 0x09;
    /// Memory BAR, 64-bit type: bit 0 clear, bits [2:1] == 0b10.
    const BAR_TYPE_64BIT: u32 = 0b100;

    impl FakeConfig {
        /// A conforming modern virtio-net device in BAR 4, with all four virtio
        /// structures inside a `BAR_WINDOW_SIZE` window.
        fn conforming() -> Self {
            let mut fake = Self {
                bytes: Box::new(MappedRegion([0u8; 4096])),
            };
            fake.w16(CFG_VENDOR, VIRTIO_VENDOR_ID);
            fake.w16(CFG_DEVICE, VIRTIO_NET_DEVICE_ID);
            fake.w16(CFG_STATUS, CAP_LIST_BIT);
            fake.bytes[CFG_CAP_PTR] = 0x40;
            fake.put_cap(0x40, 0x50, 1, 4, 0x0000, 16);
            fake.put_cap(0x50, 0x64, 2, 4, 0x3000, 20);
            fake.w32(0x50 + 16, 4);
            fake.put_cap(0x64, 0x74, 3, 4, 0x1000, 16);
            fake.put_cap(0x74, 0x00, 4, 4, 0x2000, 16);
            fake.w32(CFG_BAR0 + 4 * 4, BAR_TYPE_64BIT);
            fake
        }

        fn w16(&mut self, off: usize, v: u16) {
            self.bytes[off..off + 2].copy_from_slice(&v.to_le_bytes());
        }
        fn w32(&mut self, off: usize, v: u32) {
            self.bytes[off..off + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn r32(&self, off: usize) -> u32 {
            u32::from_le_bytes(self.bytes[off..off + 4].try_into().unwrap())
        }
        fn r16(&self, off: usize) -> u16 {
            u16::from_le_bytes(self.bytes[off..off + 2].try_into().unwrap())
        }
        fn put_cap(&mut self, at: usize, next: u8, cfg_type: u8, bar: u8, offset: u32, len: u8) {
            self.bytes[at] = CAP_ID_VNDR;
            self.bytes[at + 1] = next;
            self.bytes[at + 2] = len;
            self.bytes[at + 3] = cfg_type;
            self.bytes[at + 4] = bar;
            self.w32(at + 8, offset);
        }
        fn config(&mut self) -> PciConfig {
            // SAFETY: `self.bytes` is a live, page-aligned,
            // configuration-space-sized buffer owned by this test and outliving
            // the value — `PciConfig::new`'s contract over plain memory.
            unsafe { PciConfig::new(self.bytes.as_mut_ptr()) }
        }
    }

    /// Run the whole handshake against `device`, from [`Offered`] to [`Live`].
    fn bring_up(device: FakeDevice) -> Result<Live<FakeDevice>, BringUpError> {
        Ok(Offered { device }
            .acknowledge()?
            .negotiate_features()?
            .configure_queues(0x3000_0000)?
            .go_live())
    }

    #[test]
    fn a_conforming_device_is_identified_and_its_bar_relocated() {
        let mut fake = FakeConfig::conforming();
        let identified = identify(&fake.config()).expect("a conforming device");
        assert_eq!(identified.caps().bar, 4);
        assert_eq!(identified.caps().common, 0);

        identified
            .place_bar(&fake.config(), 0x5000_0000)
            .expect("an aligned 32-bit target");
        // The low half carries the address, the high half is cleared, and
        // decoding is on again: bit 1 (memory) and bit 2 (bus master).
        assert_eq!(fake.r32(CFG_BAR0 + 4 * 4), 0x5000_0000);
        assert_eq!(fake.r32(CFG_BAR0 + 5 * 4), 0);
        assert_eq!(fake.r16(0x04) & 0b110, 0b110);
    }

    #[test]
    fn a_device_that_is_not_virtio_net_is_refused_by_its_ids() {
        let mut fake = FakeConfig::conforming();
        fake.w16(CFG_DEVICE, 0x1000);
        assert_eq!(
            identify(&fake.config()),
            Err(BringUpError::NotVirtioNet {
                vendor: VIRTIO_VENDOR_ID,
                device: 0x1000,
            })
        );
    }

    #[test]
    fn every_capability_list_fault_reaches_the_operator_distinctly() {
        // ENG-12: a device with no capability list and one whose chain loops
        // must not produce the same console line. Each is driven to its own
        // `CapError`, and the error carries which.
        let mut absent = FakeConfig::conforming();
        absent.w16(CFG_STATUS, 0);
        assert_eq!(
            identify(&absent.config()),
            Err(BringUpError::Capabilities(CapError::NoCapabilities))
        );

        let mut looped = FakeConfig::conforming();
        // 0x40 chains to itself, so the walk never terminates on its own.
        looped.bytes[0x41] = 0x40;
        assert_eq!(
            identify(&looped.config()),
            Err(BringUpError::Capabilities(CapError::Malformed))
        );

        let mut split = FakeConfig::conforming();
        split.bytes[0x50 + 4] = 2;
        assert_eq!(
            identify(&split.config()),
            Err(BringUpError::Capabilities(CapError::MultipleBars))
        );

        let mut invalid = FakeConfig::conforming();
        invalid.bytes[0x40 + 4] = 9;
        assert_eq!(
            identify(&invalid.config()),
            Err(BringUpError::Capabilities(CapError::InvalidBar))
        );

        let mut missing = FakeConfig::conforming();
        // Drop the ISR capability out of the chain.
        missing.bytes[0x50 + 1] = 0x74;
        assert_eq!(
            identify(&missing.config()),
            Err(BringUpError::Capabilities(CapError::MissingStructure))
        );
    }

    #[test]
    fn a_structure_outside_the_mapped_window_is_refused_before_any_dereference() {
        let mut fake = FakeConfig::conforming();
        // The device claims its common-configuration structure sits past the
        // window the driver mapped.
        fake.w32(0x40 + 8, BAR_WINDOW_SIZE as u32);
        let error = identify(&fake.config()).expect_err("outside the window");
        assert!(matches!(
            error,
            BringUpError::StructuresOutsideBar {
                bar_window: BAR_WINDOW_SIZE,
                ..
            }
        ));
        assert!(!error.signalled_to_device());
    }

    #[test]
    fn a_misaligned_common_configuration_offset_is_refused_before_any_dereference() {
        // Regression for the fuzz finding whose reproducer is
        // `fuzz/corpus/find_virtio_caps/unaligned_common_cfg_offset`: a device
        // that advertises common-cfg at 0x0009 instead of 0x0000. The offset
        // fits the window, so `within` passes and the old `identify` accepted
        // it; `PlacedBar::map` then built a `CommonCfg` on an odd base and
        // `negotiate_features` performed a misaligned `u32` volatile write.
        //
        // Every non-multiple-of-four is the same fault, including the merely
        // even ones — the common-configuration registers are mostly 32-bit, so
        // two-byte alignment is not enough.
        // The last entry is the largest offset that still fits the window, made
        // odd: extent and alignment must be judged independently right up to
        // the boundary where one of them is about to fail on its own.
        for offset in [
            1u32,
            2,
            3,
            9,
            0x102,
            (BAR_WINDOW_SIZE - pci::COMMON_CFG_MIN_LEN - 1) as u32,
        ] {
            let mut fake = FakeConfig::conforming();
            fake.w32(0x40 + 8, offset);
            let error = identify(&fake.config()).expect_err("a misaligned common-cfg offset");
            assert_eq!(
                error,
                BringUpError::CommonCfgMisaligned {
                    offset,
                    required: pci::COMMON_CFG_ALIGN,
                },
                "offset {offset:#x} must be refused by alignment, not by extent"
            );
            // Before the BAR is mapped there is no status register to write.
            assert!(!error.signalled_to_device());
        }
    }

    #[test]
    fn an_aligned_common_configuration_offset_inside_the_window_is_accepted() {
        // The other side of the boundary, so the check is pinned to the
        // alignment and is not simply refusing every non-zero offset.
        for offset in [
            0u32,
            4,
            8,
            0x100,
            (BAR_WINDOW_SIZE - pci::COMMON_CFG_MIN_LEN) as u32,
        ] {
            let mut fake = FakeConfig::conforming();
            fake.w32(0x40 + 8, offset);
            let identified = identify(&fake.config()).expect("an aligned offset inside the window");
            assert_eq!(identified.caps().common, offset);
            assert!(identified.caps().common_is_aligned());
        }
    }

    #[test]
    fn a_bar_that_is_not_a_64_bit_pair_is_refused() {
        let mut fake = FakeConfig::conforming();
        // A 32-bit memory BAR: bits [2:1] are 0b00.
        fake.w32(CFG_BAR0 + 4 * 4, 0);
        assert_eq!(
            identify(&fake.config()),
            Err(BringUpError::BarNotSixtyFourBit { bar: 4 })
        );
    }

    #[test]
    fn a_64_bit_bar_5_is_refused_because_it_has_no_high_half() {
        // BAR 5's successor register is the CardBus-CIS pointer, so relocating
        // it would corrupt a non-BAR register. The capability chain is the
        // device's, so this is a malformed device, not a driver error.
        let mut fake = FakeConfig::conforming();
        for cap in [0x40usize, 0x50, 0x64, 0x74] {
            fake.bytes[cap + 4] = 5;
        }
        fake.w32(CFG_BAR0 + 5 * 4, BAR_TYPE_64BIT);
        let identified = identify(&fake.config()).expect("a 64-bit BAR 5 identifies");
        assert_eq!(
            identified.place_bar(&fake.config(), 0x5000_0000),
            Err(BringUpError::BarIndexRefused(BarError::NoHighHalf(5)))
        );
    }

    #[test]
    fn an_unusable_bar_relocation_target_is_refused_without_touching_the_device() {
        let mut fake = FakeConfig::conforming();
        let before = fake.r32(CFG_BAR0 + 4 * 4);
        for paddr in [
            0,
            0x5000_0001,
            BAR_WINDOW_SIZE / 2,
            0x1_0000_0000,
            usize::MAX,
        ] {
            let identified = identify(&fake.config()).unwrap();
            assert_eq!(
                identified.place_bar(&fake.config(), paddr),
                Err(BringUpError::BarTargetUnusable { paddr }),
                "target {paddr:#x} must be refused"
            );
        }
        assert_eq!(
            fake.r32(CFG_BAR0 + 4 * 4),
            before,
            "the BAR was not written"
        );
    }

    #[test]
    fn the_handshake_writes_the_status_bits_in_the_order_the_spec_requires() {
        let log = Log::new();
        let device = FakeDevice::conforming(&log);
        bring_up(device).expect("a conforming device");

        assert_eq!(
            log.events(),
            vec![
                Event::Reset,
                Event::Status(STATUS_ACKNOWLEDGE),
                Event::Status(STATUS_ACKNOWLEDGE | STATUS_DRIVER),
                Event::DriverFeatures(ACCEPTED_FEATURES),
                Event::Status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
                Event::QueueConfigured(RX_QUEUE),
                Event::DoorbellPlaced(RX_QUEUE),
                Event::QueueConfigured(TX_QUEUE),
                Event::DoorbellPlaced(TX_QUEUE),
                Event::Status(
                    STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK
                ),
                Event::Rang(RX_QUEUE),
            ],
            "reset, acknowledge, driver, features, queues, DRIVER_OK, then the doorbell"
        );
    }

    #[test]
    fn the_receive_doorbell_is_never_rung_before_driver_ok() {
        // The invariant that was previously only a comment. `Configured` holds
        // the doorbells privately and `go_live` is the only way to reach them,
        // so the strongest statement available is that no ring precedes the
        // DRIVER_OK write in the recorded order — there is no API through which
        // one could.
        let log = Log::new();
        bring_up(FakeDevice::conforming(&log)).expect("a conforming device");
        let events = log.events();
        let driver_ok = events
            .iter()
            .position(|event| {
                *event
                    == Event::Status(
                        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
                    )
            })
            .expect("DRIVER_OK is written");
        let first_ring = events
            .iter()
            .position(|event| matches!(event, Event::Rang(_)))
            .expect("the receive doorbell is rung");
        assert!(driver_ok < first_ring);
    }

    #[test]
    fn the_feature_mask_accepts_only_what_this_driver_implements() {
        // A device offering every feature bit must still be told this driver
        // accepts exactly one: accepting a bit no code handles licences the
        // device to produce buffers this driver cannot service.
        let log = Log::new();
        let device = FakeDevice::conforming(&log).offering(u64::MAX);
        let live = bring_up(device);
        assert!(live.is_ok());
        assert!(
            log.events()
                .contains(&Event::DriverFeatures(ACCEPTED_FEATURES))
        );
        assert_eq!(ACCEPTED_FEATURES, features::VIRTIO_F_VERSION_1);
    }

    #[test]
    fn a_device_refusing_the_reset_is_rejected_and_told_so() {
        let log = Log::new();
        let device = FakeDevice::conforming(&log).refusing_reset(0x42);
        assert_eq!(
            bring_up(device).err(),
            Some(BringUpError::ResetRefused(ResetError::NotAcknowledged {
                status: 0x42
            }))
        );
        assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
    }

    #[test]
    fn a_device_without_virtio_1_is_rejected_with_the_offer_it_made() {
        let log = Log::new();
        // Everything but virtio 1.0.
        let offered = !features::VIRTIO_F_VERSION_1;
        let device = FakeDevice::conforming(&log).offering(offered);
        assert_eq!(
            bring_up(device).err(),
            Some(BringUpError::NoVirtio1 { offered })
        );
        assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
        assert!(
            !log.events()
                .iter()
                .any(|event| matches!(event, Event::DriverFeatures(_))),
            "features must not be written to a device that cannot carry them"
        );
    }

    #[test]
    fn a_device_clearing_features_ok_stops_initialization() {
        let log = Log::new();
        let device = FakeDevice::conforming(&log).clearing_features_ok();
        assert_eq!(
            bring_up(device).err(),
            Some(BringUpError::FeaturesRejected {
                status: STATUS_ACKNOWLEDGE | STATUS_DRIVER
            })
        );
        assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
        assert!(
            !log.events()
                .iter()
                .any(|event| matches!(event, Event::QueueConfigured(_))),
            "no queue may be programmed into a device that refused the features"
        );
    }

    #[test]
    fn a_device_with_too_few_queues_cannot_transmit_and_is_rejected() {
        for offered in [0u16, 1] {
            let log = Log::new();
            let device = FakeDevice::conforming(&log).with_queues(offered);
            assert_eq!(
                bring_up(device).err(),
                Some(BringUpError::TransmitQueueAbsent {
                    offered,
                    required: TX_QUEUE + 1,
                })
            );
            assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
        }
    }

    #[test]
    fn an_unusable_virtqueue_region_address_is_refused() {
        for paddr in [0u64, 0x3000_0800, u64::MAX] {
            let log = Log::new();
            let device = FakeDevice::conforming(&log);
            let negotiated = Offered { device }
                .acknowledge()
                .unwrap()
                .negotiate_features()
                .unwrap();
            assert_eq!(
                negotiated.configure_queues(paddr).err(),
                Some(BringUpError::VirtqueueRegionUnusable { paddr }),
                "region address {paddr:#x} must be refused"
            );
            assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
        }
    }

    #[test]
    fn a_refused_queue_names_which_queue_and_why() {
        // Both directions, and both `QueueSetupError` variants, so the operator
        // can tell "the device has no transmit queue" from "its transmit queue
        // is smaller than we program".
        for (index, error) in [
            (RX_QUEUE, QueueSetupError::QueueAbsent { index: RX_QUEUE }),
            (
                TX_QUEUE,
                QueueSetupError::QueueTooSmall {
                    index: TX_QUEUE,
                    device_max: 4,
                    required: QUEUE_SIZE,
                },
            ),
        ] {
            let log = Log::new();
            let device = FakeDevice::conforming(&log).refusing_queue(index, error);
            assert_eq!(
                bring_up(device).err(),
                Some(BringUpError::QueueSetupRefused { index, error })
            );
            assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
        }
    }

    #[test]
    fn a_refused_doorbell_names_which_queue_and_why() {
        for index in [RX_QUEUE, TX_QUEUE] {
            let error = NotifyError::SlotMisaligned { offset: 0x3001 };
            let log = Log::new();
            let device = FakeDevice::conforming(&log).refusing_doorbell(index, error);
            assert_eq!(
                bring_up(device).err(),
                Some(BringUpError::DoorbellRefused { index, error })
            );
            assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
            assert!(
                !log.events().iter().any(|e| matches!(e, Event::Rang(_))),
                "a device whose doorbell could not be placed is never rung"
            );
        }
    }

    #[test]
    fn status_failed_is_signalled_once_the_device_is_reachable() {
        // The claim `BringUpError::signalled_to_device` makes, checked against
        // what the code actually wrote, for every variant a handshake can
        // produce. A variant that says it signalled and did not would tell an
        // operator the device was stopped when it was left mid-handshake.
        let cases: [fn(&Log) -> FakeDevice; 6] = [
            |log| FakeDevice::conforming(log).refusing_reset(1),
            |log| FakeDevice::conforming(log).offering(0),
            |log| FakeDevice::conforming(log).clearing_features_ok(),
            |log| FakeDevice::conforming(log).with_queues(1),
            |log| {
                FakeDevice::conforming(log)
                    .refusing_queue(RX_QUEUE, QueueSetupError::QueueAbsent { index: RX_QUEUE })
            },
            |log| {
                FakeDevice::conforming(log)
                    .refusing_doorbell(TX_QUEUE, NotifyError::SlotMisaligned { offset: 1 })
            },
        ];
        for build in cases {
            let log = Log::new();
            let error = bring_up(build(&log)).err().expect("a rejection");
            assert!(error.signalled_to_device(), "{error:?} claims no signal");
            assert!(
                log.events().contains(&Event::Status(STATUS_FAILED)),
                "{error:?} claims a signal it did not send"
            );
        }
        // And the pre-BAR variant, whose register does not exist yet.
        let mut fake = FakeConfig::conforming();
        fake.w16(CFG_DEVICE, 0);
        let error = identify(&fake.config()).expect_err("not virtio-net");
        assert!(!error.signalled_to_device());
    }

    /// A BAR window with the common-configuration structure at `common`, seeded
    /// so a `CommonCfg` driven over it answers as a conforming device would:
    /// virtio 1.0 offered, two virtqueues, a queue maximum of [`QUEUE_SIZE`],
    /// and notify slot 3.
    fn seeded_bar(common: usize) -> Box<MappedRegion<BAR_WINDOW_SIZE>> {
        let mut bar = Box::new(MappedRegion([0u8; BAR_WINDOW_SIZE]));
        let put16 = |bar: &mut [u8; BAR_WINDOW_SIZE], off: usize, v: u16| {
            bar[off..off + 2].copy_from_slice(&v.to_le_bytes());
        };
        // `device_features` reads the same register under both selector
        // windows over plain memory, so bit 0 here becomes bit 32 of the pair
        // — which is VIRTIO_F_VERSION_1, the one bit this driver requires.
        bar[common + 4..common + 8].copy_from_slice(&1u32.to_le_bytes());
        put16(&mut bar, common + 18, 2); // num_queues
        put16(&mut bar, common + 24, QUEUE_SIZE as u16); // queue_size maximum
        put16(&mut bar, common + 30, 3); // queue_notify_off
        bar
    }

    #[test]
    fn the_shipped_device_handshake_reaches_every_register_the_layout_names() {
        // `MappedDevice` is the implementation that ships, and every method on
        // it is a delegation to a `CommonCfg` register. A delegation to the
        // *wrong* register is invisible to the fake-device tests — they never
        // touch an offset — and on real hardware would surface as a device
        // that silently does nothing. Driving the whole handshake over plain
        // memory and reading the bytes back is what pins each one.
        const COMMON: usize = 0x100;
        const NOTIFY: usize = 0x200;
        const VQ_PADDR: u64 = 0x3000_0000;
        let mut bar = seeded_bar(COMMON);
        let caps = VirtioCaps {
            bar: 4,
            common: COMMON as u32,
            notify: NOTIFY as u32,
            notify_multiplier: 4,
            device: 0x300,
        };
        // The two predicates `identify` establishes on a real device,
        // discharged here directly because this test builds the capabilities
        // itself.
        assert!(caps.within(BAR_WINDOW_SIZE));
        assert!(caps.common_is_aligned());
        // SAFETY: `bar` is a live, owned, page-aligned BAR_WINDOW_SIZE-byte
        // buffer that outlives everything derived from it, and both of the
        // predicates `map` relies on `identify` for were just asserted for that
        // size — `PlacedBar::map`'s contract.
        let live = unsafe { PlacedBar { caps }.map(bar.as_mut_ptr()) }
            .acknowledge()
            .expect("a zeroed status register reads back as an acknowledged reset")
            .negotiate_features()
            .expect("virtio 1.0 is offered and two queues are reported");
        assert_eq!(
            live.features(),
            ACCEPTED_FEATURES,
            "the offer is masked to what this driver implements"
        );
        let live = live
            .configure_queues(VQ_PADDR)
            .expect("both queues fit the device maximum")
            .go_live();

        let read16 = |off: usize| u16::from_le_bytes([bar[off], bar[off + 1]]);
        let read64 = |off: usize| u64::from_le_bytes(bar[off..off + 8].try_into().unwrap());
        // The handshake's final status, at common+20.
        assert_eq!(
            bar[COMMON + 20],
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK
        );
        // The driver's accepted feature set, written low half first at
        // common+12 under selector 1 — so the high half of ACCEPTED_FEATURES.
        assert_eq!(
            u32::from_le_bytes(bar[COMMON + 12..COMMON + 16].try_into().unwrap()),
            (ACCEPTED_FEATURES >> 32) as u32
        );
        // The last queue programmed is the transmit one, at TX_VQ_OFFSET into
        // the region, with its ring addresses and the enable bit.
        assert_eq!(read16(COMMON + 22), TX_QUEUE, "queue_select");
        assert_eq!(read16(COMMON + 24), QUEUE_SIZE as u16, "queue_size");
        assert_eq!(read16(COMMON + 28), 1, "queue_enable");
        let layout = &DriverVirtqueue::LAYOUT;
        let tx_ring = VQ_PADDR + TX_VQ_OFFSET as u64;
        assert_eq!(
            read64(COMMON + 32),
            tx_ring + layout.descriptor_offset as u64
        );
        assert_eq!(read64(COMMON + 40), tx_ring + layout.driver_offset as u64);
        assert_eq!(read64(COMMON + 48), tx_ring + layout.device_offset as u64);
        // `go_live` rang the receive doorbell at notify + 3 * 4.
        assert_eq!(read16(NOTIFY + 12), RX_QUEUE);
        live.ring_transmit();
        assert_eq!(read16(NOTIFY + 12), TX_QUEUE);
    }

    #[test]
    fn a_mapped_device_reaches_the_registers_the_capabilities_name() {
        // The one implementation that touches real MMIO, driven over plain
        // memory: it must reach the *common-configuration* structure at the
        // offset the capabilities named, not the BAR base. Reading back the
        // status byte the accessor wrote is what pins the offset.
        let mut bar = Box::new(MappedRegion([0u8; BAR_WINDOW_SIZE]));
        let caps = VirtioCaps {
            bar: 4,
            common: 0x100,
            notify: 0x200,
            notify_multiplier: 4,
            device: 0x300,
        };
        assert!(caps.within(BAR_WINDOW_SIZE));
        assert!(caps.common_is_aligned());
        // SAFETY: `bar` is a live, BAR_WINDOW_SIZE-byte, page-aligned buffer
        // owned by this test and outliving `device`; both `caps.within` and
        // `caps.common_is_aligned` were just asserted, which is what
        // `PlacedBar::map` relies on `identify` for.
        let device = unsafe { PlacedBar { caps }.map(bar.as_mut_ptr()) }.device;

        device.set_status(STATUS_DRIVER);
        assert_eq!(bar[0x100 + 20], STATUS_DRIVER, "device_status at common+20");
        assert_eq!(device.status(), STATUS_DRIVER);

        // Slot 3 of a multiplier-4 notify structure: 0x200 + 12.
        let doorbell = device.place_doorbell(3).expect("a slot inside the window");
        doorbell.ring(TX_QUEUE);
        assert_eq!(
            u16::from_le_bytes([bar[0x200 + 12], bar[0x200 + 13]]),
            TX_QUEUE
        );
    }

    #[test]
    fn a_mapped_device_refuses_a_doorbell_slot_outside_the_window() {
        let mut bar = Box::new(MappedRegion([0u8; BAR_WINDOW_SIZE]));
        let caps = VirtioCaps {
            bar: 4,
            common: 0,
            notify: 0x3000,
            notify_multiplier: u32::MAX,
            device: 0x2000,
        };
        assert!(caps.within(BAR_WINDOW_SIZE) && caps.common_is_aligned());
        // SAFETY: as above — a live, owned, page-aligned BAR_WINDOW_SIZE-byte
        // buffer, with capability offsets that fit it and a common-configuration
        // offset that is aligned, both just asserted.
        let device = unsafe { PlacedBar { caps }.map(bar.as_mut_ptr()) }.device;
        assert!(matches!(
            device.place_doorbell(u16::MAX),
            Err(NotifyError::SlotOutsideBar { .. })
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// Arbitrary configuration space: whatever bytes a hostile device puts
        /// in its ECAM page, `identify` must answer with a value or a typed
        /// error and never panic, index out of range, or overflow. The whole
        /// page is randomised, so the capability chain, the ids, the status
        /// word and the BAR type bits are all adversarial together.
        #[test]
        fn identify_never_panics_on_arbitrary_configuration_space(
            seed in prop::collection::vec(any::<u8>(), 0..512),
            base in prop::array::uniform4(any::<u8>()),
        ) {
            let mut bytes = Box::new([0u8; 4096]);
            // Seed the head of the page, where the capability pointer and the
            // chain live, and keep the ids reachable so the walk is entered.
            for (slot, byte) in bytes.iter_mut().zip(seed.iter()) {
                *slot = *byte;
            }
            bytes[0x00..0x04].copy_from_slice(&base);
            // SAFETY: a live, owned 4096-byte buffer outliving the value —
            // `PciConfig::new`'s contract over plain memory.
            let config = unsafe { PciConfig::new(bytes.as_mut_ptr()) };
            match identify(&config) {
                // Anything accepted must satisfy both halves of what
                // `PlacedBar::map`'s safety comment names `identify` as the
                // guarantor of: inside the window, or a later dereference
                // leaves it, and aligned, or every register behind it is a
                // misaligned volatile access.
                Ok(identified) => {
                    prop_assert!(identified.caps().within(BAR_WINDOW_SIZE));
                    prop_assert!(identified.caps().common_is_aligned());
                }
                Err(error) => prop_assert!(!error.signalled_to_device()),
            }
        }

        /// The common-configuration offset alone, under the device's full
        /// authority over the `u32` it names, against a chain that is otherwise
        /// conforming — so the accepting path is reached often rather than by
        /// luck. `identify` must decide, and the decision must be exactly the
        /// conjunction of the two independent predicates, each reported through
        /// its own error so an operator can tell "outside my window" from "at
        /// an offset I cannot address".
        #[test]
        fn identify_accepts_a_common_offset_only_when_bounded_and_aligned(
            common in prop_oneof![
                0u32..=64,
                (BAR_WINDOW_SIZE as u32 - 128)..=(BAR_WINDOW_SIZE as u32 + 128),
                any::<u32>(),
            ],
        ) {
            let mut fake = FakeConfig::conforming();
            fake.w32(0x40 + 8, common);
            let fits = common as usize + pci::COMMON_CFG_MIN_LEN <= BAR_WINDOW_SIZE;
            let aligned = (common as usize).is_multiple_of(pci::COMMON_CFG_ALIGN);
            match identify(&fake.config()) {
                Ok(identified) => {
                    prop_assert!(fits && aligned);
                    prop_assert_eq!(identified.caps().common, common);
                }
                Err(BringUpError::StructuresOutsideBar { caps, bar_window }) => {
                    prop_assert!(!fits);
                    prop_assert_eq!(caps.common, common);
                    prop_assert_eq!(bar_window, BAR_WINDOW_SIZE);
                }
                Err(BringUpError::CommonCfgMisaligned { offset, required }) => {
                    // Ordered after the extent check, so this variant also
                    // asserts the offset was in range: the two are reported
                    // distinctly rather than collapsed into one rejection.
                    prop_assert!(fits && !aligned);
                    prop_assert_eq!(offset, common);
                    prop_assert_eq!(required, pci::COMMON_CFG_ALIGN);
                }
                Err(other) => prop_assert!(
                    false,
                    "a conforming chain with common={common:#x} was refused as {other:?}"
                ),
            }
        }

        /// Arbitrary device behaviour through the whole handshake: any feature
        /// offer, any queue count, any `queue_notify_off`, and a reset that may
        /// never be acknowledged. Bring-up must terminate with a live device or
        /// a typed error, and a rejection must always have been signalled.
        #[test]
        fn the_handshake_never_panics_on_arbitrary_device_behaviour(
            offered in any::<u64>(),
            queues in any::<u16>(),
            notify_off in any::<u16>(),
            reset_ok in any::<bool>(),
            features_ok in any::<bool>(),
        ) {
            let log = Log::new();
            let mut device = FakeDevice::conforming(&log)
                .offering(offered)
                .with_queues(queues)
                .with_notify_off(notify_off);
            if !reset_ok {
                device = device.refusing_reset(0xff);
            }
            if !features_ok {
                device = device.clearing_features_ok();
            }
            match bring_up(device) {
                Ok(live) => {
                    // Accepting implies the device offered virtio 1.0 and both
                    // queues; ringing is safe because a doorbell was placed.
                    prop_assert!(offered & features::VIRTIO_F_VERSION_1 != 0);
                    prop_assert!(queues > TX_QUEUE);
                    live.ring_transmit();
                }
                Err(error) => {
                    prop_assert!(error.signalled_to_device());
                    prop_assert!(log.events().contains(&Event::Status(STATUS_FAILED)));
                }
            }
        }
    }
}
