//! Host-testable virtio-blk bring-up: PCI identification, BAR placement, the
//! device-initialization handshake, feature negotiation, and configuring the
//! single request virtqueue.
//!
//! # The adversary
//!
//! Every byte read here — the configuration-space ids, the capability chain,
//! the BAR type bits, the feature bitmap, the `device_status` readback, the
//! queue count, the `capacity` in the device-configuration structure, the
//! `queue_notify_off` — is written by a **hostile or
//! malfunctioning device**. A merely broken device produces the same bytes as a
//! malicious one, so both are answered the same way: a typed [`BringUpError`]
//! naming the cause. A driver protection domain that cannot bring its device up
//! parks; it never faults.
//!
//! # Why the sequence is a typestate
//!
//! virtio 1.0 section 3.1.1 fixes the initialization order, and getting it wrong is
//! silent: a device whose features are written before `DRIVER` is set, or which
//! is told `DRIVER_OK` before its virtqueue carries addresses, misbehaves as a
//! dead disk rather than as an error. The order is therefore carried by types
//! that consume the state they advance from, rather than by a call sequence a
//! caller is trusted to write.
//!
//! # Accepting a feature is not observing one
//!
//! [`ACCEPTED_FEATURES`] is one bit, for the reason `nic_driver_core`'s is:
//! accepting a bit widens what the device is *permitted to produce*, and no
//! code here handles a discard, a write-zeroes or a multi-queue layout. Two
//! further bits are read out of the offer and never accepted, because they are
//! facts about the device rather than requests to it — whether it will take a
//! write at all ([`features::VIRTIO_BLK_F_RO`], which is refused by name), and
//! whether a flush is honoured rather than silently dropped
//! ([`features::VIRTIO_BLK_F_FLUSH`], reported through
//! [`Live::flush_supported`]).

use virtio::pci::{
    self, BarError, CapError, CommonCfg, Doorbell, NotifyError, PciConfig, QueueSetupError,
    ResetError, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FAILED,
    STATUS_FEATURES_OK, VIRTIO_BLK_DEVICE_ID, VIRTIO_VENDOR_ID, VirtioCaps,
};
use virtio::queue::QueueLayout;

use crate::{
    BAR_WINDOW_SIZE, BLK_QUEUE, BlkVirtqueue, DMA_REGION_SIZE, PAGE_SIZE, Refusal, RefusalDetail,
};

/// Feature bits this driver knows about.
pub mod features {
    /// The modern layout this transport programs. Required.
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
    /// The device is read-only. Observed and refused, never accepted: this
    /// driver exists to persist, and a medium that cannot be written must fail
    /// bring-up by name rather than fail every write later.
    pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;
    /// The device honours `VIRTIO_BLK_T_FLUSH`. Observed and reported, never
    /// accepted: it changes nothing about the buffers the device may produce,
    /// and a caller must not guess whether its flush reached the medium.
    pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
}

/// The one bit this driver accepts if the device offers it.
pub const ACCEPTED_FEATURES: u64 = features::VIRTIO_F_VERSION_1;

/// Byte offset of `capacity` within the virtio-blk device-configuration
/// structure, and the extent and alignment reading it needs. Fixed by virtio
/// 1.0 section 5.2.4; the value is in 512-byte sectors whatever `blk_size` says.
const CAPACITY_OFFSET: usize = 0;
const CAPACITY_LEN: usize = size_of::<u64>();
const CAPACITY_ALIGN: usize = align_of::<u64>();

/// Why bring-up refused to continue.
///
/// Each variant carries the value that caused the rejection: an operator with
/// no shell can only tell a device that exposes no capability
/// list from one whose chain loops if the two produce different console lines,
/// and a single "bring-up failed" would collapse the causes into one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BringUpError {
    NotVirtioBlk {
        vendor: u16,
        device: u16,
    },
    Capabilities(CapError),
    /// A virtio structure's offset, or its extent, lies outside the window the
    /// driver mapped.
    StructuresOutsideBar {
        caps: VirtioCaps,
        bar_window: usize,
    },
    /// An offset that fits the mapped window and is still unusable: the
    /// common-configuration registers are `u16` and `u32` volatile accesses,
    /// and this offset decides their alignment.
    CommonCfgMisaligned {
        offset: u32,
        required: usize,
    },
    /// The device-configuration structure fits [`VirtioCaps::within`]'s
    /// one-byte probe and not the eight bytes `capacity` is read at. A distinct
    /// fault from [`StructuresOutsideBar`](Self::StructuresOutsideBar), which
    /// cannot see it: only a driver that reads a field knows the extent.
    DeviceCfgOutsideBar {
        offset: u32,
        needed: usize,
        bar_window: usize,
    },
    /// The device-configuration structure is inside the window and not
    /// eight-byte aligned, so the `u64` read of `capacity` at it would be
    /// misaligned — undefined behaviour, not a slow access.
    DeviceCfgMisaligned {
        offset: u32,
        required: usize,
    },
    BarNotSixtyFourBit {
        bar: u8,
    },
    BarIndexRefused(BarError),
    /// Zero, above 4 GiB, or not [`BAR_WINDOW_SIZE`]-aligned. Build data, not
    /// device input, checked because a wrong value leaves the mapped window and
    /// the decoded window describing different bytes.
    BarTargetUnusable {
        paddr: usize,
    },
    ResetRefused(ResetError),
    NoVirtio1 {
        offered: u64,
    },
    /// The device offers `VIRTIO_BLK_F_RO`. Refused rather than accepted with
    /// writes disabled: this driver's whole purpose is to persist, and a
    /// read-only medium is a misconfiguration an operator must see at boot.
    DeviceReadOnly {
        offered: u64,
    },
    /// The device cleared `FEATURES_OK` on readback; virtio 1.0 section 3.1.1 requires
    /// initialization to stop here.
    FeaturesRejected {
        status: u8,
    },
    /// The device reports fewer virtqueues than [`BLK_QUEUE`] names.
    QueueAbsent {
        offered: u16,
        required: u16,
    },
    /// The device claims no sectors, so every request this driver could make
    /// would be out of range. Its own claim, and refused here rather than at
    /// each request.
    CapacityZero,
    /// Zero, not page-aligned, or so high the region would wrap. Build data,
    /// checked because it is programmed into a device that will DMA to it.
    DmaRegionUnusable {
        paddr: u64,
    },
    QueueSetupRefused {
        error: QueueSetupError,
    },
    DoorbellRefused {
        error: NotifyError,
    },
}

impl BringUpError {
    /// Whether `STATUS_FAILED` was written to the device before this error was
    /// returned — which of two states the device was left in, for the console
    /// line an operator reads.
    ///
    /// False for every rejection raised before [`PlacedBar::map`]: the status
    /// register lives in a BAR that has not been placed, so there is nothing to
    /// write it through. True from [`Offered::acknowledge`] onward, where every
    /// rejection writes it before returning. The two halves are held to agree
    /// by `status_failed_is_signalled_once_the_device_is_reachable`.
    #[must_use]
    pub fn signalled_to_device(&self) -> bool {
        match self {
            Self::NotVirtioBlk { .. }
            | Self::Capabilities(_)
            | Self::StructuresOutsideBar { .. }
            | Self::CommonCfgMisaligned { .. }
            | Self::DeviceCfgOutsideBar { .. }
            | Self::DeviceCfgMisaligned { .. }
            | Self::BarNotSixtyFourBit { .. }
            | Self::BarIndexRefused(_)
            | Self::BarTargetUnusable { .. } => false,
            Self::ResetRefused(_)
            | Self::NoVirtio1 { .. }
            | Self::DeviceReadOnly { .. }
            | Self::FeaturesRejected { .. }
            | Self::QueueAbsent { .. }
            | Self::CapacityZero
            | Self::DmaRegionUnusable { .. }
            | Self::QueueSetupRefused { .. }
            | Self::DoorbellRefused { .. } => true,
        }
    }

    /// This refusal as the console record of it. The tokens are minted here
    /// rather than in a logging crate because they name this tree, and a second
    /// copy of it beside the event vocabulary would go stale with nothing
    /// failing. The `match` is exhaustive, so a new variant is a compile error
    /// until it has a token.
    #[must_use]
    pub fn refusal(&self) -> Refusal {
        let (cause, detail) = self.cause();
        Refusal {
            cause,
            detail,
            signalled: self.signalled_to_device(),
        }
    }

    /// What a refusal is called and the at most two numbers it carries. Where a
    /// variant holds more, the pair kept is the one that identifies the fault:
    /// `StructuresOutsideBar` keeps the window and not the four capability
    /// offsets that left it, all readable from the device itself, and
    /// `DeviceCfgOutsideBar` keeps the offset and the window rather than the
    /// extent, which is this driver's constant.
    fn cause(&self) -> (&'static str, RefusalDetail) {
        match *self {
            Self::NotVirtioBlk { vendor, device } => (
                "not-virtio-blk",
                RefusalDetail::Two(vendor.into(), device.into()),
            ),
            Self::Capabilities(error) => (capability_cause(error), RefusalDetail::None),
            Self::StructuresOutsideBar { bar_window, .. } => (
                "structures-outside-bar",
                RefusalDetail::One(bar_window as u64),
            ),
            Self::CommonCfgMisaligned { offset, required } => (
                "common-cfg-misaligned",
                RefusalDetail::Two(offset.into(), required as u64),
            ),
            Self::DeviceCfgOutsideBar {
                offset, bar_window, ..
            } => (
                "device-cfg-outside-bar",
                RefusalDetail::Two(offset.into(), bar_window as u64),
            ),
            Self::DeviceCfgMisaligned { offset, required } => (
                "device-cfg-misaligned",
                RefusalDetail::Two(offset.into(), required as u64),
            ),
            Self::BarNotSixtyFourBit { bar } => ("bar-not-64-bit", RefusalDetail::One(bar.into())),
            Self::BarIndexRefused(BarError::IndexOutOfRange(bar)) => {
                ("bar-index-out-of-range", RefusalDetail::One(bar.into()))
            }
            Self::BarIndexRefused(BarError::NoHighHalf(bar)) => {
                ("bar-has-no-high-half", RefusalDetail::One(bar.into()))
            }
            Self::BarTargetUnusable { paddr } => {
                ("bar-target-unusable", RefusalDetail::One(paddr as u64))
            }
            Self::ResetRefused(ResetError::NotAcknowledged { status }) => {
                ("reset-not-acknowledged", RefusalDetail::One(status.into()))
            }
            Self::NoVirtio1 { offered } => ("no-virtio-1", RefusalDetail::One(offered)),
            Self::DeviceReadOnly { offered } => ("device-read-only", RefusalDetail::One(offered)),
            Self::FeaturesRejected { status } => {
                ("features-rejected", RefusalDetail::One(status.into()))
            }
            Self::QueueAbsent { offered, required } => (
                "queue-absent",
                RefusalDetail::Two(offered.into(), required.into()),
            ),
            Self::CapacityZero => ("capacity-zero", RefusalDetail::None),
            Self::DmaRegionUnusable { paddr } => ("dma-region-unusable", RefusalDetail::One(paddr)),
            Self::QueueSetupRefused {
                error: QueueSetupError::QueueAbsent { index },
            } => ("queue-size-zero", RefusalDetail::One(index.into())),
            Self::QueueSetupRefused {
                error:
                    QueueSetupError::QueueTooSmall {
                        device_max,
                        required,
                        ..
                    },
            } => (
                "queue-too-small",
                RefusalDetail::Two(device_max.into(), required as u64),
            ),
            Self::DoorbellRefused {
                error: NotifyError::SlotOutsideBar { slot_end, bar_size },
            } => (
                "doorbell-outside-bar",
                match slot_end {
                    Some(end) => RefusalDetail::Two(end as u64, bar_size as u64),
                    // The offset overflowed, so there is no end to report.
                    None => RefusalDetail::One(bar_size as u64),
                },
            ),
            Self::DoorbellRefused {
                error: NotifyError::SlotMisaligned { offset },
            } => ("doorbell-misaligned", RefusalDetail::One(offset as u64)),
        }
    }
}

/// The capability-chain refusals, which carry nothing beyond themselves.
fn capability_cause(error: CapError) -> &'static str {
    match error {
        CapError::NoCapabilities => "no-capability-list",
        CapError::Malformed => "malformed-capability-list",
        CapError::MultipleBars => "structures-across-bars",
        CapError::InvalidBar => "invalid-structure-bar",
        CapError::MissingStructure => "missing-virtio-structure",
    }
}

/// The request queue's doorbell: writing it tells the device to examine the
/// queue.
///
/// A seam over [`Doorbell`], because a doorbell write is a two-byte MMIO store
/// into a device BAR and no host test can observe it *in order* relative to the
/// status writes around it — which is the order [`Configured::go_live`] exists
/// to get right.
pub trait QueueDoorbell {
    fn ring(&self, queue: u16);
}

impl QueueDoorbell for Doorbell {
    fn ring(&self, queue: u16) {
        Doorbell::ring(self, queue);
    }
}

/// Everything bring-up does to a virtio-blk device once its BAR is placed.
///
/// A seam, because the interesting device behaviours — refusing a reset,
/// clearing `FEATURES_OK` on readback, reporting no queue, claiming an absurd
/// capacity — are *disagreements* between what the driver wrote and what it
/// reads back, and a [`CommonCfg`] mapped over plain host memory reads back
/// exactly what was written. Without the seam those branches would be reachable
/// only under QEMU, whose virtio-blk conforms and so never takes them.
pub trait BlkDevice {
    type Doorbell: QueueDoorbell;

    /// Reset the device and wait, bounded, for it to acknowledge.
    fn reset(&self) -> Result<(), ResetError>;

    fn status(&self) -> u8;

    fn set_status(&self, value: u8);

    fn device_features(&self) -> u64;

    fn set_driver_features(&self, features: u64);

    fn num_queues(&self) -> u16;

    /// The device's `capacity`, in [`crate::SECTOR_SIZE`] sectors — raw device
    /// output, and the bound every sector range a caller names is judged
    /// against.
    fn capacity_sectors(&self) -> u64;

    /// Program the request virtqueue's ring addresses and enable it, returning
    /// the device's `queue_notify_off` — raw device output, bounded by nothing,
    /// and so fit only to be handed to [`place_doorbell`](Self::place_doorbell).
    fn setup_queue(
        &self,
        index: u16,
        layout: &QueueLayout,
        ring_paddr: u64,
    ) -> Result<u16, QueueSetupError>;

    /// Turn a `queue_notify_off` into a doorbell, bounding it against the
    /// window the device's BAR is mapped into.
    fn place_doorbell(&self, notify_off: u16) -> Result<Self::Doorbell, NotifyError>;
}

/// A virtio-blk device reached through its mapped MMIO BAR.
///
/// Its fields are private and it has no public constructor, so the only way to
/// obtain one is [`PlacedBar::map`]. A public `new` would put unvalidated
/// capability offsets one call away from a raw pointer.
pub struct MappedBlkDevice {
    common: CommonCfg,
    bar_base: *mut u8,
    caps: VirtioCaps,
}

impl BlkDevice for MappedBlkDevice {
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

    fn capacity_sectors(&self) -> u64 {
        // SAFETY: `bar_base` names a live mapping of `BAR_WINDOW_SIZE` bytes,
        // guaranteed by `PlacedBar::map`, this type's only constructor.
        // `identify` — the only producer of the `Identified` that value came
        // from — ran `device_cfg_within(BAR_WINDOW_SIZE, CAPACITY_LEN)` for the
        // extent and `device_is_aligned(CAPACITY_ALIGN)` for the alignment, so
        // all eight bytes lie inside the window and the `u64` pointer is
        // naturally aligned over a page-aligned base.
        unsafe {
            self.bar_base
                .add(self.caps.device as usize + CAPACITY_OFFSET)
                .cast::<u64>()
                .read_volatile()
        }
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
        // SAFETY: `bar_base` names a live, `COMMON_CFG_ALIGN`-aligned mapping of
        // `BAR_WINDOW_SIZE` bytes, guaranteed by `PlacedBar::map`; four bytes of
        // alignment subsume the two `Doorbell::new` requires. The
        // device-supplied `notify_off` needs nothing from this side —
        // `Doorbell::new` bounds and aligns it, proved by `virtio::pci`'s
        // `doorbell_rejects_a_slot_outside_the_bar`.
        unsafe { Doorbell::new(self.bar_base, BAR_WINDOW_SIZE, &self.caps, notify_off) }
    }
}

/// Identify the device at the pinned function and validate everything about it
/// that can be checked before its BAR is placed.
///
/// **This function is the enforcer the rest of the chain names.** All
/// four device-offset checks are made here — extent and alignment for the
/// common-configuration structure, and again for the device-configuration
/// structure at the extent `capacity` is read to — and every later state is
/// reachable only through the [`Identified`] this returns, so what a pointer
/// into either structure rests on holds before a value that could form one
/// exists. Extent and alignment are separate errors in both cases because an
/// offset that fits the window can still misalign every access behind it.
///
/// # Errors
/// A [`BringUpError`]; nothing is written to the device on any of them.
pub fn identify(config: &PciConfig) -> Result<Identified, BringUpError> {
    let (vendor, device) = config.ids();
    if vendor != VIRTIO_VENDOR_ID || device != VIRTIO_BLK_DEVICE_ID {
        return Err(BringUpError::NotVirtioBlk { vendor, device });
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
    if !caps.device_cfg_within(BAR_WINDOW_SIZE, CAPACITY_OFFSET + CAPACITY_LEN) {
        return Err(BringUpError::DeviceCfgOutsideBar {
            offset: caps.device,
            needed: CAPACITY_OFFSET + CAPACITY_LEN,
            bar_window: BAR_WINDOW_SIZE,
        });
    }
    if !caps.device_is_aligned(CAPACITY_ALIGN) {
        return Err(BringUpError::DeviceCfgMisaligned {
            offset: caps.device,
            required: CAPACITY_ALIGN,
        });
    }
    match config.bar_is_64bit(caps.bar) {
        Ok(true) => Ok(Identified { caps }),
        Ok(false) => Err(BringUpError::BarNotSixtyFourBit { bar: caps.bar }),
        Err(error) => Err(BringUpError::BarIndexRefused(error)),
    }
}

/// A device that is the one this driver is built for, whose virtio structures
/// fit the window the driver mapped and whose two structure offsets are aligned
/// for the accesses behind them. Produced only by [`identify`].
#[derive(Debug, PartialEq, Eq)]
pub struct Identified {
    caps: VirtioCaps,
}

impl Identified {
    #[must_use]
    pub fn caps(&self) -> VirtioCaps {
        self.caps
    }

    /// Relocate the device's BAR to `bar_paddr` and re-enable memory decoding
    /// and bus mastering. Nothing is written to the device on rejection.
    ///
    /// `bar_paddr` is build data and is validated rather than trusted, because
    /// it is also the address the driver mapped: a value that is not
    /// [`BAR_WINDOW_SIZE`]-aligned leaves the mapped window and the decoded
    /// window describing different bytes, and every later bound would then be
    /// checked against the wrong region.
    ///
    /// # Errors
    /// [`BringUpError::BarTargetUnusable`] or
    /// [`BringUpError::BarIndexRefused`].
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
#[derive(Debug, PartialEq, Eq)]
pub struct PlacedBar {
    caps: VirtioCaps,
}

impl PlacedBar {
    /// Attach to the mapped BAR window, yielding the first handshake state.
    ///
    /// # Safety
    /// `bar_base` must point to a live mapping of exactly [`BAR_WINDOW_SIZE`]
    /// bytes of the BAR just relocated, at least eight-byte aligned, staying
    /// mapped for as long as the returned value or anything derived from it is
    /// used. Eight, not four: the common-configuration registers are `u32`
    /// volatiles but `capacity` is a `u64` one, and a Microkit mapping is
    /// page-aligned, so this costs the caller nothing.
    ///
    /// Nothing is required of the caller about the *device's* offsets:
    /// [`identify`] is their enforcer, proved by
    /// `a_structure_outside_the_mapped_window_is_refused_before_any_dereference`
    /// and its three siblings.
    #[must_use]
    pub unsafe fn map(self, bar_base: *mut u8) -> Offered<MappedBlkDevice> {
        // SAFETY: `CommonCfg::new` requires `COMMON_CFG_MIN_LEN` readable and
        // writable bytes at a `COMMON_CFG_ALIGN`-aligned address. The caller
        // guarantees `bar_base` names a live, eight-byte-aligned mapping of
        // `BAR_WINDOW_SIZE` bytes; `identify` — the only producer of the
        // `Identified` this value came from, its field being private —
        // guarantees `caps.within(BAR_WINDOW_SIZE)` for the extent and
        // `caps.common_is_aligned()` for the alignment of the offset added.
        let common = unsafe { CommonCfg::new(bar_base.add(self.caps.common as usize)) };
        Offered {
            device: MappedBlkDevice {
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

impl<D: BlkDevice> Offered<D> {
    /// Wrap an already-reachable device in the first handshake state.
    ///
    /// Public, and no wider than the surrounding types already are: `D` is any
    /// [`BlkDevice`], and the one implementation that reaches real MMIO —
    /// [`MappedBlkDevice`] — has no constructor outside this crate, so what
    /// this admits is a stand-in.
    #[must_use]
    pub fn new(device: D) -> Self {
        Self { device }
    }

    /// Reset the device, then tell it the driver has noticed it and knows how
    /// to drive it (`ACKNOWLEDGE`, then `ACKNOWLEDGE | DRIVER`).
    ///
    /// Both writes are cumulative ORs, as virtio 1.0 section 3.1.1 requires: the
    /// device latches the status byte as written, so setting `DRIVER` alone
    /// would retract `ACKNOWLEDGE`.
    ///
    /// # Errors
    /// [`BringUpError::ResetRefused`], with `STATUS_FAILED` written first.
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

/// A device that has been reset and told the driver is present.
pub struct Acknowledged<D> {
    device: D,
}

impl<D: BlkDevice> Acknowledged<D> {
    /// Negotiate features, confirm the request queue exists, and take the
    /// device's capacity.
    ///
    /// The status byte is **re-read** after `FEATURES_OK` is set: a virtio 1.0
    /// device may clear that bit to refuse the set, and a driver that does not
    /// read it back proceeds against a device that has already said no. The
    /// read-only refusal comes before the driver's own features are written, so
    /// a medium this driver cannot use is never negotiated with.
    ///
    /// # Errors
    /// [`BringUpError::NoVirtio1`], [`BringUpError::DeviceReadOnly`],
    /// [`BringUpError::FeaturesRejected`], [`BringUpError::QueueAbsent`] or
    /// [`BringUpError::CapacityZero`], each with `STATUS_FAILED` written first.
    pub fn negotiate_features(self) -> Result<Negotiated<D>, BringUpError> {
        let offered = self.device.device_features();
        let fail = |error| {
            self.device.set_status(STATUS_FAILED);
            error
        };
        if offered & features::VIRTIO_F_VERSION_1 == 0 {
            return Err(fail(BringUpError::NoVirtio1 { offered }));
        }
        if offered & features::VIRTIO_BLK_F_RO != 0 {
            return Err(fail(BringUpError::DeviceReadOnly { offered }));
        }
        self.device.set_driver_features(offered & ACCEPTED_FEATURES);
        self.device
            .set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
        let status = self.device.status();
        if status & STATUS_FEATURES_OK == 0 {
            return Err(fail(BringUpError::FeaturesRejected { status }));
        }
        // Written against the count the queue index implies rather than
        // against the index itself, which is zero and makes the comparison read
        // as a tautology.
        let required = BLK_QUEUE + 1;
        let queues = self.device.num_queues();
        if queues < required {
            return Err(fail(BringUpError::QueueAbsent {
                offered: queues,
                required,
            }));
        }
        let capacity_sectors = self.device.capacity_sectors();
        if capacity_sectors == 0 {
            return Err(fail(BringUpError::CapacityZero));
        }
        Ok(Negotiated {
            device: self.device,
            offered,
            capacity_sectors,
        })
    }
}

/// A device that has accepted this driver's feature set, offers the request
/// queue, and claims a non-zero capacity.
pub struct Negotiated<D> {
    device: D,
    offered: u64,
    capacity_sectors: u64,
}

impl<D: BlkDevice> Negotiated<D> {
    /// The offered set masked to [`ACCEPTED_FEATURES`], never the device's raw
    /// offer.
    #[must_use]
    pub fn features(&self) -> u64 {
        self.offered & ACCEPTED_FEATURES
    }

    /// Whether the device offered [`features::VIRTIO_BLK_F_FLUSH`]: observed,
    /// not accepted, and the difference is the point — a flush issued to a
    /// device without it is answered but commits nothing.
    #[must_use]
    pub fn flush_supported(&self) -> bool {
        self.offered & features::VIRTIO_BLK_F_FLUSH != 0
    }

    #[must_use]
    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    /// Program the request virtqueue into the device and place its doorbell.
    ///
    /// `dma_paddr` is build data, checked for the same reason `bar_paddr` is:
    /// it is handed to a device that will DMA to it, so a zero, misaligned or
    /// wrapping value must fail visibly rather than point the hardware at
    /// whatever lies there. **This check is the enforcer
    /// [`crate::request::Requests::attach`] names for the same address**,
    /// proved by `an_unusable_dma_region_address_is_refused`.
    ///
    /// The doorbell is placed here rather than returned as an offset, so a
    /// `queue_notify_off` never leaves as a bare number: it is either bounded
    /// into a [`QueueDoorbell`] or it is an error.
    ///
    /// # Errors
    /// [`BringUpError::DmaRegionUnusable`],
    /// [`BringUpError::QueueSetupRefused`] or
    /// [`BringUpError::DoorbellRefused`], each with `STATUS_FAILED` written
    /// first.
    pub fn configure_queue(self, dma_paddr: u64) -> Result<Configured<D>, BringUpError> {
        let fail = |error| {
            self.device.set_status(STATUS_FAILED);
            error
        };
        let addressable = dma_paddr.checked_add(DMA_REGION_SIZE as u64).is_some();
        if !addressable || dma_paddr == 0 || !dma_paddr.is_multiple_of(PAGE_SIZE as u64) {
            return Err(fail(BringUpError::DmaRegionUnusable { paddr: dma_paddr }));
        }
        let notify_off = self
            .device
            .setup_queue(BLK_QUEUE, &BlkVirtqueue::LAYOUT, dma_paddr)
            .map_err(|error| fail(BringUpError::QueueSetupRefused { error }))?;
        let doorbell = self
            .device
            .place_doorbell(notify_off)
            .map_err(|error| fail(BringUpError::DoorbellRefused { error }))?;
        Ok(Configured {
            device: self.device,
            doorbell,
            offered: self.offered,
            capacity_sectors: self.capacity_sectors,
        })
    }
}

/// A device whose virtqueue is programmed and whose doorbell is placed, but
/// which has not been told the driver is ready. The doorbell is held privately
/// and becomes ringable only in [`Live`].
pub struct Configured<D: BlkDevice> {
    device: D,
    doorbell: D::Doorbell,
    offered: u64,
    capacity_sectors: u64,
}

impl<D: BlkDevice> Configured<D> {
    /// Set `DRIVER_OK`.
    ///
    /// Nothing is rung: unlike a network receive queue, a block queue is empty
    /// at this point, and a notification for a queue carrying no request tells
    /// the device nothing. The first ring is the first
    /// [`crate::request::Requests::submit`]'s caller's.
    #[must_use]
    pub fn go_live(self) -> Live<D> {
        self.device
            .set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
        Live {
            doorbell: self.doorbell,
            offered: self.offered,
            capacity_sectors: self.capacity_sectors,
        }
    }
}

/// A live device: [`Configured::go_live`] drops the device handle, because past
/// `DRIVER_OK` the steady-state driver touches no common-configuration
/// register, only the doorbell and the virtqueue in the DMA region — keeping
/// the MMIO handle would be reach this domain does not need.
pub struct Live<D: BlkDevice> {
    doorbell: D::Doorbell,
    offered: u64,
    capacity_sectors: u64,
}

impl<D: BlkDevice> Live<D> {
    /// Tell the device to examine the request queue. Separate from
    /// [`crate::request::Requests::submit`] so a caller submitting a batch pays
    /// for one notification rather than one per request.
    pub fn ring(&self) {
        self.doorbell.ring(BLK_QUEUE);
    }

    /// The capacity to hand [`crate::request::Requests::attach`], in
    /// [`crate::SECTOR_SIZE`] sectors.
    #[must_use]
    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    /// Whether a flush this driver submits will actually commit. See
    /// [`Negotiated::flush_supported`].
    #[must_use]
    pub fn flush_supported(&self) -> bool {
        self.offered & features::VIRTIO_BLK_F_FLUSH != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};
    use proptest::prelude::*;
    use std::{boxed::Box, rc::Rc, vec, vec::Vec};

    /// One thing a driver did to the device, in the order it did it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Reset,
        Status(u8),
        DriverFeatures(u64),
        QueueConfigured(u16),
        DoorbellPlaced,
        Rang(u16),
    }

    /// The shared, ordered record every fake in a test appends to.
    #[derive(Clone, Default)]
    struct Log(Rc<RefCell<Vec<Event>>>);

    impl Log {
        fn new() -> Self {
            Self::default()
        }
        fn events(&self) -> Vec<Event> {
            self.0.borrow().clone()
        }
        fn record(&self, event: Event) {
            self.0.borrow_mut().push(event);
        }
    }

    struct FakeDoorbell {
        log: Log,
    }

    impl QueueDoorbell for FakeDoorbell {
        fn ring(&self, queue: u16) {
            self.log.record(Event::Rang(queue));
        }
    }

    /// A virtio-blk device that answers however a test tells it to.
    ///
    /// It models the *authority a device has* — any feature bitmap, any queue
    /// count, any capacity, any `queue_notify_off`, a reset it may simply not
    /// acknowledge — and constrains none of it to what a conforming device
    /// would do. [`FakeBlkDevice::conforming`] is the well-behaved
    /// baseline; every builder method takes one capability away from it.
    struct FakeBlkDevice {
        log: Log,
        offered: u64,
        queues: u16,
        capacity: u64,
        notify_off: u16,
        reset_refused: Option<u8>,
        clears_features_ok: bool,
        refused_queue: Option<QueueSetupError>,
        refused_doorbell: Option<NotifyError>,
        status: Cell<u8>,
    }

    impl FakeBlkDevice {
        fn conforming(log: &Log) -> Self {
            Self {
                log: log.clone(),
                offered: ACCEPTED_FEATURES | features::VIRTIO_BLK_F_FLUSH,
                queues: 1,
                capacity: 2048,
                notify_off: 3,
                reset_refused: None,
                clears_features_ok: false,
                refused_queue: None,
                refused_doorbell: None,
                status: Cell::new(0),
            }
        }
        fn offering(mut self, features: u64) -> Self {
            self.offered = features;
            self
        }
        fn with_queues(mut self, queues: u16) -> Self {
            self.queues = queues;
            self
        }
        fn with_capacity(mut self, capacity: u64) -> Self {
            self.capacity = capacity;
            self
        }
        fn refusing_reset(mut self, status: u8) -> Self {
            self.reset_refused = Some(status);
            self
        }
        fn clearing_features_ok(mut self) -> Self {
            self.clears_features_ok = true;
            self
        }
        fn refusing_queue(mut self, error: QueueSetupError) -> Self {
            self.refused_queue = Some(error);
            self
        }
        fn refusing_doorbell(mut self, error: NotifyError) -> Self {
            self.refused_doorbell = Some(error);
            self
        }
    }

    impl BlkDevice for FakeBlkDevice {
        type Doorbell = FakeDoorbell;

        fn reset(&self) -> Result<(), ResetError> {
            self.log.record(Event::Reset);
            match self.reset_refused {
                Some(status) => Err(ResetError::NotAcknowledged { status }),
                None => {
                    self.status.set(0);
                    Ok(())
                }
            }
        }

        fn status(&self) -> u8 {
            let held = self.status.get();
            if self.clears_features_ok {
                held & !STATUS_FEATURES_OK
            } else {
                held
            }
        }

        fn set_status(&self, value: u8) {
            self.log.record(Event::Status(value));
            self.status.set(value);
        }

        fn device_features(&self) -> u64 {
            self.offered
        }

        fn set_driver_features(&self, features: u64) {
            self.log.record(Event::DriverFeatures(features));
        }

        fn num_queues(&self) -> u16 {
            self.queues
        }

        fn capacity_sectors(&self) -> u64 {
            self.capacity
        }

        fn setup_queue(
            &self,
            index: u16,
            _layout: &QueueLayout,
            _ring_paddr: u64,
        ) -> Result<u16, QueueSetupError> {
            if let Some(error) = self.refused_queue {
                return Err(error);
            }
            self.log.record(Event::QueueConfigured(index));
            Ok(self.notify_off)
        }

        fn place_doorbell(&self, _notify_off: u16) -> Result<FakeDoorbell, NotifyError> {
            if let Some(error) = self.refused_doorbell {
                return Err(error);
            }
            self.log.record(Event::DoorbellPlaced);
            Ok(FakeDoorbell {
                log: self.log.clone(),
            })
        }
    }

    const DMA_PADDR: u64 = 0x3000_0000;

    /// Run the whole handshake against `device`, from [`Offered`] to [`Live`].
    fn bring_up(device: FakeBlkDevice) -> Result<Live<FakeBlkDevice>, BringUpError> {
        Ok(Offered::new(device)
            .acknowledge()?
            .negotiate_features()?
            .configure_queue(DMA_PADDR)?
            .go_live())
    }

    /// The heap allocation a fixture region owns, carrying the alignment a
    /// Microkit mapping supplies. `[u8; N]` has `align_of == 1`, so a fixture
    /// handing one to `PciConfig::new` or `PlacedBar::map` would under-deliver
    /// on the very contract under test and manufacture its own misalignment.
    #[repr(C, align(4096))]
    struct Page<const N: usize>([u8; N]);

    /// A fixture mapping, reachable only through the one raw pointer the driver
    /// under test is attached to.
    ///
    /// The bytes are `Box::into_raw`d and no `&`/`&mut` into them is ever
    /// formed, so fixture and driver share a single tag for the whole region's
    /// life. A reference would not survive: the driver writes its registers
    /// through the raw pointer, and such a write invalidates any reference
    /// derived from the same allocation, so a fixture that read a register back
    /// through one would itself be undefined behaviour while claiming to prove
    /// the driver's conduct against a hostile device. Exposing no
    /// reference makes that unrepresentable rather than a rule to remember.
    struct MappedRegion<const N: usize> {
        page: *mut Page<N>,
    }

    impl<const N: usize> MappedRegion<N> {
        fn zeroed() -> Self {
            Self {
                page: Box::into_raw(Box::new(Page([0u8; N]))),
            }
        }

        /// The pointer the driver is mapped over, and the only route to the
        /// bytes — `*mut` from `&self` deliberately, because handing the driver
        /// a second, separately derived pointer is what a fixture must not do.
        fn base(&self) -> *mut u8 {
            self.page.cast::<u8>()
        }

        fn read<const M: usize>(&self, off: usize) -> [u8; M] {
            assert!(
                off.saturating_add(M) <= N,
                "read of {off:#x} escapes {N:#x}"
            );
            // SAFETY: the assertion above puts `off..off + M` inside the
            // `N`-byte allocation `zeroed` made, which `Drop` alone frees and
            // which therefore outlives `self`; `[u8; M]` imposes no alignment.
            unsafe { self.base().add(off).cast::<[u8; M]>().read_volatile() }
        }

        fn write<const M: usize>(&mut self, off: usize, bytes: [u8; M]) {
            assert!(
                off.saturating_add(M) <= N,
                "write of {off:#x} escapes {N:#x}"
            );
            // SAFETY: bounded by the assertion above into the allocation
            // `zeroed` made and `Drop` alone frees, exactly as `read`.
            unsafe { self.base().add(off).cast::<[u8; M]>().write_volatile(bytes) };
        }
    }

    impl MappedRegion<4096> {
        fn config(&mut self) -> PciConfig {
            // SAFETY: `N == 4096` makes this allocation exactly the ECAM page
            // `PciConfig::new` names, page-aligned by `Page`, live until this
            // region's `Drop` and so outliving the value.
            unsafe { PciConfig::new(self.base()) }
        }
    }

    impl MappedRegion<BAR_WINDOW_SIZE> {
        /// Attach the driver to this region as though `caps` had come from
        /// [`identify`], which is the only other way a `PlacedBar` is made.
        fn map(&mut self, caps: VirtioCaps) -> Offered<MappedBlkDevice> {
            assert!(caps.within(BAR_WINDOW_SIZE));
            assert!(caps.common_is_aligned());
            assert!(caps.device_cfg_within(BAR_WINDOW_SIZE, CAPACITY_LEN));
            assert!(caps.device_is_aligned(CAPACITY_ALIGN));
            // SAFETY: `N == BAR_WINDOW_SIZE` makes this allocation exactly the
            // window `PlacedBar::map` names, page-aligned by `Page` and live
            // until this region's `Drop`, which nothing derived here outlives.
            // The predicates it relies on `identify` for were just asserted,
            // this being the literal construction they guard.
            unsafe { PlacedBar { caps }.map(self.base()) }
        }
    }

    impl<const N: usize> Drop for MappedRegion<N> {
        fn drop(&mut self) {
            // SAFETY: `page` came from `Box::into_raw` in `zeroed`, is never
            // replaced, and no other owner exists, so this reconstructs that
            // `Box` exactly once.
            drop(unsafe { Box::from_raw(self.page) });
        }
    }

    /// A synthetic 4 KiB configuration space with a virtio capability chain, so
    /// `identify` and `place_bar` run against real `PciConfig` accessors over
    /// plain memory.
    struct FakeConfig {
        region: MappedRegion<4096>,
    }

    // Configuration-space offsets the fixture writes, restated here because a
    // test that cannot address the registers cannot model a malformed device.
    const CFG_VENDOR: usize = 0x00;
    const CFG_DEVICE: usize = 0x02;
    const CFG_STATUS: usize = 0x06;
    const CFG_CAP_PTR: usize = 0x34;
    const CFG_BAR0: usize = 0x10;
    const CAP_LIST_BIT: u16 = 1 << 4;
    const CAP_ID_VNDR: u8 = 0x09;
    /// Memory BAR, 64-bit type: bit 0 clear, bits [2:1] == 0b10.
    const BAR_TYPE_64BIT: u32 = 0b100;
    /// Where the fixture's device-configuration capability points.
    const DEVICE_CFG_AT: u32 = 0x2000;

    impl FakeConfig {
        /// A conforming modern virtio-blk device in BAR 4, with all four virtio
        /// structures inside a `BAR_WINDOW_SIZE` window.
        fn conforming() -> Self {
            let mut fake = Self {
                region: MappedRegion::zeroed(),
            };
            fake.w16(CFG_VENDOR, VIRTIO_VENDOR_ID);
            fake.w16(CFG_DEVICE, VIRTIO_BLK_DEVICE_ID);
            fake.w16(CFG_STATUS, CAP_LIST_BIT);
            fake.w8(CFG_CAP_PTR, 0x40);
            fake.put_cap(0x40, 0x50, 1, 4, 0x0000, 16);
            fake.put_cap(0x50, 0x64, 2, 4, 0x3000, 20);
            fake.w32(0x50 + 16, 4);
            fake.put_cap(0x64, 0x74, 3, 4, 0x1000, 16);
            fake.put_cap(0x74, 0x00, 4, 4, DEVICE_CFG_AT, 16);
            fake.w32(CFG_BAR0 + 4 * 4, BAR_TYPE_64BIT);
            fake
        }

        fn w8(&mut self, off: usize, v: u8) {
            self.region.write(off, [v]);
        }
        fn w16(&mut self, off: usize, v: u16) {
            self.region.write(off, v.to_le_bytes());
        }
        fn w32(&mut self, off: usize, v: u32) {
            self.region.write(off, v.to_le_bytes());
        }
        fn r32(&self, off: usize) -> u32 {
            u32::from_le_bytes(self.region.read(off))
        }
        fn r16(&self, off: usize) -> u16 {
            u16::from_le_bytes(self.region.read(off))
        }
        /// Move the device-configuration capability's offset, the one field
        /// three of the refusals below turn on.
        fn device_cfg(&mut self, offset: u32) {
            self.w32(0x74 + 8, offset);
        }
        fn put_cap(&mut self, at: usize, next: u8, cfg_type: u8, bar: u8, offset: u32, len: u8) {
            self.w8(at, CAP_ID_VNDR);
            self.w8(at + 1, next);
            self.w8(at + 2, len);
            self.w8(at + 3, cfg_type);
            self.w8(at + 4, bar);
            self.w32(at + 8, offset);
        }
        fn config(&mut self) -> PciConfig {
            self.region.config()
        }
    }

    #[test]
    fn a_conforming_device_is_identified_and_its_bar_relocated() {
        let mut fake = FakeConfig::conforming();
        let identified = identify(&fake.config()).expect("a conforming device");
        assert_eq!(identified.caps().bar, 4);
        assert_eq!(identified.caps().device, DEVICE_CFG_AT);

        identified
            .place_bar(&fake.config(), 0x5000_0000)
            .expect("an aligned 32-bit target");
        assert_eq!(fake.r32(CFG_BAR0 + 4 * 4), 0x5000_0000);
        assert_eq!(fake.r32(CFG_BAR0 + 5 * 4), 0);
        assert_eq!(fake.r16(0x04) & 0b110, 0b110, "memory and bus master");
    }

    #[test]
    fn a_device_that_is_not_virtio_blk_is_refused_by_its_ids() {
        // Including virtio-net, which shares the vendor and would otherwise be
        // driven with a block driver's register map.
        for device in [0x1000u16, 0x1041] {
            let mut fake = FakeConfig::conforming();
            fake.w16(CFG_DEVICE, device);
            assert_eq!(
                identify(&fake.config()),
                Err(BringUpError::NotVirtioBlk {
                    vendor: VIRTIO_VENDOR_ID,
                    device,
                })
            );
        }
    }

    #[test]
    fn every_capability_list_fault_reaches_the_operator_distinctly() {
        let mut absent = FakeConfig::conforming();
        absent.w16(CFG_STATUS, 0);
        assert_eq!(
            identify(&absent.config()),
            Err(BringUpError::Capabilities(CapError::NoCapabilities))
        );

        let mut looped = FakeConfig::conforming();
        looped.w8(0x41, 0x40);
        assert_eq!(
            identify(&looped.config()),
            Err(BringUpError::Capabilities(CapError::Malformed))
        );

        let mut split = FakeConfig::conforming();
        split.w8(0x50 + 4, 2);
        assert_eq!(
            identify(&split.config()),
            Err(BringUpError::Capabilities(CapError::MultipleBars))
        );

        let mut invalid = FakeConfig::conforming();
        invalid.w8(0x40 + 4, 9);
        assert_eq!(
            identify(&invalid.config()),
            Err(BringUpError::Capabilities(CapError::InvalidBar))
        );

        let mut missing = FakeConfig::conforming();
        missing.w8(0x50 + 1, 0x74);
        assert_eq!(
            identify(&missing.config()),
            Err(BringUpError::Capabilities(CapError::MissingStructure))
        );
    }

    #[test]
    fn a_structure_outside_the_mapped_window_is_refused_before_any_dereference() {
        let mut fake = FakeConfig::conforming();
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
        for offset in [1u32, 2, 3, 9, 0x102] {
            let mut fake = FakeConfig::conforming();
            fake.w32(0x40 + 8, offset);
            assert_eq!(
                identify(&fake.config()),
                Err(BringUpError::CommonCfgMisaligned {
                    offset,
                    required: pci::COMMON_CFG_ALIGN,
                }),
                "offset {offset:#x} must be refused by alignment, not by extent"
            );
        }
    }

    #[test]
    fn a_device_configuration_structure_without_room_for_capacity_is_refused() {
        // Each of these leaves at least one byte inside the window, so
        // `VirtioCaps::within` passes and only the driver's own eight-byte
        // extent check can catch it — which is the whole reason
        // `device_cfg_within` exists.
        for offset in [
            (BAR_WINDOW_SIZE - 8) as u32 + 8,
            (BAR_WINDOW_SIZE - 4) as u32,
            (BAR_WINDOW_SIZE - 1) as u32,
        ] {
            let mut fake = FakeConfig::conforming();
            fake.device_cfg(offset);
            let error = identify(&fake.config()).expect_err("no room for capacity");
            assert!(
                matches!(
                    error,
                    BringUpError::DeviceCfgOutsideBar {
                        needed: CAPACITY_LEN,
                        bar_window: BAR_WINDOW_SIZE,
                        ..
                    } | BringUpError::StructuresOutsideBar { .. }
                ),
                "offset {offset:#x} produced {error:?}"
            );
            assert!(!error.signalled_to_device());
        }
        // And exactly at the boundary, where the eight bytes are the last of
        // the window: accepted, so the check is pinned to the extent rather
        // than refusing every high offset.
        let mut fits = FakeConfig::conforming();
        fits.device_cfg((BAR_WINDOW_SIZE - CAPACITY_LEN) as u32);
        identify(&fits.config()).expect("the last eight bytes are inside the window");
    }

    #[test]
    fn a_misaligned_device_configuration_offset_is_refused_before_any_dereference() {
        // Every non-multiple of eight is the same fault, including the merely
        // four-aligned ones a `u32` read would have tolerated.
        for offset in [1u32, 2, 4, 0x2004, 0x200c] {
            let mut fake = FakeConfig::conforming();
            fake.device_cfg(offset);
            let error = identify(&fake.config()).expect_err("a misaligned capacity");
            assert_eq!(
                error,
                BringUpError::DeviceCfgMisaligned {
                    offset,
                    required: CAPACITY_ALIGN,
                }
            );
            assert!(!error.signalled_to_device());
        }
    }

    #[test]
    fn a_bar_that_is_not_a_64_bit_pair_is_refused() {
        let mut fake = FakeConfig::conforming();
        fake.w32(CFG_BAR0 + 4 * 4, 0);
        assert_eq!(
            identify(&fake.config()),
            Err(BringUpError::BarNotSixtyFourBit { bar: 4 })
        );
    }

    #[test]
    fn a_bar_index_that_is_not_a_bar_of_this_function_is_refused() {
        // The capability walk refuses an index above 5 itself, so the only way
        // to reach `bar_is_64bit`'s own refusal is an index it accepts and the
        // BAR register does not exist for — BAR 5's missing high half.
        let mut fake = FakeConfig::conforming();
        for cap in [0x40usize, 0x50, 0x64, 0x74] {
            fake.w8(cap + 4, 5);
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
        bring_up(FakeBlkDevice::conforming(&log)).expect("a conforming device");
        assert_eq!(
            log.events(),
            vec![
                Event::Reset,
                Event::Status(STATUS_ACKNOWLEDGE),
                Event::Status(STATUS_ACKNOWLEDGE | STATUS_DRIVER),
                Event::DriverFeatures(ACCEPTED_FEATURES),
                Event::Status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
                Event::QueueConfigured(BLK_QUEUE),
                Event::DoorbellPlaced,
                Event::Status(
                    STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK
                ),
            ],
            "reset, acknowledge, driver, features, queue, then DRIVER_OK"
        );
    }

    #[test]
    fn nothing_is_rung_until_a_caller_has_something_to_notify_about() {
        let log = Log::new();
        let live = bring_up(FakeBlkDevice::conforming(&log)).expect("a conforming device");
        assert!(
            !log.events().iter().any(|e| matches!(e, Event::Rang(_))),
            "an empty block queue is nothing to notify about"
        );
        live.ring();
        assert_eq!(log.events().last(), Some(&Event::Rang(BLK_QUEUE)));
    }

    #[test]
    fn the_feature_mask_accepts_only_what_this_driver_implements() {
        // A device offering every bit but read-only must still be told this
        // driver accepts exactly one: accepting a bit no code handles licences
        // the device to produce buffers this driver cannot service.
        let log = Log::new();
        let offered = !features::VIRTIO_BLK_F_RO;
        let live = bring_up(FakeBlkDevice::conforming(&log).offering(offered))
            .expect("virtio 1.0 and a writable medium");
        assert!(
            log.events()
                .contains(&Event::DriverFeatures(ACCEPTED_FEATURES))
        );
        assert_eq!(ACCEPTED_FEATURES, features::VIRTIO_F_VERSION_1);
        assert!(
            live.flush_supported(),
            "the bit was offered, so it is a fact"
        );
    }

    #[test]
    fn a_device_that_does_not_offer_flush_says_so_rather_than_letting_a_caller_guess() {
        let log = Log::new();
        let live = bring_up(FakeBlkDevice::conforming(&log).offering(ACCEPTED_FEATURES))
            .expect("virtio 1.0 alone is enough to run");
        assert!(!live.flush_supported());
        assert_eq!(live.capacity_sectors(), 2048);
    }

    #[test]
    fn a_read_only_device_is_refused_by_name_rather_than_at_the_first_write() {
        let log = Log::new();
        let offered = ACCEPTED_FEATURES | features::VIRTIO_BLK_F_RO;
        assert_eq!(
            bring_up(FakeBlkDevice::conforming(&log).offering(offered)).err(),
            Some(BringUpError::DeviceReadOnly { offered })
        );
        assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
        assert!(
            !log.events()
                .iter()
                .any(|e| matches!(e, Event::DriverFeatures(_))),
            "a medium this driver cannot use is never negotiated with"
        );
    }

    #[test]
    fn a_device_refusing_the_reset_is_rejected_and_told_so() {
        let log = Log::new();
        assert_eq!(
            bring_up(FakeBlkDevice::conforming(&log).refusing_reset(0x42)).err(),
            Some(BringUpError::ResetRefused(ResetError::NotAcknowledged {
                status: 0x42
            }))
        );
        assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
    }

    #[test]
    fn a_device_without_virtio_1_is_rejected_with_the_offer_it_made() {
        let log = Log::new();
        let offered = features::VIRTIO_BLK_F_FLUSH;
        assert_eq!(
            bring_up(FakeBlkDevice::conforming(&log).offering(offered)).err(),
            Some(BringUpError::NoVirtio1 { offered })
        );
        assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
    }

    #[test]
    fn a_device_clearing_features_ok_stops_initialization() {
        let log = Log::new();
        assert_eq!(
            bring_up(FakeBlkDevice::conforming(&log).clearing_features_ok()).err(),
            Some(BringUpError::FeaturesRejected {
                status: STATUS_ACKNOWLEDGE | STATUS_DRIVER
            })
        );
        assert!(
            !log.events()
                .iter()
                .any(|e| matches!(e, Event::QueueConfigured(_))),
            "no queue may be programmed into a device that refused the features"
        );
    }

    #[test]
    fn a_device_with_no_request_queue_is_rejected() {
        let log = Log::new();
        assert_eq!(
            bring_up(FakeBlkDevice::conforming(&log).with_queues(0)).err(),
            Some(BringUpError::QueueAbsent {
                offered: 0,
                required: 1,
            })
        );
        assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
    }

    #[test]
    fn a_device_claiming_no_sectors_is_rejected_at_bring_up() {
        let log = Log::new();
        assert_eq!(
            bring_up(FakeBlkDevice::conforming(&log).with_capacity(0)).err(),
            Some(BringUpError::CapacityZero)
        );
        assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
    }

    #[test]
    fn an_unusable_dma_region_address_is_refused() {
        // The enforcer `Requests::attach` names for the same address:
        // zero, not page-aligned, and a base whose region would wrap.
        for paddr in [0u64, 0x3000_0800, u64::MAX, u64::MAX - 0x800] {
            let log = Log::new();
            let negotiated = Offered::new(FakeBlkDevice::conforming(&log))
                .acknowledge()
                .unwrap()
                .negotiate_features()
                .unwrap();
            assert_eq!(
                negotiated.configure_queue(paddr).err(),
                Some(BringUpError::DmaRegionUnusable { paddr }),
                "region address {paddr:#x} must be refused"
            );
            assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
        }
    }

    #[test]
    fn a_refused_queue_or_doorbell_names_why() {
        for error in [
            QueueSetupError::QueueAbsent { index: BLK_QUEUE },
            QueueSetupError::QueueTooSmall {
                index: BLK_QUEUE,
                device_max: 4,
                required: crate::QUEUE_SIZE,
            },
        ] {
            let log = Log::new();
            assert_eq!(
                bring_up(FakeBlkDevice::conforming(&log).refusing_queue(error)).err(),
                Some(BringUpError::QueueSetupRefused { error })
            );
            assert_eq!(log.events().last(), Some(&Event::Status(STATUS_FAILED)));
        }
        for error in [
            NotifyError::SlotMisaligned { offset: 0x3001 },
            NotifyError::SlotOutsideBar {
                slot_end: Some(BAR_WINDOW_SIZE + 2),
                bar_size: BAR_WINDOW_SIZE,
            },
        ] {
            let log = Log::new();
            assert_eq!(
                bring_up(FakeBlkDevice::conforming(&log).refusing_doorbell(error)).err(),
                Some(BringUpError::DoorbellRefused { error })
            );
            assert!(
                !log.events().iter().any(|e| matches!(e, Event::Rang(_))),
                "a device whose doorbell could not be placed is never rung"
            );
        }
    }

    #[test]
    fn status_failed_is_signalled_once_the_device_is_reachable() {
        // The claim `signalled_to_device` makes, checked against what the code
        // actually wrote, for every variant a handshake can produce.
        let cases: [fn(&Log) -> FakeBlkDevice; 8] = [
            |log| FakeBlkDevice::conforming(log).refusing_reset(1),
            |log| FakeBlkDevice::conforming(log).offering(0),
            |log| {
                FakeBlkDevice::conforming(log)
                    .offering(ACCEPTED_FEATURES | features::VIRTIO_BLK_F_RO)
            },
            |log| FakeBlkDevice::conforming(log).clearing_features_ok(),
            |log| FakeBlkDevice::conforming(log).with_queues(0),
            |log| FakeBlkDevice::conforming(log).with_capacity(0),
            |log| {
                FakeBlkDevice::conforming(log)
                    .refusing_queue(QueueSetupError::QueueAbsent { index: BLK_QUEUE })
            },
            |log| {
                FakeBlkDevice::conforming(log)
                    .refusing_doorbell(NotifyError::SlotMisaligned { offset: 1 })
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
        // And a pre-BAR variant, whose register does not exist yet.
        let mut fake = FakeConfig::conforming();
        fake.w16(CFG_DEVICE, 0);
        assert!(
            !identify(&fake.config())
                .expect_err("not virtio-blk")
                .signalled_to_device()
        );
    }

    /// A BAR window seeded so a `CommonCfg` driven over it answers as a
    /// conforming device would: virtio 1.0 offered, one virtqueue, a queue
    /// maximum of `QUEUE_SIZE`, notify slot 3, and a capacity.
    fn seeded_bar(common: usize, device_cfg: usize) -> MappedRegion<BAR_WINDOW_SIZE> {
        let mut bar = MappedRegion::zeroed();
        // `device_features` reads the same register under both selector
        // windows over plain memory, so bit 0 here becomes bit 32 of the pair —
        // which is VIRTIO_F_VERSION_1, the one bit this driver requires.
        bar.write(common + 4, 1u32.to_le_bytes());
        bar.write(common + 18, 1u16.to_le_bytes());
        bar.write(common + 24, (crate::QUEUE_SIZE as u16).to_le_bytes());
        bar.write(common + 30, 3u16.to_le_bytes());
        bar.write(device_cfg, 4096u64.to_le_bytes());
        bar
    }

    #[test]
    fn the_shipped_device_handshake_reaches_every_register_the_layout_names() {
        // `MappedBlkDevice` is the implementation that ships, and every method
        // on it is a delegation to a register at an offset. A delegation to the
        // *wrong* register is invisible to the fake-device tests — they never
        // touch an offset — and on real hardware would surface as a device that
        // silently does nothing.
        const COMMON: usize = 0x100;
        const NOTIFY: usize = 0x200;
        const DEVICE_CFG: usize = 0x300;
        let mut bar = seeded_bar(COMMON, DEVICE_CFG);
        let caps = VirtioCaps {
            bar: 4,
            common: COMMON as u32,
            notify: NOTIFY as u32,
            notify_multiplier: 4,
            device: DEVICE_CFG as u32,
        };
        let negotiated = bar
            .map(caps)
            .acknowledge()
            .expect("a zeroed status register reads back as an acknowledged reset")
            .negotiate_features()
            .expect("virtio 1.0, one queue and a capacity");
        assert_eq!(negotiated.features(), ACCEPTED_FEATURES);
        assert_eq!(
            negotiated.capacity_sectors(),
            4096,
            "capacity is read from the device-configuration structure, not the BAR base"
        );
        assert!(!negotiated.flush_supported());
        let live = negotiated
            .configure_queue(DMA_PADDR)
            .expect("the queue fits the device maximum")
            .go_live();

        assert_eq!(
            u8::from_le_bytes(bar.read(COMMON + 20)),
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK
        );
        // The driver's accepted set, written low half first at common+12 under
        // selector 1 — so the high half of ACCEPTED_FEATURES.
        assert_eq!(
            u32::from_le_bytes(bar.read(COMMON + 12)),
            (ACCEPTED_FEATURES >> 32) as u32
        );
        assert_eq!(u16::from_le_bytes(bar.read(COMMON + 22)), BLK_QUEUE);
        assert_eq!(
            u16::from_le_bytes(bar.read(COMMON + 24)),
            crate::QUEUE_SIZE as u16
        );
        assert_eq!(u16::from_le_bytes(bar.read(COMMON + 28)), 1, "queue_enable");
        let layout = &BlkVirtqueue::LAYOUT;
        assert_eq!(
            u64::from_le_bytes(bar.read(COMMON + 32)),
            DMA_PADDR + layout.descriptor_offset as u64
        );
        assert_eq!(
            u64::from_le_bytes(bar.read(COMMON + 40)),
            DMA_PADDR + layout.driver_offset as u64
        );
        assert_eq!(
            u64::from_le_bytes(bar.read(COMMON + 48)),
            DMA_PADDR + layout.device_offset as u64
        );
        // Nothing rung yet; slot 3 of a multiplier-4 notify structure.
        assert_eq!(u16::from_le_bytes(bar.read(NOTIFY + 12)), 0);
        live.ring();
        assert_eq!(u16::from_le_bytes(bar.read(NOTIFY + 12)), BLK_QUEUE);
        assert_eq!(live.capacity_sectors(), 4096);
    }

    #[test]
    fn a_mapped_device_refuses_a_doorbell_slot_outside_the_window() {
        let mut bar = MappedRegion::zeroed();
        let device = bar
            .map(VirtioCaps {
                bar: 4,
                common: 0,
                notify: 0x3000,
                notify_multiplier: u32::MAX,
                device: 0x2000,
            })
            .device;
        assert!(matches!(
            device.place_doorbell(u16::MAX),
            Err(NotifyError::SlotOutsideBar { .. })
        ));
        // And the shipped reset path, which a zeroed register acknowledges.
        assert_eq!(device.reset(), Ok(()));
        assert_eq!(device.status(), 0);
        assert_eq!(device.num_queues(), 0);
        assert_eq!(device.capacity_sectors(), 0);
    }

    /// One of every refusal, so the token mapping is checked exhaustively
    /// rather than only where a handshake happens to reach.
    fn every_bring_up_error() -> Vec<BringUpError> {
        let mut errors = vec![
            BringUpError::NotVirtioBlk {
                vendor: 0x8086,
                device: 0x100e,
            },
            BringUpError::StructuresOutsideBar {
                caps: VirtioCaps {
                    bar: 4,
                    common: 0,
                    notify: 0,
                    notify_multiplier: 0,
                    device: 0,
                },
                bar_window: BAR_WINDOW_SIZE,
            },
            BringUpError::CommonCfgMisaligned {
                offset: 3,
                required: pci::COMMON_CFG_ALIGN,
            },
            BringUpError::DeviceCfgOutsideBar {
                offset: 0x3ffc,
                needed: CAPACITY_LEN,
                bar_window: BAR_WINDOW_SIZE,
            },
            BringUpError::DeviceCfgMisaligned {
                offset: 4,
                required: CAPACITY_ALIGN,
            },
            BringUpError::BarNotSixtyFourBit { bar: 4 },
            BringUpError::BarIndexRefused(BarError::IndexOutOfRange(9)),
            BringUpError::BarIndexRefused(BarError::NoHighHalf(5)),
            BringUpError::BarTargetUnusable { paddr: 1 },
            BringUpError::ResetRefused(ResetError::NotAcknowledged { status: 0x0f }),
            BringUpError::NoVirtio1 { offered: 0 },
            BringUpError::DeviceReadOnly { offered: 1 << 5 },
            BringUpError::FeaturesRejected { status: 0x0b },
            BringUpError::QueueAbsent {
                offered: 0,
                required: 1,
            },
            BringUpError::CapacityZero,
            BringUpError::DmaRegionUnusable { paddr: 1 },
            BringUpError::QueueSetupRefused {
                error: QueueSetupError::QueueAbsent { index: BLK_QUEUE },
            },
            BringUpError::QueueSetupRefused {
                error: QueueSetupError::QueueTooSmall {
                    index: BLK_QUEUE,
                    device_max: 8,
                    required: crate::QUEUE_SIZE,
                },
            },
            BringUpError::DoorbellRefused {
                error: NotifyError::SlotOutsideBar {
                    slot_end: Some(BAR_WINDOW_SIZE + 2),
                    bar_size: BAR_WINDOW_SIZE,
                },
            },
            BringUpError::DoorbellRefused {
                error: NotifyError::SlotMisaligned { offset: 1 },
            },
        ];
        for cap in [
            CapError::NoCapabilities,
            CapError::Malformed,
            CapError::MultipleBars,
            CapError::InvalidBar,
            CapError::MissingStructure,
        ] {
            errors.push(BringUpError::Capabilities(cap));
        }
        errors
    }

    /// The console line's cause budget.
    ///
    /// **Cross-artifact:** equal to `lfw_log::MAX_CAUSE_LEN` and
    /// `wire::LOG_CAUSE_BYTES`. This crate depends on neither — its dependency
    /// set is `virtio` alone — so there is no build-time enforcer, and a
    /// disagreement would surface where a protection domain converts a
    /// [`Refusal`] into a log record. This test is the only thing holding the
    /// tokens to it.
    const MAX_CAUSE_LEN: usize = 40;

    #[test]
    fn every_refusal_token_is_distinct_and_fits_the_console_line() {
        // Two faults that render the same line are one line an operator cannot
        // act on.
        let mut tokens = Vec::new();
        for error in every_bring_up_error() {
            let refusal = error.refusal();
            assert!(
                !refusal.cause.is_empty() && refusal.cause.len() <= MAX_CAUSE_LEN,
                "{error:?} names {:?}, which does not fit the console line",
                refusal.cause
            );
            assert!(
                refusal
                    .cause
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{error:?} names {:?}, which is not a console token",
                refusal.cause
            );
            assert_eq!(refusal.signalled, error.signalled_to_device());
            tokens.push(refusal.cause);
        }
        let count = tokens.len();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(tokens.len(), count, "two refusals render as one token");
    }

    #[test]
    fn a_refusal_carries_the_values_that_made_it_one() {
        // The numbers are the half a token cannot carry.
        assert_eq!(
            BringUpError::NotVirtioBlk {
                vendor: 0x8086,
                device: 0x100e,
            }
            .refusal()
            .detail,
            RefusalDetail::Two(0x8086, 0x100e)
        );
        assert_eq!(
            BringUpError::CapacityZero.refusal().detail,
            RefusalDetail::None
        );
        assert_eq!(
            BringUpError::DmaRegionUnusable { paddr: 0x3000_0800 }
                .refusal()
                .detail,
            RefusalDetail::One(0x3000_0800)
        );
        // The one variant whose operand count depends on its own contents.
        assert_eq!(
            BringUpError::DoorbellRefused {
                error: NotifyError::SlotOutsideBar {
                    slot_end: None,
                    bar_size: 0x4000,
                },
            }
            .refusal()
            .detail,
            RefusalDetail::One(0x4000)
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// Arbitrary configuration space: whatever bytes a hostile device puts
        /// in its ECAM page, `identify` must answer with a value or a typed
        /// error and never panic, index out of range, or overflow.
        #[test]
        fn identify_never_panics_on_arbitrary_configuration_space(
            seed in prop::collection::vec(any::<u8>(), 0..512),
            base in prop::array::uniform4(any::<u8>()),
        ) {
            let mut page = MappedRegion::<4096>::zeroed();
            for (offset, byte) in seed.iter().enumerate() {
                page.write(offset, [*byte]);
            }
            page.write(0x00, base);
            match identify(&page.config()) {
                // Anything accepted must satisfy all four halves of what
                // `PlacedBar::map` and `capacity_sectors` name `identify` as
                // the guarantor of.
                Ok(identified) => {
                    prop_assert!(identified.caps().within(BAR_WINDOW_SIZE));
                    prop_assert!(identified.caps().common_is_aligned());
                    prop_assert!(identified.caps().device_cfg_within(BAR_WINDOW_SIZE, CAPACITY_LEN));
                    prop_assert!(identified.caps().device_is_aligned(CAPACITY_ALIGN));
                }
                Err(error) => prop_assert!(!error.signalled_to_device()),
            }
        }

        /// The device-configuration offset alone, under the device's full
        /// authority over the `u32` it names, against an otherwise conforming
        /// chain. The decision must be exactly the conjunction of the two
        /// independent predicates, each reported through its own error.
        #[test]
        fn identify_accepts_a_device_cfg_offset_only_when_bounded_and_aligned(
            device_cfg in prop_oneof![
                0u32..=64,
                (BAR_WINDOW_SIZE as u32 - 128)..=(BAR_WINDOW_SIZE as u32 + 128),
                any::<u32>(),
            ],
        ) {
            let mut fake = FakeConfig::conforming();
            fake.device_cfg(device_cfg);
            let probe_fits = (device_cfg as usize).checked_add(1)
                .is_some_and(|end| end <= BAR_WINDOW_SIZE);
            let fits = (device_cfg as usize).checked_add(CAPACITY_LEN)
                .is_some_and(|end| end <= BAR_WINDOW_SIZE);
            let aligned = (device_cfg as usize).is_multiple_of(CAPACITY_ALIGN);
            match identify(&fake.config()) {
                Ok(_) => prop_assert!(fits && aligned),
                Err(BringUpError::StructuresOutsideBar { .. }) => prop_assert!(!probe_fits),
                Err(BringUpError::DeviceCfgOutsideBar { offset, needed, bar_window }) => {
                    prop_assert!(probe_fits && !fits);
                    prop_assert_eq!(offset, device_cfg);
                    prop_assert_eq!(needed, CAPACITY_LEN);
                    prop_assert_eq!(bar_window, BAR_WINDOW_SIZE);
                }
                Err(BringUpError::DeviceCfgMisaligned { offset, required }) => {
                    // Ordered after the extent check, so this variant also
                    // asserts the offset was in range.
                    prop_assert!(fits && !aligned);
                    prop_assert_eq!(offset, device_cfg);
                    prop_assert_eq!(required, CAPACITY_ALIGN);
                }
                Err(other) => prop_assert!(
                    false, "a conforming chain with device={device_cfg:#x} was refused as {other:?}"
                ),
            }
        }

        /// Arbitrary device behaviour through the whole handshake. Bring-up
        /// must terminate with a live device or a typed error, and a rejection
        /// must always have been signalled.
        #[test]
        fn the_handshake_never_panics_on_arbitrary_device_behaviour(
            offered in any::<u64>(),
            queues in any::<u16>(),
            capacity in any::<u64>(),
            dma in any::<u64>(),
            reset_ok in any::<bool>(),
            features_ok in any::<bool>(),
        ) {
            let log = Log::new();
            let mut device = FakeBlkDevice::conforming(&log)
                .offering(offered)
                .with_queues(queues)
                .with_capacity(capacity);
            if !reset_ok {
                device = device.refusing_reset(0xff);
            }
            if !features_ok {
                device = device.clearing_features_ok();
            }
            let outcome = Offered::new(device)
                .acknowledge()
                .and_then(Acknowledged::negotiate_features)
                .and_then(|negotiated| negotiated.configure_queue(dma))
                .map(Configured::go_live);
            match outcome {
                Ok(live) => {
                    prop_assert!(offered & features::VIRTIO_F_VERSION_1 != 0);
                    prop_assert!(offered & features::VIRTIO_BLK_F_RO == 0);
                    prop_assert!(queues > BLK_QUEUE);
                    prop_assert_eq!(live.capacity_sectors(), capacity);
                    prop_assert!(capacity > 0);
                    live.ring();
                }
                Err(error) => {
                    prop_assert!(error.signalled_to_device());
                    prop_assert!(log.events().contains(&Event::Status(STATUS_FAILED)));
                }
            }
        }
    }
}
