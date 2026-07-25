//! Modern virtio 1.0 PCI transport for x86.
//!
//! Two mapped windows drive a virtio-pci device: its PCI **configuration
//! space** (reached here through the q35 ECAM/MMCONFIG window) and a memory
//! **BAR** holding the virtio structures. It walks the virtio PCI
//! capabilities, reprograms the BAR to an address the driver PD pre-mapped,
//! runs the device-init handshake, and programs a virtqueue ([`crate::queue`])
//! into the device's common configuration. It is written from scratch rather
//! than reusing `virtio-drivers`, whose rust-sel4 integration ships only an ARM
//! virtio-MMIO transport — there is no x86 PCI transport to reuse (CONCEPT §8).
//!
//! All device access is volatile MMIO. The transport holds raw pointers into
//! the two mapped windows; the driver PD establishes those mappings (static
//! `.system` capabilities) and upholds their validity.
//!
//! # The device is untrusted
//!
//! The adversary here is CONCEPT §7.1's **hostile or malfunctioning device**.
//! Every byte this module reads is the device's: its configuration-space
//! registers, its capability list, its BAR type bits, and — after the
//! handshake — its `queue_size` and `queue_notify_off` registers. A device that
//! is merely broken produces the same bytes as one that is malicious, so both
//! are handled the same way: **no device value reaches a pointer computation
//! before a check this module performs itself**, and every rejection is a typed
//! error rather than a panic, so bring-up fails visibly in the driver PD
//! instead of faulting it.
//!
//! Concretely, and in the order bring-up meets them:
//!
//! - **A capability's BAR index is range-checked where it is parsed.**
//!   [`record_bar`] rejects anything outside 0..=5, so no index that is not a
//!   BAR of this function can reach BAR programming.
//! - **Being a BAR is not enough to be a 64-bit BAR pair.**
//!   [`PciConfig::reprogram_bar64`] additionally rejects BAR 5, whose successor
//!   register is the CardBus-CIS pointer rather than the pair's high half, and
//!   [`PciConfig::bar_is_64bit`] refuses to answer for a non-BAR index instead
//!   of reading an unrelated register and reporting a meaningless answer.
//! - **The structure offsets are bounded against the window actually mapped**
//!   ([`VirtioCaps::within`]) before any structure is dereferenced.
//! - **The common-configuration offset is checked for alignment, not only for
//!   extent.** Its registers are reached as `u16` and `u32` volatile accesses,
//!   so an offset that fits the window perfectly still makes every one of them
//!   misaligned unless it is [`COMMON_CFG_ALIGN`]-aligned — undefined behaviour
//!   in the abstract machine and a split transaction on the wire, from a value
//!   the device simply advertises. [`VirtioCaps::common_is_aligned`] is the
//!   predicate; the shipped enforcer is `nic_driver_core::bringup::identify`,
//!   which runs it before anything that can construct a [`CommonCfg`] exists.
//! - **The handshake is bounded.** [`CommonCfg::reset`] polls a device-owned
//!   status byte a fixed number of times and gives up, rather than spinning
//!   until the device chooses to answer.
//! - **The device's queue maximum is checked, not trusted.**
//!   [`CommonCfg::setup_queue`] refuses to program a queue the device says does
//!   not exist, or one larger than the device admits to.
//! - **The doorbell slot is bounded by the callee that writes it.** The
//!   `queue_notify_off` register and the notify multiplier are both device
//!   data, and their product is unbounded relative to the mapped BAR;
//!   [`Doorbell::new`] is the one place that checks it, and the resulting
//!   [`Doorbell::ring`] needs no further check.
//!
//! What is **not** checked, because it is not checkable from this side: whether
//! the device honours anything it was programmed with. A device may ignore the
//! queue size it acknowledged, DMA outside the addresses it was given (nothing
//! but an IOMMU can stop that — CONCEPT §7.2, an open item), or never complete
//! a descriptor. The first two are outside this module's reach; the third is a
//! stall, visible to the driver as a queue that stops making progress.

use core::sync::atomic::{Ordering, fence};

use crate::queue::QueueLayout;

/// PCI vendor id for virtio devices.
pub const VIRTIO_VENDOR_ID: u16 = 0x1af4;
/// PCI device id of a modern (virtio 1.0) network device.
pub const VIRTIO_NET_DEVICE_ID: u16 = 0x1041;

// PCI configuration-space register offsets.
const PCI_VENDOR_ID: u16 = 0x00;
const PCI_DEVICE_ID: u16 = 0x02;
const PCI_COMMAND: u16 = 0x04;
const PCI_STATUS: u16 = 0x06;
const PCI_CAPABILITIES_PTR: u16 = 0x34;
const PCI_BAR0: u16 = 0x10;

/// Highest BAR index a PCI function has: BARs are 0..=5.
const PCI_LAST_BAR: u8 = 5;
/// Highest BAR index that can be the **low half** of a 64-bit BAR pair. BAR 5's
/// successor register is the CardBus-CIS pointer, not a BAR.
const PCI_LAST_BAR64_LOW_HALF: u8 = 4;

// PCI command-register bits.
const PCI_COMMAND_MEMORY: u16 = 1 << 1;
const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;
// PCI status-register bit: a capability list is present.
const PCI_STATUS_CAP_LIST: u16 = 1 << 4;

// Vendor-specific capability id; virtio config caps carry it.
const PCI_CAP_ID_VNDR: u8 = 0x09;

// virtio PCI capability `cfg_type` values.
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

// virtio device-status bits, written to the common-config `device_status`
// register to step the device through the initialization handshake (virtio 1.x
// §2.1). The driver ORs these in cumulatively; the device latches them.
/// The driver has noticed the device. First bit set in the handshake.
pub const STATUS_ACKNOWLEDGE: u8 = 1;
/// The driver knows how to drive this device type. Set together with
/// [`STATUS_ACKNOWLEDGE`] before feature negotiation begins.
pub const STATUS_DRIVER: u8 = 2;
/// The driver is set up and ready to drive the device. Set last, after the
/// virtqueues are configured, to bring the device live.
pub const STATUS_DRIVER_OK: u8 = 4;
/// The driver has written the feature bits it accepts. Set after
/// `set_driver_features`; if the device then clears it, the negotiated feature
/// set is unacceptable and initialization must not continue.
pub const STATUS_FEATURES_OK: u8 = 8;
/// The device signals an unrecoverable internal error, or the driver sets it to
/// give up on the device. Terminal: the device must be reset to recover.
///
/// The driver PD writes this on every bring-up rejection it can still reach the
/// device for — that is, once the BAR has been relocated and [`CommonCfg`]
/// exists. A rejection before that point (a malformed capability list, an
/// unusable BAR) cannot be signalled at all, because the register lives in the
/// BAR that has not yet been placed.
pub const STATUS_FAILED: u8 = 0x80;

/// Why a BAR operation refused the index it was given. Both variants mean the
/// *index* is wrong, which for an index that came from the device's own
/// capability list means the device is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarError {
    /// The index is not a BAR of this function: a PCI function has at most six
    /// (0..=5). Reading at the corresponding offset would land on an unrelated
    /// configuration register, so no answer is given and nothing is written.
    IndexOutOfRange(u8),
    /// The index names BAR 5, so the register that would hold the high half of
    /// a 64-bit BAR pair is the CardBus-CIS pointer instead. A device
    /// advertising a 64-bit BAR 5 is malformed; writing it would corrupt a
    /// non-BAR register.
    NoHighHalf(u8),
}

/// Access to one PCI function's 4 KiB configuration space, as mapped through
/// ECAM. Reads and writes are volatile.
pub struct PciConfig {
    base: *mut u8,
}

impl PciConfig {
    /// # Safety
    /// `function_base` must point to the mapped 4 KiB ECAM page of the target
    /// PCI function and stay valid for the lifetime of this value.
    #[must_use]
    pub unsafe fn new(function_base: *mut u8) -> Self {
        Self {
            base: function_base,
        }
    }

    /// # Safety
    /// `offset` must be less than 4096, so the byte lies within the
    /// configuration space [`PciConfig::new`]'s contract maps.
    unsafe fn read8(&self, offset: u16) -> u8 {
        // SAFETY: `offset < 4096` per this fn's contract, so the byte lies within the page `PciConfig::new` guarantees.
        unsafe { self.base.add(offset as usize).read_volatile() }
    }

    /// # Safety
    /// `offset` must be even and `offset + 2` must be at most 4096, so the
    /// whole 16-bit value lies within the mapped configuration space and is
    /// naturally aligned.
    unsafe fn read16(&self, offset: u16) -> u16 {
        // SAFETY: `offset` is even and `offset + 2 <= 4096` per this fn's contract, so the read is aligned and within the page `PciConfig::new` guarantees.
        unsafe { self.base.add(offset as usize).cast::<u16>().read_volatile() }
    }

    /// # Safety
    /// `offset` must be a multiple of 4 and `offset + 4` must be at most 4096,
    /// so the whole 32-bit value lies within the mapped configuration space and
    /// is naturally aligned.
    unsafe fn read32(&self, offset: u16) -> u32 {
        // SAFETY: `offset` is 4-aligned and `offset + 4 <= 4096` per this fn's contract, so the read is aligned and within the page `PciConfig::new` guarantees.
        unsafe { self.base.add(offset as usize).cast::<u32>().read_volatile() }
    }

    /// # Safety
    /// `offset` must be even and `offset + 2` must be at most 4096, so the
    /// whole 16-bit value lies within the mapped configuration space and is
    /// naturally aligned.
    unsafe fn write16(&self, offset: u16, value: u16) {
        // SAFETY: `offset` is even and `offset + 2 <= 4096` per this fn's contract, so the write is aligned and within the page `PciConfig::new` guarantees.
        unsafe {
            self.base
                .add(offset as usize)
                .cast::<u16>()
                .write_volatile(value)
        }
    }

    /// # Safety
    /// `offset` must be a multiple of 4 and `offset + 4` must be at most 4096,
    /// so the whole 32-bit value lies within the mapped configuration space and
    /// is naturally aligned.
    unsafe fn write32(&self, offset: u16, value: u32) {
        // SAFETY: `offset` is 4-aligned and `offset + 4 <= 4096` per this fn's contract, so the write is aligned and within the page `PciConfig::new` guarantees.
        unsafe {
            self.base
                .add(offset as usize)
                .cast::<u32>()
                .write_volatile(value)
        }
    }

    /// The device's (vendor, device) id pair.
    #[must_use]
    pub fn ids(&self) -> (u16, u16) {
        // SAFETY: both offsets are even, fixed constants below 4096 — `read16`'s contract.
        unsafe { (self.read16(PCI_VENDOR_ID), self.read16(PCI_DEVICE_ID)) }
    }

    /// Enable memory-space decoding and bus-master DMA for the device.
    ///
    /// This is also what re-enables decoding after
    /// [`reprogram_bar64`](Self::reprogram_bar64), which deliberately leaves it
    /// off.
    pub fn enable_memory_and_bus_master(&self) {
        // SAFETY: `PCI_COMMAND` is an even, fixed constant below 4096 — `read16`/`write16`'s contract.
        unsafe {
            let command = self.read16(PCI_COMMAND);
            self.write16(
                PCI_COMMAND,
                command | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
            );
        }
    }

    /// Disable memory-space decoding (before reprogramming a BAR).
    fn disable_memory(&self) {
        // SAFETY: `PCI_COMMAND` is an even, fixed constant below 4096 — `read16`/`write16`'s contract.
        unsafe {
            let command = self.read16(PCI_COMMAND);
            self.write16(PCI_COMMAND, command & !PCI_COMMAND_MEMORY);
        }
    }

    /// Configuration-space offset of BAR `bar_index`, for an index already
    /// range-checked against [`PCI_LAST_BAR`]. Returning the offset from the
    /// same place that owns the range check keeps the two from drifting apart.
    fn bar_offset(bar_index: u8) -> u16 {
        PCI_BAR0 + (bar_index as u16) * 4
    }

    /// Whether BAR `bar_index` is a 64-bit memory BAR (so its address spans
    /// this register and the next). The driver checks this before treating a
    /// BAR as a 64-bit pair, rather than trusting the device's layout.
    ///
    /// # Errors
    /// [`BarError::IndexOutOfRange`] when `bar_index` is not a BAR of this
    /// function (0..=5). The question is refused rather than answered from an
    /// unrelated configuration register, which would report a type for
    /// something that is not a BAR at all.
    pub fn bar_is_64bit(&self, bar_index: u8) -> Result<bool, BarError> {
        if bar_index > PCI_LAST_BAR {
            return Err(BarError::IndexOutOfRange(bar_index));
        }
        // SAFETY: `bar_index <= 5` was just checked, so the offset is at most
        // `0x10 + 5*4 = 0x24` — 4-aligned and far below 4096, which is
        // `read32`'s contract.
        let low = unsafe { self.read32(Self::bar_offset(bar_index)) };
        // Bit 0 == 0 => memory BAR; bits [2:1] == 0b10 => 64-bit.
        Ok(low & 0x1 == 0 && (low >> 1) & 0x3 == 0x2)
    }

    /// Point a 64-bit memory BAR at `address` (below 4 GiB). `bar_index` is the
    /// low half of the 64-bit BAR pair.
    ///
    /// # Side effect
    /// Memory-space decoding is switched **off** before the write and is *not*
    /// switched back on: a BAR must not be moved while the device decodes it,
    /// and the caller may have further BARs to place. Call
    /// [`enable_memory_and_bus_master`](Self::enable_memory_and_bus_master)
    /// once the BARs are final — until then the device decodes nothing. Bus
    /// mastering and I/O decoding are left as they were.
    ///
    /// # Errors
    /// [`BarError::IndexOutOfRange`] when `bar_index` is not a BAR at all, and
    /// [`BarError::NoHighHalf`] when it is BAR 5, whose successor register is
    /// the CardBus-CIS pointer. Both are rejected before decoding is disabled,
    /// so a refused call leaves the device exactly as it found it.
    pub fn reprogram_bar64(&self, bar_index: u8, address: u32) -> Result<(), BarError> {
        if bar_index > PCI_LAST_BAR {
            return Err(BarError::IndexOutOfRange(bar_index));
        }
        if bar_index > PCI_LAST_BAR64_LOW_HALF {
            return Err(BarError::NoHighHalf(bar_index));
        }
        let low = Self::bar_offset(bar_index);
        let high = low + 4;
        self.disable_memory();
        // SAFETY: `bar_index <= 4` was just checked, so `low` is at most
        // `0x10 + 4*4 = 0x20` and `high` at most `0x24` — both 4-aligned and far
        // below 4096, which is `write32`'s contract. The low bits the hardware
        // treats as read-only type flags are ignored on write, so writing the
        // aligned address is well defined.
        unsafe {
            self.write32(low, address);
            self.write32(high, 0);
        }
        Ok(())
    }
}

/// The locations of the virtio structures within the device's BAR, discovered
/// by walking the PCI capability list. All offsets are byte offsets into the
/// BAR named by [`bar`](Self::bar); this transport requires every structure to
/// live in the same BAR (true for QEMU's modern virtio-net-pci).
///
/// Every field is the **device's own claim**, checked only for what
/// [`find_virtio_caps`] can check on its own (a real BAR index, one BAR shared
/// by all the structures). The offsets are bounded against the window actually
/// mapped by [`within`](Self::within) and [`notify_slot_within`](Self::notify_slot_within),
/// and the common-configuration offset is additionally checked for alignment by
/// [`common_is_aligned`](Self::common_is_aligned) — all of which the caller must
/// run before dereferencing anything. Extent and alignment are independent
/// faults: an offset can fit the window and still be unusable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioCaps {
    /// Index of the BAR that holds every virtio structure below, always 0..=5
    /// because [`find_virtio_caps`] rejects any other. All the offsets are
    /// relative to the mapped base of this one BAR.
    pub bar: u8,
    /// Byte offset of the common configuration structure (device/driver status,
    /// feature negotiation, and per-queue setup registers) within the BAR.
    ///
    /// Two independent things must hold before this becomes a pointer: the
    /// structure must fit the mapped window ([`within`](Self::within)) and the
    /// offset must be [`COMMON_CFG_ALIGN`]-aligned
    /// ([`common_is_aligned`](Self::common_is_aligned)), because the registers
    /// behind it are `u16` and `u32` volatile accesses.
    pub common: u32,
    /// Byte offset of the notification structure within the BAR. A queue's
    /// doorbell sits at `notify + queue_notify_off * notify_multiplier`, which
    /// [`Doorbell::new`] bounds before writing.
    pub notify: u32,
    /// Multiplier that scales a queue's `notify_off` into a byte offset within
    /// the notification structure.
    pub notify_multiplier: u32,
    /// Byte offset of the device-specific configuration structure within the
    /// BAR (for virtio-net, the MAC address and status fields).
    ///
    /// Nothing in this workspace forms a pointer from this offset: the driver
    /// reads neither the MAC nor the device status, so [`within`](Self::within)
    /// bounds it against a one-byte extent and no alignment is required of it.
    /// Both of those are adequate only while that stays true — virtio-net's
    /// `status` field is a `u16`, so the first read of it needs a wider extent
    /// *and* the same alignment check [`common_is_aligned`](Self::common_is_aligned)
    /// performs, added here rather than assumed at the dereference.
    pub device: u32,
}

/// Byte extent of the virtio common configuration structure that this transport
/// accesses: through `queue_device` at offset 48 plus its eight bytes.
///
/// A caller establishing [`CommonCfg::new`]'s contract needs this number, which
/// is why it is public: it is the amount of mapped memory the accessors assume.
pub const COMMON_CFG_MIN_LEN: usize = 56;

/// Byte alignment the **base** of the common configuration structure must have
/// for [`CommonCfg`]'s accessors to be sound.
///
/// The widest access this transport makes into the structure is a `u32` — a
/// 64-bit register is written as two `u32` halves, following the virtio spec's
/// 64-bit access rules — and every field offset carries the base's alignment
/// through rather than adding to it (the const assertions beside the offsets
/// pin that). So the base's alignment *is* the accesses' alignment: a
/// 4-aligned base makes every one of them natural, and a base off by a byte
/// makes every wide one misaligned.
///
/// It is public for the same reason [`COMMON_CFG_MIN_LEN`] is: a caller
/// establishing [`CommonCfg::new`]'s contract has to know the number, and
/// [`VirtioCaps::common_is_aligned`] is what checks the device's claim against
/// it.
pub const COMMON_CFG_ALIGN: usize = 4;
/// Byte width of one notify doorbell: a single `u16` queue index.
const NOTIFY_SLOT_LEN: usize = 2;
/// Minimum byte extent the driver accesses in the device-specific
/// configuration structure.
const DEVICE_CFG_MIN_LEN: usize = 1;

// `notify_off * multiplier` is bounded by `u16::MAX * u32::MAX < 2^48`, so on a
// 64-bit `usize` the product cannot overflow. x86_64 is the only target
// (CONCEPT §3), and this assertion is what holds that reasoning to the code
// rather than to a comment.
const _: () = assert!(
    usize::BITS >= 64,
    "notify-slot arithmetic assumes a 64-bit usize"
);

/// Byte offset of a queue's notify slot within the notify structure:
/// `queue_notify_off * notify_multiplier`.
///
/// Both operands are device data and the result is bounded only by 2^48, which
/// is why this is an offset and not a location: it says nothing about whether
/// the slot is mapped. [`VirtioCaps::notify_slot_within`] answers that.
fn notify_offset_bytes(notify_off: u16, multiplier: u32) -> usize {
    // Cannot overflow: see the `usize::BITS` assertion above.
    (notify_off as usize) * (multiplier as usize)
}

impl VirtioCaps {
    /// Whether every structure this transport dereferences at a **fixed**
    /// offset fits within a BAR window of `bar_size` bytes, accounting for the
    /// extent the driver accesses in each: [`COMMON_CFG_MIN_LEN`] bytes of the
    /// common configuration, one doorbell at the notify structure's base, and
    /// one byte of the device-specific configuration.
    ///
    /// This deliberately does **not** cover a queue's doorbell, which is the
    /// one access whose offset is not fixed: it sits at
    /// `notify + queue_notify_off * notify_multiplier`, and `queue_notify_off`
    /// is not known until [`CommonCfg::setup_queue`] has run. Bounding the
    /// notify base proves only that *some* doorbell fits, never that a
    /// particular queue's does — [`notify_slot_within`](Self::notify_slot_within)
    /// is what proves that, and [`Doorbell::new`] is what enforces it.
    ///
    /// It also says nothing about **alignment**, which is a separate fault an
    /// extent check cannot see: a structure can fit the window exactly and
    /// still sit at an offset that makes every wide access into it misaligned.
    /// [`common_is_aligned`](Self::common_is_aligned) is what answers that for
    /// the common configuration, and a caller needs both.
    ///
    /// The offsets come from the (untrusted) device, so this must be checked
    /// against the window actually mapped before any structure is dereferenced.
    #[must_use]
    pub fn within(&self, bar_size: usize) -> bool {
        let fits = |offset: u32, needed: usize| {
            (offset as usize)
                .checked_add(needed)
                .is_some_and(|end| end <= bar_size)
        };
        fits(self.common, COMMON_CFG_MIN_LEN)
            && fits(self.notify, NOTIFY_SLOT_LEN)
            && fits(self.device, DEVICE_CFG_MIN_LEN)
    }

    /// Whether the common configuration structure's offset is
    /// [`COMMON_CFG_ALIGN`]-aligned, so that adding it to a BAR window that is
    /// itself at least that aligned yields a base [`CommonCfg`]'s accessors can
    /// use.
    ///
    /// This is the half [`within`](Self::within) cannot answer, and the two are
    /// independent: `common` is a raw `u32` lifted straight out of the device's
    /// capability list, and an odd value fits any window large enough for it
    /// while making every `u16` and `u32` access into the structure misaligned.
    /// That is undefined behaviour rather than a slow load, and it is exactly
    /// the fault [`NotifyError::SlotMisaligned`] answers for the notify slot —
    /// checked here for the same reason and against the same kind of adversary.
    ///
    /// A caller mapping the BAR at page granularity (as Microkit does) needs
    /// nothing further: `bar_base + common` is `COMMON_CFG_ALIGN`-aligned
    /// exactly when this returns true.
    #[must_use]
    pub fn common_is_aligned(&self) -> bool {
        (self.common as usize).is_multiple_of(COMMON_CFG_ALIGN)
    }

    /// Whether the doorbell of a queue whose `queue_notify_off` is `notify_off`
    /// lies wholly within a BAR window of `bar_size` bytes.
    ///
    /// `notify_off` is the device's own [`CommonCfg::setup_queue`] output and
    /// `notify_multiplier` its own capability datum, so their product is
    /// bounded only by 2^48 — far outside any mapped window. Every step is
    /// computed with checked arithmetic, so an offset that cannot be
    /// represented is rejected rather than wrapped into range.
    ///
    /// Fitting is necessary but not sufficient to make the doorbell usable: the
    /// offset must also be even, since the slot is written as a `u16`. That is
    /// [`Doorbell::new`]'s business, and `Doorbell::new` is what a caller should
    /// use rather than deciding from this predicate alone.
    #[must_use]
    pub fn notify_slot_within(&self, notify_off: u16, bar_size: usize) -> bool {
        self.notify_slot_end(notify_off)
            .is_some_and(|end| end <= bar_size)
    }

    /// One past the last byte of the queue's doorbell, relative to the BAR
    /// base, or `None` if that offset is not representable.
    fn notify_slot_end(&self, notify_off: u16) -> Option<usize> {
        (self.notify as usize)
            .checked_add(notify_offset_bytes(notify_off, self.notify_multiplier))?
            .checked_add(NOTIFY_SLOT_LEN)
    }
}

/// Walk the PCI capability list and locate the virtio configuration
/// structures. All four (common, notify, ISR, device) must be present and share
/// one BAR.
///
/// The ISR structure's presence is required — a modern virtio device exposes
/// one, and its capability participates in the shared-BAR check — but its
/// offset is not retained: this transport is busy-poll only and never reads the
/// ISR status register (README, *virtio-net driver*). It will be carried in
/// [`VirtioCaps`] when interrupt delivery lands and there is something to read
/// it for.
///
/// # Errors
/// A [`CapError`] if the device exposes no capability list, the chain is
/// malformed, a capability names an invalid BAR, the structures span multiple
/// BARs, or a required structure is absent.
pub fn find_virtio_caps(config: &PciConfig) -> Result<VirtioCaps, CapError> {
    // SAFETY: every offset read below is either a fixed, aligned constant
    // (`PCI_STATUS` at 6, `PCI_CAPABILITIES_PTR` at 0x34) or `pointer + k` where
    // `pointer <= 0xfc` (masked with `& 0xfc`, which also makes it 4-aligned)
    // and `k <= 16` — at most 268, well inside the 4 KiB page `PciConfig::new`
    // guarantees, and correctly aligned for each accessor's width.
    unsafe {
        if config.read16(PCI_STATUS) & PCI_STATUS_CAP_LIST == 0 {
            return Err(CapError::NoCapabilities);
        }
        let mut bar: Option<u8> = None;
        let mut common = None;
        let mut notify = None;
        let mut notify_multiplier = 0;
        let mut isr_present = false;
        let mut device = None;

        let mut pointer = (config.read8(PCI_CAPABILITIES_PTR) & 0xfc) as u16;
        let mut guard = 0;
        while pointer != 0 {
            guard += 1;
            if guard > 64 {
                return Err(CapError::Malformed);
            }
            let id = config.read8(pointer);
            let next = (config.read8(pointer + 1) & 0xfc) as u16;
            if id == PCI_CAP_ID_VNDR {
                let cap_len = config.read8(pointer + 2);
                let cfg_type = config.read8(pointer + 3);
                let cap_bar = config.read8(pointer + 4);
                let offset = config.read32(pointer + 8);
                if cap_len >= 16 {
                    // Only the four structures we actually map must share a BAR;
                    // other virtio caps (e.g. VIRTIO_PCI_CAP_PCI_CFG, type 5)
                    // legitimately reference a different BAR and are ignored.
                    match cfg_type {
                        VIRTIO_PCI_CAP_COMMON_CFG => {
                            record_bar(&mut bar, cap_bar)?;
                            common.get_or_insert(offset);
                        }
                        VIRTIO_PCI_CAP_ISR_CFG => {
                            record_bar(&mut bar, cap_bar)?;
                            isr_present = true;
                        }
                        VIRTIO_PCI_CAP_DEVICE_CFG => {
                            record_bar(&mut bar, cap_bar)?;
                            device.get_or_insert(offset);
                        }
                        VIRTIO_PCI_CAP_NOTIFY_CFG if cap_len >= 20 && notify.is_none() => {
                            record_bar(&mut bar, cap_bar)?;
                            notify = Some(offset);
                            notify_multiplier = config.read32(pointer + 16);
                        }
                        _ => {}
                    }
                }
            }
            pointer = next;
        }

        match (bar, common, notify, isr_present, device) {
            (Some(bar), Some(common), Some(notify), true, Some(device)) => Ok(VirtioCaps {
                bar,
                common,
                notify,
                notify_multiplier,
                device,
            }),
            _ => Err(CapError::MissingStructure),
        }
    }
}

/// Record the BAR index a used virtio structure lives in, rejecting a mix of
/// BARs across the structures the transport maps together.
fn record_bar(bar: &mut Option<u8>, cap_bar: u8) -> Result<(), CapError> {
    // A PCI function has at most six BARs (0..=5); a capability naming anything
    // else is a malformed, untrusted device descriptor and is rejected here,
    // before the index could ever reach BAR programming.
    if cap_bar > PCI_LAST_BAR {
        return Err(CapError::InvalidBar);
    }
    match *bar {
        Some(existing) if existing != cap_bar => Err(CapError::MultipleBars),
        _ => {
            *bar = Some(cap_bar);
            Ok(())
        }
    }
}

/// Why [`find_virtio_caps`] could not resolve the virtio structures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapError {
    /// The device advertises no PCI capability list.
    NoCapabilities,
    /// The capability chain is malformed (looped or out of range).
    Malformed,
    /// virtio structures are split across BARs (unsupported here).
    MultipleBars,
    /// A capability named a BAR index outside the valid range 0..=5.
    InvalidBar,
    /// A required structure (common, notify, ISR, or device) was absent.
    MissingStructure,
}

// virtio_pci_common_cfg field offsets (bytes into the common structure).
const CFG_DEVICE_FEATURE_SELECT: usize = 0;
const CFG_DEVICE_FEATURE: usize = 4;
const CFG_DRIVER_FEATURE_SELECT: usize = 8;
const CFG_DRIVER_FEATURE: usize = 12;
const CFG_NUM_QUEUES: usize = 18;
const CFG_DEVICE_STATUS: usize = 20;
const CFG_QUEUE_SELECT: usize = 22;
const CFG_QUEUE_SIZE: usize = 24;
const CFG_QUEUE_ENABLE: usize = 28;
const CFG_QUEUE_NOTIFY_OFF: usize = 30;
const CFG_QUEUE_DESC: usize = 32;
const CFG_QUEUE_DRIVER: usize = 40;
const CFG_QUEUE_DEVICE: usize = 48;

// Every offset above must lie inside the extent `CommonCfg::new` requires its
// caller to map, so the accessors' safety contracts are satisfied by the
// constructor's alone.
const _: () = assert!(CFG_QUEUE_DEVICE + 8 == COMMON_CFG_MIN_LEN);

// And every offset must carry the base's alignment through to the access made
// at it, or a `COMMON_CFG_ALIGN`-aligned base would not be enough to make the
// accessors sound and `VirtioCaps::common_is_aligned` would be checking the
// wrong thing. This is the compile-time half of every accessor's `SAFETY:`
// comment — the half about `off` — and it is asserted rather than described
// because the field offsets are a layout the virtio spec fixes and this file
// transcribes, so a transcription error is the failure mode to catch.
//
// `COMMON_CFG_ALIGN` must cover the widest access (a `u32`); the `u32`-wide
// registers, and both halves of each 64-bit one, must then be 4-aligned, and
// the `u16`-wide registers even. `r8`/`w8` need nothing.
const _: () = assert!(COMMON_CFG_ALIGN.is_multiple_of(align_of::<u32>()));
const _: () = assert!(CFG_DEVICE_FEATURE_SELECT.is_multiple_of(COMMON_CFG_ALIGN));
const _: () = assert!(CFG_DEVICE_FEATURE.is_multiple_of(COMMON_CFG_ALIGN));
const _: () = assert!(CFG_DRIVER_FEATURE_SELECT.is_multiple_of(COMMON_CFG_ALIGN));
const _: () = assert!(CFG_DRIVER_FEATURE.is_multiple_of(COMMON_CFG_ALIGN));
const _: () = assert!(CFG_QUEUE_DESC.is_multiple_of(COMMON_CFG_ALIGN));
const _: () = assert!(CFG_QUEUE_DRIVER.is_multiple_of(COMMON_CFG_ALIGN));
const _: () = assert!(CFG_QUEUE_DEVICE.is_multiple_of(COMMON_CFG_ALIGN));
const _: () = assert!(CFG_NUM_QUEUES.is_multiple_of(align_of::<u16>()));
const _: () = assert!(CFG_QUEUE_SELECT.is_multiple_of(align_of::<u16>()));
const _: () = assert!(CFG_QUEUE_SIZE.is_multiple_of(align_of::<u16>()));
const _: () = assert!(CFG_QUEUE_ENABLE.is_multiple_of(align_of::<u16>()));
const _: () = assert!(CFG_QUEUE_NOTIFY_OFF.is_multiple_of(align_of::<u16>()));
// The one byte-wide register needs no alignment, only the extent.
const _: () = assert!(CFG_DEVICE_STATUS < COMMON_CFG_MIN_LEN);

/// How many times [`CommonCfg::reset`] reads the device-status register back
/// before giving up.
///
/// This bounds **polls, not elapsed time**: a driver protection domain has no
/// timer capability, so there is no clock to bound a wait against, and the
/// only adversary-independent quantity available is the iteration count. What
/// it guarantees is therefore exactly what a caller may rely on — that `reset`
/// returns — and not that it returns within any particular interval.
const RESET_POLL_LIMIT: u32 = 1_000_000;

/// Why [`CommonCfg::reset`] gave up on the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetError {
    /// The device did not read back a zero `device_status` within
    /// [`RESET_POLL_LIMIT`] polls. The last value observed is carried so a
    /// caller can report which bits the device is holding.
    NotAcknowledged {
        /// The `device_status` byte read on the final poll.
        status: u8,
    },
}

/// Why [`CommonCfg::setup_queue`] refused to program a virtqueue. Both variants
/// are device faults at bring-up: the device's own `queue_size` register
/// contradicts what the driver must program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueSetupError {
    /// The device reports a maximum queue size of zero at this index, which
    /// means the queue does not exist.
    QueueAbsent {
        /// The virtqueue index selected.
        index: u16,
    },
    /// The device's maximum queue size is smaller than the layout the driver
    /// must program. Programming the driver's larger size would tell the device
    /// to read a ring past the end of the one it admits to.
    QueueTooSmall {
        /// The virtqueue index selected.
        index: u16,
        /// The maximum the device advertised.
        device_max: u16,
        /// The number of descriptors the layout requires.
        required: usize,
    },
}

/// The virtio common configuration structure, mapped in the device BAR.
pub struct CommonCfg {
    base: *mut u8,
}

impl CommonCfg {
    /// # Safety
    /// `base` must point to at least [`COMMON_CFG_MIN_LEN`] readable and
    /// writable bytes of the device's mapped `virtio_pci_common_cfg` (the BAR
    /// vaddr plus the common-cfg offset), they must stay valid for use, and
    /// `base` must be [`COMMON_CFG_ALIGN`]-aligned.
    ///
    /// Two requirements because there are two ways to get this wrong, and an
    /// extent check catches only one of them:
    ///
    /// - **Extent.** Every accessor reaches through `queue_device` at offset 48,
    ///   so the whole [`COMMON_CFG_MIN_LEN`] is required, not merely the
    ///   structure's base. A caller establishes it with [`VirtioCaps::within`],
    ///   which bounds `common + COMMON_CFG_MIN_LEN` against the size of the BAR
    ///   window it actually mapped.
    /// - **Alignment.** Every accessor casts `base + off` to a `u16` or a `u32`,
    ///   and the field offsets carry the base's alignment through rather than
    ///   supplying any of their own (const-asserted beside them), so **the
    ///   base's alignment is what makes those accesses aligned**. A caller
    ///   establishes it with [`VirtioCaps::common_is_aligned`] over a BAR window
    ///   that is itself at least [`COMMON_CFG_ALIGN`]-aligned — which a page
    ///   mapping is.
    ///
    /// Both halves are the device's claim, so neither may be assumed. The
    /// shipped enforcer of both is `nic_driver_core::bringup::identify`: it runs
    /// the two predicates before an `Identified` exists, and `PlacedBar` — the
    /// only thing that constructs this type outside tests — is reachable only
    /// from an `Identified`. Its
    /// `a_structure_outside_the_mapped_window_is_refused_before_any_dereference`
    /// and `a_misaligned_common_configuration_offset_is_refused_before_any_dereference`
    /// tests are what prove that enforcement rather than assert it (DOC-7).
    #[must_use]
    pub unsafe fn new(base: *mut u8) -> Self {
        Self { base }
    }

    /// # Safety
    /// `off` must be less than [`COMMON_CFG_MIN_LEN`].
    unsafe fn r8(&self, off: usize) -> u8 {
        // SAFETY: `off < COMMON_CFG_MIN_LEN` per this fn's contract, so the byte lies within the extent `CommonCfg::new` requires mapped; a one-byte access needs no alignment.
        unsafe { self.base.add(off).read_volatile() }
    }

    /// # Safety
    /// `off` must be less than [`COMMON_CFG_MIN_LEN`].
    unsafe fn w8(&self, off: usize, v: u8) {
        // SAFETY: `off < COMMON_CFG_MIN_LEN` per this fn's contract, so the byte lies within the extent `CommonCfg::new` requires mapped; a one-byte access needs no alignment.
        unsafe { self.base.add(off).write_volatile(v) }
    }

    /// # Safety
    /// `off` must be even and `off + 2` at most [`COMMON_CFG_MIN_LEN`], so the
    /// whole value is mapped and naturally aligned.
    unsafe fn r16(&self, off: usize) -> u16 {
        // SAFETY: `base` is `COMMON_CFG_ALIGN`-aligned per `CommonCfg::new`'s contract and `off` is even per this fn's, so `base + off` is two-byte aligned; `off + 2 <= COMMON_CFG_MIN_LEN` keeps it within the extent that same contract requires mapped.
        unsafe { self.base.add(off).cast::<u16>().read_volatile() }
    }

    /// # Safety
    /// `off` must be even and `off + 2` at most [`COMMON_CFG_MIN_LEN`], so the
    /// whole value is mapped and naturally aligned.
    unsafe fn w16(&self, off: usize, v: u16) {
        // SAFETY: `base` is `COMMON_CFG_ALIGN`-aligned per `CommonCfg::new`'s contract and `off` is even per this fn's, so `base + off` is two-byte aligned; `off + 2 <= COMMON_CFG_MIN_LEN` keeps it within the extent that same contract requires mapped.
        unsafe { self.base.add(off).cast::<u16>().write_volatile(v) }
    }

    /// # Safety
    /// `off` must be a multiple of 4 and `off + 4` at most
    /// [`COMMON_CFG_MIN_LEN`], so the whole value is mapped and naturally
    /// aligned.
    unsafe fn r32(&self, off: usize) -> u32 {
        // SAFETY: `base` is `COMMON_CFG_ALIGN`-aligned per `CommonCfg::new`'s contract and `off` is a multiple of it per this fn's, so `base + off` is 4-aligned; `off + 4 <= COMMON_CFG_MIN_LEN` keeps it within the extent that same contract requires mapped.
        unsafe { self.base.add(off).cast::<u32>().read_volatile() }
    }

    /// # Safety
    /// `off` must be a multiple of 4 and `off + 4` at most
    /// [`COMMON_CFG_MIN_LEN`], so the whole value is mapped and naturally
    /// aligned.
    unsafe fn w32(&self, off: usize, v: u32) {
        // SAFETY: `base` is `COMMON_CFG_ALIGN`-aligned per `CommonCfg::new`'s contract and `off` is a multiple of it per this fn's, so `base + off` is 4-aligned; `off + 4 <= COMMON_CFG_MIN_LEN` keeps it within the extent that same contract requires mapped.
        unsafe { self.base.add(off).cast::<u32>().write_volatile(v) }
    }

    /// # Safety
    /// `off` must be a multiple of 4 and `off + 8` at most
    /// [`COMMON_CFG_MIN_LEN`]: **both** four-byte halves — `off` and `off + 4`
    /// — are written, so the requirement covers eight bytes, not four.
    unsafe fn w64(&self, off: usize, v: u64) {
        // Written as two 32-bit halves, low first, matching the virtio spec's
        // 64-bit register access rules.
        // SAFETY: `base` is `COMMON_CFG_ALIGN`-aligned per `CommonCfg::new`'s contract and `off` is a multiple of it per this fn's, so `base + off` and `base + off + 4` are both 4-aligned; `off + 8 <= COMMON_CFG_MIN_LEN` keeps both halves within the extent that same contract requires mapped.
        unsafe {
            self.base.add(off).cast::<u32>().write_volatile(v as u32);
            self.base
                .add(off + 4)
                .cast::<u32>()
                .write_volatile((v >> 32) as u32);
        }
    }

    /// Current device-status byte.
    #[must_use]
    pub fn status(&self) -> u8 {
        // SAFETY: `CFG_DEVICE_STATUS` is 20, below `COMMON_CFG_MIN_LEN` — `r8`'s contract.
        unsafe { self.r8(CFG_DEVICE_STATUS) }
    }

    /// Overwrite the device-status byte.
    pub fn set_status(&self, value: u8) {
        // SAFETY: `CFG_DEVICE_STATUS` is 20, below `COMMON_CFG_MIN_LEN` — `w8`'s contract.
        unsafe { self.w8(CFG_DEVICE_STATUS, value) }
    }

    /// Reset the device and poll until it acknowledges by reading back a zero
    /// `device_status`.
    ///
    /// # Errors
    /// [`ResetError::NotAcknowledged`] once [`RESET_POLL_LIMIT`] polls have
    /// passed without the device answering. A device that never acknowledges is
    /// a hardware or deployment fault, and this is where it becomes visible:
    /// the alternative is a driver protection domain spinning for as long as
    /// the device cares to withhold the answer.
    pub fn reset(&self) -> Result<(), ResetError> {
        self.set_status(0);
        poll_status_cleared(|| self.status())
    }

    /// Number of virtqueues the device offers.
    #[must_use]
    pub fn num_queues(&self) -> u16 {
        // SAFETY: `CFG_NUM_QUEUES` is 18 — even, and `18 + 2 <= COMMON_CFG_MIN_LEN` — `r16`'s contract.
        unsafe { self.r16(CFG_NUM_QUEUES) }
    }

    /// Read the device's 64-bit feature bitmap across both selector windows.
    #[must_use]
    pub fn device_features(&self) -> u64 {
        // SAFETY: `CFG_DEVICE_FEATURE_SELECT` (0) and `CFG_DEVICE_FEATURE` (4) are 4-aligned, and each plus 4 is at most `COMMON_CFG_MIN_LEN` — `r32`/`w32`'s contract.
        unsafe {
            self.w32(CFG_DEVICE_FEATURE_SELECT, 0);
            let low = self.r32(CFG_DEVICE_FEATURE) as u64;
            self.w32(CFG_DEVICE_FEATURE_SELECT, 1);
            let high = self.r32(CFG_DEVICE_FEATURE) as u64;
            low | (high << 32)
        }
    }

    /// Write the negotiated 64-bit feature bitmap across both selector windows.
    pub fn set_driver_features(&self, features: u64) {
        // SAFETY: `CFG_DRIVER_FEATURE_SELECT` (8) and `CFG_DRIVER_FEATURE` (12) are 4-aligned, and each plus 4 is at most `COMMON_CFG_MIN_LEN` — `w32`'s contract.
        unsafe {
            self.w32(CFG_DRIVER_FEATURE_SELECT, 0);
            self.w32(CFG_DRIVER_FEATURE, features as u32);
            self.w32(CFG_DRIVER_FEATURE_SELECT, 1);
            self.w32(CFG_DRIVER_FEATURE, (features >> 32) as u32);
        }
    }

    /// Program one virtqueue's descriptor/driver/device area physical
    /// addresses and enable it. The three areas are placed contiguously per
    /// [`QueueLayout`] at `ring_paddr`.
    ///
    /// # Returns
    /// The device's `queue_notify_off` for this queue — **raw device output**,
    /// read straight out of a register the device controls, and bounded by
    /// nothing but its width. Multiplied by `notify_multiplier` it reaches 2^48,
    /// so it must never be turned into a doorbell address without a bounds
    /// check against the BAR window actually mapped. [`Doorbell::new`] performs
    /// that check and is the only supported way to reach a doorbell from this
    /// value; it is proved by the `doorbell_rejects_a_slot_outside_the_bar` and
    /// `notify_slot_bound_is_computable_and_exact` tests in this module.
    ///
    /// # Errors
    /// [`QueueSetupError`] when the device's own `queue_size` register says the
    /// queue does not exist or is smaller than `layout` requires. Nothing is
    /// programmed in either case: the queue is left disabled, so a caller that
    /// gives up leaves the device with no ring addresses it could act on.
    pub fn setup_queue(
        &self,
        index: u16,
        layout: &QueueLayout,
        ring_paddr: u64,
    ) -> Result<u16, QueueSetupError> {
        // SAFETY: `CFG_QUEUE_SELECT` (22) and `CFG_QUEUE_SIZE` (24) are even and
        // each plus 2 is at most `COMMON_CFG_MIN_LEN` — `w16`/`r16`'s contract.
        let device_max = unsafe {
            self.w16(CFG_QUEUE_SELECT, index);
            // The device initialises queue_size to its maximum for this queue.
            self.r16(CFG_QUEUE_SIZE)
        };
        if device_max == 0 {
            return Err(QueueSetupError::QueueAbsent { index });
        }
        // A layout wider than a `u16` cannot be programmed into a `u16`
        // register at all, which is the same refusal as a device maximum below
        // it — and doing the comparison after the conversion keeps every
        // arithmetic step below in one width.
        let too_small = |device_max| QueueSetupError::QueueTooSmall {
            index,
            device_max,
            required: layout.size,
        };
        let Ok(required) = u16::try_from(layout.size) else {
            return Err(too_small(device_max));
        };
        if device_max < required {
            return Err(too_small(device_max));
        }

        // `ring_paddr` and the layout offsets are the driver's own — the DMA
        // region's physical address patched from `librefirewall.system` and
        // `QueueLayout`'s offsets within it — so these sums are internal
        // invariants, not device input, and an overflow here would be a
        // build-time misconfiguration that must fail visibly.
        // SAFETY: every offset written below is 4-aligned (`CFG_QUEUE_DESC` 32,
        // `CFG_QUEUE_DRIVER` 40, `CFG_QUEUE_DEVICE` 48) or even
        // (`CFG_QUEUE_SIZE` 24, `CFG_QUEUE_ENABLE` 28, `CFG_QUEUE_NOTIFY_OFF`
        // 30), and each plus its width is at most `COMMON_CFG_MIN_LEN` — the
        // `CFG_QUEUE_DEVICE + 8 == COMMON_CFG_MIN_LEN` assertion above pins the
        // largest of them. The write order (size, addresses, enable) follows the
        // virtio spec.
        unsafe {
            self.w16(CFG_QUEUE_SIZE, required);
            self.w64(CFG_QUEUE_DESC, ring_paddr + layout.descriptor_offset as u64);
            self.w64(CFG_QUEUE_DRIVER, ring_paddr + layout.driver_offset as u64);
            self.w64(CFG_QUEUE_DEVICE, ring_paddr + layout.device_offset as u64);
            self.w16(CFG_QUEUE_ENABLE, 1);
            Ok(self.r16(CFG_QUEUE_NOTIFY_OFF))
        }
    }
}

/// Read `status` until it reads back zero, at most [`RESET_POLL_LIMIT`] times.
///
/// Split out of [`CommonCfg::reset`] because the give-up path is otherwise not
/// host-testable: a `CommonCfg` over plain memory reads back the very zero
/// `reset` just wrote, so the device that *never* acknowledges — the one that
/// used to hang the driver protection domain — cannot be modelled through the
/// MMIO accessors at all. Here it is a closure, and the bound is proved against
/// it directly.
fn poll_status_cleared(mut status: impl FnMut() -> u8) -> Result<(), ResetError> {
    for _ in 0..RESET_POLL_LIMIT {
        if status() == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(ResetError::NotAcknowledged { status: status() })
}

/// Why a [`Doorbell`] could not be placed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyError {
    /// The queue's doorbell does not lie within the mapped BAR window. Its
    /// offset is `notify + queue_notify_off * notify_multiplier`, all three of
    /// them device data, so this is a malformed device rather than a driver
    /// error. `slot_end` is `None` when the offset is not even representable.
    SlotOutsideBar {
        /// One past the doorbell's last byte, relative to the BAR base, or
        /// `None` when that offset overflows.
        slot_end: Option<usize>,
        /// The size of the BAR window the driver mapped.
        bar_size: usize,
    },
    /// The doorbell's offset within the BAR is odd, so the `u16` write would be
    /// unaligned — undefined behaviour, not merely a slow access.
    ///
    /// Nothing this driver can enforce makes the offset even: `notify` and
    /// `notify_multiplier` come from the device's capability and
    /// `queue_notify_off` from its `setup_queue` register, so a device that
    /// names an odd product gets an unaligned volatile write unless it is
    /// refused here.
    SlotMisaligned {
        /// The doorbell's offset relative to the BAR base.
        offset: usize,
    },
}

/// One virtqueue's doorbell: a validated pointer to the `u16` slot whose write
/// tells the device to look at that queue.
///
/// This type exists so the bound is checked **once, where it can fail**, rather
/// than on every ring in the poll loop or — as it was — nowhere at all. Placing
/// the doorbell is fallible because its offset is device data; ringing it is
/// then infallible and safe, because the only value that varies afterwards is
/// the queue index being written, which is the driver's own.
#[derive(Debug)]
pub struct Doorbell {
    slot: *mut u16,
}

impl Doorbell {
    /// Place the doorbell of the queue whose `queue_notify_off` is `notify_off`
    /// within a BAR window of `bar_size` bytes starting at `bar_base`.
    ///
    /// # Errors
    /// [`NotifyError::SlotOutsideBar`] when the doorbell would not lie wholly
    /// within the window — including when its offset is not representable at
    /// all — and [`NotifyError::SlotMisaligned`] when that offset is odd.
    /// Together these are the whole notify path's guarantee: `notify_off` and
    /// `notify_multiplier` are both device data, their product reaches 2^48 and
    /// need not be even, so without these two checks a conforming caller still
    /// gets an out-of-bounds or unaligned volatile write.
    ///
    /// # Safety
    /// `bar_base` must point to a mapped window of at least `bar_size` bytes —
    /// the device's BAR as the driver relocated and mapped it — it must be at
    /// least two-byte aligned (any BAR mapping is page-aligned, so this is
    /// free), and the window must stay valid for the lifetime of the returned
    /// value. Nothing else is required of the caller: the device-supplied
    /// offsets are bounded and aligned here, not by the caller.
    pub unsafe fn new(
        bar_base: *mut u8,
        bar_size: usize,
        caps: &VirtioCaps,
        notify_off: u16,
    ) -> Result<Self, NotifyError> {
        let slot_end = caps.notify_slot_end(notify_off);
        if slot_end.is_none_or(|end| end > bar_size) {
            return Err(NotifyError::SlotOutsideBar { slot_end, bar_size });
        }
        // `slot_end <= bar_size` was just checked and `slot_end` is the offset
        // plus the slot's own two bytes, so the offset itself is at most
        // `bar_size - 2` and this addition cannot overflow.
        let offset = caps.notify as usize + notify_offset_bytes(notify_off, caps.notify_multiplier);
        if !offset.is_multiple_of(2) {
            return Err(NotifyError::SlotMisaligned { offset });
        }
        // SAFETY: `offset + 2 <= bar_size` and `bar_base` names a mapped window
        // of at least `bar_size` bytes per this fn's contract, so the whole slot
        // lies within it; `offset` is even and `bar_base` is two-byte aligned by
        // the same contract, so the `u16` pointer is naturally aligned. Both
        // conditions were checked immediately above.
        let slot = unsafe { bar_base.add(offset).cast::<u16>() };
        Ok(Self { slot })
    }

    /// Ring the doorbell for `queue`, telling the device to examine that
    /// virtqueue.
    ///
    /// Safe and infallible: [`new`](Self::new) established that the slot lies
    /// within the mapped BAR, and nothing since can have moved it.
    pub fn ring(&self, queue: u16) {
        // Ensure prior descriptor/avail publication is visible before the
        // doorbell, which is what licenses the device to read them.
        fence(Ordering::Release);
        // SAFETY: `Doorbell::new` bounded this slot inside the mapped BAR window
        // its caller vouched for, and a `Doorbell` cannot be constructed any
        // other way.
        unsafe { self.slot.write_volatile(queue) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A 4 KiB buffer with the alignment a mapped ECAM page has.
    ///
    /// `[u8; 4096]` has `align_of == 1`, so a fixture handing one to
    /// `PciConfig::new` or `CommonCfg::new` would be under-delivering on the
    /// contract it is testing against and manufacturing its own misalignment —
    /// which it could then not tell apart from the device's, the very
    /// confusion `VirtioCaps::common_is_aligned` exists to remove. A real
    /// mapping is page-aligned, so the fixture is too.
    #[repr(C, align(4096))]
    struct AlignedPage([u8; 4096]);

    impl core::ops::Deref for AlignedPage {
        type Target = [u8; 4096];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl core::ops::DerefMut for AlignedPage {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    // A synthetic 4 KiB config space with a virtio capability chain, used to
    // test the pure capability-walk logic without a device.
    struct FakeConfig {
        bytes: Box<AlignedPage>,
    }

    impl FakeConfig {
        fn new() -> Self {
            Self {
                bytes: Box::new(AlignedPage([0u8; 4096])),
            }
        }
        fn w8(&mut self, off: usize, v: u8) {
            self.bytes[off] = v;
        }
        fn w16(&mut self, off: usize, v: u16) {
            self.bytes[off..off + 2].copy_from_slice(&v.to_le_bytes());
        }
        fn w32(&mut self, off: usize, v: u32) {
            self.bytes[off..off + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn r8(&self, off: usize) -> u8 {
            self.bytes[off]
        }
        fn r16(&self, off: usize) -> u16 {
            u16::from_le_bytes(self.bytes[off..off + 2].try_into().unwrap())
        }
        fn r32(&self, off: usize) -> u32 {
            u32::from_le_bytes(self.bytes[off..off + 4].try_into().unwrap())
        }
        fn r64(&self, off: usize) -> u64 {
            u64::from_le_bytes(self.bytes[off..off + 8].try_into().unwrap())
        }
        fn config(&mut self) -> PciConfig {
            // SAFETY: `self.bytes` is a live, page-aligned, config-space-sized buffer owned by this test — `PciConfig::new`'s contract over plain memory.
            unsafe { PciConfig::new(self.bytes.as_mut_ptr()) }
        }
        // A `CommonCfg` mapped over this buffer's base, so its register methods
        // can be driven against plain backing memory the test seeds and reads
        // back — the same pointer-into-a-Box pattern the queue tests use.
        fn common(&mut self) -> CommonCfg {
            // SAFETY: `self.bytes` is 4096 bytes, far more than `COMMON_CFG_MIN_LEN`, is page-aligned (so `COMMON_CFG_ALIGN`-aligned) as an `AlignedPage`, and outlives the value — `CommonCfg::new`'s contract in both halves.
            unsafe { CommonCfg::new(self.bytes.as_mut_ptr()) }
        }
        // Write a virtio cap at `at`, chaining to `next`.
        fn put_cap(&mut self, at: usize, next: u8, cfg_type: u8, bar: u8, offset: u32, len: u8) {
            self.bytes[at] = PCI_CAP_ID_VNDR;
            self.bytes[at + 1] = next;
            self.bytes[at + 2] = len;
            self.bytes[at + 3] = cfg_type;
            self.bytes[at + 4] = bar;
            self.w32(at + 8, offset);
        }
        // The full four-structure chain every valid-device case needs, in BAR
        // `bar` with notify multiplier 4.
        fn put_full_chain(&mut self, bar: u8) {
            self.w16(PCI_STATUS as usize, PCI_STATUS_CAP_LIST);
            self.bytes[PCI_CAPABILITIES_PTR as usize] = 0x40;
            self.put_cap(0x40, 0x50, VIRTIO_PCI_CAP_COMMON_CFG, bar, 0x0000, 16);
            self.put_cap(0x50, 0x64, VIRTIO_PCI_CAP_NOTIFY_CFG, bar, 0x3000, 20);
            self.w32(0x50 + 16, 4);
            self.put_cap(0x64, 0x74, VIRTIO_PCI_CAP_ISR_CFG, bar, 0x1000, 16);
            self.put_cap(0x74, 0x00, VIRTIO_PCI_CAP_DEVICE_CFG, bar, 0x2000, 16);
        }
    }

    /// A layout the queue-setup cases share: 16 descriptors, matching
    /// `SplitVirtqueue::<16>::LAYOUT`.
    fn layout16() -> QueueLayout {
        QueueLayout {
            size: 16,
            descriptor_offset: 0,
            driver_offset: 256,
            device_offset: 296,
            total_bytes: 430,
        }
    }

    #[test]
    fn finds_all_virtio_structures_in_one_bar() {
        let mut fake = FakeConfig::new();
        fake.w16(PCI_VENDOR_ID as usize, VIRTIO_VENDOR_ID);
        fake.w16(PCI_DEVICE_ID as usize, VIRTIO_NET_DEVICE_ID);
        // common @0x40 -> notify @0x50 -> isr @0x64 -> device @0x74 -> end
        fake.put_full_chain(4);

        let caps = find_virtio_caps(&fake.config()).unwrap();
        assert_eq!(
            caps,
            VirtioCaps {
                bar: 4,
                common: 0x0000,
                notify: 0x3000,
                notify_multiplier: 4,
                device: 0x2000,
            }
        );
    }

    #[test]
    fn reads_the_vendor_and_device_id_pair() {
        // The pair the driver PD pins its device on, and the first device data
        // it ever reads. A swapped offset would report the ids reversed, which
        // an all-zero or all-ones config space could not distinguish.
        let mut fake = FakeConfig::new();
        fake.w16(PCI_VENDOR_ID as usize, VIRTIO_VENDOR_ID);
        fake.w16(PCI_DEVICE_ID as usize, VIRTIO_NET_DEVICE_ID);
        assert_eq!(
            fake.config().ids(),
            (VIRTIO_VENDOR_ID, VIRTIO_NET_DEVICE_ID)
        );
    }

    #[test]
    fn rejects_a_device_without_capabilities() {
        let mut fake = FakeConfig::new();
        // status has no cap-list bit
        assert_eq!(
            find_virtio_caps(&fake.config()),
            Err(CapError::NoCapabilities)
        );
    }

    #[test]
    fn rejects_structures_split_across_bars() {
        let mut fake = FakeConfig::new();
        fake.w16(PCI_STATUS as usize, PCI_STATUS_CAP_LIST);
        fake.bytes[PCI_CAPABILITIES_PTR as usize] = 0x40;
        fake.put_cap(0x40, 0x50, VIRTIO_PCI_CAP_COMMON_CFG, 4, 0, 16);
        fake.put_cap(0x50, 0x00, VIRTIO_PCI_CAP_NOTIFY_CFG, 2, 0x3000, 20);
        assert_eq!(
            find_virtio_caps(&fake.config()),
            Err(CapError::MultipleBars)
        );
    }

    #[test]
    fn notify_offset_applies_the_multiplier() {
        assert_eq!(notify_offset_bytes(3, 4), 12);
        assert_eq!(notify_offset_bytes(0, 4), 0);
        // The widest product the device can name, which must not overflow.
        assert_eq!(
            notify_offset_bytes(u16::MAX, u32::MAX),
            65535 * 4_294_967_295usize
        );
    }

    #[test]
    fn caps_within_bounds_every_fixed_offset_structure() {
        let caps = VirtioCaps {
            bar: 4,
            common: 0,
            notify: 0x3000,
            notify_multiplier: 4,
            device: 0x2000,
        };
        assert!(caps.within(0x4000));
        // notify at 0x3000 leaves no room for its doorbell in a 0x3000 window.
        assert!(!caps.within(0x3000));
    }

    #[test]
    fn caps_within_rejects_a_structure_that_would_overrun_the_window() {
        // The common structure needs COMMON_CFG_MIN_LEN bytes; starting it 32
        // bytes below the window end must be rejected even though its start
        // offset is in range.
        let caps = VirtioCaps {
            bar: 4,
            common: 0x4000 - 32,
            notify: 0,
            notify_multiplier: 4,
            device: 0,
        };
        assert!(!caps.within(0x4000));
    }

    #[test]
    fn caps_common_alignment_is_independent_of_the_extent_check() {
        // Regression for the fuzz finding reproduced by
        // `fuzz/corpus/find_virtio_caps/unaligned_common_cfg_offset`: the
        // device advertised a common-configuration offset of 9, which fits any
        // reasonable window and so passed `within`, and the misaligned `u32`
        // volatile write in `device_features` followed. The two predicates
        // answer different questions and neither implies the other.
        let misaligned = VirtioCaps {
            bar: 4,
            common: 9,
            notify: 0x3000,
            notify_multiplier: 4,
            device: 0x2000,
        };
        assert!(
            misaligned.within(0x4000),
            "the offset fits — which is precisely why an extent check misses it"
        );
        assert!(!misaligned.common_is_aligned());

        // And the converse: an aligned offset that does not fit is still
        // refused, by the other predicate.
        let aligned_but_outside = VirtioCaps {
            common: 0x4000,
            ..misaligned
        };
        assert!(aligned_but_outside.common_is_aligned());
        assert!(!aligned_but_outside.within(0x4000));
    }

    #[test]
    fn caps_common_alignment_admits_exactly_the_multiples_of_the_required_align() {
        // Every residue class at the boundary, so the predicate is pinned to
        // `COMMON_CFG_ALIGN` rather than to "even" — a two-byte-aligned offset
        // still misaligns the `u32` registers, which are the majority.
        for offset in 0u32..=16 {
            let caps = VirtioCaps {
                bar: 0,
                common: offset,
                notify: 0,
                notify_multiplier: 0,
                device: 0,
            };
            assert_eq!(
                caps.common_is_aligned(),
                offset % 4 == 0,
                "offset {offset} was judged wrongly"
            );
        }
    }

    #[test]
    fn a_misaligned_common_offset_survives_the_capability_walk_and_is_caught_by_the_predicate() {
        // The walk's job is to find the structures, not to judge their offsets:
        // it reports what the device claimed. This pins where the boundary
        // actually is, so a later reader does not assume `find_virtio_caps`
        // filtered the offset it did not.
        let mut fake = FakeConfig::new();
        fake.put_full_chain(4);
        fake.w32(0x40 + 8, 0x0009);
        let caps = find_virtio_caps(&fake.config()).expect("the chain is well formed");
        assert_eq!(caps.common, 0x0009);
        assert!(!caps.common_is_aligned());
    }

    #[test]
    fn every_common_cfg_register_stays_aligned_over_an_aligned_base() {
        // The run-time half of the const assertions beside the field offsets,
        // and what makes each accessor's `SAFETY:` comment true: given a base
        // the constructor's contract requires, every register this transport
        // touches is naturally aligned for the width it is touched at. A
        // transcribed offset that broke this would make the accessor comments
        // false while every existing test still passed.
        let mut fake = FakeConfig::new();
        let base = fake.bytes.as_mut_ptr() as usize;
        assert!(base.is_multiple_of(COMMON_CFG_ALIGN), "the fixture's base");
        for off in [
            CFG_DEVICE_FEATURE_SELECT,
            CFG_DEVICE_FEATURE,
            CFG_DRIVER_FEATURE_SELECT,
            CFG_DRIVER_FEATURE,
            CFG_QUEUE_DESC,
            CFG_QUEUE_DRIVER,
            CFG_QUEUE_DEVICE,
            CFG_QUEUE_DEVICE + 4,
        ] {
            assert!(
                (base + off).is_multiple_of(align_of::<u32>()),
                "the 32-bit register at {off} is misaligned"
            );
            assert!(off + 4 <= COMMON_CFG_MIN_LEN);
        }
        for off in [
            CFG_NUM_QUEUES,
            CFG_QUEUE_SELECT,
            CFG_QUEUE_SIZE,
            CFG_QUEUE_ENABLE,
            CFG_QUEUE_NOTIFY_OFF,
        ] {
            assert!(
                (base + off).is_multiple_of(align_of::<u16>()),
                "the 16-bit register at {off} is misaligned"
            );
            assert!(off + 2 <= COMMON_CFG_MIN_LEN);
        }
    }

    #[test]
    fn rejects_missing_required_structures() {
        let mut fake = FakeConfig::new();
        fake.w16(PCI_STATUS as usize, PCI_STATUS_CAP_LIST);
        fake.bytes[PCI_CAPABILITIES_PTR as usize] = 0x40;
        // Only common and notify are present; ISR and device are absent.
        fake.put_cap(0x40, 0x50, VIRTIO_PCI_CAP_COMMON_CFG, 4, 0, 16);
        fake.put_cap(0x50, 0x00, VIRTIO_PCI_CAP_NOTIFY_CFG, 4, 0x3000, 20);
        fake.w32(0x50 + 16, 4);
        assert_eq!(
            find_virtio_caps(&fake.config()),
            Err(CapError::MissingStructure)
        );
    }

    #[test]
    fn rejects_a_device_without_an_isr_structure() {
        // The ISR offset is not retained, but a device that does not expose the
        // structure at all is still non-conforming and must be refused — the
        // presence check is what makes the shared-BAR rule cover it too.
        let mut fake = FakeConfig::new();
        fake.w16(PCI_STATUS as usize, PCI_STATUS_CAP_LIST);
        fake.bytes[PCI_CAPABILITIES_PTR as usize] = 0x40;
        fake.put_cap(0x40, 0x50, VIRTIO_PCI_CAP_COMMON_CFG, 4, 0, 16);
        fake.put_cap(0x50, 0x64, VIRTIO_PCI_CAP_NOTIFY_CFG, 4, 0x3000, 20);
        fake.w32(0x50 + 16, 4);
        fake.put_cap(0x64, 0x00, VIRTIO_PCI_CAP_DEVICE_CFG, 4, 0x2000, 16);
        assert_eq!(
            find_virtio_caps(&fake.config()),
            Err(CapError::MissingStructure)
        );
    }

    #[test]
    fn rejects_a_looping_capability_chain() {
        let mut fake = FakeConfig::new();
        fake.w16(PCI_STATUS as usize, PCI_STATUS_CAP_LIST);
        fake.bytes[PCI_CAPABILITIES_PTR as usize] = 0x40;
        // A -> B -> A never terminates; the iteration guard must trip.
        fake.put_cap(0x40, 0x50, VIRTIO_PCI_CAP_COMMON_CFG, 4, 0, 16);
        fake.put_cap(0x50, 0x40, VIRTIO_PCI_CAP_ISR_CFG, 4, 0x1000, 16);
        assert_eq!(find_virtio_caps(&fake.config()), Err(CapError::Malformed));
    }

    #[test]
    fn rejects_a_capability_naming_an_invalid_bar() {
        let mut fake = FakeConfig::new();
        fake.w16(PCI_STATUS as usize, PCI_STATUS_CAP_LIST);
        fake.bytes[PCI_CAPABILITIES_PTR as usize] = 0x40;
        // BAR 6 is outside the valid 0..=5 range.
        fake.put_cap(0x40, 0x00, VIRTIO_PCI_CAP_COMMON_CFG, 6, 0, 16);
        assert_eq!(find_virtio_caps(&fake.config()), Err(CapError::InvalidBar));
    }

    #[test]
    fn a_capability_naming_bar5_is_refused_at_bar_relocation() {
        // BAR 5 is a real BAR, so the capability walk accepts it — but it can
        // never be the low half of a 64-bit pair, because the register after it
        // is the CardBus-CIS pointer. This is the full device-driven path that
        // used to end in a panic: caps -> caps.bar == 5 -> reprogram_bar64(5).
        let mut fake = FakeConfig::new();
        fake.put_full_chain(5);
        let caps = find_virtio_caps(&fake.config()).unwrap();
        assert_eq!(caps.bar, 5);

        // Memory decoding is on going in; a refused relocation must leave both
        // it and the CardBus-CIS pointer untouched.
        fake.w16(
            PCI_COMMAND as usize,
            PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
        );
        let cis_before = fake.r32(PCI_BAR0 as usize + 6 * 4);
        assert_eq!(
            fake.config().reprogram_bar64(caps.bar, 0x5000_0000),
            Err(BarError::NoHighHalf(5))
        );
        assert_eq!(fake.r32(PCI_BAR0 as usize + 6 * 4), cis_before);
        assert_eq!(fake.r32(PCI_BAR0 as usize + 5 * 4), 0);
        assert_eq!(
            fake.r16(PCI_COMMAND as usize),
            PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER
        );
    }

    #[test]
    fn bar_operations_refuse_an_index_that_is_not_a_bar() {
        let mut fake = FakeConfig::new();
        // 6 is one past the last BAR; reading there would answer from the
        // CardBus-CIS pointer, and writing there would corrupt it.
        assert_eq!(
            fake.config().bar_is_64bit(6),
            Err(BarError::IndexOutOfRange(6))
        );
        assert_eq!(
            fake.config().bar_is_64bit(u8::MAX),
            Err(BarError::IndexOutOfRange(u8::MAX))
        );
        assert_eq!(
            fake.config().reprogram_bar64(6, 0x5000_0000),
            Err(BarError::IndexOutOfRange(6))
        );
        // Nothing was written anywhere in the header.
        assert_eq!(fake.r32(PCI_BAR0 as usize + 6 * 4), 0);
        assert_eq!(fake.r16(PCI_COMMAND as usize), 0);
    }

    #[test]
    fn bar_type_detects_64bit_memory_bars() {
        let mut fake = FakeConfig::new();
        // BAR4: memory (bit0=0), 64-bit (bits[2:1]=0b10), prefetchable (bit3).
        fake.w32(PCI_BAR0 as usize + 4 * 4, 0x0000_000c);
        // BAR2: 32-bit memory BAR.
        fake.w32(PCI_BAR0 as usize + 2 * 4, 0x0000_0000);
        let config = fake.config();
        assert_eq!(config.bar_is_64bit(4), Ok(true));
        assert_eq!(config.bar_is_64bit(2), Ok(false));
        // The last valid index is answered, not refused.
        assert_eq!(config.bar_is_64bit(PCI_LAST_BAR), Ok(false));
    }

    #[test]
    fn bar_type_rejects_an_io_space_bar() {
        let mut fake = FakeConfig::new();
        // Bit 0 set marks an I/O-space BAR, which is never a 64-bit memory pair.
        fake.w32(PCI_BAR0 as usize + 3 * 4, 0x0000_0001);
        assert_eq!(fake.config().bar_is_64bit(3), Ok(false));
    }

    #[test]
    fn enable_memory_and_bus_master_sets_only_those_command_bits() {
        let mut fake = FakeConfig::new();
        // A device whose command register already has I/O decode (bit 0) on:
        // the call must OR in memory + bus-master and disturb nothing else.
        fake.w16(PCI_COMMAND as usize, 0x0001);
        fake.config().enable_memory_and_bus_master();
        assert_eq!(
            fake.r16(PCI_COMMAND as usize),
            0x0001 | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER
        );
    }

    #[test]
    fn reprogram_bar64_writes_low_and_high_with_memory_decode_disabled() {
        let mut fake = FakeConfig::new();
        // Memory + bus-master + I/O all enabled going in; the high half of the
        // BAR pair holds stale bits that must be cleared to zero.
        fake.w16(
            PCI_COMMAND as usize,
            PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER | 0x0001,
        );
        fake.w32(PCI_BAR0 as usize + 4 * 4 + 4, 0xFFFF_FFFF);
        assert_eq!(fake.config().reprogram_bar64(4, 0x5000_0000), Ok(()));
        // Low half receives the address; high half is zeroed (address < 4 GiB).
        assert_eq!(fake.r32(PCI_BAR0 as usize + 4 * 4), 0x5000_0000);
        assert_eq!(fake.r32(PCI_BAR0 as usize + 4 * 4 + 4), 0);
        // Memory decode was disabled across the change and not re-enabled here;
        // the untouched bus-master and I/O bits remain.
        let command = fake.r16(PCI_COMMAND as usize);
        assert_eq!(command & PCI_COMMAND_MEMORY, 0);
        assert_eq!(command & PCI_COMMAND_BUS_MASTER, PCI_COMMAND_BUS_MASTER);
        assert_eq!(command & 0x0001, 0x0001);
    }

    #[test]
    fn common_cfg_reads_and_writes_status() {
        let mut fake = FakeConfig::new();
        let cfg = fake.common();
        cfg.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        assert_eq!(cfg.status(), STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        assert_eq!(
            fake.r8(CFG_DEVICE_STATUS),
            STATUS_ACKNOWLEDGE | STATUS_DRIVER
        );
    }

    #[test]
    fn common_cfg_reads_num_queues() {
        let mut fake = FakeConfig::new();
        fake.w16(CFG_NUM_QUEUES, 2);
        assert_eq!(fake.common().num_queues(), 2);
    }

    #[test]
    fn common_cfg_device_features_reads_across_both_selector_windows() {
        let mut fake = FakeConfig::new();
        // The device-feature register is one 32-bit window multiplexed by the
        // select field; a plain buffer presents the same value in both windows,
        // so the assembled result is `low | (low << 32)`. The point of the test
        // is that the read targets CFG_DEVICE_FEATURE, assembles the halves with
        // the high word shifted, and leaves the selector advanced to window 1.
        fake.w32(CFG_DEVICE_FEATURE, 0xDEAD_BEEF);
        let features = fake.common().device_features();
        assert_eq!(features, 0xDEAD_BEEF | (0xDEAD_BEEF << 32));
        assert_eq!(fake.r32(CFG_DEVICE_FEATURE_SELECT), 1);
    }

    #[test]
    fn common_cfg_set_driver_features_writes_the_high_half_last() {
        let mut fake = FakeConfig::new();
        fake.common().set_driver_features(0x1122_3344_5566_7788);
        // The write sequence ends with the high window selected and the high
        // 32 bits in the feature register; a swapped half-order or a wrong
        // offset changes this observable final state.
        assert_eq!(fake.r32(CFG_DRIVER_FEATURE_SELECT), 1);
        assert_eq!(fake.r32(CFG_DRIVER_FEATURE), 0x1122_3344);
    }

    #[test]
    fn setup_queue_programs_the_areas_and_returns_the_notify_offset() {
        let mut fake = FakeConfig::new();
        // The device advertises a queue max at least as large as our layout and
        // a notify offset the driver must return unchanged.
        fake.w16(CFG_QUEUE_SIZE, 32);
        fake.w16(CFG_QUEUE_NOTIFY_OFF, 7);
        let layout = layout16();
        let ring_paddr = 0x5000_0000u64;
        let notify_off = fake.common().setup_queue(1, &layout, ring_paddr);

        assert_eq!(notify_off, Ok(7));
        assert_eq!(fake.r16(CFG_QUEUE_SELECT), 1);
        // The driver clamps the programmed size to its own layout, not the
        // device's larger maximum.
        assert_eq!(fake.r16(CFG_QUEUE_SIZE), 16);
        // The three area addresses are written as 64-bit values, low half first,
        // at their contiguous offsets from the ring base.
        assert_eq!(
            fake.r64(CFG_QUEUE_DESC),
            ring_paddr + layout.descriptor_offset as u64
        );
        assert_eq!(
            fake.r64(CFG_QUEUE_DRIVER),
            ring_paddr + layout.driver_offset as u64
        );
        assert_eq!(
            fake.r64(CFG_QUEUE_DEVICE),
            ring_paddr + layout.device_offset as u64
        );
        assert_eq!(fake.r16(CFG_QUEUE_ENABLE), 1);
    }

    #[test]
    fn setup_queue_rejects_a_zero_device_queue_size() {
        let mut fake = FakeConfig::new();
        // A device-reported max of 0 means the queue does not exist.
        fake.w16(CFG_QUEUE_SIZE, 0);
        assert_eq!(
            fake.common().setup_queue(3, &layout16(), 0x5000_0000),
            Err(QueueSetupError::QueueAbsent { index: 3 })
        );
        // Nothing was programmed: the queue is left disabled and no ring
        // address was handed to the device.
        assert_eq!(fake.r16(CFG_QUEUE_ENABLE), 0);
        assert_eq!(fake.r64(CFG_QUEUE_DESC), 0);
        assert_eq!(fake.r16(CFG_QUEUE_SIZE), 0);
    }

    #[test]
    fn setup_queue_rejects_a_device_queue_smaller_than_the_layout() {
        let mut fake = FakeConfig::new();
        // The device offers only 8 descriptors; programming 16 is a protocol
        // violation the driver must refuse.
        fake.w16(CFG_QUEUE_SIZE, 8);
        assert_eq!(
            fake.common().setup_queue(0, &layout16(), 0x5000_0000),
            Err(QueueSetupError::QueueTooSmall {
                index: 0,
                device_max: 8,
                required: 16,
            })
        );
        assert_eq!(fake.r16(CFG_QUEUE_ENABLE), 0);
        assert_eq!(fake.r64(CFG_QUEUE_DESC), 0);
        // The device's own advertised maximum is left in place, unprogrammed.
        assert_eq!(fake.r16(CFG_QUEUE_SIZE), 8);
    }

    #[test]
    fn setup_queue_rejects_a_layout_wider_than_the_queue_size_register() {
        // A layout larger than any `u16` cannot be programmed at all. It is not
        // device input, but it must not be truncated into a size the device
        // would then read a shorter ring for than the driver publishes into.
        let mut fake = FakeConfig::new();
        fake.w16(CFG_QUEUE_SIZE, u16::MAX);
        let layout = QueueLayout {
            size: usize::from(u16::MAX) + 1,
            descriptor_offset: 0,
            driver_offset: 256,
            device_offset: 296,
            total_bytes: 430,
        };
        assert_eq!(
            fake.common().setup_queue(0, &layout, 0x5000_0000),
            Err(QueueSetupError::QueueTooSmall {
                index: 0,
                device_max: u16::MAX,
                required: usize::from(u16::MAX) + 1,
            })
        );
        assert_eq!(fake.r16(CFG_QUEUE_ENABLE), 0);
    }

    #[test]
    fn setup_queue_accepts_a_device_max_exactly_equal_to_the_layout() {
        let mut fake = FakeConfig::new();
        fake.w16(CFG_QUEUE_SIZE, 16);
        fake.w16(CFG_QUEUE_NOTIFY_OFF, 2);
        assert_eq!(
            fake.common().setup_queue(0, &layout16(), 0x5000_0000),
            Ok(2)
        );
        assert_eq!(fake.r16(CFG_QUEUE_ENABLE), 1);
    }

    #[test]
    fn reset_returns_once_status_reads_zero() {
        let mut fake = FakeConfig::new();
        // The status byte is already zero (a fresh device), so the reset writes
        // zero and observes the acknowledgement immediately without polling.
        fake.w8(CFG_DEVICE_STATUS, 0);
        assert_eq!(fake.common().reset(), Ok(()));
        assert_eq!(fake.r8(CFG_DEVICE_STATUS), 0);
    }

    #[test]
    fn reset_gives_up_on_a_device_that_never_acknowledges() {
        // The device latches a status it never clears. Before the poll bound
        // this spun in the driver protection domain forever, for exactly as
        // long as the device chose to withhold the answer.
        let stuck = STATUS_FAILED | STATUS_DRIVER;
        let mut polls = 0u32;
        assert_eq!(
            poll_status_cleared(|| {
                polls += 1;
                stuck
            }),
            Err(ResetError::NotAcknowledged { status: stuck })
        );
        // The work done is the driver's own limit plus the one read that fills
        // in the reported status — a device-independent quantity.
        assert_eq!(polls, RESET_POLL_LIMIT + 1);
    }

    #[test]
    fn reset_accepts_an_acknowledgement_that_arrives_late() {
        // A slow but conforming device: the poll must keep going until the
        // status clears, and stop the moment it does.
        let mut polls = 0u32;
        assert_eq!(
            poll_status_cleared(|| {
                polls += 1;
                u8::from(polls < 5)
            }),
            Ok(())
        );
        assert_eq!(polls, 5);
    }

    #[test]
    fn doorbell_writes_the_index_at_the_computed_slot() {
        // A BAR window whose notify structure sits at offset 16; the doorbell
        // for notify_off 3 with multiplier 4 lands at 16 + 12 = 28.
        let mut bar = Box::new([0u8; 256]);
        let caps = VirtioCaps {
            bar: 4,
            common: 0,
            notify: 16,
            notify_multiplier: 4,
            device: 0,
        };
        // SAFETY: `bar` is a live 256-byte buffer that outlives the doorbell — `Doorbell::new`'s contract.
        let doorbell = unsafe { Doorbell::new(bar.as_mut_ptr(), 256, &caps, 3) }.unwrap();
        doorbell.ring(1);
        assert_eq!(u16::from_le_bytes([bar[28], bar[29]]), 1);
        // Nothing was written at the notify base or anywhere else.
        assert_eq!(u16::from_le_bytes([bar[16], bar[17]]), 0);
        assert!(bar[..28].iter().all(|&b| b == 0));
        assert!(bar[30..].iter().all(|&b| b == 0));
    }

    #[test]
    fn doorbell_rejects_a_slot_outside_the_bar() {
        let mut bar = Box::new([0u8; 256]);
        let caps = VirtioCaps {
            bar: 4,
            common: 0,
            notify: 16,
            notify_multiplier: 0x1000,
            device: 0,
        };
        // The notify *base* is comfortably inside the window, so `within` is
        // satisfied — and yet the slot for queue 1 is at 16 + 4096, far outside.
        // This is the out-of-bounds volatile write the old contract permitted.
        assert!(caps.within(256));
        // SAFETY: `bar` is a live 256-byte buffer that outlives the call — `Doorbell::new`'s contract.
        let placed = unsafe { Doorbell::new(bar.as_mut_ptr(), 256, &caps, 1) };
        assert_eq!(
            placed.err(),
            Some(NotifyError::SlotOutsideBar {
                slot_end: Some(16 + 0x1000 + 2),
                bar_size: 256,
            })
        );
        assert!(bar.iter().all(|&b| b == 0));
    }

    #[test]
    fn doorbell_rejects_a_slot_that_ends_one_byte_past_the_window() {
        // The doorbell is two bytes wide, so a slot starting at the last byte
        // of the window is out of range even though its start offset is in it.
        let mut bar = Box::new([0u8; 256]);
        let caps = VirtioCaps {
            bar: 4,
            common: 0,
            notify: 255,
            notify_multiplier: 1,
            device: 0,
        };
        // SAFETY: `bar` is a live 256-byte buffer that outlives the call — `Doorbell::new`'s contract.
        let placed = unsafe { Doorbell::new(bar.as_mut_ptr(), 256, &caps, 0) };
        assert_eq!(
            placed.err(),
            Some(NotifyError::SlotOutsideBar {
                slot_end: Some(257),
                bar_size: 256,
            })
        );
        // One byte earlier the same slot fits exactly.
        let caps = VirtioCaps {
            notify: 254,
            ..caps
        };
        // SAFETY: `bar` is a live 256-byte buffer that outlives the doorbell — `Doorbell::new`'s contract.
        let doorbell = unsafe { Doorbell::new(bar.as_mut_ptr(), 256, &caps, 0) }.unwrap();
        doorbell.ring(7);
        assert_eq!(u16::from_le_bytes([bar[254], bar[255]]), 7);
    }

    #[test]
    fn doorbell_rejects_a_misaligned_slot() {
        // Nothing makes the device's notify offset even. An odd one fits the
        // window perfectly well and would still make the `u16` doorbell write
        // unaligned — undefined behaviour, and the one failure mode a bounds
        // check alone does not catch.
        #[repr(align(2))]
        struct Window([u8; 256]);
        let mut bar = Box::new(Window([0u8; 256]));
        let caps = VirtioCaps {
            bar: 4,
            common: 0,
            notify: 17,
            notify_multiplier: 1,
            device: 0,
        };
        assert!(caps.notify_slot_within(0, 256));
        // SAFETY: `bar` is a live, two-byte-aligned 256-byte buffer that outlives the call — `Doorbell::new`'s contract.
        let placed = unsafe { Doorbell::new(bar.0.as_mut_ptr(), 256, &caps, 0) };
        assert_eq!(
            placed.err(),
            Some(NotifyError::SlotMisaligned { offset: 17 })
        );
        // An odd multiplier against an even base is the same fault one step
        // further along, and must be refused the same way.
        let caps = VirtioCaps {
            notify: 16,
            notify_multiplier: 3,
            ..caps
        };
        // SAFETY: as above — `bar` is live, two-byte aligned, and outlives the call.
        let placed = unsafe { Doorbell::new(bar.0.as_mut_ptr(), 256, &caps, 1) };
        assert_eq!(
            placed.err(),
            Some(NotifyError::SlotMisaligned { offset: 19 })
        );
        assert!(bar.0.iter().all(|&b| b == 0));
    }

    #[test]
    fn notify_slot_offset_cannot_be_wrapped_into_range() {
        // The widest offset the device can name: `notify` at u32::MAX and the
        // full u16 x u32 product. Nothing here may wrap into a small number
        // that would then pass the window check.
        let caps = VirtioCaps {
            bar: 0,
            common: 0,
            notify: u32::MAX,
            notify_multiplier: u32::MAX,
            device: 0,
        };
        assert!(!caps.notify_slot_within(u16::MAX, 0x4000));
        assert_eq!(
            caps.notify_slot_end(u16::MAX),
            Some(u32::MAX as usize + 65535 * 4_294_967_295usize + 2)
        );
    }

    #[test]
    fn skips_a_short_vendor_capability() {
        let mut fake = FakeConfig::new();
        // The four real structures live in BAR 4; a trailing vendor cap shorter
        // than 16 bytes names BAR 2. It must be ignored on its length alone: if
        // the short cap were not skipped, recording its BAR would trip
        // MultipleBars instead of resolving cleanly.
        fake.put_full_chain(4);
        fake.put_cap(0x74, 0x88, VIRTIO_PCI_CAP_DEVICE_CFG, 4, 0x2000, 16);
        fake.put_cap(0x88, 0x00, VIRTIO_PCI_CAP_COMMON_CFG, 2, 0x9999, 8);
        let caps = find_virtio_caps(&fake.config()).unwrap();
        assert_eq!(caps.common, 0x0000);
        assert_eq!(caps.bar, 4);
    }

    #[test]
    fn ignores_a_notify_capability_that_is_too_short() {
        let mut fake = FakeConfig::new();
        fake.w16(PCI_STATUS as usize, PCI_STATUS_CAP_LIST);
        fake.bytes[PCI_CAPABILITIES_PTR as usize] = 0x40;
        // A notify cap needs at least 20 bytes (it carries the multiplier); a
        // 16-byte one is not accepted, leaving notify absent.
        fake.put_cap(0x40, 0x50, VIRTIO_PCI_CAP_COMMON_CFG, 4, 0, 16);
        fake.put_cap(0x50, 0x64, VIRTIO_PCI_CAP_NOTIFY_CFG, 4, 0x3000, 16);
        fake.put_cap(0x64, 0x74, VIRTIO_PCI_CAP_ISR_CFG, 4, 0x1000, 16);
        fake.put_cap(0x74, 0x00, VIRTIO_PCI_CAP_DEVICE_CFG, 4, 0x2000, 16);
        assert_eq!(
            find_virtio_caps(&fake.config()),
            Err(CapError::MissingStructure)
        );
    }

    #[test]
    fn keeps_the_first_of_a_duplicated_capability_type() {
        let mut fake = FakeConfig::new();
        fake.w16(PCI_STATUS as usize, PCI_STATUS_CAP_LIST);
        fake.bytes[PCI_CAPABILITIES_PTR as usize] = 0x40;
        // Two common caps: `get_or_insert` keeps the first offset seen.
        fake.put_cap(0x40, 0x50, VIRTIO_PCI_CAP_COMMON_CFG, 4, 0x1111, 16);
        fake.put_cap(0x50, 0x60, VIRTIO_PCI_CAP_COMMON_CFG, 4, 0x2222, 16);
        fake.put_cap(0x60, 0x74, VIRTIO_PCI_CAP_NOTIFY_CFG, 4, 0x3000, 20);
        fake.w32(0x60 + 16, 4);
        fake.put_cap(0x74, 0x84, VIRTIO_PCI_CAP_ISR_CFG, 4, 0x1000, 16);
        fake.put_cap(0x84, 0x00, VIRTIO_PCI_CAP_DEVICE_CFG, 4, 0x2000, 16);
        assert_eq!(find_virtio_caps(&fake.config()).unwrap().common, 0x1111);
    }

    #[test]
    fn ignores_a_pci_cfg_capability_in_a_different_bar() {
        let mut fake = FakeConfig::new();
        // A type-5 (PCI_CFG) cap legitimately references another BAR; it is not
        // one of the four mapped structures, so it must not trip MultipleBars.
        fake.put_full_chain(4);
        fake.put_cap(0x74, 0x84, VIRTIO_PCI_CAP_DEVICE_CFG, 4, 0x2000, 16);
        fake.put_cap(0x84, 0x00, 5, 2, 0x5000, 16);
        assert_eq!(find_virtio_caps(&fake.config()).unwrap().bar, 4);
    }

    #[test]
    fn rejects_a_cap_list_whose_pointer_is_zero() {
        let mut fake = FakeConfig::new();
        // The status bit claims a capability list, but the pointer is null: the
        // walk visits nothing and every required structure is absent.
        fake.w16(PCI_STATUS as usize, PCI_STATUS_CAP_LIST);
        fake.bytes[PCI_CAPABILITIES_PTR as usize] = 0x00;
        assert_eq!(
            find_virtio_caps(&fake.config()),
            Err(CapError::MissingStructure)
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// The device controls every byte of its configuration space, so the
        /// capability walk must terminate on any of them without panicking or
        /// reading outside the mapped page — and whatever it accepts must carry
        /// a BAR index that is a real BAR, since that index goes on to select a
        /// configuration register to write.
        #[test]
        fn find_virtio_caps_terminates_on_an_arbitrary_config_space(
            bytes in prop::collection::vec(any::<u8>(), 4096),
            cap_list in any::<bool>(),
            cap_pointer in any::<u8>(),
        ) {
            let mut space: Box<[u8; 4096]> = Box::new([0u8; 4096]);
            space.copy_from_slice(&bytes);
            // The status bit and the head pointer are steered explicitly so the
            // walk actually traverses on roughly half the cases; every byte it
            // then reads is still arbitrary.
            let status = if cap_list { PCI_STATUS_CAP_LIST } else { 0 };
            space[PCI_STATUS as usize..PCI_STATUS as usize + 2]
                .copy_from_slice(&status.to_le_bytes());
            space[PCI_CAPABILITIES_PTR as usize] = cap_pointer;
            // SAFETY: `space` is a live 4096-byte buffer that outlives `config` — `PciConfig::new`'s contract.
            let config = unsafe { PciConfig::new(space.as_mut_ptr()) };
            if let Ok(caps) = find_virtio_caps(&config) {
                prop_assert!(caps.bar <= PCI_LAST_BAR);
                // The accepted index must therefore be answerable, never
                // refused as a non-BAR: the two range checks agree.
                prop_assert!(config.bar_is_64bit(caps.bar).is_ok());
                // And the offsets are still just claims: `within` decides, and
                // its answer must be reachable without panicking either way.
                let _ = caps.within(0x4000);
            }
        }

        /// A well-formed four-capability chain with every device-controlled
        /// field perturbed. This reaches the accepting paths a wholly random
        /// page never would, so the walk's own rejections — a mixed BAR, an
        /// invalid BAR, a chain that loops — are exercised alongside success.
        /// Whatever it accepts must name a BAR that BAR programming will then
        /// answer for, which is the property that connects this walk to the
        /// register write at the other end.
        #[test]
        fn find_virtio_caps_survives_a_perturbed_capability_chain(
            bars in prop::collection::vec(any::<u8>(), 4),
            lens in prop::collection::vec(prop_oneof![Just(16u8), Just(20u8), any::<u8>()], 4),
            types in prop::collection::vec(prop_oneof![1u8..=5, any::<u8>()], 4),
            nexts in prop::collection::vec(
                prop_oneof![Just(0u8), Just(0x40u8), Just(0x50u8), any::<u8>()],
                4,
            ),
            offsets in prop::collection::vec(any::<u32>(), 4),
            multiplier in any::<u32>(),
        ) {
            let mut fake = FakeConfig::new();
            fake.w16(PCI_STATUS as usize, PCI_STATUS_CAP_LIST);
            fake.bytes[PCI_CAPABILITIES_PTR as usize] = 0x40;
            let slots = [0x40usize, 0x50, 0x64, 0x74];
            for (index, at) in slots.iter().enumerate() {
                // The last capability's `next` is perturbed like the rest, so a
                // chain that loops back on itself is representable.
                let next = if index + 1 < slots.len() && nexts[index] == 0 {
                    slots[index + 1] as u8
                } else {
                    nexts[index]
                };
                fake.put_cap(*at, next, types[index], bars[index], offsets[index], lens[index]);
            }
            fake.w32(0x50 + 16, multiplier);

            match find_virtio_caps(&fake.config()) {
                Ok(caps) => {
                    prop_assert!(caps.bar <= PCI_LAST_BAR);
                    prop_assert!(fake.config().bar_is_64bit(caps.bar).is_ok());
                    // Placing a doorbell from these offsets must decide, not
                    // fault: the window is real and exactly 0x4000 bytes.
                    let mut window = vec![0u8; 0x4000];
                    // SAFETY: `window` is a live 0x4000-byte buffer that outlives the call — `Doorbell::new`'s contract.
                    let placed = unsafe {
                        Doorbell::new(window.as_mut_ptr(), 0x4000, &caps, u16::MAX)
                    };
                    prop_assert_eq!(
                        placed.is_ok(),
                        caps.notify_slot_within(u16::MAX, 0x4000)
                    );
                }
                Err(error) => prop_assert!(matches!(
                    error,
                    CapError::Malformed
                        | CapError::MultipleBars
                        | CapError::InvalidBar
                        | CapError::MissingStructure
                )),
            }
        }

        /// The common-configuration offset under the device's full authority
        /// over the `u32` it names. Three claims, because a predicate that is
        /// merely present proves none of them:
        ///
        /// * **Total** — it answers for every value, with no arithmetic that
        ///   could wrap or trap on the way.
        /// * **Exact** — it admits precisely the multiples of
        ///   [`COMMON_CFG_ALIGN`], and reads nothing but `common`, so it cannot
        ///   be accidentally answering the extent question instead.
        /// * **Sufficient** — everything it admits is genuinely usable. That is
        ///   asserted by building a `CommonCfg` at the accepted offset inside a
        ///   real page-aligned window and driving every register width through
        ///   it: an offset that passed the predicate while being misaligned
        ///   would abort here on the pointer-alignment precondition, which is
        ///   the exact failure the fuzz corpus entry
        ///   `unaligned_common_cfg_offset` produced before this check existed.
        #[test]
        fn common_offset_alignment_is_total_exact_and_sufficient(
            common in prop_oneof![0u32..=64, 0u32..=0x4000, any::<u32>()],
            notify in any::<u32>(),
            device in any::<u32>(),
            multiplier in any::<u32>(),
            queue_max in any::<u16>(),
        ) {
            const WINDOW_BYTES: usize = 0x4000;
            #[repr(C, align(4096))]
            struct Window([u8; WINDOW_BYTES]);

            let caps = VirtioCaps {
                bar: 0,
                common,
                notify,
                notify_multiplier: multiplier,
                device,
            };
            let aligned = caps.common_is_aligned();
            prop_assert_eq!(aligned, (common as usize).is_multiple_of(COMMON_CFG_ALIGN));
            // Only `common` may reach the answer: zeroing every other field
            // must not move it, or the predicate is reading the wrong input.
            let isolated = VirtioCaps {
                notify: 0,
                notify_multiplier: 0,
                device: 0,
                ..caps
            };
            prop_assert_eq!(aligned, isolated.common_is_aligned());

            // The sufficiency half needs the offset to be usable at all, which
            // is the *other* predicate's business; where they disagree there is
            // nothing to construct.
            if !aligned || !caps.within(WINDOW_BYTES) {
                return Ok(());
            }
            let mut window = Box::new(Window([0u8; WINDOW_BYTES]));
            let at = common as usize;
            // A device maximum the queue programming can act on, so the 64-bit
            // ring-address writes are reached rather than short-circuited.
            window.0[at + CFG_QUEUE_SIZE..at + CFG_QUEUE_SIZE + 2]
                .copy_from_slice(&queue_max.to_le_bytes());
            let base = window.0.as_mut_ptr();
            // SAFETY: `window` is a live, page-aligned `WINDOW_BYTES`-byte buffer owned by this test; `caps.within(WINDOW_BYTES)` was just checked, so `COMMON_CFG_MIN_LEN` bytes from `base + common` lie inside it, and `caps.common_is_aligned()` with a page-aligned `base` makes that address `COMMON_CFG_ALIGN`-aligned — `CommonCfg::new`'s contract in both halves.
            let cfg = unsafe { CommonCfg::new(base.add(at)) };
            // Every accessor width the transport uses: 8, 16, 32, and the
            // 64-bit register written as two halves.
            cfg.set_status(STATUS_ACKNOWLEDGE);
            prop_assert_eq!(cfg.status(), STATUS_ACKNOWLEDGE);
            let _ = cfg.num_queues();
            let _ = cfg.device_features();
            cfg.set_driver_features(u64::MAX);
            let programmed = cfg.setup_queue(0, &layout16(), 0x5000_0000);
            prop_assert_eq!(
                programmed.is_ok(),
                queue_max >= 16,
                "a queue is programmed exactly when the device admits to one that large"
            );
        }

        /// The doorbell bound over the pair the device fully controls. The
        /// offset must be computable without overflow whatever the device
        /// names, the predicate must agree exactly with the arithmetic, and
        /// `Doorbell::new` must accept precisely the slots the predicate
        /// admits — never one byte more.
        #[test]
        fn notify_slot_bound_is_computable_and_exact(
            // Each strategy keeps `any::<..>()` in the union, so the device's
            // full authority over the value is retained; the narrow arms only
            // make the in-window region reachable often enough to be tested.
            notify in prop_oneof![Just(0u32), 0u32..=0x200, any::<u32>()],
            notify_off in prop_oneof![0u16..=64, any::<u16>()],
            multiplier in prop_oneof![Just(0u32), 1u32..=8, any::<u32>()],
            bar_size in 0usize..=0x1_0000,
        ) {
            let caps = VirtioCaps {
                bar: 0,
                common: 0,
                notify,
                notify_multiplier: multiplier,
                device: 0,
            };
            // Every offset the device can name is representable: the product is
            // bounded by 2^48 and the addends by 2^32, so nothing wraps.
            let end = caps.notify_slot_end(notify_off);
            prop_assert_eq!(
                end,
                Some(notify as usize + (notify_off as usize) * (multiplier as usize) + 2)
            );
            prop_assert_eq!(
                caps.notify_slot_within(notify_off, bar_size),
                end.is_some_and(|end| end <= bar_size)
            );

            // Drive the enforcing constructor over a real window of the same
            // size and confirm it admits exactly the slots that both fit and
            // are two-byte aligned — an odd offset would make the `u16` write
            // unaligned, which is undefined behaviour rather than a slow store.
            let slot = (notify as usize) + (notify_off as usize) * (multiplier as usize);
            let mut window = vec![0u16; bar_size.div_ceil(2)];
            let base = window.as_mut_ptr().cast::<u8>();
            // SAFETY: `window` holds at least `bar_size` bytes, is `u16`-aligned, and outlives the call — `Doorbell::new`'s contract.
            let placed = unsafe { Doorbell::new(base, bar_size, &caps, notify_off) };
            prop_assert_eq!(
                placed.is_ok(),
                caps.notify_slot_within(notify_off, bar_size) && slot.is_multiple_of(2)
            );
            if let Ok(doorbell) = placed {
                doorbell.ring(0xBEEF);
                // The write landed wholly inside the window, at the offset the
                // arithmetic named and nowhere else.
                prop_assert_eq!(window[slot / 2], 0xBEEFu16);
                prop_assert!(window[..slot / 2].iter().all(|&v| v == 0));
                prop_assert!(window[slot / 2 + 1..].iter().all(|&v| v == 0));
            }
        }
    }
}
