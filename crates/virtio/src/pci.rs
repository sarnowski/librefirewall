//! Modern virtio 1.0 PCI transport for x86.
//!
//! Two mapped windows drive a virtio-pci device: its PCI **configuration
//! space**, reached here through the q35 ECAM/MMCONFIG window, and a memory
//! **BAR** holding the virtio structures. This module walks the virtio PCI
//! capabilities, reprograms the BAR to an address the driver PD pre-mapped,
//! runs the device-init handshake, and programs a virtqueue ([`crate::queue`])
//! into the device's common configuration.
//!
//! All device access is volatile MMIO through raw pointers into those two
//! windows. The driver PD establishes the mappings as static `.system`
//! capabilities and upholds their validity.
//!
//! # The device is untrusted
//!
//! The adversary is CONCEPT §7.1's **hostile or malfunctioning device**. Every
//! byte this module reads is the device's: its configuration registers, its
//! capability list, its BAR type bits, and — after the handshake — its
//! `queue_size` and `queue_notify_off` registers. A device that is merely
//! broken produces the same bytes as one that is malicious, so both meet the
//! same rule: **no device value reaches a pointer computation before a check
//! this module performs itself**, and every rejection is a typed error rather
//! than a panic, so bring-up fails visibly in the driver PD instead of faulting
//! it. Extent and alignment are independent faults throughout — an offset can
//! fit the mapped window perfectly and still make every wide access into it
//! misaligned — so each is checked on its own.
//!
//! Keeping the two apart is what the offset types are for. The driver's own
//! register offsets are constants, so they are settled when the program is
//! compiled and no access can be made at one that was not. The device's values
//! — a capability pointer, a BAR index, a structure offset, a
//! `queue_notify_off` — are settled at every use, by the type whose only
//! constructor is that check.
//!
//! What is **not** checked, because it is not checkable from this side: whether
//! the device honours anything it was programmed with. It may ignore the queue
//! size it acknowledged, DMA outside the addresses it was given (nothing but an
//! IOMMU can stop that — CONCEPT §7.2, an open item), or never complete a
//! descriptor. The first two are outside this module's reach; the third is a
//! stall, visible to the driver as a queue that stops making progress.

use core::{
    marker::PhantomData,
    sync::atomic::{Ordering, fence},
};

use crate::queue::QueueLayout;

pub const VIRTIO_VENDOR_ID: u16 = 0x1af4;
/// A modern (virtio 1.0) network device.
pub const VIRTIO_NET_DEVICE_ID: u16 = 0x1041;

/// Byte extent of one PCI function's configuration space, as ECAM maps it.
pub const PCI_CONFIG_LEN: usize = 4096;

/// A mapped MMIO structure this module reaches into, described by what an
/// offset has to be judged against: the bytes a caller must have mapped, and
/// the alignment the base is required to carry. Judging is all it is for — no
/// value of an implementing type is ever built.
trait Region {
    /// Bytes the region's constructor requires mapped.
    const LEN: usize;
    /// Alignment the region's constructor requires of the base, which every
    /// offset into it carries through to the access made there.
    const BASE_ALIGN: usize;
}

/// One PCI function's configuration space, through the ECAM window.
#[derive(Clone, Copy)]
enum ConfigSpace {}

impl Region for ConfigSpace {
    const LEN: usize = PCI_CONFIG_LEN;
    const BASE_ALIGN: usize = align_of::<u32>();
}

/// The virtio common configuration structure, inside the device BAR.
#[derive(Clone, Copy)]
enum CommonRegion {}

impl Region for CommonRegion {
    const LEN: usize = COMMON_CFG_MIN_LEN;
    const BASE_ALIGN: usize = COMMON_CFG_ALIGN;
}

/// An offset into `R` at which an access `WIDTH` bytes wide, needing `ALIGN`
/// bytes of alignment, is both in range and correctly aligned.
///
/// Extent and alignment are separate parameters because they are separate
/// faults: a 64-bit virtio register is written as two 32-bit halves, so it
/// spans eight bytes while needing only four of alignment, and one parameter
/// would demand an alignment the access does not have.
#[derive(Clone, Copy)]
struct Off<R: Region, const ALIGN: usize, const WIDTH: usize>(usize, PhantomData<R>);

impl<R: Region, const ALIGN: usize, const WIDTH: usize> Off<R, ALIGN, WIDTH> {
    /// The offset `OFFSET`, admitted only when the whole access fits `R` and is
    /// aligned within it — decided while the program is compiled, so an offset
    /// that would not be is not a value this program can hold.
    const fn at<const OFFSET: usize>() -> Self {
        const {
            assert!(
                ALIGN <= R::BASE_ALIGN,
                "the access needs more alignment than the region's base carries"
            );
            assert!(
                OFFSET.is_multiple_of(ALIGN),
                "the offset misaligns the access made at it"
            );
            assert!(
                OFFSET + WIDTH <= R::LEN,
                "the access runs past the end of the region"
            );
        }
        Self(OFFSET, PhantomData)
    }

    const fn bytes(self) -> usize {
        self.0
    }

    /// One past the last byte the access at this offset touches.
    const fn end(self) -> usize {
        self.0 + WIDTH
    }
}

/// A configuration-space access whose alignment requirement is its own width,
/// which every access this module makes there has.
type CfgOff<const WIDTH: usize> = Off<ConfigSpace, WIDTH, WIDTH>;
/// The same, into the common configuration structure.
type CommonOff<const WIDTH: usize> = Off<CommonRegion, WIDTH, WIDTH>;
/// A 64-bit common-configuration register: eight bytes, written as two
/// four-byte halves and so needing only four-byte alignment.
type CommonOff64 = Off<CommonRegion, 4, 8>;

// PCI configuration-space registers, as offsets an access may be made at.
const PCI_VENDOR_ID: CfgOff<2> = CfgOff::at::<0x00>();
const PCI_DEVICE_ID: CfgOff<2> = CfgOff::at::<0x02>();
const PCI_COMMAND: CfgOff<2> = CfgOff::at::<0x04>();
const PCI_STATUS: CfgOff<2> = CfgOff::at::<0x06>();
const PCI_CAPABILITIES_PTR: CfgOff<1> = CfgOff::at::<0x34>();

/// The first BAR register. The rest follow it at four-byte intervals, which
/// [`BarIndex::register`] is the only way to reach.
const PCI_BAR0: usize = 0x10;
/// Bytes between one BAR register and the next, which is also the width of one.
const PCI_BAR_STRIDE: usize = 4;

const PCI_LAST_BAR: u8 = 5;
/// Highest index that can be the **low half** of a 64-bit BAR pair: BAR 5's
/// successor register is the CardBus-CIS pointer, not a BAR.
const PCI_LAST_BAR64_LOW_HALF: u8 = 4;

const PCI_COMMAND_MEMORY: u16 = 1 << 1;
const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;
/// PCI status-register bit: a capability list is present.
const PCI_STATUS_CAP_LIST: u16 = 1 << 4;

/// Vendor-specific capability id; virtio config caps carry it.
const PCI_CAP_ID_VNDR: u8 = 0x09;

// virtio PCI capability `cfg_type` values.
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

// virtio device-status bits, ORed cumulatively into the common-config
// `device_status` register to step the device through the initialization
// handshake (virtio 1.x §2.1); the device latches them.
pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
/// Set once the driver has written the features it accepts. A device that then
/// clears it rejects the negotiated set, and initialization must not continue.
pub const STATUS_FEATURES_OK: u8 = 8;
/// An unrecoverable device error, or the driver giving up on the device.
/// Terminal: only a reset recovers. It lives in the BAR, so it cannot be
/// signalled for a rejection that happens before the BAR is placed.
pub const STATUS_FAILED: u8 = 0x80;

/// Why a BAR operation refused the index it was given. An index that came from
/// the device's own capability list means a malformed device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarError {
    /// Not a BAR of this function; the offset would land on an unrelated
    /// configuration register.
    IndexOutOfRange(u8),
    /// BAR 5, whose successor register is the CardBus-CIS pointer rather than
    /// the high half of a 64-bit pair; writing it would corrupt a non-BAR.
    NoHighHalf(u8),
}

/// A BAR index that is a BAR of this function, so the register it names is one
/// rather than an unrelated configuration register. The index reaching here is
/// the device's own claim, out of its capability list, so the range check is
/// this type's only constructor.
#[derive(Clone, Copy)]
struct BarIndex(u8);

impl BarIndex {
    /// # Errors
    /// [`BarError::IndexOutOfRange`] for an index that is not a BAR.
    const fn new(index: u8) -> Result<Self, BarError> {
        if index > PCI_LAST_BAR {
            return Err(BarError::IndexOutOfRange(index));
        }
        Ok(Self(index))
    }

    /// This BAR's own register.
    fn register(self) -> CfgOff<4> {
        const {
            assert!(
                PCI_BAR0.is_multiple_of(PCI_BAR_STRIDE),
                "the first BAR register is not aligned for a 32-bit access"
            );
            assert!(
                PCI_BAR0 + (PCI_LAST_BAR as usize + 1) * PCI_BAR_STRIDE <= PCI_CONFIG_LEN,
                "the last BAR register runs past the configuration space"
            );
        }
        Off(PCI_BAR0 + self.0 as usize * PCI_BAR_STRIDE, PhantomData)
    }

    /// The register holding the high half of the 64-bit pair this index is the
    /// low half of.
    ///
    /// # Errors
    /// [`BarError::NoHighHalf`] for BAR 5: the pair does not exist there, so
    /// neither does an offset naming its high half.
    fn high_half(self) -> Result<CfgOff<4>, BarError> {
        if self.0 > PCI_LAST_BAR64_LOW_HALF {
            return Err(BarError::NoHighHalf(self.0));
        }
        const {
            assert!(
                PCI_BAR0 + (PCI_LAST_BAR64_LOW_HALF as usize + 2) * PCI_BAR_STRIDE
                    <= PCI_CONFIG_LEN,
                "the high half of the last 64-bit pair runs past the configuration space"
            );
        }
        Ok(Off(
            PCI_BAR0 + (self.0 as usize + 1) * PCI_BAR_STRIDE,
            PhantomData,
        ))
    }
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

    fn read8(&self, offset: CfgOff<1>) -> u8 {
        // SAFETY: `CfgOff` admits only an access inside the page `PciConfig::new` requires mapped, aligned for its width.
        unsafe { self.base.add(offset.bytes()).read_volatile() }
    }

    fn read16(&self, offset: CfgOff<2>) -> u16 {
        // SAFETY: `CfgOff` admits only an access inside the page `PciConfig::new` requires mapped, aligned for its width.
        unsafe { self.base.add(offset.bytes()).cast::<u16>().read_volatile() }
    }

    fn read32(&self, offset: CfgOff<4>) -> u32 {
        // SAFETY: `CfgOff` admits only an access inside the page `PciConfig::new` requires mapped, aligned for its width.
        unsafe { self.base.add(offset.bytes()).cast::<u32>().read_volatile() }
    }

    fn write16(&self, offset: CfgOff<2>, value: u16) {
        // SAFETY: `CfgOff` admits only an access inside the page `PciConfig::new` requires mapped, aligned for its width.
        unsafe {
            self.base
                .add(offset.bytes())
                .cast::<u16>()
                .write_volatile(value);
        }
    }

    fn write32(&self, offset: CfgOff<4>, value: u32) {
        // SAFETY: `CfgOff` admits only an access inside the page `PciConfig::new` requires mapped, aligned for its width.
        unsafe {
            self.base
                .add(offset.bytes())
                .cast::<u32>()
                .write_volatile(value);
        }
    }

    /// The device's (vendor, device) id pair.
    #[must_use]
    pub fn ids(&self) -> (u16, u16) {
        (self.read16(PCI_VENDOR_ID), self.read16(PCI_DEVICE_ID))
    }

    /// Enable memory-space decoding and bus-master DMA for the device.
    ///
    /// This is also what re-enables decoding after
    /// [`reprogram_bar64`](Self::reprogram_bar64), which deliberately leaves it
    /// off.
    pub fn enable_memory_and_bus_master(&self) {
        let command = self.read16(PCI_COMMAND);
        self.write16(
            PCI_COMMAND,
            command | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
        );
    }

    fn disable_memory(&self) {
        let command = self.read16(PCI_COMMAND);
        self.write16(PCI_COMMAND, command & !PCI_COMMAND_MEMORY);
    }

    /// Whether BAR `bar_index` is a 64-bit memory BAR, so its address spans
    /// this register and the next.
    ///
    /// # Errors
    /// [`BarError::IndexOutOfRange`] for an index that is not a BAR: the
    /// question is refused rather than answered from an unrelated register.
    pub fn bar_is_64bit(&self, bar_index: u8) -> Result<bool, BarError> {
        let low = self.read32(BarIndex::new(bar_index)?.register());
        // Bit 0 == 0 => memory BAR; bits [2:1] == 0b10 => 64-bit.
        Ok(low & 0x1 == 0 && (low >> 1) & 0x3 == 0x2)
    }

    /// Point the 64-bit memory BAR pair whose low half is `bar_index` at
    /// `address` (below 4 GiB).
    ///
    /// # Side effect
    /// Memory-space decoding is switched **off** before the write and is *not*
    /// switched back on: a BAR must not be moved while the device decodes it,
    /// and the caller may have further BARs to place. Call
    /// [`enable_memory_and_bus_master`](Self::enable_memory_and_bus_master)
    /// once the BARs are final. Bus mastering and I/O decoding are untouched.
    ///
    /// # Errors
    /// [`BarError`], rejected before decoding is disabled, so a refused call
    /// leaves the device exactly as it found it.
    pub fn reprogram_bar64(&self, bar_index: u8, address: u32) -> Result<(), BarError> {
        let bar = BarIndex::new(bar_index)?;
        let low = bar.register();
        let high = bar.high_half()?;
        self.disable_memory();
        // The hardware ignores writes to the read-only type flags in the low
        // bits, so writing the aligned address whole is defined.
        self.write32(low, address);
        self.write32(high, 0);
        Ok(())
    }
}

/// Where the virtio structures sit within the device's BAR, as the PCI
/// capability walk found them. Every field is the **device's own claim**;
/// [`within`](Self::within) and [`common_is_aligned`](Self::common_is_aligned)
/// are what a caller must run before turning one into a pointer.
///
/// Every offset is relative to the base of the single BAR named by `bar`. This
/// transport requires all four structures to share one BAR, which QEMU's modern
/// virtio-net-pci does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioCaps {
    pub bar: u8,
    /// Device/driver status, feature negotiation, and the per-queue setup
    /// registers.
    pub common: u32,
    /// The notification structure. A queue's doorbell sits at
    /// `notify + queue_notify_off * notify_multiplier`.
    pub notify: u32,
    pub notify_multiplier: u32,
    /// The device-specific structure — for virtio-net, the MAC address and
    /// status fields. [`within`](Self::within) bounds it against a one-byte
    /// extent and requires no alignment of it, which suffices only while
    /// nothing forms a pointer from it: virtio-net's `status` is a `u16`, so
    /// reading it needs a wider extent and an alignment check first.
    pub device: u32,
}

/// Byte extent of the common configuration structure this transport reaches
/// into: through `queue_device` at offset 48 plus its eight bytes. Public
/// because a caller establishing [`CommonCfg::new`]'s contract needs it.
pub const COMMON_CFG_MIN_LEN: usize = 56;

/// Byte alignment the **base** of the common configuration structure must have
/// for [`CommonCfg`]'s accessors to be sound.
///
/// A field offset carries the base's alignment through to the access made at it
/// rather than adding to it, so the base's alignment *is* every access's
/// alignment: a base off by one byte misaligns every wide one. Whether this
/// value is enough for a given register is settled where that register's offset
/// is written down, when the program is compiled.
pub const COMMON_CFG_ALIGN: usize = 4;
/// One notify doorbell: a single `u16` queue index.
const NOTIFY_SLOT_LEN: usize = 2;
const DEVICE_CFG_MIN_LEN: usize = 1;

// `notify_off * multiplier` is bounded by `u16::MAX * u32::MAX < 2^48`, so on a
// 64-bit `usize` the product cannot overflow. x86_64 is the only target
// (CONCEPT §3), and this holds that reasoning to the code.
const _: () = assert!(
    usize::BITS >= 64,
    "notify-slot arithmetic assumes a 64-bit usize"
);

/// A queue's notify slot as an *offset* rather than a location: both operands
/// are device data and the product is bounded only by 2^48, so this says
/// nothing about whether the slot is mapped.
fn notify_offset_bytes(notify_off: u16, multiplier: u32) -> usize {
    // Cannot overflow: see the `usize::BITS` assertion above.
    (notify_off as usize) * (multiplier as usize)
}

impl VirtioCaps {
    /// Whether every structure reached at a **fixed** offset fits within a BAR
    /// window of `bar_size` bytes, at the extent each is accessed to.
    ///
    /// Deliberately not a queue's doorbell, the one access whose offset is not
    /// fixed: `queue_notify_off` is unknown until [`CommonCfg::setup_queue`]
    /// has run, so bounding the notify base proves only that *some* doorbell
    /// fits, never that a particular queue's does.
    /// [`notify_slot_within`](Self::notify_slot_within) proves that, and
    /// [`Doorbell::new`] enforces it.
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

    /// Whether `common` is [`COMMON_CFG_ALIGN`]-aligned — the half
    /// [`within`](Self::within) cannot answer.
    ///
    /// `common` is a raw `u32` lifted out of the device's capability list, and
    /// an odd value fits any window large enough for it while misaligning every
    /// `u16` and `u32` access into the structure. A caller mapping the BAR at
    /// page granularity, as Microkit does, needs nothing further: `bar_base +
    /// common` is aligned exactly when this returns true.
    #[must_use]
    pub fn common_is_aligned(&self) -> bool {
        (self.common as usize).is_multiple_of(COMMON_CFG_ALIGN)
    }

    /// Whether the doorbell of a queue whose `queue_notify_off` is `notify_off`
    /// lies wholly within a BAR window of `bar_size` bytes.
    ///
    /// Both operands are device data, so the product reaches 2^48 — far outside
    /// any mapped window — and every step is checked arithmetic, so an offset
    /// that cannot be represented is rejected rather than wrapped into range.
    /// Fitting is necessary but not sufficient: the offset must also be even,
    /// which is [`Doorbell::new`]'s business, so a caller should use that
    /// rather than decide from this predicate alone.
    #[must_use]
    pub fn notify_slot_within(&self, notify_off: u16, bar_size: usize) -> bool {
        self.notify_slot_end(notify_off)
            .is_some_and(|end| end <= bar_size)
    }

    /// One past the doorbell's last byte, relative to the BAR base, or `None`
    /// when that offset is not representable.
    fn notify_slot_end(&self, notify_off: u16) -> Option<usize> {
        (self.notify as usize)
            .checked_add(notify_offset_bytes(notify_off, self.notify_multiplier))?
            .checked_add(NOTIFY_SLOT_LEN)
    }
}

/// Walk the PCI capability list and locate the virtio configuration structures.
/// All four — common, notify, ISR, device — must be present and share one BAR.
/// The ISR's offset is not retained: this transport is busy-poll only and reads
/// no ISR status register, so its capability serves only the shared-BAR check.
///
/// # Errors
/// A [`CapError`].
pub fn find_virtio_caps(config: &PciConfig) -> Result<VirtioCaps, CapError> {
    if config.read16(PCI_STATUS) & PCI_STATUS_CAP_LIST == 0 {
        return Err(CapError::NoCapabilities);
    }
    let mut bar: Option<u8> = None;
    let mut common = None;
    let mut notify = None;
    let mut notify_multiplier = 0;
    let mut isr_present = false;
    let mut device = None;

    let mut pointer = CapPointer::from_device_byte(config.read8(PCI_CAPABILITIES_PTR));
    let mut guard = 0;
    while !pointer.is_end() {
        guard += 1;
        if guard > 64 {
            return Err(CapError::Malformed);
        }
        let id = config.read8(pointer.field::<0, 1>());
        let next = CapPointer::from_device_byte(config.read8(pointer.field::<1, 1>()));
        if id == PCI_CAP_ID_VNDR {
            let cap_len = config.read8(pointer.field::<2, 1>());
            let cfg_type = config.read8(pointer.field::<3, 1>());
            let cap_bar = config.read8(pointer.field::<4, 1>());
            let offset = config.read32(pointer.field::<8, 4>());
            if cap_len >= 16 {
                // Only the four mapped structures must share a BAR; another
                // virtio cap (VIRTIO_PCI_CAP_PCI_CFG, type 5) legitimately
                // names a different one and is ignored.
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
                        notify_multiplier = config.read32(pointer.field::<16, 4>());
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

/// Bytes in one unit of a [`CapPointer`]. PCI capability structures are
/// four-byte aligned and the pointer's low two bits are reserved — hardware
/// semantics, so a constant rather than something derived.
const CAP_POINTER_UNIT: usize = 4;

/// A PCI capability-list pointer, held in the four-byte units the PCI
/// specification defines it in rather than in bytes.
///
/// The representation is what bounds every access derived from it: a `u8` of
/// units makes [`bytes`](Self::bytes) at most `u8::MAX * CAP_POINTER_UNIT` and
/// a multiple of `CAP_POINTER_UNIT`, so [`field`](Self::field) has only the
/// constant it adds left to judge. The device supplies the byte; nothing else
/// about it is trusted.
#[derive(Clone, Copy)]
struct CapPointer(u8);

impl CapPointer {
    /// The widest byte offset any pointer can name, from the `u8` it is held in.
    const MAX_BYTES: usize = u8::MAX as usize * CAP_POINTER_UNIT;

    /// Take the device's byte, dropping the two reserved low bits.
    const fn from_device_byte(byte: u8) -> Self {
        Self(byte >> 2)
    }

    /// Whether this is the list terminator.
    const fn is_end(self) -> bool {
        self.0 == 0
    }

    const fn bytes(self) -> usize {
        self.0 as usize * CAP_POINTER_UNIT
    }

    /// The field `SKIP` bytes into the capability this points at.
    fn field<const SKIP: usize, const WIDTH: usize>(self) -> CfgOff<WIDTH> {
        const {
            assert!(
                CAP_POINTER_UNIT.is_multiple_of(WIDTH),
                "the pointer's four-byte alignment does not carry this width"
            );
            assert!(
                SKIP.is_multiple_of(WIDTH),
                "the field's own offset misaligns the access"
            );
            assert!(
                CapPointer::MAX_BYTES + SKIP + WIDTH <= PCI_CONFIG_LEN,
                "a capability at the furthest reachable pointer would overrun the page"
            );
        }
        Off(self.bytes() + SKIP, PhantomData)
    }
}

/// Record the BAR index a mapped virtio structure lives in, rejecting a mix of
/// BARs across the four and any index that is not a BAR of this function — the
/// point at which a malformed index is stopped from reaching BAR programming.
fn record_bar(bar: &mut Option<u8>, cap_bar: u8) -> Result<(), CapError> {
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
    NoCapabilities,
    /// The chain looped or ran past the configuration space.
    Malformed,
    /// The structures are split across BARs, which this transport does not map.
    MultipleBars,
    InvalidBar,
    MissingStructure,
}

// virtio_pci_common_cfg registers, as offsets an access may be made at. The
// layout is one the virtio spec fixes and this file transcribes, so a
// transcription error is the failure mode to catch: an offset that misaligned
// or overran the access made at it is refused where it is written down.
const CFG_DEVICE_FEATURE_SELECT: CommonOff<4> = CommonOff::at::<0>();
const CFG_DEVICE_FEATURE: CommonOff<4> = CommonOff::at::<4>();
const CFG_DRIVER_FEATURE_SELECT: CommonOff<4> = CommonOff::at::<8>();
const CFG_DRIVER_FEATURE: CommonOff<4> = CommonOff::at::<12>();
const CFG_NUM_QUEUES: CommonOff<2> = CommonOff::at::<18>();
const CFG_DEVICE_STATUS: CommonOff<1> = CommonOff::at::<20>();
const CFG_QUEUE_SELECT: CommonOff<2> = CommonOff::at::<22>();
const CFG_QUEUE_SIZE: CommonOff<2> = CommonOff::at::<24>();
const CFG_QUEUE_ENABLE: CommonOff<2> = CommonOff::at::<28>();
const CFG_QUEUE_NOTIFY_OFF: CommonOff<2> = CommonOff::at::<30>();
const CFG_QUEUE_DESC: CommonOff64 = CommonOff64::at::<32>();
const CFG_QUEUE_DRIVER: CommonOff64 = CommonOff64::at::<40>();
const CFG_QUEUE_DEVICE: CommonOff64 = CommonOff64::at::<48>();

// The extent is exactly what the last register needs and no more: a larger one
// would demand mapped bytes this transport never touches. `Off` decides the
// other direction, that no register runs past it.
const _: () = assert!(CFG_QUEUE_DEVICE.end() == COMMON_CFG_MIN_LEN);

/// How many times [`CommonCfg::reset`] reads the device-status register back
/// before giving up.
///
/// Polls, **not elapsed time**: a driver protection domain has no timer
/// capability, so the iteration count is the only adversary-independent
/// quantity available. It guarantees that `reset` returns, not when.
const RESET_POLL_LIMIT: u32 = 1_000_000;

/// Why [`CommonCfg::reset`] gave up on the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetError {
    /// The device did not read back a zero `device_status` within
    /// [`RESET_POLL_LIMIT`] polls.
    NotAcknowledged {
        /// The `device_status` byte read on the final poll, so a caller can
        /// report which bits the device is holding.
        status: u8,
    },
}

/// Why [`CommonCfg::setup_queue`] refused to program a virtqueue. Both variants
/// are device faults at bring-up: the device's own `queue_size` register
/// contradicts what the driver must program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueSetupError {
    /// The device reports a maximum queue size of zero, meaning the queue does
    /// not exist.
    QueueAbsent { index: u16 },
    /// The device's maximum is smaller than the layout the driver must program.
    /// Programming the larger size would tell the device to read a ring past
    /// the end of the one it admits to.
    QueueTooSmall {
        index: u16,
        device_max: u16,
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
    /// writable bytes of the device's mapped `virtio_pci_common_cfg` — the BAR
    /// vaddr plus the common-cfg offset — that stay valid for use, and must be
    /// [`COMMON_CFG_ALIGN`]-aligned. Both are the device's claim, so neither may
    /// be assumed, and an extent check catches only the first.
    ///
    /// The shipped enforcer of both is `nic_driver_core::bringup::identify`: it
    /// runs [`VirtioCaps::within`] and [`VirtioCaps::common_is_aligned`] before
    /// an `Identified` exists, and the `PlacedBar` that constructs this type
    /// outside tests is reachable only from one. Its
    /// `a_structure_outside_the_mapped_window_is_refused_before_any_dereference`
    /// and `a_misaligned_common_configuration_offset_is_refused_before_any_dereference`
    /// tests prove that enforcement rather than assert it (DOC-7).
    #[must_use]
    pub unsafe fn new(base: *mut u8) -> Self {
        Self { base }
    }

    fn read8(&self, off: CommonOff<1>) -> u8 {
        // SAFETY: `CommonOff` admits only an access inside the extent `CommonCfg::new` requires mapped, aligned for its width over the base that contract requires aligned.
        unsafe { self.base.add(off.bytes()).read_volatile() }
    }

    fn write8(&self, off: CommonOff<1>, v: u8) {
        // SAFETY: `CommonOff` admits only an access inside the extent `CommonCfg::new` requires mapped, aligned for its width over the base that contract requires aligned.
        unsafe { self.base.add(off.bytes()).write_volatile(v) }
    }

    fn read16(&self, off: CommonOff<2>) -> u16 {
        // SAFETY: `CommonOff` admits only an access inside the extent `CommonCfg::new` requires mapped, aligned for its width over the base that contract requires aligned.
        unsafe { self.base.add(off.bytes()).cast::<u16>().read_volatile() }
    }

    fn write16(&self, off: CommonOff<2>, v: u16) {
        // SAFETY: `CommonOff` admits only an access inside the extent `CommonCfg::new` requires mapped, aligned for its width over the base that contract requires aligned.
        unsafe { self.base.add(off.bytes()).cast::<u16>().write_volatile(v) }
    }

    fn read32(&self, off: CommonOff<4>) -> u32 {
        // SAFETY: `CommonOff` admits only an access inside the extent `CommonCfg::new` requires mapped, aligned for its width over the base that contract requires aligned.
        unsafe { self.base.add(off.bytes()).cast::<u32>().read_volatile() }
    }

    fn write32(&self, off: CommonOff<4>, v: u32) {
        // SAFETY: `CommonOff` admits only an access inside the extent `CommonCfg::new` requires mapped, aligned for its width over the base that contract requires aligned.
        unsafe { self.base.add(off.bytes()).cast::<u32>().write_volatile(v) }
    }

    fn write64(&self, off: CommonOff64, v: u64) {
        // Two 32-bit halves, low first, matching the virtio spec's 64-bit
        // register access rules.
        // SAFETY: `CommonOff64` admits only an eight-byte, four-byte-aligned access inside the extent `CommonCfg::new` requires mapped, over the base that contract requires aligned, so both halves lie in it and each is aligned.
        unsafe {
            let low = self.base.add(off.bytes()).cast::<u32>();
            low.write_volatile(v as u32);
            low.add(1).write_volatile((v >> 32) as u32);
        }
    }

    /// Current device-status byte.
    #[must_use]
    pub fn status(&self) -> u8 {
        self.read8(CFG_DEVICE_STATUS)
    }

    /// Overwrite the device-status byte.
    pub fn set_status(&self, value: u8) {
        self.write8(CFG_DEVICE_STATUS, value);
    }

    /// Reset the device and poll until it acknowledges by reading back a zero
    /// `device_status`.
    ///
    /// # Errors
    /// [`ResetError::NotAcknowledged`] once [`RESET_POLL_LIMIT`] polls have
    /// passed without an answer. The alternative is a driver protection domain
    /// spinning for as long as the device cares to withhold one.
    pub fn reset(&self) -> Result<(), ResetError> {
        self.set_status(0);
        poll_status_cleared(|| self.status())
    }

    /// Number of virtqueues the device offers.
    #[must_use]
    pub fn num_queues(&self) -> u16 {
        self.read16(CFG_NUM_QUEUES)
    }

    /// Read the device's 64-bit feature bitmap across both selector windows.
    #[must_use]
    pub fn device_features(&self) -> u64 {
        self.write32(CFG_DEVICE_FEATURE_SELECT, 0);
        let low = self.read32(CFG_DEVICE_FEATURE) as u64;
        self.write32(CFG_DEVICE_FEATURE_SELECT, 1);
        let high = self.read32(CFG_DEVICE_FEATURE) as u64;
        low | (high << 32)
    }

    /// Write the negotiated 64-bit feature bitmap across both selector windows.
    pub fn set_driver_features(&self, features: u64) {
        self.write32(CFG_DRIVER_FEATURE_SELECT, 0);
        self.write32(CFG_DRIVER_FEATURE, features as u32);
        self.write32(CFG_DRIVER_FEATURE_SELECT, 1);
        self.write32(CFG_DRIVER_FEATURE, (features >> 32) as u32);
    }

    /// Program one virtqueue's three area addresses, placed contiguously per
    /// [`QueueLayout`] at `ring_paddr`, and enable it.
    ///
    /// # Returns
    /// The device's `queue_notify_off` — **raw device output**, bounded by
    /// nothing but its width, and reaching 2^48 once multiplied by
    /// `notify_multiplier`. Turn it into a doorbell only through
    /// [`Doorbell::new`], which bounds it against the mapped BAR window;
    /// `doorbell_rejects_a_slot_outside_the_bar` and
    /// `notify_slot_bound_is_computable_and_exact` prove that (DOC-7).
    ///
    /// # Errors
    /// [`QueueSetupError`] when the device's own `queue_size` register says the
    /// queue does not exist or is smaller than `layout` requires. Nothing is
    /// programmed in either case, so a caller that gives up leaves the device
    /// with no ring addresses it could act on.
    pub fn setup_queue(
        &self,
        index: u16,
        layout: &QueueLayout,
        ring_paddr: u64,
    ) -> Result<u16, QueueSetupError> {
        self.write16(CFG_QUEUE_SELECT, index);
        // The device initialises queue_size to its maximum for this queue.
        let device_max = self.read16(CFG_QUEUE_SIZE);
        if device_max == 0 {
            return Err(QueueSetupError::QueueAbsent { index });
        }
        // A layout wider than the `u16` register is the same refusal as a
        // device maximum below it, and converting first keeps the comparison
        // and everything after it in one width.
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
        // region's physical address patched from `librefirewall.system`, and
        // `QueueLayout`'s offsets within it — so an overflow in these sums is a
        // build-time misconfiguration that must fail visibly, not device input.
        // The write order (size, addresses, enable) follows the virtio spec.
        self.write16(CFG_QUEUE_SIZE, required);
        self.write64(CFG_QUEUE_DESC, ring_paddr + layout.descriptor_offset as u64);
        self.write64(CFG_QUEUE_DRIVER, ring_paddr + layout.driver_offset as u64);
        self.write64(CFG_QUEUE_DEVICE, ring_paddr + layout.device_offset as u64);
        self.write16(CFG_QUEUE_ENABLE, 1);
        Ok(self.read16(CFG_QUEUE_NOTIFY_OFF))
    }
}

/// Read `status` until it reads back zero, at most [`RESET_POLL_LIMIT`] times.
///
/// A closure rather than a method because the give-up path is otherwise not
/// host-testable: a `CommonCfg` over plain memory reads back the very zero
/// `reset` just wrote, so a device that never acknowledges cannot be modelled
/// through the MMIO accessors at all.
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
    /// The doorbell does not lie within the mapped BAR window. Its offset is
    /// `notify + queue_notify_off * notify_multiplier`, all three device data,
    /// so this is a malformed device rather than a driver error.
    SlotOutsideBar {
        /// One past the doorbell's last byte, relative to the BAR base, or
        /// `None` when that offset overflows.
        slot_end: Option<usize>,
        bar_size: usize,
    },
    /// The doorbell's offset within the BAR is odd, making the `u16` write
    /// unaligned — undefined behaviour, not merely a slow access. Nothing this
    /// driver can enforce makes the product of three device-supplied values
    /// even, so a device that names an odd one is refused here.
    SlotMisaligned { offset: usize },
}

/// One virtqueue's doorbell: a validated pointer to the `u16` slot whose write
/// tells the device to look at that queue.
///
/// The type exists to check the bound **once, where it can fail**, rather than
/// on every ring in the poll loop: placing the doorbell is fallible because its
/// offset is device data, and ringing it is then infallible and safe, the only
/// value that varies afterwards being the driver's own queue index.
#[derive(Debug)]
pub struct Doorbell {
    slot: *mut u16,
}

impl Doorbell {
    /// Place the doorbell of the queue whose `queue_notify_off` is `notify_off`
    /// within a BAR window of `bar_size` bytes starting at `bar_base`.
    ///
    /// # Errors
    /// [`NotifyError`], which between them are the whole notify path's
    /// guarantee: the device's `notify_off` and `notify_multiplier` have a
    /// product that reaches 2^48 and need not be even, so without these two
    /// checks even a conforming caller gets an out-of-bounds or unaligned
    /// volatile write.
    ///
    /// # Safety
    /// `bar_base` must point to a mapped window of at least `bar_size` bytes —
    /// the device's BAR as the driver relocated and mapped it — must be at
    /// least two-byte aligned, and must stay valid for the lifetime of the
    /// returned value. Nothing else: the device-supplied offsets are bounded
    /// and aligned here rather than by the caller.
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
        // `slot_end` is this offset plus the slot's own two bytes and was just
        // bounded by `bar_size`, so the addition cannot overflow.
        let offset = caps.notify as usize + notify_offset_bytes(notify_off, caps.notify_multiplier);
        if !offset.is_multiple_of(2) {
            return Err(NotifyError::SlotMisaligned { offset });
        }
        // SAFETY: the two checks above give `offset + 2 <= bar_size` and an
        // even `offset`; `bar_base` names a mapped, two-byte-aligned window of
        // at least `bar_size` bytes per this fn's contract, so the whole slot
        // lies within it and the `u16` pointer is naturally aligned.
        let slot = unsafe { bar_base.add(offset).cast::<u16>() };
        Ok(Self { slot })
    }

    /// Ring the doorbell for `queue`, telling the device to examine that
    /// virtqueue.
    pub fn ring(&self, queue: u16) {
        // The doorbell is what licenses the device to read the descriptors, so
        // their publication has to be visible first.
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

    /// The heap allocation a fixture region owns, carrying the alignment a
    /// Microkit mapping supplies.
    ///
    /// `[u8; N]` has `align_of == 1`, so a fixture handing one to
    /// `PciConfig::new` or `CommonCfg::new` would under-deliver on the very
    /// contract under test and manufacture its own misalignment — which it
    /// could then not tell apart from the device's, the confusion
    /// `VirtioCaps::common_is_aligned` exists to remove.
    #[repr(C, align(4096))]
    struct Page<const N: usize>([u8; N]);

    /// A fixture mapping, reachable only through the one raw pointer the code
    /// under test is attached to.
    ///
    /// The bytes are `Box::into_raw`d and no `&`/`&mut` into them is ever
    /// formed, so fixture and transport share a single tag for the whole
    /// region's life. A reference would not survive: the transport writes its
    /// registers through the raw pointer, and such a write invalidates any
    /// reference derived from the same allocation, so a fixture that read a
    /// register back through one would itself be undefined behaviour while
    /// claiming to prove the transport's conduct against a hostile device
    /// (TEST-6). Exposing no reference makes that unrepresentable rather than a
    /// rule to remember (DOC-9).
    struct MappedRegion<const N: usize> {
        page: *mut Page<N>,
    }

    impl<const N: usize> MappedRegion<N> {
        fn zeroed() -> Self {
            Self {
                page: Box::into_raw(Box::new(Page([0u8; N]))),
            }
        }

        /// The pointer the code under test is mapped over, and the only route
        /// to the bytes — `*mut` from `&self` deliberately, because handing it
        /// a second, separately derived pointer is what a fixture must not do.
        fn base(&self) -> *mut u8 {
            self.page.cast::<u8>()
        }

        // Byte at a time rather than one volatile access of the whole `[u8; M]`:
        // a 64 KiB volatile load segfaults LLVM's SelectionDAG on the pinned
        // nightly, and the region-sized reads below are exactly that shape.
        fn read<const M: usize>(&self, off: usize) -> [u8; M] {
            assert!(
                off.saturating_add(M) <= N,
                "read of {off:#x} escapes {N:#x}"
            );
            let mut out = [0u8; M];
            for (index, byte) in out.iter_mut().enumerate() {
                // SAFETY: the assertion above puts `off + index` inside the
                // `N`-byte allocation `zeroed` made, which `Drop` alone frees
                // and which therefore outlives `self`; a byte needs no
                // alignment.
                *byte = unsafe { self.base().add(off + index).read_volatile() };
            }
            out
        }

        fn write<const M: usize>(&mut self, off: usize, bytes: [u8; M]) {
            assert!(
                off.saturating_add(M) <= N,
                "write of {off:#x} escapes {N:#x}"
            );
            for (index, byte) in bytes.into_iter().enumerate() {
                // SAFETY: bounded by the assertion above into the allocation
                // `zeroed` made and `Drop` alone frees, exactly as `read`.
                unsafe { self.base().add(off + index).write_volatile(byte) };
            }
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

    // A synthetic 4 KiB config space with a virtio capability chain, used to
    // test the pure capability-walk logic without a device.
    struct FakeConfig {
        region: MappedRegion<4096>,
    }

    impl FakeConfig {
        fn new() -> Self {
            Self {
                region: MappedRegion::zeroed(),
            }
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
        fn r8(&self, off: usize) -> u8 {
            self.region.read::<1>(off)[0]
        }
        fn r16(&self, off: usize) -> u16 {
            u16::from_le_bytes(self.region.read(off))
        }
        fn r32(&self, off: usize) -> u32 {
            u32::from_le_bytes(self.region.read(off))
        }
        fn r64(&self, off: usize) -> u64 {
            u64::from_le_bytes(self.region.read(off))
        }
        fn config(&mut self) -> PciConfig {
            // SAFETY: `MappedRegion<4096>` is exactly the page-aligned ECAM page `PciConfig::new` names, live until this fixture's `Drop` and so outliving the value.
            unsafe { PciConfig::new(self.region.base()) }
        }
        // A `CommonCfg` over this region's base, so its register methods can be
        // driven against plain backing memory the test seeds and reads back.
        fn common(&mut self) -> CommonCfg {
            // SAFETY: the region is 4096 bytes, far more than `COMMON_CFG_MIN_LEN`, page-aligned by `Page` (so `COMMON_CFG_ALIGN`-aligned), and outlives the value — `CommonCfg::new`'s contract in both halves.
            unsafe { CommonCfg::new(self.region.base()) }
        }
        // Write a virtio cap at `at`, chaining to `next`.
        fn put_cap(&mut self, at: usize, next: u8, cfg_type: u8, bar: u8, offset: u32, len: u8) {
            self.region
                .write(at, [PCI_CAP_ID_VNDR, next, len, cfg_type, bar]);
            self.w32(at + 8, offset);
        }
        // The full four-structure chain every valid-device case needs, in BAR
        // `bar` with notify multiplier 4.
        fn put_full_chain(&mut self, bar: u8) {
            self.w16(PCI_STATUS.bytes(), PCI_STATUS_CAP_LIST);
            self.w8(PCI_CAPABILITIES_PTR.bytes(), 0x40);
            self.put_cap(0x40, 0x50, VIRTIO_PCI_CAP_COMMON_CFG, bar, 0x0000, 16);
            self.put_cap(0x50, 0x64, VIRTIO_PCI_CAP_NOTIFY_CFG, bar, 0x3000, 20);
            self.w32(0x50 + 16, 4);
            self.put_cap(0x64, 0x74, VIRTIO_PCI_CAP_ISR_CFG, bar, 0x1000, 16);
            self.put_cap(0x74, 0x00, VIRTIO_PCI_CAP_DEVICE_CFG, bar, 0x2000, 16);
        }
    }

    /// The widest BAR window the doorbell cases draw, and the size the fixture
    /// region is backed at.
    const MAX_BAR_BYTES: usize = 0x1_0000;

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
        fake.w16(PCI_VENDOR_ID.bytes(), VIRTIO_VENDOR_ID);
        fake.w16(PCI_DEVICE_ID.bytes(), VIRTIO_NET_DEVICE_ID);
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
        fake.w16(PCI_VENDOR_ID.bytes(), VIRTIO_VENDOR_ID);
        fake.w16(PCI_DEVICE_ID.bytes(), VIRTIO_NET_DEVICE_ID);
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
        fake.w16(PCI_STATUS.bytes(), PCI_STATUS_CAP_LIST);
        fake.w8(PCI_CAPABILITIES_PTR.bytes(), 0x40);
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
    fn the_capability_pointer_keeps_the_four_byte_units_the_mask_produced() {
        // `CapPointer` holds units rather than bytes, and that representation
        // is what bounds every access derived from it. It must still name the
        // same byte the discarded `& 0xfc` named, for every byte a device can
        // supply — a shift that kept the wrong bits would walk the chain to
        // offsets no test distinguishes from the right ones.
        for byte in 0..=u8::MAX {
            let pointer = CapPointer::from_device_byte(byte);
            assert_eq!(pointer.bytes(), usize::from(byte & 0xfc), "byte {byte:#x}");
            assert_eq!(pointer.is_end(), byte & 0xfc == 0, "byte {byte:#x}");
            // The furthest field the walk reads must stay inside the page the
            // accessors are bounded to, which is what `field`'s const block
            // decides for the widest pointer rather than for this one.
            assert!(pointer.field::<16, 4>().end() <= PCI_CONFIG_LEN);
        }
    }

    #[test]
    fn a_bar_index_names_its_own_register_and_the_high_half_after_it() {
        // The two offsets BAR programming writes, against the register layout
        // the tests below read back by hand. An index is only a `BarIndex`
        // after the range check, so this also pins that the check and the
        // arithmetic agree at the boundary.
        for index in 0..=PCI_LAST_BAR {
            let bar = BarIndex::new(index).expect("a BAR of this function");
            assert_eq!(bar.register().bytes(), PCI_BAR0 + usize::from(index) * 4);
            assert!(bar.register().end() <= PCI_CONFIG_LEN);
        }
        assert_eq!(
            BarIndex::new(PCI_LAST_BAR + 1).err(),
            Some(BarError::IndexOutOfRange(PCI_LAST_BAR + 1))
        );
        let low = BarIndex::new(PCI_LAST_BAR64_LOW_HALF).expect("a 64-bit low half");
        assert_eq!(
            low.high_half().map(|high| high.bytes()),
            Ok(PCI_BAR0 + usize::from(PCI_LAST_BAR64_LOW_HALF + 1) * 4)
        );
        assert_eq!(
            BarIndex::new(PCI_LAST_BAR)
                .expect("a BAR of this function")
                .high_half()
                .err(),
            Some(BarError::NoHighHalf(PCI_LAST_BAR))
        );
    }

    #[test]
    fn rejects_missing_required_structures() {
        let mut fake = FakeConfig::new();
        fake.w16(PCI_STATUS.bytes(), PCI_STATUS_CAP_LIST);
        fake.w8(PCI_CAPABILITIES_PTR.bytes(), 0x40);
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
        fake.w16(PCI_STATUS.bytes(), PCI_STATUS_CAP_LIST);
        fake.w8(PCI_CAPABILITIES_PTR.bytes(), 0x40);
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
        fake.w16(PCI_STATUS.bytes(), PCI_STATUS_CAP_LIST);
        fake.w8(PCI_CAPABILITIES_PTR.bytes(), 0x40);
        // A -> B -> A never terminates; the iteration guard must trip.
        fake.put_cap(0x40, 0x50, VIRTIO_PCI_CAP_COMMON_CFG, 4, 0, 16);
        fake.put_cap(0x50, 0x40, VIRTIO_PCI_CAP_ISR_CFG, 4, 0x1000, 16);
        assert_eq!(find_virtio_caps(&fake.config()), Err(CapError::Malformed));
    }

    #[test]
    fn rejects_a_capability_naming_an_invalid_bar() {
        let mut fake = FakeConfig::new();
        fake.w16(PCI_STATUS.bytes(), PCI_STATUS_CAP_LIST);
        fake.w8(PCI_CAPABILITIES_PTR.bytes(), 0x40);
        // BAR 6 is outside the valid 0..=5 range.
        fake.put_cap(0x40, 0x00, VIRTIO_PCI_CAP_COMMON_CFG, 6, 0, 16);
        assert_eq!(find_virtio_caps(&fake.config()), Err(CapError::InvalidBar));
    }

    #[test]
    fn a_capability_naming_bar5_is_refused_at_bar_relocation() {
        // BAR 5 is a real BAR, so the capability walk accepts it — but it can
        // never be the low half of a 64-bit pair, because the register after
        // it is the CardBus-CIS pointer. This drives the whole device-driven
        // path: caps -> caps.bar == 5 -> reprogram_bar64(5).
        let mut fake = FakeConfig::new();
        fake.put_full_chain(5);
        let caps = find_virtio_caps(&fake.config()).unwrap();
        assert_eq!(caps.bar, 5);

        // Memory decoding is on going in; a refused relocation must leave both
        // it and the CardBus-CIS pointer untouched.
        fake.w16(
            PCI_COMMAND.bytes(),
            PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
        );
        let cis_before = fake.r32(PCI_BAR0 + 6 * 4);
        assert_eq!(
            fake.config().reprogram_bar64(caps.bar, 0x5000_0000),
            Err(BarError::NoHighHalf(5))
        );
        assert_eq!(fake.r32(PCI_BAR0 + 6 * 4), cis_before);
        assert_eq!(fake.r32(PCI_BAR0 + 5 * 4), 0);
        assert_eq!(
            fake.r16(PCI_COMMAND.bytes()),
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
        assert_eq!(fake.r32(PCI_BAR0 + 6 * 4), 0);
        assert_eq!(fake.r16(PCI_COMMAND.bytes()), 0);
    }

    #[test]
    fn bar_type_detects_64bit_memory_bars() {
        let mut fake = FakeConfig::new();
        // BAR4: memory (bit0=0), 64-bit (bits[2:1]=0b10), prefetchable (bit3).
        fake.w32(PCI_BAR0 + 4 * 4, 0x0000_000c);
        // BAR2: 32-bit memory BAR.
        fake.w32(PCI_BAR0 + 2 * 4, 0x0000_0000);
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
        fake.w32(PCI_BAR0 + 3 * 4, 0x0000_0001);
        assert_eq!(fake.config().bar_is_64bit(3), Ok(false));
    }

    #[test]
    fn enable_memory_and_bus_master_sets_only_those_command_bits() {
        let mut fake = FakeConfig::new();
        // A device whose command register already has I/O decode (bit 0) on:
        // the call must OR in memory + bus-master and disturb nothing else.
        fake.w16(PCI_COMMAND.bytes(), 0x0001);
        fake.config().enable_memory_and_bus_master();
        assert_eq!(
            fake.r16(PCI_COMMAND.bytes()),
            0x0001 | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER
        );
    }

    #[test]
    fn reprogram_bar64_writes_low_and_high_with_memory_decode_disabled() {
        let mut fake = FakeConfig::new();
        // Memory + bus-master + I/O all enabled going in; the high half of the
        // BAR pair holds stale bits that must be cleared to zero.
        fake.w16(
            PCI_COMMAND.bytes(),
            PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER | 0x0001,
        );
        fake.w32(PCI_BAR0 + 4 * 4 + 4, 0xFFFF_FFFF);
        assert_eq!(fake.config().reprogram_bar64(4, 0x5000_0000), Ok(()));
        // Low half receives the address; high half is zeroed (address < 4 GiB).
        assert_eq!(fake.r32(PCI_BAR0 + 4 * 4), 0x5000_0000);
        assert_eq!(fake.r32(PCI_BAR0 + 4 * 4 + 4), 0);
        // Memory decode was disabled across the change and not re-enabled here;
        // the untouched bus-master and I/O bits remain.
        let command = fake.r16(PCI_COMMAND.bytes());
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
            fake.r8(CFG_DEVICE_STATUS.bytes()),
            STATUS_ACKNOWLEDGE | STATUS_DRIVER
        );
    }

    #[test]
    fn common_cfg_reads_num_queues() {
        let mut fake = FakeConfig::new();
        fake.w16(CFG_NUM_QUEUES.bytes(), 2);
        assert_eq!(fake.common().num_queues(), 2);
    }

    #[test]
    fn common_cfg_device_features_reads_across_both_selector_windows() {
        let mut fake = FakeConfig::new();
        // The device-feature register is one 32-bit window multiplexed by the
        // select field; a plain buffer presents the same value in both windows,
        // so the assembled result is `low | (low << 32)`. The point of the test
        // is that the read targets CFG_DEVICE_FEATURE.bytes(), assembles the halves with
        // the high word shifted, and leaves the selector advanced to window 1.
        fake.w32(CFG_DEVICE_FEATURE.bytes(), 0xDEAD_BEEF);
        let features = fake.common().device_features();
        assert_eq!(features, 0xDEAD_BEEF | (0xDEAD_BEEF << 32));
        assert_eq!(fake.r32(CFG_DEVICE_FEATURE_SELECT.bytes()), 1);
    }

    #[test]
    fn common_cfg_set_driver_features_writes_the_high_half_last() {
        let mut fake = FakeConfig::new();
        fake.common().set_driver_features(0x1122_3344_5566_7788);
        // The write sequence ends with the high window selected and the high
        // 32 bits in the feature register; a swapped half-order or a wrong
        // offset changes this observable final state.
        assert_eq!(fake.r32(CFG_DRIVER_FEATURE_SELECT.bytes()), 1);
        assert_eq!(fake.r32(CFG_DRIVER_FEATURE.bytes()), 0x1122_3344);
    }

    #[test]
    fn setup_queue_programs_the_areas_and_returns_the_notify_offset() {
        let mut fake = FakeConfig::new();
        // The device advertises a queue max at least as large as our layout and
        // a notify offset the driver must return unchanged.
        fake.w16(CFG_QUEUE_SIZE.bytes(), 32);
        fake.w16(CFG_QUEUE_NOTIFY_OFF.bytes(), 7);
        let layout = layout16();
        let ring_paddr = 0x5000_0000u64;
        let notify_off = fake.common().setup_queue(1, &layout, ring_paddr);

        assert_eq!(notify_off, Ok(7));
        assert_eq!(fake.r16(CFG_QUEUE_SELECT.bytes()), 1);
        // The driver clamps the programmed size to its own layout, not the
        // device's larger maximum.
        assert_eq!(fake.r16(CFG_QUEUE_SIZE.bytes()), 16);
        // The three area addresses are written as 64-bit values, low half first,
        // at their contiguous offsets from the ring base.
        assert_eq!(
            fake.r64(CFG_QUEUE_DESC.bytes()),
            ring_paddr + layout.descriptor_offset as u64
        );
        assert_eq!(
            fake.r64(CFG_QUEUE_DRIVER.bytes()),
            ring_paddr + layout.driver_offset as u64
        );
        assert_eq!(
            fake.r64(CFG_QUEUE_DEVICE.bytes()),
            ring_paddr + layout.device_offset as u64
        );
        assert_eq!(fake.r16(CFG_QUEUE_ENABLE.bytes()), 1);
    }

    #[test]
    fn setup_queue_rejects_a_zero_device_queue_size() {
        let mut fake = FakeConfig::new();
        // A device-reported max of 0 means the queue does not exist.
        fake.w16(CFG_QUEUE_SIZE.bytes(), 0);
        assert_eq!(
            fake.common().setup_queue(3, &layout16(), 0x5000_0000),
            Err(QueueSetupError::QueueAbsent { index: 3 })
        );
        // Nothing was programmed: the queue is left disabled and no ring
        // address was handed to the device.
        assert_eq!(fake.r16(CFG_QUEUE_ENABLE.bytes()), 0);
        assert_eq!(fake.r64(CFG_QUEUE_DESC.bytes()), 0);
        assert_eq!(fake.r16(CFG_QUEUE_SIZE.bytes()), 0);
    }

    #[test]
    fn setup_queue_rejects_a_device_queue_smaller_than_the_layout() {
        let mut fake = FakeConfig::new();
        // The device offers only 8 descriptors; programming 16 is a protocol
        // violation the driver must refuse.
        fake.w16(CFG_QUEUE_SIZE.bytes(), 8);
        assert_eq!(
            fake.common().setup_queue(0, &layout16(), 0x5000_0000),
            Err(QueueSetupError::QueueTooSmall {
                index: 0,
                device_max: 8,
                required: 16,
            })
        );
        assert_eq!(fake.r16(CFG_QUEUE_ENABLE.bytes()), 0);
        assert_eq!(fake.r64(CFG_QUEUE_DESC.bytes()), 0);
        // The device's own advertised maximum is left in place, unprogrammed.
        assert_eq!(fake.r16(CFG_QUEUE_SIZE.bytes()), 8);
    }

    #[test]
    fn setup_queue_rejects_a_layout_wider_than_the_queue_size_register() {
        // A layout larger than any `u16` cannot be programmed at all. It is not
        // device input, but it must not be truncated into a size the device
        // would then read a shorter ring for than the driver publishes into.
        let mut fake = FakeConfig::new();
        fake.w16(CFG_QUEUE_SIZE.bytes(), u16::MAX);
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
        assert_eq!(fake.r16(CFG_QUEUE_ENABLE.bytes()), 0);
    }

    #[test]
    fn setup_queue_accepts_a_device_max_exactly_equal_to_the_layout() {
        let mut fake = FakeConfig::new();
        fake.w16(CFG_QUEUE_SIZE.bytes(), 16);
        fake.w16(CFG_QUEUE_NOTIFY_OFF.bytes(), 2);
        assert_eq!(
            fake.common().setup_queue(0, &layout16(), 0x5000_0000),
            Ok(2)
        );
        assert_eq!(fake.r16(CFG_QUEUE_ENABLE.bytes()), 1);
    }

    #[test]
    fn reset_returns_once_status_reads_zero() {
        let mut fake = FakeConfig::new();
        // The status byte is already zero (a fresh device), so the reset writes
        // zero and observes the acknowledgement immediately without polling.
        fake.w8(CFG_DEVICE_STATUS.bytes(), 0);
        assert_eq!(fake.common().reset(), Ok(()));
        assert_eq!(fake.r8(CFG_DEVICE_STATUS.bytes()), 0);
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
        let bar = MappedRegion::<256>::zeroed();
        let caps = VirtioCaps {
            bar: 4,
            common: 0,
            notify: 16,
            notify_multiplier: 4,
            device: 0,
        };
        // SAFETY: a live, page-aligned (so two-byte-aligned) 256-byte window that outlives the doorbell — `Doorbell::new`'s contract.
        let doorbell = unsafe { Doorbell::new(bar.base(), 256, &caps, 3) }.unwrap();
        doorbell.ring(1);
        let image = bar.read::<256>(0);
        assert_eq!(u16::from_le_bytes([image[28], image[29]]), 1);
        // Nothing was written at the notify base or anywhere else.
        assert_eq!(u16::from_le_bytes([image[16], image[17]]), 0);
        assert!(image[..28].iter().all(|&b| b == 0));
        assert!(image[30..].iter().all(|&b| b == 0));
    }

    #[test]
    fn doorbell_rejects_a_slot_outside_the_bar() {
        let bar = MappedRegion::<256>::zeroed();
        let caps = VirtioCaps {
            bar: 4,
            common: 0,
            notify: 16,
            notify_multiplier: 0x1000,
            device: 0,
        };
        // The notify *base* is comfortably inside the window, so `within` is
        // satisfied — and yet the slot for queue 1 is at 16 + 4096, far
        // outside: the out-of-bounds volatile write an extent check misses.
        assert!(caps.within(256));
        // SAFETY: a live, page-aligned (so two-byte-aligned) 256-byte window that outlives the call — `Doorbell::new`'s contract.
        let placed = unsafe { Doorbell::new(bar.base(), 256, &caps, 1) };
        assert_eq!(
            placed.err(),
            Some(NotifyError::SlotOutsideBar {
                slot_end: Some(16 + 0x1000 + 2),
                bar_size: 256,
            })
        );
        assert!(bar.read::<256>(0).iter().all(|&b| b == 0));
    }

    #[test]
    fn doorbell_rejects_a_slot_that_ends_one_byte_past_the_window() {
        // The doorbell is two bytes wide, so a slot starting at the last byte
        // of the window is out of range even though its start offset is in it.
        let bar = MappedRegion::<256>::zeroed();
        let caps = VirtioCaps {
            bar: 4,
            common: 0,
            notify: 255,
            notify_multiplier: 1,
            device: 0,
        };
        // SAFETY: a live, page-aligned (so two-byte-aligned) 256-byte window that outlives the call — `Doorbell::new`'s contract.
        let placed = unsafe { Doorbell::new(bar.base(), 256, &caps, 0) };
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
        // SAFETY: as above — a live, two-byte-aligned window outliving the doorbell.
        let doorbell = unsafe { Doorbell::new(bar.base(), 256, &caps, 0) }.unwrap();
        doorbell.ring(7);
        assert_eq!(u16::from_le_bytes(bar.read::<2>(254)), 7);
    }

    #[test]
    fn doorbell_rejects_a_misaligned_slot() {
        // Nothing makes the device's notify offset even. An odd one fits the
        // window perfectly well and would still make the `u16` doorbell write
        // unaligned — undefined behaviour, and the one failure mode a bounds
        // check alone does not catch.
        let bar = MappedRegion::<256>::zeroed();
        let caps = VirtioCaps {
            bar: 4,
            common: 0,
            notify: 17,
            notify_multiplier: 1,
            device: 0,
        };
        assert!(caps.notify_slot_within(0, 256));
        // SAFETY: a live, page-aligned (so two-byte-aligned) 256-byte window that outlives the call — `Doorbell::new`'s contract.
        let placed = unsafe { Doorbell::new(bar.base(), 256, &caps, 0) };
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
        // SAFETY: as above — live, two-byte aligned, and outliving the call.
        let placed = unsafe { Doorbell::new(bar.base(), 256, &caps, 1) };
        assert_eq!(
            placed.err(),
            Some(NotifyError::SlotMisaligned { offset: 19 })
        );
        assert!(bar.read::<256>(0).iter().all(|&b| b == 0));
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
        fake.w16(PCI_STATUS.bytes(), PCI_STATUS_CAP_LIST);
        fake.w8(PCI_CAPABILITIES_PTR.bytes(), 0x40);
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
        fake.w16(PCI_STATUS.bytes(), PCI_STATUS_CAP_LIST);
        fake.w8(PCI_CAPABILITIES_PTR.bytes(), 0x40);
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
        fake.w16(PCI_STATUS.bytes(), PCI_STATUS_CAP_LIST);
        fake.w8(PCI_CAPABILITIES_PTR.bytes(), 0x00);
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
            let mut fake = FakeConfig::new();
            let page: [u8; 4096] = bytes.try_into().expect("the strategy yields 4096 bytes");
            fake.region.write(0, page);
            // The status bit and the head pointer are steered explicitly so the
            // walk actually traverses on roughly half the cases; every byte it
            // then reads is still arbitrary.
            let status = if cap_list { PCI_STATUS_CAP_LIST } else { 0 };
            fake.w16(PCI_STATUS.bytes(), status);
            fake.w8(PCI_CAPABILITIES_PTR.bytes(), cap_pointer);
            let config = fake.config();
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
            fake.w16(PCI_STATUS.bytes(), PCI_STATUS_CAP_LIST);
            fake.w8(PCI_CAPABILITIES_PTR.bytes(), 0x40);
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
                    let window = MappedRegion::<0x4000>::zeroed();
                    // SAFETY: a live, page-aligned (so two-byte-aligned) 0x4000-byte window that outlives the call — `Doorbell::new`'s contract.
                    let placed = unsafe {
                        Doorbell::new(window.base(), 0x4000, &caps, u16::MAX)
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
            let mut window = MappedRegion::<WINDOW_BYTES>::zeroed();
            let at = common as usize;
            // A device maximum the queue programming can act on, so the 64-bit
            // ring-address writes are reached rather than short-circuited.
            window.write(at + CFG_QUEUE_SIZE.bytes(), queue_max.to_le_bytes());
            // SAFETY: a live, page-aligned `WINDOW_BYTES`-byte region owned by this test; `caps.within(WINDOW_BYTES)` was just checked, so `COMMON_CFG_MIN_LEN` bytes from `base + common` lie inside it, and `caps.common_is_aligned()` over a page-aligned base makes that address `COMMON_CFG_ALIGN`-aligned — `CommonCfg::new`'s contract in both halves.
            let cfg = unsafe { CommonCfg::new(window.base().add(at)) };
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
            bar_size in 0usize..=MAX_BAR_BYTES,
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
            // Backed at the widest `bar_size` the strategy draws; `Doorbell`
            // is told `bar_size`, which its contract requires the window to be
            // at least, so a larger backing store changes no decision.
            let window = MappedRegion::<MAX_BAR_BYTES>::zeroed();
            // SAFETY: a live, page-aligned (so two-byte-aligned) region of at least `bar_size` bytes that outlives the call — `Doorbell::new`'s contract.
            let placed = unsafe { Doorbell::new(window.base(), bar_size, &caps, notify_off) };
            prop_assert_eq!(
                placed.is_ok(),
                caps.notify_slot_within(notify_off, bar_size) && slot.is_multiple_of(2)
            );
            if let Ok(doorbell) = placed {
                doorbell.ring(0xBEEF);
                // The write landed wholly inside the window, at the offset the
                // arithmetic named and nowhere else.
                let image = window.read::<MAX_BAR_BYTES>(0);
                prop_assert_eq!(u16::from_le_bytes([image[slot], image[slot + 1]]), 0xBEEF);
                prop_assert!(image[..slot].iter().all(|&v| v == 0));
                prop_assert!(image[slot + 2..].iter().all(|&v| v == 0));
            }
        }
    }
}
