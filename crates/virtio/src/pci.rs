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

// virtio device-status bits.
pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_FAILED: u8 = 0x80;

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
    /// `offset` must be within the 4 KiB configuration space and aligned for
    /// the accessed width (the private callers below all satisfy this).
    unsafe fn read8(&self, offset: u16) -> u8 {
        unsafe { self.base.add(offset as usize).read_volatile() }
    }
    unsafe fn read16(&self, offset: u16) -> u16 {
        unsafe { self.base.add(offset as usize).cast::<u16>().read_volatile() }
    }
    unsafe fn read32(&self, offset: u16) -> u32 {
        unsafe { self.base.add(offset as usize).cast::<u32>().read_volatile() }
    }
    unsafe fn write16(&self, offset: u16, value: u16) {
        unsafe {
            self.base
                .add(offset as usize)
                .cast::<u16>()
                .write_volatile(value)
        }
    }
    unsafe fn write32(&self, offset: u16, value: u32) {
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
        // SAFETY: both offsets are fixed, aligned, in-bounds config registers.
        unsafe { (self.read16(PCI_VENDOR_ID), self.read16(PCI_DEVICE_ID)) }
    }

    /// Enable memory-space decoding and bus-master DMA for the device.
    pub fn enable_memory_and_bus_master(&self) {
        // SAFETY: PCI_COMMAND is a fixed, aligned, in-bounds config register.
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
        // SAFETY: PCI_COMMAND is a fixed, aligned, in-bounds config register.
        unsafe {
            let command = self.read16(PCI_COMMAND);
            self.write16(PCI_COMMAND, command & !PCI_COMMAND_MEMORY);
        }
    }

    /// Whether BAR `bar_index` is a 64-bit memory BAR (so its address spans
    /// this register and the next). The driver verifies this before treating a
    /// BAR as a 64-bit pair, rather than trusting the device's layout.
    #[must_use]
    pub fn bar_is_64bit(&self, bar_index: u8) -> bool {
        let offset = PCI_BAR0 + (bar_index as u16) * 4;
        // SAFETY: a BAR is a fixed, aligned, in-bounds config register.
        let low = unsafe { self.read32(offset) };
        // Bit 0 == 0 => memory BAR; bits [2:1] == 0b10 => 64-bit.
        low & 0x1 == 0 && (low >> 1) & 0x3 == 0x2
    }

    /// Point a 64-bit memory BAR at `address` (below 4 GiB), with memory
    /// decoding disabled across the change. `bar_index` is the low half of the
    /// 64-bit BAR pair.
    pub fn reprogram_bar64(&self, bar_index: u8, address: u32) {
        let low = PCI_BAR0 + (bar_index as u16) * 4;
        let high = low + 4;
        self.disable_memory();
        // SAFETY: BAR registers are fixed, aligned, in-bounds config registers;
        // the low bits the hardware treats as read-only type flags are ignored
        // on write, so writing the aligned address is well defined.
        unsafe {
            self.write32(low, address);
            self.write32(high, 0);
        }
    }
}

/// The locations of the virtio structures within the device's BAR, discovered
/// by walking the PCI capability list. All offsets are byte offsets into the
/// BAR named by [`bar`](Self::bar); this transport requires every structure to
/// live in the same BAR (true for QEMU's modern virtio-net-pci).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioCaps {
    pub bar: u8,
    pub common: u32,
    pub notify: u32,
    pub notify_multiplier: u32,
    pub isr: u32,
    pub device: u32,
}

/// Minimum byte extent the driver accesses in each virtio structure, used to
/// bounds-check the device-supplied offsets against the mapped BAR window so a
/// structure placed near the window's end cannot let a field access run past it.
const COMMON_CFG_MIN_LEN: usize = 56; // through queue_device (offset 48) + 8 bytes
const NOTIFY_MIN_LEN: usize = 2; // at least one doorbell u16
const ISR_MIN_LEN: usize = 1;
const DEVICE_CFG_MIN_LEN: usize = 1;

impl VirtioCaps {
    /// Whether every structure fits within a BAR window of `bar_size` bytes,
    /// accounting for the minimum extent the driver accesses in each. The
    /// offsets come from the (untrusted) device, so they are bounds-checked
    /// against the window actually mapped before any structure is dereferenced.
    #[must_use]
    pub fn within(&self, bar_size: usize) -> bool {
        let fits = |offset: u32, needed: usize| {
            (offset as usize)
                .checked_add(needed)
                .is_some_and(|end| end <= bar_size)
        };
        fits(self.common, COMMON_CFG_MIN_LEN)
            && fits(self.notify, NOTIFY_MIN_LEN)
            && fits(self.isr, ISR_MIN_LEN)
            && fits(self.device, DEVICE_CFG_MIN_LEN)
    }
}

/// Walk the PCI capability list and locate the virtio configuration
/// structures. All four (common, notify, ISR, device) must be present and share
/// one BAR. Returns a [`CapError`] if the device exposes no capability list, the
/// chain is malformed, a capability names an invalid BAR, the structures span
/// multiple BARs, or a required structure is absent.
pub fn find_virtio_caps(config: &PciConfig) -> Result<VirtioCaps, CapError> {
    // SAFETY: the walk only touches capability structures the device advertises,
    // reached at masked (aligned) pointers that stay within the mapped 4 KiB
    // ECAM page — a capability may sit near the top of the 256-byte conventional
    // space and read a few bytes past it, still inside the mapped page.
    unsafe {
        if config.read16(PCI_STATUS) & PCI_STATUS_CAP_LIST == 0 {
            return Err(CapError::NoCapabilities);
        }
        let mut bar: Option<u8> = None;
        let mut common = None;
        let mut notify = None;
        let mut notify_multiplier = 0;
        let mut isr = None;
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
                            isr.get_or_insert(offset);
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

        match (bar, common, notify, isr, device) {
            (Some(bar), Some(common), Some(notify), Some(isr), Some(device)) => Ok(VirtioCaps {
                bar,
                common,
                notify,
                notify_multiplier,
                isr,
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
    if cap_bar > 5 {
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

/// Upper bound on reset-acknowledge polling before declaring the device dead.
const RESET_TIMEOUT_SPINS: u32 = 1_000_000;

/// The virtio common configuration structure, mapped in the device BAR.
pub struct CommonCfg {
    base: *mut u8,
}

impl CommonCfg {
    /// # Safety
    /// `base` must point to the device's mapped `virtio_pci_common_cfg` (BAR
    /// vaddr + the common-cfg offset) and stay valid for use.
    #[must_use]
    pub unsafe fn new(base: *mut u8) -> Self {
        Self { base }
    }

    unsafe fn r8(&self, off: usize) -> u8 {
        unsafe { self.base.add(off).read_volatile() }
    }
    unsafe fn w8(&self, off: usize, v: u8) {
        unsafe { self.base.add(off).write_volatile(v) }
    }
    unsafe fn r16(&self, off: usize) -> u16 {
        unsafe { self.base.add(off).cast::<u16>().read_volatile() }
    }
    unsafe fn w16(&self, off: usize, v: u16) {
        unsafe { self.base.add(off).cast::<u16>().write_volatile(v) }
    }
    unsafe fn r32(&self, off: usize) -> u32 {
        unsafe { self.base.add(off).cast::<u32>().read_volatile() }
    }
    unsafe fn w32(&self, off: usize, v: u32) {
        unsafe { self.base.add(off).cast::<u32>().write_volatile(v) }
    }
    unsafe fn w64(&self, off: usize, v: u64) {
        // Written as two 32-bit halves, low first, matching the virtio spec's
        // 64-bit register access rules.
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
        // SAFETY: fixed in-bounds field of the mapped structure.
        unsafe { self.r8(CFG_DEVICE_STATUS) }
    }

    /// Overwrite the device-status byte.
    pub fn set_status(&self, value: u8) {
        // SAFETY: fixed in-bounds field of the mapped structure.
        unsafe { self.w8(CFG_DEVICE_STATUS, value) }
    }

    /// Reset the device and spin until it acknowledges by reading back 0.
    pub fn reset(&self) {
        self.set_status(0);
        // A device that never acknowledges the reset is a hardware/deployment
        // fault; bound the wait and fail visibly at init rather than hang the
        // driver PD forever.
        let mut spins: u32 = 0;
        while self.status() != 0 {
            spins += 1;
            assert!(
                spins < RESET_TIMEOUT_SPINS,
                "virtio device did not acknowledge reset"
            );
            core::hint::spin_loop();
        }
    }

    /// Number of virtqueues the device offers.
    #[must_use]
    pub fn num_queues(&self) -> u16 {
        // SAFETY: fixed in-bounds field of the mapped structure.
        unsafe { self.r16(CFG_NUM_QUEUES) }
    }

    /// Read the device's 64-bit feature bitmap across both selector windows.
    #[must_use]
    pub fn device_features(&self) -> u64 {
        // SAFETY: fixed in-bounds fields of the mapped structure.
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
        // SAFETY: fixed in-bounds fields of the mapped structure.
        unsafe {
            self.w32(CFG_DRIVER_FEATURE_SELECT, 0);
            self.w32(CFG_DRIVER_FEATURE, features as u32);
            self.w32(CFG_DRIVER_FEATURE_SELECT, 1);
            self.w32(CFG_DRIVER_FEATURE, (features >> 32) as u32);
        }
    }

    /// Program one virtqueue's descriptor/driver/device area physical
    /// addresses and enable it, returning its `queue_notify_off`. The three
    /// areas are placed contiguously per [`QueueLayout`] at `ring_paddr`.
    pub fn setup_queue(&self, index: u16, layout: &QueueLayout, ring_paddr: u64) -> u16 {
        // SAFETY: fixed in-bounds fields of the mapped structure; the write
        // order (select, size, addresses, enable) follows the virtio spec.
        unsafe {
            self.w16(CFG_QUEUE_SELECT, index);
            // The device initialises queue_size to its maximum for this queue;
            // the driver must not program a larger size, and a max of 0 means
            // the queue does not exist. Both are device faults at bring-up, so
            // fail visibly rather than program an out-of-contract size.
            let device_max = self.r16(CFG_QUEUE_SIZE);
            assert!(device_max != 0, "device has no virtqueue at this index");
            assert!(
                device_max as usize >= layout.size,
                "device virtqueue smaller than the required layout"
            );
            self.w16(CFG_QUEUE_SIZE, layout.size as u16);
            self.w64(CFG_QUEUE_DESC, ring_paddr + layout.descriptor_offset as u64);
            self.w64(CFG_QUEUE_DRIVER, ring_paddr + layout.driver_offset as u64);
            self.w64(CFG_QUEUE_DEVICE, ring_paddr + layout.device_offset as u64);
            self.w16(CFG_QUEUE_ENABLE, 1);
            self.r16(CFG_QUEUE_NOTIFY_OFF)
        }
    }
}

/// Byte offset of a queue's notify slot within the notify structure:
/// `queue_notify_off * notify_multiplier`.
#[must_use]
pub fn notify_offset_bytes(notify_off: u16, multiplier: u32) -> usize {
    notify_off as usize * multiplier as usize
}

/// Ring the doorbell for `queue` by writing its index to its notify slot.
///
/// # Safety
/// `notify_base` must point to the mapped notify structure in the device BAR,
/// and `notify_off`/`multiplier` must come from the device's notify capability,
/// so the computed slot lies within the mapped region.
pub unsafe fn notify_queue(notify_base: *mut u8, notify_off: u16, multiplier: u32, queue: u16) {
    // Ensure prior descriptor/avail publication is visible before the doorbell.
    fence(Ordering::Release);
    let slot = unsafe {
        notify_base
            .add(notify_offset_bytes(notify_off, multiplier))
            .cast::<u16>()
    };
    unsafe { slot.write_volatile(queue) };
}

#[cfg(test)]
mod tests {
    use super::*;

    // A synthetic 4 KiB config space with a virtio capability chain, used to
    // test the pure capability-walk logic without a device.
    struct FakeConfig {
        bytes: Box<[u8; 4096]>,
    }

    impl FakeConfig {
        fn new() -> Self {
            Self {
                bytes: Box::new([0u8; 4096]),
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
            unsafe { PciConfig::new(self.bytes.as_mut_ptr()) }
        }
        // A `CommonCfg` mapped over this buffer's base, so its register methods
        // can be driven against plain backing memory the test seeds and reads
        // back — the same pointer-into-a-Box pattern the queue tests use.
        fn common(&mut self) -> CommonCfg {
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
    }

    #[test]
    fn finds_all_virtio_structures_in_one_bar() {
        let mut fake = FakeConfig::new();
        fake.w16(PCI_VENDOR_ID as usize, VIRTIO_VENDOR_ID);
        fake.w16(PCI_DEVICE_ID as usize, VIRTIO_NET_DEVICE_ID);
        fake.w16(PCI_STATUS as usize, PCI_STATUS_CAP_LIST);
        fake.bytes[PCI_CAPABILITIES_PTR as usize] = 0x40;
        // common @0x40 -> notify @0x50 -> isr @0x64 -> device @0x74 -> end
        fake.put_cap(0x40, 0x50, VIRTIO_PCI_CAP_COMMON_CFG, 4, 0x0000, 16);
        fake.put_cap(0x50, 0x64, VIRTIO_PCI_CAP_NOTIFY_CFG, 4, 0x3000, 20);
        fake.w32(0x50 + 16, 4); // notify multiplier
        fake.put_cap(0x64, 0x74, VIRTIO_PCI_CAP_ISR_CFG, 4, 0x1000, 16);
        fake.put_cap(0x74, 0x00, VIRTIO_PCI_CAP_DEVICE_CFG, 4, 0x2000, 16);

        let caps = find_virtio_caps(&fake.config()).unwrap();
        assert_eq!(
            caps,
            VirtioCaps {
                bar: 4,
                common: 0x0000,
                notify: 0x3000,
                notify_multiplier: 4,
                isr: 0x1000,
                device: 0x2000,
            }
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
    }

    #[test]
    fn caps_within_bounds_every_offset() {
        let caps = VirtioCaps {
            bar: 4,
            common: 0,
            notify: 0x3000,
            notify_multiplier: 4,
            isr: 0x1000,
            device: 0x2000,
        };
        assert!(caps.within(0x4000));
        // notify at 0x3000 is not within a 0x3000 window.
        assert!(!caps.within(0x3000));
    }

    #[test]
    fn caps_within_rejects_a_structure_that_would_overrun_the_window() {
        // The common structure needs 56 bytes; starting it 32 bytes below the
        // window end must be rejected even though its start offset is in range.
        let caps = VirtioCaps {
            bar: 4,
            common: 0x4000 - 32,
            notify: 0,
            notify_multiplier: 4,
            isr: 0,
            device: 0,
        };
        assert!(!caps.within(0x4000));
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
    fn bar_type_detects_64bit_memory_bars() {
        let mut fake = FakeConfig::new();
        // BAR4: memory (bit0=0), 64-bit (bits[2:1]=0b10), prefetchable (bit3).
        fake.w32(PCI_BAR0 as usize + 4 * 4, 0x0000_000c);
        // BAR2: 32-bit memory BAR.
        fake.w32(PCI_BAR0 as usize + 2 * 4, 0x0000_0000);
        let config = fake.config();
        assert!(config.bar_is_64bit(4));
        assert!(!config.bar_is_64bit(2));
    }

    #[test]
    fn bar_type_rejects_an_io_space_bar() {
        let mut fake = FakeConfig::new();
        // Bit 0 set marks an I/O-space BAR, which is never a 64-bit memory pair.
        fake.w32(PCI_BAR0 as usize + 3 * 4, 0x0000_0001);
        assert!(!fake.config().bar_is_64bit(3));
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
        fake.config().reprogram_bar64(4, 0x5000_0000);
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
        let layout = QueueLayout {
            size: 16,
            descriptor_offset: 0,
            driver_offset: 256,
            device_offset: 296,
            total_bytes: 430,
        };
        let ring_paddr = 0x5000_0000u64;
        let notify_off = fake.common().setup_queue(1, &layout, ring_paddr);

        assert_eq!(notify_off, 7);
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
    #[should_panic(expected = "device has no virtqueue at this index")]
    fn setup_queue_rejects_a_zero_device_queue_size() {
        let mut fake = FakeConfig::new();
        // A device-reported max of 0 means the queue does not exist.
        fake.w16(CFG_QUEUE_SIZE, 0);
        let layout = QueueLayout {
            size: 16,
            descriptor_offset: 0,
            driver_offset: 256,
            device_offset: 296,
            total_bytes: 430,
        };
        let _ = fake.common().setup_queue(0, &layout, 0x5000_0000);
    }

    #[test]
    #[should_panic(expected = "device virtqueue smaller than the required layout")]
    fn setup_queue_rejects_a_device_queue_smaller_than_the_layout() {
        let mut fake = FakeConfig::new();
        // The device offers only 8 descriptors; programming 16 is a protocol
        // violation the driver must refuse.
        fake.w16(CFG_QUEUE_SIZE, 8);
        let layout = QueueLayout {
            size: 16,
            descriptor_offset: 0,
            driver_offset: 256,
            device_offset: 296,
            total_bytes: 430,
        };
        let _ = fake.common().setup_queue(0, &layout, 0x5000_0000);
    }

    #[test]
    fn reset_returns_once_status_reads_zero() {
        let mut fake = FakeConfig::new();
        // The status byte is already zero (a fresh device), so the reset writes
        // zero and observes the acknowledgement immediately without spinning.
        fake.w8(CFG_DEVICE_STATUS, 0);
        fake.common().reset();
        assert_eq!(fake.r8(CFG_DEVICE_STATUS), 0);
    }

    #[test]
    fn notify_queue_writes_the_index_at_the_computed_slot() {
        // A dedicated notify window (separate from config space) large enough to
        // hold the doorbell at offset notify_off * multiplier.
        let mut notify = Box::new([0u8; 256]);
        // SAFETY: the pointer names the whole boxed window, valid for the call,
        // and `3 * 4 = 12` leaves room for a u16 within 256 bytes.
        unsafe { notify_queue(notify.as_mut_ptr(), 3, 4, 1) };
        assert_eq!(u16::from_le_bytes([notify[12], notify[13]]), 1);
        // Nothing was written at the base slot.
        assert_eq!(u16::from_le_bytes([notify[0], notify[1]]), 0);
    }

    #[test]
    fn skips_a_short_vendor_capability() {
        let mut fake = FakeConfig::new();
        fake.w16(PCI_STATUS as usize, PCI_STATUS_CAP_LIST);
        fake.bytes[PCI_CAPABILITIES_PTR as usize] = 0x40;
        // The four real structures live in BAR 4; a trailing vendor cap shorter
        // than 16 bytes names BAR 2. It must be ignored on its length alone: if
        // the short cap were not skipped, recording its BAR would trip
        // MultipleBars instead of resolving cleanly.
        fake.put_cap(0x40, 0x50, VIRTIO_PCI_CAP_COMMON_CFG, 4, 0x0000, 16);
        fake.put_cap(0x50, 0x64, VIRTIO_PCI_CAP_NOTIFY_CFG, 4, 0x3000, 20);
        fake.w32(0x50 + 16, 4);
        fake.put_cap(0x64, 0x74, VIRTIO_PCI_CAP_ISR_CFG, 4, 0x1000, 16);
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
        fake.w16(PCI_STATUS as usize, PCI_STATUS_CAP_LIST);
        fake.bytes[PCI_CAPABILITIES_PTR as usize] = 0x40;
        // A type-5 (PCI_CFG) cap legitimately references another BAR; it is not
        // one of the four mapped structures, so it must not trip MultipleBars.
        fake.put_cap(0x40, 0x50, VIRTIO_PCI_CAP_COMMON_CFG, 4, 0, 16);
        fake.put_cap(0x50, 0x64, VIRTIO_PCI_CAP_NOTIFY_CFG, 4, 0x3000, 20);
        fake.w32(0x50 + 16, 4);
        fake.put_cap(0x64, 0x74, VIRTIO_PCI_CAP_ISR_CFG, 4, 0x1000, 16);
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
}
