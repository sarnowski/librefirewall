//! virtio-blk device class: bring-up over the [`virtio`] PCI transport
//! ([`bringup`]), the request state machine that turns block reads, writes and
//! flushes into descriptor chains on one virtqueue ([`request`]), the bounded
//! staging window those requests name their buffers in ([`io`]), and the
//! boot-time proof that the whole path reaches a real medium ([`smoke`]).
//!
//! The protection domain that drives persistent storage is a thin adapter: it
//! maps the regions its system description grants it, runs the handshake, and
//! loops over submit and poll. The logic lives here instead because welded to
//! the Microkit entrypoint none of it could be reached by a host test — the
//! same split, and for the same reason, as `nic-driver-core`.
//!
//! # The adversary
//!
//! CONCEPT §7.1's **hostile or malfunctioning device**. Every byte this crate
//! reads is the device's: the configuration-space ids, the capability chain,
//! the feature bitmap, the `device_status` readback, the queue count, the
//! `capacity` in its device-configuration structure, the used-ring completions,
//! and the status byte it writes into the DMA region at the end of every
//! request. A merely broken device produces the same bytes as a malicious one,
//! so both are answered the same way: a typed error naming the cause, never a
//! panic. Two of those bytes deserve naming, because believing either is a
//! memory-safety fault rather than a wrong answer — the `capacity` bounds every
//! sector range this driver will let a caller name, and the used-ring
//! descriptor index decides which slot's status byte is read.
//!
//! # Constraints that shaped it
//!
//! The dependency set is exactly [`virtio`]. A refusal reaches an operator as a
//! console record, which elsewhere means `lfw_log::Refusal`; depending on that
//! crate for one struct would pull the whole log vocabulary into a device-class
//! layer, so [`Refusal`] is declared here and a protection domain converts it.
//! Page granularity is likewise a literal rather than a `wire` dependency.
//!
//! The driver accepts exactly one feature bit while *observing* two more. The
//! two are not the same act: accepting a bit changes what the device is
//! permitted to produce, whereas observing one tells the caller a fact about
//! the device it must not guess. [`bringup::ACCEPTED_FEATURES`] and
//! [`bringup::Live::flush_supported`] are the two halves.

#![cfg_attr(not(test), no_std)]

pub mod bringup;
pub mod io;
pub mod request;
pub mod smoke;

use request::RequestHeader;
use virtio::queue::SplitVirtqueue;

/// The virtqueue index of a virtio-blk device's single request queue, fixed by
/// the specification.
pub const BLK_QUEUE: u16 = 0;

/// Descriptors in that virtqueue: a driver constant rather than the
/// device-reported maximum, so a loop bounded by it is bounded by a value the
/// adversary does not choose (ENG-4). QEMU's virtio-blk reports 256 and this
/// programs 16, which is what [`virtio::pci::CommonCfg::setup_queue`] checks
/// against.
pub const QUEUE_SIZE: usize = 16;

/// A block, in bytes. Fixed by virtio 1.0 §5.2 for every virtio-blk device
/// regardless of the `blk_size` it may report, which describes its preferred
/// I/O granularity and not the unit `sector` counts in.
pub const SECTOR_SIZE: usize = 512;

pub type BlkVirtqueue = SplitVirtqueue<QUEUE_SIZE>;

/// Size of the device MMIO BAR window a driver protection domain maps, the
/// bound every device-supplied BAR offset is checked against, and the alignment
/// [`bringup::Identified::place_bar`] requires of the address the BAR is
/// relocated to — so the mapped window and the decoded window describe the same
/// bytes.
///
/// **Cross-artifact (DOC-7):** it must equal the `size` attribute of `bar3` in
/// `systems/qemu-x86_64/librefirewall.system`, whose enforcer is
/// `xtask::sysdesc` — it reads the description back and holds it to this
/// constant, as it already does for `nic_driver_core`'s `BAR_WINDOW_SIZE`.
pub const BAR_WINDOW_SIZE: usize = 0x4000;

/// Microkit's mapping granularity. `wire::PAGE_SIZE` is the same number, and
/// this crate declines to depend on `wire` for one integer.
const PAGE_SIZE: usize = 0x1000;

/// Byte offset of the per-slot request headers within the DMA region. Placed
/// after the virtqueue and aligned for [`RequestHeader`], whose `u64` sector
/// field is what fixes the eight bytes.
const HEADER_AREA_OFFSET: usize = 0x200;

/// Byte offset of the per-slot status bytes within the DMA region.
const STATUS_AREA_OFFSET: usize = 0x280;

/// Size of the DMA region a driver protection domain maps and programs into the
/// device.
///
/// One page, which is the smallest a Microkit mapping comes in and already
/// three times what the layout needs: the virtqueue's 430 bytes at offset 0,
/// [`request::SLOTS`] sixteen-byte headers at [`HEADER_AREA_OFFSET`], and
/// [`request::SLOTS`] status bytes at [`STATUS_AREA_OFFSET`], ending at 0x288.
/// The assertions below are what hold that arithmetic rather than this
/// sentence.
///
/// **Cross-artifact (DOC-7):** as [`BAR_WINDOW_SIZE`], for `blk_dma`.
pub const DMA_REGION_SIZE: usize = 0x1000;

/// Size of the DMA-visible staging region the recorder protection domain reads
/// and writes the device through — the bytes a request's data segment names.
///
/// Held apart from [`DMA_REGION_SIZE`], which carries this driver's own
/// bookkeeping: the virtqueue, the per-slot headers and the status bytes. This
/// one carries *payload*, so it is sized by how much a caller may have in flight
/// rather than by a layout, and it can grow with the recording workload without
/// moving an offset the request protocol is stated in. 256 KiB, which is
/// [`io::IO_SECTORS`] sectors.
///
/// **Cross-artifact (DOC-7):** as [`BAR_WINDOW_SIZE`], for `blk_io`.
pub const BLK_IO_REGION_SIZE: usize = 0x40000;

// The region layout, decided when the program is compiled rather than argued
// about in prose. Together these are what every offset `request::SlotIndex`
// derives rests on: a slot is `< SLOTS` by construction, so its header and
// status both lie inside the region by arithmetic.
const _: () = assert!(
    BlkVirtqueue::LAYOUT.total_bytes <= HEADER_AREA_OFFSET,
    "the header area overlaps the virtqueue"
);
const _: () = assert!(
    HEADER_AREA_OFFSET.is_multiple_of(align_of::<RequestHeader>()),
    "a slot header is not aligned for the type whose image it holds"
);
const _: () = assert!(
    HEADER_AREA_OFFSET + request::SLOTS * RequestHeader::LEN <= STATUS_AREA_OFFSET,
    "the status area overlaps the last slot's header"
);
const _: () = assert!(
    STATUS_AREA_OFFSET + request::SLOTS <= DMA_REGION_SIZE,
    "the last slot's status byte runs past the DMA region"
);
const _: () = assert!(
    DMA_REGION_SIZE.is_multiple_of(PAGE_SIZE),
    "the DMA region is not a whole number of mapped pages"
);
const _: () = assert!(
    BAR_WINDOW_SIZE.is_multiple_of(PAGE_SIZE),
    "the BAR window is not a whole number of mapped pages"
);
const _: () = assert!(
    BLK_IO_REGION_SIZE.is_multiple_of(PAGE_SIZE),
    "the staging region is not a whole number of mapped pages"
);
// Without this, no device-named offset could ever pass `VirtioCaps::within`.
const _: () = assert!(virtio::pci::COMMON_CFG_MIN_LEN <= BAR_WINDOW_SIZE);

/// Why a domain refused to bring its block device up, and what that left the
/// device in.
///
/// A structural copy of `lfw_log::Refusal`, declared here so this crate's
/// dependency set stays [`virtio`] alone: the field names and meanings match,
/// so a protection domain that already depends on the log vocabulary converts
/// one into the other field by field. The `cause` is deliberately a token
/// rather than an enum, for the reason `lfw_log` gives: the refusal tree
/// belongs to the crate that raises it, and a second copy of this one beside
/// the event vocabulary would go stale with nothing failing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// What was refused, as a console token.
    pub cause: &'static str,
    /// The numbers `cause` names, in the order it names them.
    pub detail: RefusalDetail,
    /// Whether the device was told to stop, or was left decoding nothing.
    pub signalled: bool,
}

/// Up to two numbers a [`Refusal`] carries, so it reaches an operator as the
/// values that made it one and not only as its class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalDetail {
    None,
    One(u64),
    Two(u64, u64),
}
