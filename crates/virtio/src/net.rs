//! virtio-net data types and constants (virtio 1.0).
//!
//! These are the in-DMA structures and negotiation constants a driver programs
//! and parses; the logic that uses them lives in the driver protection domain.
//! Only the pieces the current Rx/Tx path needs are defined here; offload and
//! control-queue fields are added when their feature is implemented.
//!
//! Multi-byte fields are little-endian per virtio 1.0. This crate targets
//! x86_64 only, where the native integer layout already equals the wire layout,
//! so the fields are declared as plain integers without byte-swapping. The
//! device-status bits live with the transport that writes them, in [`crate::pci`].

use core::mem::{align_of, offset_of, size_of};

/// The per-buffer header virtio-net prepends to every packet in both
/// directions. With virtio 1.0 the `num_buffers` field is always present,
/// fixing the header at 12 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VirtioNetHdr {
    /// Bitmask of `VIRTIO_NET_HDR_F_*`.
    pub flags: u8,
    /// One of `VIRTIO_NET_HDR_GSO_*`.
    pub gso_type: u8,
    /// Size of the header to prepend, for GSO.
    pub hdr_len: u16,
    /// Maximum segment size, for GSO.
    pub gso_size: u16,
    /// Offset from packet start at which to begin the checksum.
    pub csum_start: u16,
    /// Offset from `csum_start` at which to store the checksum.
    pub csum_offset: u16,
    /// Number of merged receive buffers this packet spans.
    pub num_buffers: u16,
}

impl VirtioNetHdr {
    /// Serialised size of the header in a DMA buffer.
    pub const LEN: usize = size_of::<Self>();
}

// The header is DMA'd verbatim to and from the device, so its layout is a fixed
// ABI: exactly the 12-byte virtio 1.0 form, with every field pinned at its wire
// offset so a field reorder or width change is a compile error.
const _: () = {
    assert!(size_of::<VirtioNetHdr>() == 12);
    assert!(align_of::<VirtioNetHdr>() == 2);
    assert!(offset_of!(VirtioNetHdr, flags) == 0);
    assert!(offset_of!(VirtioNetHdr, gso_type) == 1);
    assert!(offset_of!(VirtioNetHdr, hdr_len) == 2);
    assert!(offset_of!(VirtioNetHdr, gso_size) == 4);
    assert!(offset_of!(VirtioNetHdr, csum_start) == 6);
    assert!(offset_of!(VirtioNetHdr, csum_offset) == 8);
    assert!(offset_of!(VirtioNetHdr, num_buffers) == 10);
};

/// Feature bits negotiated with a virtio-net device (the subset the driver
/// negotiates today).
pub mod features {
    /// Device provides a MAC address in config space.
    pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
    /// virtio 1.0 (non-legacy) device. Mandatory for the modern layout.
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
}
