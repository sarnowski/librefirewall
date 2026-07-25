//! virtio-net data types and constants (virtio 1.0).
//!
//! [`VirtioNetHdr`] is the 12-byte header virtio-net places in front of every
//! packet in both directions, inside the DMA buffer itself. Its sole consumer
//! is `nic_driver_core`, and it consumes exactly two things: [`VirtioNetHdr::LEN`],
//! to skip the header on receive and to reserve room for it on transmit, and
//! [`VirtioNetHdr::TX_NO_OFFLOAD`], the bytes written in front of a transmit
//! frame.
//!
//! # No field is parsed, and that is deliberate
//!
//! Nothing in this system reads a *field* of a received header, and there is
//! no validator for one. Every field describes an offload — segmentation
//! (`gso_type`, `gso_size`, `hdr_len`), checksum placement (`csum_start`,
//! `csum_offset`), or merged receive buffers (`num_buffers`) — and this driver
//! negotiates no offload feature at all, so a conformant device must leave all
//! of them zero. Acting on them would mean trusting a hostile device's
//! description of a buffer it also wrote (CONCEPT §7.1); ignoring them cannot
//! be wrong, because the frame bytes that follow the header stand on their own
//! and are bounded by the length the driver programmed. Each field is
//! therefore documented for what the *device* means by it, not as something
//! this code believes. When an offload feature is negotiated, the field it
//! governs stops being ignorable and gains a validator at that point.
//!
//! On transmit the direction reverses and the driver writes the header, so
//! there is nothing to distrust: [`VirtioNetHdr::TX_NO_OFFLOAD`] is the image
//! of a header with every field zero — no segmentation, no checksum request.
//!
//! Multi-byte fields are little-endian per virtio 1.0. This crate targets
//! x86_64 only, where the native integer layout already equals the wire layout,
//! so the fields are declared as plain integers without byte-swapping; the
//! byte-image tests below pin that equivalence rather than assuming it. The
//! device-status bits live with the transport that writes them, in
//! [`crate::pci`].

use core::mem::{align_of, offset_of, size_of};

/// The per-buffer header virtio-net prepends to every packet in both
/// directions. With virtio 1.0 the `num_buffers` field is always present,
/// fixing the header at 12 bytes.
///
/// The type exists to pin that ABI: its size, alignment, and every field
/// offset are asserted at compile time below, so a reorder or a width change
/// fails the build rather than silently shifting the frame. On receive its
/// fields are deliberately never read — see the module header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VirtioNetHdr {
    /// Bitmask of `VIRTIO_NET_HDR_F_*` the device sets; zero without offloads.
    pub flags: u8,
    /// One of `VIRTIO_NET_HDR_GSO_*`; `NONE` (0) without offloads.
    pub gso_type: u8,
    /// Size of the header the device would have prepended, for GSO.
    pub hdr_len: u16,
    /// Maximum segment size, for GSO.
    pub gso_size: u16,
    /// Offset from packet start at which to begin the checksum.
    pub csum_start: u16,
    /// Offset from `csum_start` at which to store the checksum.
    pub csum_offset: u16,
    /// Number of merged receive buffers this packet spans; always 1 without
    /// `VIRTIO_NET_F_MRG_RXBUF`, which is not negotiated.
    pub num_buffers: u16,
}

impl VirtioNetHdr {
    /// Serialised size of the header in a DMA buffer.
    pub const LEN: usize = size_of::<Self>();

    /// The transmit header for a frame with no offloads requested: every field
    /// zero, which is `gso_type = NONE` and no checksum request.
    ///
    /// This is what the driver writes in front of a frame, so it is the one
    /// place a header's byte image is produced rather than ignored. It is a
    /// plain zero image only because no offload feature is negotiated; a test
    /// below ties it to the serialised form of a zeroed [`VirtioNetHdr`], so
    /// the two cannot drift apart if a field is ever given a non-zero default.
    pub const TX_NO_OFFLOAD: [u8; Self::LEN] = [0; Self::LEN];
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

/// Feature bits negotiated with a virtio-net device.
///
/// Only bits the driver actually acts on are defined. Negotiating a feature
/// changes what the device is permitted to do — accepting one whose behaviour
/// no code implements would let the device legitimately produce buffers this
/// driver cannot handle, so a bit appears here when its handling does.
pub mod features {
    /// virtio 1.0 (non-legacy) device. Mandatory for the modern layout this
    /// transport programs, and the one feature the driver requires.
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The header's DMA byte image, which is what the device actually reads or
    /// writes. Production never serialises a populated header — the whole point
    /// of the module — so the conversion lives here, where it exists to *prove*
    /// the ABI rather than to be relied on.
    fn image(header: &VirtioNetHdr) -> [u8; VirtioNetHdr::LEN] {
        // SAFETY: `VirtioNetHdr` is `#[repr(C)]` with 12 bytes of fields and no
        // padding (asserted above: the u8 pair fills offsets 0..2, and every
        // u16 is 2-byte aligned through offset 10), so all `LEN` bytes at the
        // header's address are initialised and readable as plain bytes.
        let bytes = unsafe {
            core::slice::from_raw_parts(core::ptr::from_ref(header).cast::<u8>(), VirtioNetHdr::LEN)
        };
        bytes.try_into().expect("the slice is exactly LEN bytes")
    }

    /// Rebuild a header from its DMA byte image, so a round-trip can assert the
    /// image carries every field losslessly and in the right place.
    fn from_image(bytes: &[u8; VirtioNetHdr::LEN]) -> VirtioNetHdr {
        // SAFETY: `VirtioNetHdr` has no padding and no invalid bit patterns
        // (every field is a plain integer), so any 12 bytes are a valid value;
        // `read_unaligned` imposes no alignment requirement on `bytes`.
        unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<VirtioNetHdr>()) }
    }

    #[test]
    fn the_byte_image_places_every_field_little_endian_at_its_wire_offset() {
        // Distinct values per field so a swapped pair or a wrong offset cannot
        // pass, and multi-byte values whose halves differ so a byte-order slip
        // is visible.
        let header = VirtioNetHdr {
            flags: 0x11,
            gso_type: 0x22,
            hdr_len: 0x4433,
            gso_size: 0x6655,
            csum_start: 0x8877,
            csum_offset: 0xAA99,
            num_buffers: 0xCCBB,
        };
        assert_eq!(
            image(&header),
            [
                0x11, // flags
                0x22, // gso_type
                0x33, 0x44, // hdr_len, little-endian
                0x55, 0x66, // gso_size
                0x77, 0x88, // csum_start
                0x99, 0xAA, // csum_offset
                0xBB, 0xCC, // num_buffers
            ]
        );
    }

    #[test]
    fn the_transmit_header_is_the_image_of_a_zeroed_header() {
        // `TX_NO_OFFLOAD` is written into a live DMA buffer, so it must be a
        // real header and not merely twelve zero bytes that happen to be the
        // right length.
        assert_eq!(VirtioNetHdr::TX_NO_OFFLOAD, image(&VirtioNetHdr::default()));
        assert_eq!(VirtioNetHdr::TX_NO_OFFLOAD.len(), VirtioNetHdr::LEN);
    }

    #[test]
    fn the_header_length_is_the_virtio_1_0_twelve_bytes() {
        // The receive path skips exactly this many bytes and the transmit path
        // reserves exactly this many, so the constant is the ABI, not a hint.
        assert_eq!(VirtioNetHdr::LEN, 12);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Any field combination survives the DMA byte image unchanged: the
        /// device and this driver must read the same 12 bytes the same way,
        /// whatever a hostile device puts in them.
        #[test]
        fn the_byte_image_round_trips_every_field(
            flags in any::<u8>(),
            gso_type in any::<u8>(),
            hdr_len in any::<u16>(),
            gso_size in any::<u16>(),
            csum_start in any::<u16>(),
            csum_offset in any::<u16>(),
            num_buffers in any::<u16>(),
        ) {
            let header = VirtioNetHdr {
                flags,
                gso_type,
                hdr_len,
                gso_size,
                csum_start,
                csum_offset,
                num_buffers,
            };
            let bytes = image(&header);
            prop_assert_eq!(from_image(&bytes), header);
            // Each multi-byte field sits little-endian at its own offset, so
            // the image is the wire form and not merely self-consistent.
            prop_assert_eq!(&bytes[2..4], &hdr_len.to_le_bytes());
            prop_assert_eq!(&bytes[4..6], &gso_size.to_le_bytes());
            prop_assert_eq!(&bytes[6..8], &csum_start.to_le_bytes());
            prop_assert_eq!(&bytes[8..10], &csum_offset.to_le_bytes());
            prop_assert_eq!(&bytes[10..12], &num_buffers.to_le_bytes());
        }
    }
}
