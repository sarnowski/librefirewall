//! virtio-net data types and constants (virtio 1.0).
//!
//! # Why no field of a received header is interpreted
//!
//! Every field of [`VirtioNetHdr`] describes an offload — segmentation
//! (`gso_type`, `gso_size`, `hdr_len`), checksum placement (`csum_start`,
//! `csum_offset`), or merged receive buffers (`num_buffers`) — so a conformant
//! device leaves all of them zero until the governing feature is negotiated.
//! Acting on one would mean trusting a hostile device's description of a
//! buffer it also wrote (CONCEPT §7.1); ignoring it cannot be wrong, because
//! the frame bytes following the header stand on their own and are bounded by
//! the length the driver programmed. Negotiating an offload feature is what
//! makes the field it governs need a validator.
//!
//! Multi-byte fields are little-endian per virtio 1.0. x86_64 is the only
//! target (CONCEPT §3) and its native integer layout already equals the wire
//! layout, so the fields are plain integers with no byte-swapping.

use core::mem::{align_of, offset_of, size_of};

/// The header virtio-net places in front of every packet in both directions,
/// inside the DMA buffer itself. virtio 1.0 always carries `num_buffers`,
/// which is what fixes the size at 12 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

impl VirtioNetHdr {
    pub const LEN: usize = size_of::<Self>();

    /// The transmit header the driver writes in front of a frame: a plain zero
    /// image only because no offload feature is negotiated, every field being
    /// the request for one.
    pub const TX_NO_OFFLOAD: [u8; Self::LEN] = [0; Self::LEN];
}

// The header is DMA'd verbatim to and from the device, so its layout is a wire
// ABI and not a Rust struct's business: a reorder or a width change has to fail
// the build rather than silently shift the frame.
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
/// A bit is defined here only once code implements its behaviour: negotiating
/// a feature widens what the device is permitted to do, so accepting one that
/// nothing handles would let it legitimately produce buffers this driver
/// cannot.
pub mod features {
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The header's DMA byte image. Production never serialises a populated
    /// header, so the conversion lives here, where it exists to prove the ABI
    /// rather than to be relied on.
    fn image(header: &VirtioNetHdr) -> [u8; VirtioNetHdr::LEN] {
        // SAFETY: the offset assertions above leave `VirtioNetHdr` no padding —
        // the `u8` pair fills 0..2 and every `u16` is 2-aligned through offset
        // 10 — so all `LEN` bytes at the header's address are initialised and
        // readable as plain bytes.
        let bytes = unsafe {
            core::slice::from_raw_parts(core::ptr::from_ref(header).cast::<u8>(), VirtioNetHdr::LEN)
        };
        bytes.try_into().expect("the slice is exactly LEN bytes")
    }

    fn from_image(bytes: &[u8; VirtioNetHdr::LEN]) -> VirtioNetHdr {
        // SAFETY: every field is a plain integer, so no bit pattern is invalid
        // and the padding-free layout asserted above makes any 12 bytes a valid
        // value; `read_unaligned` imposes no alignment on `bytes`.
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
