//! The layout of the descriptor protection domains exchange over the
//! shared-memory dataplane queues.
//!
//! Faces the byzantine peer protection domain (CONCEPT §7.1): a descriptor read
//! out of a shared region is peer-written input. This crate fixes the ABI only
//! — it validates nothing and accounts nothing.
//!
//! Every field is a little-endian `u32` and no byte-swapping code exists,
//! because x86_64 is the only target (CONCEPT §3): the native image of a
//! `#[repr(C)]` struct of `u32`s already *is* the wire image. The byte-image
//! tests below exist so a port to a big-endian target fails them rather than
//! silently shipping swapped descriptors. That fixes the descriptor as a peer
//! domain reads it, and says nothing about byte order inside packet payloads.

#![cfg_attr(not(test), no_std)]

use core::mem::{align_of, offset_of, size_of};

/// The `len` bytes at `offset` in pool buffer `buffer`.
///
/// `offset` exists so a producer can publish data that does not begin at the
/// buffer's front: on a NIC receive the frame sits behind the device's own
/// header, and handing the descriptor on publishes it without moving a byte.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub buffer: u32,
    pub offset: u32,
    pub len: u32,
}

impl Descriptor {
    pub const ZERO: Self = Self {
        buffer: 0,
        offset: 0,
        len: 0,
    };

    #[must_use]
    pub const fn new(buffer: u32, offset: u32, len: u32) -> Self {
        Self {
            buffer,
            offset,
            len,
        }
    }
}

impl Default for Descriptor {
    fn default() -> Self {
        Self::ZERO
    }
}

// The descriptor crosses protection domains byte for byte, so a field reorder
// or a width change must be a compile error here rather than a silent break of
// the image the peer domain reads.
const _: () = {
    assert!(size_of::<Descriptor>() == 12);
    assert!(align_of::<Descriptor>() == 4);
    assert!(offset_of!(Descriptor, buffer) == 0);
    assert!(offset_of!(Descriptor, offset) == 4);
    assert!(offset_of!(Descriptor, len) == 8);
};

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn zero_matches_default_and_explicit_zero() {
        assert_eq!(Descriptor::default(), Descriptor::ZERO);
        assert_eq!(Descriptor::ZERO, Descriptor::new(0, 0, 0));
    }

    #[test]
    fn descriptor_has_stable_little_endian_byte_layout() {
        // The exact on-wire image the peer PD reads: three little-endian u32s in
        // declaration order. This is the ABI regression test beyond size/align.
        let d = Descriptor::new(0x1122_3344, 0x5566_7788, 0x99AA_BBCC);
        // SAFETY: `Descriptor` is `#[repr(C)]`, `Copy`, and asserted to be 12
        // bytes with no padding, so transmuting it to `[u8; 12]` is sound.
        let bytes: [u8; 12] = unsafe { core::mem::transmute(d) };
        assert_eq!(
            bytes,
            [
                0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xCC, 0xBB, 0xAA, 0x99
            ]
        );
    }

    proptest! {
        /// For any field values, a descriptor round-trips through its wire image:
        /// its fields are exactly the constructor arguments, and its 12-byte
        /// `#[repr(C)]` image is the three fields as little-endian `u32`s in
        /// declaration order — and reconstructing a descriptor from those bytes
        /// yields the original.
        #[test]
        fn descriptor_round_trips_through_its_byte_image(
            buffer in any::<u32>(),
            offset in any::<u32>(),
            len in any::<u32>(),
        ) {
            let descriptor = Descriptor::new(buffer, offset, len);
            prop_assert_eq!(descriptor.buffer, buffer);
            prop_assert_eq!(descriptor.offset, offset);
            prop_assert_eq!(descriptor.len, len);

            // SAFETY: `Descriptor` is `#[repr(C)]`, `Copy`, and asserted to be 12
            // bytes with no padding, so it transmutes to and from `[u8; 12]`.
            let bytes: [u8; 12] = unsafe { core::mem::transmute(descriptor) };
            let mut expected = [0u8; 12];
            expected[0..4].copy_from_slice(&buffer.to_le_bytes());
            expected[4..8].copy_from_slice(&offset.to_le_bytes());
            expected[8..12].copy_from_slice(&len.to_le_bytes());
            prop_assert_eq!(bytes, expected);

            // SAFETY: same `repr(C)`, 12-byte, no-padding guarantee in reverse;
            // any bit pattern is a valid `Descriptor` (three `u32` fields).
            let recovered: Descriptor = unsafe { core::mem::transmute(bytes) };
            prop_assert_eq!(recovered, descriptor);
        }
    }
}
