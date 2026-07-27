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
//!
//! The verdict rides in the descriptor because a domain that decides against a
//! frame cannot return its buffer: a return is a produce on a free ring that
//! already has one producer. One `u32` moves the decision to the domain that
//! owns that producer, and costs no new grant.

#![cfg_attr(not(test), no_std)]

use core::mem::{align_of, offset_of, size_of};

/// The producing domain's decision about the frame a [`Descriptor`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Transmit,
    /// The buffer goes back to its owner unread.
    Discard,
}

impl Verdict {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Transmit => 0,
            Self::Discard => 1,
        }
    }

    /// `None` for every other bit pattern: the field is peer-written, so an
    /// undecodable value is input to reject rather than one to coerce.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Transmit),
            1 => Some(Self::Discard),
            _ => None,
        }
    }
}

/// The `len` bytes at `offset` in pool buffer `buffer`, and the verdict on them.
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
    /// The producing domain's [`Verdict`] as raw bits — this crate fixes the
    /// ABI and validates nothing, so the consumer decodes and may refuse it.
    pub verdict: u32,
}

impl Descriptor {
    pub const ZERO: Self = Self {
        buffer: 0,
        offset: 0,
        len: 0,
        verdict: 0,
    };

    /// Takes a [`Verdict`] rather than bits, so only a peer writing the shared
    /// word directly can mint a descriptor its consumer cannot decode.
    #[must_use]
    pub const fn new(buffer: u32, offset: u32, len: u32, verdict: Verdict) -> Self {
        Self {
            buffer,
            offset,
            len,
            verdict: verdict.to_bits(),
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
    assert!(size_of::<Descriptor>() == 16);
    assert!(align_of::<Descriptor>() == 4);
    assert!(offset_of!(Descriptor, buffer) == 0);
    assert!(offset_of!(Descriptor, offset) == 4);
    assert!(offset_of!(Descriptor, len) == 8);
    assert!(offset_of!(Descriptor, verdict) == 12);
    // Transmit is zero, so a zeroed region is still the valid empty state.
    assert!(Verdict::Transmit.to_bits() == 0);
};

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Either verdict, so a property covers both encodable values.
    fn any_verdict() -> impl Strategy<Value = Verdict> {
        prop_oneof![Just(Verdict::Transmit), Just(Verdict::Discard)]
    }

    #[test]
    fn zero_matches_default_and_explicit_zero() {
        assert_eq!(Descriptor::default(), Descriptor::ZERO);
        assert_eq!(
            Descriptor::ZERO,
            Descriptor::new(0, 0, 0, Verdict::Transmit)
        );
    }

    #[test]
    fn descriptor_has_stable_little_endian_byte_layout() {
        // The exact on-wire image the peer PD reads: four little-endian u32s in
        // declaration order. This is the ABI regression test beyond size/align.
        let d = Descriptor::new(0x1122_3344, 0x5566_7788, 0x99AA_BBCC, Verdict::Discard);
        // SAFETY: `Descriptor` is `#[repr(C)]`, `Copy`, and asserted to be 16
        // bytes with no padding, so transmuting it to `[u8; 16]` is sound.
        let bytes: [u8; 16] = unsafe { core::mem::transmute(d) };
        assert_eq!(
            bytes,
            [
                0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xCC, 0xBB, 0xAA, 0x99, 0x01, 0x00,
                0x00, 0x00
            ]
        );
    }

    proptest! {
        /// For any field values, a descriptor round-trips through its wire image:
        /// its fields are exactly the constructor arguments, and its 16-byte
        /// `#[repr(C)]` image is the four fields as little-endian `u32`s in
        /// declaration order — and reconstructing a descriptor from those bytes
        /// yields the original.
        #[test]
        fn descriptor_round_trips_through_its_byte_image(
            buffer in any::<u32>(),
            offset in any::<u32>(),
            len in any::<u32>(),
            verdict in any_verdict(),
        ) {
            let descriptor = Descriptor::new(buffer, offset, len, verdict);
            prop_assert_eq!(descriptor.buffer, buffer);
            prop_assert_eq!(descriptor.offset, offset);
            prop_assert_eq!(descriptor.len, len);
            prop_assert_eq!(Verdict::from_bits(descriptor.verdict), Some(verdict));

            // SAFETY: `Descriptor` is `#[repr(C)]`, `Copy`, and asserted to be 16
            // bytes with no padding, so it transmutes to and from `[u8; 16]`.
            let bytes: [u8; 16] = unsafe { core::mem::transmute(descriptor) };
            let mut expected = [0u8; 16];
            expected[0..4].copy_from_slice(&buffer.to_le_bytes());
            expected[4..8].copy_from_slice(&offset.to_le_bytes());
            expected[8..12].copy_from_slice(&len.to_le_bytes());
            expected[12..16].copy_from_slice(&verdict.to_bits().to_le_bytes());
            prop_assert_eq!(bytes, expected);

            // SAFETY: same `repr(C)`, 16-byte, no-padding guarantee in reverse;
            // any bit pattern is a valid `Descriptor` (four `u32` fields).
            let recovered: Descriptor = unsafe { core::mem::transmute(bytes) };
            prop_assert_eq!(recovered, descriptor);
        }

        /// The verdict word is peer-written, so decoding is total over `u32`:
        /// exactly the values `to_bits` can produce decode, every other one is
        /// refused rather than coerced to a variant nobody chose.
        #[test]
        fn from_bits_accepts_exactly_what_to_bits_produces(bits in any::<u32>()) {
            let expected = [Verdict::Transmit, Verdict::Discard]
                .into_iter()
                .find(|verdict| verdict.to_bits() == bits);
            prop_assert_eq!(Verdict::from_bits(bits), expected);
            if let Some(verdict) = Verdict::from_bits(bits) {
                prop_assert_eq!(verdict.to_bits(), bits);
            }
        }
    }
}
