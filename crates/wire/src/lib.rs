//! Wire types shared across protection domains.
//!
//! A [`Descriptor`] is the unit of ownership transfer on the dataplane: it
//! names one buffer in the shared pool and how many bytes of it are valid. It
//! is the element type of the shared-memory queues, so its layout is part of
//! the cross-protection-domain ABI and is asserted below.
//!
//! A descriptor received from a peer is **untrusted**: its `buffer`, `offset`,
//! and `len` must be range-validated by the receiver before the buffer they
//! name is touched (`pd_runtime::descriptor_in_bounds`, backstopped by the
//! `packet-buffer` accessors' own span checks). This crate defines the ABI; it
//! does not enforce that validation, and it does not account ownership either
//! — see [`Descriptor`].
//!
//! # Byte order
//!
//! Every field is a **little-endian** `u32`, and the type carries no
//! byte-swapping code because none is needed: the project targets x86_64
//! exclusively (CONCEPT §3), so the native representation of a `#[repr(C)]`
//! struct of `u32`s already *is* the wire image. That is a deliberate
//! consequence of the single-architecture decision rather than an oversight, and
//! it is pinned by the byte-image tests below, so a future port to a big-endian
//! target would fail them rather than silently ship swapped descriptors.
//!
//! The rule applies to the descriptor as it sits in a shared region, which is
//! also how a peer protection domain reads it. It says nothing about network
//! byte order in packet *payloads*: those are parsed by the protocol crates,
//! which convert explicitly.

#![cfg_attr(not(test), no_std)]

use core::mem::{align_of, offset_of, size_of};

/// A reference to a span of one pool buffer moving through a queue.
///
/// `buffer` indexes the shared buffer pool, and the valid data is the `len`
/// bytes starting at `offset` within that buffer. The offset lets a producer
/// hand over data that does not start at the buffer's front — for a NIC
/// receive that is the frame after the device's header, published zero-copy
/// without moving the bytes. Handing a descriptor on is what transferring the
/// buffer means.
///
/// The value is deliberately `Copy`, which means **holding one proves nothing
/// about ownership**: enqueuing a descriptor leaves the producer with an
/// identical value, and a descriptor in a ring is bytes on shared memory that a
/// byzantine peer can write, so neither the borrow checker nor the queue
/// protocol can make single ownership a property of this type — the `queue`
/// crate explicitly disclaims it. What actually accounts ownership is the
/// pool owner's ledger, `packet_buffer::FreeList`, which tracks buffers by
/// identity and refuses to reclaim an index that is out of range or not
/// outstanding, together with `pd_runtime::PoolOwner`, which additionally
/// refuses an index it never lent out. This type is the message; those two are
/// the accounting.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// Index of the owned buffer within the shared pool.
    pub buffer: u32,
    /// Byte offset of the valid data within the buffer.
    pub offset: u32,
    /// Number of valid bytes at `offset`.
    pub len: u32,
}

impl Descriptor {
    /// The all-zero descriptor. Also the value of a freshly zeroed queue slot,
    /// which is why a zeroed shared region is a valid empty ring.
    pub const ZERO: Self = Self {
        buffer: 0,
        offset: 0,
        len: 0,
    };

    /// A descriptor naming `len` valid bytes at `offset` within pool `buffer`.
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

// The descriptor is copied verbatim between protection domains, so its size,
// alignment, and field offsets are a fixed ABI rather than an implementation
// detail: a field reorder or width change is a compile error here, not a silent
// break of the mapping the peer PD reads.
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
