//! Wire types shared across protection domains.
//!
//! A [`Descriptor`] is the unit of ownership transfer on the dataplane: it
//! names one buffer in the shared pool and how many bytes of it are valid. It
//! is the element type of the shared-memory queues, so its layout is part of
//! the cross-protection-domain ABI and is asserted below.

#![cfg_attr(not(test), no_std)]

use core::mem::{align_of, size_of};

/// A reference to a span of one pool buffer moving through a queue.
///
/// `buffer` indexes the shared buffer pool, and the valid data is the `len`
/// bytes starting at `offset` within that buffer. The offset lets a producer
/// hand over data that does not start at the buffer's front — for a NIC
/// receive that is the frame after the device's header, published zero-copy
/// without moving the bytes. Holding a descriptor is what "owning" the buffer
/// means. The value is deliberately `Copy`: the ring moves it by value, and
/// single ownership is enforced by the queue protocol, not by the borrow
/// checker, which cannot reach across the shared-memory boundary.
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

// The descriptor is copied verbatim between protection domains, so its size and
// alignment are a fixed ABI rather than an implementation detail.
const _: () = assert!(size_of::<Descriptor>() == 12);
const _: () = assert!(align_of::<Descriptor>() == 4);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_default() {
        assert_eq!(Descriptor::default(), Descriptor::ZERO);
        assert_eq!(Descriptor::ZERO, Descriptor::new(0, 0, 0));
    }

    #[test]
    fn fields_round_trip() {
        let d = Descriptor::new(7, 12, 42);
        assert_eq!(d.buffer, 7);
        assert_eq!(d.offset, 12);
        assert_eq!(d.len, 42);
    }
}
