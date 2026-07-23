//! Shared packet buffers and the owner-side free list.
//!
//! [`BufferPool`] is the contiguous, fixed-size backing store that descriptors
//! index; it lives in memory shared between protection domains, so its layout
//! is a cross-domain ABI. Buffer *ownership* is not expressed in the type
//! system — it cannot be, across a shared-memory boundary — it is a protocol
//! invariant: a buffer is touched only by the domain that currently holds its
//! descriptor. The pool accessors are therefore `unsafe`, and the caller
//! asserts it owns the index.
//!
//! [`FreeList`] is the complement: a domain-local record of which buffers a
//! protection domain currently owns and may hand out. It is ordinary private
//! memory, not shared.

#![cfg_attr(not(test), no_std)]

use core::cell::UnsafeCell;

/// Size in bytes of every buffer in the pool.
pub const BUFFER_SIZE: usize = 2048;

/// A pool of `N` fixed-size buffers shared between protection domains.
#[repr(C)]
pub struct BufferPool<const N: usize> {
    buffers: [UnsafeCell<[u8; BUFFER_SIZE]>; N],
}

// SAFETY: the pool grants no interior access on its own. Every read/write goes
// through the `unsafe` accessors below, whose contract requires the caller to
// currently own the index; ownership is single by the queue protocol, so no
// two domains ever touch the same buffer concurrently.
unsafe impl<const N: usize> Sync for BufferPool<N> {}

impl<const N: usize> BufferPool<N> {
    /// A new, zeroed pool. A zeroed shared region is already a valid pool, so
    /// this exists mainly for host construction.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffers: [const { UnsafeCell::new([0u8; BUFFER_SIZE]) }; N],
        }
    }

    /// The number of buffers in the pool.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Copy `data` into buffer `index`, truncated to [`BUFFER_SIZE`], and return
    /// the number of bytes written.
    ///
    /// # Safety
    /// The caller must currently own `index`, and `index` must be `< N`.
    pub unsafe fn write(&self, index: usize, data: &[u8]) -> u32 {
        let n = if data.len() < BUFFER_SIZE {
            data.len()
        } else {
            BUFFER_SIZE
        };
        let dst = self.buffers[index].get().cast::<u8>();
        // SAFETY: `dst` points to `BUFFER_SIZE` owned bytes and `n <=
        // BUFFER_SIZE`; source and destination do not overlap (distinct
        // allocations).
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, n) };
        n as u32
    }

    /// Copy `data` into buffer `index` starting at `offset`, leaving the rest
    /// of the buffer untouched. A driver uses this to place a device header in
    /// front of an already-DMA'd frame without moving the frame bytes.
    ///
    /// # Safety
    /// The caller must currently own `index`, `index` must be `< N`, and
    /// `offset + data.len()` must be `<= BUFFER_SIZE`.
    pub unsafe fn write_at(&self, index: usize, offset: usize, data: &[u8]) {
        let dst = self.buffers[index].get().cast::<u8>();
        // SAFETY: `offset + data.len() <= BUFFER_SIZE` of owned bytes, so the
        // span is in-bounds; source and destination do not overlap (distinct
        // allocations).
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst.add(offset), data.len()) };
    }

    /// Borrow `len` bytes of buffer `index` starting at `offset`.
    ///
    /// # Safety
    /// The caller must currently own `index`, `index` must be `< N`, and
    /// `offset + len` must be `<= BUFFER_SIZE`. The borrow must end before
    /// ownership of the buffer is released back to the peer.
    pub unsafe fn read(&self, index: usize, offset: usize, len: u32) -> &[u8] {
        let src = self.buffers[index].get().cast::<u8>();
        // SAFETY: `offset + len <= BUFFER_SIZE` of owned, initialised bytes, so
        // the span is in-bounds; the caller owns the buffer for the borrow.
        unsafe { core::slice::from_raw_parts(src.add(offset), len as usize) }
    }
}

impl<const N: usize> Default for BufferPool<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// A domain-local LIFO of the buffer indices a protection domain owns.
///
/// This is private per-domain state, never shared: it records which pool
/// buffers the owning domain is currently free to fill and hand out.
pub struct FreeList<const N: usize> {
    indices: [u32; N],
    top: usize,
}

impl<const N: usize> FreeList<N> {
    /// An empty free list, owning no buffers.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            indices: [0; N],
            top: 0,
        }
    }

    /// A free list owning every buffer index `0..N`.
    #[must_use]
    pub fn full() -> Self {
        let mut list = Self::empty();
        for index in 0..N {
            list.indices[index] = index as u32;
        }
        list.top = N;
        list
    }

    /// Record ownership of `index`. Returns `false` if the list is already full,
    /// which for a correctly accounted pool cannot happen.
    pub fn push(&mut self, index: u32) -> bool {
        if self.top == N {
            return false;
        }
        self.indices[self.top] = index;
        self.top += 1;
        true
    }

    /// Take ownership of one buffer index, or `None` if the domain owns none.
    pub fn pop(&mut self) -> Option<u32> {
        if self.top == 0 {
            return None;
        }
        self.top -= 1;
        Some(self.indices[self.top])
    }

    /// The number of buffers currently owned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.top
    }

    /// Whether the domain currently owns no buffers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.top == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_round_trips_bytes() {
        let pool = BufferPool::<4>::new();
        let payload = [1u8, 2, 3, 4, 5];
        // SAFETY: single-threaded test; we own index 2 for the whole test.
        let len = unsafe { pool.write(2, &payload) };
        assert_eq!(len, 5);
        let bytes = unsafe { pool.read(2, 0, len) };
        assert_eq!(bytes, &payload);
        // A non-zero offset borrows a later span of the same buffer.
        let tail = unsafe { pool.read(2, 2, 3) };
        assert_eq!(tail, &payload[2..5]);
    }

    #[test]
    fn write_at_places_data_mid_buffer_without_touching_the_rest() {
        let pool = BufferPool::<1>::new();
        // SAFETY: single-threaded test; we own index 0 for the whole test.
        unsafe { pool.write(0, &[0xEEu8; 32]) };
        unsafe { pool.write_at(0, 12, &[1, 2, 3]) };
        let bytes = unsafe { pool.read(0, 0, 16) };
        assert_eq!(&bytes[..12], &[0xEE; 12]);
        assert_eq!(&bytes[12..15], &[1, 2, 3]);
        assert_eq!(bytes[15], 0xEE);
    }

    #[test]
    fn write_truncates_to_buffer_size() {
        let pool = BufferPool::<1>::new();
        let oversized = [0xAAu8; BUFFER_SIZE + 100];
        let len = unsafe { pool.write(0, &oversized) };
        assert_eq!(len as usize, BUFFER_SIZE);
    }

    #[test]
    fn full_free_list_owns_every_index_once() {
        let mut list = FreeList::<4>::full();
        assert_eq!(list.len(), 4);
        let mut seen = [false; 4];
        while let Some(index) = list.pop() {
            assert!(!seen[index as usize], "index handed out twice");
            seen[index as usize] = true;
        }
        assert!(list.is_empty());
        assert!(seen.iter().all(|s| *s));
    }

    #[test]
    fn push_beyond_capacity_is_rejected() {
        let mut list = FreeList::<2>::empty();
        assert!(list.push(0));
        assert!(list.push(1));
        assert!(!list.push(2));
        assert_eq!(list.len(), 2);
    }
}
