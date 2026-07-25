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
//!
//! # Untrusted indices
//!
//! A [`wire::Descriptor`] arriving from a peer PD carries a `buffer` index,
//! `offset`, and `len` that are **untrusted**. Nothing in this crate validates
//! them for you: the `unsafe` accessors trust their arguments, so a caller
//! handling a peer descriptor must range-check it (`buffer < N`,
//! `offset + len <= BUFFER_SIZE`) before calling in. Feeding an unvalidated
//! peer index to [`FreeList::push`] likewise breaks the single-owner invariant;
//! `push` is the point where the caller must already have validated the index.
//!
//! # Buffer size and DMA alignment
//!
//! [`BUFFER_SIZE`] is 2048 — a power of two large enough for a 1518-byte
//! Ethernet frame plus the virtio-net header and headroom. Jumbo frames are
//! deliberately unsupported; an oversized write is truncated, never allowed to
//! overrun. The pool's own `align_of` is 1, because per-buffer DMA alignment
//! comes from *placement*, not the struct: the shared region is mapped at a
//! page-aligned physical address, and the fixed 2048-byte stride keeps every
//! buffer 2048-aligned from that base — enough for NIC DMA without over-aligning
//! the type.

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

// The pool is a cross-domain shared-memory ABI: `N` buffers of `BUFFER_SIZE`,
// tightly packed, byte-aligned as a type (placement supplies DMA alignment).
const _: () = {
    assert!(core::mem::size_of::<BufferPool<4>>() == 4 * BUFFER_SIZE);
    assert!(core::mem::align_of::<BufferPool<4>>() == 1);
};

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
    /// The caller must currently own `index` (single-owner protocol), and
    /// `data` must not borrow from this pool (it aliases otherwise — see
    /// [`read`](Self::read)). `index < N` is checked and panics if violated; it
    /// is not a soundness precondition.
    #[must_use = "write truncates to BUFFER_SIZE; a dropped count hides silent truncation"]
    pub unsafe fn write(&self, index: usize, data: &[u8]) -> u32 {
        let n = if data.len() < BUFFER_SIZE {
            data.len()
        } else {
            BUFFER_SIZE
        };
        let dst = self.buffers[index].get().cast::<u8>();
        // SAFETY: `dst` points to `BUFFER_SIZE` owned bytes and `n <=
        // BUFFER_SIZE`, so the write is in bounds. The caller's contract
        // guarantees `data` does not alias this pool, so the ranges are
        // non-overlapping as `copy_nonoverlapping` requires.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, n) };
        n as u32
    }

    /// Copy `data` into buffer `index` starting at `offset`, leaving the rest
    /// of the buffer untouched. A driver uses this to place a device header in
    /// front of an already-DMA'd frame without moving the frame bytes.
    ///
    /// # Safety
    /// The caller must currently own `index`, `data` must not borrow from this
    /// pool, and `offset + data.len()` must be `<= BUFFER_SIZE` (this span bound
    /// is a genuine soundness precondition — violating it is out-of-bounds).
    /// `index < N` is checked and panics if violated.
    pub unsafe fn write_at(&self, index: usize, offset: usize, data: &[u8]) {
        debug_assert!(
            offset + data.len() <= BUFFER_SIZE,
            "write_at span exceeds buffer"
        );
        let dst = self.buffers[index].get().cast::<u8>();
        // SAFETY: the caller's contract guarantees `offset + data.len() <=
        // BUFFER_SIZE` owned bytes, so the destination span is in bounds, and
        // that `data` does not alias this pool, so the ranges do not overlap.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst.add(offset), data.len()) };
    }

    /// Borrow `len` bytes of buffer `index` starting at `offset`.
    ///
    /// # Safety
    /// The caller must currently own `index`, and `offset + len` must be
    /// `<= BUFFER_SIZE` (a genuine soundness precondition). The returned borrow
    /// must end before ownership of the buffer is released to the peer, and no
    /// write to this buffer may occur while the borrow is live. `index < N` is
    /// checked and panics if violated.
    pub unsafe fn read(&self, index: usize, offset: usize, len: u32) -> &[u8] {
        debug_assert!(
            offset + len as usize <= BUFFER_SIZE,
            "read span exceeds buffer"
        );
        let src = self.buffers[index].get().cast::<u8>();
        // SAFETY: the caller's contract guarantees `offset + len <= BUFFER_SIZE`
        // owned, initialised bytes, so the span is in bounds, and that the
        // buffer is owned and not concurrently written for the borrow's life.
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

    /// Record ownership of `index`.
    ///
    /// The caller must have validated `index` against the pool before calling:
    /// `push` is the trust boundary for the single-owner invariant, not a
    /// validator. Returns `false` if the list is already full, which for a
    /// correctly accounted pool cannot happen and signals an accounting bug the
    /// caller must surface rather than ignore.
    #[must_use = "a full free list signals a buffer-accounting bug that must be surfaced"]
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
    use proptest::prelude::*;

    #[test]
    fn write_then_read_round_trips_bytes() {
        let pool = BufferPool::<4>::new();
        let payload = [1u8, 2, 3, 4, 5];
        // SAFETY: single-threaded test; we own index 2 for the whole test, and
        // `payload` is a local that does not borrow from the pool.
        let len = unsafe { pool.write(2, &payload) };
        assert_eq!(len, 5);
        // SAFETY: own index 2; no live borrow into it while we read.
        let bytes = unsafe { pool.read(2, 0, len) };
        assert_eq!(bytes, &payload);
        // SAFETY: as above; a non-zero offset just borrows a later span.
        let tail = unsafe { pool.read(2, 2, 3) };
        assert_eq!(tail, &payload[2..5]);
    }

    #[test]
    fn write_at_places_data_mid_buffer_without_touching_the_rest() {
        let pool = BufferPool::<1>::new();
        // SAFETY: single-threaded test; we own index 0 throughout; inputs local.
        unsafe {
            let _ = pool.write(0, &[0xEEu8; 32]);
            pool.write_at(0, 12, &[1, 2, 3]);
        }
        // SAFETY: own index 0; no live borrow into it while we read.
        let bytes = unsafe { pool.read(0, 0, 16) };
        assert_eq!(&bytes[..12], &[0xEE; 12]);
        assert_eq!(&bytes[12..15], &[1, 2, 3]);
        assert_eq!(bytes[15], 0xEE);
    }

    #[test]
    fn write_truncates_to_buffer_size() {
        let pool = BufferPool::<1>::new();
        let oversized = [0xAAu8; BUFFER_SIZE + 100];
        // SAFETY: own index 0; input is local.
        let len = unsafe { pool.write(0, &oversized) };
        assert_eq!(len as usize, BUFFER_SIZE);
    }

    #[test]
    fn write_exactly_buffer_size_is_not_truncated() {
        let pool = BufferPool::<1>::new();
        let exact = [0xBBu8; BUFFER_SIZE];
        // SAFETY: own index 0; input is local.
        let len = unsafe { pool.write(0, &exact) };
        assert_eq!(len as usize, BUFFER_SIZE);
    }

    #[test]
    fn empty_write_writes_nothing() {
        let pool = BufferPool::<1>::new();
        // SAFETY: own index 0; input is local.
        let len = unsafe { pool.write(0, &[]) };
        assert_eq!(len, 0);
    }

    #[test]
    fn read_and_write_at_span_may_end_exactly_at_buffer_end() {
        let pool = BufferPool::<1>::new();
        let tail = [0xCDu8; 8];
        // SAFETY: own index 0; span ends exactly at BUFFER_SIZE; input local.
        unsafe { pool.write_at(0, BUFFER_SIZE - 8, &tail) };
        // SAFETY: own index 0; span ends exactly at BUFFER_SIZE; no live borrow.
        let bytes = unsafe { pool.read(0, BUFFER_SIZE - 8, 8) };
        assert_eq!(bytes, &tail);
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
    fn free_list_is_lifo() {
        let mut list = FreeList::<4>::empty();
        assert!(list.push(7));
        assert!(list.push(9));
        assert_eq!(list.pop(), Some(9));
        assert_eq!(list.pop(), Some(7));
        assert_eq!(list.pop(), None);
    }

    #[test]
    fn pop_on_empty_is_none() {
        let mut list = FreeList::<2>::empty();
        assert_eq!(list.pop(), None);
        assert!(list.is_empty());
    }

    #[test]
    fn push_beyond_capacity_is_rejected() {
        let mut list = FreeList::<2>::empty();
        assert!(list.push(0));
        assert!(list.push(1));
        assert!(!list.push(2));
        assert_eq!(list.len(), 2);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// The single-owner invariant under random pop/return sequences: driving
        /// the free list the way the pool protocol does — only ever returning an
        /// index that was previously taken out — the count of owned-plus-out
        /// indices is conserved at `N`, the list stays a faithful LIFO of a model
        /// stack, and no index is ever handed out while already out (no buffer is
        /// double-owned).
        #[test]
        fn free_list_conserves_single_ownership(ops in prop::collection::vec(any::<bool>(), 0..300)) {
            const N: usize = 8;
            let mut list = FreeList::<N>::full();
            let mut owned: Vec<u32> = (0..N as u32).collect(); // model LIFO stack
            let mut out: Vec<u32> = Vec::new(); // taken out, not yet returned

            for take in ops {
                if take {
                    match list.pop() {
                        Some(index) => {
                            prop_assert!((index as usize) < N);
                            prop_assert_eq!(owned.pop(), Some(index)); // LIFO matches model
                            prop_assert!(!out.contains(&index)); // not already out: single owner
                            out.push(index);
                        }
                        None => prop_assert!(owned.is_empty()),
                    }
                } else if let Some(index) = out.pop() {
                    // Returning an index we hold exclusively can never overflow,
                    // since owned + out always totals N.
                    prop_assert!(list.push(index));
                    owned.push(index);
                }
                prop_assert_eq!(list.len(), owned.len());
                prop_assert_eq!(owned.len() + out.len(), N);
                // The owned set carries each index at most once.
                let mut seen = [false; N];
                for &i in &owned {
                    prop_assert!(!seen[i as usize], "index {} owned twice", i);
                    seen[i as usize] = true;
                }
            }
        }

        /// Pushing distinct indices onto an empty list never exceeds capacity:
        /// the first `N` succeed and every further push is rejected.
        #[test]
        fn free_list_push_is_bounded_by_capacity(extra in 0usize..8) {
            const N: usize = 4;
            let mut list = FreeList::<N>::empty();
            for i in 0..N {
                prop_assert!(list.push(i as u32));
            }
            for i in 0..extra {
                prop_assert!(!list.push((N + i) as u32));
            }
            prop_assert_eq!(list.len(), N);
        }
    }
}
