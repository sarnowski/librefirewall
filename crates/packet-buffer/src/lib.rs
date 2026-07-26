//! The shared packet buffers and the owning domain's ownership ledger.
//!
//! [`BufferPool`] is the fixed-size backing store descriptors index, in memory
//! shared with a byzantine peer protection domain and written by a NIC's DMA
//! engine (CONCEPT §7.1). [`FreeList`] is its complement: domain-private
//! memory, never shared, recording which buffers this domain may hand out.
//!
//! # Ownership is an identity, not a count
//!
//! The ledger records per index whether it is free or outstanding, rather than
//! counting. A count is satisfied by returning any index twice, which hands one
//! buffer to two owners while a third is lost forever.
//!
//! # The trust boundary
//!
//! A token cannot cross a protection-domain boundary: an index handed to a peer
//! or a NIC travels through a shared ring as a plain number and comes back as
//! one, chosen by an untrusted peer. [`FreeList::reclaim`] is that re-entry
//! point and the only place here that accepts an index it did not mint.
//!
//! It does **not** distinguish a buffer lent to a peer from one still posted as
//! this domain's own DMA target — both are merely outstanding here. The *lent*
//! set that separates them is `pd_runtime::PoolOwner`'s, one layer up, which is
//! where the return of a buffer the domain still holds is refused.
//!
//! # Untrusted spans, and why nothing borrows the pool
//!
//! The accessors are `unsafe` because a buffer's *ownership* cannot be checked
//! here at all — only its bounds can, and those are checked unconditionally,
//! never under a `debug_assert`: the protection domains ship optimized, so a
//! check that disappears in a release build is absent from every image that
//! boots.
//!
//! No accessor hands back a reference into the pool. A `&[u8]` over bytes a
//! peer or a DMA engine may write at any instant asserts an exclusivity the
//! platform cannot supply — undefined behaviour, not merely a stale read.
//! [`BufferPool::copy_out`] therefore fills the caller's own storage and
//! borrows *that*. A snapshot in private memory is also the only thing a
//! filtering decision can rest on, since bytes left in the pool are free to
//! change under the decision that inspected them.
//!
//! # Buffer size and DMA alignment
//!
//! [`BUFFER_SIZE`] is a power of two large enough for a 1518-byte Ethernet
//! frame plus the virtio-net header and headroom. Jumbo frames are deliberately
//! unsupported: an oversized write is refused, never truncated.
//!
//! The pool's own `align_of` is 1, so nothing this crate can see fixes where
//! its buffers land in physical memory. The power-of-two stride buys only
//! congruence: every buffer shares whatever alignment the pool's base has, up
//! to [`BUFFER_SIZE`]. That base is a *placement* precondition discharged
//! outside this crate: a pool is granted a whole Microkit memory region and so
//! *is* that region, at the page-aligned physical address the system
//! description fixes. No offset enters the chain — buffer `i` sits at the
//! region base plus `i * BUFFER_SIZE` — so one build-time assertion in
//! `crates/pd-runtime/src/lib.rs` holds the whole argument
//! (`MAPPING_ALIGN.is_multiple_of(BUFFER_SIZE)`), and its
//! `a_pool_region_gives_every_buffer_the_region_alignment` test walks it.
//!
//! What that yields is [`BUFFER_SIZE`] alignment and no more; a device needing
//! more must have it enforced where the placement is decided.

#![cfg_attr(not(test), no_std)]

use core::cell::UnsafeCell;
use core::fmt;

pub const BUFFER_SIZE: usize = 2048;

#[repr(C)]
pub struct BufferPool<const N: usize> {
    buffers: [UnsafeCell<[u8; BUFFER_SIZE]>; N],
}

// SAFETY: every accessor on this type copies through a raw pointer, so a shared
// `&BufferPool` yields no reference into the region and cannot by itself create
// an alias. Which domain may touch which index is an obligation each accessor
// states on its own; this impl asserts nothing about it.
unsafe impl<const N: usize> Sync for BufferPool<N> {}

// A cross-domain shared-memory ABI: `N` tightly packed buffers, byte-aligned as
// a type. The power-of-two stride is what lets every buffer inherit the base's
// alignment, which is the whole of the header's DMA argument.
const _: () = {
    assert!(BUFFER_SIZE.is_power_of_two());
    assert!(core::mem::size_of::<BufferPool<4>>() == 4 * BUFFER_SIZE);
    assert!(core::mem::align_of::<BufferPool<4>>() == 1);
};

/// A write was refused because the data does not fit one pool buffer.
/// Truncating would silently ship a corrupted frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteTooLarge {
    /// The rejected length; always greater than [`BUFFER_SIZE`].
    pub len: usize,
}

impl fmt::Display for WriteTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "write of {} bytes exceeds the {BUFFER_SIZE}-byte buffer",
            self.len
        )
    }
}

impl<const N: usize> BufferPool<N> {
    /// A zeroed pool, for host construction: a zeroed shared region is already
    /// a valid one.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffers: [const { UnsafeCell::new([0u8; BUFFER_SIZE]) }; N],
        }
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// # Panics
    /// If `index` is not a pool index.
    fn buffer(&self, index: usize) -> *mut u8 {
        match self.buffers.get(index) {
            Some(cell) => cell.get().cast::<u8>(),
            None => panic!("buffer index is outside the pool"),
        }
    }

    /// Copy `data` into buffer `index`, returning `data.len()` in the `u32` a
    /// descriptor's length field takes.
    ///
    /// # Errors
    /// [`WriteTooLarge`] if `data` is longer than [`BUFFER_SIZE`]; the buffer is
    /// left untouched rather than shortened into a corrupt frame.
    ///
    /// # Panics
    /// If `index` is not a pool index — the recorded defect on
    /// [`write_at`](Self::write_at) applies here too.
    ///
    /// # Safety
    /// The caller must currently own `index`, and `data` must not borrow from
    /// this pool.
    pub unsafe fn write(&self, index: usize, data: &[u8]) -> Result<u32, WriteTooLarge> {
        if data.len() > BUFFER_SIZE {
            return Err(WriteTooLarge { len: data.len() });
        }
        let dst = self.buffer(index);
        // SAFETY: `buffer` bounded `index` to the pool, so `dst` points to
        // `BUFFER_SIZE` bytes, and the length was just checked against that.
        // The caller's contract guarantees `data` does not alias this pool, so
        // the ranges are non-overlapping as `copy_nonoverlapping` requires.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()) };
        // Lossless: the length is at most `BUFFER_SIZE`.
        Ok(data.len() as u32)
    }

    /// Copy `data` into buffer `index` starting at `offset`, leaving the rest of
    /// the buffer untouched — how a device header is placed in front of an
    /// already-DMA'd frame without moving the frame bytes.
    ///
    /// # Panics
    /// If `index` is not a pool index, or if `offset + data.len()` exceeds
    /// [`BUFFER_SIZE`] (computed without overflow). Both fault in every build
    /// profile, an unchecked span here being an out-of-bounds write.
    ///
    /// Those faults are a recorded ENG-5 defect rather than a contract: neither
    /// value is bounded by this function, so fed peer-derived bytes it crashes
    /// on untrusted input. No comment closes it — an unreachability proof would
    /// have to name a caller, the claim DOC-10 forbids. The fix is a typed
    /// `Result`, which changes this signature and every call site with it.
    ///
    /// # Safety
    /// The caller must currently own `index`, and `data` must not borrow from
    /// this pool.
    pub unsafe fn write_at(&self, index: usize, offset: usize, data: &[u8]) {
        assert!(
            span_fits(offset, data.len()),
            "write_at span exceeds the buffer"
        );
        let dst = self.buffer(index);
        // SAFETY: `buffer` bounded `index` to the pool and `span_fits` bounded
        // `offset + data.len()` to one buffer's `BUFFER_SIZE` bytes, so the
        // destination is in bounds. The caller's contract guarantees `data`
        // does not alias this pool, so the ranges do not overlap.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst.add(offset), data.len()) };
    }

    /// Snapshot `len` bytes of buffer `index` starting at `offset` into `into`,
    /// returning the prefix of `into` that was filled — a borrow of the
    /// caller's storage, never of the pool; see the crate header.
    ///
    /// # Errors
    /// [`CopyOutError::SpanOutsideBuffer`] if `index` is not a pool index or
    /// `offset + len` leaves the buffer (computed without overflow);
    /// [`CopyOutError::DestinationTooSmall`] if `into` is shorter than `len`.
    /// Nothing is copied on either.
    ///
    /// # Safety
    /// The caller must currently own `index`. That is a protocol claim no
    /// component can enforce against a byzantine peer, so violating it is not
    /// prevented here; it yields a snapshot of bytes another domain was
    /// writing — which the caller already treats as untrusted — and never a
    /// dangling or aliased reference.
    pub unsafe fn copy_out<'dst>(
        &self,
        index: usize,
        offset: usize,
        len: u32,
        into: &'dst mut [u8],
    ) -> Result<&'dst [u8], CopyOutError> {
        let len = len as usize;
        let outside = CopyOutError::SpanOutsideBuffer { index, offset, len };
        let Some(buffer) = self.buffers.get(index) else {
            return Err(outside);
        };
        if !span_fits(offset, len) {
            return Err(outside);
        }
        let capacity = into.len();
        let Some(snapshot) = into.get_mut(..len) else {
            return Err(CopyOutError::DestinationTooSmall { len, capacity });
        };
        let src = buffer.get().cast::<u8>();
        // SAFETY: `buffers.get` returned this cell, so `index` is in range, and
        // `span_fits` bounded `offset + len` to the cell's `BUFFER_SIZE` bytes,
        // which are initialised (the pool is created zeroed and never
        // deinitialised). `snapshot` is exactly `len` bytes of the caller's own
        // storage, which cannot overlap a pool the caller has no reference into,
        // so the ranges are disjoint as `copy_nonoverlapping` requires.
        unsafe { core::ptr::copy_nonoverlapping(src.add(offset), snapshot.as_mut_ptr(), len) };
        Ok(snapshot)
    }
}

/// Why bytes could not be snapshotted out of a pool buffer. Every variant
/// carries what was refused, so a rejected read is attributable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyOutError {
    /// `index` is not a pool index, or `offset + len` leaves the buffer.
    SpanOutsideBuffer {
        index: usize,
        offset: usize,
        len: usize,
    },
    /// Filling only part of the caller's storage would hand back a silently
    /// short frame, so a short destination is refused instead.
    DestinationTooSmall { len: usize, capacity: usize },
}

impl fmt::Display for CopyOutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SpanOutsideBuffer { index, offset, len } => write!(
                f,
                "span {offset}..+{len} of buffer {index} is not within one {BUFFER_SIZE}-byte buffer"
            ),
            Self::DestinationTooSmall { len, capacity } => {
                write!(
                    f,
                    "a {len}-byte span does not fit {capacity} bytes of storage"
                )
            }
        }
    }
}

/// `checked_add` because the operands are peer-controlled and their sum can
/// itself overflow, wrapping into a span that looks small enough.
const fn span_fits(offset: usize, len: usize) -> bool {
    match offset.checked_add(len) {
        Some(end) => end <= BUFFER_SIZE,
        None => false,
    }
}

impl<const N: usize> Default for BufferPool<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Proof of exclusive ownership of one pool buffer. Neither `Copy` nor `Clone`,
/// so the compiler rather than a runtime check makes a local double return
/// unrepresentable.
///
/// Dropping a token does **not** return the buffer; the index stays outstanding
/// until it comes back through [`FreeList::reclaim`]. That is deliberate —
/// dropping the token is how a buffer leaves Rust's ownership tracking and
/// enters the cross-domain ring protocol as a plain index — and it means a
/// token dropped with no matching `reclaim` leaks its buffer permanently.
#[must_use]
#[derive(Debug)]
pub struct OwnedBuffer(u32);

impl OwnedBuffer {
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.0
    }
}

/// Why a buffer could not be returned to a [`FreeList`]. Every variant carries
/// the offending index, so the caller can count *which* buffer was returned
/// badly instead of discovering later that one went missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnError {
    /// Outside the pool's `0..N`: it never named a buffer, so it is forged.
    OutOfRange(u32),
    /// A real buffer that is already free — the duplicate return, and the
    /// return of a buffer this ledger never handed out.
    NotOutstanding(u32),
    /// Unreachable while the free/outstanding partition holds, an outstanding
    /// index proving a free slot exists. It exists so that a broken internal
    /// invariant surfaces as a typed error instead of an out-of-bounds write.
    ListFull(u32),
}

impl fmt::Display for ReturnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange(index) => write!(f, "buffer index {index} is outside the pool"),
            Self::NotOutstanding(index) => {
                write!(f, "buffer index {index} is not outstanding")
            }
            Self::ListFull(index) => write!(
                f,
                "free list is full, so buffer index {index} cannot be returned"
            ),
        }
    }
}

/// A domain-private ledger of which pool buffers this domain may hand out.
pub struct FreeList<const N: usize> {
    /// The free indices, `indices[..top]`, as a LIFO stack: the most recently
    /// returned buffer is the warmest in cache.
    indices: [u32; N],
    /// A flag per index rather than a packed bit: a `[u64; N.div_ceil(64)]`
    /// word array needs `generic_const_exprs`, an incomplete feature whose
    /// `where` bound leaks into every downstream type naming a `FreeList`. At
    /// the pool sizes in play the difference is tens of bytes of private
    /// memory, which does not buy an unstable feature in a soundness crate.
    outstanding: [bool; N],
    top: usize,
}

impl<const N: usize> FreeList<N> {
    /// A ledger owning every buffer index `0..N`, none outstanding — the sole
    /// entry to the state machine, so the free-plus-outstanding partition holds
    /// by construction.
    #[must_use]
    pub const fn full() -> Self {
        // An index is handed out as a `u32`, so a pool that cannot name all of
        // its buffers in one is a build error rather than a silent truncation.
        const { assert!(N <= u32::MAX as usize, "a pool index must fit in a u32") };
        let mut indices = [0u32; N];
        let mut index = 0;
        while index < N {
            indices[index] = index as u32;
            index += 1;
        }
        Self {
            indices,
            outstanding: [false; N],
            top: N,
        }
    }

    /// Take exclusive ownership of one free buffer, marking its index
    /// outstanding until it comes back through [`push`](Self::push) or
    /// [`reclaim`](Self::reclaim).
    #[must_use = "dropping the token leaves its buffer outstanding forever unless it is reclaimed"]
    pub fn pop(&mut self) -> Option<OwnedBuffer> {
        if self.top == 0 {
            return None;
        }
        self.top -= 1;
        let index = self.indices[self.top];
        self.outstanding[index as usize] = true;
        Some(OwnedBuffer(index))
    }

    /// Return a buffer this domain still holds, consuming its token.
    ///
    /// The index is still checked: an `OwnedBuffer` is not branded with the
    /// ledger that minted it, so holding one does not prove *this* ledger
    /// handed it out — it may come from a ledger over a differently sized pool,
    /// or its index may have been taken back through
    /// [`reclaim`](Self::reclaim) from under it. Branding the token is the
    /// recorded DOC-9 fix.
    ///
    /// # Errors
    /// The ledger is unchanged and the token is consumed on any error, so
    /// unless the caller kept the index the buffer stays outstanding for good —
    /// count the error rather than discard it.
    pub fn push(&mut self, buffer: OwnedBuffer) -> Result<(), ReturnError> {
        self.accept(buffer.index())
    }

    /// Return a buffer named by a bare index, as a peer or a device does — the
    /// crate's trust boundary.
    ///
    /// Rejecting a *non-outstanding* index is what makes a duplicate or forged
    /// return impossible rather than merely counted: accepting one hands a
    /// buffer that is already free to a second owner.
    ///
    /// # Errors
    /// A rejected return leaves the ledger untouched, so the index keeps its
    /// state and a buffer that really is outstanding can still be returned by
    /// whoever holds it.
    pub fn reclaim(&mut self, index: u32) -> Result<(), ReturnError> {
        self.accept(index)
    }

    /// Validate first and mutate only afterwards, so a rejected return cannot
    /// half-apply and lose the buffer it named.
    fn accept(&mut self, index: u32) -> Result<(), ReturnError> {
        let slot = index as usize;
        if slot >= N {
            return Err(ReturnError::OutOfRange(index));
        }
        if !self.outstanding[slot] {
            return Err(ReturnError::NotOutstanding(index));
        }
        if self.top == N {
            return Err(ReturnError::ListFull(index));
        }
        self.outstanding[slot] = false;
        self.indices[self.top] = index;
        self.top += 1;
        Ok(())
    }

    /// How many buffers are free to hand out; the rest of the pool's `N`
    /// indices are outstanding.
    #[must_use]
    pub fn len(&self) -> usize {
        self.top
    }

    /// Whether every buffer is outstanding, so [`pop`](Self::pop) would fail.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.top == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The ledger invariant the whole design rests on: the free stack holds no
    /// index twice, and free plus outstanding covers `0..N` exactly once each.
    /// Read through the private fields on purpose — a black-box check could only
    /// observe the counts, which is the accounting this change replaces.
    fn assert_partitions_the_pool<const N: usize>(list: &FreeList<N>) {
        let mut seen = [false; N];
        for &index in &list.indices[..list.top] {
            assert!(!seen[index as usize], "index {index} is free twice");
            seen[index as usize] = true;
        }
        for (index, &outstanding) in list.outstanding.iter().enumerate() {
            assert_ne!(
                seen[index], outstanding,
                "index {index} is both or neither free and outstanding"
            );
            seen[index] |= outstanding;
        }
        assert!(seen.iter().all(|covered| *covered), "an index vanished");
        assert!(list.len() <= N);
    }

    /// Snapshot a span into fresh storage and hand back an owned copy, so a
    /// test never keeps the caller-side buffer alive by accident.
    fn snapshot<const N: usize>(
        pool: &BufferPool<N>,
        index: usize,
        offset: usize,
        len: u32,
    ) -> std::vec::Vec<u8> {
        let mut storage = [0u8; BUFFER_SIZE];
        // SAFETY: single-threaded test that owns every index of its own pool.
        unsafe { pool.copy_out(index, offset, len, &mut storage) }
            .expect("the test spans all lie within a buffer")
            .to_vec()
    }

    #[test]
    fn write_then_copy_out_round_trips_bytes() {
        let pool = BufferPool::<4>::new();
        let payload = [1u8, 2, 3, 4, 5];
        // SAFETY: single-threaded test; we own index 2 for the whole test, and
        // `payload` is a local that does not borrow from the pool.
        let len = unsafe { pool.write(2, &payload) }.expect("five bytes fit a buffer");
        assert_eq!(len, 5);
        assert_eq!(snapshot(&pool, 2, 0, len), &payload);
        assert_eq!(snapshot(&pool, 2, 2, 3), &payload[2..5]);
    }

    #[test]
    fn copy_out_borrows_the_callers_storage_and_leaves_the_tail_alone() {
        let pool = BufferPool::<1>::new();
        // SAFETY: own index 0; input is local.
        unsafe { pool.write(0, &[0xEEu8; 8]) }.expect("eight bytes fit");
        let mut storage = [0xFFu8; 16];
        // SAFETY: own index 0; storage is a local that cannot alias the pool.
        let bytes = unsafe { pool.copy_out(0, 0, 4, &mut storage) }.expect("four bytes fit");
        assert_eq!(bytes, &[0xEE; 4]);
        // The returned slice is exactly the span; the rest of the caller's
        // storage is untouched, which is what makes the return value the only
        // thing a caller may read.
        assert_eq!(bytes.len(), 4);
        assert_eq!(&storage[4..], &[0xFF; 12]);
    }

    #[test]
    fn write_at_places_data_mid_buffer_without_touching_the_rest() {
        let pool = BufferPool::<1>::default();
        assert_eq!(pool.capacity(), 1);
        // SAFETY: single-threaded test; we own index 0 throughout; inputs local.
        unsafe {
            pool.write(0, &[0xEEu8; 32]).expect("32 bytes fit a buffer");
            pool.write_at(0, 12, &[1, 2, 3]);
        }
        let bytes = snapshot(&pool, 0, 0, 16);
        assert_eq!(&bytes[..12], &[0xEE; 12]);
        assert_eq!(&bytes[12..15], &[1, 2, 3]);
        assert_eq!(bytes[15], 0xEE);
    }

    #[test]
    fn write_larger_than_a_buffer_is_refused_and_leaves_the_buffer_intact() {
        let pool = BufferPool::<1>::new();
        // SAFETY: own index 0; inputs are local.
        unsafe {
            pool.write(0, &[0x11u8; 4]).expect("four bytes fit");
            let oversized = [0xAAu8; BUFFER_SIZE + 1];
            assert_eq!(
                pool.write(0, &oversized),
                Err(WriteTooLarge {
                    len: BUFFER_SIZE + 1
                })
            );
        }
        // Refused, not partially applied: the earlier contents survive.
        assert_eq!(snapshot(&pool, 0, 0, 4), &[0x11u8; 4]);
    }

    #[test]
    fn write_exactly_buffer_size_is_accepted() {
        let pool = BufferPool::<1>::new();
        let exact = [0xBBu8; BUFFER_SIZE];
        // SAFETY: own index 0; input is local.
        let len = unsafe { pool.write(0, &exact) }.expect("a full buffer fits exactly");
        assert_eq!(len as usize, BUFFER_SIZE);
    }

    #[test]
    fn empty_write_writes_nothing() {
        let pool = BufferPool::<1>::new();
        // SAFETY: own index 0; input is local.
        let len = unsafe { pool.write(0, &[]) }.expect("an empty write always fits");
        assert_eq!(len, 0);
    }

    #[test]
    fn copy_out_and_write_at_span_may_end_exactly_at_buffer_end() {
        let pool = BufferPool::<1>::new();
        let tail = [0xCDu8; 8];
        // SAFETY: own index 0; span ends exactly at BUFFER_SIZE; input local.
        unsafe { pool.write_at(0, BUFFER_SIZE - 8, &tail) };
        assert_eq!(snapshot(&pool, 0, BUFFER_SIZE - 8, 8), &tail);
    }

    #[test]
    #[should_panic(expected = "write_at span exceeds the buffer")]
    fn write_at_past_the_buffer_end_panics_in_every_profile() {
        let pool = BufferPool::<1>::new();
        // SAFETY: own index 0; the call is expected to fault on the span check
        // before it writes anything, which is what this test asserts.
        unsafe { pool.write_at(0, BUFFER_SIZE - 1, &[1, 2]) };
    }

    #[test]
    #[should_panic(expected = "write_at span exceeds the buffer")]
    fn write_at_offset_that_overflows_the_span_sum_panics() {
        let pool = BufferPool::<1>::new();
        // A peer-shaped offset whose `offset + len` wraps: the checked sum must
        // reject it rather than wrap into a span that looks small enough.
        // SAFETY: own index 0; expected to fault on the span check.
        unsafe { pool.write_at(0, usize::MAX, &[1, 2]) };
    }

    #[test]
    fn copy_out_refuses_every_span_that_leaves_the_buffer() {
        let pool = BufferPool::<2>::new();
        let mut storage = [0u8; BUFFER_SIZE];
        // Past the end, an offset whose `offset + len` sum wraps, and an index
        // outside the pool: each a shape a peer descriptor can carry, each a
        // typed rejection rather than a fault.
        for (index, offset, len) in [
            (0, 1, BUFFER_SIZE as u32),
            (0, usize::MAX, 8),
            (0, BUFFER_SIZE, 1),
            (2, 0, 1),
            (usize::MAX, 0, 1),
        ] {
            // SAFETY: single-threaded test owning its own pool; every call is
            // expected to reject before it reads anything.
            let outcome = unsafe { pool.copy_out(index, offset, len, &mut storage) };
            assert_eq!(
                outcome,
                Err(CopyOutError::SpanOutsideBuffer {
                    index,
                    offset,
                    len: len as usize
                })
            );
        }
        // Nothing was copied into the caller's storage by any of them.
        assert_eq!(storage[..8], [0u8; 8]);
    }

    #[test]
    fn copy_out_refuses_storage_shorter_than_the_span() {
        let pool = BufferPool::<1>::new();
        // SAFETY: own index 0; input is local.
        unsafe { pool.write(0, &[0xABu8; 64]) }.expect("64 bytes fit");
        let mut storage = [0u8; 8];
        // SAFETY: own index 0; expected to reject before copying.
        let outcome = unsafe { pool.copy_out(0, 0, 9, &mut storage) };
        assert_eq!(
            outcome,
            Err(CopyOutError::DestinationTooSmall {
                len: 9,
                capacity: 8
            })
        );
        // Refused, not truncated: a short frame is never silently handed back.
        assert_eq!(storage, [0u8; 8]);
        // SAFETY: own index 0; the span now fits exactly.
        let bytes = unsafe { pool.copy_out(0, 0, 8, &mut storage) }.expect("eight bytes fit");
        assert_eq!(bytes, &[0xAB; 8]);
    }

    #[test]
    fn an_empty_copy_out_is_accepted_and_borrows_nothing() {
        let pool = BufferPool::<1>::new();
        let mut storage = [];
        // A zero-length span at the very end of the buffer is in bounds, and
        // empty caller storage is large enough for it.
        // SAFETY: own index 0; storage is a local.
        let bytes = unsafe { pool.copy_out(0, BUFFER_SIZE, 0, &mut storage) }
            .expect("an empty span at the end is still within the buffer");
        assert!(bytes.is_empty());
    }

    #[test]
    fn copy_out_errors_name_the_values_they_refused() {
        assert_eq!(
            std::format!(
                "{}",
                CopyOutError::SpanOutsideBuffer {
                    index: 3,
                    offset: 2040,
                    len: 16
                }
            ),
            "span 2040..+16 of buffer 3 is not within one 2048-byte buffer"
        );
        assert_eq!(
            std::format!(
                "{}",
                CopyOutError::DestinationTooSmall {
                    len: 64,
                    capacity: 8
                }
            ),
            "a 64-byte span does not fit 8 bytes of storage"
        );
    }

    #[test]
    fn write_too_large_reports_the_rejected_length() {
        let error = WriteTooLarge { len: 4096 };
        assert_eq!(
            std::format!("{error}"),
            "write of 4096 bytes exceeds the 2048-byte buffer"
        );
    }

    #[test]
    fn a_full_ledger_hands_out_every_index_exactly_once() {
        let mut list = FreeList::<4>::full();
        assert_eq!(list.len(), 4);
        let mut seen = [false; 4];
        while let Some(buffer) = list.pop() {
            assert!(!seen[buffer.index() as usize], "index handed out twice");
            seen[buffer.index() as usize] = true;
            assert_partitions_the_pool(&list);
        }
        assert!(list.is_empty());
        assert_eq!(list.pop().map(|buffer| buffer.index()), None);
        assert!(seen.iter().all(|s| *s));
    }

    #[test]
    fn returned_buffers_come_back_in_lifo_order() {
        let mut list = FreeList::<4>::full();
        let first = list.pop().expect("a full ledger has buffers");
        let second = list.pop().expect("a full ledger has buffers");
        let (first_index, second_index) = (first.index(), second.index());
        assert!(list.push(first).is_ok());
        assert!(list.push(second).is_ok());
        assert_eq!(
            list.pop().map(|buffer| buffer.index()),
            Some(second_index),
            "the most recent return is handed out first"
        );
        assert_eq!(list.pop().map(|buffer| buffer.index()), Some(first_index));
    }

    #[test]
    fn a_duplicate_reclaim_cannot_double_own_a_buffer() {
        // The regression this design exists for: while a return was accounted
        // by count alone, taking two buffers out and returning the *same* index
        // twice was accepted twice — the free stack then held that index twice,
        // handing one buffer to two owners, while the other was lost for good.
        let mut list = FreeList::<4>::full();
        let first = list.pop().expect("a full ledger has buffers");
        let second = list.pop().expect("a full ledger has buffers");
        let (first_index, second_index) = (first.index(), second.index());
        // Dropping the token is how a buffer leaves as a bare index on a ring.
        drop(first);

        assert_eq!(list.reclaim(first_index), Ok(()));
        assert_eq!(
            list.reclaim(first_index),
            Err(ReturnError::NotOutstanding(first_index)),
            "the second return of the same index must be refused"
        );
        assert_partitions_the_pool(&list);

        // The refusal cost nothing: the other buffer is still returnable, and
        // the pool comes back whole.
        assert_eq!(list.push(second), Ok(()));
        assert_eq!(list.len(), 4);
        assert_partitions_the_pool(&list);
        let handed_out: std::vec::Vec<u32> =
            core::iter::from_fn(|| list.pop().map(|buffer| buffer.index())).collect();
        assert!(handed_out.contains(&first_index));
        assert!(handed_out.contains(&second_index));
        assert_eq!(handed_out.len(), 4);
    }

    #[test]
    fn a_forged_out_of_range_reclaim_is_refused_without_disturbing_the_ledger() {
        let mut list = FreeList::<4>::full();
        let buffer = list.pop().expect("a full ledger has buffers");
        let index = buffer.index();

        assert_eq!(list.reclaim(999), Err(ReturnError::OutOfRange(999)));
        assert_eq!(list.reclaim(4), Err(ReturnError::OutOfRange(4)));
        assert_eq!(
            list.reclaim(u32::MAX),
            Err(ReturnError::OutOfRange(u32::MAX))
        );
        assert_eq!(list.len(), 3);
        assert_partitions_the_pool(&list);

        // The forged returns neither leaked nor freed the buffer we really hold.
        assert_eq!(list.push(buffer), Ok(()));
        assert_eq!(list.len(), 4);
        assert!(!list.outstanding[index as usize]);
        assert_partitions_the_pool(&list);
    }

    #[test]
    fn reclaiming_a_never_allocated_index_is_refused() {
        let mut list = FreeList::<4>::full();
        // Nothing has been handed out, so every index is free and no return can
        // be legitimate.
        for index in 0..4u32 {
            assert_eq!(
                list.reclaim(index),
                Err(ReturnError::NotOutstanding(index)),
                "a buffer that was never allocated cannot be returned"
            );
        }
        assert_eq!(list.len(), 4);
        assert_partitions_the_pool(&list);
    }

    #[test]
    fn over_returning_is_refused_and_names_the_buffer() {
        let mut list = FreeList::<2>::full();
        let first = list.pop().expect("a full ledger has buffers");
        let second = list.pop().expect("a full ledger has buffers");
        let extra = first.index();
        assert_eq!(list.push(first), Ok(()));
        assert_eq!(list.push(second), Ok(()));
        // One more return than was ever handed out: refused, and the error says
        // which index, so the caller can attribute it instead of losing a
        // buffer silently.
        assert_eq!(list.reclaim(extra), Err(ReturnError::NotOutstanding(extra)));
        assert_eq!(list.len(), 2);
        assert_partitions_the_pool(&list);
    }

    #[test]
    fn a_token_from_a_larger_pool_is_refused_as_out_of_range() {
        let mut small = FreeList::<4>::full();
        let mut large = FreeList::<8>::full();
        let stray = large.pop().expect("a full ledger has buffers");
        assert_eq!(stray.index(), 7, "the LIFO hands out the last index first");
        assert_eq!(small.push(stray), Err(ReturnError::OutOfRange(7)));
        assert_eq!(small.len(), 4);
        assert_partitions_the_pool(&small);
    }

    #[test]
    fn a_token_this_ledger_never_handed_out_is_refused() {
        let mut left = FreeList::<4>::full();
        let mut right = FreeList::<4>::full();
        let stray = right.pop().expect("a full ledger has buffers");
        let index = stray.index();
        // Range-valid, but `left` never handed this index out, so accepting it
        // would free a buffer that is already on its free stack.
        assert_eq!(left.push(stray), Err(ReturnError::NotOutstanding(index)));
        assert_partitions_the_pool(&left);
    }

    #[test]
    fn a_broken_partition_surfaces_as_list_full_rather_than_an_overrun() {
        // `ListFull` is unreachable through the public API, because an
        // outstanding index proves a free slot exists. Corrupt the invariant
        // directly to prove the guard converts it into a typed error instead of
        // writing past the free stack.
        let mut list = FreeList::<2>::full();
        list.outstanding[1] = true;
        assert_eq!(list.len(), 2, "the corrupt state is deliberately full");
        assert_eq!(list.reclaim(1), Err(ReturnError::ListFull(1)));
    }

    #[test]
    fn return_errors_name_the_offending_index() {
        assert_eq!(
            std::format!("{}", ReturnError::OutOfRange(999)),
            "buffer index 999 is outside the pool"
        );
        assert_eq!(
            std::format!("{}", ReturnError::NotOutstanding(3)),
            "buffer index 3 is not outstanding"
        );
        assert_eq!(
            std::format!("{}", ReturnError::ListFull(1)),
            "free list is full, so buffer index 1 cannot be returned"
        );
    }

    /// Peer-shaped span components: mostly plausible values, so the in-bounds
    /// cases are actually reached, with arbitrary ones mixed in so the forged
    /// and overflowing shapes are too. Modelling the *authority* a peer has —
    /// any `usize`, any `u32` — rather than the values a correct peer would
    /// send is what keeps the adversarial region in the strategy (TEST-8).
    fn any_span() -> impl Strategy<Value = (usize, usize, u32, usize)> {
        let index = prop_oneof![3 => 0usize..8, 1 => any::<usize>()];
        let offset = prop_oneof![3 => 0usize..=BUFFER_SIZE, 1 => any::<usize>()];
        let len = prop_oneof![3 => 0u32..=BUFFER_SIZE as u32, 1 => any::<u32>()];
        let capacity = prop_oneof![3 => 0usize..=BUFFER_SIZE, 1 => Just(0usize)];
        (index, offset, len, capacity)
    }

    /// The byte buffer `index` is filled with, so an accepted snapshot can be
    /// checked against the buffer it claims to come from.
    const fn fill(index: usize) -> u8 {
        (index as u8).wrapping_add(1)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The span accessor under a byzantine peer: arbitrary index, offset and
        /// length against caller storage of arbitrary size. Nothing may panic;
        /// acceptance must match the bounds exactly; an accepted snapshot must be
        /// exactly as long as asked for and carry the bytes of the buffer it
        /// named; and a refusal must leave the caller's storage wholly untouched,
        /// which is what makes a rejected span indistinguishable from one never
        /// attempted.
        #[test]
        fn arbitrary_spans_are_refused_or_snapshotted_exactly(
            (index, offset, len, capacity) in any_span(),
        ) {
            const N: usize = 4;
            let pool = BufferPool::<N>::new();
            for buffer in 0..N {
                // SAFETY: single-threaded test that owns every index of its own
                // pool; the source is a local array.
                unsafe { pool.write(buffer, &[fill(buffer); BUFFER_SIZE]) }
                    .expect("a whole buffer fits exactly");
            }

            const UNTOUCHED: u8 = 0xA5;
            let mut storage = std::vec![UNTOUCHED; capacity];
            // Copy any accepted snapshot out so the borrow of `storage` ends and
            // the storage itself can be inspected below.
            // SAFETY: single-threaded test owning every index of its own pool;
            // `storage` is a separate allocation that cannot alias it.
            let observed = unsafe { pool.copy_out(index, offset, len, &mut storage) }
                .map(<[u8]>::to_vec);

            let in_bounds = index < N
                && offset.checked_add(len as usize).is_some_and(|end| end <= BUFFER_SIZE);
            let fits = len as usize <= capacity;

            match observed {
                Ok(bytes) => {
                    prop_assert!(in_bounds && fits);
                    prop_assert_eq!(bytes.len(), len as usize);
                    prop_assert!(bytes.iter().all(|byte| *byte == fill(index)));
                    // Only the span was written; the rest of the caller's
                    // storage is still the caller's.
                    prop_assert!(storage[len as usize..].iter().all(|b| *b == UNTOUCHED));
                }
                Err(error) => {
                    prop_assert!(!in_bounds || !fits);
                    prop_assert!(
                        storage.iter().all(|byte| *byte == UNTOUCHED),
                        "a refused span wrote to the caller's storage"
                    );
                    match error {
                        CopyOutError::SpanOutsideBuffer { .. } => prop_assert!(!in_bounds),
                        CopyOutError::DestinationTooSmall { .. } => {
                            prop_assert!(in_bounds && !fits);
                        }
                    }
                }
            }
        }
    }

    /// One step of the untrusted-peer model: take a buffer, return one we hold,
    /// or feed the trust boundary a bare index of the peer's choosing.
    #[derive(Clone, Debug)]
    enum Step {
        Pop,
        ReturnHeld(usize),
        ReclaimBare(u32),
    }

    fn any_step(pool_size: u32) -> impl Strategy<Value = Step> {
        prop_oneof![
            2 => Just(Step::Pop),
            2 => any::<usize>().prop_map(Step::ReturnHeld),
            // Bias towards indices that name a real buffer, so the interesting
            // duplicate and stale-token returns are reached, while arbitrary
            // `u32`s keep forged and out-of-range values in the mix.
            3 => (0..pool_size).prop_map(Step::ReclaimBare),
            3 => any::<u32>().prop_map(Step::ReclaimBare),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The ledger under a byzantine peer: arbitrary indices, arbitrary
        /// order, duplicates, forged and out-of-range values, and stale tokens
        /// whose index was reclaimed behind their back. Nothing may panic, every
        /// outcome must match the model exactly, and after every single step the
        /// free and outstanding sets must still partition `0..N` — no index
        /// duplicated (no buffer double-owned), none lost, none invented.
        #[test]
        fn arbitrary_returns_never_double_own_or_invent_a_buffer(
            steps in prop::collection::vec(any_step(8), 0..400),
        ) {
            const N: usize = 8;
            let mut list = FreeList::<N>::full();
            // The model: which indices are free (in LIFO order) and which are
            // outstanding, tracked by identity, independent of the code.
            let mut free: std::vec::Vec<u32> = (0..N as u32).collect();
            let mut outstanding = [false; N];
            // Tokens physically in hand. A token stays here after its index is
            // reclaimed from under it, so returning it later must be refused.
            let mut held: std::vec::Vec<OwnedBuffer> = std::vec::Vec::new();

            for step in steps {
                match step {
                    Step::Pop => match list.pop() {
                        Some(buffer) => {
                            let index = buffer.index();
                            prop_assert_eq!(Some(index), free.pop());
                            outstanding[index as usize] = true;
                            held.push(buffer);
                        }
                        None => prop_assert!(free.is_empty()),
                    },
                    Step::ReturnHeld(which) => {
                        if held.is_empty() {
                            continue;
                        }
                        let buffer = held.remove(which % held.len());
                        let index = buffer.index();
                        let expected = expected_outcome(index, N, &outstanding, free.len());
                        prop_assert_eq!(list.push(buffer), expected);
                        if expected.is_ok() {
                            outstanding[index as usize] = false;
                            free.push(index);
                        }
                    }
                    Step::ReclaimBare(index) => {
                        let expected = expected_outcome(index, N, &outstanding, free.len());
                        prop_assert_eq!(list.reclaim(index), expected);
                        if expected.is_ok() {
                            outstanding[index as usize] = false;
                            free.push(index);
                        }
                    }
                }
                prop_assert_eq!(list.len(), free.len());
                prop_assert_eq!(&list.indices[..list.top], &free[..]);
                prop_assert_eq!(&list.outstanding[..], &outstanding[..]);
                assert_partitions_the_pool(&list);
            }
        }
    }

    /// What the ledger must answer for a return of `index`, derived from the
    /// model alone. `ListFull` never appears: an outstanding index implies a
    /// free slot, which is the invariant the property is there to confirm.
    fn expected_outcome(
        index: u32,
        pool_size: usize,
        outstanding: &[bool],
        free_len: usize,
    ) -> Result<(), ReturnError> {
        if index as usize >= pool_size {
            return Err(ReturnError::OutOfRange(index));
        }
        if !outstanding[index as usize] {
            return Err(ReturnError::NotOutstanding(index));
        }
        assert!(
            free_len < pool_size,
            "an outstanding index implies a free slot"
        );
        Ok(())
    }
}
