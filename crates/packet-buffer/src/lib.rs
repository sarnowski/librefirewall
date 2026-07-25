//! Shared packet buffers and the owner-side ownership ledger.
//!
//! [`BufferPool`] is the contiguous, fixed-size backing store that descriptors
//! index; it lives in memory shared between protection domains, so its layout
//! is a cross-domain ABI. [`FreeList`] is its complement: the *domain-local*
//! ledger of which pool buffers the owning domain may hand out. The ledger is
//! ordinary private memory, never shared and never mapped by a peer.
//!
//! # Ownership is an identity, not a count
//!
//! Every index in `0..N` is at all times in exactly one of two states, and the
//! [`FreeList`] records which for each index individually:
//!
//! * **free** — on the ledger's LIFO stack, available to [`FreeList::pop`];
//! * **outstanding** — handed out, and unavailable until it is returned.
//!
//! The two sets partition `0..N`: `free + outstanding == N` holds from
//! construction and across every operation, no index is ever in both, and none
//! can be invented or destroyed. Accounting ownership *by identity* like this is
//! what a plain count cannot do — a count is satisfied by returning any index
//! twice, which hands the same buffer to two owners at once while a third
//! buffer is lost forever.
//!
//! [`FreeList::pop`] mints an [`OwnedBuffer`]: the proof of exclusive ownership
//! of one index. It is neither `Copy` nor `Clone` and returning it consumes it,
//! so at most one token per index exists and a *local* double return is not
//! representable rather than merely detected. Handing a buffer onward is
//! therefore a move, and the compiler tracks it.
//!
//! # The trust boundary
//!
//! A token cannot cross a protection-domain boundary: an index handed to a peer
//! (or to a NIC) travels through a shared ring as a plain number and comes back
//! as one, chosen by an untrusted peer (CONCEPT §7.1). [`FreeList::reclaim`] is
//! that re-entry point and the only place in this crate that accepts an index it
//! did not mint, which makes it the trust boundary: it refuses an index outside
//! `0..N` and an index that is not currently outstanding. A duplicate return, a
//! return of a buffer the domain still holds, and a forged index are all
//! rejected as [`ReturnError`] rather than counted.
//!
//! A rejected return changes nothing: the index it names keeps its state, so the
//! rightful holder can still return the buffer afterwards. The error carries the
//! offending index so the caller can attribute and count it instead of losing a
//! buffer silently.
//!
//! # Untrusted spans
//!
//! A descriptor arriving from a peer carries `buffer`, `offset`, and `len` that
//! are equally untrusted, and the pool accessors are `unsafe` because a buffer's
//! *ownership* cannot be checked here at all — only its bounds can. A caller
//! handling a peer descriptor must validate the span against the pool before
//! calling in. The accessors nevertheless check the span they are given
//! unconditionally, in every build profile: that check is the backstop that
//! turns a caller's contract violation into a controlled panic instead of an
//! out-of-bounds read or write, and it is deliberately not a `debug_assert`,
//! because a check on externally driven input that disappears in a release build
//! is not a check.
//!
//! # Buffer size and DMA alignment
//!
//! [`BUFFER_SIZE`] is 2048 — a power of two large enough for a 1518-byte
//! Ethernet frame plus the virtio-net header and headroom. Jumbo frames are
//! deliberately unsupported: an oversized write is refused, never truncated and
//! never allowed to overrun.
//!
//! The pool's own `align_of` is 1, so *nothing this crate can see* determines
//! how its buffers are aligned in physical memory. What the pool guarantees by
//! itself is only relative: because the stride is a power of two, every buffer
//! is congruent to the pool's base modulo 2048, so all `N` buffers share
//! whatever alignment the base has, up to 2048. The base's alignment is a
//! *placement* precondition owned by two components outside this crate:
//!
//! * the Microkit system description, which fixes the physical address the
//!   shared region is mapped at (page-aligned by the mapping granularity); and
//! * `pd_runtime::Pipeline`, whose field *order* fixes the pool's byte offset
//!   *within* that region.
//!
//! Both are discharged, and by a named component rather than by assumption.
//! `Pipeline` places the pool **first** — deliberately, as its own type
//! documentation says — so the pool's offset is zero and each buffer's absolute
//! alignment is exactly the region base's. Three build-time assertions in
//! `crates/pd-runtime/src/lib.rs` hold that chain together: `offset_of!(
//! Pipeline, pool) == 0` pins the field order, `Pipeline::POOL_OFFSET
//! .is_multiple_of(BUFFER_SIZE)` turns that offset into a stride multiple, and
//! `MAPPING_ALIGN.is_multiple_of(BUFFER_SIZE)` supplies the base. The runtime
//! restatement is that crate's
//! `the_pool_sits_at_the_front_so_every_buffer_inherits_the_region_alignment`
//! test, which walks every index and checks the address a NIC would be handed.
//! Reordering `Pipeline` to put the pool behind the rings — where its offset
//! would be a multiple of neither the stride nor a page — fails the build on
//! the first of those assertions rather than silently weakening every buffer
//! address.
//!
//! What that yields is [`BUFFER_SIZE`] alignment and no more. A device needing
//! a stronger guarantee must have it enforced where the placement is decided;
//! a caller cannot obtain it by choosing a different index here.

#![cfg_attr(not(test), no_std)]

use core::cell::UnsafeCell;
use core::fmt;

/// Size in bytes of every buffer in the pool.
pub const BUFFER_SIZE: usize = 2048;

/// A pool of `N` fixed-size buffers shared between protection domains.
#[repr(C)]
pub struct BufferPool<const N: usize> {
    buffers: [UnsafeCell<[u8; BUFFER_SIZE]>; N],
}

// SAFETY: `BufferPool` exposes no safe path to its interior, so sharing a
// `&BufferPool` across threads cannot by itself create a data race: every read
// and write goes through an `unsafe` accessor whose contract puts the obligation
// to hold the index exclusively on the caller. This impl therefore asserts
// nothing about who owns what — it states only that the obligation lives
// entirely in those contracts. Within a domain, `FreeList` discharges it by
// partitioning `0..N` into free and outstanding and minting at most one
// `OwnedBuffer` per index. Across domains it is a protocol obligation the
// descriptor rings carry, which a byzantine peer mapping the same region can
// break (CONCEPT §7.1) — no Rust type can stop a peer PD from writing bytes it
// does not own, which is precisely why the pool never hands out a safe
// reference to those bytes.
unsafe impl<const N: usize> Sync for BufferPool<N> {}

// The pool is a cross-domain shared-memory ABI: `N` buffers of `BUFFER_SIZE`,
// tightly packed and byte-aligned as a type, with any stronger alignment coming
// from where the pool is placed rather than from here. The power-of-two stride
// is what lets every buffer inherit the base's alignment, which is the whole of
// the header's DMA argument.
const _: () = {
    assert!(BUFFER_SIZE.is_power_of_two());
    assert!(core::mem::size_of::<BufferPool<4>>() == 4 * BUFFER_SIZE);
    assert!(core::mem::align_of::<BufferPool<4>>() == 1);
};

/// A write was refused because the data does not fit one pool buffer.
///
/// Truncating instead would silently ship a corrupted frame, so an oversized
/// write is a rejection the caller must handle, not a fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteTooLarge {
    /// Length of the rejected data in bytes; always greater than
    /// [`BUFFER_SIZE`].
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

    /// Copy `data` into buffer `index`, returning the number of bytes written —
    /// always `data.len()`, in the `u32` form a descriptor's length field takes.
    ///
    /// # Errors
    /// [`WriteTooLarge`] if `data` is longer than [`BUFFER_SIZE`]. The buffer is
    /// left untouched — an oversized frame is refused rather than truncated,
    /// because a silently shortened frame is a corrupt frame the caller would
    /// go on to publish.
    ///
    /// # Panics
    /// If `index >= N`. That is a contract violation, not a soundness
    /// precondition: the caller owns the index it passes.
    ///
    /// # Safety
    /// The caller must currently own `index` (it holds the [`OwnedBuffer`], or
    /// the descriptor naming it), and `data` must not borrow from this pool — it
    /// would alias otherwise, see [`read`](Self::read).
    pub unsafe fn write(&self, index: usize, data: &[u8]) -> Result<u32, WriteTooLarge> {
        if data.len() > BUFFER_SIZE {
            return Err(WriteTooLarge { len: data.len() });
        }
        let dst = self.buffers[index].get().cast::<u8>();
        // SAFETY: `dst` points to `BUFFER_SIZE` bytes the caller owns and the
        // length was just checked against that, so the write is in bounds. The
        // caller's contract guarantees `data` does not alias this pool, so the
        // ranges are non-overlapping as `copy_nonoverlapping` requires.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()) };
        // Lossless: the length is at most `BUFFER_SIZE`.
        Ok(data.len() as u32)
    }

    /// Copy `data` into buffer `index` starting at `offset`, leaving the rest
    /// of the buffer untouched. A driver uses this to place a device header in
    /// front of an already-DMA'd frame without moving the frame bytes.
    ///
    /// # Panics
    /// If `offset + data.len()` exceeds [`BUFFER_SIZE`] (computed without
    /// overflow), or if `index >= N`. Both are contract violations, and both
    /// panic in every build profile: an unchecked span here is an out-of-bounds
    /// write, so a controlled fault is the only acceptable outcome. A caller
    /// acting on a peer-supplied span must validate it before calling rather
    /// than rely on this backstop.
    ///
    /// # Safety
    /// The caller must currently own `index`, and `data` must not borrow from
    /// this pool.
    pub unsafe fn write_at(&self, index: usize, offset: usize, data: &[u8]) {
        assert!(
            span_fits(offset, data.len()),
            "write_at span exceeds the buffer"
        );
        let dst = self.buffers[index].get().cast::<u8>();
        // SAFETY: the span was just checked to lie within the buffer, and
        // indexing checked `index`, so the destination is in bounds; the
        // caller's contract guarantees `data` does not alias this pool, so the
        // ranges do not overlap.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst.add(offset), data.len()) };
    }

    /// Borrow `len` bytes of buffer `index` starting at `offset`.
    ///
    /// # Panics
    /// If `offset + len` exceeds [`BUFFER_SIZE`] (computed without overflow), or
    /// if `index >= N` — unconditionally, for the reason given on
    /// [`write_at`](Self::write_at).
    ///
    /// # Safety
    /// The caller must currently own `index`, the borrow must end before
    /// ownership of the buffer is released, and no write to the buffer may occur
    /// while the borrow is live.
    ///
    /// The returned borrow is tied to the pool, not to an [`OwnedBuffer`],
    /// because the domain that reads a buffer is generally not the one that
    /// allocated it: a consumer's ownership arrives as a descriptor dequeued
    /// from a peer's ring — a plain index with no token attached, since a token
    /// cannot cross a domain boundary. Tying the borrow to a token would leave
    /// the entire consumer side, which is where reads happen, unable to call
    /// this at all. Ending the borrow before the buffer is handed on is
    /// therefore an obligation on the caller that the type system does not
    /// carry.
    pub unsafe fn read(&self, index: usize, offset: usize, len: u32) -> &[u8] {
        assert!(
            span_fits(offset, len as usize),
            "read span exceeds the buffer"
        );
        let src = self.buffers[index].get().cast::<u8>();
        // SAFETY: the span was just checked to lie within the buffer, and
        // indexing checked `index`, so it covers owned, initialised bytes (the
        // pool is created zeroed and never deinitialised). The caller's contract
        // keeps the buffer owned and unwritten for the borrow's life.
        unsafe { core::slice::from_raw_parts(src.add(offset), len as usize) }
    }
}

/// Whether `offset..offset + len` lies within a single buffer. `checked_add`
/// because the operands are peer-controlled and their sum can itself overflow,
/// which would otherwise wrap into a span that looks small enough.
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

/// Proof of exclusive ownership of one pool buffer.
///
/// Minted only by [`FreeList::pop`] and consumed by [`FreeList::push`]. It is
/// neither `Copy` nor `Clone`, so it is the compiler rather than a runtime
/// check that makes returning the same buffer twice through `push`
/// unrepresentable.
///
/// Dropping a token does **not** return the buffer: the index stays outstanding
/// and the pool cannot hand it out again until it comes back through
/// [`FreeList::reclaim`]. That is deliberate — dropping the token is exactly how
/// a buffer leaves Rust's ownership tracking and enters the cross-domain ring
/// protocol, where it travels as a plain index. A token dropped with no matching
/// `reclaim` is therefore a leaked buffer, permanently.
#[must_use]
#[derive(Debug)]
pub struct OwnedBuffer(u32);

impl OwnedBuffer {
    /// The pool index this token owns, for indexing the [`BufferPool`] or
    /// filling a descriptor.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.0
    }
}

/// Why a buffer could not be returned to a [`FreeList`].
///
/// Every variant carries the offending index, so a rejected return is
/// attributable: the caller can log and count *which* buffer was returned badly
/// instead of discovering later that one went missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnError {
    /// The index lies outside the pool's `0..N`. It never named a buffer, so it
    /// is forged or corrupted.
    OutOfRange(u32),
    /// The index names a real buffer that is not currently outstanding — it is
    /// already free. This is the duplicate return, and the return of a buffer
    /// this ledger never handed out.
    NotOutstanding(u32),
    /// The free stack has no room. Unreachable while the free/outstanding
    /// partition holds, since an outstanding index proves a free slot exists;
    /// it exists so that a broken internal invariant surfaces as a typed error
    /// instead of an out-of-bounds write.
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

/// A domain-local ledger of which pool buffers a protection domain may hand out.
///
/// Private per-domain state, never shared. It holds the free indices as a LIFO
/// stack — the most recently returned buffer is the warmest in cache — and
/// beside it the outstanding set, one flag per index. Together they partition
/// `0..N` into free and outstanding, which is what makes ownership an identity
/// rather than a count; see the crate header.
pub struct FreeList<const N: usize> {
    /// The free indices, `indices[..top]`. Each index appears at most once, an
    /// invariant the outstanding set is what enforces.
    indices: [u32; N],
    /// Whether each index is currently handed out. A flag per index rather than
    /// a packed bit per index: a `[u64; N.div_ceil(64)]` word array cannot be
    /// expressed without `generic_const_exprs`, an incomplete feature whose
    /// `where` bound leaks into every downstream type that names a `FreeList`.
    /// At the pool sizes in play the difference is tens of bytes of private
    /// memory, which does not buy an unstable feature in a crate whose purpose
    /// is soundness.
    outstanding: [bool; N],
    top: usize,
}

impl<const N: usize> FreeList<N> {
    /// A ledger owning every buffer index `0..N`, none outstanding.
    ///
    /// The only constructor: a ledger always accounts for the whole pool, so
    /// there is exactly one way to enter the state machine and the
    /// free-plus-outstanding invariant holds by construction.
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

    /// Take exclusive ownership of one free buffer, or `None` if every buffer is
    /// already outstanding.
    ///
    /// The returned token marks its index outstanding until it is returned
    /// through [`push`](Self::push) or [`reclaim`](Self::reclaim); see
    /// [`OwnedBuffer`] for why dropping it leaks the buffer.
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
    /// This is the type-safe return: a token cannot be copied or used twice, so
    /// the caller cannot express a double return here. The index is still
    /// checked, because holding a token does not by itself prove *this* ledger
    /// handed it out — it may have been minted by a ledger over a larger pool,
    /// or its index may already have been taken back through
    /// [`reclaim`](Self::reclaim) from under it.
    ///
    /// # Errors
    /// [`ReturnError::OutOfRange`] if the token comes from a larger pool,
    /// [`ReturnError::NotOutstanding`] if this ledger does not have that index
    /// handed out, [`ReturnError::ListFull`] if its internal invariant is
    /// broken. On any error the ledger is unchanged and the token is consumed,
    /// so unless the caller kept the index the buffer stays outstanding for
    /// good — count the error rather than discard it.
    pub fn push(&mut self, buffer: OwnedBuffer) -> Result<(), ReturnError> {
        self.accept(buffer.index())
    }

    /// Return a buffer named by a bare index, as a peer or a device does.
    ///
    /// This is the crate's trust boundary. The index is untrusted: it arrives
    /// over shared memory from a domain that may be byzantine, so it is checked
    /// against the pool's range and against the outstanding set before it is
    /// believed. Rejecting a *non-outstanding* index is what makes a duplicate
    /// or forged return impossible rather than merely counted — accepting one
    /// would hand a buffer that is already free to a second owner.
    ///
    /// # Errors
    /// [`ReturnError::OutOfRange`] if `index` is not a pool index,
    /// [`ReturnError::NotOutstanding`] if it is not currently handed out (a
    /// duplicate, or a buffer never allocated), [`ReturnError::ListFull`] if the
    /// ledger's internal invariant is broken. A rejected return leaves the
    /// ledger untouched: the index keeps its state, so a buffer that really is
    /// outstanding can still be returned by whoever holds it.
    pub fn reclaim(&mut self, index: u32) -> Result<(), ReturnError> {
        self.accept(index)
    }

    /// The shared body of [`push`](Self::push) and [`reclaim`](Self::reclaim):
    /// validate first and mutate only afterwards, so a rejected return cannot
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

    /// How many buffers are free to hand out. The rest of the pool's `N` indices
    /// are outstanding.
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

    #[test]
    fn write_then_read_round_trips_bytes() {
        let pool = BufferPool::<4>::new();
        let payload = [1u8, 2, 3, 4, 5];
        // SAFETY: single-threaded test; we own index 2 for the whole test, and
        // `payload` is a local that does not borrow from the pool.
        let len = unsafe { pool.write(2, &payload) }.expect("five bytes fit a buffer");
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
        let pool = BufferPool::<1>::default();
        assert_eq!(pool.capacity(), 1);
        // SAFETY: single-threaded test; we own index 0 throughout; inputs local.
        unsafe {
            pool.write(0, &[0xEEu8; 32]).expect("32 bytes fit a buffer");
            pool.write_at(0, 12, &[1, 2, 3]);
        }
        // SAFETY: own index 0; no live borrow into it while we read.
        let bytes = unsafe { pool.read(0, 0, 16) };
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
            // Refused, not partially applied: the earlier contents survive.
            assert_eq!(pool.read(0, 0, 4), &[0x11u8; 4]);
        }
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
    #[should_panic(expected = "read span exceeds the buffer")]
    fn read_past_the_buffer_end_panics_in_every_profile() {
        let pool = BufferPool::<1>::new();
        // SAFETY: own index 0; expected to fault on the span check before it
        // constructs any slice.
        let _ = unsafe { pool.read(0, 1, BUFFER_SIZE as u32) };
    }

    #[test]
    #[should_panic(expected = "read span exceeds the buffer")]
    fn read_offset_that_overflows_the_span_sum_panics() {
        let pool = BufferPool::<1>::new();
        // SAFETY: own index 0; expected to fault on the span check.
        let _ = unsafe { pool.read(0, usize::MAX, 8) };
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
