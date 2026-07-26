//! The shared dataplane regions and the buffer-ownership protocol common to the
//! protection domains.
//!
//! Faces the byzantine peer protection domain (CONCEPT §7.1): this crate *is*
//! the inter-PD protocol, so it defines what one domain must withstand from
//! another.
//!
//! It carries no seL4/Microkit dependency on purpose: region layout and
//! ownership protocol are pure logic, so both are exercised in full on the
//! host, and the protection-domain binaries stay thin adapters that map a
//! region, hand its address here, and drive the protocol from notifications.
//!
//! # One pipeline is three regions, because a region is the unit of grant
//!
//! A pipeline joins three domains into `rx driver -> forwarder -> tx driver`
//! over one buffer pool. One pool is what makes forwarding zero-copy end to
//! end: the receiving NIC DMAs a frame into a pool buffer, the transmitting NIC
//! DMAs it back out of that very buffer, and only the descriptor moves.
//!
//! Microkit grants memory a region at a time, so what a domain can reach is
//! decided by where the region boundaries fall and never by which fields its
//! code touches. The pipeline is therefore cut three ways — [`Pool`],
//! [`ForwardRings`], [`ReturnRing`] — which lets the forwarder hold the two
//! rings it moves descriptors between while holding neither the pool it never
//! dereferences nor the return ring it never produces on. The cut is free: the
//! two ring regions each round up to one mapping page, which is what all three
//! rings in one region rounded up to. A [`Pool`] goes to the two drivers alone,
//! and to the receiving one as a physical address with no mapping at all.
//!
//! # Handles are taken once, at attach (DOC-9)
//!
//! A handle holds its side's ring position, so a second one restarts at slot
//! zero and redelivers descriptors the first already handed over. Every role
//! type here therefore borrows its region for its lifetime and takes each
//! handle in its `attach` constructor — but nothing stops a domain calling two
//! `attach`es over one ring end, and this crate's own tests take extra handles
//! deliberately. Closing it needs the once-only claim `queue`'s header
//! describes, threaded through every role's `attach` across this crate and
//! `nic-driver-core`.
//!
//! # What a hostile peer cannot cause, and what enforces it
//!
//! * **No out-of-bounds slot access and no redelivery of a descriptor already
//!   handed over** — `queue`, whose positions live in memory the peer cannot
//!   map and whose only shared read is masked into range.
//! * **No out-of-bounds dereference of a forged descriptor** —
//!   [`descriptor_in_bounds`] on the consuming side before the span is touched,
//!   backstopped unconditionally by `packet_buffer`'s own span checks.
//! * **No double-owned buffer through a forged or duplicated return** —
//!   [`PoolOwner::reclaim`], in two layers: `packet_buffer`'s ledger for the
//!   index itself, and this crate's *lent* set for what the ledger cannot see.
//! * **No unbounded work** — [`DRAIN_LIMIT`], derived from this crate's own
//!   constants and never from a peer-influenced estimate.
//! * **No panic** — every rejection above is a counted drop ([`PoolCounters`],
//!   [`ForwardCounters`]). Peer-supplied values are input and are rejected
//!   safely; only a violated invariant of this domain's own private state fails
//!   visibly.
//!
//! # The accepted, tracked residue
//!
//! * **Buffer loss.** A peer stalling its side of a ring can leave
//!   [`ForwardStage::poll`] unable to place a descriptor it already dequeued.
//!   A dequeue cannot be undone and this domain does not produce onto that
//!   ring, so the buffer is lost to its owner's ledger for good. The pool
//!   shrinks; nothing is double-owned and nothing crashes.
//! * **Frame loss and reordering**, by forging a cursor.
//! * **Writing pool bytes at any time.** The two drivers share a pool, and no
//!   Rust type stops one of them scribbling a buffer it does not own. That is
//!   contained by the pool never handing out a safe reference to those bytes,
//!   and it is why an IOMMU (CONCEPT §7.2) is what finally confines a NIC's DMA
//!   rather than anything here.

#![cfg_attr(not(test), no_std)]

use core::mem::{align_of, offset_of, size_of};

use packet_buffer::{BufferPool, FreeList, ReturnError};
use queue::SpscRing;

pub use packet_buffer::{BUFFER_SIZE, OwnedBuffer};
pub use queue::{RingConsumer, RingProducer};
pub use wire::Descriptor;

pub const POOL_BUFFERS: usize = 64;

/// Power of two; usable capacity is one less. Sized above [`POOL_BUFFERS`] so
/// no ring can fill before the pool is exhausted, which makes buffer hand-offs
/// along a correctly accounted chain infallible.
pub const RING_SLOTS: usize = 128;

/// The most descriptors any single drain of a peer-fed ring will process.
///
/// A peer that keeps advancing its published cursor keeps a dequeue returning
/// descriptors forever, and a domain stuck in that loop stops servicing its own
/// device. One full ring's worth is the natural bound — no legitimate backlog
/// can exceed `RING_SLOTS - 1` real descriptors or [`POOL_BUFFERS`] outstanding
/// buffers — and it comes from this crate's own constants rather than from a
/// ring's peer-influenced `len()`.
pub const DRAIN_LIMIT: usize = RING_SLOTS;

/// The granularity Microkit maps a memory region at, and so the alignment every
/// region base has. For a [`Pool`] it is also what fixes each buffer's DMA
/// alignment, the pool being the whole of its region rather than a field in one.
pub const MAPPING_ALIGN: usize = 0x1000;

pub type Ring = SpscRing<RING_SLOTS>;

/// Both NICs' DMA target, and the whole of one memory region: pool buffer `i`
/// sits at the region's own physical base plus `i * BUFFER_SIZE`, with no
/// offset to add and none to get wrong.
pub type Pool = BufferPool<POOL_BUFFERS>;

/// Bytes the system description reserves for each region
/// (`systems/qemu-x86_64/librefirewall.system:99-104`), derived rather than
/// chosen: the fewest [`MAPPING_ALIGN`] pages that hold the region's type. As a
/// literal the single-region size drifted to 1.93x its type, mapping bytes no
/// field names into three domains. Nothing here re-reads that XML, so a smaller
/// `size=` still surfaces only at boot, as a truncated mapping.
pub const POOL_REGION_SIZE: usize = size_of::<Pool>().next_multiple_of(MAPPING_ALIGN);

/// As [`POOL_REGION_SIZE`], for the forwarder's region.
pub const FORWARD_REGION_SIZE: usize = size_of::<ForwardRings>().next_multiple_of(MAPPING_ALIGN);

/// As [`POOL_REGION_SIZE`], for the return region.
pub const RETURN_REGION_SIZE: usize = size_of::<ReturnRing>().next_multiple_of(MAPPING_ALIGN);

/// Whether a descriptor from a neighbouring protection domain names a span
/// within one pool buffer. A failing descriptor is rejected, never followed.
#[must_use]
pub fn descriptor_in_bounds(descriptor: &Descriptor) -> bool {
    (descriptor.buffer as usize) < POOL_BUFFERS
        && (descriptor.offset as usize)
            .checked_add(descriptor.len as usize)
            .is_some_and(|end| end <= BUFFER_SIZE)
}

/// Saturating rather than wrapping: the rate is attacker-controlled, and a
/// wrapped counter turns a sustained flood back into a small number.
fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// The forwarder's region: the two rings a descriptor crosses on its way from
/// the receiving driver to the transmitting one.
///
/// This is the whole of what the forwarder is granted. The pool those
/// descriptors index and the ring the buffers come back on are separate
/// regions, which it never maps.
///
/// A zeroed region is the valid empty state, so no domain constructs one; each
/// attaches to the mapped frames with [`attach_region!`].
#[repr(C)]
pub struct ForwardRings {
    /// Received frames, rx driver to forwarder.
    pub rx: Ring,
    /// Frames to transmit, forwarder to tx driver.
    pub tx: Ring,
}

/// The return region: transmitted buffers, tx driver back to the pool-owning rx
/// driver.
///
/// Its own region rather than a third field beside [`ForwardRings`], which is
/// what denies the forwarder the ability to forge a return — the one move that
/// would put a live buffer back on an owner's free stack.
#[repr(C)]
pub struct ReturnRing {
    pub free: Ring,
}

// A peer domain reads these bytes at these offsets, so pin every field offset
// and not merely the component sizes: a reorder keeps the sizes identical while
// silently making one domain's `rx` another's `tx`. Offsets and total size
// together also prove each layout carries no padding.
const _: () = {
    assert!(size_of::<Ring>() == 8 + RING_SLOTS * size_of::<Descriptor>());
    assert!(size_of::<Ring>() == 1544);
    assert!(size_of::<Pool>() == POOL_BUFFERS * BUFFER_SIZE);
    assert!(size_of::<Pool>() == 0x20000);
    assert!(offset_of!(ForwardRings, rx) == 0);
    assert!(offset_of!(ForwardRings, tx) == size_of::<Ring>());
    assert!(size_of::<ForwardRings>() == 2 * size_of::<Ring>());
    assert!(size_of::<ForwardRings>() == 3088);
    assert!(offset_of!(ReturnRing, free) == 0);
    assert!(size_of::<ReturnRing>() == size_of::<Ring>());
    // Exactly four, not merely "within a page": the rings' `AtomicU32`s are the
    // only alignment in either region, and an upper-bound check can never fail,
    // so it could never catch the reorder or field-type change it exists to
    // catch. A `Pool` is byte-aligned as a type, which is why its buffers' DMA
    // alignment comes from its region base instead.
    assert!(align_of::<ForwardRings>() == 4);
    assert!(align_of::<ReturnRing>() == 4);
};

// The three grants, pinned as tightly as the fields: each `size=` in the system
// description is one of these literals, and each region exceeds its type by less
// than one page, so no unaddressed slack can return unnoticed.
const _: () = {
    assert!(POOL_REGION_SIZE == 0x20000);
    assert!(FORWARD_REGION_SIZE == 0x1000);
    assert!(RETURN_REGION_SIZE == 0x1000);
    assert!(POOL_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(FORWARD_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(RETURN_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    // The pool region is its type exactly, with no rounding remainder at all.
    assert!(POOL_REGION_SIZE == size_of::<Pool>());
    assert!(FORWARD_REGION_SIZE - size_of::<ForwardRings>() < MAPPING_ALIGN);
    assert!(RETURN_REGION_SIZE - size_of::<ReturnRing>() < MAPPING_ALIGN);
    // Splitting the pipeline cost no page: the three regions together are
    // exactly what one region holding all four components rounded up to. A
    // change that made the cut expensive fails here rather than in a report
    // nobody diffed.
    assert!(
        POOL_REGION_SIZE + FORWARD_REGION_SIZE + RETURN_REGION_SIZE
            == (size_of::<Pool>() + 3 * size_of::<Ring>()).next_multiple_of(MAPPING_ALIGN)
    );
};

// The DMA-alignment obligation `packet_buffer` names this crate as the owner
// of: buffer `i` sits at `pool_paddr + i * BUFFER_SIZE`, and a pool is the whole
// of its region, so a region base at the mapping granularity makes every buffer
// `BUFFER_SIZE`-aligned with no offset in the chain to get wrong.
const _: () = assert!(MAPPING_ALIGN.is_multiple_of(BUFFER_SIZE));

impl ForwardRings {
    /// For host use; a mapped region is already zeroed and needs no
    /// construction.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rx: Ring::new(),
            tx: Ring::new(),
        }
    }
}

impl Default for ForwardRings {
    fn default() -> Self {
        Self::new()
    }
}

impl ReturnRing {
    /// For host use; see [`ForwardRings::new`].
    #[must_use]
    pub const fn new() -> Self {
        Self { free: Ring::new() }
    }
}

impl Default for ReturnRing {
    fn default() -> Self {
        Self::new()
    }
}

/// Physical address of pool buffer `index`, where `pool_paddr` is the [`Pool`]
/// region's own physical base — the address a Microkit `setvar region_paddr`
/// patches into the driver that hands it to its NIC.
///
/// # Panics
/// If `index >= POOL_BUFFERS`, in every build profile — a `debug_assert!` would
/// be absent from every image that boots (ENG-10, BLD-3). The result would
/// otherwise address *outside* the region, and a driver posts it to a NIC as a
/// DMA target: with no IOMMU, an arbitrary physical write.
///
/// A first-party invariant break rather than untrusted input, because `index`
/// is bounded before every call by one of two enforcers:
///
/// * an [`OwnedBuffer`] index, which exists only if [`PoolOwner::alloc`] minted
///   it from a `FreeList<POOL_BUFFERS>` — proven by this crate's
///   `a_forged_out_of_range_return_is_dropped_and_counted`, which asserts every
///   minted index is below `POOL_BUFFERS`;
/// * a peer-supplied [`Descriptor`]`::buffer` past an unconditional
///   [`descriptor_in_bounds`] rejection — proven by
///   `descriptor_in_bounds_matches_a_widened_reference`.
///
/// A hostile peer or device therefore reaches a rejection, never this
/// assertion; reaching it means an enforcer broke, which is surfaced visibly
/// rather than counted as traffic (ENG-5, ENG-12).
#[must_use]
pub const fn buffer_paddr(pool_paddr: u64, index: u32) -> u64 {
    assert!(
        (index as usize) < POOL_BUFFERS,
        "buffer_paddr would address outside the pool"
    );
    pool_paddr + index as u64 * BUFFER_SIZE as u64
}

/// Attach to a mapped region and borrow it for the domain's lifetime.
/// Protection domains call this through [`attach_region!`], which states the
/// aliasing invariant once for every call site.
///
/// # Panics
/// If `ptr` is not aligned for `T`, in every build profile: a bound absent from
/// the shipped image is not a bound (ENG-10), and it costs one compare.
///
/// # Safety
/// `ptr` must be aligned to `align_of::<T>()`, point to a live mapping of at
/// least `size_of::<T>()` bytes that is either zeroed or already a valid value,
/// and outlive `'a`. The mapping may be shared read-write with peer protection
/// domains and used as a device DMA target, so `T` must expose no safe path to
/// its own bytes — a peer's writes are then a protocol concern rather than a
/// soundness one — and the caller must never create a `&mut T` to it.
#[must_use]
pub unsafe fn attach_region<'a, T: Sync>(ptr: *mut T) -> &'a T {
    assert!(ptr.is_aligned(), "region is misaligned");
    // SAFETY: the caller guarantees an aligned, live, correctly sized,
    // correctly initialised mapping outliving `'a`, and the assertion above
    // re-checks the alignment unconditionally. Aliasing with the peer domains
    // and with NIC DMA is sound because the caller also guarantees `T` exposes
    // no safe path to its bytes, so no safe code can hold a reference to a byte
    // a peer may concurrently write.
    unsafe { &*ptr }
}

/// Attach this protection domain to the region a Microkit `setvar_vaddr` symbol
/// names, yielding a `&'static` borrow of `$region`.
///
/// Every domain attaches through this macro so the aliasing invariant that
/// makes the `&'static` share sound is written once instead of re-derived at
/// every call site, where one copy drifted and understated the aliasing set.
///
/// A [`ForwardRings`] region is mapped read-write into three protection domains
/// at once and a [`ReturnRing`] into two; a [`Pool`] is mapped into the
/// transmitting driver alone and is additionally a DMA target of both NICs
/// (`systems/qemu-x86_64/librefirewall.system:113-161`). Sharing any of them as
/// a `&` is sound in the face of that because none exposes a safe path to those
/// bytes; whether the peers behave is the protocol question the crate header
/// answers, not a soundness one.
///
/// The calling crate must depend on `sel4-microkit`; this crate deliberately
/// does not, so the protocol stays host-testable.
#[macro_export]
macro_rules! attach_region {
    ($vaddr_symbol:ident : $region:ty) => {{
        // SAFETY: `attach_region`'s preconditions come from four different
        // components, and only the first is the Microkit tool's.
        //
        // * Address, page alignment, lifetime — the Microkit tool, which
        //   patches `$vaddr_symbol` from the matching `<map ... setvar_vaddr>`
        //   in `systems/qemu-x86_64/librefirewall.system:113-161`, maps at page
        //   granularity (far beyond any region type's 4 bytes), and makes the
        //   mapping static, so it outlives the protection domain.
        // * Zero-initialisation — the seL4 kernel, which zeroes a frame
        //   retyped from a general-purpose untyped but not one retyped from a
        //   device untyped. Which it is follows from the region's `phys_addr`
        //   lying inside RAM (`librefirewall.system:30-39,99-104`), and that
        //   from QEMU's `-m 1G` (`tools/xtask/src/qemu.rs:245`). Nothing
        //   first-party re-checks it; a region outside RAM surfaces as unbacked
        //   reads at run time rather than as a build or boot error.
        // * Minimum size — the `size=` attribute on that region, which must
        //   equal the matching `POOL_REGION_SIZE` / `FORWARD_REGION_SIZE` /
        //   `RETURN_REGION_SIZE`. Those are derived from the region types, but
        //   nothing here re-reads that XML, so the two move together or not at
        //   all.
        // * No safe path to the bytes — this crate's region types, whose fields
        //   are atomics (`Ring`) or an `UnsafeCell` reachable only through an
        //   `unsafe` accessor (`Pool`).
        //
        // No `&mut` is created here or by `attach_region`.
        unsafe {
            $crate::attach_region::<$region>(
                ::sel4_microkit::memory_region_symbol!($vaddr_symbol: *mut $region).as_ptr(),
            )
        }
    }};
}

/// Counts of the pool owner's untrusted-input rejections, which are otherwise
/// invisible: a byzantine peer's activity looks exactly like an idle link.
///
/// Monotonic for the domain's life and saturating; there is no reset, because a
/// metrics endpoint (CONCEPT §11) differences successive scrapes and a reset
/// would forge a negative rate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PoolCounters {
    /// Returns naming an index this domain never lent: forged, out of range, a
    /// duplicate of a return already accepted, or — the reason the lent set
    /// exists — a real buffer still posted to this domain's own NIC.
    pub reclaim_not_lent: u64,
    /// Returns of a lent index that `packet_buffer`'s ledger nevertheless
    /// refused. Unreachable while the lent set and the ledger agree, a lent
    /// index being outstanding by construction; counted rather than asserted so
    /// a divergence surfaces as a lost buffer with a number attached.
    pub reclaim_refused: u64,
}

/// The pool-owning side of a pipeline: it owns every buffer, lends them out as
/// bare indices, and takes them back off the [`ReturnRing`].
///
/// Ownership is a move-only [`OwnedBuffer`] for as long as the buffer stays
/// inside this domain, so a local double-release is not expressible. The token
/// dissolves to a bare index at [`lend`](Self::lend) alone, that being where
/// the buffer leaves Rust's ownership tracking for the ring protocol.
///
/// It borrows the return ring and **not** the [`Pool`]: an owner accounts for
/// buffers by index and never reads or writes their bytes, which is what lets
/// the receiving driver take its pool's physical address without mapping it.
pub struct PoolOwner<'ring> {
    ledger: FreeList<POOL_BUFFERS>,
    /// Which indices were dissolved onto a ring and may therefore legitimately
    /// come back. The ledger cannot answer this: a buffer posted to this
    /// domain's own NIC is "outstanding" exactly as a lent one is, and a peer
    /// naming it would otherwise have a live DMA target handed back to the free
    /// stack and re-issued to a second owner.
    lent: [bool; POOL_BUFFERS],
    free: RingConsumer<'ring, RING_SLOTS>,
    counters: PoolCounters,
}

impl<'ring> PoolOwner<'ring> {
    /// Take ownership of this domain's pool and of `returns`' consumer handle —
    /// once per protection domain per pipeline; see the crate header.
    #[must_use]
    pub fn attach(returns: &'ring ReturnRing) -> Self {
        Self {
            ledger: FreeList::full(),
            lent: [false; POOL_BUFFERS],
            free: returns.free.consumer(),
            counters: PoolCounters::default(),
        }
    }

    /// Take exclusive ownership of a free buffer, e.g. to hand to a device for
    /// it to fill. `None` when the pool is momentarily exhausted.
    pub fn alloc(&mut self) -> Option<OwnedBuffer> {
        self.ledger.pop()
    }

    /// Return a buffer this domain still holds, without publishing it — the
    /// path taken when a hand-off could not proceed.
    ///
    /// # Panics
    /// If the ledger refuses the token: a violation of *this domain's own*
    /// invariant rather than untrusted input, so it fails visibly. Holding the
    /// token means the index is outstanding, and the only route by which a peer
    /// could have had it freed underneath us is [`reclaim`](Self::reclaim),
    /// which accepts an index only if it is in the lent set — which a held
    /// token's index never is. Proven by this crate's
    /// `a_return_of_a_buffer_still_held_by_this_domain_is_refused`.
    pub fn release(&mut self, buffer: OwnedBuffer) {
        self.ledger
            .push(buffer)
            .expect("a held token names an outstanding, unlent buffer");
    }

    /// Publish `len` bytes at `offset` of an already-filled buffer on `ring`,
    /// handing it to the next domain without copying.
    ///
    /// The token is consumed and only a bare index crosses onto the shared
    /// ring, a move-only token being unable to cross a protection-domain
    /// boundary. The index is recorded as lent, which is what later lets
    /// [`reclaim`](Self::reclaim) tell a legitimate return from a peer naming a
    /// buffer it was never given.
    ///
    /// `buffer` must have been minted by *this* owner's [`alloc`](Self::alloc):
    /// an [`OwnedBuffer`] is not branded with its ledger, so one from a
    /// differently sized pool would index the lent set out of range. Branding
    /// the token with its pool size is the recorded DOC-9 fix.
    ///
    /// # Errors
    /// Returns the token unchanged when the ring is momentarily full, so the
    /// caller still owns the buffer and can [`release`](Self::release) it. The
    /// buffer is not marked lent in that case: nothing was handed over.
    pub fn lend(
        &mut self,
        ring: &mut RingProducer<'_, RING_SLOTS>,
        buffer: OwnedBuffer,
        offset: u32,
        len: u32,
    ) -> Result<(), OwnedBuffer> {
        let index = buffer.index();
        if ring
            .try_enqueue(Descriptor::new(index, offset, len))
            .is_err()
        {
            return Err(buffer);
        }
        // In range because `alloc` mints only from this owner's
        // `FreeList<POOL_BUFFERS>`, so no peer value reaches this index;
        // asserted by `a_forged_out_of_range_return_is_dropped_and_counted`.
        self.lent[index as usize] = true;
        Ok(())
    }

    /// Take back the buffers the transmitting domain has returned, until the
    /// `free` ring is observed empty or [`DRAIN_LIMIT`] descriptors have been
    /// processed. Returns how many buffers were reclaimed.
    ///
    /// Every index here is peer-supplied, so a return is accepted only if the
    /// index is in this domain's lent set *and* `packet_buffer`'s ledger
    /// accepts it. A rejected return changes nothing and is counted in
    /// [`counters`](Self::counters), so the buffer it named keeps whatever
    /// state it really had and its rightful holder can still return it.
    pub fn reclaim(&mut self) -> usize {
        let Self {
            ledger,
            lent,
            free,
            counters,
        } = self;
        let mut reclaimed = 0;
        for descriptor in free.drain(DRAIN_LIMIT) {
            let index = descriptor.buffer;
            // `get` rather than an index: `index` is a peer value, so an
            // out-of-range one must be a rejection and never a panic.
            if lent.get(index as usize) != Some(&true) {
                bump(&mut counters.reclaim_not_lent);
                continue;
            }
            match ledger.reclaim(index) {
                Ok(()) => {
                    lent[index as usize] = false;
                    reclaimed += 1;
                }
                Err(ReturnError::OutOfRange(_))
                | Err(ReturnError::NotOutstanding(_))
                | Err(ReturnError::ListFull(_)) => bump(&mut counters.reclaim_refused),
            }
        }
        reclaimed
    }

    /// How many buffers the owner currently holds free.
    #[must_use]
    pub fn owned(&self) -> usize {
        self.ledger.len()
    }

    #[must_use]
    pub fn counters(&self) -> PoolCounters {
        self.counters
    }
}

/// Monotonic and saturating for the reasons given on [`PoolCounters`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ForwardCounters {
    /// Descriptors moved onward, ownership and all.
    pub forwarded: u64,
    /// Descriptors dropped because the destination ring would not take them.
    /// Each loses its buffer to the pool for good — see the crate header — so
    /// a rising count is a shrinking pool.
    pub dropped: u64,
}

/// One direction of the forwarding chain: it moves descriptors from a
/// pipeline's `rx` ring to its `tx` ring, transferring buffer ownership onward
/// without touching the bytes.
///
/// [`ForwardRings`] is the only region it borrows, and the whole of what its
/// domain is granted.
pub struct ForwardStage<'ring> {
    from: RingConsumer<'ring, RING_SLOTS>,
    to: RingProducer<'ring, RING_SLOTS>,
    counters: ForwardCounters,
}

impl<'ring> ForwardStage<'ring> {
    /// Take `rings`' `rx` consumer and `tx` producer handles — once per
    /// protection domain per pipeline; see the crate header.
    #[must_use]
    pub fn attach(rings: &'ring ForwardRings) -> Self {
        Self {
            from: rings.rx.consumer(),
            to: rings.tx.producer(),
            counters: ForwardCounters::default(),
        }
    }

    /// Move descriptors onward until the source ring is observed empty, the
    /// destination refuses one, or [`DRAIN_LIMIT`] descriptors have been moved.
    /// Returns how many moved.
    ///
    /// The rings are sized above the pool, so along a correctly accounted chain
    /// the destination can always take what the source held. A refusal means
    /// accounting has already broken — a byzantine peer over-filling the source
    /// while the destination stalls — and the response is to count the drop and
    /// stop draining rather than fault, the descriptor being peer input.
    /// Stopping on the first refusal is deliberate: every further dequeue into
    /// a full destination would lose another buffer.
    pub fn poll(&mut self) -> usize {
        let Self { from, to, counters } = self;
        let mut moved = 0;
        for descriptor in from.drain(DRAIN_LIMIT) {
            if to.try_enqueue(descriptor).is_err() {
                bump(&mut counters.dropped);
                break;
            }
            moved += 1;
        }
        counters.forwarded = counters.forwarded.saturating_add(moved as u64);
        moved
    }

    #[must_use]
    pub fn counters(&self) -> ForwardCounters {
        self.counters
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use proptest::prelude::*;
    use std::boxed::Box;
    use std::collections::BTreeSet;
    use std::thread;
    use std::vec::Vec;

    /// One pipeline's three regions, allocated the way a protection domain is
    /// handed them: separate mappings that share nothing.
    struct Regions {
        pool: Box<Pool>,
        rings: Box<ForwardRings>,
        returns: Box<ReturnRing>,
    }

    impl Regions {
        fn new() -> Self {
            Self {
                pool: Box::new(Pool::new()),
                rings: Box::new(ForwardRings::new()),
                returns: Box::new(ReturnRing::new()),
            }
        }
    }

    /// Overwrite a ring's shared cursors the way a byzantine peer that maps the
    /// region read-write can at any moment. The cursors are private to `queue`,
    /// so reach them through the region's known ABI: `head` then `tail`, both
    /// `u32`, at the ring's front (pinned by that crate's own layout asserts).
    fn forge_cursors(ring: &Ring, head: u32, tail: u32) {
        let base = core::ptr::from_ref(ring).cast::<AtomicU32>();
        // SAFETY: `SpscRing` is `#[repr(C)]` with `head` at offset 0 and `tail`
        // at offset 4 as `AtomicU32`s (asserted in `queue`), so both pointers
        // are in bounds and correctly aligned for the live ring borrowed here.
        // Atomic stores are exactly what a peer domain performs on these words.
        unsafe {
            (*base).store(head, Ordering::Relaxed);
            (*base.add(1)).store(tail, Ordering::Relaxed);
        }
    }

    /// Stand in for the receiving NIC: take a free buffer, fill it as a DMA
    /// would, and publish the span on the pipeline's `rx` ring. Returns the
    /// buffer index published, or `None` when the pool is momentarily empty.
    fn receive(
        pool: &Pool,
        owner: &mut PoolOwner<'_>,
        rx: &mut RingProducer<'_, RING_SLOTS>,
        payload: &[u8],
    ) -> Option<u32> {
        let buffer = owner.alloc()?;
        let index = buffer.index();
        // SAFETY: `buffer` came from our ledger, so we own it exclusively until
        // `lend` transfers it; `payload` is a local, not a pool borrow.
        let len = unsafe { pool.write(index as usize, payload) }
            .expect("the test payloads are far smaller than a buffer");
        match owner.lend(rx, buffer, 0, len) {
            Ok(()) => Some(index),
            Err(buffer) => {
                owner.release(buffer);
                None
            }
        }
    }

    /// Stand in for the transmitting NIC: drain every frame queued on `tx`,
    /// read its payload back, and return the buffer to its owner on `free`,
    /// invoking `on_payload` for each. Returns how many frames were transmitted.
    fn transmit(
        pool: &Pool,
        tx: &mut RingConsumer<'_, RING_SLOTS>,
        free: &mut RingProducer<'_, RING_SLOTS>,
        mut on_payload: impl FnMut(&[u8]),
    ) -> usize {
        let mut count = 0;
        // One buffer's worth of private storage, reused across the drain: what
        // `on_payload` inspects is a snapshot here, never a borrow of the pool.
        let mut storage = [0u8; BUFFER_SIZE];
        for descriptor in tx.drain(DRAIN_LIMIT) {
            {
                // SAFETY: we dequeued this descriptor, so we own its buffer
                // until it is returned below. The data is the `len` bytes at
                // `offset` the rx side published, and the snapshot lands in
                // `storage`, so the borrow handed to `on_payload` is of this
                // frame's own memory and ends before the buffer is returned.
                let bytes = unsafe {
                    pool.copy_out(
                        descriptor.buffer as usize,
                        descriptor.offset as usize,
                        descriptor.len,
                        &mut storage,
                    )
                }
                .expect("`receive` published a span within one buffer");
                on_payload(bytes);
            }
            free.try_enqueue(descriptor)
                .expect("free ring has a slot for every pool buffer");
            count += 1;
        }
        count
    }

    #[test]
    fn zeroed_regions_are_valid_and_empty() {
        // Regions built from zeroed memory (as seL4 provides) must be empty and
        // immediately usable. A fresh handle starts at position zero, which is
        // exactly what a zeroed region's cursors say, so attaching to one sees
        // an empty ring without reading anything a peer could have written.
        let r = Regions::new();
        assert!(r.rings.rx.consumer().is_empty());
        assert!(r.rings.tx.consumer().is_empty());
        assert!(r.returns.free.consumer().is_empty());
        assert_eq!(r.pool.capacity(), POOL_BUFFERS);
        assert_eq!(PoolOwner::attach(&r.returns).owned(), POOL_BUFFERS);
    }

    #[test]
    fn a_pool_region_gives_every_buffer_the_region_alignment() {
        // The property `packet_buffer` names this crate as the owner of. A pool
        // is the whole of its region, so there is no offset in the chain and
        // the region base's alignment is each buffer's, up to the stride.
        assert!(MAPPING_ALIGN.is_multiple_of(BUFFER_SIZE));
        let pool_paddr = 0x3100_0000u64;
        assert!(pool_paddr.is_multiple_of(MAPPING_ALIGN as u64));
        for index in 0..POOL_BUFFERS as u32 {
            assert!(buffer_paddr(pool_paddr, index).is_multiple_of(BUFFER_SIZE as u64));
        }
        // The last buffer ends exactly at the region's end: the grant holds the
        // pool and not one byte more.
        assert_eq!(
            buffer_paddr(pool_paddr, POOL_BUFFERS as u32 - 1) + BUFFER_SIZE as u64,
            pool_paddr + POOL_REGION_SIZE as u64
        );
    }

    #[test]
    fn the_region_layout_is_the_pinned_cross_domain_abi() {
        // The same offsets the `const _` blocks pin, restated as values so a
        // reviewer sees the actual region map and the sizes the system
        // description must reserve.
        assert_eq!(size_of::<Pool>(), POOL_BUFFERS * BUFFER_SIZE);
        assert_eq!(size_of::<Ring>(), 8 + RING_SLOTS * size_of::<Descriptor>());
        assert_eq!(offset_of!(ForwardRings, rx), 0);
        assert_eq!(offset_of!(ForwardRings, tx), size_of::<Ring>());
        assert_eq!(size_of::<ForwardRings>(), 2 * size_of::<Ring>());
        assert_eq!(offset_of!(ReturnRing, free), 0);
        assert_eq!(size_of::<ReturnRing>(), size_of::<Ring>());
        assert_eq!(align_of::<ForwardRings>(), 4);
        assert_eq!(align_of::<ReturnRing>(), 4);
        // The three grants the system description must declare, as values.
        assert_eq!(size_of::<Pool>(), 0x20000);
        assert_eq!(size_of::<ForwardRings>(), 3088);
        assert_eq!(size_of::<ReturnRing>(), 1544);
        assert_eq!(POOL_REGION_SIZE, 0x20000);
        assert_eq!(FORWARD_REGION_SIZE, 0x1000);
        assert_eq!(RETURN_REGION_SIZE, 0x1000);
        // And the reason the split is free: three regions, the same 0x22000 one
        // region holding all four components rounded up to.
        assert_eq!(
            POOL_REGION_SIZE + FORWARD_REGION_SIZE + RETURN_REGION_SIZE,
            0x22000
        );
    }

    #[test]
    fn descriptor_bounds_reject_out_of_pool_spans() {
        let max = BUFFER_SIZE as u32;
        assert!(descriptor_in_bounds(&Descriptor::new(0, 0, max)));
        assert!(descriptor_in_bounds(&Descriptor::new(
            POOL_BUFFERS as u32 - 1,
            max - 1,
            1
        )));
        assert!(descriptor_in_bounds(&Descriptor::new(0, max, 0)));
        // Buffer index outside the pool.
        assert!(!descriptor_in_bounds(&Descriptor::new(
            POOL_BUFFERS as u32,
            0,
            1
        )));
        // Span runs past the buffer end.
        assert!(!descriptor_in_bounds(&Descriptor::new(0, 1, max)));
        // Offset + len overflows.
        assert!(!descriptor_in_bounds(&Descriptor::new(
            0,
            u32::MAX,
            u32::MAX
        )));
    }

    #[test]
    #[should_panic(expected = "buffer_paddr would address outside the pool")]
    fn a_paddr_for_an_index_outside_the_pool_faults_rather_than_leaving_the_region() {
        // The exact step by which a forged index used to become a DMA-writable
        // address outside the shared region. Ungated: the bound is compiled
        // into every profile, so gating this on `debug_assertions` would prove
        // a property of a build that never boots.
        let _ = buffer_paddr(0x3100_0000, POOL_BUFFERS as u32);
    }

    #[test]
    fn attaching_to_an_aligned_zeroed_region_yields_the_empty_state() {
        // What a protection domain actually does at start-up: seL4 hands over a
        // zeroed, page-aligned mapping, and attaching to it must observe empty
        // rings and a full pool without touching anything a peer controls.
        let rings = Box::into_raw(Box::new(ForwardRings::new()));
        let returns = Box::into_raw(Box::new(ReturnRing::new()));
        // SAFETY: both pointers come from `Box::into_raw`, so each is aligned,
        // live, and exactly its region type's size holding a valid value; both
        // are reclaimed below, after the borrows end.
        let (rings_ref, returns_ref) =
            unsafe { (attach_region(rings), attach_region::<ReturnRing>(returns)) };
        assert!(rings_ref.rx.consumer().is_empty());
        assert!(rings_ref.tx.consumer().is_empty());
        assert_eq!(PoolOwner::attach(returns_ref).owned(), POOL_BUFFERS);
        // SAFETY: the borrows above have ended and both pointers are the ones
        // `Box::into_raw` produced, so reconstituting the boxes is the matching
        // deallocation.
        unsafe {
            drop(Box::from_raw(rings));
            drop(Box::from_raw(returns));
        }
    }

    #[test]
    #[should_panic(expected = "region is misaligned")]
    fn attaching_to_a_misaligned_region_faults_before_the_reference_is_made() {
        // Alignment is a soundness precondition of the reference `attach_region`
        // creates, so it must fault before that, not after — in every profile,
        // which is why this test is not gated on `debug_assertions`.
        let mut backing = Box::new([0u8; size_of::<ForwardRings>() + 8]);
        // SAFETY: the offset stays inside the live allocation, so forming the
        // pointer is defined; the call is expected to fault on the alignment
        // check before it ever dereferences it.
        let misaligned = unsafe { backing.as_mut_ptr().add(1) }.cast::<ForwardRings>();
        // SAFETY: as above — this must panic on the alignment assertion; nothing
        // past it is expected to run.
        let _ = unsafe { attach_region(misaligned) };
    }

    #[test]
    fn forward_moves_descriptors_in_order() {
        let r = Regions::new();
        let mut rx_in = r.rings.rx.producer();
        let mut stage = ForwardStage::attach(&r.rings);
        let mut tx_out = r.rings.tx.consumer();
        for i in 0..5 {
            rx_in.try_enqueue(Descriptor::new(i, 12, i)).unwrap();
        }
        assert_eq!(stage.poll(), 5);
        assert_eq!(
            stage.counters(),
            ForwardCounters {
                forwarded: 5,
                dropped: 0
            }
        );
        for i in 0..5 {
            assert_eq!(tx_out.try_dequeue(), Some(Descriptor::new(i, 12, i)));
        }
        // A second poll on a drained ring moves nothing and counts nothing.
        assert_eq!(stage.poll(), 0);
    }

    #[test]
    fn forward_drops_and_counts_instead_of_panicking_when_the_destination_is_full() {
        // A byzantine rx peer over-fills `rx` while the tx driver stalls. The
        // old code panicked here, taking a well-behaved PD down on peer input.
        // The destination is filled *through the stage itself*, since a second
        // producer handle would restart at slot zero and prove nothing.
        let r = Regions::new();
        let mut rx_in = r.rings.rx.producer();
        let mut stage = ForwardStage::attach(&r.rings);

        let capacity = r.rings.tx.capacity();
        for i in 0..capacity as u32 {
            rx_in.try_enqueue(Descriptor::new(i, 0, i)).unwrap();
        }
        assert_eq!(stage.poll(), capacity, "the destination is now full");

        for i in 0..4 {
            rx_in.try_enqueue(Descriptor::new(i, 0, i)).unwrap();
        }
        assert_eq!(stage.poll(), 0);
        assert_eq!(
            stage.counters(),
            ForwardCounters {
                forwarded: capacity as u64,
                dropped: 1
            }
        );
        // Draining stopped at the first refusal rather than emptying `rx` into
        // a full destination and losing every buffer with it.
        assert_eq!(r.rings.rx.consumer().len(), 3);
    }

    #[test]
    fn forward_is_bounded_when_a_peer_keeps_the_source_ring_non_empty() {
        // A peer that keeps advancing its published `tail` makes the source
        // look permanently non-empty. Work per poll must still be finite.
        let r = Regions::new();
        let mut stage = ForwardStage::attach(&r.rings);
        let mut tx_out = r.rings.tx.consumer();
        for round in 0..8u32 {
            forge_cursors(&r.rings.rx, 0, round.wrapping_mul(37).wrapping_add(11));
            let moved = stage.poll();
            assert!(moved <= DRAIN_LIMIT, "poll moved {moved} descriptors");
            // Keep the destination drained so the bound, not fullness, is what
            // stops the loop.
            let _ = tx_out.drain(DRAIN_LIMIT).count();
        }
    }

    #[test]
    fn single_threaded_pipeline_round_trip_preserves_payloads() {
        // The three-PD forwarding chain in one thread: receive two frames,
        // forward them, transmit them, then reclaim — full pool ownership must
        // return and both payloads must survive intact and in order.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = ForwardStage::attach(&r.rings);
        let mut tx_out = r.rings.tx.consumer();
        let mut free_in = r.returns.free.producer();

        assert!(receive(&r.pool, &mut owner, &mut rx_in, &7u64.to_le_bytes()).is_some());
        assert!(receive(&r.pool, &mut owner, &mut rx_in, &8u64.to_le_bytes()).is_some());
        assert_eq!(owner.owned(), POOL_BUFFERS - 2);

        assert_eq!(stage.poll(), 2);

        let mut seen = Vec::new();
        let transmitted = transmit(&r.pool, &mut tx_out, &mut free_in, |bytes| {
            seen.push(u64::from_le_bytes(bytes.try_into().unwrap()));
        });
        assert_eq!(transmitted, 2);
        assert_eq!(seen, std::vec![7, 8]);

        // Buffers are back on the free ring; reclaiming restores full ownership.
        assert_eq!(owner.reclaim(), 2);
        assert_eq!(owner.owned(), POOL_BUFFERS);
        assert_eq!(owner.counters(), PoolCounters::default());
    }

    #[test]
    fn lend_reports_a_full_ring_and_hands_the_token_back_unlent() {
        // `lend` is a thin publish onto the ring; when the ring is full it must
        // return the token so the caller keeps the buffer, and must not record
        // it as lent — nothing was handed over.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();

        // The ring is sized above the pool, so fill it with bare descriptors
        // first; only then can a real lend be refused.
        for _ in 0..r.rings.rx.capacity() {
            rx_in.try_enqueue(Descriptor::ZERO).unwrap();
        }
        let buffer = owner.alloc().expect("a full pool has buffers");
        let index = buffer.index();
        let Err(returned) = owner.lend(&mut rx_in, buffer, 0, 0) else {
            panic!("a full ring must refuse the lend");
        };
        assert_eq!(returned.index(), index);
        owner.release(returned);
        assert_eq!(owner.owned(), POOL_BUFFERS);

        // Having never been lent, that index cannot be returned by the peer.
        let mut free_in = r.returns.free.producer();
        free_in
            .try_enqueue(Descriptor::new(index, 0, 0))
            .expect("the free ring is empty");
        assert_eq!(owner.reclaim(), 0);
        assert_eq!(owner.counters().reclaim_not_lent, 1);
    }

    #[test]
    fn a_forged_out_of_range_return_is_dropped_and_counted() {
        // The critical path: a peer injects an index that never named a buffer.
        // Accepting it put a forged index on the free stack, `alloc` handed it
        // out, and `buffer_paddr` turned it into a DMA-writable address outside
        // the region.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut free_in = r.returns.free.producer();
        for forged in [POOL_BUFFERS as u32, 999, u32::MAX] {
            free_in
                .try_enqueue(Descriptor::new(forged, 0, 0))
                .expect("the free ring has room");
        }

        assert_eq!(owner.reclaim(), 0);
        assert_eq!(owner.counters().reclaim_not_lent, 3);
        assert_eq!(owner.counters().reclaim_refused, 0);
        // The ledger is untouched and still hands out only real buffers.
        assert_eq!(owner.owned(), POOL_BUFFERS);
        let mut seen = BTreeSet::new();
        while let Some(buffer) = owner.alloc() {
            assert!((buffer.index() as usize) < POOL_BUFFERS);
            assert!(seen.insert(buffer.index()), "an index was handed out twice");
            drop(buffer);
        }
        assert_eq!(seen.len(), POOL_BUFFERS);
    }

    #[test]
    fn a_duplicate_return_is_accepted_once_and_then_refused() {
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut free_in = r.returns.free.producer();

        let buffer = owner.alloc().expect("a full pool has buffers");
        let index = buffer.index();
        owner
            .lend(&mut rx_in, buffer, 0, 0)
            .expect("the ring is empty");
        for _ in 0..3 {
            free_in
                .try_enqueue(Descriptor::new(index, 0, 0))
                .expect("the free ring has room");
        }

        assert_eq!(owner.reclaim(), 1, "only the first return is legitimate");
        assert_eq!(owner.counters().reclaim_not_lent, 2);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn a_return_of_a_buffer_still_held_by_this_domain_is_refused() {
        // The hole the lent set closes: the buffer is outstanding — posted to
        // our own NIC as a DMA target — so the ledger alone would accept the
        // return, free it, and let `alloc` hand the live DMA target to a second
        // owner.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut free_in = r.returns.free.producer();

        let posted = owner.alloc().expect("a full pool has buffers");
        let index = posted.index();
        free_in
            .try_enqueue(Descriptor::new(index, 0, 0))
            .expect("the free ring is empty");

        assert_eq!(owner.reclaim(), 0);
        assert_eq!(owner.counters().reclaim_not_lent, 1);
        assert_eq!(owner.owned(), POOL_BUFFERS - 1);
        // We still hold it, and returning it ourselves still works.
        owner.release(posted);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn a_ledger_that_disagrees_with_the_lent_set_is_counted_not_faulted() {
        // `reclaim_refused` is unreachable through the public API, since a lent
        // index is by construction outstanding. Corrupt the private lent set
        // directly — the only way to reach it — to prove the disagreement
        // surfaces as a counted drop rather than a panic or a freed buffer.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut free_in = r.returns.free.producer();
        owner.lent[3] = true;
        free_in
            .try_enqueue(Descriptor::new(3, 0, 0))
            .expect("the free ring is empty");

        assert_eq!(owner.reclaim(), 0);
        assert_eq!(owner.counters().reclaim_refused, 1);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn an_over_return_beyond_the_ring_capacity_is_dropped_not_panicked() {
        // A peer fills the whole `free` ring with returns of buffers that were
        // never lent — more of them than the pool has buffers. The old code
        // asserted on the first one.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut free_in = r.returns.free.producer();
        let mut offered = 0u64;
        while free_in
            .try_enqueue(Descriptor::new(offered as u32 % POOL_BUFFERS as u32, 0, 0))
            .is_ok()
        {
            offered += 1;
        }
        assert!(offered > POOL_BUFFERS as u64);

        assert_eq!(owner.reclaim(), 0);
        assert_eq!(owner.counters().reclaim_not_lent, offered);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn reclaim_is_bounded_when_a_peer_keeps_the_free_ring_non_empty() {
        // A forged `tail` makes the free ring look permanently non-empty; the
        // domain must return from `reclaim` and get on with servicing its NIC.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        for round in 0..8u32 {
            forge_cursors(&r.returns.free, 0, round.wrapping_mul(29).wrapping_add(5));
            let reclaimed = owner.reclaim();
            assert!(reclaimed <= DRAIN_LIMIT);
        }
        // Every phantom descriptor read out of an untouched ring names buffer 0,
        // which was never lent, so all of them were rejected.
        assert!(owner.counters().reclaim_not_lent > 0);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn a_peer_restart_that_rezeroes_the_cursors_does_not_double_own_a_buffer() {
        // The peer crashes mid-stream and comes back with both shared cursors
        // zeroed while buffers are in flight. The owner's ledger and lent set
        // are private, so nothing is freed twice; at worst descriptors are
        // replayed, and a replayed return is refused.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut free_in = r.returns.free.producer();

        let mut indices = Vec::new();
        for _ in 0..4 {
            let buffer = owner.alloc().expect("a full pool has buffers");
            indices.push(buffer.index());
            owner
                .lend(&mut rx_in, buffer, 0, 0)
                .expect("the ring is empty");
        }
        for index in &indices {
            free_in
                .try_enqueue(Descriptor::new(*index, 0, 0))
                .expect("the free ring has room");
        }
        assert_eq!(owner.reclaim(), 4);
        assert_eq!(owner.owned(), POOL_BUFFERS);

        // The restart. The owner's consume position is private, so a peer that
        // resumes from its own position zero cannot rewind it; what it can do
        // is drive the position onward over slots it never published, which
        // walks the ring all the way round and presents the four already-
        // consumed returns a second time. Every one of them must be refused.
        forge_cursors(&r.returns.free, 0, 3);
        assert_eq!(owner.reclaim(), 0, "a replayed return frees nothing");
        assert!(owner.counters().reclaim_not_lent >= 4);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn concurrent_pipeline_chain_transfers_every_buffer_in_order() {
        // The three-PD forwarding scenario end to end under real threads: an
        // rx-driver thread fills and publishes buffers, a forwarder thread moves
        // them onward, and a tx-driver thread consumes and returns them, so
        // every buffer cycles rx -> forward -> tx -> free far more times than
        // the pool holds. Both rings wrap repeatedly and every buffer is reused;
        // the sequence-numbered payloads must arrive intact and in order, and
        // full pool ownership must return to the rx driver.
        //
        // The forwarder thread borrows `rings` alone, which is the grant the
        // system description gives that domain: it can reach neither `pool` nor
        // `returns` here for the same reason it cannot there.
        const TOTAL: u64 = 500_000;
        let r = Regions::new();
        let pool: &Pool = &r.pool;
        let rings: &ForwardRings = &r.rings;
        let returns: &ReturnRing = &r.returns;

        // Scoped threads because each domain's role type borrows its region: a
        // handle *is* that domain's position, so it is taken once inside the
        // thread that owns the role and kept for the thread's life, exactly as a
        // protection domain takes it once at attach.
        thread::scope(|scope| {
            scope.spawn(move || {
                let mut owner = PoolOwner::attach(returns);
                let mut rx_in = rings.rx.producer();
                let mut sent = 0u64;
                while sent < TOTAL {
                    owner.reclaim();
                    if receive(pool, &mut owner, &mut rx_in, &sent.to_le_bytes()).is_some() {
                        sent += 1;
                    } else {
                        std::hint::spin_loop();
                    }
                }
                // Wait for the chain to hand every buffer back.
                loop {
                    owner.reclaim();
                    if owner.owned() == POOL_BUFFERS {
                        break;
                    }
                    std::hint::spin_loop();
                }
                assert_eq!(owner.counters(), PoolCounters::default());
            });

            scope.spawn(move || {
                let mut stage = ForwardStage::attach(rings);
                let mut moved = 0u64;
                while moved < TOTAL {
                    moved += stage.poll() as u64;
                    std::hint::spin_loop();
                }
                assert_eq!(stage.counters().dropped, 0);
            });

            scope.spawn(move || {
                let mut tx_out = rings.tx.consumer();
                let mut free_in = returns.free.producer();
                let mut expected = 0u64;
                while expected < TOTAL {
                    transmit(pool, &mut tx_out, &mut free_in, |bytes| {
                        let value = u64::from_le_bytes(bytes.try_into().unwrap());
                        assert_eq!(value, expected, "out-of-order or corrupted buffer");
                        expected += 1;
                    });
                    std::hint::spin_loop();
                }
            });
        });
    }

    /// One move a byzantine neighbour can make against the pool owner and the
    /// forwarding stage.
    #[derive(Clone, Debug)]
    enum PeerStep {
        /// Take a buffer and publish it, as the driver legitimately would.
        Receive,
        /// Take a buffer and keep it, as a buffer posted to the NIC is kept.
        Hold,
        /// Move descriptors along the chain.
        Forward,
        /// Push an arbitrary descriptor onto the `free` ring, as a byzantine tx
        /// driver does: forged indices, duplicates, buffers never lent.
        ReturnBare(u32),
        /// Take the returns back.
        Reclaim,
        /// Scribble a ring's shared cursors.
        ForgeCursors(u8, u32, u32),
    }

    fn any_peer_step() -> impl Strategy<Value = PeerStep> {
        prop_oneof![
            4 => Just(PeerStep::Receive),
            1 => Just(PeerStep::Hold),
            3 => Just(PeerStep::Forward),
            // Biased towards real indices so duplicate and never-lent returns
            // are reached, with arbitrary values keeping forged ones in the mix.
            3 => (0..POOL_BUFFERS as u32).prop_map(PeerStep::ReturnBare),
            2 => any::<u32>().prop_map(PeerStep::ReturnBare),
            3 => Just(PeerStep::Reclaim),
            2 => (0u8..3, any::<u32>(), any::<u32>())
                .prop_map(|(ring, head, tail)| PeerStep::ForgeCursors(ring, head, tail)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// The whole `alloc -> lend -> forward -> reclaim` chain driven by an
        /// arbitrary hostile neighbour: forged and duplicated indices on the
        /// `free` ring, scribbled cursors on every ring, and arbitrary
        /// interleaving. Nothing may panic, every step must do bounded work,
        /// and the owner set must stay conserved — the ledger may only ever
        /// hand out real, distinct pool indices, and the buffers it holds free
        /// plus those it has lent or that are held in hand can never exceed the
        /// pool.
        #[test]
        fn a_byzantine_neighbour_cannot_panic_or_double_own_a_buffer(
            steps in prop::collection::vec(any_peer_step(), 0..250),
        ) {
            let r = Regions::new();
            let mut owner = PoolOwner::attach(&r.returns);
            let mut rx_in = r.rings.rx.producer();
            let mut stage = ForwardStage::attach(&r.rings);
            let mut tx_out = r.rings.tx.consumer();
            let mut free_in = r.returns.free.producer();
            // Tokens this domain holds, standing in for buffers posted to a NIC.
            let mut held: Vec<OwnedBuffer> = Vec::new();

            for step in steps {
                match step {
                    PeerStep::Receive => {
                        if let Some(buffer) = owner.alloc()
                            && let Err(returned) = owner.lend(&mut rx_in, buffer, 0, 4)
                        {
                            owner.release(returned);
                        }
                    }
                    PeerStep::Hold => {
                        if let Some(buffer) = owner.alloc() {
                            held.push(buffer);
                        }
                    }
                    PeerStep::Forward => {
                        prop_assert!(stage.poll() <= DRAIN_LIMIT);
                        // Play the tx driver: take what arrived and hand each
                        // buffer straight back, as a well-behaved peer would.
                        for descriptor in tx_out.drain(DRAIN_LIMIT) {
                            let _ = free_in.try_enqueue(descriptor);
                        }
                    }
                    PeerStep::ReturnBare(index) => {
                        let _ = free_in.try_enqueue(Descriptor::new(index, 0, 0));
                    }
                    PeerStep::Reclaim => {
                        prop_assert!(owner.reclaim() <= DRAIN_LIMIT);
                    }
                    PeerStep::ForgeCursors(which, head, tail) => {
                        let ring = match which {
                            0 => &r.rings.rx,
                            1 => &r.rings.tx,
                            _ => &r.returns.free,
                        };
                        forge_cursors(ring, head, tail);
                    }
                }
                // Nothing was invented: free plus held can never exceed the
                // pool, and a buffer in hand is never also on the free stack.
                prop_assert!(owner.owned() <= POOL_BUFFERS);
                prop_assert!(owner.owned() + held.len() <= POOL_BUFFERS);
            }

            // The ledger still hands out only real, distinct indices, and never
            // one this domain is still holding — the conserved owner set.
            let still_held: BTreeSet<u32> = held.iter().map(OwnedBuffer::index).collect();
            let mut handed_out: BTreeSet<u32> = BTreeSet::new();
            while let Some(buffer) = owner.alloc() {
                let index = buffer.index();
                prop_assert!((index as usize) < POOL_BUFFERS, "a forged index was handed out");
                prop_assert!(handed_out.insert(index), "one buffer was handed to two owners");
                prop_assert!(!still_held.contains(&index), "a held buffer was handed out again");
                drop(buffer);
            }
            prop_assert!(handed_out.len() + still_held.len() <= POOL_BUFFERS);
        }

        /// The untrusted-descriptor validator accepts exactly the triples that
        /// name a span within one pool buffer and rejects the rest, computed
        /// against a widened-arithmetic reference so it never disagrees and never
        /// overflows — including at the `u32` extremes where `offset + len`
        /// would wrap a 32-bit sum. `any::<u32>()` biases toward those edges;
        /// the explicit boundary strategies pin the exact pool/buffer limits.
        #[test]
        fn descriptor_in_bounds_matches_a_widened_reference(
            buffer in prop_oneof![
                any::<u32>(),
                (POOL_BUFFERS as u32 - 2)..=(POOL_BUFFERS as u32 + 2),
            ],
            offset in prop_oneof![any::<u32>(), (BUFFER_SIZE as u32 - 2)..=(BUFFER_SIZE as u32 + 2)],
            len in prop_oneof![any::<u32>(), 0u32..=(BUFFER_SIZE as u32 + 2)],
        ) {
            let descriptor = Descriptor::new(buffer, offset, len);
            // Reference in `usize`, which cannot overflow for two `u32`s on a
            // 64-bit host — the authority the checked-arithmetic implementation
            // must match exactly.
            let expected = (buffer as usize) < POOL_BUFFERS
                && (offset as usize) + (len as usize) <= BUFFER_SIZE;
            prop_assert_eq!(descriptor_in_bounds(&descriptor), expected);
        }
    }
}
