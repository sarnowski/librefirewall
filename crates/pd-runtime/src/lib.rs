//! The shared dataplane region and the buffer-ownership protocol common to the
//! protection domains.
//!
//! This crate deliberately carries no seL4/Microkit dependency: the region
//! layout and the ownership protocol are pure logic and are exercised in full
//! on the host (see the concurrency test below). The protection-domain binaries
//! are thin adapters that map a region, hand its address here, and drive the
//! protocol from Microkit notifications.
//!
//! # The forwarding region
//!
//! [`Pipeline`] joins three domains into the forwarding chain
//! `rx driver -> forwarder -> tx driver` over one buffer pool: `rx` carries
//! received frames to the forwarder, `tx` carries them onward to the
//! transmitting driver, and `free` returns transmitted buffers to the
//! pool-owning rx driver. A buffer is always owned by exactly one side: it sits
//! in the owner's [`FreeList`], or in exactly one ring, or in one domain's hand
//! — never in two places at once. That single-ownership chain is what makes
//! forwarding zero-copy end to end: the receiving NIC DMAs a frame into a pool
//! buffer and the transmitting NIC DMAs it back out of that very buffer, and
//! only the descriptor ever moves.
//!
//! # Handles are taken once, at attach
//!
//! A `queue` ring carries no operations; each side drives it through a handle
//! that holds *that side's own position* in domain-private memory. A handle
//! taken per call would restart at slot zero every time and re-walk slots the
//! previous one had already used — reinstating precisely the redelivery bug the
//! private position exists to prevent. So every role type here
//! ([`PoolOwner`], [`ForwardStage`], and their counterparts in
//! `nic-driver-core`) is parameterised by the region's lifetime and **takes
//! each handle exactly once, in its `attach` constructor, keeping it for the
//! protection domain's whole life**. A protection domain must call each role's
//! `attach` once per pipeline and never construct a second role over the same
//! ring end.
//!
//! # Trust stance: a byzantine peer PD
//!
//! This crate *is* the inter-PD protocol, so it defines what one protection
//! domain must withstand from another. Every neighbour shares read-write access
//! to the whole region — both ring cursors and every slot, and the pool bytes —
//! and is treated as untrusted (CONCEPT §7.1). What a hostile peer cannot cause
//! here, and which component enforces each:
//!
//! * **No out-of-bounds slot access, no arithmetic panic, and no redelivery of
//!   a descriptor already handed over** — enforced by `queue`: each side's
//!   position lives in domain-private memory the peer cannot map, and the only
//!   shared word a side reads is the peer's cursor, masked into range.
//! * **No out-of-bounds dereference of a forged descriptor** — enforced by the
//!   consumer, which validates every inbound descriptor with
//!   [`descriptor_in_bounds`] before touching the span it names, backstopped
//!   unconditionally by `packet_buffer`'s own span checks.
//! * **No double-owned buffer through a forged or duplicated return** —
//!   enforced in two layers by [`PoolOwner::reclaim`]. `packet_buffer`'s
//!   [`FreeList::reclaim`] is the trust boundary for the index itself: it
//!   refuses an index outside the pool and one that is not outstanding, so a
//!   forged or duplicated return is rejected rather than counted. On top of
//!   that the owner keeps its own *lent* set, because the ledger alone cannot
//!   tell a buffer lent to the peer from one still posted to this domain's own
//!   NIC — both are merely "outstanding" — and accepting the latter back would
//!   free a live DMA target. Only an index this domain actually dissolved onto
//!   a ring is accepted.
//! * **No unbounded work.** Every loop driven by a peer-fed ring drains through
//!   [`RingConsumer::drain`] with a [`DRAIN_LIMIT`] derived from this crate's
//!   own [`RING_SLOTS`] and [`POOL_BUFFERS`], never from a peer-influenced
//!   estimate, so a peer that keeps its published cursor moving cannot stop the
//!   domain from servicing its device.
//! * **No panic.** Every rejection above is a counted drop
//!   ([`PoolCounters`], [`ForwardCounters`]) rather than a fault. The
//!   distinction this crate keeps is the one AGENTS.md draws: peer-supplied
//!   values are *input* and are rejected safely; only a violated invariant of
//!   this domain's own private state fails visibly.
//!
//! What a hostile peer **can** still cause — the accepted, tracked residue:
//!
//! * **Buffer loss.** A peer that stalls its side of a ring can make
//!   [`ForwardStage::poll`] unable to place a descriptor it has already
//!   dequeued; the descriptor is dropped and counted, and the buffer it named
//!   is then lost to its owner's ledger for good (a descriptor cannot be
//!   un-dequeued, and this domain is not that ring's producer, so it cannot
//!   return it either). The pool shrinks; nothing is double-owned and nothing
//!   crashes.
//! * **Frame loss and reordering**, by forging a cursor: `queue` documents that
//!   flow control is advisory.
//! * **Writing pool bytes at any time.** No Rust type can stop a peer mapping
//!   the same region from scribbling a buffer it does not own. That is a data
//!   integrity problem, contained by the fact that the pool never hands out a
//!   safe reference to those bytes, and it is why an IOMMU (CONCEPT §7.2) is
//!   what finally confines a NIC's DMA rather than anything in this crate.

#![cfg_attr(not(test), no_std)]

use core::mem::{align_of, offset_of, size_of};

use packet_buffer::{BufferPool, FreeList, ReturnError};
use queue::SpscRing;

pub use packet_buffer::{BUFFER_SIZE, OwnedBuffer};
pub use queue::{RingConsumer, RingProducer};
pub use wire::Descriptor;

/// Number of buffers in a shared pool.
pub const POOL_BUFFERS: usize = 64;

/// Slot count of each ring. Power of two; usable capacity is one less. Sized
/// above [`POOL_BUFFERS`] so no ring can fill before the pool is exhausted,
/// which makes buffer hand-offs along a correctly accounted chain infallible.
pub const RING_SLOTS: usize = 128;

/// The most descriptors any single drain of a peer-fed ring will process.
///
/// The bound exists because the producing side of every ring here is untrusted:
/// a peer that keeps advancing its published cursor keeps a dequeue returning
/// descriptors forever, and a domain stuck in such a loop stops servicing its
/// own device. It is deliberately derived from this crate's own constants and
/// never from a ring's `len()`, which is a peer-influenced estimate.
///
/// One full ring's worth is the natural size: a ring cannot hold more than
/// `RING_SLOTS - 1` real descriptors and the pool cannot have more than
/// [`POOL_BUFFERS`] buffers outstanding, so any legitimate backlog is drained
/// in a single round while a fabricated one is cut off after a fixed amount of
/// work.
pub const DRAIN_LIMIT: usize = RING_SLOTS;

/// Bytes reserved for a region in the system description. The `const _`
/// assertions below fail the build if a region type outgrows this, so the Rust
/// types can never silently exceed the mapping declared in the `.system` file.
/// The guarantee is one-directional: nothing here re-reads the `.system`
/// `<memory_region>` size, so shrinking that XML below this constant is caught
/// only at boot (a truncated mapping), not at build time.
pub const REGION_SIZE: usize = 0x40000;

/// The granularity Microkit maps a memory region at, and therefore the
/// alignment a [`Pipeline`]'s base address is guaranteed to have.
///
/// It is what ultimately fixes the DMA alignment of every pool buffer: the pool
/// sits at the region's front (see [`Pipeline`]), so a buffer's alignment is the
/// region base's, and the assertion below proves a page-aligned base is enough
/// for the [`BUFFER_SIZE`] stride.
pub const MAPPING_ALIGN: usize = 0x1000;

/// A ring sized for this dataplane.
///
/// A ring carries no operations of its own: each domain takes a
/// [`RingProducer`] or [`RingConsumer`] handle once and keeps it, because the
/// handle holds that side's position in memory the peer cannot reach.
pub type Ring = SpscRing<RING_SLOTS>;

/// The pool sized for this dataplane.
pub type Pool = BufferPool<POOL_BUFFERS>;

/// Whether a descriptor received from a neighbouring protection domain names
/// a span that lies within one pool buffer. Neighbours are untrusted, so a
/// domain validates every inbound descriptor with this before dereferencing
/// the span; a failing descriptor is rejected, never followed.
#[must_use]
pub fn descriptor_in_bounds(descriptor: &Descriptor) -> bool {
    (descriptor.buffer as usize) < POOL_BUFFERS
        && (descriptor.offset as usize)
            .checked_add(descriptor.len as usize)
            .is_some_and(|end| end <= BUFFER_SIZE)
}

/// Increment a counter of untrusted-input events, saturating rather than
/// wrapping. The rate is attacker-controlled, and a wrapped counter would turn
/// a sustained flood back into a small number and hide it.
fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// The three-domain forwarding region: an rx driver, a forwarder, and a tx
/// driver joined by three rings over one pool. The single pool is what makes
/// forwarding zero-copy end to end: the receiving NIC DMAs a frame into a pool
/// buffer, and the transmitting NIC DMAs it back out of the very same buffer;
/// only the descriptor moves.
///
/// The **pool comes first**, and that ordering is load-bearing rather than
/// cosmetic. `packet_buffer` guarantees only that its buffers are mutually
/// congruent modulo [`BUFFER_SIZE`]; their absolute alignment is decided by
/// whoever places the pool, which is this type. With the pool at offset zero a
/// buffer's alignment is exactly the region base's, which Microkit guarantees to
/// be [`MAPPING_ALIGN`] — a multiple of [`BUFFER_SIZE`], as the assertions below
/// prove. Behind the rings the pool would start at their combined size, which is
/// neither a multiple of [`BUFFER_SIZE`] nor of a page, and every buffer address
/// handed to a NIC would inherit that much weaker alignment.
///
/// seL4 hands out the region zero-initialised, and a zeroed value is the valid
/// empty state (all rings empty, all buffers zeroed), so no domain needs to
/// construct it — each attaches to the mapped frames with [`attach_pipeline!`].
#[repr(C)]
pub struct Pipeline {
    /// Backing storage the descriptors index; also both NICs' DMA target. First
    /// so that its alignment is the region's own — see the type's documentation.
    pub pool: Pool,
    /// Received frames, rx driver to forwarder.
    pub rx: Ring,
    /// Frames to transmit, forwarder to tx driver.
    pub tx: Ring,
    /// Transmitted buffers, tx driver back to the pool-owning rx driver.
    pub free: Ring,
}

// The region is aliased into multiple protection domains, so its layout is a
// hard ABI: a peer PD reads these bytes at these offsets. Pin every field
// offset, not merely the component sizes — a reorder keeps the sizes identical
// while silently making one domain's `rx` another's `tx`. Pinning the offsets
// *and* the total size together also proves the layout carries no padding.
const _: () = {
    assert!(size_of::<Ring>() == 8 + RING_SLOTS * size_of::<Descriptor>());
    assert!(size_of::<Pool>() == POOL_BUFFERS * BUFFER_SIZE);
    assert!(offset_of!(Pipeline, pool) == 0);
    assert!(offset_of!(Pipeline, rx) == size_of::<Pool>());
    assert!(offset_of!(Pipeline, tx) == size_of::<Pool>() + size_of::<Ring>());
    assert!(offset_of!(Pipeline, free) == size_of::<Pool>() + 2 * size_of::<Ring>());
    assert!(size_of::<Pipeline>() == size_of::<Pool>() + 3 * size_of::<Ring>());
    // Exactly four, not merely "within a page": the rings' `AtomicU32`s are the
    // only alignment in the region, and an upper-bound check can never fail, so
    // it could never catch the reorder or field-type change it exists to catch.
    assert!(align_of::<Pipeline>() == 4);
    assert!(size_of::<Pipeline>() <= REGION_SIZE);
};

// The DMA-alignment obligation `packet_buffer` names this type as the owner of:
// buffer `i` sits at `region_paddr + POOL_OFFSET + i * BUFFER_SIZE`, so buffers
// are `BUFFER_SIZE`-aligned exactly when the pool's offset is a multiple of the
// stride and the region base is too. The first assertion holds the offset, the
// second holds the mapping granularity that supplies the base.
const _: () = assert!(Pipeline::POOL_OFFSET.is_multiple_of(BUFFER_SIZE));
const _: () = assert!(MAPPING_ALIGN.is_multiple_of(BUFFER_SIZE));

impl Pipeline {
    /// Byte offset of the buffer pool within the region. A driver that also
    /// hands the pool to a device (NIC DMA) adds this to the region's physical
    /// address to get each buffer's physical address.
    pub const POOL_OFFSET: usize = offset_of!(Pipeline, pool);

    /// Physical address of the buffer pool, given the region's physical address
    /// (from a `region_paddr` mapping).
    #[must_use]
    pub const fn pool_paddr(region_paddr: u64) -> u64 {
        region_paddr + Self::POOL_OFFSET as u64
    }

    /// Physical address of pool buffer `index`.
    ///
    /// # Panics
    /// If `index >= POOL_BUFFERS` — in every build profile. The result would
    /// otherwise be an address *outside* the region, and a driver posts what
    /// this returns to a NIC as a DMA target; with no IOMMU that is an
    /// arbitrary physical write.
    ///
    /// The fault is a first-party invariant break rather than untrusted input,
    /// because the index is bounded before every call and the two guarantors
    /// are:
    ///
    /// * `nic-driver-core`'s `RxPath::refill` passes an [`OwnedBuffer`] index,
    ///   and a token exists only if [`PoolOwner::alloc`] minted it from a
    ///   `FreeList<POOL_BUFFERS>`, which names no other value — proven by the
    ///   `a_forged_out_of_range_return_is_dropped_and_counted` test in this
    ///   crate, which asserts every minted index is below `POOL_BUFFERS`.
    /// * `nic-driver-core`'s `TxPath::post` passes a peer-supplied
    ///   [`Descriptor`]`::buffer`, but only past an unconditional
    ///   [`descriptor_in_bounds`] rejection, which bounds it to the pool and is
    ///   proven by that function's `descriptor_in_bounds_matches_a_widened_reference`
    ///   property.
    ///
    /// So a hostile peer or device reaches a *rejection*, never this assertion;
    /// reaching it means one of those guarantors broke, which is surfaced
    /// visibly rather than counted as traffic (AGENTS.md ENG-5, ENG-12). It is
    /// deliberately not a `debug_assert!`: the protection domains are compiled
    /// with the optimized profile in every seL4 configuration, so a
    /// debug-only bound would be absent from every image that ever boots
    /// (ENG-10, BLD-3).
    #[must_use]
    pub const fn buffer_paddr(region_paddr: u64, index: u32) -> u64 {
        assert!(
            (index as usize) < POOL_BUFFERS,
            "buffer_paddr would address outside the pool"
        );
        Self::pool_paddr(region_paddr) + index as u64 * BUFFER_SIZE as u64
    }

    /// A new, empty region. Const so it can back a static; mainly for host use,
    /// since the mapped region is already zeroed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pool: Pool::new(),
            rx: Ring::new(),
            tx: Ring::new(),
            free: Ring::new(),
        }
    }

    /// Attach to a mapped region and borrow it for the domain's lifetime.
    ///
    /// Protection domains call this through [`attach_pipeline!`], which states
    /// the aliasing invariant once for every call site.
    ///
    /// # Panics
    /// If `ptr` is not aligned for `Self` — in every build profile, since a
    /// bound that is absent from the shipped image is not a bound (AGENTS.md
    /// ENG-10). It costs one compare once per protection domain at start-up.
    ///
    /// # Safety
    /// `ptr` must
    ///
    /// * be aligned to `align_of::<Self>()` — creating the reference below is
    ///   undefined behaviour otherwise, and a mapped region's page alignment
    ///   supplies far more than this type needs;
    /// * point to a live mapping of at least `size_of::<Self>()` bytes that is
    ///   either zeroed or already a valid value; and
    /// * outlive `'a`.
    ///
    /// The mapping may be shared read-write with peer protection domains and
    /// used as a device DMA target: `Pipeline` exposes no safe path to its
    /// bytes, so a peer's writes are a protocol concern rather than a soundness
    /// one. The caller must not, however, create a `&mut Self` to it.
    #[must_use]
    pub unsafe fn attach<'a>(ptr: *mut Self) -> &'a Self {
        // Alignment is a soundness precondition of the reference below, so the
        // check that enforces it is unconditional. Production callers reach
        // here through `attach_pipeline!`, where the Microkit tool's
        // page-granular mapping supplies far more alignment than this type
        // needs; this catches a first-party caller that constructs a pointer
        // some other way, in the profile that actually ships.
        assert!(ptr.is_aligned(), "pipeline region is misaligned");
        // SAFETY: the caller guarantees an aligned, live, correctly sized,
        // correctly initialised mapping outliving `'a`. Aliasing with the peer
        // domains and with NIC DMA is sound because every field is either an
        // atomic (the rings) or an `UnsafeCell` reachable only through an
        // `unsafe` accessor (the pool), so no safe code can hold a reference to
        // a byte a peer may concurrently write.
        unsafe { &*ptr }
    }
}

/// Attach this protection domain to the [`Pipeline`] region a Microkit
/// `setvar_vaddr` symbol names, yielding a `&'static Pipeline`.
///
/// Every domain sharing a pipeline attaches through this macro so that the
/// aliasing invariant which makes the `&'static` share sound is written once,
/// here, instead of being re-derived at four call sites — where one copy drifted
/// out of step with the system description and understated the aliasing set.
///
/// The invariant, stated for `systems/qemu-x86_64/librefirewall.system`: the
/// Microkit tool patches the symbol with the virtual address of a mapped,
/// zero-initialised, page-aligned region of at least `size_of::<Pipeline>()`
/// bytes that exists for the whole life of the system, so it outlives the
/// `'static` borrow, and page alignment covers the type's own. Each pipeline
/// region is mapped **read-write into three protection domains at once** — the
/// forwarder, the driver that receives into it, and the driver that transmits
/// out of it — and its pool is additionally a DMA target of both NICs. Sharing
/// it as `&Pipeline` is sound in the face of all of that because `Pipeline`
/// exposes no safe path to those bytes; whether the peers behave is a protocol
/// question the crate header answers, not a soundness one.
///
/// The calling crate must depend on `sel4-microkit`; this crate deliberately
/// does not, so that the protocol stays host-testable.
#[macro_export]
macro_rules! attach_pipeline {
    ($vaddr_symbol:ident) => {{
        // SAFETY: the Microkit tool patches `$vaddr_symbol` with the address of
        // a live, page-aligned, zero-initialised mapping of at least
        // `size_of::<Pipeline>()` bytes that outlives the protection domain, and
        // no `&mut Pipeline` is ever created to it. Read-write aliasing with the
        // two peer domains and with NIC DMA is expected and sound — see this
        // macro's documentation for why, and for the exact aliasing set.
        unsafe {
            $crate::Pipeline::attach(
                ::sel4_microkit::memory_region_symbol!($vaddr_symbol: *mut $crate::Pipeline)
                    .as_ptr(),
            )
        }
    }};
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Counts of the pool owner's untrusted-input rejections, which are otherwise
/// invisible: a byzantine peer's activity would look exactly like an idle link.
///
/// Every field is monotonic for the domain's life and saturates at
/// [`u64::MAX`]; there is no reset, because a metrics endpoint (CONCEPT §11)
/// consumes a counter by differencing successive scrapes and a reset would
/// forge a negative rate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PoolCounters {
    /// Buffer returns naming an index this domain never lent to the peer: a
    /// forged or out-of-range index, a duplicate of a return already accepted,
    /// or — the reason this set exists at all — a real buffer that is still
    /// posted to this domain's own NIC as a DMA target.
    pub reclaim_not_lent: u64,
    /// Returns of a lent index that `packet_buffer`'s ledger nevertheless
    /// refused. Unreachable while the lent set and the ledger agree, since a
    /// lent index is by construction outstanding; it is counted rather than
    /// asserted so that a divergence between the two surfaces as a lost buffer
    /// with a number attached instead of a silent one.
    pub reclaim_refused: u64,
}

/// The pool-owning side of a [`Pipeline`]: it owns every buffer in the pool,
/// lends buffers out as bare indices, and takes them back off the `free` ring.
///
/// An rx driver is the pool owner of its receive pipeline. It takes the `free`
/// ring's consumer handle here, once, at [`attach`](Self::attach) — see the
/// crate header on why that must not happen per call.
///
/// Ownership is carried as a move-only [`OwnedBuffer`] for as long as the buffer
/// stays inside this domain, so a local double-release is not expressible.
/// The token is dissolved to a bare index at exactly one place,
/// [`lend`](Self::lend), because that is where the buffer leaves Rust's
/// ownership tracking and enters the cross-domain ring protocol.
pub struct PoolOwner<'pipe> {
    /// Which indices are free to hand out, by identity.
    ledger: FreeList<POOL_BUFFERS>,
    /// Which indices were dissolved onto a ring and may therefore legitimately
    /// come back. The ledger cannot answer this: a buffer posted to this
    /// domain's own NIC is "outstanding" exactly as a lent one is, and a peer
    /// naming it would otherwise have a live DMA target handed back to the free
    /// stack and re-issued to a second owner.
    lent: [bool; POOL_BUFFERS],
    /// Returns from the transmitting domain. Taken once; see the crate header.
    free: RingConsumer<'pipe, RING_SLOTS>,
    counters: PoolCounters,
}

impl<'pipe> PoolOwner<'pipe> {
    /// Take ownership of `pipeline`'s pool and of its `free` ring's consumer
    /// handle.
    ///
    /// Call once per protection domain per pipeline: the handle is this
    /// domain's position in the ring, so a second owner over the same pipeline
    /// would re-read slots this one has already consumed, and both would
    /// believe they own the same buffers.
    #[must_use]
    pub fn attach(pipeline: &'pipe Pipeline) -> Self {
        Self {
            ledger: FreeList::full(),
            lent: [false; POOL_BUFFERS],
            free: pipeline.free.consumer(),
            counters: PoolCounters::default(),
        }
    }

    /// Take exclusive ownership of a free buffer, e.g. to hand to a device for
    /// it to fill. `None` when the pool is momentarily exhausted.
    ///
    /// The token proves the caller holds the buffer alone. Dropping it without
    /// returning it leaks the buffer for the domain's life, which is why it is
    /// `#[must_use]` in `packet_buffer`.
    pub fn alloc(&mut self) -> Option<OwnedBuffer> {
        self.ledger.pop()
    }

    /// Return a buffer this domain still holds, without publishing it — the
    /// path taken when a hand-off could not proceed.
    ///
    /// # Panics
    /// If the ledger refuses the token. That is unreachable, and deliberately
    /// left as a visible failure rather than a counted drop, because it is a
    /// violation of *this domain's own* invariant rather than untrusted input:
    /// holding the token means the index is outstanding, and the only route by
    /// which a peer could have had it freed underneath us is
    /// [`reclaim`](Self::reclaim), which accepts an index only if it is in the
    /// lent set — which a held token's index never is. That refusal is proven
    /// by the `a_return_of_a_buffer_still_held_by_this_domain_is_refused`
    /// test in this crate.
    pub fn release(&mut self, buffer: OwnedBuffer) {
        self.ledger
            .push(buffer)
            .expect("a held token names an outstanding, unlent buffer");
    }

    /// Publish `len` bytes at `offset` of an already-filled buffer on `ring`,
    /// handing it to the next domain. No bytes are copied.
    ///
    /// This is the one place a buffer's identity stops being tracked by the
    /// compiler: the token is consumed and only a bare index crosses onto the
    /// shared ring, because a move-only token cannot cross a protection-domain
    /// boundary. The index is recorded as lent, which is what later lets
    /// [`reclaim`](Self::reclaim) tell a legitimate return from a peer naming a
    /// buffer it was never given.
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
        // In range because the token was minted by a `FreeList<POOL_BUFFERS>`,
        // so no peer value reaches this index.
        self.lent[index as usize] = true;
        Ok(())
    }

    /// Take back the buffers the transmitting domain has returned, until the
    /// `free` ring is observed empty or [`DRAIN_LIMIT`] descriptors have been
    /// processed, whichever comes first. Returns how many buffers were
    /// reclaimed.
    ///
    /// Every index here is peer-supplied and therefore untrusted (CONCEPT
    /// §7.1). A return is accepted only if the index is in this domain's lent
    /// set *and* `packet_buffer`'s ledger — the crate's own trust boundary —
    /// accepts it. A rejected return is dropped and counted in
    /// [`counters`](Self::counters); it changes nothing, so the buffer it named
    /// keeps whatever state it really had and its rightful holder can still
    /// return it. Nothing here panics: these are inputs, not invariants.
    ///
    /// The bound is what keeps a peer from parking this domain in a drain loop
    /// forever; see [`DRAIN_LIMIT`].
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

    /// The untrusted-input rejections seen so far; see [`PoolCounters`].
    #[must_use]
    pub fn counters(&self) -> PoolCounters {
        self.counters
    }
}

/// Counts of the forwarding stage's outcomes. Monotonic and saturating for the
/// reasons given on [`PoolCounters`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ForwardCounters {
    /// Descriptors moved onward, ownership and all.
    pub forwarded: u64,
    /// Descriptors dropped because the destination ring would not take them.
    /// Each one loses its buffer to the pool for good — see the crate header —
    /// so this counter is the only trace such a peer leaves.
    pub dropped: u64,
}

/// One direction of the forwarding chain: it moves descriptors from a
/// pipeline's `rx` ring to its `tx` ring, transferring buffer ownership onward
/// without touching the bytes.
///
/// Both handles are taken once, at [`attach`](Self::attach), and kept for the
/// domain's life — see the crate header.
pub struct ForwardStage<'pipe> {
    from: RingConsumer<'pipe, RING_SLOTS>,
    to: RingProducer<'pipe, RING_SLOTS>,
    counters: ForwardCounters,
}

impl<'pipe> ForwardStage<'pipe> {
    /// Take `pipeline`'s `rx` consumer and `tx` producer handles.
    ///
    /// Call once per protection domain per pipeline; a second stage over the
    /// same pipeline would restart both positions at slot zero and redeliver
    /// descriptors the first has already forwarded.
    #[must_use]
    pub fn attach(pipeline: &'pipe Pipeline) -> Self {
        Self {
            from: pipeline.rx.consumer(),
            to: pipeline.tx.producer(),
            counters: ForwardCounters::default(),
        }
    }

    /// Move descriptors onward until the source ring is observed empty, the
    /// destination refuses one, or [`DRAIN_LIMIT`] descriptors have been moved.
    /// Returns how many moved.
    ///
    /// The rings are sized above the pool, so along a correctly accounted chain
    /// the destination can always take what the source held and this never
    /// drops. A refusal means accounting has already broken — a byzantine peer
    /// over-filling the source while the destination stalls — and the response
    /// is to count the drop and stop draining, not to fault: the descriptor is
    /// peer-supplied input. Stopping on the first refusal is deliberate, since
    /// every further dequeue into a full destination would lose another buffer.
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

    /// The forwarding tallies so far; see [`ForwardCounters`].
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
        pipeline: &Pipeline,
        owner: &mut PoolOwner<'_>,
        rx: &mut RingProducer<'_, RING_SLOTS>,
        payload: &[u8],
    ) -> Option<u32> {
        let buffer = owner.alloc()?;
        let index = buffer.index();
        // SAFETY: `buffer` came from our ledger, so we own it exclusively until
        // `lend` transfers it; `payload` is a local, not a pool borrow.
        let len = unsafe { pipeline.pool.write(index as usize, payload) }
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
        pipeline: &Pipeline,
        tx: &mut RingConsumer<'_, RING_SLOTS>,
        free: &mut RingProducer<'_, RING_SLOTS>,
        mut on_payload: impl FnMut(&[u8]),
    ) -> usize {
        let mut count = 0;
        for descriptor in tx.drain(DRAIN_LIMIT) {
            {
                // SAFETY: we dequeued this descriptor, so we own its buffer
                // until it is returned below; the borrow ends before that. The
                // data is the `len` bytes at `offset` the rx side published.
                let bytes = unsafe {
                    pipeline.pool.read(
                        descriptor.buffer as usize,
                        descriptor.offset as usize,
                        descriptor.len,
                    )
                };
                on_payload(bytes);
            }
            free.try_enqueue(descriptor)
                .expect("free ring has a slot for every pool buffer");
            count += 1;
        }
        count
    }

    #[test]
    fn zeroed_region_is_valid_and_empty() {
        // A region built from zeroed memory (as seL4 provides) must be empty
        // and immediately usable. A fresh handle starts at position zero, which
        // is exactly what a zeroed region's cursors say, so attaching to one
        // sees an empty ring without reading anything a peer could have written.
        let pipeline = Box::new(Pipeline::new());
        assert!(pipeline.rx.consumer().is_empty());
        assert!(pipeline.tx.consumer().is_empty());
        assert!(pipeline.free.consumer().is_empty());
        assert_eq!(pipeline.pool.capacity(), POOL_BUFFERS);
        assert_eq!(PoolOwner::attach(&pipeline).owned(), POOL_BUFFERS);
    }

    #[test]
    fn the_pool_sits_at_the_front_so_every_buffer_inherits_the_region_alignment() {
        // The property `packet_buffer` names this crate as the owner of. Assert
        // it at runtime too, not only in the `const _` block, so the intent is
        // visible where a layout change would be reviewed.
        assert_eq!(Pipeline::POOL_OFFSET, 0);
        assert!(Pipeline::POOL_OFFSET.is_multiple_of(BUFFER_SIZE));
        assert!(MAPPING_ALIGN.is_multiple_of(BUFFER_SIZE));
        // A page-aligned region base therefore yields buffer addresses that are
        // all BUFFER_SIZE-aligned, which is what a NIC is handed.
        let region = 0x3100_0000u64;
        assert!(region.is_multiple_of(MAPPING_ALIGN as u64));
        for index in 0..POOL_BUFFERS as u32 {
            assert!(Pipeline::buffer_paddr(region, index).is_multiple_of(BUFFER_SIZE as u64));
        }
    }

    #[test]
    fn the_region_layout_is_the_pinned_cross_domain_abi() {
        // The same offsets the `const _` block pins, restated as values so a
        // reviewer sees the actual region map and the size the system
        // description must reserve.
        assert_eq!(size_of::<Pool>(), POOL_BUFFERS * BUFFER_SIZE);
        assert_eq!(size_of::<Ring>(), 8 + RING_SLOTS * size_of::<Descriptor>());
        assert_eq!(offset_of!(Pipeline, pool), 0);
        assert_eq!(offset_of!(Pipeline, rx), size_of::<Pool>());
        assert_eq!(
            offset_of!(Pipeline, tx),
            size_of::<Pool>() + size_of::<Ring>()
        );
        assert_eq!(
            offset_of!(Pipeline, free),
            size_of::<Pool>() + 2 * size_of::<Ring>()
        );
        assert_eq!(align_of::<Pipeline>(), 4);
        assert_eq!(
            size_of::<Pipeline>(),
            size_of::<Pool>() + 3 * size_of::<Ring>()
        );
        assert!(size_of::<Pipeline>() <= REGION_SIZE);
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
        let _ = Pipeline::buffer_paddr(0x3100_0000, POOL_BUFFERS as u32);
    }

    #[test]
    fn attaching_to_an_aligned_zeroed_region_yields_the_empty_state() {
        // What a protection domain actually does at start-up: seL4 hands over a
        // zeroed, page-aligned mapping, and attaching to it must observe empty
        // rings and a full pool without touching anything a peer controls.
        let region = Box::new(Pipeline::new());
        let ptr = Box::into_raw(region);
        // SAFETY: `ptr` comes from `Box::into_raw`, so it is aligned, live, and
        // exactly `size_of::<Pipeline>()` bytes of a valid value; it is
        // reclaimed below, after the borrow ends.
        let pipeline = unsafe { Pipeline::attach(ptr) };
        assert!(pipeline.rx.consumer().is_empty());
        assert_eq!(PoolOwner::attach(pipeline).owned(), POOL_BUFFERS);
        // SAFETY: the borrow above has ended and the pointer is the one
        // `Box::into_raw` produced, so reconstituting the box is the matching
        // deallocation.
        drop(unsafe { Box::from_raw(ptr) });
    }

    #[test]
    #[should_panic(expected = "pipeline region is misaligned")]
    fn attaching_to_a_misaligned_region_faults_before_the_reference_is_made() {
        // Alignment is a soundness precondition of the reference `attach`
        // creates, so it must fault before that, not after — in every profile,
        // which is why this test is no longer gated on `debug_assertions`.
        let mut backing = Box::new([0u8; size_of::<Pipeline>() + 8]);
        // SAFETY: the offset stays inside the live allocation, so forming the
        // pointer is defined; the call is expected to fault on the alignment
        // check before it ever dereferences it.
        let misaligned = unsafe { backing.as_mut_ptr().add(1) }.cast::<Pipeline>();
        // SAFETY: as above — this must panic on the alignment assertion; nothing
        // past it is expected to run.
        let _ = unsafe { Pipeline::attach(misaligned) };
    }

    #[test]
    fn forward_moves_descriptors_in_order() {
        let pipeline = Box::new(Pipeline::new());
        let mut rx_in = pipeline.rx.producer();
        let mut stage = ForwardStage::attach(&pipeline);
        let mut tx_out = pipeline.tx.consumer();
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
        let pipeline = Box::new(Pipeline::new());
        let mut rx_in = pipeline.rx.producer();
        let mut stage = ForwardStage::attach(&pipeline);

        let capacity = pipeline.tx.capacity();
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
        assert_eq!(pipeline.rx.consumer().len(), 3);
    }

    #[test]
    fn forward_is_bounded_when_a_peer_keeps_the_source_ring_non_empty() {
        // A peer that keeps advancing its published `tail` makes the source
        // look permanently non-empty. Work per poll must still be finite.
        let pipeline = Box::new(Pipeline::new());
        let mut stage = ForwardStage::attach(&pipeline);
        let mut tx_out = pipeline.tx.consumer();
        for round in 0..8u32 {
            forge_cursors(&pipeline.rx, 0, round.wrapping_mul(37).wrapping_add(11));
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
        let pipeline = Box::new(Pipeline::new());
        let mut owner = PoolOwner::attach(&pipeline);
        let mut rx_in = pipeline.rx.producer();
        let mut stage = ForwardStage::attach(&pipeline);
        let mut tx_out = pipeline.tx.consumer();
        let mut free_in = pipeline.free.producer();

        assert!(receive(&pipeline, &mut owner, &mut rx_in, &7u64.to_le_bytes()).is_some());
        assert!(receive(&pipeline, &mut owner, &mut rx_in, &8u64.to_le_bytes()).is_some());
        assert_eq!(owner.owned(), POOL_BUFFERS - 2);

        assert_eq!(stage.poll(), 2);

        let mut seen = Vec::new();
        let transmitted = transmit(&pipeline, &mut tx_out, &mut free_in, |bytes| {
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
        let pipeline = Box::new(Pipeline::new());
        let mut owner = PoolOwner::attach(&pipeline);
        let mut rx_in = pipeline.rx.producer();

        // The ring is sized above the pool, so fill it with bare descriptors
        // first; only then can a real lend be refused.
        for _ in 0..pipeline.rx.capacity() {
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
        let mut free_in = pipeline.free.producer();
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
        let pipeline = Box::new(Pipeline::new());
        let mut owner = PoolOwner::attach(&pipeline);
        let mut free_in = pipeline.free.producer();
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
        let pipeline = Box::new(Pipeline::new());
        let mut owner = PoolOwner::attach(&pipeline);
        let mut rx_in = pipeline.rx.producer();
        let mut free_in = pipeline.free.producer();

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
        let pipeline = Box::new(Pipeline::new());
        let mut owner = PoolOwner::attach(&pipeline);
        let mut free_in = pipeline.free.producer();

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
        let pipeline = Box::new(Pipeline::new());
        let mut owner = PoolOwner::attach(&pipeline);
        let mut free_in = pipeline.free.producer();
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
        let pipeline = Box::new(Pipeline::new());
        let mut owner = PoolOwner::attach(&pipeline);
        let mut free_in = pipeline.free.producer();
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
        let pipeline = Box::new(Pipeline::new());
        let mut owner = PoolOwner::attach(&pipeline);
        for round in 0..8u32 {
            forge_cursors(&pipeline.free, 0, round.wrapping_mul(29).wrapping_add(5));
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
        let pipeline = Box::new(Pipeline::new());
        let mut owner = PoolOwner::attach(&pipeline);
        let mut rx_in = pipeline.rx.producer();
        let mut free_in = pipeline.free.producer();

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
        forge_cursors(&pipeline.free, 0, 3);
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
        const TOTAL: u64 = 500_000;
        let region = Box::new(Pipeline::new());
        let pipeline: &Pipeline = &region;

        // Scoped threads because each domain's role type borrows the region: a
        // handle *is* that domain's position, so it is taken once inside the
        // thread that owns the role and kept for the thread's life, exactly as a
        // protection domain takes it once at attach.
        thread::scope(|scope| {
            scope.spawn(|| {
                let mut owner = PoolOwner::attach(pipeline);
                let mut rx_in = pipeline.rx.producer();
                let mut sent = 0u64;
                while sent < TOTAL {
                    owner.reclaim();
                    if receive(pipeline, &mut owner, &mut rx_in, &sent.to_le_bytes()).is_some() {
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

            scope.spawn(|| {
                let mut stage = ForwardStage::attach(pipeline);
                let mut moved = 0u64;
                while moved < TOTAL {
                    moved += stage.poll() as u64;
                    std::hint::spin_loop();
                }
                assert_eq!(stage.counters().dropped, 0);
            });

            scope.spawn(|| {
                let mut tx_out = pipeline.tx.consumer();
                let mut free_in = pipeline.free.producer();
                let mut expected = 0u64;
                while expected < TOTAL {
                    transmit(pipeline, &mut tx_out, &mut free_in, |bytes| {
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
            let region = Box::new(Pipeline::new());
            let pipeline: &Pipeline = &region;
            let mut owner = PoolOwner::attach(pipeline);
            let mut rx_in = pipeline.rx.producer();
            let mut stage = ForwardStage::attach(pipeline);
            let mut tx_out = pipeline.tx.consumer();
            let mut free_in = pipeline.free.producer();
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
                            0 => &pipeline.rx,
                            1 => &pipeline.tx,
                            _ => &pipeline.free,
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
