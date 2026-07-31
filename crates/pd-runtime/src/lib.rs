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
//! [`ForwardRings`], [`ReturnRing`] — which lets the forwarder hold the pool
//! whose L2/L3 headers it rewrites and the two rings it moves descriptors
//! between, while holding neither pipeline's return ring. The cut costs one
//! mapping page over a single region holding all four, and that page is what
//! buys the separation: the ring on which a forged return would put a live DMA
//! target back onto an owner's free stack is not addressable from the forwarder
//! at all. A [`Pool`] goes to the forwarder and the transmitting driver, and to
//! the receiving one as a physical address with no mapping at all.
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
//! # A stage holds no forwarding table, so a commit lands between two polls
//!
//! [`RouteStage`] takes the [`Configuration`] it decides under as a parameter
//! of [`RouteStage::poll`] and keeps none of it. Holding one made a second
//! configuration unrepresentable — the borrow lasted as long as the stage — and
//! passing it per call also settles *when* a commit takes effect without a
//! lock: a Microkit protection domain runs one `notified` to completion at a
//! time, so the caller cannot run while a poll holds the table it was lent.
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
//!   [`RouteCounters`]). Peer-supplied values are input and are rejected
//!   safely; only a violated invariant of this domain's own private state fails
//!   visibly.
//!
//! # The accepted, tracked residue
//!
//! * **Buffer loss.** A peer stalling its side of a ring can leave
//!   [`RouteStage::poll`] unable to place a descriptor it already dequeued.
//!   A dequeue cannot be undone and this domain does not produce onto that
//!   ring, so the buffer is lost to its owner's ledger for good. The pool
//!   shrinks; nothing is double-owned and nothing crashes.
//! * **A verdict rests on a snapshot, not on the frame.** [`RouteStage`] routes
//!   a copy taken into its own memory, because a decision made on pool bytes a
//!   peer may rewrite under it is no decision at all. The peer keeps the bytes:
//!   it may rewrite them after the snapshot and before the transmitting NIC
//!   reads them, so what leaves the port can differ from what was decided on,
//!   in every field the rewrite does not overwrite. Nothing here closes that —
//!   an IOMMU (CONCEPT §7.2) or a per-buffer cross-domain ownership epoch would.
//! * **Frame loss and reordering**, by forging a cursor.
//! * **Writing pool bytes at any time.** The two drivers share a pool, and no
//!   Rust type stops one of them scribbling a buffer it does not own. That is
//!   contained by the pool never handing out a safe reference to those bytes,
//!   and it is why an IOMMU (CONCEPT §7.2) is what finally confines a NIC's DMA
//!   rather than anything here.

#![cfg_attr(not(test), no_std)]

use core::mem::{align_of, offset_of, size_of};

use net_headers::{ETHERNET_HEADER_LEN, Frame, IPV4_HEADER_LEN, TtlExpired};
use packet_buffer::{BufferPool, CopyOutError, FreeList, ReturnError};
use queue::SpscRing;
use routing::{Decision, DropCounters, DropReason, PortId, Router};

pub use packet_buffer::{BUFFER_SIZE, OwnedBuffer};
pub use queue::{RingConsumer, RingProducer};
pub use wire::{Descriptor, Verdict};

/// Re-exported rather than restated: one number, one declaration. What is this
/// crate's own is what it additionally fixes — a [`Pool`] is the whole of its
/// region, so a region base's alignment is every buffer's DMA alignment.
pub use wire::MAPPING_ALIGN;

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

pub type Ring = SpscRing<RING_SLOTS>;

/// Both NICs' DMA target, and the whole of one memory region: pool buffer `i`
/// sits at the region's own physical base plus `i * BUFFER_SIZE`, with no
/// offset to add and none to get wrong.
pub type Pool = BufferPool<POOL_BUFFERS>;

/// Bytes the system description reserves for each region, derived rather than
/// chosen: the fewest [`MAPPING_ALIGN`] pages that hold the region's type. As a
/// literal the single-region size drifted to 1.93x its type, mapping bytes no
/// field names into three domains. `xtask::sysdesc` reads that file back and
/// holds every `size=` to the constant here, proved by its
/// `a_short_region_is_reported_against_the_constant_it_must_equal`.
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
pub(crate) fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// The forwarder's region: the two rings a descriptor crosses on its way from
/// the receiving driver to the transmitting one.
///
/// The ring the buffers come back on is a separate region, which the forwarder
/// never maps; the [`Pool`] those descriptors index is a third, and it is
/// mapped, because the routed frame's headers are rewritten in place.
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
    assert!(size_of::<Ring>() == 2056);
    assert!(size_of::<Pool>() == POOL_BUFFERS * BUFFER_SIZE);
    assert!(size_of::<Pool>() == 0x20000);
    assert!(offset_of!(ForwardRings, rx) == 0);
    assert!(offset_of!(ForwardRings, tx) == size_of::<Ring>());
    assert!(size_of::<ForwardRings>() == 2 * size_of::<Ring>());
    assert!(size_of::<ForwardRings>() == 4112);
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

// The three grants, pinned as tightly as the fields: each region exceeds its
// type by less than one page, so no unaddressed slack can return unnoticed.
const _: () = {
    assert!(POOL_REGION_SIZE == 0x20000);
    assert!(FORWARD_REGION_SIZE == 0x2000);
    assert!(RETURN_REGION_SIZE == 0x1000);
    assert!(POOL_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(FORWARD_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(RETURN_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    // The pool region is its type exactly, with no rounding remainder at all.
    assert!(POOL_REGION_SIZE == size_of::<Pool>());
    assert!(FORWARD_REGION_SIZE - size_of::<ForwardRings>() < MAPPING_ALIGN);
    assert!(RETURN_REGION_SIZE - size_of::<ReturnRing>() < MAPPING_ALIGN);
    // What the split costs, stated here rather than left to a report nobody
    // diffed: one mapping page. It was nothing while a descriptor was 12 bytes;
    // a 16-byte one pushes `ForwardRings` past a page. The page is what buys
    // the grant separation, and a cut that cost *more* fails here.
    assert!(
        POOL_REGION_SIZE + FORWARD_REGION_SIZE + RETURN_REGION_SIZE
            == (size_of::<Pool>() + 3 * size_of::<Ring>()).next_multiple_of(MAPPING_ALIGN)
                + MAPPING_ALIGN
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
/// * an `OwnedBuffer<POOL_BUFFERS>` index, which the token's own type bounds
///   below `POOL_BUFFERS`;
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
/// transmitting driver alone and is additionally a DMA target of both NICs; the
/// two configuration regions are mapped into two domains, each writable in one
/// of them. Sharing any of them as a `&` is sound in the face of that because
/// none exposes a safe path to those bytes; whether the peers behave is the
/// protocol question the crate header answers, not a soundness one.
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
        //   in `systems/qemu-x86_64/librefirewall.system`, maps at page
        //   granularity (far beyond any region type's 4 bytes), and makes the
        //   mapping static, so it outlives the protection domain.
        // * Zero-initialisation — the seL4 kernel, which zeroes a frame
        //   retyped from a general-purpose untyped but not one retyped from a
        //   device untyped. Which it is follows from the region's `phys_addr`
        //   lying inside RAM, and that from QEMU's `-m 1G`
        //   (`tools/xtask/src/qemu.rs`). This is the one precondition here that
        //   no build step checks; a region outside RAM surfaces as unbacked
        //   reads at run time rather than as a build or boot error.
        // * Minimum size — the `size=` attribute on that region, which
        //   `xtask::sysdesc`'s `REGIONS` table names a rule for and
        //   `check_region_size` holds *equal* to the constant the domains map
        //   it as: `POOL_REGION_SIZE`, `FORWARD_REGION_SIZE`,
        //   `RETURN_REGION_SIZE`, `CONFIG_REGION_SIZE`, `CONFIG_ACK_REGION_SIZE`.
        //   The log regions are the exception: that table names no rule for one
        //   yet, so they alone are sized by agreement until it does. Both checks
        //   run in the fast gate and again before the image is assembled.
        // * No safe path to the bytes — the region types, whose fields are
        //   atomics (`Ring`, `wire`'s configuration regions) or an `UnsafeCell`
        //   reachable only through an `unsafe` accessor (`Pool`).
        //
        // No `&mut` is created here or by `attach_region`.
        unsafe {
            $crate::attach_region::<$region>(
                ::sel4_microkit::memory_region_symbol!($vaddr_symbol: *mut $region).as_ptr(),
            )
        }
    }};
}

pub mod handover;
pub mod terminal;

pub use handover::{ConfigCounters, ConfigPublisher, ConfigurationSwitch, Offer, router_from};
pub use terminal::{TerminalCounters, TerminalStage};
pub use wire::{ConfigAck, ConfigHandover, ConfigImage, MAX_INTERFACES, MAX_NEIGHBOURS};

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
    pub fn alloc(&mut self) -> Option<OwnedBuffer<POOL_BUFFERS>> {
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
    pub fn release(&mut self, buffer: OwnedBuffer<POOL_BUFFERS>) {
        self.ledger
            .push(buffer)
            .expect("a held token names an outstanding, unlent buffer");
    }

    /// Publish `len` bytes at `offset` of an already-filled buffer on `ring`
    /// under `verdict`, handing it to the next domain without copying.
    ///
    /// The token is consumed and only a bare index crosses onto the shared
    /// ring, a move-only token being unable to cross a protection-domain
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
        buffer: OwnedBuffer<POOL_BUFFERS>,
        offset: u32,
        len: u32,
        verdict: Verdict,
    ) -> Result<(), OwnedBuffer<POOL_BUFFERS>> {
        let index = buffer.index();
        if ring
            .try_enqueue(Descriptor::new(index, offset, len, verdict))
            .is_err()
        {
            return Err(buffer);
        }
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

/// The bytes a forwarding rewrite can touch, and so the whole of what
/// [`RouteStage`] puts back into the pool: the Ethernet header and the IPv4
/// header, never a payload byte.
///
/// The IPv4 header sits at [`ETHERNET_HEADER_LEN`] with nothing in between,
/// because a frame that reaches a rewrite is never 802.1Q-tagged: `Router`
/// answers a tagged frame with `DropReason::VlanTagged` before it resolves
/// anything, proved by `routing`'s
/// `a_tagged_frame_is_dropped_for_want_of_a_sub_interface`. A tag would move
/// the L3 header four bytes along and this window would then write the wrong
/// bytes back over the right ones.
const REWRITTEN_HEADER_LEN: usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;

// What makes the fixed-range write-back slice of `scratch` unable to leave it:
// a build error rather than a bounds check on the per-frame path.
const _: () = assert!(REWRITTEN_HEADER_LEN <= BUFFER_SIZE);

/// Monotonic and saturating for the reasons given on [`PoolCounters`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RouteCounters {
    /// The generation the most recent poll decided under. The counts below span
    /// the domain's life and no commit resets them, so this is what tells two
    /// scrapes apart: a pair naming one generation differences to a rate under
    /// one configuration.
    pub generation: u32,
    /// Frames rewritten for their next hop and handed to the transmitting
    /// driver.
    pub forwarded: u64,
    /// Descriptors the destination ring would not take. Each loses its buffer
    /// to the pool for good — see the crate header — so a rising count is a
    /// shrinking pool.
    pub egress_full: u64,
    /// Descriptors naming a span outside the pool. Such a descriptor names no
    /// buffer the transmitting driver could return, so handing it on would be
    /// inventing a return rather than granting one; it is dropped instead.
    pub malformed_descriptor: u64,
    /// Spans the pool refused to snapshot, leaving nothing to route on.
    pub snapshot_failed: u64,
    /// Frames that are not the IPv4-over-Ethernet packet they would have to be
    /// to be routed. One counter for every [`net_headers::ParseError`]: this
    /// domain has no surface to report which (MONITORING.md — a drop is
    /// currently unobservable), so a finer split would be numbers nobody reads.
    pub unparsable: u64,
    /// Frames the router would forward out of a port this stage is not wired
    /// to. A stage is a fixed cross-connect between one ingress and one egress
    /// port, so such a decision cannot be carried out here at all.
    pub misrouted: u64,
    /// Rewritten headers the pool refused to take back. The buffer then still
    /// holds the frame as it arrived, so it is discarded rather than
    /// transmitted with its original MACs and TTL — which would loop it.
    pub writeback_failed: u64,
    /// Why the router refused a frame, one counter per reason.
    pub drops: DropCounters,
}

/// The forwarding table a poll decides under, and the generation that produced
/// it: one value, because a count attributed to a table that did not produce it
/// is worse than an unattributed one. The pairing is made where the
/// configuration is held, and a poll takes it whole or not at all.
#[derive(Clone, Copy, Debug)]
pub struct Configuration<'table, const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize> {
    generation: u32,
    table: &'table Router<MAX_INTERFACES, MAX_NEIGHBOURS>,
}

impl<'table, const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize>
    Configuration<'table, MAX_INTERFACES, MAX_NEIGHBOURS>
{
    #[must_use]
    pub const fn new(
        generation: u32,
        table: &'table Router<MAX_INTERFACES, MAX_NEIGHBOURS>,
    ) -> Self {
        Self { generation, table }
    }
}

/// One direction of the routed dataplane: it snapshots each frame a pipeline's
/// `rx` ring names, decides on it, rewrites the headers of the ones it
/// forwards, and hands every descriptor on under the verdict the transmitting
/// driver acts on.
///
/// A discarded frame's descriptor travels onward exactly as a forwarded one's
/// does. This domain maps no `free` ring — that is what denies it the ability
/// to forge a return — so the transmitting driver is the only domain that can
/// give the buffer back, and the verdict is how it is told to.
pub struct RouteStage<'ring> {
    ingress: PortId,
    egress: PortId,
    from: RingConsumer<'ring, RING_SLOTS>,
    to: RingProducer<'ring, RING_SLOTS>,
    pool: &'ring Pool,
    /// Private storage the frame is snapshotted into. A field rather than a
    /// `poll` local because the protection domain's stack is 16 KiB and this is
    /// 2 KiB per stage.
    scratch: [u8; BUFFER_SIZE],
    counters: RouteCounters,
}

impl<'ring> RouteStage<'ring> {
    /// Take `rings`' `rx` consumer and `tx` producer handles — once per
    /// protection domain per pipeline; see the crate header — and borrow the
    /// pool those descriptors index.
    #[must_use]
    pub fn attach(
        rings: &'ring ForwardRings,
        pool: &'ring Pool,
        ingress: PortId,
        egress: PortId,
    ) -> Self {
        Self {
            ingress,
            egress,
            from: rings.rx.consumer(),
            to: rings.tx.producer(),
            pool,
            scratch: [0; BUFFER_SIZE],
            counters: RouteCounters::default(),
        }
    }

    /// Route descriptors onward under `configuration` until the source ring is
    /// observed empty, the destination refuses one, or [`DRAIN_LIMIT`] have
    /// been handled. Returns how many reached the destination ring under either
    /// verdict — which is the number of buffers that are on their way back to
    /// their owner, and so the quantity a caller can act on; how many were
    /// forwarded is [`RouteCounters::forwarded`].
    ///
    /// The rings are sized above the pool, so along a correctly accounted chain
    /// the destination can always take what the source held. A refusal means
    /// accounting has already broken — a byzantine peer over-filling the source
    /// while the destination stalls — and the response is to count the drop and
    /// stop draining rather than fault, the descriptor being peer input.
    /// Stopping on the first refusal is deliberate: every further dequeue into
    /// a full destination would lose another buffer.
    pub fn poll<const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize>(
        &mut self,
        configuration: Configuration<'_, MAX_INTERFACES, MAX_NEIGHBOURS>,
    ) -> usize {
        let Self {
            ingress,
            egress,
            from,
            to,
            pool,
            scratch,
            counters,
        } = self;
        let router = configuration.table;
        counters.generation = configuration.generation;
        let mut handed_on = 0;
        for descriptor in from.drain(DRAIN_LIMIT) {
            // Unconditionally, and before the buffer is touched: the descriptor
            // is peer input, and this is the span the two pool accessors below
            // are argued from.
            if !descriptor_in_bounds(&descriptor) {
                bump(&mut counters.malformed_descriptor);
                continue;
            }
            let verdict = match snapshot(pool, &descriptor, scratch) {
                Ok(frame_bytes) => route_frame(router, *ingress, *egress, frame_bytes, counters),
                Err(_) => {
                    bump(&mut counters.snapshot_failed);
                    Verdict::Discard
                }
            };
            let verdict = match verdict {
                Verdict::Transmit => write_back(pool, &descriptor, scratch, counters),
                Verdict::Discard => Verdict::Discard,
            };
            if to
                .try_enqueue(Descriptor {
                    verdict: verdict.to_bits(),
                    ..descriptor
                })
                .is_err()
            {
                bump(&mut counters.egress_full);
                break;
            }
            handed_on += 1;
            if verdict == Verdict::Transmit {
                bump(&mut counters.forwarded);
            }
        }
        handed_on
    }

    #[must_use]
    pub fn counters(&self) -> RouteCounters {
        self.counters
    }
}

/// Snapshot the frame `descriptor` names into `scratch`, yielding the exactly
/// `len`-byte prefix that holds it.
///
/// The copy is what makes a decision defensible at all: bytes left in the pool
/// are free to change under the decision that inspected them
/// (`packet_buffer`'s crate header), so what is parsed and rewritten is this
/// domain's own memory, and only the finished header goes back.
///
/// # Errors
/// [`CopyOutError`], carrying the span that was refused: `scratch` shorter than
/// the frame, or a span that leaves its buffer.
fn snapshot<'scratch>(
    pool: &Pool,
    descriptor: &Descriptor,
    scratch: &'scratch mut [u8],
) -> Result<&'scratch mut [u8], CopyOutError> {
    let len = descriptor.len as usize;
    let capacity = scratch.len();
    let Some(frame_bytes) = scratch.get_mut(..len) else {
        return Err(CopyOutError::DestinationTooSmall { len, capacity });
    };
    // SAFETY: `copy_out`'s one clause is that the caller currently owns the
    // index, and this domain does not: it holds a descriptor in transit, not a
    // buffer. That clause has no enforcer anywhere in the system and is not
    // claimed here; `packet_buffer`'s own header states what violating it
    // yields — "a snapshot of bytes another domain was writing, which the
    // caller already treats as untrusted, and never a dangling or aliased
    // reference" — and the crate header above records it as accepted residue.
    // What makes the call sound is guaranteed: the mapping is the
    // `<map mr="pool0"/"pool1" perms="rw" cached="true">` grant to the
    // forwarder in systems/qemu-x86_64/librefirewall.system, taken through
    // `attach_region!`; the span is bounded by `descriptor_in_bounds` in
    // `RouteStage::poll` and again, unconditionally, by the pool's own span
    // check, which answers in the return value rather than faulting; and
    // `frame_bytes` is the caller's own storage, which cannot alias a pool it
    // holds no reference into.
    unsafe {
        pool.copy_out(
            descriptor.buffer as usize,
            descriptor.offset as usize,
            descriptor.len,
            frame_bytes,
        )
    }?;
    Ok(frame_bytes)
}

/// The verdict on one snapshotted frame, rewritten in place for its next hop
/// when the verdict is to forward it.
fn route_frame<const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize>(
    router: &Router<MAX_INTERFACES, MAX_NEIGHBOURS>,
    ingress: PortId,
    egress: PortId,
    frame_bytes: &mut [u8],
    counters: &mut RouteCounters,
) -> Verdict {
    let mut frame = match Frame::parse(frame_bytes) {
        Ok(frame) => frame,
        Err(_) => {
            bump(&mut counters.unparsable);
            return Verdict::Discard;
        }
    };
    match router.decide(ingress, &frame) {
        Decision::Drop(reason) => {
            counters.drops.record(reason);
            Verdict::Discard
        }
        Decision::Forward {
            egress: decided, ..
        } if decided != egress => {
            bump(&mut counters.misrouted);
            Verdict::Discard
        }
        Decision::Forward {
            source,
            destination,
            ..
        } => match frame.rewrite_for_forwarding(source, destination) {
            Ok(()) => Verdict::Transmit,
            // The router refuses a TTL that cannot survive a hop before it
            // resolves a route, so this is one rejection reached through the
            // second of two enforcers. Recording it under the reason the first
            // would have used keeps one refused packet to one drop.
            Err(TtlExpired { .. }) => {
                counters.drops.record(DropReason::TtlExpired);
                Verdict::Discard
            }
        },
    }
}

/// Put the rewritten headers back into the pool buffer, and answer whether the
/// frame may still be transmitted.
///
/// Only [`REWRITTEN_HEADER_LEN`] bytes go back. The payload is never written:
/// it is the sender's, this stage does not alter it, and copying it back would
/// overwrite whatever the peer has legitimately done to those bytes since.
fn write_back(
    pool: &Pool,
    descriptor: &Descriptor,
    scratch: &[u8; BUFFER_SIZE],
    counters: &mut RouteCounters,
) -> Verdict {
    // SAFETY: the ownership clause, the mapping and the span are exactly as
    // `snapshot` states them for the same buffer, `write_at` differing only in
    // direction; the source is this domain's own storage, so it cannot alias
    // the pool. The written window is a fixed range of a fixed-size array,
    // bounded by the `REWRITTEN_HEADER_LEN <= BUFFER_SIZE` assertion above at
    // build time, and where it lands in the buffer is `write_at`'s own business
    // — it bounds that unconditionally and answers in its return value.
    let placed = unsafe {
        pool.write_at(
            descriptor.buffer as usize,
            descriptor.offset as usize,
            &scratch[..REWRITTEN_HEADER_LEN],
        )
    };
    match placed {
        Ok(()) => Verdict::Transmit,
        Err(_) => {
            bump(&mut counters.writeback_failed);
            Verdict::Discard
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use net_headers::{EtherType, Ipv4Address, MacAddress, Protocol, Transport, UDP_HEADER_LEN};
    use proptest::prelude::*;
    use routing::{Interface, Neighbour};
    use std::boxed::Box;
    use std::collections::BTreeSet;
    use std::sync::LazyLock;
    use std::thread;
    use std::vec::Vec;

    const PORT0: PortId = PortId(0);
    const PORT1: PortId = PortId(1);
    const GATEWAY0_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]);
    const GATEWAY1_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x51]);
    const HOST_A_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0a]);
    const HOST_B_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0b]);
    const HOST_A: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 2]);
    const HOST_B: Ipv4Address = Ipv4Address::from_octets([10, 0, 1, 2]);

    /// The offset a published frame sits at, as the receiving driver publishes
    /// it: the device's own 12-byte header occupies the front of the buffer, so
    /// a stage that assumed a frame starts at zero would rewrite the header's
    /// bytes and read the frame's as headers.
    const DEVICE_HEADER_LEN: u32 = 12;

    /// Bytes of UDP payload the concurrent chain carries its sequence number
    /// in — a `u64`, so half a million frames are all distinguishable.
    const SEQUENCE_LEN: usize = 8;

    /// Turns a thread of the concurrent chain spins without progress before it
    /// declares the run stalled. Measured worst case on an idle host is a few
    /// thousand, so this leaves five orders of magnitude of headroom and is
    /// still seconds rather than forever — which is what turns a buffer lost
    /// across a commit, or an assertion that killed the thread holding the far
    /// end, into a named failure instead of a test that hangs.
    const STALL_SPINS: u64 = 1 << 28;

    /// The configuration `pds/forwarder` compiles in, so what these tests hold
    /// the stage to is the appliance's own topology rather than one invented
    /// here.
    const INTERFACE0: Interface = Interface {
        port: PORT0,
        mac: GATEWAY0_MAC,
        address: Ipv4Address::from_octets([10, 0, 0, 1]),
        prefix_length: 24,
        enabled: true,
    };
    const INTERFACE1: Interface = Interface {
        port: PORT1,
        mac: GATEWAY1_MAC,
        address: Ipv4Address::from_octets([10, 0, 1, 1]),
        prefix_length: 24,
        enabled: true,
    };
    const NEIGHBOURS: [Neighbour; 2] = [
        Neighbour {
            port: PORT0,
            address: HOST_A,
            mac: HOST_A_MAC,
        },
        Neighbour {
            port: PORT1,
            address: HOST_B,
            mac: HOST_B_MAC,
        },
    ];

    /// Built once and shared, the appliance's own two-port topology at the
    /// generation a first commit produces.
    static ROUTER: LazyLock<Router<2, 2>> = LazyLock::new(|| {
        Router::from_slices(&[INTERFACE0, INTERFACE1], &NEIGHBOURS).expect("two of each fit in two")
    });

    /// The same topology with port 0 administratively down, so the one drop
    /// reason a fully enabled configuration cannot reach is reachable here.
    static ROUTER_PORT0_DOWN: LazyLock<Router<2, 2>> = LazyLock::new(|| {
        Router::from_slices(
            &[
                Interface {
                    enabled: false,
                    ..INTERFACE0
                },
                INTERFACE1,
            ],
            &NEIGHBOURS,
        )
        .expect("two of each fit in two")
    });

    /// What a test decides under when the configuration is not what it is
    /// about: the appliance's own table, at the generation a first commit
    /// produces.
    fn running() -> Configuration<'static, 2, 2> {
        Configuration::new(1, &ROUTER)
    }

    /// The two addresses generation `number` writes into a forwarded frame: the
    /// egress interface's own MAC, and the MAC of the neighbour it resolves the
    /// next hop to. Both carry `number`, so no two generations share either,
    /// and a frame rewritten out of two tables at once names a pair that
    /// belongs to neither.
    fn generation_macs(number: u8) -> (MacAddress, MacAddress) {
        (
            MacAddress([0x52, 0x54, 0x00, 0xAA, number, 0x01]),
            MacAddress([0x52, 0x54, 0x00, 0xBB, number, 0x02]),
        )
    }

    /// One generation of the appliance's configuration: the two real subnets
    /// throughout, with `port0_up` deciding whether the ingress interface is
    /// administratively up and [`generation_macs`] supplying the pair a rewrite
    /// is attributed by.
    fn generation(number: u8, port0_up: bool) -> (u32, Router<2, 2>) {
        let (egress_mac, next_hop_mac) = generation_macs(number);
        let table = Router::from_slices(
            &[
                Interface {
                    enabled: port0_up,
                    ..INTERFACE0
                },
                Interface {
                    mac: egress_mac,
                    ..INTERFACE1
                },
            ],
            &[
                NEIGHBOURS[0],
                Neighbour {
                    mac: next_hop_mac,
                    ..NEIGHBOURS[1]
                },
            ],
        )
        .expect("two of each fit in two");
        (u32::from(number), table)
    }

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

    /// One frame an endpoint puts on the wire, in the shape the tests vary it:
    /// every field a routing decision reads, and nothing else.
    struct FrameSpec {
        destination_mac: MacAddress,
        source: Ipv4Address,
        destination: Ipv4Address,
        ttl: u8,
        tagged: bool,
        payload_len: usize,
    }

    impl FrameSpec {
        /// Host A to host B across the appliance: the frame the whole dataplane
        /// exists to carry, and the base every rejection below is one edit from.
        fn a_to_b() -> Self {
            Self {
                destination_mac: GATEWAY0_MAC,
                source: HOST_A,
                destination: HOST_B,
                ttl: 64,
                tagged: false,
                payload_len: 24,
            }
        }

        fn build(&self) -> Vec<u8> {
            let mut frame = Vec::new();
            frame.extend_from_slice(&self.destination_mac.0);
            frame.extend_from_slice(&HOST_A_MAC.0);
            if self.tagged {
                frame.extend_from_slice(&EtherType::VLAN.0.to_be_bytes());
                frame.extend_from_slice(&0x0064u16.to_be_bytes());
            }
            frame.extend_from_slice(&EtherType::IPV4.0.to_be_bytes());

            let total_length = (IPV4_HEADER_LEN + UDP_HEADER_LEN + self.payload_len) as u16;
            let mut ip = [0u8; IPV4_HEADER_LEN];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&total_length.to_be_bytes());
            ip[8] = self.ttl;
            ip[9] = Protocol::UDP.0;
            ip[12..16].copy_from_slice(&self.source.octets());
            ip[16..20].copy_from_slice(&self.destination.octets());
            let checksum = ipv4_checksum(&ip);
            ip[10..12].copy_from_slice(&checksum.to_be_bytes());
            frame.extend_from_slice(&ip);

            frame.extend_from_slice(&4444u16.to_be_bytes());
            frame.extend_from_slice(&5000u16.to_be_bytes());
            frame.extend_from_slice(&((UDP_HEADER_LEN + self.payload_len) as u16).to_be_bytes());
            frame.extend_from_slice(&0u16.to_be_bytes());
            frame.extend(payload_pattern(self.payload_len));
            frame
        }
    }

    /// A recognisable payload, so "the payload was not touched" is a claim
    /// about bytes that could have been changed rather than about a run of
    /// zeroes that would look untouched however it were corrupted.
    fn payload_pattern(len: usize) -> impl Iterator<Item = u8> {
        (0..len).map(|index| (index as u8).wrapping_mul(31).wrapping_add(7))
    }

    /// The RFC 1071 header checksum, written the naive way rather than reusing
    /// `net_headers`: a builder that computed it the way the parser verifies it
    /// would agree with itself no matter which of the two was wrong.
    fn ipv4_checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
        let mut sum = 0u32;
        for (index, pair) in header.chunks(2).enumerate() {
            if index == 5 {
                continue;
            }
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Stand in for the receiving NIC: take a free buffer, fill it as a DMA
    /// would — behind the device header, where a real frame lands — and publish
    /// the span on the pipeline's `rx` ring. Returns the buffer index
    /// published, or `None` when the pool is momentarily empty.
    fn receive(
        pool: &Pool,
        owner: &mut PoolOwner<'_>,
        rx: &mut RingProducer<'_, RING_SLOTS>,
        frame: &[u8],
    ) -> Option<u32> {
        let buffer = owner.alloc()?;
        let index = buffer.index();
        // SAFETY: `buffer` came from our ledger, so we own it exclusively until
        // `lend` transfers it; `frame` is a local, not a pool borrow.
        unsafe { pool.write_at(index as usize, DEVICE_HEADER_LEN as usize, frame) }
            .expect("the test frames are far smaller than a buffer");
        match owner.lend(
            rx,
            buffer,
            DEVICE_HEADER_LEN,
            frame.len() as u32,
            Verdict::Transmit,
        ) {
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
        mut on_frame: impl FnMut(&Descriptor, &[u8]),
    ) -> usize {
        let mut count = 0;
        // One buffer's worth of private storage, reused across the drain: what
        // `on_frame` inspects is a snapshot here, never a borrow of the pool.
        let mut storage = [0u8; BUFFER_SIZE];
        for descriptor in tx.drain(DRAIN_LIMIT) {
            {
                // SAFETY: we dequeued this descriptor, so we own its buffer
                // until it is returned below. The data is the `len` bytes at
                // `offset` the rx side published, and the snapshot lands in
                // `storage`, so the borrow handed to `on_frame` is of this
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
                on_frame(&descriptor, bytes);
            }
            // Under either verdict: this is the only domain that can return the
            // buffer, which is what the verdict rides in the descriptor for.
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
        assert_eq!(size_of::<ForwardRings>(), 4112);
        assert_eq!(size_of::<ReturnRing>(), 2056);
        assert_eq!(POOL_REGION_SIZE, 0x20000);
        assert_eq!(FORWARD_REGION_SIZE, 0x2000);
        assert_eq!(RETURN_REGION_SIZE, 0x1000);
        // And what the split costs, as values: 0x23000 against the 0x22000 one
        // region holding all four components rounds up to — one page.
        assert_eq!(
            POOL_REGION_SIZE + FORWARD_REGION_SIZE + RETURN_REGION_SIZE,
            0x23000
        );
        assert_eq!(
            (size_of::<Pool>() + 3 * size_of::<Ring>()).next_multiple_of(MAPPING_ALIGN),
            0x22000
        );
    }

    #[test]
    fn descriptor_bounds_reject_out_of_pool_spans() {
        let max = BUFFER_SIZE as u32;
        assert!(descriptor_in_bounds(&Descriptor::new(
            0,
            0,
            max,
            Verdict::Transmit
        )));
        assert!(descriptor_in_bounds(&Descriptor::new(
            POOL_BUFFERS as u32 - 1,
            max - 1,
            1,
            Verdict::Transmit
        )));
        assert!(descriptor_in_bounds(&Descriptor::new(
            0,
            max,
            0,
            Verdict::Transmit
        )));
        // Buffer index outside the pool.
        assert!(!descriptor_in_bounds(&Descriptor::new(
            POOL_BUFFERS as u32,
            0,
            1,
            Verdict::Transmit
        )));
        // Span runs past the buffer end.
        assert!(!descriptor_in_bounds(&Descriptor::new(
            0,
            1,
            max,
            Verdict::Transmit
        )));
        // Offset + len overflows.
        assert!(!descriptor_in_bounds(&Descriptor::new(
            0,
            u32::MAX,
            u32::MAX,
            Verdict::Transmit
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
    fn a_routable_packet_is_rewritten_in_the_pool_and_marked_for_transmission() {
        // The whole of what the stage is for, asserted on the bytes the
        // transmitting NIC will read rather than on the verdict alone: a frame
        // marked `Transmit` whose pool buffer still held the arriving MACs
        // would be sent straight back to the subnet it came from.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut tx_out = r.rings.tx.consumer();
        let mut free_in = r.returns.free.producer();

        let sent = FrameSpec::a_to_b().build();
        receive(&r.pool, &mut owner, &mut rx_in, &sent).expect("a full pool has buffers");
        assert_eq!(stage.poll(running()), 1);
        assert_eq!(stage.counters().forwarded, 1);
        assert_eq!(stage.counters().drops.total(), 0);

        let mut seen = 0;
        transmit(&r.pool, &mut tx_out, &mut free_in, |descriptor, bytes| {
            seen += 1;
            assert_eq!(
                Verdict::from_bits(descriptor.verdict),
                Some(Verdict::Transmit)
            );
            assert_eq!(
                descriptor.offset, DEVICE_HEADER_LEN,
                "the span must be the one published"
            );
            assert_eq!(descriptor.len as usize, sent.len());

            // Re-parsed rather than compared byte-wise, so what is asserted is
            // what the next hop will make of the frame.
            let mut copy = bytes.to_vec();
            let frame = Frame::parse(&mut copy).expect("a rewritten frame stays well-formed");
            assert_eq!(
                frame.source_mac(),
                GATEWAY1_MAC,
                "the egress interface's own MAC"
            );
            assert_eq!(frame.destination_mac(), HOST_B_MAC, "the next hop's MAC");
            assert_eq!(frame.ipv4().ttl, 63);
            assert_eq!(frame.ipv4().source, HOST_A);
            assert_eq!(frame.ipv4().destination, HOST_B);
            assert!(matches!(frame.transport(), Transport::Udp(_)));

            // Everything past the two rewritten headers is the sender's, and
            // is byte-identical to what arrived.
            assert_eq!(
                &bytes[REWRITTEN_HEADER_LEN..],
                &sent[REWRITTEN_HEADER_LEN..]
            );
        });
        assert_eq!(seen, 1);
        assert_eq!(owner.reclaim(), 1);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn a_forwarded_frame_is_rewritten_where_the_producer_published_it() {
        // The frame sits behind the device's own header, so the rewrite must
        // land at the descriptor's `offset`. A stage that wrote back at the
        // buffer's front would corrupt that header and leave the frame's own
        // first 34 bytes as they arrived — which still parses, still routes,
        // and loops.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);

        let sent = FrameSpec::a_to_b().build();
        let index =
            receive(&r.pool, &mut owner, &mut rx_in, &sent).expect("a full pool has buffers");
        assert_eq!(stage.poll(running()), 1);

        let mut whole = [0u8; BUFFER_SIZE];
        // SAFETY: the buffer is lent, and this test is the only other party to
        // the pool; the snapshot lands in this function's own storage.
        let buffer = unsafe {
            r.pool
                .copy_out(index as usize, 0, BUFFER_SIZE as u32, &mut whole)
        }
        .expect("a whole buffer is in bounds");
        assert_eq!(
            &buffer[..DEVICE_HEADER_LEN as usize],
            &[0u8; DEVICE_HEADER_LEN as usize],
            "the device header space was written over"
        );
        let mut frame_bytes = buffer[DEVICE_HEADER_LEN as usize..][..sent.len()].to_vec();
        let frame = Frame::parse(&mut frame_bytes).expect("the rewritten frame parses");
        assert_eq!(frame.destination_mac(), HOST_B_MAC);
    }

    #[test]
    fn lend_publishes_the_verdict_it_was_given() {
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut rx_out = r.rings.rx.consumer();
        for verdict in [Verdict::Transmit, Verdict::Discard] {
            let buffer = owner.alloc().expect("a full pool has buffers");
            let index = buffer.index();
            owner
                .lend(&mut rx_in, buffer, 4, 8, verdict)
                .expect("the ring is empty");
            assert_eq!(
                rx_out.try_dequeue(),
                Some(Descriptor::new(index, 4, 8, verdict))
            );
        }
    }

    #[test]
    fn the_verdict_a_producer_published_is_replaced_by_this_stages_own_decision() {
        // The rx driver's verdict word is peer input: a byzantine one can mark
        // a perfectly routable frame `Discard`, or write a word that decodes to
        // nothing at all. Neither may decide anything here — this stage is the
        // domain that judges the frame, and it overwrites the word it was
        // handed with what it concluded.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut tx_out = r.rings.tx.consumer();

        let sent = FrameSpec::a_to_b().build();
        for forged in [Verdict::Discard.to_bits(), 0xDEAD_BEEF] {
            let buffer = owner.alloc().expect("a full pool has buffers");
            let index = buffer.index();
            // SAFETY: the token is ours, and `sent` is a local rather than a
            // pool borrow.
            unsafe {
                r.pool
                    .write_at(index as usize, DEVICE_HEADER_LEN as usize, &sent)
            }
            .expect("a frame is far smaller than a buffer");
            // A field-wise literal, not `Descriptor::new`: `lend` takes a
            // `Verdict`, so a word decoding to nothing can only be published by
            // a peer writing the slot itself — which is what this is.
            rx_in
                .try_enqueue(Descriptor {
                    buffer: index,
                    offset: DEVICE_HEADER_LEN,
                    len: sent.len() as u32,
                    verdict: forged,
                })
                .expect("the ring is empty");
            drop(buffer);

            assert_eq!(stage.poll(running()), 1);
            let handed_on = tx_out.try_dequeue().expect("the frame was handed on");
            assert_eq!(
                Verdict::from_bits(handed_on.verdict),
                Some(Verdict::Transmit),
                "a routable frame must be transmitted whatever the producer claimed"
            );
        }
        assert_eq!(stage.counters().forwarded, 2);
    }

    #[test]
    fn a_full_destination_ring_is_counted_and_stops_the_drain() {
        // A byzantine rx peer over-fills `rx` while the tx driver stalls.
        // The destination is filled *through the stage itself*, since a second
        // producer handle would restart at slot zero and prove nothing. The
        // buffers those refused descriptors named are lost to the pool, which
        // is the residue the crate header records.
        let r = Regions::new();
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);

        // Descriptors naming empty buffers: in bounds, so they reach the
        // destination ring under a `Discard` verdict and fill it.
        let capacity = r.rings.tx.capacity();
        for index in 0..capacity as u32 {
            rx_in
                .try_enqueue(Descriptor::new(
                    index % POOL_BUFFERS as u32,
                    0,
                    64,
                    Verdict::Transmit,
                ))
                .unwrap();
        }
        assert_eq!(
            stage.poll(running()),
            capacity,
            "the destination is now full"
        );
        assert_eq!(stage.counters().egress_full, 0);

        for index in 0..4 {
            rx_in
                .try_enqueue(Descriptor::new(index, 0, 64, Verdict::Transmit))
                .unwrap();
        }
        assert_eq!(stage.poll(running()), 0);
        assert_eq!(stage.counters().egress_full, 1);
        // Draining stopped at the first refusal rather than emptying `rx` into
        // a full destination and losing every buffer with it.
        assert_eq!(r.rings.rx.consumer().len(), 3);
    }

    #[test]
    fn poll_is_bounded_when_a_peer_keeps_the_source_ring_non_empty() {
        // A peer that keeps advancing its published `tail` makes the source
        // look permanently non-empty. Work per poll must still be finite.
        let r = Regions::new();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut tx_out = r.rings.tx.consumer();
        for round in 0..8u32 {
            forge_cursors(&r.rings.rx, 0, round.wrapping_mul(37).wrapping_add(11));
            let handed_on = stage.poll(running());
            assert!(
                handed_on <= DRAIN_LIMIT,
                "poll handled {handed_on} descriptors"
            );
            // Keep the destination drained so the bound, not fullness, is what
            // stops the loop.
            let _ = tx_out.drain(DRAIN_LIMIT).count();
        }
    }

    #[test]
    fn a_descriptor_naming_no_pool_buffer_is_counted_and_never_dereferenced() {
        // The forged descriptor is the one thing the stage may not hand on:
        // it names no buffer the transmitting driver could return, so passing
        // it along would be inventing a return rather than granting one. It is
        // also the case where a missing bounds check would have the stage read
        // outside the pool.
        let r = Regions::new();
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut tx_out = r.rings.tx.consumer();

        for forged in [
            Descriptor::new(POOL_BUFFERS as u32, 0, 64, Verdict::Transmit),
            Descriptor::new(u32::MAX, 0, 64, Verdict::Transmit),
            Descriptor::new(0, 1, BUFFER_SIZE as u32, Verdict::Transmit),
            Descriptor::new(0, u32::MAX, u32::MAX, Verdict::Transmit),
        ] {
            rx_in.try_enqueue(forged).expect("the ring has room");
        }

        assert_eq!(stage.poll(running()), 0, "nothing may be handed on");
        assert_eq!(stage.counters().malformed_descriptor, 4);
        assert_eq!(stage.counters().snapshot_failed, 0);
        assert_eq!(tx_out.try_dequeue(), None);
    }

    #[test]
    fn every_reason_the_router_refuses_a_frame_for_still_hands_the_buffer_back() {
        // The property the verdict mechanism exists for, over every drop the
        // router can reach: this domain maps no `free` ring, so a frame it
        // decides against must still travel to the transmitting driver — the
        // only domain that can give the buffer back. A stage that dropped the
        // descriptor instead would shrink the pool by one buffer per hostile
        // packet, which is a denial of service with no counter attached.
        let cases = [
            (
                DropReason::UnconfiguredIngressPort,
                &*ROUTER,
                PortId(7),
                FrameSpec::a_to_b(),
            ),
            (
                DropReason::InterfaceDisabled,
                &*ROUTER_PORT0_DOWN,
                PORT0,
                FrameSpec::a_to_b(),
            ),
            (
                DropReason::NotAddressedToUs,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    destination_mac: MacAddress::BROADCAST,
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::VlanTagged,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    tagged: true,
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::MartianSource,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    source: Ipv4Address::from_octets([224, 0, 0, 1]),
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::UnroutableDestination,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    destination: Ipv4Address::from_octets([255, 255, 255, 255]),
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::AddressedToThisRouter,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    destination: Ipv4Address::from_octets([10, 0, 1, 1]),
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::TtlExpired,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    ttl: 1,
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::NoRoute,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    destination: Ipv4Address::from_octets([192, 0, 2, 9]),
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::EgressIsIngress,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    destination: Ipv4Address::from_octets([10, 0, 0, 9]),
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::NoNeighbour,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    destination: Ipv4Address::from_octets([10, 0, 1, 77]),
                    ..FrameSpec::a_to_b()
                },
            ),
        ];

        // What makes the name of this test true rather than aspirational: a
        // reason added to the enum without a case here fails at once.
        let mut covered: Vec<DropReason> = cases.iter().map(|(reason, ..)| *reason).collect();
        covered.sort_unstable();
        covered.dedup();
        assert_eq!(
            covered,
            DropReason::ALL.to_vec(),
            "a drop reason no case here reaches"
        );

        for (reason, table, ingress, spec) in cases {
            let r = Regions::new();
            let mut owner = PoolOwner::attach(&r.returns);
            let mut rx_in = r.rings.rx.producer();
            let mut stage = RouteStage::attach(&r.rings, &r.pool, ingress, PORT1);
            let mut tx_out = r.rings.tx.consumer();
            let mut free_in = r.returns.free.producer();

            let sent = spec.build();
            receive(&r.pool, &mut owner, &mut rx_in, &sent).expect("a full pool has buffers");
            assert_eq!(
                stage.poll(Configuration::new(1, table)),
                1,
                "{reason}: the descriptor must travel on"
            );

            let counters = stage.counters();
            assert_eq!(counters.drops.get(reason), 1, "{reason}: not counted");
            assert_eq!(
                counters.drops.total(),
                1,
                "{reason}: counted as something else too"
            );
            assert_eq!(counters.forwarded, 0, "{reason}");

            let mut seen = 0;
            transmit(&r.pool, &mut tx_out, &mut free_in, |descriptor, bytes| {
                seen += 1;
                assert_eq!(
                    Verdict::from_bits(descriptor.verdict),
                    Some(Verdict::Discard),
                    "{reason}: a refused frame must not be transmitted"
                );
                assert_eq!(bytes, sent, "{reason}: a refused frame was rewritten");
            });
            assert_eq!(seen, 1, "{reason}");
            // The buffer is back where it started: nothing leaked.
            assert_eq!(owner.reclaim(), 1, "{reason}");
            assert_eq!(owner.owned(), POOL_BUFFERS, "{reason}");
        }
    }

    #[test]
    fn a_frame_that_is_not_a_routable_packet_is_discarded_and_handed_back() {
        // Arbitrary bytes on the wire: not IPv4, not long enough, and a frame
        // whose IPv4 header contradicts itself. None of them is attributable to
        // a routing decision, so none of them may be counted as one.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut tx_out = r.rings.tx.consumer();
        let mut free_in = r.returns.free.producer();

        let mut truncated_ip = FrameSpec::a_to_b().build();
        truncated_ip.truncate(ETHERNET_HEADER_LEN + 4);
        let mut bad_checksum = FrameSpec::a_to_b().build();
        bad_checksum[ETHERNET_HEADER_LEN + 10] ^= 0xff;
        let unroutable = [
            std::vec![0xAA; 64],
            std::vec![0x00; 10],
            truncated_ip,
            bad_checksum,
        ];
        for frame in &unroutable {
            receive(&r.pool, &mut owner, &mut rx_in, frame).expect("a full pool has buffers");
        }

        assert_eq!(stage.poll(running()), unroutable.len());
        assert_eq!(stage.counters().unparsable, unroutable.len() as u64);
        assert_eq!(
            stage.counters().drops.total(),
            0,
            "no routing decision was made"
        );
        assert_eq!(stage.counters().forwarded, 0);

        let returned = transmit(&r.pool, &mut tx_out, &mut free_in, |descriptor, _| {
            assert_eq!(
                Verdict::from_bits(descriptor.verdict),
                Some(Verdict::Discard)
            );
        });
        assert_eq!(returned, unroutable.len());
        assert_eq!(owner.reclaim(), unroutable.len());
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn a_route_out_of_a_port_this_stage_is_not_wired_to_is_discarded() {
        // A stage is a fixed cross-connect. This one is wired ingress port 0 to
        // egress port 0, so the router's decision — out of port 1 — names a
        // ring this stage does not hold, and carrying it out would put the
        // frame back on the subnet it arrived from.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT0);
        let mut tx_out = r.rings.tx.consumer();

        let sent = FrameSpec::a_to_b().build();
        receive(&r.pool, &mut owner, &mut rx_in, &sent).expect("a full pool has buffers");

        assert_eq!(stage.poll(running()), 1);
        assert_eq!(stage.counters().misrouted, 1);
        assert_eq!(stage.counters().forwarded, 0);
        assert_eq!(
            stage.counters().drops.total(),
            0,
            "the router had no objection; this stage did"
        );
        let handed_on = tx_out.try_dequeue().expect("the buffer must travel back");
        assert_eq!(
            Verdict::from_bits(handed_on.verdict),
            Some(Verdict::Discard)
        );
    }

    #[test]
    fn a_snapshot_that_cannot_be_taken_names_what_it_refused() {
        // Both refusals `snapshot` can answer with, neither of which
        // `RouteStage::poll` can reach: `descriptor_in_bounds` rules out the
        // span, and the stage's own storage is a whole buffer. They exist
        // because the alternative to answering is a truncated frame that still
        // parses — a decision made on bytes that are not the packet.
        let r = Regions::new();
        let mut short = [0u8; 8];
        assert_eq!(
            snapshot(
                &r.pool,
                &Descriptor::new(0, 0, 16, Verdict::Transmit),
                &mut short
            ),
            Err(CopyOutError::DestinationTooSmall {
                len: 16,
                capacity: 8
            })
        );

        let mut whole = [0u8; BUFFER_SIZE];
        assert_eq!(
            snapshot(
                &r.pool,
                &Descriptor::new(POOL_BUFFERS as u32, 0, 4, Verdict::Transmit),
                &mut whole
            ),
            Err(CopyOutError::SpanOutsideBuffer {
                index: POOL_BUFFERS,
                offset: 0,
                len: 4
            })
        );
    }

    #[test]
    fn a_write_back_the_pool_refuses_discards_the_frame_rather_than_transmitting_it() {
        // The header window is written at the descriptor's own offset, so a
        // span the descriptor validator passes can still leave no room for it.
        // Transmitting anyway would put the frame on the wire with the MACs and
        // the TTL it arrived with, which is a loop rather than a hop.
        let r = Regions::new();
        let mut counters = RouteCounters::default();
        let scratch = [0u8; BUFFER_SIZE];
        let no_room = Descriptor::new(0, BUFFER_SIZE as u32 - 4, 4, Verdict::Transmit);
        assert!(
            descriptor_in_bounds(&no_room),
            "the span itself is in bounds"
        );
        assert_eq!(
            write_back(&r.pool, &no_room, &scratch, &mut counters),
            Verdict::Discard
        );
        assert_eq!(counters.writeback_failed, 1);
    }

    #[test]
    fn single_threaded_pipeline_round_trip_forwards_both_frames_in_order() {
        // The three-PD routed chain in one thread: receive two frames, route
        // them, transmit them, then reclaim — full pool ownership must return
        // and both payloads must survive intact and in order.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut tx_out = r.rings.tx.consumer();
        let mut free_in = r.returns.free.producer();

        let frames: Vec<Vec<u8>> = [7usize, 8]
            .into_iter()
            .map(|payload_len| {
                FrameSpec {
                    payload_len,
                    ..FrameSpec::a_to_b()
                }
                .build()
            })
            .collect();
        for frame in &frames {
            assert!(receive(&r.pool, &mut owner, &mut rx_in, frame).is_some());
        }
        assert_eq!(owner.owned(), POOL_BUFFERS - 2);

        assert_eq!(stage.poll(running()), 2);

        let mut seen = Vec::new();
        let transmitted = transmit(&r.pool, &mut tx_out, &mut free_in, |_, bytes| {
            seen.push(bytes[REWRITTEN_HEADER_LEN..].to_vec());
        });
        assert_eq!(transmitted, 2);
        let expected: Vec<Vec<u8>> = frames
            .iter()
            .map(|frame| frame[REWRITTEN_HEADER_LEN..].to_vec())
            .collect();
        assert_eq!(seen, expected, "payloads must arrive intact and in order");

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
        let Err(returned) = owner.lend(&mut rx_in, buffer, 0, 0, Verdict::Transmit) else {
            panic!("a full ring must refuse the lend");
        };
        assert_eq!(returned.index(), index);
        owner.release(returned);
        assert_eq!(owner.owned(), POOL_BUFFERS);

        // Having never been lent, that index cannot be returned by the peer.
        let mut free_in = r.returns.free.producer();
        free_in
            .try_enqueue(Descriptor::new(index, 0, 0, Verdict::Transmit))
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
                .try_enqueue(Descriptor::new(forged, 0, 0, Verdict::Transmit))
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
            .lend(&mut rx_in, buffer, 0, 0, Verdict::Transmit)
            .expect("the ring is empty");
        for _ in 0..3 {
            free_in
                .try_enqueue(Descriptor::new(index, 0, 0, Verdict::Transmit))
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
            .try_enqueue(Descriptor::new(index, 0, 0, Verdict::Transmit))
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
            .try_enqueue(Descriptor::new(3, 0, 0, Verdict::Transmit))
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
            .try_enqueue(Descriptor::new(
                offered as u32 % POOL_BUFFERS as u32,
                0,
                0,
                Verdict::Transmit,
            ))
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
    fn a_lapping_peer_cursor_redelivers_returns_that_the_lent_set_refuses() {
        // The upper half of the division of responsibility `queue`'s
        // `a_forged_tail_that_laps_the_ring_does_redeliver_and_this_layer_permits_it`
        // states the lower half of. That test proves the ring *will* hand a
        // descriptor over twice when a peer rewinds its published cursor far
        // enough to lap the consumer; this one proves the second delivery buys
        // the peer nothing, because a return is accepted only for an index that
        // is currently lent, and the first delivery cleared that bit.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut free_in = r.returns.free.producer();

        // Lend three buffers and let the transmitting peer return them
        // legitimately, which is what advances the owner's private `head` to 3
        // and clears the three lent bits.
        let mut lent = Vec::new();
        for _ in 0..3 {
            let buffer = owner.alloc().expect("a full pool has buffers");
            lent.push(buffer.index());
            owner
                .lend(&mut rx_in, buffer, 0, 0, Verdict::Transmit)
                .expect("the ring is empty");
        }
        for index in &lent {
            free_in
                .try_enqueue(Descriptor::new(*index, 0, 0, Verdict::Transmit))
                .expect("the free ring has room");
        }
        assert_eq!(owner.reclaim(), 3, "the legitimate returns are accepted");
        assert_eq!(owner.owned(), POOL_BUFFERS);
        assert_eq!(owner.counters(), PoolCounters::default());

        // Now the lap. The owner's private head is 3; a published tail of 2
        // keeps the ring looking non-empty until head walks all the way round
        // to it, replaying every slot on the way — the three real returns
        // included.
        forge_cursors(&r.returns.free, 0, 2);

        // Not one is accepted a second time, and each refusal is attributed to
        // the peer rather than to this domain's own bookkeeping.
        assert_eq!(owner.reclaim(), 0, "a redelivered return was accepted");
        assert_eq!(
            owner.counters().reclaim_not_lent,
            (RING_SLOTS - 1) as u64,
            "every slot the lap replayed must be refused as not lent"
        );
        assert_eq!(owner.counters().reclaim_refused, 0);

        // The pool is whole and still hands out each index exactly once, which
        // is what a doubly accepted return would have broken.
        assert_eq!(owner.owned(), POOL_BUFFERS);
        let mut seen = BTreeSet::new();
        while let Some(buffer) = owner.alloc() {
            assert!(seen.insert(buffer.index()), "an index was handed out twice");
        }
        assert_eq!(seen.len(), POOL_BUFFERS);
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
                .lend(&mut rx_in, buffer, 0, 0, Verdict::Transmit)
                .expect("the ring is empty");
        }
        for index in &indices {
            free_in
                .try_enqueue(Descriptor::new(*index, 0, 0, Verdict::Transmit))
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
    fn one_stage_polled_under_three_tables_decides_each_frame_under_the_one_it_was_handed() {
        // The stage carries no configuration of its own, which is the whole of
        // what makes a second commit expressible. The same stage over the same
        // frame three times, with nothing between the polls but the table
        // handed to the next: two that forward it to different next hops under
        // different source MACs, and one that refuses it outright.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut tx_out = r.rings.tx.consumer();
        let mut free_in = r.returns.free.producer();

        let sent = FrameSpec::a_to_b().build();
        for (tag, port0_up) in [(1u8, true), (2u8, true), (3u8, false)] {
            let (number, table) = generation(tag, port0_up);
            receive(&r.pool, &mut owner, &mut rx_in, &sent).expect("a full pool has buffers");
            assert_eq!(stage.poll(Configuration::new(number, &table)), 1);
            assert_eq!(stage.counters().generation, number);

            let expected = port0_up.then(|| generation_macs(tag));
            let mut seen = 0;
            transmit(&r.pool, &mut tx_out, &mut free_in, |descriptor, bytes| {
                seen += 1;
                let verdict = Verdict::from_bits(descriptor.verdict);
                match expected {
                    Some((egress_mac, next_hop_mac)) => {
                        assert_eq!(verdict, Some(Verdict::Transmit), "generation {number}");
                        assert_eq!(&bytes[..6], &next_hop_mac.0, "generation {number}");
                        assert_eq!(&bytes[6..12], &egress_mac.0, "generation {number}");
                    }
                    None => assert_eq!(verdict, Some(Verdict::Discard), "generation {number}"),
                }
            });
            assert_eq!(seen, 1);
            assert_eq!(owner.reclaim(), 1);
            assert_eq!(owner.owned(), POOL_BUFFERS);
        }
        assert_eq!(stage.counters().forwarded, 2);
        assert_eq!(stage.counters().drops.get(DropReason::InterfaceDisabled), 1);
    }

    #[test]
    fn a_configuration_swapped_under_load_decides_every_frame_under_exactly_one_table() {
        // The three-PD routed scenario end to end under real threads, with the
        // configuration replaced between polls throughout: an rx-driver thread
        // fills and publishes buffers, a forwarder thread routes them onward
        // under a table it exchanges for the other one after every poll that
        // carried traffic, and a tx-driver thread consumes and returns them, so
        // every buffer cycles rx -> route -> tx -> free far more times than the
        // pool holds and every one of those cycles crosses a commit. Both rings
        // wrap repeatedly and every buffer is reused.
        //
        // Three things must hold, and the two tables are built to make the
        // first of them observable: they share neither the egress interface's
        // MAC nor the next hop's, so the pair in a frame's rewritten header
        // names exactly one generation, and a frame carrying one table's source
        // MAC under the other's destination MAC — a decision taken across a
        // swap — matches neither and fails here.
        //
        //  * every forwarded frame is rewritten out of one table, never a blend;
        //  * the pool comes back whole, so no commit lost or duplicated a
        //    buffer in flight across it;
        //  * the sequence-numbered payloads arrive intact and in order under
        //    those rewritten headers.
        //
        // The forwarder thread borrows `rings` and `pool`, which is the grant
        // the system description gives that domain: it can reach `returns` here
        // no more than it can there. It owns the two tables, as the domain will
        // own its running and staged configurations, and nothing else can
        // reach them — which is what leaves the swap point at a poll boundary.
        const TOTAL: u64 = 500_000;
        let r = Regions::new();
        let pool: &Pool = &r.pool;
        let rings: &ForwardRings = &r.rings;
        let returns: &ReturnRing = &r.returns;
        let generations = [generation(1, true), generation(2, true)];
        let generations = &generations;
        let rewrites = [generation_macs(1), generation_macs(2)];

        // Scoped threads because each domain's role type borrows its region: a
        // handle *is* that domain's position, so it is taken once inside the
        // thread that owns the role and kept for the thread's life, exactly as a
        // protection domain takes it once at attach.
        let (applied, per_generation) = thread::scope(|scope| {
            scope.spawn(move || {
                let mut owner = PoolOwner::attach(returns);
                let mut rx_in = rings.rx.producer();
                // One frame, its payload patched per send: the IPv4 checksum
                // covers the header alone, so a sequence number written into
                // the payload leaves the frame exactly as well-formed and the
                // 500,000 sends cost no rebuilding.
                let mut frame = FrameSpec {
                    payload_len: SEQUENCE_LEN,
                    ..FrameSpec::a_to_b()
                }
                .build();
                let sequence_at = frame.len() - SEQUENCE_LEN;
                let mut sent = 0u64;
                let mut idle = 0u64;
                while sent < TOTAL {
                    owner.reclaim();
                    frame[sequence_at..].copy_from_slice(&sent.to_le_bytes());
                    if receive(pool, &mut owner, &mut rx_in, &frame).is_some() {
                        sent += 1;
                        idle = 0;
                    } else {
                        idle += 1;
                        assert!(
                            idle < STALL_SPINS,
                            "the chain stopped taking frames at {sent}"
                        );
                        std::hint::spin_loop();
                    }
                }
                // Wait for the chain to hand every buffer back.
                let mut idle = 0u64;
                while owner.owned() != POOL_BUFFERS {
                    owner.reclaim();
                    idle += 1;
                    assert!(
                        idle < STALL_SPINS,
                        "{} buffers never came back",
                        POOL_BUFFERS - owner.owned()
                    );
                    std::hint::spin_loop();
                }
                assert_eq!(owner.counters(), PoolCounters::default());
            });

            let forwarder = scope.spawn(move || {
                let mut stage = RouteStage::attach(rings, pool, PORT0, PORT1);
                let mut handed_on = 0u64;
                let mut current = 0usize;
                let mut applied = 0u64;
                let mut idle = 0u64;
                while handed_on < TOTAL {
                    let (number, table) = &generations[current];
                    let moved = stage.poll(Configuration::new(*number, table));
                    if moved > 0 {
                        handed_on += moved as u64;
                        // The commit, and the only point one can occur: the
                        // tables are this thread's own, and the poll the last
                        // of them was lent to has returned.
                        current ^= 1;
                        applied += 1;
                        idle = 0;
                    } else {
                        idle += 1;
                        assert!(idle < STALL_SPINS, "nothing to route after {handed_on}");
                    }
                    std::hint::spin_loop();
                }
                let counters = stage.counters();
                assert_eq!(counters.egress_full, 0);
                assert_eq!(counters.forwarded, TOTAL, "every frame was routable");
                assert_eq!(counters.drops.total(), 0);
                assert_eq!(
                    counters.generation,
                    generations[current ^ 1].0,
                    "the sample names a generation other than the one it was taken under"
                );
                applied
            });

            let transmitter = scope.spawn(move || {
                let mut tx_out = rings.tx.consumer();
                let mut free_in = returns.free.producer();
                let mut expected = 0u64;
                let mut per_generation = [0u64; 2];
                let mut idle = 0u64;
                while expected < TOTAL {
                    let before = expected;
                    transmit(pool, &mut tx_out, &mut free_in, |descriptor, bytes| {
                        assert_eq!(
                            Verdict::from_bits(descriptor.verdict),
                            Some(Verdict::Transmit)
                        );
                        // Which table decided this frame, taken from the source
                        // MAC alone, and then the next hop held to that same
                        // table's neighbour. A frame decided across a commit
                        // carries one generation's source MAC under the other's
                        // destination MAC, which is a pair neither table holds.
                        let decided_by = rewrites
                            .iter()
                            .position(|(egress_mac, _)| bytes[6..12] == egress_mac.0)
                            .expect("a source MAC no configuration's egress interface holds");
                        assert_eq!(
                            &bytes[..6],
                            &rewrites[decided_by].1.0,
                            "the next hop and the source MAC come from different generations"
                        );
                        per_generation[decided_by] += 1;
                        // The rewrite happened, and it happened to this frame:
                        // a stage that wrote one buffer's header into another's
                        // would show up here as the wrong sequence number under
                        // a correct MAC, or the reverse.
                        let value = u64::from_le_bytes(
                            bytes[bytes.len() - SEQUENCE_LEN..]
                                .try_into()
                                .expect("the payload is the sequence number"),
                        );
                        assert_eq!(value, expected, "out-of-order or corrupted buffer");
                        expected += 1;
                    });
                    if expected == before {
                        idle += 1;
                        assert!(idle < STALL_SPINS, "nothing to transmit after {expected}");
                    } else {
                        idle = 0;
                    }
                    std::hint::spin_loop();
                }
                per_generation
            });

            (
                forwarder.join().expect("the forwarder thread"),
                transmitter.join().expect("the tx-driver thread"),
            )
        });

        // What makes the run evidence rather than a green light: a poll moves
        // at most `DRAIN_LIMIT` descriptors, so carrying `TOTAL` frames takes
        // at least this many polls that carried traffic — and the table is
        // exchanged after every one of them. A run in which nothing was
        // swapped attributes every frame to one generation and fails here.
        let least_polls = TOTAL.div_ceil(DRAIN_LIMIT as u64);
        assert!(
            applied >= least_polls,
            "{applied} commits over {TOTAL} frames, fewer than the {least_polls} the drain \
             bound forces"
        );
        assert_eq!(per_generation[0] + per_generation[1], TOTAL);
        for (index, forwarded) in per_generation.iter().enumerate() {
            assert!(
                *forwarded >= least_polls / 2,
                "generation {} decided {forwarded} frames, too few to have run under load",
                generations[index].0
            );
        }
        println!(
            "swapped configuration {applied} times under load; generation {} decided {} frames \
             and generation {} decided {}",
            generations[0].0, per_generation[0], generations[1].0, per_generation[1]
        );
    }

    /// The traffic mix both properties below draw from: every shape the stage
    /// answers differently, in the proportions that keep each answer frequent.
    /// The unroutable ones are not decoration — a stage that leaked a buffer
    /// would leak it on exactly these.
    fn any_frame() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            // Routable in the direction under test, and its reverse, which this
            // stage must refuse rather than send back out of its ingress port.
            4 => Just(FrameSpec::a_to_b().build()),
            2 => Just(FrameSpec {
                destination_mac: GATEWAY1_MAC,
                source: HOST_B,
                destination: HOST_A,
                ..FrameSpec::a_to_b()
            }.build()),
            // One frame per family of router rejection.
            1 => Just(FrameSpec { ttl: 1, ..FrameSpec::a_to_b() }.build()),
            1 => Just(FrameSpec { tagged: true, ..FrameSpec::a_to_b() }.build()),
            1 => Just(FrameSpec {
                destination: Ipv4Address::from_octets([203, 0, 113, 4]),
                ..FrameSpec::a_to_b()
            }.build()),
            1 => Just(FrameSpec {
                destination_mac: MacAddress::BROADCAST,
                ..FrameSpec::a_to_b()
            }.build()),
            // And what the wire really carries: bytes of any length that were
            // never a frame at all.
            3 => prop::collection::vec(any::<u8>(), 0..600),
        ]
    }

    /// One move a byzantine neighbour can make against the pool owner and the
    /// routing stage.
    #[derive(Clone, Debug)]
    enum PeerStep {
        /// Take a buffer, fill it with a frame, and publish it as the receiving
        /// driver legitimately would.
        Receive(Vec<u8>),
        /// Take a buffer and keep it, as a buffer posted to the NIC is kept.
        Hold,
        /// Route what is queued.
        Route,
        /// Push an arbitrary descriptor onto the `free` ring, as a byzantine tx
        /// driver does: forged indices, duplicates, buffers never lent.
        ReturnBare(u32),
        /// Take the returns back.
        Reclaim,
        /// Scribble a ring's shared cursors.
        ForgeCursors(u8, u32, u32),
        /// Overwrite a pool buffer's bytes, which every domain mapping the pool
        /// can do at any instant — including between this stage's snapshot and
        /// the transmitting NIC's read.
        ScribblePool(u32, u8),
    }

    fn any_peer_step() -> impl Strategy<Value = PeerStep> {
        prop_oneof![
            4 => any_frame().prop_map(PeerStep::Receive),
            1 => Just(PeerStep::Hold),
            3 => Just(PeerStep::Route),
            // Biased towards real indices so duplicate and never-lent returns
            // are reached, with arbitrary values keeping forged ones in the mix.
            3 => (0..POOL_BUFFERS as u32).prop_map(PeerStep::ReturnBare),
            2 => any::<u32>().prop_map(PeerStep::ReturnBare),
            3 => Just(PeerStep::Reclaim),
            2 => (0u8..3, any::<u32>(), any::<u32>())
                .prop_map(|(ring, head, tail)| PeerStep::ForgeCursors(ring, head, tail)),
            2 => (0..POOL_BUFFERS as u32, any::<u8>())
                .prop_map(|(index, byte)| PeerStep::ScribblePool(index, byte)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// The whole `alloc -> lend -> route -> reclaim` chain driven by an
        /// arbitrary hostile neighbour: arbitrary frames, forged and duplicated
        /// indices on the `free` ring, scribbled cursors on every ring,
        /// rewritten pool bytes, and arbitrary interleaving. Nothing may panic,
        /// every step must do bounded work, and the owner set must stay
        /// conserved — the ledger may only ever hand out real, distinct pool
        /// indices, and the buffers it holds free plus those it has lent or that
        /// are held in hand can never exceed the pool.
        #[test]
        fn a_byzantine_neighbour_cannot_panic_or_double_own_a_buffer(
            steps in prop::collection::vec(any_peer_step(), 0..250),
        ) {
            let r = Regions::new();
            let mut owner = PoolOwner::attach(&r.returns);
            let mut rx_in = r.rings.rx.producer();
            let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
            let mut tx_out = r.rings.tx.consumer();
            let mut free_in = r.returns.free.producer();
            // Tokens this domain holds, standing in for buffers posted to a NIC.
            let mut held: Vec<OwnedBuffer<POOL_BUFFERS>> = Vec::new();

            for step in steps {
                match step {
                    PeerStep::Receive(frame) => {
                        let _ = receive(&r.pool, &mut owner, &mut rx_in, &frame);
                    }
                    PeerStep::Hold => {
                        if let Some(buffer) = owner.alloc() {
                            held.push(buffer);
                        }
                    }
                    PeerStep::Route => {
                        prop_assert!(stage.poll(running()) <= DRAIN_LIMIT);
                        // Play the tx driver: take what arrived and hand each
                        // buffer straight back, as a well-behaved peer would.
                        for descriptor in tx_out.drain(DRAIN_LIMIT) {
                            let _ = free_in.try_enqueue(descriptor);
                        }
                    }
                    PeerStep::ReturnBare(index) => {
                        let _ = free_in.try_enqueue(Descriptor::new(index, 0, 0, Verdict::Transmit));
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
                    PeerStep::ScribblePool(index, byte) => {
                        // SAFETY: `write_at`'s ownership clause is exactly the
                        // one a byzantine peer disregards, which is what this
                        // step reproduces; the source is a local, so it cannot
                        // alias the pool, and the span is the accessor's own
                        // business — it answers in its return value.
                        let _ = unsafe {
                            r.pool.write_at(index as usize, 0, &[byte; BUFFER_SIZE])
                        };
                    }
                }
                // Nothing was invented: free plus held can never exceed the
                // pool, and a buffer in hand is never also on the free stack.
                prop_assert!(owner.owned() <= POOL_BUFFERS);
                prop_assert!(owner.owned() + held.len() <= POOL_BUFFERS);
            }

            // The ledger still hands out only real, distinct indices, and never
            // one this domain is still holding — the conserved owner set.
            let still_held: BTreeSet<u32> =
                held.iter().map(OwnedBuffer::<POOL_BUFFERS>::index).collect();
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

        /// The no-leak invariant the whole verdict mechanism exists for: over
        /// any mix of routable, unroutable, malformed and garbage traffic,
        /// every descriptor that enters the stage leaves it, so every buffer
        /// reaches the one domain that can return it and the pool comes back
        /// whole.
        ///
        /// Forged descriptors are in the mix and are the one exception, stated
        /// as such rather than excluded: they name no buffer, so there is
        /// nothing to hand back and nothing to lose. The pool is what proves
        /// the difference — a stage that silently dropped a real descriptor
        /// would leave the ledger short, whatever its counters said.
        #[test]
        fn no_frame_the_stage_accepts_costs_the_pool_a_buffer(
            frames in prop::collection::vec(any_frame(), 1..40),
            forged in prop::collection::vec(any::<u32>(), 0..8),
        ) {
            let r = Regions::new();
            let mut owner = PoolOwner::attach(&r.returns);
            let mut rx_in = r.rings.rx.producer();
            let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
            let mut tx_out = r.rings.tx.consumer();
            let mut free_in = r.returns.free.producer();

            let mut published = 0usize;
            for frame in &frames {
                if receive(&r.pool, &mut owner, &mut rx_in, frame).is_some() {
                    published += 1;
                }
            }
            // Descriptors naming no buffer, interleaved after the real ones so
            // they cannot be dismissed as a prefix the stage never reached.
            for index in &forged {
                let _ = rx_in.try_enqueue(Descriptor::new(
                    index.saturating_add(POOL_BUFFERS as u32),
                    0,
                    64,
                    Verdict::Transmit,
                ));
            }

            // Fewer than the pool holds and far fewer than a ring, so nothing
            // here can be refused for want of room: what the stage does with a
            // descriptor is the only thing under test.
            let handed_on = stage.poll(running());
            let counters = stage.counters();
            prop_assert_eq!(counters.egress_full, 0);
            prop_assert_eq!(handed_on, published, "a real descriptor did not travel on");
            prop_assert_eq!(counters.malformed_descriptor, forged.len() as u64);

            // Every verdict is one of the two, and the tallies account for
            // every frame exactly once.
            let discarded = counters.drops.total()
                + counters.unparsable
                + counters.misrouted
                + counters.snapshot_failed
                + counters.writeback_failed;
            prop_assert_eq!(counters.forwarded + discarded, published as u64);

            // The tx driver takes them all and returns each buffer, whichever
            // verdict it carries; the pool must then be whole again.
            let returned = transmit(&r.pool, &mut tx_out, &mut free_in, |_, _| {});
            prop_assert_eq!(returned, published);
            prop_assert_eq!(owner.reclaim(), published);
            prop_assert_eq!(owner.owned(), POOL_BUFFERS);
            prop_assert_eq!(owner.counters(), PoolCounters::default());
        }

        /// A configuration exchanged between polls, over an arbitrary schedule
        /// of tables and an arbitrary traffic mix. At every boundary a commit
        /// falls on, the pool must be whole — nothing lost to the swap and
        /// nothing returned twice across it — and every frame a poll forwarded
        /// must carry the rewrite of the table *that* poll was handed, not a
        /// neighbouring generation's. A stage keeping a table of its own would
        /// answer with the previous generation's addresses here.
        #[test]
        fn swapping_configuration_between_polls_never_loses_a_buffer(
            schedule in prop::collection::vec((1u8..=9, any::<bool>()), 1..12),
            frames in prop::collection::vec(any_frame(), 1..8),
        ) {
            let r = Regions::new();
            let mut owner = PoolOwner::attach(&r.returns);
            let mut rx_in = r.rings.rx.producer();
            let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
            let mut tx_out = r.rings.tx.consumer();
            let mut free_in = r.returns.free.producer();

            for (tag, port0_up) in schedule {
                let (number, table) = generation(tag, port0_up);
                let mut published = 0usize;
                for frame in &frames {
                    if receive(&r.pool, &mut owner, &mut rx_in, frame).is_some() {
                        published += 1;
                    }
                }
                prop_assert_eq!(stage.poll(Configuration::new(number, &table)), published);
                prop_assert_eq!(stage.counters().generation, number);

                let (egress_mac, next_hop_mac) = generation_macs(tag);
                let mut rewritten = Vec::new();
                let returned = transmit(&r.pool, &mut tx_out, &mut free_in, |descriptor, bytes| {
                    if Verdict::from_bits(descriptor.verdict) == Some(Verdict::Transmit) {
                        rewritten.push((bytes[..6].to_vec(), bytes[6..12].to_vec()));
                    }
                });
                for (destination, source) in rewritten {
                    prop_assert_eq!(destination, next_hop_mac.0.to_vec());
                    prop_assert_eq!(source, egress_mac.0.to_vec());
                }
                prop_assert_eq!(returned, published);
                prop_assert_eq!(owner.reclaim(), published);
                prop_assert_eq!(owner.owned(), POOL_BUFFERS);
                prop_assert_eq!(owner.counters(), PoolCounters::default());
            }
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
            let descriptor = Descriptor::new(buffer, offset, len, Verdict::Transmit);
            // Reference in `usize`, which cannot overflow for two `u32`s on a
            // 64-bit host — the authority the checked-arithmetic implementation
            // must match exactly.
            let expected = (buffer as usize) < POOL_BUFFERS
                && (offset as usize) + (len as usize) <= BUFFER_SIZE;
            prop_assert_eq!(descriptor_in_bounds(&descriptor), expected);
        }
    }
}
