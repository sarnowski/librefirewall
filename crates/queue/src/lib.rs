//! Lock-free single-producer/single-consumer ring, the primitive the whole
//! dataplane moves descriptors over.
//!
//! # Two structures, not one
//!
//! [`SpscRing`] is the shared-memory image: two cursors and a slot array,
//! `#[repr(C)]` because it is mapped into two protection domains at once. It
//! carries no queue operations at all. Each side instead takes a handle —
//! [`SpscRing::producer`] on the enqueuing side, [`SpscRing::consumer`] on the
//! dequeuing side — and drives the ring through that handle for as long as the
//! domain uses it.
//!
//! A handle holds **this domain's own position** in private memory, which the
//! peer does not map and cannot write. The matching cursor inside the shared
//! image is a *publication* of that position for the peer's flow control, never
//! a value this side reads back. The only shared word a side ever reads is the
//! *peer's* cursor, and it is masked into `0..CAP` before it is used for
//! anything.
//!
//! Exactly one handle of each kind may exist per ring for the ring's lifetime.
//! A second handle would restart at position zero and re-walk slots the first
//! already used, so taking one is a protocol error — the same class of caller
//! contract as the one-producer/one-consumer rule itself, which the types
//! likewise cannot express because a shared region is reachable through a
//! shared reference by construction.
//!
//! # Why the position is private
//!
//! The peer maps the whole region read-write, both cursors included
//! (CONCEPT §7.1), so any value read back from there is attacker-controlled. A
//! side that re-read *its own* cursor from the shared image would hand the peer
//! two levers, and both are ownership bugs rather than mere corruption:
//!
//! * rewinding the consumer's cursor would make it deliver a descriptor it had
//!   already delivered, so one packet buffer would have two owners; and
//! * rewinding the producer's cursor would make it overwrite a slot the
//!   consumer had not yet read, losing a buffer that had already been handed
//!   over.
//!
//! With the position private, neither is reachable: **each side's position is a
//! function of that side's own history alone — it starts at zero and advances
//! exactly one slot per successful operation — and no peer write can move it.**
//! That is what makes "this side is the sole accessor of the slot at its own
//! position" a statement about local state rather than about peer cooperation.
//!
//! The position also needs no atomic ordering of its own: it is an ordinary
//! `u32` in domain-private memory that only this domain reads or writes, so
//! there is nothing to synchronise. Ordering is needed only for the two shared
//! cursors, where a release store publishes a position and the peer's acquire
//! load observes it, establishing happens-before for the slot access on either
//! side. On x86 those compile to plain loads and stores plus compiler fences,
//! so the hot path stays cheap.
//!
//! # Slots are atomic, so a byzantine write is defined behaviour
//!
//! A slot is a [`Descriptor`] laid out field for field as [`AtomicU32`]s, and
//! every slot access goes through those atomics. This is a soundness mechanism,
//! not an optimisation: the peer can write any slot at any moment, and a
//! non-atomic access racing with that write would be undefined behaviour in the
//! Rust abstract machine — which would let the compiler assume the memory
//! cannot change underneath it. Atomic accesses cannot race by definition, so
//! the worst a byzantine writer achieves is an unexpected *value*. That is why
//! this crate contains no `unsafe` at all (`#![forbid(unsafe_code)]`) and why
//! [`SpscRing`] is `Sync` by the ordinary auto-trait rules rather than by an
//! `unsafe impl` resting on a promise the API cannot keep.
//!
//! The slot accesses themselves are `Relaxed`, because all the ordering they
//! need comes from the release/acquire pair on the published cursor: the
//! producer's release store to `tail` orders its slot writes before the
//! consumer's acquire load of `tail`, and the consumer's release store to
//! `head` orders its slot reads before the producer's acquire load of `head`.
//!
//! # Ownership protocol
//!
//! A [`Descriptor`] in the ring names a packet buffer, and enqueuing it is how
//! the producing domain hands that buffer over: after a successful
//! [`RingProducer::try_enqueue`] the buffer belongs to the consuming domain,
//! and after a successful [`RingConsumer::try_dequeue`] it belongs to this one.
//! A rejected enqueue returns the descriptor in `Err`, so nothing was handed
//! over and the producer still owns the buffer.
//!
//! That hand-over is a *protocol* obligation, and this crate cannot enforce it.
//! [`Descriptor`] is `Copy`, so a successful enqueue leaves the producer
//! holding an identical value and nothing in the type system stops it enqueuing
//! the same buffer twice. A move-only token such as `packet_buffer::OwnedBuffer`
//! cannot close that gap here either: a descriptor in the ring is bytes on
//! shared memory that a peer domain writes, not a Rust value whose moves the
//! compiler can follow. What does catch a buffer handed over twice is the pool
//! owner's ledger — `packet_buffer::FreeList` accounts buffers by identity and
//! refuses to reclaim an index that is out of range or not outstanding. The
//! ring moves descriptors; it claims nothing beyond that.
//!
//! # Initialisation
//!
//! The shared region is zero-initialised, which is already a valid empty ring
//! ([`Descriptor::ZERO`] slots, both cursors zero), so no explicit setup step is
//! required. A handle likewise starts at position zero and never consults the
//! shared image to do so, so attaching depends on nothing the peer controls.
//! One slot is always left unused, which is what distinguishes a full ring from
//! an empty one without a separate flag.
//!
//! # What remains outside this crate's control
//!
//! The private position bounds what a hostile peer can do; it does not
//! eliminate it. Honestly stated, the residue is:
//!
//! * **Flow control is advisory.** The peer's published cursor is what gates
//!   whether an operation proceeds. A forged `head` can stall a producer
//!   indefinitely, or let it overwrite a slot the consumer has not read; a
//!   forged `tail` can present a consumer with up to [`SpscRing::capacity`]
//!   slots that were never published. Those slots are stale or zero — in
//!   bounds, never out of it — and each such phantom dequeue still costs the
//!   consumer one step of its own position, so no peer write makes a single
//!   slot deliver twice in a row.
//! * **Slot contents are untrusted input.** Because the atomics are per field,
//!   a peer writing a slot concurrently can yield a `Descriptor` whose three
//!   fields come from different writes. It is always a well-formed value and
//!   never undefined behaviour, and like any peer input it must be
//!   range-validated (`pd_runtime::descriptor_in_bounds`) before the span it
//!   names is touched.
//! * **Buffer ownership is not accounted here**, for the reason given above;
//!   `packet_buffer::FreeList` is where a duplicate or forged return is caught.
//! * **A one-sided restart desynchronises the ring.** A domain that restarts
//!   while its peer keeps running resumes at position zero with the peer
//!   somewhere else, after which descriptors are replayed or lost. Recovering
//!   from that means restarting the region and both domains together, which is
//!   a system-level question this crate cannot answer.
//! * **Unbounded drainage is the caller's to prevent.** A peer that keeps
//!   advancing `tail` keeps [`RingConsumer::try_dequeue`] returning `Some`, so
//!   a consumer loop must cap its own work — see [`RingConsumer::drain`].

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU32, Ordering};

use wire::Descriptor;

/// One ring slot: a [`Descriptor`] laid out field for field as atomics.
///
/// Per-field rather than a single wider atomic because a `Descriptor` is 12
/// bytes and no atomic of that width exists. The consequence — a concurrent
/// peer write can be observed as a mix of two descriptors — is a *value*
/// problem the consumer already validates for, not a soundness problem.
#[repr(C)]
struct Slot {
    buffer: AtomicU32,
    offset: AtomicU32,
    len: AtomicU32,
}

impl Slot {
    /// The image of [`Descriptor::ZERO`], and the state of a freshly zeroed
    /// shared region. A `const fn` rather than an associated constant because a
    /// constant holding atomics is copied at each use, which is a trap worth
    /// keeping out of the crate even where the array initialiser below would
    /// have been a correct use of one.
    const fn zero() -> Self {
        Self {
            buffer: AtomicU32::new(0),
            offset: AtomicU32::new(0),
            len: AtomicU32::new(0),
        }
    }

    /// `Relaxed` throughout: the release store to the publishing cursor that
    /// follows is what orders these writes for the peer.
    fn store(&self, descriptor: Descriptor) {
        self.buffer.store(descriptor.buffer, Ordering::Relaxed);
        self.offset.store(descriptor.offset, Ordering::Relaxed);
        self.len.store(descriptor.len, Ordering::Relaxed);
    }

    /// `Relaxed` throughout: the acquire load of the peer's cursor that
    /// precedes it is what makes the producer's writes visible here.
    fn load(&self) -> Descriptor {
        Descriptor::new(
            self.buffer.load(Ordering::Relaxed),
            self.offset.load(Ordering::Relaxed),
            self.len.load(Ordering::Relaxed),
        )
    }
}

/// The shared-memory image of a bounded lock-free SPSC ring of [`Descriptor`]s.
///
/// `CAP` is the number of slots and must be a power of two of at least 2; the
/// usable capacity is `CAP - 1`. The layout is `#[repr(C)]` because the ring is
/// aliased into two address spaces.
///
/// This type carries no queue operations. Take a [`producer`](Self::producer)
/// or a [`consumer`](Self::consumer) handle once and keep it — see the crate
/// header for why the position lives there and not here.
#[repr(C)]
pub struct SpscRing<const CAP: usize> {
    /// The consumer's published position. Written by the consumer's domain,
    /// read by the producer's as advisory flow control — never read back by the
    /// consumer.
    head: AtomicU32,
    /// The producer's published position, mirroring [`head`](Self::head).
    tail: AtomicU32,
    slots: [Slot; CAP],
}

// The ring is a cross-PD shared-memory ABI; pin its layout so a field reorder or
// size change becomes a compile error rather than a silent corruption of the
// mapping the peer PD reads.
const _: () = {
    assert!(core::mem::offset_of!(SpscRing<2>, head) == 0);
    assert!(core::mem::offset_of!(SpscRing<2>, tail) == 4);
    assert!(core::mem::offset_of!(SpscRing<2>, slots) == 8);
    assert!(core::mem::align_of::<SpscRing<2>>() == 4);
    assert!(core::mem::size_of::<SpscRing<2>>() == 8 + 2 * core::mem::size_of::<Descriptor>());
    // A slot is a `Descriptor` field for field, so expressing the slots as
    // atomics leaves the image the peer maps byte-identical. Without these the
    // switch could silently move the ABI.
    assert!(core::mem::size_of::<Slot>() == core::mem::size_of::<Descriptor>());
    assert!(core::mem::align_of::<Slot>() == core::mem::align_of::<Descriptor>());
    assert!(core::mem::offset_of!(Slot, buffer) == core::mem::offset_of!(Descriptor, buffer));
    assert!(core::mem::offset_of!(Slot, offset) == core::mem::offset_of!(Descriptor, offset));
    assert!(core::mem::offset_of!(Slot, len) == core::mem::offset_of!(Descriptor, len));
};

impl<const CAP: usize> SpscRing<CAP> {
    const MASK: u32 = {
        assert!(
            CAP.is_power_of_two(),
            "ring capacity must be a power of two"
        );
        assert!(CAP >= 2, "ring capacity must be at least 2");
        // `CAP - 1` rather than `CAP <= u32::MAX + 1`, whose right-hand side
        // overflows `usize` on a 32-bit target and replaces this message with a
        // const-eval overflow. `CAP >= 2` above makes the subtraction safe.
        assert!(
            CAP - 1 <= u32::MAX as usize,
            "ring capacity must fit a u32 cursor"
        );
        (CAP - 1) as u32
    };

    /// A new, empty ring. Const so it can initialise a shared region in place;
    /// note that a zeroed region is already a valid empty ring.
    #[must_use]
    pub const fn new() -> Self {
        let _ = Self::MASK;
        Self {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            slots: [const { Slot::zero() }; CAP],
        }
    }

    /// The number of descriptors the ring can hold at once.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        // `MASK` *is* the usable capacity, and naming it evaluates the capacity
        // invariants. A production ring is not constructed but cast from a
        // mapped region, so `new` cannot be relied on to force them; every way
        // into the ring names `MASK` for that reason, so an invalid `CAP` is a
        // build error whichever door the caller comes through.
        Self::MASK as usize
    }

    /// Take the enqueuing side's handle, positioned at the start of the ring.
    ///
    /// Call this once per ring and keep the handle for as long as the domain
    /// enqueues: the handle *is* this side's position, so a second one restarts
    /// at slot zero and re-walks slots the first already published to. The
    /// position starts at zero rather than at the shared cursor's value because
    /// that value is peer-controlled, and a zeroed region is by definition the
    /// ring's initial state.
    #[must_use]
    pub const fn producer(&self) -> RingProducer<'_, CAP> {
        let _ = Self::MASK;
        RingProducer {
            ring: self,
            tail: 0,
        }
    }

    /// Take the dequeuing side's handle, positioned at the start of the ring.
    /// The single-handle rule and the zero start of [`producer`](Self::producer)
    /// apply here too.
    #[must_use]
    pub const fn consumer(&self) -> RingConsumer<'_, CAP> {
        let _ = Self::MASK;
        RingConsumer {
            ring: self,
            head: 0,
        }
    }
}

impl<const CAP: usize> Default for SpscRing<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

/// The enqueuing side of a [`SpscRing`], holding this domain's publish position
/// in private memory.
///
/// See the crate header: the position advances exactly one slot per successful
/// enqueue and no peer write can move it.
pub struct RingProducer<'ring, const CAP: usize> {
    ring: &'ring SpscRing<CAP>,
    /// Where the next descriptor is written. Private to this domain, and always
    /// already masked into `0..CAP`, so it indexes `slots` directly; that is an
    /// internal invariant, and the slice index is its unconditional backstop.
    tail: u32,
}

impl<const CAP: usize> RingProducer<'_, CAP> {
    const MASK: u32 = SpscRing::<CAP>::MASK;

    /// The number of descriptors the ring can hold at once.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.ring.capacity()
    }

    /// The peer's published position, masked into range because it is
    /// attacker-controlled. Acquire so that the consumer's reads of a slot are
    /// ordered before this side overwrites it.
    fn peer_head(&self) -> u32 {
        self.ring.head.load(Ordering::Acquire) & Self::MASK
    }

    /// Enqueue one descriptor, handing the buffer it names to the consuming
    /// domain.
    ///
    /// # Errors
    /// Returns the descriptor unchanged in `Err` when the ring appears full, so
    /// the caller retains ownership of the buffer it names and can release or
    /// retry it. "Appears" is deliberate: fullness is judged against the peer's
    /// published cursor, which a hostile peer can forge in either direction —
    /// it can withhold a slot that is really free, or claim room in a slot the
    /// consumer has not read, in which case the unread descriptor is
    /// overwritten and the buffer it named is lost to the pool ledger.
    pub fn try_enqueue(&mut self, descriptor: Descriptor) -> Result<(), Descriptor> {
        let next = self.tail.wrapping_add(1) & Self::MASK;
        if next == self.peer_head() {
            return Err(descriptor);
        }
        self.ring.slots[self.tail as usize].store(descriptor);
        self.tail = next;
        self.ring.tail.store(next, Ordering::Release);
        Ok(())
    }

    /// A best-effort instantaneous estimate of how many descriptors are queued.
    ///
    /// Only the first operand is this side's own position; the other is the
    /// peer's published cursor, so the answer is a snapshot of a value that may
    /// already have changed, and under a hostile peer it is an arbitrary number
    /// in `0..=capacity()`. Never use it to size a following batch — the ring
    /// may hold fewer descriptors by then, or the peer may simply have lied.
    /// Drive enqueues from the `Result` of [`try_enqueue`](Self::try_enqueue)
    /// instead.
    #[must_use]
    pub fn len(&self) -> usize {
        (self.tail.wrapping_sub(self.peer_head()) & Self::MASK) as usize
    }

    /// Whether [`len`](Self::len) is zero, and exactly as best-effort as it is —
    /// the two are defined against the same snapshot so they can never
    /// contradict each other.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The dequeuing side of a [`SpscRing`], holding this domain's consume position
/// in private memory.
///
/// See the crate header: the position advances exactly one slot per successful
/// dequeue and no peer write can move it, which is what stops a rewound peer
/// cursor from delivering the same descriptor twice.
pub struct RingConsumer<'ring, const CAP: usize> {
    ring: &'ring SpscRing<CAP>,
    /// Where the next descriptor is read from. Private to this domain, and
    /// always already masked into `0..CAP`; see [`RingProducer::tail`].
    head: u32,
}

impl<'ring, const CAP: usize> RingConsumer<'ring, CAP> {
    const MASK: u32 = SpscRing::<CAP>::MASK;

    /// The number of descriptors the ring can hold at once.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.ring.capacity()
    }

    /// The peer's published position, masked into range because it is
    /// attacker-controlled. Acquire so that the producer's slot writes are
    /// visible before this side reads them.
    fn peer_tail(&self) -> u32 {
        self.ring.tail.load(Ordering::Acquire) & Self::MASK
    }

    /// Dequeue one descriptor, taking ownership of the buffer it names.
    ///
    /// `None` means only that nothing is queued *at this instant*, judged
    /// against the peer's published cursor; it is not a durable state, and a
    /// later call may well return `Some`.
    ///
    /// A returned descriptor is untrusted input. The producing domain may be
    /// byzantine, so it may name any buffer, any span, or a slot that was never
    /// published — range-validate it (`pd_runtime::descriptor_in_bounds`) before
    /// touching the span, and remember that the pool ledger, not this ring, is
    /// what decides whether the buffer was really the peer's to hand over.
    pub fn try_dequeue(&mut self) -> Option<Descriptor> {
        if self.head == self.peer_tail() {
            return None;
        }
        let descriptor = self.ring.slots[self.head as usize].load();
        self.head = self.head.wrapping_add(1) & Self::MASK;
        self.ring.head.store(self.head, Ordering::Release);
        Some(descriptor)
    }

    /// Dequeue at most `limit` descriptors, as an iterator that also stops early
    /// once the ring appears empty.
    ///
    /// This is the bounded form every consumer loop should use. Draining with
    /// `while let Some(..)` is unbounded work driven by an untrusted peer: a
    /// producer that keeps advancing its published cursor keeps
    /// [`try_dequeue`](Self::try_dequeue) returning `Some`, so such a loop never
    /// returns and the domain stops making progress on anything else. The cap
    /// belongs to the caller because only the caller knows its own budget per
    /// scheduling round; [`len`](Self::len) must not supply it, being a peer-
    /// influenced estimate.
    #[must_use = "a drain iterator dequeues nothing until it is consumed"]
    pub fn drain(&mut self, limit: usize) -> Drain<'_, 'ring, CAP> {
        Drain {
            consumer: self,
            remaining: limit,
        }
    }

    /// A best-effort instantaneous estimate of how many descriptors are queued;
    /// as best-effort as [`RingProducer::len`], and bounded the same way.
    #[must_use]
    pub fn len(&self) -> usize {
        (self.peer_tail().wrapping_sub(self.head) & Self::MASK) as usize
    }

    /// Whether [`len`](Self::len) is zero, defined against the same snapshot so
    /// the two can never contradict each other.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A bounded dequeue iterator over a [`RingConsumer`], created by
/// [`RingConsumer::drain`].
///
/// Yields at most the `limit` it was created with, and stops early the first
/// time the ring appears empty. Dropping it early leaves the remaining
/// descriptors queued.
pub struct Drain<'consumer, 'ring, const CAP: usize> {
    consumer: &'consumer mut RingConsumer<'ring, CAP>,
    remaining: usize,
}

impl<const CAP: usize> Iterator for Drain<'_, '_, CAP> {
    type Item = Descriptor;

    fn next(&mut self) -> Option<Descriptor> {
        if self.remaining == 0 {
            return None;
        }
        let descriptor = self.consumer.try_dequeue()?;
        self.remaining -= 1;
        Some(descriptor)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // The upper bound is the whole guarantee: a caller can rely on the
        // iteration being finite whatever the peer does.
        (0, Some(self.remaining))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::{BTreeSet, VecDeque};
    use std::sync::atomic::AtomicBool;
    use std::thread;
    use std::vec::Vec;

    /// A descriptor whose three fields all carry `value`, so a dequeued
    /// descriptor identifies which enqueue produced it.
    fn tagged(value: u32) -> Descriptor {
        Descriptor::new(value, value, value)
    }

    #[test]
    fn a_zeroed_slot_reads_as_the_zero_descriptor() {
        // What the header's "a zeroed region is already a valid empty ring"
        // rests on: an untouched slot reads back as `Descriptor::ZERO`, so
        // expressing the slots as per-field atomics did not put some other bit
        // pattern in the image the peer maps.
        assert_eq!(Slot::zero().load(), Descriptor::ZERO);
        let ring = SpscRing::<4>::new();
        assert_eq!(ring.slots[0].load(), Descriptor::ZERO);
    }

    #[test]
    fn a_defaulted_ring_is_an_empty_ring() {
        let ring = SpscRing::<4>::default();
        let mut producer = ring.producer();
        let mut consumer = ring.consumer();
        assert!(consumer.is_empty());
        assert_eq!(consumer.try_dequeue(), None);
        producer.try_enqueue(tagged(9)).unwrap();
        assert_eq!(consumer.try_dequeue(), Some(tagged(9)));
    }

    #[test]
    fn empty_ring_dequeues_nothing() {
        let ring = SpscRing::<8>::new();
        let mut consumer = ring.consumer();
        assert!(consumer.is_empty());
        assert_eq!(consumer.len(), 0);
        assert_eq!(consumer.try_dequeue(), None);
    }

    #[test]
    fn minimum_ring_holds_exactly_one() {
        // CAP == 2 is the edge where full and empty are one slot apart.
        let ring = SpscRing::<2>::new();
        let mut producer = ring.producer();
        let mut consumer = ring.consumer();
        assert_eq!(ring.capacity(), 1);
        assert_eq!(producer.capacity(), 1);
        assert_eq!(consumer.capacity(), 1);
        assert!(producer.try_enqueue(tagged(1)).is_ok());
        assert_eq!(producer.len(), 1);
        assert_eq!(producer.try_enqueue(tagged(4)), Err(tagged(4)));
        assert_eq!(consumer.try_dequeue(), Some(tagged(1)));
        assert_eq!(consumer.try_dequeue(), None);
    }

    #[test]
    fn fills_to_capacity_then_reports_full() {
        let ring = SpscRing::<8>::new();
        let mut producer = ring.producer();
        assert_eq!(producer.capacity(), 7);
        for i in 0..7 {
            assert!(producer.try_enqueue(Descriptor::new(i, 0, i)).is_ok());
        }
        assert_eq!(producer.len(), 7);
        // The eighth enqueue must fail and hand the descriptor back.
        assert_eq!(
            producer.try_enqueue(Descriptor::new(99, 0, 99)),
            Err(Descriptor::new(99, 0, 99))
        );
    }

    #[test]
    fn fifo_order_is_preserved() {
        let ring = SpscRing::<8>::new();
        let mut producer = ring.producer();
        let mut consumer = ring.consumer();
        for i in 0..5 {
            producer.try_enqueue(tagged(i)).unwrap();
        }
        for i in 0..5 {
            assert_eq!(consumer.try_dequeue(), Some(tagged(i)));
        }
        assert!(consumer.is_empty());
    }

    #[test]
    fn wraps_around_the_slot_array_repeatedly() {
        let ring = SpscRing::<4>::new();
        let mut producer = ring.producer();
        let mut consumer = ring.consumer();
        // Usable capacity 3; push/pop far more than CAP so both positions wrap
        // the underlying array many times.
        for i in 0..1000 {
            producer.try_enqueue(tagged(i)).unwrap();
            assert_eq!(consumer.try_dequeue(), Some(tagged(i)));
            assert!(consumer.is_empty());
        }
    }

    #[test]
    fn full_empty_transitions_hold_across_wrap() {
        let ring = SpscRing::<4>::new();
        let mut producer = ring.producer();
        let mut consumer = ring.consumer();
        for round in 0..50 {
            for i in 0..3 {
                producer.try_enqueue(tagged(round * 3 + i)).unwrap();
            }
            assert!(producer.try_enqueue(Descriptor::ZERO).is_err());
            assert_eq!(producer.len(), 3);
            assert_eq!(consumer.len(), 3);
            for i in 0..3 {
                assert_eq!(consumer.try_dequeue(), Some(tagged(round * 3 + i)));
            }
            assert_eq!(consumer.try_dequeue(), None);
        }
    }

    #[test]
    fn hostile_peer_cursor_never_indexes_out_of_bounds() {
        // The peer shares write access to both cursors. Garbage values must be
        // masked into range, never panic or index past the slot array.
        let ring = SpscRing::<8>::new();
        let mut producer = ring.producer();
        let mut consumer = ring.consumer();
        ring.tail.store(u32::MAX, Ordering::Relaxed);
        let _ = producer.try_enqueue(tagged(1));
        ring.head.store(u32::MAX, Ordering::Relaxed);
        let _ = consumer.try_dequeue();
        // Both estimates stay bounded by the mask regardless of cursor values.
        assert!(producer.len() <= producer.capacity());
        assert!(consumer.len() <= consumer.capacity());
    }

    #[test]
    fn is_empty_and_len_never_contradict_each_other_under_a_hostile_cursor() {
        // The regression: while `is_empty` compared cursors raw and `len` masked
        // them, head == 8 with tail == 0 on a CAP == 8 ring reported a non-empty
        // ring of length zero, and drove phantom dequeues of stale slots.
        let ring = SpscRing::<8>::new();
        let consumer = ring.consumer();
        let producer = ring.producer();
        for (head, tail) in [(8u32, 0u32), (0, 8), (u32::MAX, 0), (16, 24), (7, 7)] {
            ring.head.store(head, Ordering::Relaxed);
            ring.tail.store(tail, Ordering::Relaxed);
            // Through locals: the agreement between the two predicates is what
            // is under test, and comparing `len()` inline would let a lint fold
            // the comparison back into `is_empty()` and make it tautological.
            let (consumer_len, producer_len) = (consumer.len(), producer.len());
            assert_eq!(consumer.is_empty(), consumer_len == 0);
            assert_eq!(producer.is_empty(), producer_len == 0);
            assert!(consumer_len <= consumer.capacity());
            assert!(producer_len <= producer.capacity());
        }
    }

    #[test]
    fn a_rewound_peer_cursor_between_dequeues_never_redelivers() {
        // The consumer's position is private, so a peer rewinding the shared
        // `head` cannot make an already-delivered descriptor come back and give
        // one packet buffer two owners.
        let ring = SpscRing::<8>::new();
        let mut producer = ring.producer();
        let mut consumer = ring.consumer();
        for i in 0..4 {
            producer.try_enqueue(tagged(i)).unwrap();
        }
        assert_eq!(consumer.try_dequeue(), Some(tagged(0)));
        // The peer rewinds the cursor this side publishes for it.
        ring.head.store(0, Ordering::Relaxed);
        assert_eq!(consumer.try_dequeue(), Some(tagged(1)));
        ring.head.store(0, Ordering::Relaxed);
        assert_eq!(consumer.try_dequeue(), Some(tagged(2)));
        assert_eq!(consumer.try_dequeue(), Some(tagged(3)));
        assert_eq!(consumer.try_dequeue(), None);
    }

    #[test]
    fn a_rewound_peer_cursor_between_enqueues_never_overwrites_a_published_slot() {
        // The producer mirror: rewinding the shared `tail` must not move where
        // the next descriptor is written, which would clobber a slot already
        // handed to the consumer.
        let ring = SpscRing::<8>::new();
        let mut producer = ring.producer();
        let mut consumer = ring.consumer();
        producer.try_enqueue(tagged(0)).unwrap();
        ring.tail.store(0, Ordering::Relaxed);
        producer.try_enqueue(tagged(1)).unwrap();
        ring.tail.store(1, Ordering::Relaxed);
        producer.try_enqueue(tagged(2)).unwrap();
        // Every descriptor landed in its own slot and survived intact.
        ring.tail.store(3, Ordering::Relaxed);
        assert_eq!(consumer.try_dequeue(), Some(tagged(0)));
        assert_eq!(consumer.try_dequeue(), Some(tagged(1)));
        assert_eq!(consumer.try_dequeue(), Some(tagged(2)));
    }

    #[test]
    fn a_peer_restart_mid_stream_does_not_redeliver_or_panic() {
        // The scenario the crate header names: the peer crashes and restarts,
        // re-zeroing the shared cursors while descriptors are in flight. Both
        // positions are private, so neither side is rewound; the ring stays in
        // bounds and the consumer carries on from where it was.
        let ring = SpscRing::<8>::new();
        let mut producer = ring.producer();
        let mut consumer = ring.consumer();
        for i in 0..5 {
            producer.try_enqueue(tagged(i)).unwrap();
        }
        assert_eq!(consumer.try_dequeue(), Some(tagged(0)));
        assert_eq!(consumer.try_dequeue(), Some(tagged(1)));

        ring.head.store(0, Ordering::Relaxed);
        ring.tail.store(0, Ordering::Relaxed);

        // Not tagged(1) again: the consumer resumes at its own position.
        let next = consumer.drain(consumer.capacity()).next();
        assert_ne!(next, Some(tagged(1)));
        assert_eq!(next, Some(tagged(2)));
        // Whatever the peer does next, the ring stays bounded and usable.
        assert!(consumer.len() <= consumer.capacity());
        assert!(producer.try_enqueue(tagged(99)).is_ok());
    }

    #[test]
    fn drain_stops_at_its_limit() {
        let ring = SpscRing::<8>::new();
        let mut producer = ring.producer();
        let mut consumer = ring.consumer();
        for i in 0..7 {
            producer.try_enqueue(tagged(i)).unwrap();
        }
        let taken: Vec<Descriptor> = consumer.drain(3).collect();
        assert_eq!(taken, std::vec![tagged(0), tagged(1), tagged(2)]);
        // The rest stayed queued.
        assert_eq!(consumer.len(), 4);
        assert_eq!(consumer.drain(100).count(), 4);
    }

    #[test]
    fn drain_stops_early_on_an_empty_ring_and_reports_its_bound() {
        let ring = SpscRing::<8>::new();
        let mut producer = ring.producer();
        let mut consumer = ring.consumer();
        producer.try_enqueue(tagged(1)).unwrap();
        let mut drain = consumer.drain(5);
        assert_eq!(drain.size_hint(), (0, Some(5)));
        assert_eq!(drain.next(), Some(tagged(1)));
        assert_eq!(drain.size_hint(), (0, Some(4)));
        assert_eq!(drain.next(), None);
        assert_eq!(consumer.drain(0).count(), 0);
    }

    #[test]
    fn drain_bounds_a_peer_that_keeps_the_ring_looking_non_empty() {
        // Nothing was ever enqueued, but a forged `tail` makes the ring look
        // full. An unbounded `while let Some(..)` would keep taking phantom
        // descriptors as the peer advances the cursor; `drain` cannot.
        let ring = SpscRing::<8>::new();
        let mut consumer = ring.consumer();
        for round in 0..10u32 {
            ring.tail
                .store(round.wrapping_mul(7).wrapping_add(3), Ordering::Relaxed);
            assert!(consumer.drain(2).count() <= 2);
        }
    }

    #[test]
    fn concurrent_producer_and_consumer_transfer_every_item_in_order() {
        // The real two-PD scenario: one thread enqueues, another dequeues,
        // through a ring far smaller than the message count so it repeatedly
        // fills, empties, and wraps under genuine contention.
        const COUNT: u32 = 200_000;
        let ring = SpscRing::<64>::new();

        thread::scope(|scope| {
            scope.spawn(|| {
                let mut producer = ring.producer();
                let mut i = 0;
                while i < COUNT {
                    if producer.try_enqueue(tagged(i)).is_ok() {
                        i += 1;
                    } else {
                        std::hint::spin_loop();
                    }
                }
            });
            scope.spawn(|| {
                let mut consumer = ring.consumer();
                let mut expected = 0;
                while expected < COUNT {
                    match consumer.try_dequeue() {
                        Some(descriptor) => {
                            assert_eq!(descriptor, tagged(expected));
                            expected += 1;
                        }
                        None => std::hint::spin_loop(),
                    }
                }
            });
        });
    }

    #[test]
    fn a_thread_scribbling_cursors_and_slots_cannot_break_either_side() {
        // The byzantine peer as it really is: a third thread rewriting both
        // shared cursors and the slot array while the producer and consumer run.
        // Nothing may panic, index out of bounds, or fail to terminate, and both
        // estimates must stay within capacity throughout. Payload equality is
        // deliberately not asserted — a peer writing slots can change what is
        // read, and that is a value problem the consumer validates for.
        const ROUNDS: u32 = 50_000;
        const CAP: usize = 16;
        let ring = SpscRing::<CAP>::new();
        let stop = AtomicBool::new(false);

        thread::scope(|scope| {
            let producer = scope.spawn(|| {
                let mut producer = ring.producer();
                for i in 0..ROUNDS {
                    let _ = producer.try_enqueue(tagged(i));
                    assert!(producer.len() <= producer.capacity());
                }
            });
            let consumer = scope.spawn(|| {
                let mut consumer = ring.consumer();
                let mut seen = 0usize;
                for _ in 0..ROUNDS {
                    seen += consumer.drain(4).count();
                    assert!(consumer.len() <= consumer.capacity());
                }
                // The bound held: four per round, never more.
                assert!(seen <= 4 * ROUNDS as usize);
            });
            let scribbler = scope.spawn(|| {
                let mut seed = 0x1234_5678u32;
                while !stop.load(Ordering::Relaxed) {
                    seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    ring.head.store(seed, Ordering::Relaxed);
                    ring.tail.store(seed.rotate_left(13), Ordering::Relaxed);
                    ring.slots[(seed as usize) % CAP].store(tagged(seed));
                }
            });

            producer.join().unwrap();
            consumer.join().unwrap();
            stop.store(true, Ordering::Relaxed);
            scribbler.join().unwrap();
        });
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Random interleavings of `try_enqueue`/`try_dequeue` against a model
        /// FIFO queue: every dequeue returns exactly what the model expects
        /// (FIFO order preserved), a rejected enqueue means the ring is at
        /// capacity, and both sides' estimates agree with the model.
        #[test]
        fn spsc_ring_matches_a_model_fifo(ops in prop::collection::vec(any::<bool>(), 0..300)) {
            const CAP: usize = 8;
            let ring = SpscRing::<CAP>::new();
            let mut producer = ring.producer();
            let mut consumer = ring.consumer();
            let mut model: VecDeque<u32> = VecDeque::new();
            let mut next: u32 = 0;

            for enqueue in ops {
                if enqueue {
                    match producer.try_enqueue(tagged(next)) {
                        Ok(()) => {
                            model.push_back(next);
                            next = next.wrapping_add(1);
                        }
                        Err(returned) => {
                            // A rejection hands the descriptor back unchanged and
                            // happens only when the ring is at usable capacity.
                            prop_assert_eq!(returned, tagged(next));
                            prop_assert_eq!(model.len(), producer.capacity());
                        }
                    }
                } else {
                    let expected = model.pop_front().map(tagged);
                    prop_assert_eq!(consumer.try_dequeue(), expected);
                }
                prop_assert_eq!(producer.len(), model.len());
                prop_assert_eq!(consumer.len(), model.len());
                prop_assert!(producer.len() <= producer.capacity());
            }
        }

        /// The invariant the ring exists to protect, stated directly rather than
        /// through FIFO equality: with distinct descriptors enqueued, what comes
        /// out is a *duplicate-free prefix* of what went in. No descriptor is
        /// delivered twice (which would give one buffer two owners), none is
        /// skipped, and none is invented.
        #[test]
        fn dequeues_are_a_duplicate_free_prefix_of_the_enqueues(
            ops in prop::collection::vec(any::<bool>(), 0..300),
        ) {
            let ring = SpscRing::<8>::new();
            let mut producer = ring.producer();
            let mut consumer = ring.consumer();
            let mut enqueued: Vec<u32> = Vec::new();
            let mut dequeued: Vec<u32> = Vec::new();
            let mut next: u32 = 0;

            for enqueue in ops {
                if enqueue {
                    if producer.try_enqueue(tagged(next)).is_ok() {
                        enqueued.push(next);
                        next += 1;
                    }
                } else if let Some(descriptor) = consumer.try_dequeue() {
                    prop_assert_eq!(descriptor, tagged(descriptor.buffer));
                    dequeued.push(descriptor.buffer);
                }
            }

            let unique: BTreeSet<u32> = dequeued.iter().copied().collect();
            prop_assert_eq!(unique.len(), dequeued.len(), "a descriptor was delivered twice");
            prop_assert!(dequeued.len() <= enqueued.len());
            prop_assert_eq!(&dequeued[..], &enqueued[..dequeued.len()]);
        }

        /// The same run with a hostile peer scribbling both shared cursors, and
        /// what the guarantee degrades to. Ordering and completeness are gone:
        /// a forged cursor can hide published descriptors or present slots that
        /// were never published. What survives is that nothing is *invented* —
        /// every descriptor read out is a value some enqueue wrote, or the zero
        /// of an untouched slot — and every operation stays in bounds.
        #[test]
        fn adversarial_cursors_degrade_to_stale_values_never_invented_ones(
            ops in prop::collection::vec((any::<bool>(), any::<u32>(), any::<bool>()), 0..300),
        ) {
            let ring = SpscRing::<8>::new();
            let mut producer = ring.producer();
            let mut consumer = ring.consumer();
            let mut written: BTreeSet<u32> = BTreeSet::new();
            written.insert(0); // an untouched slot reads as `Descriptor::ZERO`
            let mut next: u32 = 1;

            for (enqueue, forged, forge_head) in ops {
                // The peer scribbles whichever cursor it does not own the
                // publication of, before the operation runs.
                if forge_head {
                    ring.head.store(forged, Ordering::Relaxed);
                } else {
                    ring.tail.store(forged, Ordering::Relaxed);
                }
                if enqueue {
                    if producer.try_enqueue(tagged(next)).is_ok() {
                        written.insert(next);
                        next += 1;
                    }
                } else if let Some(descriptor) = consumer.try_dequeue() {
                    prop_assert!(
                        written.contains(&descriptor.buffer),
                        "a descriptor no enqueue ever wrote came out of the ring"
                    );
                    prop_assert_eq!(descriptor, tagged(descriptor.buffer));
                }
                prop_assert!(producer.len() <= producer.capacity());
                let consumer_len = consumer.len();
                prop_assert!(consumer_len <= consumer.capacity());
                prop_assert_eq!(consumer.is_empty(), consumer_len == 0);
            }
        }

        /// A hostile peer may scribble either shared cursor with an arbitrary
        /// value. Masking must keep every operation in bounds: no panic, no
        /// out-of-range index, and both estimates stay within capacity.
        #[test]
        fn spsc_ring_survives_arbitrary_cursor_values(
            head in any::<u32>(),
            tail in any::<u32>(),
            enqueue_first in any::<bool>(),
            limit in 0usize..16,
        ) {
            let ring = SpscRing::<8>::new();
            let mut producer = ring.producer();
            let mut consumer = ring.consumer();
            ring.head.store(head, Ordering::Relaxed);
            ring.tail.store(tail, Ordering::Relaxed);
            // Exercise every operation regardless of the garbage cursors.
            if enqueue_first {
                let _ = producer.try_enqueue(tagged(1));
                let _ = consumer.try_dequeue();
            } else {
                let _ = consumer.try_dequeue();
                let _ = producer.try_enqueue(tagged(1));
            }
            prop_assert!(consumer.drain(limit).count() <= limit);
            let producer_len = producer.len();
            prop_assert!(producer_len <= producer.capacity());
            prop_assert!(consumer.len() <= consumer.capacity());
            prop_assert_eq!(producer.is_empty(), producer_len == 0);
        }
    }
}
