//! Lock-free single-producer/single-consumer ring, the primitive the whole
//! dataplane moves descriptors over.
//!
//! # Ownership protocol
//!
//! A [`Descriptor`] in the ring names a packet buffer, and enqueuing it
//! **transfers ownership** of that buffer to the consumer; a rejected enqueue
//! ([`SpscRing::try_enqueue`] returning `Err`) hands ownership back to the
//! producer. The ring moves descriptors, not bytes — the buffers themselves
//! live in `packet-buffer`.
//!
//! # Concurrency
//!
//! The ring lives in memory shared between two protection domains. Exactly one
//! domain enqueues (the producer) and exactly one dequeues (the consumer); this
//! is a contract the caller upholds, not something the types enforce. One slot
//! is always left unused so a full ring is distinguishable from an empty one
//! without a separate flag. Correctness rests on a release/acquire handshake on
//! the two cursors: the producer publishes a slot by releasing `tail`, the
//! consumer observes it by acquiring `tail` (establishing happens-before for the
//! slot write), and the mirror holds for `head`. On x86 these compile to plain
//! loads/stores plus compiler fences, so the hot path stays cheap.
//!
//! # Initialisation and peer trust
//!
//! The shared region is zero-initialised, which is already a valid empty ring
//! ([`Descriptor::ZERO`] slots, `head == tail == 0`), so no explicit setup step
//! is required. The peer shares write access to the whole region, including the
//! cursors, so it is treated as untrusted: every cursor read back from shared
//! memory is masked into range before it indexes the slot array, so a peer that
//! writes a garbage cursor cannot drive this side out of bounds or into an
//! arithmetic panic. A peer that restarts and re-zeroes its cursor is seen as an
//! empty (or not-full) ring, never as a memory-safety violation. The one thing a
//! hostile peer can still cause — reordered or dropped descriptors — is a
//! protocol error for the owning PD to detect through buffer-ownership
//! accounting, not a soundness problem of the ring.

#![cfg_attr(not(test), no_std)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

use wire::Descriptor;

/// A bounded lock-free SPSC ring of [`Descriptor`]s.
///
/// `CAP` is the number of slots and must be a power of two of at least 2; the
/// usable capacity is `CAP - 1`. The layout is `#[repr(C)]` because the ring is
/// aliased into two address spaces.
#[repr(C)]
pub struct SpscRing<const CAP: usize> {
    /// Dequeue cursor, owned by the consumer, read by the producer to spot a
    /// full ring.
    head: AtomicU32,
    /// Enqueue cursor, owned by the producer, read by the consumer to spot an
    /// empty ring.
    tail: AtomicU32,
    slots: [UnsafeCell<Descriptor>; CAP],
}

// SAFETY: the head/tail release/acquire handshake gives each slot a single
// accessor at a time — the producer writes a slot only before publishing it via
// `tail`, and the consumer reads it only after acquiring `tail` and before
// releasing it via `head` — so the `UnsafeCell` slots are never accessed
// concurrently for the same index despite the shared `&SpscRing`.
unsafe impl<const CAP: usize> Sync for SpscRing<CAP> {}

// The ring is a cross-PD shared-memory ABI; pin its layout so a field reorder or
// size change becomes a compile error rather than a silent corruption of the
// mapping the peer PD reads.
const _: () = {
    assert!(core::mem::offset_of!(SpscRing<2>, head) == 0);
    assert!(core::mem::offset_of!(SpscRing<2>, tail) == 4);
    assert!(core::mem::offset_of!(SpscRing<2>, slots) == 8);
    assert!(core::mem::align_of::<SpscRing<2>>() == 4);
    assert!(core::mem::size_of::<SpscRing<2>>() == 8 + 2 * core::mem::size_of::<Descriptor>());
};

impl<const CAP: usize> SpscRing<CAP> {
    const MASK: u32 = {
        assert!(
            CAP.is_power_of_two(),
            "ring capacity must be a power of two"
        );
        assert!(CAP >= 2, "ring capacity must be at least 2");
        assert!(
            CAP <= (u32::MAX as usize) + 1,
            "ring capacity must fit a u32 cursor"
        );
        (CAP - 1) as u32
    };

    /// A new, empty ring. Const so it can initialise a shared region in place;
    /// note that a zeroed region is already a valid empty ring.
    #[must_use]
    pub const fn new() -> Self {
        // Force the capacity invariants (`MASK`) to be evaluated even for a ring
        // that is only ever constructed, never enqueued to, so an invalid `CAP`
        // fails at construction rather than at first use.
        let _ = Self::MASK;
        Self {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            slots: [const { UnsafeCell::new(Descriptor::ZERO) }; CAP],
        }
    }

    /// The number of descriptors the ring can hold at once.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        CAP - 1
    }

    /// Enqueue one descriptor. Producer side only.
    ///
    /// Returns the descriptor back in `Err` when the ring is full, so the
    /// caller retains ownership of the buffer it names.
    pub fn try_enqueue(&self, descriptor: Descriptor) -> Result<(), Descriptor> {
        let tail = self.tail.load(Ordering::Relaxed);
        let next = tail.wrapping_add(1) & Self::MASK;
        if next == self.head.load(Ordering::Acquire) {
            return Err(descriptor);
        }
        // SAFETY: `tail` is masked into range before indexing, so the access is
        // in bounds even if a hostile peer scribbled the shared cursor. This
        // slot sits at `tail`, which the consumer cannot observe until the
        // release store below, so the producer is its sole accessor.
        unsafe {
            self.slots[(tail & Self::MASK) as usize]
                .get()
                .write(descriptor)
        };
        self.tail.store(next, Ordering::Release);
        Ok(())
    }

    /// Dequeue one descriptor. Consumer side only.
    pub fn try_dequeue(&self) -> Option<Descriptor> {
        let head = self.head.load(Ordering::Relaxed);
        if head == self.tail.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: `head` is masked into range before indexing, so the access is
        // in bounds even under a hostile peer cursor. The producer published
        // this slot with a release store to `tail` that our acquire load
        // synchronised with, so the write is visible; and it will not reuse the
        // slot until we advance `head` below, so we are its sole accessor.
        let descriptor = unsafe { self.slots[(head & Self::MASK) as usize].get().read() };
        self.head
            .store(head.wrapping_add(1) & Self::MASK, Ordering::Release);
        Some(descriptor)
    }

    /// Whether the ring currently holds no descriptors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
    }

    /// The number of descriptors currently queued.
    #[must_use]
    pub fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        (tail.wrapping_sub(head) & Self::MASK) as usize
    }
}

impl<const CAP: usize> Default for SpscRing<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn empty_ring_dequeues_nothing() {
        let ring = SpscRing::<8>::new();
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.try_dequeue(), None);
    }

    #[test]
    fn minimum_ring_holds_exactly_one() {
        // CAP == 2 is the edge where full and empty are one slot apart.
        let ring = SpscRing::<2>::new();
        assert_eq!(ring.capacity(), 1);
        assert!(ring.try_enqueue(Descriptor::new(1, 2, 3)).is_ok());
        assert_eq!(ring.len(), 1);
        assert_eq!(
            ring.try_enqueue(Descriptor::new(4, 5, 6)),
            Err(Descriptor::new(4, 5, 6))
        );
        assert_eq!(ring.try_dequeue(), Some(Descriptor::new(1, 2, 3)));
        assert_eq!(ring.try_dequeue(), None);
    }

    #[test]
    fn fills_to_capacity_then_reports_full() {
        let ring = SpscRing::<8>::new();
        assert_eq!(ring.capacity(), 7);
        for i in 0..7 {
            assert!(ring.try_enqueue(Descriptor::new(i, 0, i)).is_ok());
        }
        assert_eq!(ring.len(), 7);
        // The eighth enqueue must fail and hand the descriptor back.
        let rejected = ring.try_enqueue(Descriptor::new(99, 0, 99));
        assert_eq!(rejected, Err(Descriptor::new(99, 0, 99)));
    }

    #[test]
    fn fifo_order_is_preserved() {
        let ring = SpscRing::<8>::new();
        for i in 0..5 {
            ring.try_enqueue(Descriptor::new(i, 0, 0)).unwrap();
        }
        for i in 0..5 {
            assert_eq!(ring.try_dequeue(), Some(Descriptor::new(i, 0, 0)));
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn wraps_around_the_slot_array_repeatedly() {
        let ring = SpscRing::<4>::new();
        // Usable capacity 3; push/pop far more than CAP so head and tail wrap
        // the underlying array many times.
        for i in 0..1000 {
            ring.try_enqueue(Descriptor::new(i, i, i)).unwrap();
            assert_eq!(ring.try_dequeue(), Some(Descriptor::new(i, i, i)));
            assert!(ring.is_empty());
        }
    }

    #[test]
    fn full_empty_transitions_hold_across_wrap() {
        let ring = SpscRing::<4>::new();
        for round in 0..50 {
            for i in 0..3 {
                ring.try_enqueue(Descriptor::new(round * 3 + i, 0, 0))
                    .unwrap();
            }
            assert!(ring.try_enqueue(Descriptor::ZERO).is_err());
            assert_eq!(ring.len(), 3);
            for i in 0..3 {
                assert_eq!(
                    ring.try_dequeue(),
                    Some(Descriptor::new(round * 3 + i, 0, 0))
                );
            }
            assert_eq!(ring.try_dequeue(), None);
        }
    }

    #[test]
    fn hostile_peer_cursor_never_indexes_out_of_bounds() {
        // The peer shares write access to both cursors. Garbage values must be
        // masked into range, never panic or index past the slot array.
        let ring = SpscRing::<8>::new();
        ring.tail.store(u32::MAX, Ordering::Relaxed);
        let _ = ring.try_enqueue(Descriptor::new(1, 1, 1));
        ring.head.store(u32::MAX, Ordering::Relaxed);
        let _ = ring.try_dequeue();
        // len() is likewise bounded by the mask regardless of cursor values.
        assert!(ring.len() <= ring.capacity());
    }

    #[test]
    fn concurrent_producer_and_consumer_transfer_every_item_in_order() {
        // The real two-PD scenario: one thread enqueues, another dequeues,
        // through a ring far smaller than the message count so it repeatedly
        // fills, empties, and wraps under genuine contention.
        const COUNT: u32 = 200_000;
        let ring = Arc::new(SpscRing::<64>::new());

        let producer = {
            let ring = Arc::clone(&ring);
            thread::spawn(move || {
                let mut i = 0;
                while i < COUNT {
                    if ring.try_enqueue(Descriptor::new(i, i, i)).is_ok() {
                        i += 1;
                    } else {
                        std::hint::spin_loop();
                    }
                }
            })
        };

        let consumer = thread::spawn(move || {
            let mut expected = 0;
            while expected < COUNT {
                match ring.try_dequeue() {
                    Some(descriptor) => {
                        assert_eq!(descriptor, Descriptor::new(expected, expected, expected));
                        expected += 1;
                    }
                    None => std::hint::spin_loop(),
                }
            }
        });

        producer.join().unwrap();
        consumer.join().unwrap();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Random interleavings of `try_enqueue`/`try_dequeue` against a model
        /// FIFO queue: every dequeue returns exactly what the model expects
        /// (FIFO order preserved), a rejected enqueue means the ring is at
        /// capacity, and `len()` never exceeds `capacity()`.
        #[test]
        fn spsc_ring_matches_a_model_fifo(ops in prop::collection::vec(any::<bool>(), 0..300)) {
            const CAP: usize = 8;
            let ring = SpscRing::<CAP>::new();
            let mut model: VecDeque<u32> = VecDeque::new();
            let mut next: u32 = 0;

            for enqueue in ops {
                if enqueue {
                    match ring.try_enqueue(Descriptor::new(next, next, next)) {
                        Ok(()) => {
                            model.push_back(next);
                            next = next.wrapping_add(1);
                        }
                        Err(returned) => {
                            // A rejection hands the descriptor back unchanged and
                            // happens only when the ring is at usable capacity.
                            prop_assert_eq!(returned, Descriptor::new(next, next, next));
                            prop_assert_eq!(model.len(), ring.capacity());
                        }
                    }
                } else {
                    let expected = model.pop_front().map(|v| Descriptor::new(v, v, v));
                    prop_assert_eq!(ring.try_dequeue(), expected);
                }
                prop_assert_eq!(ring.len(), model.len());
                prop_assert!(ring.len() <= ring.capacity());
            }
        }

        /// A hostile peer may scribble either shared cursor with an arbitrary
        /// value. Masking must keep every operation in bounds: no panic, no
        /// out-of-range index, and `len()` stays within capacity.
        #[test]
        fn spsc_ring_survives_arbitrary_cursor_values(
            head in any::<u32>(),
            tail in any::<u32>(),
            enqueue_first in any::<bool>(),
        ) {
            let ring = SpscRing::<8>::new();
            ring.head.store(head, Ordering::Relaxed);
            ring.tail.store(tail, Ordering::Relaxed);
            // Exercise both operations regardless of the garbage cursors.
            if enqueue_first {
                let _ = ring.try_enqueue(Descriptor::new(1, 2, 3));
                let _ = ring.try_dequeue();
            } else {
                let _ = ring.try_dequeue();
                let _ = ring.try_enqueue(Descriptor::new(1, 2, 3));
            }
            prop_assert!(ring.len() <= ring.capacity());
            let _ = ring.is_empty();
        }
    }
}
