//! Lock-free single-producer/single-consumer ring, the primitive the whole
//! dataplane moves descriptors over.
//!
//! The ring lives in memory shared between two protection domains. Exactly one
//! domain enqueues (the producer) and exactly one dequeues (the consumer); this
//! is a contract the caller must uphold, not something the types enforce. One
//! slot is always left unused so a full ring is distinguishable from an empty
//! one without a separate flag.
//!
//! Correctness rests on a release/acquire handshake on the two cursors: the
//! producer publishes a slot by releasing `tail`, and the consumer observes it
//! by acquiring `tail`, which establishes happens-before for the slot write.
//! The mirror holds for `head`. On x86 these are plain loads/stores plus
//! compiler fences, so the hot path stays cheap.

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

impl<const CAP: usize> SpscRing<CAP> {
    const MASK: u32 = {
        assert!(
            CAP.is_power_of_two(),
            "ring capacity must be a power of two"
        );
        assert!(CAP >= 2, "ring capacity must be at least 2");
        (CAP - 1) as u32
    };

    /// A new, empty ring. Const so it can initialise a shared region in place;
    /// note that a zeroed region is already a valid empty ring.
    #[must_use]
    pub const fn new() -> Self {
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
        let next = (tail + 1) & Self::MASK;
        if next == self.head.load(Ordering::Acquire) {
            return Err(descriptor);
        }
        // SAFETY: this slot sits at `tail`, which the consumer cannot observe
        // until the release store below, so the producer is its sole accessor.
        unsafe { self.slots[tail as usize].get().write(descriptor) };
        self.tail.store(next, Ordering::Release);
        Ok(())
    }

    /// Dequeue one descriptor. Consumer side only.
    pub fn try_dequeue(&self) -> Option<Descriptor> {
        let head = self.head.load(Ordering::Relaxed);
        if head == self.tail.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: the producer published this slot with a release store to
        // `tail` that our acquire load synchronised with, so the write is
        // visible; and the producer will not reuse the slot until we advance
        // `head` below, so we are its sole accessor.
        let descriptor = unsafe { self.slots[head as usize].get().read() };
        self.head.store((head + 1) & Self::MASK, Ordering::Release);
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
    fn fills_to_capacity_then_reports_full() {
        let ring = SpscRing::<8>::new();
        assert_eq!(ring.capacity(), 7);
        for i in 0..7 {
            assert!(ring.try_enqueue(Descriptor::new(i, i)).is_ok());
        }
        assert_eq!(ring.len(), 7);
        // The eighth enqueue must fail and hand the descriptor back.
        let rejected = ring.try_enqueue(Descriptor::new(99, 99));
        assert_eq!(rejected, Err(Descriptor::new(99, 99)));
    }

    #[test]
    fn fifo_order_is_preserved() {
        let ring = SpscRing::<8>::new();
        for i in 0..5 {
            ring.try_enqueue(Descriptor::new(i, 0)).unwrap();
        }
        for i in 0..5 {
            assert_eq!(ring.try_dequeue(), Some(Descriptor::new(i, 0)));
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn wraps_around_the_slot_array_repeatedly() {
        let ring = SpscRing::<4>::new();
        // Usable capacity 3; push/pop far more than CAP so head and tail wrap
        // the underlying array many times.
        for i in 0..1000 {
            ring.try_enqueue(Descriptor::new(i, i)).unwrap();
            assert_eq!(ring.try_dequeue(), Some(Descriptor::new(i, i)));
            assert!(ring.is_empty());
        }
    }

    #[test]
    fn full_empty_transitions_hold_across_wrap() {
        let ring = SpscRing::<4>::new();
        for round in 0..50 {
            for i in 0..3 {
                ring.try_enqueue(Descriptor::new(round * 3 + i, 0)).unwrap();
            }
            assert!(ring.try_enqueue(Descriptor::ZERO).is_err());
            assert_eq!(ring.len(), 3);
            for i in 0..3 {
                assert_eq!(ring.try_dequeue(), Some(Descriptor::new(round * 3 + i, 0)));
            }
            assert_eq!(ring.try_dequeue(), None);
        }
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
                    if ring.try_enqueue(Descriptor::new(i, i)).is_ok() {
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
                        assert_eq!(descriptor, Descriptor::new(expected, expected));
                        expected += 1;
                    }
                    None => std::hint::spin_loop(),
                }
            }
        });

        producer.join().unwrap();
        consumer.join().unwrap();
    }
}
