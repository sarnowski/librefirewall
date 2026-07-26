//! The byzantine peer's reach into a shared `queue::SpscRing`.
//!
//! # Why this exists
//!
//! `SpscRing`'s two cursors and its slot array are **private fields**, and that
//! is correct: no first-party code should reach them. A peer protection domain
//! is under no such constraint. It maps the very same region read-write
//! (CONCEPT §7.1, and `pd_runtime`'s `attach_region!` states the aliasing set
//! explicitly), so every one of those words is a plain address it can store to
//! at any moment. A harness that could not write them would be modelling a
//! *polite* peer and would exclude the entire adversarial region — the TEST-8
//! failure this workspace exists to correct.
//!
//! So the peer is reproduced the way the peer really works: through the
//! ring's `#[repr(C)]` ABI, with atomic stores, exactly as `pd_runtime`'s and
//! `nic-driver-core`'s own tests do it. That is not a back door into private
//! state; it is the shared-memory image, and it is an ABI precisely so a second
//! address space can address it.
//!
//! # The layout this rests on, and who guarantees it
//!
//! Guaranteed by the `const _` block in `crates/queue/src/lib.rs`, which fails
//! the build if any of it moves:
//!
//! * `offset_of!(SpscRing<CAP>, head) == 0` and `tail == 4`, both `AtomicU32`;
//! * `offset_of!(SpscRing<CAP>, slots) == 8`;
//! * `size_of::<Slot>() == size_of::<Descriptor>() == 12` and
//!   `align_of::<Slot>() == align_of::<Descriptor>() == 4`;
//! * each `Slot` field sits at its `Descriptor` counterpart's offset —
//!   `buffer` at 0, `offset` at 4, `len` at 8 — and each is an `AtomicU32`.
//!
//! So the ring is exactly `2 + 3 * CAP` consecutive `AtomicU32` words, and word
//! `2 + 3 * slot + field` is slot `slot`'s field `field`. Every offset below is
//! computed from `CAP` alone — never from a value read out of the region — and
//! every slot index is reduced modulo `CAP` before use, so no input can drive
//! an access outside the ring.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicU32, Ordering};

use queue::SpscRing;
use wire::Descriptor;

/// Word index of the `head` cursor within the ring.
const HEAD_WORD: usize = 0;
/// Word index of the `tail` cursor within the ring.
const TAIL_WORD: usize = 1;
/// Word index at which the slot array starts.
const SLOTS_WORD: usize = 2;
/// `u32` words per slot: `buffer`, `offset`, `len`.
const WORDS_PER_SLOT: usize = 3;

/// A byzantine peer's view of a shared ring: both cursors and every slot.
///
/// Holds the ring borrow, so the words it addresses are live for as long as the
/// view is. Constructing one asserts nothing about the peer's behaviour — the
/// point is that it has no obligations at all.
pub struct PeerView<'ring, const CAP: usize> {
    words: *const AtomicU32,
    ring: PhantomData<&'ring SpscRing<CAP>>,
}

impl<'ring, const CAP: usize> PeerView<'ring, CAP> {
    /// Map a peer's view over `ring`.
    #[must_use]
    pub fn new(ring: &'ring SpscRing<CAP>) -> Self {
        Self {
            words: std::ptr::from_ref(ring).cast::<AtomicU32>(),
            ring: PhantomData,
        }
    }

    /// Borrow one `u32` word of the ring image by word index.
    ///
    /// # Safety
    /// `word` must be less than `2 + 3 * CAP`, so the reference lies within the
    /// ring the view borrows. Every caller below derives `word` from `CAP` and
    /// a value reduced modulo `CAP`, never from region contents.
    unsafe fn word(&self, word: usize) -> &AtomicU32 {
        // SAFETY: the caller guarantees `word < 2 + 3 * CAP`, and the ring's
        // pinned `#[repr(C)]` layout (see this module's header, enforced by the
        // `const _` block in `crates/queue/src/lib.rs`) makes that many
        // consecutive, 4-aligned `AtomicU32`s the whole of the borrowed ring.
        unsafe { &*self.words.add(word) }
    }

    /// Forge the consumer's published cursor. Rewinding, advancing, or
    /// scribbling it is what a peer does to stall a producer or to invite it to
    /// overwrite an unread slot.
    pub fn set_head(&self, value: u32) {
        // SAFETY: `HEAD_WORD` is 0, within `2 + 3 * CAP` for every `CAP >= 2`.
        unsafe { self.word(HEAD_WORD) }.store(value, Ordering::Relaxed);
    }

    /// Forge the producer's published cursor: the lever that presents a
    /// consumer with slots that were never published.
    pub fn set_tail(&self, value: u32) {
        // SAFETY: `TAIL_WORD` is 1, within `2 + 3 * CAP` for every `CAP >= 2`.
        unsafe { self.word(TAIL_WORD) }.store(value, Ordering::Relaxed);
    }

    /// Read the consumer's published cursor, so a harness can predict what the
    /// producer under test will decide.
    #[must_use]
    pub fn head(&self) -> u32 {
        // SAFETY: as `set_head`.
        unsafe { self.word(HEAD_WORD) }.load(Ordering::Relaxed)
    }

    /// Read the producer's published cursor; see [`head`](Self::head).
    #[must_use]
    pub fn tail(&self) -> u32 {
        // SAFETY: as `set_tail`.
        unsafe { self.word(TAIL_WORD) }.load(Ordering::Relaxed)
    }

    /// Overwrite slot `slot % CAP` with `descriptor`, field by field, as a peer
    /// storing to the mapped image does.
    pub fn store_slot(&self, slot: usize, descriptor: Descriptor) {
        let base = SLOTS_WORD + WORDS_PER_SLOT * (slot % CAP);
        for (offset, value) in [descriptor.buffer, descriptor.offset, descriptor.len]
            .into_iter()
            .enumerate()
        {
            // SAFETY: `slot % CAP < CAP` and `offset < 3`, so
            // `base + offset < 2 + 3 * CAP` — inside the ring image.
            unsafe { self.word(base + offset) }.store(value, Ordering::Relaxed);
        }
    }

    /// Read slot `slot % CAP` back, so a harness can assert what the code under
    /// test dequeued is what that slot actually held.
    #[must_use]
    pub fn load_slot(&self, slot: usize) -> Descriptor {
        let base = SLOTS_WORD + WORDS_PER_SLOT * (slot % CAP);
        // SAFETY: as `store_slot` — `base + 2 < 2 + 3 * CAP`.
        unsafe {
            Descriptor::new(
                self.word(base).load(Ordering::Relaxed),
                self.word(base + 1).load(Ordering::Relaxed),
                self.word(base + 2).load(Ordering::Relaxed),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_peer_view_addresses_the_words_the_ring_really_uses() {
        // If the pinned layout ever moved, this would read a cursor as a slot
        // and every harness resting on the view would quietly stop testing the
        // thing it names.
        let ring = SpscRing::<8>::new();
        let peer = PeerView::new(&ring);
        let mut producer = ring.producer();

        peer.set_head(0x1234);
        peer.set_tail(0x5678);
        assert_eq!(peer.head(), 0x1234);
        assert_eq!(peer.tail(), 0x5678);

        // Restore an empty ring, enqueue, and read the slot back through the
        // peer's view: the producer writes slot 0 first.
        peer.set_head(0);
        peer.set_tail(0);
        let published = Descriptor::new(9, 12, 34);
        producer.try_enqueue(published).expect("the ring is empty");
        assert_eq!(peer.load_slot(0), published);
        assert_eq!(peer.tail(), 1, "the producer publishes its new position");

        // A peer store lands where the consumer will read it.
        let forged = Descriptor::new(0xDEAD, 0xBEEF, 0xF00D);
        peer.store_slot(1, forged);
        peer.set_tail(2);
        let mut consumer = ring.consumer();
        assert_eq!(consumer.try_dequeue(), Some(published));
        assert_eq!(consumer.try_dequeue(), Some(forged));
    }

    #[test]
    fn slot_indices_wrap_rather_than_leaving_the_ring() {
        let ring = SpscRing::<4>::new();
        let peer = PeerView::new(&ring);
        let forged = Descriptor::new(1, 2, 3);
        peer.store_slot(usize::MAX, forged);
        assert_eq!(peer.load_slot(usize::MAX % 4), forged);
    }
}
