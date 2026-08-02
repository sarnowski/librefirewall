//! The byzantine peer's reach into a shared `queue::SpscRing`.
//!
//! # Why this exists
//!
//! `SpscRing`'s two cursors and its slot array are **private fields**, and that
//! is correct: no first-party code should reach them. A peer protection domain
//! is under no such constraint. It maps the very same region read-write
//! (`pd_runtime`'s `attach_region!` states the aliasing set
//! explicitly), so every one of those words is a plain address it can store to
//! at any moment. A harness that could not write them would be modelling a
//! *polite* peer and would exclude the entire adversarial region — the
//! harness failure mode this workspace exists to correct.
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
//! * `size_of::<Slot>() == size_of::<Descriptor>() == 16` and
//!   `align_of::<Slot>() == align_of::<Descriptor>() == 4`;
//! * each `Slot` field sits at its `Descriptor` counterpart's offset —
//!   `buffer` at 0, `offset` at 4, `len` at 8, `verdict` at 12 — and each is an
//!   `AtomicU32`.
//!
//! So the ring is exactly `2 + 4 * CAP` consecutive `AtomicU32` words, and word
//! `2 + 4 * slot + field` is slot `slot`'s field `field`. Every offset below is
//! computed from `CAP` alone — never from a value read out of the region — and
//! every slot index is reduced modulo `CAP` before use, so no input can drive
//! an access outside the ring.
//!
//! # Why the peer stores one word at a time
//!
//! A slot is four separate `AtomicU32`s and `queue::Slot::load` reads them as
//! four separate relaxed loads, so the peer's real granularity is **one
//! word**, not one descriptor. That distinction is the whole of the torn-read
//! hazard the `queue` crate names ("a concurrent peer write can yield a
//! descriptor whose four fields come from different writes"), and a view that
//! could only store whole descriptors would have excluded the adversary's
//! real capability: a *conforming* peer publishes whole descriptors and only a byzantine one
//! leaves a slot half-rewritten.
//!
//! [`SlotField::Verdict`] is the one word no first-party producer can put an
//! arbitrary value in — `wire::Descriptor::new` takes a `Verdict`, so the type
//! system rules the undecodable case out on this side of the boundary. It is
//! plain shared memory to the peer, so a harness that could not write it would
//! leave every consumer's decoding path permanently unexercised.
//!
//! [`store_slot_field`](PeerView::store_slot_field) is therefore the primitive
//! and [`store_slot`](PeerView::store_slot) is four of it. Single-location
//! coherence makes that sufficient rather than merely convenient: each field
//! `load` returns *some* value stored to that field at or before it, so the
//! descriptors a torn read can produce are exactly the field-wise mixtures, and
//! a harness that can set each field independently between operations reaches
//! all of them without a second thread — whose unsynchronised writes into the
//! same words would be a data race this harness manufactured itself.

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
/// `u32` words per slot: `buffer`, `offset`, `len`, `verdict`.
const WORDS_PER_SLOT: usize = 4;

/// Which of a slot's four `AtomicU32` words a peer store lands in.
///
/// An enum rather than an index, so no caller can name a fifth word: the
/// bound `store_slot_field`'s safety argument rests on is carried by the type
/// instead of by a check the caller is trusted to have made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotField {
    Buffer,
    Offset,
    Len,
    Verdict,
}

impl SlotField {
    /// The four words in the order [`PeerView::load_slot`] and
    /// `queue::Slot::load` read them.
    pub const ALL: [Self; WORDS_PER_SLOT] = [Self::Buffer, Self::Offset, Self::Len, Self::Verdict];

    /// This field's word index within its slot; `< WORDS_PER_SLOT` for every
    /// variant, which is what bounds the accesses below and what lets a caller
    /// index its own per-word shadow of a slot by the same number.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Buffer => 0,
            Self::Offset => 1,
            Self::Len => 2,
            Self::Verdict => 3,
        }
    }

    /// Pick a field from an arbitrary byte, so the fuzzer chooses which word a
    /// peer store lands in.
    #[must_use]
    pub const fn from_selector(selector: u32) -> Self {
        match selector % WORDS_PER_SLOT as u32 {
            0 => Self::Buffer,
            1 => Self::Offset,
            2 => Self::Len,
            _ => Self::Verdict,
        }
    }
}

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
    /// `word` must be less than `2 + 4 * CAP`, so the reference lies within the
    /// ring the view borrows. Every caller below derives `word` from `CAP` and
    /// a value reduced modulo `CAP`, never from region contents.
    unsafe fn word(&self, word: usize) -> &AtomicU32 {
        // SAFETY: the caller guarantees `word < 2 + 4 * CAP`, and the ring's
        // pinned `#[repr(C)]` layout (see this module's header, enforced by the
        // `const _` block in `crates/queue/src/lib.rs`) makes that many
        // consecutive, 4-aligned `AtomicU32`s the whole of the borrowed ring.
        unsafe { &*self.words.add(word) }
    }

    /// Forge the consumer's published cursor. Rewinding, advancing, or
    /// scribbling it is what a peer does to stall a producer or to invite it to
    /// overwrite an unread slot.
    pub fn set_head(&self, value: u32) {
        // SAFETY: `HEAD_WORD` is 0, within `2 + 4 * CAP` for every `CAP >= 2`.
        unsafe { self.word(HEAD_WORD) }.store(value, Ordering::Relaxed);
    }

    /// Forge the producer's published cursor: the lever that presents a
    /// consumer with slots that were never published.
    pub fn set_tail(&self, value: u32) {
        // SAFETY: `TAIL_WORD` is 1, within `2 + 4 * CAP` for every `CAP >= 2`.
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

    /// Store one `u32` word of slot `slot % CAP` — the peer's real granularity,
    /// and the primitive every other slot write here is built from.
    ///
    /// Leaving the other two words alone is what a torn descriptor *is*: the
    /// next `queue::Slot::load` mixes this value with whatever the untouched
    /// words still hold, which is exactly what a peer store landing between two
    /// of that function's four relaxed loads produces.
    pub fn store_slot_field(&self, slot: usize, field: SlotField, value: u32) {
        let word = SLOTS_WORD + WORDS_PER_SLOT * (slot % CAP) + field.index();
        // SAFETY: `slot % CAP < CAP` and `SlotField::index() < WORDS_PER_SLOT`,
        // so `word < 2 + 4 * CAP` — inside the ring image.
        unsafe { self.word(word) }.store(value, Ordering::Relaxed);
    }

    /// Overwrite all four words of slot `slot % CAP`, as a peer publishing a
    /// whole descriptor into the mapped image does.
    ///
    /// Four [`store_slot_field`](Self::store_slot_field) calls and nothing
    /// more: a peer has no wider store, and expressing it any other way would
    /// let this convenience drift from the granularity it stands for.
    pub fn store_slot(&self, slot: usize, descriptor: Descriptor) {
        for (field, value) in SlotField::ALL.into_iter().zip([
            descriptor.buffer,
            descriptor.offset,
            descriptor.len,
            descriptor.verdict,
        ]) {
            self.store_slot_field(slot, field, value);
        }
    }

    /// Read slot `slot % CAP` back, so a harness can assert what the code under
    /// test dequeued is what that slot actually held.
    #[must_use]
    pub fn load_slot(&self, slot: usize) -> Descriptor {
        let base = SLOTS_WORD + WORDS_PER_SLOT * (slot % CAP);
        // SAFETY: as `store_slot` — `base + 3 < 2 + 4 * CAP`.
        //
        // A field-wise literal and not `Descriptor::new`, whose `Verdict`
        // argument would force this view to rule on a word the peer owns; the
        // point of reading a slot back is to see whatever is really in it.
        unsafe {
            Descriptor {
                buffer: self.word(base).load(Ordering::Relaxed),
                offset: self.word(base + 1).load(Ordering::Relaxed),
                len: self.word(base + 2).load(Ordering::Relaxed),
                verdict: self.word(base + 3).load(Ordering::Relaxed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wire::Verdict;

    /// A descriptor with the verdict word set to `verdict`, whatever that is —
    /// the field is the peer's, so a test of the peer's view builds it the way
    /// the peer does rather than through a `Verdict`.
    fn raw(buffer: u32, offset: u32, len: u32, verdict: u32) -> Descriptor {
        Descriptor {
            buffer,
            offset,
            len,
            verdict,
        }
    }

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
        let published = Descriptor::new(9, 12, 34, Verdict::Discard);
        producer.try_enqueue(published).expect("the ring is empty");
        assert_eq!(peer.load_slot(0), published);
        assert_eq!(peer.tail(), 1, "the producer publishes its new position");

        // A peer store lands where the consumer will read it — verdict word
        // included, and set to a value no `Verdict` encodes.
        let forged = raw(0xDEAD, 0xBEEF, 0xF00D, 0xC0DE_C0DE);
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
        let forged = raw(1, 2, 3, 4);
        peer.store_slot(usize::MAX, forged);
        assert_eq!(peer.load_slot(usize::MAX % 4), forged);
        for field in SlotField::ALL {
            peer.store_slot_field(usize::MAX, field, 0xC0DE);
        }
        assert_eq!(
            peer.load_slot(usize::MAX % 4),
            raw(0xC0DE, 0xC0DE, 0xC0DE, 0xC0DE)
        );
    }

    #[test]
    fn a_single_field_store_tears_the_descriptor_the_consumer_reads() {
        // The torn read, generated without a second thread: the producer
        // publishes a whole descriptor, the peer rewrites one word of that same
        // slot, and `try_dequeue` hands back the mixture — some fields from the
        // producer's write and some from the peer's, which is precisely what a
        // store landing between two of `Slot::load`'s four relaxed loads
        // yields.
        //
        // The verdict is one of the words rewritten, and to a value that
        // decodes to no `Verdict`: it is the only field a producer cannot put
        // such a value in, so a peer store is the sole route to it.
        let ring = SpscRing::<8>::new();
        let peer = PeerView::new(&ring);
        let mut producer = ring.producer();
        let mut consumer = ring.consumer();

        producer
            .try_enqueue(Descriptor::new(0x1111, 0x2222, 0x3333, Verdict::Transmit))
            .expect("the ring is empty");
        peer.store_slot_field(0, SlotField::Offset, 0xDEAD);
        peer.store_slot_field(0, SlotField::Verdict, 0xBEEF);
        assert_eq!(
            consumer.try_dequeue(),
            Some(raw(0x1111, 0xDEAD, 0x3333, 0xBEEF)),
            "a field-wise mixture must reach the consumer verbatim"
        );
    }

    #[test]
    fn each_field_selector_reaches_exactly_its_own_word() {
        // If two selectors collided the harness would believe it had torn a
        // descriptor while writing the same word twice, and the torn-delivery
        // count resting on this mapping would be fiction.
        let ring = SpscRing::<2>::new();
        let peer = PeerView::new(&ring);
        for (selector, field) in (0u32..4).zip(SlotField::ALL) {
            assert_eq!(SlotField::from_selector(selector), field);
            assert_eq!(SlotField::from_selector(selector + 4), field);
        }
        peer.store_slot_field(0, SlotField::Buffer, 7);
        assert_eq!(peer.load_slot(0), raw(7, 0, 0, 0));
        peer.store_slot_field(0, SlotField::Offset, 8);
        assert_eq!(peer.load_slot(0), raw(7, 8, 0, 0));
        peer.store_slot_field(0, SlotField::Len, 9);
        assert_eq!(peer.load_slot(0), raw(7, 8, 9, 0));
        peer.store_slot_field(0, SlotField::Verdict, 10);
        assert_eq!(peer.load_slot(0), raw(7, 8, 9, 10));
    }
}
