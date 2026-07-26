//! `queue::SpscRing` under a byzantine neighbour PD.
//!
//! # The adversary and the surface
//!
//! The peer maps the whole ring read-write (CONCEPT §7.1): both published
//! cursors and every one of the `3 * CAP` slot words. The crate's central claim
//! is that this buys the peer *values*, never *positions* — each side's own
//! position lives in private memory the peer cannot map.
//!
//! # What the adversary may express here
//!
//! Both cursors take a full, unreduced `u32` — rewound, advanced past the ring,
//! `u32::MAX`, anything. Any slot may be overwritten whole, **or one `u32` word
//! at a time**, which is the peer's real granularity and the only way a torn
//! descriptor is expressible (see [`crate::ring_abi`]). All of it interleaves
//! freely with this side's enqueues and dequeues.
//!
//! The harness also violates the crate's own **single-handle rule** on demand:
//! `SpscRing::producer` and `SpscRing::consumer` take `&self`, so a second
//! handle is an ordinary call, and the crate header states plainly what it
//! costs ("a second restarts at position zero and re-walks slots the first
//! already used"). That is a *caller* contract no type enforces, which is
//! exactly why a harness that took one handle each and stopped there could
//! never show what breaking it does. Each handle carries its own shadow
//! position, so the consequence is measured rather than assumed.
//!
//! # What is asserted
//!
//! * **The position is private, per handle.** Before each dequeue the harness
//!   reads, through the peer's own view of the shared image, the slot at *that
//!   handle's* shadow position — tracked from that handle's history alone — and
//!   the descriptor that comes out must be exactly those bytes. The producer
//!   mirror is asserted the same way. This says where each side reads and
//!   writes; on its own it says **nothing** about redelivery, which is why the
//!   multiplicity ledger below exists.
//! * **Delivery multiplicity, bounded rather than predicted.** Every descriptor
//!   this side enqueues is tracked by *provenance* — which write put each word
//!   in each slot — so a descriptor handed out twice is counted rather than
//!   inferred. The queue layer genuinely permits redelivery; what it promises
//!   is that redelivery has a **cause**, and the assertion is that one is
//!   always present: a peer `tail` forge, or a second handle. Under a peer that
//!   forges no `tail` and one handle of each kind, no descriptor is ever
//!   delivered twice.
//! * **Exact flow control, against an independent model.** Both published
//!   cursors are predicted from this harness's own history — this side's
//!   publishes and the peer's forges — never read back out of the ring, and the
//!   prediction is compared with the image after every operation. Whether an
//!   enqueue is refused and whether a dequeue yields is then decided from that
//!   model.
//! * **Nothing is invented, per word.** Every `u32` that comes out of a slot
//!   field is a value some enqueue or some peer store actually wrote into *that
//!   field of that slot*, or the zero of an untouched one. Per word, not per
//!   descriptor: with per-field stores a delivered descriptor is routinely a
//!   triple nobody ever wrote as a triple, and that is the correct outcome, not
//!   a violation.
//! * **`drain(limit)` never yields more than `limit`**, and yields exactly the
//!   sequence the shadow position predicts.
//! * **`is_empty()` and `len()` never contradict**, and `len()` never exceeds
//!   `capacity()`, on every handle after every operation.
//!
//! # The counterexample this harness is shaped by
//!
//! The previous version predicted emptiness as `shadow_head == peer.tail()`,
//! which is `try_dequeue`'s own condition with `peer.tail()` read back out of
//! the ring — the code checked against itself. Fill the ring, drain it, and let
//! the peer store a `tail` *behind* the consumer's private position: the
//! consumer laps the slot array and hands back descriptors it has already
//! delivered. Every one of those redeliveries satisfied the old oracle, so the
//! harness asserted that the redelivery was **correct**. The committed seed
//! `lapping_tail_rewind` is that input at this harness's `CAP`, and
//! `a_forged_tail_laps_the_consumer_and_the_redelivery_is_counted` is the
//! demonstration; the bound in `deliver` is what replaced the prediction.

use std::collections::BTreeSet;

use arbitrary::Unstructured;
use queue::{RingConsumer, RingProducer, SpscRing};
use wire::Descriptor;

use crate::ring_abi::{PeerView, SlotField};
use crate::{MAX_OPERATIONS, any_index, any_u32, next_op};

/// Ring slots the harness drives. A power of two, small enough that the fuzzer
/// wraps the array within a handful of operations.
const CAP: usize = 8;
/// The mask both sides reduce a cursor by; `CAP - 1` because one slot is always
/// left unused to tell full from empty.
const MASK: u32 = (CAP - 1) as u32;

/// Which write put a given `u32` into a given slot word.
///
/// Identity by *provenance* rather than by value, because the peer may store
/// any `u32` it likes into any word — including a value this side also
/// enqueued. A value-matching ledger would then have to guess, and would guess
/// in whichever direction hid a redelivery; provenance cannot collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wrote {
    /// The zero of a slot no one has written since the region was zeroed.
    Zeroed,
    /// This side's `n`-th enqueue, which wrote all three words at once.
    Enqueue(u64),
    /// The peer's `n`-th store, whether of one word or of three.
    Peer(u64),
}

/// What one run of the harness observed.
///
/// Returned so the tests below can *demonstrate* that a shape is generable —
/// a claim that an adversary capability is reachable is worth nothing without
/// an input that reaches it (TEST-8). Every invariant resting on these counters
/// is asserted inside [`observe`] as it runs, not here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Observed {
    /// Descriptors handed out by any consumer handle.
    pub(crate) deliveries: u64,
    /// Deliveries of a descriptor this side had already been handed once.
    pub(crate) redeliveries: u64,
    /// Deliveries whose three words did not all come from one write.
    pub(crate) torn_deliveries: u64,
    /// Handles taken past the first, in violation of the single-handle rule.
    pub(crate) extra_producer_handles: u64,
    pub(crate) extra_consumer_handles: u64,
    /// Peer writes to each shared cursor.
    pub(crate) tail_forges: u64,
    pub(crate) head_forges: u64,
    /// Peer stores of a single slot word, leaving the other two alone.
    pub(crate) field_stores: u64,
}

/// One consumer handle and the private position the harness believes it holds.
struct ConsumerSide<'ring> {
    handle: RingConsumer<'ring, CAP>,
    head: u32,
}

/// One producer handle and its believed private position.
struct ProducerSide<'ring> {
    handle: RingProducer<'ring, CAP>,
    tail: u32,
}

/// The harness's independent model of the shared image: what each word holds,
/// who wrote it, and every value ever written to it.
struct Image {
    /// Provenance of each of the `3 * CAP` slot words.
    wrote: [[Wrote; 3]; CAP],
    /// Every value ever written to each slot word, so "nothing is invented" is
    /// checkable per word rather than per descriptor.
    seen: [[BTreeSet<u32>; 3]; CAP],
    /// The two published cursors as this harness's own history says they are —
    /// never read back out of the ring, which is what makes comparing them with
    /// the ring a claim rather than a tautology.
    published_head: u32,
    published_tail: u32,
}

impl Image {
    /// The model of a freshly zeroed region: both cursors zero, every word zero
    /// and untouched.
    fn zeroed() -> Self {
        Self {
            wrote: [[Wrote::Zeroed; 3]; CAP],
            seen: core::array::from_fn(|_| core::array::from_fn(|_| BTreeSet::from([0u32]))),
            published_head: 0,
            published_tail: 0,
        }
    }

    /// Record a write of one slot word.
    fn record(&mut self, slot: usize, field: SlotField, value: u32, wrote: Wrote) {
        self.wrote[slot % CAP][field.index()] = wrote;
        self.seen[slot % CAP][field.index()].insert(value);
    }

    /// Record a write of all three words of one slot.
    fn record_descriptor(&mut self, slot: usize, descriptor: Descriptor, wrote: Wrote) {
        for (field, value) in
            SlotField::ALL
                .into_iter()
                .zip([descriptor.buffer, descriptor.offset, descriptor.len])
        {
            self.record(slot, field, value, wrote);
        }
    }
}

/// Drive both sides of a shared ring against a peer that owns the cursors and
/// every slot word.
pub fn spsc_ring_harness(data: &[u8]) {
    let _ = observe(data);
}

/// The harness body, returning what it saw so a test can prove a shape reachable.
pub(crate) fn observe(data: &[u8]) -> Observed {
    let mut unstructured = Unstructured::new(data);
    let ring = SpscRing::<CAP>::new();
    let peer = PeerView::new(&ring);

    let mut producers = vec![ProducerSide {
        handle: ring.producer(),
        tail: 0,
    }];
    let mut consumers = vec![ConsumerSide {
        handle: ring.consumer(),
        head: 0,
    }];

    let mut image = Image::zeroed();
    let mut observed = Observed::default();
    // How many times each of this side's enqueues has been handed out. Indexed
    // by the enqueue's ordinal, which is what `Wrote::Enqueue` carries.
    let mut handed_out: Vec<u64> = Vec::new();
    // Every peer store gets its own ordinal, so two words of one slot compare
    // equal exactly when the same peer store wrote both. A shared ordinal would
    // make a mixture of two peer writes read as untorn.
    let mut peer_writes: u64 = 0;

    for _ in 0..MAX_OPERATIONS {
        let Some(op) = next_op(&mut unstructured) else {
            break;
        };
        match op % 8 {
            0 => {
                let index = any_index(&mut unstructured, producers.len());
                let side = &mut producers[index];
                let ordinal = handed_out.len() as u64;
                let descriptor = Descriptor::new(
                    any_u32(&mut unstructured),
                    any_u32(&mut unstructured),
                    any_u32(&mut unstructured),
                );
                // Flow control is judged against the modelled cursor, not
                // against one read back out of the ring.
                let refused = (side.tail.wrapping_add(1) & MASK) == (image.published_head & MASK);
                let slot = side.tail as usize;
                let outcome = side.handle.try_enqueue(descriptor);
                if refused {
                    assert_eq!(
                        outcome,
                        Err(descriptor),
                        "a refused enqueue must hand the descriptor back unchanged"
                    );
                } else {
                    assert_eq!(outcome, Ok(()), "the ring had room but refused the enqueue");
                    assert_eq!(
                        peer.load_slot(slot),
                        descriptor,
                        "the producer wrote somewhere other than its own private position"
                    );
                    image.record_descriptor(slot, descriptor, Wrote::Enqueue(ordinal));
                    handed_out.push(0);
                    side.tail = side.tail.wrapping_add(1) & MASK;
                    image.published_tail = side.tail;
                }
            }
            1 => {
                let index = any_index(&mut unstructured, consumers.len());
                let side = &mut consumers[index];
                let empty = side.head == (image.published_tail & MASK);
                let slot = side.head as usize;
                let held = peer.load_slot(slot);
                let outcome = side.handle.try_dequeue();
                if empty {
                    assert_eq!(outcome, None, "the ring appeared empty but yielded anyway");
                } else {
                    assert_eq!(
                        outcome,
                        Some(held),
                        "the consumer read somewhere other than its own private position"
                    );
                    side.head = side.head.wrapping_add(1) & MASK;
                    image.published_head = side.head;
                    deliver(slot, held, &image, &mut handed_out, &mut observed);
                }
            }
            2 => {
                // Predict the whole drain before running it: nothing in the
                // iterator changes a slot or either published cursor, so the
                // sequence the private position must produce is fully
                // determined here, from the model rather than from the image.
                let index = any_index(&mut unstructured, consumers.len());
                let limit = any_u32(&mut unstructured) as usize % (2 * CAP + 2);
                let modelled_tail = image.published_tail & MASK;
                let mut predicted = Vec::new();
                let mut position = consumers[index].head;
                for _ in 0..limit {
                    if position == modelled_tail {
                        break;
                    }
                    predicted.push((position as usize, peer.load_slot(position as usize)));
                    position = position.wrapping_add(1) & MASK;
                }
                let taken: Vec<Descriptor> = consumers[index].handle.drain(limit).collect();
                assert!(
                    taken.len() <= limit,
                    "drain yielded {} descriptors for a limit of {limit}",
                    taken.len()
                );
                assert_eq!(
                    taken,
                    predicted
                        .iter()
                        .map(|(_, descriptor)| *descriptor)
                        .collect::<Vec<Descriptor>>(),
                    "drain diverged from the private position"
                );
                consumers[index].head = position;
                if !predicted.is_empty() {
                    image.published_head = position;
                }
                for (slot, descriptor) in predicted {
                    deliver(slot, descriptor, &image, &mut handed_out, &mut observed);
                }
            }
            3 => {
                let forged = any_u32(&mut unstructured);
                peer.set_head(forged);
                image.published_head = forged;
                observed.head_forges += 1;
            }
            4 => {
                let forged = any_u32(&mut unstructured);
                peer.set_tail(forged);
                image.published_tail = forged;
                observed.tail_forges += 1;
            }
            5 => {
                let slot = any_u32(&mut unstructured) as usize;
                let descriptor = Descriptor::new(
                    any_u32(&mut unstructured),
                    any_u32(&mut unstructured),
                    any_u32(&mut unstructured),
                );
                peer.store_slot(slot, descriptor);
                peer_writes += 1;
                image.record_descriptor(slot, descriptor, Wrote::Peer(peer_writes));
            }
            6 => {
                // One word, leaving the other two as they were: the torn
                // descriptor, which a whole-descriptor store cannot express.
                let slot = any_u32(&mut unstructured) as usize;
                let field = SlotField::from_selector(any_u32(&mut unstructured));
                let value = any_u32(&mut unstructured);
                peer.store_slot_field(slot, field, value);
                observed.field_stores += 1;
                peer_writes += 1;
                image.record(slot, field, value, Wrote::Peer(peer_writes));
            }
            _ => {
                // Break the single-handle rule. The new handle starts at
                // position zero, as `SpscRing::consumer`/`producer` promise,
                // and re-walks whatever the first has already used.
                if (any_u32(&mut unstructured) & 1) == 1 {
                    producers.push(ProducerSide {
                        handle: ring.producer(),
                        tail: 0,
                    });
                    observed.extra_producer_handles += 1;
                } else {
                    consumers.push(ConsumerSide {
                        handle: ring.consumer(),
                        head: 0,
                    });
                    observed.extra_consumer_handles += 1;
                }
            }
        }

        // The publication claim: each side writes its own private position to
        // the shared cursor and nothing else writes it. The model was built
        // from this side's history and the peer's forges alone, so agreeing
        // with the image is a statement about the code.
        assert_eq!(
            peer.head(),
            image.published_head,
            "the shared head cursor holds a value nothing in this run published"
        );
        assert_eq!(
            peer.tail(),
            image.published_tail,
            "the shared tail cursor holds a value nothing in this run published"
        );

        // The two estimates are snapshots of a peer-influenced quantity, so
        // nothing is claimed about their *value* — only that they stay inside
        // the ring and cannot contradict each other, which is what a consumer
        // sizing a batch from them would rely on.
        for side in &producers {
            let len = side.handle.len();
            assert!(len <= side.handle.capacity(), "producer len left the ring");
            assert_eq!(side.handle.is_empty(), len == 0);
            assert!(side.tail < CAP as u32);
        }
        for side in &consumers {
            let len = side.handle.len();
            assert!(len <= side.handle.capacity(), "consumer len left the ring");
            assert_eq!(side.handle.is_empty(), len == 0);
            assert!(side.head < CAP as u32);
        }
    }

    // A peer that keeps advancing `tail` keeps the ring looking non-empty
    // forever; `drain` is the bounded form that must stop anyway. Assert the
    // bound holds rather than assuming it: an unbounded `while let Some(..)`
    // here would hang instead of failing, which is the shape of harness that
    // proves nothing.
    // Neither this forge nor what the four drains yield is accounted: the claim
    // under test here is the bound on the iterator and nothing else, `deliver`
    // is not reached again, and leaving `tail_forges` alone keeps "this run
    // forged no tail" a statement a demonstration can make.
    peer.set_tail(any_u32(&mut unstructured));
    for limit in [0usize, 1, CAP, 2 * CAP] {
        assert!(
            consumers[0].handle.drain(limit).count() <= limit,
            "drain exceeded its limit"
        );
    }

    observed
}

/// Account for one descriptor handed to a consumer, and assert what the queue
/// layer promises about how often that may happen.
///
/// Split out only because a dequeue and a drain must account identically; the
/// assertions stay with the accounting so the two cannot drift.
fn deliver(
    slot: usize,
    descriptor: Descriptor,
    image: &Image,
    handed_out: &mut [u64],
    observed: &mut Observed,
) {
    observed.deliveries += 1;

    // Nothing invented, per word: each field is a value written to *that* field
    // of *that* slot, or the zero it started as.
    for (index, value) in [descriptor.buffer, descriptor.offset, descriptor.len]
        .into_iter()
        .enumerate()
    {
        assert!(
            image.seen[slot][index].contains(&value),
            "slot {slot} word {index} read back {value:#x}, which nothing ever wrote there"
        );
    }

    let wrote = image.wrote[slot];
    if wrote[0] != wrote[1] || wrote[1] != wrote[2] {
        // A descriptor assembled from more than one write — exactly what a peer
        // store landing between two of `Slot::load`'s three relaxed loads
        // produces. Well-formed, in bounds, and untrusted, which is all the
        // crate claims for it. It is not one of this side's descriptors any
        // more, so it is deliberately outside the multiplicity ledger below:
        // the peer replaced part of it, and a mixture cannot be a *re*delivery
        // of something never delivered whole.
        observed.torn_deliveries += 1;
        return;
    }

    let Wrote::Enqueue(ordinal) = wrote[0] else {
        // A zeroed slot or a descriptor the peer wrote whole. Neither is one of
        // this side's, so neither can be a *re*delivery of one.
        return;
    };
    let count = &mut handed_out[ordinal as usize];
    *count += 1;
    if *count > 1 {
        observed.redeliveries += 1;
        // The claim the crate header rests on, stated as a bound rather than
        // predicted away: redelivery is possible, and it always has a cause the
        // caller can point at. With one handle of each kind and a peer that
        // never forges `tail`, this side's position advances one slot per
        // delivery against a cursor only its own producer moves, so it cannot
        // lap the ring and no descriptor can come back.
        assert!(
            observed.tail_forges > 0
                || observed.extra_producer_handles > 0
                || observed.extra_consumer_handles > 0,
            "enqueue {ordinal} was delivered {} times with no forged tail and a single handle of \
             each kind — the private position failed to prevent redelivery",
            *count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Build one harness input, so a demonstration reads as the operation
    /// stream it drives rather than as a hex blob.
    #[derive(Default)]
    struct Input(Vec<u8>);

    impl Input {
        /// Select the operation `op % 8` runs.
        fn op(mut self, op: u8) -> Self {
            self.0.push(op);
            self
        }

        /// Append one `any_u32`/`any_index` argument, little-endian, as
        /// `arbitrary` reads it.
        fn arg(mut self, value: u32) -> Self {
            self.0.extend_from_slice(&value.to_le_bytes());
            self
        }

        fn enqueue(self, handle: u32, buffer: u32, offset: u32, len: u32) -> Self {
            self.op(0).arg(handle).arg(buffer).arg(offset).arg(len)
        }

        fn dequeue(self, handle: u32) -> Self {
            self.op(1).arg(handle)
        }

        fn forge_tail(self, value: u32) -> Self {
            self.op(4).arg(value)
        }

        fn store_field(self, slot: u32, field: u32, value: u32) -> Self {
            self.op(6).arg(slot).arg(field).arg(value)
        }

        /// `selector & 1 == 1` takes a producer handle, otherwise a consumer.
        fn take_handle(self, selector: u32) -> Self {
            self.op(7).arg(selector)
        }

        fn bytes(self) -> Vec<u8> {
            self.0
        }
    }

    /// The committed seed of that name, so a demonstration and the corpus entry
    /// that preserves it cannot drift apart.
    fn seed(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join("spsc_ring_peer")
            .join(name);
        fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    /// Finding 8's verified counterexample, at this harness's `CAP = 8`: fill
    /// the ring, drain it, then let the peer rewind `tail` behind the
    /// consumer's private position. The consumer laps and hands back
    /// descriptors it has already delivered — which the previous oracle
    /// asserted was *correct*, because it predicted emptiness from the very
    /// cursor the peer had just forged.
    fn lapping_tail_rewind() -> Vec<u8> {
        let mut input = Input::default();
        for stamp in 1..=7u32 {
            input = input.enqueue(0, stamp, 0, 0);
        }
        for _ in 0..7 {
            input = input.dequeue(0);
        }
        // head is now 7 and tail is 7. Rewinding tail to 4 makes every slot
        // from 7 round to 3 look published again.
        input = input.forge_tail(4);
        for _ in 0..5 {
            input = input.dequeue(0);
        }
        input.bytes()
    }

    /// A second consumer handle, taken while the first is mid-stream: it starts
    /// at position zero and re-walks slots the first already consumed. The
    /// single-handle rule is a caller contract no type enforces, so breaking it
    /// is an ordinary call — and one no previous harness ever made.
    fn second_consumer_handle() -> Vec<u8> {
        let mut input = Input::default();
        for stamp in 1..=4u32 {
            input = input.enqueue(0, stamp, 0, 0);
        }
        for _ in 0..4 {
            input = input.dequeue(0);
        }
        // Handle 1 starts at head 0 while tail stands at 4.
        input = input.take_handle(0);
        for _ in 0..4 {
            input = input.dequeue(1);
        }
        input.bytes()
    }

    /// A peer store of one slot word between two whole-descriptor writes: the
    /// consumer is handed a descriptor assembled from two different writes,
    /// which is what a store landing between two of `Slot::load`'s three
    /// relaxed loads produces and what a whole-descriptor-only peer could not
    /// express.
    fn torn_slot_word() -> Vec<u8> {
        Input::default()
            .enqueue(0, 0x1111_1111, 0x2222_2222, 0x3333_3333)
            .store_field(0, 2, 0xDEAD_BEEF)
            .dequeue(0)
            .bytes()
    }

    #[test]
    fn a_forged_tail_laps_the_consumer_and_the_redelivery_is_counted() {
        let observed = observe(&lapping_tail_rewind());
        assert!(
            observed.redeliveries > 0,
            "the lapping rewind delivered nothing twice: {observed:?}"
        );
        assert_eq!(observed.tail_forges, 1);
        assert_eq!(observed.extra_consumer_handles, 0);
        assert_eq!(observed.extra_producer_handles, 0);
    }

    #[test]
    fn a_second_consumer_handle_rewalks_slots_the_first_consumed() {
        let observed = observe(&second_consumer_handle());
        assert_eq!(observed.extra_consumer_handles, 1);
        assert_eq!(observed.tail_forges, 0);
        assert!(
            observed.redeliveries > 0,
            "the second handle delivered nothing the first had: {observed:?}"
        );
    }

    #[test]
    fn a_single_word_peer_store_tears_a_delivered_descriptor() {
        let observed = observe(&torn_slot_word());
        assert_eq!(observed.field_stores, 1);
        assert_eq!(
            observed.torn_deliveries, 1,
            "the single-word store did not tear a delivery: {observed:?}"
        );
    }

    /// Each demonstration is committed as the seed of the same name, byte for
    /// byte, so a cold fuzz run starts from the shapes above and an edit that
    /// changed the operation encoding could not leave the corpus silently
    /// meaning something else.
    #[test]
    fn every_demonstration_is_the_committed_seed_of_its_name() {
        for (name, built) in [
            ("lapping_tail_rewind", lapping_tail_rewind()),
            ("second_consumer_handle", second_consumer_handle()),
            ("torn_slot_word", torn_slot_word()),
        ] {
            assert_eq!(
                seed(name),
                built,
                "seed {name} is not the input it stands for"
            );
        }
    }

    /// The other half of the multiplicity claim: with one handle of each kind
    /// and no forged `tail`, an arbitrary stream of peer slot writes and `head`
    /// forges delivers nothing twice. `deliver`'s assertion would fire if it
    /// did; this states the same thing as a positive result so the bound is not
    /// merely vacuously satisfied.
    #[test]
    fn without_a_forged_tail_or_a_second_handle_nothing_is_delivered_twice() {
        let mut input = Input::default();
        for stamp in 1..=7u32 {
            input = input.enqueue(0, stamp, stamp, stamp);
        }
        for round in 0..7u32 {
            input = input.op(3).arg(round.wrapping_mul(0x9E37_79B9));
            input = input.dequeue(0);
        }
        let observed = observe(&input.bytes());
        assert_eq!(observed.redeliveries, 0);
        assert!(observed.head_forges > 0 && observed.deliveries > 0);
    }
}
