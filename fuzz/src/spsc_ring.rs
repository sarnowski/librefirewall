//! `queue::SpscRing` under a byzantine neighbour PD.
//!
//! # The adversary and the surface
//!
//! The peer maps the whole ring read-write (CONCEPT §7.1): both published
//! cursors and every slot. The crate's central claim is that this buys the peer
//! *values*, never *positions* — each side's own position lives in private
//! memory the peer cannot map, so a rewound `head` cannot make the consumer
//! redeliver a descriptor (one buffer, two owners) and a rewound `tail` cannot
//! make the producer overwrite a slot already handed over (one buffer, lost).
//!
//! # What the adversary may express here
//!
//! Both cursors take a full, unreduced `u32` — rewound, advanced past the ring,
//! `u32::MAX`, anything — and any slot may be overwritten with any descriptor at
//! any point in the stream, interleaved freely with the local side's enqueues
//! and dequeues. Nothing about the peer is assumed well-formed, because nothing
//! about it is.
//!
//! # What is asserted
//!
//! * **The position is private.** Before each dequeue the harness reads, through
//!   the peer's own view of the shared image, the slot at the *shadow* position
//!   it has tracked from this side's history alone; the descriptor that comes
//!   out must be exactly that slot's contents. The producer mirror is asserted
//!   the same way. This is the redelivery and overwrite invariant stated
//!   directly, and no cursor the peer forges can satisfy it by accident.
//! * **Exact flow-control semantics.** Whether an enqueue is refused and whether
//!   a dequeue yields is predicted from the shadow position and the peer's
//!   published cursor before each call, and compared.
//! * **Nothing is invented.** Every descriptor read out is a value some enqueue
//!   or some peer store actually wrote into a slot, or the zero of an untouched
//!   one.
//! * **`drain(limit)` never yields more than `limit`**, and yields exactly the
//!   sequence the shadow position predicts.
//! * **`is_empty()` and `len()` never contradict**, and `len()` never exceeds
//!   `capacity()`, after every operation and under every forged cursor.

use std::collections::BTreeSet;

use arbitrary::Unstructured;
use queue::SpscRing;
use wire::Descriptor;

use crate::ring_abi::PeerView;
use crate::{MAX_OPERATIONS, any_u32, next_op};

/// Ring slots the harness drives. A power of two, small enough that the fuzzer
/// wraps the array within a handful of operations.
const CAP: usize = 8;
/// The mask both sides reduce a cursor by; `CAP - 1` because one slot is always
/// left unused to tell full from empty.
const MASK: u32 = (CAP - 1) as u32;

/// Drive both sides of a shared ring against a peer that owns the cursors and
/// the slots.
pub fn spsc_ring_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let ring = SpscRing::<CAP>::new();
    let peer = PeerView::new(&ring);
    let mut producer = ring.producer();
    let mut consumer = ring.consumer();

    // The shadow positions: what each side's private cursor must be, derived
    // from this side's own history alone — never from anything the peer wrote.
    let mut shadow_tail: u32 = 0;
    let mut shadow_head: u32 = 0;
    // Every descriptor value that has ever been stored into a slot, by either
    // side. A dequeue may only ever produce one of these.
    let mut written: BTreeSet<(u32, u32, u32)> = BTreeSet::new();
    written.insert((0, 0, 0));

    for _ in 0..MAX_OPERATIONS {
        let Some(op) = next_op(&mut unstructured) else {
            break;
        };
        match op % 6 {
            0 => {
                let descriptor = Descriptor::new(
                    any_u32(&mut unstructured),
                    any_u32(&mut unstructured),
                    any_u32(&mut unstructured),
                );
                // Flow control is judged against the peer's published cursor,
                // which the peer may have forged a moment ago.
                let refused = (shadow_tail.wrapping_add(1) & MASK) == (peer.head() & MASK);
                let outcome = producer.try_enqueue(descriptor);
                if refused {
                    assert_eq!(
                        outcome,
                        Err(descriptor),
                        "a refused enqueue must hand the descriptor back unchanged"
                    );
                } else {
                    assert_eq!(outcome, Ok(()), "the ring had room but refused the enqueue");
                    assert_eq!(
                        peer.load_slot(shadow_tail as usize),
                        descriptor,
                        "the producer wrote somewhere other than its own private position"
                    );
                    written.insert((descriptor.buffer, descriptor.offset, descriptor.len));
                    shadow_tail = shadow_tail.wrapping_add(1) & MASK;
                }
            }
            1 => {
                let empty = shadow_head == (peer.tail() & MASK);
                let slot = peer.load_slot(shadow_head as usize);
                let outcome = consumer.try_dequeue();
                if empty {
                    assert_eq!(outcome, None, "the ring appeared empty but yielded anyway");
                } else {
                    assert_eq!(
                        outcome,
                        Some(slot),
                        "the consumer read somewhere other than its own private position"
                    );
                    shadow_head = shadow_head.wrapping_add(1) & MASK;
                }
            }
            2 => {
                // Predict the whole drain before running it: nothing in the
                // iterator changes a slot or the peer's `tail`, so the sequence
                // the private position must produce is fully determined here.
                let limit = any_u32(&mut unstructured) as usize % (2 * CAP + 2);
                let peer_tail = peer.tail() & MASK;
                let mut predicted = Vec::new();
                let mut position = shadow_head;
                for _ in 0..limit {
                    if position == peer_tail {
                        break;
                    }
                    predicted.push(peer.load_slot(position as usize));
                    position = position.wrapping_add(1) & MASK;
                }
                let taken: Vec<Descriptor> = consumer.drain(limit).collect();
                assert!(
                    taken.len() <= limit,
                    "drain yielded {} descriptors for a limit of {limit}",
                    taken.len()
                );
                assert_eq!(taken, predicted, "drain diverged from the private position");
                shadow_head = position;
            }
            3 => peer.set_head(any_u32(&mut unstructured)),
            4 => peer.set_tail(any_u32(&mut unstructured)),
            _ => {
                let slot = any_u32(&mut unstructured) as usize;
                let descriptor = Descriptor::new(
                    any_u32(&mut unstructured),
                    any_u32(&mut unstructured),
                    any_u32(&mut unstructured),
                );
                peer.store_slot(slot, descriptor);
                written.insert((descriptor.buffer, descriptor.offset, descriptor.len));
            }
        }

        // Nothing invented: whatever is in the slot the consumer will read next
        // is a value someone actually wrote there.
        let next = peer.load_slot(shadow_head as usize);
        assert!(
            written.contains(&(next.buffer, next.offset, next.len)),
            "a descriptor no enqueue and no peer store ever wrote appeared in the ring"
        );

        // The two estimates are snapshots of a peer-influenced quantity, so
        // nothing is claimed about their *value* — only that they stay inside
        // the ring and cannot contradict each other, which is what a consumer
        // sizing a batch from them would rely on.
        let producer_len = producer.len();
        let consumer_len = consumer.len();
        assert!(
            producer_len <= producer.capacity(),
            "producer len left the ring"
        );
        assert!(
            consumer_len <= consumer.capacity(),
            "consumer len left the ring"
        );
        assert_eq!(producer.is_empty(), producer_len == 0);
        assert_eq!(consumer.is_empty(), consumer_len == 0);
        assert!(shadow_head < CAP as u32 && shadow_tail < CAP as u32);
    }

    // A peer that keeps advancing `tail` keeps the ring looking non-empty
    // forever; `drain` is the bounded form that must stop anyway. Assert the
    // bound holds rather than assuming it: an unbounded `while let Some(..)`
    // here would hang instead of failing, which is the shape of harness that
    // proves nothing.
    peer.set_tail(any_u32(&mut unstructured));
    for limit in [0usize, 1, CAP, 2 * CAP] {
        assert!(
            consumer.drain(limit).count() <= limit,
            "drain exceeded its limit"
        );
    }
}
