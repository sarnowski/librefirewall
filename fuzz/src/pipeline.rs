//! `pd_runtime` under a byzantine neighbour PD.
//!
//! # The adversary and the surface
//!
//! `Pipeline` is the inter-PD protocol itself, so this is where "what one
//! protection domain must withstand from another" is defined (CONCEPT §7.1).
//! Every neighbour maps the whole region read-write — both cursors of all three
//! rings, every slot, and the pool bytes — and the two mechanisms that stop
//! that from becoming a double-owned buffer are `PoolOwner`'s *lent* set and
//! `packet_buffer`'s ledger beneath it.
//!
//! The worst outcome this guards is not a crash. It is a forged index reaching
//! the free stack, being handed back out by `alloc`, and turned into a physical
//! address by `Pipeline::buffer_paddr` — a DMA target **outside the shared
//! region**, which with no IOMMU is an arbitrary physical-memory write. This
//! harness asserts the containment of that address explicitly rather than
//! inferring it from the absence of a crash.
//!
//! # Roles
//!
//! Exactly one handle per ring end, as the crate requires; a second handle
//! would restart at slot zero and prove nothing:
//!
//! | ring | producer | consumer |
//! |---|---|---|
//! | `rx` | the rx driver — under test, through `PoolOwner::lend` | the forwarder — under test, inside `ForwardStage` |
//! | `tx` | the forwarder — under test, inside `ForwardStage` | the tx driver — **the adversary** |
//! | `free` | the tx driver — **the adversary** | the rx driver — under test, inside `PoolOwner` |
//!
//! # What the adversary may express here
//!
//! Arbitrary descriptors on the `free` ring — forged indices, indices never
//! lent, duplicates of a return already accepted, indices this domain still
//! holds posted to its own NIC — arbitrary cursors on every ring, and arbitrary
//! slot contents on the rings this side consumes. The spans a lend publishes
//! are arbitrary too, because from `ForwardStage`'s point of view the rx driver
//! is itself a peer.
//!
//! # What is asserted
//!
//! * **Containment.** Every index `alloc` hands out is a pool index, and the
//!   physical address `buffer_paddr` derives from it lies wholly inside the
//!   pool. This is the arbitrary-physical-write invariant, stated directly.
//! * **No double ownership.** `alloc` never hands out an index this side is
//!   already holding, and the final drain of the ledger yields pairwise
//!   distinct indices — no buffer invented, none free twice.
//! * **Bounded work.** `PoolOwner::reclaim` and `ForwardStage::poll` each move
//!   at most `DRAIN_LIMIT` descriptors per call, whatever cursor the peer
//!   publishes.
//! * **The delegated precondition terminates.** `descriptor_in_bounds` is the
//!   component `packet_buffer`'s accessors name as the enforcer for a
//!   peer-supplied span (AGENTS.md DOC-7). Every descriptor that reaches the tx
//!   side and passes it is then actually read through the pool, so a
//!   disagreement between the two surfaces as a fault rather than as a comment
//!   nobody checked.
//! * **Counters only ever rise**, so a rejection is never silently un-counted.

use std::collections::BTreeSet;

use arbitrary::Unstructured;
use pd_runtime::{
    BUFFER_SIZE, DRAIN_LIMIT, Descriptor, ForwardStage, OwnedBuffer, POOL_BUFFERS, Pipeline,
    PoolOwner, RING_SLOTS, descriptor_in_bounds,
};

use crate::region::ZeroedRegion;
use crate::ring_abi::PeerView;
use crate::{MAX_OPERATIONS, any_index, any_u32, next_op};

/// Physical address the region is mapped at. Page-aligned, as Microkit
/// guarantees, because `Pipeline`'s own alignment argument rests on it.
const REGION_PADDR: u64 = 0x3100_0000;

/// One descriptor whose three fields the peer chose freely.
fn any_descriptor(unstructured: &mut Unstructured<'_>) -> Descriptor {
    Descriptor::new(
        any_u32(unstructured),
        any_u32(unstructured),
        any_u32(unstructured),
    )
}

/// Drive the pool ownership protocol and the forwarding stage against a peer
/// that owns the `free` ring and every shared word in the region.
pub fn pipeline_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let region = ZeroedRegion::<Pipeline>::new();
    // SAFETY: `region` is a live, zeroed allocation of exactly one `Pipeline`,
    // aligned to `align_of::<Pipeline>()` by `Layout::new`, and it outlives
    // every handle taken below — `Pipeline::attach`'s contract in full. No
    // `&mut Pipeline` is ever created to it: the borrow returned here is shared,
    // and every mutation goes through an atomic or an `UnsafeCell` accessor.
    let pipeline: &Pipeline = unsafe { Pipeline::attach(region.as_ptr()) };

    let mut owner = PoolOwner::attach(pipeline);
    let mut rx_producer = pipeline.rx.producer();
    let mut stage = ForwardStage::attach(pipeline);
    let mut peer_free = pipeline.free.producer();
    let mut peer_tx = pipeline.tx.consumer();
    let rx_view = PeerView::<RING_SLOTS>::new(&pipeline.rx);
    let tx_view = PeerView::<RING_SLOTS>::new(&pipeline.tx);
    let free_view = PeerView::<RING_SLOTS>::new(&pipeline.free);

    let pool_base = Pipeline::pool_paddr(REGION_PADDR);
    let pool_end = pool_base + (POOL_BUFFERS * BUFFER_SIZE) as u64;

    let mut held: Vec<OwnedBuffer> = Vec::new();
    let mut holding = [false; POOL_BUFFERS];
    let mut previous_pool = owner.counters();
    let mut previous_forward = stage.counters();

    for _ in 0..MAX_OPERATIONS {
        let Some(op) = next_op(&mut unstructured) else {
            break;
        };
        match op % 9 {
            0 => {
                if let Some(buffer) = owner.alloc() {
                    let index = buffer.index();
                    // Containment, and the double-ownership check the pool's
                    // whole design exists for.
                    assert!(
                        (index as usize) < POOL_BUFFERS,
                        "alloc handed out index {index}, outside the pool — the address derived \
                         from it would be a DMA target outside the shared region"
                    );
                    assert!(
                        !holding[index as usize],
                        "alloc handed out index {index} while this domain already held it"
                    );
                    let paddr = Pipeline::buffer_paddr(REGION_PADDR, index);
                    assert!(
                        paddr >= pool_base && paddr + BUFFER_SIZE as u64 <= pool_end,
                        "buffer {index} resolves to {paddr:#x}, outside the pool \
                         [{pool_base:#x}, {pool_end:#x})"
                    );
                    holding[index as usize] = true;
                    held.push(buffer);
                }
            }
            1 => {
                if held.is_empty() {
                    continue;
                }
                let buffer = held.remove(any_index(&mut unstructured, held.len()));
                let index = buffer.index();
                // The span is the rx driver's own claim, and the rx driver is a
                // peer of the forwarder, so it is not constrained here.
                let offset = any_u32(&mut unstructured);
                let len = any_u32(&mut unstructured);
                match owner.lend(&mut rx_producer, buffer, offset, len) {
                    Ok(()) => holding[index as usize] = false,
                    Err(returned) => {
                        assert_eq!(
                            returned.index(),
                            index,
                            "lend handed back a different buffer"
                        );
                        held.push(returned);
                    }
                }
            }
            2 => {
                if held.is_empty() {
                    continue;
                }
                let buffer = held.remove(any_index(&mut unstructured, held.len()));
                holding[buffer.index() as usize] = false;
                owner.release(buffer);
            }
            3 => {
                let reclaimed = owner.reclaim();
                assert!(
                    reclaimed <= DRAIN_LIMIT,
                    "reclaim processed {reclaimed} returns, past the {DRAIN_LIMIT} bound"
                );
            }
            4 => {
                let moved = stage.poll();
                assert!(
                    moved <= DRAIN_LIMIT,
                    "the forwarder moved {moved} descriptors, past the {DRAIN_LIMIT} bound"
                );
            }
            // The trust boundary: a return of the peer's choosing. Half the
            // stream is biased into the pool's index range so duplicates and
            // returns of still-held buffers come up often; the other half is a
            // wholly unreduced descriptor.
            5 | 6 => {
                let mut descriptor = any_descriptor(&mut unstructured);
                if op % 9 == 6 {
                    descriptor.buffer %= POOL_BUFFERS as u32 + 2;
                }
                let _full = peer_free.try_enqueue(descriptor);
            }
            7 => {
                // The tx driver taking frames, validating each span through the
                // component the pool accessors name as its enforcer, and
                // returning the buffer the way a real tx driver does.
                let limit = any_u32(&mut unstructured) as usize % (2 * DRAIN_LIMIT + 2);
                let mut taken = 0usize;
                let drained: Vec<Descriptor> = peer_tx.drain(limit).collect();
                assert!(drained.len() <= limit, "drain exceeded its limit");
                for descriptor in drained {
                    taken += 1;
                    if descriptor_in_bounds(&descriptor) {
                        // SAFETY: this side dequeued the descriptor, so by the
                        // ring protocol it owns the buffer until it returns it
                        // below; the borrow ends before that. `descriptor_in_bounds`
                        // just proved the span lies within one pool buffer,
                        // which is the precondition `BufferPool::read` names —
                        // and the unconditional span check inside it is what
                        // turns a disagreement between the two into a fault
                        // here instead of an out-of-bounds read.
                        let bytes = unsafe {
                            pipeline.pool.read(
                                descriptor.buffer as usize,
                                descriptor.offset as usize,
                                descriptor.len,
                            )
                        };
                        assert_eq!(bytes.len(), descriptor.len as usize);
                    }
                    let _full = peer_free.try_enqueue(descriptor);
                }
                assert!(taken <= limit);
            }
            _ => {
                // Cursors and slots, on whichever ring the peer feels like.
                let head = any_u32(&mut unstructured);
                let tail = any_u32(&mut unstructured);
                let slot = any_u32(&mut unstructured) as usize;
                let descriptor = any_descriptor(&mut unstructured);
                let view = match any_u32(&mut unstructured) % 3 {
                    0 => &rx_view,
                    1 => &tx_view,
                    _ => &free_view,
                };
                view.set_head(head);
                view.set_tail(tail);
                view.store_slot(slot, descriptor);
            }
        }

        assert!(
            owner.owned() <= POOL_BUFFERS,
            "the ledger grew past the pool"
        );
        assert!(
            owner.owned() + held.len() <= POOL_BUFFERS,
            "free plus held exceeds the pool, so a buffer was invented"
        );
        // Counters are monotonic and saturating for the domain's life; a
        // rejection that stopped being counted would hide a byzantine peer.
        let pool_counters = owner.counters();
        let forward_counters = stage.counters();
        assert!(pool_counters.reclaim_not_lent >= previous_pool.reclaim_not_lent);
        assert!(pool_counters.reclaim_refused >= previous_pool.reclaim_refused);
        assert!(forward_counters.forwarded >= previous_forward.forwarded);
        assert!(forward_counters.dropped >= previous_forward.dropped);
        previous_pool = pool_counters;
        previous_forward = forward_counters;
    }

    // Definitive conservation, read out of the ledger: hand every token back,
    // then drain. What comes out must be pairwise distinct pool indices, each
    // resolving to an address inside the pool. A repeat here is one buffer with
    // two owners; an out-of-range index is a DMA target outside the region.
    for buffer in held {
        holding[buffer.index() as usize] = false;
        owner.release(buffer);
    }
    let mut drained = BTreeSet::new();
    // One more than the pool holds, so the loop must end on exhaustion; that is
    // asserted immediately afterwards rather than left to the bound.
    for _ in 0..=POOL_BUFFERS {
        let Some(buffer) = owner.alloc() else {
            break;
        };
        let index = buffer.index();
        assert!(
            (index as usize) < POOL_BUFFERS,
            "the ledger held index {index}"
        );
        let paddr = Pipeline::buffer_paddr(REGION_PADDR, index);
        assert!(paddr >= pool_base && paddr + BUFFER_SIZE as u64 <= pool_end);
        assert!(drained.insert(index), "index {index} was free twice");
    }
    assert_eq!(
        owner.owned(),
        0,
        "the final drain ended on its own bound rather than on an empty ledger"
    );
    assert!(drained.len() <= POOL_BUFFERS);
}
