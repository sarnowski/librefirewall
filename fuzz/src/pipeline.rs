//! `pd_runtime` under a byzantine neighbour PD.
//!
//! # The adversary and the surface
//!
//! `pd_runtime` is the inter-PD protocol itself, so this is where "what one
//! protection domain must withstand from another" is defined.
//! The peer this harness plays is the transmitting driver, which maps every
//! region under test read-write — both cursors of all three rings, every slot,
//! and the pool bytes — and the two mechanisms that stop that from becoming a
//! double-owned buffer are `PoolOwner`'s *lent* set and `packet_buffer`'s
//! ledger beneath it.
//!
//! The forwarder is granted less than this harness gives its peer: it maps the
//! pool and both rings of a pipeline, and neither `free` ring. That is a
//! property of the system description, not of `pd_runtime`, so this harness
//! keeps modelling the *widest* peer any region has — narrowing it to what one
//! domain happens to map would delete adversary authority the protocol must
//! still withstand.
//!
//! The worst outcome this guards is not a crash. It is a forged index reaching
//! the free stack, being handed back out by `alloc`, and turned into a physical
//! address by `buffer_paddr` — a DMA target **outside the pool region**, which
//! with no IOMMU is an arbitrary physical-memory write. This harness asserts
//! the containment of that address explicitly rather than inferring it from the
//! absence of a crash.
//!
//! # Roles
//!
//! Exactly one handle per ring end, as the crate requires; a second handle
//! would restart at slot zero and prove nothing:
//!
//! | ring | producer | consumer |
//! |---|---|---|
//! | `rx` | the rx driver — under test, through `PoolOwner::lend` | the forwarder — under test, inside `RouteStage` |
//! | `tx` | the forwarder — under test, inside `RouteStage` | the tx driver — **the adversary** |
//! | `free` | the tx driver — **the adversary** | the rx driver — under test, inside `PoolOwner` |
//!
//! # What the adversary may express here
//!
//! Arbitrary descriptors on the `free` ring — forged indices, indices never
//! lent, duplicates of a return already accepted, indices this domain still
//! holds posted to its own NIC — arbitrary cursors on every ring, and arbitrary
//! slot contents on the rings this side consumes, **verdict word included**:
//! it is one more shared `u32`, and the values it may hold are not confined to
//! the two a `Verdict` encodes. The spans a lend publishes are arbitrary too,
//! because from `RouteStage`'s point of view the rx driver is itself a peer;
//! its *verdict* is not, because `PoolOwner::lend` takes a `Verdict` and so a
//! first-party producer can only publish one of the two — which is the point of
//! the type, and why the undecodable case arrives here by a peer slot store.
//!
//! The **frame bytes** are the adversary's too, and they are now interpreted:
//! `RouteStage` parses every buffer it is handed and rewrites the ones it
//! forwards. This harness therefore writes arbitrary bytes over pool buffers at
//! arbitrary moments — including between a snapshot and the transmit that
//! follows it — because every domain mapping the pool can, and because a
//! harness that only ever placed well-formed frames would exercise the parser
//! on the one input shape it was written for.
//!
//! # What is asserted
//!
//! * **Containment.** Every index `alloc` hands out is a pool index, and the
//!   physical address `buffer_paddr` derives from it lies wholly inside the
//!   pool. This is the arbitrary-physical-write invariant, stated directly.
//! * **No double ownership.** `alloc` never hands out an index this side is
//!   already holding, and the final drain of the ledger yields pairwise
//!   distinct indices — no buffer invented, none free twice.
//! * **Bounded work.** `PoolOwner::reclaim` and `RouteStage::poll` each move
//!   at most `DRAIN_LIMIT` descriptors per call, whatever cursor the peer
//!   publishes.
//! * **The delegated precondition terminates, and its two ends agree.**
//!   `descriptor_in_bounds` is the component `packet_buffer`'s accessors name
//!   as the enforcer for a peer-supplied span, and
//!   `copy_out` re-checks that span itself. Every descriptor reaching the tx
//!   side is put to *both*, and their verdicts asserted equal — in both
//!   directions, which is why the copy is attempted even for a span the
//!   validator rejects. A guard that passes what the accessor refuses, or
//!   refuses what it would have served, surfaces as a fault rather than as a
//!   comment nobody checked.
//! * **Counters only ever rise**, so a rejection is never silently un-counted.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use arbitrary::Unstructured;
use net_headers::{Ipv4Address, MacAddress, ParseFailure};
use packet_buffer::CopyOutError;
use pd_runtime::{
    BUFFER_SIZE, Configuration, DRAIN_LIMIT, Descriptor, ForwardRings, OwnedBuffer, POOL_BUFFERS,
    Pool, PoolOwner, RING_SLOTS, ReturnRing, RouteStage, Verdict, attach_region, buffer_paddr,
    descriptor_in_bounds,
};
use routing::{Interface, Neighbour, PortId, Router};

use crate::region::ZeroedRegion;
use crate::ring_abi::PeerView;
use crate::{MAX_OPERATIONS, any_index, any_u32, next_op};

/// Physical address the pool region is mapped at. Page-aligned, as Microkit
/// guarantees, because the pool's own DMA-alignment argument rests on it.
const POOL_PADDR: u64 = 0x3100_0000;

const PORT0: PortId = PortId(0);
const PORT1: PortId = PortId(1);

/// The generation the table below is attributed to. The configuration is the
/// forwarder's own and reaches the stage per poll, so it is not something this
/// peer can express; the number is fixed here for that reason.
const GENERATION: u32 = 1;

/// A two-port topology of the shape the appliance is configured into at run
/// time. The routing decision is not
/// what this harness is aimed at — `routing` is total over every header by its
/// own property tests — but it must be the real table, or the frames the
/// adversary happens to produce would be judged against a topology nothing
/// runs.
static ROUTER: LazyLock<Router<2, 2>> = LazyLock::new(|| {
    Router::from_slices(
        &[
            Interface {
                port: PORT0,
                mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]),
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
                prefix_length: 24,
                enabled: true,
            },
            Interface {
                port: PORT1,
                mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x51]),
                address: Ipv4Address::from_octets([10, 0, 1, 1]),
                prefix_length: 24,
                enabled: true,
            },
        ],
        &[
            Neighbour {
                port: PORT0,
                address: Ipv4Address::from_octets([10, 0, 0, 2]),
                mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0a]),
            },
            Neighbour {
                port: PORT1,
                address: Ipv4Address::from_octets([10, 0, 1, 2]),
                mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0b]),
            },
        ],
    )
    .expect("two of each fit in two")
});

/// One descriptor whose four fields the peer chose freely — a field-wise
/// literal and not `Descriptor::new`, whose `Verdict` argument would confine
/// the one word this harness must be able to make undecodable.
fn any_descriptor(unstructured: &mut Unstructured<'_>) -> Descriptor {
    Descriptor {
        buffer: any_u32(unstructured),
        offset: any_u32(unstructured),
        len: any_u32(unstructured),
        verdict: any_u32(unstructured),
    }
}

/// Either verdict a first-party producer can publish; see the module header on
/// why the undecodable word does not come from here.
fn any_verdict(unstructured: &mut Unstructured<'_>) -> Verdict {
    if any_u32(unstructured) & 1 == 0 {
        Verdict::Transmit
    } else {
        Verdict::Discard
    }
}

/// Drive the pool ownership protocol and the forwarding stage against a peer
/// that owns the `free` ring and every shared word in the region.
pub fn pipeline_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    // The three regions a pipeline is granted as, separately allocated exactly
    // as Microkit maps them: nothing here places them adjacently, so a harness
    // that accidentally reached past one region's end would fault rather than
    // land in another.
    let pool_region = ZeroedRegion::<Pool>::new();
    let rings_region = ZeroedRegion::<ForwardRings>::new();
    let returns_region = ZeroedRegion::<ReturnRing>::new();
    // SAFETY: each is a live, zeroed allocation of exactly its region type,
    // aligned by `Layout::new`, outliving every handle taken below, and `Sync`
    // with no safe path to its bytes — `attach_region`'s contract in full. No
    // `&mut` is ever created to any of them: the borrows returned here are
    // shared, and every mutation goes through an atomic or an `UnsafeCell`
    // accessor.
    let pool: &Pool = unsafe { attach_region(pool_region.as_ptr()) };
    // SAFETY: as above, for the forwarder's region.
    let rings: &ForwardRings = unsafe { attach_region(rings_region.as_ptr()) };
    // SAFETY: as above, for the return region.
    let returns: &ReturnRing = unsafe { attach_region(returns_region.as_ptr()) };

    let mut owner = PoolOwner::attach(returns);
    let mut rx_producer = rings.rx.producer();
    let mut stage = RouteStage::attach(rings, pool, PORT0, PORT1);
    let mut peer_free = returns.free.producer();
    let mut peer_tx = rings.tx.consumer();
    let rx_view = PeerView::<RING_SLOTS>::new(&rings.rx);
    let tx_view = PeerView::<RING_SLOTS>::new(&rings.tx);
    let free_view = PeerView::<RING_SLOTS>::new(&returns.free);

    let pool_base = POOL_PADDR;
    let pool_end = pool_base + (POOL_BUFFERS * BUFFER_SIZE) as u64;

    let mut held: Vec<OwnedBuffer<POOL_BUFFERS>> = Vec::new();
    let mut holding = [false; POOL_BUFFERS];
    let mut previous_pool = owner.counters();
    let mut previous_route = stage.counters();

    for _ in 0..MAX_OPERATIONS {
        let Some(op) = next_op(&mut unstructured) else {
            break;
        };
        match op % 10 {
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
                    let paddr = buffer_paddr(POOL_PADDR, index);
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
                let verdict = any_verdict(&mut unstructured);
                match owner.lend(&mut rx_producer, buffer, offset, len, verdict) {
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
                let handed_on = stage.poll(Configuration::new(GENERATION, &ROUTER), None);
                assert!(
                    handed_on <= DRAIN_LIMIT,
                    "the forwarder handed on {handed_on} descriptors, past the {DRAIN_LIMIT} bound"
                );
            }
            // The trust boundary: a return of the peer's choosing. Half the
            // stream is biased into the pool's index range so duplicates and
            // returns of still-held buffers come up often; the other half is a
            // wholly unreduced descriptor.
            5 | 6 => {
                let mut descriptor = any_descriptor(&mut unstructured);
                if op % 10 == 6 {
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
                // Sized at one whole buffer, which is what makes the two
                // verdicts below comparable at all: a destination this size
                // cannot be the reason `copy_out` refuses an in-bounds span,
                // since `descriptor_in_bounds` has already bounded `len` to
                // `BUFFER_SIZE`. Any `DestinationTooSmall` is therefore a
                // defect in this harness's own sizing, and is asserted as one
                // rather than folded in with the span verdict.
                let mut storage = [0u8; BUFFER_SIZE];
                for descriptor in drained {
                    taken += 1;
                    // `descriptor_in_bounds` is the enforcer `packet_buffer`
                    // names for a peer-supplied span, and
                    // `copy_out` re-checks that same span unconditionally. Both
                    // rule on the identical question over the identical pool —
                    // `Pool` is `BufferPool<POOL_BUFFERS>`, the very bound the
                    // validator tests — so their verdicts must agree exactly,
                    // and the copy is attempted for every descriptor rather
                    // than only the ones that pass, or the disagreement this
                    // asserts could never be observed in one direction.
                    //
                    // A disagreement is a defect in one of the two, never a
                    // peer's doing: a span the validator passes and the
                    // accessor refuses means the guard does not guard what it
                    // claims, and the converse means the validator rejects
                    // frames the pool would have served. Neither is untrusted
                    // input, so both fail here instead of being counted.
                    let in_bounds = descriptor_in_bounds(&descriptor);
                    // SAFETY: this side dequeued the descriptor, so by the ring
                    // protocol it owns the buffer until it returns it below.
                    // The snapshot lands in this harness's own `storage`, so
                    // nothing borrows the pool and the call is sound for an
                    // out-of-bounds span too — which is what lets it be made
                    // unconditionally, as the assertion requires.
                    let snapshot = unsafe {
                        pool.copy_out(
                            descriptor.buffer as usize,
                            descriptor.offset as usize,
                            descriptor.len,
                            &mut storage,
                        )
                    };
                    match snapshot {
                        Ok(bytes) => {
                            assert!(
                                in_bounds,
                                "copy_out accepted buffer {} span {}..+{}, which \
                                 descriptor_in_bounds refused",
                                descriptor.buffer, descriptor.offset, descriptor.len
                            );
                            assert_eq!(
                                bytes.len(),
                                descriptor.len as usize,
                                "copy_out filled a prefix of a length other than the one asked for"
                            );
                        }
                        Err(CopyOutError::SpanOutsideBuffer { .. }) => {
                            assert!(
                                !in_bounds,
                                "descriptor_in_bounds passed buffer {} span {}..+{}, which \
                                 copy_out refused as outside the buffer",
                                descriptor.buffer, descriptor.offset, descriptor.len
                            );
                        }
                        Err(error @ CopyOutError::DestinationTooSmall { .. }) => {
                            panic!(
                                "{error}: storage is a whole buffer, so no in-bounds span exceeds it"
                            )
                        }
                    }
                    let _full = peer_free.try_enqueue(descriptor);
                }
                assert!(taken <= limit);
            }
            8 => {
                // The pool bytes, which every domain mapping the region may
                // rewrite at any instant — this one included, between the
                // stage's snapshot and the transmit that follows it. A frame
                // the stage decided on is not the frame that leaves.
                let index = any_u32(&mut unstructured) as usize % POOL_BUFFERS;
                let offset = any_u32(&mut unstructured) as usize % BUFFER_SIZE;
                let byte = any_u32(&mut unstructured) as u8;
                let len = any_u32(&mut unstructured) as usize % (BUFFER_SIZE + 1);
                // SAFETY: `write_at`'s ownership clause is exactly the one a
                // byzantine peer disregards, which is what this step is; the
                // source is a local and cannot alias the pool, and the span is
                // the accessor's own business — it bounds it unconditionally
                // and answers in its return value rather than faulting.
                let _refused = unsafe { pool.write_at(index, offset, &vec![byte; len]) };
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
        let route_counters = stage.counters();
        assert!(pool_counters.reclaim_not_lent >= previous_pool.reclaim_not_lent);
        assert!(pool_counters.reclaim_refused >= previous_pool.reclaim_refused);
        assert!(route_counters.forwarded >= previous_route.forwarded);
        assert!(route_counters.egress_full >= previous_route.egress_full);
        assert!(route_counters.malformed_descriptor >= previous_route.malformed_descriptor);
        assert!(route_counters.snapshot_failed >= previous_route.snapshot_failed);
        // Per class, not merely in total: a split that lost a class would keep
        // the total rising while one label stopped moving.
        for failure in ParseFailure::ALL {
            assert!(
                route_counters.unparsable.get(failure) >= previous_route.unparsable.get(failure),
                "the {failure} count fell"
            );
        }
        assert!(route_counters.misrouted >= previous_route.misrouted);
        assert!(route_counters.writeback_failed >= previous_route.writeback_failed);
        assert!(route_counters.drops.total() >= previous_route.drops.total());
        previous_pool = pool_counters;
        previous_route = route_counters;
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
        let paddr = buffer_paddr(POOL_PADDR, index);
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
