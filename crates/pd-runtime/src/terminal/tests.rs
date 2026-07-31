use super::*;
use crate::{BUFFER_SIZE, Descriptor, POOL_BUFFERS, PoolOwner, Ring, Verdict};
use proptest::prelude::*;
use std::boxed::Box;
use std::vec;
use std::vec::Vec;

/// Where a received frame sits: the device's own 12-byte header occupies the
/// front of the buffer, exactly as `nic_driver_core::RxPath::drain` publishes it.
const DEVICE_HEADER_LEN: u32 = 12;

/// A frame length that fits behind that header.
const FRAME_LEN: u32 = 64;

/// One pipeline's regions and the two roles that face each other across it,
/// allocated the way protection domains are handed them: separate mappings that
/// share nothing, leaked so both roles borrow them for `'static`. Every handle
/// is taken once for the fixture's life, because a second restarts at slot zero.
struct Fixture {
    /// The driver that owns the pool: it lends buffers onto `rx` and consumes
    /// the returns this stage produces.
    owner: PoolOwner<'static>,
    /// The driver's `rx` producer handle.
    publish: RingProducer<'static, RING_SLOTS>,
    stage: TerminalStage<'static>,
}

impl Fixture {
    fn new() -> Self {
        let rings: &'static ForwardRings = Box::leak(Box::new(ForwardRings::new()));
        let returns: &'static ReturnRing = Box::leak(Box::new(ReturnRing::new()));
        Self {
            owner: PoolOwner::attach(returns),
            publish: rings.rx.producer(),
            stage: TerminalStage::attach(rings, returns),
        }
    }

    /// Stand in for the receiving driver: take a buffer and publish `len` bytes
    /// of it at the offset a virtio-net header leaves free. Answers the index
    /// published, or `None` when the pool is momentarily empty.
    fn receive(&mut self, len: u32) -> Option<u32> {
        let buffer = self.owner.alloc()?;
        let index = buffer.index();
        self.owner
            .lend(
                &mut self.publish,
                buffer,
                DEVICE_HEADER_LEN,
                len,
                Verdict::Transmit,
            )
            .ok()?;
        Some(index)
    }

    /// Publish a descriptor no correct driver would produce, as a byzantine one
    /// can at any moment: the ring is shared read-write.
    fn publish_raw(&mut self, descriptor: Descriptor) -> bool {
        self.publish.try_enqueue(descriptor).is_ok()
    }
}

#[test]
fn a_fresh_stage_has_seen_nothing_and_an_empty_pipeline_leaves_it_that_way() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.stage.counters(), TerminalCounters::default());
    assert_eq!(fixture.stage.poll(), 0);
    assert_eq!(fixture.stage.counters(), TerminalCounters::default());
}

/// The whole cycle, which is the property a terminal port rests on: a frame the
/// driver lends is counted here and its buffer reaches that driver's own ledger
/// again, so the pool neither shrinks nor ends up double-owned.
#[test]
fn a_received_frame_is_counted_and_its_buffer_returned_to_the_owner() {
    let mut fixture = Fixture::new();
    let full = fixture.owner.owned();
    fixture.receive(FRAME_LEN).expect("the pool starts full");
    assert_eq!(fixture.owner.owned(), full - 1, "the buffer is lent");

    assert_eq!(fixture.stage.poll(), 1);
    assert_eq!(
        fixture.stage.counters(),
        TerminalCounters {
            frames: 1,
            bytes: u64::from(FRAME_LEN),
            ..TerminalCounters::default()
        }
    );

    assert_eq!(fixture.owner.reclaim(), 1);
    assert_eq!(fixture.owner.owned(), full, "the buffer is back");
    assert_eq!(fixture.owner.counters(), crate::PoolCounters::default());
}

/// The port runs indefinitely on a pool of [`POOL_BUFFERS`], which it can only
/// do if every buffer really does come back: more frames than the pool holds,
/// through one stage, with the owner reclaiming as a driver does.
#[test]
fn a_pool_sized_run_never_runs_the_owner_out_of_buffers() {
    let mut fixture = Fixture::new();
    let full = fixture.owner.owned();
    for _ in 0..POOL_BUFFERS * 4 {
        fixture.receive(FRAME_LEN).expect("a buffer is always free");
        assert_eq!(fixture.stage.poll(), 1);
        assert_eq!(fixture.owner.reclaim(), 1);
    }
    assert_eq!(fixture.owner.owned(), full);
    assert_eq!(fixture.stage.counters().frames, (POOL_BUFFERS * 4) as u64);
    assert_eq!(fixture.owner.counters(), crate::PoolCounters::default());
}

/// `bytes` is a sum and not a multiple of one length, which a fixed-size probe
/// could never tell apart.
#[test]
fn the_byte_total_is_the_sum_of_the_lengths_the_driver_published() {
    let mut fixture = Fixture::new();
    let lengths = [
        1u32,
        60,
        64,
        100,
        128,
        (BUFFER_SIZE as u32) - DEVICE_HEADER_LEN,
    ];
    for len in lengths {
        fixture.receive(len).expect("the pool holds six");
    }
    assert_eq!(fixture.stage.poll(), lengths.len());
    let counters = fixture.stage.counters();
    assert_eq!(counters.frames, lengths.len() as u64);
    assert_eq!(
        counters.bytes,
        lengths.iter().copied().map(u64::from).sum::<u64>()
    );
    assert_eq!(counters.malformed_descriptor, 0);
}

/// A drain answers with frames rather than descriptors, so a pass that moved
/// nothing but rubbish reports nothing new — which is what keeps a caller from
/// announcing a count that did not change.
#[test]
fn a_pass_that_moved_only_malformed_descriptors_counts_no_frame_and_no_byte() {
    let mut fixture = Fixture::new();
    let malformed = malformed_descriptors();
    for descriptor in &malformed {
        assert!(fixture.publish_raw(*descriptor));
    }
    assert_eq!(fixture.stage.poll(), 0);
    let counters = fixture.stage.counters();
    assert_eq!(counters.frames, 0);
    assert_eq!(counters.bytes, 0, "no unbelievable span reaches the total");
    assert_eq!(counters.malformed_descriptor, malformed.len() as u64);
}

/// Every one of them is nevertheless handed back, and the owner is what judges
/// the index: a forged one is refused there and counted as the forgery it is,
/// rather than being silently believed here or silently withheld.
#[test]
fn a_malformed_descriptor_is_still_returned_and_the_owner_judges_its_index() {
    let mut fixture = Fixture::new();
    let full = fixture.owner.owned();
    assert!(fixture.publish_raw(Descriptor::new(
        POOL_BUFFERS as u32,
        0,
        1,
        Verdict::Transmit,
    )));
    assert_eq!(fixture.stage.poll(), 0);
    assert_eq!(fixture.stage.counters().malformed_descriptor, 1);

    assert_eq!(fixture.owner.reclaim(), 0);
    assert_eq!(fixture.owner.counters().reclaim_not_lent, 1);
    assert_eq!(fixture.owner.owned(), full);
}

/// A real, lent buffer whose *span* the peer got wrong is recovered rather than
/// stranded: the index is good, so the return is legitimate and the owner takes
/// it, while the length is not counted.
#[test]
fn a_lent_buffer_with_an_unbelievable_span_is_recovered_and_its_length_ignored() {
    let mut fixture = Fixture::new();
    let full = fixture.owner.owned();
    let lent = fixture.receive(FRAME_LEN).expect("the pool starts full");
    // The driver's own descriptor is dropped unread, and a second one naming
    // the same lent index with a span off the end of the buffer takes its place
    // — which is exactly the edit a byzantine driver makes in the shared ring.
    let _ = fixture.stage.poll();
    assert_eq!(fixture.owner.reclaim(), 1);
    assert_eq!(fixture.owner.owned(), full);

    let index = fixture.receive(FRAME_LEN).expect("a buffer is free");
    assert!(fixture.publish_raw(Descriptor::new(
        index,
        DEVICE_HEADER_LEN,
        BUFFER_SIZE as u32,
        Verdict::Transmit,
    )));
    // Two descriptors now name the one lent buffer: the driver's and the forged
    // one. The stage counts one frame and one malformed span, and produces two
    // returns — of which the owner accepts exactly one, the second naming a
    // buffer it no longer has lent.
    assert_eq!(fixture.stage.poll(), 1);
    assert_eq!(fixture.stage.counters().malformed_descriptor, 1);
    assert_eq!(fixture.owner.reclaim(), 1);
    assert_eq!(fixture.owner.counters().reclaim_not_lent, 1);
    assert_eq!(fixture.owner.owned(), full);
    assert_ne!(lent, u32::MAX);
}

/// The residue this role shares with every other: a peer that stops reclaiming
/// fills the return ring, and the response is a count and a stop rather than a
/// fault or an unbounded loop.
#[test]
fn a_full_return_ring_stops_the_drain_and_is_counted() {
    let rings: &ForwardRings = &ForwardRings::new();
    let returns: &ReturnRing = &ReturnRing::new();
    let mut stage = TerminalStage::attach(rings, returns);
    let mut publish = rings.rx.producer();
    let frame = |index: u32| {
        Descriptor::new(
            index % POOL_BUFFERS as u32,
            DEVICE_HEADER_LEN,
            FRAME_LEN,
            Verdict::Transmit,
        )
    };

    // Fill the ingress ring to capacity and drain it with nobody reclaiming, so
    // the return ring ends the pass exactly full — the state a driver that has
    // stopped taking its buffers back leaves it in. Both rings hold one below
    // their slot count, so this fills the second precisely.
    let mut published = 0u32;
    while publish.try_enqueue(frame(published)).is_ok() {
        published += 1;
    }
    assert_eq!(stage.poll(), published as usize);
    assert_eq!(stage.counters().return_ring_full, 0);

    // Two more frames arrive and neither buffer has anywhere to go. The first
    // is still counted — it did arrive — and its refused return ends the pass,
    // so the second is not dequeued into a ring that cannot take it either.
    for index in 0..2 {
        publish
            .try_enqueue(frame(index))
            .expect("the ingress ring was just drained");
    }
    assert_eq!(stage.poll(), 1);
    let counters = stage.counters();
    assert_eq!(counters.return_ring_full, 1);
    assert_eq!(counters.frames, u64::from(published) + 1);
    assert_eq!(counters.malformed_descriptor, 0);

    // What stopping bought: at most one buffer is stranded per pass, so the
    // second frame is still on the ingress ring when the next one runs. It is
    // counted then and stranded in its turn, one at a time, for as long as the
    // owner stays stalled — never a whole ring's worth at once.
    assert_eq!(stage.poll(), 1);
    let counters = stage.counters();
    assert_eq!(counters.return_ring_full, 2);
    assert_eq!(counters.frames, u64::from(published) + 2);
    assert_eq!(stage.poll(), 0, "and now the ingress ring is empty");
}

/// Descriptors a byzantine driver can publish that name no span inside a pool
/// buffer: a forged index, a span that runs off the end, and one whose offset
/// and length sum past what a `u32` holds.
fn malformed_descriptors() -> Vec<Descriptor> {
    vec![
        Descriptor::new(POOL_BUFFERS as u32, 0, 1, Verdict::Transmit),
        Descriptor::new(u32::MAX, 0, 1, Verdict::Transmit),
        Descriptor::new(0, 0, (BUFFER_SIZE as u32) + 1, Verdict::Transmit),
        Descriptor::new(0, BUFFER_SIZE as u32, 1, Verdict::Transmit),
        Descriptor::new(0, u32::MAX, u32::MAX, Verdict::Transmit),
    ]
}

/// Overwrite a ring's shared cursors the way a byzantine peer that maps the
/// region read-write can at any moment. The cursors are private to `queue`, so
/// reach them through the region's known ABI: `head` then `tail`, both `u32`, at
/// the ring's front (pinned by that crate's own layout asserts).
fn forge_cursors(ring: &Ring, head: u32, tail: u32) {
    use core::sync::atomic::{AtomicU32, Ordering};
    let base = core::ptr::from_ref(ring).cast::<AtomicU32>();
    // SAFETY: `SpscRing` is `#[repr(C)]` with `head` at offset 0 and `tail` at
    // offset 4 as `AtomicU32`s (asserted in `queue`), so both pointers are in
    // bounds and correctly aligned for the live ring borrowed here. Atomic
    // stores are exactly what a peer domain performs on these words.
    unsafe {
        (*base).store(head, Ordering::Relaxed);
        (*base.add(1)).store(tail, Ordering::Relaxed);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// A byzantine driver driving the stage: arbitrary descriptors and, between
    /// passes, arbitrary cursors. No pass may panic, each is bounded by this
    /// crate's own [`DRAIN_LIMIT`] rather than by anything the peer published,
    /// every counter is monotonic, and a counted frame may add at most one
    /// buffer's worth of bytes to the total — so a forged span cannot inflate a
    /// number an operator reads.
    #[test]
    fn every_pass_is_bounded_and_counts_only_believable_lengths(
        descriptors in prop::collection::vec(
            (any::<u32>(), any::<u32>(), any::<u32>(), any::<u32>()),
            0..200,
        ),
        forged in prop::collection::vec((any::<u32>(), any::<u32>()), 0..8),
    ) {
        let rings: &ForwardRings = &ForwardRings::new();
        let returns: &ReturnRing = &ReturnRing::new();
        let mut stage = TerminalStage::attach(rings, returns);
        let mut publish = rings.rx.producer();
        // The owner's end, drained every pass so the stage meets a peer that
        // keeps up as well as one that does not.
        let mut reclaim = returns.free.consumer();

        let mut previous = TerminalCounters::default();
        for (buffer, offset, len, verdict) in descriptors {
            // A full ring is one of the states under test, so a refused enqueue
            // is part of the scenario rather than a failure.
            let _ring_may_be_full = publish.try_enqueue(Descriptor {
                buffer,
                offset,
                len,
                verdict,
            });
            let frames = stage.poll();
            let counters = stage.counters();

            prop_assert!(frames <= DRAIN_LIMIT);
            prop_assert!(counters.frames >= previous.frames);
            prop_assert!(counters.bytes >= previous.bytes);
            prop_assert!(counters.malformed_descriptor >= previous.malformed_descriptor);
            prop_assert!(counters.return_ring_full >= previous.return_ring_full);

            let counted = counters.frames - previous.frames;
            prop_assert_eq!(counted, frames as u64);
            prop_assert!(counters.bytes - previous.bytes <= counted * BUFFER_SIZE as u64);
            previous = counters;

            let returned = reclaim.drain(DRAIN_LIMIT).count();
            prop_assert!(returned <= DRAIN_LIMIT);
        }

        for (head, tail) in forged {
            forge_cursors(&rings.rx, head, tail);
            prop_assert!(stage.poll() <= DRAIN_LIMIT);
        }
    }
}
