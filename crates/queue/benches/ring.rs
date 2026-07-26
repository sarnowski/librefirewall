//! Microbenchmarks for the SPSC ring hot path.
//!
//! These measure the per-operation cost of the primitive every descriptor
//! crosses on the dataplane: an uncontended enqueue/dequeue pair, a bounded
//! batch drain, and the two backpressure fast paths (`try_enqueue` on a full
//! ring, `try_dequeue` on an empty one) that a spinning producer or consumer
//! hits. They are single-core measurements; cross-core throughput against the
//! 10 Gbit/s budget belongs in the QEMU/KVM forwarding regression, not here.
//!
//! Every measured call asserts its outcome. A benchmark that silently accepted
//! a rejection would report the cost of the rejection path under the name of the
//! path it claims to measure, which is worse than no number at all.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use queue::SpscRing;
use wire::Descriptor;

/// Enqueue one descriptor then dequeue it, keeping the ring near-empty so each
/// call takes the uncontended fast path and the pair measures a single
/// `try_enqueue` plus a single `try_dequeue`.
fn enqueue_dequeue_pair(c: &mut Criterion) {
    let ring = SpscRing::<1024>::new();
    let mut producer = ring.producer();
    let mut consumer = ring.consumer();
    c.bench_function("spsc_enqueue_dequeue_pair", |b| {
        b.iter(|| {
            // Both outcomes are asserted so the pair cannot drift into measuring
            // backpressure: a rejected enqueue would mean the ring never drained,
            // and a `None` dequeue would mean it is filling up.
            black_box(producer.try_enqueue(black_box(Descriptor::new(1, 2, 3))))
                .expect("the ring is drained every iteration, so it is never full");
            assert!(
                black_box(consumer.try_dequeue()).is_some(),
                "the descriptor enqueued this iteration must come straight back"
            );
        });
    });
}

/// A bounded batch drain, the shape a consumer protection domain uses per
/// scheduling round: the per-descriptor cost when the ring is kept full enough
/// that the limit, not emptiness, ends the iteration.
fn drain_batch(c: &mut Criterion) {
    const BATCH: usize = 32;
    let ring = SpscRing::<1024>::new();
    let mut producer = ring.producer();
    let mut consumer = ring.consumer();
    c.bench_function("spsc_drain_batch_32", |b| {
        b.iter(|| {
            for i in 0..BATCH as u32 {
                producer
                    .try_enqueue(black_box(Descriptor::new(i, 0, i)))
                    .expect("the batch is far smaller than the ring");
            }
            assert_eq!(black_box(consumer.drain(BATCH)).count(), BATCH);
        });
    });
}

/// `try_enqueue` against a full ring: the rejection fast path a blocked
/// producer spins on until the consumer drains a slot.
fn try_enqueue_on_full(c: &mut Criterion) {
    let ring = SpscRing::<64>::new();
    let mut producer = ring.producer();
    while producer.try_enqueue(Descriptor::new(0, 0, 0)).is_ok() {}
    c.bench_function("spsc_try_enqueue_on_full", |b| {
        b.iter(|| {
            assert!(
                black_box(producer.try_enqueue(black_box(Descriptor::new(1, 1, 1)))).is_err(),
                "the ring was filled before the measurement and nothing drains it"
            );
        });
    });
}

/// `try_dequeue` against an empty ring: the `None` fast path a starved consumer
/// spins on until the producer publishes a descriptor.
fn try_dequeue_on_empty(c: &mut Criterion) {
    let ring = SpscRing::<64>::new();
    let mut consumer = ring.consumer();
    c.bench_function("spsc_try_dequeue_on_empty", |b| {
        b.iter(|| {
            assert!(
                black_box(consumer.try_dequeue()).is_none(),
                "nothing is ever enqueued on this ring"
            );
        });
    });
}

criterion_group!(
    benches,
    enqueue_dequeue_pair,
    drain_batch,
    try_enqueue_on_full,
    try_dequeue_on_empty
);
criterion_main!(benches);
