//! Microbenchmarks for the SPSC ring hot path.
//!
//! These measure the per-operation cost of the primitive every descriptor
//! crosses on the dataplane: an uncontended enqueue/dequeue pair, and the two
//! backpressure fast paths (`try_enqueue` on a full ring, `try_dequeue` on an
//! empty one) that a spinning producer or consumer hits. They are single-core
//! measurements; cross-core throughput against the 10 Gbit/s budget belongs in
//! the QEMU/KVM forwarding regression, not here.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use queue::SpscRing;
use wire::Descriptor;

/// Enqueue one descriptor then dequeue it, keeping the ring near-empty so each
/// call takes the uncontended fast path and the pair measures a single
/// `try_enqueue` plus a single `try_dequeue`.
fn enqueue_dequeue_pair(c: &mut Criterion) {
    let ring = SpscRing::<1024>::new();
    c.bench_function("spsc_enqueue_dequeue_pair", |b| {
        b.iter(|| {
            black_box(ring.try_enqueue(black_box(Descriptor::new(1, 2, 3)))).ok();
            black_box(ring.try_dequeue());
        });
    });
}

/// `try_enqueue` against a full ring: the rejection fast path a blocked
/// producer spins on until the consumer drains a slot.
fn try_enqueue_on_full(c: &mut Criterion) {
    let ring = SpscRing::<64>::new();
    while ring.try_enqueue(Descriptor::new(0, 0, 0)).is_ok() {}
    c.bench_function("spsc_try_enqueue_on_full", |b| {
        b.iter(|| black_box(ring.try_enqueue(black_box(Descriptor::new(1, 1, 1)))));
    });
}

/// `try_dequeue` against an empty ring: the `None` fast path a starved consumer
/// spins on until the producer publishes a descriptor.
fn try_dequeue_on_empty(c: &mut Criterion) {
    let ring = SpscRing::<64>::new();
    c.bench_function("spsc_try_dequeue_on_empty", |b| {
        b.iter(|| black_box(ring.try_dequeue()));
    });
}

criterion_group!(
    benches,
    enqueue_dequeue_pair,
    try_enqueue_on_full,
    try_dequeue_on_empty
);
criterion_main!(benches);
