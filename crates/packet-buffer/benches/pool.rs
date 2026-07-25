//! Microbenchmarks for the packet buffer pool and the owner-side ownership
//! ledger.
//!
//! `write`/`write_at`/`read` are the only byte copies on the "zero-copy"
//! dataplane, so their cost is benched across representative frame sizes (64,
//! 512, 1500 bytes) to confirm they scale with payload and stay header-cheap.
//!
//! The ledger runs once per buffer per packet, so its two return paths are
//! benched separately: `push` takes an ownership token back from within the
//! domain, while `reclaim` is the trust boundary a peer's bare index crosses and
//! pays for the range and outstanding-set checks. Both are expected to stay in
//! the handful-of-cycles range; the point of the bench is to catch a regression
//! that makes validation cost real time on the per-packet path.

// Benchmark target: no public API to document (the `criterion_group!` macro
// expands to public items).
#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use packet_buffer::{BufferPool, FreeList};

/// Representative Ethernet payload sizes: a minimum frame, a mid-size frame,
/// and a near-MTU frame.
const SIZES: [usize; 3] = [64, 512, 1500];

fn buffer_pool_write(c: &mut Criterion) {
    let pool = BufferPool::<4>::new();
    let mut group = c.benchmark_group("buffer_pool_write");
    for &size in &SIZES {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            // SAFETY: single-threaded bench owns index 0 throughout; `data` is a
            // separate allocation and never borrows from the pool.
            b.iter(|| black_box(unsafe { pool.write(0, black_box(data)) }));
        });
    }
    group.finish();
}

fn buffer_pool_write_at(c: &mut Criterion) {
    let pool = BufferPool::<4>::new();
    // Offset 12 mirrors placing a virtio-net header in front of a DMA'd frame.
    const HEADER: usize = 12;
    let mut group = c.benchmark_group("buffer_pool_write_at");
    for &size in &SIZES {
        let data = vec![0xCDu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            // SAFETY: own index 0; `HEADER + size <= BUFFER_SIZE` for every
            // benched size; `data` does not borrow from the pool.
            b.iter(|| unsafe { pool.write_at(0, HEADER, black_box(data)) });
        });
    }
    group.finish();
}

fn buffer_pool_read(c: &mut Criterion) {
    let pool = BufferPool::<4>::new();
    // SAFETY: own index 0; the payload fits in BUFFER_SIZE.
    unsafe { pool.write(0, &[0xEFu8; 1500]) }.expect("1500 bytes fit a buffer");
    let mut group = c.benchmark_group("buffer_pool_read");
    for &size in &SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            // SAFETY: own index 0; `offset + len <= BUFFER_SIZE`.
            b.iter(|| black_box(unsafe { pool.read(0, 0, black_box(size as u32)) }));
        });
    }
    group.finish();
}

fn free_list_pop_push(c: &mut Criterion) {
    // The in-domain cycle: take a buffer and give the same token straight back,
    // leaving the ledger exactly as it started for the next iteration.
    let mut list = FreeList::<64>::full();
    c.bench_function("free_list_pop_push", |b| {
        b.iter(|| {
            let buffer = list.pop().expect("the ledger is restored every iteration");
            black_box(list.push(black_box(buffer))).expect("the buffer was just taken out");
        });
    });
}

fn free_list_pop_reclaim(c: &mut Criterion) {
    // The cross-domain cycle: the index leaves as a token, comes back as a bare
    // number, and pays the trust boundary's validation on the way in.
    let mut list = FreeList::<64>::full();
    c.bench_function("free_list_pop_reclaim", |b| {
        b.iter(|| {
            let index = list
                .pop()
                .expect("the ledger is restored every iteration")
                .index();
            black_box(list.reclaim(black_box(index))).expect("the buffer is outstanding");
        });
    });
}

criterion_group!(
    benches,
    buffer_pool_write,
    buffer_pool_write_at,
    buffer_pool_read,
    free_list_pop_push,
    free_list_pop_reclaim
);
criterion_main!(benches);
