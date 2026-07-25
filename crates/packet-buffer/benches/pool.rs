//! Microbenchmarks for the packet buffer pool and the owner-side free list.
//!
//! `write`/`write_at`/`read` are the only byte copies on the "zero-copy"
//! dataplane, so their cost is benched across representative frame sizes (64,
//! 512, 1500 bytes) to confirm they scale with payload and stay header-cheap.
//! `FreeList::push`/`pop` are the per-buffer ownership bookkeeping and are
//! expected to be near-free; the bench exists to catch a regression if
//! validation logic is ever added.

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
    unsafe {
        let _ = pool.write(0, &[0xEFu8; 1500]);
    }
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

fn free_list_push_pop(c: &mut Criterion) {
    let mut list = FreeList::<64>::empty();
    c.bench_function("free_list_push_pop", |b| {
        b.iter(|| {
            black_box(list.push(black_box(7)));
            black_box(list.pop());
        });
    });
}

criterion_group!(
    benches,
    buffer_pool_write,
    buffer_pool_write_at,
    buffer_pool_read,
    free_list_push_pop
);
criterion_main!(benches);
