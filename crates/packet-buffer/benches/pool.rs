//! Microbenchmarks for the packet buffer pool and the owner-side ownership
//! ledger.
//!
//! `write`/`write_at`/`copy_out` are the only byte copies on the "zero-copy"
//! dataplane, so their cost is benched across representative frame sizes (64,
//! 512, 1500 bytes) to confirm they scale with payload and stay header-cheap.
//!
//! The ledger runs once per buffer per packet, so its two return paths are
//! benched separately: `push` takes an ownership token back from within the
//! domain, while `reclaim` is the trust boundary a peer's bare index crosses and
//! pays for the range and outstanding-set checks. Both are expected to stay in
//! the handful-of-cycles range; the point of the bench is to catch a regression
//! that makes validation cost real time on the per-packet path.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use packet_buffer::{BUFFER_SIZE, BufferPool, FreeList};

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
            // SAFETY: `write`'s two clauses. `pool` is constructed in this
            // function and handed to nothing else, so index 0 is owned here;
            // `data` is a separate `Vec` and so cannot borrow from the pool.
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
            // SAFETY: `write_at`'s two clauses. `pool` is constructed in this
            // function and handed to nothing else, so index 0 is owned here;
            // `data` is a separate `Vec` and so cannot borrow from the pool.
            // (`HEADER + size` stays inside `BUFFER_SIZE` for every benched
            // size, which keeps the `# Panics` assert quiet — not a soundness
            // clause: `write_at` checks that span itself.)
            b.iter(|| unsafe { pool.write_at(0, HEADER, black_box(data)) });
        });
    }
    group.finish();
}

fn buffer_pool_copy_out(c: &mut Criterion) {
    let pool = BufferPool::<4>::new();
    // SAFETY: `write`'s two clauses. `pool` is local to this function, so index
    // 0 is owned here, and the literal is not a borrow from the pool.
    unsafe { pool.write(0, &[0xEFu8; 1500]) }.expect("1500 bytes fit a buffer");
    let mut group = c.benchmark_group("buffer_pool_copy_out");
    for &size in &SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            // The destination is the caller's to provide, so it is allocated
            // once here rather than inside `iter`: a per-iteration buffer would
            // put its zeroing — which grows with the benched size — inside the
            // measurement and report it as copy cost.
            let mut storage = [0u8; BUFFER_SIZE];
            b.iter(|| {
                // SAFETY: `copy_out`'s one clause is ownership of the index,
                // and `pool` is local to this function, so index 0 is owned
                // here. The span is not a soundness clause — `copy_out` bounds
                // it itself and returns `SpanOutsideBuffer` — which is why the
                // returned slice borrows `storage` and never the pool.
                let copied = unsafe { pool.copy_out(0, 0, black_box(size as u32), &mut storage) }
                    .expect("the span lies within one buffer and storage holds a whole one");
                // Reduced to its length before it leaves the closure: the
                // returned slice borrows `storage`, which is captured, and an
                // `FnMut` cannot let such a borrow escape its body. The
                // destination is fenced separately because nothing here reads
                // the bytes back, and the copy is the whole measurement — it
                // must not be elided as dead.
                black_box(copied.len());
                black_box(&mut storage);
            });
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
    buffer_pool_copy_out,
    free_list_pop_push,
    free_list_pop_reclaim
);
criterion_main!(benches);
