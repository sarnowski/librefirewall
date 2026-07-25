//! Microbenchmarks for the virtio driver hot paths.
//!
//! Two operations dominate the driver's per-frame cost: the split-virtqueue
//! post/reap/reclaim cycle (`add_writable` + `poll` + `recycle`) and, at
//! bring-up, the PCI capability walk (`find_virtio_caps`).
//!
//! The virtqueue bench has to play the device side itself — otherwise `poll`
//! would only ever return `None` and the reap path would never run — but the
//! device's writes are not the driver's cost, so they are kept **outside** the
//! timed region: each round posts a full ring (timed), lets the device complete
//! every descriptor (untimed), then reaps and reclaims the ring (timed). A full
//! ring per round also amortises the two `Instant::now()` pairs over `QSIZE`
//! descriptors, which a per-descriptor timing could not do without measuring
//! mostly the clock.

// Benchmark target: no public API to document (the `criterion_group!` macro
// expands to public items).
#![allow(missing_docs)]

use std::hint::black_box;
use std::sync::atomic::{Ordering, fence};
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use virtio::pci::{PciConfig, find_virtio_caps};
use virtio::queue::SplitVirtqueue;

const QSIZE: usize = 16;

/// A 16-byte-aligned backing region for the virtqueue, matching the alignment
/// [`SplitVirtqueue::new`] requires.
#[repr(C, align(16))]
struct Region([u8; 4096]);

/// Write a used-ring completion for descriptor `head` at the next used slot,
/// exactly as the device would, using only the public queue layout offsets.
///
/// # Safety
/// `region` must point to a live virtqueue region of at least the queue's
/// `total_bytes`, and `*used_idx` must be the device's current used index.
unsafe fn device_complete(region: *mut u8, used_idx: &mut u16, head: u16, len: u32) {
    let used_base = SplitVirtqueue::<QSIZE>::LAYOUT.device_offset;
    let slot = (*used_idx as usize) & (QSIZE - 1);
    let elem = used_base + 4 + slot * 8;
    // SAFETY: `region` is the live virtqueue region (this fn's contract) and
    // `elem`/`used_base + 2` are computed from the public layout, so both lie
    // within its `total_bytes`.
    unsafe {
        region.add(elem).cast::<u32>().write_volatile(head as u32);
        region.add(elem + 4).cast::<u32>().write_volatile(len);
        fence(Ordering::Release);
        *used_idx = used_idx.wrapping_add(1);
        region
            .add(used_base + 2)
            .cast::<u16>()
            .write_volatile(*used_idx);
    }
}

fn virtqueue_post_and_reap_a_full_ring(c: &mut Criterion) {
    let mut region = Box::new(Region([0u8; 4096]));
    let ptr = region.0.as_mut_ptr();
    // SAFETY: `region` is 16-byte aligned, zeroed, and larger than the queue's
    // total_bytes; it is the sole owner of this queue for the bench's lifetime.
    let mut queue = unsafe { SplitVirtqueue::<QSIZE>::new(ptr) };
    let mut used_idx: u16 = 0;

    c.bench_function("virtqueue_post_and_reap_a_full_ring", |b| {
        b.iter_custom(|rounds| {
            let mut driver_time = Duration::ZERO;
            for _ in 0..rounds {
                let start = Instant::now();
                for _ in 0..QSIZE {
                    queue
                        .add_writable(black_box(0x1000), black_box(64))
                        .expect("a descriptor is free");
                }
                driver_time += start.elapsed();

                // The device's side of the ring: three volatile writes and a
                // release fence per completion, none of it driver cost.
                for head in 0..QSIZE as u16 {
                    // SAFETY: `ptr` is the live region, `used_idx` tracks the
                    // device index, and `head < QSIZE` names a posted
                    // descriptor.
                    unsafe { device_complete(ptr, &mut used_idx, head, 64) };
                }

                let start = Instant::now();
                while let Some((token, len)) = queue.poll() {
                    black_box(len);
                    queue.recycle(token).expect("a just-reaped descriptor");
                }
                driver_time += start.elapsed();
            }
            driver_time
        });
    });
}

/// Write a virtio PCI vendor capability at `at`, chaining to `next`.
fn put_cap(
    bytes: &mut [u8; 4096],
    at: usize,
    next: u8,
    cfg_type: u8,
    bar: u8,
    offset: u32,
    len: u8,
) {
    bytes[at] = 0x09; // PCI_CAP_ID_VNDR
    bytes[at + 1] = next;
    bytes[at + 2] = len;
    bytes[at + 3] = cfg_type;
    bytes[at + 4] = bar;
    bytes[at + 8..at + 12].copy_from_slice(&offset.to_le_bytes());
}

/// Build a well-formed 4 KiB PCI config space with the four virtio structures
/// in one BAR, mirroring QEMU's modern virtio-net-pci device.
fn valid_config_space() -> Box<[u8; 4096]> {
    let mut bytes = Box::new([0u8; 4096]);
    // Status register: capability list present.
    bytes[0x06] = 0x10;
    // Capabilities pointer.
    bytes[0x34] = 0x40;
    // common @0x40 -> notify @0x50 -> isr @0x64 -> device @0x74.
    put_cap(&mut bytes, 0x40, 0x50, 1, 4, 0x0000, 16);
    put_cap(&mut bytes, 0x50, 0x64, 2, 4, 0x3000, 20);
    bytes[0x50 + 16..0x50 + 20].copy_from_slice(&4u32.to_le_bytes()); // notify multiplier
    put_cap(&mut bytes, 0x64, 0x74, 3, 4, 0x1000, 16);
    put_cap(&mut bytes, 0x74, 0x00, 4, 4, 0x2000, 16);
    bytes
}

fn find_caps(c: &mut Criterion) {
    let mut bytes = valid_config_space();
    // SAFETY: `bytes` is a live 4 KiB buffer; `find_virtio_caps` only reads
    // config registers within it.
    let config = unsafe { PciConfig::new(bytes.as_mut_ptr()) };
    c.bench_function("find_virtio_caps_valid", |b| {
        b.iter(|| black_box(find_virtio_caps(black_box(&config))));
    });
}

criterion_group!(benches, virtqueue_post_and_reap_a_full_ring, find_caps);
criterion_main!(benches);
