//! The shared dataplane region and the producer/consumer round-trip protocol
//! common to the protection domains.
//!
//! This crate deliberately carries no seL4/Microkit dependency: the region
//! layout and the ownership protocol are pure logic and are exercised in full
//! on the host (see the concurrency test below). The protection-domain binaries
//! are thin adapters that map the region, hand its address here, and drive the
//! protocol from Microkit notifications.
//!
//! Two rings and a pool make up the region. `used` carries filled buffers from
//! the producer to the consumer; `free` returns emptied buffers the other way;
//! `pool` is the backing storage the descriptors index. A buffer is always
//! owned by exactly one side: it sits in the producer's [`FreeList`], or in the
//! `used` ring, or in the consumer's hand, or in the `free` ring — never in two
//! at once. That single-ownership chain is what makes the transfer zero-copy
//! and race-free.

#![cfg_attr(not(test), no_std)]

use core::mem::{align_of, offset_of, size_of};

use packet_buffer::{BufferPool, FreeList};
use queue::SpscRing;
use wire::Descriptor;

/// Size in bytes of each pool buffer.
pub use packet_buffer::BUFFER_SIZE;

/// Number of buffers in the shared pool.
pub const POOL_BUFFERS: usize = 64;

/// Slot count of each ring. Power of two; usable capacity is one less. Sized
/// above [`POOL_BUFFERS`] so neither ring can fill before the pool is
/// exhausted, which makes buffer returns infallible.
pub const RING_SLOTS: usize = 128;

/// Bytes reserved for the region in the system description. The build fails if
/// [`Shared`] outgrows it, keeping the Rust type and the `.system` `<memory_region>`
/// size in lockstep.
pub const REGION_SIZE: usize = 0x40000;

/// A ring sized for this dataplane.
pub type Ring = SpscRing<RING_SLOTS>;

/// The pool sized for this dataplane.
pub type Pool = BufferPool<POOL_BUFFERS>;

/// The shared-memory dataplane region mapped into both protection domains.
///
/// seL4 hands out this region zero-initialised, and a zeroed value is the valid
/// empty state (both rings empty, all buffers zeroed), so no domain needs to
/// construct it — each attaches to the mapped frames with [`Shared::attach`].
#[repr(C)]
pub struct Shared {
    /// Filled buffers, producer to consumer.
    pub used: Ring,
    /// Emptied buffers, consumer back to producer.
    pub free: Ring,
    /// Backing storage the descriptors index.
    pub pool: Pool,
}

// The region is aliased into two protection domains, so its layout is a hard
// ABI. Pin the ring and pool sizes, keep the region alignment within a page,
// and guarantee it fits the mapping declared in the system description.
const _: () = assert!(size_of::<Ring>() == 8 + RING_SLOTS * size_of::<Descriptor>());
const _: () = assert!(size_of::<Pool>() == POOL_BUFFERS * BUFFER_SIZE);
const _: () = assert!(align_of::<Shared>() <= 0x1000);
const _: () = assert!(size_of::<Shared>() <= REGION_SIZE);

impl Shared {
    /// Byte offset of the buffer pool within the region. A driver that also
    /// hands the pool to a device (NIC DMA) adds this to the region's physical
    /// address to get each buffer's physical address.
    pub const POOL_OFFSET: usize = offset_of!(Shared, pool);

    /// Physical address of the buffer pool, given the region's physical
    /// address (from a `region_paddr` mapping).
    #[must_use]
    pub const fn pool_paddr(region_paddr: u64) -> u64 {
        region_paddr + Self::POOL_OFFSET as u64
    }

    /// Physical address of pool buffer `index`.
    #[must_use]
    pub const fn buffer_paddr(region_paddr: u64, index: u32) -> u64 {
        Self::pool_paddr(region_paddr) + index as u64 * BUFFER_SIZE as u64
    }

    /// A new, empty region. Const so it can back a static; mainly for host use,
    /// since the mapped region is already zeroed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            used: Ring::new(),
            free: Ring::new(),
            pool: Pool::new(),
        }
    }

    /// Attach to a mapped region and borrow it for the domain's lifetime.
    ///
    /// # Safety
    /// `ptr` must point to a live mapping of at least `size_of::<Shared>()`
    /// bytes that is either zeroed or already a valid `Shared`, outlives `'a`,
    /// and is shared only with the peer protection domain under this protocol.
    #[must_use]
    pub unsafe fn attach<'a>(ptr: *mut Shared) -> &'a Shared {
        // SAFETY: the caller guarantees a live, correctly sized, correctly
        // initialised mapping outliving `'a`; `Shared` is `Sync`, so a shared
        // borrow aliased with the peer domain is sound under the protocol.
        unsafe { &*ptr }
    }
}

impl Default for Shared {
    fn default() -> Self {
        Self::new()
    }
}

/// Producer side: owns the pool's free buffers and publishes filled ones on
/// `used`, reclaiming returns from `free`.
///
/// Two ways to publish exist. [`produce`](Self::produce) fills a buffer from a
/// byte slice — for a domain that generates data in-process. A driver whose
/// buffers are filled by hardware DMA instead uses [`alloc`](Self::alloc) to
/// take a buffer to hand to the device and [`submit`](Self::submit) to publish
/// the already-filled span zero-copy, never touching the bytes.
pub struct Producer {
    free: FreeList<POOL_BUFFERS>,
}

impl Producer {
    /// A producer that starts owning every pool buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            free: FreeList::full(),
        }
    }

    /// Take ownership of a free buffer index, e.g. to hand to a device for it
    /// to fill. `None` when the pool is momentarily exhausted.
    pub fn alloc(&mut self) -> Option<u32> {
        self.free.pop()
    }

    /// Return a buffer to the free pool without publishing it (e.g. when a
    /// submit could not proceed).
    pub fn release(&mut self, buffer: u32) {
        let pushed = self.free.push(buffer);
        assert!(pushed, "free list overflow: buffer accounting is broken");
    }

    /// Publish `len` bytes at `offset` of an already-filled `buffer` on `used`,
    /// transferring the buffer to the consumer. No bytes are copied. Returns
    /// `false` if the ring is momentarily full, leaving the buffer owned by the
    /// caller (which should [`release`](Self::release) it).
    #[must_use]
    pub fn submit(&mut self, shared: &Shared, buffer: u32, offset: u32, len: u32) -> bool {
        shared
            .used
            .try_enqueue(Descriptor::new(buffer, offset, len))
            .is_ok()
    }

    /// Reclaim every buffer the consumer has returned on `free`.
    pub fn reclaim(&mut self, shared: &Shared) {
        while let Some(descriptor) = shared.free.try_dequeue() {
            self.release(descriptor.buffer);
        }
    }

    /// Copy `payload` into a fresh buffer at offset 0 and publish it on `used`.
    ///
    /// Returns `false` when no buffer is free or the ring is full, leaving
    /// ownership unchanged so the caller can retry after reclaiming.
    pub fn produce(&mut self, shared: &Shared, payload: &[u8]) -> bool {
        let Some(index) = self.alloc() else {
            return false;
        };
        // SAFETY: `index` came from our free list, so we own it.
        let len = unsafe { shared.pool.write(index as usize, payload) };
        if self.submit(shared, index, 0, len) {
            true
        } else {
            self.release(index);
            false
        }
    }

    /// How many buffers the producer currently owns.
    #[must_use]
    pub fn owned(&self) -> usize {
        self.free.len()
    }
}

impl Default for Producer {
    fn default() -> Self {
        Self::new()
    }
}

/// Consumer side: takes filled buffers off `used`, hands each to a callback,
/// and returns the emptied buffer on `free`.
pub struct Consumer;

impl Consumer {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Drain every currently-available buffer, invoking `on_buffer(index,
    /// bytes)` for each, then return it to the producer. Returns how many
    /// buffers were processed.
    ///
    /// Draining the whole ring in one call is what absorbs coalesced
    /// notifications: one wakeup may cover many published buffers.
    pub fn drain(&mut self, shared: &Shared, mut on_buffer: impl FnMut(u32, &[u8])) -> usize {
        let mut count = 0;
        while let Some(descriptor) = shared.used.try_dequeue() {
            {
                // SAFETY: we dequeued this descriptor, so we own its buffer
                // until we return it below; the borrow ends before that. The
                // data is the `len` bytes at `offset` the producer published.
                let bytes = unsafe {
                    shared.pool.read(
                        descriptor.buffer as usize,
                        descriptor.offset as usize,
                        descriptor.len,
                    )
                };
                on_buffer(descriptor.buffer, bytes);
            }
            // The free ring has a slot for every pool buffer, so a correctly
            // accounted return cannot fail; a failure means the invariant broke.
            if shared.free.try_enqueue(descriptor).is_err() {
                panic!("free ring overflow: buffer accounting is broken");
            }
            count += 1;
        }
        count
    }
}

impl Default for Consumer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn zeroed_region_is_a_valid_empty_shared() {
        // A `Shared` built from zeroed memory (as seL4 provides) must be empty
        // and immediately usable.
        let shared = Box::new(Shared::new());
        assert!(shared.used.is_empty());
        assert!(shared.free.is_empty());
        assert_eq!(shared.pool.capacity(), POOL_BUFFERS);
    }

    #[test]
    fn single_threaded_round_trip_preserves_payloads() {
        let shared = Box::new(Shared::new());
        let mut producer = Producer::new();
        let mut consumer = Consumer::new();

        assert!(producer.produce(&shared, &7u64.to_le_bytes()));
        assert!(producer.produce(&shared, &8u64.to_le_bytes()));
        assert_eq!(producer.owned(), POOL_BUFFERS - 2);

        let mut seen = std::vec::Vec::new();
        let drained = consumer.drain(&shared, |_buffer, bytes| {
            seen.push(u64::from_le_bytes(bytes.try_into().unwrap()));
        });
        assert_eq!(drained, 2);
        assert_eq!(seen, std::vec![7, 8]);

        // Buffers are back in the ring; reclaiming restores full ownership.
        producer.reclaim(&shared);
        assert_eq!(producer.owned(), POOL_BUFFERS);
    }

    #[test]
    fn concurrent_round_trip_transfers_every_buffer_in_order() {
        // The two-PD scenario end to end: a producer thread cycles the whole
        // pool many times while a consumer thread drains and returns buffers,
        // so both rings wrap repeatedly and every buffer is reused. The
        // sequence-numbered payloads must arrive intact and in order.
        const TOTAL: u64 = 500_000;
        let shared: Arc<Shared> = Arc::new(Shared::new());

        let producer_shared = Arc::clone(&shared);
        let producer = thread::spawn(move || {
            let mut producer = Producer::new();
            let mut sent = 0u64;
            while sent < TOTAL {
                producer.reclaim(&producer_shared);
                if producer.produce(&producer_shared, &sent.to_le_bytes()) {
                    sent += 1;
                } else {
                    std::hint::spin_loop();
                }
            }
        });

        let consumer = thread::spawn(move || {
            let mut consumer = Consumer::new();
            let mut expected = 0u64;
            while expected < TOTAL {
                consumer.drain(&shared, |_buffer, bytes| {
                    let value = u64::from_le_bytes(bytes.try_into().unwrap());
                    assert_eq!(value, expected, "out-of-order or corrupted buffer");
                    expected += 1;
                });
                std::hint::spin_loop();
            }
        });

        producer.join().unwrap();
        consumer.join().unwrap();
    }
}
