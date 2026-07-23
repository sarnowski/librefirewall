//! The shared dataplane regions and the buffer-ownership protocol common to
//! the protection domains.
//!
//! This crate deliberately carries no seL4/Microkit dependency: the region
//! layouts and the ownership protocol are pure logic and are exercised in full
//! on the host (see the concurrency tests below). The protection-domain
//! binaries are thin adapters that map a region, hand its address here, and
//! drive the protocol from Microkit notifications.
//!
//! Two region shapes exist. [`Shared`] joins two domains: `used` carries
//! filled buffers from the producer to the consumer and `free` returns them.
//! [`Pipeline`] joins three domains into the forwarding chain
//! `rx driver -> forwarder -> tx driver`: `rx` carries received frames to the
//! forwarder, `tx` carries them onward to the transmitting driver, and `free`
//! returns transmitted buffers to the pool-owning rx driver. In both shapes a
//! buffer is always owned by exactly one side: it sits in the owner's
//! [`FreeList`], or in exactly one ring, or in one domain's hand — never in
//! two places at once. That single-ownership chain is what makes every
//! transfer zero-copy and race-free.

#![cfg_attr(not(test), no_std)]

use core::mem::{align_of, offset_of, size_of};

use packet_buffer::{BufferPool, FreeList};
use queue::SpscRing;

pub use packet_buffer::BUFFER_SIZE;
pub use wire::Descriptor;

/// Number of buffers in a shared pool.
pub const POOL_BUFFERS: usize = 64;

/// Slot count of each ring. Power of two; usable capacity is one less. Sized
/// above [`POOL_BUFFERS`] so no ring can fill before the pool is exhausted,
/// which makes buffer hand-offs along an correctly accounted chain infallible.
pub const RING_SLOTS: usize = 128;

/// Bytes reserved for a region in the system description. The build fails if
/// a region type outgrows it, keeping the Rust types and the `.system`
/// `<memory_region>` sizes in lockstep.
pub const REGION_SIZE: usize = 0x40000;

/// A ring sized for this dataplane.
pub type Ring = SpscRing<RING_SLOTS>;

/// The pool sized for this dataplane.
pub type Pool = BufferPool<POOL_BUFFERS>;

/// Whether a descriptor received from a neighbouring protection domain names
/// a span that lies within one pool buffer. Neighbours are untrusted, so a
/// domain validates every inbound descriptor with this before dereferencing
/// the span; a failing descriptor is rejected, never followed.
#[must_use]
pub fn descriptor_in_bounds(descriptor: &Descriptor) -> bool {
    (descriptor.buffer as usize) < POOL_BUFFERS
        && (descriptor.offset as usize)
            .checked_add(descriptor.len as usize)
            .is_some_and(|end| end <= BUFFER_SIZE)
}

/// The two-domain dataplane region: producer and consumer joined by a `used`
/// and a `free` ring over one pool.
///
/// seL4 hands out the region zero-initialised, and a zeroed value is the valid
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

/// The three-domain forwarding region: an rx driver, a forwarder, and a tx
/// driver joined by three rings over one pool. The single pool is what makes
/// forwarding zero-copy end to end: the receiving NIC DMAs a frame into a pool
/// buffer, and the transmitting NIC DMAs it back out of the very same buffer;
/// only the descriptor moves.
///
/// Like [`Shared`], a zeroed region is the valid empty state and each domain
/// attaches with [`Pipeline::attach`].
#[repr(C)]
pub struct Pipeline {
    /// Received frames, rx driver to forwarder.
    pub rx: Ring,
    /// Frames to transmit, forwarder to tx driver.
    pub tx: Ring,
    /// Transmitted buffers, tx driver back to the pool-owning rx driver.
    pub free: Ring,
    /// Backing storage the descriptors index; also both NICs' DMA target.
    pub pool: Pool,
}

// The regions are aliased into multiple protection domains, so their layouts
// are a hard ABI. Pin the ring and pool sizes, keep the region alignment
// within a page, and guarantee both fit the mapping declared in the system
// description.
const _: () = assert!(size_of::<Ring>() == 8 + RING_SLOTS * size_of::<Descriptor>());
const _: () = assert!(size_of::<Pool>() == POOL_BUFFERS * BUFFER_SIZE);
const _: () = assert!(align_of::<Shared>() <= 0x1000);
const _: () = assert!(size_of::<Shared>() <= REGION_SIZE);
const _: () = assert!(align_of::<Pipeline>() <= 0x1000);
const _: () = assert!(size_of::<Pipeline>() <= REGION_SIZE);

macro_rules! region_impl {
    ($region:ident { $($ring:ident),+ }) => {
        impl $region {
            /// Byte offset of the buffer pool within the region. A driver that
            /// also hands the pool to a device (NIC DMA) adds this to the
            /// region's physical address to get each buffer's physical address.
            pub const POOL_OFFSET: usize = offset_of!($region, pool);

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

            /// A new, empty region. Const so it can back a static; mainly for
            /// host use, since the mapped region is already zeroed.
            #[must_use]
            pub const fn new() -> Self {
                Self {
                    $($ring: Ring::new(),)+
                    pool: Pool::new(),
                }
            }

            /// Attach to a mapped region and borrow it for the domain's
            /// lifetime.
            ///
            /// # Safety
            /// `ptr` must point to a live mapping of at least
            /// `size_of::<Self>()` bytes that is either zeroed or already a
            /// valid value, outlives `'a`, and is shared only with the peer
            /// protection domains under this protocol.
            #[must_use]
            pub unsafe fn attach<'a>(ptr: *mut Self) -> &'a Self {
                // SAFETY: the caller guarantees a live, correctly sized,
                // correctly initialised mapping outliving `'a`; the region is
                // `Sync`, so a shared borrow aliased with the peer domains is
                // sound under the protocol.
                unsafe { &*ptr }
            }
        }

        impl Default for $region {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

region_impl!(Shared { used, free });
region_impl!(Pipeline { rx, tx, free });

/// Pool-owner side: owns the pool's free buffers, publishes filled ones, and
/// reclaims returns. The rings are passed per call so the same role drives
/// either region shape — a [`Shared`] producer submits on `used` and reclaims
/// from `free`; a [`Pipeline`] rx driver submits on `rx` and reclaims from
/// `free`.
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

    /// Publish `len` bytes at `offset` of an already-filled `buffer` on
    /// `ring`, transferring the buffer to the next domain. No bytes are
    /// copied. Returns `false` if the ring is momentarily full, leaving the
    /// buffer owned by the caller (which should [`release`](Self::release)
    /// it).
    #[must_use]
    pub fn submit(&mut self, ring: &Ring, buffer: u32, offset: u32, len: u32) -> bool {
        ring.try_enqueue(Descriptor::new(buffer, offset, len))
            .is_ok()
    }

    /// Reclaim every buffer returned on `ring`.
    pub fn reclaim(&mut self, ring: &Ring) {
        while let Some(descriptor) = ring.try_dequeue() {
            self.release(descriptor.buffer);
        }
    }

    /// Copy `payload` into a fresh pool buffer at offset 0 and publish it on
    /// `ring`.
    ///
    /// Returns `false` when no buffer is free or the ring is full, leaving
    /// ownership unchanged so the caller can retry after reclaiming.
    pub fn produce(&mut self, pool: &Pool, ring: &Ring, payload: &[u8]) -> bool {
        let Some(index) = self.alloc() else {
            return false;
        };
        // SAFETY: `index` came from our free list, so we own it.
        let len = unsafe { pool.write(index as usize, payload) };
        if self.submit(ring, index, 0, len) {
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

/// Sink side: takes filled buffers off one ring, hands each to a callback,
/// and returns the emptied buffer on another.
pub struct Consumer;

impl Consumer {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Drain every buffer currently on `take`, invoking `on_buffer(index,
    /// bytes)` for each, then return it on `give`. Returns how many buffers
    /// were processed.
    ///
    /// Draining the whole ring in one call is what absorbs coalesced
    /// notifications: one wakeup may cover many published buffers.
    pub fn drain(
        &mut self,
        take: &Ring,
        give: &Ring,
        pool: &Pool,
        mut on_buffer: impl FnMut(u32, &[u8]),
    ) -> usize {
        let mut count = 0;
        while let Some(descriptor) = take.try_dequeue() {
            {
                // SAFETY: we dequeued this descriptor, so we own its buffer
                // until we return it below; the borrow ends before that. The
                // data is the `len` bytes at `offset` the producer published.
                let bytes = unsafe {
                    pool.read(
                        descriptor.buffer as usize,
                        descriptor.offset as usize,
                        descriptor.len,
                    )
                };
                on_buffer(descriptor.buffer, bytes);
            }
            // The return ring has a slot for every pool buffer, so a correctly
            // accounted return cannot fail; a failure means the invariant broke.
            if give.try_enqueue(descriptor).is_err() {
                panic!("return ring overflow: buffer accounting is broken");
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

/// Forwarder stage: move every descriptor currently queued on `from` to `to`,
/// transferring buffer ownership onward without touching the bytes. Returns
/// how many descriptors moved.
///
/// The rings are sized above the pool, so along a correctly accounted chain
/// `to` can always take what `from` held; an enqueue failure means the
/// single-ownership invariant broke and the domain fails visibly.
pub fn forward(from: &Ring, to: &Ring) -> usize {
    let mut moved = 0;
    while let Some(descriptor) = from.try_dequeue() {
        if to.try_enqueue(descriptor).is_err() {
            panic!("forward ring overflow: buffer accounting is broken");
        }
        moved += 1;
    }
    moved
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn zeroed_regions_are_valid_and_empty() {
        // Regions built from zeroed memory (as seL4 provides) must be empty
        // and immediately usable.
        let shared = Box::new(Shared::new());
        assert!(shared.used.is_empty());
        assert!(shared.free.is_empty());
        assert_eq!(shared.pool.capacity(), POOL_BUFFERS);

        let pipeline = Box::new(Pipeline::new());
        assert!(pipeline.rx.is_empty());
        assert!(pipeline.tx.is_empty());
        assert!(pipeline.free.is_empty());
        assert_eq!(pipeline.pool.capacity(), POOL_BUFFERS);
    }

    #[test]
    fn descriptor_bounds_reject_out_of_pool_spans() {
        let max = BUFFER_SIZE as u32;
        assert!(descriptor_in_bounds(&Descriptor::new(0, 0, max)));
        assert!(descriptor_in_bounds(&Descriptor::new(
            POOL_BUFFERS as u32 - 1,
            max - 1,
            1
        )));
        assert!(descriptor_in_bounds(&Descriptor::new(0, max, 0)));
        // Buffer index outside the pool.
        assert!(!descriptor_in_bounds(&Descriptor::new(
            POOL_BUFFERS as u32,
            0,
            1
        )));
        // Span runs past the buffer end.
        assert!(!descriptor_in_bounds(&Descriptor::new(0, 1, max)));
        // Offset + len overflows.
        assert!(!descriptor_in_bounds(&Descriptor::new(
            0,
            u32::MAX,
            u32::MAX
        )));
    }

    #[test]
    fn single_threaded_round_trip_preserves_payloads() {
        let shared = Box::new(Shared::new());
        let mut producer = Producer::new();
        let mut consumer = Consumer::new();

        assert!(producer.produce(&shared.pool, &shared.used, &7u64.to_le_bytes()));
        assert!(producer.produce(&shared.pool, &shared.used, &8u64.to_le_bytes()));
        assert_eq!(producer.owned(), POOL_BUFFERS - 2);

        let mut seen = std::vec::Vec::new();
        let drained = consumer.drain(
            &shared.used,
            &shared.free,
            &shared.pool,
            |_buffer, bytes| {
                seen.push(u64::from_le_bytes(bytes.try_into().unwrap()));
            },
        );
        assert_eq!(drained, 2);
        assert_eq!(seen, std::vec![7, 8]);

        // Buffers are back in the ring; reclaiming restores full ownership.
        producer.reclaim(&shared.free);
        assert_eq!(producer.owned(), POOL_BUFFERS);
    }

    #[test]
    fn forward_moves_descriptors_in_order() {
        let pipeline = Box::new(Pipeline::new());
        for i in 0..5 {
            pipeline.rx.try_enqueue(Descriptor::new(i, 12, i)).unwrap();
        }
        assert_eq!(forward(&pipeline.rx, &pipeline.tx), 5);
        assert!(pipeline.rx.is_empty());
        for i in 0..5 {
            assert_eq!(pipeline.tx.try_dequeue(), Some(Descriptor::new(i, 12, i)));
        }
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
                producer.reclaim(&producer_shared.free);
                if producer.produce(
                    &producer_shared.pool,
                    &producer_shared.used,
                    &sent.to_le_bytes(),
                ) {
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
                consumer.drain(
                    &shared.used,
                    &shared.free,
                    &shared.pool,
                    |_buffer, bytes| {
                        let value = u64::from_le_bytes(bytes.try_into().unwrap());
                        assert_eq!(value, expected, "out-of-order or corrupted buffer");
                        expected += 1;
                    },
                );
                std::hint::spin_loop();
            }
        });

        producer.join().unwrap();
        consumer.join().unwrap();
    }

    #[test]
    fn concurrent_pipeline_chain_transfers_every_buffer_in_order() {
        // The three-PD forwarding scenario end to end: an rx-driver thread
        // fills and publishes buffers, a forwarder thread moves them onward,
        // and a tx-driver thread consumes and returns them, so every buffer
        // cycles rx -> forward -> tx -> free far more times than the pool
        // holds. The sequence-numbered payloads must arrive intact and in
        // order, and full pool ownership must return to the rx driver.
        const TOTAL: u64 = 500_000;
        let pipeline: Arc<Pipeline> = Arc::new(Pipeline::new());

        let rx_pipeline = Arc::clone(&pipeline);
        let rx_driver = thread::spawn(move || {
            let mut producer = Producer::new();
            let mut sent = 0u64;
            while sent < TOTAL {
                producer.reclaim(&rx_pipeline.free);
                if producer.produce(&rx_pipeline.pool, &rx_pipeline.rx, &sent.to_le_bytes()) {
                    sent += 1;
                } else {
                    std::hint::spin_loop();
                }
            }
            // Wait for the chain to hand every buffer back.
            loop {
                producer.reclaim(&rx_pipeline.free);
                if producer.owned() == POOL_BUFFERS {
                    break;
                }
                std::hint::spin_loop();
            }
        });

        let fwd_pipeline = Arc::clone(&pipeline);
        let forwarder = thread::spawn(move || {
            let mut moved = 0u64;
            while moved < TOTAL {
                moved += forward(&fwd_pipeline.rx, &fwd_pipeline.tx) as u64;
                std::hint::spin_loop();
            }
        });

        let tx_driver = thread::spawn(move || {
            let mut consumer = Consumer::new();
            let mut expected = 0u64;
            while expected < TOTAL {
                consumer.drain(
                    &pipeline.tx,
                    &pipeline.free,
                    &pipeline.pool,
                    |_buffer, bytes| {
                        let value = u64::from_le_bytes(bytes.try_into().unwrap());
                        assert_eq!(value, expected, "out-of-order or corrupted buffer");
                        expected += 1;
                    },
                );
                std::hint::spin_loop();
            }
        });

        rx_driver.join().unwrap();
        forwarder.join().unwrap();
        tx_driver.join().unwrap();
    }
}
