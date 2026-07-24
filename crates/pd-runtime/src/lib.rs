//! The shared dataplane region and the buffer-ownership protocol common to the
//! protection domains.
//!
//! This crate deliberately carries no seL4/Microkit dependency: the region
//! layout and the ownership protocol are pure logic and are exercised in full
//! on the host (see the concurrency test below). The protection-domain binaries
//! are thin adapters that map a region, hand its address here, and drive the
//! protocol from Microkit notifications.
//!
//! # The forwarding region
//!
//! [`Pipeline`] joins three domains into the forwarding chain
//! `rx driver -> forwarder -> tx driver` over one buffer pool: `rx` carries
//! received frames to the forwarder, `tx` carries them onward to the
//! transmitting driver, and `free` returns transmitted buffers to the
//! pool-owning rx driver. A buffer is always owned by exactly one side: it sits
//! in the owner's [`FreeList`], or in exactly one ring, or in one domain's hand
//! — never in two places at once. That single-ownership chain is what makes
//! forwarding zero-copy end to end: the receiving NIC DMAs a frame into a pool
//! buffer and the transmitting NIC DMAs it back out of that very buffer, and
//! only the descriptor ever moves.
//!
//! # Trust stance: a byzantine peer PD
//!
//! This crate *is* the inter-PD protocol, so it defines what one protection
//! domain must withstand from another. Every neighbour shares read-write access
//! to the whole region — both ring cursors and every slot, and the pool bytes —
//! and is treated as untrusted (CONCEPT §7.1).
//!
//! What a hostile peer **cannot** cause: a forged ring cursor never drives this
//! side to an out-of-bounds slot access or an arithmetic panic, because the
//! `queue` crate masks every cursor into range; and a forged descriptor is
//! never dereferenced out of bounds, because a consumer validates every inbound
//! descriptor with [`descriptor_in_bounds`] before touching the span it names.
//!
//! What a hostile peer **can** currently cause — the accepted, tracked gap:
//! buffer ownership is accounted by count, not against an outstanding-set, so a
//! peer that returns more descriptors on a ring than it was ever handed
//! (duplicates or forged indices) is not yet contained. Today the pool owner
//! fails *visibly* on the resulting overflow — [`Producer::release`] and
//! [`forward`] panic when a ring cannot accept an over-return — and, short of
//! overflow, a duplicate return can double-own a buffer. This is a deliberate
//! fail-visible choice for the current milestone and a known deviation from the
//! CONCEPT §7.1 target ("never allowed to ... crash a well-behaved PD"): the
//! byzantine-containment work — treat an over-return as malformed input, drop
//! and count it, and validate returns against an outstanding-set — is tracked
//! and deferred, not done in this crate.

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
/// which makes buffer hand-offs along a correctly accounted chain infallible.
pub const RING_SLOTS: usize = 128;

/// Bytes reserved for a region in the system description. The `const _`
/// assertions below fail the build if a region type outgrows this, so the Rust
/// types can never silently exceed the mapping declared in the `.system` file.
/// The guarantee is one-directional: nothing here re-reads the `.system`
/// `<memory_region>` size, so shrinking that XML below this constant is caught
/// only at boot (a truncated mapping), not at build time.
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

/// The three-domain forwarding region: an rx driver, a forwarder, and a tx
/// driver joined by three rings over one pool. The single pool is what makes
/// forwarding zero-copy end to end: the receiving NIC DMAs a frame into a pool
/// buffer, and the transmitting NIC DMAs it back out of the very same buffer;
/// only the descriptor moves.
///
/// seL4 hands out the region zero-initialised, and a zeroed value is the valid
/// empty state (all rings empty, all buffers zeroed), so no domain needs to
/// construct it — each attaches to the mapped frames with [`Pipeline::attach`].
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

// The region is aliased into multiple protection domains, so its layout is a
// hard ABI. Pin the ring and pool sizes, keep the region alignment within a
// page, and guarantee it fits the mapping declared in the system description.
const _: () = assert!(size_of::<Ring>() == 8 + RING_SLOTS * size_of::<Descriptor>());
const _: () = assert!(size_of::<Pool>() == POOL_BUFFERS * BUFFER_SIZE);
const _: () = assert!(align_of::<Pipeline>() <= 0x1000);
const _: () = assert!(size_of::<Pipeline>() <= REGION_SIZE);

impl Pipeline {
    /// Byte offset of the buffer pool within the region. A driver that also
    /// hands the pool to a device (NIC DMA) adds this to the region's physical
    /// address to get each buffer's physical address.
    pub const POOL_OFFSET: usize = offset_of!(Pipeline, pool);

    /// Physical address of the buffer pool, given the region's physical address
    /// (from a `region_paddr` mapping).
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
            rx: Ring::new(),
            tx: Ring::new(),
            free: Ring::new(),
            pool: Pool::new(),
        }
    }

    /// Attach to a mapped region and borrow it for the domain's lifetime.
    ///
    /// # Safety
    /// `ptr` must point to a live mapping of at least `size_of::<Self>()` bytes
    /// that is either zeroed or already a valid value, outlives `'a`, and is
    /// shared only with the peer protection domains under this protocol.
    #[must_use]
    pub unsafe fn attach<'a>(ptr: *mut Self) -> &'a Self {
        // SAFETY: the caller guarantees a live, correctly sized, correctly
        // initialised mapping outliving `'a`; the region is `Sync`, so a shared
        // borrow aliased with the peer domains is sound under the protocol.
        unsafe { &*ptr }
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Pool-owner side: owns the pool's free buffers, publishes filled ones, and
/// reclaims returns. The rings are passed per call, so the same role drives
/// each leg of a [`Pipeline`] — an rx driver [`submit`](Self::submit)s frames on
/// `rx` and [`reclaim`](Self::reclaim)s spent buffers from `free`.
///
/// A driver's buffers are filled by hardware DMA, so publishing is zero-copy:
/// [`alloc`](Self::alloc) takes a buffer to hand to the device, and
/// [`submit`](Self::submit) publishes the already-filled span onward without
/// ever touching the bytes. [`release`](Self::release) returns a buffer to the
/// pool when a submit cannot proceed.
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

/// Forwarder stage: move every descriptor currently queued on `from` to `to`,
/// transferring buffer ownership onward without touching the bytes. Returns
/// how many descriptors moved.
///
/// The rings are sized above the pool, so along a correctly accounted chain
/// `to` can always take what `from` held. An enqueue failure therefore means
/// buffer accounting broke — a byzantine peer over-filling `from` while `to`
/// stalls — and the stage fails visibly. That crash-on-hostile-neighbour is the
/// tracked byzantine-containment gap documented at the crate level, not a
/// condition a well-behaved chain can reach.
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

    /// Stand in for the receiving NIC: take a free buffer, fill it as a DMA
    /// would, and publish the span on the pipeline's `rx` ring. Returns the
    /// buffer index published, or `None` when the pool is momentarily empty.
    fn receive(pipeline: &Pipeline, producer: &mut Producer, payload: &[u8]) -> Option<u32> {
        let buffer = producer.alloc()?;
        // SAFETY: `buffer` came from our free list, so we own it exclusively
        // until `submit` transfers it; `payload` is a local, not a pool borrow.
        let len = unsafe { pipeline.pool.write(buffer as usize, payload) };
        if producer.submit(&pipeline.rx, buffer, 0, len) {
            Some(buffer)
        } else {
            producer.release(buffer);
            None
        }
    }

    /// Stand in for the transmitting NIC: drain every frame queued on `tx`,
    /// read its payload back, and return the buffer to its owner on `free`,
    /// invoking `on_payload` for each. Returns how many frames were transmitted.
    fn transmit(pipeline: &Pipeline, mut on_payload: impl FnMut(&[u8])) -> usize {
        let mut count = 0;
        while let Some(descriptor) = pipeline.tx.try_dequeue() {
            {
                // SAFETY: we dequeued this descriptor, so we own its buffer
                // until it is returned below; the borrow ends before that. The
                // data is the `len` bytes at `offset` the rx side published.
                let bytes = unsafe {
                    pipeline.pool.read(
                        descriptor.buffer as usize,
                        descriptor.offset as usize,
                        descriptor.len,
                    )
                };
                on_payload(bytes);
            }
            pipeline
                .free
                .try_enqueue(descriptor)
                .expect("free ring has a slot for every pool buffer");
            count += 1;
        }
        count
    }

    #[test]
    fn zeroed_region_is_valid_and_empty() {
        // A region built from zeroed memory (as seL4 provides) must be empty
        // and immediately usable.
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
    fn single_threaded_pipeline_round_trip_preserves_payloads() {
        // The three-PD forwarding chain in one thread: receive two frames,
        // forward them, transmit them, then reclaim — full pool ownership must
        // return and both payloads must survive intact and in order.
        let pipeline = Box::new(Pipeline::new());
        let mut producer = Producer::new();

        assert!(receive(&pipeline, &mut producer, &7u64.to_le_bytes()).is_some());
        assert!(receive(&pipeline, &mut producer, &8u64.to_le_bytes()).is_some());
        assert_eq!(producer.owned(), POOL_BUFFERS - 2);

        assert_eq!(forward(&pipeline.rx, &pipeline.tx), 2);

        let mut seen = std::vec::Vec::new();
        let transmitted = transmit(&pipeline, |bytes| {
            seen.push(u64::from_le_bytes(bytes.try_into().unwrap()));
        });
        assert_eq!(transmitted, 2);
        assert_eq!(seen, std::vec![7, 8]);

        // Buffers are back on the free ring; reclaiming restores full ownership.
        producer.reclaim(&pipeline.free);
        assert_eq!(producer.owned(), POOL_BUFFERS);
    }

    #[test]
    fn submit_reports_a_full_ring_without_enqueuing() {
        // `submit` is a thin publish onto the ring; when the ring is full it
        // must report `false` and enqueue nothing, so the caller keeps the
        // buffer to release and retry. The ring is sized above the pool, so it
        // never fills from real pool buffers — drive the full-ring path
        // directly by publishing more descriptors than the ring can hold.
        let pipeline = Box::new(Pipeline::new());
        let mut producer = Producer::new();
        let capacity = pipeline.rx.capacity();

        for _ in 0..capacity {
            assert!(producer.submit(&pipeline.rx, 0, 0, 0));
        }
        assert!(!producer.submit(&pipeline.rx, 0, 0, 0));
        assert_eq!(pipeline.rx.len(), capacity);
    }

    #[test]
    fn buffer_paddr_is_pool_base_plus_indexed_stride() {
        // The DMA-address contract the NIC depends on: buffer `i` sits at the
        // pool base plus `i` strides of BUFFER_SIZE.
        let region = 0x3100_0000u64;
        assert_eq!(
            Pipeline::pool_paddr(region),
            region + Pipeline::POOL_OFFSET as u64
        );
        for index in [0u32, 1, 7, POOL_BUFFERS as u32 - 1] {
            assert_eq!(
                Pipeline::buffer_paddr(region, index),
                Pipeline::pool_paddr(region) + index as u64 * BUFFER_SIZE as u64
            );
        }
    }

    #[test]
    fn concurrent_pipeline_chain_transfers_every_buffer_in_order() {
        // The three-PD forwarding scenario end to end under real threads: an
        // rx-driver thread fills and publishes buffers, a forwarder thread moves
        // them onward, and a tx-driver thread consumes and returns them, so
        // every buffer cycles rx -> forward -> tx -> free far more times than
        // the pool holds. Both rings wrap repeatedly and every buffer is reused;
        // the sequence-numbered payloads must arrive intact and in order, and
        // full pool ownership must return to the rx driver.
        const TOTAL: u64 = 500_000;
        let pipeline: Arc<Pipeline> = Arc::new(Pipeline::new());

        let rx_pipeline = Arc::clone(&pipeline);
        let rx_driver = thread::spawn(move || {
            let mut producer = Producer::new();
            let mut sent = 0u64;
            while sent < TOTAL {
                producer.reclaim(&rx_pipeline.free);
                if receive(&rx_pipeline, &mut producer, &sent.to_le_bytes()).is_some() {
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
            let mut expected = 0u64;
            while expected < TOTAL {
                transmit(&pipeline, |bytes| {
                    let value = u64::from_le_bytes(bytes.try_into().unwrap());
                    assert_eq!(value, expected, "out-of-order or corrupted buffer");
                    expected += 1;
                });
                std::hint::spin_loop();
            }
        });

        rx_driver.join().unwrap();
        forwarder.join().unwrap();
        tx_driver.join().unwrap();
    }
}
