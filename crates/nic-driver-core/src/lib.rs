//! Host-testable steady-state dataplane for the virtio-net driver protection
//! domain.
//!
//! The driver PD (`pds/nic-driver`) is a thin adapter: it owns the unsafe,
//! seL4-only device bring-up — PCI discovery, BAR relocation, feature
//! negotiation, virtqueue placement, and the notify doorbells — and then hands
//! control to this crate's [`RxPath`] and [`TxPath`] for every steady-state
//! poll. The split is deliberate: the security-critical logic — rejecting a
//! device's duplicate or forged completions, clamping a device-reported length,
//! dropping a runt frame, validating an untrusted peer's transmit descriptors —
//! lives here in portable `no_std` code so it runs under host unit tests, which
//! it never could while welded to the Microkit entrypoint.
//!
//! # Untrusted inputs
//!
//! Two distrust boundaries meet in this crate (CONCEPT §7.1):
//!
//! - **The device** is hostile: its used-ring completions carry a token index
//!   and a written length treated as adversarial. A completion for a descriptor
//!   that is not outstanding (a duplicate or a forged echo) is rejected and
//!   never recycled — recycling it would corrupt the virtqueue free list — and
//!   the written length is clamped to the buffer before any downstream domain
//!   reads the frame. A frame shorter than the virtio-net header is dropped at
//!   the rx edge rather than forwarded as a header-only frame.
//! - **The forwarder peer** is untrusted: every transmit descriptor it queues
//!   is range-validated ([`pd_runtime::descriptor_in_bounds`], plus header
//!   room) before the span is touched; a descriptor naming a real pool buffer
//!   is returned to its owner, while a forged index is dropped.
//!
//! Neither can drive this crate to an out-of-bounds access or unbounded work.
//! Returning a buffer on the pipeline free ring inherits pd-runtime's tracked
//! byzantine-containment gap (a flooding peer meets a visible panic); see that
//! crate's header.
//!
//! # Observability groundwork
//!
//! [`Counters`] tallies the drops that are otherwise invisible. It exists so
//! the future Prometheus metrics endpoint (CONCEPT §11) has real numbers to
//! expose; today the driver reads it to latch a one-time console diagnostic.

#![cfg_attr(not(test), no_std)]

use pd_runtime::{
    BUFFER_SIZE, Descriptor, POOL_BUFFERS, Pipeline, Producer, Ring, descriptor_in_bounds,
};
use virtio::net::VirtioNetHdr;
use virtio::queue::SplitVirtqueue;

/// Counts of frames dropped on the untrusted-input boundaries, which are
/// otherwise invisible. This is deliberate groundwork for the Prometheus
/// metrics endpoint (CONCEPT §11): the numbers exist now so the future endpoint
/// can expose them, and the driver adapter reads them to latch a bounded
/// console diagnostic without letting a hostile neighbour flood the console.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    /// Device completions for a descriptor that was not outstanding (a
    /// duplicate or forged used-ring echo), rejected without recycling.
    pub rx_not_outstanding: u64,
    /// Received frames shorter than the virtio-net header, dropped at the rx
    /// edge instead of forwarded as a header-only frame.
    pub rx_runt_dropped: u64,
    /// Transmit descriptors from the peer that failed span/header validation.
    pub tx_malformed: u64,
}

/// The receive path's per-descriptor bookkeeping over a virtqueue of `Q`
/// descriptors: which pool buffer was posted in each slot, and whether that
/// slot is currently outstanding at the device. The `outstanding` flags are
/// what let the path reject a duplicate or forged completion, which would
/// otherwise double-own a buffer and corrupt the virtqueue free list.
pub struct RxPath<const Q: usize> {
    buffer: [u32; Q],
    outstanding: [bool; Q],
}

impl<const Q: usize> RxPath<Q> {
    /// A receive path with no buffers posted.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffer: [0; Q],
            outstanding: [false; Q],
        }
    }

    /// Post free pool buffers to the receive virtqueue until either the queue
    /// or the pool runs dry, recording which buffer went in each descriptor.
    /// `pool_paddr` is the physical address of pool buffer 0, so buffer `i`
    /// lands at `pool_paddr + i * BUFFER_SIZE`. Returns whether any buffer was
    /// posted, so the caller knows whether to ring the receive doorbell.
    pub fn refill(
        &mut self,
        rx: &mut SplitVirtqueue<Q>,
        producer: &mut Producer,
        pool_paddr: u64,
    ) -> bool {
        let mut posted = false;
        while let Some(buffer) = producer.alloc() {
            let paddr = pool_paddr + buffer as u64 * BUFFER_SIZE as u64;
            match rx.add_writable(paddr, BUFFER_SIZE as u32) {
                Some(token) => {
                    let index = token.index() as usize;
                    self.buffer[index] = buffer;
                    self.outstanding[index] = true;
                    posted = true;
                }
                None => {
                    // The receive queue is full; keep the buffer for next time.
                    producer.release(buffer);
                    break;
                }
            }
        }
        posted
    }

    /// Drain every completed receive descriptor, handing each valid frame to
    /// the forwarder on `rx_pipe.rx` with no copy. Returns whether any frame was
    /// submitted, so the caller knows whether to notify the forwarder.
    ///
    /// The device is untrusted, so each completion is checked before use: a
    /// not-outstanding token (duplicate or forged) is counted and skipped
    /// *without* recycling — recycling it would corrupt the virtqueue free
    /// list; the device-reported length is clamped to the buffer; a runt frame
    /// (nothing past the virtio-net header) is dropped and counted at the edge;
    /// and a buffer whose submit fails is released rather than leaked. Every
    /// consumed completion recycles its virtqueue descriptor.
    pub fn drain(
        &mut self,
        rx: &mut SplitVirtqueue<Q>,
        producer: &mut Producer,
        rx_pipe: &Pipeline,
        counters: &mut Counters,
    ) -> bool {
        let mut received = false;
        while let Some((token, used_len)) = rx.poll() {
            let index = token.index() as usize;
            if !core::mem::replace(&mut self.outstanding[index], false) {
                counters.rx_not_outstanding += 1;
                continue;
            }
            let buffer = self.buffer[index];
            // `used_len` is device-controlled; clamp to the buffer so a device
            // that over-reports cannot make a downstream PD read out of bounds.
            let frame_len = (used_len as usize)
                .min(BUFFER_SIZE)
                .saturating_sub(VirtioNetHdr::LEN);
            if frame_len == 0 {
                // A frame with nothing past the header carries no payload; drop
                // it at the rx edge rather than forward a header-only frame.
                counters.rx_runt_dropped += 1;
                producer.release(buffer);
                rx.recycle(token);
                continue;
            }
            // Hand the frame span (after the virtio header) to the forwarder
            // with no copy; the buffer is owned downstream until it comes back
            // on the free ring.
            if producer.submit(
                &rx_pipe.rx,
                buffer,
                VirtioNetHdr::LEN as u32,
                frame_len as u32,
            ) {
                received = true;
            } else {
                producer.release(buffer);
            }
            rx.recycle(token);
        }
        received
    }
}

impl<const Q: usize> Default for RxPath<Q> {
    fn default() -> Self {
        Self::new()
    }
}

/// The transmit path's per-descriptor bookkeeping over a virtqueue of `Q`
/// descriptors: the peer descriptor posted in each slot (so the buffer can be
/// returned to its owner on completion), and whether the slot is outstanding at
/// the device (to reject a duplicate or forged completion).
pub struct TxPath<const Q: usize> {
    descriptor: [Descriptor; Q],
    outstanding: [bool; Q],
}

impl<const Q: usize> TxPath<Q> {
    /// A transmit path with no frames in flight.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            descriptor: [Descriptor::ZERO; Q],
            outstanding: [false; Q],
        }
    }

    /// Reap transmit completions, returning each transmitted buffer to its
    /// pool-owning peer on `tx_pipe.free`. A not-outstanding completion (a
    /// duplicate or forged echo from the untrusted device) is skipped without
    /// recycling or returning a buffer.
    pub fn reap(&mut self, tx: &mut SplitVirtqueue<Q>, tx_pipe: &Pipeline) {
        while let Some((token, _written)) = tx.poll() {
            let index = token.index() as usize;
            if !core::mem::replace(&mut self.outstanding[index], false) {
                continue;
            }
            return_buffer(&tx_pipe.free, self.descriptor[index]);
            tx.recycle(token);
        }
    }

    /// Post frames the forwarder queued on `tx_pipe.tx` to the device while
    /// descriptors are free. `tx_pipe_paddr` is the physical address of the tx
    /// pipeline region. Returns whether any frame was posted, so the caller
    /// knows whether to ring the transmit doorbell.
    ///
    /// Each descriptor crossed a protection-domain boundary and is untrusted:
    /// its span must lie within one pool buffer and leave room for the
    /// virtio-net header in front of the frame. A malformed descriptor is
    /// counted and dropped; its buffer is returned to the pool only when the
    /// index names a real pool buffer (a forged index has no owner and is
    /// dropped). A valid frame has its 12-byte header zeroed in place — no
    /// offloads are negotiated — and is handed to the device zero-copy.
    pub fn post(
        &mut self,
        tx: &mut SplitVirtqueue<Q>,
        tx_pipe: &Pipeline,
        tx_pipe_paddr: u64,
        counters: &mut Counters,
    ) -> bool {
        let mut sent = false;
        while tx.free_count() > 0 {
            let Some(descriptor) = tx_pipe.tx.try_dequeue() else {
                break;
            };
            if !descriptor_in_bounds(&descriptor)
                || (descriptor.offset as usize) < VirtioNetHdr::LEN
            {
                counters.tx_malformed += 1;
                if (descriptor.buffer as usize) < POOL_BUFFERS {
                    return_buffer(&tx_pipe.free, descriptor);
                }
                continue;
            }
            let header_offset = descriptor.offset as usize - VirtioNetHdr::LEN;
            // The 12 bytes in front of the frame are reserved header space in
            // the same buffer (on the receive side the device's own header
            // occupied them). Zero them: no offloads are negotiated, so the
            // transmit header is all zeroes (gso NONE, no checksum request).
            // SAFETY: we own the buffer between dequeue and completion; the
            // index and span were validated above, so `header_offset .. +12`
            // lies within the buffer.
            unsafe {
                tx_pipe.pool.write_at(
                    descriptor.buffer as usize,
                    header_offset,
                    &[0u8; VirtioNetHdr::LEN],
                );
            }
            let paddr =
                Pipeline::buffer_paddr(tx_pipe_paddr, descriptor.buffer) + header_offset as u64;
            let token = tx
                .add_readable(paddr, descriptor.len + VirtioNetHdr::LEN as u32)
                .expect("a free transmit descriptor was checked before dequeue");
            let index = token.index() as usize;
            self.descriptor[index] = descriptor;
            self.outstanding[index] = true;
            sent = true;
        }
        sent
    }
}

impl<const Q: usize> Default for TxPath<Q> {
    fn default() -> Self {
        Self::new()
    }
}

/// Return a transmitted (or rejected) buffer to the pipeline's pool owner. The
/// free ring is sized above the pool, so a correctly accounted return cannot
/// fail; a failure means a byzantine peer broke buffer accounting, met here by
/// the fail-visible panic that is pd-runtime's tracked containment gap.
fn return_buffer(free: &Ring, descriptor: Descriptor) {
    if free.try_enqueue(descriptor).is_err() {
        panic!("free ring overflow: buffer accounting is broken");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{Ordering, fence};
    use std::boxed::Box;
    use std::vec::Vec;

    const Q: usize = 16;
    type Vq = SplitVirtqueue<Q>;

    /// A 16-byte-aligned virtqueue backing region (the alignment `Vq::new`
    /// requires), large enough for `Vq::LAYOUT.total_bytes`.
    #[repr(C, align(16))]
    struct VqRegion([u8; 4096]);

    impl VqRegion {
        fn boxed() -> Box<Self> {
            Box::new(Self([0; 4096]))
        }
    }

    /// The far side of one virtqueue, playing the device in the same thread: it
    /// reads the driver's available ring, addresses the real Box-backed buffer
    /// the descriptor names, and publishes a used-ring completion — the same
    /// shape as the fake in `crates/virtio/src/queue.rs`.
    struct FakeDevice {
        region: *mut u8,
        last_avail: u16,
        used_idx: u16,
    }

    impl FakeDevice {
        fn new(region: *mut u8) -> Self {
            Self {
                region,
                last_avail: 0,
                used_idx: 0,
            }
        }

        unsafe fn r16(&self, off: usize) -> u16 {
            // SAFETY: `off` is within the live, test-owned region (this fn's contract), aligned for its width.
            unsafe { self.region.add(off).cast::<u16>().read_volatile() }
        }
        unsafe fn w16(&self, off: usize, v: u16) {
            // SAFETY: `off` is within the live, test-owned region (this fn's contract), aligned for its width.
            unsafe { self.region.add(off).cast::<u16>().write_volatile(v) }
        }
        unsafe fn w32(&self, off: usize, v: u32) {
            // SAFETY: `off` is within the live, test-owned region (this fn's contract), aligned for its width.
            unsafe { self.region.add(off).cast::<u32>().write_volatile(v) }
        }
        unsafe fn r32(&self, off: usize) -> u32 {
            // SAFETY: `off` is within the live, test-owned region (this fn's contract), aligned for its width.
            unsafe { self.region.add(off).cast::<u32>().read_volatile() }
        }
        unsafe fn r64(&self, off: usize) -> u64 {
            // SAFETY: `off` is within the live, test-owned region (this fn's contract), aligned for its width.
            unsafe { self.region.add(off).cast::<u64>().read_volatile() }
        }

        fn driver_off() -> usize {
            Vq::LAYOUT.driver_offset
        }
        fn device_off() -> usize {
            Vq::LAYOUT.device_offset
        }

        /// The next head index the driver made available, or `None`.
        fn next_avail(&mut self) -> Option<u16> {
            let d = Self::driver_off();
            // SAFETY: single-threaded test; the offset lies within the live, test-owned virtqueue region.
            let avail_idx = unsafe { self.r16(d + 2) };
            if avail_idx == self.last_avail {
                return None;
            }
            fence(Ordering::Acquire);
            let slot = (self.last_avail as usize) & (Q - 1);
            // SAFETY: single-threaded test; the offset lies within the live, test-owned virtqueue region.
            let head = unsafe { self.r16(d + 4 + slot * 2) };
            self.last_avail = self.last_avail.wrapping_add(1);
            Some(head)
        }

        fn desc_addr(&self, head: u16) -> u64 {
            // SAFETY: `head < Q` (a posted descriptor), so the descriptor fields lie within the owned region.
            unsafe { self.r64(head as usize * 16) }
        }
        fn desc_len(&self, head: u16) -> u32 {
            // SAFETY: `head < Q` (a posted descriptor), so the descriptor fields lie within the owned region.
            unsafe { self.r32(head as usize * 16 + 8) }
        }

        /// Publish a used-ring completion for `head`, reporting `used_len`.
        fn complete(&mut self, head: u16, used_len: u32) {
            let u = Self::device_off();
            let slot = (self.used_idx as usize) & (Q - 1);
            // SAFETY: single-threaded test; the offset lies within the live, test-owned virtqueue region.
            unsafe {
                self.w32(u + 4 + slot * 8, head as u32);
                self.w32(u + 4 + slot * 8 + 4, used_len);
            }
            fence(Ordering::Release);
            self.used_idx = self.used_idx.wrapping_add(1);
            // SAFETY: single-threaded test; the offset lies within the live, test-owned virtqueue region.
            unsafe { self.w16(u + 2, self.used_idx) };
        }

        /// Receive side: fill the next posted buffer with `frame` and complete
        /// it reporting `used_len` (which the caller varies to exercise the
        /// clamp and runt paths). Returns the completed head index.
        fn deliver(&mut self, frame: &[u8], used_len: u32) -> u16 {
            let head = self.next_avail().expect("a buffer was posted");
            let addr = self.desc_addr(head) as *mut u8;
            let cap = self.desc_len(head) as usize;
            let n = frame.len().min(cap);
            // SAFETY: `addr` is the real backing buffer the descriptor names and `n = min(frame, cap)` stays within it.
            unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), addr, n) };
            self.complete(head, used_len);
            head
        }

        /// Transmit side: read out the next posted frame's bytes and complete
        /// it. Returns the bytes the device would have put on the wire.
        fn transmit(&mut self) -> Vec<u8> {
            let head = self.next_avail().expect("a frame was posted");
            let addr = self.desc_addr(head) as *const u8;
            let len = self.desc_len(head) as usize;
            // SAFETY: `addr`/`len` come from the descriptor the driver posted, naming a live buffer of that length.
            let bytes = unsafe { core::slice::from_raw_parts(addr, len) }.to_vec();
            self.complete(head, len as u32);
            bytes
        }
    }

    /// One receive virtqueue over a fresh region, plus the device on its far
    /// side and the pipeline it feeds.
    struct RxFixture {
        pipeline: Box<Pipeline>,
        _region: Box<VqRegion>,
        vq: Vq,
        device: FakeDevice,
        pool_paddr: u64,
    }

    impl RxFixture {
        fn new() -> Self {
            let pipeline = Box::new(Pipeline::new());
            let mut region = VqRegion::boxed();
            let ptr = region.0.as_mut_ptr();
            // SAFETY: `ptr` backs a 16-byte-aligned, zeroed VqRegion owned solely by this test — `Vq::new`'s contract.
            let vq = unsafe { Vq::new(ptr) };
            let device = FakeDevice::new(ptr);
            // The device writes to the descriptor address as a real pointer, so
            // the "physical" pool base is the pool's actual host address.
            let pool_paddr = &pipeline.pool as *const _ as u64;
            Self {
                pipeline,
                _region: region,
                vq,
                device,
                pool_paddr,
            }
        }
    }

    /// One transmit virtqueue over a fresh region, plus the device on its far
    /// side and the pipeline it drains.
    struct TxFixture {
        pipeline: Box<Pipeline>,
        _region: Box<VqRegion>,
        vq: Vq,
        device: FakeDevice,
        pipe_paddr: u64,
    }

    impl TxFixture {
        fn new() -> Self {
            let pipeline = Box::new(Pipeline::new());
            let mut region = VqRegion::boxed();
            let ptr = region.0.as_mut_ptr();
            // SAFETY: `ptr` backs a 16-byte-aligned, zeroed VqRegion owned solely by this test — `Vq::new`'s contract.
            let vq = unsafe { Vq::new(ptr) };
            let device = FakeDevice::new(ptr);
            // `post` computes buffer addresses via `Pipeline::buffer_paddr`
            // from the region base, so the region base is the pipeline's host
            // address; the pool then resolves to its real bytes.
            let pipe_paddr = &*pipeline as *const Pipeline as u64;
            Self {
                pipeline,
                _region: region,
                vq,
                device,
                pipe_paddr,
            }
        }

        /// Place a frame the forwarder would have queued: write `payload` at
        /// `offset` (with a non-zero 12-byte header in front, so the header
        /// zeroing is observable) into pool buffer `buffer`, and enqueue the
        /// matching descriptor on the tx ring.
        fn enqueue_frame(&self, buffer: u32, offset: usize, payload: &[u8]) {
            // SAFETY: single-threaded test; the buffer is not otherwise in use.
            unsafe {
                self.pipeline.pool.write_at(
                    buffer as usize,
                    offset - VirtioNetHdr::LEN,
                    &[0xFFu8; VirtioNetHdr::LEN],
                );
                self.pipeline
                    .pool
                    .write_at(buffer as usize, offset, payload);
            }
            self.pipeline
                .tx
                .try_enqueue(Descriptor::new(buffer, offset as u32, payload.len() as u32))
                .expect("tx ring has room");
        }
    }

    #[test]
    fn refill_posts_up_to_the_queue_when_the_pool_is_larger() {
        let mut fx = RxFixture::new();
        let mut rx = RxPath::<Q>::new();
        let mut producer = Producer::new();

        assert!(rx.refill(&mut fx.vq, &mut producer, fx.pool_paddr));
        // The queue holds Q descriptors, the pool 64 buffers, so the queue is
        // the limit: Q posted, the rest still owned.
        assert_eq!(fx.vq.free_count(), 0);
        assert_eq!(producer.owned(), POOL_BUFFERS - Q);
    }

    #[test]
    fn refill_stops_when_the_pool_is_exhausted() {
        let mut fx = RxFixture::new();
        let mut rx = RxPath::<Q>::new();
        let mut producer = Producer::new();

        // Leave the producer owning fewer buffers than the queue can hold.
        let mut held = Vec::new();
        while producer.owned() > 4 {
            held.push(producer.alloc().unwrap());
        }
        assert!(rx.refill(&mut fx.vq, &mut producer, fx.pool_paddr));
        assert_eq!(producer.owned(), 0);
        // Only four descriptors were consumed; the rest of the queue is free.
        assert_eq!(fx.vq.free_count(), Q - 4);
    }

    #[test]
    fn a_valid_frame_is_submitted_after_the_header() {
        let mut fx = RxFixture::new();
        let mut rx = RxPath::<Q>::new();
        let mut producer = Producer::new();
        let mut counters = Counters::default();

        rx.refill(&mut fx.vq, &mut producer, fx.pool_paddr);
        let payload = [0xA1u8, 0xA2, 0xA3, 0xA4];
        let mut frame = std::vec![0u8; VirtioNetHdr::LEN];
        frame.extend_from_slice(&payload);
        fx.device.deliver(&frame, frame.len() as u32);

        assert!(rx.drain(&mut fx.vq, &mut producer, &fx.pipeline, &mut counters));
        assert_eq!(counters, Counters::default());
        let descriptor = fx.pipeline.rx.try_dequeue().expect("one frame forwarded");
        assert_eq!(descriptor.offset, VirtioNetHdr::LEN as u32);
        assert_eq!(descriptor.len, payload.len() as u32);
        // SAFETY: single-threaded test; we hold the dequeued descriptor.
        let bytes = unsafe {
            fx.pipeline.pool.read(
                descriptor.buffer as usize,
                descriptor.offset as usize,
                descriptor.len,
            )
        };
        assert_eq!(bytes, &payload);
    }

    #[test]
    fn a_not_outstanding_completion_is_rejected_without_recycling() {
        let mut fx = RxFixture::new();
        let mut rx = RxPath::<Q>::new();
        let mut producer = Producer::new();
        let mut counters = Counters::default();

        rx.refill(&mut fx.vq, &mut producer, fx.pool_paddr);
        let frame = std::vec![0u8; VirtioNetHdr::LEN + 8];
        let head = fx.device.deliver(&frame, frame.len() as u32);
        assert!(rx.drain(&mut fx.vq, &mut producer, &fx.pipeline, &mut counters));
        let free_after_first = fx.vq.free_count();

        // The device echoes the same head a second time without a repost: the
        // slot is no longer outstanding, so the duplicate is counted and must
        // NOT be recycled (recycling it would corrupt the virtqueue free list).
        fx.device.complete(head, frame.len() as u32);
        assert!(!rx.drain(&mut fx.vq, &mut producer, &fx.pipeline, &mut counters));
        assert_eq!(counters.rx_not_outstanding, 1);
        assert_eq!(fx.vq.free_count(), free_after_first);
        // The duplicate submitted no second frame.
        assert!(fx.pipeline.rx.try_dequeue().is_some());
        assert!(fx.pipeline.rx.try_dequeue().is_none());
    }

    #[test]
    fn an_over_reported_length_is_clamped_to_the_buffer() {
        let mut fx = RxFixture::new();
        let mut rx = RxPath::<Q>::new();
        let mut producer = Producer::new();
        let mut counters = Counters::default();

        rx.refill(&mut fx.vq, &mut producer, fx.pool_paddr);
        // The device claims far more than the buffer holds.
        fx.device.deliver(&[0u8; 16], BUFFER_SIZE as u32 + 1000);

        assert!(rx.drain(&mut fx.vq, &mut producer, &fx.pipeline, &mut counters));
        assert_eq!(counters, Counters::default());
        let descriptor = fx.pipeline.rx.try_dequeue().expect("frame forwarded");
        // Clamped to the buffer, then the header removed.
        assert_eq!(descriptor.len, (BUFFER_SIZE - VirtioNetHdr::LEN) as u32);
    }

    #[test]
    fn a_runt_frame_is_dropped_and_counted() {
        let mut fx = RxFixture::new();
        let mut rx = RxPath::<Q>::new();
        let mut producer = Producer::new();
        let mut counters = Counters::default();

        rx.refill(&mut fx.vq, &mut producer, fx.pool_paddr);
        let owned_before = producer.owned();
        let free_before = fx.vq.free_count();
        // Nothing past the 12-byte header.
        fx.device
            .deliver(&[0u8; VirtioNetHdr::LEN], (VirtioNetHdr::LEN - 4) as u32);

        assert!(!rx.drain(&mut fx.vq, &mut producer, &fx.pipeline, &mut counters));
        assert_eq!(counters.rx_runt_dropped, 1);
        assert!(fx.pipeline.rx.try_dequeue().is_none());
        // The buffer was released back and the descriptor recycled.
        assert_eq!(producer.owned(), owned_before + 1);
        assert_eq!(fx.vq.free_count(), free_before + 1);
    }

    #[test]
    fn a_buffer_is_released_when_the_forwarder_ring_is_full() {
        let mut fx = RxFixture::new();
        let mut rx = RxPath::<Q>::new();
        let mut producer = Producer::new();
        let mut counters = Counters::default();

        // Fill the forwarder rx ring so every submit fails.
        while fx.pipeline.rx.try_enqueue(Descriptor::ZERO).is_ok() {}

        rx.refill(&mut fx.vq, &mut producer, fx.pool_paddr);
        let owned_before = producer.owned();
        let free_before = fx.vq.free_count();
        let frame = std::vec![0u8; VirtioNetHdr::LEN + 8];
        fx.device.deliver(&frame, frame.len() as u32);

        assert!(!rx.drain(&mut fx.vq, &mut producer, &fx.pipeline, &mut counters));
        assert_eq!(counters, Counters::default());
        // The buffer came back to the producer and the descriptor was recycled;
        // the full forwarder ring is unchanged.
        assert_eq!(producer.owned(), owned_before + 1);
        assert_eq!(fx.vq.free_count(), free_before + 1);
        assert_eq!(fx.pipeline.rx.len(), fx.pipeline.rx.capacity());
    }

    #[test]
    fn a_valid_frame_is_posted_with_a_zeroed_header_and_returned_on_completion() {
        let mut fx = TxFixture::new();
        let mut tx = TxPath::<Q>::new();
        let mut counters = Counters::default();

        let payload = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let descriptor = Descriptor::new(7, VirtioNetHdr::LEN as u32, payload.len() as u32);
        fx.enqueue_frame(7, VirtioNetHdr::LEN, &payload);

        assert!(tx.post(&mut fx.vq, &fx.pipeline, fx.pipe_paddr, &mut counters));
        assert_eq!(counters, Counters::default());

        // The device sees the frame with the 12 header bytes zeroed in front.
        let on_wire = fx.device.transmit();
        assert_eq!(on_wire.len(), VirtioNetHdr::LEN + payload.len());
        assert_eq!(&on_wire[..VirtioNetHdr::LEN], &[0u8; VirtioNetHdr::LEN]);
        assert_eq!(&on_wire[VirtioNetHdr::LEN..], &payload);

        // Reaping the completion returns the original descriptor to its owner.
        tx.reap(&mut fx.vq, &fx.pipeline);
        assert_eq!(fx.pipeline.free.try_dequeue(), Some(descriptor));
        assert_eq!(fx.vq.free_count(), Q);
    }

    #[test]
    fn a_forged_buffer_index_is_dropped_without_a_return() {
        let mut fx = TxFixture::new();
        let mut tx = TxPath::<Q>::new();
        let mut counters = Counters::default();

        // Buffer index past the pool: it has no owner to return to.
        fx.pipeline
            .tx
            .try_enqueue(Descriptor::new(
                POOL_BUFFERS as u32,
                VirtioNetHdr::LEN as u32,
                8,
            ))
            .unwrap();

        assert!(!tx.post(&mut fx.vq, &fx.pipeline, fx.pipe_paddr, &mut counters));
        assert_eq!(counters.tx_malformed, 1);
        assert!(fx.pipeline.free.try_dequeue().is_none());
        assert_eq!(fx.vq.free_count(), Q);
    }

    #[test]
    fn an_out_of_bounds_span_is_dropped_and_the_buffer_returned() {
        let mut fx = TxFixture::new();
        let mut tx = TxPath::<Q>::new();
        let mut counters = Counters::default();

        // Real buffer, but the span runs past the buffer end.
        let bad = Descriptor::new(3, VirtioNetHdr::LEN as u32, BUFFER_SIZE as u32);
        fx.pipeline.tx.try_enqueue(bad).unwrap();

        assert!(!tx.post(&mut fx.vq, &fx.pipeline, fx.pipe_paddr, &mut counters));
        assert_eq!(counters.tx_malformed, 1);
        // The index names a real buffer, so it is returned, not leaked.
        assert_eq!(fx.pipeline.free.try_dequeue(), Some(bad));
        assert_eq!(fx.vq.free_count(), Q);
    }

    #[test]
    fn a_frame_without_header_room_is_dropped_and_the_buffer_returned() {
        let mut fx = TxFixture::new();
        let mut tx = TxPath::<Q>::new();
        let mut counters = Counters::default();

        // In bounds, but the offset leaves no room for the virtio-net header.
        let bad = Descriptor::new(5, (VirtioNetHdr::LEN - 1) as u32, 8);
        fx.pipeline.tx.try_enqueue(bad).unwrap();

        assert!(!tx.post(&mut fx.vq, &fx.pipeline, fx.pipe_paddr, &mut counters));
        assert_eq!(counters.tx_malformed, 1);
        assert_eq!(fx.pipeline.free.try_dequeue(), Some(bad));
        assert_eq!(fx.vq.free_count(), Q);
    }

    #[test]
    fn reap_ignores_a_not_outstanding_completion() {
        let mut fx = TxFixture::new();
        let mut tx = TxPath::<Q>::new();
        let mut counters = Counters::default();

        let payload = [1u8, 2, 3, 4];
        fx.enqueue_frame(9, VirtioNetHdr::LEN, &payload);
        assert!(tx.post(&mut fx.vq, &fx.pipeline, fx.pipe_paddr, &mut counters));
        let head = fx.device.next_avail().expect("a frame was posted");
        fx.device
            .complete(head, (VirtioNetHdr::LEN + payload.len()) as u32);

        // First reap returns the buffer and recycles the descriptor.
        tx.reap(&mut fx.vq, &fx.pipeline);
        assert!(fx.pipeline.free.try_dequeue().is_some());
        let free_after = fx.vq.free_count();

        // A duplicate completion for the same head is no longer outstanding: it
        // must not return a second buffer or recycle again.
        fx.device.complete(head, 0);
        tx.reap(&mut fx.vq, &fx.pipeline);
        assert!(fx.pipeline.free.try_dequeue().is_none());
        assert_eq!(fx.vq.free_count(), free_after);
    }
}
