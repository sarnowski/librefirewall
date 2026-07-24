#![no_main]
#![no_std]

//! virtio-net driver protection domain: it drives one dataplane port (QEMU
//! q35, virtio 1.0 PCI). One instance runs per dataplane port of the current
//! two-port forwarding bring-up; the management, session-replication, and
//! mirror roles of the full port model (CONCEPT §9) are future ports, not part
//! of this slice.
//!
//! The same binary serves both ports: the Microkit tool patches each instance
//! with its own device windows (ECAM page, relocated BAR), its own virtqueue
//! DMA region, and the two pipeline regions it participates in. The driver
//! brings up the NIC entirely from static capabilities: it reaches PCI config
//! space through the mapped ECAM window, reprograms the device's MMIO BAR to
//! the address this PD pre-mapped, negotiates virtio 1.0, sets up the receive
//! and transmit virtqueues in a DMA region, and then polls both used rings —
//! there is no interrupt (the polling rationale is below).
//!
//! Both directions are **zero-copy** over one buffer pool per pipeline:
//!
//! - **Receive**: the receive buffers are the `rx` pipeline's pool itself, so
//!   the NIC DMAs each frame directly into a buffer the forwarder and the
//!   peer driver read in place. On completion the driver publishes a
//!   descriptor for the frame span (after the 12-byte virtio-net header) and
//!   reposts buffers returned on the pipeline's free ring.
//! - **Transmit**: frames arrive as descriptors on the `tx` pipeline's tx
//!   ring, pointing into that pipeline's pool (owned by the peer driver). The
//!   driver zeroes the 12 header bytes in front of the frame — space the
//!   receiving side reserved — and hands the device the same buffer to DMA
//!   out of. On completion the buffer goes back to its owner on the free
//!   ring. Descriptors come from a neighbouring PD and are validated before
//!   any byte of the span is touched.
//!
//! Because Microkit has no periodic wakeup, the driver polls by never
//! returning from `init`; the forwarder runs at a higher priority and
//! preempts on notification, so the busy loop does not starve it.

use pd_runtime::{
    BUFFER_SIZE, Descriptor, POOL_BUFFERS, Pipeline, Producer, Ring, descriptor_in_bounds,
};
use sel4_microkit::{Channel, debug_println, memory_region_symbol, protection_domain, var};
use virtio::net::{VirtioNetHdr, features};
use virtio::pci::{
    self, CommonCfg, PciConfig, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK,
    STATUS_FEATURES_OK, VIRTIO_NET_DEVICE_ID, VIRTIO_VENDOR_ID,
};
use virtio::queue::SplitVirtqueue;

const FORWARDER: Channel = Channel::new(0);

/// virtio-net virtqueue indices: queue 0 receives, queue 1 transmits.
const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;
/// Descriptors per virtqueue (buffers posted to the NIC at once).
const QUEUE_SIZE: usize = 16;
/// Byte offset of the transmit virtqueue within the virtqueue DMA region; the
/// receive virtqueue sits at offset 0.
const TX_VQ_OFFSET: usize = 0x800;
/// Size of the virtqueue DMA region (matches librefirewall.system).
const VQ_REGION_SIZE: usize = 0x1000;
/// Size of the mapped BAR window (matches librefirewall.system); every
/// device-supplied BAR offset is bounded against this before use.
const BAR_SIZE: usize = 0x4000;

type Vq = SplitVirtqueue<QUEUE_SIZE>;

// Both virtqueues must fit their DMA region, with the transmit queue's
// 16-byte descriptor-table alignment preserved.
const _: () = assert!(Vq::LAYOUT.total_bytes <= TX_VQ_OFFSET);
const _: () = assert!(TX_VQ_OFFSET % 16 == 0);
const _: () = assert!(TX_VQ_OFFSET + Vq::LAYOUT.total_bytes <= VQ_REGION_SIZE);

#[protection_domain]
fn init() -> NicDriver {
    debug_println!("LIBREFIREWALL_NIC:driver:start");

    // Mapped windows and DMA physical addresses, all patched by the Microkit
    // tool from librefirewall.system. The pointers are just addresses here; their
    // use below (config access, ring setup) carries the safety.
    let ecam = memory_region_symbol!(ecam_vaddr: *mut u8).as_ptr();
    let bar = memory_region_symbol!(bar_vaddr: *mut u8).as_ptr();
    let vq = memory_region_symbol!(vq_vaddr: *mut u8).as_ptr();
    // SAFETY: patched to the pipeline regions shared read-write with the
    // forwarder and the peer driver PD. `rx_pipe`'s buffer pool doubles as
    // this NIC's receive DMA source; `tx_pipe`'s as its transmit DMA source.
    let rx_pipe =
        unsafe { Pipeline::attach(memory_region_symbol!(rx_pipe_vaddr: *mut Pipeline).as_ptr()) };
    let tx_pipe =
        unsafe { Pipeline::attach(memory_region_symbol!(tx_pipe_vaddr: *mut Pipeline).as_ptr()) };
    let bar_paddr = *var!(bar_paddr: usize = 0);
    let vq_paddr = *var!(vq_paddr: usize = 0) as u64;
    let rx_pipe_paddr = *var!(rx_pipe_paddr: usize = 0) as u64;
    let tx_pipe_paddr = *var!(tx_pipe_paddr: usize = 0) as u64;
    assert!(
        bar_paddr != 0 && bar_paddr <= u32::MAX as usize && bar_paddr % BAR_SIZE == 0,
        "BAR relocation target must be a BAR-size-aligned 32-bit address"
    );

    // --- Stage A: PCI discovery ---
    let config = unsafe { PciConfig::new(ecam) };
    let (vendor, device) = config.ids();
    debug_println!("LIBREFIREWALL_NIC:pci vendor={vendor:#06x} device={device:#06x}");
    assert!(
        vendor == VIRTIO_VENDOR_ID && device == VIRTIO_NET_DEVICE_ID,
        "expected a modern virtio-net device at the pinned BDF"
    );

    let caps = pci::find_virtio_caps(&config).expect("virtio PCI capabilities");
    debug_println!(
        "LIBREFIREWALL_NIC:caps bar={} common={:#x} notify={:#x} mult={} device={:#x}",
        caps.bar,
        caps.common,
        caps.notify,
        caps.notify_multiplier,
        caps.device
    );

    // The structure offsets come from the untrusted device; refuse to proceed
    // unless they fit the BAR window we mapped, and unless the BAR is the
    // 64-bit kind we relocate.
    assert!(
        caps.within(BAR_SIZE),
        "virtio structures outside the mapped BAR window"
    );
    assert!(
        config.bar_is_64bit(caps.bar),
        "expected a 64-bit virtio BAR"
    );

    // --- Stage B: relocate the BAR, enable the device, negotiate virtio 1.0 ---
    config.reprogram_bar64(caps.bar, bar_paddr as u32);
    config.enable_memory_and_bus_master();

    let common = unsafe { CommonCfg::new(bar.add(caps.common as usize)) };
    common.reset();
    common.set_status(STATUS_ACKNOWLEDGE);
    common.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    let offered = common.device_features();
    let negotiated = offered & (features::VIRTIO_F_VERSION_1 | features::VIRTIO_NET_F_MAC);
    assert!(
        negotiated & features::VIRTIO_F_VERSION_1 != 0,
        "device does not offer virtio 1.0"
    );
    common.set_driver_features(negotiated);
    common.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    assert!(
        common.status() & STATUS_FEATURES_OK != 0,
        "device rejected the negotiated features"
    );
    assert!(
        common.num_queues() > TX_QUEUE,
        "device offers no transmit virtqueue"
    );
    debug_println!("LIBREFIREWALL_NIC:features negotiated={negotiated:#x}");

    // Both virtqueues live in the DMA region: receive at offset 0, transmit at
    // TX_VQ_OFFSET. The receive buffers are the rx pipeline's pool; the
    // transmit buffers are the tx pipeline's pool.
    let mut rx = unsafe { Vq::new(vq) };
    let mut tx = unsafe { Vq::new(vq.add(TX_VQ_OFFSET)) };
    let rx_notify_off = common.setup_queue(RX_QUEUE, &Vq::LAYOUT, vq_paddr);
    let tx_notify_off = common.setup_queue(TX_QUEUE, &Vq::LAYOUT, vq_paddr + TX_VQ_OFFSET as u64);
    for notify_off in [rx_notify_off, tx_notify_off] {
        assert!(
            caps.notify as usize + pci::notify_offset_bytes(notify_off, caps.notify_multiplier) + 2
                <= BAR_SIZE,
            "queue notify slot outside the mapped BAR window"
        );
    }
    let notify_base = unsafe { bar.add(caps.notify as usize) };

    let mut producer = Producer::new();
    // Per virtio descriptor: what was posted in it, and whether it is
    // currently outstanding at the device. `outstanding` lets the driver
    // reject a duplicate or forged completion from the untrusted device,
    // which would otherwise double-own a buffer and corrupt the virtqueue
    // free list.
    let mut rx_buffer = [0u32; QUEUE_SIZE];
    let mut rx_outstanding = [false; QUEUE_SIZE];
    let mut tx_descriptor = [Descriptor::ZERO; QUEUE_SIZE];
    let mut tx_outstanding = [false; QUEUE_SIZE];
    refill(
        &mut rx,
        &mut producer,
        &mut rx_buffer,
        &mut rx_outstanding,
        rx_pipe_paddr,
    );

    // DRIVER_OK before the first doorbell: a device need not act on
    // notifications until the driver signals it is ready.
    common.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    unsafe {
        pci::notify_queue(notify_base, rx_notify_off, caps.notify_multiplier, RX_QUEUE);
    }
    debug_println!("LIBREFIREWALL_NIC:driver-ok rx-posted={QUEUE_SIZE}");

    // Latch for the malformed-descriptor diagnostic: a hostile neighbour must
    // not be able to drive unbounded serial output.
    let mut reported_malformed = false;

    // --- Stage C: zero-copy receive + transmit loop (never returns) ---
    loop {
        // Receive: reclaim returned buffers, repost them to the NIC, and hand
        // completed frames to the forwarder.
        producer.reclaim(&rx_pipe.free);
        let reposted = refill(
            &mut rx,
            &mut producer,
            &mut rx_buffer,
            &mut rx_outstanding,
            rx_pipe_paddr,
        );
        let mut received = false;
        while let Some((token, used_len)) = rx.poll() {
            let index = token.index() as usize;
            // Reject a completion for a descriptor that is not outstanding: a
            // duplicate or forged used-ring entry from the untrusted device.
            // Do not recycle it — recycling a non-outstanding descriptor would
            // corrupt the virtqueue free list.
            if !core::mem::replace(&mut rx_outstanding[index], false) {
                continue;
            }
            let buffer = rx_buffer[index];
            // `used_len` is device-controlled; clamp to the buffer so a device
            // that over-reports cannot make a downstream PD read out of bounds.
            let frame_len = (used_len as usize)
                .min(BUFFER_SIZE)
                .saturating_sub(VirtioNetHdr::LEN) as u32;
            // Hand the frame span (after the virtio header) to the forwarder
            // with no copy; the buffer is owned downstream until it comes back
            // on the free ring.
            if producer.submit(&rx_pipe.rx, buffer, VirtioNetHdr::LEN as u32, frame_len) {
                received = true;
            } else {
                producer.release(buffer);
            }
            rx.recycle(token);
        }
        if received {
            FORWARDER.notify();
        }
        if reposted {
            unsafe {
                pci::notify_queue(notify_base, rx_notify_off, caps.notify_multiplier, RX_QUEUE);
            }
        }

        // Transmit: reap completions first (returning each buffer to its
        // pool-owning peer), then post frames the forwarder queued.
        while let Some((token, _written)) = tx.poll() {
            let index = token.index() as usize;
            if !core::mem::replace(&mut tx_outstanding[index], false) {
                continue;
            }
            return_buffer(&tx_pipe.free, tx_descriptor[index]);
            tx.recycle(token);
        }
        let mut sent = false;
        while tx.free_count() > 0 {
            let Some(descriptor) = tx_pipe.tx.try_dequeue() else {
                break;
            };
            // The descriptor crossed a protection-domain boundary and is not
            // trusted: the span must lie within one pool buffer and leave room
            // for the virtio-net header in front of the frame.
            if !descriptor_in_bounds(&descriptor)
                || (descriptor.offset as usize) < VirtioNetHdr::LEN
            {
                if !reported_malformed {
                    reported_malformed = true;
                    debug_println!("LIBREFIREWALL_NIC:malformed-tx-descriptor(s) dropped");
                }
                // Return the buffer when the index at least names a real pool
                // buffer, so a bad span does not leak it; a forged index has
                // no owner to return to and is dropped.
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
            // SAFETY: we own the buffer between dequeue and completion, the
            // index and span were validated above.
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
            tx_descriptor[token.index() as usize] = descriptor;
            tx_outstanding[token.index() as usize] = true;
            sent = true;
        }
        if sent {
            unsafe {
                pci::notify_queue(notify_base, tx_notify_off, caps.notify_multiplier, TX_QUEUE);
            }
        }

        core::hint::spin_loop();
    }
}

/// Post free pool buffers to the NIC's receive queue until either the queue or
/// the pool runs dry, recording which buffer went in each descriptor. Returns
/// whether any buffer was posted (so the caller knows to ring the doorbell).
fn refill(
    rx: &mut Vq,
    producer: &mut Producer,
    rx_buffer: &mut [u32; QUEUE_SIZE],
    rx_outstanding: &mut [bool; QUEUE_SIZE],
    rx_pipe_paddr: u64,
) -> bool {
    let mut posted = false;
    loop {
        let Some(buffer) = producer.alloc() else {
            break;
        };
        let paddr = Pipeline::buffer_paddr(rx_pipe_paddr, buffer);
        match rx.add_writable(paddr, BUFFER_SIZE as u32) {
            Some(token) => {
                rx_buffer[token.index() as usize] = buffer;
                rx_outstanding[token.index() as usize] = true;
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

/// Return a transmitted (or rejected) buffer to the pipeline's pool owner. The
/// free ring is sized above the pool, so a correctly accounted return cannot
/// fail; a failure means the single-ownership invariant broke.
fn return_buffer(free: &Ring, descriptor: Descriptor) {
    if free.try_enqueue(descriptor).is_err() {
        panic!("free ring overflow: buffer accounting is broken");
    }
}

/// The driver never returns from `init`, so this handler is only a type for the
/// Microkit entrypoint signature; its methods are never invoked.
struct NicDriver;

impl sel4_microkit::Handler for NicDriver {
    type Error = sel4_microkit::Infallible;

    fn notified(&mut self, _channels: sel4_microkit::ChannelSet) -> Result<(), Self::Error> {
        Ok(())
    }
}
