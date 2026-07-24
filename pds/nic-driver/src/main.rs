#![no_main]
#![no_std]

//! virtio-net driver protection domain: it drives one dataplane port (QEMU
//! q35, virtio 1.0 PCI). One instance runs per dataplane port of the current
//! two-port forwarding bring-up; the management, session-replication, and
//! mirror roles of the full port model (CONCEPT §9) are future ports, not part
//! of this slice.
//!
//! This binary is a thin adapter. It owns the unsafe, seL4-only device bring-up
//! and the poll loop, and delegates the steady-state dataplane — the
//! device-distrust and peer-distrust logic — to the host-tested
//! `nic-driver-core` crate ([`RxPath`], [`TxPath`], [`Counters`]). The same
//! binary serves both ports: the Microkit tool patches each instance with its
//! own device windows (ECAM page, relocated BAR), its own virtqueue DMA region,
//! and the two pipeline regions it participates in.
//!
//! Bring-up reaches PCI config space through the mapped ECAM window, reprograms
//! the device's MMIO BAR to the address this PD pre-mapped, negotiates virtio
//! 1.0, and sets up the receive and transmit virtqueues in a DMA region. Both
//! directions are then **zero-copy** over one buffer pool per pipeline: the
//! receive buffers are the rx pipeline's pool itself (the NIC DMAs each frame
//! into a buffer the forwarder and peer driver read in place), and transmit
//! frames are DMA'd straight out of the tx pipeline's pool after the driver
//! zeroes the 12-byte virtio-net header in front of the frame.
//!
//! Because Microkit has no periodic wakeup, the driver polls by never returning
//! from `init`; the forwarder runs at a higher priority and preempts on
//! notification, so the busy loop does not starve it. There is no interrupt
//! (no MSI-X, no INTx) by design.

use nic_driver_core::{Counters, RxPath, TxPath};
use pd_runtime::{Pipeline, Producer};
use sel4_microkit::{Channel, debug_println, memory_region_symbol, protection_domain, var};
use virtio::net::features;
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

    // Steady-state bookkeeping lives in the host-tested core; this adapter owns
    // only the device MMIO and the poll loop.
    let mut producer = Producer::new();
    let mut rx_path = RxPath::<QUEUE_SIZE>::new();
    let mut tx_path = TxPath::<QUEUE_SIZE>::new();
    let mut counters = Counters::default();
    let rx_pool_paddr = Pipeline::pool_paddr(rx_pipe_paddr);

    rx_path.refill(&mut rx, &mut producer, rx_pool_paddr);

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
        let reposted = rx_path.refill(&mut rx, &mut producer, rx_pool_paddr);
        if rx_path.drain(&mut rx, &mut producer, rx_pipe, &mut counters) {
            FORWARDER.notify();
        }
        if reposted {
            unsafe {
                pci::notify_queue(notify_base, rx_notify_off, caps.notify_multiplier, RX_QUEUE);
            }
        }

        // Transmit: reap completions first (returning each buffer to its
        // pool-owning peer), then post frames the forwarder queued.
        tx_path.reap(&mut tx, tx_pipe);
        if tx_path.post(&mut tx, tx_pipe, tx_pipe_paddr, &mut counters) {
            unsafe {
                pci::notify_queue(notify_base, tx_notify_off, caps.notify_multiplier, TX_QUEUE);
            }
        }

        // Emit the malformed-descriptor diagnostic once, off the counter going
        // non-zero, so a hostile neighbour cannot flood the console.
        if counters.tx_malformed > 0 && !reported_malformed {
            reported_malformed = true;
            debug_println!("LIBREFIREWALL_NIC:malformed-tx-descriptor(s) dropped");
        }

        core::hint::spin_loop();
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
