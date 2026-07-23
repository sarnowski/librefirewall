#![no_main]
#![no_std]

//! virtio-net receive driver protection domain (QEMU q35, virtio 1.0 PCI).
//!
//! Brings up the NIC entirely from static capabilities: it reaches PCI config
//! space through the mapped ECAM window, reprograms the device's MMIO BAR to an
//! address this PD pre-mapped, negotiates virtio 1.0, sets up the receive
//! virtqueue in a DMA region, and then polls the used ring — there is no
//! interrupt (see docs/virtio-net-driver.md for why polling). Each received
//! frame is forwarded, over the shared SPSC ring, to the consumer PD.
//!
//! Because Microkit has no periodic wakeup, the driver polls by never returning
//! from `init`; the consumer runs at a higher priority and preempts on
//! notification, so the busy loop does not starve it.

use pd_runtime::{Producer, Shared};
use sel4_microkit::{Channel, debug_println, memory_region_symbol, protection_domain, var};
use virtio::net::{VirtioNetHdr, features};
use virtio::pci::{
    self, CommonCfg, PciConfig, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK,
    STATUS_FEATURES_OK, VIRTIO_NET_DEVICE_ID, VIRTIO_VENDOR_ID,
};
use virtio::queue::SplitVirtqueue;

const CONSUMER: Channel = Channel::new(0);

/// Receive virtqueue index for virtio-net.
const RX_QUEUE: u16 = 0;
/// Descriptors in the receive queue (also the number of receive buffers).
const RX_QUEUE_SIZE: usize = 16;
/// Size of each receive DMA buffer; holds the 12-byte header plus a full frame.
const RX_BUFFER_SIZE: usize = 2048;
/// Physical address we relocate the device's MMIO BAR to (matches nic.system).
const BAR_ADDR: u32 = 0x5000_0000;
/// Size of the mapped BAR window (matches nic.system); every device-supplied
/// BAR offset is bounded against this before use.
const BAR_SIZE: usize = 0x4000;

type Rx = SplitVirtqueue<RX_QUEUE_SIZE>;

#[protection_domain]
fn init() -> NicDriver {
    debug_println!("LIBREFIREWALL_NIC:driver:start");

    // Mapped windows and DMA physical addresses, all patched by the Microkit
    // tool from nic.system. The pointers are just addresses here; their use
    // below (config access, ring setup, frame reads) carries the safety.
    let ecam = memory_region_symbol!(ecam_vaddr: *mut u8).as_ptr();
    let bar = memory_region_symbol!(bar_vaddr: *mut u8).as_ptr();
    let ring = memory_region_symbol!(rx_ring_vaddr: *mut u8).as_ptr();
    let buffers = memory_region_symbol!(rx_buffers_vaddr: *mut u8).as_ptr();
    // SAFETY: patched to the region shared read-write with the consumer PD.
    let shared =
        unsafe { Shared::attach(memory_region_symbol!(dataplane_vaddr: *mut Shared).as_ptr()) };
    let ring_paddr = *var!(rx_ring_paddr: usize = 0) as u64;
    let buffers_paddr = *var!(rx_buffers_paddr: usize = 0) as u64;

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
    config.reprogram_bar64(caps.bar, BAR_ADDR);
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
    debug_println!("LIBREFIREWALL_NIC:features negotiated={negotiated:#x}");

    // Receive virtqueue in the DMA ring region, its buffers in the DMA buffer
    // region. Buffer i is permanently associated with descriptor i.
    let mut rx = unsafe { Rx::new(ring) };
    let notify_off = common.setup_queue(RX_QUEUE, &Rx::LAYOUT, ring_paddr);
    // The device chose queue_notify_off; bound its resulting slot to the mapped
    // notify window before we ever write the doorbell.
    assert!(
        caps.notify as usize + pci::notify_offset_bytes(notify_off, caps.notify_multiplier) + 2
            <= BAR_SIZE,
        "queue notify slot outside the mapped BAR window"
    );
    let notify_base = unsafe { bar.add(caps.notify as usize) };
    for index in 0..RX_QUEUE_SIZE as u64 {
        rx.add_writable(
            buffers_paddr + index * RX_BUFFER_SIZE as u64,
            RX_BUFFER_SIZE as u32,
        );
    }
    // DRIVER_OK before the first doorbell: a device need not act on
    // notifications until the driver signals it is ready.
    common.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    unsafe {
        pci::notify_queue(notify_base, notify_off, caps.notify_multiplier, RX_QUEUE);
    }
    debug_println!("LIBREFIREWALL_NIC:driver-ok rx-posted={RX_QUEUE_SIZE}");

    // --- Stage C: receive loop (never returns) ---
    let mut producer = Producer::new();
    loop {
        producer.reclaim(shared);
        let mut reposted = false;
        while let Some((token, len)) = rx.poll() {
            let index = token.0 as usize;
            let start = index * RX_BUFFER_SIZE + VirtioNetHdr::LEN;
            // `len` is device-controlled; clamp it to the buffer before slicing
            // so a device that over-reports its write cannot drive an
            // out-of-bounds read (frame_len <= RX_BUFFER_SIZE - 12).
            let frame_len = (len as usize)
                .min(RX_BUFFER_SIZE)
                .saturating_sub(VirtioNetHdr::LEN);
            // SAFETY: `index < 16` (poll bounds the used id) and `frame_len <=
            // RX_BUFFER_SIZE - 12`, so the slice lies within buffer `index` of
            // the mapped rx_buffers region.
            let frame =
                unsafe { core::slice::from_raw_parts(buffers.add(start) as *const u8, frame_len) };
            producer.produce(shared, frame);
            CONSUMER.notify();

            // Return the buffer to the device for reuse.
            rx.recycle(token);
            rx.add_writable(
                buffers_paddr + token.0 as u64 * RX_BUFFER_SIZE as u64,
                RX_BUFFER_SIZE as u32,
            );
            reposted = true;
        }
        if reposted {
            unsafe {
                pci::notify_queue(notify_base, notify_off, caps.notify_multiplier, RX_QUEUE);
            }
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
