#![no_main]
#![no_std]

//! virtio-net receive driver protection domain (QEMU q35, virtio 1.0 PCI).
//!
//! Brings up the NIC entirely from static capabilities: it reaches PCI config
//! space through the mapped ECAM window, reprograms the device's MMIO BAR to an
//! address this PD pre-mapped, negotiates virtio 1.0, sets up the receive
//! virtqueue in a DMA ring, and then polls the used ring — there is no
//! interrupt (see docs/virtio-net-driver.md for why polling).
//!
//! Receive is **zero-copy**: the receive buffers are the shared SPSC pool
//! itself, so the NIC DMAs each frame directly into a buffer the consumer PD
//! reads in place. The driver never touches the frame bytes — on completion it
//! hands the buffer to the consumer by publishing a descriptor for the frame
//! span (after the 12-byte virtio-net header) and reposts buffers the consumer
//! returns.
//!
//! Because Microkit has no periodic wakeup, the driver polls by never returning
//! from `init`; the consumer runs at a higher priority and preempts on
//! notification, so the busy loop does not starve it.

use pd_runtime::{BUFFER_SIZE, Producer, Shared};
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
/// Descriptors in the receive virtqueue (buffers posted to the NIC at once).
const RX_QUEUE_SIZE: usize = 16;
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
    // below (config access, ring setup) carries the safety.
    let ecam = memory_region_symbol!(ecam_vaddr: *mut u8).as_ptr();
    let bar = memory_region_symbol!(bar_vaddr: *mut u8).as_ptr();
    let ring = memory_region_symbol!(rx_ring_vaddr: *mut u8).as_ptr();
    // SAFETY: patched to the region shared read-write with the consumer PD; its
    // buffer pool doubles as the NIC's receive DMA target.
    let shared =
        unsafe { Shared::attach(memory_region_symbol!(dataplane_vaddr: *mut Shared).as_ptr()) };
    let ring_paddr = *var!(rx_ring_paddr: usize = 0) as u64;
    let dataplane_paddr = *var!(dataplane_paddr: usize = 0) as u64;

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

    // The receive virtqueue lives in the DMA ring region; its buffers are the
    // shared SPSC pool, which the driver owns until it posts them to the NIC.
    let mut rx = unsafe { Rx::new(ring) };
    let notify_off = common.setup_queue(RX_QUEUE, &Rx::LAYOUT, ring_paddr);
    assert!(
        caps.notify as usize + pci::notify_offset_bytes(notify_off, caps.notify_multiplier) + 2
            <= BAR_SIZE,
        "queue notify slot outside the mapped BAR window"
    );
    let notify_base = unsafe { bar.add(caps.notify as usize) };

    let mut producer = Producer::new();
    // Per virtio descriptor: the pool buffer posted in it, and whether it is
    // currently outstanding at the device. `outstanding` lets the driver reject
    // a duplicate or forged completion from the untrusted device, which would
    // otherwise double-own a buffer and corrupt the virtqueue free list.
    let mut descriptor_buffer = [0u32; RX_QUEUE_SIZE];
    let mut outstanding = [false; RX_QUEUE_SIZE];
    refill(
        &mut rx,
        &mut producer,
        &mut descriptor_buffer,
        &mut outstanding,
        dataplane_paddr,
    );

    // DRIVER_OK before the first doorbell: a device need not act on
    // notifications until the driver signals it is ready.
    common.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    unsafe {
        pci::notify_queue(notify_base, notify_off, caps.notify_multiplier, RX_QUEUE);
    }
    debug_println!("LIBREFIREWALL_NIC:driver-ok rx-posted={RX_QUEUE_SIZE}");

    // --- Stage C: zero-copy receive loop (never returns) ---
    loop {
        producer.reclaim(shared);
        let reposted = refill(
            &mut rx,
            &mut producer,
            &mut descriptor_buffer,
            &mut outstanding,
            dataplane_paddr,
        );
        while let Some((token, used_len)) = rx.poll() {
            let index = token.0 as usize;
            // Reject a completion for a descriptor that is not outstanding: a
            // duplicate or forged used-ring entry from the untrusted device.
            // Do not recycle it — recycling a non-outstanding descriptor would
            // corrupt the virtqueue free list.
            if !core::mem::replace(&mut outstanding[index], false) {
                continue;
            }
            let buffer = descriptor_buffer[index];
            // `used_len` is device-controlled; clamp to the buffer so a device
            // that over-reports cannot make the consumer read out of bounds.
            let frame_len = (used_len as usize)
                .min(BUFFER_SIZE)
                .saturating_sub(VirtioNetHdr::LEN) as u32;
            // Hand the frame span (after the virtio header) to the consumer with
            // no copy; the buffer is now owned by the consumer until it returns
            // it on the free ring.
            if producer.submit(shared, buffer, VirtioNetHdr::LEN as u32, frame_len) {
                CONSUMER.notify();
            } else {
                producer.release(buffer);
            }
            rx.recycle(token);
        }
        if reposted {
            unsafe {
                pci::notify_queue(notify_base, notify_off, caps.notify_multiplier, RX_QUEUE);
            }
        }
        core::hint::spin_loop();
    }
}

/// Post free pool buffers to the NIC's receive queue until either the queue or
/// the pool runs dry, recording which buffer went in each descriptor. Returns
/// whether any buffer was posted (so the caller knows to ring the doorbell).
fn refill(
    rx: &mut Rx,
    producer: &mut Producer,
    descriptor_buffer: &mut [u32; RX_QUEUE_SIZE],
    outstanding: &mut [bool; RX_QUEUE_SIZE],
    dataplane_paddr: u64,
) -> bool {
    let mut posted = false;
    loop {
        let Some(buffer) = producer.alloc() else {
            break;
        };
        let paddr = Shared::buffer_paddr(dataplane_paddr, buffer);
        match rx.add_writable(paddr, BUFFER_SIZE as u32) {
            Some(token) => {
                descriptor_buffer[token.0 as usize] = buffer;
                outstanding[token.0 as usize] = true;
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

/// The driver never returns from `init`, so this handler is only a type for the
/// Microkit entrypoint signature; its methods are never invoked.
struct NicDriver;

impl sel4_microkit::Handler for NicDriver {
    type Error = sel4_microkit::Infallible;

    fn notified(&mut self, _channels: sel4_microkit::ChannelSet) -> Result<(), Self::Error> {
        Ok(())
    }
}
