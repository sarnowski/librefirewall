#![no_main]
#![no_std]

//! Sink protection domain for the NIC receive path.
//!
//! Drains frames the driver forwards over the shared SPSC ring and, on seeing
//! the injected test frame's magic payload, emits the success marker the QEMU
//! NIC harness asserts on. This proves a real frame crossed from the virtio
//! device, through the driver, over the zero-copy queue, to a second isolated
//! protection domain.

use pd_runtime::{Consumer, Shared};
use sel4_microkit::{
    Channel, ChannelSet, Handler, Infallible, debug_println, memory_region_symbol,
    protection_domain,
};

const DRIVER: Channel = Channel::new(0);

/// Magic payload the harness injects; must match tools/xtask/src/nic_harness.rs.
const MAGIC: &[u8] = b"LIBREFIREWALL-NIC-RX";

#[protection_domain]
fn init() -> NicConsumer {
    // SAFETY: patched to the region shared read-write with the driver PD.
    let shared =
        unsafe { Shared::attach(memory_region_symbol!(dataplane_vaddr: *mut Shared).as_ptr()) };
    NicConsumer {
        shared,
        consumer: Consumer::new(),
        passed: false,
    }
}

struct NicConsumer {
    shared: &'static Shared,
    consumer: Consumer,
    passed: bool,
}

impl Handler for NicConsumer {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        assert!(channels.contains(DRIVER));
        let consumer = &mut self.consumer;
        let passed = &mut self.passed;
        consumer.drain(self.shared, |_buffer, frame| {
            if !*passed && contains(frame, MAGIC) {
                *passed = true;
                debug_println!("LIBREFIREWALL_NIC_PASS:virtio-rx-frame-forwarded");
            }
        });
        Ok(())
    }
}

/// Whether `haystack` contains `needle` as a contiguous subsequence.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
