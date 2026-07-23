#![no_main]
#![no_std]

//! Consumer protection domain.
//!
//! Drains filled buffers off the `used` ring, verifies each carries the next
//! expected sequence number — proving the zero-copy transfer preserved order
//! and content — and returns the emptied buffer on `free`. When the full run
//! has arrived intact it emits the unique success marker the QEMU harness
//! asserts on; a gap or corruption faults the domain loudly instead.

use pd_runtime::{Consumer, Shared};
use sel4_microkit::{
    Channel, ChannelSet, Handler, Infallible, debug_println, memory_region_symbol,
    protection_domain,
};

const PRODUCER: Channel = Channel::new(0);

/// Must match the producer's total.
const TOTAL: u64 = 1024;

#[protection_domain]
fn init() -> ConsumerPd {
    // SAFETY: `dataplane_vaddr` is patched by the Microkit tool to the address
    // of the region mapped read-write into this PD; the region is zeroed by
    // seL4 and shared only with the producer under the dataplane protocol.
    let shared =
        unsafe { Shared::attach(memory_region_symbol!(dataplane_vaddr: *mut Shared).as_ptr()) };
    ConsumerPd {
        shared,
        consumer: Consumer::new(),
        received: 0,
    }
}

struct ConsumerPd {
    shared: &'static Shared,
    consumer: Consumer,
    received: u64,
}

impl Handler for ConsumerPd {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        assert!(channels.contains(PRODUCER));

        let consumer = &mut self.consumer;
        let received = &mut self.received;
        let shared = self.shared;
        consumer.drain(
            &shared.used,
            &shared.free,
            &shared.pool,
            |_buffer, bytes| {
                let value = u64::from_le_bytes(bytes.try_into().expect("8-byte sequence payload"));
                assert!(
                    value == *received,
                    "dataplane out of order: got {}, expected {}",
                    value,
                    *received,
                );
                *received += 1;
            },
        );

        if self.received < TOTAL {
            PRODUCER.notify();
        } else {
            debug_println!("LIBREFIREWALL_DATAPLANE_PASS:spsc-zero-copy-descriptor-round-trip");
        }
        Ok(())
    }
}
