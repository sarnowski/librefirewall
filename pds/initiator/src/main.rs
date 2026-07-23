#![no_main]
#![no_std]

//! Producer protection domain.
//!
//! Drives the dataplane round-trip: fills buffers from the shared pool with a
//! monotonic sequence number and publishes them on the `used` ring, reclaiming
//! emptied buffers the consumer returns on `free`. The exchange is paced by
//! notifications — one per batch — so the hot path stays out of the kernel.

use pd_runtime::{Producer, Shared};
use sel4_microkit::{
    Channel, ChannelSet, Handler, Infallible, debug_println, memory_region_symbol,
    protection_domain,
};

const CONSUMER: Channel = Channel::new(0);

/// Total buffers pushed through the round-trip. Chosen well above the pool and
/// ring sizes so the run wraps both rings many times and reuses every buffer.
const TOTAL: u64 = 1024;

/// Buffers published per notification.
const BATCH: u64 = 16;

#[protection_domain]
fn init() -> ProducerPd {
    // SAFETY: `dataplane_vaddr` is patched by the Microkit tool to the address
    // of the region mapped read-write into this PD; the region is zeroed by
    // seL4 and shared only with the consumer under the dataplane protocol.
    let shared =
        unsafe { Shared::attach(memory_region_symbol!(dataplane_vaddr: *mut Shared).as_ptr()) };
    debug_println!("LIBREFIREWALL_DATAPLANE:producer:start");

    let mut producer = Producer::new();
    let sent = produce_batch(&mut producer, shared, 0);
    CONSUMER.notify();

    ProducerPd {
        shared,
        producer,
        sent,
    }
}

struct ProducerPd {
    shared: &'static Shared,
    producer: Producer,
    sent: u64,
}

impl Handler for ProducerPd {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        assert!(channels.contains(CONSUMER));
        self.producer.reclaim(&self.shared.free);
        if self.sent < TOTAL {
            self.sent = produce_batch(&mut self.producer, self.shared, self.sent);
            CONSUMER.notify();
        }
        Ok(())
    }
}

/// Publish up to [`BATCH`] buffers starting at sequence `from`, each carrying
/// its sequence number as eight little-endian bytes, and return the new sent
/// total. Stops early if the producer momentarily runs out of buffers; the next
/// notification reclaims and continues.
fn produce_batch(producer: &mut Producer, shared: &Shared, from: u64) -> u64 {
    let end = if from + BATCH < TOTAL {
        from + BATCH
    } else {
        TOTAL
    };
    let mut sequence = from;
    while sequence < end {
        if !producer.produce(&shared.pool, &shared.used, &sequence.to_le_bytes()) {
            break;
        }
        sequence += 1;
    }
    sequence
}
