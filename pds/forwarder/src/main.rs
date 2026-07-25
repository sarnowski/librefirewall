#![no_main]
#![no_std]
// Binary crate: no library API to document.
#![allow(missing_docs)]

//! Forwarder protection domain — the software stage between the two NIC
//! ports.
//!
//! Each direction is one [`Pipeline`]: pipeline 0 carries frames received on
//! port 0 to port 1's transmitter, pipeline 1 the reverse. On every driver
//! notification the forwarder moves the queued frame descriptors from a
//! pipeline's `rx` ring to its `tx` ring — ownership moves, bytes never do.
//! This is the seat where the classifier and filter shards will later sit;
//! today it forwards everything.
//!
//! Notifications are coalesced, and a wakeup does not say which port it came
//! from, so both pipelines are drained unconditionally. The drivers poll their
//! rings, so no notification is sent onward.

use pd_runtime::{Pipeline, forward};
use sel4_microkit::{
    ChannelSet, Handler, Infallible, debug_println, memory_region_symbol, protection_domain,
};

#[protection_domain]
fn init() -> Forwarder {
    // SAFETY: patched to the pipeline region shared read-write with driver 0 —
    // `Pipeline::attach`'s contract.
    let pipe0 =
        unsafe { Pipeline::attach(memory_region_symbol!(pipe0_vaddr: *mut Pipeline).as_ptr()) };
    // SAFETY: as above, for the pipeline region shared with driver 1.
    let pipe1 =
        unsafe { Pipeline::attach(memory_region_symbol!(pipe1_vaddr: *mut Pipeline).as_ptr()) };
    debug_println!("LIBREFIREWALL_FWD:start");
    Forwarder {
        pipes: [pipe0, pipe1],
        announced: [false; 2],
    }
}

struct Forwarder {
    pipes: [&'static Pipeline; 2],
    announced: [bool; 2],
}

impl Handler for Forwarder {
    type Error = Infallible;

    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        for (direction, pipe) in self.pipes.iter().enumerate() {
            let moved = forward(&pipe.rx, &pipe.tx);
            // One-time serial marker per direction, for boot diagnostics; the
            // system test asserts on actual frame egress, not on this.
            if moved > 0 && !self.announced[direction] {
                self.announced[direction] = true;
                debug_println!(
                    "LIBREFIREWALL_FWD:first-frame port{direction}->port{}",
                    1 - direction
                );
            }
        }
        Ok(())
    }
}
