#![no_main]
#![no_std]

//! Forwarder protection domain — the software stage between the two NIC ports.
//! Each direction is one [`Pipeline`]: pipeline 0 carries frames received on
//! port 0 to port 1's transmitter, pipeline 1 the reverse. Forwarding moves
//! descriptors from a pipeline's `rx` ring to its `tx` ring — ownership moves,
//! bytes never do.
//!
//! # Adversary
//!
//! A byzantine neighbour PD (CONCEPT §7.1): every descriptor this domain reads
//! was written into shared memory by one of the two NIC driver domains, and
//! nothing about it is trusted.
//!
//! # Constraints
//!
//! The ring handles are taken once at start-up and kept for the domain's life,
//! because a handle *is* this domain's position in a ring: taking one per
//! notification would restart at slot zero and re-deliver descriptors already
//! forwarded.
//!
//! Microkit coalesces notifications and a wakeup does not say which port it
//! came from, so both pipelines are drained unconditionally. The drivers poll
//! their rings, so nothing is notified onward.

use pd_runtime::{ForwardStage, Pipeline, attach_pipeline};
use sel4_microkit::{ChannelSet, Handler, Infallible, debug_println, protection_domain};

#[protection_domain]
fn init() -> Forwarder {
    let pipe0: &'static Pipeline = attach_pipeline!(pipe0_vaddr);
    let pipe1: &'static Pipeline = attach_pipeline!(pipe1_vaddr);
    debug_println!("LIBREFIREWALL_FWD:start");
    Forwarder {
        stages: [ForwardStage::attach(pipe0), ForwardStage::attach(pipe1)],
    }
}

/// The forwarder's steady state: one stage per direction. `'static` is a
/// Microkit memory region's lifetime — mapped for the whole life of the system.
struct Forwarder {
    stages: [ForwardStage<'static>; 2],
}

impl Handler for Forwarder {
    type Error = Infallible;

    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        for stage in &mut self.stages {
            stage.poll();
        }
        Ok(())
    }
}
