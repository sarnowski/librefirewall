#![no_main]
#![no_std]

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
//! The ring handles live in the [`ForwardStage`]s, taken once here at start-up
//! and kept for the domain's life: a handle *is* this domain's position in a
//! ring, so taking one per notification would restart at slot zero and
//! re-deliver descriptors already forwarded (see the `pd_runtime` crate
//! header).
//!
//! Notifications are coalesced, and a wakeup does not say which port it came
//! from, so both pipelines are drained unconditionally. The drivers poll their
//! rings, so no notification is sent onward.

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

/// The forwarder's steady state: one stage per direction.
///
/// `'static` is the region's lifetime — a Microkit memory region is mapped for
/// the whole life of the system — and it is what lets each stage hold its ring
/// handles across notifications instead of re-taking them.
struct Forwarder {
    /// Index 0 forwards port 0 to port 1, index 1 the reverse. Each stage owns
    /// its pipeline's `rx` consumer and `tx` producer handle.
    stages: [ForwardStage<'static>; 2],
}

impl Handler for Forwarder {
    type Error = Infallible;

    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        for stage in &mut self.stages {
            // Bounded per call and drop-and-count on a stalled destination; the
            // tallies are for the future metrics endpoint, and deliberately not
            // for the console, which carries system state only (MONITORING.md).
            stage.poll();
        }
        Ok(())
    }
}
