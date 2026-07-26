#![no_main]
#![no_std]

//! Forwarder protection domain — the software stage between the two NIC ports.
//! Pipeline 0 carries frames received on port 0 to port 1's transmitter and
//! pipeline 1 the reverse, moving descriptors from a pipeline's `rx` ring to
//! its `tx`: ownership moves, bytes never do.
//!
//! # Adversary
//!
//! A byzantine neighbour PD (CONCEPT §7.1): every descriptor this domain reads
//! was written into shared memory by a NIC driver domain and is untrusted.
//!
//! # Constraints
//!
//! Two [`ForwardRings`] regions are the entire grant — no device capability,
//! and of each pipeline only the two rings a descriptor crosses. The 128 KiB
//! pool those descriptors index and the ring they return on are regions this
//! domain holds no mapping for, so a compromised forwarder can neither corrupt
//! a frame in flight nor forge a return; dropping, reordering and duplicating
//! descriptors is what it keeps, and what neighbours survive.
//!
//! Ring handles are taken once and kept for the domain's life, a handle being
//! this domain's position: one per notification would restart at slot zero and
//! re-deliver. Microkit coalesces notifications and a wakeup names no port, so
//! both pipelines drain unconditionally; the drivers poll, so nothing is
//! notified onward.

use pd_runtime::{ForwardRings, ForwardStage, attach_region};
use sel4_microkit::{ChannelSet, Handler, Infallible, debug_println, protection_domain};

#[protection_domain]
fn init() -> Forwarder {
    let fwd0: &'static ForwardRings = attach_region!(fwd0_vaddr: ForwardRings);
    let fwd1: &'static ForwardRings = attach_region!(fwd1_vaddr: ForwardRings);
    debug_println!("LIBREFIREWALL_FWD:start");
    Forwarder {
        stages: [ForwardStage::attach(fwd0), ForwardStage::attach(fwd1)],
    }
}

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
