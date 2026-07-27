#![no_main]
#![no_std]

//! Forwarder protection domain — the routing stage between the two NIC ports.
//! Pipeline 0 carries frames received on port 0 to port 1's transmitter and
//! pipeline 1 the reverse: each frame is snapshotted out of the pool, parsed,
//! decided on, and — if it is to be forwarded — rewritten for its next hop in
//! place, so ownership and 34 bytes of header move and the payload never does.
//!
//! # Adversary
//!
//! Untrusted network traffic **and** a byzantine neighbour PD (CONCEPT §7.1).
//! Every descriptor read here, every byte parsed, and the configuration decided
//! under were all written by another domain or by whatever is attached to a
//! dataplane port. All three are rejected by a counted drop rather than a
//! fault, in `net_headers`, `routing` and `pd_runtime`, where it is tested.
//!
//! # Constraints
//!
//! Two [`ForwardRings`] regions, the two [`Pool`]s they index, and the two
//! configuration regions are the entire grant — no device capability, and of
//! each pipeline not the `free` ring, on which a forged return would put a live
//! DMA target back onto an owner's free stack. The pool is mapped because a
//! routed frame's L2/L3 headers are rewritten in place, so a compromised
//! forwarder can corrupt a frame in flight; it still cannot forge a return,
//! which is the isolation the region split exists for. The handover region is
//! read-only, so it cannot rewrite the configuration it is judged by either.
//!
//! Ring handles are taken once and kept for the domain's life, a handle being
//! this domain's position: one per notification would restart at slot zero and
//! re-deliver. Microkit coalesces notifications and a wakeup names no port, so
//! both pipelines drain unconditionally; the drivers poll, so nothing is
//! notified onward.
//!
//! # There is no configuration in this file
//!
//! The forwarding table arrives at run time from the configuration domain, and
//! generation 0 — no interfaces, no neighbours, nothing forwarded — is what
//! this domain runs under until one does. That is the absence of policy rather
//! than a default: an appliance whose configuration was refused forwards
//! nothing and says so, instead of carrying traffic under a table nobody wrote.
//! What is still compiled in is the *wiring* — which ports exist and which
//! pipeline joins which pair — fixed by the system description (CONCEPT §12.3).
//!
//! # Why the console `Sink` is written here and not once in `crates/log`
//!
//! Printing needs `sel4_microkit::debug_println`, and everything under
//! `crates/` is deliberately free of Microkit so that it can be host-tested, so
//! each protection domain carries its own dozen lines of backend.

use lfw_log::{
    Domain, DomainDetail, DomainState, Event, GenerationOutcome, MAX_LINE_LEN, Sink, render,
};
use pd_runtime::{
    ConfigAck, ConfigHandover, Configuration, ConfigurationSwitch, ForwardRings, MAX_INTERFACES,
    MAX_NEIGHBOURS, Offer, Pool, RouteStage, attach_region,
};
use routing::PortId;
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, debug_println, protection_domain};

const PORT0: PortId = PortId(0);
const PORT1: PortId = PortId(1);

/// How many dataplane ports this domain is wired to — the same build fact
/// [`PORT0`] and [`PORT1`] express. An offered configuration is held to it, so
/// a table naming a port with no driver is refused here too, not only where it
/// was written.
const PORTS: u8 = 2;

/// The configuration domain. Unlike the driver channels, this one carries
/// notifications both ways; see the system description on why.
const CONFIG: Channel = Channel::new(2);

const CONSOLE: Console = Console;

/// The console as a [`Sink`]: the only channel this build has (CONCEPT §11), so
/// a line that will not render is reported as the event it came from (ENG-12).
struct Console;

impl Sink for Console {
    fn emit(&self, event: &Event) {
        let mut line = [0u8; MAX_LINE_LEN];
        let rendered = render(event, &mut line)
            .ok()
            .and_then(|written| line.get(..written))
            .and_then(|bytes| core::str::from_utf8(bytes).ok());
        match rendered {
            Some(text) => debug_println!("{text}"),
            None => debug_println!("LFW-PD unrendered={event:?}"),
        }
    }
}

#[protection_domain]
fn init() -> Forwarder {
    let fwd0: &'static ForwardRings = attach_region!(fwd0_vaddr: ForwardRings);
    let fwd1: &'static ForwardRings = attach_region!(fwd1_vaddr: ForwardRings);
    let pool0: &'static Pool = attach_region!(pool0_vaddr: Pool);
    let pool1: &'static Pool = attach_region!(pool1_vaddr: Pool);
    let handover: &'static ConfigHandover = attach_region!(cfg_vaddr: ConfigHandover);
    let ack: &'static ConfigAck = attach_region!(cfgack_vaddr: ConfigAck);

    CONSOLE.emit(&Event::Domain {
        domain: Domain::Forwarder,
        state: DomainState::Starting,
        detail: DomainDetail::None,
    });
    // Recorded, so a node that never leaves the fail-closed generation is
    // distinguishable from one that was never configured at all.
    CONSOLE.emit(&applied(0));

    Forwarder {
        stages: [
            RouteStage::attach(fwd0, pool0, PORT0, PORT1),
            RouteStage::attach(fwd1, pool1, PORT1, PORT0),
        ],
        switch: ConfigurationSwitch::new(PORTS),
        handover,
        ack,
    }
}

const fn applied(generation: u32) -> Event {
    Event::ConfigGeneration {
        generation,
        outcome: GenerationOutcome::Applied,
        // The diff is the publishing domain's record; this one says which
        // generation is now carrying traffic.
        changes: 0,
    }
}

struct Forwarder {
    stages: [RouteStage<'static>; 2],
    switch: ConfigurationSwitch<MAX_INTERFACES, MAX_NEIGHBOURS>,
    handover: &'static ConfigHandover,
    ack: &'static ConfigAck,
}

impl Handler for Forwarder {
    type Error = Infallible;

    /// A wakeup names neither a port nor a reason, so every question is asked
    /// of the regions: take a newly offered configuration, switch to one the
    /// publisher has released, then drain both pipelines.
    ///
    /// The order is what makes a commit atomic: the switch happens before the
    /// first poll of this wakeup and cannot happen during one, so a frame is
    /// decided entirely under one generation.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        if let Some(offer) = self.switch.take_offer(self.handover, self.ack) {
            if let Some(event) = offer.event() {
                CONSOLE.emit(&event);
            }
            if matches!(offer, Offer::Staged { .. }) {
                // The publisher commits nothing until it sees this.
                CONFIG.notify();
            }
        }
        if let Some(generation) = self.switch.take_commit(self.handover, self.ack) {
            CONSOLE.emit(&applied(generation));
        }
        let configuration: Configuration<'_, MAX_INTERFACES, MAX_NEIGHBOURS> =
            self.switch.configuration();
        for stage in &mut self.stages {
            stage.poll(configuration);
        }
        Ok(())
    }
}
