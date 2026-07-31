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
//! Two [`ForwardRings`] regions, the two [`Pool`]s they index, the two
//! configuration regions, its own log ring and its own metric shard are the
//! entire grant — no device capability, and of each pipeline not the `free`
//! ring, on which a forged return would put a live DMA target back onto an
//! owner's free stack. The pool is mapped because a routed frame's headers are
//! rewritten in place, so a compromised forwarder can corrupt a frame in flight;
//! it still cannot forge a return. The handover region is read-only.
//!
//! Ring handles are taken once and kept for the domain's life, a handle being
//! this domain's position: one per notification would restart at slot zero and
//! re-deliver. A wakeup names no port, so both pipelines drain unconditionally;
//! the drivers poll, so nothing is notified onward.
//!
//! # There is no configuration in this file
//!
//! The forwarding table arrives at run time from the configuration domain, and
//! generation 0 — no interfaces, no neighbours, nothing forwarded — is what this
//! domain runs under until one does: the absence of policy rather than a
//! default. What is still compiled in is the *wiring* (CONCEPT §12.3).
//!
//! # Records go to a ring, not to `debug_println!`
//!
//! That macro compiles to `seL4_DebugPutChar`, absent from the release kernel.
//!
//! # Numbers go to a shard, once per wakeup
//!
//! Every drop this domain counts now reaches one shared region it is the sole
//! writer of, which the management domain maps read-only and renders into
//! `GET /metrics`. The write is at the end of a wakeup and not per frame, so a
//! pass of up to `DRAIN_LIMIT` descriptors costs one bounded run of relaxed
//! stores (OBS-3).

use lfw_log::{Domain, DomainDetail, DomainState, Event, GenerationOutcome, RingSink, Sink};
use lfw_metrics::StatsShard;
use pd_runtime::{
    ConfigAck, ConfigHandover, Configuration, ConfigurationSwitch, ForwardRings, MAX_INTERFACES,
    MAX_NEIGHBOURS, Offer, Pool, RouteStage, attach_region, forwarder_sample, log_sample,
};
use routing::PortId;
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, protection_domain};
use wire::{LogConsume, LogRecords};

const PORT0: PortId = PortId(0);
const PORT1: PortId = PortId(1);

/// How many dataplane ports this domain is wired to — the same build fact
/// [`PORT0`] and [`PORT1`] express. An offered configuration is held to it, so
/// a table naming a port with no driver is refused here too.
const PORTS: u8 = 2;

/// The configuration domain. Unlike the driver channels, this one carries
/// notifications both ways; see the system description on why.
const CONFIG: Channel = Channel::new(2);

#[protection_domain]
fn init() -> Forwarder {
    let fwd0: &'static ForwardRings = attach_region!(fwd0_vaddr: ForwardRings);
    let fwd1: &'static ForwardRings = attach_region!(fwd1_vaddr: ForwardRings);
    let pool0: &'static Pool = attach_region!(pool0_vaddr: Pool);
    let pool1: &'static Pool = attach_region!(pool1_vaddr: Pool);
    let handover: &'static ConfigHandover = attach_region!(cfg_vaddr: ConfigHandover);
    let ack: &'static ConfigAck = attach_region!(cfgack_vaddr: ConfigAck);
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let stats: &'static StatsShard = attach_region!(stats_vaddr: StatsShard);
    let sink = RingSink::new(log.writer(log_consume));

    sink.emit(&Event::Domain {
        domain: Domain::Forwarder,
        state: DomainState::Starting,
        detail: DomainDetail::None,
    });
    // Recorded, so a node that never leaves the fail-closed generation is
    // distinguishable from one that was never configured at all.
    sink.emit(&applied(0));

    Forwarder {
        stages: [
            RouteStage::attach(fwd0, pool0, PORT0, PORT1),
            RouteStage::attach(fwd1, pool1, PORT1, PORT0),
        ],
        switch: ConfigurationSwitch::new(PORTS),
        handover,
        ack,
        stats,
        sink,
    }
}

const fn applied(generation: u32) -> Event {
    Event::ConfigGeneration {
        generation,
        outcome: GenerationOutcome::Applied,
        // The diff is the publisher's record; this says what carries traffic.
        changes: 0,
    }
}

struct Forwarder {
    stages: [RouteStage<'static>; 2],
    switch: ConfigurationSwitch<MAX_INTERFACES, MAX_NEIGHBOURS>,
    handover: &'static ConfigHandover,
    ack: &'static ConfigAck,
    /// The one region this domain writes its counters into.
    stats: &'static StatsShard,
    /// Kept for the domain's life; a second half would restart at slot zero.
    sink: RingSink<'static>,
}

impl Forwarder {
    /// Write everything this domain counts into its shard. Assembled in
    /// `pd_runtime::stats`, where a test holds the metric surface's vocabulary
    /// to the enums it names (LAY-2); this file supplies the log ring's own drop
    /// counts and the region.
    fn publish(&self) {
        let sample = forwarder_sample(
            [self.stages[0].counters_ref(), self.stages[1].counters_ref()],
            self.switch.generation(),
            self.switch.counters(),
            log_sample(self.sink.dropped(), self.sink.refused()),
        );
        self.stats.publish(&sample.values());
    }
}

impl Handler for Forwarder {
    type Error = Infallible;

    /// A wakeup names neither a port nor a reason, so every question is asked
    /// of the regions: take a newly offered configuration, switch to one the
    /// publisher has released, then drain both pipelines. The order is what
    /// makes a commit atomic — the switch cannot happen during a poll, so a
    /// frame is decided entirely under one generation.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        if let Some(offer) = self.switch.take_offer(self.handover, self.ack) {
            if let Some(event) = offer.event() {
                self.sink.emit(&event);
            }
            if matches!(offer, Offer::Staged { .. }) {
                // The publisher commits nothing until it sees this.
                CONFIG.notify();
            }
        }
        if let Some(generation) = self.switch.take_commit(self.handover, self.ack) {
            self.sink.emit(&applied(generation));
        }
        let configuration: Configuration<'_, MAX_INTERFACES, MAX_NEIGHBOURS> =
            self.switch.configuration();
        for stage in &mut self.stages {
            stage.poll(configuration);
        }
        self.publish();
        Ok(())
    }
}
