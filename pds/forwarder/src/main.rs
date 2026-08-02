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
//! Untrusted network traffic **and** a byzantine neighbour PD.
//! Every descriptor read here, every byte parsed, and the configuration decided
//! under were written by another domain or by whatever is attached to a
//! dataplane port. All three are rejected by a counted drop rather than a fault,
//! in `net_headers`, `routing` and `pd_runtime`.
//!
//! # Constraints
//!
//! Two [`ForwardRings`] regions, the two [`Pool`]s they index, the two
//! configuration regions, the capture tap, its own log ring and its own metric
//! shard are the entire grant — no device capability, and of each pipeline not
//! the `free` ring, on which a forged return would put a live DMA target back
//! onto an owner's free stack. The pool is mapped because a routed frame's
//! headers are rewritten in place, so a compromised forwarder can corrupt a
//! frame in flight; it still cannot forge a return.
//!
//! Ring handles are taken once and kept, a handle being this domain's position.
//! A wakeup names no port, so both pipelines drain unconditionally; the drivers
//! poll, so nothing is notified onward.
//!
//! # There is no configuration in this file
//!
//! The forwarding table arrives at run time, and generation 0 — no interfaces,
//! nothing forwarded — is what this domain runs under until one does: the
//! absence of policy rather than a default. What is compiled in is the
//! *wiring*, which the system description fixes at build time.
//!
//! Records go to a ring, not `debug_println!` — no `seL4_DebugPutChar` in the
//! release kernel.
//!
//! # Every frame the router decides on is offered to the recorder
//!
//! This domain never waits on the tap ring: a full one costs the newest
//! observation and is counted, because a tap that backpressured forwarding
//! would let a traffic generator stall the dataplane. What is recorded is
//! `pd_runtime::RouteStage`'s.
//!
//! # Numbers go to a shard, once per wakeup
//!
//! Every drop this domain counts reaches one region it is the sole writer of,
//! which the management domain maps read-only and renders into `GET /metrics`.
//! The write is at the end of a wakeup and not per frame, off the hot path.

use lfw_log::{Domain, DomainDetail, DomainState, Event, GenerationOutcome, RingSink, Sink};
use lfw_metrics::StatsShard;
use pd_runtime::{
    ConfigAck, ConfigHandover, Configuration, ConfigurationSwitch, ForwardRings, MAX_INTERFACES,
    MAX_NEIGHBOURS, Offer, PdClock, Pool, RouteStage, Tap, attach_region, forwarder_sample,
    log_sample,
};
use routing::PortId;
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, protection_domain};
use wire::{ClockCalibration, LogConsume, LogRecords, TapConsume, TapRecords};

const PORT0: PortId = PortId(0);
const PORT1: PortId = PortId(1);

/// How many dataplane ports this domain is wired to. An offered configuration
/// is held to it, so a table naming a port with no driver is refused here too.
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
    let clock: &'static ClockCalibration = attach_region!(clock_vaddr: ClockCalibration);
    let tap_records: &'static TapRecords = attach_region!(tap_vaddr: TapRecords);
    let tap_consume: &'static TapConsume = attach_region!(tap_consume_vaddr: TapConsume);
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(clock));

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
        tap: Tap::attach(tap_records, tap_consume),
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
    /// One per domain: a packet identity is per appliance.
    tap: Tap<'static>,
    handover: &'static ConfigHandover,
    ack: &'static ConfigAck,
    /// The one region this domain writes its counters into.
    stats: &'static StatsShard,
    /// Kept for the domain's life; a second half would restart at slot zero.
    sink: RingSink<'static, PdClock<'static>>,
}

impl Forwarder {
    /// Write everything this domain counts into its shard. Assembled in
    /// `pd_runtime::stats`, where a test holds the metric surface's vocabulary
    /// to the enums it names; this file supplies the log ring's own drop
    /// counts and the region.
    fn publish(&self) {
        let sample = forwarder_sample(
            [self.stages[0].counters_ref(), self.stages[1].counters_ref()],
            self.switch.generation(),
            self.switch.counters(),
            self.tap.counters(),
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
            stage.poll(configuration, Some(&mut self.tap));
        }
        self.publish();
        Ok(())
    }
}
