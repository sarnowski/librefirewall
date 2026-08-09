#![no_main]
#![no_std]

//! Forwarder protection domain — the verdict pipeline between the two NIC
//! ports. Pipeline 0 carries frames received on port 0 to port 1's transmitter
//! and pipeline 1 the reverse: each frame is snapshotted out of the pool,
//! parsed, put through the pipeline, and — if the verdict is to forward it —
//! rewritten for its next hop in place, so ownership and 34 bytes of header
//! move and the payload never does. The two [`RouteStage`]s are per direction
//! because their rings, pool and scratch are; the [`Pipeline`] is not, because a
//! stage of it may hold state spanning both directions of a flow, so it is owned
//! here and lent to each poll.
//!
//! # Adversary
//!
//! Untrusted network traffic **and** a byzantine neighbour PD.
//! Every descriptor read here, every byte parsed, and the configuration decided
//! under were written by another domain or by whatever is attached to a
//! dataplane port. All three are rejected by a counted drop rather than a fault,
//! in `net_headers`, `pipeline` and `pd_runtime`.
//!
//! # An appliance with no owner forwards nothing
//!
//! One word, published by the domain that holds the identity and mapped
//! read-only here, says whether a management plane has taken this appliance. A
//! node that none has forwards nothing at all — every frame is refused under the
//! pipeline's own ownership reason, so it is counted, recorded and named on the
//! console like every other refusal rather than vanishing unexplained.
//!
//! The reading is latched by [`OwnershipWatch`] rather than mirrored: the
//! writer is a peer, and one that could clear the word would hold a switch over
//! the whole dataplane. So this domain follows the one transition a boot can
//! honestly carry — being adopted while it runs — and never the reverse.
//!
//! # Constraints
//!
//! Two [`ForwardRings`] regions, the two [`Pool`]s they index, the two
//! configuration regions, the ownership word, the capture tap, its own log ring
//! and its own metric shard are the entire grant — no device capability, and of
//! each pipeline not
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
//! absence of policy rather than a default. Ownership is the second such
//! arrival and is independent of it: an unowned node with a committed
//! generation forwards nothing, and so does an owned one still on generation 0. What is compiled in is the
//! *wiring*, which the system description fixes at build time.
//!
//! Records go to a ring, not `debug_println!` — no `seL4_DebugPutChar` in the
//! release kernel.
//!
//! # Every frame the pipeline decides on is offered to the recorder
//!
//! This domain never waits on the tap ring: a full one costs the newest
//! observation and is counted, because a tap that backpressured forwarding
//! would let a traffic generator stall the dataplane. What is recorded is
//! `pd_runtime::RouteStage`'s.
//!
//! # A commit re-decides the connection table, a window at a time
//!
//! The filter is consulted once per conversation, so narrowing a rule would leave
//! every conversation it already admitted running. [`PolicySweep`] is what closes
//! that: a commit arms a pass over the flow table, and each wakeup works off one
//! bounded window of it, taking back the flows the new policy would not admit and
//! offering each to the recorder as the end of that conversation. It runs on every
//! wakeup while a pass is owed and costs nothing on the others.
//!
//! How much of a pass one wakeup works off is what the drain left unspent of its
//! own frame budget, so a quiet wakeup finishes a pass four times sooner and a
//! saturated one never spends more on re-deciding than the drain itself cost.
//!
//! The pass therefore advances on wakeups rather than on a timer, which is what
//! bounds the window in the only terms that matter here: a conversation forwards
//! only when its packets arrive, every arriving frame wakes this domain, so a flow
//! the new policy forbids is generating the wakeups that end it. A node forwarding
//! nothing does not finish its pass and is forwarding nothing either.
//!
//! # Numbers go to a shard, once per wakeup
//!
//! Every drop this domain counts reaches one region it is the sole writer of,
//! which the management domain maps read-only and renders into `GET /metrics`.
//! The write is at the end of a wakeup and not per frame, off the hot path.

use lfw_log::{
    Domain, DomainDetail, DomainState, Event, GenerationOutcome, Ownership, RingSink, Sink,
};
use lfw_metrics::StatsShard;
use pd_runtime::{
    ApplianceFlowTable, ApplianceOwnership, ConfigAck, ConfigHandover, Configuration,
    ConfigurationSwitch, ForwardRings, ForwarderCounters, MAX_INTERFACES, MAX_NEIGHBOURS, Offer,
    OwnershipChange, OwnershipWatch, PdClock, PolicySweep, Pool, Revocation, RouteStage, Tap,
    Tracking, attach_flow_table, attach_region, flow_sample, forwarder_sample, log_sample,
    read_timestamp_counter,
};
use pipeline::Pipeline;
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
    let owner: &'static ApplianceOwnership = attach_region!(owner_vaddr: ApplianceOwnership);
    let tap_records: &'static TapRecords = attach_region!(tap_vaddr: TapRecords);
    let tap_consume: &'static TapConsume = attach_region!(tap_consume_vaddr: TapConsume);
    // The one region this domain owns outright, and the only one borrowed
    // mutably anywhere in the system; the macro's safety comment names what
    // makes that sound, and the one clause it cannot delegate — that this is the
    // only borrow ever taken — is checked rather than claimed.
    let flows: &'static mut ApplianceFlowTable = attach_flow_table!(flow_table_vaddr);
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(clock));

    sink.emit(&Event::Domain {
        domain: Domain::Forwarder,
        state: DomainState::Starting,
        detail: DomainDetail::None,
    });
    // Once, and before this domain claims to be running under any generation:
    // every method on the table assumes a linked free list and an occupancy that
    // counts the slots, and a zeroed region has neither — it is only a table with
    // no flows *in* it. A restart therefore starts from an empty table rather
    // than from the previous boot's, which is the right side of that trade for a
    // firewall: connections do not outlive the thing deciding about them.
    //
    // It is between the two records deliberately, so what the walk over a
    // million slots costs at bring-up is a span an operator can read off the
    // console rather than a number somebody measured once.
    flows.initialise();

    // Recorded, so a node that never leaves the fail-closed generation is
    // distinguishable from one that was never configured at all.
    sink.emit(&applied(0));

    // And the other reason this domain may be forwarding nothing, read and said
    // once at bring-up. The two are different things for an operator to go and
    // do — commit a document, or onboard the appliance — and a node that is both
    // says so twice rather than leaving one of them to be guessed at.
    let mut ownership = OwnershipWatch::new();
    ownership.poll(owner);
    sink.emit(&ownership_record(ownership.ownership()));

    Forwarder {
        stages: [
            RouteStage::attach(fwd0, pool0, PORT0, PORT1),
            RouteStage::attach(fwd1, pool1, PORT1, PORT0),
        ],
        pipeline: Pipeline::new(),
        switch: ConfigurationSwitch::new(PORTS),
        sweep: PolicySweep::new(),
        flows,
        clock: PdClock::new(clock),
        owner,
        ownership,
        tap: Tap::attach(tap_records, tap_consume),
        handover,
        ack,
        stats,
        sink,
    }
}

/// What this domain says about ownership: the word an operator reads on the
/// console, in the same spelling the drop reason and the metric label carry.
const fn ownership_record(ownership: pd_runtime::Ownership) -> Event {
    Event::Domain {
        domain: Domain::Forwarder,
        state: DomainState::Ready,
        detail: DomainDetail::Ownership(match ownership {
            pd_runtime::Ownership::Unowned => Ownership::Unowned,
            pd_runtime::Ownership::Owned => Ownership::Owned,
        }),
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
    pipeline: Pipeline,
    switch: ConfigurationSwitch<MAX_INTERFACES, MAX_NEIGHBOURS>,
    /// The re-decision a commit owes the table, carried across wakeups.
    sweep: PolicySweep,
    /// One per domain, not one per pipeline: a flow *is* both directions, so two
    /// tables would be two half-views agreeing about nothing.
    flows: &'static mut ApplianceFlowTable,
    /// Read once per wakeup, for the deadlines the table's timeouts are stated
    /// against. Unclocked it reads the boot instant, under which nothing expires
    /// — the table fills and then refuses, which is fail-closed.
    clock: PdClock<'static>,
    /// The word the domain holding the identity publishes, and this domain's
    /// own latched reading of it. Read every wakeup, because the appliance can
    /// be taken while this domain is running and the transition is the one thing
    /// that changes what it forwards.
    owner: &'static ApplianceOwnership,
    ownership: OwnershipWatch,
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
    /// to the enums it names; this file supplies the log ring's own counts.
    fn publish(&self) {
        let sample = forwarder_sample(&ForwarderCounters {
            pipelines: [self.stages[0].counters_ref(), self.stages[1].counters_ref()],
            generation: self.switch.generation(),
            configuration: self.switch.counters(),
            policy: self.pipeline.policy_counters(),
            // Both halves read from the one table at the same moment, so the
            // occupancy a scrape reports is the occupancy those counters left.
            flow: flow_sample(self.flows.counters(), self.flows.occupancy()),
            sweep: &self.sweep,
            tap: self.tap.counters(),
            log: log_sample(self.sink.dropped(), self.sink.refused()),
        });
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
        // Before the drain, so a wakeup that carries the adoption also carries
        // the first frames this appliance is allowed to forward. Exactly one
        // record can come of it per boot: the reading is latched, so a peer that
        // rewrites the word cannot choose how many lines this domain writes.
        if self.ownership.poll(self.owner) == OwnershipChange::Adopted {
            self.sink
                .emit(&ownership_record(self.ownership.ownership()));
        }
        if let Some(generation) = self.switch.take_commit(self.handover, self.ack) {
            self.sink.emit(&applied(generation));
            // Both tables have just been replaced, so every flow the previous
            // generation admitted is owed a re-decision — including on a commit
            // that changed no rule, a routing change moving which egress a rule
            // is about.
            self.sweep.arm(generation);
        }
        let configuration: Configuration<'_, MAX_INTERFACES, MAX_NEIGHBOURS> =
            self.switch.configuration();
        // One instant for the whole wakeup: a flow's deadlines are seconds and
        // minutes wide, so reading the counter per frame would buy nothing and
        // cost a serialising instruction on the hot path.
        let now = self.clock.monotonic();
        let mut tracking = Tracking::new(self.flows, now);
        // Kept, because it is what the re-decision below sizes its share of this
        // wakeup against: a wakeup that drained little has the budget of a full
        // drain still unspent.
        let mut forwarded = 0usize;
        for stage in &mut self.stages {
            forwarded = forwarded.saturating_add(stage.poll(
                &mut self.pipeline,
                configuration,
                &mut tracking,
                self.ownership.ownership(),
                Some(&mut self.tap),
            ));
        }
        // Unconditionally, and after the drain: the sweep is bounded to a window
        // of slots, so it costs the same whether traffic arrived or not, and a
        // wakeup that forwarded nothing is exactly when there is room to reclaim.
        self.flows.poll(now);
        // And one window of the re-decision a commit owes, if one is owed. After
        // the drain for the timeout sweep's reason, and after it for a second: a
        // frame of a flow this window is about to revoke was decided under the
        // generation in force when it arrived, which is the one that had already
        // committed. The `Tap` is borrowed inside the closure rather than around
        // the call, so nothing but a revoked flow reaches it.
        let Self {
            sweep, flows, tap, ..
        } = self;
        let generation = self.switch.generation();
        let mut tracking = Tracking::new(flows, now);
        sweep.advance(&configuration, &mut tracking, forwarded, |flow| {
            tap.observe_revocation(Revocation {
                timestamp: read_timestamp_counter().0,
                flow,
                generation,
            });
        });
        self.publish();
        Ok(())
    }
}
