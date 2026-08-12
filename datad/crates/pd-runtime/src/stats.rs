//! Turning what a protection domain has counted into the shard it publishes.
//!
//! `lfw_metrics` carries plain data and depends on none of the crates whose
//! counters it mirrors, so every conversion lives in the crate that *owns* the
//! counters — this one for the dataplane, the endpoint and the transport,
//! `nic_driver_core` for a driver's, `lfw_log` and `uart_16550` for the
//! console's. Each of those is also where a test holds the metric surface's
//! vocabulary tokens to the enum they name; the ones for this module are at the
//! end of it.
//!
//! # Adversary
//!
//! A **byzantine neighbour protection domain**, on the writing
//! side. A shard is one region this domain is the sole writer of and the
//! management domain reads, so a store here is a claim about *this* domain and
//! never about another — which is what makes a per-domain series something an
//! operator can act on, and what makes the read-only grant on the reader's side
//! the whole of the argument (see the system description).

use lfw_blk::request::{Operation, RequestFaults};
use lfw_clock::UtcNanos;
use lfw_flow::{Classification, FlowCounters, FlowState, Occupancy, RefusalKind};
use lfw_ip_endpoint::{Endpoint, TcpCounters, Unhandled};
use lfw_metrics::{
    ConfigSample, EndpointSample, FlowSample, ForwarderSample, HttpSample, LogSample,
    ManagementSample, NeighbourSample, OnboardSample, OutboundSample, PipelineSample, PolicySample,
    PolicySweepSample, PoolSample, ROUTE_DROP_REASONS, RecorderSample, SHARD_COUNT, SINKS,
    SinkSample, Snapshot, StatsShard, StoreSample, TapSample, TcpSample,
};
use lfw_recorder::RecorderCounters;
use wire::StatsRelay;

use net_headers::ParseFailure;
use pipeline::{DropReason, PolicyCounters, PolicySweep, PolicySweepCounters};

use crate::{ConfigCounters, EndpointStageCounters, PoolCounters, RouteCounters, TapCounters};

/// Every stats region the management domain is granted, in `lfw_metrics::SHARDS`
/// order.
///
/// One value rather than eight arguments because the order **is** the ABI: a
/// snapshot reads slot 3 as `nic_driver2`'s, and a domain that handed them over
/// in another order would attribute one port's traffic to another. Copy, so the
/// endpoint that renders from it owns it outright.
#[derive(Clone, Copy)]
pub struct StatsRegions<'ring> {
    pub shards: [&'ring StatsShard; SHARD_COUNT],
}

impl StatsRegions<'_> {
    /// This node's whole metric surface, as one reading.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot::read(self.shards)
    }

    /// Publish one whole reading, stamped with the instant it was taken at.
    pub fn publish_relay(&self, relay: &StatsRelay, utc: Option<UtcNanos>) {
        relay.publish(
            utc.map_or(0, UtcNanos::as_nanos),
            &self.snapshot().relay_values(),
        );
    }

    /// The shard this domain writes its own counters into.
    #[must_use]
    pub fn own(&self) -> &StatsShard {
        // Every index into a fixed array of `SHARD_COUNT` is in range, and the
        // constant is `lfw_metrics`'; the fallback is a value rather than an
        // assertion because nothing about a metric may fault a domain.
        self.shards
            .get(lfw_metrics::MANAGEMENT_SHARD)
            .copied()
            .unwrap_or(self.shards[0])
    }
}

/// One writing domain's own account of its log ring.
#[must_use]
pub const fn log_sample(dropped: u32, refused: u32) -> LogSample {
    LogSample {
        dropped: dropped as u64,
        refused: refused as u64,
    }
}

/// One routed direction, as the forwarder's shard lays it out.
#[must_use]
pub fn pipeline_sample(counters: &RouteCounters) -> PipelineSample {
    let mut route_drops = [0u64; ROUTE_DROP_REASONS.len()];
    for (slot, reason) in DropReason::ALL.iter().enumerate() {
        if let Some(count) = route_drops.get_mut(slot) {
            *count = counters.drops.get(*reason);
        }
    }
    let parse = &counters.unparsable;
    PipelineSample {
        forwarded: counters.forwarded,
        route_drops,
        stage_drops: [
            counters.egress_full,
            counters.malformed_descriptor,
            counters.snapshot_failed,
            parse.get(ParseFailure::FrameTooShort),
            parse.get(ParseFailure::Ethernet),
            parse.get(ParseFailure::Ipv4),
            parse.get(ParseFailure::Ipv4Checksum),
            counters.misrouted,
            counters.writeback_failed,
        ],
    }
}

/// What the filter decided, as the forwarder's shard lays it out.
///
/// The per-rule block is copied out whole rather than only as far as the running
/// generation declared: which positions name a rule is the *renderer's* to decide
/// from the committed configuration, and a writer that stopped early would leave
/// a stale count behind at a position a later, shorter policy no longer reaches.
#[must_use]
pub fn policy_sample(counters: &PolicyCounters) -> PolicySample {
    PolicySample {
        accepted_packets: counters.accepted_packets(),
        accepted_bytes: counters.accepted_bytes(),
        denied_packets: counters.denied_packets(),
        denied_bytes: counters.denied_bytes(),
        rule_hits: *counters.all_hits(),
    }
}

/// What the connection tracker has done, as the forwarder's shard lays it out.
///
/// The two arguments are read from the one table at the same moment, so the
/// occupancy a scrape reports is the occupancy the counters beside it left
/// behind. Every array is filled by iterating the owning enum's `ALL` rather
/// than by a written-out list, which is what keeps the slot order and the label
/// order one order: a state or a refusal added upstream lands in its own slot or
/// fails to compile.
#[must_use]
pub fn flow_sample(counters: &FlowCounters, occupancy: Occupancy) -> FlowSample {
    let mut sample = FlowSample {
        packets_seen: counters.packets_seen,
        outcomes: [0; Classification::ALL.len()],
        refusals: [0; RefusalKind::ALL.len()],
        lifecycle: [
            counters.flows_expired,
            counters.flows_evicted,
            counters.flows_closed,
            counters.flows_withdrawn,
            counters.flows_revoked,
        ],
        entries: [0; FlowState::ALL.len()],
        probe_collisions: counters.probe_tag_collisions,
        slot_desync: counters.internal_slot_desync,
    };
    for (slot, classification) in sample.outcomes.iter_mut().zip(Classification::ALL) {
        *slot = counters.classified(classification);
    }
    for (slot, kind) in sample.refusals.iter_mut().zip(RefusalKind::ALL) {
        *slot = counters.refused(kind);
    }
    for (slot, state) in sample.entries.iter_mut().zip(FlowState::ALL) {
        *slot = u64::from(occupancy.get(state));
    }
    sample
}

/// What the pass re-deciding the table against a newly committed policy has done,
/// as the forwarder's shard lays it out.
///
/// The sweep is taken whole rather than as its counters alone, because the gauge
/// an operator reads the window off — whether a pass is still owed — is state and
/// not a count.
#[must_use]
pub fn policy_sweep_sample(sweep: &PolicySweep) -> PolicySweepSample {
    let PolicySweepCounters {
        completed,
        deferred,
        buckets,
        examined,
    } = sweep.counters();
    PolicySweepSample {
        // In `lfw_metrics::POLICY_SWEEP_OUTCOMES` order, which is the ABI: the
        // pair swapped here would report every deferred commit as a completed pass,
        // and so report a window as closed while it is open.
        outcomes: [completed, deferred],
        running: u64::from(sweep.running()),
        // In `lfw_metrics::POLICY_SWEEP_PROGRESS_KINDS` order.
        progress: [buckets, examined],
    }
}

/// Everything the forwarding domain has counted, in one value.
///
/// A struct rather than eight arguments, on [`SubmissionCounters`]' terms and for
/// a sharper version of its reason: two of the members are `&RouteCounters` and
/// two more are plain counter structs, so a pair transposed in an argument list
/// would attribute one direction's traffic to the other and compile.
pub struct ForwarderCounters<'domain> {
    /// One per routed direction, in pipeline order — which **is** the ABI.
    pub pipelines: [&'domain RouteCounters; 2],
    pub generation: u32,
    pub configuration: ConfigCounters,
    /// One filter serves both directions, so its counters come off the pipeline
    /// rather than off either stage.
    pub policy: &'domain PolicyCounters,
    pub flow: FlowSample,
    pub sweep: &'domain PolicySweep,
    pub tap: TapCounters,
    pub log: LogSample,
}

/// The forwarding domain's whole shard.
#[must_use]
pub fn forwarder_sample(counters: &ForwarderCounters<'_>) -> ForwarderSample {
    ForwarderSample {
        pipelines: [
            pipeline_sample(counters.pipelines[0]),
            pipeline_sample(counters.pipelines[1]),
        ],
        generation: u64::from(counters.generation),
        images_applied: counters.configuration.applied,
        images_refused: counters.configuration.refused,
        policy: policy_sample(counters.policy),
        flow: counters.flow,
        sweep: policy_sweep_sample(counters.sweep),
        tap: TapSample {
            observed: counters.tap.observed,
            dropped: counters.tap.dropped,
            refused: counters.tap.refused,
        },
        log: counters.log,
    }
}

/// One transport's counters as the shard's fields.
///
/// A function because the management port carries two stacks — the HTTP
/// server's and the onboarding port's — and they are the same numbers about
/// two different tables. Written twice, the two could drift into disagreeing
/// about which counter is which, and the exposition keys its series by
/// position.
fn tcp_sample(counters: TcpCounters) -> TcpSample {
    TcpSample {
        segments_received: counters.segments_received,
        segments_sent: counters.segments_sent,
        connections_accepted: counters.connections_accepted,
        connections_dialled: counters.connections_dialled,
        connections_established: counters.connections_established,
        connections_closed: counters.connections_closed,
        connections_evicted: counters.connections_evicted,
        connections_reaped: counters.connections_reaped,
        connections_abandoned: counters.connections_abandoned,
        bytes_received: counters.bytes_received,
        bytes_sent: counters.bytes_sent,
        bytes_retransmitted: counters.bytes_retransmitted,
        retransmits: counters.retransmits,
        refused_malformed: counters.refused_malformed,
        refused_bad_checksum: counters.refused_bad_checksum,
        refused_out_of_window: counters.refused_out_of_window,
        refused_table_full: counters.refused_table_full,
        refused_not_listening: counters.refused_not_listening,
        refused_no_connection: counters.refused_no_connection,
        refused_unacceptable_ack: counters.refused_unacceptable_ack,
        refused_no_acknowledgement: counters.refused_no_acknowledgement,
        refused_not_a_handshake: counters.refused_not_a_handshake,
        refused_out_of_order: counters.refused_out_of_order,
        urgent_ignored: counters.urgent_ignored,
        challenge_acks: counters.challenge_acks,
        challenges_suppressed: counters.challenges_suppressed,
        resets_received: counters.resets_received,
        resets_sent: counters.resets_sent,
        write_refused: counters.write_refused,
    }
}

/// The management domain's whole shard, assembled from the stage, the endpoint
/// it holds and the transport under it.
#[must_use]
pub fn management_sample(
    stage: &EndpointStageCounters,
    transmit_pool: PoolCounters,
    endpoint: Option<&Endpoint>,
    log: LogSample,
) -> ManagementSample {
    let (endpoint_sample, neighbours, outbound, tcp, onboarding, http, onboard) = match endpoint {
        Some(endpoint) => {
            let counters = endpoint.counters();
            let mut unhandled = [0u64; Unhandled::ALL.len()];
            for (slot, reason) in Unhandled::ALL.iter().enumerate() {
                if let Some(count) = unhandled.get_mut(slot) {
                    *count = counters.unhandled(*reason);
                }
            }
            let tcp = endpoint.tcp_counters();
            let onboarding = endpoint.onboarding_counters();
            let served = endpoint.http_counters();
            let neighbours = endpoint.neighbour_counters();
            let dials = endpoint.outbound_counters();
            let stream = endpoint.stream_counters();
            (
                EndpointSample {
                    arp_replies: counters.arp_replies,
                    echo_replies: counters.echo_replies,
                    not_for_us: counters.not_for_us,
                    malformed: counters.malformed,
                    reply_refused: counters.reply_refused,
                    tcp_segments: counters.tcp_segments,
                    unclocked: counters.unclocked,
                    unhandled,
                },
                NeighbourSample {
                    requested: neighbours.requested,
                    replies: [
                        neighbours.learned,
                        neighbours.unsolicited,
                        neighbours.rebinding_refused,
                        neighbours.not_unicast,
                    ],
                    expired: neighbours.expired,
                    failed: [neighbours.abandoned, neighbours.no_room],
                },
                OutboundSample {
                    sessions: [
                        dials.opened,
                        dials.open_refused,
                        dials.established,
                        dials.ended,
                    ],
                    dialled: dials.dialled,
                    dropped_unresolved: dials.dropped_unresolved,
                    bytes: [dials.sent, dials.received],
                    overflowed: dials.overflowed,
                    refused: dials.refused,
                },
                tcp_sample(tcp),
                tcp_sample(onboarding),
                HttpSample {
                    requests: served.requests,
                    responses: served.responses,
                    response_bytes: served.response_bytes,
                    overflowed: served.overflowed,
                    bodies_refused: served.bodies_refused,
                    bodies_taken: served.bodies_taken,
                    bodies_timed_out: served.bodies_timed_out,
                    bodies_overrun: served.bodies_overrun,
                    retransmits_unavailable: served.retransmits_unavailable,
                    slots_exhausted: served.slots_exhausted,
                },
                OnboardSample {
                    accepted: stream.accepted,
                    forgotten: stream.forgotten,
                    received: stream.received,
                    sent: stream.sent,
                    closed_by_peer: stream.closed_by_peer,
                    closed_by_consumer: stream.closed_by_consumer,
                    overflowed: stream.overflowed,
                    refused: stream.refused,
                },
            )
        }
        // An unaddressed port has no endpoint, so its endpoint, transport and
        // server series read zero — which is what "no address yet" looks like
        // and is not the same as "addressed and idle": the stage's own
        // `frames`/`unaddressed` pair is what tells those apart.
        None => (
            EndpointSample::default(),
            NeighbourSample::default(),
            OutboundSample::default(),
            TcpSample::default(),
            TcpSample::default(),
            HttpSample::default(),
            OnboardSample::default(),
        ),
    };
    ManagementSample {
        frames: stage.frames,
        bytes: stage.bytes,
        stage_drops: [
            stage.malformed_descriptor,
            stage.snapshot_failed,
            stage.return_ring_full,
            stage.unaddressed,
        ],
        replies_sent: stage.replies_sent,
        replies_lost: [
            stage.reply_pool_exhausted,
            stage.reply_ring_full,
            stage.reply_write_failed,
        ],
        generation: u64::from(stage.generation),
        images_refused: stage.configs_refused,
        clock_generation: u64::from(stage.clock_generation),
        clocks_refused: stage.clocks_refused,
        timer_segments: stage.timer_segments,
        transmit_pool: PoolSample {
            not_lent: transmit_pool.reclaim_not_lent,
            ledger_refused: transmit_pool.reclaim_refused,
        },
        endpoint: endpoint_sample,
        neighbours,
        outbound,
        tcp,
        onboarding,
        http,
        onboard,
        streams: [
            stage.downloads.started,
            stage.downloads.abandoned,
            stage.downloads.windows,
            stage.downloads.bytes,
        ],
        log,
    }
}

/// What the deciding domain has decided, in the console's own outcome order.
///
/// A struct rather than three arguments: the array `ConfigSample` publishes is
/// keyed by position, and three counts handed over out of order would attribute a
/// refusal to a generation that applied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubmissionCounters {
    pub applied: u64,
    pub refused: u64,
    pub unchanged: u64,
    /// Times the running document was stated out of this node.
    pub reads: u64,
}

/// The configuration publisher's shard.
#[must_use]
pub const fn config_sample(
    generation: u32,
    submissions: SubmissionCounters,
    log: LogSample,
) -> ConfigSample {
    ConfigSample {
        generation: generation as u64,
        // In `lfw_metrics::GENERATION_OUTCOME_NAMES` order, which is the ABI: a
        // pair swapped here reports every refusal as an applied generation.
        submissions: [
            submissions.applied,
            submissions.refused,
            submissions.unchanged,
        ],
        reads: submissions.reads,
        log,
    }
}

/// What one block operation moved. Reads and writes apart rather than summed: a
/// medium refusing writes is invisible in a total the reads dominate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockCounters {
    pub reads: u64,
    pub read_bytes: u64,
    pub writes: u64,
    pub write_bytes: u64,
}

impl BlockCounters {
    /// Record one successful completion, saturating for the reason every counter
    /// here does: a wrap forges a negative rate between two scrapes.
    pub fn completed(&mut self, operation: Operation, bytes: u32) {
        let (count, total) = match operation {
            Operation::Read => (&mut self.reads, &mut self.read_bytes),
            Operation::Write => (&mut self.writes, &mut self.write_bytes),
            // A flush moves no data, so counting it as either would inflate a
            // series an operator reads as bytes that crossed the bus.
            Operation::Flush => return,
        };
        *count = count.saturating_add(1);
        *total = total.saturating_add(u64::from(bytes));
    }
}

/// The recorder's whole shard. `capacity_sectors` is the device's own claim,
/// taken once at bring-up: it bounds every range the domain names, so exposing
/// it shows an operator a device smaller than the recording configured for it.
#[must_use]
pub fn recorder_sample(
    capacity_sectors: u64,
    blocks: BlockCounters,
    faults: RequestFaults,
    recording: RecorderCounters,
    log: LogSample,
) -> RecorderSample {
    let mut sinks = [SinkSample::default(); SINKS];
    for (slot, counters) in sinks.iter_mut().zip(recording.sinks) {
        *slot = SinkSample {
            records: counters.records,
            record_bytes: counters.record_bytes,
            dropped: [counters.dropped_oversized, counters.dropped_refused],
            staging_deferrals: counters.staging_deferrals,
            segments_closed: counters.segments_closed,
            wraps: counters.wraps,
            sectors_written: counters.sectors_written,
            padding_bytes: counters.padding_bytes,
            download_overruns: counters.download_overruns,
        };
    }
    RecorderSample {
        capacity_sectors,
        requests: [blocks.reads, blocks.writes],
        bytes: [blocks.read_bytes, blocks.write_bytes],
        device_faults: [
            faults.device.completion_out_of_range,
            faults.device.completion_not_posted,
            faults.device.completion_length_over_reported,
        ],
        status_undecodable: faults.status_undecodable,
        // The recorder's own invariant fault joins the block driver's: both are
        // a completion nothing was waiting on, one seen by the request layer
        // and one by the pass above it.
        completion_unmapped: faults
            .completion_unmapped
            .saturating_add(recording.completions_unexpected),
        sinks,
        tap: [
            recording.tap_records,
            recording.tap_refused,
            recording.tap_dropped_by_writer,
        ],
        downloads: [recording.downloads_served, recording.downloads_refused],
        // In `lfw_metrics::RECORDING_SNAPSHOTS`' label order, which is the ABI: a
        // pair swapped here reports every reading that never reached the medium
        // as one that did.
        snapshots: [
            recording.snapshots_written,
            recording.snapshots_missed,
            recording.snapshots_dropped,
        ],
        transcripts: [recording.transcripts_written, recording.transcripts_dropped],
        transcript_lines: recording.transcript_lines,
        records_unclocked: recording.records_unclocked,
        log,
    }
}

/// The store domain's whole shard: what it established about the appliance's
/// identity, and what its device did.
///
/// The identity half is four flags and a position — **no key material and no
/// identifier**. A private scalar has no representation on this surface and the
/// 128-bit name is not a number a time series can carry; the console record is
/// where an operator reads one, and this is where a fleet asks whether there is
/// an identity at all.
#[must_use]
pub fn store_sample(
    identity: StoreIdentity,
    signing: StoreSigning,
    capacity_sectors: u64,
    blocks: BlockCounters,
    faults: RequestFaults,
    log: LogSample,
) -> StoreSample {
    StoreSample {
        established: identity.established,
        minted: identity.minted,
        generation: identity.generation,
        onboarded: identity.onboarded,
        reset: identity.reset,
        signatures: signing.signatures,
        sign_refusals: signing.refusals,
        capacity_sectors,
        requests: [blocks.reads, blocks.writes],
        bytes: [blocks.read_bytes, blocks.write_bytes],
        device_faults: [
            faults.device.completion_out_of_range,
            faults.device.completion_not_posted,
            faults.device.completion_length_over_reported,
        ],
        status_undecodable: faults.status_undecodable,
        completion_unmapped: faults.completion_unmapped,
        log,
    }
}

/// What the appliance's identity has come to, as the five values its shard
/// exposes.
///
/// Established at start-up and, on two of the five, moved afterwards: taking
/// ownership out of an onboarding package advances the generation and turns
/// `onboarded` on, so a scrape reads what the medium now holds rather than what
/// the boot found.
///
/// A struct rather than four arguments because they are one answer: an
/// appliance that is established and was minted this boot is a different node
/// from one that is established and was not, and a caller passing them
/// positionally is a caller that can swap them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreIdentity {
    /// Whether this node holds an identity at all, minted or reloaded.
    pub established: bool,
    /// Whether this boot is the one that minted it.
    pub minted: bool,
    /// The generation of the state record in force, or zero where there is none.
    pub generation: u64,
    pub onboarded: bool,
    /// Whether this boot honoured a factory-reset request. Beside `minted` and
    /// not folded into it: both a first boot and a reset mint, and only this says
    /// which of the two a scrape is looking at.
    pub reset: bool,
}

/// What the delegation this domain answers has come to, as the two counts its
/// shard exposes.
///
/// Its own struct beside [`StoreIdentity`] rather than two more fields inside it,
/// because they answer a different question and change on a different schedule:
/// these move every time a peer asks, while an identity is established at
/// start-up and afterwards changes only when the appliance is given an owner. A
/// caller that had to pass all seven positionally is a caller that can swap two
/// `u64`s.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreSigning {
    /// Signatures produced under the device key.
    pub signatures: u64,
    /// Requests answered with a typed refusal instead of a signature.
    pub refusals: u64,
}

#[cfg(test)]
mod tests;
