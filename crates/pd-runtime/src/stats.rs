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
//! CONCEPT §7.1's **byzantine neighbour protection domain**, on the writing
//! side. A shard is one region this domain is the sole writer of and the
//! management domain reads, so a store here is a claim about *this* domain and
//! never about another — which is what makes a per-domain series something an
//! operator can act on, and what makes the read-only grant on the reader's side
//! the whole of the argument (see the system description).

use lfw_ip_endpoint::{Endpoint, Unhandled};
use lfw_metrics::{
    ConfigSample, EndpointSample, ForwarderSample, HttpSample, LogSample, ManagementSample,
    PipelineSample, PoolSample, ROUTE_DROP_REASONS, SHARD_COUNT, Snapshot, StatsShard, TcpSample,
};
use routing::DropReason;

use crate::{ConfigCounters, EndpointStageCounters, PoolCounters, RouteCounters};

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
    PipelineSample {
        forwarded: counters.forwarded,
        route_drops,
        stage_drops: [
            counters.egress_full,
            counters.malformed_descriptor,
            counters.snapshot_failed,
            counters.unparsable,
            counters.misrouted,
            counters.writeback_failed,
        ],
    }
}

/// The forwarding domain's whole shard.
#[must_use]
pub fn forwarder_sample(
    pipelines: [&RouteCounters; 2],
    generation: u32,
    configuration: ConfigCounters,
    log: LogSample,
) -> ForwarderSample {
    ForwarderSample {
        pipelines: [pipeline_sample(pipelines[0]), pipeline_sample(pipelines[1])],
        generation: u64::from(generation),
        images_applied: configuration.applied,
        images_refused: configuration.refused,
        log,
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
    let (endpoint_sample, tcp, http) = match endpoint {
        Some(endpoint) => {
            let counters = endpoint.counters();
            let mut unhandled = [0u64; Unhandled::ALL.len()];
            for (slot, reason) in Unhandled::ALL.iter().enumerate() {
                if let Some(count) = unhandled.get_mut(slot) {
                    *count = counters.unhandled(*reason);
                }
            }
            let tcp = endpoint.tcp_counters();
            let served = endpoint.http_counters();
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
                TcpSample {
                    segments_received: tcp.segments_received,
                    segments_sent: tcp.segments_sent,
                    connections_accepted: tcp.connections_accepted,
                    connections_established: tcp.connections_established,
                    connections_closed: tcp.connections_closed,
                    connections_evicted: tcp.connections_evicted,
                    connections_reaped: tcp.connections_reaped,
                    connections_abandoned: tcp.connections_abandoned,
                    bytes_received: tcp.bytes_received,
                    bytes_sent: tcp.bytes_sent,
                    bytes_retransmitted: tcp.bytes_retransmitted,
                    retransmits: tcp.retransmits,
                    refused_malformed: tcp.refused_malformed,
                    refused_bad_checksum: tcp.refused_bad_checksum,
                    refused_out_of_window: tcp.refused_out_of_window,
                    refused_table_full: tcp.refused_table_full,
                    refused_not_listening: tcp.refused_not_listening,
                    refused_no_connection: tcp.refused_no_connection,
                    refused_unacceptable_ack: tcp.refused_unacceptable_ack,
                    refused_no_acknowledgement: tcp.refused_no_acknowledgement,
                    refused_out_of_order: tcp.refused_out_of_order,
                    urgent_ignored: tcp.urgent_ignored,
                    challenge_acks: tcp.challenge_acks,
                    resets_received: tcp.resets_received,
                    resets_sent: tcp.resets_sent,
                    write_refused: tcp.write_refused,
                },
                HttpSample {
                    requests: served.requests,
                    responses: served.responses,
                    response_bytes: served.response_bytes,
                    overflowed: served.overflowed,
                    expositions_refused: served.expositions_refused,
                    retransmits_unavailable: served.retransmits_unavailable,
                    slots_exhausted: served.slots_exhausted,
                },
            )
        }
        // An unaddressed port has no endpoint, so its endpoint, transport and
        // server series read zero — which is what "no address yet" looks like
        // and is not the same as "addressed and idle": the stage's own
        // `frames`/`unaddressed` pair is what tells those apart.
        None => (
            EndpointSample::default(),
            TcpSample::default(),
            HttpSample::default(),
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
        tcp,
        http,
        log,
    }
}

/// The configuration publisher's shard.
#[must_use]
pub const fn config_sample(generation: u32, log: LogSample) -> ConfigSample {
    ConfigSample {
        generation: generation as u64,
        log,
    }
}

#[cfg(test)]
mod tests;
