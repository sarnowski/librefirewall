use lfw_flow::FlowTable;
use lfw_http::Status;
use lfw_metrics::{
    FLOW_LIFECYCLE_EVENTS, FLOW_OUTCOMES, FLOW_REFUSALS, FLOW_STATES, HTTP_STATUSES, PIPELINES,
    ROUTE_STAGE_DROP_REASONS, SHARDS, STATS_SLOTS,
};
use lfw_tcp::TcpCounters;
use net_headers::{ParseCounters, ParseError, ParseFailure};

use super::*;

/// The metric surface names the router's reasons itself, because `lfw_metrics`
/// depends on none of the crates whose counters it mirrors. This is the enforcer
/// that obligation names: the two lists are one vocabulary in two places,
/// and a reason added to `routing` without a slot here would render under the
/// wrong name rather than not at all.
#[test]
fn the_route_drop_vocabulary_is_the_routers_own() {
    assert_eq!(ROUTE_DROP_REASONS.len(), DropReason::ALL.len());
    for (token, reason) in ROUTE_DROP_REASONS.iter().zip(DropReason::ALL) {
        assert_eq!(*token, reason.name(), "{reason:?}");
    }
}

/// The same for the endpoint's refusal vocabulary.
#[test]
fn the_unhandled_vocabulary_is_the_endpoints_own() {
    let series: Vec<&str> = lfw_metrics::ManagementSample::SERIES
        .iter()
        .filter(|series| series.metric.name == "librefirewall_endpoint_unhandled_total")
        .filter_map(|series| {
            series
                .labels
                .iter()
                .find(|label| label.name == "reason")
                .map(|label| label.value)
        })
        .collect();
    assert_eq!(series.len(), Unhandled::ALL.len());
    for (token, reason) in series.iter().zip(Unhandled::ALL) {
        assert_eq!(*token, reason.name(), "{reason:?}");
    }
}

/// And for the statuses the server can answer with: the counter table's order is
/// `lfw_http::Status::ALL`'s, so a slot is stable and a status added to one and
/// not the other is a build-time mismatch here rather than a miscounted response.
#[test]
fn the_status_vocabulary_is_the_servers_own() {
    assert_eq!(HTTP_STATUSES.len(), Status::ALL.len());
    for (token, status) in HTTP_STATUSES.iter().zip(Status::ALL) {
        assert_eq!(*token, status.token(), "{status:?}");
        assert_eq!(HTTP_STATUSES[status.slot()], status.token());
    }
}

/// The shard count and the pipeline count are build facts the system description
/// fixes; `xtask::sysdesc` holds that file to them from the other side.
#[test]
fn the_build_facts_the_catalogue_states_are_this_builds() {
    assert_eq!(PIPELINES, usize::from(2u8), "two dataplane pipelines");
    assert_eq!(SHARDS.len(), lfw_metrics::SHARD_COUNT);
    assert_eq!(SHARDS[lfw_metrics::FORWARDER_SHARD].domain, "forwarder");
    assert_eq!(SHARDS[lfw_metrics::MANAGEMENT_SHARD].domain, "management");
}

/// Every field of `RouteCounters` reaches a slot, checked by giving each a
/// distinct value and reading the whole sample back: a conversion that dropped
/// one, or wrote one twice, leaves a zero behind.
#[test]
fn every_route_counter_reaches_its_own_slot() {
    let mut unparsable = ParseCounters::new();
    // One more of each class than the last, so a conversion that transposed two
    // parse slots leaves a value in the wrong one rather than an equal number.
    for (index, error) in [
        ParseError::FrameTooShort { needed: 14, got: 0 },
        ParseError::StackedVlanTags,
        ParseError::Ipv4VersionNotFour(6),
        ParseError::Ipv4ChecksumInvalid {
            found: 1,
            computed: 2,
        },
    ]
    .into_iter()
    .enumerate()
    {
        for _ in 0..=index {
            unparsable.record(error);
        }
    }
    let mut counters = RouteCounters {
        forwarded: 1,
        egress_full: 2,
        malformed_descriptor: 3,
        snapshot_failed: 4,
        unparsable,
        misrouted: 6,
        writeback_failed: 7,
        ..RouteCounters::default()
    };
    for reason in DropReason::ALL {
        for _ in 0..=reason as u64 {
            counters.drops.record(reason);
        }
    }
    let sample = pipeline_sample(&counters);
    assert_eq!(sample.forwarded, 1);
    assert_eq!(
        sample.stage_drops,
        [2, 3, 4, 1, 2, 3, 4, 6, 7],
        "the stage's own reasons are out of order"
    );
    assert_eq!(sample.stage_drops.len(), ROUTE_STAGE_DROP_REASONS.len());
    for (slot, reason) in DropReason::ALL.iter().enumerate() {
        assert_eq!(sample.route_drops[slot], *reason as u64 + 1);
    }
}

/// The stage's parse classes are `net_headers`' own vocabulary, as the router's
/// reasons are `routing`'s: `lfw_metrics` names them itself, so this is the
/// enforcer that separation obliges. A class added upstream without a slot here
/// would render under the wrong name rather than not at all.
#[test]
fn the_parse_failure_vocabulary_is_net_headers_own() {
    let declared: Vec<&str> = ROUTE_STAGE_DROP_REASONS
        .iter()
        .copied()
        .filter(|reason| {
            ParseFailure::ALL
                .iter()
                .any(|failure| failure.name() == *reason)
        })
        .collect();
    assert_eq!(declared.len(), ParseFailure::ALL.len());
    for (token, failure) in declared.iter().zip(ParseFailure::ALL) {
        assert_eq!(*token, failure.name(), "{failure:?}");
    }
}

/// The forwarder's whole shard: two pipelines that must not be transposed, and
/// the configuration and log counts behind them.
#[test]
fn the_forwarder_sample_keeps_its_two_pipelines_apart() {
    let first = RouteCounters {
        forwarded: 11,
        ..RouteCounters::default()
    };
    let second = RouteCounters {
        forwarded: 22,
        ..RouteCounters::default()
    };
    let sample = forwarder_sample(
        [&first, &second],
        7,
        ConfigCounters {
            applied: 3,
            refused: 1,
        },
        // A filter that has decided nothing, so this case stays about the two
        // pipelines. What the policy block maps to is driven through a real poll
        // by `the_filters_three_outcomes_reach_three_different_places_in_the_shard`,
        // the counters being the stage's to move and nobody else's.
        &PolicyCounters::new(),
        // As the filter: a table that has classified nothing, so this case stays
        // about the two pipelines. What the flow block maps to is driven through
        // a real table by `every_flow_counter_reaches_the_slot_its_series_names`.
        flow_sample(&FlowCounters::new(), FlowTable::<16>::new().occupancy()),
        TapCounters {
            observed: 33,
            dropped: 4,
            refused: 0,
        },
        log_sample(5, 2),
    );
    assert_eq!(sample.pipelines[0].forwarded, 11);
    assert_eq!(sample.pipelines[1].forwarded, 22);
    assert_eq!(sample.generation, 7);
    assert_eq!(sample.images_applied, 3);
    assert_eq!(sample.images_refused, 1);
    assert_eq!(sample.tap.observed, 33);
    assert_eq!(sample.tap.dropped, 4);
    assert_eq!(sample.log.dropped, 5);
    assert_eq!(sample.log.refused, 2);
    assert_eq!(sample.policy, lfw_metrics::PolicySample::default());
    assert!(sample.values().len() <= STATS_SLOTS);
}

/// A port with no endpoint publishes zeros for everything above the stage, and
/// the stage's own counts regardless: "not addressed yet" and "addressed and
/// idle" are told apart by `frames` and `unaddressed`, not by an absent series.
#[test]
fn an_unaddressed_port_publishes_its_stage_and_zeroes_the_rest() {
    let stage = EndpointStageCounters {
        frames: 9,
        bytes: 900,
        unaddressed: 9,
        ..EndpointStageCounters::default()
    };
    let sample = management_sample(&stage, PoolCounters::default(), None, log_sample(0, 0));
    assert_eq!(sample.frames, 9);
    assert_eq!(sample.bytes, 900);
    assert_eq!(sample.stage_drops[3], 9);
    assert_eq!(sample.endpoint, lfw_metrics::EndpointSample::default());
    assert_eq!(sample.tcp, lfw_metrics::TcpSample::default());
    assert_eq!(sample.http, lfw_metrics::HttpSample::default());
}

/// Every field of `TcpCounters` reaches a slot of its own. The transport has
/// twenty-seven causes, and counters must attribute a refusal to what the peer
/// sent — kept apart from what accuses this code — so a conversion that merged
/// two would be the one defect that attribution exists to prevent.
#[test]
fn every_transport_counter_reaches_its_own_slot() {
    // A distinct value per field, produced by walking the struct through its own
    // byte image: any two fields that shared a slot would collide.
    let counters = TcpCounters {
        segments_received: 1,
        segments_sent: 2,
        connections_accepted: 3,
        connections_established: 4,
        connections_closed: 5,
        connections_evicted: 6,
        connections_reaped: 7,
        connections_abandoned: 8,
        bytes_received: 9,
        bytes_sent: 10,
        bytes_retransmitted: 11,
        retransmits: 12,
        refused_malformed: 13,
        refused_bad_checksum: 14,
        refused_out_of_window: 15,
        refused_table_full: 16,
        refused_not_listening: 17,
        refused_no_connection: 18,
        refused_unacceptable_ack: 19,
        refused_no_acknowledgement: 20,
        refused_out_of_order: 21,
        urgent_ignored: 22,
        challenge_acks: 23,
        resets_received: 24,
        resets_sent: 25,
        write_refused: 26,
        challenges_suppressed: 27,
    };
    let sample = TcpSample {
        segments_received: counters.segments_received,
        segments_sent: counters.segments_sent,
        connections_accepted: counters.connections_accepted,
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
        refused_out_of_order: counters.refused_out_of_order,
        urgent_ignored: counters.urgent_ignored,
        challenge_acks: counters.challenge_acks,
        challenges_suppressed: counters.challenges_suppressed,
        resets_received: counters.resets_received,
        resets_sent: counters.resets_sent,
        write_refused: counters.write_refused,
    };
    let management = ManagementSample {
        tcp: sample,
        ..ManagementSample::default()
    };
    let values = management.values();
    let mut seen: Vec<u64> = values.iter().copied().filter(|value| *value != 0).collect();
    seen.sort_unstable();
    assert_eq!(seen, (1..=27).collect::<Vec<u64>>());
}

/// A log ring's counts are `u32` on the writing side and `u64` on the wire, and
/// the widening is where a value could be lost.
#[test]
fn a_log_sample_widens_rather_than_truncates() {
    let sample = log_sample(u32::MAX, u32::MAX - 1);
    assert_eq!(sample.dropped, u64::from(u32::MAX));
    assert_eq!(sample.refused, u64::from(u32::MAX - 1));
    assert_eq!(
        config_sample(u32::MAX, sample).generation,
        u64::from(u32::MAX)
    );
}

/// The recorder's shard lays its two operations out in the order its series
/// name them, and a flush — which moves nothing — inflates neither.
#[test]
fn the_block_counters_keep_reads_and_writes_apart() {
    let mut blocks = BlockCounters::default();
    blocks.completed(Operation::Read, 512);
    blocks.completed(Operation::Read, 1024);
    blocks.completed(Operation::Write, 4096);
    blocks.completed(Operation::Flush, u32::MAX);

    assert_eq!(
        blocks,
        BlockCounters {
            reads: 2,
            read_bytes: 1536,
            writes: 1,
            write_bytes: 4096,
        }
    );

    let recording = RecorderCounters {
        sinks: [
            lfw_recorder::SinkCounters {
                records: 9,
                record_bytes: 900,
                ..lfw_recorder::SinkCounters::default()
            },
            lfw_recorder::SinkCounters {
                records: 8,
                record_bytes: 8000,
                ..lfw_recorder::SinkCounters::default()
            },
        ],
        tap_records: 9,
        downloads_served: 2,
        ..RecorderCounters::default()
    };
    let sample = recorder_sample(
        2048,
        blocks,
        RequestFaults::default(),
        recording,
        log_sample(3, 4),
    );
    assert_eq!(sample.capacity_sectors, 2048);
    assert_eq!(sample.requests, [2, 1]);
    assert_eq!(sample.bytes, [1536, 4096]);
    assert_eq!(sample.sinks[0].records, 9);
    assert_eq!(sample.sinks[1].record_bytes, 8000);
    assert_eq!(sample.tap[0], 9);
    assert_eq!(sample.downloads, [2, 0]);
    assert_eq!(sample.log.dropped, 3);
    assert_eq!(sample.log.refused, 4);
}

/// Every fault the request layer can raise reaches its own slot, and no two
/// share one: a device replaying completions and a device writing garbage
/// statuses must be distinguishable in a scrape.
#[test]
fn every_request_fault_reaches_a_slot_of_its_own() {
    let faults = RequestFaults {
        device: lfw_blk::request::DeviceFaults {
            completion_out_of_range: 1,
            completion_not_posted: 2,
            completion_length_over_reported: 3,
        },
        status_undecodable: 4,
        completion_unmapped: 5,
    };
    let sample = recorder_sample(
        0,
        BlockCounters::default(),
        faults,
        RecorderCounters::default(),
        LogSample::default(),
    );
    assert_eq!(sample.device_faults, [1, 2, 3]);
    assert_eq!(sample.status_undecodable, 4);
    assert_eq!(sample.completion_unmapped, 5);

    let values = sample.values();
    let mut seen: Vec<u64> = values.iter().copied().filter(|value| *value != 0).collect();
    seen.sort_unstable();
    assert_eq!(seen, (1..=5).collect::<Vec<u64>>());
}

/// The counters saturate rather than wrapping, for the reason every counter on
/// this surface does: a scraper differences successive samples, so a wrap turns
/// a sustained rate into a negative one.
#[test]
fn a_block_counter_saturates_rather_than_wrapping() {
    let mut blocks = BlockCounters {
        reads: u64::MAX,
        read_bytes: u64::MAX,
        writes: u64::MAX - 1,
        write_bytes: 0,
    };
    blocks.completed(Operation::Read, 512);
    blocks.completed(Operation::Write, 512);
    blocks.completed(Operation::Write, 512);
    assert_eq!(blocks.reads, u64::MAX);
    assert_eq!(blocks.read_bytes, u64::MAX);
    assert_eq!(blocks.writes, u64::MAX);
    assert_eq!(blocks.write_bytes, 1024);
}

/// The connection tracker's four vocabularies are the owning enums' own, name
/// for name and in their order — the same obligation the router's reasons carry,
/// and for the same reason: `lfw_metrics` depends on none of the crates whose
/// counters it mirrors, so this is where the two lists are held to being one.
#[test]
fn the_flow_vocabularies_are_the_trackers_own() {
    assert_eq!(FLOW_OUTCOMES.len(), Classification::ALL.len());
    for (token, classification) in FLOW_OUTCOMES.iter().zip(Classification::ALL) {
        assert_eq!(*token, classification.name(), "{classification:?}");
    }

    assert_eq!(FLOW_REFUSALS.len(), RefusalKind::ALL.len());
    for (token, kind) in FLOW_REFUSALS.iter().zip(RefusalKind::ALL) {
        assert_eq!(*token, kind.name(), "{kind:?}");
    }

    assert_eq!(FLOW_STATES.len(), FlowState::ALL.len());
    for (token, state) in FLOW_STATES.iter().zip(FlowState::ALL) {
        assert_eq!(*token, state.name(), "{state:?}");
    }

    // The lifecycle family deliberately has no `created` value: a flow is
    // created by exactly the packet counted as `new` above, and two series for
    // one counter would invite an operator to add them.
    assert_eq!(
        FLOW_LIFECYCLE_EVENTS,
        ["expired", "evicted", "closed", "withdrawn"]
    );
}

/// Every flow counter reaches the slot its series names, and no two share one.
///
/// Distinct values per field, so a sample assembled with two fields transposed
/// moves a number rather than repeating one — which is the failure a
/// written-out slot list makes easy and this test makes visible.
#[test]
fn every_flow_counter_reaches_the_slot_its_series_names() {
    let mut counters = FlowCounters::new();
    counters.packets_seen = 1;
    counters.flows_created = 2;
    counters.packets_established = 3;
    counters.packets_related = 4;
    counters.flows_expired = 5;
    counters.flows_evicted = 6;
    counters.flows_closed = 7;
    counters.flows_withdrawn = 8;
    counters.probe_tag_collisions = 9;
    counters.internal_slot_desync = 10;
    counters.refused_unsupported_protocol = 21;
    counters.refused_fragment = 22;
    counters.refused_malformed = 23;
    counters.refused_invalid_flags = 24;
    counters.refused_mid_stream = 25;
    counters.refused_invalid_state = 26;
    counters.refused_out_of_window = 27;
    counters.refused_no_flow = 28;
    counters.refused_quoted_invalid = 29;
    counters.refused_unsupported_icmp = 30;
    counters.refused_table_full = 31;
    counters.refused_bucket_full = 32;

    let table = FlowTable::<16>::new();
    let sample = flow_sample(&counters, table.occupancy());

    assert_eq!(sample.packets_seen, 1);
    assert_eq!(sample.outcomes, [2, 3, 4]);
    assert_eq!(sample.lifecycle, [5, 6, 7, 8]);
    assert_eq!(sample.probe_collisions, 9);
    assert_eq!(sample.slot_desync, 10);
    for (slot, kind) in sample.refusals.iter().zip(RefusalKind::ALL) {
        assert_eq!(*slot, counters.refused(kind), "{kind:?}");
    }
    // The occupancy comes off the table itself, so an empty one reports every
    // slot vacant and nothing else — and the values sum to the capacity.
    assert_eq!(sample.entries.iter().sum::<u64>(), 16);
    assert_eq!(
        sample.entries.first().copied(),
        Some(16),
        "a fresh table does not report every slot vacant"
    );
}
