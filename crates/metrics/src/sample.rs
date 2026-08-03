//! What each protection domain publishes, and the slot order it publishes in.
//!
//! A sample type is plain data: `u64` fields and fixed arrays, no dependency on
//! the crate whose counters it mirrors. That direction is deliberate. The crate
//! that *owns* a counter converts it into a sample — `nic_driver_core` for a
//! driver's, `pd_runtime` for the dataplane and the endpoint's, `lfw_log` and
//! `uart_16550` for the console's — and each of those conversions is where a
//! test holds this module's vocabulary tokens to the enum they name. Reaching
//! the other way would make this crate depend on `nic_driver_core`, which
//! depends on `pd_runtime`, which depends on this one.
//!
//! **The `SERIES` table is the slot order.** A sample's `values()` returns its
//! counters in exactly the order the table lists them, so index *is* slot and
//! one table serves the writer and the reader. There is deliberately no
//! `from_values`: the renderer needs `(series, value)` pairs and never the
//! struct, so the mapping is defined once and can carry no second copy to drift
//! from.
//!
//! Field-level documentation is deliberately absent: every field's
//! meaning is the `help` text of the metric its slot renders as, which is the
//! sentence an operator actually reads, and a second one here would be an
//! untested assertion beside it.

use crate::catalog::{
    BLOCK_BYTES, BLOCK_CAPACITY_SECTORS, BLOCK_REQUESTS, BLOCK_STATUS_UNDECODABLE,
    CLOCK_CALIBRATIONS_REFUSED, CLOCK_FREQUENCY_HERTZ, CLOCK_GENERATION, CONFIGURATION_GENERATION,
    CONFIGURATION_IMAGES, CONFIGURATION_READS, CONFIGURATION_SUBMISSIONS, CONSOLE_RECORDS,
    DEVICE_FAULTS, ENDPOINT_BYTES, ENDPOINT_FRAMES, ENDPOINT_MALFORMED, ENDPOINT_NOT_FOR_US,
    ENDPOINT_REPLIES, ENDPOINT_REPLIES_LOST, ENDPOINT_REPLIES_SENT, ENDPOINT_REPLY_REFUSED,
    ENDPOINT_STAGE_DROPS, ENDPOINT_TCP_SEGMENTS, ENDPOINT_TIMER_SEGMENTS, ENDPOINT_UNCLOCKED,
    ENDPOINT_UNHANDLED, FLOW_LIFECYCLE, FLOW_PACKETS, FLOW_PACKETS_REFUSED, FLOW_PACKETS_SEEN,
    FLOW_PROBE_COLLISIONS, FLOW_TABLE_ENTRIES, FORWARDED_FRAMES, HTTP_BODIES_REFUSED,
    HTTP_BODIES_TAKEN, HTTP_BODY_OVERRUNS, HTTP_REQUESTS, HTTP_REQUESTS_OVERFLOWED,
    HTTP_RESPONSE_BYTES, HTTP_RESPONSES, HTTP_RETRANSMITS_UNAVAILABLE, HTTP_SLOTS_EXHAUSTED,
    INPUT_DROPS, INVARIANT_FAULTS, LOG_RECORDS_DROPPED, LOG_RECORDS_REFUSED, Label, POLICY_BYTES,
    POLICY_PACKETS, POOL_RETURNS_REFUSED, QUEUE_POSTED, RECEIVE_BYTES, RECEIVE_FRAMES,
    RECORDING_DOWNLOAD_OVERRUNS, RECORDING_DOWNLOADS, RECORDING_PADDING_BYTES,
    RECORDING_RECORD_BYTES, RECORDING_RECORDS, RECORDING_RECORDS_DROPPED,
    RECORDING_RECORDS_UNCLOCKED, RECORDING_SECTORS_WRITTEN, RECORDING_SEGMENTS_CLOSED,
    RECORDING_STAGING_DEFERRALS, RECORDING_STREAM_BYTES, RECORDING_STREAM_WINDOWS,
    RECORDING_STREAMS, RECORDING_TAP_DROPPED_BY_WRITER, RECORDING_TAP_RECORDS,
    RECORDING_TAP_REFUSED, RECORDING_WRAPS, ROUTE_DROPS, ROUTE_STAGE_DROPS, Series,
    TAP_OBSERVATIONS, TAP_OBSERVATIONS_LOST, TCP_BYTES, TCP_CHALLENGE_ACKS,
    TCP_CHALLENGES_SUPPRESSED, TCP_CONNECTIONS, TCP_REFUSED, TCP_RESETS, TCP_RETRANSMITS,
    TCP_SEGMENTS, TCP_URGENT_IGNORED, TCP_WRITE_REFUSED, TRANSMIT_BYTES, TRANSMIT_FRAMES,
    UART_BYTES_WRITTEN, UART_INIT_FAILURES, UART_TRANSMITTER_TIMEOUTS, plain, s,
};
use crate::rules::MAX_RULE_SERIES;

/// Dataplane pipelines the forwarder carries, one per direction. A build fact
/// matching `config::PORT_COUNT`, held to it by a test in `pd_runtime`.
pub const PIPELINES: usize = 2;

/// The pipeline's whole refusal vocabulary, in `pipeline::DropReason::ALL` order —
/// which a test in `pd_runtime` holds this array to, name for name.
pub const ROUTE_DROP_REASONS: [&str; 25] = [
    "unconfigured_ingress_port",
    "interface_disabled",
    "not_addressed_to_us",
    "vlan_tagged",
    "martian_source",
    "unroutable_destination",
    "addressed_to_this_router",
    "ttl_expired",
    "no_route",
    "egress_is_ingress",
    "no_neighbour",
    "flow_unsupported_protocol",
    "flow_fragment",
    "flow_malformed",
    "flow_invalid_flags",
    "flow_mid_stream",
    "flow_invalid_state",
    "flow_out_of_window",
    "flow_no_such_flow",
    "flow_quoted_invalid",
    "flow_unsupported_icmp",
    "flow_table_full",
    "flow_bucket_full",
    "policy_denied",
    "no_policy_match",
];

/// What the connection tracker made of a packet it did not refuse, in
/// `lfw_flow::Classification::ALL` order — which a test in `pd_runtime` holds
/// this array to, name for name. There is no `refused` value: a refusal is its
/// own family, because merging the two would put "belongs to a conversation" and
/// "was turned away" under one label an alert cannot separate.
pub const FLOW_OUTCOMES: [&str; 3] = ["new", "established", "related"];

/// Why the tracker turned a packet away, in `lfw_flow::RefusalKind::ALL` order —
/// which a test in `pd_runtime` holds this array to, name for name.
pub const FLOW_REFUSALS: [&str; 12] = [
    "unsupported_protocol",
    "fragment",
    "malformed",
    "invalid_flags",
    "mid_stream",
    "invalid_state",
    "out_of_window",
    "no_such_flow",
    "quoted_invalid",
    "unsupported_icmp",
    "table_full",
    "bucket_full",
];

/// What ended a flow. Deliberately without `created`, which is the `new` value of
/// [`FLOW_OUTCOMES`] seen from the other side: one counter, one series.
pub const FLOW_LIFECYCLE_EVENTS: [&str; 4] = ["expired", "evicted", "closed", "withdrawn"];

/// The states a slot of the connection table can be in, in
/// `lfw_flow::FlowState::ALL` order — which a test in `pd_runtime` holds this
/// array to. `vacant` is one of them; see the family's help text.
pub const FLOW_STATES: [&str; 13] = [
    "vacant",
    "syn_sent",
    "syn_received",
    "established",
    "fin_wait",
    "close_wait",
    "closing",
    "time_wait",
    "closed",
    "udp_unreplied",
    "udp_assured",
    "icmp_unreplied",
    "icmp_replied",
];

/// What the routing *stage* refuses around the router's decision: a descriptor, a
/// pool operation, or a frame no parser would read.
///
/// The four parse classes are `net_headers::ParseFailure::ALL`'s, name for name —
/// which a test in `pd_runtime` holds this array to, as it does the router's own
/// vocabulary.
pub const ROUTE_STAGE_DROP_REASONS: [&str; 9] = [
    "egress_full",
    "malformed_descriptor",
    "snapshot_failed",
    "frame_too_short",
    "ethernet_unparsable",
    "ipv4_unparsable",
    "ipv4_checksum_invalid",
    "misrouted",
    "writeback_failed",
];

/// Status codes the management server can answer with, in the order
/// [`HttpSample::responses`] holds them; `lfw_http::Status::ALL` is the same set
/// and a test in `lfw_ip_endpoint` holds the two together.
pub const HTTP_STATUSES: [&str; 9] = [
    "200", "400", "404", "405", "413", "414", "431", "503", "505",
];

/// Every writing domain's own account of its log ring.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogSample {
    pub dropped: u64,
    pub refused: u64,
}

/// One pool owner's refused returns, split by which check refused them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolSample {
    pub not_lent: u64,
    pub ledger_refused: u64,
}

/// One direction of the routed dataplane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PipelineSample {
    pub forwarded: u64,
    pub route_drops: [u64; ROUTE_DROP_REASONS.len()],
    pub stage_drops: [u64; ROUTE_STAGE_DROP_REASONS.len()],
}

/// What the forwarder published to the recorder, and what it could not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TapSample {
    pub observed: u64,
    pub dropped: u64,
    pub refused: u64,
}

/// What the filter decided, which is one account for the whole domain rather
/// than one per direction: a single `pipeline::PolicyStage` serves both, so there
/// is no per-direction number to report.
///
/// `rule_hits` is indexed by a rule's position in the running generation. Every
/// slot the ABI admits is published; which of them names a rule an operator wrote
/// is [`crate::RuleInventory`]'s to say, and a position no generation declared
/// reaches no series.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicySample {
    pub accepted_packets: u64,
    pub accepted_bytes: u64,
    pub denied_packets: u64,
    pub denied_bytes: u64,
    pub rule_hits: [u64; MAX_RULE_SERIES],
}

impl Default for PolicySample {
    /// Written out because an array this long is past the width `Default` is
    /// derived for.
    fn default() -> Self {
        Self {
            accepted_packets: 0,
            accepted_bytes: 0,
            denied_packets: 0,
            denied_bytes: 0,
            rule_hits: [0; MAX_RULE_SERIES],
        }
    }
}

/// What the connection tracker has done, which is one account for the whole
/// domain rather than one per direction: a flow spans both, so a per-pipeline
/// split would be two half-views of one conversation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowSample {
    pub packets_seen: u64,
    pub outcomes: [u64; FLOW_OUTCOMES.len()],
    pub refusals: [u64; FLOW_REFUSALS.len()],
    pub lifecycle: [u64; FLOW_LIFECYCLE_EVENTS.len()],
    pub entries: [u64; FLOW_STATES.len()],
    pub probe_collisions: u64,
    pub slot_desync: u64,
}

/// Slots [`FlowSample`] occupies.
pub const FLOW_SLOTS: usize = 1
    + FLOW_OUTCOMES.len()
    + FLOW_REFUSALS.len()
    + FLOW_LIFECYCLE_EVENTS.len()
    + FLOW_STATES.len()
    + 2;

/// Slots [`ForwarderSample`]'s own **table** occupies — the series the catalogue
/// names, and so the slot the per-rule block starts at.
pub const FORWARDER_SLOTS: usize =
    PIPELINES * (1 + ROUTE_DROP_REASONS.len() + ROUTE_STAGE_DROP_REASONS.len()) + 12 + FLOW_SLOTS;

/// Where a rule's hit counter sits: its position in the running generation,
/// offset past the table above.
///
/// The one place the two halves of a rule series are bound together. The
/// forwarding domain writes here by position and the renderer reads here by
/// position, so a slot moved on one side and not the other does not compile.
pub const RULE_HITS_BASE: usize = FORWARDER_SLOTS;

/// Every slot the forwarding domain writes, table and per-rule block together.
///
/// Larger than the table because the per-rule series are not in it: their labels
/// are the running document's text, so they cannot be a `&'static [Series]`. The
/// shard is sized by this and the catalogue by [`FORWARDER_SLOTS`], which is what
/// keeps the block reachable and unnamed rather than named and empty.
pub const FORWARDER_SHARD_SLOTS: usize = FORWARDER_SLOTS + MAX_RULE_SERIES;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForwarderSample {
    pub pipelines: [PipelineSample; PIPELINES],
    pub generation: u64,
    pub images_applied: u64,
    pub images_refused: u64,
    pub policy: PolicySample,
    pub flow: FlowSample,
    pub tap: TapSample,
    pub log: LogSample,
}

impl ForwarderSample {
    pub const SERIES: &'static [Series] = &[
        // Pipeline 0.
        s(&FORWARDED_FRAMES, &[Label::new("pipeline", "0")]),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "unconfigured_ingress_port"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "interface_disabled"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "not_addressed_to_us"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "vlan_tagged"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "martian_source"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "unroutable_destination"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "addressed_to_this_router"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "ttl_expired"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "no_route"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "egress_is_ingress"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "no_neighbour"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "flow_unsupported_protocol"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "flow_fragment"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "flow_malformed"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "flow_invalid_flags"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "flow_mid_stream"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "flow_invalid_state"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "flow_out_of_window"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "flow_no_such_flow"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "flow_quoted_invalid"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "flow_unsupported_icmp"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "flow_table_full"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "flow_bucket_full"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "policy_denied"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "no_policy_match"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "egress_full"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "malformed_descriptor"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "snapshot_failed"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "frame_too_short"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "ethernet_unparsable"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "ipv4_unparsable"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "ipv4_checksum_invalid"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "misrouted"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "0"),
                Label::new("reason", "writeback_failed"),
            ],
        ),
        // Pipeline 1.
        s(&FORWARDED_FRAMES, &[Label::new("pipeline", "1")]),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "unconfigured_ingress_port"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "interface_disabled"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "not_addressed_to_us"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "vlan_tagged"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "martian_source"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "unroutable_destination"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "addressed_to_this_router"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "ttl_expired"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "no_route"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "egress_is_ingress"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "no_neighbour"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "flow_unsupported_protocol"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "flow_fragment"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "flow_malformed"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "flow_invalid_flags"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "flow_mid_stream"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "flow_invalid_state"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "flow_out_of_window"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "flow_no_such_flow"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "flow_quoted_invalid"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "flow_unsupported_icmp"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "flow_table_full"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "flow_bucket_full"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "policy_denied"),
            ],
        ),
        s(
            &ROUTE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "no_policy_match"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "egress_full"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "malformed_descriptor"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "snapshot_failed"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "frame_too_short"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "ethernet_unparsable"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "ipv4_unparsable"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "ipv4_checksum_invalid"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "misrouted"),
            ],
        ),
        s(
            &ROUTE_STAGE_DROPS,
            &[
                Label::new("pipeline", "1"),
                Label::new("reason", "writeback_failed"),
            ],
        ),
        // The configuration this domain decides under, and the log ring it
        // publishes through.
        plain(&CONFIGURATION_GENERATION),
        s(&CONFIGURATION_IMAGES, &[Label::new("outcome", "applied")]),
        s(&CONFIGURATION_IMAGES, &[Label::new("outcome", "refused")]),
        // The filter's own totals. No `pipeline` label: one stage serves both
        // directions, so there is no per-direction number to report.
        s(&POLICY_PACKETS, &[Label::new("verdict", "accepted")]),
        s(&POLICY_PACKETS, &[Label::new("verdict", "denied")]),
        s(&POLICY_BYTES, &[Label::new("verdict", "accepted")]),
        s(&POLICY_BYTES, &[Label::new("verdict", "denied")]),
        // The connection tracker. No `pipeline` label either, and for the
        // filter's reason twice over: one table serves both directions because
        // a flow *is* both directions.
        plain(&FLOW_PACKETS_SEEN),
        s(&FLOW_PACKETS, &[Label::new("outcome", "new")]),
        s(&FLOW_PACKETS, &[Label::new("outcome", "established")]),
        s(&FLOW_PACKETS, &[Label::new("outcome", "related")]),
        s(
            &FLOW_PACKETS_REFUSED,
            &[Label::new("reason", "unsupported_protocol")],
        ),
        s(&FLOW_PACKETS_REFUSED, &[Label::new("reason", "fragment")]),
        s(&FLOW_PACKETS_REFUSED, &[Label::new("reason", "malformed")]),
        s(
            &FLOW_PACKETS_REFUSED,
            &[Label::new("reason", "invalid_flags")],
        ),
        s(&FLOW_PACKETS_REFUSED, &[Label::new("reason", "mid_stream")]),
        s(
            &FLOW_PACKETS_REFUSED,
            &[Label::new("reason", "invalid_state")],
        ),
        s(
            &FLOW_PACKETS_REFUSED,
            &[Label::new("reason", "out_of_window")],
        ),
        s(
            &FLOW_PACKETS_REFUSED,
            &[Label::new("reason", "no_such_flow")],
        ),
        s(
            &FLOW_PACKETS_REFUSED,
            &[Label::new("reason", "quoted_invalid")],
        ),
        s(
            &FLOW_PACKETS_REFUSED,
            &[Label::new("reason", "unsupported_icmp")],
        ),
        s(&FLOW_PACKETS_REFUSED, &[Label::new("reason", "table_full")]),
        s(
            &FLOW_PACKETS_REFUSED,
            &[Label::new("reason", "bucket_full")],
        ),
        s(&FLOW_LIFECYCLE, &[Label::new("event", "expired")]),
        s(&FLOW_LIFECYCLE, &[Label::new("event", "evicted")]),
        s(&FLOW_LIFECYCLE, &[Label::new("event", "closed")]),
        s(&FLOW_LIFECYCLE, &[Label::new("event", "withdrawn")]),
        s(&FLOW_TABLE_ENTRIES, &[Label::new("state", "vacant")]),
        s(&FLOW_TABLE_ENTRIES, &[Label::new("state", "syn_sent")]),
        s(&FLOW_TABLE_ENTRIES, &[Label::new("state", "syn_received")]),
        s(&FLOW_TABLE_ENTRIES, &[Label::new("state", "established")]),
        s(&FLOW_TABLE_ENTRIES, &[Label::new("state", "fin_wait")]),
        s(&FLOW_TABLE_ENTRIES, &[Label::new("state", "close_wait")]),
        s(&FLOW_TABLE_ENTRIES, &[Label::new("state", "closing")]),
        s(&FLOW_TABLE_ENTRIES, &[Label::new("state", "time_wait")]),
        s(&FLOW_TABLE_ENTRIES, &[Label::new("state", "closed")]),
        s(&FLOW_TABLE_ENTRIES, &[Label::new("state", "udp_unreplied")]),
        s(&FLOW_TABLE_ENTRIES, &[Label::new("state", "udp_assured")]),
        s(
            &FLOW_TABLE_ENTRIES,
            &[Label::new("state", "icmp_unreplied")],
        ),
        s(&FLOW_TABLE_ENTRIES, &[Label::new("state", "icmp_replied")]),
        plain(&FLOW_PROBE_COLLISIONS),
        s(
            &INVARIANT_FAULTS,
            &[Label::new("fault", "flow_slot_desync")],
        ),
        plain(&TAP_OBSERVATIONS),
        s(&TAP_OBSERVATIONS_LOST, &[Label::new("reason", "ring_full")]),
        s(
            &TAP_OBSERVATIONS_LOST,
            &[Label::new("reason", "inconsistent")],
        ),
        plain(&LOG_RECORDS_DROPPED),
        plain(&LOG_RECORDS_REFUSED),
    ];

    /// Every slot this domain publishes: the table above in [`SERIES`] order,
    /// then the per-rule block at [`RULE_HITS_BASE`].
    ///
    /// [`SERIES`]: ForwarderSample::SERIES
    #[must_use]
    pub fn values(&self) -> [u64; FORWARDER_SHARD_SLOTS] {
        let mut values = [0u64; FORWARDER_SHARD_SLOTS];
        let mut at = 0;
        for pipeline in &self.pipelines {
            put(&mut values, &mut at, pipeline.forwarded);
            put_all(&mut values, &mut at, &pipeline.route_drops);
            put_all(&mut values, &mut at, &pipeline.stage_drops);
        }
        put(&mut values, &mut at, self.generation);
        put(&mut values, &mut at, self.images_applied);
        put(&mut values, &mut at, self.images_refused);
        put(&mut values, &mut at, self.policy.accepted_packets);
        put(&mut values, &mut at, self.policy.denied_packets);
        put(&mut values, &mut at, self.policy.accepted_bytes);
        put(&mut values, &mut at, self.policy.denied_bytes);
        put(&mut values, &mut at, self.flow.packets_seen);
        put_all(&mut values, &mut at, &self.flow.outcomes);
        put_all(&mut values, &mut at, &self.flow.refusals);
        put_all(&mut values, &mut at, &self.flow.lifecycle);
        put_all(&mut values, &mut at, &self.flow.entries);
        put(&mut values, &mut at, self.flow.probe_collisions);
        put(&mut values, &mut at, self.flow.slot_desync);
        put(&mut values, &mut at, self.tap.observed);
        put(&mut values, &mut at, self.tap.dropped);
        put(&mut values, &mut at, self.tap.refused);
        put(&mut values, &mut at, self.log.dropped);
        put(&mut values, &mut at, self.log.refused);
        // The cursor has reached the end of the named table exactly, which the
        // assertion below is what guarantees; the block that follows is placed
        // by position rather than by the cursor because that is how it is read.
        put_all(&mut values, &mut at, &self.policy.rule_hits);
        values
    }
}

/// Slots [`DriverSample`] occupies.
pub const DRIVER_SLOTS: usize = 27;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DriverSample {
    pub receive_frames: u64,
    pub receive_bytes: u64,
    pub transmit_frames: u64,
    pub transmit_bytes: u64,
    pub input_drops: [u64; 7],
    pub invariant_faults: [u64; 4],
    pub receive_device_faults: [u64; 3],
    pub transmit_device_faults: [u64; 3],
    pub queue_posted: [u64; 2],
    pub receive_pool: PoolSample,
    pub log: LogSample,
}

impl DriverSample {
    pub const SERIES: &'static [Series] = &[
        plain(&RECEIVE_FRAMES),
        plain(&RECEIVE_BYTES),
        plain(&TRANSMIT_FRAMES),
        plain(&TRANSMIT_BYTES),
        s(&INPUT_DROPS, &[Label::new("reason", "rx_runt")]),
        s(&INPUT_DROPS, &[Label::new("reason", "rx_peer_ring_full")]),
        s(&INPUT_DROPS, &[Label::new("reason", "tx_malformed")]),
        s(&INPUT_DROPS, &[Label::new("reason", "tx_duplicate")]),
        s(&INPUT_DROPS, &[Label::new("reason", "tx_discarded")]),
        s(
            &INPUT_DROPS,
            &[Label::new("reason", "tx_verdict_undecodable")],
        ),
        s(&INPUT_DROPS, &[Label::new("reason", "tx_free_ring_full")]),
        s(
            &INVARIANT_FAULTS,
            &[Label::new("fault", "rx_completion_unmapped")],
        ),
        s(
            &INVARIANT_FAULTS,
            &[Label::new("fault", "tx_completion_unmapped")],
        ),
        s(
            &INVARIANT_FAULTS,
            &[Label::new("fault", "rx_slot_occupied")],
        ),
        s(
            &INVARIANT_FAULTS,
            &[Label::new("fault", "tx_slot_occupied")],
        ),
        s(
            &DEVICE_FAULTS,
            &[
                Label::new("queue", "receive"),
                Label::new("fault", "completion_out_of_range"),
            ],
        ),
        s(
            &DEVICE_FAULTS,
            &[
                Label::new("queue", "receive"),
                Label::new("fault", "completion_not_posted"),
            ],
        ),
        s(
            &DEVICE_FAULTS,
            &[
                Label::new("queue", "receive"),
                Label::new("fault", "completion_length_over_reported"),
            ],
        ),
        s(
            &DEVICE_FAULTS,
            &[
                Label::new("queue", "transmit"),
                Label::new("fault", "completion_out_of_range"),
            ],
        ),
        s(
            &DEVICE_FAULTS,
            &[
                Label::new("queue", "transmit"),
                Label::new("fault", "completion_not_posted"),
            ],
        ),
        s(
            &DEVICE_FAULTS,
            &[
                Label::new("queue", "transmit"),
                Label::new("fault", "completion_length_over_reported"),
            ],
        ),
        s(&QUEUE_POSTED, &[Label::new("queue", "receive")]),
        s(&QUEUE_POSTED, &[Label::new("queue", "transmit")]),
        s(
            &POOL_RETURNS_REFUSED,
            &[
                Label::new("pool", "receive"),
                Label::new("reason", "not_lent"),
            ],
        ),
        s(
            &POOL_RETURNS_REFUSED,
            &[
                Label::new("pool", "receive"),
                Label::new("reason", "ledger_refused"),
            ],
        ),
        plain(&LOG_RECORDS_DROPPED),
        plain(&LOG_RECORDS_REFUSED),
    ];

    #[must_use]
    pub fn values(&self) -> [u64; DRIVER_SLOTS] {
        let mut values = [0u64; DRIVER_SLOTS];
        let mut at = 0;
        put(&mut values, &mut at, self.receive_frames);
        put(&mut values, &mut at, self.receive_bytes);
        put(&mut values, &mut at, self.transmit_frames);
        put(&mut values, &mut at, self.transmit_bytes);
        put_all(&mut values, &mut at, &self.input_drops);
        put_all(&mut values, &mut at, &self.invariant_faults);
        put_all(&mut values, &mut at, &self.receive_device_faults);
        put_all(&mut values, &mut at, &self.transmit_device_faults);
        put_all(&mut values, &mut at, &self.queue_posted);
        put(&mut values, &mut at, self.receive_pool.not_lent);
        put(&mut values, &mut at, self.receive_pool.ledger_refused);
        put(&mut values, &mut at, self.log.dropped);
        put(&mut values, &mut at, self.log.refused);
        values
    }
}

/// What the terminal endpoint made of the frames addressed to it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EndpointSample {
    pub arp_replies: u64,
    pub echo_replies: u64,
    pub not_for_us: u64,
    pub malformed: u64,
    pub reply_refused: u64,
    pub tcp_segments: u64,
    pub unclocked: u64,
    pub unhandled: [u64; 9],
}

/// The transport's twenty-seven causes, in `lfw_tcp::TcpCounters` declaration
/// order — which a test in `pd_runtime` holds this to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpSample {
    pub segments_received: u64,
    pub segments_sent: u64,
    pub connections_accepted: u64,
    pub connections_established: u64,
    pub connections_closed: u64,
    pub connections_evicted: u64,
    pub connections_reaped: u64,
    pub connections_abandoned: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub bytes_retransmitted: u64,
    pub retransmits: u64,
    pub refused_malformed: u64,
    pub refused_bad_checksum: u64,
    pub refused_out_of_window: u64,
    pub refused_table_full: u64,
    pub refused_not_listening: u64,
    pub refused_no_connection: u64,
    pub refused_unacceptable_ack: u64,
    pub refused_no_acknowledgement: u64,
    pub refused_out_of_order: u64,
    pub urgent_ignored: u64,
    pub challenge_acks: u64,
    pub challenges_suppressed: u64,
    pub resets_received: u64,
    pub resets_sent: u64,
    pub write_refused: u64,
}

/// What the management HTTP server did with the connections it carried.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HttpSample {
    pub requests: u64,
    pub responses: [u64; HTTP_STATUSES.len()],
    pub response_bytes: u64,
    pub overflowed: u64,
    pub bodies_refused: u64,
    pub bodies_taken: u64,
    pub bodies_overrun: u64,
    pub retransmits_unavailable: u64,
    pub slots_exhausted: u64,
}

/// Slots [`ManagementSample`] occupies — the largest of the eight, and what
/// [`crate::STATS_SLOTS`] is sized by.
pub const MANAGEMENT_SLOTS: usize = 83;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ManagementSample {
    pub frames: u64,
    pub bytes: u64,
    pub stage_drops: [u64; 4],
    pub replies_sent: u64,
    pub replies_lost: [u64; 3],
    pub generation: u64,
    pub images_refused: u64,
    pub clock_generation: u64,
    pub clocks_refused: u64,
    pub timer_segments: u64,
    pub transmit_pool: PoolSample,
    pub endpoint: EndpointSample,
    pub tcp: TcpSample,
    pub http: HttpSample,
    /// Streams begun, given up on, windows handed over, and their bytes.
    pub streams: [u64; 4],
    pub log: LogSample,
}

impl ManagementSample {
    pub const SERIES: &'static [Series] = &[
        plain(&ENDPOINT_FRAMES),
        plain(&ENDPOINT_BYTES),
        s(
            &ENDPOINT_STAGE_DROPS,
            &[Label::new("reason", "malformed_descriptor")],
        ),
        s(
            &ENDPOINT_STAGE_DROPS,
            &[Label::new("reason", "snapshot_failed")],
        ),
        s(
            &ENDPOINT_STAGE_DROPS,
            &[Label::new("reason", "return_ring_full")],
        ),
        s(
            &ENDPOINT_STAGE_DROPS,
            &[Label::new("reason", "unaddressed")],
        ),
        plain(&ENDPOINT_REPLIES_SENT),
        s(
            &ENDPOINT_REPLIES_LOST,
            &[Label::new("reason", "pool_exhausted")],
        ),
        s(&ENDPOINT_REPLIES_LOST, &[Label::new("reason", "ring_full")]),
        s(
            &ENDPOINT_REPLIES_LOST,
            &[Label::new("reason", "write_failed")],
        ),
        plain(&CONFIGURATION_GENERATION),
        s(&CONFIGURATION_IMAGES, &[Label::new("outcome", "refused")]),
        plain(&CLOCK_GENERATION),
        plain(&CLOCK_CALIBRATIONS_REFUSED),
        plain(&ENDPOINT_TIMER_SEGMENTS),
        s(
            &POOL_RETURNS_REFUSED,
            &[
                Label::new("pool", "transmit"),
                Label::new("reason", "not_lent"),
            ],
        ),
        s(
            &POOL_RETURNS_REFUSED,
            &[
                Label::new("pool", "transmit"),
                Label::new("reason", "ledger_refused"),
            ],
        ),
        // The endpoint's own outcomes.
        s(&ENDPOINT_REPLIES, &[Label::new("protocol", "arp")]),
        s(&ENDPOINT_REPLIES, &[Label::new("protocol", "icmp_echo")]),
        plain(&ENDPOINT_NOT_FOR_US),
        plain(&ENDPOINT_MALFORMED),
        plain(&ENDPOINT_REPLY_REFUSED),
        plain(&ENDPOINT_TCP_SEGMENTS),
        plain(&ENDPOINT_UNCLOCKED),
        s(&ENDPOINT_UNHANDLED, &[Label::new("reason", "vlan_tagged")]),
        s(
            &ENDPOINT_UNHANDLED,
            &[Label::new("reason", "ethertype_not_handled")],
        ),
        s(
            &ENDPOINT_UNHANDLED,
            &[Label::new("reason", "arp_not_a_request")],
        ),
        s(
            &ENDPOINT_UNHANDLED,
            &[Label::new("reason", "protocol_not_handled")],
        ),
        s(
            &ENDPOINT_UNHANDLED,
            &[Label::new("reason", "not_an_echo_request")],
        ),
        s(&ENDPOINT_UNHANDLED, &[Label::new("reason", "fragmented")]),
        s(
            &ENDPOINT_UNHANDLED,
            &[Label::new("reason", "source_not_unicast")],
        ),
        s(
            &ENDPOINT_UNHANDLED,
            &[Label::new("reason", "source_off_link")],
        ),
        s(
            &ENDPOINT_UNHANDLED,
            &[Label::new("reason", "arp_sender_mac_mismatch")],
        ),
        // The transport.
        s(&TCP_SEGMENTS, &[Label::new("direction", "received")]),
        s(&TCP_SEGMENTS, &[Label::new("direction", "sent")]),
        s(&TCP_CONNECTIONS, &[Label::new("event", "accepted")]),
        s(&TCP_CONNECTIONS, &[Label::new("event", "established")]),
        s(&TCP_CONNECTIONS, &[Label::new("event", "closed")]),
        s(&TCP_CONNECTIONS, &[Label::new("event", "evicted")]),
        s(&TCP_CONNECTIONS, &[Label::new("event", "reaped")]),
        s(&TCP_CONNECTIONS, &[Label::new("event", "abandoned")]),
        s(&TCP_BYTES, &[Label::new("direction", "received")]),
        s(&TCP_BYTES, &[Label::new("direction", "sent")]),
        s(&TCP_BYTES, &[Label::new("direction", "retransmitted")]),
        plain(&TCP_RETRANSMITS),
        s(&TCP_REFUSED, &[Label::new("reason", "malformed")]),
        s(&TCP_REFUSED, &[Label::new("reason", "bad_checksum")]),
        s(&TCP_REFUSED, &[Label::new("reason", "out_of_window")]),
        s(&TCP_REFUSED, &[Label::new("reason", "table_full")]),
        s(&TCP_REFUSED, &[Label::new("reason", "not_listening")]),
        s(&TCP_REFUSED, &[Label::new("reason", "no_connection")]),
        s(&TCP_REFUSED, &[Label::new("reason", "unacceptable_ack")]),
        s(&TCP_REFUSED, &[Label::new("reason", "no_acknowledgement")]),
        s(&TCP_REFUSED, &[Label::new("reason", "out_of_order")]),
        plain(&TCP_URGENT_IGNORED),
        plain(&TCP_CHALLENGE_ACKS),
        plain(&TCP_CHALLENGES_SUPPRESSED),
        s(&TCP_RESETS, &[Label::new("direction", "received")]),
        s(&TCP_RESETS, &[Label::new("direction", "sent")]),
        plain(&TCP_WRITE_REFUSED),
        // The server above it.
        plain(&HTTP_REQUESTS),
        s(&HTTP_RESPONSES, &[Label::new("status", "200")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "400")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "404")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "405")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "413")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "414")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "431")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "503")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "505")]),
        plain(&HTTP_RESPONSE_BYTES),
        plain(&HTTP_REQUESTS_OVERFLOWED),
        plain(&HTTP_BODIES_REFUSED),
        plain(&HTTP_BODIES_TAKEN),
        plain(&HTTP_BODY_OVERRUNS),
        plain(&HTTP_RETRANSMITS_UNAVAILABLE),
        plain(&HTTP_SLOTS_EXHAUSTED),
        s(&RECORDING_STREAMS, &[Label::new("outcome", "started")]),
        s(&RECORDING_STREAMS, &[Label::new("outcome", "abandoned")]),
        plain(&RECORDING_STREAM_WINDOWS),
        plain(&RECORDING_STREAM_BYTES),
        plain(&LOG_RECORDS_DROPPED),
        plain(&LOG_RECORDS_REFUSED),
    ];

    #[must_use]
    pub fn values(&self) -> [u64; MANAGEMENT_SLOTS] {
        let mut values = [0u64; MANAGEMENT_SLOTS];
        let mut at = 0;
        put(&mut values, &mut at, self.frames);
        put(&mut values, &mut at, self.bytes);
        put_all(&mut values, &mut at, &self.stage_drops);
        put(&mut values, &mut at, self.replies_sent);
        put_all(&mut values, &mut at, &self.replies_lost);
        put(&mut values, &mut at, self.generation);
        put(&mut values, &mut at, self.images_refused);
        put(&mut values, &mut at, self.clock_generation);
        put(&mut values, &mut at, self.clocks_refused);
        put(&mut values, &mut at, self.timer_segments);
        put(&mut values, &mut at, self.transmit_pool.not_lent);
        put(&mut values, &mut at, self.transmit_pool.ledger_refused);

        let endpoint = &self.endpoint;
        put(&mut values, &mut at, endpoint.arp_replies);
        put(&mut values, &mut at, endpoint.echo_replies);
        put(&mut values, &mut at, endpoint.not_for_us);
        put(&mut values, &mut at, endpoint.malformed);
        put(&mut values, &mut at, endpoint.reply_refused);
        put(&mut values, &mut at, endpoint.tcp_segments);
        put(&mut values, &mut at, endpoint.unclocked);
        put_all(&mut values, &mut at, &endpoint.unhandled);

        let tcp = &self.tcp;
        put(&mut values, &mut at, tcp.segments_received);
        put(&mut values, &mut at, tcp.segments_sent);
        put(&mut values, &mut at, tcp.connections_accepted);
        put(&mut values, &mut at, tcp.connections_established);
        put(&mut values, &mut at, tcp.connections_closed);
        put(&mut values, &mut at, tcp.connections_evicted);
        put(&mut values, &mut at, tcp.connections_reaped);
        put(&mut values, &mut at, tcp.connections_abandoned);
        put(&mut values, &mut at, tcp.bytes_received);
        put(&mut values, &mut at, tcp.bytes_sent);
        put(&mut values, &mut at, tcp.bytes_retransmitted);
        put(&mut values, &mut at, tcp.retransmits);
        put(&mut values, &mut at, tcp.refused_malformed);
        put(&mut values, &mut at, tcp.refused_bad_checksum);
        put(&mut values, &mut at, tcp.refused_out_of_window);
        put(&mut values, &mut at, tcp.refused_table_full);
        put(&mut values, &mut at, tcp.refused_not_listening);
        put(&mut values, &mut at, tcp.refused_no_connection);
        put(&mut values, &mut at, tcp.refused_unacceptable_ack);
        put(&mut values, &mut at, tcp.refused_no_acknowledgement);
        put(&mut values, &mut at, tcp.refused_out_of_order);
        put(&mut values, &mut at, tcp.urgent_ignored);
        put(&mut values, &mut at, tcp.challenge_acks);
        put(&mut values, &mut at, tcp.challenges_suppressed);
        put(&mut values, &mut at, tcp.resets_received);
        put(&mut values, &mut at, tcp.resets_sent);
        put(&mut values, &mut at, tcp.write_refused);

        let http = &self.http;
        put(&mut values, &mut at, http.requests);
        put_all(&mut values, &mut at, &http.responses);
        put(&mut values, &mut at, http.response_bytes);
        put(&mut values, &mut at, http.overflowed);
        put(&mut values, &mut at, http.bodies_refused);
        put(&mut values, &mut at, http.bodies_taken);
        put(&mut values, &mut at, http.bodies_overrun);
        put(&mut values, &mut at, http.retransmits_unavailable);
        put(&mut values, &mut at, http.slots_exhausted);

        put_all(&mut values, &mut at, &self.streams);
        put(&mut values, &mut at, self.log.dropped);
        put(&mut values, &mut at, self.log.refused);
        values
    }
}

/// What the serial controller under the console has to say about itself.
///
/// Its own type rather than three arguments, and here rather than in either of
/// the two crates that fill it: `uart_16550` measures the numbers and `lfw_log`
/// assembles the shard they belong to, and neither depends on the other —
/// `lfw_log::ByteSink` is deliberately the whole of what the console knows about
/// a writer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UartSample {
    pub bytes_written: u64,
    pub thre_timeouts: u64,
    pub init_failures: u64,
}

/// Slots [`ConsoleSample`] occupies.
pub const CONSOLE_SLOTS: usize = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConsoleSample {
    /// Printed, malformed, unknown, unrenderable, write-failed, in that order.
    pub records: [u64; 5],
    pub uart_bytes_written: u64,
    pub uart_transmitter_timeouts: u64,
    pub uart_init_failures: u64,
}

impl ConsoleSample {
    pub const SERIES: &'static [Series] = &[
        s(&CONSOLE_RECORDS, &[Label::new("outcome", "printed")]),
        s(&CONSOLE_RECORDS, &[Label::new("outcome", "malformed")]),
        s(&CONSOLE_RECORDS, &[Label::new("outcome", "unknown")]),
        s(&CONSOLE_RECORDS, &[Label::new("outcome", "unrenderable")]),
        s(&CONSOLE_RECORDS, &[Label::new("outcome", "write_failed")]),
        plain(&UART_BYTES_WRITTEN),
        plain(&UART_TRANSMITTER_TIMEOUTS),
        plain(&UART_INIT_FAILURES),
    ];

    #[must_use]
    pub fn values(&self) -> [u64; CONSOLE_SLOTS] {
        let mut values = [0u64; CONSOLE_SLOTS];
        let mut at = 0;
        put_all(&mut values, &mut at, &self.records);
        put(&mut values, &mut at, self.uart_bytes_written);
        put(&mut values, &mut at, self.uart_transmitter_timeouts);
        put(&mut values, &mut at, self.uart_init_failures);
        values
    }
}

/// Slots [`ConfigSample`] occupies.
pub const CONFIG_SLOTS: usize = 4 + GENERATION_OUTCOMES;

/// What the deciding domain can have decided about a submitted document, in
/// [`ConfigSample::submissions`]' order.
///
/// The console's own `GenerationOutcome` vocabulary, name for name, which a test
/// in `pd_runtime` holds this array to as it does the transport's: an operator
/// reading a refusal on the console and graphing the refusal rate must be reading
/// one thing.
pub const GENERATION_OUTCOMES: usize = 3;
pub const GENERATION_OUTCOME_NAMES: [&str; GENERATION_OUTCOMES] =
    ["applied", "refused", "unchanged"];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfigSample {
    pub generation: u64,
    /// One slot per [`GENERATION_OUTCOME_NAMES`] entry.
    pub submissions: [u64; GENERATION_OUTCOMES],
    pub reads: u64,
    pub log: LogSample,
}

impl ConfigSample {
    pub const SERIES: &'static [Series] = &[
        plain(&CONFIGURATION_GENERATION),
        s(
            &CONFIGURATION_SUBMISSIONS,
            &[Label::new("outcome", GENERATION_OUTCOME_NAMES[0])],
        ),
        s(
            &CONFIGURATION_SUBMISSIONS,
            &[Label::new("outcome", GENERATION_OUTCOME_NAMES[1])],
        ),
        s(
            &CONFIGURATION_SUBMISSIONS,
            &[Label::new("outcome", GENERATION_OUTCOME_NAMES[2])],
        ),
        plain(&CONFIGURATION_READS),
        plain(&LOG_RECORDS_DROPPED),
        plain(&LOG_RECORDS_REFUSED),
    ];

    #[must_use]
    pub fn values(&self) -> [u64; CONFIG_SLOTS] {
        [
            self.generation,
            self.submissions[0],
            self.submissions[1],
            self.submissions[2],
            self.reads,
            self.log.dropped,
            self.log.refused,
        ]
    }
}

/// Slots [`ClockSample`] occupies.
pub const CLOCK_SLOTS: usize = 3;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClockSample {
    pub frequency_hertz: u64,
    pub log: LogSample,
}

impl ClockSample {
    pub const SERIES: &'static [Series] = &[
        plain(&CLOCK_FREQUENCY_HERTZ),
        plain(&LOG_RECORDS_DROPPED),
        plain(&LOG_RECORDS_REFUSED),
    ];

    #[must_use]
    pub fn values(&self) -> [u64; CLOCK_SLOTS] {
        [self.frequency_hertz, self.log.dropped, self.log.refused]
    }
}

/// One recording, in `lfw_recorder::SinkCounters` order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SinkSample {
    pub records: u64,
    pub record_bytes: u64,
    /// Oversized then refused, as the series name them. A deferral is not
    /// among them: `staging_deferrals` is its own series because the record
    /// is still the caller's and reaches the recording on a later pass.
    pub dropped: [u64; 2],
    pub staging_deferrals: u64,
    pub segments_closed: u64,
    pub wraps: u64,
    pub sectors_written: u64,
    pub padding_bytes: u64,
    pub download_overruns: u64,
}

/// Recordings this appliance keeps: the capture sink and the log sink.
pub const SINKS: usize = 2;

const SINK_SLOTS: usize = 10;

/// Slots [`RecorderSample`] occupies.
pub const RECORDER_SLOTS: usize = 12 + SINKS * SINK_SLOTS + 6;

/// What the domain owning the block device has to say about itself. Its faults
/// carry `queue="request"` on the family a driver's carry `queue="receive"`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecorderSample {
    pub capacity_sectors: u64,
    /// Read then write, as the series name them.
    pub requests: [u64; 2],
    pub bytes: [u64; 2],
    /// In `virtio::queue::DeviceFaults` field order.
    pub device_faults: [u64; 3],
    pub status_undecodable: u64,
    pub completion_unmapped: u64,
    pub sinks: [SinkSample; SINKS],
    /// Tap records drained, annotations refused, and drops the forwarder
    /// claims about itself.
    pub tap: [u64; 3],
    /// Downloads served then refused.
    pub downloads: [u64; 2],
    pub records_unclocked: u64,
    pub log: LogSample,
}

impl RecorderSample {
    pub const SERIES: &'static [Series] = &[
        plain(&BLOCK_CAPACITY_SECTORS),
        s(&BLOCK_REQUESTS, &[Label::new("operation", "read")]),
        s(&BLOCK_REQUESTS, &[Label::new("operation", "write")]),
        s(&BLOCK_BYTES, &[Label::new("operation", "read")]),
        s(&BLOCK_BYTES, &[Label::new("operation", "write")]),
        s(
            &DEVICE_FAULTS,
            &[
                Label::new("queue", "request"),
                Label::new("fault", "completion_out_of_range"),
            ],
        ),
        s(
            &DEVICE_FAULTS,
            &[
                Label::new("queue", "request"),
                Label::new("fault", "completion_not_posted"),
            ],
        ),
        s(
            &DEVICE_FAULTS,
            &[
                Label::new("queue", "request"),
                Label::new("fault", "completion_length_over_reported"),
            ],
        ),
        plain(&BLOCK_STATUS_UNDECODABLE),
        s(
            &INVARIANT_FAULTS,
            &[Label::new("fault", "block_completion_unmapped")],
        ),
        s(&RECORDING_RECORDS, &[Label::new("sink", "log")]),
        s(&RECORDING_RECORD_BYTES, &[Label::new("sink", "log")]),
        s(
            &RECORDING_RECORDS_DROPPED,
            &[Label::new("sink", "log"), Label::new("reason", "oversized")],
        ),
        s(
            &RECORDING_RECORDS_DROPPED,
            &[Label::new("sink", "log"), Label::new("reason", "refused")],
        ),
        s(&RECORDING_STAGING_DEFERRALS, &[Label::new("sink", "log")]),
        s(&RECORDING_SEGMENTS_CLOSED, &[Label::new("sink", "log")]),
        s(&RECORDING_WRAPS, &[Label::new("sink", "log")]),
        s(&RECORDING_SECTORS_WRITTEN, &[Label::new("sink", "log")]),
        s(&RECORDING_PADDING_BYTES, &[Label::new("sink", "log")]),
        s(&RECORDING_DOWNLOAD_OVERRUNS, &[Label::new("sink", "log")]),
        s(&RECORDING_RECORDS, &[Label::new("sink", "capture")]),
        s(&RECORDING_RECORD_BYTES, &[Label::new("sink", "capture")]),
        s(
            &RECORDING_RECORDS_DROPPED,
            &[
                Label::new("sink", "capture"),
                Label::new("reason", "oversized"),
            ],
        ),
        s(
            &RECORDING_RECORDS_DROPPED,
            &[
                Label::new("sink", "capture"),
                Label::new("reason", "refused"),
            ],
        ),
        s(
            &RECORDING_STAGING_DEFERRALS,
            &[Label::new("sink", "capture")],
        ),
        s(&RECORDING_SEGMENTS_CLOSED, &[Label::new("sink", "capture")]),
        s(&RECORDING_WRAPS, &[Label::new("sink", "capture")]),
        s(&RECORDING_SECTORS_WRITTEN, &[Label::new("sink", "capture")]),
        s(&RECORDING_PADDING_BYTES, &[Label::new("sink", "capture")]),
        s(
            &RECORDING_DOWNLOAD_OVERRUNS,
            &[Label::new("sink", "capture")],
        ),
        plain(&RECORDING_TAP_RECORDS),
        plain(&RECORDING_TAP_REFUSED),
        plain(&RECORDING_TAP_DROPPED_BY_WRITER),
        s(&RECORDING_DOWNLOADS, &[Label::new("outcome", "served")]),
        s(&RECORDING_DOWNLOADS, &[Label::new("outcome", "refused")]),
        plain(&RECORDING_RECORDS_UNCLOCKED),
        plain(&LOG_RECORDS_DROPPED),
        plain(&LOG_RECORDS_REFUSED),
    ];

    #[must_use]
    pub fn values(&self) -> [u64; RECORDER_SLOTS] {
        let mut values = [0u64; RECORDER_SLOTS];
        let mut at = 0;
        put(&mut values, &mut at, self.capacity_sectors);
        put_all(&mut values, &mut at, &self.requests);
        put_all(&mut values, &mut at, &self.bytes);
        put_all(&mut values, &mut at, &self.device_faults);
        put(&mut values, &mut at, self.status_undecodable);
        put(&mut values, &mut at, self.completion_unmapped);
        for sink in &self.sinks {
            put(&mut values, &mut at, sink.records);
            put(&mut values, &mut at, sink.record_bytes);
            put_all(&mut values, &mut at, &sink.dropped);
            put(&mut values, &mut at, sink.staging_deferrals);
            put(&mut values, &mut at, sink.segments_closed);
            put(&mut values, &mut at, sink.wraps);
            put(&mut values, &mut at, sink.sectors_written);
            put(&mut values, &mut at, sink.padding_bytes);
            put(&mut values, &mut at, sink.download_overruns);
        }
        put_all(&mut values, &mut at, &self.tap);
        put_all(&mut values, &mut at, &self.downloads);
        put(&mut values, &mut at, self.records_unclocked);
        put(&mut values, &mut at, self.log.dropped);
        put(&mut values, &mut at, self.log.refused);
        values
    }
}

/// Place one value at the running slot. Bounded by the array rather than by the
/// cursor, so an arithmetic slip is a dropped write and never an index that
/// leaves it — and the assertions below make even that unreachable.
fn put(values: &mut [u64], at: &mut usize, value: u64) {
    if let Some(slot) = values.get_mut(*at) {
        *slot = value;
    }
    *at = at.saturating_add(1);
}

fn put_all(values: &mut [u64], at: &mut usize, source: &[u64]) {
    for value in source {
        put(values, at, *value);
    }
}

// Slot order and table length are one fact, so a series added without a value —
// or a value without a series — is a build error rather than a slot that
// renders as zero forever.
const _: () = {
    assert!(ForwarderSample::SERIES.len() == FORWARDER_SLOTS);
    assert!(DriverSample::SERIES.len() == DRIVER_SLOTS);
    assert!(ManagementSample::SERIES.len() == MANAGEMENT_SLOTS);
    assert!(ConsoleSample::SERIES.len() == CONSOLE_SLOTS);
    assert!(ConfigSample::SERIES.len() == CONFIG_SLOTS);
    assert!(ClockSample::SERIES.len() == CLOCK_SLOTS);
    assert!(RecorderSample::SERIES.len() == RECORDER_SLOTS);

    // The per-rule block begins exactly where the named table ends, which is
    // what makes the two writers of a rule series — the domain that publishes by
    // position and the renderer that reads by position — one fact.
    assert!(RULE_HITS_BASE == ForwarderSample::SERIES.len());
    assert!(FORWARDER_SHARD_SLOTS == RULE_HITS_BASE + MAX_RULE_SERIES);

    // The forwarder's shard is the widest published set, the per-rule block
    // putting it past the management endpoint's table, and that is the fact
    // `crate::STATS_SLOTS` is derived from — so every set fits the shard it is
    // published into and `StatsShard::publish` can truncate without any
    // first-party caller ever reaching the truncation.
    assert!(MANAGEMENT_SLOTS <= FORWARDER_SHARD_SLOTS);
    assert!(DRIVER_SLOTS <= MANAGEMENT_SLOTS);
    assert!(CONSOLE_SLOTS <= MANAGEMENT_SLOTS);
    assert!(CONFIG_SLOTS <= MANAGEMENT_SLOTS);
    assert!(CLOCK_SLOTS <= MANAGEMENT_SLOTS);
    assert!(RECORDER_SLOTS <= MANAGEMENT_SLOTS);
    assert!(FORWARDER_SHARD_SLOTS <= crate::STATS_SLOTS);
};
