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
//! Field-level documentation is deliberately absent (DOC-4): every field's
//! meaning is the `help` text of the metric its slot renders as, which is the
//! sentence an operator actually reads, and a second one here would be an
//! untested assertion beside it.

use crate::catalog::{
    CLOCK_CALIBRATIONS_REFUSED, CLOCK_FREQUENCY_HERTZ, CLOCK_GENERATION, CONFIGURATION_GENERATION,
    CONFIGURATION_IMAGES, CONSOLE_RECORDS, DEVICE_FAULTS, ENDPOINT_BYTES, ENDPOINT_FRAMES,
    ENDPOINT_MALFORMED, ENDPOINT_NOT_FOR_US, ENDPOINT_REPLIES, ENDPOINT_REPLIES_LOST,
    ENDPOINT_REPLIES_SENT, ENDPOINT_REPLY_REFUSED, ENDPOINT_STAGE_DROPS, ENDPOINT_TCP_SEGMENTS,
    ENDPOINT_TIMER_SEGMENTS, ENDPOINT_UNCLOCKED, ENDPOINT_UNHANDLED, FORWARDED_FRAMES,
    HTTP_EXPOSITIONS_REFUSED, HTTP_REQUESTS, HTTP_REQUESTS_OVERFLOWED, HTTP_RESPONSE_BYTES,
    HTTP_RESPONSES, HTTP_RETRANSMITS_UNAVAILABLE, HTTP_SLOTS_EXHAUSTED, INPUT_DROPS,
    INVARIANT_FAULTS, LOG_RECORDS_DROPPED, LOG_RECORDS_REFUSED, Label, POOL_RETURNS_REFUSED,
    RECEIVE_BYTES, RECEIVE_FRAMES, ROUTE_DROPS, ROUTE_STAGE_DROPS, Series, TCP_BYTES,
    TCP_CHALLENGE_ACKS, TCP_CONNECTIONS, TCP_REFUSED, TCP_RESETS, TCP_RETRANSMITS, TCP_SEGMENTS,
    TCP_URGENT_IGNORED, TCP_WRITE_REFUSED, TRANSMIT_BYTES, TRANSMIT_FRAMES, UART_BYTES_WRITTEN,
    UART_INIT_FAILURES, UART_TRANSMITTER_TIMEOUTS, plain, s,
};

/// Dataplane pipelines the forwarder carries, one per direction. A build fact
/// matching `config::PORT_COUNT`, held to it by a test in `pd_runtime`.
pub const PIPELINES: usize = 2;

/// The router's own refusal vocabulary, in `routing::DropReason::ALL` order —
/// which a test in `pd_runtime` holds this array to, name for name.
pub const ROUTE_DROP_REASONS: [&str; 11] = [
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
];

/// What the routing *stage* refuses around the router's decision: a descriptor
/// or a pool operation rather than a header.
pub const ROUTE_STAGE_DROP_REASONS: [&str; 6] = [
    "egress_full",
    "malformed_descriptor",
    "snapshot_failed",
    "unparsable",
    "misrouted",
    "writeback_failed",
];

/// Status codes the management server can answer with, in the order
/// [`HttpSample::responses`] holds them; `lfw_http::Status::ALL` is the same set
/// and a test in `lfw_ip_endpoint` holds the two together.
pub const HTTP_STATUSES: [&str; 8] = ["200", "400", "404", "405", "414", "431", "503", "505"];

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

/// Slots [`ForwarderSample`] occupies.
pub const FORWARDER_SLOTS: usize = PIPELINES * (1 + ROUTE_DROP_REASONS.len() + 6) + 5;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForwarderSample {
    pub pipelines: [PipelineSample; PIPELINES],
    pub generation: u64,
    pub images_applied: u64,
    pub images_refused: u64,
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
                Label::new("reason", "unparsable"),
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
                Label::new("reason", "unparsable"),
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
        plain(&LOG_RECORDS_DROPPED),
        plain(&LOG_RECORDS_REFUSED),
    ];

    #[must_use]
    pub fn values(&self) -> [u64; FORWARDER_SLOTS] {
        let mut values = [0u64; FORWARDER_SLOTS];
        let mut at = 0;
        for pipeline in &self.pipelines {
            put(&mut values, &mut at, pipeline.forwarded);
            put_all(&mut values, &mut at, &pipeline.route_drops);
            put_all(&mut values, &mut at, &pipeline.stage_drops);
        }
        put(&mut values, &mut at, self.generation);
        put(&mut values, &mut at, self.images_applied);
        put(&mut values, &mut at, self.images_refused);
        put(&mut values, &mut at, self.log.dropped);
        put(&mut values, &mut at, self.log.refused);
        values
    }
}

/// Slots [`DriverSample`] occupies.
pub const DRIVER_SLOTS: usize = 25;

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

/// The transport's twenty-six causes, in `lfw_tcp::TcpCounters` declaration
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
    pub expositions_refused: u64,
    pub retransmits_unavailable: u64,
    pub slots_exhausted: u64,
}

/// Slots [`ManagementSample`] occupies — the largest of the eight, and what
/// [`crate::STATS_SLOTS`] is sized by.
pub const MANAGEMENT_SLOTS: usize = 75;

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
        s(&TCP_RESETS, &[Label::new("direction", "received")]),
        s(&TCP_RESETS, &[Label::new("direction", "sent")]),
        plain(&TCP_WRITE_REFUSED),
        // The server above it.
        plain(&HTTP_REQUESTS),
        s(&HTTP_RESPONSES, &[Label::new("status", "200")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "400")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "404")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "405")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "414")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "431")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "503")]),
        s(&HTTP_RESPONSES, &[Label::new("status", "505")]),
        plain(&HTTP_RESPONSE_BYTES),
        plain(&HTTP_REQUESTS_OVERFLOWED),
        plain(&HTTP_EXPOSITIONS_REFUSED),
        plain(&HTTP_RETRANSMITS_UNAVAILABLE),
        plain(&HTTP_SLOTS_EXHAUSTED),
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
        put(&mut values, &mut at, tcp.resets_received);
        put(&mut values, &mut at, tcp.resets_sent);
        put(&mut values, &mut at, tcp.write_refused);

        let http = &self.http;
        put(&mut values, &mut at, http.requests);
        put_all(&mut values, &mut at, &http.responses);
        put(&mut values, &mut at, http.response_bytes);
        put(&mut values, &mut at, http.overflowed);
        put(&mut values, &mut at, http.expositions_refused);
        put(&mut values, &mut at, http.retransmits_unavailable);
        put(&mut values, &mut at, http.slots_exhausted);

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
pub const CONFIG_SLOTS: usize = 3;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfigSample {
    pub generation: u64,
    pub log: LogSample,
}

impl ConfigSample {
    pub const SERIES: &'static [Series] = &[
        plain(&CONFIGURATION_GENERATION),
        plain(&LOG_RECORDS_DROPPED),
        plain(&LOG_RECORDS_REFUSED),
    ];

    #[must_use]
    pub fn values(&self) -> [u64; CONFIG_SLOTS] {
        [self.generation, self.log.dropped, self.log.refused]
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

/// Place one value at the running slot. Bounded by the array rather than by the
/// cursor, so an arithmetic slip is a dropped write and never an index that
/// leaves it (ENG-5) — and the assertions below make even that unreachable.
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
// renders as zero forever (TEST-5).
const _: () = {
    assert!(ForwarderSample::SERIES.len() == FORWARDER_SLOTS);
    assert!(DriverSample::SERIES.len() == DRIVER_SLOTS);
    assert!(ManagementSample::SERIES.len() == MANAGEMENT_SLOTS);
    assert!(ConsoleSample::SERIES.len() == CONSOLE_SLOTS);
    assert!(ConfigSample::SERIES.len() == CONFIG_SLOTS);
    assert!(ClockSample::SERIES.len() == CLOCK_SLOTS);

    // Every table fits the shard it is published into, so `StatsShard::publish`
    // can truncate without any first-party caller ever reaching the truncation.
    assert!(FORWARDER_SLOTS <= crate::STATS_SLOTS);
    assert!(DRIVER_SLOTS <= crate::STATS_SLOTS);
    assert!(MANAGEMENT_SLOTS <= crate::STATS_SLOTS);
    assert!(CONSOLE_SLOTS <= crate::STATS_SLOTS);
    assert!(CONFIG_SLOTS <= crate::STATS_SLOTS);
    assert!(CLOCK_SLOTS <= crate::STATS_SLOTS);
};
