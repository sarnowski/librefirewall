//! Every metric name, label and vocabulary token this appliance exposes, and
//! the eight shards they are grouped into.
//!
//! # The transliteration rule
//!
//! One naming scheme is fixed across every surface: the Prometheus surface
//! carries the console's own keys and tokens transliterated
//! to each transport's own separator convention. This is that transliteration,
//! and it is one rule with no exceptions:
//!
//! > A metric name, a label name and a label value is the console key or
//! > vocabulary token with every `-` replaced by `_`. A metric name additionally
//! > carries the `librefirewall_` prefix, and a counter the `_total` suffix.
//!
//! So the console's `domain=nic-driver` is this surface's `domain="nic_driver0"`
//! — the same token, the same separator convention throughout, and the instance
//! number the console cannot carry because three driver instances share one
//! binary and therefore one domain name. The `-`→`_` half is not a preference:
//! Prometheus metric and label *names* are `[a-zA-Z_:][a-zA-Z0-9_:]*`, so a
//! hyphen is ungrammatical there, and applying the same rule to label values —
//! where a hyphen would be legal — is what keeps one identifier reading the same
//! everywhere on this surface rather than in two spellings a reader has to know
//! about.
//!
//! # Attribution is structural
//!
//! The binding attribution rule keeps three classes apart, and they
//! are three different metric families here rather than three values of one
//! label: what a **device** got wrong about its own protocol
//! ([`DEVICE_FAULTS`]), what a **device or peer sent** that a layer refused
//! ([`INPUT_DROPS`], [`ROUTE_DROPS`], [`TCP_REFUSED`], …), and what **we** got
//! wrong ([`INVARIANT_FAULTS`], [`TCP_WRITE_REFUSED`],
//! [`HTTP_EXPOSITIONS_REFUSED`], [`CONSOLE_RECORDS`]'s `unrenderable`). An alert
//! can be written against the third class by name, which is the whole point of
//! not merging them.

use crate::sample::{
    ClockSample, ConfigSample, ConsoleSample, DriverSample, ForwarderSample, ManagementSample,
    RecorderSample,
};

/// Whether a series is a monotonic total or a value that may move in either
/// direction. Prometheus needs it on the `# TYPE` line; this crate needs it
/// because a gauge is the one shape the exposed counter semantics — never
/// reset, saturating — deliberately do not apply to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Counter,
    Gauge,
}

impl Kind {
    /// The token Prometheus's `# TYPE` line takes.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
        }
    }
}

/// One metric family: a name, a type and the sentence an operator reads beside
/// it. Several [`Series`] share one, distinguished by their labels.
#[derive(Debug)]
pub struct Metric {
    pub name: &'static str,
    pub kind: Kind,
    /// One line, no newline, no backslash: [`crate::Snapshot::render`] writes it
    /// verbatim and the exposition format escapes neither.
    pub help: &'static str,
}

/// One label pair, already transliterated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label {
    pub name: &'static str,
    pub value: &'static str,
}

impl Label {
    #[must_use]
    pub const fn new(name: &'static str, value: &'static str) -> Self {
        Self { name, value }
    }
}

/// One exposed time series: a family and the labels that pick this instance of
/// it out. Its position in a [`ShardSpec::series`] table **is** its slot in the
/// shard, which is what lets one table serve the writer and the reader.
#[derive(Debug)]
pub struct Series {
    pub metric: &'static Metric,
    /// Everything but the `domain` label, which the shard supplies.
    pub labels: &'static [Label],
}

impl Series {
    const fn new(metric: &'static Metric, labels: &'static [Label]) -> Self {
        Self { metric, labels }
    }
}

/// Shorthand for a table entry, which is otherwise four lines of punctuation per
/// series and the table is two hundred entries long.
pub(crate) const fn s(metric: &'static Metric, labels: &'static [Label]) -> Series {
    Series::new(metric, labels)
}

/// A family with no labels beyond `domain`.
pub(crate) const fn plain(metric: &'static Metric) -> Series {
    Series::new(metric, &[])
}

/// Build a metric family. A function rather than a struct literal so every
/// declaration below reads as one line and a missing field is impossible.
#[must_use]
pub const fn metric(name: &'static str, kind: Kind, help: &'static str) -> Metric {
    Metric { name, kind, help }
}

// ── The dataplane ───────────────────────────────────────────────────────────

pub const FORWARDED_FRAMES: Metric = metric(
    "librefirewall_forwarded_frames_total",
    Kind::Counter,
    "Frames rewritten for their next hop and handed to the transmitting driver.",
);

pub const ROUTE_DROPS: Metric = metric(
    "librefirewall_route_drops_total",
    Kind::Counter,
    "Frames the router refused, by the reason it named.",
);

pub const ROUTE_STAGE_DROPS: Metric = metric(
    "librefirewall_route_stage_drops_total",
    Kind::Counter,
    "Frames the routing stage refused around the router's own decision.",
);

// ── The filter, on the forwarder that decides it ────────────────────────────

/// The filter's own account of what it decided, which is why these two carry no
/// `pipeline` label where every other forwarder family does: one
/// `pipeline::PolicyStage` serves both directions, because a stage of that chain
/// may hold state spanning a whole flow.
pub const POLICY_PACKETS: Metric = metric(
    "librefirewall_policy_packets_total",
    Kind::Counter,
    "Packets the filter decided on, by the verdict it reached; `denied` covers both a rule that \
     said so and the default deny, which the route drop reasons tell apart.",
);

pub const POLICY_BYTES: Metric = metric(
    "librefirewall_policy_bytes_total",
    Kind::Counter,
    "Datagram bytes the filter decided on, by the verdict it reached; the sender's own IPv4 total \
     length, so it is comparable against a link's throughput.",
);

/// The second family whose samples do not come from a shard's table: the numbers
/// are the forwarder's, taken from its shard by position, and the `rule` label is
/// the id the committed document gave the rule at that position. One series per
/// rule the running generation declares and none for a position it does not, so a
/// two-rule policy exposes two series.
pub const RULE_HITS: Metric = metric(
    "librefirewall_rule_hits_total",
    Kind::Counter,
    "Packets matched by each rule of the running policy, under the id the configuration document \
     gave it. First match wins, so a packet is counted against one rule at most.",
);

// ── The connection tracker, on the forwarder that keeps it ──────────────────

/// What the table made of the packets it was offered, which is the family that
/// says whether state is doing anything at all: `established` climbing beside a
/// flat `librefirewall_rule_hits_total` is a reply carried by its flow rather
/// than by a rule, and that is the whole reason the table exists.
pub const FLOW_PACKETS: Metric = metric(
    "librefirewall_flow_packets_total",
    Kind::Counter,
    "Packets the connection tracker classified, by what it made of them. `new` opened a flow,      `established` advanced one the table already held, and `related` is an ICMP error reporting      on one. A packet counted here was not refused; a packet refused is in      `librefirewall_flow_packets_refused_total` and in neither of the two.",
);

pub const FLOW_PACKETS_SEEN: Metric = metric(
    "librefirewall_flow_packets_seen_total",
    Kind::Counter,
    "Packets offered to the connection tracker, whatever became of them. The denominator the      classified and refused families are read against.",
);

pub const FLOW_PACKETS_REFUSED: Metric = metric(
    "librefirewall_flow_packets_refused_total",
    Kind::Counter,
    "Packets the connection tracker turned away, by what refused them. `mid_stream` counts      attempts to walk around default deny by starting inside a conversation this appliance never      saw begin; `table_full` is the fail-closed answer to a connection flood and means legitimate      new connections are being refused.",
);

pub const FLOW_LIFECYCLE: Metric = metric(
    "librefirewall_flow_lifecycle_total",
    Kind::Counter,
    "Flows that left the table, by what ended them. `expired` reached their state's idle timeout,      `evicted` were taken back under pressure and are never assured ones, `closed` were ended by      their own endpoints, and `withdrawn` were opened by a packet the filter then refused. There      is no `created`: a flow is created by exactly the packet counted as `new` above.",
);

pub const FLOW_TABLE_ENTRIES: Metric = metric(
    "librefirewall_flow_table_entries",
    Kind::Gauge,
    "Slots of the connection table, by the state of the flow in each. `vacant` is how much room      is left, so the values sum to the table's capacity and a flood is watched as `vacant`      falling rather than as an occupancy needing a capacity nothing publishes.",
);

pub const FLOW_PROBE_COLLISIONS: Metric = metric(
    "librefirewall_flow_probe_collisions_total",
    Kind::Counter,
    "Chain steps that reached an entry which was not the one looked up. Not a refusal — the walk      simply continued — and exposed because the ratio against      `librefirewall_flow_packets_seen_total` is what says whether the index is doing its job.",
);

// ── The recording tap, on the forwarder that fills it ───────────────────────

pub const TAP_OBSERVATIONS: Metric = metric(
    "librefirewall_tap_observations_total",
    Kind::Counter,
    "Frame observations the forwarder published to the recorder.",
);

pub const TAP_OBSERVATIONS_LOST: Metric = metric(
    "librefirewall_tap_observations_lost_total",
    Kind::Counter,
    "Observations the tap could not publish; `ring_full` is the recorder falling behind, \
     `inconsistent` is ours and expected to stay zero.",
);

// ── Configuration, on both of its readers ───────────────────────────────────

pub const CONFIGURATION_GENERATION: Metric = metric(
    "librefirewall_configuration_generation",
    Kind::Gauge,
    "The configuration generation this domain is running under; 0 is the fail-closed empty table.",
);

/// What the domain that decides on a document has decided.
///
/// The count no other surface carries: a node that refuses every document an
/// operator submits looks, on the generation gauge alone, exactly like a node
/// nobody has submitted one to. Its `outcome` values are the console's own
/// generation vocabulary, so a line an operator reads and a series they graph name
/// the same three things.
pub const CONFIGURATION_SUBMISSIONS: Metric = metric(
    "librefirewall_configuration_submissions_total",
    Kind::Counter,
    "Documents submitted to this node over the management API, by what the \
     configuration domain decided: `applied` moved the generation, `unchanged` was \
     the configuration already running, `refused` broke a rule and changed nothing.",
);

/// Documents the deciding domain was asked for.
pub const CONFIGURATION_READS: Metric = metric(
    "librefirewall_configuration_reads_total",
    Kind::Counter,
    "Times the running configuration document was read out of this node.",
);

pub const CONFIGURATION_IMAGES: Metric = metric(
    "librefirewall_configuration_images_total",
    Kind::Counter,
    "Configuration images this domain applied or refused. Only the forwarder carries `applied`: \
     the management endpoint reads a committed image for its own address and never applies one, \
     so it reports `refused` alone.",
);

/// The one family whose samples come from the committed configuration rather than
/// from a shard. A gauge because no exposed counter semantics applies
/// to a constant: the value is always `1` and a query joins its labels on `domain`.
pub const INTERFACE_INFO: Metric = metric(
    "librefirewall_interface_info",
    Kind::Gauge,
    "The identity of each configured interface; always 1, the labels carrying the whole of it.",
);

// ── The log transport, on every writing domain ──────────────────────────────

pub const LOG_RECORDS_DROPPED: Metric = metric(
    "librefirewall_log_records_dropped_total",
    Kind::Counter,
    "Records this domain could not publish because its ring had no slot.",
);

pub const LOG_RECORDS_REFUSED: Metric = metric(
    "librefirewall_log_records_refused_total",
    Kind::Counter,
    "Records this domain minted and never put in its ring: an event the record ABI cannot carry, \
     or a sink already borrowed further up the same stack. Ours either way, expected to stay zero.",
);

// ── The NIC drivers ─────────────────────────────────────────────────────────

pub const RECEIVE_FRAMES: Metric = metric(
    "librefirewall_receive_frames_total",
    Kind::Counter,
    "Frames this port's device delivered and the driver handed to its peer.",
);

pub const RECEIVE_BYTES: Metric = metric(
    "librefirewall_receive_bytes_total",
    Kind::Counter,
    "Bytes those frames carried, after the device's own header.",
);

pub const TRANSMIT_FRAMES: Metric = metric(
    "librefirewall_transmit_frames_total",
    Kind::Counter,
    "Frames this driver posted to its device for transmission.",
);

pub const TRANSMIT_BYTES: Metric = metric(
    "librefirewall_transmit_bytes_total",
    Kind::Counter,
    "Bytes those frames carried, after the device's own header.",
);

pub const INPUT_DROPS: Metric = metric(
    "librefirewall_input_drops_total",
    Kind::Counter,
    "Frames this driver did not move for a reason outside itself: a peer or the wire.",
);

pub const INVARIANT_FAULTS: Metric = metric(
    "librefirewall_invariant_faults_total",
    Kind::Counter,
    "A domain's own broken bookkeeping; ours, never traffic, expected to stay zero. Each domain \
     raises its own faults and no other's: `rx_completion_unmapped`, `tx_completion_unmapped`, \
     `rx_slot_occupied` and `tx_slot_occupied` are a NIC driver's, `block_completion_unmapped` \
     the recorder's, and `flow_slot_desync` the forwarder's.",
);

pub const DEVICE_FAULTS: Metric = metric(
    "librefirewall_device_faults_total",
    Kind::Counter,
    "Virtqueue completions the device got wrong about its own protocol. Each domain carries only \
     the queues it has: `receive` and `transmit` on a NIC driver, `request` on the recorder's \
     block device.",
);

pub const QUEUE_POSTED: Metric = metric(
    "librefirewall_virtqueue_posted",
    Kind::Gauge,
    "Buffers posted to the device on this virtqueue and not yet completed. A device that accepts \
     buffers and completes none leaves this pinned while every fault counter stays at zero, which \
     is the only reading that tells a stalled port from an idle link.",
);

pub const POOL_RETURNS_REFUSED: Metric = metric(
    "librefirewall_pool_returns_refused_total",
    Kind::Counter,
    "Buffer returns a pool owner refused: forged, out of range, duplicated or never lent. Each \
     domain owns one pool: `receive` on a NIC driver, `transmit` on the management endpoint.",
);

// ── The management endpoint ─────────────────────────────────────────────────

pub const ENDPOINT_FRAMES: Metric = metric(
    "librefirewall_endpoint_frames_total",
    Kind::Counter,
    "Frames the terminal endpoint took off its pipeline.",
);

pub const ENDPOINT_BYTES: Metric = metric(
    "librefirewall_endpoint_bytes_total",
    Kind::Counter,
    "Bytes those frames carried, as the ingress driver measured them.",
);

pub const ENDPOINT_STAGE_DROPS: Metric = metric(
    "librefirewall_endpoint_stage_drops_total",
    Kind::Counter,
    "Descriptors or frames the endpoint stage could not answer, by reason.",
);

pub const ENDPOINT_REPLIES_SENT: Metric = metric(
    "librefirewall_endpoint_replies_sent_total",
    Kind::Counter,
    "Replies the endpoint composed and the stage handed to the driver.",
);

pub const ENDPOINT_REPLIES_LOST: Metric = metric(
    "librefirewall_endpoint_replies_lost_total",
    Kind::Counter,
    "Replies composed and then lost, by where they were lost.",
);

pub const ENDPOINT_REPLIES: Metric = metric(
    "librefirewall_endpoint_replies_total",
    Kind::Counter,
    "Stateless replies the endpoint answered a request with, by protocol.",
);

pub const ENDPOINT_NOT_FOR_US: Metric = metric(
    "librefirewall_endpoint_not_for_us_total",
    Kind::Counter,
    "Frames addressed to somebody else at layer 2 or 3.",
);

pub const ENDPOINT_MALFORMED: Metric = metric(
    "librefirewall_endpoint_malformed_total",
    Kind::Counter,
    "Frames no parser would read.",
);

pub const ENDPOINT_REPLY_REFUSED: Metric = metric(
    "librefirewall_endpoint_reply_refused_total",
    Kind::Counter,
    "Replies decided on and not written, the caller's storage being too small; ours.",
);

pub const ENDPOINT_TCP_SEGMENTS: Metric = metric(
    "librefirewall_endpoint_tcp_segments_total",
    Kind::Counter,
    "Segments the endpoint handed to its transport.",
);

pub const ENDPOINT_UNCLOCKED: Metric = metric(
    "librefirewall_endpoint_unclocked_total",
    Kind::Counter,
    "Segments that arrived before this node had established a time; ours, not the sender's.",
);

pub const ENDPOINT_UNHANDLED: Metric = metric(
    "librefirewall_endpoint_unhandled_total",
    Kind::Counter,
    "Well-formed frames for this endpoint that it deliberately does not answer, by reason.",
);

pub const ENDPOINT_TIMER_SEGMENTS: Metric = metric(
    "librefirewall_endpoint_timer_segments_total",
    Kind::Counter,
    "Segments the transport composed out of its own timers rather than in answer to a frame.",
);

// ── The clock, on the domain that measured it and the one that reads it ─────

pub const CLOCK_GENERATION: Metric = metric(
    "librefirewall_clock_generation",
    Kind::Gauge,
    "The calibration generation this domain converts counter readings with; 0 is none.",
);

pub const CLOCK_CALIBRATIONS_REFUSED: Metric = metric(
    "librefirewall_clock_calibrations_refused_total",
    Kind::Counter,
    "Published calibrations this domain would not use.",
);

pub const CLOCK_FREQUENCY_HERTZ: Metric = metric(
    "librefirewall_clock_frequency_hertz",
    Kind::Gauge,
    "The timestamp counter frequency this node measured at boot; 0 before it did.",
);

// ── The transport ───────────────────────────────────────────────────────────

pub const TCP_SEGMENTS: Metric = metric(
    "librefirewall_tcp_segments_total",
    Kind::Counter,
    "Segments the stack received or composed.",
);

pub const TCP_BYTES: Metric = metric(
    "librefirewall_tcp_bytes_total",
    Kind::Counter,
    "Payload bytes delivered in order, handed to the stack to send, or re-sent.",
);

pub const TCP_RETRANSMITS: Metric = metric(
    "librefirewall_tcp_retransmits_total",
    Kind::Counter,
    "Segments re-sent, data and control alike.",
);

pub const TCP_CONNECTIONS: Metric = metric(
    "librefirewall_tcp_connections_total",
    Kind::Counter,
    "Connections that reached each lifecycle event.",
);

pub const TCP_REFUSED: Metric = metric(
    "librefirewall_tcp_refused_total",
    Kind::Counter,
    "Segments the transport refused, by the cause it named; what a peer sent.",
);

pub const TCP_CHALLENGE_ACKS: Metric = metric(
    "librefirewall_tcp_challenge_acks_total",
    Kind::Counter,
    "Segments challenged rather than acted on under RFC 5961 — a blind in-window RST (§3.2) or a \
     SYN on a synchronized connection (§4). Whether the acknowledgement left is §7's budget's \
     answer.",
);

pub const TCP_CHALLENGES_SUPPRESSED: Metric = metric(
    "librefirewall_tcp_challenges_suppressed_total",
    Kind::Counter,
    "Unsolicited replies withheld by RFC 5961 §7's per-second budget: a challenge \
     acknowledgement, or the reset a segment naming no connection would have drawn.",
);

pub const TCP_RESETS: Metric = metric(
    "librefirewall_tcp_resets_total",
    Kind::Counter,
    "Resets accepted or sent.",
);

pub const TCP_URGENT_IGNORED: Metric = metric(
    "librefirewall_tcp_urgent_ignored_total",
    Kind::Counter,
    "Segments carrying URG, whose urgent pointer is ignored and data delivered in band.",
);

pub const TCP_WRITE_REFUSED: Metric = metric(
    "librefirewall_tcp_write_refused_total",
    Kind::Counter,
    "Segments the stack decided to send that did not fit its caller's storage; ours.",
);

// ── The management HTTP server ──────────────────────────────────────────────

pub const HTTP_REQUESTS: Metric = metric(
    "librefirewall_http_requests_total",
    Kind::Counter,
    "Requests the server read to their end and decided on.",
);

pub const HTTP_RESPONSES: Metric = metric(
    "librefirewall_http_responses_total",
    Kind::Counter,
    "Responses composed, by status code.",
);

pub const HTTP_RESPONSE_BYTES: Metric = metric(
    "librefirewall_http_response_bytes_total",
    Kind::Counter,
    "Response bytes handed to the transport, headers included.",
);

pub const HTTP_REQUESTS_OVERFLOWED: Metric = metric(
    "librefirewall_http_requests_overflowed_total",
    Kind::Counter,
    "Requests that outgrew the bounded request buffer before their head ended.",
);

pub const HTTP_BODIES_REFUSED: Metric = metric(
    "librefirewall_http_bodies_refused_total",
    Kind::Counter,
    "Response bodies a renderer would not fit in the staging buffer, whichever target asked; \
     ours, expected to stay zero.",
);

pub const HTTP_BODIES_TAKEN: Metric = metric(
    "librefirewall_http_bodies_taken_total",
    Kind::Counter,
    "Request bodies accumulated whole and handed to the domain that decides on them.",
);

pub const HTTP_BODY_OVERRUNS: Metric = metric(
    "librefirewall_http_body_overruns_total",
    Kind::Counter,
    "Request-body bytes a client sent past the length it declared, dropped unread.",
);

pub const HTTP_RETRANSMITS_UNAVAILABLE: Metric = metric(
    "librefirewall_http_retransmits_unavailable_total",
    Kind::Counter,
    "Ranges the transport asked for again that no response buffer held; ours, expected to stay zero.",
);

pub const HTTP_SLOTS_EXHAUSTED: Metric = metric(
    "librefirewall_http_slots_exhausted_total",
    Kind::Counter,
    "Connections the server had no slot for; ours, the tables being one size, expected to stay zero.",
);

// ── The recorder and its block device ───────────────────────────────────────

pub const BLOCK_CAPACITY_SECTORS: Metric = metric(
    "librefirewall_block_capacity_sectors",
    Kind::Gauge,
    "Sectors the block device claimed at bring-up; the bound every range is judged against.",
);

pub const BLOCK_REQUESTS: Metric = metric(
    "librefirewall_block_requests_total",
    Kind::Counter,
    "Block requests the device completed successfully, by operation.",
);

pub const BLOCK_BYTES: Metric = metric(
    "librefirewall_block_bytes_total",
    Kind::Counter,
    "Bytes those requests moved, as the driver derived them rather than as the device claimed.",
);

pub const BLOCK_STATUS_UNDECODABLE: Metric = metric(
    "librefirewall_block_status_undecodable_total",
    Kind::Counter,
    "Completions whose status byte was none of the three virtio-blk defines; the device's fault.",
);

// ── The two recordings the recorder writes ──────────────────────────────────

pub const RECORDING_RECORDS: Metric = metric(
    "librefirewall_recording_records_total",
    Kind::Counter,
    "Observations encoded into a recording, by sink.",
);

pub const RECORDING_RECORD_BYTES: Metric = metric(
    "librefirewall_recording_record_bytes_total",
    Kind::Counter,
    "Bytes those records occupy, padding excluded.",
);

pub const RECORDING_RECORDS_DROPPED: Metric = metric(
    "librefirewall_recording_records_dropped_total",
    Kind::Counter,
    "Observations a sink could not encode, by why; every one is a gap the recording states.",
);

pub const RECORDING_STAGING_DEFERRALS: Metric = metric(
    "librefirewall_recording_staging_deferrals_total",
    Kind::Counter,
    "Records a recording could not stage yet and re-offered. Not a loss: a deferred record is \
     held and placed on a later pass.",
);

pub const RECORDING_SEGMENTS_CLOSED: Metric = metric(
    "librefirewall_recording_segments_closed_total",
    Kind::Counter,
    "Segments sealed and rolled past, by sink.",
);

pub const RECORDING_WRAPS: Metric = metric(
    "librefirewall_recording_wraps_total",
    Kind::Counter,
    "Times a ring returned to its first segment, evicting the oldest history it held.",
);

pub const RECORDING_SECTORS_WRITTEN: Metric = metric(
    "librefirewall_recording_sectors_written_total",
    Kind::Counter,
    "Sectors of a recording the device acknowledged.",
);

pub const RECORDING_PADDING_BYTES: Metric = metric(
    "librefirewall_recording_padding_bytes_total",
    Kind::Counter,
    "Bytes of pcapng padding written to keep every device write a whole sector.",
);

pub const RECORDING_TAP_RECORDS: Metric = metric(
    "librefirewall_recording_tap_records_total",
    Kind::Counter,
    "Observations the recorder drained from the tap ring.",
);

pub const RECORDING_TAP_REFUSED: Metric = metric(
    "librefirewall_recording_tap_refused_total",
    Kind::Counter,
    "Tap annotations the recorder would not decode; the forwarder's fault, expected to stay zero.",
);

pub const RECORDING_TAP_DROPPED_BY_WRITER: Metric = metric(
    "librefirewall_recording_tap_dropped_by_writer_total",
    Kind::Counter,
    "Observations the forwarder says the ring had no slot for; its claim about itself.",
);

pub const RECORDING_DOWNLOADS: Metric = metric(
    "librefirewall_recording_downloads_total",
    Kind::Counter,
    "Download windows the recorder answered, by whether it served bytes or refused.",
);

pub const RECORDING_RECORDS_UNCLOCKED: Metric = metric(
    "librefirewall_recording_records_unclocked_total",
    Kind::Counter,
    "Records placed before any calibration was published, so the recording states no instant \
     for them rather than a counter reading.",
);

pub const RECORDING_DOWNLOAD_OVERRUNS: Metric = metric(
    "librefirewall_recording_download_overruns_total",
    Kind::Counter,
    "Downloads the ring wrapped past mid-read, by sink; a reader the traffic outran.",
);

pub const RECORDING_STREAMS: Metric = metric(
    "librefirewall_recording_streams_total",
    Kind::Counter,
    "Recording downloads the management endpoint began, and those it gave up on part-sent.",
);

pub const RECORDING_STREAM_WINDOWS: Metric = metric(
    "librefirewall_recording_stream_windows_total",
    Kind::Counter,
    "Windows of a recording handed to the transport.",
);

pub const RECORDING_STREAM_BYTES: Metric = metric(
    "librefirewall_recording_stream_bytes_total",
    Kind::Counter,
    "Body bytes those windows carried.",
);

// ── The console and its device ──────────────────────────────────────────────

pub const CONSOLE_RECORDS: Metric = metric(
    "librefirewall_console_records_total",
    Kind::Counter,
    "Records the console path resolved, by outcome; each outcome accuses a different party.",
);

pub const UART_BYTES_WRITTEN: Metric = metric(
    "librefirewall_uart_bytes_written_total",
    Kind::Counter,
    "Bytes handed to the transmitter-holding register.",
);

pub const UART_TRANSMITTER_TIMEOUTS: Metric = metric(
    "librefirewall_uart_transmitter_timeouts_total",
    Kind::Counter,
    "Bytes dropped because the transmitter never reported itself empty; the device's fault.",
);

pub const UART_INIT_FAILURES: Metric = metric(
    "librefirewall_uart_init_failures_total",
    Kind::Counter,
    "Refused initialisations of the serial controller. Non-zero means this node has no console: \
     the domain publishes its shard from the refusal path so that a scrape can say so.",
);

/// Every family, in the order the exposition emits them.
///
/// The renderer walks this rather than the shard tables, because the exposition
/// format asks for every sample of a family to arrive as one group under one
/// `# HELP`/`# TYPE` pair — and a family's samples are spread across up to eight
/// shards. It is exhaustive by test: a series naming a family absent from here
/// would render with no type line at all.
pub const ALL_METRICS: &[&Metric] = &[
    &FORWARDED_FRAMES,
    &ROUTE_DROPS,
    &ROUTE_STAGE_DROPS,
    &POLICY_PACKETS,
    &POLICY_BYTES,
    &RULE_HITS,
    &FLOW_PACKETS,
    &FLOW_PACKETS_SEEN,
    &FLOW_PACKETS_REFUSED,
    &FLOW_LIFECYCLE,
    &FLOW_TABLE_ENTRIES,
    &FLOW_PROBE_COLLISIONS,
    &TAP_OBSERVATIONS,
    &TAP_OBSERVATIONS_LOST,
    &RECEIVE_FRAMES,
    &RECEIVE_BYTES,
    &TRANSMIT_FRAMES,
    &TRANSMIT_BYTES,
    &INPUT_DROPS,
    &INVARIANT_FAULTS,
    &DEVICE_FAULTS,
    &QUEUE_POSTED,
    &POOL_RETURNS_REFUSED,
    &ENDPOINT_FRAMES,
    &ENDPOINT_BYTES,
    &ENDPOINT_STAGE_DROPS,
    &ENDPOINT_REPLIES_SENT,
    &ENDPOINT_REPLIES_LOST,
    &ENDPOINT_REPLIES,
    &ENDPOINT_NOT_FOR_US,
    &ENDPOINT_MALFORMED,
    &ENDPOINT_REPLY_REFUSED,
    &ENDPOINT_TCP_SEGMENTS,
    &ENDPOINT_UNCLOCKED,
    &ENDPOINT_UNHANDLED,
    &ENDPOINT_TIMER_SEGMENTS,
    &TCP_SEGMENTS,
    &TCP_BYTES,
    &TCP_RETRANSMITS,
    &TCP_CONNECTIONS,
    &TCP_REFUSED,
    &TCP_CHALLENGE_ACKS,
    &TCP_CHALLENGES_SUPPRESSED,
    &TCP_RESETS,
    &TCP_URGENT_IGNORED,
    &TCP_WRITE_REFUSED,
    &HTTP_REQUESTS,
    &HTTP_RESPONSES,
    &HTTP_RESPONSE_BYTES,
    &HTTP_REQUESTS_OVERFLOWED,
    &HTTP_BODIES_REFUSED,
    &HTTP_BODIES_TAKEN,
    &HTTP_BODY_OVERRUNS,
    &HTTP_RETRANSMITS_UNAVAILABLE,
    &HTTP_SLOTS_EXHAUSTED,
    &BLOCK_CAPACITY_SECTORS,
    &BLOCK_REQUESTS,
    &BLOCK_BYTES,
    &BLOCK_STATUS_UNDECODABLE,
    &RECORDING_RECORDS,
    &RECORDING_RECORD_BYTES,
    &RECORDING_RECORDS_DROPPED,
    &RECORDING_STAGING_DEFERRALS,
    &RECORDING_SEGMENTS_CLOSED,
    &RECORDING_WRAPS,
    &RECORDING_SECTORS_WRITTEN,
    &RECORDING_PADDING_BYTES,
    &RECORDING_TAP_RECORDS,
    &RECORDING_TAP_REFUSED,
    &RECORDING_TAP_DROPPED_BY_WRITER,
    &RECORDING_DOWNLOADS,
    &RECORDING_DOWNLOAD_OVERRUNS,
    &RECORDING_RECORDS_UNCLOCKED,
    &RECORDING_STREAMS,
    &RECORDING_STREAM_WINDOWS,
    &RECORDING_STREAM_BYTES,
    &CONSOLE_RECORDS,
    &UART_BYTES_WRITTEN,
    &UART_TRANSMITTER_TIMEOUTS,
    &UART_INIT_FAILURES,
    &CONFIGURATION_GENERATION,
    &CONFIGURATION_SUBMISSIONS,
    &CONFIGURATION_READS,
    &CONFIGURATION_IMAGES,
    &INTERFACE_INFO,
    &CLOCK_GENERATION,
    &CLOCK_CALIBRATIONS_REFUSED,
    &CLOCK_FREQUENCY_HERTZ,
    &LOG_RECORDS_DROPPED,
    &LOG_RECORDS_REFUSED,
];

/// One shard: the protection domain that owns it and the table that says what
/// each of its slots is.
#[derive(Debug)]
pub struct ShardSpec {
    /// The `domain` label every series in this shard carries — the domain's name
    /// in the Microkit system description, transliterated, so a metric and the
    /// capability topology use one identity. The three driver instances share
    /// one binary and one console `domain=` token, so the instance number is the
    /// part this surface adds.
    pub domain: &'static str,
    pub series: &'static [Series],
}

/// Shards this system has, in the fixed order a snapshot holds them: the
/// forwarder, the three driver instances, the management endpoint, the console,
/// the configuration publisher, the clock and the recorder.
///
/// One per protection domain and no exceptions, which is what makes "every
/// writing domain's own drop counters are exposed" true rather than nearly true.
///
/// A new shard is APPENDED. The order **is** the ABI a snapshot is read through
/// (`pd_runtime::StatsRegions`), so one inserted in the middle re-numbers every
/// shard after it and attributes one domain's numbers to another.
pub const SHARDS: [ShardSpec; SHARD_COUNT] = [
    ShardSpec {
        domain: "forwarder",
        series: ForwarderSample::SERIES,
    },
    ShardSpec {
        domain: "nic_driver0",
        series: DriverSample::SERIES,
    },
    ShardSpec {
        domain: "nic_driver1",
        series: DriverSample::SERIES,
    },
    ShardSpec {
        domain: "nic_driver2",
        series: DriverSample::SERIES,
    },
    ShardSpec {
        domain: "management",
        series: ManagementSample::SERIES,
    },
    ShardSpec {
        domain: "console",
        series: ConsoleSample::SERIES,
    },
    ShardSpec {
        domain: "config",
        series: ConfigSample::SERIES,
    },
    ShardSpec {
        domain: "clock",
        series: ClockSample::SERIES,
    },
    ShardSpec {
        domain: "recorder",
        series: RecorderSample::SERIES,
    },
];

/// How many shards a snapshot carries. A build fact — the system description
/// declares one region per protection domain — and `xtask::sysdesc` holds the
/// description to it from the other side.
pub const SHARD_COUNT: usize = 9;

/// Where the forwarder's shard sits in [`SHARDS`], for the cross-check the QEMU
/// gate makes against traffic it observed itself.
pub const FORWARDER_SHARD: usize = 0;

/// Where the management endpoint's own shard sits, which is the one the domain
/// that renders the exposition also writes.
pub const MANAGEMENT_SHARD: usize = 4;

/// Whether two strings are the same text in a `const` context, which `==` is not.
pub(crate) const fn same(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut at = 0;
    while at < left.len() {
        if left[at] != right[at] {
            return false;
        }
        at += 1;
    }
    true
}
