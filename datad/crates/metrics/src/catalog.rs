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
    ClockSample, ConfigSample, ConsoleSample, CryptoSample, DriverSample, ForwarderSample,
    HardwareProbeSample, ManagementSample, RecorderSample, StoreSample,
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
    "Flows that left the table, by what ended them. `expired` reached their state's idle timeout,      `evicted` were taken back under pressure and are never assured ones, `closed` were ended by      their own endpoints, `withdrawn` were opened by a packet the filter then refused, and      `revoked` were admitted by a policy a commit has replaced with one that no longer admits      them. There is no `created`: a flow is created by exactly the packet counted as `new` above.",
);

/// What the pass that re-decides the connection table against a newly committed
/// policy has done.
///
/// The window a commit opens is what an operator watches here: a conversation the
/// new policy forbids goes on forwarding until the pass reaches it, so `completed`
/// rising past the commit is what says every flow has been re-decided. `deferred`
/// is a commit that arrived while a pass was still running: the running pass is not
/// abandoned, and a fresh one over the whole table follows it — so the window such a
/// commit opens closes one `completed` later than the pass it queued behind.
pub const POLICY_SWEEP: Metric = metric(
    "librefirewall_policy_sweep_total",
    Kind::Counter,
    "Passes over the connection table re-deciding it against a newly committed policy. `completed` \
     reached the last bucket, so every flow has been judged against the running policy; \
     `deferred` arrived while a pass was running and queued a fresh pass behind it.",
);

pub const POLICY_SWEEP_RUNNING: Metric = metric(
    "librefirewall_policy_sweep_running",
    Kind::Gauge,
    "1 while a pass over the connection table is still owed, 0 once it has finished. The window a \
     commit opens: while it reads 1, a conversation the new policy forbids may still be \
     forwarding.",
);

pub const POLICY_SWEEP_PROGRESS: Metric = metric(
    "librefirewall_policy_sweep_progress_total",
    Kind::Counter,
    "What the re-deciding passes have walked: `buckets` of the connection index, and `flows` that \
     were live enough to be judged. Read against the table's capacity, they say how far a pass \
     gets per wakeup.",
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

// ── The neighbour cache under the endpoint ───────────────────────────

pub const NEIGHBOUR_REQUESTS: Metric = metric(
    "librefirewall_endpoint_neighbour_requests_total",
    Kind::Counter,
    "Address resolution requests this port composed for a next hop, retries included.",
);

pub const NEIGHBOUR_REPLIES: Metric = metric(
    "librefirewall_endpoint_neighbour_replies_total",
    Kind::Counter,
    "Address resolution replies this port read, by what it did with each. Only `learned` \
     becomes an entry: `unsolicited` answered nothing this end asked, `rebinding_refused` named \
     a next hop already resolved, and `not_unicast` claimed a hardware address no frame may be \
     addressed to.",
);

pub const NEIGHBOUR_ENTRIES_EXPIRED: Metric = metric(
    "librefirewall_endpoint_neighbour_entries_expired_total",
    Kind::Counter,
    "Entries dropped because their lifetime ran out.",
);

pub const NEIGHBOUR_RESOLUTIONS_FAILED: Metric = metric(
    "librefirewall_endpoint_neighbour_resolutions_failed_total",
    Kind::Counter,
    "Next hops this port could not resolve: `abandoned` spent every request unanswered, and \
     `no_room` could not be asked about at all, the table holding only live entries.",
);

// ── The outbound half: this port reaching out rather than answering ────────

pub const OUTBOUND_SESSIONS: Metric = metric(
    "librefirewall_endpoint_outbound_sessions_total",
    Kind::Counter,
    "Connections this appliance originated out of its management port, by what became of each. \
     `opened` counts every one begun and `refused` those declined before a frame was composed, \
     so the two say what this end decided; `answered` and `failed` say how the ones that went \
     out ended.",
);

pub const OUTBOUND_DIALS: Metric = metric(
    "librefirewall_endpoint_outbound_dials_total",
    Kind::Counter,
    "SYNs the transport composed for an originated connection.",
);

pub const OUTBOUND_SEGMENTS_DROPPED: Metric = metric(
    "librefirewall_endpoint_outbound_segments_dropped_total",
    Kind::Counter,
    "Segments composed and then dropped for want of a hardware address for the next hop. Each \
     is re-sent by the transport's own retransmission, so a small number is a resolution that \
     ran while a timer was armed and a large one is a next hop that answers slowly or not at \
     all.",
);

pub const OUTBOUND_BYTES: Metric = metric(
    "librefirewall_endpoint_outbound_bytes_total",
    Kind::Counter,
    "Request bytes handed to the transport, and answer bytes taken from a peer and kept.",
);

pub const OUTBOUND_ANSWER_OVERFLOWED: Metric = metric(
    "librefirewall_endpoint_outbound_answer_overflowed_total",
    Kind::Counter,
    "Answer bytes a peer sent past the room one session keeps, dropped rather than allowed to \
     displace what came before them.",
);

// ── The onboarding port: the second listening port, carrying a byte stream ──

pub const ONBOARD_CONNECTIONS: Metric = metric(
    "librefirewall_endpoint_onboard_connections_total",
    Kind::Counter,
    "Connections the onboarding port accepted, and those the transport stopped holding while a \
     session was running on one. `accepted` counts every connection whatever became of it, so a \
     count larger than the sessions reported is a peer that connected and produced no session; \
     `forgotten` is a reset, an eviction or a reaping, which is a different thing to look at from \
     either end closing.",
);

pub const ONBOARD_BYTES: Metric = metric(
    "librefirewall_endpoint_onboard_bytes_total",
    Kind::Counter,
    "Bytes the onboarding port took off a peer and held for the terminating domain, and bytes \
     that domain answered with and the transport took. Opaque record bytes counted and never \
     read: no byte of a session reaches any surface.",
);

pub const ONBOARD_SESSIONS_CLOSED: Metric = metric(
    "librefirewall_endpoint_onboard_sessions_closed_total",
    Kind::Counter,
    "Sessions on the onboarding port each end finished, by which end said so first.",
);

pub const ONBOARD_OVERFLOWED: Metric = metric(
    "librefirewall_endpoint_onboard_overflowed_total",
    Kind::Counter,
    "Bytes a peer sent past the room the onboarding port had left, refused rather than allowed to \
     displace what came before them. Unreachable while the advertised window is honoured, so a \
     number here is a peer that ignored it.",
);

pub const ONBOARD_ANSWERS_REFUSED: Metric = metric(
    "librefirewall_endpoint_onboard_answers_refused_total",
    Kind::Counter,
    "Bytes the terminating domain answered with that the onboarding port had no room for. Ours \
     rather than a peer's: the answer outgrew the room this end keeps for one.",
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

// ── The hardware probe ──────────────────────────────────────────────────────

pub const HARDWARE_PROBE_PROVEN: Metric = metric(
    "librefirewall_hardware_probe_proven",
    Kind::Gauge,
    "1 once the AES and carry-less-multiply known answers held on every pass and the XMM \
     pattern survived every preemption the probe observed; 0 before, and forever on a node \
     that refused.",
);

pub const HARDWARE_PROBE_ITERATIONS: Metric = metric(
    "librefirewall_hardware_probe_iterations_total",
    Kind::Counter,
    "Probe passes run before the verdict; each re-ran both known answers and re-checked the \
     XMM pattern.",
);

pub const HARDWARE_PROBE_PREEMPTIONS: Metric = metric(
    "librefirewall_hardware_probe_preemptions_total",
    Kind::Counter,
    "Preemptions the probe observed as timestamp-counter gaps while its XMM state was live.",
);

// ── Cryptography ────────────────────────────────────────────────────────────

pub const CRYPTO_PROVEN: Metric = metric(
    "librefirewall_crypto_proven",
    Kind::Gauge,
    "1 once every primitive answered every published vector this image carries for it; 0 before, \
     and forever on a node that refused.",
);

pub const CRYPTO_VECTORS: Metric = metric(
    "librefirewall_crypto_vectors_proven_total",
    Kind::Counter,
    "Published NIST CAVP, RFC and Wycheproof vectors this node re-ran at bring-up and answered \
     correctly, per primitive.",
);

pub const CRYPTO_MILLI_CYCLES_PER_BYTE: Metric = metric(
    "librefirewall_crypto_milli_cycles_per_byte",
    Kind::Gauge,
    "Thousandths of a timestamp-counter cycle per byte this node measured for a primitive at \
     bring-up; 0 for a primitive it does not measure.",
);

pub const CRYPTO_CYCLES_PER_OPERATION: Metric = metric(
    "librefirewall_crypto_cycles_per_operation",
    Kind::Gauge,
    "Timestamp-counter cycles one operation of a primitive cost this node at bring-up, for the \
     primitives whose work has one size rather than a length; 0 for a primitive measured per \
     byte instead.",
);

// ── The appliance's own identity ─────────────────────────────────────────────

pub const STORE_IDENTITY: Metric = metric(
    "librefirewall_store_identity",
    Kind::Gauge,
    "1 once this appliance's identity is established on the store medium — minted on a fresh \
     medium or reloaded and verified from an existing one; 0 before, and forever on a node that \
     refused. No key material is exposed here or anywhere else on this surface.",
);

pub const STORE_MINTED: Metric = metric(
    "librefirewall_store_minted",
    Kind::Gauge,
    "1 where this boot minted a fresh identity because the medium carried none, 0 where it \
     reloaded the one already there. A node whose value flips to 1 after a boot at 0 has lost \
     its identity, which is the fleet's own alert rather than a fault of the boot.",
);

pub const STORE_GENERATION: Metric = metric(
    "librefirewall_store_generation",
    Kind::Gauge,
    "The generation of the state record this node is running on, which advances by one on every \
     durable commit. A gauge rather than a counter: it is a position and not a rate.",
);

pub const STORE_ONBOARDED: Metric = metric(
    "librefirewall_store_onboarded",
    Kind::Gauge,
    "1 once a management plane has adopted this appliance, 0 while it is unowned.",
);

pub const STORE_RESET: Metric = metric(
    "librefirewall_store_reset",
    Kind::Gauge,
    "1 where this boot found a factory-reset request on the store medium and honoured it, 0 \
     otherwise. It is what tells an intentional reset from a lost medium: both mint, and only \
     this says which one was asked for.",
);

pub const STORE_SIGNATURES: Metric = metric(
    "librefirewall_store_signatures_total",
    Kind::Counter,
    "Signatures this domain has produced under the device key on behalf of a domain that holds no \
     key. It is the only operator-visible sign that the delegation is working, and it is a count \
     rather than anything about a signature: no message, no signature and no key is exposed here \
     or anywhere else on this surface.",
);

pub const STORE_SIGN_REFUSALS: Metric = metric(
    "librefirewall_store_sign_refusals_total",
    Kind::Counter,
    "Signing requests this domain answered with a refusal rather than a signature — an appliance \
     with no established identity, an operation it has none of, or a message longer than a \
     request may carry. A non-zero value beside a zero \
     `librefirewall_store_signatures_total` is a peer asking for something this node cannot give.",
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

pub const HTTP_BODIES_TIMED_OUT: Metric = metric(
    "librefirewall_http_bodies_timed_out_total",
    Kind::Counter,
    "Request bodies given up on for not arriving whole in time, answered 408 and reset; each one \
     is a stretch in which the other body-bearing surfaces answered 503.",
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
    &POLICY_SWEEP,
    &POLICY_SWEEP_RUNNING,
    &POLICY_SWEEP_PROGRESS,
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
    &NEIGHBOUR_REQUESTS,
    &NEIGHBOUR_REPLIES,
    &NEIGHBOUR_ENTRIES_EXPIRED,
    &NEIGHBOUR_RESOLUTIONS_FAILED,
    &OUTBOUND_SESSIONS,
    &OUTBOUND_DIALS,
    &OUTBOUND_SEGMENTS_DROPPED,
    &OUTBOUND_BYTES,
    &OUTBOUND_ANSWER_OVERFLOWED,
    &ONBOARD_CONNECTIONS,
    &ONBOARD_BYTES,
    &ONBOARD_SESSIONS_CLOSED,
    &ONBOARD_OVERFLOWED,
    &ONBOARD_ANSWERS_REFUSED,
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
    &HTTP_BODIES_TIMED_OUT,
    &HTTP_BODY_OVERRUNS,
    &HTTP_RETRANSMITS_UNAVAILABLE,
    &HTTP_SLOTS_EXHAUSTED,
    &BLOCK_CAPACITY_SECTORS,
    &BLOCK_REQUESTS,
    &BLOCK_BYTES,
    &BLOCK_STATUS_UNDECODABLE,
    &STORE_IDENTITY,
    &STORE_MINTED,
    &STORE_GENERATION,
    &STORE_ONBOARDED,
    &STORE_RESET,
    &STORE_SIGNATURES,
    &STORE_SIGN_REFUSALS,
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
    &HARDWARE_PROBE_PROVEN,
    &HARDWARE_PROBE_ITERATIONS,
    &HARDWARE_PROBE_PREEMPTIONS,
    &CRYPTO_PROVEN,
    &CRYPTO_VECTORS,
    &CRYPTO_MILLI_CYCLES_PER_BYTE,
    &CRYPTO_CYCLES_PER_OPERATION,
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
/// the configuration publisher, the clock, the recorder and the hardware probe.
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
    ShardSpec {
        domain: "hardware_probe",
        series: HardwareProbeSample::SERIES,
    },
    ShardSpec {
        domain: "crypto",
        series: CryptoSample::SERIES,
    },
    ShardSpec {
        domain: "store",
        series: StoreSample::SERIES,
    },
];

/// How many shards a snapshot carries. A build fact — the system description
/// declares one region per protection domain — and `xtask::sysdesc` holds the
/// description to it from the other side.
pub const SHARD_COUNT: usize = 12;

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
