# Prometheus metrics

**Purpose:** expose every moving part of the firewall for monitoring and for the state half of the
debug dump, scrapably and without degrading the dataplane.

**Endpoint:** `GET /metrics`, Prometheus exposition format, on the management interface.

**Coverage intent:** every internal queue, buffer pool, and ring; per-NIC and per-core counters;
dataplane verdict and throughput counters; connection/flow-table occupancy and limits; the local log
buffer's occupancy and drop count; and the applied-configuration state reflected as metrics.

Of that intent the per-NIC and dataplane verdict and throughput counters, the pool ownership
faults, the transport's connection accounting, the applied-configuration state and the identity of
each configured interface are published today; the inventory below is the whole of what a scrape returns. Per-*core* counters await the
multicore dataplane, queue and ring occupancy and the flow table await the stateful dataplane, and
the local log buffer awaits the buffer itself — none of those exist to be counted yet.

**Counter semantics (binding).** Every counter is **monotonic for the protection domain's life** and
**saturates** rather than wrapping. There is no reset: a scraper derives a rate by differencing
successive scrapes, so a reset would forge a negative rate, and a wrap would turn a sustained flood
back into a small number — which is exactly the signal a counter of attacker-driven events exists to
carry. A domain restart is therefore the only discontinuity, and it is one a scraper can see.

**Attribution (binding).** A drop counter names *who* misbehaved, because a number that does not is
not actionable. Three classes stay separate and never merge: what a **device** got wrong about its
own protocol, what a **device or peer sent** that a layer refused, and what **we** got wrong —
a violation of a domain's own invariant, which is expected to read zero forever and is an alert, not
a traffic statistic.

**Transliteration (binding).** A metric name, a label name and a label value are the console's own
key or token with `-` replaced by `_`, under the `librefirewall_` prefix, with `_total` on a counter.
`no-route` on the console is `reason="no_route"` here; `nic-driver0` is `domain="nic_driver0"`. The
rule exists so an operator reading a console line and an operator reading a dashboard are looking at
the same word, and so neither has to keep a mapping table. A label value may begin with a digit
(`pipeline="0"`), which the exposition format permits and a metric *name* does not.

**No node-side pre-summing (binding).** Every series carries `domain`, and the node publishes no
total across domains. Two pipelines forwarding four frames each are two series of `4`, never one of
`8`. Summing is the scraper's job and it is lossless there; summing here would destroy the
attribution the section above requires, and a node that published both would be asserting an
equality it cannot keep across a domain restart.

**Freshness (binding).** A counter is published by the domain that owns it, into that domain's own
shared region, and a scrape reads whatever was last written. There is no barrier and no seqlock: the
values are individually meaningful, so a scrape may straddle two publications of *different* domains
and each number is still exactly what its owner last wrote. What a scrape is therefore *not* is an
instantaneous snapshot of the whole node, and no cross-domain equality should be alerted on at
single-scrape resolution. The management domain publishes its own shard before rendering, so a
scrape always reports the request that asked for it — its own response, composed afterwards, appears
in the *next* one.

## Metric inventory

74 families; the `domain` column lists every value that appears, which is the set of protection
domains publishing that family. The whole document is about 32 KiB on the shipped configuration —
250 counter and gauge series from the nine shards, plus one info series per configured interface.

### Dataplane: what the forwarder decided

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_forwarded_frames_total` | counter | `forwarder` | `pipeline`&nbsp;(`0`, `1`) | Frames rewritten for their next hop and handed to the transmitting driver. |
| `librefirewall_route_drops_total` | counter | `forwarder` | `pipeline`&nbsp;(`0`, `1`), `reason`&nbsp;(`addressed_to_this_router`, `egress_is_ingress`, `interface_disabled`, `martian_source`, `no_neighbour`, `no_route`, `not_addressed_to_us`, `ttl_expired`, `unconfigured_ingress_port`, `unroutable_destination`, `vlan_tagged`) | Frames the router refused, by the reason it named. |
| `librefirewall_route_stage_drops_total` | counter | `forwarder` | `pipeline`&nbsp;(`0`, `1`), `reason`&nbsp;(`egress_full`, `malformed_descriptor`, `misrouted`, `snapshot_failed`, `unparsable`, `writeback_failed`) | Frames the routing stage refused around the router's own decision. |
| `librefirewall_tap_observations_total` | counter | `forwarder` | — | Frame observations the forwarder published to the recorder. |
| `librefirewall_tap_observations_lost_total` | counter | `forwarder` | `reason`&nbsp;(`inconsistent`, `ring_full`) | Observations the tap could not publish; `ring_full` is the recorder falling behind, `inconsistent` is ours and expected to stay zero. |

The tap is one ring for the domain, not one per pipeline, so neither family carries `pipeline`: the
packet identity a recording relates two observations by is per appliance, and a per-pipeline split
would be two halves of a number nothing produces.

**`observations + observations_lost` is below `forwarded + route_drops`, and the gap is not loss.**
Three classes of frame are counted on the tables above and deliberately recorded nowhere, because
the tap ABI mirrors the router's own drop reasons exactly and has no honest encoding for them: a
frame no routing decision was reached about (`malformed_descriptor`, `snapshot_failed`,
`unparsable`), one routed out of a port the stage is not wired to (`misrouted`), and one recorded as
forwarded that a later refusal still lost (`egress_full`, `writeback_failed`, and the second
`ttl_expired` enforcer). An operator reconciling a recording against the counters subtracts those.

### Dataplane: what each NIC moved, and what it got wrong

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_device_faults_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2`, `recorder` | `fault`&nbsp;(`completion_length_over_reported`, `completion_not_posted`, `completion_out_of_range`), `queue`&nbsp;(`receive`, `request`, `transmit`) | Virtqueue completions the device got wrong about its own protocol. `queue="request"` is the block device's single queue; the other two are a NIC's. |
| `librefirewall_input_drops_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | `reason`&nbsp;(`rx_peer_ring_full`, `rx_runt`, `tx_discarded`, `tx_duplicate`, `tx_free_ring_full`, `tx_malformed`, `tx_verdict_undecodable`) | Frames this driver did not move for a reason outside itself: a peer or the wire. |
| `librefirewall_invariant_faults_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2`, `recorder` | `fault`&nbsp;(`block_completion_unmapped`, `rx_completion_unmapped`, `rx_slot_occupied`, `tx_completion_unmapped`, `tx_slot_occupied`) | This driver's own broken bookkeeping; ours, never traffic, expected to stay zero. |
| `librefirewall_pool_returns_refused_total` | counter | `management`, `nic_driver0`, `nic_driver1`, `nic_driver2` | `pool`&nbsp;(`receive`, `transmit`), `reason`&nbsp;(`ledger_refused`, `not_lent`) | Buffer returns a pool owner refused: forged, out of range, duplicated or never lent. |
| `librefirewall_receive_bytes_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Bytes those frames carried, after the device's own header. |
| `librefirewall_receive_frames_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Frames this port's device delivered and the driver handed to its peer. |
| `librefirewall_transmit_bytes_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Bytes those frames carried, after the device's own header. |
| `librefirewall_transmit_frames_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Frames this driver posted to its device for transmission. |

### The management port: frames, and what the endpoint made of them

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_endpoint_bytes_total` | counter | `management` | — | Bytes those frames carried, as the ingress driver measured them. |
| `librefirewall_endpoint_frames_total` | counter | `management` | — | Frames the terminal endpoint took off its pipeline. |
| `librefirewall_endpoint_malformed_total` | counter | `management` | — | Frames no parser would read. |
| `librefirewall_endpoint_not_for_us_total` | counter | `management` | — | Frames addressed to somebody else at layer 2 or 3. |
| `librefirewall_endpoint_replies_lost_total` | counter | `management` | `reason`&nbsp;(`pool_exhausted`, `ring_full`, `write_failed`) | Replies composed and then lost, by where they were lost. |
| `librefirewall_endpoint_replies_sent_total` | counter | `management` | — | Replies the endpoint composed and the stage handed to the driver. |
| `librefirewall_endpoint_replies_total` | counter | `management` | `protocol`&nbsp;(`arp`, `icmp_echo`) | Stateless replies the endpoint answered a request with, by protocol. |
| `librefirewall_endpoint_reply_refused_total` | counter | `management` | — | Replies decided on and not written, the caller's storage being too small; ours. |
| `librefirewall_endpoint_stage_drops_total` | counter | `management` | `reason`&nbsp;(`malformed_descriptor`, `return_ring_full`, `snapshot_failed`, `unaddressed`) | Descriptors or frames the endpoint stage could not answer, by reason. |
| `librefirewall_endpoint_tcp_segments_total` | counter | `management` | — | Segments the endpoint handed to its transport. |
| `librefirewall_endpoint_timer_segments_total` | counter | `management` | — | Segments the transport composed out of its own timers rather than in answer to a frame. |
| `librefirewall_endpoint_unclocked_total` | counter | `management` | — | Segments that arrived before this node had established a time; ours, not the sender's. |
| `librefirewall_endpoint_unhandled_total` | counter | `management` | `reason`&nbsp;(`arp_not_a_request`, `arp_sender_mac_mismatch`, `ethertype_not_handled`, `fragmented`, `not_an_echo_request`, `protocol_not_handled`, `source_not_unicast`, `source_off_link`, `vlan_tagged`) | Well-formed frames for this endpoint that it deliberately does not answer, by reason. |

### The management port: the TCP transport

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_tcp_bytes_total` | counter | `management` | `direction`&nbsp;(`received`, `retransmitted`, `sent`) | Payload bytes delivered in order, handed to the stack to send, or re-sent. |
| `librefirewall_tcp_challenge_acks_total` | counter | `management` | — | RFC 5961 challenge acknowledgements sent. |
| `librefirewall_tcp_connections_total` | counter | `management` | `event`&nbsp;(`abandoned`, `accepted`, `closed`, `established`, `evicted`, `reaped`) | Connections that reached each lifecycle event. |
| `librefirewall_tcp_refused_total` | counter | `management` | `reason`&nbsp;(`bad_checksum`, `malformed`, `no_acknowledgement`, `no_connection`, `not_listening`, `out_of_order`, `out_of_window`, `table_full`, `unacceptable_ack`) | Segments the transport refused, by the cause it named; what a peer sent. |
| `librefirewall_tcp_resets_total` | counter | `management` | `direction`&nbsp;(`received`, `sent`) | Resets accepted or sent. |
| `librefirewall_tcp_retransmits_total` | counter | `management` | — | Segments re-sent, data and control alike. |
| `librefirewall_tcp_segments_total` | counter | `management` | `direction`&nbsp;(`received`, `sent`) | Segments the stack received or composed. |
| `librefirewall_tcp_urgent_ignored_total` | counter | `management` | — | Segments carrying URG, whose urgent pointer is ignored and data delivered in band. |
| `librefirewall_tcp_write_refused_total` | counter | `management` | — | Segments the stack decided to send that did not fit its caller's storage; ours. |

### The management port: the HTTP server

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_http_expositions_refused_total` | counter | `management` | — | Expositions the renderer would not fit in the staging buffer; ours, expected to stay zero. |
| `librefirewall_http_requests_overflowed_total` | counter | `management` | — | Requests that outgrew the bounded request buffer before their head ended. |
| `librefirewall_http_requests_total` | counter | `management` | — | Requests the server read to their end and decided on. |
| `librefirewall_http_response_bytes_total` | counter | `management` | — | Response bytes handed to the transport, headers included. |
| `librefirewall_http_responses_total` | counter | `management` | `status`&nbsp;(`200`, `400`, `404`, `405`, `414`, `431`, `503`, `505`) | Responses composed, by status code. |
| `librefirewall_http_retransmits_unavailable_total` | counter | `management` | — | Ranges the transport asked for again that no response buffer held; ours, expected to stay zero. |
| `librefirewall_http_slots_exhausted_total` | counter | `management` | — | Connections the server had no slot for; ours, the tables being one size, expected to stay zero. |

### The console path, and what it loses

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_console_records_total` | counter | `console` | `outcome`&nbsp;(`malformed`, `printed`, `unknown`, `unrenderable`, `write_failed`) | Records the console path resolved, by outcome; each outcome accuses a different party. |
| `librefirewall_log_records_dropped_total` | counter | `clock`, `config`, `forwarder`, `management`, `nic_driver0`, `nic_driver1`, `nic_driver2`, `recorder` | — | Records this domain could not publish because its ring had no slot. |
| `librefirewall_log_records_refused_total` | counter | `clock`, `config`, `forwarder`, `management`, `nic_driver0`, `nic_driver1`, `nic_driver2`, `recorder` | — | Events this domain minted that the record ABI cannot carry; ours, expected to stay zero. |
| `librefirewall_uart_bytes_written_total` | counter | `console` | — | Bytes handed to the transmitter-holding register. |
| `librefirewall_uart_init_failures_total` | counter | `console` | — | Refused initialisations of the serial controller. |
| `librefirewall_uart_transmitter_timeouts_total` | counter | `console` | — | Bytes dropped because the transmitter never reported itself empty; the device's fault. |

### The block device the recorder owns

`librefirewall_block_capacity_sectors` is the device's own claim, taken once at bring-up and
republished unchanged: it bounds every sector range the domain will name, so a device that came up
smaller than the recording configured for it is visible in a scrape rather than only in a refusal.
A sector is 512 bytes, fixed by the virtio 1.0 specification (its block-device section) regardless
of the `blk_size` a device reports.

The two `_total` families count only **successful** completions and the bytes those moved, derived
by the driver from what it submitted rather than taken from the device's own byte count — which
answers a different question per operation and is only informative on a short read. Nothing here
counts a refused submit: a request the driver would not publish is a defect in this appliance, and
it reaches an operator as a console refusal rather than as a series.

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_block_bytes_total` | counter | `recorder` | `operation`&nbsp;(`read`, `write`) | Bytes those requests moved, as the driver derived them rather than as the device claimed. |
| `librefirewall_block_capacity_sectors` | gauge | `recorder` | — | Sectors the block device claimed at bring-up; the bound every range is judged against. |
| `librefirewall_block_requests_total` | counter | `recorder` | `operation`&nbsp;(`read`, `write`) | Block requests the device completed successfully, by operation. |
| `librefirewall_block_status_undecodable_total` | counter | `recorder` | — | Completions whose status byte was none of the three virtio-blk defines; the device's fault. |

The recorder's virtqueue faults are **not** a family of their own: they are
`librefirewall_device_faults_total{queue="request"}` and
`librefirewall_invariant_faults_total{fault="block_completion_unmapped"}`, on the tables above. A
virtqueue that lied about its own protocol is one kind of event whatever the queue carries, and an
operator alerting on it should not have to know which domain owns which device.

### The two recordings, and the downloads served out of them

Every family here carries `sink` where it describes one recording and omits it where it describes
the tap between the forwarder and this domain, which is one ring feeding both.

`librefirewall_recording_records_total` is what a recording **encoded**, not what reached the
medium: bytes become durable one whole sector at a time, so the tail of a recording sits in staging
until a seal — which a download performs — pushes it out. Compare it against
`librefirewall_recording_sectors_written_total` for what the device has acknowledged.

`librefirewall_recording_tap_dropped_by_writer_total` is the **forwarder's** claim about itself,
read out of the shared ring and republished here beside this domain's own counts rather than
instead of them. It is the same number as
`librefirewall_tap_observations_lost_total{reason="ring_full"}`, and the two disagreeing is a peer
misreporting rather than a lost record.

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_recording_download_overruns_total` | counter | `recorder` | `sink`&nbsp;(`capture`, `log`) | Downloads the ring wrapped past mid-read, by sink; a reader the traffic outran. |
| `librefirewall_recording_downloads_total` | counter | `recorder` | `outcome`&nbsp;(`refused`, `served`) | Download windows the recorder answered, by whether it served bytes or refused. |
| `librefirewall_recording_padding_bytes_total` | counter | `recorder` | `sink`&nbsp;(`capture`, `log`) | Bytes of pcapng padding written to keep every device write a whole sector. |
| `librefirewall_recording_record_bytes_total` | counter | `recorder` | `sink`&nbsp;(`capture`, `log`) | Bytes those records occupy, padding excluded. |
| `librefirewall_recording_records_dropped_total` | counter | `recorder` | `sink`&nbsp;(`capture`, `log`), `reason`&nbsp;(`oversized`, `refused`, `staging_full`) | Observations a sink could not encode, by why; every one is a gap the recording states. |
| `librefirewall_recording_records_total` | counter | `recorder` | `sink`&nbsp;(`capture`, `log`) | Observations encoded into a recording, by sink. |
| `librefirewall_recording_records_unclocked_total` | counter | `recorder` | — | Records placed before any calibration was published, so the recording states no instant for them rather than a counter reading. |
| `librefirewall_recording_sectors_written_total` | counter | `recorder` | `sink`&nbsp;(`capture`, `log`) | Sectors of a recording the device acknowledged. |
| `librefirewall_recording_segments_closed_total` | counter | `recorder` | `sink`&nbsp;(`capture`, `log`) | Segments sealed and rolled past, by sink. |
| `librefirewall_recording_tap_dropped_by_writer_total` | counter | `recorder` | — | Observations the forwarder says the ring had no slot for; its claim about itself. |
| `librefirewall_recording_tap_records_total` | counter | `recorder` | — | Observations the recorder drained from the tap ring. |
| `librefirewall_recording_tap_refused_total` | counter | `recorder` | — | Tap annotations the recorder would not decode; the forwarder's fault, expected to stay zero. |
| `librefirewall_recording_wraps_total` | counter | `recorder` | `sink`&nbsp;(`capture`, `log`) | Times a ring returned to its first segment, evicting the oldest history it held. |

The download's other half is on the management domain, because that is the domain that serves it:

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_recording_stream_bytes_total` | counter | `management` | — | Body bytes those windows carried. |
| `librefirewall_recording_stream_windows_total` | counter | `management` | — | Windows of a recording handed to the transport. |
| `librefirewall_recording_streams_total` | counter | `management` | `outcome`&nbsp;(`abandoned`, `started`) | Recording downloads the management endpoint began, and those it gave up on part-sent. |

**No series describes ring occupancy**, and none describes how much history a recording holds: a
wrap count says a segment was evicted and not how far behind a reader is, because no reader
registers a cursor yet (a mechanism the [recording design](../design/recording.md) calls for).

### What each configured interface is

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_interface_info` | gauge | `nic_driver0`, `nic_driver1`, `nic_driver2` | `interface`, `role`&nbsp;(`dataplane`, `management`), `address`, `prefix_length`, `mac` | The identity of one configured interface. **An info gauge: its value is always `1` and carries nothing at all** — everything it says is in its labels. |

**This is the one family that is not a measurement, and the counter rules above do not apply to it.**
Monotonicity, saturation and "no reset" are statements about counters; a constant is none of them.
It is a gauge, it therefore carries no `_total` suffix, and a reader that differenced two scrapes of
it would be differencing `1` from `1`. What *does* change between two scrapes is which series exist
and what their labels say — a re-addressed interface is a series that disappears and one that
appears, which is exactly how Prometheus's own `*_info` families behave.

The labels, one by one:

| Label | What it is |
|---|---|
| `domain` | The protection domain driving that port, spelled exactly as every counter family spells it. **This is the join key** and it is the only label here whose value comes from the build rather than from the configuration: which domain drives which port is fixed in the Microkit system description (see the [architecture design](../design/architecture.md)), recorded once in `lfw_metrics::PORT_DOMAINS`, and checked against that description at build time by `xtask::sysdesc`. |
| `interface` | The `id` attribute of the document's `<interface>` — `dataplane-0` on the shipped configuration. The `<management>` element has no `id`, a document holding exactly one, so its series reads `interface="management"`: the same identity a `LFW-CFG` change record about it carries as `key=management`. |
| `role` | `dataplane` or `management`. The design makes the role the architectural unit rather than the port number (see the [architecture design](../design/architecture.md)), so it is what a query groups by. **The vocabulary is these two today and grows with the design's other roles — session replication, mirror — when ports in them exist.** A third token appearing before then is a defect. |
| `address` | The configured IPv4 address, dotted quad. |
| `prefix_length` | The prefix length, decimal, as a string — every Prometheus label value is one. |
| `mac` | The configured MAC, lower case and colon-separated, the same form a console record writes it in. |

**Cardinality: one series per configured interface, and no more.** At most `wire::MAX_INTERFACES` + 1
= 9 today, which is what the exposition's worst-case bound reserves, and at most 7 under the
design's target port model — six dataplane ports and the management one. It does not grow with
traffic, with connections, or with anything an adversary controls.

**A node that has committed no configuration carries no series of this family**, and the two comment
lines still appear. That is the truth rather than a gap: generation 0 is the fail-closed empty
configuration and configures no interface, so a series for one would name an interface the node does
not have.

**There is no `enabled` label, and the two roles differ in what a disabled interface looks like.**
This is the one thing about the family an operator will otherwise read wrong:

- A **dataplane** interface has a series whether or not it is enabled. Its addressing is in the
  configuration image either way, because the router needs the row in order to *refuse* traffic on
  it — which is visible as `librefirewall_route_drops_total{reason="interface_disabled"}` on the
  forwarder. So a series here says "the document configures this port", not "this port carries
  traffic".
- The **management** interface has a series only when it is addressed. A disabled `<management>`
  element is indistinguishable from an absent one by the image's own design — its fields are not
  interpreted at all — so the port is unaddressed and there is nothing to report an identity for.

An `enabled` label is deliberately absent rather than pending. It would have to be ragged across the
two roles to be truthful, nothing consumes it, and the exact running configuration — enable flags
included — is what `GET /config` returns. The state that *matters* for reading a counter is already
observable: an interface configured and refusing traffic shows as an `interface_disabled` drop count
beside an info series.

### The join idiom

Counter series carry `domain` and nothing else that identifies a port, deliberately. Putting the
addressing on every counter instead would multiply five labels across every NIC and endpoint family,
and — worse — a re-addressed interface would **fork every one of its counter series**, so a `rate()`
across the change would read as a series ending and a new one starting from zero. The identity lives
in one place and the join happens in the query:

```promql
# Received frames per second, by the interface the configuration names.
rate(librefirewall_receive_frames_total[5m])
  * on(domain) group_left(interface, role, address, prefix_length)
    librefirewall_interface_info
```

`* on(domain) group_left(…)` is the conventional info-metric join: multiplying by a series whose
value is always `1` leaves the left-hand value untouched and copies the named labels onto it. The
result is one series per interface, labelled with the id an operator wrote in the document.

Two more, for the shapes an operator actually asks for:

```promql
# Drop reasons on the dataplane ports alone, excluding the management port:
# filtering the info series on the right restricts the join to that role.
sum by (interface, reason) (
  librefirewall_input_drops_total
    * on(domain) group_left(interface)
      librefirewall_interface_info{role="dataplane"}
)

# What each port is, as a table: one row per interface, whatever it is counting.
librefirewall_interface_info
```

Note what the join does **not** give: `librefirewall_forwarded_frames_total` is the forwarder's and
carries `domain="forwarder"` with a `pipeline` label, so it does not join on `domain` to an
interface. Pipeline *n* and port *n* are the same index, and nothing on this surface says so — the
forwarder publishes per pipeline because that is the state it keeps, and the mapping from pipeline to
port is a build fact this reference does not yet expose. Join the *drivers'*
`librefirewall_transmit_frames_total` instead, which is the same frames one hop later and does carry
a driver `domain`.

### Configuration and the clock

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_clock_calibrations_refused_total` | counter | `management` | — | Published calibrations this domain would not use. |
| `librefirewall_clock_frequency_hertz` | gauge | `clock` | — | The timestamp counter frequency this node measured at boot; 0 before it did. |
| `librefirewall_clock_generation` | gauge | `management` | — | The calibration generation this domain converts counter readings with; 0 is none. |
| `librefirewall_configuration_generation` | gauge | `config`, `forwarder`, `management` | — | The configuration generation this domain is running under; 0 is the fail-closed empty table. |
| `librefirewall_configuration_images_total` | counter | `forwarder`, `management` | `outcome`&nbsp;(`applied`, `refused`) | Configuration images this domain applied or refused. |

**No metric was added when every record gained an instant, and that is deliberate.** Whether a
domain has a calibration is visible on each record it emits — `time=unsynchronized` against an
instant — so a counter of unsynchronized records would restate, at lower resolution, something the
records already carry per record. `librefirewall_clock_frequency_hertz` says what this node
measured and `librefirewall_clock_generation` says which calibration the management domain converts
with; the other six writing domains publish no such gauge, so *which* of them has taken the
calibration up is answerable from the log stream and not from a scrape. That is a gap, it is small,
and it is named here rather than closed with a series nothing needs.

The three attribution classes are kept apart exactly as stated above and are worth naming against
the table: `librefirewall_device_faults_total` is what a **device** got wrong about its own protocol;
`librefirewall_input_drops_total`, `librefirewall_route_drops_total` and
`librefirewall_tcp_refused_total` are what a **device or peer sent** that a layer refused; and
`librefirewall_invariant_faults_total`, `librefirewall_route_stage_drops_total`,
`librefirewall_endpoint_stage_drops_total` and `librefirewall_tcp_write_refused_total` accuse **this
code** and are expected to read zero forever — they are alerts, not traffic statistics.

**What a scrape costs the dataplane.** Nothing measurable, and by construction rather than by
measurement: a counter update is a relaxed add to a `u64` in the publishing domain's own cache-line
aligned region, and the exposition is rendered in the management domain out of a read of those
regions. No dataplane domain does any work on a scrape, and no lock is shared with one.

**Still absent.** `/config` and `/logs` (see [Observability surfaces](observability.md)) are
unimplemented, so of the debug dump only the state half and the recordings exist. The endpoint is
**plain HTTP with no client authentication**: the design requires mutual TLS on the management
interface (see the [management design](../design/management.md)), and until that lands anyone who
can reach the management interface can scrape it. That is a deviation, recorded in the
[status table](../status.md) and in `lfw_ip_endpoint`'s crate header. The endpoint stages one
response at a time, so a scrape arriving while another is still going out is answered `503` and
counted as `librefirewall_http_responses_total{status="503"}`.
