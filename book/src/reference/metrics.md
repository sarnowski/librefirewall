# Prometheus metrics

**Purpose:** expose every moving part of the firewall for monitoring and for the state half of the
debug dump, scrapably and without degrading the dataplane.

**Endpoint:** `GET /metrics`, Prometheus exposition format, on the management port.

**Coverage:** the inventory below is the whole of what a scrape returns, and every family in it is a
contract — its type, its labels and the domains that publish it. It reaches the dataplane's verdict
and throughput counters, each NIC's own faults and losses, buffer-pool ownership, the management
port's endpoint and its TCP and HTTP layers, the block device under the recordings and the two
recordings themselves, the console path's losses, the applied-configuration state and the clock,
the hardware probe's verdict, and the identity of each configured interface.

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

**Transliteration (binding).** A metric name, a label name and a **closed-vocabulary** label value
are the console's own key or token with `-` replaced by `_`, under the `librefirewall_` prefix, with
`_total` on a counter. `no-route` on the console is `reason="no_route"` here; `nic-driver` is
`domain="nic_driver0"`, `1` or `2`, the instance number being what this surface adds to a token the
console leaves whole. The rule exists so an operator reading a console line and an operator reading
a dashboard are looking at the same word, and so neither has to keep a mapping table. A label value
may begin with a digit (`pipeline="0"`), which the exposition format permits and a metric *name*
does not.

**The three runtime-text values of `librefirewall_interface_info` are outside that rule**, exactly
as the console alphabet rule carves out a MAC's colons and an address's dots. `interface`, `address`
and `mac` carry text an operator wrote in the configuration document, in the document's own
spelling: `interface="dataplane-0"` keeps its hyphen, an address is a dotted quad and a MAC is
colon-separated. Transliterating them would break the one property they exist for, which is that an
identity on a dashboard is the identity in the document. Every other value on this surface comes
from a closed vocabulary and follows the rule above.

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

122 families; the `domain` column lists every value that appears, which is the set of protection
domains publishing that family. A scrape is 461 counter and gauge series from the 12 shards,
plus one info series per configured interface and one hit counter per rule the running policy
declares, and the document they render into is bounded at 99 784 bytes — a worst case computed from
these tables at build time, which is what the staging buffer behind the endpoint is sized from.

That bound is dominated by the rules: it covers a policy naming all 256 the configuration accepts,
each under a sixteen-byte id, so a document declaring two rules produces a scrape a third of the
size. The buffer is sized by what an operator is *entitled* to write rather than by what this
appliance happens to be running, because the alternative is an endpoint that answers a scrape until
somebody adds a rule.

**A family's `domain` set and its label values are not a cross-product.** Several families are
partitioned, one domain carrying part of a label's vocabulary and another domain the rest, and each
of those says so in its own `HELP` text on the wire as well as in the Meaning column below. An alert
written against a combination no domain publishes will never fire, which is the failure mode worth
avoiding: it looks exactly like a healthy node.

### Dataplane: what the forwarder decided

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_forwarded_frames_total` | counter | `forwarder` | `pipeline`&nbsp;(`0`, `1`) | Frames rewritten for their next hop and handed to the transmitting driver. |
| `librefirewall_route_drops_total` | counter | `forwarder` | `pipeline`&nbsp;(`0`, `1`), `reason`&nbsp;(`addressed_to_this_router`, `egress_is_ingress`, `flow_bucket_full`, `flow_fragment`, `flow_invalid_flags`, `flow_invalid_state`, `flow_malformed`, `flow_mid_stream`, `flow_no_such_flow`, `flow_out_of_window`, `flow_quoted_invalid`, `flow_table_full`, `flow_unsupported_icmp`, `flow_unsupported_protocol`, `interface_disabled`, `martian_source`, `no_neighbour`, `no_policy_match`, `no_route`, `not_addressed_to_us`, `policy_denied`, `ttl_expired`, `unconfigured_ingress_port`, `unowned`, `unroutable_destination`, `vlan_tagged`) | Frames the router refused, by the reason it named. `unowned` is the appliance rather than the frame: a node no management plane has onboarded forwards nothing, so every frame is counted here and none reaches any other reason — the console says the same word at boot. The twelve `flow_` reasons are the connection tracker's, refused in front of the filter; `policy_denied` is a rule that said drop and `no_policy_match` is the default deny, which is a property of the fallthrough rather than of any rule. |
| `librefirewall_route_stage_drops_total` | counter | `forwarder` | `pipeline`&nbsp;(`0`, `1`), `reason`&nbsp;(`egress_full`, `ethernet_unparsable`, `frame_too_short`, `ipv4_checksum_invalid`, `ipv4_unparsable`, `malformed_descriptor`, `misrouted`, `snapshot_failed`, `writeback_failed`) | Frames the routing stage refused around the router's own decision. The four parse reasons name where the frame stopped being readable, which is what says whether a port is being fed the wrong link type or malformed IPv4. |
| `librefirewall_policy_packets_total` | counter | `forwarder` | `verdict`&nbsp;(`accepted`, `denied`) | Packets the filter decided on, by the verdict it reached; `denied` covers both a rule that said so and the default deny, which the route drop reasons tell apart. |
| `librefirewall_policy_bytes_total` | counter | `forwarder` | `verdict`&nbsp;(`accepted`, `denied`) | Datagram bytes the filter decided on, by the verdict it reached; the sender's own IPv4 total length, so it is comparable against a link's throughput. |
| `librefirewall_rule_hits_total` | counter | `forwarder` | `rule` | Packets matched by each rule of the running policy, under the id the configuration document gave it. First match wins, so a packet is counted against one rule at most. |
| `librefirewall_flow_packets_seen_total` | counter | `forwarder` | — | Packets offered to the connection tracker, whatever became of them. The denominator the classified and refused families are read against. |
| `librefirewall_flow_packets_total` | counter | `forwarder` | `outcome`&nbsp;(`established`, `new`, `related`) | Packets the connection tracker classified, by what it made of them. `new` opened a flow, `established` advanced one the table already held, and `related` is an ICMP error reporting on one. A packet counted here was not refused; a packet refused is in `librefirewall_flow_packets_refused_total` and in neither of the two. |
| `librefirewall_flow_packets_refused_total` | counter | `forwarder` | `reason`&nbsp;(`bucket_full`, `fragment`, `invalid_flags`, `invalid_state`, `malformed`, `mid_stream`, `no_such_flow`, `out_of_window`, `quoted_invalid`, `table_full`, `unsupported_icmp`, `unsupported_protocol`) | Packets the connection tracker turned away, by what refused them. `mid_stream` counts attempts to walk around default deny by starting inside a conversation this appliance never saw begin; `table_full` is the fail-closed answer to a connection flood and means legitimate new connections are being refused. |
| `librefirewall_flow_lifecycle_total` | counter | `forwarder` | `event`&nbsp;(`closed`, `evicted`, `expired`, `revoked`, `withdrawn`) | Flows that left the table, by what ended them. `expired` reached their state's idle timeout, `evicted` were taken back under pressure and are never assured ones, `closed` were ended by their own endpoints, `withdrawn` were opened by a packet the filter then refused, and `revoked` were admitted by a policy a commit has replaced with one that no longer admits them. There is no `created`: a flow is created by exactly the packet counted as `new` above. |
| `librefirewall_flow_table_entries` | gauge | `forwarder` | `state`&nbsp;(`close_wait`, `closed`, `closing`, `established`, `fin_wait`, `icmp_replied`, `icmp_unreplied`, `syn_received`, `syn_sent`, `time_wait`, `udp_assured`, `udp_unreplied`, `vacant`) | Slots of the connection table, by the state of the flow in each. `vacant` is how much room is left, so the values sum to the table's capacity and a flood is watched as `vacant` falling rather than as an occupancy needing a capacity nothing publishes. |
| `librefirewall_flow_probe_collisions_total` | counter | `forwarder` | — | Chain steps that reached an entry which was not the one looked up. Not a refusal — the walk simply continued — and exposed because the ratio against `librefirewall_flow_packets_seen_total` is what says whether the index is doing its job. |
| `librefirewall_policy_sweep_total` | counter | `forwarder` | `outcome`&nbsp;(`completed`, `deferred`) | Passes over the connection table re-deciding it against a newly committed policy. `completed` reached the last bucket, so every flow has been judged against the running policy; `deferred` arrived while a pass was running and queued a fresh pass behind it. |
| `librefirewall_policy_sweep_running` | gauge | `forwarder` | — | 1 while a pass over the connection table is still owed, 0 once it has finished. The window a commit opens: while it reads 1, a conversation the new policy forbids may still be forwarding. |
| `librefirewall_policy_sweep_progress_total` | counter | `forwarder` | `walked`&nbsp;(`buckets`, `flows`) | What the re-deciding passes have walked: `buckets` of the connection index, and `flows` that were live enough to be judged. Read against the table's capacity, they say how far a pass gets per wakeup. |
| `librefirewall_tap_observations_total` | counter | `forwarder` | — | Frame observations the forwarder published to the recorder. |
| `librefirewall_tap_observations_lost_total` | counter | `forwarder` | `reason`&nbsp;(`inconsistent`, `ring_full`) | Observations the tap could not publish; `ring_full` is the recorder falling behind, `inconsistent` is ours and expected to stay zero. |

**The three filter families carry no `pipeline` either**, and for a different reason: one filter
serves both directions of the dataplane, because a stage of that chain may hold state spanning a
whole conversation. There is no per-direction number to report, so none is invented.

**`librefirewall_rule_hits_total` is the one family whose cardinality an operator sets.** It carries
one series per rule the running document declares — two rules, two series — and none at all while a
node is on generation 0, which is the honest report of a policy that declares nothing. The `rule`
label is the id from the document, and that is what makes the family readable: a counter labelled by
a rule's position in the file would move under every edit above it. The count comes from the
forwarding domain and the id from the configuration, joined on the rule's position, so a hit is a
number only the forwarder could have written under a name only an operator could have chosen.

Three checks are worth making across these families rather than reading any of them alone.
`rule_hits` summed over the `accept` rules equals `policy_packets{verdict="accepted"}`, because
first match wins. `policy_packets{verdict="denied"}` equals `route_drops` summed over
`policy_denied` and `no_policy_match` across both pipelines — the same refusals counted by the filter
and by the pipeline around it. And a rule whose counter never moves is a rule that has never matched:
on an appliance that denies what nothing matched, an `accept` sitting at zero is the shape a policy
mistake takes.

The tap is one ring for the domain, not one per pipeline, so neither family carries `pipeline`: the
packet identity a recording relates two observations by is per appliance, and a per-pipeline split
would be two halves of a number nothing produces.

**`observations + observations_lost` is below `forwarded + route_drops`, and the gap is not loss.**
Three classes of frame are counted on the tables above and deliberately recorded nowhere, because
the tap ABI mirrors the router's own drop reasons exactly and has no honest encoding for them: a
frame no routing decision was reached about (`malformed_descriptor`, `snapshot_failed`,
`frame_too_short`, `ethernet_unparsable`, `ipv4_unparsable`, `ipv4_checksum_invalid`), one routed
out of a port the stage is not wired to (`misrouted`), and one recorded as
forwarded that a later refusal still lost (`egress_full`, `writeback_failed`, and the second
`ttl_expired` enforcer). An operator reconciling a recording against the counters subtracts those.

### Dataplane: what each NIC moved, and what it got wrong

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_device_faults_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2`, `recorder`, `store` | `fault`&nbsp;(`completion_length_over_reported`, `completion_not_posted`, `completion_out_of_range`), `queue`&nbsp;(`receive`, `request`, `transmit`) | Virtqueue completions the device got wrong about its own protocol. **Each domain carries only the queues it has**: `receive` and `transmit` on a NIC driver, `request` on the two block devices. |
| `librefirewall_input_drops_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | `reason`&nbsp;(`rx_peer_ring_full`, `rx_runt`, `tx_discarded`, `tx_duplicate`, `tx_free_ring_full`, `tx_malformed`, `tx_verdict_undecodable`) | Frames this driver did not move for a reason outside itself: a peer or the wire. |
| `librefirewall_invariant_faults_total` | counter | `forwarder`, `nic_driver0`, `nic_driver1`, `nic_driver2`, `recorder`, `store` | `fault`&nbsp;(`block_completion_unmapped`, `flow_slot_desync`, `rx_completion_unmapped`, `rx_slot_occupied`, `tx_completion_unmapped`, `tx_slot_occupied`) | A domain's own broken bookkeeping; ours, never traffic, expected to stay zero. **Each domain raises its own faults and no other's**: the four `rx_`/`tx_` faults are a NIC driver's, `block_completion_unmapped` either block domain's, and `flow_slot_desync` the forwarder's — the connection table finding no slot to allocate while believing it holds vacant ones. |
| `librefirewall_pool_returns_refused_total` | counter | `management`, `nic_driver0`, `nic_driver1`, `nic_driver2` | `pool`&nbsp;(`receive`, `transmit`), `reason`&nbsp;(`ledger_refused`, `not_lent`) | Buffer returns a pool owner refused: forged, out of range, duplicated or never lent. **Each domain owns one pool**: `receive` on a NIC driver, `transmit` on the management port's endpoint. |
| `librefirewall_receive_bytes_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Bytes those frames carried, after the device's own header. |
| `librefirewall_receive_frames_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Frames this port's device delivered and the driver handed to its peer. |
| `librefirewall_transmit_bytes_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Bytes those frames carried, after the device's own header. |
| `librefirewall_transmit_frames_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Frames this driver posted to its device for transmission. |
| `librefirewall_virtqueue_posted` | gauge | `nic_driver0`, `nic_driver1`, `nic_driver2` | `queue`&nbsp;(`receive`, `transmit`) | Buffers posted to the device on this virtqueue and not yet completed. A device that takes buffers and completes none holds this pinned while every fault counter stays at zero, which is the one reading that tells a stalled port from an idle link. |

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
| `librefirewall_endpoint_unhandled_total` | counter | `management` | `reason`&nbsp;(`arp_sender_mac_mismatch`, `ethertype_not_handled`, `fragmented`, `not_an_echo_request`, `protocol_not_handled`, `source_not_unicast`, `source_off_link`, `vlan_tagged`) | Well-formed frames for this endpoint that it deliberately does not answer, by reason. |

### The management port: the neighbour cache under the endpoint

Where the endpoint resolves the next hop it addresses an outbound frame to. Every series here is
about a station **this port asked about or was answered by**, so the four refusal outcomes are what
tells a quiet link from one somebody else is on.

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_endpoint_neighbour_entries_expired_total` | counter | `management` | — | Entries dropped because their lifetime ran out. |
| `librefirewall_endpoint_neighbour_replies_total` | counter | `management` | `outcome`&nbsp;(`learned`, `not_unicast`, `rebinding_refused`, `unsolicited`) | Address resolution replies this port read, by what it did with each. Only `learned` becomes an entry. **`rebinding_refused` is the one to watch**: it names a station answering for a next hop this appliance is already using, which is an attempt to redirect what it sends. |
| `librefirewall_endpoint_neighbour_requests_total` | counter | `management` | — | Resolution requests this port composed for a next hop, retries included. |
| `librefirewall_endpoint_neighbour_resolutions_failed_total` | counter | `management` | `reason`&nbsp;(`abandoned`, `no_room`) | Next hops this port could not resolve: `abandoned` spent every request unanswered, and `no_room` could not be asked about at all. |

### The management port: the connection it dials out

The other direction of the port. Everything above is the appliance answering something that arrived;
these five are the one connection it **originates**, which is the channel a management plane is
reached over.

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_endpoint_outbound_answer_overflowed_total` | counter | `management` | — | Answer bytes a peer sent past the room one session keeps, dropped rather than allowed to displace what came before them. |
| `librefirewall_endpoint_outbound_bytes_total` | counter | `management` | `direction`&nbsp;(`answer`, `request`) | Request bytes handed to the transport, and answer bytes taken from a peer and kept. |
| `librefirewall_endpoint_outbound_dials_total` | counter | `management` | — | `SYN`s the transport composed for an originated connection. |
| `librefirewall_endpoint_outbound_segments_dropped_total` | counter | `management` | — | Segments composed and then dropped for want of a hardware address for the next hop. Each is re-sent by the transport's own retransmission, so a small number is a resolution that ran while a timer was armed and a large one is a next hop that answers slowly or not at all. |
| `librefirewall_endpoint_outbound_sessions_total` | counter | `management` | `outcome`&nbsp;(`answered`, `failed`, `opened`, `refused`) | Connections this appliance originated, by what became of each. `opened` and `refused` are what this end decided before a frame was composed; `answered` and `failed` are how the ones that went out ended. **`opened` minus `answered` minus `failed` is the session running now**, which is at most one. |

**These five and the console's own `dial-outcome=` record are two readings of one channel**, and
they answer different questions: the record says how the channel ended and is written once, while
these say how much was spent getting there. A node whose `sessions_total{outcome="failed"}` moves
without `outbound_dials_total` moving is one refusing its own opens rather than one nothing answers.

### The management port: the onboarding port it listens on

The port's **second** listening port, which carries a byte stream rather than requests: bytes an
administrator's session sends cross to the domain that terminates TLS, and bytes that domain answers
with go back on the wire unread. Every count here is a count of bytes or connections; **no byte of a
session reaches this surface or any other**.

These eight and the console's own `onboard-` records are two readings of one port, and the split
matters: a console record exists only once a session has *ended*, so a peer that connects, floods the
port past the window it was given and disappears leaves no record at all — and moves three of these.
Read them when the console is silent and something is nevertheless wrong.

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_endpoint_onboard_answers_refused_total` | counter | `management` | — | Bytes the terminating domain answered with that this port had no room for. Ours rather than a peer's: the answer outgrew the room this end keeps for one, and the session is ended rather than carried on with a hole in the middle of it. |
| `librefirewall_endpoint_onboard_bytes_total` | counter | `management` | `direction`&nbsp;(`received`, `sent`) | Bytes taken off a peer and held for the terminating domain, and bytes that domain answered with and the transport took. **Compare `received` against the console's `onboard-received=` summed over the boot**: a gap is bytes this port took off the wire that never crossed the relay. |
| `librefirewall_endpoint_onboard_connections_total` | counter | `management` | `event`&nbsp;(`accepted`, `forgotten`) | Connections the port accepted, and those the transport stopped holding while a session ran on one — a reset, an eviction, or a reaping. **`accepted` larger than the number of session records is a peer that connected and produced no session.** |
| `librefirewall_endpoint_onboard_overflowed_total` | counter | `management` | — | Bytes a peer sent past the room this port had left, refused rather than allowed to displace what came before them. The receive window is kept equal to the room actually left, so this is **unreachable while a peer honours it** — any number here is a peer that did not. |
| `librefirewall_endpoint_onboard_sessions_closed_total` | counter | `management` | `by`&nbsp;(`consumer`, `peer`) | Sessions each end finished, by which end said so first. Neither moving while `connections_total{event="forgotten"}` does is a link that keeps dropping connections mid-session. |

The port holds **one** connection at a time, and structurally: a second peer's `SYN` while a session
is live finds no slot and nothing evictable, so it is dropped by the transport itself rather than
appearing here. It is counted by the transport under this port —
`librefirewall_tcp_refused_total{service="onboarding",reason="table_full"}` in the families below.

### The management port: the two TCP transports

The management port carries **two** transports with two connection tables, and every family here is
published once for each: the stack under the HTTP server, and the stack under the onboarding port.
`service` is what tells them apart, and it is a label rather than a second set of families because a
refused segment or an accepted connection means the same thing whichever port it happened on —
`sum by (service)` separates them and a query that omits the label gets the whole port, which is
usually what a first look wants.

Read the two differently. The HTTP stack both listens and dials, so its `connections_total` moves on
`accepted` and on `dialled`. The onboarding stack only ever listens: `dialled` and `abandoned` stay
at zero there, and a number in either is a defect rather than a peer. Its table holds one
connection, so `refused{reason="table_full"}` is the ordinary answer to a second administrator
connecting while a session runs — on the HTTP stack the same series means eight connections were
already live, which is a very different thing.

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_tcp_bytes_total` | counter | `management` | `service`&nbsp;(`http`, `onboarding`), `direction`&nbsp;(`received`, `retransmitted`, `sent`) | Payload bytes delivered in order, handed to the stack to send, or re-sent. |
| `librefirewall_tcp_challenge_acks_total` | counter | `management` | `service`&nbsp;(`http`, `onboarding`) | Segments challenged rather than acted on under RFC 5961 — a blind in-window `RST` (§3.2) or a `SYN` on a synchronized connection (§4). Whether the acknowledgement left is §7's budget's answer. |
| `librefirewall_tcp_challenges_suppressed_total` | counter | `management` | `service`&nbsp;(`http`, `onboarding`) | Unsolicited replies withheld by RFC 5961 §7's per-second budget: a challenge acknowledgement, or the reset a segment naming no connection would have drawn. The budget is per transport and shared across that transport's whole connection table, so this rising is the node declining to be an amplifier and not a connection in trouble. |
| `librefirewall_tcp_connections_total` | counter | `management` | `service`&nbsp;(`http`, `onboarding`), `event`&nbsp;(`abandoned`, `accepted`, `closed`, `dialled`, `established`, `evicted`, `reaped`) | Connections that reached each lifecycle event. `accepted` is a handshake a peer began and `dialled` one this node began, and the two are never merged: dials rising while `established` stays flat is a node that cannot reach where it is trying to go. Only the HTTP stack dials, so `dialled` and `abandoned` are zero under `service="onboarding"`. |
| `librefirewall_tcp_refused_total` | counter | `management` | `service`&nbsp;(`http`, `onboarding`), `reason`&nbsp;(`bad_checksum`, `malformed`, `no_acknowledgement`, `no_connection`, `not_a_handshake`, `not_listening`, `out_of_order`, `out_of_window`, `table_full`, `unacceptable_ack`) | Segments the transport refused, by the cause it named; what a peer sent. `not_a_handshake` is a segment answering a connection this node dialled that carried neither `SYN` nor `RST`, which such a connection has no window to refuse under. |
| `librefirewall_tcp_resets_total` | counter | `management` | `service`&nbsp;(`http`, `onboarding`), `direction`&nbsp;(`received`, `sent`) | Resets accepted or sent. |
| `librefirewall_tcp_retransmits_total` | counter | `management` | `service`&nbsp;(`http`, `onboarding`) | Segments re-sent, data and control alike. |
| `librefirewall_tcp_segments_total` | counter | `management` | `service`&nbsp;(`http`, `onboarding`), `direction`&nbsp;(`received`, `sent`) | Segments the stack received or composed. |
| `librefirewall_tcp_urgent_ignored_total` | counter | `management` | `service`&nbsp;(`http`, `onboarding`) | Segments carrying URG, whose urgent pointer is ignored and data delivered in band. |
| `librefirewall_tcp_write_refused_total` | counter | `management` | `service`&nbsp;(`http`, `onboarding`) | Segments the stack decided to send that did not fit its caller's storage; ours. |

### The management port: the HTTP server

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_http_bodies_refused_total` | counter | `management` | — | Response bodies a renderer would not fit in the staging buffer, whichever target asked; ours, expected to stay zero. |
| `librefirewall_http_bodies_taken_total` | counter | `management` | — | Request bodies accumulated whole and handed to the domain that decides on them. |
| `librefirewall_http_bodies_timed_out_total` | counter | `management` | — | Request bodies given up on for not arriving whole in time, answered 408 and reset; each one is a stretch in which the other body-bearing surfaces answered 503. |
| `librefirewall_http_body_overruns_total` | counter | `management` | — | Request-body bytes a client sent past the length it declared, dropped unread. |
| `librefirewall_http_requests_overflowed_total` | counter | `management` | — | Requests that outgrew the bounded request buffer before their head ended. |
| `librefirewall_http_requests_total` | counter | `management` | — | Requests the server read to their end and decided on. |
| `librefirewall_http_response_bytes_total` | counter | `management` | — | Response bytes handed to the transport, headers included. |
| `librefirewall_http_responses_total` | counter | `management` | `status`&nbsp;(`200`, `400`, `404`, `405`, `408`, `410`, `413`, `414`, `429`, `431`, `503`, `505`) | Responses composed, by status code. `429` and `410` are the onboarding surface's — its rate limiter, and an appliance that has an owner and has shut that surface — and neither can appear on this port, which limits nothing and is never shut: the label set is the whole of what this appliance's one response writer can compose. |
| `librefirewall_http_retransmits_unavailable_total` | counter | `management` | — | Ranges the transport asked for again that no response buffer held; ours, expected to stay zero. |
| `librefirewall_http_slots_exhausted_total` | counter | `management` | — | Connections the server had no slot for; ours, the tables being one size, expected to stay zero. |

### The console path, and what it loses

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_console_records_total` | counter | `console` | `outcome`&nbsp;(`malformed`, `printed`, `unknown`, `unrenderable`, `write_failed`) | Records the console path resolved, by outcome; each outcome accuses a different party. |
| `librefirewall_log_records_dropped_total` | counter | `clock`, `config`, `crypto`, `forwarder`, `hardware_probe`, `management`, `nic_driver0`, `nic_driver1`, `nic_driver2`, `recorder`, `store` | — | Records this domain could not publish because its ring had no slot. |
| `librefirewall_log_records_refused_total` | counter | `clock`, `config`, `crypto`, `forwarder`, `hardware_probe`, `management`, `nic_driver0`, `nic_driver1`, `nic_driver2`, `recorder`, `store` | — | Records this domain minted and never put in its ring: an event the record ABI cannot carry, or a sink already borrowed further up the same stack. Ours either way, expected to stay zero. |
| `librefirewall_uart_bytes_written_total` | counter | `console` | — | Bytes handed to the transmitter-holding register. |
| `librefirewall_uart_init_failures_total` | counter | `console` | — | Refused initialisations of the serial controller. Non-zero means this node has no console: the domain publishes its shard from the refusal path so that a scrape can say so. |
| `librefirewall_uart_transmitter_timeouts_total` | counter | `console` | — | Bytes dropped because the transmitter never reported itself empty; the device's fault. |

### The two block devices

There are two, and the four families below carry both: the recorder's, which holds the recordings,
and the store's, which holds the appliance's own persistent state. They are separate authorities
rather than two views of one device — no domain maps any part of the other's — so `domain=` is what
tells one device's numbers from the other's and reading either alone says nothing about the other.

`librefirewall_block_capacity_sectors` is the device's own claim, taken once at bring-up and
republished unchanged: it bounds every sector range the domain will name, so a device that came up
smaller than the recording — or the state layout — configured for it is visible in a scrape rather
than only in a refusal.
A sector is 512 bytes, fixed by the virtio 1.0 specification (its block-device section) regardless
of the `blk_size` a device reports.

The two `_total` families count only **successful** completions and the bytes those moved, derived
by the driver from what it submitted rather than taken from the device's own byte count — which
answers a different question per operation and is only informative on a short read. Nothing here
counts a refused submit: a request the driver would not publish is a defect in this appliance, and
it reaches an operator as a console refusal rather than as a series.

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_block_bytes_total` | counter | `recorder`, `store` | `operation`&nbsp;(`read`, `write`) | Bytes those requests moved, as the driver derived them rather than as the device claimed. |
| `librefirewall_block_capacity_sectors` | gauge | `recorder`, `store` | — | Sectors the block device claimed at bring-up; the bound every range is judged against. |
| `librefirewall_block_requests_total` | counter | `recorder`, `store` | `operation`&nbsp;(`read`, `write`) | Block requests the device completed successfully, by operation. |
| `librefirewall_block_status_undecodable_total` | counter | `recorder`, `store` | — | Completions whose status byte was none of the three virtio-blk defines; the device's fault. |

Either domain's virtqueue faults are **not** a family of their own: they are
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

**The two sinks' counts are meant to differ, and by a lot.** They record different things (see
[Recording downloads](recordings.md)): the capture's count is every observation the recorder drained,
which is `librefirewall_recording_tap_records_total`, while the log's is the subset that carried a
connection lifecycle or policy event. A log count close to the capture's is a node whose traffic is
almost all connection openings and refusals; one far below it is the ordinary case, and the ratio
between them is the cheapest reading of how much of the traffic is new conversations rather than
packets on established ones.

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
| `librefirewall_recording_records_dropped_total` | counter | `recorder` | `sink`&nbsp;(`capture`, `log`), `reason`&nbsp;(`oversized`, `refused`) | Observations a sink could not encode, by why; every one is a gap the recording states. |
| `librefirewall_recording_records_total` | counter | `recorder` | `sink`&nbsp;(`capture`, `log`) | Observations encoded into a recording, by sink. |
| `librefirewall_recording_staging_deferrals_total` | counter | `recorder` | `sink`&nbsp;(`capture`, `log`) | Records a recording could not stage yet and re-offered. **Not a loss**: a deferred record is held and placed on a later pass, so this rising says the medium is behind the encoder and never that a recording has a gap. |
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
| `librefirewall_recording_streams_total` | counter | `management` | `outcome`&nbsp;(`abandoned`, `started`) | Recording downloads this domain began, and those it gave up on part-sent. |

**No series describes ring occupancy**, and none describes how much history a recording holds. A
wrap count says a segment was evicted; it does not say how far behind a reader was when it went, and
nothing on this surface does — no reader registers a cursor for one to be measured against.

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
| `role` | `dataplane` or `management`. The design makes the role the architectural unit rather than the port number (see the [architecture design](../design/architecture.md)), so it is what a query groups by. **The vocabulary is closed at those two**, and a third token is a defect rather than an extension — the deployment design's other roles, session replication and mirror, are not values this label takes. |
| `address` | The configured IPv4 address, dotted quad. |
| `prefix_length` | The prefix length, decimal, as a string — every Prometheus label value is one. |
| `mac` | The configured MAC, lower case and colon-separated, the same form a console record writes it in. |

**Cardinality: one series per configured interface, and no more.** At most `wire::MAX_INTERFACES` + 1
= 9, which is what the exposition's worst-case bound reserves, and at most 7 on the largest port
model the deployment design describes — the management port, the session-replication port, two
dataplane pairs and the mirror. It does not grow with traffic, with connections, or with anything an
adversary controls.

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
port is a build fact no series carries. Join the *drivers'*
`librefirewall_transmit_frames_total` instead, which is the same frames one hop later and does carry
a driver `domain`.

### Configuration and the clock

**Two unrelated generations meet in this table.** A *configuration* generation is the datastore's
counter, assigned per commit and named on every `LFW-CFG` record; a *calibration* generation numbers
the clock domain's publications of its frequency, anchor and epoch. They advance for different
reasons and neither bounds the other, so the metric names them apart and nothing should join them.

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_clock_calibrations_refused_total` | counter | `management` | — | Published calibrations this domain would not use. |
| `librefirewall_clock_frequency_hertz` | gauge | `clock` | — | The timestamp counter frequency this node measured at boot; 0 before it did. |
| `librefirewall_clock_generation` | gauge | `management` | — | The calibration generation this domain converts counter readings with; 0 is none. |
| `librefirewall_configuration_generation` | gauge | `config`, `forwarder`, `management` | — | The configuration generation this domain is running under; 0 is the fail-closed empty table. |
| `librefirewall_configuration_images_total` | counter | `forwarder`, `management` | `outcome`&nbsp;(`applied`, `refused`) | Configuration images this domain applied or refused. **Only the forwarder carries `applied`**: the management port's endpoint reads a committed image for its own address and never applies one, so it reports `refused` alone. |
| `librefirewall_configuration_reads_total` | counter | `config` | — | Times the running configuration document was read out of this node. |
| `librefirewall_configuration_submissions_total` | counter | `config` | `outcome`&nbsp;(`applied`, `refused`, `unchanged`) | Documents submitted to this node over the management API, by what the configuration domain decided: `applied` moved the generation, `unchanged` was the configuration already running, `refused` broke a rule and changed nothing. |

### The hardware probe

The domain compiled with the SIMD target reports its verdict here as well as on the console, so a
scrape can answer whether this node proved the hardware-cryptography profile without a serial
capture. The three families are written once, when the probe parks, and never move again.

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_hardware_probe_proven` | gauge | `hardware_probe` | — | 1 once the AES and carry-less-multiply known answers held on every pass and the XMM pattern survived every preemption the probe observed; 0 before, and forever on a node that refused. |
| `librefirewall_hardware_probe_iterations_total` | counter | `hardware_probe` | — | Probe passes run before the verdict; each re-ran both known answers and re-checked the XMM pattern. |
| `librefirewall_hardware_probe_preemptions_total` | counter | `hardware_probe` | — | Preemptions the probe observed as timestamp-counter gaps while its XMM state was live. |

### Cryptography

The cryptography domain reports here as well as on the console, so a scrape answers whether this
node proved its cryptography and what each primitive cost it, without a serial capture. The
per-primitive label values are the console's names with hyphens turned into underscores, because a
label value on this surface is an underscore token everywhere; the [cryptography
profile](crypto-profile.md) is where what each primitive is proved against, and what a cost figure
does and does not assert, is written down. All three families are written once, when the domain
parks, and never move again.

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_crypto_proven` | gauge | `crypto` | — | 1 once every primitive answered every published vector this image carries for it; 0 before, and forever on a node that refused. |
| `librefirewall_crypto_vectors_proven_total` | counter | `crypto` | `primitive`&nbsp;(`sha_256`, `hmac_sha_256`, `hkdf_sha_256`, `chacha20`, `chacha20_poly1305`, `aes_256_gcm`, `chacha20_drbg`, `ecdsa_p256`, `x25519`, `ml_kem_768`) | Published NIST CAVP, RFC and Wycheproof vectors this node re-ran at bring-up and answered correctly, per primitive. |
| `librefirewall_crypto_milli_cycles_per_byte` | gauge | `crypto` | `primitive`&nbsp;(`sha_256`, `hmac_sha_256`, `hkdf_sha_256`, `chacha20`, `chacha20_poly1305`, `aes_256_gcm`, `chacha20_drbg`, `ecdsa_p256`, `x25519`, `ml_kem_768`) | Thousandths of a timestamp-counter cycle per byte this node measured for a primitive at bring-up; 0 for a primitive it does not measure. |
| `librefirewall_crypto_cycles_per_operation` | gauge | `crypto` | `primitive`&nbsp;(`sha_256`, `hmac_sha_256`, `hkdf_sha_256`, `chacha20`, `chacha20_poly1305`, `aes_256_gcm`, `chacha20_drbg`, `ecdsa_p256`, `x25519`, `ml_kem_768`) | Timestamp-counter cycles one operation of a primitive cost this node at bring-up, for the primitives whose work has one size rather than a length; 0 for a primitive measured per byte instead. |

### The appliance's own identity

The store domain reports here as well as on the console, so a scrape answers whether this node
*has* an identity without a serial capture. The five families are written once, when the domain
parks, and never move again.

**The identifier itself is not here, and neither is any key.** A 128-bit name is not a number a time
series can carry, and the private scalar has no representation on any surface at all; what this
answers is whether there is an identity, whether this boot had to mint one, and how far the record
has advanced. Which appliance it is, and which key it authenticates with, is on the
[console](console.md) — the two places an administrator reads a rendering, and the only two.

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_store_generation` | gauge | `store` | — | The generation of the state record this node is running on, which advances by one on every durable commit. A gauge rather than a counter: it is a position and not a rate. |
| `librefirewall_store_identity` | gauge | `store` | — | 1 once this appliance's identity is established on the store medium — minted on a fresh medium or reloaded and verified from an existing one; 0 before, and forever on a node that refused. No key material is exposed here or anywhere else on this surface. |
| `librefirewall_store_minted` | gauge | `store` | — | 1 where this boot minted a fresh identity because the medium carried none, 0 where it reloaded the one already there. A node whose value flips to 1 after a boot at 0 has lost its identity, which is the fleet's own alert rather than a fault of the boot. |
| `librefirewall_store_onboarded` | gauge | `store` | — | 1 once a management plane has adopted this appliance, 0 while it is unowned. It is one of the two values on this surface that can move **during** a boot rather than only across one: an onboarding package installed while the node is running turns it on, and `librefirewall_store_generation` advances beside it. A factory reset is the only way back to 0, and a reset is a reboot. |
| `librefirewall_store_reset` | gauge | `store` | — | 1 where this boot found a factory-reset request on the store medium and honoured it, 0 otherwise. It is what tells an intentional reset from a lost medium: both mint, and only this says which one was asked for. |
| `librefirewall_store_sign_refusals_total` | counter | `store` | — | Delegation requests this domain answered with a refusal rather than an answer — an appliance with no established identity, an operation it has none of, a message longer than a request may carry, or an **onboarding package it would not install**. Every request over that channel is counted here: the certificate over the device key and the install of a package are asked for on it as well as a signature. A non-zero value beside a zero `librefirewall_store_signatures_total` is a peer asking for something this node cannot give — and which of the two it is, and which rule refused a package, is on the [console](console.md) rather than here. |
| `librefirewall_store_signatures_total` | counter | `store` | — | Signatures this domain has produced under the device key on behalf of a domain that holds no key. It is the only operator-visible sign that the delegation is working, and it is a count rather than anything about a signature: no message, no signature and no key is exposed here or anywhere else on this surface. |

**`librefirewall_store_minted` is the one to alert on, and
`librefirewall_store_reset` is what the alert has to be read with.** An appliance mints exactly once
in its life — on its first boot, and again only after a factory reset — so a node reporting 1 where a
previous scrape reported 0 has lost the medium's contents, and every certificate issued to it now
names a key it no longer holds. The reset gauge is what separates the two causes: `minted` and `reset`
both at 1 is an ownership transfer somebody with the medium in their hands asked for, while `minted`
at 1 with `reset` at 0 is a node that lost its identity and nobody asked it to. The generation is the
corroborating reading either way: a fresh mint is generation 1.

**The two signing counters are how the delegation is watched, and they are counts on purpose.** The
appliance's private key lives in this one domain, and the domain that authenticates to the network
asks it for a signature — and for the certificate over that key — rather than holding either. What
that exchange can be seen from the outside is exactly these two numbers:
`librefirewall_store_signatures_total` climbing means handshakes are being authenticated, and
`librefirewall_store_sign_refusals_total` climbing instead means a peer is asking for something this
node will not give — most often an appliance whose identity never established, in
which case `librefirewall_store_identity` reads 0 and the console says why. Neither carries a message,
a signature or a key, because there is nothing about a signature an operator needs and much that must
never be exposed. The refusals reach this surface and **not the console** deliberately: this domain's
log ring is bounded and single-producer, so a record per refusal would let the asking domain choose
the rate at which the identity and fingerprint records an operator actually needs are pushed out of
it, while a counter is something a hostile peer cannot use to hide anything.

**No series counts unsynchronized records, and that is deliberate.** Whether a domain has a
calibration is visible on each record it emits — `time=unsynchronized` against an instant — so such
a counter would restate, at lower resolution, something the records already carry one by one.
`librefirewall_clock_frequency_hertz` says what this node measured and
`librefirewall_clock_generation` says which calibration the management domain converts
with; the eight other writing domains publish no such gauge, so *which* of them has taken the
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

**What stands in front of this endpoint.** Nothing: it is **plain HTTP with no client
authentication**, so anyone who can reach the management port can scrape it, and a scrape carries
the node's whole measurable state. The design requires mutual TLS on that port (see the
[management design](../design/management.md)); this is a deviation from it, recorded in the
[status table](../status.md) and in `lfw_ip_endpoint`'s crate header. The endpoint stages one
response at a time, so a scrape arriving while another is still going out is answered `503` and
counted as `librefirewall_http_responses_total{status="503"}`.
