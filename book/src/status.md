# Development status

Statuses are **done**, **partial**, or **open**. Every *partial* capability is broken down
further — what exists and what specifically remains — in the developer chapter,
[Implementation status in detail](developers/status-detail.md), so the work can be picked up
without re-deriving it from the code. This page is the evaluator's view: what the appliance does
today, what it does not, and where the project is heading.

One reorientation frames everything below. The design chapters now describe a **two-component
product**: an appliance with no management surface of its own, dialing home over one
mutually-authenticated channel, and a central [management server](design/management-server.md) that
owns onboarding, configuration and telemetry. Very little of that exists yet — the
[redesign table](#management-plane-redesign) below records it as open — while the appliance built so
far, its plain-HTTP management surface included, is present, working, and deliberately kept until
the channel replaces it: the end-to-end gate's whole cross-check strategy rests on those HTTP
surfaces, so they are erased last, not first.

## The current deployable system

The current deployable system is a two-dataplane-port **filtering** IPv4 slice: one driver
protection domain per port brings up a `virtio-net-pci` device on QEMU q35 from static seL4
capabilities alone, and an isolated forwarder protection domain decides each frame between the two
ports — parsing it, working out where it would go, consulting the operator's filter rules, and
rewriting its Ethernet and IPv4 headers in place if a rule permits it. A frame is never moved **between** buffers: one pool buffer carries it from one
NIC's DMA to the other's, and only the 34 rewritten header bytes travel back into it. The decision
itself is taken on a private copy, because a verdict reached on bytes a peer may rewrite underneath
it is no verdict — so a hop costs one copy of the payload, and a second when the recording tap is
attached.

That configuration is a schema-validated XML document, read and committed by a protection domain
of its own that holds no device and no dataplane memory, and handed to the forwarder through a
shared region under an offer/acknowledge protocol. The forwarder boots **fail-closed** — an empty
table, forwarding nothing — and switches to a configuration only after re-deciding, itself, every
one of the 42 rules the validating domain applied — at that domain's own strength on all but two,
each named where it is declared and each about something the image cannot see or has no stake in — so
a compromised parser cannot hand it a table those rules refuse. Every boot therefore performs a live
configuration swap on a running dataplane.

A document can now be **submitted to a running node** over the management API: `POST /config` takes
an XML document, `GET /config` states the one in force, and a submission that passes every rule is
committed under the next generation and picked up by the dataplane at its next poll boundary. The
end-to-end gate proves the whole of that on the release image — it boots a node, injects traffic the
shipped policy forwards, `POST`s a document that reverses that policy, waits for the forwarding
domain to report the new generation, and injects again: the traffic that was forwarded is now dropped
and the traffic that was dropped is now forwarded, with no domain having restarted in between. Two
documents submitted after it are refused with a reason and leave the generation where it was: one the
reader stops, and one that parses cleanly and a *rule* refuses — the case where a configuration could
half-apply at all, so the node is additionally held to still stating what it committed and still
deciding traffic by it. A separate boot shows the other end of the same posture: a node whose *own*
document a rule refuses comes up on generation 0, forwards nothing at all, and says so on its serial
console, which is the only surface it has. The document a build embeds is now the *first* generation
rather than the only one; a **hardware** change still requires a new image, which is the line the
design draws.

**Anyone who can reach the management port can replace this appliance's policy.** There is no
authentication and no TLS in front of it — see the paragraph below — so the port must not be exposed
to an untrusted network.

A **dedicated management port** is the third NIC, and it is an addressed IPv4 endpoint that
answers for itself and forwards nothing. It answers ARP requests for its own address, ICMP echo
requests to it, and HTTP over a first-party TCP stack: `GET /metrics` returns a Prometheus
exposition, and `GET /logs.pcapng` and `GET /capture.pcapng` return the two traffic recordings
whole; `GET /config` states the running configuration and `POST /config` replaces it. All of it is
plain HTTP — **there is no TLS and no authentication in front of any of it yet**, so anyone who can
reach the port can scrape the metrics, download every packet the appliance recorded, read the policy,
and *replace* it. That last one is not a lesser gap than the others: it is the authority to decide
what this firewall forwards. Until the [management-plane redesign](design/management.md) replaces
this surface with the onboarding flow and the authenticated channel, the management port belongs on
an isolated network and nowhere else. The port's MAC, address and prefix
come from the configuration document like every other address on the appliance, so the port is
configured rather than compiled in.

The isolation between management and dataplane is a property of what each domain is granted, not a
rule anybody has to remember: the management domain holds no dataplane memory and the forwarder
holds no management memory, and the end-to-end gate asserts the same exclusion on the wire, in
both directions, on the release image — no frame injected on the management port ever appears on a
dataplane port, and no dataplane probe ever appears on the management one.

Another protection domain owns the serial console — the PC-compatible COM1 port — and is the only
writer of the line; every other domain reaches an operator by publishing a typed record, which the
console domain renders and puts on the line. It replaced a kernel debug facility the release
kernel is not built with: until this landed, a **release image printed nothing at all**, so a node
that parked on a refused NIC or came up fail-closed on a refused document said so only in the
profile nobody ships.

Booting that release image for the first time found a second, deeper defect underneath the first,
which had been latent since the boot chain was written: the bootloader was free to place the
system image in the 640 KiB below 1 MiB, from where seL4's x86 boot would load the userland image
over its own running kernel — a triple fault before any protection domain executed. Whether it
happened was decided by whether the system image happened to fit down there, so **the debug
profile was green by luck**. The GRUB configuration now denies the bootloader that memory and the
build refuses an image small enough to fit what remains; see
[Signed boot chain](developers/status-detail.md#signed-boot-chain).

Both defects were reachable only in the configuration no gate booted, and both are the reason the
gate now boots the shipped one: every QEMU scenario in `make ci` runs the release image, and the
only debug kernel any gate boots is the one re-run to diagnose a scenario that has already failed.

A clock domain establishes what time it is. It calibrates the timestamp counter against the HPET —
a timer whose rate is self-describing — reads the real-time clock once for an epoch to anchor that
counter to, and publishes the calibration to every other domain. **Every structured record
therefore carries the UTC instant it was emitted at**, rendered as RFC 3339 — and the records
emitted before the calibration exists carry the token `unsynchronized` rather than a fake 1970. It
is **not** a trusted time source — see the status table below and its
[detail](developers/status-detail.md#trusted-time-source).

A recorder domain owns the appliance's **block device** and turns the traffic into a durable
record. It brings a virtio-blk device up, proves the path to the medium by reading a sector and
writing a recognisable one back, and then writes **two pcapng recordings** onto that device, and
they differ by *what they record*. The **capture** holds every frame the pipeline reached a verdict
about, with that verdict on it: allow or deny, the reason, the rule where one matched, and the
conversation it belongs to. The **connection history** holds a record only where the appliance
reached a lifecycle or policy event — a conversation opened, advanced or closed, a policy refusal, a
tracker refusal — anchored to the packet that caused it and carrying that packet's L2–L4 headers.
Both are lifted while the frame is still the one that arrived rather than the one this appliance will
send on, which is what makes a recording evidence about the wire and not about the appliance's own
output. Either recording is downloadable whole over the management port — `GET /logs.pcapng`,
`GET /capture.pcapng` — and `tcpdump -r` opens both natively. Each recording is a ring across a
fixed extent of the disk, and the first sectors of that extent are its **superblock**: a doubled,
checksummed record of the ring's geometry and of how far it has been durably written, so the extent
can be read back from the medium alone with nothing else to consult. The recorder is the only
domain in the system that can put a byte on persistent storage, and the only path between it and
the dataplane is a one-way tap that can never backpressure forwarding.

**The appliance filters.** A packet is forwarded because a rule the operator wrote permits it, and
for no other reason: the `<rules>` section of the configuration document is a list of stateless
L2–L4 rules, matched first-match-wins in document order, and a packet no rule is about is
dropped. That last part is the whole posture and it is not a setting — the default deny is a
property of the fallthrough rather than of any document, so there is no `<rules>` section an
operator can write that makes an unmatched packet pass, and an empty one forwards nothing. Each
rule matches on ingress and egress interface, source and destination CIDR block, protocol, source
and destination port or port range, and ICMP type; every criterion is written out, `any` included,
so no attribute widens a rule by being left out. The two refusals a filter can reach stay separate
findings — a rule that said drop, and the fallthrough — and each rule carries its own hit counter on
`/metrics` under the id the document gave it.

**The filter is stateful, and it follows pf's model rather than netfilter's.** A connection tracker
sits between the forwarding decision and the filter, and a packet an existing flow already accounts
for is forwarded without the filter being consulted at all. So a ruleset decides which conversations
may **open**, and the traffic that follows one is carried by the flow. A reply comes back with no
rule naming it, which is the whole value of tracking state — the alternative is writing the reverse
of every rule and opening the appliance in both directions to permit one. And an edit to the policy
cannot cut a conversation already running *on the packet path*, because the rule that admitted it was
consulted once, when it opened. Under netfilter's model that acceptance is a rule an operator writes and can forget;
here it is structural, which is the trade this appliance makes for the OT environments it is aimed
at.

**And a commit can still end a conversation, because it re-decides the table rather than the
packet.** The moment a configuration commits, the appliance sweeps its own flow table against the new
policy and takes back every conversation that policy would no longer admit — once per commit rather
than once per packet, so the ruleset stays off the hot path and every flow the new policy still allows
is left exactly as it was. A host found to be compromised can therefore be cut off by an edit to the
document, which is what the model owed and did not previously deliver.

**How long that takes does not depend on how many conversations there are.** A pass is carried across
wakeups, and how much of it a wakeup works off scales with how full the table is — so a million-flow
table an attacker filled is swept in the same number of wakeups an empty one is, rather than sixteen
times as many. On the million-slot table this appliance builds that is at most 513 wakeups per pass at
any occupancy, and a commit arriving mid-pass queues one fresh pass behind the running one rather than
restarting it — so at most two passes, however fast documents are submitted. What that costs and the
arithmetic behind it is [in the detail](developers/status-detail.md#connection-tracking).

**Two things reach the filter, and a rule names which.** One is a conversation opening. The other is
traffic an existing conversation is the *reason* for without belonging to it — today an ICMP error
quoting one of its datagrams — which whoever sent it composed, with a source address of their
choosing. Recognising it decides where it would go and never whether it may, so it is put to the
filter like anything else and a document that admits no such traffic denies it. A rule writes
`tracking="opening"`, `tracking="related"`, or `tracking="any"`. There is deliberately no
`established` value: traffic inside a tracked conversation never reaches the filter, so the word
would name a choice an operator does not have, and it is refused rather than accepted and ignored.

It costs something, and the cost is in two places. A packet the tracker cannot keep state for is
refused *before* the filter, so no rule can permit a non-initial fragment, a protocol the appliance
does not decode, or a TCP segment from the middle of a conversation it never saw begin; each of
those refusals is its own reason on `/metrics`. There is no NAT. The ARP and ICMP that exist belong to the
management port alone — the dataplane resolves a next hop from a static neighbour table and answers
nothing for itself.

**The tracker's lifecycle reaches the recordings.** `/logs.pcapng` is a connection history: a
conversation opening names the rule that admitted it, an advance names what the packet moved, a close
names *how* it closed, a policy refusal names the rule or the default deny that refused it, a tracker
refusal names its reason, and a conversation a policy commit ended names the flow it ended and the
state it was in. Every record but that last one is anchored to the packet that caused it, so the file
opens in a pcapng reader as a packet list with real addresses and ports; the revocation is anchored to
no packet and **says so** rather than inventing one — no captured bytes, no wire length, no direction
and no classification, which is what a record about a conversation rather than about a frame looks
like. What is still missing is a **recording selector**: the capture sink records every frame the
dataplane decided on rather than the flows a policy picks out, and the filter rules above decide what
the appliance *forwards* and select nothing for recording. A conversation reclaimed by its idle
timeout still produces no close event — that record would have no causing packet either, and unlike a
revocation nothing emits one.

## Traffic inspection and enforcement

| Capability | Status | Notes |
|---|---|---|
| Stateful L2–L4 filtering | **partial** | configurable first-match-wins rules over ingress/egress interface, CIDR blocks, protocol, ports and ICMP type, with default deny and a per-rule hit counter; a ruleset decides which flows may open, and a commit re-decides the flow table so removing a rule **does** end the conversations it admitted. There is no `reject` and no zones — [detail](developers/status-detail.md#stateful-filtering) |
| Connection tracking | **partial** | a million-flow table in a region of the forwarder's own, classifying every routed packet: TCP sequence and window validation, UDP and ICMP flows, ICMP errors related to a flow they quote, per-state timeouts, eviction that refuses a new flow rather than displacing an established one, and withdrawal of a flow whose opening packet the filter then refused. An established or related packet is forwarded without the filter; every refusal is its own drop reason and its own metric. A flood of distinct five-tuples is now watched on the release image: every opening the default deny refuses gives its slot straight back, occupancy stays at the one conversation the policy admits, and that conversation's own traffic still crosses afterwards — what remains host-level is the behaviour at the capacity boundary, which no scenario can inject its way to. A configuration commit re-decides the whole table against the new policy and takes back the flows it no longer admits, a bounded window of the table per wakeup whose size scales with occupancy so a pass takes the same number of wakeups however full the table is — [detail](developers/status-detail.md#connection-tracking) |
| Routing, ARP, ICMP | **partial** | ARP and ICMP echo exist for the **management port only**, not for the dataplane — [detail](developers/status-detail.md#routed-ipv4-forwarding) |
| Virtual-wire (bump-in-the-wire) operation | **open** | see the [architecture design](design/architecture.md) |
| NAT (SNAT/masquerade, DNAT, static 1:1) | **open** | see the [architecture design](design/architecture.md) |
| Flow classifier (cut-through vs. proxy path) | **open** | |
| L7 protocol parsing (HTTP/1.1, HTTP/2, HTTP/3) | **partial** | a server-side HTTP/1.1 request parser (`datad/crates/http`) reads the management port's requests; it is a bounded head parser with no body, no HTTP/2 and no HTTP/3, and no dataplane consumer — described with the [`/metrics` endpoint](developers/status-detail.md#prometheus-metrics) |
| OT/industrial protocol inspection | **open** | |
| DoS resilience (SYN cookies, rate limiting, bounded state) | **open** | this row is about the dataplane and the proxy, where nothing exists. **The onboarding endpoints are now rate-limited with backoff**, as the [management design](design/management.md) requires: a burst of eight requests, an interval that doubles per consecutive refusal to a bound of thirty-two seconds, a refusal that always expires — a permanent lockout being a remote bricking primitive against the only port into an unprovisioned appliance — and a refusal an operator reads on the console with the wait beside it. **Nothing bounds the rate of requests to the plain-HTTP management port**, whose only rate bound is RFC 5961 §7's per-second challenge budget, which caps unsolicited TCP replies and not requests. What does exist is bounded *state*: the transport's connection table is fixed and reaped under pressure — [detail](developers/status-detail.md#proxy-tcp-stack) |
| Mirror port | **open** | the [recording design](design/recording.md) holds the recording sinks and a mirror to be complementary rather than alternatives; the sinks exist, the mirror does not |
| TLS termination and re-origination | **open** | |
| QUIC / HTTP-3 termination | **open** | |
| Isolated sign-only CA protection domain | **open** | |
| Trusted time source | **partial** | a protection domain establishes real time at boot and publishes it to every other domain, so every structured record carries the instant it was emitted at; nothing about it is *trusted* — [detail](developers/status-detail.md#trusted-time-source) |
| Streaming DPI / signature matching | **open** | |
| Full-object content scanning (YARA-X) | **open** | |
| Web filtering | **open** | |

## Dataplane, platform and hardware

| Capability | Status | Notes |
|---|---|---|
| Zero-copy shared-memory dataplane | **partial** | [detail](developers/status-detail.md#zero-copy-dataplane) |
| First-party virtio-net driver | **partial** | [detail](developers/status-detail.md#virtio-net-driver) |
| Multicore dataplane, RSS, per-core flow shards | **open** | single vCPU today |
| Proxy TCP stack | **partial** | a first-party stack carries a real connection on the management port and opens one of its own, and it is the stack the dataplane proxy will run on; no SACK, no congestion control, and no dataplane consumer — [detail](developers/status-detail.md#proxy-tcp-stack) |
| 10 Gbit/s per dataplane port pair | **open** | nothing has been measured against the target |
| IOMMU (VT-d) DMA confinement | **open** | bus-master DMA is unconfined. seL4 leaves the IOMMU *enabled* — Microkit's x86 default, recorded in the [update design](design/updates.md) — which is not the same thing: a device's writes are bounded only once that device is placed in an IOMMU domain, and none is |
| Full port role model (management, session-replication, mirror, multiple pairs) | **partial** | a dedicated management port exists, is addressed, answers ARP, ICMP echo and TCP, and is isolated from the dataplane; no other role does — [detail](developers/status-detail.md#full-port-role-model) |
| Hardware image variants (3/4/6/7-NIC) | **open** | one system description, `datad/systems/qemu-x86_64` |
| ixgbe (SFP+ 10 Gbit/s) driver | **open** | |
| Azure netvsc / MANA drivers, Azure NVA (GWLB, VXLAN) | **open** | |
| Proxmox and bare-metal targets | **open** | QEMU only |

## Recording and persistent storage

| Capability | Status | Notes |
|---|---|---|
| First-party virtio-blk driver | **partial** | now driving **two** devices from two domains that share no region: the recorder's recordings and the store's state record — [detail](developers/status-detail.md#virtio-blk-driver) |
| A persistent appliance identity | **partial** | minted on a fresh store medium and reloaded on every later boot, reported on the console as the device identifier and the SPKI fingerprint, and given up on a [factory reset](design/updates.md#factory-reset) asked for by writing one sector of that medium. What the record can hold and nothing yet writes: the delivered device certificate, the trust anchor, the management endpoint and the configuration slots — [detail](developers/status-detail.md#the-appliance-identity) |
| pcapng encoder | **partial** | `datad/crates/pcapng` writes SHB, IDB, EPB, ISB, Custom Block and a padding block, allocation-free, `no_std` and `forbid(unsafe_code)`, and `tcpdump` reads what it produces. The [recording design](design/recording.md)'s Decryption Secrets Block is not implemented, and of what is, only the blocks the recorder uses are exercised end to end — no ISB is emitted — described with the [recordings](developers/status-detail.md#recording-and-download) |
| Two pcapng recording sinks (a connection history and a capture) | **partial** | both are written to the device from the forwarder's tap and both parse as pcapng off the medium, and **they differ by what they record**: the history holds a record where the appliance reached a lifecycle or policy event, the capture holds every observation with its verdict, and each record carries the flow, the rule and the event as a PEN-tagged annotation. There is still no recording selector, so the capture records every frame the dataplane decided on rather than the flows a policy picks out, and a conversation reclaimed by its idle timeout produces no close event — [detail](developers/status-detail.md#recording-and-download) |
| Recording download over HTTP | **partial** | `GET /logs.pcapng` and `GET /capture.pcapng` answer a whole recording as a windowed body with an exact `Content-Length`; no `Range`, no `If-Match`, no way to ask for part of a recording, and **no TLS and no authentication in front of them**. The [management design](design/management.md) now replaces these downloads with range reads over the channel; they stay until it does — [detail](developers/status-detail.md#recording-and-download) |
| A recording that states its own loss in-band | **partial** | `epb_dropcount` is fed: the recorder differences the forwarder's tap-drop counter on every pass and carries the rise as a debt onto the next record placed, so a file does state the observations the tap ring lost ahead of each block. It states **only** those — what a sink could not encode and what the medium refused reach `/metrics` and never the file, and no Interface Statistics Block is emitted — see the [recording design](design/recording.md) |
| Paired ingress/egress observation of one forwarded frame | **open** | one observation per frame, taken at the decision point; `epb_packetid` is minted and monotone but never relates two records — see the [recording design](design/recording.md) |
| Recording the management port | **open** | only the dataplane is tapped, so nothing on the management port — including a download — is recorded |
| Retention bound and zeroization | **open** | the only bound is the ring's size; there is no time bound and nothing is erased on stop — see the [recording design](design/recording.md) |
| Rotation and checkpointing on a schedule | **open** | a superblock is written when the recorder decides to, never on a clock |
| Resuming a recording across a boot | **open** | `Sink::resume` exists and is host-tested; nothing calls it, so a reboot starts a fresh ring over the old bytes |
| Reader cursors in the ring superblock, one writer many readers | **open** | the superblock carries four reader-cursor slots and no reader registers one; the ring has exactly one reader, the download path. That is a named deviation from the [recording design](design/recording.md), whose cursor-holding reader is now the [management channel](design/management.md), and it is why no series says how much history a recording still holds: a wrap count says a segment was evicted and there is no cursor for it to have been evicted past |
| Registered Private Enterprise Number | **open** | the annotations are tagged `0xFFFFFFFF`, IANA-reserved so it cannot collide, but registered to nobody — a recording must not leave a customer's premises under it. Which party would hold one is itself unsettled — [detail](developers/status-detail.md#recording-and-download) |
| Storage binding from the configuration document | **open** | the extents are compiled into `lfw_recorder::deck` and the device is the whole of one disk; nothing resolves a partition and no configuration item names one — see the [configuration](design/configuration.md) and [recording](design/recording.md) designs |
| Decryption Secrets Block (inspected flow as ciphertext plus keys) | **open** | nothing is inspected, so there is no key material — see the [recording design](design/recording.md) |

## High availability

| Capability | Status | Notes |
|---|---|---|
| Active/passive pair, failover | **open** | per-environment mechanisms settled in the [deployment design](design/deployment.md) |
| Batched session-state replication | **open** | |
| Isolated HA state-sync protection domain | **open** | |

## Management, configuration and observability

| Capability | Status | Notes |
|---|---|---|
| Management HTTP API | **partial** | the API exists and carries the whole surface — `GET /metrics`, `GET /config`, `POST /config` and both recording downloads — over **plain HTTP with no authentication at all**. Anyone who can reach the port can read the policy and replace it, so the port must not be exposed to an untrusted network. The [management design](design/management.md) now erases this surface entirely in favor of the authenticated channel; it stays, exactly as insecure as stated, until the channel replaces it — [detail](developers/status-detail.md#full-port-role-model) |
| Schema-validated XML configuration, hardened validator PD | **partial** | [detail](developers/status-detail.md#configuration-management) |
| Candidate/commit-confirm transactions, versioning, rollback | **partial** | a document is submitted with `POST /config`, staged as the candidate, validated and committed under the next generation, and refusing one changes nothing; the candidate/running split and monotonic generations are what carry it. Neither **rollback** nor **commit-confirm** exists, so a change that validates and then breaks management connectivity is not undone by anything — [detail](developers/status-detail.md#configuration-management) |
| Distributed staged rollout across the pair | **open** | there is no pair; the handover protocol has one consumer |
| Console device and log transport (16550 COM1, one owning PD) | **partial** | [detail](developers/status-detail.md#console-device-and-log-transport) |
| Console system-state events | **partial** | [detail](developers/status-detail.md#console-system-state-events) |
| Structured log events and their transport | **open** | call sites emit typed events (`datad/crates/log`); the console is one rendering of them, and the record a domain publishes into its log ring is a second, already-structured one. Those call sites are the System category alone — audit and traffic events for the channel have no producers yet. **The OpenTelemetry export the design used to intend is superseded**: the [management design](design/management.md) erases OTEL from the appliance, and events travel the channel instead — which does not exist either, so the ring's only reader remains the download path. The [observability reference](reference/observability.md) still describes the OTEL surface and is retargeted in the phase that changes the surface, never before |
| Prometheus `/metrics` | **partial** | `GET /metrics` answers an exposition covering every protection domain, the capture tap and both recordings, with each NIC's counters joinable to the interface the configuration document names; scraped with `curl` in the gate against two different documents. The endpoint has **no mutual TLS and no bound on how often it may be asked**. Of the coverage the design intends, per-core counters await the multicore dataplane; the connection table publishes its own occupancy, lifecycle and every refusal, and the rest of the occupancy is half-published — each port's virtqueue depth is a gauge, and the dataplane's own queues and rings are not — and the log buffer's occupancy awaits the buffer — [detail](developers/status-detail.md#prometheus-metrics) |
| Local log buffer (`GET /logs`) | **open** | not to be confused with `GET /logs.pcapng`, which exists: that is the pcapng *connection history* on the block device ([detail](developers/status-detail.md#recording-and-download)), a different artifact on a different medium. Of the debug dump the [observability reference](reference/observability.md) describes, the state half, the running document and the recordings are what a node can be asked for; the retained records cannot be, and the reference's local-buffer inventory is empty |

## Management plane redesign

The two-component target — the channel, onboarding, the store, and the management server — measured
against what exists. The [contracts](contracts/configuration-package.md) the rows below implement
against are written; almost nothing that implements them is.

| Capability | Status | Notes |
|---|---|---|
| Outbound management channel | **partial** | the persistent mutually-authenticated connection of the [channel framing contract](contracts/channel-framing.md). **The appliance now dials**: on every boot the management domain opens one outbound session out of its own port — it resolves the next hop, dials, carries a fixed first-party probe, reads what comes back, closes, and reports the channel on the console whichever way it went — one record where it came up, and that record plus the counts that place the failure where it did not (below). A booted release image is held to the whole of that on both sides of the wire — and to how it **fails**, on four more boots whose station misbehaves in each of the four ways a management server or the link to it can: each reports the one outcome that misbehaviour produces, and the node goes on forwarding and counting throughout. **Every one of those failures is now diagnosable from the console alone**, which is the only debug surface a deployed node has: each distinct cause has a token of its own — a dead server, one refusing the port and one that is not speaking TCP correctly were a single token between them, and are three now — and a channel that failed adds three further records carrying the facts that place it, four where the station acknowledged a number that was never sent. **Missing:** everything above the transport. What crosses is ten bytes of probe and no protocol at all — no TLS, no authentication of either end, no framing, and nothing persistent: the session the cryptography domain proves against itself is still carried by nothing. The destination is a **constant compiled into that domain** rather than the endpoint the store holds — replacing it with the endpoint onboarding installs there is what comes next |
| Onboarding | **partial** | the HTTPS onboarding server, the CSR, the package upload and its tar reader ([contract](contracts/configuration-package.md)); the upload itself does not exist, and the unboarded/onboarded state machine has nowhere to be stored. **The port and the handover under it now do.** The management endpoint listens on a second TCP port of its own — not the plain-HTTP one — and carries a byte stream on it rather than a request and a response: one connection at a time, fixed arrays each way, and nothing in the crate that owns the network that interprets a byte. What arrives crosses to the domain that holds the keys over two regions with opposite grants — one connection at a time because there is no identifier in the ABI to name a second, no operation in it that asks for a plaintext, and no field in it a private key fits in — and that domain accepts the session, counts what crosses and closes. Every distinct way that path can fail has a console token of its own; both domains report each session's own account, and the close that ends a session carries **how** it ended, so a session the transport forgot is not reported as one the peer closed by the end that cannot see the wire. The port's own counts — connections accepted and lost, bytes a peer sent past its window, bytes an answer had no room for — reach the console beside each session and `/metrics` whether a session ever ended, and **the transport under it now reaches `/metrics` as well**, told apart from the HTTP server's stack by a `service` label rather than by a second set of families: a second administrator's handshake refused for want of the port's one slot used to move nothing any surface carried. An open is itself the end of any session the far end still believed in, so an answer this port gave up on costs one session rather than every session after it. **A booted release image is now held to that port on three boots**, one per way a session on it can end: a session an administrator finishes with, one a peer abandons by resetting after the appliance has acknowledged its payload, and a second connection opened while one is established — which an established connection is never given up for, so the appliance answers it with nothing at all and the boot carries one session rather than two. Each holds both domains' account of the one session to each other and to what the station on the wire actually sent, and the node goes on forwarding and counting to the byte throughout. **And the far end of that handover now terminates TLS.** The cryptography domain opens a TLS 1.3 server when the relay opens a session, drives it a delivery at a time and answers with what it produced, presents the appliance's own onboarding certificate taken from the domain that minted it, signs through the same key delegation the boot proof uses, and winds its bounded arena back at both ends of every session — so a peer that opens a thousand connections costs the region what one costs. **How each handshake ended reaches the console with the facts that ending holds**, which is the whole point: one token per cause and none standing for two — completed with its three code points, a peer that sent nothing, a peer that left part way, the alert a peer sent, the library's own incompatibility, a suite or group mismatch carrying what the peer really offered, this end's own refusal as the library's error variant, an exhausted arena, a direction that outgrew what it holds — with the library's two error vocabularies quoted whole rather than folded, so a client with no TLS 1.3 and one whose suites this appliance does not have are different lines. **A fourth boot proves it with clients this project did not write**: `openssl s_client` completes a handshake over `TLS_CHACHA20_POLY1305_SHA256` and `X25519MLKEM768` and is shown a certificate whose subject is the identifier the store domain printed on the same boot, and three more clients — one speaking only TLS 1.2, one offering a suite this appliance does not have, and one that connects and says nothing — each draw their own token. **And the read-only half of the onboarding protocol now runs above that record layer.** The session carries HTTP/1.1, and it serves exactly two things: `GET /` is a deliberately plain, unstyled page carrying the appliance's identifier and the SPKI fingerprint an administrator compares against the console, rendered exactly as the [certificate profile](contracts/certificate-profile.md) fixes it; and `GET /certificate.csr` is the PKCS#10 request that profile defines, subject common name the device identifier, **signed through the same key delegation** and composed **once at bring-up** rather than per request — so what an unauthenticated peer can provoke by asking for it is a copy of an array and never a signature in the domain that holds the key. Everything else is refused, and each of the twenty distinct ways a request can be refused has a console token of its own: the rate limiter, an identity that does not exist yet, an address nothing serves, a method nothing serves it under, a head that never ends, and the fifteen the request parser distinguishes. The endpoints are **rate-limited with backoff and never permanently locked out** — a burst of eight, an interval that doubles per consecutive refusal up to thirty-two seconds and no further, and a wait that always expires, because a lockout that did not would be a way to make an unonboarded appliance unonboardable from across a network. A fifth boot proves it with `curl`: five requests over one boot, every one pinned to the fingerprint the store domain printed on that same boot, the page holding that fingerprint and that identifier, the request read back through `openssl req` as a PKCS#10 whose subject is that identifier with its own signature verified, and three requests refused under three different tokens. **And the package an administrator carries back is now read**, though nothing yet takes delivery of one: a reader holds an uploaded archive to the whole of the [package contract](contracts/configuration-package.md) — uncompressed ustar only, the magic and version required, every GNU and PAX extension refused by its own type flag, regular files only, the four names compared byte for byte with no path prefix, every size field read as bounded octal and checked against the bytes present, every header checksum verified, exactly four members each exactly once — and then holds what they carry to its rules: the device certificate must bind **this appliance's own key**, taken from the one place in the certificate that binds it rather than found somewhere in its bytes; the endpoint must be an address literal and a port; and the document goes through the same configuration reader a document submitted any other way does. Whether the certificate chains to the delivered anchor is **not** decided there: it is an injected verifier the cryptography domain will supply out of the chain validator it already carries, and a package cannot be produced without that verifier having accepted — the type says so, not a comment. Nothing partial ever leaves: there is no way to hold a package that did not pass every rule. It is proved against a package **the management server itself produced**, committed as a fixture, and the server's own suite asserts its writer still reproduces that fixture byte for byte — so the two implementations of one format cannot drift apart without one of the two gates failing. **Missing:** `POST /configuration.tar` itself — nothing routes an upload to that reader and nothing installs what a package carries — which is why the page states the endpoint in a sentence rather than offering a form that would fail; the unboarded/onboarded state machine has nowhere to be stored, and closing the server permanently after onboarding has nothing to close on; and no scenario reaches the port's behaviour under a peer that overruns the window it was given, which a station speaking over a lossless host socket cannot play |
| Appliance identity | **partial** | **The appliance now has an identity that survives a reboot.** A store protection domain owns a block device of its own, and on a fresh medium it mints what the [certificate profile](contracts/certificate-profile.md) defines — 128 bits of device identifier from its own `RDRAND`-seeded generator, an ECDSA P-256 keypair, a self-signed onboarding certificate binding the two — writes all of it behind a device barrier, and reports the identifier and the SPKI fingerprint on the console. On every later boot it loads the same record, holds the three halves of the identity to each other, and reports that the same appliance returned. **Factory reset now takes that identity away**: a request written to one sector of the medium — the only path into a node with no shell, and one that needs the medium in hand — is cleared and made durable before every sector the layout claims is overwritten, and the appliance mints afresh and comes back unowned, having said on the console what it destroyed. Three QEMU scenarios share one medium: the second is held to the first's answer, which is the only shape a persistence claim has, and the third resets it and must come back a different, unowned appliance with the previous scalar occurring nowhere on the medium. **And the appliance now authenticates under that key without any other domain holding it.** The store domain keeps the keypair after establishing it and answers a signing delegation over two shared regions: the asking domain writes a request and reads an answer, the holder does the reverse, and neither ABI direction has a field a private scalar fits in — so the key cannot cross, which is a property of what the channel can express *together with* which domain may write which half. The cryptography domain proves it on every console-judged boot: it asks which key the holder has, has it sign a fixed challenge, verifies that signature against that key, takes the **onboarding certificate over that key** from the same domain and finds the very same public point inside it, and then runs the **server half of its TLS 1.3 session under the delegated key**, where `sign` is called synchronously inside the handshake. The certificate is fetched rather than reissued because an identity is a keypair with a certificate binding it and the store domain is the one that minted both; it is a public artifact, so the channel carries it without carrying anything secret. The gate holds the identifier that domain reports to the holder's own, character for character, requires the holder's signature tally to have moved across the session, and requires the certificate's size to be non-zero and the same on both records — one appliance having one certificate. **And the CSR over that key is now served**: the cryptography domain composes it once at bring-up, signing through the same delegation, and the onboarding surface hands it out — so the identifier on the console, the subject of the certificate a client validates, and the subject of the request an administrator carries to the management application are one string that a booted image is held to on all three. **Missing:** the device certificate and trust anchor an owner delivers have a place in the record and nothing delivers them, the configuration slot array is written by nothing, and the recorder's medium has no reset of its own |
| Hardware-accelerated cryptography | **partial** | Built and proven on the shipped image, symmetric and asymmetric both: a cryptography protection domain, compiled with the SIMD target, re-runs **154** published NIST CAVP, NIST ACVP, RFC 8439, RFC 6979 and Wycheproof vectors covering SHA-256, HMAC-SHA-256, HKDF-SHA-256, ChaCha20, ChaCha20-Poly1305, AES-256-GCM, the node's random bit generator, **ECDSA P-256, X25519 and ML-KEM-768**; measures each primitive's cost — per byte where it has a length, per operation where it does not; seeds the generator from `RDRAND`; and then **establishes a complete mutually-authenticated TLS 1.3 session with itself** over rustls and a first-party crypto provider, negotiating `TLS_CHACHA20_POLY1305_SHA256` and the hybrid `X25519MLKEM768`, validating both certificate chains against a trust anchor it issued, and carrying application data both ways. All of it is judged on every console-judged QEMU scenario, with the AES-256-GCM figure held below a ceiling no portable implementation reaches — and the whole of it now comes up **under emulation as well as on hardware**, which it did not before BMI2 was withdrawn from the target (below). The hardware draw, its health check and the generator behind it are now `lfw-crypto`'s rather than this domain's, because the store domain seeds its own from the same hardware by the same rules — each domain that holds key material seeds itself, a seed crossing a channel being reproducible at the other end. The domain carries the appliance's **only allocator**: a 2 MiB bounded arena, confined to it, whose exhaustion is a typed refusal that closes the session rather than a fault — proved on the image by a second, deliberately starved session that must be refused with the allocator's own refusal count still zero. The [cryptography profile](reference/crypto-profile.md) states all of it and is held to the target specification, the console vocabulary and the gate's own ceilings by the build. **The session's server half now authenticates under the appliance's real key, which lives in another protection domain.** The signing interface has a second implementation that forwards over a channel and returns the same bytes, so nothing above that line changed; the domain holds no scalar of any kind for that identity, and what crosses is a public point, a public name and signatures, because those are the only shapes the ABI has fields for. **Missing:** nothing dials with any of this — the appliance's own dial carries ten bytes of first-party probe and no TLS at all, the channel above it does not exist, and the onboarding server this domain now runs, with the request surface above it, speaks to an administrator's client rather than to a management server — so the boot's own session is still proved against this same build on both ends, and the client end and the anchor above both are still generated here, standing in for a management server this appliance has never spoken to. SHA-NI is not reachable on this target, for a reason the detail chapter records. Per-primitive cost comes off the image on every boot; what remains unmeasured is the whole-path throughput target, which needs bare metal and an external traffic generator rather than a guest |
| Persistent store | **partial** | the third virtio-blk device and the store domain exist, and the [double-buffered state record](design/configuration.md#persistence) is written and read back: two 4 KiB copies with a monotonic generation and a SHA-256 digest each, a whole-state write into one copy and a device flush behind it, so a power cut costs the newer copy and leaves the older decodable. `VIRTIO_BLK_F_FLUSH` is now negotiated on both block devices and the store's own commit waits for the flush to complete, as does the write that clears a [factory-reset](design/updates.md#factory-reset) request before the reset destroys anything. **Missing:** the configuration history — the slot array is in the record and nothing places a document in it — and a reset of the recorder's medium, which needs a layout decision rather than a repeat of the store's |
| Transport active open | **partial** | the TCP stack now opens connections: `SynSent`, a connect entry point, the simultaneous open, RFC 793's reset-not-a-state-change answer to an acknowledgement of something never sent, and an unanswered dial abandoned in silence at the retransmission limit. A neighbour cache exists beside it — bounded, expiring, learning only replies it asked for, and refusing to re-bind a resolved entry — held by unit, property and fuzz tests. Two of the three things dialling out needs are now built and unused: an **ARP request writer**, whose type cannot express a request addressed to a station this end has not resolved, and a **route decision** that answers on-link with the destination and off-link with the port's gateway, refusing anything else under its own typed cause and never handing back an address that is not a unicast station on this port's own link. The **configuration document can now state that gateway**: `<management>` carries one — an address, or the word `none` for a port that reaches only its own link — refused at load time if it is not unicast, is the port's own address, or lies off the port's prefix, and re-decided on the same three rules where it crosses into the handover image. It sits on `<management>` and not on `<interface>` because the management port is the only one that dials; a gateway on a dataplane interface would be a value nothing in this build reads. The **endpoint now uses all three**: it holds the gateway the committed document states, chooses a next hop with the route decision, asks for that next hop's hardware address with an ARP request, takes the reply into the cache under the cache's own three rules, and drives an outbound session — open to an address and port, carry a fixed request, read what comes back, close. A segment for a next hop that is not resolved yet is dropped under a typed reason rather than queued, the transport's own retransmission being what re-sends it, and the return path a dial uses comes from the resolution rather than from the frames its answer arrives in, so whoever answers cannot redirect what this end sends next. A session gives its connection back to the transport when it ends, whichever way it ended, so the next dial to the same address and port opens a genuinely new one — and what that release owes the peer follows from the state the connection stood in rather than from the call. **The management domain is now the caller.** Once its port is addressed it opens one session per boot to a first-party address and port, drives it on every wakeup, and reports the outcome — answered, or the typed reason it ended — in exactly one console record, with the counts that place a failure in further records beside it. Bounded by an attempt count of its own rather than by any elapsed time, so a slow station is a slow station and a silent one ends the channel after a fixed number of tries. A booted release image proves it from both sides at once: the appliance's own record, and a station on the wire that saw the resolution, answered it, accepted the connection, read the probe and answered it. **And the adversarial cases are now proved on a booted node too**, one boot each, against a station that answers the resolution and never the connection, one that resets it, one that answers a `SYN` by acknowledging a number that was never sent, and one that answers for an address nobody asked about. Each reports the one outcome its misbehaviour can produce, after the number of sessions the appliance's own bound allows — and in each the node stays healthy: the dataplane goes on forwarding through the whole boot, the management port reports every frame put on its wire to the byte, and neither the appliance's attempt count nor its retransmission budget is exceeded. The neighbour cache's eight counters and the outbound half's nine now reach `/metrics` beside the transport's. The dial's own vocabulary is 13 outcomes, one per distinct cause, and a failing channel reports beside it where its frames were sent and which part of the addressing chose that, how many requests the resolution spent and what it learned, how many replies the port turned away and why, how many handshakes went out, whether anything came back at all, the resets in each direction, and — where a station claimed a sequence number that was never sent — that number against the one really sent. **Missing:** the destination is a constant compiled into the domain rather than the endpoint the store holds, and nothing retries after the channel is decided |
| Configuration over the channel | **open** | stage, validate, commit with confirmation over a fresh connection, rollback, and the version history — the operations exist today only as `POST /config`'s single stage-validate-commit step |
| Management server (`ctrld`) | **partial** | an administrator can sign in and onboard an appliance end to end: the server is its own certificate authority with its signing keys sealed in Postgres under an environment-supplied key, it validates an uploaded PKCS#10 request against the [certificate profile](contracts/certificate-profile.md), issues a device certificate, and hands back an onboarding [package](contracts/configuration-package.md) whose bytes `tar` and `openssl` verify. Local accounts, an inventory with an honest status, and an audit trail exist; the ClickHouse telemetry schema and its writer exist with no producer. **No channel listener and no pcapng decoder**, so nothing has ever connected — and the web interface is plain HTTP — [detail](developers/status-detail.md#management-server) |
| Erasing the HTTP management surface | **open** | deliberately last: the end-to-end gate's cross-check strategy — metrics against recordings against injected frames — rests on the HTTP surfaces, so they are removed only once the channel carries a replacement cross-check |

## Lifecycle, boot and trust

| Capability | Status | Notes |
|---|---|---|
| Signed A/B disk image and slot selection | **partial** | [detail](developers/status-detail.md#ab-image-update) |
| Signature-enforced boot chain (OVMF → GRUB → Multiboot2 → seL4) | **partial** | [detail](developers/status-detail.md#signed-boot-chain) |
| In-system update/health protection domain | **open** | nothing inside seL4 holds a capability on the **boot** disk, so nothing can write boot state. The recorder's block device is a second, data-only disk and reaches no partition of the boot one — [detail](developers/status-detail.md#ab-image-update) |
| Configuration, identity or secrets on persistent storage | **partial** | **identity yes, configuration not yet.** Two domains now hold a disk capability, on two separate devices that neither reaches the other's: the recorder writes recordings and the store domain writes the appliance's own state record, which carries the device key. The [store device and store domain](design/updates.md#the-store-device) the design intends exist; the configuration history in that record is written by nothing, and the DATA partition of the *boot* disk is still an empty unformatted GPT entry — [detail](developers/status-detail.md#configuration-management) |
| UEFI Secure Boot enrolment | **open** | manifest records `secure_boot: false` |
| TPM-backed anti-rollback | **open** | no TPM anywhere, including the QEMU harness |

## Architecture and assurance

| Capability | Status | Notes |
|---|---|---|
| Pure-Rust userspace | **done** | the only C is the seL4 kernel and its boot chain |
| Least-privilege PD decomposition | **partial** | [detail](developers/status-detail.md#protection-domain-decomposition) |
| Untrusted-device hardening | **partial** | [detail](developers/status-detail.md#untrusted-device-hardening) |
| Untrusted-peer (byzantine neighbour) containment | **partial** | [detail](developers/status-detail.md#untrusted-peer-containment) |
| PD fault handling and restart | **open** | a rejected bring-up parks its domain; nothing restarts it, and there is no fault handler |

## Open decisions and known risks

The design chapters record the settled target picture. The following are, respectively, decisions
not yet made and known risks. They are recorded here so they are not mistaken for oversights.

### Open decisions

- **CA signing-trust sharing across HA nodes** — required; the form (e.g. per-node intermediate CAs
  under a common trusted root) is open. This is the TLS-*interception* CA; the device-issuing CA is
  settled — it is the [management server](design/management-server.md).
- **CA rollover for the management CA.** The [non-remotable trust anchor](design/threat-model.md#the-compromised-management-server)
  makes remote anchor rotation impossible, so rotating the management CA means visiting every
  appliance. Two directions exist — carrying two anchor slots and permitting the *addition* of a
  second while the current one is valid (reversible, therefore not self-harming), never the removal
  of the last; or deferring entirely. Deferred, because there is no fleet yet; this is the one item
  that control is expected to force a revisit of.
- **HA-link split-brain arbitration** — witness, quorum, or fencing.
- **Trusted time source mechanism** for the inspection path. The management channel deliberately
  judges its certificates against the CMOS-derived clock (a recorded decision in the
  [threat model](design/threat-model.md)); validating upstream certificates on behalf of protected
  clients still needs a genuinely trusted source, and that mechanism is open.
- **Proxy vs. cut-through throughput split** — the proportion of traffic on the terminating proxy
  path, which drives core sizing.
- **Access control and multi-admin concurrent editing in the management server** — roles and scopes
  over appliances and policy subtrees, and the concurrent-editing model (changeset review with
  semantic merge, or a live shared candidate with presence).
- **Whether anything replaces CI.** The pipeline definition is deleted and the git hooks are the
  whole gate; no replacement has been decided.

### Known risks

- **x86_64 seL4/Microkit maturity.** x86_64 on Microkit is recent (added in 2.1.0, November 2025)
  and exposes only generic/QEMU platforms (no dedicated x86 hardware board); x86_64 with
  SMP is the least-exercised seL4 configuration.
- **No existing 10 Gbit/s or x86 NIC driver.** The public sDDF tree contains only virtio and
  Arm-SoC drivers; all NIC drivers (virtio, SFP+ 10G, netvsc, MANA) are implemented from scratch in
  Rust.
- **TCP stack effort.** Building a first-party proxy TCP stack is a substantial effort, and it
  is larger than the one an adopted stack would have left: the correctness of a transport under
  hostile input, and the years of exposure that establishes it, are what adopting one buys and
  writing one forgoes. SACK, congestion control, and scaling to many concurrent proxied connections
  at 10 Gbit/s are each ahead. The trade is deliberate — that effort against a copy per segment —
  and naming it does not reduce it.
- **Pure-Rust signature matching at line rate.** Whether the pure-Rust `aho-corasick` /
  `regex-automata` engines sustain line rate with a realistic ruleset is unproven and needs an
  early benchmark (as does the crypto provider).
- **Azure platform scope.** Azure support requires Hyper-V/VMBus (for netvsc), the MANA driver,
  Gateway Load Balancer VXLAN handling, and seL4 booting as an Azure guest — a substantial platform
  effort, not a single NIC driver.
- **SHA-NI is unreachable on this target, and the same mechanism is what keeps AVX out.** The
  adopted hash library selects its SHA-NI backend through a runtime feature probe that compiles to
  a constant `false` on a freestanding target, so SHA-256 runs the portable implementation whatever
  the processor offers. Making that probe run would also make the AVX probes in the cipher
  libraries run, and those must not: the pinned kernel does not save the wide vector state, so an
  AVX instruction in a protection domain is silent corruption rather than a fault. The build now
  asserts the absence by disassembling the shipped domains — both the wide registers and, since the
  BMI2 withdrawal below, the vector encoding itself. Recovering SHA-NI without recovering
  AVX needs either a per-crate way to force the backend or a wider kernel save area, and neither is
  in scope; the cost is one primitive running at roughly a tenth of its accelerated rate, measured
  and reported on every boot.
- **BMI2 was withdrawn from the SIMD target, and the image is now proved on both accelerators.**
  The three-tier hardware profile placed ADX and BMI2 in a "free" tier on the reasoning that
  general-purpose-register instructions carry no saved vector state. That is true of the register
  file and false of what matters: BMI2 is **VEX-encoded**, and an emulated processor refuses a
  VEX-encoded instruction — the general-purpose ones included — unless the guest has *enabled* the
  vector state, which a kernel saving only x87 and SSE state never does. Real parts do not enforce
  that, so the image ran under KVM and took an invalid-opcode fault under emulation, inside the
  P-256 scalar multiplication, on a guest whose `CPUID` advertised BMI2 and whose feature gate had
  passed. An acceleration only one of the two accelerators can execute is one the gate cannot
  prove, and a verdict that depends on the machine it ran on is not a verdict — so BMI2 is
  disabled, the guest CPU model no longer advertises it, and neither domain's `CPUID` gate demands
  it. ADX stays: it is legacy-encoded and unaffected, though this build currently emits no `adcx`
  or `adox` instruction, so the requirement is presently a permission rather than a use. The cost
  is a few per cent on X25519 and ML-KEM-768 and nothing measurable on ECDSA P-256, reported on the
  [cryptography profile](reference/crypto-profile.md). The build now refuses the whole encoding
  rather than the feature: it reads the raw bytes of every instruction in the shipped protection
  domains and fails on any VEX or EVEX prefix, which cannot go stale the way a list of mnemonics
  would. And what keeps "proved on both" true is a boot rather than a check: one scenario is forced
  onto the emulator whatever the machine offers, and judges this domain there.
- **The physical address window is measured, and the store domain has now spent from it.**
  Nineteen regions carry a fixed physical address inside RAM, claiming 1092 KiB and packed into
  `0x30000000..0x3110D000` — so RAM must reach past **785.05 MiB**, and under the harness's 1 GiB it
  does with **238.95 MiB** to spare; the upper bound is unchanged, RAM having to stay below the
  `0x50000000` device window at 1280 MiB. The two regions added are the store device's virtqueue
  page and its staging window — 4 KiB and 256 KiB, the second being `lfw_blk`'s grant for the block
  device class rather than this domain's appetite, whose whole record is eight sectors. Its
  configuration page and relocated BAR sit outside RAM in the ECAM and PCI-hole windows, which are
  nowhere near full. **None of the cryptography domain's four regions is in that count**, the 2 MiB
  arena included: nothing reads them by physical address, so they are ordinary untyped memory. The
  window is not what constrains the next phase; it is still unasserted, and that is unchanged.
- **The post-quantum primitive is RustCrypto `ml-kem`, and the architecture chapter now names it.**
  `libcrux-ml-kem` — formally verified, and the first choice while it was still a hypothesis — was
  investigated and **does build** cleanly for this target, portable path and all. What it costs is
  the dependency policy: a transitive crate of its own takes an unconditional dependency on a
  random-number crate a major version ahead of the one the elliptic-curve crates here already use,
  which puts two versions of it in the graph — a duplicate the policy denies — and it pulls a libc
  binding into an appliance that has no libc. RustCrypto `ml-kem` is audited, FIPS 203 final, and
  costs no exception at all, so it is what is adopted. The formal-verification assurance is the
  price paid, and recovering it needs upstream to loosen that dependency.
- **The TLS session is proved against itself, which is the strongest proof available before there
  is a network.** Both ends of the handshake are in the cryptography domain, over a transport that
  is two buffers, so what is proved is the whole stack — hybrid key exchange, signature, chain
  validation, key schedule, record layer, mutual authentication, clean close. What is *not* proved
  is anything about interoperating with a peer that is not this build: a second implementation on
  the other end is the first thing the channel milestone establishes.
- **Hardware cryptography's foundational hypothesis is verified; two narrower ones remain.** The
  pinned kernel saves x87 and SSE state per thread, so the XMM instruction sets the
  [CPU baseline](design/architecture.md#hardware-cryptography-profile) requires — AES-NI,
  PCLMULQDQ, SHA-NI — are architecturally available; what disabled them was a generated default in
  the shipped target specifications. The hardware-probe protection domain — built with a
  first-party hardfloat, SSE-enabled target — now proves on every console-judged QEMU boot that
  such a domain builds and boots on Microkit, that `AESENC` and `PCLMULQDQ` execute and answer
  their known answers, and that a live XMM value survives the kernel's context switches. Still
  hypotheses, to resolve in the crypto milestone: whether the IPC fastpath preserves XMM across a
  *domain boundary* (the probe holds no channel, so its preemptions exercise the context switch and
  not the fastpath), and whether a domain can be opted out of paying for FPU state it does not use.
  AVX and AVX2 are genuinely unavailable without building the kernel ourselves, and are deferred —
  and BMI2 has joined them there, for the encoding reason recorded above rather than for the saved
  state.
- **Full-rate capture of everything is not reachable, and the recording selector is the sizing
  control.** A capture sink recording all traffic at the target rate (see the
  [recording design](design/recording.md)) would have to sustain writes at the dataplane's own
  rate, which no practical device does and which would consume the medium's write endurance in
  short order. The sink is therefore sized by the selector that decides what reaches it — not by
  the filter rules, which decide what is forwarded — and a selector drawn too broadly yields loss. The loss is reported in-band and is measurable rather than silent,
  which is the mitigation available — but it remains loss, and choosing a selector narrow enough is
  an operational discipline the appliance can measure and cannot impose.
- **The throughput target and the recording sinks compete for one memory-bandwidth budget.**
  Copying frames into a ring and writing them out draws on the same bandwidth the inspection path
  is already sized to consume. How much recording the target rate can carry is unmeasured, and
  it is the class of cost that does not appear until both run at once — so it belongs to the same
  early benchmarking as the crypto provider and the signature engines.
