# Development status

Statuses are **done**, **partial**, or **open**. Every *partial* capability is broken down
further — what exists and what specifically remains — in the developer chapter,
[Implementation status in detail](developers/status-detail.md), so the work can be picked up
without re-deriving it from the code. This page is the evaluator's view: what the appliance does
today, what it does not, and where the project is heading.

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
what this firewall forwards. Until the intended mTLS termination and certificate handling exist, the
management port belongs on an isolated network and nowhere else. The port's MAC, address and prefix
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
| L7 protocol parsing (HTTP/1.1, HTTP/2, HTTP/3) | **partial** | a server-side HTTP/1.1 request parser (`crates/http`) reads the management port's requests; it is a bounded head parser with no body, no HTTP/2 and no HTTP/3, and no dataplane consumer — described with the [`/metrics` endpoint](developers/status-detail.md#prometheus-metrics) |
| OT/industrial protocol inspection | **open** | |
| DoS resilience (SYN cookies, rate limiting, bounded state) | **open** | this row is about the dataplane and the proxy, where nothing exists. **Nothing bounds the rate of requests to the management port either** — the [management design](design/management.md) asks it to, and the only rate bound anywhere in the appliance is RFC 5961 §7's per-second challenge budget, which caps unsolicited TCP replies and not requests. What does exist is bounded *state*: the transport's connection table is fixed and reaped under pressure — [detail](developers/status-detail.md#proxy-tcp-stack) |
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
| Proxy TCP stack | **partial** | a first-party passive-open stack carries a real connection on the management port, and it is the stack the dataplane proxy will run on; no active open, no SACK, no congestion control, and no dataplane consumer — [detail](developers/status-detail.md#proxy-tcp-stack) |
| 10 Gbit/s per dataplane port pair | **open** | nothing has been measured against the target |
| IOMMU (VT-d) DMA confinement | **open** | bus-master DMA is unconfined. seL4 leaves the IOMMU *enabled* — Microkit's x86 default, recorded in the [update design](design/updates.md) — which is not the same thing: a device's writes are bounded only once that device is placed in an IOMMU domain, and none is |
| Full port role model (management, session-replication, mirror, multiple pairs) | **partial** | a dedicated management port exists, is addressed, answers ARP, ICMP echo and TCP, and is isolated from the dataplane; no other role does — [detail](developers/status-detail.md#full-port-role-model) |
| Hardware image variants (3/4/6/7-NIC) | **open** | one system description, `systems/qemu-x86_64` |
| ixgbe (SFP+ 10 Gbit/s) driver | **open** | |
| Azure netvsc / MANA drivers, Azure NVA (GWLB, VXLAN) | **open** | |
| Proxmox and bare-metal targets | **open** | QEMU only |

## Recording and persistent storage

| Capability | Status | Notes |
|---|---|---|
| First-party virtio-blk driver | **partial** | [detail](developers/status-detail.md#virtio-blk-driver) |
| pcapng encoder | **partial** | `crates/pcapng` writes SHB, IDB, EPB, ISB, Custom Block and a padding block, allocation-free, `no_std` and `forbid(unsafe_code)`, and `tcpdump` reads what it produces. The [recording design](design/recording.md)'s Decryption Secrets Block is not implemented, and of what is, only the blocks the recorder uses are exercised end to end — no ISB is emitted — described with the [recordings](developers/status-detail.md#recording-and-download) |
| Two pcapng recording sinks (a connection history and a capture) | **partial** | both are written to the device from the forwarder's tap and both parse as pcapng off the medium, and **they differ by what they record**: the history holds a record where the appliance reached a lifecycle or policy event, the capture holds every observation with its verdict, and each record carries the flow, the rule and the event as a PEN-tagged annotation. There is still no recording selector, so the capture records every frame the dataplane decided on rather than the flows a policy picks out, and a conversation reclaimed by its idle timeout produces no close event — [detail](developers/status-detail.md#recording-and-download) |
| Recording download over HTTP | **partial** | `GET /logs.pcapng` and `GET /capture.pcapng` answer a whole recording as a windowed body with an exact `Content-Length`; no `Range`, no `If-Match`, no way to ask for the *time range* the [management design](design/management.md) does ask for, and **no TLS and no authentication in front of them** — [detail](developers/status-detail.md#recording-and-download) |
| A recording that states its own loss in-band | **partial** | `epb_dropcount` is fed: the recorder differences the forwarder's tap-drop counter on every pass and carries the rise as a debt onto the next record placed, so a file does state the observations the tap ring lost ahead of each block. It states **only** those — what a sink could not encode and what the medium refused reach `/metrics` and never the file, and no Interface Statistics Block is emitted — see the [recording design](design/recording.md) |
| Paired ingress/egress observation of one forwarded frame | **open** | one observation per frame, taken at the decision point; `epb_packetid` is minted and monotone but never relates two records — see the [recording design](design/recording.md) |
| Recording the management port | **open** | only the dataplane is tapped, so nothing on the management port — including a download — is recorded |
| Retention bound and zeroization | **open** | the only bound is the ring's size; there is no time bound and nothing is erased on stop — see the [recording design](design/recording.md) |
| Rotation and checkpointing on a schedule | **open** | a superblock is written when the recorder decides to, never on a clock |
| Resuming a recording across a boot | **open** | `Sink::resume` exists and is host-tested; nothing calls it, so a reboot starts a fresh ring over the old bytes |
| Reader cursors in the ring superblock, one writer many readers | **open** | the superblock carries four reader-cursor slots and no reader registers one; the ring has exactly one reader, the download path. That is a named deviation from the [recording design](design/recording.md), and it is why no series says how much history a recording still holds: a wrap count says a segment was evicted and there is no cursor for it to have been evicted past |
| Live event stream, OTEL and syslog exporters as ring readers | **open** | see the [management](design/management.md) and [recording](design/recording.md) designs |
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
| Management HTTP API over mTLS | **partial** | the API exists and carries the whole surface — `GET /metrics`, `GET /config`, `POST /config` and both recording downloads — over **plain HTTP with no authentication at all**. Anyone who can reach the port can read the policy and replace it, so the port must not be exposed to an untrusted network; the mTLS pair, the authorization split and the request-rate bound the [management design](design/management.md) requires are all absent — [detail](developers/status-detail.md#management-http-api) |
| Schema-validated XML configuration, hardened validator PD | **partial** | [detail](developers/status-detail.md#configuration-management) |
| Candidate/commit-confirm transactions, versioning, rollback | **partial** | a document is submitted with `POST /config`, staged as the candidate, validated and committed under the next generation, and refusing one changes nothing; the candidate/running split and monotonic generations are what carry it. Neither **rollback** nor **commit-confirm** exists, so a change that validates and then breaks management connectivity is not undone by anything — [detail](developers/status-detail.md#configuration-management) |
| Distributed staged rollout across the pair | **open** | there is no pair; the handover protocol has one consumer |
| Console device and log transport (16550 COM1, one owning PD) | **partial** | [detail](developers/status-detail.md#console-device-and-log-transport) |
| Console system-state events | **partial** | [detail](developers/status-detail.md#console-system-state-events) |
| OpenTelemetry structured logs | **open** | call sites emit typed events (`crates/log`); the console is one rendering of them, and the record a domain publishes into its log ring is a second, already-structured one. Those call sites are the design's **System** category alone — Audit, Traffic and Subsystem have none. No transport, exporter or receiver exists, so the OpenTelemetry inventory in the [observability reference](reference/observability.md) is empty, and the exporter the [management design](design/management.md) makes a reader of the recording ring is not one of the ring's readers either — it has none but the download path |
| Prometheus `/metrics` | **partial** | `GET /metrics` answers an exposition covering every protection domain, the capture tap and both recordings, with each NIC's counters joinable to the interface the configuration document names; scraped with `curl` in the gate against two different documents. The endpoint has **no mutual TLS and no bound on how often it may be asked**. Of the coverage the design intends, per-core counters await the multicore dataplane; the connection table publishes its own occupancy, lifecycle and every refusal, and the rest of the occupancy is half-published — each port's virtqueue depth is a gauge, and the dataplane's own queues and rings are not — and the log buffer's occupancy awaits the buffer — [detail](developers/status-detail.md#prometheus-metrics) |
| Local log buffer (`GET /logs`) | **open** | not to be confused with `GET /logs.pcapng`, which exists: that is the pcapng *connection history* on the block device ([detail](developers/status-detail.md#recording-and-download)), a different artifact on a different medium. Of the debug dump the [observability reference](reference/observability.md) describes, the state half, the running document and the recordings are what a node can be asked for; the retained records cannot be, and the reference's local-buffer inventory is empty |

## Lifecycle, boot and trust

| Capability | Status | Notes |
|---|---|---|
| Signed A/B disk image and slot selection | **partial** | [detail](developers/status-detail.md#ab-image-update) |
| Signature-enforced boot chain (OVMF → GRUB → Multiboot2 → seL4) | **partial** | [detail](developers/status-detail.md#signed-boot-chain) |
| In-system update/health protection domain | **open** | nothing inside seL4 holds a capability on the **boot** disk, so nothing can write boot state. The recorder's block device is a second, data-only disk and reaches no partition of the boot one — [detail](developers/status-detail.md#ab-image-update) |
| Configuration, identity or secrets on persistent storage | **open** | one domain now holds a disk capability, but it writes recordings and nothing else; the DATA partition is still an empty unformatted GPT entry with no consumer and no encryption — [detail](developers/status-detail.md#configuration-management) |
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

- **Onboarding process** for issuing the management mTLS certificate pair — required; its design is
  open.
- **TLS crypto provider** for rustls (pure-Rust vs. an external provider), to be resolved by
  benchmarking.
- **CA signing-trust sharing across HA nodes** — required; the form (e.g. per-node intermediate CAs
  under a common trusted root) is open.
- **HA-link split-brain arbitration** — witness, quorum, or fencing.
- **Trusted time source mechanism.**
- **Proxy vs. cut-through throughput split** — the proportion of traffic on the terminating proxy
  path, which drives core sizing.
- **Central configuration management application** (multi-cluster) — built later.

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
- **FPU/SIMD in protection domains.** Dataplane PDs run without FPU/SSE state. Sustaining
  checksums, crypto, and DPI at 10 Gbit/s will require either kernel-supported FPU context for the
  relevant PDs or staying scalar — a design constraint to resolve when performance work begins.
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
