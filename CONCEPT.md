# librefirewall — Concept & Target Picture

This document describes the agreed target picture for **librefirewall**: a high-performance,
deeply-inspecting network firewall appliance built on the seL4 microkernel and Rust. It records
what the solution *is* — the settled design decisions and the principles behind them — and, in
§13, the topics that are deliberately still open and the known risks. It is the shared reference
for anyone (human or agent) working on the project.

---

## 1. Overview

librefirewall is a network firewall / security gateway that performs full deep packet inspection
(DPI) across ISO layers 2 through 7, including TLS interception and inline content scanning. It is
built on the **seL4 microkernel** and written in **Rust**, and it uses seL4's capability-based
isolation to compartmentalize data flows as strongly as possible. It is a defensive-security
appliance for the operator's own infrastructure, spanning use cases from **operational technology
(OT)** environments through to **web filtering**.

---

## 2. Purpose and Scope

- **Full inspection across all relevant layers**, from L2 addressing through L7 application
  protocols, with TLS interception and inline content scanning.
- **Usable across the full range from OT to the web**: it protects industrial/OT environments
  (e.g. factory networks built on PLCs and PROFINET) as well as corporate networks, data centers,
  colocations, and cloud environments.
- **Deployed at network/zone boundaries.** In OT contexts it is an **upstream IT/OT gateway** at
  the zone boundary — it does not sit inline within the industrial control loop (e.g. not between
  two PROFINET participants).
- It is legitimate for the appliance to filter any traffic crossing the boundary it protects,
  including tenant traffic; inspecting traffic to protect systems and data is its core function.

---

## 3. Guiding Principles

- **Pure-Rust stack.** All first-party code is written in Rust for memory safety, especially on the
  parsing and filtering paths that constitute the appliance's attack surface. The only C in the
  system is the seL4 kernel and its boot/loader chain, which are the trusted, high-assurance base
  the system builds on.
- **seL4 capability isolation as the primary security mechanism.** The system is decomposed into
  many small, least-privilege protection domains (PDs) whose authority is enforced at runtime by
  the kernel. Isolation of data flows is maximized.
- **Correctness through a minimal, high-assurance base — not dependence on whole-system formal
  verification.** The value of seL4 here is a tiny, well-tested kernel, runtime-enforced capability
  isolation, and the discipline of a static component model. Formal verification of the complete
  system is not a project goal.
- **Minimal attack surface.** No user interface; isolated components; hardened input handling;
  the smallest possible trusted paths.
- **x86_64 only.** The system targets x86_64 exclusively and makes no accommodations for other
  architectures.

---

## 4. Performance Target

The target is **10 Gbit/s of sustained, fully-inspected, inline throughput per dataplane port
pair, in each direction, with low and predictable added latency**, on a single modern multi-core
x86_64 machine. The scope is deliberately this class of throughput — not higher (e.g. 100 Gbit/s)
classes. A deployment may carry more than one dataplane port pair (§9); the per-pair figure is the
unit the architecture is sized against.

**Inline TLS threat prevention is the costliest path, and it is what sizes the system.**
Terminating TLS (and QUIC), re-originating it, and scanning the plaintext inline dominates the
compute budget — far above L2–L4 forwarding — so the crypto provider, the proxy TCP/TLS stacks, and
the streaming inspection engines are chosen and laid out around sustaining *that* path at the
target rate. Every architectural decision below is made in that light.

This is achieved through:

- a **multicore dataplane**;
- **RSS (symmetric hashing)** that steers each flow to a fixed core; both directions of a flow, and
  **both legs of a proxied connection**, are kept on the same core (the re-originated leg's tuple
  is chosen so that RSS maps it to the core that owns the flow);
- **per-core, shared-nothing flow shards** (no cross-core locking on the hot path);
- a **zero-copy dataplane** with **batched notifications** that keeps the hot path out of the
  kernel; and
- **streaming inspection** on the inline inspection path, so line-rate-inspected traffic is not
  buffered end-to-end. (Full-object content scanning, which necessarily buffers, is handled
  separately and selectively — see §5.)

Latency is kept low and predictable: forwarded/cut-through traffic (including OT and pass-through
traffic) incurs minimal, predictable added latency suitable for soft-real-time OT; TLS/L7-inspected
traffic is proxied (terminated and re-originated) and incurs only the small additional latency
inherent to termination. The proportion of total throughput that traverses the proxy path versus
the cut-through path — which drives core sizing — is an open item (§13.1).

---

## 5. Inspection Scope by Layer

| Layer | Coverage |
|---|---|
| **L2** | MAC addresses, VLAN (802.1Q) |
| **L3** | IPv4, IPv6 |
| **L4** | TCP, UDP, ICMP (and further L4 protocols) |
| **L5/6** | TLS — via interception/termination |
| **L7** | HTTP, HTTPS, HTTP/2, HTTP/3, QUIC |
| **OT** | Industrial protocols (e.g. PROFINET) at the IT/OT boundary |
| **Content** | Inline content scanning |

**TLS, QUIC and HTTP/3 are inspected by terminating them.** They cannot be inspected passively, so
the appliance acts as a man-in-the-middle endpoint (terminate and re-originate) for flows that are
to be inspected at these layers.

**Inline content scanning** is performed in two forms: streaming signature/pattern matching applied
inline at line rate, and deeper full-object scanning handled by a dedicated, isolated scanner
component (an ICAP-style separation of the scanner from the dataplane). Full-object scanning
necessarily buffers the object before reaching a verdict, so it is applied **selectively and with
bounded buffers** and does not sit on the line-rate streaming path.

---

## 6. System Architecture

### 6.1 Foundation

The system is built on **seL4** with the **Microkit** static component model and an **sDDF-style
dataplane** (zero-copy shared-memory queues between protection domains). Components are protection
domains (PDs) connected only by explicit zero-copy queues and notification channels; packets move
by descriptor, not by copy. Notifications are batched so the hot path stays out of the kernel.

The architecture follows, conceptually, the seL4 sDDF/Microkit networking component model (as
demonstrated by the LionsOS firewall example). librefirewall does **not reuse that code**: it is
implemented from scratch in Rust, including a Rust implementation of the sDDF lock-free
single-producer/single-consumer queue protocol.

Because Microkit's component model is **static**, the system's structure — every PD, memory
region, capability, and hardware address (MMIO windows, DMA regions) — is fixed at build time in
the system description rather than discovered at runtime. Hardware addressing is therefore a
build-time pinning problem, not a runtime probing one, and adding *hardware* (another NIC) is a
rebuild. Everything above the hardware — including whether a present interface is used at all — is
runtime configuration (§12.3).

### 6.2 Two data paths

A **classifier** steers each flow to one of two paths:

- **Cut-through (non-terminating) path** — stateful L2–L4 filtering, OT/industrial traffic, and
  pass-through traffic. Minimal, predictable latency. Flow state on this path is synchronized for
  High Availability.
- **Terminating proxy path** — TCP, TLS and QUIC are terminated and re-originated; L7 protocols are
  parsed; content is inspected. Used for TLS/L7 inspection and web filtering.

### 6.3 Component decomposition

The dataplane and control plane are decomposed into isolated PDs, each with least authority,
connected by zero-copy queues. Representative components:

- **NIC driver PD(s)** — one per network interface.
- **Rx/Tx virtualisers** — demultiplex and multiplex traffic between drivers and the processing
  components.
- **Classifier** — selects the data path per flow.
- **Stateful filter / connection-tracking PDs** — L2–L4 filtering and flow state.
- **Routing / ARP / ICMP PDs** — for routed/gateway operation.
- **TLS/proxy PDs** — terminate and re-originate TCP/TLS (and QUIC) on the proxy path.
- **L7 parser PDs** — per-protocol application parsing, each isolated.
- **DPI / signature engine** — streaming pattern matching.
- **Content scanner PD** — isolated, for deeper full-object scanning.
- **CA signing-key PD**, **management API PD**, **configuration validator PD**, **HA state-sync
  PD** — see the respective sections.

### 6.4 Operating posture

A dataplane port pair operates in one of **two modes**, selected by configuration:

- **Routed gateway.** The appliance is an L3 hop: it holds addresses, provides routing/ARP/ICMP
  (§6.3), performs address translation (§6.5), terminates the proxy path as an endpoint, and is
  placed as an upstream IT/OT gateway in OT contexts. This is the mode Azure requires, where the
  appliance is a routed Network Virtual Appliance (§9).
- **Virtual wire (bump-in-the-wire).** The two ports of a pair are strictly bound to each other: the
  appliance holds no address on the path and makes no forwarding decision, so everything arriving on
  one port leaves on the other unless policy drops it. VLAN tags pass through untouched.

Virtual wire exists because it is frequently the *only* deployable mode, above all in OT. An
industrial network usually cannot be re-addressed, and inserting a routed hop splits the L2
broadcast domain, which breaks the link-local discovery and control protocols those environments
depend on (PROFINET DCP, LLDP, and similar). A bump-in-the-wire requires no change to any PLC, HMI,
or engineering station. The same property makes it the way to retrofit inspection into an existing
IT network without renumbering it.

**A transparent learning bridge is deliberately out of scope.** MAC learning turns the appliance
into a switch and brings loop, STP, and BPDU handling with it — switch concerns that add
significant risk in an inline security device and, in an HA pair, a loop hazard. The strict
port-pair binding of virtual wire delivers the transparency that matters without any of it.

### 6.5 Address translation

The appliance performs **NAT** on the routed path: source NAT (including masquerading behind an
interface address), destination NAT (port forwarding), and static 1:1 mappings. NAT is not an
independent stage but a property of a tracked flow, which imposes three couplings:

- The translation binding **lives in the connection-tracking entry** (§6.3); creating a flow and
  choosing its translation are one decision.
- NAT bindings are part of the state **replicated for High Availability** (§10) — without them,
  every translated session breaks on failover even though its flow state survived.
- On the proxy path, the re-originated leg's tuple is already constrained so that RSS maps it to the
  core owning the flow (§4). Translation must respect that constraint rather than compete with it.

Virtual-wire mode performs no translation, by construction.

---

## 7. Threat Model & Isolation

### 7.1 Assets, adversaries, and trust boundaries

The design starts from what must be protected, who the attacker is, and where the trust boundaries
lie.

**Assets**, in rough order of value: the TLS-interception **CA signing key**; the **running
configuration** and management credentials; **flow and connection state** (including per-connection
TLS material on the proxy path); and the **packet buffers** in flight.

**Adversaries the design assumes:**

- **Untrusted network traffic** on every dataplane port — arbitrary, adversarial bytes at line
  rate. This is the primary attack surface and the reason every parser is memory-safe and isolated.
- **A hostile or malfunctioning NIC device.** A driver treats everything the device writes
  (descriptors, used rings, config space) as untrusted input and must never be driven to
  out-of-bounds access, unbounded work, or a panic by device behaviour.
- **A compromised parser or inspection PD.** Because parsers are the most-exposed code, each runs
  in its own least-privilege PD; a full compromise of one must not reach flows, memory, or keys it
  holds no capability for.
- **A byzantine neighbour PD.** Every PD treats the queues and messages from adjacent PDs as
  untrusted: malformed descriptors, stale or forged ownership, and backpressure are rejected
  safely, never allowed to corrupt state or crash a well-behaved PD.
- **A management-plane attacker** reaching the API, and a **connection-flood / state-exhaustion
  attacker** targeting the proxy (§7.2).

**Trust boundaries.** The **seL4 kernel and its boot/loader chain are the trusted computing base**;
runtime capability isolation is enforced by the kernel and is relied upon. The **`rust-sel4` /
Microkit runtime** is likewise trusted. Everything above — every first-party PD — is mutually
distrustful across the queue and channel boundaries fixed by the static system description. A
physical attacker with arbitrary hardware access is out of scope for the software design; Secure
Boot and TPM measures (§14) raise that bar separately.

**Consequence for verification.** Because the kernel and runtime are the trusted base, the project
does not test them — it assumes seL4, Microkit, and `rust-sel4` are correct — and instead
exhaustively tests and fuzzes all first-party logic: parsers, queues, ownership, policy, and state
machines. "Reject untrusted input safely; fail visibly on internal invariant violation" is the
dividing line those tests enforce (see AGENTS.md).

### 7.2 Isolation model

- **Least-privilege PDs.** Every component holds only the capabilities it needs. A compromise of
  one component cannot reach flows, memory, or keys it has no capability for.
- **Parser isolation.** Each protocol parser runs in its own PD so that a parser compromise is
  contained; faulting PDs are restartable.
- **CA signing key isolation.** The private CA key used for TLS interception lives in its own
  **sign-only** PD, ideally HSM/TPM-backed. It is never exposed to any other component; components
  can request signatures but cannot read the key.
- **Management-plane isolation.** The management API runs in its own isolated PD. A full compromise
  of that PD must not be able to reach dataplane packet buffers or the CA key.
- **Configuration validator isolation.** Parsing and validation of configuration input runs in an
  isolated, capability-minimal, restartable PD, so that an exploit attempt against the config
  mechanism cannot reach the dataplane or keys.
- **DMA isolation.** The IOMMU (VT-d) is used to confine NIC DMA.
- **Denial-of-service resilience.** Because the terminating proxy commits per-connection state
  (TCP and TLS) at connection setup, it is a target for connection-flood and state-exhaustion
  attacks. The appliance resists these with standard measures such as SYN cookies, connection-rate
  limiting, and bounded flow tables with eviction.
- **Trusted time.** TLS certificate validation — of upstream server certificates and of the
  appliance's own re-signed certificates — depends on accurate, trusted time, so the appliance
  requires a trusted time source. The source mechanism is open (§13.1).

---

## 8. Technology Stack

All first-party code is Rust. Building blocks:

- **seL4** microkernel; **Microkit** static component model; **rust-sel4 / sel4-microkit** runtime
  (protection domains written in Rust).
- **sDDF queue protocol reimplemented in Rust** (zero-copy, lock-free SPSC queues).
- **TCP:** a **first-party** stack, owning no socket buffers and sharded per core, with selective
  acknowledgement and congestion control as intended extensions. smoltcp is rejected on the shape
  of its API rather than on its quality: its sockets are backed by `RingBuffer<'a, u8>`, so a
  stream is copied into a socket buffer on receive and out of one on send. A copy per segment is
  precisely what the zero-copy dataplane of §4 exists to avoid, and no amount of hardening
  or extension removes it — the buffers *are* the interface. Per-core shardability and the ability
  to tune the transport for a terminating 10 Gbit/s proxy path point the same way.
- **TLS:** **rustls**, with a pluggable crypto provider.
- **QUIC:** a Rust-native QUIC stack (e.g. quinn, s2n-quic, or quiche), used as both server and
  client to terminate and re-originate.
- **DPI / signature matching:** the Rust `aho-corasick` (Teddy SIMD) and `regex-automata` engines,
  used in streaming mode.
- **Content scanning:** **YARA-X** (Rust).
- **NIC drivers:** implemented in Rust, drawing on ixy.rs for virtio/ixgbe register-level logic.

**C boundary:** the only C in the system is the seL4 kernel and its boot/loader chain (the trusted
base). The TLS crypto provider choice (pure-Rust vs. an external provider) is open — see §13.

---

## 9. Deployment Targets, Ports & Form Factors

**Architecture: x86_64 only.**

### 9.1 Port roles

Interfaces are assigned **roles**, and the role — not a fixed port count — is the architectural
unit. Four roles exist:

- **Management port** — the *only* surface that exposes the management API (§11). It is isolated
  from the dataplane and carries no forwarded traffic.
- **Session-replication port** — the dedicated HA link (§10) carrying heartbeat and batched
  flow-state synchronization between the two nodes of a pair.
- **Dataplane ports** — the inspected-traffic ports, handled in **pairs**. The common labels
  "uplink" and "internal" describe a typical north-south deployment, but the role is semantically
  neutral: a pair may equally carry east-west traffic between two internal zones. A deployment has
  one or more dataplane pairs.
- **Mirror port** — an optional, egress-only port that emits a copy of selected traffic to an
  external capture/IDS system. It is **complementary to the on-box recording sinks (§15), not an
  alternative to them**: a mirror moves traffic off the box at full rate but can annotate none of
  it, cannot render several interfaces into one artifact, and costs both a spare port and a
  dedicated machine able to absorb the mirrored rate; the sinks record annotated,
  verdict-bearing evidence on the box and need neither. A deployment that wants full-rate capture
  on dedicated hardware uses the mirror; one that wants to know why the appliance did what it did
  uses the sinks; a deployment may want both.

### 9.2 NIC configurations

The role model yields the supported hardware configurations:

| Configuration | NICs | Ports |
|---|---|---|
| **Single node** | 3 | management; one dataplane pair |
| **HA pair** | 4 | management; session-replication; one dataplane pair |
| **HA + redundant dataplane** | 6 | management; session-replication; two dataplane pairs |
| **HA appliance, full** | 7 | management; session-replication; two dataplane pairs; mirror |

The **4-NIC HA configuration is the primary Azure target**; the **7-NIC configuration is the
hardware-appliance build**, which populates every role and simply leaves ports unused when a site
needs fewer (no redundant pair, no mirror). A node without HA uses the 3-NIC configuration.

Because hardware topology is static (§12.3), **each row is a build-time image variant**: the number
of NICs a system drives is fixed in its system description. Which of those present ports a
deployment actually uses, and in which role, is runtime configuration — an unused port is
administratively disabled, not built out.

### 9.3 Targets and form factors

**Targets:**

- **QEMU** — development.
- **Proxmox** — virtual machine.
- **Azure** — virtual machine.
- **Bare-metal hardware** — the physical appliance.

**Form factors:**

- **Bare-metal appliance** — inline, with SFP+ 10 Gbit/s dataplane ports (§9.1).
- **Virtual machine** — on Proxmox and Azure.
- **Cloud (Azure)** — deployed as a routed **Network Virtual Appliance (NVA) behind a Gateway Load
  Balancer**. The dataplane terminates the load balancer's **VXLAN tunnels** (internal and
  external), encapsulating and decapsulating that traffic.

### 9.4 NIC drivers (all Rust)

- **virtio-net** — the first/foundational driver; covers QEMU, Proxmox, and development.
- **x86 10 Gbit/s NIC** — for the bare-metal appliance, using a register-programmable **SFP+** NIC
  of the Intel **ixgbe family (82599 / X520)**.
- **Azure** — **netvsc** as the baseline interface, and **MANA** (Microsoft Azure Network Adapter)
  for the high-performance path, which is required for Azure eventually.

Azure support is a substantial platform effort rather than a single NIC driver — see §13.2.

---

## 10. High Availability

- **Active/passive pair** with **session synchronization** for immediate failover.
- **Session state is synchronized in batches**, giving a millisecond-scale loss window on failover.
- **No TLS session synchronization.** L2–L4 flow/connection state is synchronized and those sessions
  survive failover; TLS-terminated / L7-proxied connections are **forced to reconnect** on
  failover. This is accepted as standard behavior.
- A **dedicated HA link** carries heartbeat and delta/batched state synchronization.
- The **HA state-sync component is its own isolated PD**.
- **Each node holds its own isolated signing capability** (§7). Sharing signing trust across the
  pair is required; its form (e.g. per-node intermediate CAs under a common trusted root) is open
  (§13.1).
- **Configuration is applied in a staggered/canary order** across the pair (standby first, verified
  healthy, then active) — see §12.
- Because hardware topology is static, a hardware change is an *image* change; **the HA pair is the
  mechanism for rolling image updates** without downtime (§12.3, §14).
- **Failover is mechanism-specific per environment**, because the takeover primitive differs:
  - **Routed, on-premises** — the pair shares a virtual IP and virtual MAC; the promoted node takes
    them over and announces the move with gratuitous ARP / unsolicited neighbour advertisements.
  - **Virtual wire, on-premises** — there is no address to take over, so failover is by **link
    state**: the standby holds its dataplane ports down and raises them on promotion, and loss of
    one port of a pair is propagated to the other so the neighbouring devices reconverge.
  - **Azure** — L2 takeover is impossible on the platform; failover is by withdrawing the node's
    Gateway Load Balancer health probe and letting the platform reprogram routing to the survivor.
- **Split-brain is arbitrated over the dedicated HA link.** The arbitration scheme (witness, quorum,
  or fencing) is open (§13.1).

---

## 11. Management Plane

- **No user interface.** The only management interface is an **HTTP API**.
- **Endpoints / operations:**

  | Operation | Purpose |
  |---|---|
  | `GET /metrics` | Metrics in Prometheus format |
  | `GET /config` | Read the current running configuration (XML) |
  | `GET /logs` | Read the most recent structured log records held in the node's local buffer |
  | Recording download | Retrieve a time range of either recording sink (§15) as a pcapng file |
  | Configuration change | The candidate/commit-confirmed workflow of §12: submit a candidate, validate, commit (with commit-confirmed), confirm, and roll back to a previous version |

  Configuration is never changed by a single unqualified write; every change goes through the
  candidate/commit-confirmed workflow (§12), so the API exposes the stage, validate, commit,
  confirm, and rollback operations that workflow requires.
- **Security:** the API provides encryption, authentication, and read/write authorization using an
  **mTLS certificate pair issued during onboarding** (the onboarding process is defined later —
  §13.1). The management API runs in an isolated PD, on a dedicated management interface, and is
  rate-limited.
- **Metrics:** exposed in **Prometheus exposition format** via `GET /metrics` — the *only* metrics
  interface — with disciplined, bounded cardinality (aggregate metrics, never per-flow labels).
  Every moving part (queues, buffer pools, per-NIC and per-core counters) is observable there
  without measurable dataplane cost, and the endpoint also reflects applied-configuration state.
- **Logs:** emitted as **structured OpenTelemetry logs** to an external receiver — the single log
  transport; syslog is not used. Audit logs (management/user actions), traffic logs, and
  per-subsystem logs are OTEL-only. System-state events (see *Console*) are additionally written to
  the console. Connection and policy events are not composed for the wire: they are written to the
  log sink (§15.1) and the OTEL exporter is one reader of that ring (§15.4), which is what lets a
  collector that was unreachable catch up rather than lose them.
- **Local log buffer:** the node retains a **bounded ring of its most recent structured log
  records** and exposes it via `GET /logs`. External OTEL collection is routinely delayed by minutes
  and can be unavailable outright, and there is no shell — so without this ring there is no way to
  observe what a node is doing *now*, which is precisely what live debugging requires. It is a
  debugging surface, not a log archive: bounded, deliberately lossy (overflow is dropped and
  counted, and the drop count is exposed), and bound by the same rule as every other surface — no
  payloads, secrets, or personal data.
- **Recording:** the two pcapng sinks (§15) are retrieved through the management API as pcapng
  files, over the same mTLS-authenticated, authorized and rate-limited surface as everything else,
  and a **live event stream** for an operator console — another reader of the log ring (§15.4) —
  is developed later. This is the one surface bounded by storage rather than by memory, and the
  only one that carries the traffic itself.
- **The recording sinks are a deliberate exception to the no-payload rule, not an oversight in
  it.** Every other surface named here is barred from carrying packet payloads, and that bar
  stands unchanged: metrics, logs, the local log buffer, and the console carry none. The capture
  sink exists precisely to carry them and the log sink carries packet headers by construction —
  recording the evidence *is* the feature, and a capture that omitted the payload would not be
  one. The exception is therefore scoped and stated: it applies to these two sinks and to nothing
  else, it is why they are gated by an authorization decision rather than merely scraped, and it
  is why an inspected flow is recorded as ciphertext plus its keys (§15.2) rather than as
  decrypted plaintext at rest.
- **Console:** carries **system state only** — the startup sequence and its success/failure, and
  runtime configuration changes (an interface brought up, a MAC reconfigured, a config version
  applied). It never carries traffic or per-request data. It is the last-resort survivability
  channel that lets an operator diagnose a node whose log streaming is unavailable.
- **No distributed tracing.** OpenTelemetry is used for structured logs only; tracing — including
  of the management API — is deliberately out of scope.
- **The exposed interfaces are the complete debug surface.** There is no shell, no CLI, and no
  other introspection mechanism. Scraping `GET /metrics`, reading `GET /config`, tailing
  `GET /logs`, and downloading the recording sinks once yields the entire observable state of a
  node — applied configuration, every metric around it, what it has just been doing, and the
  recorded evidence of what it did to traffic — which is, by design, all that is available to
  debug it. The externalized logs and metrics are therefore a first-class operator contract,
  specified in **MONITORING.md**.
- **Management application:** configuration management, log analysis, and metric analysis are
  handled by a separate management application, developed later.

---

## 12. Configuration Management

- **Configuration is a fully schema-validated XML file** (the schema is defined by the project).
- **Full validation before any apply.** Configuration is validated both **structurally** (against
  the schema) and **semantically** (e.g. references resolve to existing zones/interfaces, no
  conflicting rules, routes are resolvable). A configuration is only applied if it fully validates.
- **The configuration mechanism is hardened against exploitation, independent of configuration
  content.** The system does not judge whether a valid configuration is sensible, but it defends
  the mechanism against any attempt to exploit it: XML entity attacks (XXE, external entities,
  entity-expansion / "billion laughs") are precluded (DTDs and external entities disabled; input
  size, depth, and complexity bounded); the exact bytes that were validated are the bytes that get
  applied; the validator's own resource use is bounded; and configuration values are sanitized
  before being written to logs or the console. Parsing and validation run in the isolated validator
  PD (§7).

### 12.1 Candidate/commit-confirm model

Configuration uses a **candidate/running datastore** model with **commit-confirmed**:

- The **running** configuration is what the appliance enforces; the **candidate** is an editable
  copy. Changes are assembled on the candidate without affecting the running configuration.
- A candidate is **validated** (structurally and semantically) as an operation that changes nothing.
- **Commit** atomically swaps candidate → running (all-or-nothing).
- **Commit-confirmed:** a commit arms a rollback timer; if it is not confirmed within the timeout,
  the appliance automatically rolls back to the previous running configuration. This protects
  against a change that validates but breaks management connectivity at runtime (anti-lockout).
- Configurations are **versioned**, enabling **rollback**.

### 12.2 Distributed staged rollout

Across the HA pair (and later across multiple clusters via central configuration management),
rollout is a **two-phase "stage & validate" → "commit"** process:

- **Phase 1 — stage & validate:** the candidate is pushed to every participating node; each node
  independently parses, structurally and semantically validates, checks local applicability,
  persists the candidate, and votes whether it can commit.
- **Phase 2 — commit:** the change is committed **only if all participants agree**; otherwise it is
  aborted and nothing changes ("all agree or nobody rolls out").
- **Per-node commit-confirmed** (§12.1) applies on top, for runtime-connectivity safety.
- Apply ordering is **staggered/canary** (standby first, verified healthy, then active), so a
  configuration that validates but fails at runtime does not take down both nodes at once.
- Commits are **idempotent, keyed by a monotonic configuration generation-id/hash**, and the
  staged (prepared) state has a timeout, so a coordinator failure cannot leave nodes stuck.
- Standalone changes (a direct configuration change against a single node) retain per-node
  commit-confirmed protection.
- **Availability of configuration changes.** Unanimous agreement is required only while all
  participants are reachable. If a participant is unavailable, a healthy node must still accept
  configuration changes (a single-node commit), marking its configuration generation as divergent
  and reconciling with the peer when it rejoins — so a configuration change is never blocked by an
  unreachable node.

**Central configuration management** for multiple clusters is developed later.

### 12.3 Static hardware, dynamic configuration

The line between what needs a new image and what is applied at runtime is drawn at **hardware**:

- **Hardware topology is static.** The set of physical devices the system drives — the NICs and the
  block devices (§15.5), their PCI addressing, and the protection domains, memory regions, and
  capabilities that follow from them — is fixed in the Microkit system description at build time
  (§6.1). Changing it (adding a NIC, moving to a different NIC count, giving a node a device to
  record onto) is a **different image**, delivered through the A/B update mechanism (§14). Hardware
  reconfiguration of a running system is not supported; each hardware configuration of §9.2 is a
  build-time image variant.
- **Everything above the hardware is dynamic.** Interface configuration and upwards is applied
  through the commit workflow without a restart: whether a present interface is used at all, its
  role, mode (§6.4) and addressing, zones, filtering rules, routes, NAT bindings, inspection policy,
  which recording sinks are enabled and what they filter (§15), and every other policy object. A
  port a deployment does not need is administratively disabled by configuration, not omitted from a
  build.

Two consequences follow, and both simplify the design:

- **A configuration change never requires a reboot to be committed.** Exactly one item defers its
  *effect*: storage binding — which extent a recording ring occupies (§15.5) — is committed like
  any other item but takes hold at the next boot, because moving a ring invalidates what the old
  extent holds. The commit itself remains an operation on the running system, so commit-confirmed
  (§12.1) still operates within one running system and its rollback timer still never has to
  survive a restart.
- **A hardware change is an image change**, so it is governed by the A/B slot mechanism's own
  try/confirm/fallback semantics (§14.2) rather than by the configuration workflow. The two
  mechanisms stay separate and each keeps its own safety property intact.

The dataplane components are built to be **data-driven at runtime** to make this hold: the
classifier, filter, routing, and NAT stages carry no compiled-in topology or policy, so one image
built for a given hardware configuration serves every deployment sharing that hardware.

---

## 13. Open Items and Risks

Everything else in this document is the settled target picture. The following are, respectively,
decisions not yet made and known risks. They are recorded here so they are not mistaken for
oversights.

### 13.1 Open decisions

- **Onboarding process** for issuing the management mTLS certificate pair — required; its design is
  open.
- **TLS crypto provider** for rustls (pure-Rust vs. an external provider), to be resolved by
  benchmarking.
- **CA signing-trust sharing across HA nodes** — required; the form (e.g. per-node intermediate CAs
  under a common trusted root) is open.
- **HA-link split-brain arbitration** — witness, quorum, or fencing (§10).
- **Trusted time source mechanism** (§7).
- **Proxy vs. cut-through throughput split** — the proportion of traffic on the terminating proxy
  path, which drives core sizing (§4).
- **Central configuration management application** (multi-cluster) — built later.

### 13.2 Known risks

- **x86_64 seL4/Microkit maturity.** x86_64 on Microkit is recent (added in 2.1.0, November 2025)
  and exposes only generic/QEMU platforms (no dedicated x86 hardware board); x86_64 with
  SMP is the least-exercised seL4 configuration.
- **No existing 10 Gbit/s or x86 NIC driver.** The public sDDF tree contains only virtio and
  Arm-SoC drivers; all NIC drivers (virtio, SFP+ 10G, netvsc, MANA) are implemented from scratch in
  Rust.
- **TCP stack effort.** Building a first-party proxy TCP stack (§8) is a substantial effort, and it
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
- **Full-rate capture of everything is not reachable, and the filter is the sizing control.** A
  capture sink (§15.1) recording all traffic at the target rate would have to sustain writes at the
  dataplane's own rate, which no practical device does and which would consume the medium's write
  endurance in short order. The sink is therefore sized by its filter rather than by the link, and
  a filter drawn too broadly yields loss. The loss is reported in-band and is measurable (§15.2,
  §15.4) rather than silent, which is the mitigation available — but it remains loss, and choosing
  filters narrow enough is an operational discipline the appliance can measure and cannot impose.
- **The throughput target and the recording sinks compete for one memory-bandwidth budget.**
  Copying frames into a ring and writing them out draws on the same bandwidth the inspection path
  (§4) is already sized to consume. How much recording the target rate can carry is unmeasured, and
  it is the class of cost that does not appear until both run at once — so it belongs to the same
  early benchmarking as the crypto provider and the signature engines.
---

## 14. Software Update & Secure Boot

The appliance updates as a **whole signed system image using two A/B slots**, not by patching a
running system. This suits the static Microkit component model — where the hardware topology is
fixed at build time, so a hardware change is a new image (§12.3) — and gives an automatic,
power-fail-safe path back to the last known-good software.

### 14.1 On-disk layout

The deployable artifact is a GPT disk image (`librefirewall-qemu-x86_64.img`) with fixed slots:

| Partition | Purpose |
|---|---|
| **ESP** | The boot manager (`EFI/BOOT/BOOTX64.EFI`) |
| **STATE** | Mutable boot-selection state (`grubenv`) |
| **SLOT_A** | A complete signed release: seL4 kernel + Microkit system image (+ detached signatures) |
| **SLOT_B** | The second release slot, identical structure |
| **DATA** | The node's own state — configuration, identity, and secrets (§11, §12) — and nothing that grows with traffic |

Each slot is self-contained because x86 Microkit boots a separate seL4 kernel ELF plus the Microkit
system image as a Multiboot2 module — both must be present and version-matched in the slot.

**This table describes the boot medium, not the whole of a node's storage.** Configuration and
identity are written in bytes per day and belong here, so that a node carries everything it needs to
come up as itself. The recording rings (§15) do not: a capture ring rewrites its medium
continuously, its write-endurance profile is not comparable to configuration's, and a single
sequential writer per device is what obtains a device's bandwidth. Rings are therefore bound to
their own devices or partitions, resolved at boot (§15.5), and how many devices a build drives is
part of its static topology (§12.3) — so a deployment target's storage is this layout plus whatever
that variant grants it to record onto.

### 14.2 Boot manager and slot selection

The boot manager is **GRUB** (built from pinned source as a minimal standalone `x86_64-efi`
image with an embedded, immutable configuration and a curated module allowlist). GRUB is chosen
because it is the one common bootloader that natively speaks the x86 Multiboot2 contract seL4
requires, while also supporting UEFI, signature verification, and a persistent environment.

Selection uses the proven `OK`/`TRY`/`ORDER` scheme (as in RAUC's GRUB integration), which is what
stock GRUB scripting can express without arithmetic: a confirmed slot (`*_OK`) boots immediately; an
unconfirmed slot is tried once (its `*_TRY` flag is set before hand-off) and, if it never confirms
health, the next slot in `ORDER` is used. The single-attempt model is a deliberate limitation of
in-bootloader logic; a multi-attempt counter and a redundant, generation-numbered state log belong
to the writable-state owner below, not to GRUB.

Confirming a freshly booted slot as healthy (setting `*_OK`) is done **off the boot path**, by an
in-system update/health protection domain holding capabilities to exactly the inactive slot and
the STATE partition and nothing else. That component is where staged installation, health
confirmation, multi-attempt counting, and redundant crash-safe state live.

### 14.3 Payload trust

Every slot's kernel and system image is signed; GRUB carries the corresponding public key embedded
in its core image and **enforces detached-signature verification** on every file it loads. This
authenticates the payload independently of the medium it sits on. The boot-selection state is
loaded unverified (it only *chooses among* already-signed slots and can never inject code).

Development builds generate a local, throwaway signing key (never committed); the release manifest
records `trust_profile: development` and the key fingerprint so a development-signed image can never
be mistaken for a production one.

### 14.4 Firmware and the seL4 hand-off contract

The target is **UEFI** (a prerequisite for the eventual Secure Boot goal). Booting seL4 under
UEFI+GRUB imposes hand-off constraints that shape the boot chain:

- seL4's x86 Multiboot2 path takes the **ACPI RSDP from the Multiboot2 ACPI tag** GRUB provides, so
  ACPI works under UEFI without the legacy BIOS memory scan.
- The seL4 boot module (the Microkit system image) must load **above** the kernel image; GRUB's
  relocator satisfies this, but it remains a real constraint on memory-constrained targets.
- **The debug kernel takes its serial console from the kernel command line**, so the kernel must be
  given its `console_port`/`debug_port` on the Multiboot2 command line or it boots silently. The
  **IOMMU is left enabled** (Microkit's x86 default); on a platform without VT-d seL4 reports zero
  IOMMUs.

### 14.5 Deliberately deferred

- **UEFI Secure Boot** and its key hierarchy (enrolling a librefirewall platform key; signing the
  EFI binary). The payload-signing and A/B mechanics above are independent of, and ready for, it.
- **TPM-backed anti-rollback** (a monotonic security epoch preventing downgrade to a known-vulnerable
  signed release).
- **The in-system update/health PD** and the staged, transactional, multi-cluster rollout that
  builds on the configuration-management workflow of §12.
- **Redundant, crash-safe boot state.** Stock `grubenv` is a single in-place block; torn-write-safe
  redundant state is part of the update-PD work, not the bootloader.
- **Virtualised/cloud targets** (Proxmox, Azure) are expected to use image/generation replacement at
  the hypervisor or load-balancer level rather than guest-managed A/B, reusing the same signed
  release and compatibility contract.

---

## 15. Recording and Persistent Storage

The appliance keeps its own durable record of the traffic it handled, on block storage it owns, in a
format an analyst opens without conversion. For the connection and policy events of §11 this is not
a second copy beside the log transport but the source beneath it: what is written here is what the
exporters ship onward, and it is what remains when nothing is listening.

### 15.1 Two sinks, one format

Two independent pcapng streams are written, and the split between them is the design:

- **The log sink** is always on, covers every interface, and applies no filter. It records
  connection lifecycle and policy decisions — a connection opening, each refinement of its protocol
  and application identity, notable events on it such as a threat or a policy deny, and its close —
  and anchors every one of them to the packet that caused it, carrying that packet's L2–L4 headers
  and nothing beyond them. It is **breadth**: every connection the appliance saw, for as long as its
  ring holds.
- **The capture sink** is filtered and records full packet content. It is **depth**: everything about
  a little.

Anchoring a log record to its causing packet, rather than composing an abstract event beside it, is
what makes the log open natively in a pcapng reader: the record renders as a packet list with real
addresses and ports, sortable and filterable with the tools an analyst already has, and needing no
bespoke viewer. A policy may raise the evidence length for the events it generates, up to the full
frame, where what was decided is worth more than the headers it was decided on.

The two sinks are the same encoder, the same ring machinery, and the same download path; only the
ring differs. They are **separate rings because their rates differ by three to four orders of
magnitude** — one record per connection against one per packet — and a traffic burst must not be
able to evict connection history.

### 15.2 pcapng as the internal representation

pcapng is the representation on the medium, not a format the appliance converts to on export. It is
chosen because it carries more than packets, and a format that carried only packets would force a
second, parallel record beside them that no reader could relate back:

- An **Interface Description Block per NIC** lets one file record every interface, so a single
  artifact holds both sides of a forwarded flow rather than one file per port.
- **`epb_packetid`** correlates the ingress and egress observations of one forwarded frame, so the
  rewrite the appliance applied — translation (§6.5), re-origination (§6.2) — is a relation between
  two records instead of something an analyst infers by comparing tuples.
- **`epb_flags`** carries direction and **`epb_verdict`** the verdict, so what the appliance decided
  sits on the packet it decided about.
- A **PEN-tagged Custom Option** carries the structured firewall state for which the format has no
  standard field: zone pair, flow identity, policy identity, application protocol stack, decryption
  status, and risk. A reader that does not know the option ignores it and still sees a valid capture.
- **`epb_dropcount`** and the **Interface Statistics Block** report the sink's own loss in-band, so
  a file is self-describing about what it did not record. A capture that silently omits is worse
  than one that states how much it omitted, because only the second can be reasoned about.
- A **Decryption Secrets Block** carries the TLS key material for the flows in the file, so an
  inspected capture is ciphertext plus keylog rather than plaintext at rest — which is what keeps
  the payload exception of §11 as narrow as it can be made.

**A mirror port is not a substitute for this, and neither replaces the other** (§9.1). A mirror
emits copies of frames and can annotate none of them: it cannot say within one artifact which
interface a frame crossed, cannot attach the verdict or the flow's application identity, and cannot
report what it dropped. It also costs a spare port and a dedicated machine able to absorb the
mirrored rate. The two are complementary — the mirror for full-rate capture off the box onto
hardware built for it, the sinks for annotated recording on the box with no additional equipment.

### 15.3 Append-only events, and reduction as a reader's view

The rings are **append-only**: a record, once written, is never rewritten. That is what makes the
writer sequential and cheap and lets a reader work from any point without coordinating with it, and
it dictates how the appliance represents a thing that changes.

A connection's identity is discovered progressively — first the transport, then that it is TLS, then
HTTP/2, then the application protocol carried over it. Each refinement is **a new event carrying the
complete protocol stack as then known**, never a delta against an earlier one. Two properties are
worth that duplication: every event is interpretable on its own, without the reader having seen its
predecessors; and the refinement history is itself evidence, because *when* the appliance learned
what a connection was is frequently the question being asked.

The merged one-row-per-connection view an operator usually wants is therefore **a fold over the
events sharing a flow identity, performed by a reader** — never a mutable table the appliance
maintains. Such a table would have to be updated in place, which an append-only medium does not do
and a partly-evicted ring could not reconcile. Because every event carries the five-tuple and the
stack current at the time, **a flow whose earlier events have already been evicted still reduces to
a usable record**, and a periodic state event re-anchors long-lived connections so a reader's
reconstruction window is bounded rather than growing with a connection's age.

**Flow identity is an (index, generation) pair, never a bare connection-table index.** Slots in the
connection table are reused as connections come and go; across a ring holding hours of history a
bare index would silently merge two unrelated connections that happened to occupy one slot at
different times — and the merge would be invisible, since the reduced record would look ordinary and
be wrong. The generation counter makes reuse explicit and the merge impossible.

**Log events derive from connection-state transitions, not from packet arrival.** The log's rate is
therefore bounded by the rate at which connections are admitted rather than by the packet rate,
which is what keeps it usable under exactly the conditions it is wanted in: a SYN flood that
produced a record per packet would evict the entire connection history in seconds and blind the log
at the moment of the attack. Policy denies create no connection and so have no transition to hang
on; they are **coalesced at their source into counted per-bucket events** for the same reason — a
port scan must cost a bounded number of records, not one per probe.

### 15.4 One writer, many readers

Each ring has **exactly one writer and any number of independent readers**, each holding its own
cursor. The ring is the single durable copy; a reader is a position in it, not a copy of it. The
readers are the pcapng download of the management API, the OpenTelemetry exporter that ships
connection events onward (§11), and a live event stream for an operator console. None is privileged;
adding one adds a cursor and nothing else.

Three properties follow, and they are the reason for the shape:

- **A collector that was unreachable catches up rather than losing data.** External collection is
  routinely delayed and can be unavailable outright (§11); with the ring as the durable copy an
  exporter resumes from its cursor instead of dropping what it could not send.
- **A slow or dead reader costs the dataplane nothing.** The writer always wins: it never waits, and
  a reader that has been overtaken detects this on its next read and reports a gap. Loss is
  therefore not merely bounded but *measurable* — the gap is the distance by which the cursor was
  overtaken, a number rather than a suspicion.
- **Delivery to an external collector is at-least-once.** A cursor advances only after the data is
  accepted, so a failure between the two replays rather than skips. Exactly-once would require the
  collector to participate in the appliance's commit, which is not a dependency an inline firewall
  takes on for the sake of avoiding a duplicate.

**Reader cursors live in the ring's own superblock**, so the medium carries the data and the delivery
state together. A node that restarts, or one that falls back to its other slot (§14.2), resumes every
reader where it stood without a separate store that could disagree with the ring.

**Rings are segmented** into fixed-size units, each beginning with its own Section Header Block and
the full interface set. Any one segment is independently parseable; any contiguous run of segments
is itself a valid pcapng file; a reader that has lost its place resynchronises at the next boundary
instead of scanning; and wrap replaces a whole segment rather than tearing one. The operational
consequence is that **a download of a time range is a byte-range read off the device with no
transformation** — the appliance does not parse, re-encode, or reassemble to serve one, so an
analyst pulling a window costs what reading it costs.

### 15.5 Storage devices and binding

Block devices are reached by a **first-party virtio-blk driver protection domain, one instance per
device** — the same pattern as the NIC drivers, where one driver binary serves several ports as
separate PDs (§6.3, §9.4). A ring's **extent** is either a whole device or a named partition on one,
resolved at boot.

**How many devices exist, and the capabilities each driver PD holds over them, is fixed in the
system description** and is therefore a per-deployment-target image variant, exactly as the NIC
count is (§9.2, §12.3). Which object lives on which extent is runtime configuration.

**Rate classes are deliberately not mixed.** Configuration and identity are written in bytes per day
and belong on the boot medium, so that a node is self-contained (§14.1). A capture ring rewrites its
device continuously and wants a device to itself: a single sequential writer per device is what
obtains that device's bandwidth, and the write-endurance profiles of the two workloads are not
comparable — sizing a medium for one says nothing about its life under the other.

**Storage binding is the first configuration item that is not hot-swappable.** Moving a ring to a
different extent invalidates the contents of the one it leaves, so the binding is committed like any
other configuration item but takes effect at the next boot (§12.3). The exception is confined to
this one item: which sinks are enabled, what the capture sink filters, the evidence length a policy
raises, and retention all apply through the ordinary commit workflow.
