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

The target is to **saturate two SFP+ 10 Gbit/s ports (uplink and downlink) inline, with full deep
packet inspection and negligible added latency.** The scope is deliberately this level of
sustained, fully-inspected throughput — not higher (e.g. 100 Gbit/s) classes.

This is achieved on a single modern multi-core x86_64 machine through:

- a **multicore dataplane**,
- **RSS (symmetric hashing)** that steers each flow to a fixed core; both directions of a flow, and
  **both legs of a proxied connection**, are kept on the same core (the re-originated leg's tuple
  is chosen so that RSS maps it to the core that owns the flow),
- **per-core, shared-nothing flow shards** (no cross-core locking on the hot path),
- a **zero-copy dataplane** with **batched notifications** that keeps the hot path out of the
  kernel, and
- **streaming inspection** on the inline inspection path, so line-rate-inspected traffic is not
  buffered end-to-end. (Full-object content scanning, which necessarily buffers, is handled
  separately and selectively — see §5.)

Latency is kept low and predictable: traffic that is forwarded/cut-through (including OT and
pass-through traffic) incurs minimal, predictable added latency suitable for soft-real-time OT;
traffic that is TLS/L7-inspected is proxied (terminated and re-originated) and incurs only the
small additional latency inherent to termination. The proportion of total throughput that
traverses the proxy path versus the cut-through path — which drives core sizing — is an open item
(§13.1).

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

The appliance provides **routed-gateway operation**: it terminates the proxy path as an endpoint,
provides routing/ARP/ICMP (§6.3), is placed as an upstream IT/OT gateway in OT contexts, and
deploys as a routed Network Virtual Appliance on Azure (§9). Whether the on-premises inline
appliance *also* operates as a transparent L2 bridge — and the resulting on-premises HA failover
mechanism and HA-link split-brain handling — are open (§13.1).

---

## 7. Isolation & Security Model

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
- **TCP:** based on **smoltcp**, hardened/extended as needed (e.g. selective acknowledgements) and
  sharded per core.
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

## 9. Deployment Targets & Form Factors

**Architecture: x86_64 only.**

**Targets:**

- **QEMU** — development.
- **Proxmox** — virtual machine.
- **Azure** — virtual machine.
- **Bare-metal hardware** — the physical appliance.

**Form factors:**

- **Bare-metal appliance** — inline, with two SFP+ 10 Gbit/s ports (uplink/downlink).
- **Virtual machine** — on Proxmox and Azure.
- **Cloud (Azure)** — deployed as a routed **Network Virtual Appliance (NVA) behind a Gateway Load
  Balancer**. The dataplane terminates the load balancer's **VXLAN tunnels** (internal and
  external), encapsulating and decapsulating that traffic.

**NIC drivers** (all Rust):

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
- **Each node holds its own isolated signing capability** (§7). How the pair shares signing trust
  across nodes (e.g. per-node intermediate CAs under a common trusted root) is open (§13.1).
- **Configuration is applied in a staggered/canary order** across the pair (standby first, verified
  healthy, then active) — see §12.
- Because the static component model requires a reboot for structural changes, **the HA pair also
  serves as the mechanism for rolling structural/configuration changes** without downtime (§12.3).
- The **on-premises HA failover mechanism and HA-link split-brain handling** are open (§13.1).
- **Azure HA is platform-specific and constrained** (no L2 takeover; failover via load-balancer
  health probes / route reprogramming); its specifics are deferred (§13.1).

---

## 11. Management Plane

- **No user interface.** The only management interface is an **HTTP API**.
- **Endpoints / operations:**

  | Operation | Purpose |
  |---|---|
  | `GET /metrics` | Metrics in Prometheus format |
  | `GET /config` | Read the current running configuration (XML) |
  | Configuration change | The candidate/commit-confirmed workflow of §12: submit a candidate, validate, commit (with commit-confirmed), confirm, and roll back to a previous version |

  Configuration is never changed by a single unqualified write; every change goes through the
  candidate/commit-confirmed workflow (§12), so the API exposes the stage, validate, commit,
  confirm, and rollback operations that workflow requires.
- **Security:** the API provides encryption, authentication, and read/write authorization using an
  **mTLS certificate pair issued during onboarding** (the onboarding process is defined later —
  §13.1). The management API runs in an isolated PD, on a dedicated management interface, and is
  rate-limited.
- **Metrics:** exposed in Prometheus format via `GET /metrics`, with disciplined cardinality
  (aggregate metrics rather than per-flow labels).
- **Logs:** streamed to an external receiver via **syslog or OpenTelemetry** (the choice is
  deferred — §13.1). Configuration-change logs are additionally echoed to the **console** as a
  debugging/survivability fallback in case remote logging is unavailable.
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

### 12.3 Structural vs. runtime changes

Runtime-mutable policy (e.g. filtering rules and routes) is changed through the commit workflow
without a restart. Structural changes (e.g. adding network interfaces or zones, which change the
static component layout) require a reboot, performed as a rolling reboot across the HA pair (§10).
The precise boundary between runtime-mutable and structural changes, and how commit-confirmed
rollback applies to a reboot-requiring change, are open (§13.1).

---

## 13. Open Items and Risks

Everything above is the settled target picture. The following are, respectively, decisions not yet
made and known risks. They are recorded here so they are not mistaken for oversights.

### 13.1 Open decisions

- **Log transport:** syslog vs. OpenTelemetry.
- **Onboarding process** for issuing the management mTLS certificate pair.
- **TLS crypto provider** for rustls (pure-Rust vs. an external provider), to be resolved by
  benchmarking.
- **CA signing-trust sharing across HA nodes** — e.g. per-node intermediate CAs under a common
  trusted root.
- **On-premises HA failover mechanism**, and **HA-link split-brain handling**.
- **Azure HA specifics** (platform-specific failover mechanism).
- **Transparent L2 bridge operation** — whether the on-premises inline appliance operates as a
  transparent bridge in addition to routed-gateway operation.
- **Trusted time source mechanism** (§7).
- **NAT** — whether it is provided.
- **Local log persistence/buffering** when the external log receiver is unavailable.
- **Proxy vs. cut-through throughput split** — the proportion of traffic on the terminating proxy
  path, which drives core sizing (§4).
- **Structural vs. runtime change boundary** — the precise set of changes that require a reboot,
  and commit-confirmed behavior across a reboot-requiring change (§12.3).
- **Central configuration management application** (multi-cluster) — built later.

### 13.2 Known risks

- **x86_64 seL4/Microkit maturity.** x86_64 on Microkit is recent (added in 2.1.0, November 2025)
  and currently exposes only generic/QEMU platforms (no dedicated x86 hardware board); x86_64 with
  SMP is the least-exercised seL4 configuration.
- **No existing 10 Gbit/s or x86 NIC driver.** The public sDDF tree contains only virtio and
  Arm-SoC drivers; all NIC drivers (virtio, SFP+ 10G, netvsc, MANA) are implemented from scratch in
  Rust.
- **TCP stack effort.** Extending smoltcp into a high-performance proxy TCP stack (SACK, and
  scaling to many concurrent proxied connections at 10 Gbit/s) is a substantial effort.
- **Pure-Rust signature matching at line rate.** Whether the pure-Rust `aho-corasick` /
  `regex-automata` engines sustain line rate with a realistic ruleset is unproven and needs an
  early benchmark (as does the crypto provider).
- **Azure platform scope.** Azure support requires Hyper-V/VMBus (for netvsc), the MANA driver,
  Gateway Load Balancer VXLAN handling, and seL4 booting as an Azure guest — a substantial platform
  effort, not a single NIC driver.