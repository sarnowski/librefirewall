# Architecture

The design chapters of this book describe the settled target design of librefirewall — what the
appliance is meant to be, the decisions behind it, and the reasoning that shaped them. That design
is deliberately larger than what exists today: these chapters state intent, not progress. The
[development status](../status.md) page is the truth about what is implemented.

## Overview

librefirewall is a network firewall / security gateway that performs full deep packet inspection
(DPI) across ISO layers 2 through 7, including TLS interception and inline content scanning. It is
built on the **seL4 microkernel** and written in **Rust**, and it uses seL4's capability-based
isolation to compartmentalize data flows as strongly as possible. It is a defensive-security
appliance for the operator's own infrastructure, spanning use cases from **operational technology
(OT)** environments through to **web filtering**.

## Purpose and scope

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

## Guiding principles

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

## Performance target

The target is **10 Gbit/s of sustained, fully-inspected, inline throughput per dataplane port
pair, in each direction, with low and predictable added latency**, on a single modern multi-core
x86_64 machine. The scope is deliberately this class of throughput — not higher (e.g. 100 Gbit/s)
classes. A deployment may carry more than one dataplane port pair (see
[Deployment and high availability](deployment.md)); the per-pair figure is the unit the
architecture is sized against.

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
  separately and selectively — see [Inspection scope by layer](#inspection-scope-by-layer).)

Latency is kept low and predictable: forwarded/cut-through traffic (including OT and pass-through
traffic) incurs minimal, predictable added latency suitable for soft-real-time OT; TLS/L7-inspected
traffic is proxied (terminated and re-originated) and incurs only the small additional latency
inherent to termination. The proportion of total throughput that traverses the proxy path versus
the cut-through path — which drives core sizing — is still an open decision (see
[development status](../status.md)).

## Inspection scope by layer

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

## Foundation

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
runtime configuration (see [Configuration](configuration.md)).

## Two data paths

A **classifier** steers each flow to one of two paths:

- **Cut-through (non-terminating) path** — stateful L2–L4 filtering, OT/industrial traffic, and
  pass-through traffic. Minimal, predictable latency. Flow state on this path is synchronized for
  High Availability.
- **Terminating proxy path** — TCP, TLS and QUIC are terminated and re-originated; L7 protocols are
  parsed; content is inspected. Used for TLS/L7 inspection and web filtering.

## Component decomposition

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
  PD** — see the [threat model](threat-model.md), the [management plane](management.md),
  [configuration](configuration.md), and [high availability](deployment.md#high-availability)
  chapters respectively.

## Operating posture

A dataplane port pair operates in one of **two modes**, selected by configuration:

- **Routed gateway.** The appliance is an L3 hop: it holds addresses, provides routing/ARP/ICMP
  (see [Component decomposition](#component-decomposition)), performs
  [address translation](#address-translation), terminates the proxy path as an endpoint, and is
  placed as an upstream IT/OT gateway in OT contexts. This is the mode Azure requires, where the
  appliance is a routed Network Virtual Appliance (see
  [Deployment and high availability](deployment.md)).
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

## Address translation

The appliance performs **NAT** on the routed path: source NAT (including masquerading behind an
interface address), destination NAT (port forwarding), and static 1:1 mappings. NAT is not an
independent stage but a property of a tracked flow, which imposes three couplings:

- The translation binding **lives in the connection-tracking entry**; creating a flow and
  choosing its translation are one decision.
- NAT bindings are part of the state **replicated for
  [High Availability](deployment.md#high-availability)** — without them, every translated session
  breaks on failover even though its flow state survived.
- On the proxy path, the re-originated leg's tuple is already constrained so that RSS maps it to the
  core owning the flow (see [Performance target](#performance-target)). Translation must respect
  that constraint rather than compete with it.

Virtual-wire mode performs no translation, by construction.

## Technology stack

All first-party code is Rust. Building blocks:

- **seL4** microkernel; **Microkit** static component model; **rust-sel4 / sel4-microkit** runtime
  (protection domains written in Rust).
- **sDDF queue protocol reimplemented in Rust** (zero-copy, lock-free SPSC queues).
- **TCP:** a **first-party** stack, owning no socket buffers and sharded per core, with selective
  acknowledgement and congestion control as intended extensions. smoltcp is rejected on the shape
  of its API rather than on its quality: its sockets are backed by `RingBuffer<'a, u8>`, so a
  stream is copied into a socket buffer on receive and out of one on send. A copy per segment is
  precisely what the [zero-copy dataplane](#performance-target) exists to avoid, and no amount of
  hardening or extension removes it — the buffers *are* the interface. Per-core shardability and
  the ability to tune the transport for a terminating 10 Gbit/s proxy path point the same way.
- **TLS:** **rustls**, with a pluggable crypto provider.
- **QUIC:** a Rust-native QUIC stack (e.g. quinn, s2n-quic, or quiche), used as both server and
  client to terminate and re-originate.
- **DPI / signature matching:** the Rust `aho-corasick` (Teddy SIMD) and `regex-automata` engines,
  used in streaming mode.
- **Content scanning:** **YARA-X** (Rust).
- **NIC drivers:** implemented in Rust, drawing on ixy.rs for virtio/ixgbe register-level logic.

**C boundary:** the only C in the system is the seL4 kernel and its boot/loader chain (the trusted
base). The TLS crypto provider choice (pure-Rust vs. an external provider) is still open, to be
resolved by benchmarking (see [development status](../status.md)).
