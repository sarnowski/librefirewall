# librefirewall

**A high-performance, deeply inspecting firewall built for strong isolation.**

librefirewall is a defensive network security gateway for x86_64 appliances and virtual machines,
built on the seL4 microkernel with a pure-Rust userspace.

**Read [CONCEPT.md](CONCEPT.md) first.** It is the source of truth for what librefirewall is meant
to be, and the picture it describes is deliberately far larger than what exists today. This document
is the source of truth for what exists today, and for how to build and test it.

## Documentation

- **[CONCEPT.md](CONCEPT.md)** — the target architecture, threat model, and critical design
  decisions.
- **[AGENTS.md](AGENTS.md)** — how to work in this repository: collaboration, source control,
  documentation and testing rules, and the build interface.
- **[MONITORING.md](MONITORING.md)** — the operator contract for the console, OpenTelemetry logs,
  and Prometheus metrics.

## Project status

Statuses are **done**, **partial**, or **open**; every *partial* capability is broken down further
below into what exists and what remains, so the work can be picked up without re-deriving it from
the code.

**The current deployable system** is a two-dataplane-port routed IPv4 slice: one virtio-net driver
protection domain per port brings up a `virtio-net-pci` device on QEMU q35 from static seL4
capabilities alone, and an isolated forwarder protection domain routes frames between the two ports
— parsing each one, deciding on it against the configuration in force, and rewriting its Ethernet
and IPv4 headers in place, so the payload is never copied.

That configuration is a schema-validated XML document, read and committed by a fourth protection
domain holding no device, no buffer pool and no ring, and handed to the forwarder through a shared
region under an offer/acknowledge protocol. The forwarder boots **fail-closed** — an empty table,
generation 0, forwarding nothing — and switches to a generation only after re-checking every field
of it itself, so every boot performs a live configuration swap on a running dataplane. There is
still no way to *submit* a document to a running node: it is embedded at build time.

A **dedicated management port** is now the third NIC, and it is an **addressed IPv4 endpoint**: it
answers ARP requests for its own address and ICMP echo requests to it, and forwards nothing. It is a
third instance of the same driver binary — the binary is port-agnostic, so driving a management port
took no code change to it — handing its frames to a `management` protection domain that reads the
frame, answers what is addressed to it, and reports the port's running total. Its MAC, address and
prefix come from the configuration document like every other address on the appliance, so the port is
configured rather than compiled in, and the domain reads that document's **committed** generation
only: it maps the configuration region read-only, maps the acknowledgement region not at all, and
takes no part in the two-phase commit the forwarder is the consumer of.

The isolation CONCEPT §9.1 asks for is a grant set rather than a rule: the management domain holds no
dataplane region and the forwarder holds no management region, and `xtask::sysdesc` names the mapper
set of every region exactly, so either grant appearing fails the gate. The QEMU gate asserts the same
exclusion on the wire, in both directions, on the release image — no frame injected on the management
port ever appears on a dataplane port, and no dataplane probe ever appears on the management one. What
the port still has no notion of is TCP, TLS or HTTP: it answers two protocols and nothing else.

Another protection domain owns the console. It holds the first of the system's two I/O-port
capabilities — the eight ports at `0x3F8`, the PC-compatible COM1 window — and every other domain
reaches an operator by publishing a typed record into a single-producer ring of its own, which that
domain drains, renders, and puts on the line. It replaced `sel4_microkit::debug_println!`, which compiles
to `seL4_DebugPutChar`, a kernel *debug* syscall the release kernel is not built with: until this
landed, a **release image printed nothing at all**, so a node that parked on a refused NIC or came
up fail-closed on a refused document said so only in the profile nobody ships.

Booting that release image for the first time found a second, deeper defect underneath the first,
which had been latent since the boot chain was written: GRUB was free to place the Microkit system
image in the 640 KiB below 1 MiB, seL4's x86 boot derives the userland load address from the end of
the last boot module, and a module below the kernel therefore made seL4 load the userland image over
its own running kernel — a triple fault before any protection domain executed. Whether it happened
was decided by whether the system image happened to fit down there, so **the debug profile was green
by luck**. `third-party/grub/grub.cfg` now denies GRUB that memory and the build refuses an image
small enough to fit what remains; see *[Signed boot chain](#signed-boot-chain)*.

Both defects were reachable only in the configuration no gate booted, and both are the reason the
gate now boots the shipped one: every QEMU scenario in `make ci` runs the release image, and the
only debug kernel any gate boots is the one re-run to diagnose a scenario that has already failed.

A sixth domain establishes what time it is. It maps the HPET's register page and holds the system's
second I/O-port capability — the two CMOS ports at `0x70` — calibrates the timestamp counter against
the timer whose rate is self-describing, reads the real-time clock once for an epoch to anchor that
counter to, publishes one console record stating both, publishes the calibration itself, and parks.
Every other domain now reads that calibration, so **every structured record carries the UTC instant
it was emitted at**, rendered as RFC 3339 — and the records emitted before the calibration exists
carry the token `unsynchronized` rather than a fake 1970. It is **not** a trusted time source — see
the status row above and its detail below.

A seventh domain owns the appliance's **block device** and turns the traffic into a durable record.
It brings a virtio-blk device up at a pinned PCI function, proves the path to the medium by reading a
sector and writing a recognisable one back — which the QEMU harness checks by reading that sector off
the disk image afterwards — and then writes **two pcapng recordings** onto that device: a *log*
recording snapped to 128 bytes and a *capture* recording snapped to 2048. What it records is what the
forwarder taps: every frame the router reached a decision about, copied out at the decision point
*before* the forwarding rewrite, so what reaches the medium is what the wire carried. Either recording
is downloadable whole over the management port — `GET /logs.pcapng`, `GET /capture.pcapng` — as a
windowed body, and `tcpdump -r` opens both natively. That domain holds no dataplane pool, no NIC
region and no I/O port; it is the only domain in the system that can put a byte on persistent
storage, and the only path between it and the dataplane is a one-way tap ring that can never
backpressure forwarding. See *[virtio-blk driver](#virtio-blk-driver)* and
*[Recording and download](#recording-and-download)*.

Parsing stops at IPv4 and UDP, and **no filtering decision of any kind is made**: a packet is
forwarded because it is routable, never because a policy allowed it. There is no connection tracking
and no NAT, and the ARP and ICMP that exist belong to the management endpoint alone — the dataplane
resolves a next hop from a static neighbour table and answers nothing for itself. What exists is a
router on a firewall's substrate, not yet a firewall.

That absence reaches the recordings, and is the largest gap in them. CONCEPT §15.1 splits the two
sinks by *what* they record — the log sink connection lifecycle and policy events anchored to their
causing packet, the capture sink filtered full content. Neither exists: with no connection tracking
there are no connection events to record, and with no filtering the capture sink is unfiltered and on
by default. **Today the two recordings differ only in their snap length**, and `/logs.pcapng` is the
capture truncated to headers rather than an event log.

### Traffic inspection and enforcement

| Capability | Status | Notes |
|---|---|---|
| Stateful L2–L4 filtering and connection tracking | **open** | |
| Routing, ARP, ICMP | **partial** | ARP and ICMP echo exist for the **management endpoint only**, not for the dataplane — [detail](#routed-ipv4-forwarding) |
| Virtual-wire (bump-in-the-wire) operation | **open** | CONCEPT §6.4 |
| NAT (SNAT/masquerade, DNAT, static 1:1) | **open** | CONCEPT §6.5 |
| Flow classifier (cut-through vs. proxy path) | **open** | |
| L7 protocol parsing (HTTP/1.1, HTTP/2, HTTP/3) | **partial** | a server-side HTTP/1.1 request parser (`crates/http`) reads the management port's requests; it is a bounded head parser with no body, no HTTP/2 and no HTTP/3, and no dataplane consumer — [detail](#prometheus-metrics) |
| OT/industrial protocol inspection | **open** | |
| DoS resilience (SYN cookies, rate limiting, bounded state) | **open** | |
| Mirror port | **open** | CONCEPT §15.2 holds the recording sinks and a mirror to be complementary rather than alternatives; the sinks exist, the mirror does not |
| TLS termination and re-origination | **open** | |
| QUIC / HTTP-3 termination | **open** | |
| Isolated sign-only CA protection domain | **open** | |
| Trusted time source | **partial** | a protection domain establishes real time at boot and publishes it to every other domain, so every structured record carries the instant it was emitted at; nothing about it is *trusted* — [detail](#trusted-time-source) |
| Streaming DPI / signature matching | **open** | |
| Full-object content scanning (YARA-X) | **open** | |
| Web filtering | **open** | |

### Dataplane, platform and hardware

| Capability | Status | Notes |
|---|---|---|
| Zero-copy shared-memory dataplane | **partial** | [detail](#zero-copy-dataplane) |
| First-party virtio-net driver | **partial** | [detail](#virtio-net-driver) |
| Multicore dataplane, RSS, per-core flow shards | **open** | single vCPU today |
| Proxy TCP stack | **partial** | a first-party passive-open stack carries a real connection on the management port, and it is the stack the dataplane proxy will run on; no active open, no SACK, no congestion control, and no dataplane consumer — [detail](#proxy-tcp-stack) |
| 10 Gbit/s per dataplane port pair | **open** | nothing has been measured against the target |
| IOMMU (VT-d) DMA confinement | **open** | bus-master DMA is currently unconfined |
| Full port role model (management, session-replication, mirror, multiple pairs) | **partial** | a dedicated management port exists, is addressed, answers ARP, ICMP echo and TCP, and is isolated from the dataplane; no other role does — [detail](#full-port-role-model) |
| Hardware image variants (3/4/6/7-NIC) | **open** | one system description, `systems/qemu-x86_64` |
| ixgbe (SFP+ 10 Gbit/s) driver | **open** | |
| Azure netvsc / MANA drivers, Azure NVA (GWLB, VXLAN) | **open** | |
| Proxmox and bare-metal targets | **open** | QEMU only |

### Recording and persistent storage

| Capability | Status | Notes |
|---|---|---|
| First-party virtio-blk driver | **partial** | [detail](#virtio-blk-driver) |
| pcapng encoder | **partial** | `crates/pcapng` writes SHB, IDB, EPB, ISB, Custom Block and a padding block, allocation-free, `no_std` and `forbid(unsafe_code)`, and `tcpdump` reads what it produces. CONCEPT §15.2's Decryption Secrets Block is not implemented, and of what is, only the blocks the recorder uses are exercised end to end — no ISB is emitted — [detail](#recording-and-download) |
| Two pcapng recording sinks (log and capture) | **partial** | both are written to the device from the forwarder's tap and both parse as pcapng off the medium; **they differ only in snap length** — there is no connection tracking, so no connection events, and no filtering, so the capture sink is unfiltered and on by default — [detail](#recording-and-download) |
| Recording download over HTTP | **partial** | `GET /logs.pcapng` and `GET /capture.pcapng` answer a whole recording as a windowed body with an exact `Content-Length`; no `Range`, no `If-Match`, and **no TLS and no authentication in front of them** — [detail](#recording-and-download) |
| A recording that states its own loss in-band | **open** | `epb_dropcount` is written on every record and is always `0` because nothing feeds it, and no Interface Statistics Block is emitted; loss reaches `/metrics` and never the file — CONCEPT §15.2 |
| Paired ingress/egress observation of one forwarded frame | **open** | one observation per frame, taken at the decision point; `epb_packetid` is minted and monotone but never relates two records — CONCEPT §15.2 |
| Recording the management port | **open** | only the dataplane is tapped, so nothing on the management port — including a download — is recorded |
| Retention bound and zeroization | **open** | the only bound is the ring's size; there is no time bound and nothing is erased on stop — CONCEPT §15 |
| Rotation and checkpointing on a schedule | **open** | a superblock is written when the recorder decides to, never on a clock |
| Resuming a recording across a boot | **open** | `Sink::resume` exists and is host-tested; nothing calls it, so a reboot starts a fresh ring over the old bytes |
| Reader cursors in the ring superblock, one writer many readers | **open** | the superblock carries four reader-cursor slots and no reader registers one; the ring has exactly one reader, the download path — CONCEPT §15.4 |
| Live event stream, OTEL and syslog exporters as ring readers | **open** | CONCEPT §11, §15.4 |
| Registered Private Enterprise Number | **open** | the annotations are tagged `0xFFFFFFFF`, IANA-reserved so it cannot collide, but not ours — a recording must not leave a customer's premises under it |
| Storage binding from the configuration document | **open** | the extents are compiled into `lfw_recorder::deck` and the device is the whole of one disk; nothing resolves a partition and no configuration item names one — CONCEPT §12.3, §15.5 |
| Decryption Secrets Block (inspected flow as ciphertext plus keys) | **open** | nothing is inspected, so there is no key material — CONCEPT §15.2 |

### High availability

| Capability | Status | Notes |
|---|---|---|
| Active/passive pair, failover | **open** | per-environment mechanisms settled in CONCEPT §10 |
| Batched session-state replication | **open** | |
| Isolated HA state-sync protection domain | **open** | |

### Management, configuration and observability

| Capability | Status | Notes |
|---|---|---|
| Management HTTP API over mTLS | **open** | |
| Schema-validated XML configuration, hardened validator PD | **partial** | [detail](#configuration-management) |
| Candidate/commit-confirm transactions, versioning, rollback | **partial** | the candidate/running split and monotonic generations exist; neither rollback nor commit-confirm does — [detail](#configuration-management) |
| Distributed staged rollout across the pair | **open** | there is no pair; the handover protocol has one consumer |
| Console device and log transport (16550 COM1, one owning PD) | **partial** | [detail](#console-device-and-log-transport) |
| Console system-state events | **partial** | [detail](#console-system-state-events) |
| OpenTelemetry structured logs | **open** | call sites emit typed events (`crates/log`); the console is one rendering of them, and the record a domain publishes into its log ring is a second, already-structured one. No transport, exporter or receiver exists, and the exporter CONCEPT §11 makes a reader of the recording ring is not one of the ring's readers either — it has none but the download path |
| Prometheus `/metrics` | **partial** | `GET /metrics` answers an exposition covering every protection domain, the capture tap and both recordings, with each NIC's counters joinable to the interface the configuration document names; scraped with `curl` in the gate against two different documents. The endpoint has **no mutual TLS**, and per-core, queue-occupancy and flow-table coverage awaits the subsystems themselves — [detail](#prometheus-metrics) |
| Local log buffer (`GET /logs`) | **open** | not to be confused with `GET /logs.pcapng`, which exists: that is the pcapng *log recording* on the block device ([detail](#recording-and-download)), a different artifact on a different medium |

### Lifecycle, boot and trust

| Capability | Status | Notes |
|---|---|---|
| Signed A/B disk image and slot selection | **partial** | [detail](#ab-image-update) |
| Signature-enforced boot chain (OVMF → GRUB → Multiboot2 → seL4) | **partial** | [detail](#signed-boot-chain) |
| In-system update/health protection domain | **open** | nothing inside seL4 holds a capability on the **boot** disk, so nothing can write boot state. The recorder's block device is a second, data-only disk and reaches no partition of the boot one — [detail](#ab-image-update) |
| Configuration, identity or secrets on persistent storage | **open** | one domain now holds a disk capability, but it writes recordings and nothing else; the DATA partition is still an empty unformatted GPT entry with no consumer and no encryption — [detail](#configuration-management) |
| UEFI Secure Boot enrolment | **open** | manifest records `secure_boot: false` |
| TPM-backed anti-rollback | **open** | no TPM anywhere, including the QEMU harness |

### Architecture and assurance

| Capability | Status | Notes |
|---|---|---|
| Pure-Rust userspace | **done** | the only C is the seL4 kernel and its boot chain |
| Least-privilege PD decomposition | **partial** | [detail](#protection-domain-decomposition) |
| Untrusted-device hardening | **partial** | [detail](#untrusted-device-hardening) |
| Untrusted-peer (byzantine neighbour) containment | **partial** | [detail](#untrusted-peer-containment) |
| PD fault handling and restart | **open** | a rejected bring-up parks its domain; nothing restarts it, and there is no fault handler |

## Partial capabilities in detail

What each partial capability already has, and what specifically remains to finish it.

### Routed IPv4 forwarding

**Done.** Two host-tested `no_std` crates carry the whole decision. `crates/net-headers` parses
Ethernet, one optional 802.1Q tag, IPv4 and UDP, and applies the four edits a hop requires — both
MACs, the TTL decrement, and the header checksum — as one operation that cannot be performed in
part. `crates/routing` turns a parsed frame and its ingress port into a verdict: forward out of a
named port under a named MAC pair, or one of eleven named drop reasons, each with its own counter.
`pd_runtime::RouteStage` joins them to the dataplane — snapshot the frame out of the pool, decide,
rewrite, and write back the 34 header bytes — and marks every frame it refuses `Verdict::Discard`
so the transmitting driver returns the buffer instead of transmitting it. The table it decides
against is data rather than code: the const parameters are capacities, the lengths are runtime
values, and the domain is handed one table and later handed another (see
*[Configuration management](#configuration-management)*).

Held by 47 unit and property tests across the two crates, by the stage's own tests in
`crates/pd-runtime` — including one that drives an arbitrary mix of routable, unroutable, malformed
and garbage traffic through it and asserts the pool comes back whole — and by a persistent fuzz
target (`route_frame`) whose input is the frame itself.

**Missing.**

- **No ARP and no ICMP on the dataplane.** Both now exist — `crates/net-headers` parses and builds
  them and `crates/ip-endpoint` answers them — but only for a port that answers *for itself*: the
  management endpoint (see *[Full port role model](#full-port-role-model)*). On a dataplane port
  neighbours are still a static table and a drop is still silent, because a dataplane frame can only
  leave the port opposite the one it arrived on: the pools are owned by the receiving drivers, so no
  domain on that path can originate a frame at all. Giving a dataplane port an ARP cache and an ICMP
  responder means giving the forwarder a pool it owns, which is a capability change and not a code
  one.
- **Interfaces, neighbours and the management interface are all that is configurable.** They come from
  `systems/qemu-x86_64/configuration.xml` and no longer from a `const` table, and that document is
  now the single source of the appliance's addressing: the MAC QEMU gives each guest NIC and the
  endpoints the system test states its contract between are both read out of it
  (`tools/xtask/src/topology.rs`), so the three literals that used to have to agree — and that
  nothing compared — are one literal and two derivations. Everything else a hop depends on is still
  compiled in: which ports exist, which pipeline joins which pair, and the pool and ring extents.
- **Connected routes only.** A destination is routable exactly when an interface prefix covers it;
  no route table, no default route, no gateway indirection.
- **IPv4 only, and no options**: `IHL != 5` is refused rather than skipped, IPv6 is absent, and a
  VLAN tag is parsed but never acted on — a tagged frame is dropped for want of a sub-interface.
- **No fragment reassembly.** A non-initial fragment is forwarded without a transport header being
  read, which is correct for routing and insufficient for anything that must see the whole datagram.

### Zero-copy dataplane

**Done.** The substrate exists as four host-tested `no_std` crates: `crates/queue` (the lock-free
SPSC ring), `crates/packet-buffer` (the shared buffer pool and its ownership ledger), `crates/wire`
(the descriptor ABI shared across domains, pinned by static layout assertion) and `crates/pd-runtime`
(the pipeline, pool owner and routing stage the protection domains are assembled from).

Correctness is held by 360 unit and property tests across those four crates — including hostile-peer
cases for forged and duplicate returns, forged cursors, exhausted rings and bounded drains — plus a
500,000-frame three-thread pipeline test that cycles every buffer through `rx → route → tx → free`
far more times than the pool holds, exchanging the forwarding table at poll boundaries as it goes.

A frame is copied twice per hop with the recorder switched out of the picture: once out of the pool
into the routing domain's own memory, because a decision made on bytes a peer may rewrite underneath
it is no decision at all, and once back — 34 bytes of header, never the payload.

**The tap makes it three, and adds a second parse.** Every frame the router decides on is copied a
third time, out of the routing domain's scratch into the tap ring the recorder reads
([detail](#recording-and-download)) — up to 2048 bytes, the whole frame rather than its header. The
copy is taken between the decision and the forwarding rewrite, which is what makes a recorded frame
the one the wire delivered, and the cost of splitting the two is that the rewrite re-parses the frame
the decision already parsed. Neither cost is measured: `crates/pd-runtime`'s Criterion routing bench
passes no tap, so what it measures is the path with recording off.

**Missing.**

- No batching API — one descriptor per call, and one notification per drain. CONCEPT §6.1's
  batched notifications are incidental today, not designed.
- Pool is 64 buffers of 2048 bytes; orders of magnitude short of a 10 Gbit/s working set.
- Fixed 2048-byte buffers: no jumbo frames, no scatter-gather, and no descriptor chaining **on this
  path** — `crates/virtio` grew chaining for the block driver's three-segment requests, and no NIC
  pipeline uses it.
- Exactly two pipelines, hard-coded in the forwarder PD. No per-core sharding, no multi-queue.
- No backpressure policy beyond releasing the buffer. A peer that stalls a destination ring makes
  `RouteStage::poll` drop a descriptor it has already dequeued, and the buffer that descriptor
  named is then lost to its owner's ledger permanently. It is counted, and nothing is double-owned
  — but the pool shrinks, and no component reclaims it.

### virtio-net driver

**Done.** A from-scratch modern virtio 1.0 PCI transport in `crates/virtio` — capability-list walk,
BAR relocation, feature negotiation, queue programming, doorbells, and a split-virtqueue driver half
— covered by 67 unit and property tests and one compile-fail doctest. Every transport entry point
the device drives returns a typed error (`BarError`, `ResetError`, `QueueSetupError`, `NotifyError`,
`CapError`) instead of panicking.

`crates/nic-driver-core` holds bring-up and the steady-state poll pass, covered by 69 further tests.
Rx and Tx clamp the device-reported length to the buffer behind it, drop runt frames, and validate
every peer transmit descriptor.

Twelve persistent fuzz targets cover this surface, the peer-facing one, the network-facing parser,
the addressed management endpoint, the configuration document and the handover image, and the log
record and its ring (see *Engineering foundations*).

**Missing.**

- **Interrupts.** Busy-poll only — no MSI-X, no INTx (deliberate for this milestone). The ISR
  capability's presence is still required of the device, but its offset is not retained and the
  status register is never read. This burns a core per port, and both driver instances run at the
  same priority and never yield, so their mutual progress rests on seL4's round-robin scheduling
  alone.
- **Real hardware.** No PCI enumeration: the BDF and the BAR physical address are pinned in the
  system description, so the driver cannot bind a device it was not built for.
- **DMA confinement.** Bus-master DMA is enabled unconditionally against fixed physical addresses;
  no VT-d.
- **Offloads.** No checksum offload, TSO/GSO, or mergeable receive buffers — prerequisites for
  10 Gbit/s. No feature but virtio 1.0 is accepted, precisely because accepting one would licence
  buffer shapes no code handles.
- No control virtqueue, no multi-queue, no link-status handling, and no MAC read-out — the device
  configuration structure's offset is bounded but never dereferenced.
- No packed virtqueue and no MMIO transport (PCI only).
- **No restart.** A rejected bring-up is a typed `BringUpError` the PD reports on the console and
  parks on, writing `STATUS_FAILED` back to the device wherever the register is reachable. The
  domain is left idle rather than faulted — but nothing restarts it, and the port stays down until
  the node is rebooted.

### virtio-blk driver

A seventh protection domain, `recorder`, owns a virtio-blk device at the pinned PCI function
00:05.0 and is the only domain in the system that can put a byte on persistent storage. The device
class is `crates/blk`: PCI identification and the virtio 1.0 handshake (`bringup`), the request
state machine over one virtqueue (`request`), and the sector-addressed staging window every data
segment names (`io`). The split is `nic-driver-core`'s — every decision is in the library where a
host test can drive it against a stand-in device, and the protection domain is an adapter (LAY-2).

**What it proves today** is that the path reaches a real medium, and it proves it as a
machine-observable contract rather than as a console line (TEST-13). `lfw_blk::smoke` reads sector 0,
then writes a 512-byte pattern that names its own target sector to sector 64, waiting for each
completion before starting the next. The QEMU harness creates a 64 MiB raw image per run, seeds a
different recognisable pattern into sector 0 before boot, and afterwards reads sector 64 back and
compares it against `lfw_blk::smoke::witness_pattern` — the appliance's own definition, called
rather than copied. Every scenario that boots the appliance must show the pattern, and the two A/B
halt scenarios, where no slot is bootable and no domain runs, must show the sector still zeroed.
That pair is what makes either verdict evidence.

The console record carries what the device said and what came back:

```
LFW-PD time=… domain=recorder state=starting
LFW-PD time=… domain=recorder state=negotiated features=0x100000000
LFW-PD time=… domain=recorder state=ready sectors=131072 leading=0x444545532d57464c
```

`sectors` is the device's claimed capacity and `leading` is the first eight bytes it actually
returned — here the harness's `LFW-SEED` marker, little-endian, which is a second, independent sign
that the *read* crossed to the medium and not merely to the driver's own staging window.

**Missing:**

- **No flush, no ordering guarantee, and no retry.** `lfw_blk` observes `VIRTIO_BLK_F_FLUSH` and
  reports whether the device offered it, deliberately without accepting it, and issues no
  `VIRTIO_BLK_T_FLUSH` at all — so nothing written here is durable across a power cut. The smoke
  proof refuses and parks rather than retrying a device that answered badly, and a recording whose
  write the medium failed **acknowledges the loss and advances**: stalling every later record behind
  a fault that retrying cannot clear would be the worse recording.
- **A failed transfer reaches no surface.** That loss is counted inside the recorder as
  `medium_failures`, and that counter is published nowhere — no metric family carries it, no console
  record states it, and the recording itself says nothing about the sectors it lost, because
  `epb_dropcount` reports observations the *sink* dropped and not bytes the *device* refused. A
  medium quietly failing every write is, today, indistinguishable from one that is merely idle.
- **One device, one extent, no partition.** `systems/qemu-x86_64` declares a single block device and
  the driver addresses the whole of it. CONCEPT §15.5's per-deployment device count and named-extent
  binding are untouched.
- **Nothing is measured.** The staging window is 256 KiB because that is a plausible amount to have
  in flight, not because a benchmark said so, and there is no Criterion bench on the block path.

### Recording and download

**Partial.** Every frame the router decides on is observed, both recordings are written to the
medium as pcapng, and either can be downloaded whole over HTTP.

The forwarder taps its own routing stage. `RouteStage` already snapshots each frame into private
scratch before deciding, so an observation costs one copy into a shared ring and no second read of
the pool. What is recorded is the frame **as it arrived** — the tap is taken between the router's
decision and the forwarding rewrite, which costs a second header parse on the forwarding path and
buys the property that makes a recording usable as evidence: what reaches the medium is what the
wire carried. Three classes of frame are counted and deliberately absent from a recording, because
`wire::TapDropReason` mirrors `routing::DropReason` exactly and there is no honest encoding for
them: a frame no routing decision was reached about (a malformed descriptor, a refused snapshot,
bytes that are not IPv4 over Ethernet), a frame routed out of a port the stage is not wired to, and
a frame recorded as forwarded that a later refusal still lost. **The tap never backpressures
forwarding**: a full ring costs the newest observation and is counted — on both sides of the ring and
on `/metrics` — because a tap that could stall the dataplane would make an observability feature a
remote outage.

The recorder keeps two recordings on the one device, both `lfw_recorder::Sink` over
`lfw_capture_ring`, differing only in extent and snap length:

| Recording | Extent | Segment | Snap length |
|---|---|---|---|
| log (`/logs.pcapng`) | sector 2048, 32768 sectors (16 MiB) | 1 MiB | 128 bytes |
| capture (`/capture.pcapng`) | sector 34816, 65536 sectors (32 MiB) | 1 MiB | 2048 bytes |

Sectors 0–2047 are reserved and belong to neither, which is where the harness's seed and the smoke
proof's witness pattern live. Within each extent the **first segment holds the superblock**, doubled
and CRC32'd, its two 512-byte copies alternating by generation parity so a torn write never leaves
the ring without a good one; payload therefore starts one segment in, giving the log recording 15
payload segments and the capture recording 31. The 256 KiB `blk_io` staging window is carved into a
64 KiB log buffer, a 128 KiB capture buffer, a 32.5 KiB download read buffer (a 32 KiB window plus
one sector, so a window can start mid-sector) and a 1 KiB superblock buffer, each sector-aligned, and
every DMA address is `io_paddr` plus one of those offsets.

Each pass of the recorder's loop settles up to eight completions, drains up to sixteen tap records
into both recordings, hands the medium whatever is ready, and services at most one download. A
record a recording cannot take yet is **held**, not dropped: `wire::TapReader` consumes a slot
irrevocably, so the pass stops drawing new records until both recordings have taken the one in hand.
Every counter reading is converted to a wall-clock instant here, against the calibration the clock
domain publishes; before there is one, a record states no instant rather than a counter value
dressed as a time.

A download pins a snapshot: offset zero seals the named recording, flushes it, and answers with the
length the response commits to; later offsets are located against that same snapshot, read back off
the medium, and delivered a window at a time. A ring that wrapped past a reader answers `Overrun`, a
medium that refused answers `DeviceError`, and either ends the response rather than truncating it
silently. The management domain drives that from `EndpointStage`'s windowed body, so nothing holds a
second copy of a megabyte: the recorder answers 32 KiB per round trip, the endpoint copies each into
a 16 KiB sliding window sized above the transport's retransmit span, and a client that stops reading
abandons the stream. Serving a body larger than the response staging buffer is what the windowed body
exists for — a scrape of `/metrics` fits in staging, a 12 KiB recording would too, and a 16 MiB one
never will.

**What a recording contains.** Each segment opens with a Section Header Block naming
`librefirewall`, then one Interface Description Block per interface — Ethernet, microsecond
timestamps, `if_snaplen` the sink's own. Every observation is an Enhanced Packet Block carrying
`epb_flags` (direction), `epb_dropcount` (the field CONCEPT §15.2 wants the sink's own loss stated in
— emitted, and always zero, because nothing feeds it), `epb_packetid`, `epb_verdict`, and a
PEN-tagged custom option holding a layout version, the
verdict, the drop reason, the interface, the direction and the **configuration generation the
decision was made under**. A sealed segment is padded to a sector boundary with a Custom Block that
any reader skips. MONITORING.md's *Recording download endpoints* is the operator-facing statement of
all of it.

The console names both extents at bring-up, which is the only way an operator learns where a
recording is — there is no shell and no CLI:

```
LFW-PD time=… domain=recorder state=ready sectors=131072 leading=0x444545532d57464c
LFW-PD time=… domain=recorder state=ready start=2048 sectors=32768
LFW-PD time=… domain=recorder state=ready start=34816 sectors=65536
```

**What the gate proves.** Every scenario whose management port is reachable — three of the six —
boots the release image on QEMU's user-mode stack, drives the same dataplane traffic every other
scenario drives, and then `curl`s `/metrics`, `/logs.pcapng` and `/capture.pcapng`, holding the
three to **each other** as well as to the wire: the packet blocks in the two recordings pair 1:1 by
`epb_packetid`, neither exceeds the record count the recorder publishes for that sink, every
injected probe appears in the capture byte-identically, and no block carries bytes the harness never
injected (`tools/xtask/src/surface_contract.rs`). A fault that hides inside any one surface shows up
as a disagreement between two. The harness walks the downloaded bytes block by block *by the lengths the file
states* — the discipline a reader actually depends on — and holds each to carrying at least as many
packet blocks as frames the harness put across the appliance, and to no captured length past the
sink's snap length. Afterwards it reads the two extents straight off the disk image and requires
each to carry a decodable superblock and a walkable recording. Two paths to one artifact, neither of
them the appliance's own account of itself (TEST-13).

**What the demonstration showed.** Separately from the gate, and by hand, the published release disk
was booted under OVMF with a 64 MiB virtio-blk data device attached at 00:05.0, and 14 routable
IPv4/UDP frames of 84 to 1384 bytes were injected on dataplane-0 for the appliance to route to
dataplane-1. This was a one-off: the script and its artifacts live under the ignored `build/` tree
and are not in the repository, so what is *repeatable* is the `recording-download` scenario above and
this is corroboration beside it. Over the management port, `curl http://…/logs.pcapng` and
`curl http://…/capture.pcapng` each returned a whole number of 512-byte sectors — which is the
padding block doing its job — 3584 and 12288 bytes for that hand-run traffic.
`tcpdump -r` reads both natively and lists all 14 packets with their real addresses, ports, lengths
and wall-clock times. An independent parse of the two files established:

- **capture:** captured length equals original length for all 14, and **every frame is byte-identical
  to the bytes injected** — the whole point of tapping before the rewrite;
- **log:** captured length clamped to 128 while the original length (84…1384) is preserved, and each
  is a byte-exact prefix of what was sent;
- every packet carries `epb_flags`, `epb_packetid` (0…13), `epb_dropcount` (0 throughout) and
  `epb_verdict`, plus the PEN-tagged annotation, which reported configuration generation 1 — the
  generation the console had just recorded as applied;
- both files carry one Section Header Block, two Interface Description Blocks and a trailing padding
  Custom Block, and the padding is transparent to `tcpdump`;
- reading the two extents straight off the data-disk image after shutdown yields **exactly the bytes
  the downloads returned**, so the medium is proved independently of the download path.

**Missing:**

- **No connection tracking, so no connection logs — the sinks differ only in snap length.**
  CONCEPT §15.1's log sink records connection lifecycle and policy decisions — an open, each
  refinement of protocol and application identity, notable events, the close — each anchored to the
  packet that caused it. None of that exists. There are no connection events, no flow identity, no
  application stack and no deny coalescing, so both recordings hold every dataplane observation and
  one merely keeps less of each frame. The annotation carries a version byte precisely so the record
  can grow when they land.
- **No filtering.** CONCEPT §15.1's capture sink is filtered by design and this one is unfiltered and
  on by default, which is development state rather than a shipping posture: a deployed node would
  record every packet crossing it, indefinitely, with no way to say otherwise.
- **No TLS and no authentication in front of either download.** This is the pre-existing CONCEPT §11
  deviation ([detail](#full-port-role-model)), and recording makes it far more consequential: it used
  to expose counters, and it now hands anyone who can reach the management port every packet the
  appliance recorded. CONCEPT §11 makes authorization a *condition* of the payload exception; the
  condition is unmet.
- **One observation per frame.** CONCEPT §15.2's paired ingress and egress observation of one
  forwarded frame — the thing a mirror port cannot give you — is not emitted: the packet identity
  that would relate them is minted and monotone, and only the ingress observation is recorded, so
  every `epb_flags` reads inbound.
- **Only the dataplane is tapped.** The management port has no tap, so nothing on it — including the
  download itself — appears in either recording.
- **Some frames are counted and deliberately not recorded**, because `wire::TapDropReason` mirrors
  `routing::DropReason` exactly and there is no honest encoding for them: a frame no routing decision
  was reached about, one routed out of a port the stage is not wired to, and one recorded as forwarded
  that a later refusal still lost. An operator reconciling a recording against `/metrics` subtracts
  those; MONITORING.md states the reconciliation.
- **A recording states none of its own loss.** CONCEPT §15.2 makes `epb_dropcount` and an Interface
  Statistics Block the in-band report of what a sink did not record, and neither carries anything:
  `Sink::note_drops` exists, is host-tested and fuzzed, and is called by no protection domain, so
  every `epb_dropcount` written to the medium is `0`; no ISB is emitted at all. A file a burst outran
  is indistinguishable from one that lost nothing, which is precisely the property the format was
  chosen for. The loss *is* counted, on `/metrics`, so the numbers exist — they are just not in the
  artifact that travels.
- **The PEN is a placeholder.** Annotations are tagged `0xFFFF_FFFF`, IANA-reserved so it can never
  collide with a real assignment — but it is not GROPYUS's, and a registered Private Enterprise Number
  is needed before a recording leaves a customer's premises.
- **The Interface Description Blocks name the port, not the interface.** They carry the literals
  `port0` and `port1` rather than the configured id `dataplane-0`. The recorder maps the `cfg` region
  read-only and could use the real names; it does not, and that row is the one `<map>` in the whole
  system description still carrying no `setvar_vaddr`, because Microkit refuses a symbol no ELF
  defines.
- **The extents are compiled in.** `lfw_recorder::deck` fixes both, and the device is the whole of one
  disk. CONCEPT §15.5's per-deployment device count and named-extent binding are untouched, and no
  configuration item names either.
- **No retention bound but the ring's size, and no zeroization.** CONCEPT §15 requires a time bound as
  well; there is none, so how long a node holds traffic is whatever its ring yields at the offered
  rate. Nothing is erased when recording stops, and nothing erases an extent on decommission.
- **Nothing resumes, and nothing rotates or checkpoints on a schedule.** A superblock is written when
  the recorder decides to — at bring-up and after a segment closes — never on a clock; and no boot
  reads one back. `Sink::resume` exists and is host-tested and nothing calls it, so a restart begins a
  fresh ring over the old bytes rather than continuing the segment it left open.
- **One reader, and no live event stream.** The superblock carries four reader-cursor slots and
  nothing registers one. CONCEPT §11 and §15.4 make the OTEL exporter, a syslog exporter and an
  operator console's live event stream readers of this ring; the ring's only reader is the download
  path.
- **A download is the whole recording.** No `Range`, no `If-Match`, no `ETag`, and no way to ask for
  one segment or a time range — CONCEPT §11 asks for a *time range* of a sink. A body over 2 GiB is
  refused outright rather than served wrong.
- **Nothing is measured.** There is no Criterion bench on the tap or the recording path, nothing has
  been measured against CONCEPT §4's 10 Gbit/s target with recording on or off, and the segment size,
  the staging split and the two drain budgets are plausible numbers rather than measured ones. The tap
  adds a per-frame copy and a second header parse to the forwarding path
  ([detail](#zero-copy-dataplane)), and the size of that is unknown.

### Configuration management

**Done.** One schema-validated XML document, `systems/qemu-x86_64/configuration.xml`, is the whole
of the appliance's addressing, and it reaches the dataplane through four stages that never mix.

`crates/config` reads it. The reader is `no_std`, allocator-free and hardened against a
management-plane adversary rather than against a typo: `<!DOCTYPE`, entity declarations, CDATA,
processing instructions and markup declarations are refused outright, only the five predefined
entities and bounded numeric character references are expanded, and every dimension is a named
bound — 64 KiB of document, 8 levels of nesting, 8 attributes per element, 32-byte names and
values. The schema is closed: an unknown element or attribute is a refusal, not something skipped,
because a misspelling nobody can see is the failure an appliance with no shell (CONCEPT §11) cannot
afford. Parsing and semantic validation are separate passes over separate inputs — bytes, then a
model — so a syntax rule cannot come to depend on an address and a topology rule cannot come to
depend on where in the file something was written. Twenty-one semantic rules then run over the model:
a duplicate interface id, neighbour id or port; a port the build does not have; a prefix length past
32; an interface address that is its own prefix's network or broadcast address; a non-unicast
address or MAC on either object; overlapping prefixes; a neighbour naming an unknown interface, or
sitting outside its interface's prefix, or equal to the interface's own address; a duplicate
neighbour address on one interface; and six over the `<management>` element, which is held to the
same field rules as an interface *and* to colliding with no dataplane prefix and no dataplane MAC —
because one address reachable both by routing and by local termination is not something the grant set
can express. A document naming more objects than the handover ABI can carry is refused by the reader
rather than truncated. Every refusal is a typed error naming a **location** and never the offending
bytes (OBS-5).

`config::Datastore` versions what passed. A candidate is staged without touching what is running,
`validate_document` takes `&self` so "an operation that changes nothing" is carried by the signature
rather than by discipline, and a commit assigns the next monotonic generation and returns the diff —
or assigns no generation at all and reports `unchanged`, a content hash held beside the generation
being what recognises a commit of the content already in force. The diff is keyed by the document's
`id`, so reordering the document produces **zero** change records — a property test, not an
intention — and a modified object produces one record per changed field and nothing for the rest.

`pds/config` is a protection domain of its own holding no device capability, no buffer pool and no
dataplane ring, so the domain that parses attacker-supplied XML cannot reach a frame, a NIC, or the
memory either travels through. It writes a fixed-layout POD image of the already-validated model
into a shared region — the forwarder never parses XML, which is the entire point of the split — and
publishes it under a two-phase protocol: offer, the consumer re-checks and acknowledges, then
commit. The two regions are separate and mirrored (`cfg` read-write here and read-only there,
`cfgack` the reverse) so neither domain can forge the other's half.

The image has **two readers with different authority**, which is the shape a second consumer takes
here. The forwarder is the *consumer* of the two-phase commit — it reads the offered generation,
stages a table and acknowledges, and a commit waits for that. The management domain reads the
**committed** generation alone (`pd_runtime::CommittedReader`) to learn its own addressing: it maps
`cfg` read-only, maps `cfgack` not at all, and therefore cannot delay a commit, refuse one on
anybody's behalf, or forge the acknowledgement that releases one.

`pd_runtime::ConfigurationSwitch` is the consumer. It treats the region as a byzantine peer's
claim — copies the image out before deciding on it, exactly as `RouteStage` snapshots a frame, and
re-checks every field: a count past capacity, an `enabled` byte that is neither 0 nor 1, a port with
no driver, a prefix length past 32, a non-unicast MAC — the management entry included, whose fields
are left uninterpreted altogether when it is disabled, so an unaddressed port has one representation
and a zeroed region is still the valid fail-closed image. A refused image leaves the running
configuration exactly as it was and is never acknowledged, so the publisher never commits it. The
switch happens **between two polls** and is provable rather than claimed: a Microkit domain runs one
entrypoint to completion, so a frame is decided entirely under one generation with no lock involved.

Because the forwarder boots fail-closed on generation 0 and the document the image carries commits
as generation 1, **every boot performs a live configuration swap on a running forwarder**, and every
changed value reaches the console as a structured `LFW-CFG` record (see
[MONITORING.md](MONITORING.md)).

Held by 182 tests in `crates/config` and 99 in `crates/log`, by the handover's own tests in
`crates/pd-runtime` — arbitrary region contents read totally and bounded, forged counts, forged
`enabled` bytes, an image round-tripping through the region — and by the 500,000-frame pipeline
test, which now exchanges the forwarding table at poll boundaries throughout and asserts that no
frame is rewritten out of a blend of two, that the pool comes back whole across every commit
boundary, and that payloads arrive in order under those rewritten headers. Two of the five QEMU
system scenarios assert the console transcript, and one of those boots an image built from a second
document that shares no address and no MAC with the first.

**Missing.**

- **No management API and no way to submit a document.** The XML is `include_bytes!`d into the
  configuration domain at build time, so a configuration change requires a new image and a reboot.
  That is a **deviation from CONCEPT §12.3**, which draws the static/dynamic line at hardware and
  holds that a configuration change never requires a reboot; the mechanism that would honour it —
  everything from the document reader to the poll-boundary switch — exists and is exercised on every
  boot, and what is missing is only a channel to deliver a second document over. Everything above
  therefore runs exactly once, at boot, and `validate_document` — the "check this without committing
  it" half of a management API — is implemented, tested, and called by nothing at run time.
- **No rollback.** CONCEPT §12.2's return to an earlier version does not exist. The datastore holds
  the running configuration and at most one candidate, so there is no version history to roll back
  *to*; with no persisted configuration and no channel to submit a second document over there could not be one
  worth holding, every generation but the single one each boot commits being unreachable by
  construction. What is implemented of §12.2's versioning is the part that is reachable: monotonic
  generations, and a content hash beside them that makes re-committing what is already running an
  `unchanged` outcome rather than a new version.
- **No commit-confirm.** The candidate/commit half of CONCEPT §12.2 exists; the confirm half does
  not, and it cannot be built here: an automatic revert needs a deadline, and there is no timer, no
  interrupt and no trusted time source anywhere in this system. It also needs a management channel
  to be *protecting* — the failure commit-confirm exists to survive is a commit that severs the
  operator's own access — and there is no such channel to sever.
- **No persistence.** A block driver now exists and one domain holds a disk capability
  ([detail](#virtio-blk-driver)) — but it is the recorder, it writes recordings and nothing else, and
  it reaches a second data-only device rather than any partition of the boot disk. The configuration
  domain holds no disk capability, there is no path from it to a medium, and a generation still
  cannot outlive a reboot. The DATA partition, where configuration is meant to live, remains an empty
  unformatted GPT entry (see *[A/B image update](#ab-image-update)*).
- **No distributed rollout.** CONCEPT §12.2's staged commit across an HA pair needs a pair; the
  handover protocol is written for exactly one consumer, and "every consumer has staged" is one
  comparison rather than a conjunction.
- **Only interfaces, neighbours and the management interface are configurable.** No routes, no policy,
  no zones, no NAT — none of which exist to configure. Queue depths, pool sizes and buffer extents are deliberately *not*
  runtime configuration: they are memory-region extents fixed in the system description, which is
  where CONCEPT §12.3 draws the line at hardware, and moving one would move a capability grant.
- **Refusal is only visible on the console.** A node that rejected its own document comes up
  forwarding nothing and says so once, on a serial line, and nothing else can be asked. There is no
  `GET /config`, no health signal, and no metric.

### Console device and log transport

**Done.** The console is a device with exactly one owner. `pds/console` holds the only I/O-port
capability that reaches it — `<ioport id="0" addr="0x3f8" size="8" />`, the PC-compatible COM1
window — and is the sole writer of the line; every other domain publishes a typed record into a single-producer
ring of its own and that domain drains, renders and transmits it. A record is therefore whole or
absent rather than spliced with another domain's, which is a property of the capability grant rather
than of scheduling.

`crates/uart-16550` carries the register protocol: interrupts off, 115200 8N1, FIFOs enabled and
emptied, each of the six steps confirmed by a readback before the next is attempted, so an absent
controller (`0xFF` everywhere) and one that took the divisor and then refused the word format are
two different typed errors rather than a node that prints nothing and says why nowhere. Every wait
is bounded by a named constant *of the crate's own* — 1,000 reads for the FIFO confirmation, 10,000
for the transmitter-empty poll — so a UART that never asserts THRE costs the domain its output and
never its liveness. It is driven on the host against a fake that misbehaves on demand, including the
property that initialisation and a write both terminate within their advertised operation bounds for
*any* sequence of device answers; a device that could make either spin would hang that test rather
than fail it, which is the failure being excluded.

Reaching a port is an **invocation of a capability**, not an `in`/`out` instruction: seL4 leaves the
TSS I/O permission bitmap denying every port and never edits it, so the `<ioport>` grant makes the
invocation legal and never the instruction. The first implementation read it the other way, held a
correct grant, and faulted with #GP on `out %al,(%dx)` against `0x3F9` at boot. The
`seL4_X86_IOPort_In8`/`Out8` invocations are the way through and `rust-sel4` exposes both as safe
Rust, so the driver and the domain each carry **zero** `unsafe` blocks — the ENG-13 budget records a
0 for both, and the clock domain's own port adapter carries zero for the same reason. `Com1::claim` then reads every register the driver can address before the domain relies
on the capability, so a grant that no longer covers what the driver reaches is a named refusal
rather than a fault in the middle of a console line.

`crates/wire` carries the transport: a 232-byte fixed-layout `LogRecord` whose every offset is a
static assertion, and a 64-slot ring laid across **two** regions with opposite permissions. The
record grew by the eight bytes of its instant and one discriminant byte taken out of existing
padding, and the slot count did not move: the ring is sized for a boot transcript whose first
generation alone is 16 change records, and 64 records of 232 bytes still fit the 16 KiB the region
already rounded to. The
records region (slots, producer cursor, the writer's drop count) is read-write to the writing domain
and read-only to the console, so the console cannot forge a line attributed to a domain that never
emitted one — it is the domain whose output is read as testimony about the others. The consume
region (the console's cursor, one word) is read-write to the console and read-only to the writer, so
a writer cannot forge how much of its own ring has been read and quietly reuse slots the console
never rendered. Fourteen regions, 140 KiB, one pair per writing domain; no writer maps another writer's.

The console busy-polls and never leaves `init`, exactly as the NIC drivers do — Microkit has no
periodic wakeup, so a `notified`-driven console would stall a boot transcript longer than the
16-byte FIFO until some unrelated domain happened to log again. Its priority is 1, *equal* to the
drivers rather than above them, so a 115200-baud write cannot preempt the dataplane. Attention is
shared round-robin with a rotating start and at most eight records taken from any one ring per pass,
both constants of this build: a domain that fills its ring faster than the line drains costs the
others a delay and never their records.

Two persistent fuzz targets drive it (`log_record`, `log_ring`), the second modelling both sides as
independently hostile — a forged cursor arriving between two steps of one drain, a slot rewritten
one atomic at a time, which is the only granularity at which a torn record is expressible. One
asserts OBS-5 directly: no record the ABI accepts can put a byte outside printable ASCII into a
rendered console line, and no text value can carry one outside `[a-z0-9-]`, so a hostile peer cannot
paint terminal escape sequences onto an operator's console.

Every end-to-end scenario now boots the **release** image, and two of the six system scenarios
assert the `LFW-CFG` console contract on it, against a transcript derived from the document the
image under test was built from; the same two hold the management port's `LFW-PD` count to the frames
the harness injected. Both halves were needed to make the defect non-recurring: a missing
console went unnoticed because no gate on the push path booted a release artifact at all, and
because the one stage that did booted it against the forwarding contract alone — and a dataplane is
indifferent to whether anything is printed.

**Missing.**

- **No interrupt.** The transmitter is polled, and the domain never blocks, so the console burns a
  share of a core for as long as the node runs. An interrupt-driven transmitter would remove the
  polling entirely; it needs the system's first `<irq>` element — a second new capability class in
  one change — and was deliberately not bundled with the first `<ioport>`.
- **No `GET /logs` retention ring.** The log rings are a transport to the line, not storage: a
  record the console has rendered is gone. There is no second reader, no retention, and nothing to
  query after the fact — the transcript exists only in whatever captured the serial port.
- **No flow control, in either sense.** The link has none — nothing on either end asserts DTR/RTS,
  and a console that blocked on a peer's readiness would stop reporting exactly when the node is in
  trouble. Nor does the ring throttle a writer: a full ring refuses the *newest* record and counts
  it, so a domain that outruns the line loses records with nothing slowing it down.
- **One port, one baud, both compiled in.** `0x3F8` and a divisor of 1 (115200) are build-time
  constants matched to the `<ioport>` grant, because a runtime base is a value the capability could
  not follow. There is no second console, no second UART, and no way to move either without a
  rebuild.
- **The console is no longer the system's only port holder.** The clock domain holds the CMOS pair,
  so "an attacker reaching any other domain reaches no port instruction" is narrower than it was:
  what holds now is that the two windows are disjoint and each has exactly one holder.
- **No Azure hardware has ever run this.** Azure Serial Console attaches to "ttyS0 or COM1" and QEMU
  q35 exposes COM1 as a 16550A, so this is the same device *by documentation* — which is why there
  is one driver and not two. It is not the same device by test: nothing in this repository has ever
  booted on an Azure VM, and the differences Microsoft documents are about availability (boot
  diagnostics enabled; the serial console possibly unavailable after live-migrating a Generation 2
  Trusted Launch VM with Secure Boot) rather than about registers.
- **The I/O-port CNode slot is hand-rolled and unchecked at build time, now in two places.**
  Microkit publishes a base slot constant for every capability class a domain can hold *except* this
  one, so the slot number is written out in `pds/console/src/com1.rs` and again in
  `pds/clock/src/cmos.rs` as a cross-artifact fact — each read from its own domain's CNode in the
  generated report, the two happening to agree. Its only detection is the
  pinned SDK version (`MICROKIT_VERSION=2.3.0`, checksum-verified, moved only through the full gate)
  read against the generated capability report; nothing compares the two automatically. What limits
  the damage is enforcement rather than detection: `Com1::claim` invokes the capability first, so a
  slot the tool moved is refused by name.
- **The single-writer property is exact only in release.** The debug kernel is built with
  `CONFIG_PRINTING` and writes the *same* port for its boot banner and its fault reports — it is
  handed `debug_port = 0x3f8` on the Multiboot2 command line, which is visible in the capture of any
  debug boot (a diagnostic re-run's `build/image/*-debug.log`, or `make run`) and in none of the
  captures the gate writes, those being release boots. That is accepted, the kernel printing on boot
  and on faults rather than per record, and it is why the claim is stated of the shipped profile.
- **The console cannot report its own failure to start.** From entry into `init` until the register
  sequence returns, the reporting mechanism is what is being started. A refused *capability* is named
  on the debug kernel's channel, which does not exist in a release image; a refused *controller* — one
  of six distinct errors the driver distinguishes — reaches nothing at all, and the node prints
  nothing. Diagnosing that is one bit where the driver has six. Closing it needs a reporting channel
  independent of the console.
- **Every counter here is now published rather than only tallied.** The UART's bytes written, THRE
  timeouts and init failures; the renderer's printed, malformed, unknown, unrenderable and write-failed; each
  writer's dropped and refused. All of them are now published and scrapable (see *Prometheus
  `/metrics`*), so a console that is silently dropping records says so on the other surface — which
  is the whole of what closes this, since the console cannot report its own silence.
- **A record that will not render is now dropped, not reported.** It is counted as `unrenderable`
  and nothing is written. The previous transport wrote a `LFW-PD unrendered=<debug form>` line
  instead; that line is gone, and MONITORING.md no longer promises it.

### Console system-state events

**Done.** The five ad-hoc bring-up markers are gone. Call sites in all seven protection-domain
binaries emit **typed events** — a closed set of named fields — and rendering happens once, in the
console domain, so the attribute structure an OpenTelemetry record needs is produced at the call
site rather than thrown away in a format string, and the structure is what crosses between domains
rather than the text. Two channels of closed vocabulary reach the line,
`LFW-PD time=… domain=… state=…` for a domain's lifecycle and `LFW-CFG time=… generation=… …` for
configuration, both specified field for field in [MONITORING.md](MONITORING.md) and matching the
existing `LFW-BOOT` convention, so a reader keys on the `LFW-` prefix alone. The instant is the
first field of both and is the emitting domain's own, taken at the moment of emission; the
pre-kernel `LFW-BOOT` channel has none, having no domain and no calibration behind it.

That the values are safe to print is structural rather than a rule to remember: an event's value
type is a closed set of already-parsed domain types with no arbitrary-bytes variant, and the one
route text takes from a configuration document to a console line is an identifier validated to
`[a-z0-9-]{1,16}` at parse time. Rendering is allocator-free into a caller's buffer and **refuses**
rather than truncates, a truncated line being one an operator reads as complete. The transcript is
a machine-checked contract, not prose: a QEMU scenario derives the records a document must produce
by running that document through the same two calls the domain makes and the same renderer its
console backend uses, then asserts the boot's `LFW-CFG` channel against it — record for record, less
each record's instant, which is the one field a build cannot predict and which a contract of its own
judges over every channel at once.

**Missing.**

- **The forwarder never reports its own outcome.** It emits `state=starting` and nothing further —
  no `ready`, no failure — so MONITORING.md's "each stage reporting healthy or the specific fault"
  holds for the driver, configuration, clock, management and recorder domains and not for the one
  that carries traffic. (The management domain gained a refusal path with its transport: it refuses
  to start at all when the hardware will not produce a per-boot secret for its sequence numbers,
  reports a published calibration it will not use without refusing to run, and — new with the
  recordings — reports an endpoint that could not register both download targets, again without
  refusing to run. The recorder reports the medium it found and where each recording lives, which is
  the only place an operator learns an extent.)
- **Nothing orders one domain's records against another's.** Within a domain they are totally
  ordered — one writer per ring, drained in the order it wrote them, with non-decreasing instants —
  and a `generation`/`seq` pair totally orders one commit's change records. Across domains there is
  no order at all: which ring is served first is decided by where the console's rotation stood. The
  instant every record now carries does not repair that. Two domains' instants are comparable
  arithmetic, but nothing serialises two domains against each other, so a record printed first
  routinely carries the later instant.
  The boot capture above shows the forwarding domain's `generation=1 outcome=applied` printed
  *before* the change records that generation is made of, which is not a fault. A reader that infers
  causality from console order is inferring it from the fairness rule.
- **Interleaving is prevented in the shipped profile only.** Records no longer tear: the port has one
  owner and one writer, so a line is whole or absent. That holds exactly in release. The debug
  kernel is built with `CONFIG_PRINTING` and writes the same port for its boot banner and fault
  reports, so a debug capture can still carry kernel prose across a record — which is why
  MONITORING.md still obliges a reader to recover records by scanning for the `LFW-` prefix rather
  than by assuming one line is one record.
- **No fault or restart events**, because there is no fault handler and no PD restart to report.
- **A record that cannot be rendered or encoded is counted and lost**, where it used to be written
  out in a debug form. See *[Console device and log transport](#console-device-and-log-transport)*.
- **Nothing beyond the console.** These are the OTEL log stream's System category by construction,
  but no transport exists (see the status table), so the records reach an operator only over a
  serial line, on a node they are already attached to.

### Full port role model

**Done.** One of the four roles CONCEPT §9.1 names exists, and it is an **addressed IPv4 endpoint
that terminates TCP connections**: a **dedicated management port** that answers for itself, carries no
forwarded traffic, and is isolated from the dataplane by a grant set. It is a third `virtio-net-pci` device at 00:04.0,
driven by a third instance of the same `nic-driver.elf` the two dataplane ports use — the binary
turned out to be port-agnostic already, so the third port cost it no code change — and its frames end
at a `management` protection domain.

That domain answers three protocols and counts everything: an **ARP request** for its own address is
answered with its own MAC; an **ICMP echo request** to it is answered with a reply carrying the same
identifier, sequence and payload and both checksums recomputed; and a **TCP connection** to port 80
is accepted, carried and closed by a first-party stack ([detail](#proxy-tcp-stack)), over which an
HTTP/1.1 server answers `GET /metrics` ([detail](#prometheus-metrics)). Everything else is refused by name and counted — a frame addressed to somebody else, a VLAN tag, an EtherType or IP protocol it does
not speak, a fragment, a non-unicast or off-link sender, a malformed header.

The decision is three host-tested `no_std` crates. `crates/net-headers` gained ARP (IPv4 over Ethernet
only; any other hardware type, protocol type, address length or operation is a typed error) and ICMP
echo, parsing into fixed-size chunks so no accessor has a panicking path, plus the two reply builders
and one checksum routine. `crates/ip-endpoint` is the endpoint state machine — the appliance answering
*for itself*, as against `crates/routing`, which forwards for others — with zero `unsafe`, a closed
`Outcome` vocabulary, and a counter per outcome; it now owns a `crates/tcp` stack and the HTTP
server above it, and keeps the transport's advertised window equal to that server's free
space. `pd_runtime::EndpointStage` joins it to the two
pipelines: copy the frame out of the receive pool, decide, and where a reply was composed take a
transmit buffer, write the reply into it and lend it to the driver.

The addressing is **configured, not compiled in**. `systems/qemu-x86_64/configuration.xml` gained a
`<management mac= address= prefix-length= enabled=/>` element — a sibling of `<interfaces>`, because
the port is not a dataplane port and `config::PORT_COUNT` is still 2 — which the schema requires, the
validator holds to its own rules *and* to not colliding with any dataplane prefix or MAC, and the
handover image carries to the domain. QEMU takes that MAC for the guest NIC, and the harness derives
its own station address from that prefix, so no address on the bench is written down twice.

It also **reads two instructions and holds no capability for either**: `RDTSC`, for the instant its
transport's timers are stated against and for the one on every record it emits, and `RDRAND` once at
start-up, for the secret those connections' initial sequence numbers are derived from. Both are
unprivileged, so nothing in the system description grants or could withhold them; a part with no
`RDRAND` refuses the domain and names the cause on the console rather than answering a `SYN` with a
predictable number. `RDRAND` is now this domain's only `unsafe` block: the counter read moved into
`pd_runtime`, where one seam serves every domain that stamps a record.

The domain reads the **committed** generation only (`pd_runtime::CommittedReader`): it maps the
configuration region read-only, the calibration region read-only, and the acknowledgement region
**not at all**, and so cannot delay a
commit, refuse one on anybody's behalf, or forge the acknowledgement that releases one. That is
strictly weaker than the forwarder's role, which is the consumer of the two-phase commit. What it
costs is stated where it lives: with no channel to the configuration domain, the port picks up its
address on the next frame that wakes it.

The isolation is a grant set, not a rule anybody has to remember. The management domain holds **no**
dataplane region, no device capability and no I/O port; the forwarder holds no management region; the
receive pool it reads is mapped **read-only**, because a frame this appliance was sent is parsed and
never altered; and `xtask::sysdesc` names the mapper set *and the perms* of every region exactly, so a
widened grant fails the gate at the point the edit is made. The management port is not in the router's
port set and no configuration document can put it there.

Its two pools are owned by different domains in opposite directions — the driver owns the receive
pool, the management domain owns the transmit pool it composes replies into — so each `free` ring has
one producer and one consumer and a forged return is refused by a ledger rather than believed. That is
`pd_runtime::EndpointStage`, host-tested against a byzantine driver: forged indices, unbelievable
spans, a stalled return ring, an exhausted transmit pool, a duplicate return on the reply pipeline,
and a pool-sized run proving every buffer comes back.

The QEMU gate asserts all of it on the release image. Every system scenario injects six frames into
the management port once the capture proves every port is up — four opaque frames of four different
lengths, an ARP request and an ICMP echo request — then opens a TCP connection with a minimal
deterministic client of its own, and then requires:

- a **well-formed ARP reply** carrying the configured MAC, decoded and compared field by field;
- a **well-formed ICMP echo reply** with matching identifier, sequence and payload and a valid
  checksum, likewise decoded rather than matched as bytes;
- a **whole TCP exchange**, every step asserted as a field comparison: `SYN` → a `SYN-ACK` whose
  flags and acknowledgement number are checked and whose sequence number is *kept*, → `ACK` carrying
  a `GET /metrics` → the **response as a stream**, fifty-odd segments acknowledged one at a time and
  reassembled in order, its `Content-Length` held to the bytes that arrived → the appliance's `FIN`,
  `Connection: close` obliging it to close first → the client's `FIN` → the final `ACK`. Every
  segment's pseudo-header checksum is verified by the harness's own summation, and a segment arriving
  at a step it does not belong to is refused;
- **distinct initial sequence numbers across the boots**, compared between scenarios — two boots of
  one disk are separated only by the per-boot `RDRAND` secret and the time component, so an equal
  pair would mean one of the two is not reaching the generator (RFC 6528);
- **exactly one of each stateless reply**, since one request is one reply;
- **nothing else on that wire at all** — no opaque frame answered, no dataplane probe leaked;
- and the **mutual exclusion in both directions**: no frame the harness put on the management wire
  ever appears on a dataplane port, and no dataplane probe ever appears on the management port.

Two of the five scenarios additionally hold the console's own record to the frames and the bytes
injected — every one of them, the TCP client's segments included, accumulated as the harness sends
them rather than tallied in advance — to the frame and to the byte; and one of the three boots a
*second* document whose management MAC, address and prefix all differ, so a compiled-in address could
not satisfy it.

**Missing.**

- **No TLS.** HTTP answers `GET /metrics` ([detail](#prometheus-metrics)) and both recordings
  ([detail](#recording-and-download)), but in the clear: CONCEPT §11 requires mutual TLS on the
  management interface and there is none, so anyone who can reach the port can scrape it — and now
  download every packet the appliance recorded. `/config` and `/logs` do not exist.
- **No ARP cache and no ARP request is ever sent.** Nothing on the port originates a connection, so
  there is nothing for a cache to serve; a reply goes to the MAC its request arrived from. An RFC 5227
  probe (sender address 0.0.0.0) is refused rather than answered, so a second station claiming this
  address is not contradicted.
- **A reply is only ever composed for a neighbour**: the sender must share the port's prefix, because
  there is no route table and no gateway behind this endpoint. An off-link station is refused and
  counted.
- **The counters reach no surface.** The console carries the port's cumulative `frames=`/`bytes=` pair
  and nothing else, so every outcome the endpoint distinguishes — and every reply it could not send —
  is invisible to an operator. They belong on `/metrics` (CONCEPT §11), which does not exist.
- **A change to the management interface is audited like any other**, but only because the change
  records are keyed by a synthetic identifier: the element has no `id` of its own, so every record
  about it reads `object=management key=management`.
- **No other role.** Session-replication, mirror and multiple port pairs are open, and so are the
  3/4/6/7-NIC hardware image variants: there is one system description with three ports in it.

### Proxy TCP stack

**Done.** `crates/tcp` is a first-party TCP implementation that completes a real handshake with a
real client, carries a byte stream, and closes cleanly — proven on the booting **release** image by
the gate performing a whole TCP exchange against the management port. It is not a
management-endpoint toy: it is the stack the dataplane proxy will run on, and every constraint below
comes from that.

It was chosen over smoltcp for one reason: smoltcp carries a stream through `RingBuffer` socket
buffers, and a copy per segment is what a zero-copy pool design cannot afford. So **the crate owns
no buffers at all.** A received segment arrives as `&[u8]` — in the appliance, a pool buffer a NIC
DMA'd into — and the in-order payload comes back out as a subslice of it; a segment to send is
composed into a `&mut [u8]` the caller supplies, at the offset it will finally occupy, and
`net_headers::Ipv4Frame` stamps the two headers in front of it afterwards, so a payload is written
exactly once. The cost is a real obligation, and it is in the type system rather than in prose:
`Timeout::Retransmit` names a sequence range the caller must supply the bytes of again, because the
stack did not keep them. That is where a send buffer belongs — with the application that produced
the bytes.

**State is per shard and nothing is shared.** A `TcpStack<CONNECTIONS>` owns its whole connection
table and reaches no `static`, no lock, no cell and no atomic; every method takes `&mut self`, so
several instances run on several cores with no coordination and the compiler is what says so
(ENG-2). The capacity is a const generic, so a shard's memory is fixed at compile time and sized by
its caller. There is no allocator and no `alloc`.

What the passive-open path implements, completely:

- **RFC 793's state machine** as a passive open reaches it: `LISTEN` → `SYN_RECEIVED` →
  `ESTABLISHED` → `CLOSE_WAIT`/`LAST_ACK`, `FIN_WAIT_1`/`FIN_WAIT_2`, `CLOSING` (the simultaneous
  close), `TIME_WAIT` and `CLOSED`.
- **Sequence-number validation.** RFC 793 p.69's four-case acceptability test; an out-of-window
  segment is answered with an acknowledgement naming what was expected and never accepted, and a
  retransmission overlapping the window's left edge is trimmed rather than refused.
- **RFC 5961 validation**, applied in *every* state rather than only the synchronized ones: a `RST`
  is obeyed only at the exact next byte expected, and an in-window one that is not — like an
  in-window `SYN` — gets a challenge acknowledgement.
- **RFC 6298 retransmission**: SRTT and RTTVAR with the RFC's own α and β, the RFC's one-second
  floor, a 60-second ceiling, exponential backoff, and Karn's algorithm — a range that has been
  re-sent yields no round-trip sample. The `SYN-ACK` and the `FIN` the stack composes itself; data
  it asks the caller for.
- **RFC 6528 initial sequence numbers**: a 4-microsecond time component plus SipHash-2-4 of the
  4-tuple under a 128-bit per-boot secret. The hash is first-party and held to the published
  reference vectors, so it is checked against something other than itself. The secret comes from
  `RDRAND` in the protection domain; a part without it refuses the domain rather than answering with
  a predictable number, because a predictable one is an off-path injection primitive against exactly
  the party this port faces.
- **Bounded state under a flood.** A fixed table, reaped by timeout *and* by capacity pressure —
  the oldest reapable entry gives way, and a table of *established* connections refuses a new one
  rather than letting a peer that completes handshakes evict everybody else. Every connection
  becomes reapable in finite time, which is a property test rather than a claim.
- **MSS clamping** (the peer's offer against this end's own limit, with RFC 1122's default and
  floor), **window scaling** (RFC 7323, negotiated at the `SYN` and clamped to shift 14), and
  correct pseudo-header checksums both ways.
- **The advertised window is the receiver's free space**, not a constant: `lfw_ip_endpoint`'s HTTP
  server keeps it equal to the room it has left, so a peer is never told it may send more than the
  endpoint can take.

Every outcome is counted, one field per cause — twenty-five of them — under MONITORING.md's
attribution rule: what a peer sent that was refused, and separately the one count that accuses this
code (`write_refused`, storage too small, expected to read zero forever). There is no device class
here, because nothing in the crate reads a register.

Zero `unsafe` (`forbid(unsafe_code)`), zero panicking constructs on any path a segment reaches, and
sequence arithmetic that is modulo-2^32 by construction: `SeqNumber` exposes no `Add`, `Sub` or
`Ord`, because the derivable ones are all wrong across the wrap. 99.7% line coverage over 126 unit
and property tests, plus a persistent fuzz target that drives arbitrary segments at arbitrary
instants — including a clock that moves backwards — against a listening stack and an established
one.

**Missing.**

- **No active open.** Nothing in the appliance originates a connection, so `SYN_SENT` and the
  simultaneous-open path have no caller; they arrive with the proxy.
- **No SACK.** Its value is retransmitting the holes in a reassembly queue, and there is no
  reassembly queue — that would be a buffer the crate owns. The SACK-permitted option is parsed and
  recorded, so adding it is a change to the state machine rather than to the parser.
- **No reassembly, so no out-of-order data.** In-window payload ahead of the next byte expected is
  dropped and re-requested by the acknowledgement that follows, counted as `refused_out_of_order`.
  On a lossless in-order link — a management port, a same-host proxy hop — the case does not arise;
  on a reordering path it costs a round trip per reorder.
- **No congestion control**, no delayed acknowledgement, no Nagle. The structural place for the
  first is `Connection::sendable`; the other two need a timer this stack is not driven by.
- **The urgent pointer is ignored.** `URG` data is delivered in band and counted.
- **No dataplane consumer.** The only caller is the management endpoint. Nothing proxies, nothing
  terminates TLS, and no throughput has been measured — the 10 Gbit/s target this design exists for
  is untouched (see the status table).
- **`RDRAND` is now a hard hardware requirement.** A part whose `CPUID.01H:ECX[30]` is clear refuses
  the management domain outright, so that node has no management port for the boot. The QEMU bench had
  to be told to expose it (`tools/xtask/src/qemu.rs`); every deployment target must have it. There is
  no software fallback and deliberately so — the alternative is a predictable sequence number, which
  is worse than no port.
- **Timers advance when the caller polls them.** The management domain is woken by a frame, so a
  `TIME_WAIT` on an otherwise silent port is reaped on the next frame rather than at its deadline.
  Bounded rather than unbounded — the table is also reaped under pressure — but not prompt.
- **The counters now reach a surface.** All twenty-five are published as
  `librefirewall_tcp_*` and scrapable; see *[Prometheus metrics](#prometheus-metrics)* and
  [MONITORING.md](MONITORING.md).

### Prometheus metrics

**Partial.** `GET /metrics` on the management port answers a real Prometheus exposition — 74 metric
families, 253 series, about 32 KiB — covering every one of the nine protection domains, and the
end-to-end gate scrapes it with `curl` off a booted release image and cross-checks a number in it
against traffic the harness watched cross the wire itself.

**A per-NIC series is joinable to the interface a configuration document names.** Every counter
family carries `domain`, the protection domain that produced it, and `domain="nic_driver0"` is a name
out of the Microkit system description that says nothing about what an operator configured. Closing
that took the conventional Prometheus info metric rather than more labels on the counters:
`librefirewall_interface_info` is a gauge whose value is always `1`, one series per configured
interface, carrying the document's own `id`, the port's `role`, its address, prefix length and MAC —
and carrying `domain` as the join key, so a query multiplies the two together
(`* on(domain) group_left(interface, role, address)`). Counter cardinality is unchanged and a
re-addressed interface does not fork every counter series it has. There is deliberately no `enabled`
label: a dataplane interface has a series whether or not it is enabled — its addressing is in the
image either way, because the router needs the row to refuse traffic on it — while a disabled
`<management>` element is indistinguishable from an absent one, so a truthful `enabled` would have to
be ragged across the two roles and nothing consumes it. MONITORING.md states the family, the
worked join, the bound on its cardinality and that asymmetry; the interface identity crosses to the management domain
in the configuration image it already reads, and the port-to-driver mapping the join key rests on is a
fact of the system description that `xtask::sysdesc` now checks at build time rather than a comment
delegating it (DOC-7).

The decision that shapes it is **one shared-memory counter shard per protection domain**, not one
shared table. A shard is a 768-byte, cache-line aligned array of 96 `AtomicU64` slots, mapped
read-write into the one domain that owns it and read-only into the management domain; slot order is
the catalogue's series order, asserted statically. So a domain publishes by relaxed store into memory
nobody else may write, and the management domain renders by reading nine regions — no lock, no
barrier, no seqlock, and nothing a dataplane domain does on a scrape. Counters are individually
meaningful, so a scrape that straddles two domains' publications is still exactly what each of them
last wrote; that is stated as a freshness boundary in MONITORING.md rather than papered over.

The exposition is rendered by `crates/metrics` (`no_std`, panic-free, with a computed
`MAX_EXPOSITION_LEN` so the buffer can never be short) and the requests are parsed by `crates/http`
(`no_std`, a bounded server-side HTTP/1.1 head parser that returns a typed error mapping onto one of
eight statuses). Both are fuzzed. The management domain publishes its own shard *before* rendering,
so a scrape always reports the request that asked for it.

**Missing.**

- **No mutual TLS — the endpoint is plain HTTP with no client authentication.** CONCEPT §11 requires
  mTLS on the management interface. Anyone who can reach the port can scrape it, and the exposition
  names every domain, drop reason and fault class in the node. This is a **deviation from CONCEPT**,
  recorded here and in `lfw_ip_endpoint`'s crate header, and it gates any deployment on a network
  the management interface is not already isolated on.
- **One response is staged at a time.** A scrape arriving while another is still going out is
  answered `503` and counted. A finished-but-not-yet-reaped connection's buffer is reclaimed rather
  than waited out, so a periodic scraper is never refused for the previous scrape — but two
  *concurrent* scrapers can refuse each other.
- **Coverage is what exists to be counted.** Per-core counters await the multicore dataplane, queue
  and ring occupancy and flow-table numbers await the stateful dataplane, and log-buffer occupancy
  awaits the buffer. None of them are absent by oversight.
- **No `/config` and no `/logs`**, so the debug dump has only its state half.

### Trusted time source

**Done.** A node establishes a wall-clock time at boot, and the whole chain that does it is
host-tested library code driven by a thin domain. `crates/clock` is the arithmetic — a tick delta
and a reference interval to a counter frequency, a counter reading to nanoseconds since boot or
since the epoch, an instant to a civil date and to an RFC 3339 line — with Hinnant's era
decomposition proved by an exhaustive round trip over every day a `u64` of nanoseconds can name.
`crates/hpet` is the reference measurement: it decides whether the block at `0xFED00000` is an HPET,
starts its main counter and measures a bounded span of it, and it earns that role by being
*self-describing* — the capabilities register states its own tick period, so no frequency is
assumed anywhere. `crates/rtc` is the epoch: the CMOS index/data protocol, two agreeing snapshots
before anything is decoded, and every field ranged.

`pds/clock` joins them. It maps the HPET page (three `unsafe` volatile accesses, each naming the
`<memory_region>` row that guarantees it), holds an `<ioport>` for `0x70`–`0x71` and proves the
capability answers before relying on it, calibrates over a one-millisecond window, reads the part
once, and emits a single `LFW-PD domain=clock state=ready tsc-hz=… utc=…` record. Every stage that
can refuse does so with a typed error carrying what the device answered; the domain turns each into
one of 25 console cause tokens and parks. Two of the five QEMU system scenarios assert that record
on the release image — that it is `ready`, that its frequency is inside the band the calibration
accepts, and that its year is inside the band the RTC reader accepts.

**Every domain consumes it, and every structured record carries an instant.** The calibration goes
into a shared region (`wire::ClockCalibration`, a seqlock: even settled, odd being written) that the
clock domain maps read-write and the other seven read-only. Each reads `RDTSC` itself — one
unprivileged instruction, behind the single `unsafe` seam in `pd_runtime::read_timestamp_counter` —
converts it with the published triple, and stamps the record it is about to emit, so an instant is
this node's own arithmetic over one counter rather than a value passed between domains. The console
renders it as a leading `time=` field in RFC 3339 with all nine fractional digits. A domain that has
no calibration yet emits `time=unsynchronized`: the absence is a case of the type all the way down
(`wire::CheckedStamp`, `lfw_log::Stamp`) rather than a zero, so no record can be dated 1970 by
accident. That is most of a boot transcript, the clock domain's own two records included — it
publishes *after* the record that states what it measured. The same two scenarios assert the whole
of this against the release image: that every record carries the field in one of its two forms, that
every instant is inside the RTC reader's year band, that no domain goes back to `unsynchronized`
after stamping, and that no domain's instants go backwards.

**Missing** — and it is everything the word *trusted* covers:

- **The time is unauthenticated and unattested.** It comes from a battery-backed register file that
  any firmware, hypervisor or dead battery can make say anything plausible. There is no NTP, no
  Roughtime, no signed time source and no attestation, so a wrong-but-plausible instant is
  indistinguishable from a right one. CONCEPT §7.2 makes certificate validity depend on accurate
  time; nothing here may be used for that.
- **UTC is assumed, not discovered.** The CMOS carries no field saying whether it holds UTC or local
  time. A machine whose firmware set it to local time yields an epoch wrong by that zone's offset,
  detectably by nothing.
- **Accurate to about a second, and nothing checks that.** The epoch is one whole-second CMOS
  reading; the nanoseconds under it are elapsed counter ticks, which are precise and say nothing
  about how well the epoch was set. A record's instant is therefore good enough to line a node up
  against an external log to about a second, and is evidence of nothing.
- **No metric says which domain has taken the calibration up.** It is readable per record on the log
  stream (`time=unsynchronized` against an instant) and `/metrics` carries the gauge for the
  management domain alone; the other six writing domains publish no such series
  ([MONITORING.md](MONITORING.md)).
- **No discipline and no monotonic guarantee across domains.** The part is read exactly once and
  never corrected; there is no timer, no interrupt, and no second reading to drift against.
- **Single-core assumption.** The calibration is a reading of one core's counter, with no check that
  the counter is invariant and no per-core anchoring — neither of which matters on the single vCPU
  this system runs on and both of which would on any multicore variant.
- **The measurement is biased high by its own overhead**, by one uncached timer read at each end of
  the window: parts in a thousand at worst, stated in `pds/clock` rather than corrected, because
  subtracting an estimate would replace a bounded one-signed error with an unbounded one.

### Protection-domain decomposition

**Done.** Nine protection domains from seven binaries (one forwarder, one configuration domain, one
console, one clock, one management endpoint, one recorder, three driver instances of one driver
binary) with real,
verifiable least
privilege: the
forwarder holds no device capability at all
and neither dataplane pipeline's `free` ring — so it cannot hand a live DMA target back to be issued a
second
time — and each driver sees only its own ECAM page, BAR, virtqueue region, and its two pipelines.
Each pipeline is three memory regions rather than one precisely so that those grants can differ; the
forwarder maps the buffer pools, because a domain that rewrites a header must reach the bytes. The
recorder is the mirror of that argument in the other direction: it is the only domain that reaches
the block device — its ECAM page, BAR, DMA region and staging window are mapped by nothing else — and
it maps no pool, no ring, no NIC region and no port, so the domain that owns the disk reaches no
frame and the domains that move frames reach no medium. What crosses between them is a tap ring
carrying annotations rather than packets, mirrored in perms so neither end can forge the other's
half. The
configuration domain's entire grant is two 4 KiB regions: no device, no pool, no ring, so the domain
that parses attacker-supplied XML cannot reach a frame or a NIC. Those two regions are one per
direction, and their perms are the argument — the forwarder maps the handover **read-only**, so it
cannot rewrite the configuration it is about to be judged by, and the publisher maps the
acknowledgement read-only, so it cannot forge the consent that releases its own generation.

Five notification channels. The three driver channels are granted in **one direction only** — a driver
may signal its consumer, and that consumer's send capability on the driver does not exist rather
than merely going unexercised. The recorder's channel to the management domain is one-directional
too, and in the opposite sense: the recorder may announce a download window, and the management
domain may not signal back, because the recorder busy-polls its request region and a send capability
it does not need is one it must not hold. The fifth, between the configuration domain and the
forwarder, is the
one granted in **both**, and stated as a decision at both ends rather than inherited from Microkit's
default: applying a configuration is a two-phase commit and each phase is a signal the other end
cannot infer. The forwarder therefore holds exactly one send capability in the whole system, on the
configuration domain alone, and the management domain holds none at all. The console holds none in
either direction — it never reaches the event
loop, so a notification on it would be authority granted for nothing. Zero IRQs. The capability
grant is machine-checkable in the Microkit capability/memory report the build generates.

Two **`<ioport>` grants**, on two domains, and they are the whole of the system's port authority.
Neither of the two instructions the management domain reads is one: `RDTSC` and `RDRAND` are
unprivileged, so no grant makes them available and none could withhold them — which is why a part
without `RDRAND` is a refusal that domain reports rather than a capability anybody could add.
The console holds eight ports (`0x3F8`–`0x3FF`, COM1) and the clock two (`0x70`–`0x71`, the CMOS
address and data registers); the other 65,526 are refused to every domain — notably the
`0xCF8`/`0xCFC` PCI configuration pair, which would be a second path to every device's configuration
space beside the ECAM mappings the drivers hold. The two windows are disjoint and neither domain
holds the other's, so the domain that renders an operator's only output cannot read or stop the
clock and the domain that reads a battery-backed register file cannot write the line its result
appears on. The drivers, the forwarder and the management domain hold zero ports between them. Each of the two in
turn
holds no pool, no dataplane ring and no configuration region, and the clock additionally holds no
ECAM page and no BAR window beyond the single timer page it maps — so a compromise of either reaches
no frame, no NIC and no configuration.

The management domain's grant is its own port's two pipelines, the configuration and calibration
regions **read-only**, and its own log ring; what it withholds is the whole of the port isolation: no
dataplane region of any kind, no ECAM page, no BAR window, no virtqueue, no I/O port and no
acknowledgement region. Of the six pipeline regions the receive **pool** is read-only — a frame this
appliance was sent is parsed and never altered — while the transmit pool is read-write, because a
reply is a frame this domain originates into a buffer it owns. The two read-only grants are the
argument in each case: a domain that could write `cfg` would rewrite the addressing it is about to be
judged by, and one that could write the calibration would move this node's own idea of time — every
transport deadline on its port — from the one domain that answers the management-plane attacker. The
one region it is granted read-write that the forwarder is refused is the receive pipeline's `free`
ring, and it is the side of it that differs: a terminal port has no egress driver to return its
buffers, so this domain **produces** returns while the driver **consumes** them as the pool's owner —
the split the dataplane already has between its two drivers, which is what keeps a forged return
refused by the ledger rather than believed.

Reaching a port is an **invocation**, never an `in`/`out` instruction; that lesson was paid for once
on the console's first boot and `pds/clock/src/cmos.rs` is written from it. Both domains prove the
capability answers before relying on it, so a slot the Microkit tool moved is a named refusal rather
than a fault mid-sequence.

**Missing.** Two of the fourteen component classes in CONCEPT §6.3 exist: the NIC driver PDs and the
configuration validator PD. The console, clock and management domains are three further domains and
*not* three
further classes — §6.3 enumerates neither, describing the console as a surface and leaving the
trusted-time mechanism open (§13.1) — so they add domains to the decomposition without closing any
of the gap below — the management domain is the endpoint of a port, not the management API PD, which
needs the TLS and HTTP that do not exist above the ARP, IP and TCP that now do. Absent: Rx/Tx virtualisers,
classifier,
filter/connection-tracking, routing/ARP/ICMP, TLS-proxy, per-protocol L7 parsers, DPI engine,
content scanner, CA signing PD, management API PD, HA state-sync PD, and the update/health PD. The
routing/ARP/ICMP class is the one that is neither: routing exists as a *stage inside* the forwarder
rather than as a domain of its own, and ARP and ICMP do not exist at all. There is no fault handler
and no PD restart, one system description, and no SMP variant.

One grant is also wider than the code needs, and it is not closed:

- **The `-m 1G` QEMU memory size is load-bearing and unasserted.** It is what keeps the virtqueue
  and pipeline regions inside RAM while leaving the BAR window above RAM in the q35 PCI hole. The
  window either side is narrow, and the management port's two pipelines have just **narrowed it
  further**: RAM must now reach past 784.55 MiB rather than 784.27 MiB, and every port added narrows
  it again; at 1280 MiB or more RAM swallows the BAR window. The reasoning is recorded in the system
  description; no code enforces it.

### Untrusted-device hardening

**Done.** Every byte the device writes — configuration-space ids, the capability chain, BAR type
bits, structure offsets, the feature bitmap, the `device_status` readback, the queue count, each
queue's `queue_notify_off`, and every used-ring completion — is treated as hostile input and
**rejected with a typed error or a counted drop, never by panicking**.

What remains of `assert!` and `expect` on these paths is a different thing and stays deliberately:
checks of a domain's *own* invariant, each stating the proof that no device value reaches it and
naming the component that establishes that. Every one of them is unconditional in every build
profile rather than a `debug_assert!`, and `overflow-checks` is on in the shipped profile, so the
arithmetic the property tests prove panic-free is the arithmetic that ships.

Held by the hostile-device cases in `crates/virtio` and `crates/nic-driver-core`, plus two
device-facing persistent fuzz targets (`find_virtio_caps`, `virtqueue_poll`) and a third
(`nic_driver_paths`) that drives a hostile device and a byzantine forwarder at once. Each models the
device's full authority over the shared region rather than a well-behaved subset of it.

`crates/uart-16550` is the second device this applies to and the smaller one: every byte it reads
back is the controller's choice, a controller that never answers is indistinguishable from one that
answers wrongly, and both are met the same way — every wait bounded by a constant of the crate's
own, every refusal a typed error and a counter, and a property test asserting that initialisation
and a write each terminate within their advertised bound for *any* sequence of device answers.

**Missing.**

- **The device's DMA is not confined.** Bus-master DMA is enabled against fixed physical addresses
  with no IOMMU (the *IOMMU (VT-d) DMA confinement* row above). Every check listed here bounds what
  the driver *believes*; none of them bounds where the device can *write*. This is the single
  largest residual against CONCEPT §7.1's hostile-device adversary, and no first-party code can
  substitute for VT-d.
- **No restart.** A device that fails bring-up leaves its port permanently down (see
  *[virtio-net driver](#virtio-net-driver)*).

### Untrusted-peer containment

**Done.** Buffer ownership is accounted **by identity**, not by count: `packet_buffer::FreeList`
refuses to reclaim an index that is out of range or not outstanding, and `pd_runtime::PoolOwner`
refuses one this domain never lent. A *local* double return is not representable, `pop` minting a
non-`Copy`, non-`Clone` `OwnedBuffer` token.

Every rejection is a **counted drop**, never a fault: `PoolCounters` and `RouteCounters` record
them, the latter attributing every refused frame to one of eleven named routing reasons or to the
stage check that caught it. `ConfigCounters` does the same for the handover, so a publisher offering
images this domain will not run is distinguishable from one that has stopped offering any.
Descriptors from a peer are range-validated (`descriptor_in_bounds`, plus the transmit header-room
check) and checked against the driver's in-flight set before any span is touched. Every peer-fed
loop is bounded by `DRAIN_LIMIT`.

The configuration handover is the same treatment applied to a second peer: the region is mapped
read-only, its image is copied out before anything is decided on it, and every field of the copy —
counts, the `enabled` byte, ports, prefix lengths, MACs — is re-checked in the consumer, which is
the domain that has to live with the result. A refused image is counted, leaves the running
configuration exactly as it was, and is never acknowledged, so the publisher cannot commit it.

The log ring is the same treatment applied to a third peer, and to a peer on **both** sides at once.
Every field of a record the console reads was chosen by another domain, so the record is decoded
before anything is rendered — a kind naming no event, a vocabulary token past its cardinality, a
text length past its own storage, a byte outside `[a-z0-9-]` are each a typed refusal and a counted
drop, never a line. Neither published cursor is ever read back by the side that owns it, so a peer
forging one costs that peer's own records and nobody else's; a drain is bounded by the console's own
burst constant and by the ring capacity rather than by anything a writer publishes; and a refusal on
one ring does not stop the pass, because the records worth reading when a domain fills its ring with
rubbish are the *other* domains'.

**Missing.**

- **A byzantine forwarder can still corrupt a frame in the shared pool.** It may name a buffer whose
  pool owner has it posted as that NIC's receive DMA target; the transmitting driver's 12-byte
  virtio-net header write then races the DMA. The damage stays inside the shared region, but
  exclusive ownership across domains is a protocol claim no single domain can verify. Closing it
  needs an IOMMU (CONCEPT §7.2) or a cross-domain per-buffer ownership epoch; neither exists.
- **A verdict rests on a snapshot, not on the frame.** `RouteStage` decides on a copy in its own
  memory, so a peer cannot change the frame under the decision — but it can change it *after*, and
  before the transmitting NIC reads it. What leaves the port may differ from what was decided on in
  every field the rewrite does not overwrite. The same IOMMU or ownership epoch is what would close
  it.
- **Buffer loss is not recovered.** A peer that stalls a destination ring costs the pool one buffer
  per dropped descriptor, permanently (see *[Zero-copy dataplane](#zero-copy-dataplane)*). It is
  counted, and nothing reclaims it.
- **A peer can still write pool bytes at any time.** No Rust type stops a domain mapping the region
  from scribbling a buffer it does not own; an IOMMU is what would confine it.
- **No PD fault handling.** A domain that a peer manages to wedge is not restarted.

### A/B image update

**Done.** A GPT disk with ESP, STATE, SLOT_A, SLOT_B and DATA partitions; both slots carry a signed
kernel and system image. GRUB is built from pinned source as a standalone EFI binary with an
embedded public key, so it *enforces* detached-signature verification on everything it loads.

The `OK`/`TRY`/`ORDER` selection scheme is implemented and covered by **eight** QEMU scenarios:
confirmed-A, try-pending-B, fallback-from-broken-B, skip-exhausted-B, confirmed-B, an `ORDER` naming
a slot that does not exist, and the two ways every slot can become unbootable — both payloads broken,
and boot state so torn that an attempt cannot be recorded. Each asserts *which slot was chosen*
against a structured boot channel, on which GRUB emits one `LFW-BOOT slot=… state=…` record per
selection decision, and each scenario declares the exact ordered sequence it must produce. Each then
asserts *that the chosen slot is healthy* through the system's real observable contract, frames
forwarded between the two NIC ports — or, for the two halt scenarios, its negative: no frame
forwarded and GRUB's halt record on the channel.

**Missing.**

- **The in-system update/health PD.** No component inside seL4 holds a capability on the **boot**
  disk, so the health flag (`*_OK`) is only ever set by the build seed or the test harness. The
  confirm half of the try/confirm cycle does not exist at runtime. The recorder's disk capability is
  no help here and deliberately so: it names a second, data-only device at a different PCI function,
  and nothing in the system can reach ESP, STATE, SLOT_A, SLOT_B or DATA once seL4 is running.
- No staged installation into the inactive slot.
- No multi-attempt counter (GRUB is single-attempt by design; the counter belongs to the missing PD).
- No redundant, torn-write-safe boot state — a single `grubenv` block. A torn block is *detected*
  and refused, but there is no second copy to fall back to, so the outcome is a halt.
- The DATA partition, where configuration, identity and secrets are meant to live, is an empty
  unformatted GPT entry with no consumer and no encryption — unchanged by the recorder, which writes
  to a separate device entirely.

### Signed boot chain

**Done.** OVMF → GRUB → Multiboot2 → seL4/Microkit with enforced payload signature verification;
the corrupt-signature fallback and the both-slots-broken halt are proven by test. A throwaway
development key is generated per checkout and never committed, and the release manifest records
`trust_profile: development` with the key fingerprint so a development-signed image cannot be
mistaken for a production one.

Signing is key-explicit and self-checked: each signature names the exact fingerprint embedded into
GRUB, and the build verifies what it just signed against that public key before anything is written
into a slot, so a mis-keyed payload fails the build rather than the appliance.

The hand-off also holds seL4's one unchecked expectation of its bootloader. seL4's x86 boot places
the userland image at `MAX(first available region's start, ROUND_UP(end of the last boot module))`,
and its available-region list is the firmware's — it still contains the memory the kernel image
occupies — so the end of the last boot module is the only thing keeping the userland image off the
running kernel. GRUB's relocator takes the lowest range that fits and, on `x86_64-efi`, the 640 KiB
below 1 MiB is free, so it will place the module *below* the kernel whenever the image is small
enough to fit there. `grub.cfg` therefore cuts conventional memory between 64 KiB and 1 MiB — 64 KiB
is left because GRUB allocates its own hand-off trampoline from low memory — and refuses to boot at
all if that reservation is itself refused. Because what remains is a window an image could still
shrink into, `xtask::grub::check_boot_module_placement` fails the **build** when the assembled system
image would fit it, reading the bound out of `grub.cfg` rather than restating it.

**Missing.** UEFI Secure Boot is not enrolled — the manifest hard-codes `secure_boot: false`, and
`BOOTX64.EFI` itself is unsigned in the Authenticode sense (no shim, MOK, or PK/KEK/db hierarchy).
There is no TPM anywhere: no vTPM in the QEMU harness, no measured boot, no PCR policy, and no
anti-rollback epoch. Production key management (HSM-backed signing) does not exist.

## Engineering foundations

Not product features, but the machinery every feature above lands through — and where most of what
is *done* currently sits.

| Foundation | Status | Notes |
|---|---|---|
| Hermetic, pinned build in a rootless OCI builder | **done** | base image by digest, dated Debian snapshot, exact version per apt package, checksum-verified SDK/toolchain/GRUB/syft, `--locked` throughout |
| Host gate: format, Clippy `-D warnings`, comment/`unsafe` ratchets, unit + property tests | **done** | run by the pre-commit hook; Clippy covers the library crates, `xtask`, and all seven protection-domain binaries in each of the two seL4 kernel configurations — which, now that every end-to-end scenario boots the release image, is the **only** thing in any gate that still compiles the debug configuration, and so the only thing keeping it buildable for the diagnostic re-run that needs it. The ratchets (`tools/xtask/src/budgets.rs` against `tools/xtask/budgets.toml`) record a comment-line ratio per production file and an `unsafe` block/fn/impl count per crate, and fail the gate on any rise |
| Coverage floor | **done** | 94% combined and 90% per library crate, enforced in the gate as line coverage, over the twenty-two library crates — `lfw-pcapng`, `lfw-blk`, `lfw-capture-ring` and `lfw-recorder` joined the floored set with this work. Every workspace member is either measured or carries a recorded AGENTS.md TEST-3 reason for being exempt, and a member in neither fails the build. **The headroom above the floor is not restated here**: the numbers a previous revision quoted predate four new crates, and `make coverage` reports the current per-crate figures |
| QEMU end-to-end gate (six system scenarios, eight A/B scenarios) | **partial** | every scenario boots the **release** image — the configuration a deployment gets (BLD-3) — and a scenario that fails there is re-run once on the debug kernel to diagnose it, which never changes the verdict. A second raw disk at 00:05.0 is attached on every invocation, and the three scenarios that reach the management endpoint judge all three of its surfaces against one another and read both extents off that disk besides ([detail](#recording-and-download)). Single vCPU, two dataplane ports and one management port; the multi-node virtual-network E2E is open |
| Criterion benchmarks | **partial** | `queue`, `packet-buffer`, `virtio` and `pd-runtime` (the per-packet routing cost: snapshot, parse, decide, rewrite, write back — measured with the recording tap switched *off*, so the tap's own per-frame cost is unmeasured); `nic-driver-core`'s poll pass, the block request path and the recording path are all hot or newly hot with no benchmark, and nothing gates a regression |
| Fuzzing | **partial** | a persistent target for every crate that parses a *structure* it did not write — a descriptor, a ring, a document, a header, a record — including the block request path, the ring superblock and the recording pass added with this work. `tools/xtask/src/host.rs` holds the authoritative target list. The register-protocol device crates (`uart-16550`, `hpet`, `rtc`) carry no target and do not need one: a single read admits one integer, which their property tests already sweep over the whole of its type. A sandbox that cannot start AddressSanitizer degrades the gate to build-plus-seed-corpus — see below |
| SBOM (SPDX 2.3), release manifest, checksums | **partial** | none of them are signed; no SLSA/in-toto attestation; and the SBOM's scope is narrower than the payload — see below |
| Reproducibility check | **partial** | `make verify-reproducible` covers kernel + system image, built in the release configuration so the claim is about the artifact that ships; not a CI gate |
| Dependency and license policy (`cargo-deny`) | **done** | `bans licenses sources` in the offline gate; `advisories` needs the RustSec database and so runs in a networked CI step — not in a local `make ci` |
| Build input pinning | **partial** | every apt package — QEMU and OVMF included — is pinned to an exact version against a dated snapshot, but no sha256 for one is recorded here, so apt's own archive signature is the integrity root; the `cargo install`ed developer tools are version-exact and `--locked`, but their integrity rests on the crates.io index rather than on a checksum in this repository |

Two of those rows deserve more than a table cell, and the fuzzing row deserves two.

**The SBOM does not describe the shipped payload.** syft catalogs the workspace *source tree*, with
`build/`, `dist/`, `target/`, `fuzz/` and `tools/` excluded, so a consumer must not read the document
as the boot payload's contents. Host-only crates that never enter an image — `criterion`, `proptest`,
and their trees — appear in the inventory. And the third-party components that genuinely *do* ship
inside the disk — the seL4 kernel from the Microkit SDK and the GRUB core image — are absent; they
are recorded as version-verified provenance in the release manifest instead.

**The two configuration harnesses assert semantics, not survival.** A target whose body is a bare
parse call proves only that the parser did not crash on that input, which for a validator is the
least interesting outcome: the failure that reaches a dataplane is an image *wrongly accepted*.
`fuzz/src/handover.rs` therefore carries its own statement of the handover ABI's rules and of the
order they are applied in, taken from the contract rather than read out of `wire`, and compares it
with `ConfigImage::check` on every input — so an image the reader admits and the contract refuses
fails exactly as loudly as a panic would. `fuzz/src/document.rs` closes the same gap across a crate
boundary: every document `crates/config` accepts must build a handover image the *consuming* domain
accepts, and a forwarding table carrying the entries the document named, which no test inside either
crate alone can observe. Both claims were checked by sabotage rather than by reading — deleting the
prefix-length rule from `ConfigImage::check`, and the port-range rule from `crates/config`, each
fails the seed-corpus smoke test on the committed seed named after it, so the corpus alone catches a
lost rule with no live fuzzing at all.

**Live fuzzing is conditional.** Every target always builds under AddressSanitizer, and the
seed-corpus smoke tests always run. Whether libFuzzer can actually *execute* is established once per
run by an explicit probe, the hermetic builder being able to stop ASan before it starts. When the
probe passes, every subsequent non-zero exit is treated as a finding and fails the gate. When it
fails, the run reports loudly and proceeds with build-plus-seed coverage only — so a gate can go
green having done no live fuzzing at all.

## Build and test

The supported developer and CI interface is GNU Make backed by rootless Podman. A pinned OCI
builder (Debian 13 by digest, a dated Debian snapshot, the Microkit SDK, `rust-sel4`, the project
Rust nightly, GRUB, OVMF, QEMU, and the coverage/lint/fuzz/SBOM tooling) provides every build input.
The downloads are sha256-pinned in [`third-party/sources.lock`](third-party/sources.lock); each apt
package is pinned to an exact version inline in the Containerfile, next to the package name, against
the snapshot that file freezes. Nothing outside the builder is required beyond Podman itself.

From a clean checkout:

```sh
make image          # build the OCI builder, then assemble the release A/B disk + bundle
make test           # fast host gate: format, clippy, unit/property tests, coverage, lint, deps
make test-system    # boot six QEMU scenarios; the three with a reachable endpoint judge metrics,
                    #   logs and captures against each other and against the wire
make ci             # the complete gate (host gate + fuzz + release image + system + A/B scenarios)
```

**Every end-to-end scenario boots the release image** — the kernel configuration a deployment gets,
which is what BLD-3 asks of a gate. `make image` therefore builds that configuration with no flag to
remember, and the debug kernel is an explicit opt-in (`make image-debug`), the interactive `make
run`, and the diagnostic re-run described below. What that costs is nothing in coverage of this
project's own code: the protection domains are compiled with the `--release` Cargo profile in both
configurations, so there is no debug binary and the Rust under test is the Rust that ships. Only the
seL4 kernel build differs.

`make test-system` is also the smoke test. It runs **five scenarios**, each a full boot of a signed
disk through OVMF and GRUB with a host-controlled endpoint attached to each NIC port, and each
asserting the routed contract in both directions, plus the management port's count and its silence:

1. **routed-forwarding** — the published disk, judged on traffic alone. It is the regression guard,
   reporting a forwarding failure as a forwarding failure and nothing else.
2. **generation-swap** — the same disk, judged additionally on what it said. Its `LFW-CFG`
   transcript must show the node coming up fail-closed on generation 0 and switching to generation
   1, whose change records must be the configuration document's own diff; and its `LFW-PD
   domain=clock` record must show a time established, with a measured counter frequency inside the
   band the calibration accepts and a year inside the band the real-time clock reader accepts. A
   separate boot, because a transcript readable only off a run whose traffic had already passed
   would be silent in exactly the case it exists for — a node that committed nothing and forwarded
   nothing. The expected transcript is *derived* from the document by the same calls and the same
   renderer the appliance uses, so a hand-written list cannot drift from either; the clock record's
   two bands are imported from the appliance's own crates for the same reason. The measurement
   itself cannot be predicted — that is what makes asserting the bands, rather than a value, the
   only honest contract available.
3. **alternate-configuration** — a disk assembled from a second document sharing no address and no
   MAC with the first, judged on both channels. This is what proves the dataplane reads its table
   from the document: a compiled-in table would satisfy the first two scenarios and fail every probe
   here.
4. **metrics-endpoint** and 5. **metrics-endpoint-alternate** — the published disk and a disk built
   from the second document, each with the management port on QEMU's user-mode stack and a host port
   forwarded to it, scraped **twice** with `curl` rather than with the harness's own frames. Two scrapes because one cannot contain the response it *is*: the endpoint counts a
   response as it composes it, which is after the shard the exposition is rendered from is published,
   so the second scrape is what carries the first's request and its `200`. Answering the second at
   all is also what proves the one staged response is released rather than held through the previous
   connection's `TIME_WAIT` — an endpoint that held it would refuse every scrape a periodic scraper
   made. The document is parsed as exposition rather than string-matched, and one number in it —
   frames forwarded — is cross-checked against the frames this same harness watched cross the
   dataplane, so the scrape is held to the wire and not merely to itself.

Every address in all of that comes from the configuration document the image under test was built
from, so no part of the bench can hold an address the appliance does not. Each scenario prints what
its two endpoints exchanged: each datagram as it came back off the wire, with its addresses and
ports, the TTL the hop decremented, the MAC pair the appliance rewrote it to, and its length. Each
boot also injects four classes of traffic the appliance must refuse — a TTL that cannot survive a
hop, a frame carrying another station's destination MAC, a destination no interface prefix covers,
and a non-IPv4 broadcast frame — and each must reach nobody. The traffic verdict is those two
sockets and nothing else; the transcript verdict is the structured `LFW-CFG` channel and nothing
else. Neither is read from timing, and neither is read from prose — the channel being recovered the
way MONITORING.md obliges every reader to, by scanning for the `LFW-` marker anywhere in the stream
rather than assuming a record begins a line. Records no longer tear into one another, the port
having one owner, and what these scenarios boot is the release kernel, which prints nothing of its
own — so no capture the gate writes carries kernel prose at all, only the firmware's and GRUB's,
both of which finish before the first domain starts. The scan is kept because it is what
MONITORING.md obliges of every reader and because the debug kernel does write that port, for its
banner and its faults, so a record preceded on its line by kernel prose remains reachable in a
diagnostic re-run, under `make run`, and in a `make image-debug` build. The one thing that scan
cannot tell apart from a record is prose *quoting* one, which is the marker's price and fails
closed: the quotation comes with its surrounding words, so it lands as a mismatch rather than as a
pass. The guest's serial output is captured to `build/image/qemu-<scenario>.log` for reading after a
failure. A failing run prints the same table with the offending probe marked, ahead of the
diagnostic naming the field that departed from the contract.

**Fail on release, diagnose on debug.** The release kernel is built without `CONFIG_PRINTING`, so a
boot that dies before the console domain claims the UART leaves an empty capture and a bare timeout
with no diagnosis in it. When a scenario fails, the harness therefore re-runs *that one scenario* —
never the others — on the debug kernel, and reports what happened beside the failure. It has three
outcomes: the scenario **passes on debug**, reported as a divergence and pointing at the kernel
configuration and the size and layout of the image GRUB has to place, which is the signature both
defects above had; it **fails on both**, in which case the debug kernel's serial output is the
diagnosis and its tail is quoted verbatim; or the debug image **could not be assembled**, reported
as its own outcome rather than as evidence of anything. The re-run never changes the verdict — a
scenario that fails on the image that ships has failed — and its artifacts are written under
separate `-debug` names so they cannot overwrite the failing run's evidence or the release artifact
in `dist/`. The operational cost is disk: a failure leaves a second, debug-configuration build tree
and scenario disk beside the release ones, so the image build tree roughly doubles at its peak —
measured here at 138 MiB for each configuration's protection-domain tree, plus about 90 MiB per
scenario disk.

`make image` is the only network-enabled phase (the OCI build). Every target that runs a build or a
gate — `make clean` included — checks that the pinned builder image already exists and refuses with
an actionable message instead of quietly provisioning it, so no gate command can turn into an OCI
build. Project commands run with networking disabled, a read-only container filesystem, no Linux
capabilities, and only the workspace mounted writable. When the host exposes `/dev/kvm` it is passed
through for accelerated QEMU; the harness falls back to emulation otherwise, and which of the two
happened is printed and written into the run log, so a silent degradation to emulation cannot pass
for an accelerated run.

The full command surface:

```sh
make image                # build the OCI builder, then `xtask image` — the RELEASE configuration
make image-debug          # assemble the debug kernel instead; an opt-in no gate reaches
make run                  # boot the image interactively in QEMU (debug kernel, for its diagnostics)
make test                 # fast host gate (format, clippy, tests, coverage floor, lint, dependency policy)
make coverage             # measure host-crate line coverage and print the per-crate summary
make bench                # run the performance benchmarks
make fuzz                 # run the seed smoke tests, build every fuzz target, exercise each briefly
make test-system          # boot the five QEMU system scenarios on the release image
make test-ab              # boot the eight A/B state-machine scenarios on the release image
make ci                   # the complete gate: host gate, fuzz, release image, system and A/B
make release              # run CI, then keep `dist/` only if it proved what it holds
make verify-reproducible  # build the release payload twice in isolation and compare artifacts
make hooks                # install the pre-commit and pre-push git hooks
make clean                # remove generated output only
```

Commits go straight to `trunk`. Install the git hooks once with `make hooks`: the pre-commit hook
runs the fast host gate (`make test`) and the pre-push hook runs the full `make ci`, so every commit
that reaches `trunk` has passed formatting, lints, tests, coverage, dependency policy, the fuzz
targets, release image assembly, and the QEMU system and A/B gates on that release image. That is
what a machine can check, and it is less than the rules the project holds itself to;
[AGENTS.md](AGENTS.md) marks each rule `GATE` or `REVIEW` so it is never ambiguous which of the two
a given property rests on.

On a development machine behind a TLS-inspecting proxy, the build automatically detects an installed
inspection CA (a `*-dpi-ca.crt` under `/usr/local/share/ca-certificates/`) and provides it as a
Podman build secret. On another inspected network, or to select a specific certificate, pass its
path explicitly:

```sh
make image ENTERPRISE_CA_FILE=/path/to/enterprise-ca.pem
```

The CA reaches only the build steps that fetch dependencies, and the bundle each of them derives is
removed within that same step, so it does not persist into an image layer. TLS verification stays
enabled for every download. Do not commit the certificate.

## Release artifacts

`make release` runs the complete acceptance gate and **boots nothing of its own**. It has nothing
left to boot: `ci` already assembles the production-oriented Microkit release configuration into
`dist/` and already holds that disk to both contracts a booted appliance owes — the forwarding
contract on all six system scenarios and all eight A/B scenarios, the `LFW-CFG` transcript and
the clock's established-time record on two of them, a `curl` scrape of `/metrics` on two more, and a
`curl` of both recordings — parsed as pcapng, then re-read straight off the data disk — on the
sixth. Each is judged against the configuration document its own image was built from. What
`make release` adds is the other half of
BLD-3: if the gate did not prove the artifact, `dist/` is emptied rather than left holding an
unproven image that looks finished. That covers a failure anywhere in the run, not a failed boot
alone, because assembly populates `dist/` partway through and an incomplete release is no more
publishable than an unproven one.

The console assertion exists because its absence is what let a release be published with no console
at all: `debug_println!` compiles to a kernel debug syscall the release kernel is not built with, no
gate on the push path booted a release image, and the one stage that did asserted forwarding alone —
and a dataplane is indifferent to whether anything is printed. A scenario judging the transcript
derives it from the document its own image was built from, by the same calls and the same renderer
the appliance uses, so passing means bytes a domain published reached the serial line *in the release
kernel*: through the log ring, through the console domain, out of the UART, in order and with the
right values. It does not enumerate the whole `LFW-PD` lifecycle channel — only the clock's own
record on it — and it is not a claim that every record renders correctly. It defends the one property
that was silently false: that the shipped profile has a console at all.

The first release boot found more than that. The image did not boot at all: GRUB had placed the
Microkit system image below the seL4 kernel and seL4 loaded the userland image over its own page
tables, triple-faulting before any protection domain ran (see
*[Signed boot chain](#signed-boot-chain)*). That defect was latent in every commit that built this
boot chain and was invisible to every gate, because no gate had ever booted a release artifact. It
is the concrete answer to why BLD-3 requires the shipped profile to be the tested profile, and the
reason the release image is no longer something one stage boots at the end but the only image any
end-to-end scenario boots at all.

The deployable artifact is `dist/librefirewall-qemu-x86_64.img`, the signed GPT A/B disk booted
through OVMF and GRUB. Alongside it, `dist/` carries five product-prefixed pieces of release
evidence and nothing else: the loose kernel and system images (the update input), a manifest
describing the target, pinned inputs and signing trust profile, an SPDX 2.3 SBOM (see *Engineering
foundations* for what it does and does not cover), and a SHA-256 checksum file covering every other
artifact. The Microkit capability/memory report is deliberately **not** published: it is a full
disclosure of the system's authority topology, so it stays under `build/image/<config>/`.

Image builds generate a throwaway development signing key under `build/dev-keys/` (never committed;
removed by `make clean`); the manifest records `trust_profile: development` so a development-signed
image can never be mistaken for a production one.

All commands force Podman's `cgroupfs` manager. Override `PODMAN` only to select a compatible Podman
executable; Docker is not a supported build interface.

## License

librefirewall is free software, licensed under the **GNU Affero General Public License, version 3 or
later (AGPL-3.0-or-later)**. The full text is in [LICENSE.md](LICENSE.md).

Copyright (C) 2026 Tobias Sarnowski

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero
General Public License for more details.
