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

A **dedicated management port** is now the third NIC. It is a third instance of the same driver
binary — the binary is port-agnostic, so driving a management port took no code change to it — handing
its frames to a `management` protection domain that counts them and reports the running total, and
forwards nothing. The isolation CONCEPT §9.1 asks for is a grant set rather than a rule: the
management domain holds no dataplane region and the forwarder holds no management region, and
`xtask::sysdesc` names the mapper set of every region exactly, so either grant appearing fails the
gate. The port has no address, no ARP and no IP — it receives and counts, and that is all.

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
counter to, publishes one console record stating both, and parks. Nothing consumes the result yet,
which is deliberate: a shared calibration region no domain maps would be a grant nobody uses. What
the domain proves in the meantime is the whole chain that would fill one, end to end on the image
that ships. It is **not** a trusted time source — see the status row above and its detail below.

Parsing stops at IPv4 and UDP, and **no filtering decision of any kind is made**: a packet is
forwarded because it is routable, never because a policy allowed it. There is no connection
tracking, no NAT, no ARP, and no ICMP. What exists is a router on a firewall's substrate, not yet a
firewall.

### Traffic inspection and enforcement

| Capability | Status | Notes |
|---|---|---|
| Stateful L2–L4 filtering and connection tracking | **open** | |
| Routing, ARP, ICMP | **partial** | [detail](#routed-ipv4-forwarding) |
| Virtual-wire (bump-in-the-wire) operation | **open** | CONCEPT §6.4 |
| NAT (SNAT/masquerade, DNAT, static 1:1) | **open** | CONCEPT §6.5 |
| Flow classifier (cut-through vs. proxy path) | **open** | |
| L7 protocol parsing (HTTP/1.1, HTTP/2, HTTP/3) | **open** | |
| OT/industrial protocol inspection | **open** | |
| DoS resilience (SYN cookies, rate limiting, bounded state) | **open** | |
| Mirror port | **open** | |
| TLS termination and re-origination | **open** | |
| QUIC / HTTP-3 termination | **open** | |
| Isolated sign-only CA protection domain | **open** | |
| Trusted time source | **partial** | a protection domain now establishes real time at boot and reports it; nothing about it is *trusted* — [detail](#trusted-time-source) |
| Streaming DPI / signature matching | **open** | |
| Full-object content scanning (YARA-X) | **open** | |
| Web filtering | **open** | |

### Dataplane, platform and hardware

| Capability | Status | Notes |
|---|---|---|
| Zero-copy shared-memory dataplane | **partial** | [detail](#zero-copy-dataplane) |
| First-party virtio-net driver | **partial** | [detail](#virtio-net-driver) |
| Multicore dataplane, RSS, per-core flow shards | **open** | single vCPU today |
| Proxy TCP stack (smoltcp, SACK) | **open** | |
| 10 Gbit/s per dataplane port pair | **open** | nothing has been measured against the target |
| IOMMU (VT-d) DMA confinement | **open** | bus-master DMA is currently unconfined |
| Full port role model (management, session-replication, mirror, multiple pairs) | **partial** | a dedicated management port exists and is isolated from the dataplane; it receives and counts and does nothing else — [detail](#full-port-role-model) |
| Hardware image variants (3/4/6/7-NIC) | **open** | one system description, `systems/qemu-x86_64` |
| ixgbe (SFP+ 10 Gbit/s) driver | **open** | |
| Azure netvsc / MANA drivers, Azure NVA (GWLB, VXLAN) | **open** | |
| Proxmox and bare-metal targets | **open** | QEMU only |

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
| OpenTelemetry structured logs | **open** | call sites emit typed events (`crates/log`); the console is one rendering of them, and the record a domain publishes into its log ring is a second, already-structured one. No transport, exporter or receiver exists |
| Prometheus `/metrics` | **open** | groundwork only: the dataplane crates, the log rings, the console renderer and the UART all tally drops and faults in memory; nothing exposes, reads or names them as metrics |
| Local log buffer (`GET /logs`) | **open** | |

### Lifecycle, boot and trust

| Capability | Status | Notes |
|---|---|---|
| Signed A/B disk image and slot selection | **partial** | [detail](#ab-image-update) |
| Signature-enforced boot chain (OVMF → GRUB → Multiboot2 → seL4) | **partial** | [detail](#signed-boot-chain) |
| In-system update/health protection domain | **open** | nothing inside seL4 can write boot state |
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

- **No ARP and no ICMP**, so neighbours are a static table and a drop is silent. Both need a domain
  that can *originate* a frame, which none can: the pools are owned by the receiving drivers, and a
  frame can only leave the port opposite the one it arrived on.
- **Interfaces and neighbours are all that is configurable.** They come from
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

Correctness is held by 191 unit and property tests across those four crates — including hostile-peer
cases for forged and duplicate returns, forged cursors, exhausted rings and bounded drains — plus a
500,000-frame three-thread pipeline test that cycles every buffer through `rx → route → tx → free`
far more times than the pool holds, exchanging the forwarding table at poll boundaries as it goes.

A frame is copied twice per hop and never more: once out of the pool into the routing domain's own
memory, because a decision made on bytes a peer may rewrite underneath it is no decision at all, and
once back — 34 bytes of header, never the payload.

**Missing.**

- No batching API — one descriptor per call, and one notification per drain. CONCEPT §6.1's
  batched notifications are incidental today, not designed.
- Pool is 64 buffers of 2048 bytes; orders of magnitude short of a 10 Gbit/s working set.
- Fixed 2048-byte buffers: no jumbo frames, no scatter-gather, no descriptor chaining.
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

Eleven persistent fuzz targets cover this surface, the peer-facing one, the network-facing parser,
the configuration document and the handover image, and the log record and its ring (see
*Engineering foundations*).

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
depend on where in the file something was written. Fifteen semantic rules then run over the model:
a duplicate interface id, neighbour id or port; a port the build does not have; a prefix length past
32; an interface address that is its own prefix's network or broadcast address; a non-unicast
address or MAC on either object; overlapping prefixes; a neighbour naming an unknown interface, or
sitting outside its interface's prefix, or equal to the interface's own address; and a duplicate
neighbour address on one interface. A document naming more objects than the handover ABI can carry
is refused by the reader rather than truncated. Every refusal is a typed error naming a **location**
and never the offending bytes (OBS-5).

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

`pd_runtime::ConfigurationSwitch` is the consumer. It treats the region as a byzantine peer's
claim — copies the image out before deciding on it, exactly as `RouteStage` snapshots a frame, and
re-checks every field: a count past capacity, an `enabled` byte that is neither 0 nor 1, a port with
no driver, a prefix length past 32, a non-unicast MAC. A refused image leaves the running
configuration exactly as it was and is never acknowledged, so the publisher never commits it. The
switch happens **between two polls** and is provable rather than claimed: a Microkit domain runs one
entrypoint to completion, so a frame is decided entirely under one generation with no lock involved.

Because the forwarder boots fail-closed on generation 0 and the document the image carries commits
as generation 1, **every boot performs a live configuration swap on a running forwarder**, and every
changed value reaches the console as a structured `LFW-CFG` record (see
[MONITORING.md](MONITORING.md)).

Held by 170 tests in `crates/config` and 96 in `crates/log`, by the handover's own tests in
`crates/pd-runtime` — arbitrary region contents read totally and bounded, forged counts, forged
`enabled` bytes, an image round-tripping through the region — and by the 500,000-frame pipeline
test, which now exchanges the forwarding table at poll boundaries throughout and asserts that no
frame is rewritten out of a blend of two, that the pool comes back whole across every commit
boundary, and that payloads arrive in order under those rewritten headers. Two of the three QEMU
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
  *to*; with no persistence and no channel to submit a second document over there could not be one
  worth holding, every generation but the single one each boot commits being unreachable by
  construction. What is implemented of §12.2's versioning is the part that is reachable: monotonic
  generations, and a content hash beside them that makes re-committing what is already running an
  `unchanged` outcome rather than a new version.
- **No commit-confirm.** The candidate/commit half of CONCEPT §12.2 exists; the confirm half does
  not, and it cannot be built here: an automatic revert needs a deadline, and there is no timer, no
  interrupt and no trusted time source anywhere in this system. It also needs a management channel
  to be *protecting* — the failure commit-confirm exists to survive is a commit that severs the
  operator's own access — and there is no such channel to sever.
- **No persistence.** Nothing inside seL4 holds a disk capability and there is no block driver, so a
  generation cannot outlive a reboot. The DATA partition, where configuration is meant to live, is
  an empty unformatted GPT entry (see *[A/B image update](#ab-image-update)*).
- **No distributed rollout.** CONCEPT §12.2's staged commit across an HA pair needs a pair; the
  handover protocol is written for exactly one consumer, and "every consumer has staged" is one
  comparison rather than a conjunction.
- **Only interfaces and neighbours are configurable.** No routes, no policy, no zones, no NAT — none
  of which exist to configure. Queue depths, pool sizes and buffer extents are deliberately *not*
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

`crates/wire` carries the transport: a 224-byte fixed-layout `LogRecord` whose every offset is a
static assertion, and a 64-slot ring laid across **two** regions with opposite permissions. The
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

Every end-to-end scenario now boots the **release** image, and two of the three system scenarios
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
- **Every counter here is in memory and unexposed.** The UART's bytes written, THRE timeouts and
  init failures; the renderer's printed, malformed, unknown, unrenderable and write-failed; each
  writer's dropped and refused. Nothing reads any of them out (see *Prometheus `/metrics`*), so a
  console that is silently dropping records is indistinguishable from one with nothing to say.
- **A record that will not render is now dropped, not reported.** It is counted as `unrenderable`
  and nothing is written. The previous transport wrote a `LFW-PD unrendered=<debug form>` line
  instead; that line is gone, and MONITORING.md no longer promises it.

### Console system-state events

**Done.** The five ad-hoc bring-up markers are gone. Call sites in all six protection-domain
binaries emit **typed events** — a closed set of named fields — and rendering happens once, in the
console domain, so the attribute structure an OpenTelemetry record needs is produced at the call
site rather than thrown away in a format string, and the structure is what crosses between domains
rather than the text. Two channels of closed vocabulary reach the line,
`LFW-PD domain=… state=…` for a domain's lifecycle and `LFW-CFG generation=… …` for configuration,
both specified field for field in [MONITORING.md](MONITORING.md) and matching the existing
`LFW-BOOT` convention, so a reader keys on the `LFW-` prefix alone.

That the values are safe to print is structural rather than a rule to remember: an event's value
type is a closed set of already-parsed domain types with no arbitrary-bytes variant, and the one
route text takes from a configuration document to a console line is an identifier validated to
`[a-z0-9-]{1,16}` at parse time. Rendering is allocator-free into a caller's buffer and **refuses**
rather than truncates, a truncated line being one an operator reads as complete. The transcript is
a machine-checked contract, not prose: a QEMU scenario derives the records a document must produce
by running that document through the same two calls the domain makes and the same renderer its
console backend uses, then asserts the boot's `LFW-CFG` channel against it.

**Missing.**

- **The forwarder never reports its own outcome.** It emits `state=starting` and nothing further —
  no `ready`, no failure — so MONITORING.md's "each stage reporting healthy or the specific fault"
  holds for the driver, configuration and clock domains and not for the one that carries traffic.
- **Nothing orders one domain's records against another's.** Within a domain they are totally
  ordered — one writer per ring, drained in the order it wrote them — and a `generation`/`seq` pair
  totally orders one commit's change records. Across domains there is no order at all: which ring is
  served first is decided by where the console's rotation stood, and no record carries a timestamp
  to appeal to.
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

**Done.** One of the four roles CONCEPT §9.1 names exists: a **dedicated management port**, isolated
from the dataplane and carrying no forwarded traffic. It is a third `virtio-net-pci` device at
00:04.0, driven by a third instance of the same `nic-driver.elf` the two dataplane ports use — the
binary turned out to be port-agnostic already, so the third port cost it no code change, only new
regions and a different peer — and its frames end at a `management` protection domain that counts
them and reports the running total on the console.

The isolation is a grant set, not a rule anybody has to remember. The management domain holds **no**
dataplane region, no buffer pool at all, no configuration region, no device capability and no I/O
port; the forwarder holds no management region; and `xtask::sysdesc` names the mapper set of every
region *exactly*, so either grant appearing fails the gate at the point the edit is made. The
management port is not in the router's port set and no configuration document can put it there —
`config::PORT_COUNT` is 2 and the forwarder refuses a table naming a port it has no driver for.

`crates/pd-runtime`'s `TerminalStage` is the mechanism, and it exists because the dataplane's does
not transfer: a routed descriptor travels *onward* and the egress driver returns the buffer, which is
what lets the forwarder be denied both `free` rings. A terminal port has no egress driver, so this
domain produces the returns itself while the driver consumes them as the pool's owner — the same
producer/consumer split the two drivers already have, which keeps a forged return refused by the
ledger rather than believed. It is host-tested against a byzantine driver: forged indices,
unbelievable spans, a stalled return ring, and a pool-sized run proving every buffer comes back.

The QEMU gate asserts both halves on the release image. Every system scenario injects four frames of
four different lengths into the management port once the capture proves every port is up, and holds
that port to carrying **nothing** back — nothing produces onto its transmit pipeline and the
forwarder cannot reach it, so a frame arriving there means one of those two facts has stopped being
true. Two of the three scenarios additionally hold the console's own record to the frames and the
bytes injected, to the frame and to the byte: `LFW-PD domain=management state=ready frames=4
bytes=352`.

**Missing** — and it is nearly everything a management port is for:

- **The port has no address.** No ARP, no IPv4, no TCP, no TLS, no HTTP, and nothing in the
  configuration document describes it: it has no `<interface>`, so its MAC is a constant in
  `tools/xtask/src/qemu.rs` rather than a configured value, and the harness's station MAC is a
  constant beside it. Both move into the document the day it gains a management interface.
- **It reads no frame.** Frames and bytes are counted off the descriptors the driver publishes, so
  the domain maps no pool and its receive pool is mapped by no protection domain at all. Parsing a
  frame needs that mapping, and it arrives with the code that does the parsing.
- **It transmits nothing.** The transmit pipeline exists because the port-agnostic driver binary
  takes a transmit side whatever port it drives; no domain produces onto it, so the port is
  receive-only in fact as well as in intent.
- **The counts are on the console and nowhere else.** They belong on `/metrics` (CONCEPT §11), which
  does not exist, and `TerminalCounters::malformed_descriptor` and `return_ring_full` reach no
  surface at all — so a management port whose driver is misbehaving is invisible.
- **No other role.** Session-replication, mirror and multiple port pairs are open, and so are the
  3/4/6/7-NIC hardware image variants: there is one system description with three ports in it.

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
one of 25 console cause tokens and parks. Two of the three QEMU system scenarios assert that record
on the release image — that it is `ready`, that its frequency is inside the band the calibration
accepts, and that its year is inside the band the RTC reader accepts.

**Missing** — and it is everything the word *trusted* covers:

- **The time is unauthenticated and unattested.** It comes from a battery-backed register file that
  any firmware, hypervisor or dead battery can make say anything plausible. There is no NTP, no
  Roughtime, no signed time source and no attestation, so a wrong-but-plausible instant is
  indistinguishable from a right one. CONCEPT §7.2 makes certificate validity depend on accurate
  time; nothing here may be used for that.
- **UTC is assumed, not discovered.** The CMOS carries no field saying whether it holds UTC or local
  time. A machine whose firmware set it to local time yields an epoch wrong by that zone's offset,
  detectably by nothing.
- **Nothing consumes it.** There is no shared calibration region, so no other domain can read the
  time, and no record but the clock's own carries an instant. Every ordering statement in
  [MONITORING.md](MONITORING.md) is unchanged.
- **No discipline and no monotonic guarantee across domains.** The part is read exactly once and
  never corrected; there is no timer, no interrupt, and no second reading to drift against.
- **Single-core assumption.** The calibration is a reading of one core's counter, with no check that
  the counter is invariant and no per-core anchoring — neither of which matters on the single vCPU
  this system runs on and both of which would on any multicore variant.
- **The measurement is biased high by its own overhead**, by one uncached timer read at each end of
  the window: parts in a thousand at worst, stated in `pds/clock` rather than corrected, because
  subtracting an estimate would replace a bounded one-signed error with an unbounded one.

### Protection-domain decomposition

**Done.** Eight protection domains from six binaries (one forwarder, one configuration domain, one
console, one clock, one management endpoint, three driver instances of one driver binary) with real,
verifiable least
privilege: the
forwarder holds no device capability at all
and neither dataplane pipeline's `free` ring — so it cannot hand a live DMA target back to be issued a
second
time — and each driver sees only its own ECAM page, BAR, virtqueue region, and its two pipelines.
Each pipeline is three memory regions rather than one precisely so that those grants can differ; the
forwarder maps the buffer pools, because a domain that rewrites a header must reach the bytes. The
configuration domain's entire grant is two 4 KiB regions: no device, no pool, no ring, so the domain
that parses attacker-supplied XML cannot reach a frame or a NIC. Those two regions are one per
direction, and their perms are the argument — the forwarder maps the handover **read-only**, so it
cannot rewrite the configuration it is about to be judged by, and the publisher maps the
acknowledgement read-only, so it cannot forge the consent that releases its own generation.

Four notification channels. The three driver channels are granted in **one direction only** — a driver
may signal its consumer, and that consumer's send capability on the driver does not exist rather
than merely going unexercised. The fourth, between the configuration domain and the forwarder, is the
one granted in **both**, and stated as a decision at both ends rather than inherited from Microkit's
default: applying a configuration is a two-phase commit and each phase is a signal the other end
cannot infer. The forwarder therefore holds exactly one send capability in the whole system, on the
configuration domain alone, and the management domain holds none at all. The console holds none in
either direction — it never reaches the event
loop, so a notification on it would be authority granted for nothing. Zero IRQs. The capability
grant is machine-checkable in the Microkit capability/memory report the build generates.

Two **`<ioport>` grants**, on two domains, and they are the whole of the system's port authority.
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

The management domain's grant is two regions plus its own log ring, and what it withholds is the
whole of the port isolation: no dataplane region of any kind, **no buffer pool at all** — not even
its own port's, frames being counted off their descriptors and never read — no configuration region,
no ECAM page, no BAR window, no virtqueue and no I/O port. Its receive pool is consequently mapped by
**no protection domain in the system**: the driver takes its physical address alone and nothing with
a CPU reaches it, which `xtask::sysdesc` carries as a rule with an empty grant set and a claim saying
why. The one region it is granted read-write that the forwarder is refused is that pipeline's `free`
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
needs ARP, IP, TCP, TLS and HTTP that do not exist. Absent: Rx/Tx virtualisers,
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

- **The in-system update/health PD.** No component inside seL4 holds a disk capability, so the
  health flag (`*_OK`) is only ever set by the build seed or the test harness. The confirm half of
  the try/confirm cycle does not exist at runtime.
- No staged installation into the inactive slot.
- No multi-attempt counter (GRUB is single-attempt by design; the counter belongs to the missing PD).
- No redundant, torn-write-safe boot state — a single `grubenv` block. A torn block is *detected*
  and refused, but there is no second copy to fall back to, so the outcome is a halt.
- The DATA partition, where configuration, identity and secrets are meant to live, is an empty
  unformatted GPT entry with no consumer and no encryption.

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
| Host gate: format, Clippy `-D warnings`, comment/`unsafe` ratchets, unit + property tests | **done** | run by the pre-commit hook; Clippy covers the fourteen library crates, `xtask`, and all six protection-domain binaries in each of the two seL4 kernel configurations — which, now that every end-to-end scenario boots the release image, is the **only** thing in any gate that still compiles the debug configuration, and so the only thing keeping it buildable for the diagnostic re-run that needs it. The ratchets (`tools/xtask/src/budgets.rs` against `tools/xtask/budgets.toml`) record a comment-line ratio per production file and an `unsafe` block/fn/impl count per crate, and fail the gate on any rise |
| Coverage floor | **done** | 94% combined and 90% per library crate, enforced in the gate as line coverage; measured 99.39% combined, weakest crate `routing` at 98.41%. Every workspace member is either measured or carries a recorded AGENTS.md TEST-3 reason for being exempt, and a member in neither fails the build |
| QEMU end-to-end gate (three system scenarios, eight A/B scenarios) | **partial** | every scenario boots the **release** image — the configuration a deployment gets (BLD-3) — and a scenario that fails there is re-run once on the debug kernel to diagnose it, which never changes the verdict. Single vCPU, two dataplane ports and one management port; the multi-node virtual-network E2E is open |
| Criterion benchmarks | **partial** | `queue`, `packet-buffer`, `virtio` and `pd-runtime` (the per-packet routing cost: snapshot, parse, decide, rewrite, write back); `nic-driver-core`'s poll pass is a hot path with no benchmark, and nothing gates a regression |
| Fuzzing | **partial** | eleven persistent targets, between them covering every crate that parses a *structure* it did not write — a descriptor, a ring, a document, a header, a record. The register-protocol device crates (`uart-16550`, `hpet`, `rtc`) carry no target and do not need one: a single read admits one integer, which their property tests already sweep over the whole of its type. A sandbox that cannot start AddressSanitizer degrades the gate to build-plus-seed-corpus — see below |
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

**Live fuzzing is conditional.** All eleven targets always build under AddressSanitizer, and the
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
make test-system    # boot three QEMU scenarios: forwarding, generation swap, alternate config
make ci             # the complete gate (host gate + fuzz + release image + system + A/B scenarios)
```

**Every end-to-end scenario boots the release image** — the kernel configuration a deployment gets,
which is what BLD-3 asks of a gate. `make image` therefore builds that configuration with no flag to
remember, and the debug kernel is an explicit opt-in (`make image-debug`), the interactive `make
run`, and the diagnostic re-run described below. What that costs is nothing in coverage of this
project's own code: the protection domains are compiled with the `--release` Cargo profile in both
configurations, so there is no debug binary and the Rust under test is the Rust that ships. Only the
seL4 kernel build differs.

`make test-system` is also the smoke test. It runs **three scenarios**, each a full boot of a signed
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
make test-system          # boot the three QEMU system scenarios on the release image
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
contract on all three system scenarios and all eight A/B scenarios, and the `LFW-CFG` transcript and
the clock's established-time record on two of the three system scenarios. What `make release` adds is the other half of
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
