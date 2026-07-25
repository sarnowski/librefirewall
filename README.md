# librefirewall

**A high-performance, deeply inspecting firewall built for strong isolation.**

librefirewall is a defensive network security gateway designed to protect everything from
industrial and operational technology environments to corporate networks, data centers, and
cloud infrastructure. It combines full packet inspection across layers 2 through 7 with TLS
interception, application-aware filtering, and inline content scanning.

Built on the seL4 microkernel with a pure-Rust userspace, librefirewall isolates drivers, protocol
parsers, inspection engines, management services, and cryptographic keys into small,
least-privilege components. This architecture aims to contain faults and compromises while keeping
the trusted computing base and attack surface as small as possible.

## Goals

- Inspect traffic from Ethernet through modern web protocols, including TLS, QUIC, and HTTP/3.
- Protect IT, OT, on-premises, virtualized, and Azure network boundaries with one architecture.
- Sustain 10 Gbit/s of fully inspected inline traffic per dataplane port pair, with low, predictable
  latency — inline TLS threat prevention being the path that sizes the design.
- Combine a zero-copy, multicore dataplane with strong capability-based isolation.
- Provide active/passive high availability with synchronized flow state and safe failover.
- Offer secure, API-only operations with validated, atomic, and automatically reversible changes.

librefirewall targets x86_64 appliances and virtual machines, from single-node gateways to
high-availability Azure Network Virtual Appliances. The project prioritizes memory safety, explicit
authority, and operational resilience without compromising dataplane performance.

## Documentation

- **[CONCEPT.md](CONCEPT.md)** — the target architecture, threat model, and critical design
  decisions. Read it first; it is the source of truth for *what* librefirewall is.
- **[AGENTS.md](AGENTS.md)** — how to work in this repository: collaboration, source control,
  documentation and testing rules, and the build interface.
- **[MONITORING.md](MONITORING.md)** — the operator contract for the console, OpenTelemetry logs,
  and Prometheus metrics: what the firewall exposes and how to interpret it.

## Project status

This section is the single source of truth for what works today. The target picture in CONCEPT.md
is deliberately larger than the current implementation. Statuses are **done**, **partial**, or
**open**; every *partial* capability is broken down further below into what exists and what remains,
so the work can be picked up without re-deriving it from the code.

**The current deployable system** is a two-dataplane-port zero-copy forwarding slice — the milestone
the build actually produces today, not a synthetic demo: one virtio-net driver protection domain per
port brings up a modern `virtio-net-pci` device on QEMU q35 from static seL4 capabilities alone, and
an isolated forwarder protection domain — the seat where the classifier and filter shards will later
run — moves frames between the two ports without copying. A frame cycles
`NIC0 → driver0 → forwarder → driver1 → NIC1` by transferring buffer *ownership* through lock-free
single-producer/single-consumer queues; its bytes are never copied and are owned by exactly one side
at a time. The reusable logic lives in host-tested `no_std` crates (`crates/`); the
protection-domain binaries (`pds/`) are thin adapters.

There is, as yet, **no packet parsing of any kind** — not even Ethernet. Frames are opaque
`(buffer, offset, length)` spans that are never interpreted; the only header the code understands is
virtio-net's 12-byte device transport header, and only as a length to skip. What exists is a
transport substrate for a firewall, not yet a firewall.

### Traffic inspection and enforcement

| Capability | Status | Notes |
|---|---|---|
| Stateful L2–L4 filtering and connection tracking | **open** | |
| Routing, ARP, ICMP | **open** | |
| Virtual-wire (bump-in-the-wire) operation | **open** | CONCEPT §6.4; maps directly onto today's port-pair relay |
| NAT (SNAT/masquerade, DNAT, static 1:1) | **open** | CONCEPT §6.5; binding lives in the conntrack entry |
| Flow classifier (cut-through vs. proxy path) | **open** | the forwarder PD is the seat reserved for it |
| L7 protocol parsing (HTTP/1.1, HTTP/2, HTTP/3) | **open** | |
| OT/industrial protocol inspection | **open** | |
| DoS resilience (SYN cookies, rate limiting, bounded state) | **open** | |
| Mirror port | **open** | |
| TLS termination and re-origination | **open** | |
| QUIC / HTTP-3 termination | **open** | |
| Isolated sign-only CA protection domain | **open** | |
| Trusted time source | **open** | |
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
| Full port role model (management, session-replication, mirror, multiple pairs) | **open** | two dataplane ports exist; no other role |
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
| Schema-validated XML configuration, hardened validator PD | **open** | |
| Candidate/commit-confirm transactions, versioning, rollback | **open** | |
| Distributed staged rollout across the pair | **open** | |
| Console system-state events | **open** | five ad-hoc bring-up markers exist; not the MONITORING.md contract |
| OpenTelemetry structured logs | **open** | |
| Prometheus `/metrics` | **open** | groundwork only: 15 in-memory counter fields, no endpoint and no reader |
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

### Zero-copy dataplane

**Done.** `crates/queue` provides the lock-free SPSC ring. Each side's position is **private**: a
`RingProducer`/`RingConsumer` handle is taken once at attach and holds that side's position in
domain-local memory the peer cannot map, so the only shared word a side reads is the *peer's*
cursor, masked into range. Slots are per-field atomics, which makes a concurrent byzantine write a
defined (if unexpected) value rather than undefined behaviour — and is why the crate is
`#![forbid(unsafe_code)]`. `RingConsumer::drain(limit)` gives every consumer a bounded pass.

`crates/packet-buffer` provides the shared pool and the owner-side ledger, which accounts buffers
**by identity, not by count**: an outstanding-set partitions `0..N`, `pop` mints a move-only
`OwnedBuffer` token, and `reclaim(index)` is the single trust boundary for a peer-supplied index —
it refuses one out of range and one that is not outstanding. `crates/wire` fixes the 12-byte
`Descriptor` ABI with static layout assertions. `crates/pd-runtime` composes them into the
`Pipeline` (pool first, then rx/tx/free rings, in one 256 KiB region), `PoolOwner` (the pool-owning
side, with its own *lent* set on top of the ledger) and `ForwardStage` (one forwarding direction).
Every field offset and the total size are pinned by const assertion, since the region is a
cross-domain ABI.

Correctness is held by 69 unit and property tests across those four crates — 32 of them explicitly
adversarial-peer cases (forged and duplicate returns, rewound and forged cursors, exhausted rings,
bounded drains) — plus a 500,000-frame three-thread pipeline test that cycles every buffer through
`rx → forward → tx → free` far more times than the pool holds, and end-to-end by byte-identical
bidirectional forwarding in QEMU.

**Missing.**

- No batching API — one descriptor per call, and one notification per drain. CONCEPT §6.1's
  batched notifications are incidental today, not designed.
- Pool is 64 buffers of 2048 bytes; orders of magnitude short of a 10 Gbit/s working set.
- Fixed 2048-byte buffers: no jumbo frames, no scatter-gather, no descriptor chaining.
- Exactly two pipelines, hard-coded in the forwarder PD. No per-core sharding, no multi-queue.
- No backpressure policy beyond releasing the buffer. A peer that stalls a destination ring makes
  `ForwardStage::poll` drop a descriptor it has already dequeued, and the buffer that descriptor
  named is then lost to its owner's ledger permanently. It is counted, and nothing is double-owned
  — but the pool shrinks, and no component reclaims it.
- The `.system` `<memory_region>` sizes and the Rust constants they must equal (`REGION_SIZE`,
  `BAR_WINDOW_SIZE`, `VQ_REGION_SIZE`) have **no build-time cross-check**. Nothing reads the XML
  back into Rust, so a divergence surfaces as a truncated mapping at boot rather than as a build
  error. This is a documented precondition with no enforcer.

### virtio-net driver

**Done.** A from-scratch modern virtio 1.0 PCI transport in `crates/virtio`: capability-list walk
with a loop guard, BAR relocation, feature negotiation, queue programming and doorbells, covered by
67 unit and property tests of which 35 are malformed- or hostile-device cases. Every transport entry
point the device drives returns a typed error (`BarError`, `ResetError`, `QueueSetupError`,
`NotifyError`, `CapError`) instead of panicking — an out-of-range or non-relocatable BAR index, a
device that never acknowledges reset, an absent or too-small virtqueue, and a doorbell slot outside
or misaligned within the mapped BAR. A split-virtqueue driver half whose descriptor lifecycle,
free-list links and posted lengths are all **driver-private**, so a device that scribbles the shared
region cannot steer the free list; every completion is validated against that private state and
refused (and counted in `DeviceFaults`) if it names a descriptor never posted or already reaped.

`crates/nic-driver-core` holds the rest: bring-up is a **typestate**
(`identify → place_bar → map → acknowledge → negotiate_features → configure_queues → go_live`), so
a wrong handshake order is unrepresentable rather than merely commented, and the poll pass
(`DataplanePort::poll_once`) fixes the steady-state ordering — `reclaim → refill → drain → notify`,
then `reap → post` — running each step exactly once, with no loop of its own. Rx/Tx
clamp the device-reported length to the buffer behind it, drop runt frames, and validate every peer
transmit descriptor. 60 further tests cover it, 17 of them device-rejection cases.

Six persistent fuzz targets cover this surface and the peer-facing one (see *Engineering
foundations*); one of them found a real CRITICAL — a device-controlled unaligned common-configuration
offset that reached a misaligned `u32` volatile write — now refused by `BringUpError::CommonCfgMisaligned`
with regression tests in both owning crates.

**Missing.**

- **Interrupts.** Busy-poll only — no MSI-X, no INTx (deliberate for this milestone). The ISR
  capability's presence is still required of the device, but its offset is not retained and the
  status register is never read; the offset returns to `VirtioCaps` when there is something to read
  it for. This burns a core per port, and both driver instances run at the same priority and never
  yield, so their mutual progress rests on seL4's round-robin scheduling alone.
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
- **No restart.** A rejected bring-up is now a typed `BringUpError` the PD reports on the console
  and parks on, writing `STATUS_FAILED` back to the device from the point the BAR is placed and the
  register is reachable (`BringUpError::signalled_to_device` says which of the two happened per
  variant). The domain is left idle rather than faulted — but nothing restarts it, and the port
  stays down until the node is rebooted.

### Protection-domain decomposition

**Done.** Three protection domains (one forwarder, two driver instances of one binary) with real,
verifiable least privilege: the forwarder holds no device capability at all, and each driver sees
only its own ECAM page, BAR, virtqueue region, and its two pipelines. Two notification channels,
each granted in **one direction only** — the drivers may signal the forwarder, and the forwarder's
ends carry `notify="false"`, so its two never-used send capabilities do not exist rather than merely
going unexercised. Zero IRQs. Every DMA mapping states `cached="true"` explicitly, because
`virtio::queue` names a cached mapping as a premise of its ordering argument and a premise is
declared where the grant is made. The capability grant is machine-checkable in the Microkit
capability/memory report the build generates.

**Missing.** Roughly one of the fourteen component classes in CONCEPT §6.3 exists. Absent: Rx/Tx
virtualisers, classifier, filter/connection-tracking, routing/ARP/ICMP, TLS-proxy, per-protocol L7
parsers, DPI engine, content scanner, CA signing PD, management API PD, configuration validator PD,
HA state-sync PD, and the update/health PD. There is no fault handler and no PD restart, one system
description, and no SMP variant.

Two grants are also wider than the code needs, and neither is closed:

- **The forwarder is over-granted.** It maps each 256 KiB pipeline read-write although
  `ForwardStage` touches only that pipeline's rx and tx rings — roughly 3 KiB. The 128 KiB buffer
  pool in the same region is never read or written by the forwarder, and it is the part a
  compromised forwarder could corrupt. Splitting the pool from the rings into separate memory
  regions is designed and costed but not done.
- **The `-m 1G` QEMU memory size is load-bearing and unasserted.** It is what places the virtqueue
  and pipeline regions inside RAM (so seL4 zeroes them, which is the whole of what establishes the
  zero-initialised precondition both `SplitVirtqueue::new` and `attach_pipeline!` require) while
  leaving the BAR window above RAM in the q35 PCI hole. The window either side is narrow — below
  roughly 785 MiB the DMA regions leave RAM, at 1280 MiB or more RAM swallows the BAR window — and
  nothing checks it. The reasoning is recorded in the system description; no code enforces it.

### Untrusted-device hardening

**Done.** Every byte the device writes — configuration-space ids, the capability chain, BAR type
bits, structure offsets, the feature bitmap, the `device_status` readback, the queue count, each
queue's `queue_notify_off`, and every used-ring completion — is treated as hostile input and
**rejected with a typed error or a counted drop, never by panicking**. The device-reachable
assertions the audit found are gone: nine `assert!`/`expect` sites in the driver protection domain
and four in the transport, plus two `debug_assert!`s that were the *only* guard on the virtqueue's
free list and so were absent from every image that ever booted.

What remains of `assert!` and `expect` on these paths is a different thing and stays deliberately:
checks of a domain's *own* invariant, each stating the proof that no device value reaches it and
naming the component that establishes that. Every one of them is unconditional in every build
profile rather than a `debug_assert!` — the protection domains are compiled with the optimized
Cargo profile in both kernel configurations, so a `debug_assert!` would be absent from every image
that ever boots and would therefore be no check at all. Specifically:

- The capability walk has a loop guard and refuses an absent list, a looping chain, an invalid BAR
  index, structures split across BARs, and a missing required structure.
- Structure offsets are bounded against the mapped BAR window *and* alignment-checked before any
  pointer is formed; a `Doorbell` is a type that exists only once its slot has been proven inside
  the window and evenly aligned.
- The reset wait is bounded by a driver-owned poll count, not by a device-controlled condition.
- The virtqueue's descriptor lifecycle, free-list links and posted lengths are driver-private, so a
  scribbled descriptor table cannot steer the free list — the remotely triggerable out-of-bounds
  write that came of chaining through device-writable memory is gone.
- Completion ids are validated against that private state; a forged, replayed or out-of-range one is
  refused and counted in `DeviceFaults`, and every device-fed loop is bounded per call by `QUEUE_SIZE`.
- A rejected bring-up writes `STATUS_FAILED` back to the device wherever the register is reachable
  and parks the domain instead of faulting it.

Held by 35 hostile-device cases in `crates/virtio` and 17 in `crates/nic-driver-core`, plus two
device-facing persistent fuzz targets (`find_virtio_caps`, `virtqueue_poll`) and a third
(`nic_driver_paths`) that drives a hostile device and a byzantine forwarder at once. Each models the
device's full authority over the shared region rather than a well-behaved subset of it.

**Missing.**

- **The device's DMA is not confined.** Bus-master DMA is enabled against fixed physical addresses
  with no IOMMU (the *IOMMU (VT-d) DMA confinement* row above). Every check listed here bounds what
  the driver *believes*; none of them bounds where the device can *write*. This is the single
  largest residual against CONCEPT §7.1's hostile-device adversary, and no first-party code can
  substitute for VT-d.
- **No restart.** A device that fails bring-up leaves its port permanently down (see
  *[virtio-net driver](#virtio-net-driver)*).
- `overflow-checks` is off in the shipped profile. The property tests prove "no panic on arbitrary
  input" while running *with* overflow checking; the binary that ships wraps silently instead. The
  arithmetic on these paths is bounded by construction, so no wrap is currently reachable — but the
  proof and the artifact are not the same build. Turning it on for the protection domains is
  undecided and human-owned.

### Untrusted-peer containment

**Done.** Buffer ownership is accounted **by identity**, not by count. `packet_buffer::FreeList`
carries an outstanding-set that partitions `0..N`; `pop` mints a non-`Copy`, non-`Clone`
`OwnedBuffer` token, so a *local* double return is not representable rather than merely detected;
and `reclaim(index)` is the one place an index the crate did not mint is accepted — the trust
boundary — refusing an index out of range and one that is not outstanding. On top of it
`pd_runtime::PoolOwner` keeps a per-index *lent* set, because the ledger alone cannot tell a buffer
lent to the peer from one still posted to this domain's own NIC (both are merely "outstanding"), and
accepting the latter back would free a live DMA target. Only an index this domain actually put on a
ring is taken back.

Every rejection is a **counted drop**, never a fault: `PoolCounters` and `ForwardCounters` record
them. Descriptors from a peer are range-validated (`descriptor_in_bounds`, plus the transmit
header-room check) and checked against the driver's in-flight set before any span is touched. Ring
positions are private to each side, so a peer rewinding a cursor cannot make a slot deliver twice.
Every peer-fed loop is bounded by `DRAIN_LIMIT`, derived from this crate's own constants and never
from a peer-influenced `len()`. The previously undocumented path from a forged buffer index to an
arbitrary physical DMA write is closed.

**Missing.**

- **A byzantine forwarder can still corrupt a frame in the shared pool.** It may name a buffer whose
  pool owner has it posted as that NIC's receive DMA target; the transmitting driver's 12-byte
  virtio-net header write then races the DMA. The damage is bounded — the address is always inside
  the region, because it is derived from an index that passed the pool bounds check — but exclusive
  ownership across domains is a protocol claim no single domain can verify. Closing it needs an
  IOMMU (CONCEPT §7.2) or a cross-domain per-buffer ownership epoch; neither exists.
- **Buffer loss is not recovered.** A peer that stalls a destination ring costs the pool one buffer
  per dropped descriptor, permanently (see *[Zero-copy dataplane](#zero-copy-dataplane)*). It is
  counted, and nothing reclaims it.
- **A peer can still write pool bytes at any time.** No Rust type stops a domain mapping the region
  from scribbling a buffer it does not own; that is why the pool never hands out a safe reference to
  those bytes, and why an IOMMU is what finally confines a NIC's DMA.
- **No PD fault handling.** A domain that a peer manages to wedge is not restarted.

### A/B image update

**Done.** A GPT disk with ESP, STATE, SLOT_A, SLOT_B and DATA partitions; both slots carry a signed
kernel and system image. GRUB is built from pinned source as a standalone EFI binary with an
embedded public key, so it *enforces* detached-signature verification on everything it loads.

The `OK`/`TRY`/`ORDER` selection scheme is implemented and covered by **eight** QEMU scenarios:
confirmed-A, try-pending-B, fallback-from-broken-B, skip-exhausted-B, confirmed-B, an `ORDER` naming
a slot that does not exist, and the two ways every slot can become unbootable — both payloads broken,
and boot state so torn that an attempt cannot be recorded. Each asserts *which slot was chosen*
against a **structured boot channel** — GRUB emits one `LFW-BOOT slot=… state=…` record per
selection decision and each scenario declares the exact ordered sequence it must produce, so
"slot B booted" cannot be confused with "slot B was tried, rejected, and A booted instead". Each
then asserts *that the chosen slot is healthy* through the system's real observable contract, frames
forwarded between the two NIC ports — or, for the two halt scenarios, its negative: no frame
forwarded and GRUB's halt record on the channel. Both slots carry byte-identical payloads, so
nothing downstream of GRUB could name the slot; the record sequence is the only thing that can.

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

Signing is key-explicit and self-checked: every signature is made with `--local-user` naming the
exact fingerprint that was exported and embedded into GRUB (a keyring holding a second key is
rejected outright rather than silently resolved), and the build then **verifies what it just
signed** against a scratch keyring seeded only from that exported public key, requiring gpg to
report `VALIDSIG` for that fingerprint — before anything is written into a slot. A mis-keyed payload
therefore fails the build rather than the appliance.

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
| Host gate: format, Clippy `-D warnings`, `missing_docs`, unit + property tests | **partial** | run by the pre-commit hook; Clippy covers the library crates and `xtask` but **not** `pds/` |
| Coverage floor | **done** | 94% combined and 90% per library crate, enforced in the gate; measured 99.69% combined, weakest crate `pd-runtime` at 98.60% |
| QEMU end-to-end gate (byte-identical forwarding, A/B scenarios) | **partial** | single vCPU, two ports; the multi-node virtual-network E2E is open |
| Criterion benchmarks | **partial** | `queue`, `packet-buffer` and `virtio` only; `pd-runtime`'s forwarding stage and `nic-driver-core`'s poll pass are hot paths with no benchmark, and nothing gates a regression |
| Fuzzing | **partial** | six persistent targets covering every crate that interprets untrusted input; a sandbox that cannot start AddressSanitizer degrades the gate to build-plus-seed-corpus |
| SBOM (SPDX 2.3), release manifest, checksums | **partial** | none of them are signed; no SLSA/in-toto attestation; and the SBOM's scope is narrower than the payload — see below |
| Reproducibility check | **partial** | `make verify-reproducible` covers kernel + system image; not a CI gate |
| Dependency and license policy (`cargo-deny`) | **done** | `bans licenses sources` in the offline gate; `advisories` needs the RustSec database and so runs in a networked CI step — not in a local `make ci` — reporting even on a red build |
| Build input pinning | **partial** | every apt package — QEMU and OVMF included — is now pinned to an exact version against a dated snapshot, but no sha256 for one is recorded here, so apt's own archive signature is the integrity root; the `cargo install`ed developer tools are version-exact and `--locked`, but their integrity rests on the crates.io index rather than on a checksum in this repository |

Three of those deserve more than a table cell.

**The protection domains are not Clippy-linted.** `cargo fmt --all --check` covers the whole
workspace and `missing_docs` is a rustc lint that fires when the PDs are built for the seL4 target,
so both reach `pds/`. Clippy does not: the gate runs it over the six library crates and `xtask`
only. `undocumented_unsafe_blocks` is a Clippy lint, so it is **unenforced on the four `unsafe`
blocks in `pds/nic-driver`** — each of which does carry a `SAFETY:` comment, but by review rather
than by the gate. Running Clippy against the seL4 target works and passes today; it is simply not
wired into any command.

**The SBOM does not describe the shipped payload.** syft catalogs the workspace *source tree*, with
`build/`, `dist/`, `target/`, `fuzz/` and `tools/` excluded. Two consequences follow, and a consumer
must not read the document as the boot payload's contents. Its cargo cataloger reads `Cargo.lock`,
which does not distinguish normal from dev dependencies, so host-only crates that never enter an
image — `criterion`, `proptest`, and their trees — appear in the inventory. And the third-party
components that genuinely *do* ship inside the disk — the seL4 kernel from the Microkit SDK and the
GRUB core image — are invisible to a source-tree scan; they are recorded as version-verified
provenance in the release manifest instead. Closing the gap needs a payload-scoped inventory syft's
single-source model does not offer.

**Live fuzzing is conditional.** All six targets always build under AddressSanitizer, and the
seed-corpus smoke tests always run. Whether libFuzzer can actually *execute* is established once per
run by an explicit probe, because the hermetic builder (`--cap-drop=all`, read-only rootfs,
`no-new-privileges`) can stop ASan before `main`. When the probe passes, every subsequent non-zero
exit is treated as a finding and fails the gate. When it fails, the run reports loudly and proceeds
with build-plus-seed coverage only — so a gate can go green having done no live fuzzing at all.

## Build and test

The supported developer and CI interface is GNU Make backed by rootless Podman. A pinned OCI
builder (Debian 13 by digest, a dated Debian snapshot, the Microkit SDK, `rust-sel4`, the project
Rust nightly, GRUB, OVMF, QEMU, and the coverage/lint/fuzz/SBOM tooling) provides every build input.
The downloads are sha256-pinned in [`third-party/sources.lock`](third-party/sources.lock); each apt
package is pinned to an exact version inline in the Containerfile, next to the package name, against
the snapshot that file freezes. Nothing outside the builder is required beyond Podman itself.

From a clean checkout:

```sh
make image          # build the OCI builder, then assemble the signed A/B disk + release bundle
make test           # fast host gate: format, clippy, unit/property tests, coverage, lint, deps
make test-system    # boot the image in QEMU and assert byte-identical forwarding on both ports
make ci             # the complete gate (host gate + fuzz + image + system + A/B scenarios)
```

`make image` is the only network-enabled phase (the OCI build), and that is now **enforced rather
than asserted**: every other target — `make clean` included — checks that the pinned builder image
already exists and refuses with an actionable message instead of quietly provisioning it. So no gate
command can turn into an OCI build. Project commands run with networking disabled, a read-only
container filesystem, no Linux capabilities, and only the workspace mounted writable. When the host
exposes `/dev/kvm` it is passed through for accelerated QEMU; the harness falls back to emulation
otherwise, and which of the two happened is printed and written into the run log, so a silent
degradation to emulation cannot pass for an accelerated run.

The full command surface:

```sh
make image                # build the OCI builder, then `xtask image`
make run                  # boot the image interactively in QEMU
make test                 # fast host gate (format, clippy, tests, coverage floor, lint, dependency policy)
make coverage             # measure host-crate line coverage and print the per-crate summary
make bench                # run the performance benchmarks
make fuzz                 # run the seed smoke tests, build every fuzz target, exercise each briefly
make test-system          # boot QEMU and assert the forwarding contract
make test-ab              # boot the eight A/B state-machine scenarios and assert on each
make ci                   # the complete gate: host gate, fuzz, image, system and A/B
make release              # run CI, then assemble AND boot the Microkit release payload
make verify-reproducible  # build twice in isolation and compare artifacts
make hooks                # install the pre-commit and pre-push git hooks
make clean                # remove generated output only
```

Commits go straight to `trunk`. Install the git hooks once with `make hooks`: the pre-commit hook
runs the fast host gate (`make test`) and the pre-push hook runs the full `make ci`, so every commit
that reaches `trunk` has passed formatting, lints, tests, coverage, dependency policy, the fuzz
targets, image assembly, and the QEMU system and A/B gates. That is what a machine can check, and it
is less than the rules the project holds itself to; [AGENTS.md](AGENTS.md) marks each rule `GATE` or
`REVIEW` so it is never ambiguous which of the two a given property rests on.

On a development machine behind a TLS-inspecting proxy, the build automatically detects an installed
inspection CA (a `*-dpi-ca.crt` under `/usr/local/share/ca-certificates/`) and provides it as a
Podman build secret. On another inspected network, or to select a specific certificate, pass its
path explicitly:

```sh
make image ENTERPRISE_CA_FILE=/path/to/enterprise-ca.pem
```

The CA is available only to the dependency-installation build step; it is never copied into an
image layer, and TLS verification stays enabled for every download. Do not commit the certificate.

## Release artifacts

`make release` runs the complete acceptance gate, then assembles the production-oriented Microkit
release configuration into `dist/` — **and then boots that release artifact against the same
forwarding contract** before it counts as a release. The release configuration is a different kernel
build from the one the gate exercises, so passing the gate on the debug image says nothing about it;
if the release disk fails the contract, `dist/` is emptied rather than left holding an unproven image
that looks finished.

The deployable artifact is `dist/librefirewall-qemu-x86_64.img`, the signed GPT A/B disk booted
through OVMF and GRUB. Alongside it, `dist/` carries five product-prefixed pieces of release
evidence and nothing else: the loose kernel and system images (the update input), a manifest
describing the target, pinned inputs and signing trust profile, an SPDX 2.3 SBOM (see *Engineering
foundations* for what it does and does not cover), and a SHA-256 checksum file covering every other
artifact. The Microkit capability/memory report is deliberately **not** published: it is a full
disclosure of the system's authority topology, and it is build-internal debugging evidence, so it
stays under `build/image/<config>/`.

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
