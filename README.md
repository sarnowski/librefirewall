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
— parsing each one, deciding on it against a static configuration, and rewriting its Ethernet and
IPv4 headers in place, so the payload is never copied.

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
| Prometheus `/metrics` | **open** | groundwork only: the dataplane crates tally drops and faults in memory; nothing exposes, reads or names them as metrics |
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
named port under a named MAC pair, or one of ten named drop reasons, each with its own counter.
`pd_runtime::RouteStage` joins them to the dataplane — snapshot the frame out of the pool, decide,
rewrite, and write back the 34 header bytes — and marks every frame it refuses `Verdict::Discard`
so the transmitting driver returns the buffer instead of transmitting it.

Held by 41 unit and property tests across the two crates, by the stage's own tests in
`crates/pd-runtime` — including one that drives an arbitrary mix of routable, unroutable, malformed
and garbage traffic through it and asserts the pool comes back whole — and by a persistent fuzz
target (`route_frame`) whose input is the frame itself.

**Missing.**

- **No ARP and no ICMP**, so neighbours are a static table and a drop is silent. Both need a domain
  that can *originate* a frame, which none can: the pools are owned by the receiving drivers, and a
  frame can only leave the port opposite the one it arrived on.
- **No configuration.** The interfaces and neighbours are a `const` table compiled into the
  forwarder PD. The two interface MACs must equal the ones QEMU gives the guest NICs
  (`tools/xtask/src/qemu.rs`), and nothing checks that they do.
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

Correctness is held by 86 unit and property tests across those four crates — including hostile-peer
cases for forged and duplicate returns, forged cursors, exhausted rings and bounded drains — plus a
500,000-frame three-thread pipeline test that cycles every buffer through `rx → route → tx → free`
far more times than the pool holds.

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

`crates/nic-driver-core` holds bring-up and the steady-state poll pass, covered by 67 further tests.
Rx and Tx clamp the device-reported length to the buffer behind it, drop runt frames, and validate
every peer transmit descriptor.

Seven persistent fuzz targets cover this surface, the peer-facing one, and the network-facing
parser (see *Engineering foundations*).

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

### Protection-domain decomposition

**Done.** Three protection domains (one forwarder, two driver instances of one binary) with real,
verifiable least privilege: the forwarder holds no device capability at all and neither pipeline's
`free` ring — so it cannot hand a live DMA target back to be issued a second time — and each driver
sees only its own ECAM page, BAR, virtqueue region, and its two pipelines. Each pipeline is three
memory regions rather than one precisely so that those grants can differ; the forwarder maps the
buffer pools, because a domain that rewrites a header must reach the bytes. Two notification channels,
each granted in **one direction only** — the drivers may signal the forwarder, and the forwarder's
two send capabilities do not exist rather than merely going unexercised. Zero IRQs. The capability
grant is machine-checkable in the Microkit capability/memory report the build generates.

**Missing.** Roughly one of the fourteen component classes in CONCEPT §6.3 exists. Absent: Rx/Tx
virtualisers, classifier, filter/connection-tracking, routing/ARP/ICMP, TLS-proxy, per-protocol L7
parsers, DPI engine, content scanner, CA signing PD, management API PD, configuration validator PD,
HA state-sync PD, and the update/health PD. There is no fault handler and no PD restart, one system
description, and no SMP variant.

One grant is also wider than the code needs, and it is not closed:

- **The `-m 1G` QEMU memory size is load-bearing and unasserted.** It is what keeps the virtqueue
  and pipeline regions inside RAM while leaving the BAR window above RAM in the q35 PCI hole. The
  window either side is narrow: below roughly 785 MiB the DMA regions leave RAM, at 1280 MiB or more
  RAM swallows the BAR window. The reasoning is recorded in the system description; no code enforces
  it.

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
them, the latter attributing every refused frame to one of ten named routing reasons or to the stage
check that caught it. Descriptors from a peer are range-validated (`descriptor_in_bounds`, plus the transmit
header-room check) and checked against the driver's in-flight set before any span is touched. Every
peer-fed loop is bounded by `DRAIN_LIMIT`.

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
| Host gate: format, Clippy `-D warnings`, comment/`unsafe` ratchets, unit + property tests | **done** | run by the pre-commit hook; Clippy covers the eight library crates, `xtask`, and both protection domains in each of the two seL4 kernel configurations. The ratchets (`tools/xtask/src/budgets.rs` against `tools/xtask/budgets.toml`) record a comment-line ratio per production file and an `unsafe` block/fn/impl count per crate, and fail the gate on any rise |
| Coverage floor | **done** | 94% combined and 90% per library crate, enforced in the gate; measured 99.26% combined, weakest crate `routing` at 98.17%. Every workspace member is either measured or carries a recorded AGENTS.md TEST-3 reason for being exempt, and a member in neither fails the build |
| QEMU end-to-end gate (the forwarding contract, A/B scenarios) | **partial** | single vCPU, two ports; the multi-node virtual-network E2E is open |
| Criterion benchmarks | **partial** | `queue`, `packet-buffer`, `virtio` and `pd-runtime` (the per-packet routing cost: snapshot, parse, decide, rewrite, write back); `nic-driver-core`'s poll pass is a hot path with no benchmark, and nothing gates a regression |
| Fuzzing | **partial** | seven persistent targets covering every crate that interprets untrusted input; a sandbox that cannot start AddressSanitizer degrades the gate to build-plus-seed-corpus |
| SBOM (SPDX 2.3), release manifest, checksums | **partial** | none of them are signed; no SLSA/in-toto attestation; and the SBOM's scope is narrower than the payload — see below |
| Reproducibility check | **partial** | `make verify-reproducible` covers kernel + system image; not a CI gate |
| Dependency and license policy (`cargo-deny`) | **done** | `bans licenses sources` in the offline gate; `advisories` needs the RustSec database and so runs in a networked CI step — not in a local `make ci` |
| Build input pinning | **partial** | every apt package — QEMU and OVMF included — is pinned to an exact version against a dated snapshot, but no sha256 for one is recorded here, so apt's own archive signature is the integrity root; the `cargo install`ed developer tools are version-exact and `--locked`, but their integrity rests on the crates.io index rather than on a checksum in this repository |

Two of those deserve more than a table cell.

**The SBOM does not describe the shipped payload.** syft catalogs the workspace *source tree*, with
`build/`, `dist/`, `target/`, `fuzz/` and `tools/` excluded, so a consumer must not read the document
as the boot payload's contents. Host-only crates that never enter an image — `criterion`, `proptest`,
and their trees — appear in the inventory. And the third-party components that genuinely *do* ship
inside the disk — the seL4 kernel from the Microkit SDK and the GRUB core image — are absent; they
are recorded as version-verified provenance in the release manifest instead.

**Live fuzzing is conditional.** All seven targets always build under AddressSanitizer, and the
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
make image          # build the OCI builder, then assemble the signed A/B disk + release bundle
make test           # fast host gate: format, clippy, unit/property tests, coverage, lint, deps
make test-system    # boot the image in QEMU and assert the forwarding contract on both ports
make ci             # the complete gate (host gate + fuzz + image + system + A/B scenarios)
```

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

The CA reaches only the build steps that fetch dependencies, and the bundle each of them derives is
removed within that same step, so it does not persist into an image layer. TLS verification stays
enabled for every download. Do not commit the certificate.

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
