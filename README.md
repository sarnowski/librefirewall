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
| Console system-state events | **open** | 8 ad-hoc serial markers exist; not the MONITORING.md contract |
| OpenTelemetry structured logs | **open** | |
| Prometheus `/metrics` | **open** | groundwork only: three drop counters in `nic-driver-core` |
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
| Untrusted-device hardening | **done** | adversarial device fixtures and two fuzz targets |
| Untrusted-peer (byzantine neighbour) containment | **partial** | [detail](#untrusted-peer-containment) |
| PD fault handling and restart | **open** | every failure path is a panic |

## Partial capabilities in detail

What each partial capability already has, and what specifically remains to finish it.

### Zero-copy dataplane

**Done.** `crates/queue` provides the lock-free SPSC ring, with every cursor read back from shared
memory masked into range so a hostile peer cannot index out of bounds. `crates/packet-buffer`
provides the shared pool and the owner-side LIFO free list; `crates/wire` fixes the 12-byte
`Descriptor` ABI with static layout assertions; `crates/pd-runtime` composes them into the
`Pipeline` (rx/tx/free rings plus pool in one 256 KiB region) and the buffer-ownership protocol.
Correctness is held by model-based property tests and a 500,000-frame three-thread pipeline test,
and end-to-end by byte-identical bidirectional forwarding in QEMU.

**Missing.**

- No batching API — one descriptor per call, and one notification per drain. CONCEPT §6.1's
  batched notifications are incidental today, not designed.
- Pool is 64 buffers of 2048 bytes; orders of magnitude short of a 10 Gbit/s working set.
- Fixed 2048-byte buffers: no jumbo frames, no scatter-gather, no descriptor chaining.
- Exactly two pipelines, hard-coded in the forwarder PD. No per-core sharding, no multi-queue.
- No backpressure policy beyond releasing the buffer, and over-return panics rather than dropping.

### virtio-net driver

**Done.** A from-scratch modern virtio 1.0 PCI transport in `crates/virtio`: capability-list walk
with a loop guard, BAR relocation, feature negotiation, queue programming and doorbells, covered by
27 unit tests of which 11 are malformed-configuration-space cases. A split-virtqueue driver half
with a bounded poll loop and rejection of out-of-range completions. Steady-state Rx/Tx in
`crates/nic-driver-core` with device-reported length clamping, runt-frame drop, rejection of
not-outstanding completions, and validation of every peer transmit descriptor. Two persistent fuzz
targets, both aimed at the untrusted device.

**Missing.**

- **Interrupts.** Busy-poll only — no MSI-X, no INTx (deliberate for this milestone). The ISR
  structure is discovered and bounds-checked but never read. This burns a core per port.
- **Real hardware.** No PCI enumeration: the BDF and the BAR physical address are pinned in the
  system description, so the driver cannot bind a device it was not built for.
- **DMA confinement.** Bus-master DMA is enabled unconditionally against fixed physical addresses;
  no VT-d.
- **Offloads.** No checksum offload, TSO/GSO, or mergeable receive buffers — prerequisites for
  10 Gbit/s.
- No control virtqueue, no multi-queue, no link-status handling, no MAC read-out despite
  negotiating `VIRTIO_NET_F_MAC`.
- No packed virtqueue and no MMIO transport (PCI only).
- Every bring-up failure is an `assert!`; `STATUS_FAILED` is defined but never used, so there is no
  graceful failure path back to the device and no restart.

### Protection-domain decomposition

**Done.** Three protection domains (one forwarder, two driver instances of one binary) with real,
verifiable least privilege: the forwarder holds no device capability at all, and each driver sees
only its own ECAM page, BAR, virtqueue region, and its two pipelines. Two notification channels,
zero IRQs. The capability grant is machine-checkable in the generated Microkit report shipped with
every build.

**Missing.** Roughly one of the fourteen component classes in CONCEPT §6.3 exists. Absent: Rx/Tx
virtualisers, classifier, filter/connection-tracking, routing/ARP/ICMP, TLS-proxy, per-protocol L7
parsers, DPI engine, content scanner, CA signing PD, management API PD, configuration validator PD,
HA state-sync PD, and the update/health PD. There is no fault handler and no PD restart, one system
description, and no SMP variant.

### Untrusted-peer containment

**Done.** Descriptors from a peer are range-validated before use (`descriptor_in_bounds`, plus the
transmit-header room check); ring cursors are masked so a hostile peer cannot drive an out-of-bounds
slot access; a forged buffer index is dropped without being returned to the pool.

**Missing — and this is a stated deviation from CONCEPT §7.1**, documented in the `pd-runtime` crate
header. Buffer ownership is accounted **by count, not against an outstanding set**, so a peer that
returns more descriptors than it was handed — duplicates or forged indices — is not contained. The
pool owner currently fails visibly: `Producer::release`, `forward`, and `return_buffer` **panic** on
the resulting overflow, and short of overflow a duplicate return silently double-owns a buffer. A
byzantine neighbour can therefore crash a well-behaved PD, which the threat model says it must not.
Closing it needs a per-buffer outstanding-set ledger, drop-and-count in place of the panics, and a
PD fault/restart story to land alongside.

### A/B image update

**Done.** A GPT disk with ESP, STATE, SLOT_A, SLOT_B and DATA partitions; both slots carry a signed
kernel and system image. GRUB is built from pinned source as a standalone EFI binary with an
embedded public key, so it *enforces* detached-signature verification on everything it loads. The
`OK`/`TRY`/`ORDER` selection scheme is implemented and covered by five QEMU scenarios —
confirmed-A, try-pending-B, fallback-from-broken-B, skip-exhausted-B, confirmed-B — each of which
also runs the full forwarding assertion, so "booted healthy" means real frames moved.

**Missing.**

- **The in-system update/health PD.** No component inside seL4 holds a disk capability, so the
  health flag (`*_OK`) is only ever set by the build seed or the test harness. The confirm half of
  the try/confirm cycle does not exist at runtime.
- No staged installation into the inactive slot.
- No multi-attempt counter (GRUB is single-attempt by design; the counter belongs to the missing PD).
- No redundant, torn-write-safe boot state — a single `grubenv` block.
- The DATA partition, where configuration, identity and secrets are meant to live, is an empty
  unformatted GPT entry with no consumer and no encryption.
- The release-configuration image is assembled but never booted or tested.

### Signed boot chain

**Done.** OVMF → GRUB → Multiboot2 → seL4/Microkit with enforced payload signature verification;
the corrupt-signature fallback path is proven by test. A throwaway development key is generated per
checkout and never committed, and the release manifest records `trust_profile: development` with the
key fingerprint so a development-signed image cannot be mistaken for a production one.

**Missing.** UEFI Secure Boot is not enrolled — the manifest hard-codes `secure_boot: false`, and
`BOOTX64.EFI` itself is unsigned in the Authenticode sense (no shim, MOK, or PK/KEK/db hierarchy).
There is no TPM anywhere: no vTPM in the QEMU harness, no measured boot, no PCR policy, and no
anti-rollback epoch. Production key management (HSM-backed signing) does not exist.

## Engineering foundations

Not product features, but the machinery every feature above lands through — and where most of what
is *done* currently sits.

| Foundation | Status | Notes |
|---|---|---|
| Hermetic, pinned build in a rootless OCI builder | **done** | base image by digest, dated Debian snapshot, checksum-verified SDK/toolchain/GRUB/syft, `--locked` throughout |
| Host gate: format, Clippy `-D warnings`, `missing_docs`, unit + property tests | **done** | run by the pre-commit hook |
| Coverage floor | **done** | 94% combined and 90% per library crate, enforced in the gate; measured ~98% |
| QEMU end-to-end gate (byte-identical forwarding, A/B scenarios) | **partial** | single vCPU, two ports, debug configuration only; the multi-node virtual-network E2E is open |
| Criterion benchmarks | **done** | present as a layer beside the code they measure |
| Fuzzing | **partial** | two persistent targets, both device-facing; no traffic-facing target exists because no traffic parser does |
| SBOM (SPDX 2.3), release manifest, checksums | **partial** | none of them are signed; no SLSA/in-toto attestation |
| Reproducibility check | **partial** | `make verify-reproducible` covers kernel + system image; not a CI gate |
| Dependency and license policy (`cargo-deny`) | **partial** | `bans licenses sources` are gated; `advisories` runs nowhere, so there is no vulnerability scanning |
| Build input pinning | **partial** | apt packages — including QEMU and OVMF — are constrained only by snapshot date, not by checksum |

## Build and test

The supported developer and CI interface is GNU Make backed by rootless Podman. A pinned OCI
builder (Debian 13 by digest, a dated Debian snapshot, the Microkit SDK, `rust-sel4`, the project
Rust nightly, GRUB, OVMF, QEMU, and the coverage/lint/fuzz/SBOM tooling) provides every build input;
checksums are recorded in [`third-party/sources.lock`](third-party/sources.lock). Nothing outside
the builder is required beyond Podman itself.

From a clean checkout:

```sh
make image          # build the OCI builder, then assemble the signed A/B disk + release bundle
make test           # fast host gate: format, clippy, unit/property tests, coverage, lint, deps
make test-system    # boot the image in QEMU and assert byte-identical forwarding on both ports
make ci             # the complete pull-request gate (host gate + image + system + A/B scenarios)
```

`make image` is the only network-enabled phase (the OCI build). Project commands then run with
networking disabled, a read-only container filesystem, no Linux capabilities, and only the
workspace mounted writable. When the host exposes `/dev/kvm` it is passed through for accelerated
QEMU; the harness falls back to emulation otherwise.

The full command surface:

```sh
make image                # build the OCI builder, then `xtask image`
make run                  # boot the image interactively in QEMU
make test                 # fast host gate (format, clippy, tests, coverage floor, lint, dependency policy)
make coverage             # measure library-crate line coverage and print the per-crate summary
make bench                # run the performance benchmarks
make fuzz                 # build every fuzz target and briefly exercise each
make test-system          # boot QEMU and assert the forwarding contract
make test-ab              # boot the A/B state-machine scenarios and assert on each
make ci                   # the complete pull-request gate
make release              # run CI, then assemble the Microkit release payload in dist/
make verify-reproducible  # build twice in isolation and compare artifacts
make hooks                # install the pre-commit and pre-push git hooks
make clean                # remove generated output only
```

Commits go straight to `trunk`. Install the git hooks once with `make hooks`: the pre-commit hook
runs the fast host gate (`make test`) and the pre-push hook runs the full `make ci`, so every commit
that reaches `trunk` has passed formatting, lints, tests, coverage, dependency policy, image
assembly, and the QEMU system and A/B gates. See [AGENTS.md](AGENTS.md) for the workflow in full.

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

`make release` first runs the complete acceptance gate and only then replaces `dist/` with the
production-oriented Microkit release configuration; release assembly without the gate is not a
release. The deployable artifact is `dist/librefirewall-qemu-x86_64.img`, the signed GPT A/B disk
booted through OVMF and GRUB. Alongside it, `dist/` carries the product-prefixed release evidence:
the loose kernel and system images (the update input and debugging evidence), a manifest describing
the target and pinned inputs, the Microkit capability/memory report, an SPDX 2.3 SBOM, and a
SHA-256 checksum file covering every other artifact. Image builds generate a throwaway development
signing key under `build/dev-keys/` (never committed; removed by `make clean`); the manifest records
`trust_profile: development` so a development-signed image can never be mistaken for a production
one.

All commands force Podman's `cgroupfs` manager. Override `PODMAN` only to select a compatible Podman
executable; Docker is not a supported build interface.

## License

librefirewall is free software, licensed under the **GNU Affero General Public License, version 3 or
later (AGPL-3.0-or-later)**. The full text is in [LICENSE.md](LICENSE.md).

Copyright (C) 2026 Tobias Sarnowski

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero
General Public License for more details.
