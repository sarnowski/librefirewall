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
is deliberately larger than the current implementation.

| Capability | Status | Notes |
|---|---|---|
| Hermetic, pinned build → signed A/B disk image | **done** | reproducibility check available (`make verify-reproducible`); not yet a CI gate |
| Signature-enforced UEFI boot (OVMF → GRUB → Multiboot2 → seL4/Microkit) | **done** | development signing keys; UEFI Secure Boot not yet enrolled (CONCEPT §14.5) |
| A/B slot selection state machine (`OK`/`TRY`/`ORDER`) with fallback | **done** | in-system health-confirmation PD not built; the test harness seeds `grubenv` |
| First-party virtio-net driver (virtio 1.0 PCI bring-up, Rx + Tx) | **partial** | polls (no MSI-X/INTx); no real-hardware BAR discovery; no VT-d DMA confinement; no MAC read-out; no offloads |
| Zero-copy forwarding dataplane (SPSC queues, packet-buffer ownership) | **partial** | one dataplane pair on QEMU; no management / session-replication / mirror ports; the forwarder has no classifier or filter stages yet |
| Untrusted device / peer hardening | **partial** | device-distrust in the driver; peer-distrust (byzantine-neighbour containment) is incomplete and tracked |
| SBOM (SPDX 2.3), release manifest, checksums | **done** | build provenance planned |
| QEMU end-to-end gate (byte-identical forwarding, A/B scenarios) | **done** | single vCPU; no management-NIC / multi-core machine yet |
| Test framework (unit · property · fuzz · bench · QEMU E2E) | **done** | unit + property tests, an enforced library coverage floor, lint (`clippy -D warnings`, `missing_docs`) and dependency (`cargo-deny`) gates, criterion benches, and the QEMU E2E gate are all in place; fuzz targets are built and briefly exercised in `make ci`; the virtual multi-node network E2E is still planned |
| Stateful L2–L4 filtering, routing, connection tracking | **planned** | |
| TLS/QUIC termination proxy, L7 parsing, DPI, content scanning | **planned** | |
| Management API, XML config, candidate/commit-confirm transactions | **planned** | |
| Observability: console system-state, OTEL logs, Prometheus metrics | **planned** | conventions fixed in MONITORING.md; only ad-hoc serial markers exist today |
| High availability, session replication, multi-core / RSS flow shards | **planned** | |
| Release-config boot test, UEFI Secure Boot, TPM anti-rollback | **planned** | |
| Additional NIC drivers (ixgbe SFP+, Azure netvsc/MANA) | **planned** | |

**The current deployable system** is a two-dataplane-port zero-copy forwarding slice — the milestone
the build actually produces today, not a synthetic demo: one virtio-net driver protection domain per port brings up a modern
`virtio-net-pci` device on QEMU q35 from static seL4 capabilities alone, and an isolated forwarder
protection domain — the seat where the classifier and filter shards will later run — moves frames
between the two ports without copying. A frame cycles `NIC0 → driver0 → forwarder → driver1 → NIC1`
by transferring buffer *ownership* through lock-free single-producer/single-consumer queues; its
bytes are never copied and are owned by exactly one side at a time. The reusable logic lives in
host-tested `no_std` crates (`crates/`); the protection-domain binaries (`pds/`) are thin adapters.

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

On a GROPYUS development machine the build automatically detects the installed inspection CA and
provides it as a Podman build secret. On another inspected network, pass its path explicitly:

```sh
make image GROPYUS_CA_FILE=/path/to/gropyus-ca.pem
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
