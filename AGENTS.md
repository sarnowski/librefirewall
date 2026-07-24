# librefirewall Engineering Guide

This file defines how to build, test, and evolve librefirewall. Read `CONCEPT.md` first: it is the
source of truth for the product target and security architecture. This guide translates that target
into repository and development practices.

## Current Milestone

The bootstrap vertical slice is complete: a clean checkout creates a pinned build environment,
compiles Rust protection domains, assembles an x86_64 seL4/Microkit system, packages it into the
signed A/B disk, boots it through OVMF and GRUB in QEMU, and tests its observable behaviour with
one command.

The deployable system is the two-port zero-copy forwarding dataplane (dev-order step 3): one
virtio-net driver PD instance per NIC, joined through a forwarder PD by one shared pipeline region
per direction, with the QEMU gate asserting byte-identical frame egress between the ports through
the booted disk. The forwarder is where the next slice inserts the processing stages:

```text
virtio driver -> Rx queue -> classifier -> filter shard -> Tx queue
```

Before that breadth, dev-order step 3 still owes its performance evidence: microbenchmarks, a
QEMU/KVM forwarding regression check behind `make bench`, and the written numeric performance
contract. Do not add protocol breadth before those and the build, boot, test, and release path are
reliable.

## Product Decomposition

Treat the repository as three related products:

1. Portable `no_std` Rust libraries containing firewall and dataplane logic.
2. seL4/Microkit protection-domain binaries and their static capability topology.
3. Platform-specific boot images and deployment metadata, initially for QEMU x86_64.

Protection-domain binaries should be thin adapters around reusable libraries. Most correctness
tests must run on the host without booting seL4. Isolation, capability, driver, shared-memory, and
whole-system behaviour must additionally be tested under seL4.

## Intended Repository Structure

Grow toward this structure as real functionality is added; do not create empty placeholders.

```text
Cargo.toml                  Rust workspace
Cargo.lock                  exact Rust dependency resolution
rust-toolchain.toml         exact Rust nightly and required components
Makefile                    stable developer and CI interface
crates/                     portable no_std libraries
  wire/                     packet and descriptor types
  queue/                    lock-free SPSC queue
  packet-buffer/            packet ownership and pools
  policy/                   policy model and evaluation
  conntrack/                connection tracking
  routing/                  routing, ARP, and ICMP logic
  stream-inspection/        streaming DPI
  config-model/             configuration model and validation
  pd-runtime/               common Microkit integration
pds/                        thin protection-domain binaries
systems/qemu-x86_64/        Microkit system description and QEMU machine definition
tools/xtask/                Rust build, test, and packaging orchestration
tools/qemu-harness/         QEMU lifecycle and system assertions
tests/                      fixtures and cross-component/system scenarios
fuzz/                       persistent parser and state-machine fuzz targets
benches/                    microbenchmarks and performance workloads
build/container/            pinned hermetic build environment
third-party/                pinned upstream source metadata
docs/                       architecture, threat model, and performance contract
```

## Build Interface

The root `Makefile` is the stable user and CI interface. Keep it small; implement non-trivial
orchestration in a Rust `xtask` rather than shell. The intended commands are:

```text
make image                  build the deployable QEMU image and release bundle
make run                    boot the image interactively in QEMU
make test                   run fast host tests
make test-system            boot QEMU and assert system behaviour
make bench                  run performance tests appropriate to the current target
make ci                     execute the complete pull-request gate
make release                run CI, then assemble the release configuration in dist/
make verify-reproducible    build twice in isolation and compare artifacts
make clean                  remove generated output only
```

`make image` must work from a clean checkout. It must:

1. Enter or create the pinned build environment.
2. acquire pinned upstream inputs and verify their checksums;
3. build every Rust library and PD with locked dependencies;
4. validate and assemble the Microkit system description;
5. produce the x86_64 Multiboot2 kernel and initialiser/system images;
6. package only deployable outputs and metadata in `dist/`; and
7. emit checksums, an SBOM, and provenance for a production release.

`make release` must run the complete debug/QEMU acceptance gate before replacing `dist/` with the
Microkit release configuration. Release assembly without the acceptance gate is not a release.

The build container is a tool, not the product artifact. The deployable output is the Microkit boot
payload and its versioned machine contract. Caches may accelerate a build but must never be required
for correctness.

Every image build emits `librefirewall-sbom.spdx.json` in SPDX 2.3 JSON, lists it in the
product-prefixed release manifest, and covers it with the product-prefixed release checksums.
Provenance may land after the bootstrap milestone, but `make image`,
`make test-system`, and `make ci` must remain honest and complete for everything they claim.

## Dependency and Toolchain Policy

Pin all build-critical inputs:

- seL4 and Microkit SDK version and checksum;
- `rust-sel4` release or commit;
- exact Rust nightly toolchain;
- Cargo dependencies through `Cargo.lock`;
- QEMU and LLVM/binutils versions in the builder; and
- the builder OCI image by digest once it is published.

Use Cargo with `--locked`; release builds should also be supportable offline from mirrored or
vendored dependencies. Never track a floating branch. Upstream updates are explicit changes that
must pass the full QEMU test before merge.

Microkit x86_64 differs from Arm and RISC-V: the kernel and initialiser/system ELF are separate and
must be loaded by a Multiboot2-compliant bootloader. Do not copy an Arm `loader.img` build or QEMU
recipe. Use the x86_64 BSP examples from the pinned SDK as the executable reference.

First-party userspace is pure Rust. Audit transitive dependencies for native code, unexpected
linking, and build scripts. Keep `unsafe` confined to small crates with documented safety invariants.

## Build Profiles

- `debug`: functional development with serial diagnostics and assertions.
- `release`: production-oriented kernel and optimized PDs; no dependence on debug output.
- `benchmark`: PMU-enabled kernel and performance instrumentation.
- `smp-*`: multicore variants used as soon as the first dataplane exists.

System tests initially use `debug` because they need an observable serial success contract. Release
artifacts must eventually have a non-console health/attestation mechanism and their own boot test.

## Test Strategy

### Host Unit and Property Tests

Run these on every change. Compile core libraries as `no_std`, with a host-only `std` test feature
where useful. Cover packet parsing, serialization, policy evaluation, connection tracking, routing,
proxy state machines, streaming inspection, and configuration validation.

Important properties include:

- arbitrary external input never panics;
- processing work and memory use are bounded;
- parse/serialize round trips preserve valid input;
- chunked and contiguous stream inspection produce the same verdict;
- a packet buffer has exactly one owner; and
- invalid state transitions cannot occur.

### Queue and Memory-Safety Tests

The SPSC queue and packet-buffer ownership model are foundational. Test randomized scheduling, ring
wrap-around, full/empty transitions, notification races, and peer restart. Use host concurrency
models, Miri, sanitizers, and bounded model checking where they apply. Add static layout assertions
for every shared-memory ABI.

### Fuzzing

Every externally controlled parser needs a persistent fuzz target. Seed fuzzers with valid protocol
samples and PCAP-derived corpora. Preserve every finding as a regression test. Fuzz for panics,
resource exhaustion, unbounded work, and semantic inconsistencies, not only memory corruption.

### Component Contract Tests

Exercise PD logic through simulated queue and message endpoints. Treat every neighbouring PD as
untrusted. Cover malformed descriptors, backpressure, stale ownership, notification coalescing,
exhausted pools, peer restart, and resource limits.

### QEMU System Tests

The QEMU harness owns process startup, timeout, output capture, assertions, and reliable shutdown.
Tests must use machine-readable unique markers or a structured test channel, not timing-sensitive
human log text.

As the system grows, QEMU scenarios cover boot, forwarding, drops, routing, bidirectional flow
affinity, proxying, DPI across packet boundaries, malformed traffic, configuration transactions,
PD faults and restart, queue saturation, resource exhaustion, and denied capability access.

The eventual QEMU machine has two virtio dataplane NICs, an isolated management NIC, multiple CPUs,
serial capture, and QMP control. Prefer socket-based network backends for unprivileged deterministic
tests; use KVM runners for realistic system regression tests.

### Performance Tests

Write a numeric performance contract before claiming the product target. It must define packet-size
distribution, directionality, loss, p50/p99/p99.99 latency, ruleset size, flow count, connection
rate, TLS handshake rate, proxy/cut-through mix, CPU allocation, and memory limits.

Use three layers:

1. Microbenchmarks for queues, parsers, policy lookup, conntrack, DPI, checksums, crypto, and TLS.
2. Controlled QEMU/KVM benchmarks for end-to-end regressions, batching, multicore scaling, and flow
   churn.
3. Dedicated physical x86_64 hardware and an external traffic generator for the actual 10 Gbit/s
   release gate.

QEMU performance is regression evidence, never proof of physical 10 Gbit/s throughput or tail
latency.

## Continuous Integration

Pull-request gates should contain formatting, Clippy with warnings denied, dependency/license/native
code policy, host tests, `no_std` builds, debug and release Microkit builds, QEMU smoke/system tests,
short fuzz runs, and stable microbenchmark checks.

Nightly jobs add the full QEMU suite, long fuzzing, Miri/sanitizers/model checking, multicore stress,
fault injection, resource exhaustion, QEMU/KVM performance runs, and reproducibility checks.

Release jobs build from a clean offline environment, run all functional and security tests, produce
and sign checksums/provenance/SBOM data, and execute the QEMU acceptance suite. Physical throughput
and latency acceptance becomes mandatory before a release can claim the 10 Gbit/s target.

## Development Order

1. Hermetic builder, pinned dependencies, x86_64 image assembly, and automated QEMU boot test.
2. Packet buffers, Rust SPSC queues, notification batching, and ownership tests.
3. Two-port virtio forwarding with measurable zero-copy behaviour.
4. Symmetric RSS, multicore ownership, and shared-nothing flow shards.
5. Stateful L2-L4 filtering and routing.
6. Early realistic DPI and crypto-provider benchmarks.
7. Incremental TCP, TLS, QUIC, and L7 proxy paths.
8. Final parser and sensitive-service PD decomposition.
9. Management, configuration transactions, observability, and fault recovery.
10. HA after single-node state machines are deterministic.

## Engineering Rules

- Preserve least privilege in the Microkit system description; capability changes are security
  changes and require review.
- Keep hot-path state per core and avoid shared locks.
- Make ownership transfer explicit in types and queue protocols.
- Bound all externally driven memory, state, and processing.
- Fail visibly on invalid internal assumptions; do not silently recover from corruption.
- Distinguish malformed/untrusted input, which is rejected safely, from internal invariant failure.
- Do not add compatibility paths without a real deployed consumer or persisted format requiring one.
- Add observability with bounded cardinality and no packet payloads, secrets, or personal data.
- Update tests and architecture documentation in the same change when behaviour or topology changes.
- Exercise changes through the same root commands users and CI run before declaring them complete.

## Source Control

Commit directly to `trunk`; this repository does not use feature branches or pull requests. Commit
subjects follow Conventional Commits (`type(scope): description`). Commit messages explain the
intent, constraints, concepts, and semantic consequences behind a change rather than narrating file
edits or other mechanical details already evident from the diff.

## Definition of Done for the Bootstrap Milestone

From a clean checkout on a supported Linux host, one documented command builds all inputs and emits
the QEMU x86_64 release bundle. Another root command boots the debug image, observes the complete
two-PD interaction, exits automatically, and fails clearly on timeout, crash, or missing output.
`make ci` runs host checks, image assembly, and that system test without manual preparation. CI uses
the same commands and build environment as developers.
