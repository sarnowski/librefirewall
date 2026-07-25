# Working in librefirewall

This guide is how to work in this repository. It assumes you have read the two documents it builds
on and treats them as authoritative:

- **[README.md](README.md)** — what the project is, the current feature status, and how to build and
  test it. README is the single source of truth for **status**.
- **[CONCEPT.md](CONCEPT.md)** — the target architecture, threat model, and critical design
  decisions. CONCEPT is the single source of truth for **intent**. It is stable: it changes only
  when a core aspect of the project changes, never to record progress.

Everything below is a rule, not an aspiration. When code and these rules disagree, that is a defect
to fix, not a precedent to follow.

## Collaboration with the user

- Align before large or ambiguous work. Reflect the request back, name the tensions and the
  decisions worth making, and settle scope before mutating many files. Small, unambiguous changes
  need no ceremony.
- Be direct and brief. State results and decisions plainly; acknowledge mistakes and fix them.
  Do not pad answers with what the diff already shows. Size changes in lines added/changed/deleted,
  never in time.
- Surface a change that turns out larger than expected *before* finishing, rather than shipping a
  partial result framed as complete.
- Safety-relevant decisions (anything that could affect the security posture of a deployed
  firewall) are reviewed and owned by a human. Reason about them freely; do not make the final
  call alone.

## Source control

- **Commit directly to `trunk`.** This repository uses no feature branches or pull requests. Do the
  work in a git worktree so parallel sessions do not collide, and remove the worktree once its
  commits have landed.
- **Every commit on `trunk` builds and passes the full gate**, so `git bisect` is always meaningful.
  This is enforced by the hooks below, not left to discipline.
- **Conventional Commits** for subjects (`type(scope): description`). Commit *messages* explain the
  intent, constraints, and semantic consequences of a change — the *why* — not a narration of the
  file edits, which the diff already shows.
- Never commit secrets or the inspection CA. Treat any secret you encounter as compromised.

## The commit gate (mandatory)

Install the hooks once per worktree:

```sh
make hooks
```

- **pre-commit** runs `make test` — the fast host gate: formatting, Clippy (warnings denied),
  `missing_docs`, the dependency/license policy, and all unit and property tests with the coverage
  threshold enforced. It does not boot QEMU, so it stays fast.
- **pre-push** runs `make ci` — the complete gate: the host gate plus image assembly and the QEMU
  system and A/B scenarios.

The point is to catch a violation at the earliest, cheapest moment and to guarantee that what
reaches `trunk` is green and bisectable. Do not bypass the hooks (`--no-verify`) to land work; fix
the violation instead. CI runs the identical commands, so a local green is a CI green.

## Documentation

Documentation earns its place by carrying what the code cannot: the goal a piece of code serves,
the constraint that shaped it, the non-obvious reason behind a choice. A comment that restates the
code is worse than none — it drifts and misleads. When in doubt, leave it out and sharpen the name.

**Project documentation lives in exactly four standalone Markdown documents, and no further
documentation files are to be created:**

- **README.md** — overview, status, build/test instructions, license.
- **CONCEPT.md** — target architecture, threat model, critical decisions.
- **AGENTS.md** — this guide.
- **MONITORING.md** — the operator contract for logs and metrics (see *Observability*).

(`LICENSE.md` is the verbatim license text, not project documentation, and is exempt from this rule.)

Everything else lives **in the source**:

- **Self-documenting code first.** Precise names for types, functions, parameters, and variables
  remove the need for most comments. Reach for a better name before a comment.
- **Comments state *why*, not *what*.** Invariants, constraints, non-obvious consequences, and the
  reason a thing is done a particular way. Never annotate what the next line plainly does, and never
  let a comment contradict the code.
- **Every crate carries a crate-level `//!` header** that explains its concepts, architecture,
  design, and invariants, so a reader understands the crate fully from its source alone. A module
  with non-obvious design carries a module `//!` header too. Architectural documentation that would
  otherwise become a standalone Markdown file (how a driver works, what a protocol's core concepts
  are, why an ABI is laid out a certain way) belongs in these headers, living with the code it
  describes.
- **Public items carry rustdoc** documenting what a caller may rely on: inputs, outputs, errors,
  side effects, and — for `unsafe` — the safety contract the caller must uphold. `missing_docs` is
  denied, so this is enforced. Do not restate type signatures or framework defaults.
- **`unsafe` blocks carry a truthful `SAFETY:` comment** stating the invariant that makes the block
  sound. A safety comment that the surrounding API does not actually guarantee is a defect.

Documentation is part of the change: if a change makes a doc, header, or comment wrong, correct it
in the same change. Code is the source of truth — when docs and code disagree, fix the docs (or the
code, if the doc captured the real intent).

## Testing

We invest heavily in tests and hold coverage high, because this codebase will grow complex and we
value correctness over development speed. The seL4 kernel, Microkit, and `rust-sel4` are the trusted
base (CONCEPT §7) and are assumed correct — we do **not** test them. Every piece of first-party
logic is tested exhaustively, including edge cases.

The testing pyramid, from broad base to narrow top:

- **Host unit and property tests** — the bulk of the suite. Core crates compile `no_std` and are
  tested on the host (a `std` test build where useful). Cover parsing, serialization, queue and
  ownership protocols, policy, connection tracking, routing, proxy and inspection state machines,
  and configuration validation. Property tests assert the invariants — arbitrary input never
  panics; work and memory are bounded; parse/serialize round-trips; chunked and contiguous
  inspection agree; a buffer has exactly one owner; invalid state transitions cannot occur. Every
  shared-memory ABI has static layout assertions.
- **Integration tests** — assemble larger parts of the system with fakes/mocks for the pieces not
  under test, to exercise complex interactions quickly. Every neighbouring protection domain is
  treated as untrusted: malformed descriptors, backpressure, stale ownership, exhausted pools, peer
  restart, and resource limits.
- **Fuzzing** — every externally driven parser (traffic *and* an untrusted device or peer) has a
  persistent fuzz target, seeded from valid samples and corpora. Fuzz for panics, resource
  exhaustion, unbounded work, and semantic inconsistency — not only memory corruption. Every
  finding becomes a regression test.
- **Performance tests** — many mechanisms are performance-critical, so writing a benchmark is a
  normal part of the change, not a special event. Criterion microbenchmarks live beside the code
  they measure; a controlled QEMU/KVM forwarding regression guards the end-to-end path. QEMU
  performance is regression evidence, never proof of the physical 10 Gbit/s target — that requires
  dedicated hardware and an external traffic generator, and gates a release that claims the target.
- **End-to-end (QEMU) tests** — boot a fully assembled, signed image and assert machine-observable
  contracts as a black box: the A/B update mechanism, and network forwarding/routing across virtual
  networks. These grow toward a full virtual network of multiple endpoints and redundant HA nodes.
  Tests assert an observable contract or a structured test channel — never timing-sensitive human
  log text.

Coverage and lint gates fail the build, locally (via the hooks) and in CI. A change that lowers
coverage below the threshold does not land. If a genuine reason excludes code from coverage (e.g. a
protection-domain adapter whose behaviour is only observable under seL4), state it explicitly rather
than weakening the gate.

## Observability

Observability is a product feature of a firewall, not an afterthought, and it is the *only* window
into a running node: there is no shell and no CLI (CONCEPT §11). The exact contract — the console
system-state events, the OpenTelemetry log structure and required context fields, and the Prometheus
metric names and labels — is specified in **[MONITORING.md](MONITORING.md)**, which is the operator's
interface definition. Keep it true: any change to an exposed signal updates MONITORING.md in the same
change.

The decisions that constrain all observability code:

- **Console** carries system state only — the startup sequence and its outcome, and runtime
  configuration changes — never traffic or per-request data. It is the last-resort channel when log
  streaming is down.
- **Logs** are **structured OpenTelemetry logs only** (no syslog). The same events written to the
  console are also emitted as OTEL logs; audit, traffic, and per-subsystem logs are OTEL-only.
- **Metrics** are exposed in **Prometheus format only**, with bounded cardinality (no per-flow
  labels) and no measurable dataplane cost. `/metrics` plus the configuration read endpoint are the
  complete debug surface.
- **No distributed tracing** — deliberately out of scope.
- Observability surfaces never carry packet payloads, secrets, or personal data.

## Build interface

The root `Makefile` is the stable interface for developers and CI; keep it thin and implement
orchestration in the Rust `xtask`, not shell. The commands are listed in README.md's *Build and
test* section and are the frozen surface. `make image` must work from a clean checkout: enter or
build the pinned environment, acquire and checksum-verify pinned inputs, build every crate and PD
with locked dependencies, validate and assemble the Microkit system description, produce the
x86_64 Multiboot2 kernel and system image, package only deployable outputs into `dist/`, and emit
checksums and an SBOM. `make release` runs the full acceptance gate before assembling the release
configuration.

The build container is a tool, not the product. The deployable output is the signed Microkit boot
payload and its versioned machine contract. A cache may accelerate a build but must never be
required for correctness.

## Repository layout

Directories have fixed purposes; grow them as real functionality lands, and do not create empty
placeholders.

- `crates/` — portable `no_std` libraries holding the firewall and dataplane logic. This is where
  most code and almost all tests live.
- `pds/` — protection-domain binaries: thin adapters that map shared regions and drive a library
  crate's logic. Correctness logic belongs in a crate, not here, so it can be host-tested.
- `systems/` — the Microkit system description(s): the static capability topology. A capability
  change is a security change (see *Engineering rules*).
- `tools/` — the `xtask` build/test/packaging orchestrator and the QEMU harness.
- `fuzz/` — the persistent `cargo-fuzz` targets for the untrusted parsers, in their own workspace so
  the ASan/libFuzzer instrumentation never enters a PD build. Criterion microbenchmarks are *not* a
  top-level directory: each lives in its crate's own `benches/`, beside the code it measures.
- `build/`, `third-party/`, `support/` — the pinned hermetic builder, pinned upstream inputs, and
  target specifications.

## Dependency and toolchain policy

Pin every build-critical input: the seL4/Microkit SDK, `rust-sel4`, the exact Rust nightly, Cargo
dependencies through `Cargo.lock`, the builder's QEMU/LLVM/GRUB/tool versions, and the builder OCI
image by digest. Build with `--locked`; a release build must be supportable offline from the pinned
inputs. Never track a floating branch — an upstream update is an explicit change that must pass the
full gate.

First-party userspace is pure Rust. Audit transitive dependencies for native code, unexpected
linking, and build scripts; the dependency/license policy is enforced by `cargo-deny` in the gate.
Keep `unsafe` confined to the crates that genuinely need it (MMIO, DMA, shared-memory ABIs), each
occurrence carrying a documented, truthful safety invariant.

Microkit x86_64 differs from Arm and RISC-V: the kernel and system image are separate ELFs loaded by
a Multiboot2 bootloader. Use the pinned SDK's x86_64 BSP examples as the executable reference; do
not copy an Arm loader recipe.

## Build profiles

- `debug` — functional development with serial diagnostics and assertions. System tests use it so
  diagnostics survive a failure; success is still the machine-observable contract, not console text.
- `release` — production-oriented kernel and optimized PDs, with no dependence on debug output.
  The release configuration needs its own boot test and a production health/attestation mechanism.
- `benchmark` — PMU-enabled kernel and performance instrumentation.
- `smp-*` — multicore variants, used as the multicore dataplane develops.

## Engineering rules

- Preserve least privilege in the Microkit system description; a capability change is a security
  change and requires review.
- Keep hot-path state per core; avoid shared locks.
- Make ownership transfer explicit in types and queue protocols.
- Bound all externally driven memory, state, and processing.
- Reject malformed or untrusted input safely; fail visibly on an internal invariant violation. Keep
  those two responses distinct — never paper over a real failure with a silent fallback, default,
  or swallowed error. Surface an error by logging it with full technical detail, marking the active
  trace/span (once tracing exists) or the relevant signal, and returning an actionable, typed error.
- **No backwards compatibility.** This project is in early development with no deployed consumers and
  no committed-to external interfaces. Every change implements the target picture directly and
  refactors everything cleanly to fit it. There is nothing to stay compatible with, so a
  compatibility path — a renamed thing kept reachable under its old name, a deprecated alias, a
  legacy branch, a format shim, a "removed but left in case" fallback — is not a courtesy but a
  defect: it is a clear sign the refactoring was done incorrectly. Rename and update every caller in
  the same change; do not preserve the old surface. (The sole exception is a genuinely persisted
  on-disk/on-wire format that real data already exists in — and today none does.)
- Target state only: after a change the code looks like the new design — old paths removed, callers
  updated, no dead code kept "just in case", no `TODO`/stub/placeholder left behind.
- Trust the framework and the pinned runtime; do not reimplement what they already provide.
- Exercise a change through the same root commands users and CI run before declaring it done.

## Definition of Done

A change is done when, from a clean checkout, the full gate is green through the same commands users
and CI run: formatting, Clippy, `missing_docs`, dependency policy, unit and property tests at or
above the coverage threshold, image assembly, and the QEMU system and A/B scenarios — with the
documentation, tests, and (where behaviour or an exposed signal changed) MONITORING.md updated in
the same change.
