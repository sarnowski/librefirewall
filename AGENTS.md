# Working in librefirewall

This guide is how to work in this repository. It assumes you have read the documents it builds on
and treats them as authoritative:

- **[README.md](README.md)** — what the project is, the current feature status, and how to build and
  test it. README is the single source of truth for **status**.
- **[CONCEPT.md](CONCEPT.md)** — the target architecture, threat model, and critical design
  decisions. CONCEPT is the single source of truth for **intent**. It is stable: it changes only
  when a core aspect of the project changes, never to record progress.
- **[MONITORING.md](MONITORING.md)** — the operator contract for the console, OpenTelemetry logs,
  and Prometheus metrics. MONITORING is the single source of truth for **exposed signals**.

Everything below is a rule, not an aspiration. When code and these rules disagree, that is a defect
to fix, not a precedent to follow.

**This document has two halves that reference each other.** The sections below state each rule and
*why* it exists — the rationale is the load-bearing part, because a rule whose purpose is not
understood gets satisfied literally and violated in substance. The **[rule index](#appendix-the-rule-index)**
at the end restates every rule as one citable line with its enforcement and its mechanical test.
Work from the index on a change; read the prose when the index line is not self-evident.

Every rule has a stable ID (`ENG-5`, `DOC-6`, …) so a commit message, a review comment, and two
different reviewers can cite the same thing and produce comparable findings. IDs are stable: a rule
that is retired leaves its number retired with it.

## The gate is necessary, not sufficient

`make ci` verifies the rules a machine can check. It does not verify the rest, and there are more of
the rest. **A green gate does not mean this document's rules are met.**

Mechanically enforced today, and nothing else:

| Check | Command |
|---|---|
| Formatting | `cargo fmt --all --check` |
| Lints, warnings denied — every host crate, and the PDs for seL4 in **both** kernel configurations | `cargo clippy` over an explicit `-p` list, in `xtask test` |
| `SAFETY` comment *present* on every `unsafe` block | `undocumented_unsafe_blocks = "deny"` |
| Per-file comment ratio and per-crate `unsafe` count never rise | `xtask test` (DOC-11 / ENG-13 ratchets) |
| Coverage floors (94% combined, 90% per library crate) | `cargo llvm-cov` in `xtask test` |
| Dependency, license and source policy | `cargo deny check bans licenses sources` |
| Fuzz targets build and their seed corpora replay; each also runs bounded where the sandbox lets an instrumented binary start | `xtask fuzz` |
| Boot, forwarding and A/B contracts | `xtask test-system`, `xtask test-ab` |

Two things that table must not be read as saying. The lint command is **not** a bare
`cargo clippy -- -D warnings`: `default-members = ["tools/xtask"]` makes that select `xtask` alone
and report clean without looking at a single library crate, which is why `xtask` names its packages
explicitly and fails the build when the list is incomplete. And the local gate runs offline, so
`cargo deny check advisories` is not in it — vulnerability scanning is a separate networked CI stage
(`azure-pipelines.yml`), so a local green is a dependency-policy pass and not an advisory scan.

Every other rule in this document is **REVIEW**-enforced: if no one checks it, nothing fails. The
index marks each rule `GATE` or `REVIEW` so it is never ambiguous which of the two you are relying
on. Where a REVIEW rule has a grep or a script that finds candidate violations, the index gives it —
a command that surfaces candidates is not enforcement, but it makes a review reproducible.

## Severity and consequences

Findings are triaged into three tiers. Without them a reviewer cannot distinguish a redundant
comment from a peer-reachable panic, and both get filed as "defect" and weighted the same.

- **CRITICAL** — the security posture of a deployed node is affected, or a well-behaved component
  can be crashed or corrupted by input the threat model (CONCEPT §7.1) says it must survive. Also
  any claim that is *false* rather than merely missing: an untrue `SAFETY` comment, an unenforced
  precondition, a `done` status that is not done. **Blocks the commit.** Fix it or revert the change;
  never batch it, never land it with a follow-up noted. A pre-existing CRITICAL found during review
  is reported immediately and owned by a human (SCM-6).
- **MAJOR** — no immediate security consequence, but enforceability or truth degrades: a missing
  test for new logic, a missing crate header, a coverage exclusion without a listed reason, a
  compatibility path left behind, a stale document. **Blocks the commit that introduces it.** A
  pre-existing MAJOR may be scheduled, but is recorded in the review verdict rather than passed over.
- **MINOR** — clarity and craft: a comment restating the code, an imprecise name, a missing
  benchmark on a path that is not hot. **May be batched** into a follow-up commit.

The rule index assigns each rule its default tier. A finding may be raised a tier by context — never
lowered.

## Collaboration with the user

This section governs the interaction, not the artifact, so it carries no rule IDs except where a
rule is checkable on a change (SCM-6).

- Align before large or ambiguous work. Reflect the request back, name the tensions and the
  decisions worth making, and settle scope before mutating many files. Small, unambiguous changes
  need no ceremony.
- Be direct and brief. State results and decisions plainly; acknowledge mistakes and fix them.
  Do not pad answers with what the diff already shows. Size changes in lines added/changed/deleted,
  never in time.
- Surface a change that turns out larger than expected *before* finishing, rather than shipping a
  partial result framed as complete.
- Safety-relevant decisions (anything that could affect the security posture of a deployed
  firewall) are reviewed and owned by a human (SCM-6). Reason about them freely; do not make the
  final call alone.

## Source control

- **Work lands on `trunk`, and only on `trunk` (SCM-1).** There are no long-lived branches, no
  remote feature branches, and no pull requests.
- **Do the work in a `git worktree` on a throwaway local branch cut from `trunk` (SCM-2)**, so
  parallel sessions do not collide. The branch is a mechanical necessity, not a feature branch: git
  refuses to check `trunk` out in two worktrees, so a scratch branch is required. It is never
  pushed. Land by rebasing it onto current `trunk`, fast-forwarding `trunk` to it, and pushing
  `trunk`; then remove the worktree and delete the branch.
- **Every commit on `trunk` builds and passes the full gate (SCM-3)**, so `git bisect` is always
  meaningful. The hooks enforce this; it is not left to discipline.
- **Conventional Commits** for subjects (`type(scope): description`) (SCM-4). Commit *messages*
  explain the intent, constraints, and semantic consequences of a change — the *why* — not a
  narration of the file edits, which the diff already shows. Cite rule IDs when a commit fixes a
  rule violation.
- **Never commit secrets or the inspection CA (SCM-5).** Treat any secret you encounter as
  compromised.
- **A change with security consequence is not self-approved (SCM-6):** the capability topology in
  `systems/`, a trust boundary, `unsafe`, the boot chain, key handling, or any code on an
  external-input path. Reason about it fully and propose it; a human owns the final call.
- **Do not bypass the hooks (SCM-7).** `--no-verify` to land work is a violation; fix the finding.

## The commit gate (mandatory)

Install the hooks once per worktree:

```sh
make hooks
```

- **pre-commit** runs `make test` — the fast host gate: formatting, Clippy (warnings denied),
  `undocumented_unsafe_blocks`, the comment-ratio and `unsafe`-count ratchets, the
  dependency/license/source policy, and all unit and property tests with the coverage floors
  enforced. It does not boot QEMU, so it stays fast.
- **pre-push** runs `make ci` — the complete gate: the host gate plus the fuzz targets, image
  assembly, and the QEMU system and A/B scenarios.

The point is to catch a mechanically detectable violation at the earliest, cheapest moment and to
guarantee that what reaches `trunk` is green and bisectable. CI runs the identical commands, so a
local green is a CI green — and, per the section above, a green that proves considerably less than
it appears to.

## Documentation

Documentation is a liability that earns its place only by carrying what the code cannot. Every
sentence is an untested assertion: nothing fails when it becomes false. A wrong comment is worse
than no comment and worse than wrong code — wrong code is eventually tested, while a wrong comment
misleads every reader and every agent until someone audits it by hand.

That gives an order of obligation, not a menu. Each step is mandatory before the next is permitted:

1. **Make it unrepresentable.** If the type system can carry the constraint, it MUST carry it.
2. **Make it checked.** If a build-time or runtime check can carry it, it MUST carry it.
3. **Only then write it down** — and only the part neither of the above can carry.

**Project documentation lives in exactly four standalone Markdown documents, and no further
documentation files are to be created (DOC-1).** Each has exactly one mandate, and content
belonging to another document's mandate is a finding in the document that hosts it:

- **README.md** — **status**: what works, what does not, and how to build and test it. Never
  architecture, never mechanism.
- **CONCEPT.md** — **intent**: target architecture, threat model, critical decisions.
- **AGENTS.md** — **the rules**.
- **MONITORING.md** — **exposed signals**: the operator contract.

(`LICENSE.md` is the verbatim license text, not project documentation, and is exempt from this rule.)

Everything else lives **in the source**:

- **A constraint the type system can express MUST be expressed in the type system, and MUST NOT be
  written as a comment (DOC-9).** Before writing any `SAFETY:`, `# Safety`, or precondition comment,
  establish whether the invariant can be made unrepresentable — a consumed `self`, a non-`Copy`
  token, a branded wrapper, a single private constructor, a typed error. If it can, it is done that
  way and the comment is not written. A comment is permitted **only** for an invariant no
  first-party type can carry, and it states which kind it is: hardware semantics, third-party
  runtime behaviour, or a cross-artifact fact. A comment asserting a property of first-party Rust
  that the compiler could have enforced is a **design defect**, not a documentation one.
- **A comment MUST carry information the code cannot (DOC-2).** The test is deletion: remove it, and
  if nothing is lost, it was a defect. It never restates the code and never contradicts it.
- **A comment MUST NOT claim anything about code outside the item it annotates (DOC-10).** "The only
  panic-capable construct in this crate", "nothing else reaches the event loop", "this is the sole
  caller" — every such claim is falsified by an edit elsewhere, is owned by nobody, and is
  unmaintainable by construction.
- **Every crate carries a crate-level `//!` header (DOC-3)** stating three things and nothing else:
  what the crate is for, which CONCEPT §7.1 adversary it faces, and the non-obvious constraints or
  rejected alternatives that shaped it. **It MUST NOT state invariants** — those are types (DOC-9),
  and an invariant in a header is a DOC-9 finding against the type system.
- **Documentation is written only where the signature does not carry the contract (DOC-4).** A typed
  error enum is the error documentation; a consumed `self` is the lifecycle documentation; a named
  type is the unit documentation. `missing_docs` is deliberately **not** enforced: forcing a comment
  onto every public item manufactures contentless prose, and a rule that makes documentation *exist*
  without making it *true* buys nothing. One obligation is retained absolutely: **every `unsafe fn`
  carries a `# Safety` section**, because a caller obligation across an unsafe boundary has no other
  carrier.
- **The comment budget only shrinks (DOC-11).** Per production file, the comment-line ratio is
  recorded and MUST NOT rise. Raising one requires human approval (SCM-6) and a recorded reason.

### `SAFETY` comments must be verifiable, not merely present

`undocumented_unsafe_blocks = "deny"` catches an *absent* safety comment. It cannot catch a *false*
one — a comment is free to assert an invariant the system does not provide, and a reader cannot tell
the two apart unless the comment says *who* provides it.

- **Every `unsafe` block carries a `SAFETY:` comment (DOC-5)** stating the invariant that makes the
  block sound.
- **The comment names the component that guarantees the invariant (DOC-6)** — a `file:line` in the
  system description, the type whose constructor establishes it, or the function that validated the
  value. *Who* guarantees it is the checkable part. "Guaranteed by `librefirewall.system:48,62`,
  which maps this region into this PD alone" can be verified in one step; "the region is only shared
  with the driver" cannot be verified at all. A safety comment the surrounding API does not actually
  guarantee is a CRITICAL defect, not a documentation nit.

### A delegated precondition names its enforcer

A precondition delegated layer by layer can complete a circle — the driver defers to the runtime,
the runtime to the queue, the queue back to its caller — and then no layer performs the check at
all. Every document reads as though the validation happens elsewhere, and the gap is invisible in
any single file. Where the value is an index into shared memory, the end of that chain is a
memory-safety violation.

- **When documentation delegates a precondition to its caller, it names the component that enforces
  it, and that component has a test proving the enforcement (DOC-7).** "The caller must ensure
  `index < pool_len`" is incomplete; "validated by `Pipeline::descriptor_in_bounds`, tested in
  `pd-runtime/src/pipeline.rs` property `rejects_out_of_range_descriptor`" is a contract. A
  precondition with no named enforcer is unenforced — treat it as absent, not as satisfied
  elsewhere. Follow the chain on review: it must terminate at a component that validates. A cycle
  is a CRITICAL finding.

Documentation is part of the change: if a change makes a doc, header, or comment wrong, correct it
in the same change (DOC-8). Code is the source of truth — when docs and code disagree, fix the docs
(or the code, if the doc captured the real intent).

## Status truth

README declares itself the single source of truth for status, which only holds if changes maintain
it. A status table is the easiest thing in the repository to leave behind: it is read far more often
than it is edited, and a row that has quietly gone stale still reads as authoritative.

- **A change that alters what works updates README's status table in the same change (STA-1)** —
  the same in-change requirement that already applies to MONITORING.md for exposed signals (OBS-6).
- **A row reads `done` only when no `Missing` bullet remains in its detail section and no prose
  elsewhere in README contradicts it (STA-2).** Otherwise it is `partial`, with the detail section
  saying exactly what remains. `done` is a claim about the product, not about the effort spent.
- **CONCEPT records intent only (STA-3).** It is never edited to record progress, to soften a target
  the implementation has not reached, or to retrofit a decision already made in code.
- **A deviation from CONCEPT is recorded where it lives (STA-4/CON-1):** in the crate header at the
  deviation, in README's status as `partial` with the deviation named, and approved by a human
  (SCM-6). An undocumented deviation is CRITICAL — CONCEPT is what reviewers check against.

## CONCEPT adherence

CONCEPT is what a reviewer checks a change against, so three of its properties are rules rather than
background.

- **Name the adversary (CON-2).** CONCEPT §7.1 enumerates five: untrusted network traffic, a hostile
  or malfunctioning device, a compromised parser PD, a byzantine neighbour PD, and a management-plane
  attacker. A crate or module that handles external input states in its header which of them it
  faces. This is what makes ENG-5 reviewable: "reachable from external input" is a judgement call
  until the code says whose input it is.
- **The trusted base is exactly seL4, Microkit and `rust-sel4` (CON-3).** Nothing first-party
  inherits that status — not a PD, not `xtask`, not a crate that "only ever sees our own data". A
  first-party component claiming trust it was not granted is how it escapes the scrutiny its
  position requires.
- **x86_64 only (CON-4).** No `cfg` branch, abstraction layer, or "portable for later" indirection
  for another architecture; CONCEPT §3 is explicit that no accommodation is made.

## Testing

We invest heavily in tests and hold coverage high, because this codebase will grow complex and we
value correctness over development speed. The seL4 kernel, Microkit, and `rust-sel4` are the trusted
base (CONCEPT §7) and are assumed correct — we do **not** test them (TEST-1). That boundary is
exactly those three components (CON-3); no first-party code inherits it. Every piece of first-party
logic is tested exhaustively, including edge cases.

The testing pyramid, from broad base to narrow top:

- **Host unit and property tests** — the bulk of the suite. Core crates compile `no_std` and are
  tested on the host (a `std` test build where useful). Cover parsing, serialization, queue and
  ownership protocols, policy, connection tracking, routing, proxy and inspection state machines,
  and configuration validation. Property tests assert the invariants (TEST-4) — arbitrary input
  never panics; work and memory are bounded; parse/serialize round-trips; chunked and contiguous
  inspection agree; a buffer has exactly one owner; invalid state transitions cannot occur. Every
  shared-memory ABI has static layout assertions (TEST-5).
- **Integration tests** — assemble larger parts of the system with fakes/mocks for the pieces not
  under test, to exercise complex interactions quickly. Every neighbouring protection domain is
  treated as untrusted (TEST-6): malformed descriptors, backpressure, stale ownership, duplicate and
  forged returns, exhausted pools, peer restart, and resource limits.
- **Fuzzing** — see the dedicated rules below.
- **Performance tests** — many mechanisms are performance-critical, so writing a benchmark is a
  normal part of the change, not a special event (TEST-11). Criterion microbenchmarks live beside
  the code they measure, and they are measurement only: `bench` sits outside every gate and
  **nothing gates a throughput regression today** (README status). The end-to-end guard is meant to
  be a controlled QEMU/KVM forwarding regression, and it does not exist yet — do not cite it as a
  control. When it lands, QEMU performance is regression evidence and never proof of the physical
  10 Gbit/s target (TEST-12) — that requires dedicated hardware and an external traffic generator,
  and gates a release that claims the target.
- **End-to-end (QEMU) tests** — boot a fully assembled, signed image and assert machine-observable
  contracts as a black box: the A/B update mechanism, and network forwarding/routing across virtual
  networks. These grow toward a full virtual network of multiple endpoints and redundant HA nodes.
  Tests assert an observable contract or a structured test channel — never timing-sensitive human
  log text (TEST-13).

### Fuzzing rules

A fuzz target that cannot reach a bug is worse than none: it reads as coverage. Two things put a
target out of reach of what it was written for — a crate the workspace does not depend on, so no
target exists for it at all, and a harness guard that filters out the very input shape the bug
requires. Neither is visible in a passing run.

- **The fuzz workspace depends on every crate that parses or interprets untrusted input (TEST-7)** —
  bytes from a device, a peer protection domain, or the network. Adding such a crate without adding
  the dependency and a target is a MAJOR finding; the crate list in `fuzz/Cargo.toml` is reviewed
  against the crate list in the workspace on every change that adds one.
- **A harness may not constrain its input in a way that excludes the adversary's capability
  (TEST-8).** If a peer can send a duplicate index, the harness must be able to generate a duplicate
  index. Guards that "keep the harness sane" delete precisely the adversarial region. Model
  the *authority* the adversary has, not the behaviour a correct peer would exhibit.
- **Harnesses assert invariants, not merely the absence of a panic (TEST-9).** Fuzz for resource
  exhaustion, unbounded work, and semantic inconsistency: a target whose body is a bare parse call
  proves only that the parser did not crash on that input. Assert the same invariants the property
  tests assert (TEST-4).
- **Every fuzz finding becomes a regression test (TEST-10)** in the owning crate's own suite, not
  only a corpus entry.

### Coverage

Coverage floors are enforced in the gate (TEST-2): 94% combined across the library crates and 90%
for each library crate on its own. A change that drops below either floor does not land. Raise a
floor as coverage rises; never lower one to land a change.

**A coverage exclusion must cite a reason from this closed list (TEST-3):**

1. **Only observable under seL4** — a protection-domain adapter whose behaviour cannot be exercised
   on the host. The exclusion names the QEMU test that covers it instead.
2. **Build orchestration** — code that never runs on a deployed appliance (`xtask`). It is
   host-tested to keep the build honest, not held to a number defending the product.
3. **Test or benchmark harness** — code whose only purpose is to run tests or benchmarks.

The trusted-base argument is **never** available for first-party code: the trusted base is seL4,
Microkit and `rust-sel4`, and nothing else (CON-3). A reason outside this list requires a human
decision (SCM-6) and is added here in the same change; an exclusion citing no listed reason is a
MAJOR finding.

## Observability

Observability is a product feature of a firewall, not an afterthought, and it is the *only* window
into a running node: there is no shell and no CLI (CONCEPT §11). The exact contract — the console
system-state events, the OpenTelemetry log structure and required context fields, and the Prometheus
metric names and labels — is specified in **[MONITORING.md](MONITORING.md)**, which is the operator's
interface definition. Keep it true: any change to an exposed signal updates MONITORING.md in the same
change (OBS-6).

The decisions that constrain all observability code:

- **Console** carries system state only (OBS-1) — the startup sequence and its outcome, and runtime
  configuration changes — never traffic or per-request data. It is the last-resort channel when log
  streaming is down.
- **Logs** are **structured OpenTelemetry logs only** (OBS-2); no syslog. The same events written to
  the console are also emitted as OTEL logs; audit, traffic, and per-subsystem logs are OTEL-only.
- **Metrics** are exposed in **Prometheus format only** (OBS-3), with bounded cardinality (no
  per-flow, per-connection or per-packet labels) and no measurable dataplane cost.
- **No distributed tracing** (OBS-4) — deliberately out of scope.
- Observability surfaces never carry packet payloads, secrets, keys, or personal data (OBS-5), **with
  one named exception: the two recording sinks of CONCEPT §15**, which exist to carry the traffic
  itself — the capture sink its payloads, the log sink the L2–L4 headers of the packet each event is
  anchored to. CONCEPT §11 states the exception rather than tolerating it, and states its bounds with
  it, which is what keeps this a rule and not a hole. Those bounds are conditions on the code:
  - **It reaches exactly two artifacts.** The console, the Prometheus exposition, the OTEL log stream
    and the local log buffer carry no payload and no secret, absolutely and without exception. A
    payload that reaches one of those is a CRITICAL finding whatever the recording does.
  - **A recording is authorized, never merely scraped.** It is a download gated by the management
    plane's authentication and authorization, not an open endpoint beside `/metrics`.
  - **An inspected flow is recorded as ciphertext plus its keys** (CONCEPT §15.2), never as decrypted
    plaintext at rest. A sink writing plaintext of an inspected flow widens the exception and is a
    CRITICAL finding.
  - **Neither sink is a licence for a third.** Widening the exception to another surface, or adding a
    sink, is a CONCEPT change under OBS-7 and not a commit.
- `/metrics`, `/config`, `/logs`, the two recording downloads (`/logs.pcapng`, `/capture.pcapng`) and
  the console are the **complete** debug surface (OBS-7). Adding another introspection mechanism — a
  debug endpoint, a side channel, a diagnostic dump — changes the product's attack surface and
  requires a CONCEPT change, not a commit.

## Build interface

The root `Makefile` is the stable interface for developers and CI; keep it thin and implement
orchestration in the Rust `xtask`, not shell (BLD-1). The commands are listed in README.md's *Build
and test* section and are the frozen surface. `make image` must work from a clean checkout (BLD-2):
enter or build the pinned environment, acquire and checksum-verify pinned inputs, build every crate
and PD with locked dependencies, validate and assemble the Microkit system description, produce the
x86_64 Multiboot2 kernel and system image, package only deployable outputs into `dist/`, and emit
checksums and an SBOM.

**The shipped profile is the tested profile (BLD-3).** *Every* end-to-end scenario boots the release
configuration: `make ci` assembles it and holds that disk to the forwarding contract across the
system and A/B scenarios, and to the configuration transcript where a scenario states one. `make
release` adds the other half of the rule — if anything in that run failed, `dist/` is emptied rather
than left holding an unproven image that looks finished.

It was not always so, and the reason it is now is worth keeping. The gate used to boot the debug
configuration and only `make release` touched the release one, which nothing ran on push; two
consecutive changes then shipped defects reachable only in release — a console that emitted nothing,
and a boot chain that loaded userland over the kernel's own page tables. A gate that boots something
other than the artifact says nothing about the artifact.

The build container is a tool, not the product. The deployable output is the signed Microkit boot
payload and its versioned machine contract (BLD-6). A cache may accelerate a build but must never be
required for correctness (BLD-4).

## Build profiles

Two profiles exist today (BLD-5):

There is no debug *binary*: the protection domains compile under the `--release` Cargo profile in
both, so first-party code is one compilation. What differs is the seL4 kernel build, which is why
"debug" is better read as "release plus kernel diagnostics".

- `release` — the artifact. Every gate that boots anything boots this one (BLD-3), and it is what
  `make image` builds with no flag. A production health/attestation mechanism is still open
  (README status).
- `debug` — a diagnostic tool, not a test target. The kernel prints, so a fault reports itself
  instead of vanishing into an empty serial log. Reached three ways: `make run`, `make image-debug`,
  and automatically when an end-to-end scenario fails — the harness re-runs that one scenario on it
  and surfaces the result as evidence, never letting it change the verdict. A scenario that fails on
  release and passes on debug is a divergence worth naming, and it is the signature both defects
  above carried. The two-kernel-configuration Clippy pass is the only thing keeping this
  configuration buildable, so it is load-bearing rather than incidental.

Two more are **intended and do not exist**. Nothing in `Cargo.toml`, `xtask`, or `systems/` wires
them, and no rule here should be read as describing a present capability:

- `benchmark` — PMU-enabled kernel and performance instrumentation.
- `smp-*` — multicore variants, to arrive with the multicore dataplane.

When either lands it lands with its own boot test (BLD-3) and a README status row (STA-1).

## Repository layout

Directories have fixed purposes; grow them as real functionality lands, and do not create empty
placeholders (LAY-7).

- `crates/` — portable `no_std` libraries holding the firewall and dataplane logic (LAY-1). This is
  where most code and almost all tests live.
- `pds/` — protection-domain binaries: thin adapters that map shared regions and drive a library
  crate's logic (LAY-2). Correctness logic belongs in a crate, not here, so it can be host-tested.
  Logic that cannot be host-tested because it sits in a PD is a layering defect, not a coverage
  exclusion (TEST-3).
- `systems/` — the Microkit system description(s): the static capability topology (LAY-3). A
  capability change is a security change (ENG-1, SCM-6).
- `tools/` — the `xtask` build/test/packaging orchestrator and the QEMU harness (LAY-4).
- `fuzz/` — the persistent `cargo-fuzz` targets for the untrusted parsers, in their own workspace so
  the ASan/libFuzzer instrumentation never enters a PD build (LAY-5). Criterion microbenchmarks are
  *not* a top-level directory: each lives in its crate's own `benches/`, beside the code it measures
  (LAY-6).
- `build/`, `third-party/`, `support/` — the pinned hermetic builder, pinned upstream inputs, and
  target specifications.

## Dependency and toolchain policy

Pin every build-critical input (DEP-1): the seL4/Microkit SDK, `rust-sel4`, the exact Rust nightly,
Cargo dependencies through `Cargo.lock`, the builder's QEMU/LLVM/GRUB/tool versions, and the builder
OCI image by digest. Build with `--locked`; a release build must be supportable offline from the
pinned inputs (DEP-2). Never track a floating branch (DEP-3) — an upstream update is an explicit
change that must pass the full gate.

First-party userspace is pure Rust (DEP-4). Audit transitive dependencies for native code,
unexpected linking, and build scripts; the dependency/license/source policy is enforced by
`cargo-deny` in the gate (DEP-5). Its fourth check, `advisories`, cannot run there — it fetches the
RustSec database and the gate's container has no network — so it runs as its own networked CI stage
against the same pinned builder. Both halves are configured in `deny.toml`; neither substitutes for
the other.

Microkit x86_64 differs from Arm and RISC-V: the kernel and system image are separate ELFs loaded by
a Multiboot2 bootloader (DEP-6). Use the pinned SDK's x86_64 BSP examples as the executable
reference; do not copy an Arm loader recipe.

## Engineering rules

- **Preserve least privilege in the Microkit system description (ENG-1).** A capability change is a
  security change and requires human review (SCM-6). The generated capability/memory report is the
  artifact to check the grant against: every build writes it to `build/image/<config>/report.txt`.
  It is deliberately *not* published — `dist/` carries only deployable outputs and the evidence
  describing them (BLD-3, BLD-6), and the report is a full disclosure of the capability and memory
  topology. Read it from the build tree; do not expect it in a release.
- **Keep hot-path state per core (ENG-2); avoid shared locks.**
- **Make ownership transfer explicit in types and queue protocols (ENG-3).** A buffer has exactly
  one owner at every instant, and the type system should say so rather than a comment.
- **Bound all externally driven memory, state, and processing (ENG-4).** Every loop driven by
  external input has a bound derived from a value the adversary does not control.

### ENG-5 — reject untrusted input safely; fail visibly on an internal invariant violation

Stated as a principle alone, this rule is agreed with and then not applied: "reject safely" reads as
advice, and each individual `unwrap` looks locally justified. The principle remains the point; what
follows is the mechanical test that makes it reviewable.

**The test.** Any `panic!`, `assert!`, `unwrap`, `expect`, `debug_assert!`, slice index (`a[i]`), or
arithmetic that can overflow, on a path reachable from bytes written by **a device, a peer
protection domain, or the network**, is a violation. Untrusted input is rejected by returning a
typed error — never by panicking, and never by a bare index or a silent truncation.

**Internal invariants may still fail visibly.** An `assert!` is permitted where the invariant is
*provably unreachable* from external input, and the comment above it states the proof and names the
component that establishes it — the same "who guarantees this" requirement as DOC-6. An assertion
whose proof is "this cannot happen" is a finding, not a proof.

**New code handling untrusted input returns a typed error.** Not `Option`, not a sentinel value, not
a clamp that silently changes meaning: a named error the caller must handle.

Candidate finder (every hit on an external-input path is a finding):

```sh
rg -n 'unwrap\(\)|expect\(|panic!|unreachable!|assert!|debug_assert!|\[[a-z_][a-z0-9_]*\]' crates/ pds/
```

### ENG-10 — `debug_assert!` is never the only check on external input

A `debug_assert!` is compiled out of the release build, and the protection domains are built with
the optimized Cargo profile in every kernel configuration (`tools/xtask/src/image.rs:83-91`) — so a
`debug_assert!` is absent from every image that boots. A bounds check written that way is not a
weaker check; in the artifact that ships it is no check at all, and what follows it is unguarded.

**A `debug_assert!` may never be the sole validation of a value that originates outside the
component.** It documents an expectation and catches a first-party mistake in development; it is
not a control. Where a value is externally driven, the check that rejects it is unconditional, and
the `debug_assert!` — if kept at all — sits *after* the real check, not instead of it. Corollary:
**the shipped profile is the tested profile** (BLD-3), because a debug-only guarantee that is never
booted in release form is not a guarantee.

### The rest

- **No backwards compatibility (ENG-6).** This project is in early development with no deployed
  consumers and no committed-to external interfaces. Every change implements the target picture
  directly and refactors everything cleanly to fit it. There is nothing to stay compatible with, so
  a compatibility path — a renamed thing kept reachable under its old name, a deprecated alias, a
  legacy branch, a format shim, a "removed but left in case" fallback — is not a courtesy but a
  defect: it is a clear sign the refactoring was done incorrectly. Rename and update every caller in
  the same change; do not preserve the old surface. (The sole exception is a genuinely persisted
  on-disk/on-wire format that real data already exists in — and today none does.)
- **Target state only (ENG-7):** after a change the code looks like the new design — old paths
  removed, callers updated, no dead code kept "just in case", no `TODO`/stub/placeholder left behind.
- **Trust the framework and the pinned runtime (ENG-8);** do not reimplement what they already
  provide.
- **Exercise a change through the same root commands users and CI run before declaring it done
  (ENG-9).**
- **Keep `unsafe` confined to the crates that genuinely need it (ENG-11)** — MMIO, DMA,
  shared-memory ABIs. `unsafe` appearing in a crate that has no hardware or ABI reason for it is a
  design finding, not a local one.
- **The `unsafe` budget only shrinks (ENG-13).** Every `unsafe` block obliges a DOC-6 claim the
  compiler cannot check, so the per-crate block count is the leading indicator of prose that no
  mechanism verifies. The count is recorded and MUST NOT rise without human approval (SCM-6).
- **Never paper over a real failure (ENG-12)** with a silent fallback, a default value, or a
  swallowed error. Surface it: log with full technical detail, mark the relevant signal (a
  trace/span once tracing exists), and return an actionable, typed error. Keep this distinct from
  ENG-5's *safe rejection* of hostile input — rejecting an attacker's malformed frame is correct
  operation and is counted, not escalated; swallowing an internal error is a defect either way.

## Interrogating a running appliance

A booted node has no shell, no CLI and no debugger (CONCEPT §11). Everything you can learn about
one, it tells you through four surfaces, and they are not a reporting afterthought — they are the
**instrument**, and the only one. Reason about a running system through them rather than about it
from the source.

They answer different questions, and the order is almost always the same:

| Surface | Answers | Reach it with |
|---|---|---|
| `GET /metrics` | **that** something is wrong, and where — which counter moved, in which domain | `curl` through the port forward |
| `GET /capture.pcapng` | **which packet** — the frames themselves, with the firewall's verdict on each | `curl`, then `tcpdump -r` or Wireshark |
| `GET /logs.pcapng` | **which observations**, at header fidelity and far more of them per byte | the same |
| the console | **what a domain said about itself** — bring-up, refusals, configuration commits | the serial capture a run leaves in `build/image/` |

A counter is a summary and a capture is evidence. When a dataplane question is open — is the frame
arriving, is it being parsed, is the verdict what the table says, is the rewrite right — **download
the recording and look at the packets**. Deducing it from a counter is slower and is frequently
wrong, because a counter can only tell you that something in a category happened.

**Use them while developing, not only at the end.** A capture answers "did my change do what I think
it did" in one boot, against the shipped artifact, with the bytes in front of you. Every QEMU
scenario now leaves its downloads at `build/image/qemu-<scenario>-{logs,capture}.pcapng` and its
serial output beside them, so after any `make test-system` run the evidence is already on disk and
costs nothing to read.

The three HTTP surfaces are also **cross-checkable, and that is where they earn the most**. The
recorder's own record counts, the packet blocks in each recording, and the frames the harness put on
the wire all describe one traffic stream from three independent vantage points, so a fault that
hides inside any one of them shows up as a disagreement between two. `xtask::surface_contract` holds
them to exactly that on every management-reachable scenario; when you add a surface, add its
agreement with the others rather than a second isolated smoke check.

Two rules follow, and they are the point of this section:

- **ENG-14 — Verify a behavioural change against the running appliance's own surfaces, not against
  unit tests alone.** A change to the dataplane, the recording path, a protection domain's
  lifecycle, or any exposed signal is verified by observing a booted node: scrape the metrics,
  download the recording, read the console. Unit and property tests prove the logic; these prove the
  system. "The gate is green" is necessary and is not this.
- **ENG-15 — When the question is about packets, read the packets.** Do not settle a dataplane
  question from a counter when a capture can answer it, and do not report a dataplane behaviour as
  verified on the strength of a counter alone. Where a capture cannot reach the question, say so
  explicitly rather than substituting the weaker evidence silently.

The same instrument serves debugging and reporting. If you cannot show the behaviour on one of these
surfaces, you have not observed it — you have inferred it, and the difference belongs in what you
tell the reader.

## Definition of Done

The author's bar. A change is done when, from a clean checkout:

1. The full gate is green through the same commands users and CI run: formatting, Clippy,
   `undocumented_unsafe_blocks`, the DOC-11 and ENG-13 ratchets, dependency policy, unit and
   property tests at or above the coverage floors, the fuzz targets, image assembly, and the QEMU
   system and A/B scenarios (ENG-9).
2. Documentation and tests are updated **in the same change** — crate headers, rustdoc, `SAFETY`
   comments with their named guarantors (DOC-6), delegated preconditions with their named enforcers
   (DOC-7).
3. **README's status table is updated** where the change alters what works (STA-1), and
   **MONITORING.md** where it alters an exposed signal (OBS-6).
4. A behavioural change has been **observed on a running node**, not only tested: the metric that
   should have moved has moved, the packets that should be in the recording are in it, and the
   console says what it should (ENG-14, ENG-15). Where the change is not observable on any surface,
   the author says so rather than leaving the reader to assume it was.
5. The author has run the reviewer checklist below against their own change, and no CRITICAL or
   MAJOR finding remains.

A green gate satisfies step 1 only. Steps 2–5 are the part the gate cannot see.

## Reviewing a change

The reviewer's bar — human or agent. Work the steps in order; each is a rule ID, so two reviewers
produce comparable output.

1. **Gate.** Confirm green. Record it, then continue: it is necessary, not sufficient.
2. **Threat surface.** Does the change touch bytes from a device, a peer PD, or the network? If yes,
   check **ENG-4, ENG-5, ENG-10, ENG-12** on every new path, and **TEST-6, TEST-7, TEST-8, TEST-9**
   on its tests. Run the ENG-5 candidate finder over the diff.
3. **`unsafe`.** For each block: **DOC-5** (present), **DOC-6** (names its guarantor), and then
   *verify the guarantor actually guarantees it* — open the named `file:line` or constructor.
   Check **ENG-11** for placement.
4. **Preconditions.** For each documented precondition delegated to a caller: **DOC-7**. Follow the
   delegation chain to a component that validates and has a test. A chain that cycles or ends
   nowhere is CRITICAL.
5. **Capabilities.** Did `systems/` change? **ENG-1**, and human sign-off under **SCM-6**. Diff the
   generated capability report, not only the description.
6. **Truth.** **STA-1/STA-2** (README status), **OBS-6** (MONITORING.md), **DOC-8** (any doc the
   change falsified), **CON-1** (any deviation from CONCEPT is documented and approved).
7. **Coverage and exclusions.** **TEST-2** floors, and **TEST-3** — any exclusion cites a reason from
   the closed list, not the trusted-base argument.
8. **Residue.** **ENG-6** (no compatibility path), **ENG-7** (no dead code, stub, `TODO`), **LAY-2**
   (no correctness logic that drifted into a PD).
9. **Signals.** **OBS-1..OBS-5, OBS-7** if anything is logged, counted, or exposed.
10. **Observation.** **ENG-14/ENG-15** — did the author observe the change on a running node, or
    only test it? For a dataplane change, ask for the capture. `build/image/` holds the last run's
    recordings and serial output, so this costs a `tcpdump -r`, not a re-run.
11. **Verdict.** Report every finding as one line:

    ```
    <RULE-ID> <CRITICAL|MAJOR|MINOR> <file>:<line> — <what is wrong, in one clause>
    ```

    Example: `ENG-5 CRITICAL crates/virtio/src/queue.rs:212 — used-ring index from the device feeds
    a slice index with no bound check`. A review with no findings says so explicitly and lists the
    steps it ran; silence is not a pass.

## Appendix: the rule index

One line per rule. **GATE** = a command in `make ci` fails on violation. **REVIEW** = a human or
agent must check it; nothing fails if no one does. **Sev** is the default severity (§*Severity and
consequences*); context may raise it, never lower it. A `check` column entry beginning with `rg` or
a command finds *candidates*, not violations — it makes the review reproducible, it does not enforce.

### SCM — source control

| ID | Rule | Sev | Enforcement / check |
|---|---|---|---|
| SCM-1 | Work lands on `trunk` only; no remote feature branches, no pull requests | MAJ | REVIEW · `git branch -r` |
| SCM-2 | Work in a `git worktree` on a throwaway local branch off `trunk`; rebase, fast-forward `trunk`, delete branch and worktree | MIN | REVIEW |
| SCM-3 | Every commit on `trunk` passes the full gate; bisect stays meaningful | MAJ | GATE · pre-push `make ci` |
| SCM-4 | Conventional Commits subject; message states the *why*, cites rule IDs when fixing a violation | MIN | REVIEW |
| SCM-5 | No secrets and no inspection CA in the repository, ever | CRIT | REVIEW · `git log -p` on added files |
| SCM-6 | Security-consequential change (capabilities, trust boundary, `unsafe`, boot chain, keys, external-input path) is human-approved, never self-approved | CRIT | REVIEW |
| SCM-7 | Hooks are not bypassed (`--no-verify`) to land work | MAJ | REVIEW |

### DOC — documentation

| ID | Rule | Sev | Enforcement / check |
|---|---|---|---|
| DOC-1 | Exactly four standalone Markdown docs, each strictly to its own mandate (README=status, CONCEPT=intent, AGENTS=rules, MONITORING=signals); content in the wrong document is a finding | MAJ | REVIEW · `find . -name '*.md' -not -path './target/*'` |
| DOC-2 | A comment MUST carry what the code cannot; deletion test — if nothing is lost, it was a defect | MAJ | REVIEW |
| DOC-3 | A crate `//!` header states purpose, adversary, and constraint — and MUST NOT state invariants | MAJ | REVIEW · `head -40 crates/*/src/lib.rs` |
| DOC-4 | Documented only where the signature does not carry the contract; `missing_docs` is NOT enforced; `# Safety` on every `unsafe fn` is absolute | MAJ | REVIEW · `rg -n 'pub unsafe fn' crates/ pds/` |
| DOC-5 | Every `unsafe` block carries a `SAFETY:` comment | MAJ | GATE · `undocumented_unsafe_blocks = "deny"` |
| DOC-6 | The `SAFETY:` comment names the component guaranteeing the invariant (`file:line`, constructor, or validating fn) — and that component really does | CRIT | REVIEW · `rg -B3 'unsafe \{' crates/ pds/` |
| DOC-7 | A precondition delegated to a caller names its enforcing component, which has a test proving enforcement; no enforcer = unenforced; a delegation cycle is CRITICAL | CRIT | REVIEW · `rg -ni -e 'caller must' -e '# Safety' crates/ pds/` |
| DOC-8 | A change that falsifies a doc, header, or comment corrects it in the same change | MAJ | REVIEW |
| DOC-9 | A constraint the type system can express MUST be a type, never a comment; a comment asserting a compiler-enforceable property of first-party Rust is a design defect | MAJ | REVIEW · for each `SAFETY`/precondition comment, name the type change that makes it redundant |
| DOC-10 | A comment MUST NOT claim anything about code outside the item it annotates | MIN | REVIEW · `rg -n 'the only\|nothing else\|sole caller\|never reaches' crates/ pds/` |
| DOC-11 | Per-file comment-line ratio MUST NOT rise; raising one needs human approval and a recorded reason | MAJ | GATE · `xtask test` (comment-ratio ratchet) |

### STA — status truth

| ID | Rule | Sev | Enforcement / check |
|---|---|---|---|
| STA-1 | A change altering what works updates README's status table in the same change | MAJ | REVIEW · diff touches `README.md` status rows |
| STA-2 | A row is `done` only with no `Missing` bullet in its detail section and no contradicting README prose | CRIT | REVIEW · cross-read row against its detail section |
| STA-3 | CONCEPT records intent only; never edited to record progress or to soften an unmet target | CRIT | REVIEW · `git diff CONCEPT.md` |
| STA-4 | A deviation from CONCEPT is `partial` in README, named in the crate header at the deviation, and human-approved | CRIT | REVIEW |

### CON — CONCEPT adherence

| ID | Rule | Sev | Enforcement / check |
|---|---|---|---|
| CON-1 | Any deviation from CONCEPT is explicit, documented at the code, and approved (SCM-6) | CRIT | REVIEW |
| CON-2 | Every new input path names which CONCEPT §7.1 adversary it faces (network, device, parser, peer PD, management) | MAJ | REVIEW · crate/module header states it |
| CON-3 | The trusted base is exactly seL4 + Microkit + `rust-sel4`; no first-party code inherits it | CRIT | REVIEW · any "trusted" claim in first-party code |
| CON-4 | x86_64 only; no accommodation for another architecture | MIN | REVIEW · `rg -n -e aarch64 -e riscv -e target_arch crates/ pds/ support/` |

### TEST — testing

| ID | Rule | Sev | Enforcement / check |
|---|---|---|---|
| TEST-1 | First-party logic is exhaustively tested; the trusted base is not tested | MAJ | REVIEW |
| TEST-2 | Coverage floors hold: 94% combined, 90% per library crate | MAJ | GATE · `xtask test` (`cargo llvm-cov`) |
| TEST-3 | A coverage exclusion cites a reason from the closed list (seL4-only / build orchestration / test harness); the trusted-base argument is never available | MAJ | REVIEW · `LIBRARY_PACKAGES` in `tools/xtask/src/host.rs` |
| TEST-4 | Property tests assert the invariants: no panic on arbitrary input, bounded work and memory, round-trip, single ownership, illegal transitions unreachable | MAJ | REVIEW |
| TEST-5 | Every shared-memory ABI has static layout assertions | CRIT | REVIEW · `rg -n -e 'const _' -e 'size_of::<' crates/wire` |
| TEST-6 | Integration tests treat every neighbouring PD as hostile: malformed descriptors, backpressure, stale/duplicate/forged ownership, exhausted pools, peer restart | CRIT | REVIEW |
| TEST-7 | The fuzz workspace depends on **every** crate that parses untrusted input, with a target per parser | MAJ | REVIEW · diff `fuzz/Cargo.toml` deps against `crates/` |
| TEST-8 | A harness may not constrain input so as to exclude the adversary's capability | CRIT | REVIEW · read each harness for guards that filter hostile shapes |
| TEST-9 | Harnesses assert invariants (exhaustion, unbounded work, semantic inconsistency), not merely absence of panic | MAJ | REVIEW · a bare parse-call body is a finding |
| TEST-10 | Every fuzz finding becomes a regression test in the owning crate's suite | MAJ | REVIEW |
| TEST-11 | Performance-relevant change carries a Criterion benchmark beside the code | MIN | REVIEW · `crates/*/benches/` |
| TEST-12 | QEMU performance is regression evidence only; the 10 Gbit/s claim needs hardware and an external generator | MAJ | REVIEW · any perf claim in docs |
| TEST-13 | E2E asserts a machine-observable contract or structured channel — never log text or timing | MAJ | REVIEW · `rg -n -e contains -e expect_line tools/xtask` |

### ENG — engineering rules

| ID | Rule | Sev | Enforcement / check |
|---|---|---|---|
| ENG-1 | Least privilege in the Microkit system description; a capability change is a security change | CRIT | REVIEW · diff `systems/` + the generated capability report |
| ENG-2 | Hot-path state is per core; no shared locks on the hot path | MAJ | REVIEW |
| ENG-3 | Ownership transfer is explicit in types and queue protocols; exactly one owner at every instant | CRIT | REVIEW |
| ENG-4 | All externally driven memory, state and processing is bounded by a value the adversary does not control | CRIT | REVIEW · every loop and allocation on an input path |
| ENG-5 | No `panic!`/`assert!`/`unwrap`/`expect`/`debug_assert!`/slice index/overflowing arithmetic reachable from device, peer-PD or network bytes; untrusted input returns a typed error; a permitted `assert!` states its unreachability proof and its guarantor | CRIT | REVIEW · the ENG-5 candidate finder above |
| ENG-6 | No backwards compatibility: no alias, shim, legacy branch, or old surface kept reachable | MAJ | REVIEW · `rg -ni -e deprecated -e legacy -e compat crates/ pds/` |
| ENG-7 | Target state only: old paths removed, callers updated, no dead code, no `TODO`/stub/placeholder | MAJ | REVIEW · `rg -n -e TODO -e FIXME -e 'todo!' -e 'unimplemented!' crates/ pds/` |
| ENG-8 | Trust the framework and pinned runtime; do not reimplement what they provide | MAJ | REVIEW |
| ENG-9 | Exercise the change through the same root commands users and CI run before declaring it done | MAJ | REVIEW |
| ENG-10 | A `debug_assert!` is never the only check on an externally driven value; the real check is unconditional | CRIT | REVIEW · `rg -n 'debug_assert' crates/ pds/` |
| ENG-11 | `unsafe` is confined to crates that genuinely need it (MMIO, DMA, shared-memory ABI) | MAJ | REVIEW · `rg -l 'unsafe' crates/` |
| ENG-12 | Never paper over a failure with a silent fallback, default, or swallowed error; log with detail and return a typed error | CRIT | REVIEW · `rg -n -e unwrap_or -e 'let _ =' -e '.ok()' crates/ pds/` |
| ENG-13 | Per-crate `unsafe` block count MUST NOT rise without human approval; every `unsafe` block mandates a DOC-6 claim the compiler cannot check | MAJ | GATE · `xtask test` (unsafe-count ratchet) |
| ENG-14 | A behavioural change is verified by observing a booted node — metrics scraped, recording downloaded, console read — not by unit tests alone | MAJ | REVIEW · `build/image/qemu-*-{logs,capture}.pcapng`, `qemu-*.log` |
| ENG-15 | A dataplane question is answered from a capture, not from a counter; where a capture cannot reach it, say so | MAJ | REVIEW · `tcpdump -r build/image/qemu-*-capture.pcapng` |

### LAY — repository layout

| ID | Rule | Sev | Enforcement / check |
|---|---|---|---|
| LAY-1 | `crates/` holds the portable `no_std` logic; most code and almost all tests live there | MAJ | REVIEW |
| LAY-2 | `pds/` are thin adapters only; correctness logic belongs in a crate so it can be host-tested | MAJ | REVIEW · line count and branching in `pds/` |
| LAY-3 | `systems/` is the capability topology; changing it is a security change (ENG-1, SCM-6) | CRIT | REVIEW |
| LAY-4 | `tools/xtask` owns orchestration; the `Makefile` stays thin (no logic in shell) | MIN | REVIEW · `Makefile` diff |
| LAY-5 | `fuzz/` is its own workspace; libFuzzer/ASan instrumentation never enters a PD build | CRIT | REVIEW · `[workspace]` in `fuzz/Cargo.toml` |
| LAY-6 | Benchmarks live in each crate's `benches/`, never a top-level directory | MIN | REVIEW |
| LAY-7 | No empty placeholder directories; a directory appears when real functionality lands | MIN | REVIEW |

### DEP — dependency and toolchain

| ID | Rule | Sev | Enforcement / check |
|---|---|---|---|
| DEP-1 | Every build-critical input is pinned: SDK, `rust-sel4`, Rust nightly, `Cargo.lock`, builder tools, OCI image by digest | CRIT | REVIEW · `third-party/sources.lock`, `rust-toolchain.toml` |
| DEP-2 | Build with `--locked`; a release build is supportable offline from the pinned inputs | MAJ | GATE · offline container (`--network=none`, `CARGO_NET_OFFLINE`) |
| DEP-3 | Never track a floating branch; an upstream bump is an explicit change through the full gate | CRIT | REVIEW · `rg 'branch =' Cargo.toml third-party/` |
| DEP-4 | First-party userspace is pure Rust; transitive native code, unexpected linking and build scripts are audited | CRIT | GATE · `cargo deny check bans` (`[bans.build]`) |
| DEP-5 | Dependency, license and source policy passes | MAJ | GATE · `cargo deny check bans licenses sources` |
| DEP-6 | x86_64 Microkit: separate kernel and system ELF via Multiboot2; the SDK's x86_64 BSP is the reference, never an Arm recipe | MAJ | REVIEW |

### BLD — build interface

| ID | Rule | Sev | Enforcement / check |
|---|---|---|---|
| BLD-1 | The `Makefile` is the stable, thin interface; orchestration lives in `xtask` | MIN | REVIEW |
| BLD-2 | `make image` works from a clean checkout and performs the full documented sequence | MAJ | GATE · `xtask image` |
| BLD-3 | The shipped profile is the tested profile: **every** end-to-end scenario boots the release artifact, and `make release` empties `dist/` when the run did not prove it | CRIT | GATE · `xtask ci`, `xtask release` |
| BLD-4 | A cache may accelerate a build but is never required for correctness | MAJ | REVIEW |
| BLD-5 | Only `debug` and `release` exist; `benchmark` and `smp-*` are intended and unimplemented — do not document them as present | MAJ | REVIEW · `rg -n -e benchmark -e 'smp-' Cargo.toml tools/ systems/` |
| BLD-6 | The deployable output is the signed boot payload and its versioned machine contract; the builder is a tool, not the product | MAJ | REVIEW · `dist/` contents |

### OBS — observability

| ID | Rule | Sev | Enforcement / check |
|---|---|---|---|
| OBS-1 | Console carries system state only — never traffic or per-request data | MAJ | REVIEW |
| OBS-2 | Logs are structured OpenTelemetry only; no syslog | MAJ | REVIEW |
| OBS-3 | Metrics are Prometheus only, bounded cardinality (no per-flow/connection/packet labels), no measurable dataplane cost | CRIT | REVIEW · label sets in the exposition |
| OBS-4 | No distributed tracing | MIN | REVIEW |
| OBS-5 | No surface carries packet payloads, secrets, keys, or personal data — **except** CONCEPT §15's two recording sinks, which exist to carry traffic; they stay authorized-download-only and record an inspected flow as ciphertext plus keys, and every other surface stays absolute | CRIT | REVIEW · every added log field and label; every write reaching a sink |
| OBS-6 | A change to an exposed signal updates MONITORING.md in the same change | MAJ | REVIEW · diff touches `MONITORING.md` |
| OBS-7 | `/metrics`, `/config`, `/logs`, `/logs.pcapng`, `/capture.pcapng` and the console are the complete debug surface; a new introspection mechanism — or a third payload-bearing sink — needs a CONCEPT change | CRIT | REVIEW |
