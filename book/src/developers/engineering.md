# Engineering practice

This chapter is the engineering practice librefirewall holds itself to. It is written for everyone
who changes the code — human or agent — and it states decisions, not aspirations: when code and
this chapter disagree, that is a defect to fix, not a precedent to follow. The practice evolves
deliberately — a decision stands and is applied consistently until it is consciously changed, and
when it changes, everything that depended on it changes in the same breath.

## What is trusted, and what never is

The trusted computing base is exactly **seL4, Microkit, and `rust-sel4`** — the kernel, the static
component model, and the runtime. They are assumed correct and are not tested here. Nothing
first-party inherits that status: not a protection domain, not `xtask`, not a crate that "only ever
sees our own data". A first-party component claiming trust it was not granted is how it escapes the
scrutiny its position requires. Everything first-party is exhaustively tested instead.

The system targets **x86_64 exclusively**: no `cfg` branch, abstraction layer, or "portable for
later" indirection for another architecture.

## Name the adversary

The [threat model](../design/threat-model.md) assumes six adversaries: untrusted network traffic, a
hostile or malfunctioning NIC device, a compromised parser or inspection domain, a byzantine
neighbour protection domain, a management-plane attacker, and a connection-flood or
state-exhaustion attacker against the terminating proxy. The last is not a mode of the first: its
every frame is well-formed and its weapon is how much per-connection state each one commits, which
is why the isolation model carries a denial-of-service item at all.

A crate or module that handles external input states in its header, in plain words, which of them
it faces. That statement is what makes "reachable from external input" reviewable rather than a
judgement call: the code says whose input it is — and an adversary this list omits is one no header
can name.

## Handling untrusted input

**Reject untrusted input safely; fail visibly on an internal invariant violation.** Stated as a
principle alone, this gets agreed with and then not applied — each individual `unwrap` looks
locally justified — so the mechanical test is the rule:

- Any `panic!`, `assert!`, `unwrap`, `expect`, `debug_assert!`, slice index (`a[i]`), or arithmetic
  that can overflow, on a path reachable from bytes written by **a device, a peer protection
  domain, or the network**, is a defect. Untrusted input is rejected by returning a **typed error**
  — never by panicking, never by a bare index, never by a silent truncation, and not by an
  `Option`, a sentinel value, or a clamp that silently changes meaning.
- Internal invariants may still fail visibly: an `assert!` is permitted where the invariant is
  *provably unreachable* from external input, and the comment above it states the proof and names
  the component that establishes it. An assertion whose proof is "this cannot happen" is a finding,
  not a proof.
- A `debug_assert!` is **never** the only check on an externally driven value. The protection
  domains are built with the optimized Cargo profile in every kernel configuration, so a
  `debug_assert!` is absent from every image that boots — a bounds check written that way is, in
  the artifact that ships, no check at all. Where a value is externally driven, the check that
  rejects it is unconditional, and the `debug_assert!` — if kept — sits *after* the real check,
  never instead of it.
- **Bound all externally driven memory, state, and processing.** Every loop driven by external
  input has a bound derived from a value the adversary does not control.
- **Never paper over a real failure** with a silent fallback, a default value, or a swallowed
  error. Surface it: log with full technical detail and return an actionable, typed error. This is
  distinct from the safe *rejection* of hostile input — rejecting an attacker's malformed frame is
  correct operation and is counted, not escalated; swallowing an internal error is a defect either
  way.

A reproducible candidate finder (every hit on an external-input path is a finding):

```sh
rg -n 'unwrap\(\)|expect\(|panic!|unreachable!|assert!|debug_assert!|\[[a-z_][a-z0-9_]*\]' crates/ pds/
```

## Ownership, state, and the hot path

- **Make ownership transfer explicit in types and queue protocols.** A buffer has exactly one owner
  at every instant, and the type system says so rather than a comment.
- **Keep hot-path state per core; avoid shared locks on the hot path.**
- **Trust the framework and the pinned runtime**; do not reimplement what they already provide.

## `unsafe`

- `unsafe` is confined to the crates that genuinely need it — MMIO, DMA, shared-memory ABIs.
  `unsafe` appearing in a crate that has no hardware or ABI reason for it is a design finding, not
  a local one.
- **Every `unsafe` block carries a `SAFETY:` comment** stating the invariant that makes the block
  sound, and **the comment names the component that guarantees the invariant** — the type whose
  constructor establishes it, the function that validated the value, or the named element of the
  Microkit system description that maps the region. *Who* guarantees it is the checkable part: a
  claim naming its guarantor can be verified in one step; "the region is only shared with the
  driver" cannot be verified at all. A safety comment the surrounding API does not actually
  guarantee is a critical defect, not a documentation nit.
- **Every `unsafe fn` carries a `# Safety` section** — a caller obligation across an unsafe
  boundary has no other carrier.
- **The `unsafe` budget only shrinks.** Every `unsafe` block obliges a prose claim the compiler
  cannot check, so the per-crate block count is the leading indicator of unverified prose. The
  count is recorded (`tools/xtask/budgets.toml`) for every crate under `crates/` and `pds/`, and
  never rises without explicit human approval. The two `unsafe` lint denials reach further than the
  ratchet does: they bind every workspace member, while the recorded counts stop at those two
  trees. In `tools/` and the separate `fuzz/` workspace the rule holds by review, not by a gate.

**A delegated precondition names its enforcer.** A precondition delegated layer by layer can
complete a circle — the driver defers to the runtime, the runtime to the queue, the queue back to
its caller — and then no layer performs the check at all; where the value is an index into shared
memory, the end of that chain is a memory-safety violation. So when documentation delegates a
precondition to its caller, it names the component that enforces it, and that component has a test
proving the enforcement. "The caller must ensure `index < pool_len`" is incomplete; "validated by
`Pipeline::descriptor_in_bounds`, tested by the `rejects_out_of_range_descriptor` property" is a
contract. A precondition with no named enforcer is unenforced — treat it as absent. On review,
follow the chain: it must terminate at a component that validates, and a cycle is a critical
finding.

## Documentation

Documentation is a liability that earns its place only by carrying what the code cannot. Every
sentence is an untested assertion: nothing fails when it becomes false, and a wrong comment is
worse than no comment — it misleads every reader until someone audits it by hand. That gives an
order of obligation, each step mandatory before the next is permitted:

1. **Make it unrepresentable.** If the type system can carry the constraint, it carries it — a
   consumed `self`, a non-`Copy` token, a branded wrapper, a single private constructor, a typed
   error. A comment asserting a property of first-party Rust that the compiler could have enforced
   is a design defect, not a documentation one.
2. **Make it checked.** If a build-time or runtime check can carry it, it carries it.
3. **Only then write it down** — and only the part neither of the above can carry: hardware
   semantics, third-party runtime behaviour, or a cross-artifact fact.

The rules for the prose that remains:

- **A comment carries information the code cannot.** The test is deletion: remove it, and if
  nothing is lost, it was a defect. It never restates the code and never contradicts it.
- **A comment claims nothing about code outside the item it annotates.** "The only panic-capable
  construct in this crate", "nothing else reaches the event loop" — every such claim is falsified
  by an edit elsewhere and is owned by nobody.
- **Every crate carries a crate-level `//!` header** stating three things and nothing else: what
  the crate is for, which adversary it faces, and the non-obvious constraints or rejected
  alternatives that shaped it. It never states invariants — those are types.
- **Documentation is written only where the signature does not carry the contract.** A typed error
  enum is the error documentation; a consumed `self` is the lifecycle documentation. `missing_docs`
  is deliberately not enforced: forcing a comment onto every public item manufactures contentless
  prose.
- **The comment budget only shrinks.** Per production file under `crates/` and `pds/`, the
  comment-line ratio is recorded and never rises without explicit human approval and a recorded
  reason. Benchmarks, test binaries and the build tooling are outside the measurement; the rule
  holds there by review.
- **Code never references documentation.** No comment, string, or error message names a
  documentation file, a book page, or a section number — such references are brittle and rot
  silently. A comment stands alone in plain language; where it must name who guarantees something,
  it names a code artifact (a type, a function, a named system-description element), never a line
  number.

Where documentation lives, each place with exactly one mandate:

- **This book** — everything: the operator contract (reference), the design and its rationale
  (design), the development practice (this part), and the [development status](../status.md) with
  its [detail](status-detail.md). The book never carries the content of the project's internal
  working rules — it is written for its readers, who cannot be expected to hold a rulebook in their
  heads. Naming where a rule lives, as this list does, is not carrying it.
- **README.md** — a short introduction and pointers here. Nothing else.
- **AGENTS.md** — the working agreement for agents. Only agents read it, so nothing a human
  developer needs lives only there.
- **The source** — local intent, inline with the code, under the rules above.

Documentation is part of the change: if a change makes any page, header, or comment wrong, the same
change corrects it. Code is the source of truth — when docs and code disagree, fix the docs (or the
code, if the doc captured the real intent).

## Status truth

The [development status](../status.md) page and its [detail chapter](status-detail.md) are the
single source of truth for what works.

- A change that alters what works updates them **in the same change**.
- A capability reads **done** only when nothing remains missing in its detail section and no prose
  elsewhere contradicts it; otherwise it is **partial**, with the detail section saying exactly
  what remains. Done is a claim about the product, not about the effort spent.
- The design chapters record **intent only**. They are never edited to record progress, to soften a
  target the implementation has not reached, or to retrofit a decision already made in code.
- A deviation from the design is recorded where it lives — in the crate header at the deviation and
  in the status detail as partial with the deviation named — and is approved by a human. An
  undocumented deviation is a critical defect, because the design is what reviewers check changes
  against.

## Testing

We invest heavily in tests and hold coverage high, because this codebase will grow complex and we
value correctness over development speed. Every piece of first-party logic is tested exhaustively,
including edge cases; the trusted base is not tested. The pyramid, from broad base to narrow top:

- **Host unit and property tests** — the bulk of the suite. Core crates compile `no_std` and are
  tested on the host. Property tests assert the invariants: arbitrary input never panics; work and
  memory are bounded; parse/serialize round-trips; chunked and contiguous processing agree; a
  buffer has exactly one owner; invalid state transitions cannot occur. Every shared-memory ABI has
  static layout assertions.
- **Integration tests** — assemble larger parts of the system with fakes for the pieces not under
  test. Every neighbouring protection domain is treated as untrusted: malformed descriptors,
  backpressure, stale ownership, duplicate and forged returns, exhausted pools, peer restart, and
  resource limits.
- **Fuzzing** — see below.
- **Performance tests** — many mechanisms are performance-critical, so writing a benchmark is a
  normal part of a change, not a special event. Criterion microbenchmarks live beside the code they
  measure, and they are measurement only: `make bench` sits outside every gate and nothing gates a
  throughput regression today. QEMU performance is regression evidence and never proof of the
  physical 10 Gbit/s target — that requires dedicated hardware and an external traffic generator,
  and gates a release that claims the target.
- **End-to-end (QEMU) tests** — boot a fully assembled, signed release image and assert
  machine-observable contracts as a black box. A test asserts an observable contract or a
  structured channel — never timing-sensitive human log text.

**Coverage floors are enforced in the gate**: 94% combined across the library crates and 90% for
each library crate on its own. A change that drops below either floor does not land; raise a floor
as coverage rises, never lower one to land a change. A coverage exclusion must cite a reason from
this closed list, recorded beside the exclusion (`tools/xtask/src/host.rs`):

1. **Only observable under seL4** — a protection-domain adapter whose behaviour cannot be exercised
   on the host. The exclusion names the QEMU test that covers it instead.
2. **Build orchestration** — code that never runs on a deployed appliance (`xtask`).
3. **Test or benchmark harness** — code whose only purpose is to run tests or benchmarks.

The trusted-base argument is never available for first-party code. A reason outside this list
requires a human decision and is added to the list in the same change.

### Fuzzing

A fuzz target that cannot reach a bug is worse than none: it reads as coverage. Two things put a
target out of reach — a crate the fuzz workspace does not depend on, so no target exists for it at
all, and a harness guard that filters out the very input shape the bug requires. Neither is visible
in a passing run.

- **The fuzz workspace depends on every crate that parses or interprets untrusted input** — bytes
  from a device, a peer protection domain, or the network — with a target per parser. Adding such a
  crate without adding the dependency and a target is a defect; review `fuzz/Cargo.toml` against
  the workspace on every change that adds one.
- **A harness never constrains its input in a way that excludes the adversary's capability.** If a
  peer can send a duplicate index, the harness must be able to generate a duplicate index. Guards
  that "keep the harness sane" delete precisely the adversarial region. Model the *authority* the
  adversary has, not the behaviour a correct peer would exhibit.
- **Harnesses assert invariants, not merely the absence of a panic** — resource exhaustion,
  unbounded work, semantic inconsistency. A target whose body is a bare parse call proves only that
  the parser did not crash on that input.
- **Every fuzz finding becomes a regression test** in the owning crate's own suite, not only a
  corpus entry.

## Observability

Observability is a product feature of a firewall, and it is the *only* window into a running node:
there is no shell and no CLI. The exact contract — the console records, the log structure, the
metric names and labels, the recording downloads — is the book's reference part, which is the
operator's interface definition. Keep it true: **any change to an exposed signal updates the
matching reference chapter in the same change.** The console and metrics chapters are read as data
by the gate and held to the code, as are the counts the [status detail](status-detail.md) states
about the gate itself, so those cannot go stale unnoticed; everything else in the book is held true
by review.

The decisions that constrain all observability code:

- The **console** carries system state only — the startup sequence and its outcome, and runtime
  configuration changes — never traffic or per-request data.
- **Logs** are structured OpenTelemetry logs only; no syslog.
- **Metrics** are Prometheus format only, with bounded cardinality (no per-flow, per-connection or
  per-packet labels) and no measurable dataplane cost.
- **No distributed tracing** — deliberately out of scope.
- **No surface carries packet payloads, secrets, keys, or personal data** — with one named
  exception: the [two recording sinks](../design/recording.md), which exist to carry the traffic
  itself. The exception is scoped and bounded: it reaches exactly those two artifacts (the console,
  the metrics exposition, the log stream and the local log buffer carry no payload and no secret,
  absolutely); a recording is authorized, never merely scraped; an inspected flow is recorded as
  ciphertext plus its keys, never as decrypted plaintext at rest; and neither sink is a licence for
  a third — widening the exception is a design change, not a commit.
- Six surfaces are the **complete** debug surface: the console, the OpenTelemetry log stream,
  `GET /metrics`, `GET /logs`, `GET /config`, and the recording download — one surface carrying two
  files, `/logs.pcapng` and `/capture.pcapng`. Adding another introspection mechanism — a debug
  endpoint, a side channel, a diagnostic dump — changes the product's attack surface and is a
  design change, not a commit.

## Verifying on a running appliance

A booted node has no shell, no CLI and no debugger. It answers only through the six surfaces above,
and four of them are the instrument you reach for while developing — reason about a running system
through them rather than about it from the source:

| Surface | Answers | Reach it with |
|---|---|---|
| `GET /metrics` | **that** something is wrong, and where — which counter moved, in which domain | `curl` through the port forward |
| `GET /capture.pcapng` | **which packet** — the frames themselves, with the firewall's verdict on each | `curl`, then `tcpdump -r` or Wireshark |
| `GET /logs.pcapng` | **which conversations, and what happened to them** — an open with the rule that admitted it, an advance, a close with how it closed, a refusal with its reason, each on the packet that caused it | the same |
| the console | **what a domain said about itself** — bring-up, refusals, configuration commits | the serial capture a run leaves in `build/image/` |

A counter is a summary and a capture is evidence. When a dataplane question is open — is the frame
arriving, is it being parsed, is the verdict what the table says, is the rewrite right — download
the recording and look at the packets. Every QEMU scenario leaves its downloads at
`build/image/qemu-<scenario>-{logs,capture}.pcapng` and its serial output beside them, so after any
`make test-system` run the evidence is already on disk. Use the surfaces while developing, not only
at the end.

The three HTTP surfaces in that table are also cross-checkable, and that is where they earn the
most: the
recorder's own record counts, the packet blocks in each recording, and the frames the harness put
on the wire all describe one traffic stream from three independent vantage points, so a fault that
hides inside any one of them shows up as a disagreement between two. `xtask::surface_contract`
holds them to exactly that; when you add a surface, add its agreement with the others rather than a
second isolated smoke check.

Two working rules follow:

- **Verify a behavioural change against the running appliance's own surfaces, not against unit
  tests alone.** Unit and property tests prove the logic; the surfaces prove the system. "The gate
  is green" is necessary and is not this.
- **When the question is about packets, read the packets.** Do not settle a dataplane question from
  a counter when a capture can answer it. Where a capture cannot reach the question, say so
  explicitly rather than substituting the weaker evidence silently.

If you cannot show a behaviour on one of these surfaces, you have not observed it — you have
inferred it, and the difference belongs in what you tell the reader.

## Target state only, and no backwards compatibility

This project is in early development with no deployed consumers and no committed-to external
interfaces. Every change implements the target picture directly and refactors everything cleanly to
fit it. There is nothing to stay compatible with, so a compatibility path — a renamed thing kept
reachable under its old name, a deprecated alias, a legacy branch, a format shim, a "removed but
left in case" fallback — is not a courtesy but a defect: it is a clear sign the refactoring was
done incorrectly. Rename and update every caller in the same change. (The sole exception is a
genuinely persisted on-disk/on-wire format that real data already exists in — and today none does.)

After a change the code looks like the new design: old paths removed, callers updated, no dead code
kept "just in case", no `TODO`, stub, or placeholder left behind. If a feature ships, it ships
complete; if the work turns out larger than expected, surface that before finishing rather than
shipping a partial result framed as complete.

## Security-consequential changes

A change with security consequence is never self-approved: the capability topology in `systems/`, a
trust boundary, `unsafe`, the boot chain, key handling, or any code on an external-input path.
Reason about it fully and propose it; a human owns the final call. **Preserve least privilege in
the Microkit system description** — a capability change is a security change, and the generated
capability/memory report (`build/image/<config>/report.txt`) is the artifact to check the grant
against.

Never commit secrets or an inspection CA; treat any secret you encounter as compromised.

## Dependencies and toolchain

- **Pin every build-critical input**: the seL4/Microkit SDK, `rust-sel4`, the exact Rust nightly,
  Cargo dependencies through `Cargo.lock`, the builder's QEMU/LLVM/GRUB/tool versions, and the
  builder OCI image by digest. Build with `--locked`; a release build must be supportable offline
  from the pinned inputs. A cache may accelerate a build but is never required for correctness.
- **Never track a floating branch** — an upstream update is an explicit change that must pass the
  full gate.
- **First-party userspace is pure Rust.** Audit transitive dependencies for native code, unexpected
  linking, and build scripts; the dependency/license/source policy is enforced by `cargo-deny` in
  the gate, and the networked `advisories` check runs as its own CI stage. Both halves are
  configured in `deny.toml`; neither substitutes for the other.
- Microkit x86_64 differs from Arm and RISC-V: the kernel and system image are separate ELFs loaded
  by a Multiboot2 bootloader. Use the pinned SDK's x86_64 BSP examples as the executable reference;
  never copy an Arm loader recipe.
