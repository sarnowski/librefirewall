# Reviewing a change

This chapter is the bar a change is held to — first the author's own, then the reviewer's. The
[gate](building.md#landing-changes) verifies what a machine can check; everything here is the part
it cannot see. A green gate is necessary, never sufficient.

## Definition of done

A change is done when, from a clean checkout:

1. The full gate is green through the same root commands users and CI run — formatting, Clippy, the
   documented-`unsafe` lint, the comment and `unsafe` budget ratchets, the system-description,
   reference-chapter and configuration-document checks, dependency policy, unit and property tests
   at or above the coverage floors, the fuzz targets, image assembly, and the QEMU system and A/B
   scenarios.
2. Documentation and tests are updated **in the same change** — crate headers, rustdoc, `SAFETY`
   comments with their named guarantors, delegated preconditions with their named enforcers, and
   every book page the change touches the truth of.
3. The [development status](../status.md) and its [detail](status-detail.md) are updated where the
   change alters what works, and the matching [reference chapter](../reference/observability.md)
   where it alters an exposed signal.
4. A behavioural change has been **observed on a running node**, not only tested: the metric that
   should have moved has moved, the packets that should be in the recording are in it, and the
   console says what it should. Where the change is not observable on any surface, the author says
   so rather than leaving the reader to assume it was.
5. The author has run the reviewer checklist below against their own change, and no critical or
   major finding remains.

## Severity

Findings are triaged into three tiers, so a redundant comment and a peer-reachable panic are never
weighted the same. Context may raise a finding's tier — never lower it.

- **Critical** — the security posture of a deployed node is affected, or a well-behaved component
  can be crashed or corrupted by input the [threat model](../design/threat-model.md) says it must
  survive. Also any claim that is *false* rather than merely missing: an untrue `SAFETY` comment,
  an unenforced precondition, a done status that is not done. **Blocks the commit** — fix it or
  revert; never batch it. A pre-existing critical found during review is reported immediately and
  owned by a human.
- **Major** — no immediate security consequence, but enforceability or truth degrades: a missing
  test for new logic, a missing crate header, a coverage exclusion without a listed reason, a
  compatibility path left behind, a stale page. **Blocks the commit that introduces it.** A
  pre-existing major may be scheduled, but is recorded in the review verdict rather than passed
  over.
- **Minor** — clarity and craft: a comment restating the code, an imprecise name, a missing
  benchmark on a path that is not hot. May be batched into a follow-up commit.

## The reviewer checklist

Work the steps in order; each names the [engineering practice](engineering.md) it checks, so two
reviewers produce comparable output.

1. **Gate.** Confirm green. Record it, then continue: it is necessary, not sufficient.
2. **Threat surface.** Does the change touch bytes from a device, a peer protection domain, or the
   network? If yes, check every new path against
   [untrusted-input handling](engineering.md#handling-untrusted-input) — typed errors, no panicking
   construct, unconditional checks, bounded work — and its tests against the
   [testing](engineering.md#testing) and [fuzzing](engineering.md#fuzzing) practice: hostile-peer
   cases, a fuzz target for every new parser, harnesses that model the adversary's full authority.
   Run the candidate finder over the diff.
3. **`unsafe`.** For each block: the `SAFETY` comment is present, names its guarantor, and *the
   guarantor actually guarantees it* — open the named constructor, function, or system-description
   element. Check [placement](engineering.md#unsafe): the crate has a hardware or ABI reason.
4. **Preconditions.** For each documented precondition delegated to a caller: follow the delegation
   chain to a component that validates and has a test. A chain that cycles or ends nowhere is
   critical.
5. **Capabilities.** Did `systems/` change? That is a security change requiring human sign-off;
   diff the generated capability report, not only the description. The gate proves the description
   still matches the constants the domains compile against — it cannot judge whether a grant should
   exist at all, and that judgement is the whole of this step.
6. **Truth.** The [status pages](../status.md) where the change alters what works; the reference
   chapters where it alters an exposed signal; any page, header, or comment the change falsified;
   any deviation from the [design](../design/architecture.md) documented and human-approved. The
   gate reads the console and metrics chapters and will catch a token, family or count that moved
   without its table, and reads the status detail chapter for the counts it states about the gate
   itself; the prose around them, the label values, and which group a token was filed under are
   unread, so those stay here.
7. **Coverage and exclusions.** The floors hold, and any exclusion cites a reason from the
   [closed list](engineering.md#testing) — the trusted-base argument is never available.
8. **Residue.** No compatibility path, no dead code, no `TODO`/stub/placeholder, and no correctness
   logic drifted into a protection-domain binary that belongs in a host-testable crate.
9. **Signals.** The [observability constraints](engineering.md#observability) hold for anything
   logged, counted, or exposed: console carries system state only, bounded metric cardinality, no
   payload or secret on any surface but the two recording sinks, no new introspection mechanism.
10. **Observation.** Did the author [observe the change on a running node](engineering.md#verifying-on-a-running-appliance),
    or only test it? For a dataplane change, ask for the capture — `build/image/` holds the last
    run's recordings and serial output, so this costs a `tcpdump -r`, not a re-run.
11. **Verdict.** Report every finding as one line:

    ```
    <CRITICAL|MAJOR|MINOR> <file>:<line> — <what is wrong, in one clause> (<the practice it violates>)
    ```

    Example: `CRITICAL crates/virtio/src/queue.rs:212 — used-ring index from the device feeds a
    slice index with no bound check (untrusted-input handling)`. A review with no findings says so
    explicitly and lists the steps it ran; silence is not a pass.
