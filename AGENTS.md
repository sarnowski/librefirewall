# Working in librefirewall

This file is the working agreement for agents, and only for agents — nothing a human developer
needs lives only here. All project knowledge is in the documentation book under `book/src/`, plain
Markdown you read directly. This file tells you what to read, how work flows, and how decisions
evolve.

## Read before changing anything

1. **[Engineering practice](book/src/developers/engineering.md)** — the decisions the project holds
   itself to: trusted base, adversaries, untrusted-input handling, `unsafe`, documentation, testing,
   observability, dependencies. Authoritative for every change.
2. **[Reviewing a change](book/src/developers/reviewing.md)** — the definition of done, the
   severity tiers, and the reviewer checklist you run against your own work before finishing.
3. **[Building and testing](book/src/developers/building.md)** — the command surface, the gate, the
   hooks, and how changes land.

Read the rest on demand:

| Question | Page |
|---|---|
| What works today, what is missing | [Development status](book/src/status.md), [in detail](book/src/developers/status-detail.md) |
| What a console record, metric, or recording means | the reference chapters: [surfaces](book/src/reference/observability.md), [console](book/src/reference/console.md), [metrics](book/src/reference/metrics.md), [recordings](book/src/reference/recordings.md) |
| Why the system is shaped the way it is | the design chapters: [architecture](book/src/design/architecture.md), [threat model](book/src/design/threat-model.md), [deployment](book/src/design/deployment.md), [management](book/src/design/management.md), [configuration](book/src/design/configuration.md), [recording](book/src/design/recording.md), [updates](book/src/design/updates.md) |

## Workflow

- Start from fresh `trunk`; do the work in a `git worktree` on a throwaway local branch, so
  parallel sessions do not collide. The branch is a mechanical necessity, never pushed: land by
  rebasing onto current `trunk`, fast-forwarding `trunk`, and pushing `trunk`; then remove the
  worktree and delete the branch.
- Install the hooks once per worktree (`make hooks`) and never bypass them — `--no-verify` to land
  work is a violation; fix the finding instead.
- Run the reviewer checklist against your own change before declaring it done. A green gate is
  necessary, never sufficient.
- A change with security consequence — the capability topology in `systems/`, a trust boundary,
  `unsafe`, the boot chain, key handling, any code on an external-input path — is never
  self-approved: reason about it fully, propose it, and a human owns the final call.
- Never commit secrets or an inspection CA; treat any secret you encounter as compromised.

## Decisions evolve; consistency is your job

Every rule in this project is a decision, not a law. Decisions are applied consistently until they
are deliberately changed — and the user owns them.

- When the user's direction conflicts with a standing decision, say so **once, in one sentence**,
  and ask whether the decision evolves. Do not re-litigate a settled answer, and do not keep
  flagging the same tension.
- When a decision changes, change everything that depended on it **in the same change** — book
  pages, code comments, tests, tooling, this file. A decision changed in one place and not the
  others is worse than either state.
- Every change ends with a consistency review: does any book page, the README, or any code comment
  now disagree with the implementation? Documentation is part of the change, never a follow-up.

Two boundaries hold whatever else changes, because they keep the documentation readable and honest:

- **The book and README never reference this file, internal rules, or each other's sections by
  number.** They are written for their readers in self-contained plain language.
- **Code never references documentation** — no file names, page names, or section numbers in
  comments, strings, or error messages. A comment stands alone; a guarantor is named as a code
  artifact.

## Collaboration

- Align before large or ambiguous work: reflect the request back, name the tensions and the
  decisions worth making, and settle scope before mutating many files. Small, unambiguous changes
  need no ceremony.
- Be direct and brief. State results and decisions plainly; acknowledge mistakes and fix them. Do
  not pad answers with what the diff already shows. Size changes in lines added/changed/deleted,
  never in time.
- Surface a change that turns out larger than expected *before* finishing, rather than shipping a
  partial result framed as complete.
