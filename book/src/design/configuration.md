# Configuration

- **Configuration is a fully schema-validated XML file** (the schema is defined by the project).
- **Full validation before any apply.** Configuration is validated both **structurally** (against
  the schema) and **semantically** (e.g. references resolve to existing zones/interfaces, no
  conflicting rules, routes are resolvable). A configuration is only applied if it fully validates.
- **The configuration mechanism is hardened against exploitation, independent of configuration
  content.** The system does not judge whether a valid configuration is sensible, but it defends
  the mechanism against any attempt to exploit it: XML entity attacks (XXE, external entities,
  entity-expansion / "billion laughs") are precluded (DTDs and external entities disabled; input
  size, depth, and complexity bounded); the exact bytes that were validated are the bytes that get
  applied; the validator's own resource use is bounded; and configuration values are sanitized
  before being written to logs or the console. Parsing and validation run in the isolated validator
  PD (see [Threat model and isolation](threat-model.md)).

## Candidate/commit-confirm model

Configuration uses a **candidate/running datastore** model with **commit-confirmed**:

- The **running** configuration is what the appliance enforces; the **candidate** is an editable
  copy. Changes are assembled on the candidate without affecting the running configuration.
- A candidate is **validated** (structurally and semantically) as an operation that changes nothing.
- **Commit** atomically swaps candidate → running (all-or-nothing).
- **Commit-confirmed:** a commit arms a rollback timer; if it is not confirmed within the timeout,
  the appliance automatically rolls back to the previous running configuration. This protects
  against a change that validates but breaks management connectivity at runtime (anti-lockout).
- Configurations are **versioned**, enabling **rollback**.

## Distributed staged rollout

Across the HA pair (and later across multiple clusters via central configuration management),
rollout is a **two-phase "stage & validate" → "commit"** process:

- **Phase 1 — stage & validate:** the candidate is pushed to every participating node; each node
  independently parses, structurally and semantically validates, checks local applicability,
  persists the candidate, and votes whether it can commit.
- **Phase 2 — commit:** the change is committed **only if all participants agree**; otherwise it is
  aborted and nothing changes ("all agree or nobody rolls out").
- **Per-node commit-confirmed** (see the
  [candidate/commit-confirm model](#candidatecommit-confirm-model)) applies on top, for
  runtime-connectivity safety.
- Apply ordering is **staggered/canary** (standby first, verified healthy, then active), so a
  configuration that validates but fails at runtime does not take down both nodes at once.
- Commits are **idempotent, keyed by a monotonic configuration generation-id/hash**, and the
  staged (prepared) state has a timeout, so a coordinator failure cannot leave nodes stuck.
- Standalone changes (a direct configuration change against a single node) retain per-node
  commit-confirmed protection.
- **Availability of configuration changes.** Unanimous agreement is required only while all
  participants are reachable. If a participant is unavailable, a healthy node must still accept
  configuration changes (a single-node commit), marking its configuration generation as divergent
  and reconciling with the peer when it rejoins — so a configuration change is never blocked by an
  unreachable node.

**Central configuration management** for multiple clusters is developed later.

## Static hardware, dynamic configuration

The line between what needs a new image and what is applied at runtime is drawn at **hardware**:

- **Hardware topology is static.** The set of physical devices the system drives — the NICs and the
  [block devices](recording.md#storage-devices-and-binding), their PCI addressing, and the
  protection domains, memory regions, and capabilities that follow from them — is fixed in the
  Microkit system description at build time (see
  [Architecture](architecture.md#foundation)). Changing it (adding a NIC, moving to a different NIC
  count, giving a node a device to record onto) is a **different image**, delivered through the
  [A/B update mechanism](updates.md). Hardware reconfiguration of a running system is not
  supported; each [hardware configuration](deployment.md#nic-configurations) is a build-time image
  variant.
- **Everything above the hardware is dynamic.** Interface configuration and upwards is applied
  through the commit workflow without a restart: whether a present interface is used at all, its
  role, [mode](architecture.md#operating-posture) and addressing, zones, filtering rules, routes,
  NAT bindings, inspection policy, which [recording sinks](recording.md) are enabled and what they
  filter, and every other policy object. A port a deployment does not need is administratively
  disabled by configuration, not omitted from a build.

Two consequences follow, and both simplify the design:

- **A configuration change never requires a reboot to be committed.** Exactly one item defers its
  *effect*: storage binding — which extent a recording ring occupies (see
  [Storage devices and binding](recording.md#storage-devices-and-binding)) — is committed like any
  other item but takes hold at the next boot, because moving a ring invalidates what the old
  extent holds. The commit itself remains an operation on the running system, so commit-confirmed
  still operates within one running system and its rollback timer still never has to survive a
  restart.
- **A hardware change is an image change**, so it is governed by the
  [A/B slot mechanism's](updates.md#boot-manager-and-slot-selection) own try/confirm/fallback
  semantics rather than by the configuration workflow. The two mechanisms stay separate and each
  keeps its own safety property intact.

The dataplane components are built to be **data-driven at runtime** to make this hold: the
classifier, filter, routing, and NAT stages carry no compiled-in topology or policy, so one image
built for a given hardware configuration serves every deployment sharing that hardware.
