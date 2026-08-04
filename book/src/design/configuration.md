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

## The filter policy in a document

Most of a configuration is a set of objects whose order does not matter: an interface is the same
interface wherever in the file it is written, and a reference resolves by name. The filter policy is
not, and the difference is a design decision rather than an accident of the file format.

- **A policy is an ordered list and the first matching rule decides.** A rule's position in the
  document is its precedence, so an operator reads a policy the way the appliance evaluates it. The
  alternative — an unordered set with explicit priorities — puts the evaluation order somewhere other
  than where the rules are written, and the question "which rule will actually decide this packet"
  then cannot be answered by reading.
- **What no rule matched is denied, and no document can say otherwise.** The default deny is a
  property of the appliance and not an entry in a policy: it is not a rule, so it cannot be
  reordered, matched around, disabled, or overridden. An empty policy therefore forwards nothing,
  which is the same posture a node holds before any configuration has been committed and after one
  has been refused — so "not yet configured", "configuration refused" and "configured to permit
  nothing" are one behaviour rather than three.
- **Every criterion is written out, the wildcard included.** A rule states each of the things it
  matches on, and a criterion that matches everything is written as such rather than omitted. No
  attribute widens a rule by being absent, because on a device whose whole purpose is to decide what
  may pass, a criterion that silently widened itself is the one defaulting mistake worth designing
  the schema around — and a policy an operator can audit by reading is worth the verbosity.
- **A rule carries an identity of its own.** An id is what an operator edits a rule by and what the
  appliance reports its matches under, so a rule's counters survive the rules above it being edited.
  Position is precedence; identity is not positional.
- **A rule decides which conversations may open, and names related traffic where it means to admit
  it.** An *established* flow bypasses the ruleset: a packet it already accounts for is forwarded
  before the filter is consulted at all, so the traffic following an admitted conversation is carried
  by the flow rather than by a line of the document. A policy is therefore mostly a statement about
  *admission* — which conversations may start.

  Two things reach the filter all the same, and the `tracking` criterion is what tells them apart:
  `tracking="opening"`, a conversation the appliance has not seen, and `tracking="related"`, traffic
  an existing conversation is the *reason* for without belonging to it — today an ICMP error quoting
  one of its datagrams. `tracking="any"` matches either. The second value exists because such an
  error is composed by whoever sent it, with a source address of its choosing, and delivered to an
  endpoint of a conversation somebody else opened: recognising it settles where it would go and must
  not settle whether it may. So the filter decides it too, and a document that admits no related
  traffic denies it, which is the same default deny everything else here is under.

  There is deliberately no third value. Traffic inside a tracked conversation never reaches the
  filter, so `established` would have no reachable meaning: an operator could write it, watch the
  document be accepted, and watch the rule sit at zero forever. A writable token that can never mean
  anything is worse on a security device than no token at all — so the word is **refused** at commit
  rather than accepted and ignored.

  **This is pf's model, and netfilter's was considered and rejected.** Under netfilter the acceptance
  of established traffic is a rule the operator writes — `--ctstate ESTABLISHED,RELATED -j ACCEPT` —
  which makes the state criterion meaningful and makes the ruleset a statement about every packet.
  It was rejected for one consequence: removing or mistyping that rule cuts every connection
  currently running. This appliance is aimed at OT and industrial environments where an operator
  editing a policy must not be able to drop a live process link by omission, so the guarantee is made
  structural instead of entrusted to a line somebody has to remember. A rule cannot be forgotten if
  there is no rule.

  The cost is stated with it, in both directions. A packet the appliance cannot keep state for — a
  fragment, a protocol it does not decode, a segment from the middle of a conversation it never saw
  begin — is refused before the filter, so no rule can permit one. And editing the policy changes
  which conversations may *start*, so on the packet path it does not reach one already running.

  **A revocation completes in a bounded number of wakeups, and the bound does not grow with the
  attacker's own state.** How much of a pass a wakeup works off scales with how full the flow table
  is, because a window of the pass stops at a fixed number of flows and so crosses less index the
  fuller the table gets. Without that scaling the conversations a narrowed policy forbids would go on
  forwarding longest exactly when there were most of them — which is the wrong direction, the state
  being the attacker's to create. A commit arriving while a pass is running queues one fresh pass
  behind it rather than restarting it, so a storm of submissions from the same unauthenticated party
  cannot stop a pass ever finishing. The figures are [in the
  detail](../developers/status-detail.md#connection-tracking).

  **What reaches one is the commit, and it reaches it by re-deciding the flow table rather than by
  consulting the policy per packet.** A commit sweeps the table against the new policy and takes back
  every conversation it would no longer admit, so removing a rule ends the connections it had
  admitted — which is what the model owes an operator who has found a host compromised. Once per
  commit rather than once per packet, so the ruleset stays off the hot path; and every flow the new
  policy still allows is left exactly as it was, which is the guarantee this whole model exists for
  and the one a sweep that merely flushed the table would have destroyed.
- **A rule that could never match is refused, not committed.** A criterion combination with no
  satisfying packet — a range whose ends run backwards, a port criterion on a protocol that has no
  ports, a block written with host bits set — is a line an operator wrote believing it was in force.
  The dangerous half of that belief is a permit that quietly matches nothing on an appliance that
  denies by default, so the document is refused rather than accepted with an inert rule in it. This
  is the one place the appliance does judge whether a valid configuration is sensible, and it is
  narrow on purpose: it refuses rules that can have no effect, never rules whose effect it disagrees
  with.
- **What the policy decides is what is forwarded, and nothing else.** It is not the selector that
  decides what reaches a [recording sink](recording.md): a packet the policy dropped is still an
  observation worth recording, and the two questions have separate answers in a document.

## Candidate/commit-confirm model

Configuration uses a **candidate/running datastore** model with **commit-confirmed**:

- The **running** configuration is what the appliance enforces; the **candidate** is an editable
  copy. Changes are assembled on the candidate without affecting the running configuration.
- A candidate is **validated** (structurally and semantically) as an operation that changes nothing.
- **Commit** atomically swaps candidate → running (all-or-nothing).
- **Commit-confirmed:** a commit arms a rollback timer; if it is not confirmed within the timeout,
  the appliance automatically rolls back to the previous running configuration. This protects
  against a change that validates but breaks management connectivity at runtime (anti-lockout).
  Because the appliance's management plane is an [outbound dial](management.md#the-channel), the
  confirmation must arrive over a **fresh** connection — one established under the committed
  configuration — since confirming over the pre-existing session proves nothing about a
  configuration that breaks new connections.
- Configurations are **versioned**, enabling **rollback**.

The stage, validate, commit and confirm operations arrive over the
[management channel](management.md); the [channel framing contract](../contracts/channel-framing.md)
carries exactly these operations and no wider write authority.

### The document travels one way, and the decision is made where a parser is safe

A submitted document crosses **two protection domains** before anything is decided about it, and the
direction is the whole of why the split exists.

- The **management** domain terminates the connection the document arrives on. It copies the bytes
  into a region and hands them on. It never parses them, never validates them, and never learns what
  they say. It holds two frame pipelines, so it is the domain an attacker reaches first — and the last
  one that should be reading an attacker's XML.
- The **validator** domain reads them. It holds no device, no buffer pool and no dataplane ring, so a
  compromise of the reader reaches no frame and no NIC. The worst it can produce is a configuration,
  and the consumer re-decides every rule about one for itself.

The bytes are **copied out of the shared region before a field of them is looked at**: the region is
written by a peer, so a decision taken on the bytes in place would be a decision taken on bytes that
are no longer there. And the answer travels back through a region the management domain may read and
not write, because a management domain that could write it could state back a policy the appliance
is not running — an operator would then edit and resubmit that, which is worse than a wrong answer.

### The appliance can state what it is running, and only what it could accept

The bytes of a submitted document are **not kept**: 64 KiB of text has nowhere to live in a domain
with no allocator, and keeping it would make the running configuration two things that could disagree.
What a read returns is therefore produced from the model in force — the canonical form of the
configuration the appliance is actually deciding under.

That makes the read authoritative rather than an echo, and it obliges one rule: **a configuration
whose canonical form does not fit the document bound is refused rather than committed.** Reading the
running configuration is the first step of changing it, so a policy an operator can read and cannot
resubmit is one they cannot edit. The refusal is narrow and reachable only by a policy close to the
bound in both directions at once; it is a rule about the *appliance's ability to state itself* rather
than about the configuration's content, and it is the one refusal that names no object in the
document.

## Persistence

The appliance persists its own state — the device private key, the signed device certificate, the
management CA certificate as delivered, the management endpoint, the onboarding state, and a bounded
history of configuration document versions — on the [store device](updates.md#the-store-device),
owned by the store domain. What follows is the mechanism, and it is chosen for one property: **a
power cut at any instant leaves either the old state or the new one, never a torn one.**

**The state record is an A/B transactional double-buffer, deliberately not a ring.** A ring
overwrites by design — the [recording rings](recording.md) are deliberately non-durable temporary
buffers, which is exactly the wrong nature for an identity. The state record is two copies at fixed
sectors, each carrying a magic, a version, a monotonic generation, its payload, and a hash covering
everything; the current state is the valid copy with the higher generation. To change anything, the
**whole** new state is composed into the *other* copy and flushed — so a power cut mid-write leaves
the previous copy intact and valid, and the either-old-or-new property is structural rather than
argued. This is the pattern U-Boot's redundant environment and RAUC's status block use. What it
reuses from the recording superblock is only that superblock's **proven primitives**: two copies at
a fixed location, a checksum covering everything, the rule that every unnamed byte must be zero, the
rule that both copies invalid means a fresh medium rather than an error, and a typestate boundary
where only a checked state may be acted on.

**Configuration version history is a fixed slot array, not a ring**: N slots, each holding one whole
document with its hash and generation, with the double-buffered record naming which slot holds which
generation and which is running versus candidate. Reuse takes the slot with the lowest generation,
and **the current configuration is never a reuse candidate** — which is the difference from a ring:
dropping the oldest *version* is bounded and intentional, while a structure that could overwrite the
running configuration would be one whose worst case is losing the state the whole store exists to
keep. Documents are bounded at 64 KiB, so the history and the record together stay under a
megabyte.

**Durability has one prerequisite: the flush.** The block device's flush feature is accepted and a
flush is issued at every point the double-buffer's ordering depends on — without it the device is
free to reorder and cache writes, and the double-buffer is theatre.

## Distributed staged rollout

Across the HA pair (and across multiple clusters via central configuration management), rollout is a
**two-phase "stage & validate" → "commit"** process:

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
- Commits are **idempotent, keyed by the monotonic configuration generation**, and the staged
  (prepared) state has a timeout, so a coordinator failure cannot leave nodes stuck. Whether a
  submitted configuration is the one already running is decided by comparing content, never by
  comparing a digest of it — a digest cheap enough to carry is short enough to collide, and a
  collision would suppress a real change.
- Standalone changes (a direct configuration change against a single node) retain per-node
  commit-confirmed protection.
- **Availability of configuration changes.** Unanimous agreement is required only while all
  participants are reachable. If a participant is unavailable, a healthy node must still accept
  configuration changes (a single-node commit), marking its configuration generation as divergent
  and reconciling with the peer when it rejoins — so a configuration change is never blocked by an
  unreachable node.

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
