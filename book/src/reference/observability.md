# Observability surfaces

These reference chapters are the **operator's interface to librefirewall**. Because the appliance
has no shell and no CLI — a deliberate design decision (see the
[management design](../design/management.md)) — the console, the OpenTelemetry log stream, the
`GET /metrics`, `GET /logs` and `GET /config` endpoints and the two recording downloads are the
*only* windows into a running node — together they are the complete, sufficient surface for
building dashboards, alerts, and analysis, and for debugging an incident. This chapter and its three
companions — [Console records](console.md), [Prometheus metrics](metrics.md) and
[Recording downloads](recordings.md) — define what that surface contains and how to interpret it, so
an operator can rely on it as a stable contract.

The conventions below are settled and binding, and they bind every surface named here whether or not
its inventory is filled. Nothing is named in an inventory ahead of the signal it belongs to: a name
published before the record carrying it exists is a guess an operator would go on to build against,
and this reference does not carry guesses.

## The surfaces, and the complete-state principle

- **Console** — a last-resort, human-readable channel carrying **system state only**. It exists so a
  node whose log streaming is down can still be diagnosed. It never carries traffic or per-request
  data. It is a physical device — a 16550 UART at `0x3F8` (COM1) at 115200 8N1 — owned by exactly
  one protection domain, which is the sole writer of the line and renders the records every other
  domain publishes to it.
- **OpenTelemetry logs** — the structured log stream to an external receiver. Everything the console
  says is also emitted here, plus audit, traffic, and per-subsystem logs. This is the only log
  transport; there is no syslog. There is no distributed tracing.
- **Local log buffer** — a bounded, on-node ring of the most recent structured log records, read
  through `GET /logs`. It is the *live* view: external OTEL collection is routinely delayed by
  minutes and can be down entirely, and there is no shell, so this is the only way to see what a
  node is doing right now.
- **Prometheus metrics** — the `GET /metrics` endpoint, the only metrics interface, exposing every
  measurable moving part at bounded cardinality and no measurable dataplane cost.
- **Configuration** — the `GET /config` endpoint, returning the configuration in force as a document,
  and `POST /config`, which replaces it. The only surface of the six that **changes** anything, and
  the only one whose reach is the authority to decide what the appliance forwards.
- **Recordings** — the two pcapng recording sinks (see the
  [recording design](../design/recording.md)). The first is a **connection history**,
  holding a record where the appliance reached a connection lifecycle or policy event; the second
  holds **every observation with the verdict on it**. This surface carries **evidence rather
  than state**: nothing on it is summarised, a reader is a packet analyser rather than a dashboard,
  and it is the only one that carries the traffic itself, at a volume the medium under it
  bounds rather than memory. It is reached over the authenticated management channel — shipped
  upstream from a cursor the server acknowledges, or asked for by extent with a range read — and
  never over HTTP; the *format* of what it carries is pcapng, and pcapng's
  specification, not this reference, is the contract for the bytes inside the file.

**Complete-state principle.** Scraping `GET /metrics`, reading `GET /config`, tailing `GET /logs`,
and downloading the two recordings **once** yields the entire observable state of a node: the
configuration in force, every metric around it, what it has just been doing, and the recorded
evidence of what it did to traffic. That *is* the debug dump — there is deliberately no other
mechanism to extract state, so those endpoints together are designed to be sufficient to diagnose the
system.

## Conventions (binding)

These apply to every signal and are the rules an operator can depend on.

### Identity and context

Every signal is attributable to a node and a configuration. The full common context is the **node
identity**, the **software build and trust profile**, and the **configuration generation** in force,
carried across the observability surfaces as OTEL resource/log attributes, Prometheus labels, and
console fields. A recording carries its own share of it differently, in the per-record annotation
rather than as a label — see [Recording downloads](recordings.md).

The console and the Prometheus exposition are the surfaces that exist, and the console carries one
part of that context. What it does carry, and what it does not:

| context | on the console | what fixes it there |
|---|---|---|
| configuration generation | `generation=` on every `LFW-CFG` record | the datastore's counter, assigned per commit and monotonic within a boot |
| emitting protection domain | `domain=` on every `LFW-PD` record | the domain's name in the Microkit system description, so a record and the capability topology use one identity — save that the driver's three instances share the one token `nic-driver`, which the Prometheus surface distinguishes and the console does not |
| node identity | **absent** | there is no management plane to be provisioned with one, and no identifier to carry; one serial console is one node, and its reader already knows which |
| software build and trust profile | **absent** | recorded in the release manifest beside the image (`trust_profile`, pinned inputs), never in a record the running system emits. `LFW-BOOT slot=` says which *slot* booted, which is not the same as which build it holds |

Neither absence is a placeholder waiting on a naming decision: each needs a fact the appliance does
not have — an identity it was provisioned with, and a build stamp compiled into the payload. Until
both exist, a record is attributable **within one boot of one node** and no wider. An operator
correlating two nodes, or one node across a reboot, is doing it from outside the contract.

### Naming

One scheme, namespaced to the product, across every surface. It is fixed by the console
implementation and binds the two that follow.

- **Record identifier**: `LFW-` followed by the channel in upper case — `LFW-BOOT` (boot manager),
  `LFW-PD` (protection-domain lifecycle), `LFW-CFG` (configuration). A reader keys on the `LFW-`
  prefix alone. Anything on the serial line without it is prose and carries no contract.
- **Fields** are `key=value`, space-separated, on one line, in a fixed order per record shape. An
  absent value omits its whole field rather than writing it empty, so a key that is present always
  has a value — and a record is read by looking a key up, never by counting fields.
- **A record's keys and vocabulary tokens** are lower-case ASCII words joined by `-`:
  `prefix-length`, `rx-posted`, `not-virtio-net`, `unknown-interface-reference`. Never camel case,
  never a Rust identifier, never an internal enum name. Where a key names a configuration attribute
  it is spelled exactly as the configuration document spells it, so a change record points at the
  text an operator edits rather than at a field name only the source reveals. The Prometheus surface
  writes the same words with `_` for `-`, so a metric name, a label name and a closed-vocabulary
  label value are the same word a record spells with hyphens; [Prometheus metrics](metrics.md)
  states that rule and the one class of label value it carves out of it.
- **The vocabularies are closed.** Every `state=`, `change=`, `object=`, `field=`, `outcome=`,
  `rejected=` and `cause=` value comes from a fixed set enumerated in
  [Console records](console.md). A value outside one is a defect, not an extension, and a reader may
  treat it as such.
- **Numbers are decimal unless the field's own meaning is a bit pattern.** `features=` and `detail=`
  are hardware values read against a datasheet and are `0x`-prefixed lower-case hexadecimal; every
  other numeric field — generations, sequence numbers, counts, offsets, indices — is decimal.
- The same keys and tokens are what every other surface carries, transliterated to its own separator
  convention. [Prometheus metrics](metrics.md) states that transliteration and the names it yields;
  an OTEL attribute key is fixed with the exporter and is deliberately not invented in advance.
- Labels and attributes are **low, bounded cardinality**: aggregate dimensions (interface, core,
  queue, subsystem, verdict class), never per-flow, per-connection, or per-packet identifiers.
- **No signal carries packet payloads, secrets, keys, or personal data — with one named exception,
  the two recording sinks.** For the console, the OTEL log stream, the local log buffer and the
  Prometheus exposition the rule is absolute and unqualified: none of them carries a byte of traffic,
  and none ever will. On the console it is structural rather than a rule to remember — the only value
  type that can carry text out of a configuration document is an identifier validated to
  `[a-z0-9-]{1,16}`, and a refusal names a *location* in the document and never the bytes at it. On
  the exposition it is structural too: a metric value is a number and a label comes from a closed
  vocabulary or a validated identifier.

  The exception is the two recordings, and it is stated rather than
  tolerated: a recording exists **to** carry the traffic, and a capture that omitted the payload
  would not be one. It is bounded to those two artifacts — the capture sink records payloads, the log
  sink the L2–L4 headers of the packet each record is anchored to — it is why a recording is
  authorized rather than openly scraped, and it is why an inspected flow is meant to be
  recorded as ciphertext plus its keys rather than as plaintext at rest. Nothing else on any surface
  moves because of it. **That authorization is now in front of it**: a recording leaves this
  appliance over the mutually-authenticated management channel and by no other route — see
  [Recordings](recordings.md).

  One consequence worth stating where a reader will look for it: `sectors=`/`leading=` on the console
  is **not** an instance of the exception. It is eight bytes of a sector rendered as an integer, and
  the paragraph on that field in [Console records](console.md) says why it is not payload.
- **The console alphabet is a guarantee, not a convention.** Every value carrying *text* is
  restricted to `[a-z0-9-]`, and the rendered line as a whole is printable ASCII — no control
  character, no ESC, and no newline but the single terminator the console appends. Values that are
  not text render in their own notation and are the only place other characters appear: `:` in a
  MAC, `.` in an address, and `-`, `T`, `:`, `.` and `Z` in the RFC 3339 instants — the `time=`
  field every record carries and the `utc=` the clock record states. Each is produced from an
  already-parsed number by first-party code, so no byte of one was ever a peer's to choose. That is
  what
  stops a peer painting terminal escape sequences onto an operator's terminal, and it is checked
  *twice against two different adversaries*: once where a call site mints a value, and again in the
  console domain where a record arrives out of a region another domain owns and every byte of it was
  that domain's choice. Neither check stands in for the other. The property is asserted by a
  persistent fuzz target over arbitrary record bytes, so a record that carried an escape sequence
  into a line would fail the gate rather than reach a terminal.

### Ordering and time

**Every in-kernel record carries the instant it was emitted, in a leading `time=` field**, and that
field has exactly two forms: an RFC 3339 instant in UTC with all nine fractional digits, or the token
**`unsynchronized`**. `LFW-BOOT` is the exception and carries no such field at all — those records
are written before seL4 starts, by a boot manager that has no protection domain, no calibration and
no counter reading behind it.

**Where the instant comes from, and how far it may be trusted.** One domain establishes a wall-clock
time at boot: it calibrates the timestamp counter against the HPET, reads the CMOS real-time clock
once, and publishes the resulting frequency, anchor reading and epoch for every other domain to
read. A domain stamps a record by reading `RDTSC` itself and converting with that triple, so an
instant is *this node's own arithmetic over one hardware counter* and never a value passed between
domains. Two consequences an operator should hold on to:

- **It is accurate to about a second, and not better.** The epoch is a CMOS reading taken once, to
  whole-second resolution, and never disciplined afterwards; the nanoseconds below that second are
  elapsed counter ticks, which are precise and say nothing about how well the epoch was set.
- **It is not a trusted time source.** The CMOS part is unauthenticated and unattested, cannot say
  whether it holds UTC or local time, and a hypervisor or a dead battery produces a plausible
  instant this appliance cannot tell from a correct one (see the [status page](../status.md)).
  Nothing may be *judged* against a record's instant — not a certificate's validity, not an audit
  claim about when an operator acted. It is a statement, on the record, of what this node believed
  the time to be.

**`unsynchronized` means the emitting domain had established no time when it emitted**, and it is
ordinary rather than a fault: a domain logs during its own `init`, several domains run before the
clock domain publishes, and the clock domain publishes *after* its own `ready` record — so its two
records are unsynchronized while stating the instant it just measured. The token is deliberately not
a zero: a record dated `1970-01-01T00:00:00.000000000Z` would be indistinguishable from one this
node really emitted at the epoch.

**A domain that has stamped a record is not thereby one that stamps every later record.** Each
domain re-reads the published calibration on every question rather than latching it, deliberately:
a cached triple would go on converting readings with one the clock domain has withdrawn. So a
calibration that is unpublished, torn under the read, or outside the band the reader accepts yields
`unsynchronized` again, after a run of instants. That the transition is one-way in practice — the clock
domain publishes once and parks — is that domain's behaviour, and a reader may not take it for a
guarantee of the field.

**Timestamps are attributable per boot and per node, and no wider.** They share the limits the
*Identity and context* section above states: there is no node identity and no build stamp on any
record, so two nodes' instants, or one node's across a reboot, are correlated by whatever an
operator knows from outside the contract. Two boots of one machine also anchor to two separate CMOS
readings.

**A rate is the scraper's arithmetic.** A counter on `/metrics` carries no timestamp and the node
contributes no time to a rate; differencing two scrapes is timed by the scraper alone. The instant
on a log record and the counters in an exposition are separate surfaces, and nothing correlates one
to the other on the node.

A record additionally carries the **configuration `generation`** it belongs to and, where one
generation produces several change records, a **`seq`** numbering them from 0 in emission order.
Those stay, and the instant does not replace them: `(generation, seq)` is an *attribution* — this
record belongs to that commit's diff, at that position — and an instant is not one. Generations are
monotonic within a boot, so `(generation, seq)` totally orders one boot's change records. `seq`
appears on `LFW-CFG` change records and on no other shape: it numbers a generation's diff, and is
neither a per-domain counter nor a sequence number for the console stream as a whole.

**Ordering across domains is not defined, and this is structural.** Every domain but the console
publishes its records into a single-producer ring of its own, and the console domain drains the
rings, renders each record and writes the line. Two guarantees follow, and no third:

- **Within one domain, order is exact.** One writer publishes into its ring in order and the console
  takes them in that order, so a domain's own records reach the line in the order that domain
  emitted them. This is what makes `(generation, seq)` reliable: one domain produces a commit's
  change records, so their order is that domain's order.
- **Across domains, nothing is ordered at all.** The console serves the rings round-robin with a
  rotating start and takes at most a bounded burst from each, which is the fairness rule that stops
  a flooding ring starving another. *Which* domain's record reaches the line first is therefore
  decided by where that rotation stood when the console next ran — not by which event happened
  first.

**The instant does not repair that, and reading it as an ordering is the mistake to avoid.** Two
domains' instants are comparable arithmetic — one counter, one epoch — but the *capture* is ordered
by the rotation, so a record printed first may carry the later instant, and on a healthy boot
routinely does. What holds is one guarantee per direction: a domain's own records appear in emission
order **and** carry non-decreasing instants; between domains, neither the order on the line nor the
order of the instants is a causal claim, because nothing serialises two domains against each other
in the first place. A concrete consequence met on every boot: the forwarding domain's
`generation=1 outcome=applied changes=0` routinely prints **before** the change records that
generation is made of, which the publishing domain emitted first. That is the rotation, not a fault.

Within a domain, then, `(generation, seq)` remains exact ordering and exact attribution, which is
what a configuration audit needs. What is now available beside it, and what still is not:

- **Duration is measurable within a boot, to counter precision.** How long bring-up took, how long a
  node sat fail-closed on generation 0, and the interval between any two of one domain's records are
  differences of two instants on one counter, and are exact to the tick.
- **Correlation outside the node is possible and is not attestable.** A neighbour's log, an
  operator's action or a packet capture can be lined up against these instants to about a second,
  which is the accuracy of the CMOS epoch. Nothing about that alignment is evidence: the epoch is
  unauthenticated, so a node whose firmware set it wrongly produces a plausible and wrong alignment.
- **Two boots are still only loosely ordered.** `generation` and `seq` restart from 0 in each, and
  the instants come from two separate CMOS readings — close enough to place two boots in sequence,
  never exact enough to order two records across one.

A record's instant is a statement and not a proof, and what would change that is the source behind
it rather than anything about the field: its form is fixed by this contract and does not depend on
how far the time it carries may be trusted.

## OpenTelemetry logs

**Purpose:** the primary, structured, streamed record of everything worth logging.

**Structure:** resource attributes (node/build/config identity, per *Conventions*), a severity
mapped from the level scheme below, a stable event/category identifier, and the curated context
attributes relevant to the event. Record schema and the required-attribute set per category are
fixed with the implementation and documented here.

**Severity levels** (used deliberately, matching the platform-wide scheme):

- **ERROR** — a system-level failure an operator must act on now.
- **WARN** — a recoverable or single-request-scoped failure.
- **INFO** — significant, low-frequency lifecycle or configuration events.
- **DEBUG / TRACE** — step-level and fine-grained detail, off in production.

**Log categories:**

- **System** — the console system-state events (see [Console records](console.md)), mirrored here in
  structured form.
- **Audit** — management and user actions (who did what, when, to which configuration).
- **Traffic** — connection- and verdict-level events from the dataplane.
- **Subsystem** — per-component operational logs (drivers, proxies, inspection engines, HA).

**Record inventory:** no attribute key is named here, under the rule at the head of this chapter.

What the **System** category's field set is, however, is settled: its call sites emit typed events
— an event is a set of named fields, and the console line is one rendering of it rather than the
thing itself — so the [console inventory](console.md) is that field set, and an exporter adds a
transport rather than a second set of call sites.

## Local log buffer

**Purpose:** answer "what is this node doing *right now*" without waiting on the external log
pipeline, and keep a node diagnosable when that pipeline is unavailable.

**Endpoint:** `GET /logs` on the management port, returning the retained records in the same
structured form as the OTEL stream.

**Semantics — a debugging surface, not a log archive:**

- **Bounded.** The buffer holds a fixed number of records in a fixed amount of memory; retention is
  whatever that bound yields, never a duration guarantee.
- **Lossy by design.** When it wraps, the oldest records are dropped. Drops are **counted and
  exposed as a metric**, so a reader can always tell whether it is seeing a complete window.
- **Not the system of record.** The OTEL stream remains the durable, complete log; this ring is a
  recent-history cache and may legitimately hold less.
- **Same content rules as every other surface.** No packet payloads, no secrets or keys, no personal
  data — being local is not a licence to retain more.

**Record and retention inventory:** the buffer size, the retention bound and the query semantics are
not named here, under the rule at the head of this chapter.

## Configuration endpoint: reading the policy and replacing it

`GET /config` returns the running configuration as XML (see the
[configuration design](../design/configuration.md)). It supplies the intent half of the debug dump:
paired with a `/metrics` scrape and a `/logs` read it gives the complete picture of *what the node
is configured to do* alongside *what it is doing* and *what it has just done*.

**What comes back is a rendering of the configuration in force, not the bytes that were submitted.**
The node keeps no copy of the document — 64 KiB of text has nowhere to live in a domain with no
allocator — so the answer is produced from the model the appliance is actually deciding under. Three
consequences, and each is the reason it is the stronger answer:

- Reformat a document, submit it, and read it back: what returns is the canonical form, not the
  whitespace and attribute order that were sent. Two documents that are one configuration state one
  document, which is the same property that makes re-submitting an unchanged configuration commit
  nothing.
- A value the schema admits in more than one spelling comes back in one of them — `protocol="6"`
  reads back as `protocol="tcp"`, a port range whose ends are equal as the single port.
- The generation a node committed **at boot** is stateable, which an echo of submitted bytes could
  never be: no other domain ever saw that document.

**What comes back is always a document the appliance would itself accept.** A configuration whose
canonical form would not fit the document bound is refused at submission with
`rejected=rendering-too-large` rather than committed, precisely so the read stays the first step of a
change: a policy an operator can read and not resubmit is one they cannot edit.

`POST /config` submits a replacement. The body is an XML document bounded by the same 64 KiB the
reader enforces; a longer one is refused `413 Content Too Large` at the request head, before a byte of
it is accumulated. The document becomes the candidate, is validated, and is committed under the next
generation; the answer is one line in the field vocabulary `LFW-CFG` uses on the console:

```text
generation=<n> outcome=applied changes=<n>
generation=<n> outcome=unchanged changes=0
generation=<n> outcome=refused rejected=<reason> offset=<n>
```

`200` for the first two, `400` for a refusal — the document is the client's and the node is
working — and the `rejected=` token is one of the reasons the [console chapter](console.md) lists.
A refusal changes nothing: the generation named is the one still running.

The generation the answer names is the one the **configuration domain** committed. The forwarding
domain switches tables at its next poll boundary, which is what the two-phase handover exists to make
happen between two frames rather than inside one — so what says a change is in force on the dataplane
is `librefirewall_configuration_generation{domain="forwarder"}` reaching that number.

**A commit ends the conversations the new policy no longer admits, over the wakeups that follow it.** A
packet an existing flow accounts for is forwarded before the filter is consulted at all, so a policy
edit does not reach a running conversation on the packet path. What reaches it is the pass the commit
arms over the flow table, which re-decides every live flow against the new policy and takes back the
ones it would not admit. The pass is bounded per wakeup, so it is worked off over the frames that
follow the commit rather than inside it, and three series say where it has got to:
`librefirewall_policy_sweep_running` reads 1 while a pass is still owed,
`librefirewall_policy_sweep_total{outcome="completed"}` rises when one finishes, and
`librefirewall_flow_lifecycle_total{event="revoked"}` counts the conversations it ended. While the
first of those reads 1, a conversation the new policy forbids may still be forwarding.
