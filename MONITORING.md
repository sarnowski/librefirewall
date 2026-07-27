# librefirewall monitoring contract

This document is the **operator's interface to librefirewall**. Because the appliance has no shell
and no CLI (CONCEPT.md §11), the console, the OpenTelemetry log stream, and the `GET /metrics`,
`GET /logs` and `GET /config` endpoints are the *only* windows into a running node — together they
are the complete, sufficient surface for building dashboards, alerts, and analysis, and for
debugging an incident. This file defines what that surface contains and how to interpret it, so an
operator can rely on it as a stable contract.

> **Status.** The conventions below are settled and binding. The concrete inventories are populated
> as each signal is implemented. The **console** inventory below is complete and is a contract as of
> the configuration-management build; the OpenTelemetry, local-buffer and metric inventories are
> still empty, and a section marked *“None implemented yet”* states the current truth of the
> contract, not a gap in it. Nothing is named in an empty inventory ahead of time: a name published
> before the signal it belongs to exists is a guess an operator would go on to build against.

## The four surfaces, and the complete-state principle

- **Console** — a last-resort, human-readable channel carrying **system state only**. It exists so a
  node whose log streaming is down can still be diagnosed. It never carries traffic or per-request
  data.
- **OpenTelemetry logs** — the structured log stream to an external receiver. Everything the console
  says is also emitted here, plus audit, traffic, and per-subsystem logs. This is the only log
  transport; there is no syslog. There is no distributed tracing.
- **Local log buffer** — a bounded, on-node ring of the most recent structured log records, read
  through `GET /logs`. It is the *live* view: external OTEL collection is routinely delayed by
  minutes and can be down entirely, and there is no shell, so this is the only way to see what a
  node is doing right now.
- **Prometheus metrics** — the `GET /metrics` endpoint, the only metrics interface, exposing every
  measurable moving part at bounded cardinality and no measurable dataplane cost.

**Complete-state principle.** Scraping `GET /metrics`, reading `GET /config`, and tailing
`GET /logs` **once** yields the entire observable state of a node: the exact configuration in force,
every metric around it, and what it has just been doing. That triple *is* the debug dump — there is
deliberately no other mechanism to extract state, so those endpoints together are designed to be
sufficient to diagnose the system.

## Conventions (binding)

These apply to every signal and are the rules an operator can depend on.

### Identity and context

Every signal is attributable to a node and a configuration. The full common context is the **node
identity**, the **software build and trust profile**, and the **configuration generation** in force,
carried across all four surfaces as OTEL resource/log attributes, Prometheus labels, and console
fields.

The console is the only surface that exists, and it carries one part of that context. What it does
carry, and what it does not:

| context | on the console | what fixes it there |
|---|---|---|
| configuration generation | `generation=` on every `LFW-CFG` record | the datastore's counter, assigned per commit and monotonic within a boot |
| emitting protection domain | `domain=` on every `LFW-PD` record | the domain's name in the Microkit system description, so a record and the capability topology use one identity |
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
- **Keys and vocabulary tokens** are lower-case ASCII words joined by `-`: `prefix-length`,
  `rx-posted`, `not-virtio-net`, `unknown-interface-reference`. Never camel case, never a Rust
  identifier, never an internal enum name. Where a key names a configuration attribute it is spelled
  exactly as the configuration document spells it, so a change record points at the text an operator
  edits rather than at a field name only the source reveals.
- **The vocabularies are closed.** Every `state=`, `change=`, `object=`, `field=`, `outcome=`,
  `rejected=` and `cause=` value comes from a fixed set enumerated below. A value outside one is a
  defect, not an extension, and a reader may treat it as such.
- **Numbers are decimal unless the field's own meaning is a bit pattern.** `features=` and `detail=`
  are hardware values read against a datasheet and are `0x`-prefixed lower-case hexadecimal; every
  other numeric field — generations, sequence numbers, counts, offsets, indices — is decimal.
- The same keys and tokens are what the OTEL and Prometheus surfaces will carry when they land,
  transliterated to each transport's own separator convention. That transliteration is a rule stated
  here; the resulting names are fixed with those implementations and are deliberately not invented
  in advance.
- Labels and attributes are **low, bounded cardinality**: aggregate dimensions (interface, core,
  queue, subsystem, verdict class), never per-flow, per-connection, or per-packet identifiers.
- No signal — on any surface — carries packet payloads, secrets, keys, or personal data. On the
  console this is structural rather than a rule to remember: the only value type that can carry text
  out of a configuration document is an identifier validated to `[a-z0-9-]{1,16}`, and a refusal
  names a *location* in the document and never the bytes at it.

### Ordering and time

**There is no clock in this system** — no timer, no interrupt of any kind, and no trusted time
source. Nothing is therefore timestamped. A record carries the **configuration `generation`** it
belongs to and, where one generation produces several change records, a **`seq`** numbering them
from 0 in emission order.
`(generation, seq)` is the whole of a record's ordering, and generations are monotonic within a
boot, so it totally orders one boot's change records.

That is exact ordering and exact attribution, which is what a configuration audit needs, and it is
preferred to inventing a time base a reader would then trust. What it costs is not small and is
stated rather than left to be discovered:

- **Nothing correlates outside the node.** Not a neighbour's log, not an operator's action, not a
  packet capture — there is no shared time base to correlate on.
- **Nothing measures duration.** How long bring-up took, how long a node sat fail-closed on
  generation 0, and the interval between any two records are all unavailable, on this surface and on
  every other.
- **Ordering holds within one boot only.** Two boots' records are ordered by nothing at all, and
  both `generation` and `seq` restart from 0 in each. A node that reboots between two records leaves
  a reader no way to tell which came first.
- **A rate is the scraper's arithmetic, not the node's.** Differencing two scrapes of a counter is
  timed by the scraper; the node contributes no time to the result.

When a trusted time source lands, records gain a timestamp field and lose none of the above:
`generation` and `seq` stay, because a change is attributed to a generation and a timestamp is not
an attribution.

## Console (system state)

**Purpose:** confirm the node's own state — did startup succeed, and if not, what failed — and
record runtime configuration changes.

**Content:** the startup sequence and its success/failure (each stage reporting healthy or the
specific fault), and runtime system-state changes such as an interface brought up or down, a MAC
address reconfigured, or a configuration version applied. It is about firewall *system* state, not
traffic or user interactions except where those trigger a system-state change.

**Event inventory.** Two record channels are emitted from inside seL4 by the protection domains:
`LFW-PD` for a domain's own lifecycle, and `LFW-CFG` for configuration. A third, `LFW-BOOT`, is
written before the kernel starts and is documented under *Boot-manager records* below. All three are
system state. None is traffic: no per-frame or per-packet record appears on this surface at all, and
a dropped frame is counted in memory instead (see *Prometheus metrics*).

Everything below is what the renderer writes, field for field. Every record of the grammars below is
one line of at most **192 bytes**, and a line is never truncated — see *Reading records off the
wire* for the two ways a line can nevertheless fail to be one record.

### `LFW-PD` — protection-domain lifecycle

```
LFW-PD domain=<domain> state=<state>[ features=0x<hex>][ rx-posted=<n>][ cause=<token> signalled=<true|false>[ detail=0x<hex>[,0x<hex>]]]
```

At most one optional group appears, decided by the state. `domain=` is one of **`forwarder`**,
**`nic-driver`**, **`config`** — the domain names in the Microkit system description. `state=` is
one of **`starting`**, **`negotiated`**, **`ready`**, **`refused`**.

Which domain emits which state is not uniform, and a reader waiting on a record that is never
written waits forever:

| domain | records it emits | tail |
|---|---|---|
| `config` | `starting`, then `ready` **or** `refused` | none |
| `forwarder` | `starting` only | none |
| `nic-driver` (once per port, two instances) | `starting`, `negotiated`, `ready` — or `starting` then `refused` | `negotiated` carries `features=`, `ready` carries `rx-posted=`, `refused` carries the refusal group |

- `features=0x<hex>` — the feature bitmap the driver and its device settled on. Which bit means what
  is virtio's vocabulary and is deliberately not decoded here.
- `rx-posted=<n>` — receive descriptors primed before the driver entered its poll loop, decimal.
- `cause=<token> signalled=<true|false>[ detail=…]` — the refusal. `signalled` says whether the
  device was told to stop (`STATUS_FAILED` written) or was left decoding nothing, which depends on
  whether its BAR had been placed when the rejection happened. `detail=` carries up to two numbers,
  hexadecimal, in the order the token names them, and is omitted where the token is the whole of the
  fault. Two is the line's budget rather than an arbitrary cut: a refusal with more to say keeps the
  pair that identifies it, and what it left out is recorded at the code that dropped it.
- `config state=refused` means **nothing is in force from this document** — it was either held to be
  wrong, or the datastore would not make the commit — and it carries no tail saying which. The
  `LFW-CFG` record emitted immediately before it does: `rejected=<reason>` for a document the reader
  or the rules refused, `outcome=refused` for a commit the datastore itself would not make. Read the
  pair, never the `LFW-PD` record alone.
- `config state=ready` does **not** imply a generation was published. A document whose content is
  already running is accepted, assigns no generation and publishes nothing, and the domain reports
  `ready`: the configuration in force *is* the one the document names, which is what `ready` claims
  and the whole of what it claims. That case reads `outcome=unchanged` on the record before it, so
  read the pair here too. On a first boot the content already running is generation 0 — the empty
  configuration, which forwards nothing — so `ready` beside `generation=0 outcome=unchanged` is a
  node that accepted its own document, published no generation, and is carrying no traffic. It takes
  a document naming nothing at all to produce that, generation 0 being empty; anything a document
  does name moves something.

The 23 `cause=` tokens are the complete set. The first two are the domain's own, raised before the
device is touched at all; the rest are the driver's bring-up tree.

| group | tokens |
|---|---|
| pool DMA base (`signalled=false` always; `detail=` is the rejected address, `0x0` meaning the `setvar` is missing or misspelled in the system description) | `receive-pool-dma-base`, `transmit-pool-dma-base` |
| capability chain (no `detail=`) | `no-capability-list`, `malformed-capability-list`, `structures-across-bars`, `invalid-structure-bar`, `missing-virtio-structure` |
| identity and BAR placement | `not-virtio-net` (vendor, device), `structures-outside-bar` (window), `common-cfg-misaligned` (offset, required), `bar-not-64-bit` (bar), `bar-index-out-of-range` (bar), `bar-has-no-high-half` (bar), `bar-target-unusable` (paddr) |
| handshake | `reset-not-acknowledged` (status), `no-virtio-1` (offered features), `features-rejected` (status) |
| queues and doorbells | `transmit-queue-absent` (offered, required), `virtqueue-region-unusable` (paddr), `queue-absent` (index), `queue-too-small` (device maximum, required), `doorbell-outside-bar` (slot end, BAR size — or BAR size alone where the offset overflowed), `doorbell-misaligned` (offset) |

### `LFW-CFG` — configuration

Three shapes, distinguished by their second key:

```
LFW-CFG generation=<n> seq=<n> change=<kind> object=<kind> key=<id> field=<name>[ from=<value>][ to=<value>]
LFW-CFG generation=<n> outcome=<applied|refused|unchanged> changes=<n>
LFW-CFG generation=<n> rejected=<reason> offset=<n>
```

**Change record** — one per configuration value that moved. An unchanged value produces nothing, so
the volume of a commit is the size of its diff.

- `change=` is **`added`**, **`removed`** or **`modified`**.
- `object=` is **`interface`** or **`neighbour`**.
- `key=` is the object's `id` from the document — its stable identity, so reordering the document
  produces no records at all.
- `field=` is **`port`**, **`enabled`**, **`mac`**, **`address`**, **`prefix-length`** or
  **`interface`**, spelled as the document's own attribute. Not every field belongs to every object:
  an `interface` carries `port`, `enabled`, `mac`, `address`, `prefix-length`; a `neighbour` carries
  `mac`, `address`, `interface`. A pairing outside those is not written.
- `from=` is absent exactly when the object was added, `to=` exactly when it was removed. A
  `modified` record carries both.
- Values render by their type: `port` and `prefix-length` decimal, `enabled` `true|false`, `mac` as
  `52:54:00:12:34:50` (lower case), `address` as a dotted quad, `interface` as the referenced id.
- Records are ordered interfaces first then neighbours, by id, then by the field order listed above.
  Two runs over one pair of configurations produce byte-identical output.

**Generation outcome** — what a commit or a switch did. `outcome=` is **`applied`** (the generation
is now in force; `changes=` is the size of its whole diff, even where more records were produced
than a buffer could hold), **`unchanged`** (the content was already running, so no generation was
assigned and no change record was written) or **`refused`** (the commit itself could not happen —
nothing was staged, or the counter is exhausted). `refused` carries no reason token because nothing
about the configuration is wrong; a *document* that is wrong is the third shape.

**Rejection** — a document or an offered image was refused, naming where and why and never the
bytes. `rejected=` is one of 30 reasons:

| group | reasons |
|---|---|
| document syntax and hardening bounds (18) | `malformed`, `doctype`, `entity-declaration`, `unknown-entity-reference`, `invalid-character-reference`, `document-too-large`, `depth-exceeded`, `too-many-attributes`, `name-too-long`, `value-too-long`, `unexpected-character-data`, `duplicate-attribute`, `unknown-element`, `unknown-attribute`, `missing-element`, `missing-attribute`, `malformed-value`, `capacity-exceeded` |
| semantic validation over the parsed model (12) | `duplicate-identifier`, `duplicate-port`, `port-out-of-range`, `prefix-length-out-of-range`, `address-not-a-host-address`, `address-not-unicast`, `mac-not-unicast`, `overlapping-prefixes`, `unknown-interface-reference`, `neighbour-outside-prefix`, `neighbour-is-interface-address`, `duplicate-neighbour-address` |

The vocabulary is deliberately coarser than the reader's own fault tree: fifteen distinct
unterminated, mismatched or misplaced constructs all read as `malformed`, because each is one edit
to the same place and a finer token would name an internal parser state rather than something an
operator can go and fix.

A refusal changes nothing — whatever was running stays running — but the two readers that can raise
one label it differently, and the label is the reliable way to tell them apart. The publishing
domain refusing a **document** writes the generation still **running**, because no generation was
ever assigned to the text it rejected. The forwarding domain refusing an **offered image** writes
the generation that image **claimed**, that being the only identity the offer had.

### Two things an operator will otherwise read wrong

**A first boot produces two `outcome=applied` records for generation 1.** `LFW-CFG` carries no
domain field, so the pair looks like a duplicate and is not. The publishing domain commits the
document and reports the diff it moved (`changes=<n>`); the forwarding domain later switches to that
generation at a poll boundary and reports only that it is now carrying traffic (`changes=0`). The
diff is the publisher's record; the switch is the consumer's. Seeing only the first means a
generation was committed and never reached the dataplane, which is a fault; seeing both is a
healthy boot. The forwarding domain additionally reports `generation=0 outcome=applied changes=0`
from its own start-up, and that is not a third copy of anything — it is the node stating that it is
running the fail-closed empty table and forwarding nothing until a generation arrives. On the
shipped document the whole sequence is 16 change records,
`generation=1 outcome=applied changes=16`, the fail-closed `generation=0 outcome=applied changes=0`,
and `generation=1 outcome=applied changes=0`.

**`offset=` is not always a byte offset.** It is the one number the reason names, and which number
that is depends on which reader refused:

| refused by | `offset=` means |
|---|---|
| the document reader (syntax, hardening bounds) | a **byte offset** into the configuration document |
| semantic validation over the parsed model | always **0** — the refusal names an object, not a position, and a byte offset for it would point at the XML declaration |
| the forwarding domain, over an offered handover image | the **entry index** within the image; for `capacity-exceeded`, either the count the image claimed or the generation number itself, depending on which capacity was exceeded |

Only five reasons can come from the third row — `capacity-exceeded`, `malformed-value`,
`port-out-of-range`, `prefix-length-out-of-range`, `mac-not-unicast` — the image being an
already-validated model rather than text. There is no field distinguishing the rows; what
distinguishes them is that a document refusal is emitted before any generation is offered.

### Reading records off the wire

The serial console is one unsynchronised device shared by every protection domain, and a record is
written with no lock. Two consequences, both observable in a normal boot capture:

- **Records interleave.** The two `nic-driver` instances run at equal priority and write during
  bring-up, so their `LFW-PD` records are routinely torn into one another —
  `LFW-PD domain=nic-driver state=staLFW-PD domain=nic-driver state=starting` is ordinary output,
  not a fault. Nothing structurally prevents the same happening to an `LFW-CFG` record; it is not
  seen today only because the publishing domain runs to completion above every other priority and
  the forwarding domain preempts the drivers rather than being preempted by them. **A reader must
  recover records by scanning for the `LFW-` prefix anywhere in the stream, not by assuming one line
  is one record.** What that scan recovers is a record that did not *begin* a line; what nothing can
  recover is a record whose own bytes were split, the continuation carrying no marker and two
  concurrent writers leaving a reader nothing to decide which fragment continues which by. Such a
  record presents as a short fragment ending where the interrupting one began, plus unmarked text
  after it — matching no grammar above, which is the whole of the guarantee available here.
- **A record that will not render is reported, not dropped.** Where the 192-byte line cannot be
  produced, the domain writes `LFW-PD unrendered=<debug form>` instead — under the `LFW-PD` prefix
  whatever channel the event belonged to, and following no grammar above. It is a defect in this
  contract wherever it appears, and it is written rather than swallowed so that it is visible as
  one.

### Boot-manager records (pre-kernel)

Before seL4 starts, the boot manager writes its slot-selection decisions to the same serial console
in a **structured, closed-vocabulary** form. This is a contract, not a diagnostic: it is the only
signal that says which slot is running.

```
LFW-BOOT slot=<A|B|none> state=<confirmed|trying|rejected|exhausted|unpersisted|bad-order|halted>
```

One record per decision, in decision order; the seven states above are the complete set. The
human-readable `librefirewall: …` lines printed beside each record are prose and carry no contract —
a reader must key on the `LFW-BOOT ` prefix alone.

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

- **System** — the console system-state events, mirrored here in structured form.
- **Audit** — management and user actions (who did what, when, to which configuration).
- **Traffic** — connection- and verdict-level events from the dataplane.
- **Subsystem** — per-component operational logs (drivers, proxies, inspection engines, HA).

**Record inventory:** *None implemented yet.* No OTEL transport exists, so nothing is named here:
an attribute key published before the record carrying it exists is a guess, and this document does
not carry guesses.

What *is* already decided is the shape of the **System** category. Its call sites emit typed events
— an event is a set of named fields, and the console line is one rendering of it rather than the
thing itself — so the console inventory above is the System category's field set, and an exporter
adds a transport rather than a second set of call sites. The other three categories have no call
sites at all yet.

## Local log buffer

**Purpose:** answer "what is this node doing *right now*" without waiting on the external log
pipeline, and keep a node diagnosable when that pipeline is unavailable.

**Endpoint:** `GET /logs` on the management interface, returning the retained records in the same
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

**Record and retention inventory:** *None implemented yet* — the buffer size, retention bound, and
query semantics are fixed with the implementation and documented here.

## Prometheus metrics

**Purpose:** expose every moving part of the firewall for monitoring and for the state half of the
debug dump, scrapably and without degrading the dataplane.

**Endpoint:** `GET /metrics`, Prometheus exposition format, on the management interface.

**Coverage intent:** every internal queue, buffer pool, and ring; per-NIC and per-core counters;
dataplane verdict and throughput counters; connection/flow-table occupancy and limits; the local log
buffer's occupancy and drop count; and the applied-configuration state reflected as metrics.

**Counter semantics (binding).** Every counter is **monotonic for the protection domain's life** and
**saturates** rather than wrapping. There is no reset: a scraper derives a rate by differencing
successive scrapes, so a reset would forge a negative rate, and a wrap would turn a sustained flood
back into a small number — which is exactly the signal a counter of attacker-driven events exists to
carry. A domain restart is therefore the only discontinuity, and it is one a scraper can see.

**Attribution (binding).** A drop counter names *who* misbehaved, because a number that does not is
not actionable. Three classes stay separate and never merge: what a **device** got wrong about its
own protocol, what a **device or peer sent** that a layer refused, and what **we** got wrong —
a violation of a domain's own invariant, which is expected to read zero forever and is an alert, not
a traffic statistic.

**Metric inventory:** *None implemented yet* — populated per subsystem as metrics are implemented,
each with its type, unit, labels, and meaning. Nothing is named in advance for the reason given
under *Record inventory*: a metric name is what an alert and a dashboard are written against, and
one published before the metric exists would be a guess an operator had already built on.

The dataplane already tallies its drops and faults in memory under the semantics above — eleven
named routing drop reasons, the pool ownership faults, and the configuration handover's applied and
refused counts — but no surface reads any of them out: **a drop is currently unobservable from
outside the node**, on this surface or any other.

## Configuration read endpoint

`GET /config` returns the exact running configuration (XML; CONCEPT.md §11–§12). It supplies the
intent half of the debug dump: paired with a `/metrics` scrape and a `/logs` read it gives the
complete picture of *what the node is configured to do* alongside *what it is doing* and *what it
has just done*.
