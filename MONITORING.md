# librefirewall monitoring contract

This document is the **operator's interface to librefirewall**. Because the appliance has no shell
and no CLI (CONCEPT.md §11), the console, the OpenTelemetry log stream, and the `GET /metrics`,
`GET /logs` and `GET /config` endpoints are the *only* windows into a running node — together they
are the complete, sufficient surface for building dashboards, alerts, and analysis, and for
debugging an incident. This file defines what that surface contains and how to interpret it, so an
operator can rely on it as a stable contract.

> **Status.** The conventions below are settled and binding. The concrete inventories are populated
> as each signal is implemented. The **console** inventory below is complete and is a contract as of
> the console-domain build, in which the serial device acquired a single owning protection domain and
> the records other domains emit began crossing to it as structured records rather than as text; the
> OpenTelemetry, local-buffer and metric inventories are still empty, and a section marked
> *“None implemented yet”* states the current truth of the
> contract, not a gap in it. Nothing is named in an empty inventory ahead of time: a name published
> before the signal it belongs to exists is a guess an operator would go on to build against.

## The four surfaces, and the complete-state principle

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
  instant this appliance cannot tell from a correct one (README, *Trusted time source*). Nothing may
  be *judged* against a record's instant — not a certificate's validity, not an audit claim about
  when an operator acted. It is a statement, on the record, of what this node believed the time to
  be.

**`unsynchronized` means the emitting domain had established no time when it emitted**, and it is
ordinary rather than a fault: a domain logs during its own `init`, several domains run before the
clock domain publishes, and the clock domain publishes *after* its own `ready` record — so its two
records are unsynchronized while stating the instant it just measured. The token is deliberately not
a zero: a record dated `1970-01-01T00:00:00.000000000Z` would be indistinguishable from one this
node really emitted at the epoch. Within one domain the transition happens once and in one
direction — a calibration is published once and never withdrawn — so a domain that has stamped a
record stamps every later one.

**Timestamps are attributable per boot and per node, and no wider.** They share the limits the
*Identity and context* section above states: there is no node identity and no build stamp on any
record, so two nodes' instants, or one node's across a reboot, are correlated by whatever an
operator knows from outside the contract. Two boots of one machine also anchor to two separate CMOS
readings.

**A rate is still the scraper's arithmetic.** A counter on `/metrics` carries no timestamp and the
node contributes no time to a rate; differencing two scrapes is timed by the scraper exactly as
before. The instant on a log record and the counters in an exposition are separate surfaces, and
nothing correlates one to the other on the node.

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
- **A rate is the scraper's arithmetic, not the node's.** Differencing two scrapes of a counter is
  timed by the scraper; the node contributes no time to the result.

When a *trusted* time source lands (CONCEPT §13.1) the field's form does not change; what changes is
what may be judged by it. Until then a record's instant is a statement and not a proof.

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
system state. **No per-frame or per-packet record appears on this surface at all**, and a dropped
frame is counted in memory instead (see *Prometheus metrics*).

One record sits at the edge of that and is stated here rather than left to be discovered: the
management port's `frames=`/`bytes=` pair is a *cumulative count of traffic*, emitted per drain and
never per frame. It is on this surface because it is the only evidence a node offers that its
management port is receiving at all, and because there is nowhere else yet — `/metrics` does not
exist. It carries no address, no port, no length of any individual frame and no byte of one, so
nothing about a packet is observable through it; what it says is "this port is up and taking
traffic", which is system state. It moves to the metrics endpoint when there is one, and this
document's inventory is where that move will be recorded.

Everything below is what the renderer writes, field for field. Every record of the grammars below is
one line of at most **228 bytes**, and a line is never truncated — see *Reading records off the
wire* for the two ways a line can nevertheless fail to be one record.

### `LFW-PD` — protection-domain lifecycle

```
LFW-PD time=<rfc3339|unsynchronized> domain=<domain> state=<state>[ features=0x<hex>][ rx-posted=<n>][ tsc-hz=<n> utc=<rfc3339>][ frames=<n> bytes=<n>][ cause=<token> signalled=<true|false>[ detail=0x<hex>[,0x<hex>]]]
```

At most one optional group appears, decided by the state. `domain=` is one of **`forwarder`**,
**`nic-driver`**, **`config`**, **`console`**, **`clock`**, **`management`** — the domain names in the
Microkit system description. `state=` is one of **`starting`**, **`negotiated`**, **`ready`**,
**`refused`**.

Which domain emits which state is not uniform, and a reader waiting on a record that is never
written waits forever:

| domain | records it emits | tail |
|---|---|---|
| `config` | `starting`, then `ready` **or** `refused` | none |
| `forwarder` | `starting` only | none |
| `nic-driver` (once per port, **three** instances — two dataplane ports and the management one) | `starting`, `negotiated`, `ready` — or `starting` then `refused` | `negotiated` carries `features=`, `ready` carries `rx-posted=`, `refused` carries the refusal group |
| `console` | `starting`, then `ready` — and **never** `refused` | none |
| `clock` | `starting`, then `ready` **or** `refused` | `ready` carries `tsc-hz=` and `utc=`, `refused` carries the refusal group |
| `management` | `starting`, then `ready`, then a further `ready` on **every drain that took at least one frame** — and **never** `refused`. It additionally emits `LFW-CFG rejected=` for a committed configuration it will not read | the repeated `ready` carries `frames=` and `bytes=`; the first carries no tail |

`console` is the domain that owns the serial device and renders every other domain's records, which
makes its two records mean something different from the rest: they are the console reporting that it
can report. Both are written *through the device it has just programmed*, so the first of them is
also the proof that there is a console at all. The absence of `refused` is not an omission — it is
the shape of the failure. A console that cannot program its controller has no way to say so, the
reporting mechanism being what failed, so **a node whose console never came up is silent rather than
apologetic**: no `LFW-PD domain=console` record, and no other record either, because nothing drains
the rings the other domains are publishing into.

An entirely empty serial line after the boot manager's `LFW-BOOT` record is therefore ambiguous, and
this document previously told an operator to read it as a refused console first. That was wrong, and
was found to be wrong the first time a release image was booted: the same silence is what a node
that never reached userspace at all looks like, because on the release kernel nothing between GRUB
and the console domain can print. The two are not distinguishable **on this surface**, and there is
no second channel yet that would separate them (no `GET /logs`, no metrics endpoint). Distinguishing
them today is an external act — attaching a debugger, or booting the debug profile, whose kernel
narrates its own start-up. In the QEMU gate that act is automated: a scenario that fails on the
release image is re-run once on the debug kernel by `tools/xtask/src/diagnose.rs`, which reports the
empty release capture as the expected silence of a kernel built without `CONFIG_PRINTING` rather
than as a second fault, and surfaces the debug boot's serial output beside it. That is a harness
convenience for this repository's own scenarios, not a channel on a deployed node: an operator
holding a silent appliance still has only the external act.

- `time=<rfc3339|unsynchronized>` — when the emitting domain emitted this record, or that it had no
  time to give it. Every record of this channel and of `LFW-CFG` carries it, first among the fields;
  *Ordering and time* above says what it is worth and what it is not.
- `features=0x<hex>` — the feature bitmap the driver and its device settled on. Which bit means what
  is virtio's vocabulary and is deliberately not decoded here.
- `rx-posted=<n>` — receive descriptors primed before the driver entered its poll loop, decimal.
- `tsc-hz=<n> utc=<rfc3339>` — what the clock domain established, which is the *source* of every
  other record's `time=` rather than another reading of it. `tsc-hz=` is the timestamp counter's
  measured frequency in hertz,
  decimal, derived from an interval measured against the HPET and always inside the band the
  appliance's own arithmetic accepts (10 MHz to 100 GHz); it is a *measurement*, so two boots of one
  machine report different numbers, and a value near the band's edges is worth looking at rather
  than a defect by itself. `utc=` is an RFC 3339 instant in UTC with all nine fractional digits, of
  the fixed form `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ` and always in the 2000–2200 band the real-time
  clock reader accepts. **It is the instant the CMOS part reported, advanced by the counter — not a
  trusted time.** The part is unauthenticated, cannot say whether it holds UTC or local time, and is
  read exactly once; a node whose firmware set it to local time reports an instant this appliance
  cannot tell from a correct one. This record's own `time=` field reads `unsynchronized`, and that
  is not a contradiction: the calibration is published *after* the record that states it, so the
  domain had none to stamp itself with at the moment it emitted.
- `frames=<n> bytes=<n>` — what a terminal port has received since the domain started: frames taken
  off its pipeline, and the bytes they carried, both decimal and both **cumulative and monotonic for
  the domain's life**. They are the management port's, and they are counts of what arrived — never any
  part of a frame (OBS-5). The pair travels together because a frame count with no byte count cannot
  be told from one carrying nothing.

  **This is a record about system state, not a traffic log.** It says "this port is receiving" and
  the numbers are the evidence; it is emitted once per *drain* that moved a frame, never once per
  frame, so a burst of a hundred frames produces as few records as the scheduler allows and a reader
  must not infer a frame boundary from a record. The counts belong on the metrics endpoint of
  CONCEPT §11 and will move there when it exists; until then this record is where they live, and it
  is the only place.

  **Everything else that port knows about itself reaches no surface at all**, and the list grew when
  the port became an addressed endpoint: descriptors naming a span outside the pool, returns the pool
  owner's ring would not take, and now every outcome the endpoint distinguishes — ARP replies and echo
  replies sent, frames not addressed to it, each reason a frame went unhandled, malformed frames, and
  replies it composed and could not send. So `frames=` and `bytes=` say the port is *receiving* and
  nothing on this surface says whether it is *answering*: that is asserted by the QEMU gate against
  the wire (README's port-role-model row) and will be readable on `/metrics` when one exists.

  `management` never reports `refused`, and unlike the console's silence that is not the shape of a
  failure: the domain has no device to answer it and no build datum to judge, so there is no third
  outcome for a refusal to name. It reaches its event loop or it faults, and a fault is the Microkit
  monitor's to report. **An unaddressed port is not a refusal either** — before the first commit, and
  under a configuration that disables the interface, the port takes frames and answers nothing, which
  is `ready` with a rising count and no reply on the wire.
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

### `LFW-PD` refusal causes

Every `cause=` token is listed below and the three tables together are the complete set: 23 the
`nic-driver` domain raises, 25 the `clock` domain raises, and 4 the `management` domain raises, with
no token shared between them. A token outside all three is a defect, not an extension. The
`forwarder` and `console` domains raise none, having no `refused` record.

**`nic-driver`.** The first two are the domain's own, raised before the device is touched at all;
the rest are the driver's bring-up tree.

| group | tokens |
|---|---|
| pool DMA base (`signalled=false` always; `detail=` is the rejected address, `0x0` meaning the `setvar` is missing or misspelled in the system description) | `receive-pool-dma-base`, `transmit-pool-dma-base` |
| capability chain (no `detail=`) | `no-capability-list`, `malformed-capability-list`, `structures-across-bars`, `invalid-structure-bar`, `missing-virtio-structure` |
| identity and BAR placement | `not-virtio-net` (vendor, device), `structures-outside-bar` (window), `common-cfg-misaligned` (offset, required), `bar-not-64-bit` (bar), `bar-index-out-of-range` (bar), `bar-has-no-high-half` (bar), `bar-target-unusable` (paddr) |
| handshake | `reset-not-acknowledged` (status), `no-virtio-1` (offered features), `features-rejected` (status) |
| queues and doorbells | `transmit-queue-absent` (offered, required), `virtqueue-region-unusable` (paddr), `queue-absent` (index), `queue-too-small` (device maximum, required), `doorbell-outside-bar` (slot end, BAR size — or BAR size alone where the offset overflowed), `doorbell-misaligned` (offset) |

**`clock`.** Grouped by the stage that refused, which the token's own prefix names: `cmos-ioport-`
the port capability, `hpet-` the reference timer, `tsc-` the measurement made against it, `rtc-` the
real-time clock, and `epoch-` the conversion of its answer. `signalled=` is **always `false`** on
this domain: it says whether a device was told to stop, and neither of these two has a stop to be
told — a refusal leaves the timer running exactly as the firmware left it and the register file
untouched. Where a refusal has more numbers than the line's two, the bound constants of the crate
that raised it (`COUNTER_POLL_LIMIT`, `UIP_POLL_LIMIT`, `SNAPSHOT_ATTEMPTS`) are what is left out,
being known without being transmitted.

| group | tokens |
|---|---|
| the port capability (no `detail=` beyond the pair) | `cmos-ioport-refused` (refused port, seL4 error code) |
| the timer block | `hpet-not-present` (capabilities word), `hpet-implausible-clock-period` (femtoseconds), `hpet-counter-too-narrow` (capabilities word), `hpet-not-enabled` (configuration readback), `hpet-counter-stalled` (the value it kept answering), `hpet-counter-too-slow` (observed, wanted), `hpet-duration-too-long` (nanoseconds) |
| the measurement | `tsc-no-ticks-elapsed`, `hpet-no-reference-interval`, `tsc-implausibly-slow` (derived hertz), `tsc-implausibly-fast` (derived hertz, saturated at `0xffffffffffffffff` where the quotient exceeds 64 bits) |
| the real-time clock | `rtc-update-never-completed` (status A), `rtc-snapshots-never-agreed`, `rtc-not-binary-coded-decimal` (CMOS index, value), `rtc-hour-outside-twelve-hour-range` (hour, PM flag), `rtc-implausible-year` (year, century register) |
| the date it named | `rtc-civil-before-epoch` (year), `rtc-civil-month-out-of-range` (month), `rtc-civil-day-out-of-range` (month, day), `rtc-civil-hour-out-of-range` (hour), `rtc-civil-minute-out-of-range` (minute), `rtc-civil-second-out-of-range` (second), `rtc-civil-nanosecond-out-of-range` (nanosecond) |
| the epoch conversion | `epoch-out-of-range` (the seconds since 1970 that would not fit nanoseconds) |

**`management`.** Four tokens, and the two halves differ in what they mean for the domain.

The first two are a **`state=refused` record and the domain's last act**: without a per-boot secret
its transport's initial sequence numbers would be predictable, and a predictable one lets an off-path
attacker inject into a connection it cannot see (RFC 6528). So the domain refuses to start rather
than answering a connection weakly, and the management port stays unaddressed for the boot. Read
either of them as "this node has no management port at all until it is rebooted on hardware that
answers".

The last two ride on a **`state=ready`** record instead, and mean something much narrower: the clock
domain published a calibration this domain will not convert readings with, so the port answers ARP
and ICMP echo — neither needs a time — and refuses TCP, counting each segment as unclocked. They are
reported once per calibration rather than once per frame. `signalled=` is always `false` on all four:
no device was told to stop, because none was told anything.

| group | tokens |
|---|---|
| the per-boot secret (a `refused` record; the domain does not start) | `rdrand-not-supported` (the `CPUID.01H:ECX` word read), `rdrand-exhausted` (which of the two 64-bit draws failed) |
| the published calibration (a `ready` record; TCP alone is refused) | `clock-not-published` (no `detail=`), `clock-implausible-frequency` (the hertz refused) |

### `LFW-CFG` — configuration

Three shapes, distinguished by their third key:

```
LFW-CFG time=<rfc3339|unsynchronized> generation=<n> seq=<n> change=<kind> object=<kind> key=<id> field=<name>[ from=<value>][ to=<value>]
LFW-CFG time=<rfc3339|unsynchronized> generation=<n> outcome=<applied|refused|unchanged> changes=<n>
LFW-CFG time=<rfc3339|unsynchronized> generation=<n> rejected=<reason> offset=<n>
```

**Change record** — one per configuration value that moved. An unchanged value produces nothing, so
the volume of a commit is the size of its diff.

- `change=` is **`added`**, **`removed`** or **`modified`**.
- `object=` is **`interface`**, **`neighbour`** or **`management`**.
- `key=` is the object's `id` from the document — its stable identity, so reordering the document
  produces no records at all. The `<management>` element has none, a document holding exactly one, so
  a record about it reads `key=management`: the two keys are the same word and neither is derived from
  the other.
- `field=` is **`port`**, **`enabled`**, **`mac`**, **`address`**, **`prefix-length`** or
  **`interface`**, spelled as the document's own attribute. Not every field belongs to every object:
  an `interface` carries `port`, `enabled`, `mac`, `address`, `prefix-length`; a `neighbour` carries
  `mac`, `address`, `interface`; `management` carries `enabled`, `mac`, `address`, `prefix-length` —
  it has no `port`, being no part of the router's port set. A pairing outside those is not written.
- `from=` is absent exactly when the object was added, `to=` exactly when it was removed. A
  `modified` record carries both.
- Values render by their type: `port` and `prefix-length` decimal, `enabled` `true|false`, `mac` as
  `52:54:00:12:34:50` (lower case), `address` as a dotted quad, `interface` as the referenced id.
- Records are ordered interfaces first, then neighbours, then the management interface, by id within
  each, then by the field order listed above. Two runs over one pair of configurations produce
  byte-identical output.

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

A refusal changes nothing — whatever was running stays running — but the readers that can raise one
label it differently, and the label is the reliable way to tell them apart. The publishing domain
refusing a **document** writes the generation still **running**, because no generation was ever
assigned to the text it rejected. The forwarding domain refusing an **offered image** writes the
generation that image **claimed**, that being the only identity the offer had. The **management**
domain can raise one too, and it is the one refusal that changes nothing anywhere: it reads the
*committed* generation to learn its own addressing, so an image it will not read is one the forwarder
has already staged and the publisher has already released. The port goes on carrying the addressing
it had, and `offset=` on such a record is the value that was refused rather than an index into
anything.

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

The serial device has **exactly one writer**: the `console` protection domain holds the only
I/O-port capability covering `0x3F8`–`0x3FF`, and every other domain reaches the line by publishing
a record into a single-producer ring that domain drains and renders. The one other port grant in the
system, the `clock` domain's CMOS pair, shares no port with it. A record is therefore **whole or
absent**, never spliced with another domain's — and that is a property of the capability grant, not
of scheduling or of a lock.

That guarantee is exact **in the release profile**, and one caveat qualifies it in the other:

- **The debug kernel writes the same port.** It is built with `CONFIG_PRINTING` and is handed
  `debug_port = 0x3f8` on its Multiboot2 command line, so in a debug image it emits its own boot
  banner and its fault reports onto the line the console domain owns. That output is prose and
  carries no contract, but it can land *inside* a line — a record preceded on its line by kernel
  text, or followed by it. **A reader must therefore still recover records by scanning for the
  `LFW-` prefix anywhere in the stream, not by assuming one line is one record.** The captures the
  gate writes are release boots and carry none of this; a debug boot is reached only by a diagnostic
  re-run of a failed scenario (`build/image/*-debug.log`), by `make run`, or from a `make
  image-debug` build, and it is those captures the caveat is about. The kernel prints on boot and on
  faults, never per record, so the interleaving is bounded and occasional rather than routine.
- **What no reader can recover** is a record whose own bytes were split. Nothing in the release
  profile splits one; in debug, a kernel fault report arriving mid-line leaves a fragment with no
  marker on its continuation, and such a fragment matches no grammar above. That is the whole of the
  guarantee available: a torn record fails to parse rather than parsing into something false.
- **A record that will not render is dropped and counted, not reported.** There is no
  `LFW-PD unrendered=…` line and no other escape hatch: a record whose bytes the ABI refuses, whose
  vocabulary token this build does not know, or that will not fit the 228-byte line is counted and
  discarded silently. Those counters are described below and **nothing exposes them**, so an
  operator reading the console cannot currently tell a record that was never emitted from one that
  was emitted and lost.

### What the console loses, and what counts it

The path from a call site to the line is bounded at every step — encoding the event, publishing it
into a ring, decoding it, rendering it, handing the bytes to the device — and every one of those
bounds is lossy. Each has its own counter, because they accuse different parties. Every counter
below follows the counter semantics under *Prometheus metrics* — monotonic for its domain's life,
saturating, no reset — and follows the **attribution** rule stated there: a drop names who
misbehaved, and the three classes never merge. **None of them is exposed on any surface today.**

| counter | kept by | accuses | what it means |
|---|---|---|---|
| `dropped` | each writing domain | itself, or the console | the ring had no slot, so the **newest** record was refused. A flood, or a console that is not draining |
| `refused` | each writing domain | *our own* invariant | an event this build minted that the record ABI cannot carry. Expected to read zero forever |
| `malformed` | the console | the **peer that sent it** | the bytes in the slot are no record at all — the writing domain published something the ABI cannot carry, or wrote a slot it had not been given |
| `unknown` | the console | the **peer that sent it** | the record decoded, but its vocabulary token names no variant this build has: the two halves of the ABI have parted, which means the two domains are different builds |
| `unrenderable` | the console | *our own* invariant | the event decoded and would not fit the 228-byte line. No peer can cause this; it is a defect in this build's renderer, and it is an alert rather than a statistic |
| `write_failed` | the console | the **device** | the controller would not take the line. Console output has been lost, and this is the one counter with nowhere to be reported *to* — the console is the reporting mechanism |
| `printed` | the console | — | lines rendered and handed to the device in full |
| `bytes_written`, `thre_timeouts`, `init_failures` | the UART driver | the **device** | bytes handed to the transmitter; bytes dropped because it never reported itself empty; refused initialisations |

Two properties of a full ring are worth stating because they are the opposite of what a log buffer
usually does:

- **A full ring refuses the newest record, not the oldest.** The ring carries the boot transcript,
  and when a domain parks the *earliest* records are the ones that say why; dropping the oldest
  would discard exactly those and keep the repetitive tail. This is the opposite bias from the
  `GET /logs` retention buffer specified below, which drops the oldest because it answers "what is
  this node doing *right now*". Both are bounded and lossy and each counts what it dropped.
- **A writer's drop count is that writer's claim about itself.** It lives in the region that writer
  owns, so it is a number to expose and never one to decide under, and it restarts at zero when that
  domain does — the one discontinuity the counter semantics admit.

### Boot-manager records (pre-kernel)

Before seL4 starts, the boot manager writes its slot-selection decisions to the same serial console
in a **structured, closed-vocabulary** form. This is a contract, not a diagnostic: it is the only
signal that says which slot is running.

```
LFW-BOOT slot=<A|B|none> state=<confirmed|trying|rejected|exhausted|unpersisted|bad-order|halted>
```

One record per decision, in decision order; the seven states above are the complete set. **This is
the one channel with no `time=` field**, and it is a fact about where the records come from rather
than an omission: they are written before seL4 starts, by a boot manager with no protection domain,
no calibration region and no counter reading behind it. The
human-readable `librefirewall: …` lines printed beside each record are prose and carry no contract —
a reader must key on the `LFW-BOOT ` prefix alone.

`state=halted` has two causes and does not distinguish them: no slot was bootable, or the boot
manager could not reserve the low memory that keeps the Microkit system image from being loaded
below the seL4 kernel (see README, *Signed boot chain*). Both are terminal and both need the same
external action, which is why they share a state; the prose line beside the record says which.

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

Of that intent the per-NIC and dataplane verdict and throughput counters, the pool ownership
faults, the transport's connection accounting and the applied-configuration state are published
today; the inventory below is the whole of what a scrape returns. Per-*core* counters await the
multicore dataplane, queue and ring occupancy and the flow table await the stateful dataplane, and
the local log buffer awaits the buffer itself — none of those exist to be counted yet.

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

**Transliteration (binding).** A metric name, a label name and a label value are the console's own
key or token with `-` replaced by `_`, under the `librefirewall_` prefix, with `_total` on a counter.
`no-route` on the console is `reason="no_route"` here; `nic-driver0` is `domain="nic_driver0"`. The
rule exists so an operator reading a console line and an operator reading a dashboard are looking at
the same word, and so neither has to keep a mapping table. A label value may begin with a digit
(`pipeline="0"`), which the exposition format permits and a metric *name* does not.

**No node-side pre-summing (binding).** Every series carries `domain`, and the node publishes no
total across domains. Two pipelines forwarding four frames each are two series of `4`, never one of
`8`. Summing is the scraper's job and it is lossless there; summing here would destroy the
attribution the section above requires, and a node that published both would be asserting an
equality it cannot keep across a domain restart.

**Freshness (binding).** A counter is published by the domain that owns it, into that domain's own
shared region, and a scrape reads whatever was last written. There is no barrier and no seqlock: the
values are individually meaningful, so a scrape may straddle two publications of *different* domains
and each number is still exactly what its owner last wrote. What a scrape is therefore *not* is an
instantaneous snapshot of the whole node, and no cross-domain equality should be alerted on at
single-scrape resolution. The management domain publishes its own shard before rendering, so a
scrape always reports the request that asked for it — its own response, composed afterwards, appears
in the *next* one.

### Metric inventory

51 families; the `domain` column lists every value that appears, which is the set of protection
domains publishing that family. The whole document is 205 series and about 25 KiB.

#### Dataplane: what the forwarder decided

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_forwarded_frames_total` | counter | `forwarder` | `pipeline`&nbsp;(`0`, `1`) | Frames rewritten for their next hop and handed to the transmitting driver. |
| `librefirewall_route_drops_total` | counter | `forwarder` | `pipeline`&nbsp;(`0`, `1`), `reason`&nbsp;(`addressed_to_this_router`, `egress_is_ingress`, `interface_disabled`, `martian_source`, `no_neighbour`, `no_route`, `not_addressed_to_us`, `ttl_expired`, `unconfigured_ingress_port`, `unroutable_destination`, `vlan_tagged`) | Frames the router refused, by the reason it named. |
| `librefirewall_route_stage_drops_total` | counter | `forwarder` | `pipeline`&nbsp;(`0`, `1`), `reason`&nbsp;(`egress_full`, `malformed_descriptor`, `misrouted`, `snapshot_failed`, `unparsable`, `writeback_failed`) | Frames the routing stage refused around the router's own decision. |

#### Dataplane: what each NIC moved, and what it got wrong

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_device_faults_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | `fault`&nbsp;(`completion_length_over_reported`, `completion_not_posted`, `completion_out_of_range`), `queue`&nbsp;(`receive`, `transmit`) | Virtqueue completions the device got wrong about its own protocol. |
| `librefirewall_input_drops_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | `reason`&nbsp;(`rx_peer_ring_full`, `rx_runt`, `tx_discarded`, `tx_duplicate`, `tx_free_ring_full`, `tx_malformed`, `tx_verdict_undecodable`) | Frames this driver did not move for a reason outside itself: a peer or the wire. |
| `librefirewall_invariant_faults_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | `fault`&nbsp;(`rx_completion_unmapped`, `rx_slot_occupied`, `tx_completion_unmapped`, `tx_slot_occupied`) | This driver's own broken bookkeeping; ours, never traffic, expected to stay zero. |
| `librefirewall_pool_returns_refused_total` | counter | `management`, `nic_driver0`, `nic_driver1`, `nic_driver2` | `pool`&nbsp;(`receive`, `transmit`), `reason`&nbsp;(`ledger_refused`, `not_lent`) | Buffer returns a pool owner refused: forged, out of range, duplicated or never lent. |
| `librefirewall_receive_bytes_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Bytes those frames carried, after the device's own header. |
| `librefirewall_receive_frames_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Frames this port's device delivered and the driver handed to its peer. |
| `librefirewall_transmit_bytes_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Bytes those frames carried, after the device's own header. |
| `librefirewall_transmit_frames_total` | counter | `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Frames this driver posted to its device for transmission. |

#### The management port: frames, and what the endpoint made of them

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_endpoint_bytes_total` | counter | `management` | — | Bytes those frames carried, as the ingress driver measured them. |
| `librefirewall_endpoint_frames_total` | counter | `management` | — | Frames the terminal endpoint took off its pipeline. |
| `librefirewall_endpoint_malformed_total` | counter | `management` | — | Frames no parser would read. |
| `librefirewall_endpoint_not_for_us_total` | counter | `management` | — | Frames addressed to somebody else at layer 2 or 3. |
| `librefirewall_endpoint_replies_lost_total` | counter | `management` | `reason`&nbsp;(`pool_exhausted`, `ring_full`, `write_failed`) | Replies composed and then lost, by where they were lost. |
| `librefirewall_endpoint_replies_sent_total` | counter | `management` | — | Replies the endpoint composed and the stage handed to the driver. |
| `librefirewall_endpoint_replies_total` | counter | `management` | `protocol`&nbsp;(`arp`, `icmp_echo`) | Stateless replies the endpoint answered a request with, by protocol. |
| `librefirewall_endpoint_reply_refused_total` | counter | `management` | — | Replies decided on and not written, the caller's storage being too small; ours. |
| `librefirewall_endpoint_stage_drops_total` | counter | `management` | `reason`&nbsp;(`malformed_descriptor`, `return_ring_full`, `snapshot_failed`, `unaddressed`) | Descriptors or frames the endpoint stage could not answer, by reason. |
| `librefirewall_endpoint_tcp_segments_total` | counter | `management` | — | Segments the endpoint handed to its transport. |
| `librefirewall_endpoint_timer_segments_total` | counter | `management` | — | Segments the transport composed out of its own timers rather than in answer to a frame. |
| `librefirewall_endpoint_unclocked_total` | counter | `management` | — | Segments that arrived before this node had established a time; ours, not the sender's. |
| `librefirewall_endpoint_unhandled_total` | counter | `management` | `reason`&nbsp;(`arp_not_a_request`, `arp_sender_mac_mismatch`, `ethertype_not_handled`, `fragmented`, `not_an_echo_request`, `protocol_not_handled`, `source_not_unicast`, `source_off_link`, `vlan_tagged`) | Well-formed frames for this endpoint that it deliberately does not answer, by reason. |

#### The management port: the TCP transport

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_tcp_bytes_total` | counter | `management` | `direction`&nbsp;(`received`, `retransmitted`, `sent`) | Payload bytes delivered in order, handed to the stack to send, or re-sent. |
| `librefirewall_tcp_challenge_acks_total` | counter | `management` | — | RFC 5961 challenge acknowledgements sent. |
| `librefirewall_tcp_connections_total` | counter | `management` | `event`&nbsp;(`abandoned`, `accepted`, `closed`, `established`, `evicted`, `reaped`) | Connections that reached each lifecycle event. |
| `librefirewall_tcp_refused_total` | counter | `management` | `reason`&nbsp;(`bad_checksum`, `malformed`, `no_acknowledgement`, `no_connection`, `not_listening`, `out_of_order`, `out_of_window`, `table_full`, `unacceptable_ack`) | Segments the transport refused, by the cause it named; what a peer sent. |
| `librefirewall_tcp_resets_total` | counter | `management` | `direction`&nbsp;(`received`, `sent`) | Resets accepted or sent. |
| `librefirewall_tcp_retransmits_total` | counter | `management` | — | Segments re-sent, data and control alike. |
| `librefirewall_tcp_segments_total` | counter | `management` | `direction`&nbsp;(`received`, `sent`) | Segments the stack received or composed. |
| `librefirewall_tcp_urgent_ignored_total` | counter | `management` | — | Segments carrying URG, whose urgent pointer is ignored and data delivered in band. |
| `librefirewall_tcp_write_refused_total` | counter | `management` | — | Segments the stack decided to send that did not fit its caller's storage; ours. |

#### The management port: the HTTP server

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_http_expositions_refused_total` | counter | `management` | — | Expositions the renderer would not fit in the staging buffer; ours, expected to stay zero. |
| `librefirewall_http_requests_overflowed_total` | counter | `management` | — | Requests that outgrew the bounded request buffer before their head ended. |
| `librefirewall_http_requests_total` | counter | `management` | — | Requests the server read to their end and decided on. |
| `librefirewall_http_response_bytes_total` | counter | `management` | — | Response bytes handed to the transport, headers included. |
| `librefirewall_http_responses_total` | counter | `management` | `status`&nbsp;(`200`, `400`, `404`, `405`, `414`, `431`, `503`, `505`) | Responses composed, by status code. |
| `librefirewall_http_retransmits_unavailable_total` | counter | `management` | — | Ranges the transport asked for again that no response buffer held; ours, expected to stay zero. |
| `librefirewall_http_slots_exhausted_total` | counter | `management` | — | Connections the server had no slot for; ours, the tables being one size, expected to stay zero. |

#### The console path, and what it loses

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_console_records_total` | counter | `console` | `outcome`&nbsp;(`malformed`, `printed`, `unknown`, `unrenderable`, `write_failed`) | Records the console path resolved, by outcome; each outcome accuses a different party. |
| `librefirewall_log_records_dropped_total` | counter | `clock`, `config`, `forwarder`, `management`, `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Records this domain could not publish because its ring had no slot. |
| `librefirewall_log_records_refused_total` | counter | `clock`, `config`, `forwarder`, `management`, `nic_driver0`, `nic_driver1`, `nic_driver2` | — | Events this domain minted that the record ABI cannot carry; ours, expected to stay zero. |
| `librefirewall_uart_bytes_written_total` | counter | `console` | — | Bytes handed to the transmitter-holding register. |
| `librefirewall_uart_init_failures_total` | counter | `console` | — | Refused initialisations of the serial controller. |
| `librefirewall_uart_transmitter_timeouts_total` | counter | `console` | — | Bytes dropped because the transmitter never reported itself empty; the device's fault. |

#### Configuration and the clock

| Metric | Type | `domain` | Other labels | Meaning |
|---|---|---|---|---|
| `librefirewall_clock_calibrations_refused_total` | counter | `management` | — | Published calibrations this domain would not use. |
| `librefirewall_clock_frequency_hertz` | gauge | `clock` | — | The timestamp counter frequency this node measured at boot; 0 before it did. |
| `librefirewall_clock_generation` | gauge | `management` | — | The calibration generation this domain converts counter readings with; 0 is none. |
| `librefirewall_configuration_generation` | gauge | `config`, `forwarder`, `management` | — | The configuration generation this domain is running under; 0 is the fail-closed empty table. |
| `librefirewall_configuration_images_total` | counter | `forwarder`, `management` | `outcome`&nbsp;(`applied`, `refused`) | Configuration images this domain applied or refused. |

**No metric was added when every record gained an instant, and that is deliberate.** Whether a
domain has a calibration is visible on each record it emits — `time=unsynchronized` against an
instant — so a counter of unsynchronized records would restate, at lower resolution, something the
records already carry per record. `librefirewall_clock_frequency_hertz` says what this node
measured and `librefirewall_clock_generation` says which calibration the management domain converts
with; the other six writing domains publish no such gauge, so *which* of them has taken the
calibration up is answerable from the log stream and not from a scrape. That is a gap, it is small,
and it is named here rather than closed with a series nothing needs.

The three attribution classes are kept apart exactly as stated above and are worth naming against
the table: `librefirewall_device_faults_total` is what a **device** got wrong about its own protocol;
`librefirewall_input_drops_total`, `librefirewall_route_drops_total` and
`librefirewall_tcp_refused_total` are what a **device or peer sent** that a layer refused; and
`librefirewall_invariant_faults_total`, `librefirewall_route_stage_drops_total`,
`librefirewall_endpoint_stage_drops_total` and `librefirewall_tcp_write_refused_total` accuse **this
code** and are expected to read zero forever — they are alerts, not traffic statistics.

**What a scrape costs the dataplane.** Nothing measurable, and by construction rather than by
measurement: a counter update is a relaxed add to a `u64` in the publishing domain's own cache-line
aligned region, and the exposition is rendered in the management domain out of a read of those
regions. No dataplane domain does any work on a scrape, and no lock is shared with one.

**Still absent.** `/config` and `/logs` (below and above) are unimplemented, so the debug dump has
only its state half. The endpoint is **plain HTTP with no client authentication**: CONCEPT.md §11
requires mutual TLS on the management interface, and until that lands anyone who can reach the
management interface can scrape it. That is a deviation, recorded in README's status table and in
`lfw_ip_endpoint`'s crate header. The endpoint stages one response at a time, so a scrape arriving
while another is still going out is answered `503` and counted as
`librefirewall_http_responses_total{status="503"}`.

## Configuration read endpoint

`GET /config` returns the exact running configuration (XML; CONCEPT.md §11–§12). It supplies the
intent half of the debug dump: paired with a `/metrics` scrape and a `/logs` read it gives the
complete picture of *what the node is configured to do* alongside *what it is doing* and *what it
has just done*.
