# librefirewall monitoring contract

This document is the **operator's interface to librefirewall**. Because the appliance has no shell
and no CLI (CONCEPT.md §11), the console, the OpenTelemetry log stream, and the `GET /metrics`,
`GET /logs` and `GET /config` endpoints are the *only* windows into a running node — together they
are the complete, sufficient surface for building dashboards, alerts, and analysis, and for
debugging an incident. This file defines what that surface contains and how to interpret it, so an
operator can rely on it as a stable contract.

> **Status.** The conventions below are settled and binding. The concrete inventories — the exact
> console events, log records, and metric names — are populated as each signal is implemented; a
> section marked *“None implemented yet”* states the current truth of the contract, not a gap in it.

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

Every signal is attributable to a node and a configuration. The common context carried across all
four surfaces (as OTEL resource/log attributes, Prometheus labels, and console prefixes) is
finalized with the first implementation and documented here; at minimum it identifies the **node
identity**, the **software build and trust profile**, and the **configuration generation** in force.

### Naming

- Prometheus metric and label names, OTEL attribute keys, and console event identifiers follow one
  consistent, documented scheme (to be fixed with the first metrics/logs implementation), namespaced
  to the product.
- Labels and attributes are **low, bounded cardinality**: aggregate dimensions (interface, core,
  queue, subsystem, verdict class), never per-flow, per-connection, or per-packet identifiers.
- No signal — on any surface — carries packet payloads, secrets, keys, or personal data.

## Console (system state)

**Purpose:** confirm the node's own state — did startup succeed, and if not, what failed — and
record runtime configuration changes.

**Content:** the startup sequence and its success/failure (each stage reporting healthy or the
specific fault), and runtime system-state changes such as an interface brought up or down, a MAC
address reconfigured, or a configuration version applied. It is about firewall *system* state, not
traffic or user interactions except where those trigger a system-state change.

**Event inventory:** *None finalized yet.* The current build emits ad-hoc bring-up markers on the
serial console. These five are pre-contract diagnostics: they are not a stable interface and are
superseded by the structured system-state events defined here. All are system state, and each is
emitted at most once per protection domain, during start-up; none is traffic — no per-frame or
per-packet event appears on this surface, and dropped frames are counted in memory instead (see
*Prometheus metrics*).

| marker | protection domain | when |
|---|---|---|
| `LIBREFIREWALL_FWD:start` | forwarder | the domain has attached to both pipelines |
| `LIBREFIREWALL_NIC:driver:start` | nic-driver (once per port) | bring-up begins |
| `LIBREFIREWALL_NIC:features negotiated=0x<hex>` | nic-driver | the device accepted the feature set |
| `LIBREFIREWALL_NIC:driver-ok rx-posted=<n>` | nic-driver | the device is live with its receive queue primed |
| `LIBREFIREWALL_NIC:fail error=<StartupError> signalled=<true\|false>` | nic-driver | start-up was refused; the domain parks |

`error=` carries the whole reason rather than a summary, rendered as Rust's `Debug` form — so
integer fields read in **decimal**, including PCI vendor and device ids. It has exactly two shapes:

- `error=Device(<BringUpError>)` — the device refused bring-up, or build data programmed into it was
  rejected. The inner variant names the fault and carries the value that caused it, e.g.
  `error=Device(NotVirtioNet { vendor: …, device: … })`.
- `error=PipelineDmaBaseUnusable { region: Receive|Transmit, paddr: <n> }` — the pipeline DMA base
  the build patched in cannot be used: `paddr: 0` means the region's `setvar` is missing or
  misspelled in the system description, any other value means it is misaligned or would place the
  region off the end of the address space. This shape is always `signalled=false`.

`signalled` says whether the device was told to stop (`STATUS_FAILED` written) or was left decoding
nothing, which depends on whether its BAR had been placed when the rejection happened.

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

**Record inventory:** *None implemented yet* — populated per category as logging is implemented.

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
each with its type, unit, labels, and meaning. The dataplane already tallies its drops and faults in
memory under the semantics above, but no surface reads them out: **a drop is currently unobservable
from outside the node**, on this surface or any other.

## Configuration read endpoint

`GET /config` returns the exact running configuration (XML; CONCEPT.md §11–§12). It supplies the
intent half of the debug dump: paired with a `/metrics` scrape and a `/logs` read it gives the
complete picture of *what the node is configured to do* alongside *what it is doing* and *what it
has just done*.
