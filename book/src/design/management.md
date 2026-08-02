# Management plane

- **No user interface.** The only management interface is an **HTTP API**.
- **Endpoints / operations:**

  | Operation | Purpose |
  |---|---|
  | `GET /metrics` | Metrics in Prometheus format |
  | `GET /config` | Read the current running configuration (XML) |
  | `GET /logs` | Read the most recent structured log records held in the node's local buffer |
  | Recording download | Retrieve a time range of either [recording sink](recording.md) as a pcapng file |
  | Configuration change | The [candidate/commit-confirmed workflow](configuration.md): submit a candidate, validate, commit (with commit-confirmed), confirm, and roll back to a previous version |

  Configuration is never changed by a single unqualified write; every change goes through the
  candidate/commit-confirmed workflow (see [Configuration](configuration.md)), so the API exposes
  the stage, validate, commit, confirm, and rollback operations that workflow requires.
- **Security:** the API provides encryption, authentication, and read/write authorization using an
  **mTLS certificate pair issued during onboarding** (the design of the onboarding process is
  still open — see [development status](../status.md)). The management API runs in an isolated PD,
  on a dedicated management interface, and is rate-limited.
- **Metrics:** exposed in **Prometheus exposition format** via `GET /metrics` — the *only* metrics
  interface — with disciplined, bounded cardinality (aggregate metrics, never per-flow labels).
  Every moving part (queues, buffer pools, per-NIC and per-core counters) is observable there
  without measurable dataplane cost, and the endpoint also reflects applied-configuration state.
- **Logs:** emitted as **structured OpenTelemetry logs** to an external receiver — the single log
  transport; syslog is not used. Audit logs (management/user actions), traffic logs, and
  per-subsystem logs are OTEL-only. System-state events (see *Console*) are additionally written to
  the console. Connection and policy events are not composed for the wire: they are written to the
  [log sink](recording.md#two-sinks-one-format) and the OTEL exporter is
  [one reader of that ring](recording.md#one-writer-many-readers), which is what lets a collector
  that was unreachable catch up rather than lose them.
- **Local log buffer:** the node retains a **bounded ring of its most recent structured log
  records** and exposes it via `GET /logs`. External OTEL collection is routinely delayed by minutes
  and can be unavailable outright, and there is no shell — so without this ring there is no way to
  observe what a node is doing *now*, which is precisely what live debugging requires. It is a
  debugging surface, not a log archive: bounded, deliberately lossy (overflow is dropped and
  counted, and the drop count is exposed), and bound by the same rule as every other surface — no
  payloads, secrets, or personal data.
- **Recording:** the two pcapng sinks (see
  [Recording and persistent storage](recording.md)) are retrieved through the management API as
  pcapng files, over the same mTLS-authenticated, authorized and rate-limited surface as everything
  else, and a **live event stream** for an operator console — another
  [reader of the log ring](recording.md#one-writer-many-readers) — is developed later. This is the
  one surface bounded by storage rather than by memory, and the only one that carries the traffic
  itself.
- **The recording sinks are a deliberate exception to the no-payload rule, not an oversight in
  it.** Every other surface named here is barred from carrying packet payloads, and that bar
  stands unchanged: metrics, logs, the local log buffer, and the console carry none. The capture
  sink exists precisely to carry them and the log sink carries packet headers by construction —
  recording the evidence *is* the feature, and a capture that omitted the payload would not be
  one. The exception is therefore scoped and stated: it applies to these two sinks and to nothing
  else, it is why they are gated by an authorization decision rather than merely scraped, and it
  is why an inspected flow is recorded as
  [ciphertext plus its keys](recording.md#pcapng-as-the-internal-representation) rather than as
  decrypted plaintext at rest.
- **Console:** carries **system state only** — the startup sequence and its success/failure, and
  runtime configuration changes (an interface brought up, a MAC reconfigured, a config version
  applied). It never carries traffic or per-request data. It is the last-resort survivability
  channel that lets an operator diagnose a node whose log streaming is unavailable.
- **No distributed tracing.** OpenTelemetry is used for structured logs only; tracing — including
  of the management API — is deliberately out of scope.
- **The exposed interfaces are the complete debug surface.** There is no shell, no CLI, and no
  other introspection mechanism. Scraping `GET /metrics`, reading `GET /config`, tailing
  `GET /logs`, and downloading the recording sinks once yields the entire observable state of a
  node — applied configuration, every metric around it, what it has just been doing, and the
  recorded evidence of what it did to traffic — which is, by design, all that is available to
  debug it. The externalized logs and metrics are therefore a first-class operator contract,
  specified in the [reference part](../reference/observability.md) of this book.
- **Management application:** configuration management, log analysis, and metric analysis are
  handled by a separate management application, developed later.
