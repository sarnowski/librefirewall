# Management plane

librefirewall is a **two-component product**: the appliance, and a central management application —
a single pane of glass for many single and clustered appliances, Panorama-like, where **appliances
have no user interface of their own at all**. The management application owns appliance onboarding,
configuration management with version control and audit, log and capture search, and the operators
who do all of it; the [management server chapter](management-server.md) is its own design. This
chapter is the appliance's side of the relationship: the channel, onboarding, and the trust model
they rest on.

The appliance exposes **no management surface**. No HTTP API, no metrics endpoint, no download
endpoint, no log exporter — nothing listens on an onboarded appliance. In their place is one
persistent **outbound**, mutually-authenticated TLS connection from the appliance to the management
server, and that connection is the whole management plane.

## The channel

One connection, multiplexing everything, in both directions:

- **Up**: pcapng blocks as the wire format — connection and policy events, metric snapshots as
  PEN-tagged custom blocks, and audit records — flushed in roughly one-second batches, so an
  administrator sees logs and metrics near-realtime.
- **Down**: configuration operations (stage, validate, commit-confirm) and recording range-read
  requests.

**The ring bytes are the wire bytes.** The pcapng recording rings on the appliance remain the source
of truth, and the channel is [one more reader of them](recording.md#one-writer-many-readers) — a
cursor-holding reader that ships the rings' own bytes onward with no re-encoding on the appliance.
One consequence is worth stating here: every surface but the
[two recording sinks](recording.md#two-sinks-one-format) is barred from carrying packet payloads,
and the channel does not widen that exception — it *carries the sinks*, under the same authorization
the sinks' own design demands, rather than being a third place payloads appear.

**The session layer is deliberately thin**: mutual TLS, a resume cursor giving at-least-once
catch-up from the ring after a reconnect, and periodic acknowledgements — nothing else. Backpressure
is the recording ring's existing semantics, not a second mechanism: the appliance **never blocks on
a slow management server**, a lagging server catches up from the ring, and true overrun — a server
that fell further behind than the ring holds — is reported in-band through the drop counts the
recordings already carry. The exact frame layout, types, cadences and bounds are the
[channel framing contract](../contracts/channel-framing.md).

## Onboarding

An appliance is **unboarded** or **onboarded**, and nothing in between.

While unboarded it **forwards nothing** — fail-closed, the same posture as before any configuration
is committed. The management port runs only a minimal HTTPS onboarding server presenting the
appliance's self-signed certificate, whose SPKI fingerprint is printed on the output-only console.
The onboarding endpoints are rate-limited with backoff and are **never permanently locked out**: a
permanent lockout would be a remote bricking primitive, and an attacker who can reach an
unprovisioned appliance's management port already holds the position the trust model assigns to the
owner (below).

The flow:

1. On first boot — and after every factory reset — the appliance generates a keypair, self-signs a
   certificate, prints the key's SPKI fingerprint on the console, and persists both.
2. The administrator reaches the onboarding server over HTTPS and verifies the presented
   certificate's fingerprint against the console output. This authenticates the appliance to the
   administrator.
3. `GET /` serves a deliberately plain, unstyled HTML page: a link to the CSR, and a form to upload
   a configuration package.
4. `GET /certificate.csr` downloads the certificate signing request (its exact profile is the
   [certificate contract](../contracts/certificate-profile.md)).
5. The administrator uploads the CSR to the management application, which shows the fingerprint
   again and signs it — the management application is the device-issuing CA.
6. The administrator downloads a package from the management application and uploads it to the
   appliance via `POST /configuration.tar`. The appliance unpacks and validates it against the
   [package contract](../contracts/configuration-package.md) and installs its contents: the signed
   device certificate, the management CA certificate as trust anchor, the management endpoint, and
   the configuration — which may already carry substantial inherited configuration, so the appliance
   comes up with the connectivity it needs.
7. The appliance prints the installed anchor's SPKI fingerprint and the endpoint on the console,
   closes the onboarding server **permanently**, and from then on dials out, pinned to the delivered
   anchor.

## The ownership trust model

Trust is established by **the administrator controlling physical and logical access to the
management port during onboarding**. Whoever reaches an unprovisioned appliance becomes its owner;
ensuring nobody else can is the administrator's job, and an attacker who can reach an unprovisioned
appliance is indistinguishable from the user who is supposed to. There is no vendor-embedded trust
anchor, deliberately: a factory-fresh appliance has no owner and cannot know which management plane
will adopt it, and a vendor anchor would make the vendor a trust root for every appliance ever
shipped, which contradicts the product.

**One asymmetry must be read precisely, because the flow above looks mutual and is not.** The
fingerprint printed on the console authenticates the *appliance to the administrator* — the
administrator cannot be intercepted and cannot onboard the wrong box. **Nothing authenticates the
administrator to the appliance.** That is deliberate, and physical access control is the property
that stands in for it. The package is accordingly [not signed](../contracts/configuration-package.md):
it is authenticated by the TLS session the administrator opened after verifying the fingerprint out
of band.

**Factory reset is the only ownership transfer.** It removes all ownership — the key, the delivered
certificate and anchor, the endpoint, the configuration history — and returns the appliance to
unowned, ready to onboard again. It is local-only and never remotely triggerable, and it is asked for
by writing one sector of a medium: the same physical possession that established ownership is what
revokes it.

**It is per-medium**, and that is a consequence of the isolation the design rests on rather than a
limitation of it. The node's own state and its recordings sit on two devices owned by two protection
domains, neither of which maps a byte of the other's; a reset reaching from one to the other would
breach exactly the property that keeps the private key out of reach of the domain that answers a
download. So each medium holding an owner's data carries its own request and its own overwrite, and
the boundary stays exact — the visit that writes one medium's request sector reaches the others. The
mechanics, the clearing order and what each medium gives up are with the
[store design](updates.md#factory-reset).

## Lifecycle rules

- **The trust anchor and the management endpoint are never changeable over the channel — ever.**
  Changing either requires factory reset and re-onboarding: the same physical boundary that
  established ownership. The [threat model](threat-model.md#the-compromised-management-server) is
  why, and the package contract makes an endpoint change
  [structurally inexpressible](../contracts/configuration-package.md#members) in a pushed document.
- **Commit-confirm must arrive over a fresh connection.** The appliance's whole relationship to its
  management plane is an outbound dial, so what a committed configuration must not break is *new*
  connections — and confirming over the pre-existing session proves nothing about those, that
  session surviving regardless. After a commit the appliance re-dials under the new configuration,
  and only a confirmation on that fresh session keeps it; the deadline passing rolls back.
- **Management unreachability is never traffic-affecting.** The dataplane keeps forwarding the last
  committed configuration; reconnection uses bounded exponential backoff; and there are no rollback
  loops — an unreachable server changes nothing about what the appliance forwards, however long it
  stays unreachable.
- **Revocation is server-side.** The management application authorizes every connection per device,
  and revoking an appliance is withdrawing that authorization. There is no CRL and no OCSP machinery
  on the appliance, and device certificates are long-lived — expiry is not the revocation mechanism
  (see the [certificate profile](../contracts/certificate-profile.md)).
- **Certificate validity windows are judged against the CMOS-derived clock.** The hardware is
  trusted at this point, and that is a recorded decision rather than an oversight: the clock is
  unauthenticated, and an adversary who can set it is an adversary with a position — firmware, the
  hypervisor, the board — that the software design already cannot defend against.

## What remains on the appliance

- **Console:** unchanged — system state only, the startup sequence and its outcome, configuration
  changes, and the onboarding records above (the fingerprint, the installed anchor, the endpoint).
  It is the last-resort survivability channel, and during onboarding it is the trust root's display.
- **Recordings:** unchanged — the two pcapng sinks remain the durable record on the appliance's own
  storage, and remain [evidence that requires physical access](threat-model.md#the-compromised-management-server)
  even after a management-server compromise.
- **The debug surface is the console, the channel, and the recordings — and it is complete.** There
  is no shell, no CLI, and no other introspection mechanism. Everything an operator learns about a
  node arrives over the channel, is printed on the console, or is read out of the recordings; adding
  another mechanism changes the product's attack surface and is a design change.
- **No distributed tracing, no syslog, no Prometheus server, no OpenTelemetry export.** Metrics are
  snapshots in the ring; logs are events in the ring; both travel the channel, and the management
  server is the [sole collector](management-server.md).
