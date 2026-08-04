# Management server

`ctrld` is the management application: the single pane of glass the
[management plane](management.md) chapter introduces. It runs fully independently of the appliance
and is bound by none of its technology choices — it is a server-side web application, and it is
designed as one.

## Stack

**Phoenix with LiveView, and no JavaScript single-page application.** The product is real-time —
live log tailing, appliances going online and offline, several administrators in one policy — and
that is what the BEAM's process model, PubSub and Presence are for; LiveView delivers the live
interface without a second frontend codebase to keep consistent with the backend.

**Postgres holds the transactional state**: configuration versions, audit records, users, sessions,
the appliance inventory, and the CA material below. **ClickHouse holds the telemetry**: flow and
connection events, logs, and metric snapshots — the append-heavy, query-wide data a relational store
is the wrong shape for.

**There are no other moving parts.** No Prometheus server, no collector, no agents: Phoenix is the
sole collector, and the total inventory of a deployment is the Phoenix release, Postgres, and
ClickHouse (see [deployment](deployment.md#deploying-the-management-server)).

## The channel terminates in a plain listener

The appliance side of the channel is a raw framed TLS socket, and the server side matches it: a
**ThousandIsland listener** speaking the
[length-prefixed framing](../contracts/channel-framing.md) over mutual TLS — **not Phoenix
Channels**. Phoenix Channels was rejected because it would tax the wrong end: the appliance would
need an HTTP/1.1 *client* (its HTTP crate has no response parser, deliberately), a WebSocket
upgrade, WebSocket framing with masking and ping/pong, and Phoenix's join/heartbeat/reply protocol
with a serializer whose default is JSON — which fights the decision that the ring bytes are the wire
bytes. "Built with Phoenix in mind" is satisfied by the BEAM side: inside the server, each
connection is a supervised process, messages dispatch to processes, and Phoenix PubSub broadcasts to
LiveView — which is where supervision, PubSub, Presence and LiveView all earn their place.

## Decoding pcapng natively

The server decodes the appliance's pcapng blocks with **native BEAM binary pattern matching — no
Rustler NIFs**. pcapng is a well-defined TLV format, and binary pattern matching over exactly that
is what the BEAM is strong at; a NIF would buy shared code at the price of native code inside the
BEAM's schedulers and a build coupling between the two components.

The decision creates two implementations of one format — a Rust encoder in the appliance, an Elixir
decoder in the server — and two implementations of one format diverge silently. That risk is managed
by construction: **the Elixir decoder's test suite runs against bytes the Rust encoder actually
produced.** The appliance's QEMU gate leaves real recordings on disk after every scenario run, and
those recordings are the fixtures — so the decoder is held to the encoder's real output, not to a
shared reading of the specification.

Data flows one way through the server: appliance → Phoenix (decode and fold) → ClickHouse for
telemetry and Postgres for configuration and audit, with PubSub fanning out to LiveView for the live
view.

## The server is the certificate authority

The management server generates and holds its own CA and the channel endpoint's server certificate,
and it signs every device CSR — issuance is the
[onboarding flow's](management.md#onboarding) step five, against the
[certificate profile](../contracts/certificate-profile.md). It will hold many CAs and private keys
over time; all of them are **stored encrypted in Postgres under a key supplied to the server as an
environment variable**, so a database backup is not a key escrow and the key never rests beside the
data it protects.

## Two endpoints, two postures

The server has two listening endpoints, and their transport postures differ deliberately:

- **The channel endpoint** — the one appliances dial — runs the server's own CA-issued certificate,
  which is exactly what every onboarded appliance pins. Its trust needs no third party and admits
  none.
- **The web interface runs plain HTTP for now.** It is a fundamentally different endpoint class —
  browsers, human operators, certificates a customer's own PKI or ACME should supply — and it will
  get an administrator-supplied certificate or ACME later. Until then it runs plain HTTP, and that
  is recorded as a deliberate temporary state rather than omitted: a deployment terminates TLS in
  front of it or keeps it on a trusted network.

## Authentication

**Local users only, with one administrator account bootstrapped** in Postgres at first start. OIDC —
and an identity-provider broker for SAML shops — comes later; **SAML is never implemented in our own
codebase**. Every administrator action lands in the audit record in Postgres.

## Appliance inventory

The inventory shows each appliance with an **honest status** — a status derived from evidence the
server holds, never an optimistic default. Before the channel exists for an appliance, that is
"onboarded" and "CSR received at *T*": the facts issuance left behind. Once the appliance dials, it
becomes **online**, **offline**, and **last seen** — facts the connection itself establishes. A
status the server cannot evidence is not displayed.
