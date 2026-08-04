# Channel framing

This page is the exact wire protocol of the management channel — the one persistent connection
between an onboarded appliance and its management server. It binds both components: the appliance's
client and the server's listener implement this page and nothing beside it. The
[management design](../design/management.md) is why the channel is shaped this way; this page is the
shape.

The protocol is deliberately thin. It exists to do three things — at-least-once catch-up of the
recording rings, configuration operations, and recording range reads — and a mechanism that none of
the three needs does not exist. There is no negotiation beyond one version field, no compression, no
per-frame checksum (TLS carries integrity), and no ping: the upstream batching below keeps the
connection never idle, and the acknowledgement cadence answers it, so liveness is observable at both
ends without a dedicated frame.

## The session

One **TLS 1.3** session, mutually authenticated, per appliance. The appliance dials the delivered
endpoint — the address literal installed by the [configuration package](configuration-package.md) —
and validates the server against the delivered trust anchor and nothing else: no system roots, no
other CA. The server authenticates the appliance by its CA-issued device certificate and authorizes
the connection per device — which is where revocation lives. Key exchange is **hybrid
X25519MLKEM768**, from the first release: the channel carries the customer's network history, so an
adversary recording it today and decrypting later is the concrete threat
([harvest now, decrypt later](../design/threat-model.md)), and hybrid key exchange is what closes
it. The cipher suite is **TLS_CHACHA20_POLY1305_SHA256**. Certificates follow the
[certificate profile](certificate-profile.md).

Only the appliance dials. The server never connects to an appliance, and an appliance listens on
nothing once onboarded.

## Frames

Inside the session, both directions carry a sequence of length-prefixed frames. Every frame starts
with a fixed **8-byte header**:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | payload length in bytes, big-endian — at most 1 MiB (1,048,576) |
| 4 | 1 | frame type |
| 5 | 3 | reserved, zero — a nonzero byte is a protocol violation |

The length bound matches the recording segment size, so one sealed ring segment always fits one
frame. Every multi-byte integer in a header or a payload is **big-endian**; the pcapng bytes a
payload carries are exempt, being self-describing byte-for-byte copies of the ring.

| Type | Name | Direction | Payload |
|---|---|---|---|
| `0x01` | HELLO | both | version, and the server's resume cursors (below) |
| `0x02` | UP_RECORDS | appliance → server | u64 ring position, then verbatim log-ring pcapng bytes |
| `0x03` | UP_CAPTURE | appliance → server | u64 ring position, then verbatim capture-ring pcapng bytes |
| `0x04` | ACK | server → appliance | u64 log cursor, u64 capture cursor |
| `0x05` | DOWN_CONFIG_STAGE | server → appliance | the configuration document bytes (at most 64 KiB) |
| `0x06` | UP_CONFIG_VALIDATE_RESULT | appliance → server | one ASCII result line (below) |
| `0x07` | DOWN_CONFIG_COMMIT | server → appliance | u64 generation, u16 confirm deadline in seconds |
| `0x08` | DOWN_COMMIT_CONFIRM | server → appliance | u64 generation |
| `0x09` | DOWN_RANGE_READ | server → appliance | u8 ring, u64 start position, u64 length |
| `0x0A` | UP_RANGE_DATA | appliance → server | u8 ring, u8 status, u64 position, then bytes |

A ring selector byte is `0` for the log ring and `1` for the capture ring. Ring positions and
cursors are byte positions in the ring's own append space — the same coordinate the ring's
superblock keeps.

## HELLO

The first frame in each direction is HELLO, and nothing precedes it. Its payload begins with a
2-byte protocol version; this page defines **version 1**. A version the receiver does not speak
closes the connection — there is no downgrade dance, because both ends of this protocol are shipped
by the same project and a mismatch means one of them is due an update.

The appliance's HELLO carries the version and nothing else: its identity is its client certificate.
The server's HELLO carries the version followed by its two resume cursors — u64 log, u64 capture —
the positions up to which it has durably ingested each ring. Those are the appliance's resume
points.

## Upstream: the rings, verbatim

UP_RECORDS and UP_CAPTURE carry the recording rings' own bytes, from the stated ring position,
**verbatim** — the ring bytes are the wire bytes, and the appliance re-encodes nothing. Everything
the management server learns from an appliance travels this way, because everything worth shipping
is already a pcapng block in a ring: connection and policy events, and the **metric snapshots and
audit records**, which are PEN-tagged pcapng Custom Blocks the appliance writes into the log ring on
a period. The Private Enterprise Number is to be registered; until it is, the blocks carry the
IANA-reserved private value `0xffffffff` — a recorded decision, and the reason a recording must not
leave a customer's premises claiming that tag means anybody in particular.

The appliance flushes accumulated ring bytes **at least once per second** whenever unsent bytes
exist, so an administrator's view is near-realtime without a frame per event.

**Acknowledgement and resume.** The server sends ACK — its durably ingested cursors — **at least
once per five seconds of received data and at every 8 MiB of received ring bytes**. The appliance
records the acknowledged cursors in the ring superblocks' reader-cursor slots. After a reconnect the
appliance resumes each ring from the cursor in the server's HELLO: delivery is **at-least-once**,
duplicates are possible across a reconnect, and the server tolerates them (a pcapng block is
self-delimiting and the ingest fold is keyed, so a replayed block is recognised, not double-counted).
A cursor the ring has already overwritten — the server fell behind further than the ring holds —
resumes from the oldest byte the ring still has, and the loss is visible in-band exactly as it is to
any lagging reader: through the drop counts the recordings carry. That is the whole backpressure
story, and it is the [recording design's](../design/recording.md#one-writer-many-readers), not a new
one: the appliance never blocks on a slow server, a lagging server catches up from the ring, and
true overrun is reported rather than hidden.

## Downstream: configuration operations

DOWN_CONFIG_STAGE carries a whole configuration document. The appliance stages it as the candidate
and validates it, and answers with UP_CONFIG_VALIDATE_RESULT: one ASCII line in the same closed
field vocabulary the console's configuration records use — `generation=<n> outcome=<token>`, with
`rejected=<reason> offset=<n>` on a refusal — so the channel invents no second result vocabulary.

DOWN_CONFIG_COMMIT names the staged generation and a confirm deadline. The appliance commits it —
the ordinary atomic candidate-to-running swap — and the commit arms the deadline. **The confirmation
must arrive over a fresh connection**: after committing, the appliance closes the session and
re-dials under the configuration it just committed, and the server sends DOWN_COMMIT_CONFIRM for
that generation on the new session. Confirming over the pre-existing session would prove nothing
about a configuration that breaks *new* connections — the pre-existing session already survives it —
and new connections are exactly what a committed configuration must not break, the appliance's whole
relationship to its management plane being an outbound dial. A commit the deadline passes without a
confirmed fresh connection rolls back to the previous running configuration, and the appliance
re-dials under that.

A staged document is bounded, validated and refused by the same reader and the same rules as any
other configuration input; the channel adds transport, never trust. And no operation the channel can
carry changes the trust anchor or the endpoint — the
[package contract](configuration-package.md#members) makes an endpoint change inexpressible, and the
[management design](../design/management.md#lifecycle-rules) is why.

## Downstream: range reads

DOWN_RANGE_READ asks for a byte extent of one ring — the interactive counterpart of the upstream
stream, for the capture bytes the server did not ingest as they were written. The appliance answers
with UP_RANGE_DATA frames carrying the extent off the medium, verbatim, split across frames under
the payload bound, each stating the ring and the position its bytes start at. The status byte is `0`
for data; a `1` (the extent has been overwritten — overrun) or `2` (the medium refused the read)
carries no bytes and ends the answer, stating rather than truncating, exactly as the recording
design requires of every reader.

## Reconnection

The appliance re-dials on any close, with **bounded exponential backoff: one second initially,
doubling per attempt, capped at five minutes, with full jitter** — each delay drawn uniformly
between zero and the current bound, so a fleet disconnected at once does not redial in step.
Management unreachability is never traffic-affecting: the dataplane keeps forwarding the last
committed configuration however long the channel is down.

## Violations

A protocol violation closes the connection, and nothing else happens: a nonzero reserved byte, an
unknown frame type, a length over the bound, a frame in the wrong direction, a first frame that is
not HELLO, a version mismatch, a malformed payload. The violation is counted and the connection is
closed — **never a panic**, on either end; the peer is external input like any other. The next dial
starts the backoff schedule fresh only if the previous session reached a successful HELLO exchange;
otherwise the schedule continues, so a server that closes every handshake cannot be made to invite a
tight redial loop.
