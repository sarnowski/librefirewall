# Recording downloads

**Purpose:** hand an analyst the appliance's own record of the traffic it handled, in a format their
tools already open. This is the evidence half of the debug dump, and the one surface that carries the
traffic itself.

**Endpoints:** `GET /logs.pcapng` and `GET /capture.pcapng` on the management interface. Each returns
one of the two recording sinks (see the [recording design](../design/recording.md)) — the same
encoder, the same ring machinery, the same download path, differing today only in extent and snap
length.

> **These bodies carry packet payloads.** They are the single named exception to the no-payload rule
> stated under the conventions in [Observability surfaces](observability.md), and nothing else on
> any surface carries a byte of traffic.
> **Today they are unauthenticated**: the port has neither TLS nor client authentication, so anyone
> who can reach it can download every packet the appliance recorded. The design requires the
> exception to be gated by an authorization decision; that gate does not exist yet. Treat reachability
> of the management port as equivalent to handing over the recordings.

## What a response is

| property | value |
|---|---|
| method | `GET`; anything else is `405` |
| `Content-Type` | `application/octet-stream` — this appliance's HTTP layer names no pcapng type and would be claiming to know a format it does not parse |
| `Content-Length` | always present, always exact, and **committed before the first body byte** |
| `Connection` | `close`, on every response, as on every other endpoint here |
| concurrency | one response at a time; a request arriving while another is going out is answered `503` |
| conditional and partial requests | none — no `Range`, no `If-Match`, no `ETag`. A client takes the whole recording or nothing |

**The length is pinned, not estimated.** The first window of a download seals the named recording —
flushing whatever was still in staging out to the medium — and takes a snapshot: the oldest segment
the ring still holds, and the durable write position. That snapshot fixes the body length, the
response commits to it in `Content-Length`, and every later window is located against the *same*
snapshot even though the recording keeps growing underneath it. A recording whose length could not be
stated is never begun rather than begun and truncated, and one longer than 2 GiB is refused outright
rather than served wrong.

**A body is assembled a window at a time and never held whole.** The recorder answers 32 KiB per
round trip out of its staging window, the endpoint copies each into a 16 KiB sliding transport window
sized above the retransmit span, and no domain holds a second copy of a megabyte. Nothing between the
medium and the wire parses the recording.

## When it goes wrong

There is no error body, and **where the failure falls decides what a client sees**:

- **Before the head is written** — nothing is on the wire yet, so the request is answered
  `503 Service Unavailable` with no body. A recorder that has nothing to serve, and a recording whose
  length exceeds the 2 GiB a windowed response can address, both land here.
- **After the head** — `Content-Length` has already been committed, so the connection simply closes
  short of it. **A client sees a truncated body, never a wrong one**, and a truncated body is
  detectable by anything that counts what it received; `curl` reports it.

The ways a download ends early, wherever it falls:

| condition | what it means | counted as |
|---|---|---|
| `Overrun` | the writer wrapped past the point being read: traffic outran the reader mid-download | `librefirewall_recording_download_overruns_total{sink}` and `librefirewall_recording_streams_total{outcome="abandoned"}` |
| `DeviceError` | the block device refused the read | `librefirewall_recording_streams_total{outcome="abandoned"}` |
| `NotReady` / `OutOfRange` / `NoSuchSink` | the recorder has nothing to serve for that request | `librefirewall_recording_streams_total{outcome="abandoned"}` |
| the transport and the recorder disagree about the range in flight | ours, and expected never to happen | `librefirewall_recording_streams_total{outcome="abandoned"}` |

None is retried: none is a state a retry improves. A download that completed is
`librefirewall_recording_streams_total{outcome="started"}` with no matching `abandoned`, and the
bytes and windows it took are `librefirewall_recording_stream_bytes_total` and
`librefirewall_recording_stream_windows_total`.

**A `404` on either target is a build fact, not a fault.** It means the endpoint's streamed-target
table would not take both recordings, which is stated once on the console as
`recording-targets-unregistered` (see [Console records](console.md)). The recorder is unaffected and
still writing to the medium.

## What is inside the file

The bytes are pcapng, and **pcapng's own specification is the contract for them** — this section
states only what this appliance puts there. A standard reader opens either file directly: `tcpdump -r`
lists the packets with their addresses, ports, lengths and wall-clock times, and ignores everything
below that it does not know.

- **A Section Header Block** opens every segment, carrying `shb_os` = `librefirewall`,
  `shb_userappl` = `librefirewall recorder`, and a PEN-tagged custom option holding the annotation
  layout version.
- **One Interface Description Block per interface**, link type `LINKTYPE_ETHERNET`, `if_tsresol` = 6
  (microsecond timestamps). `if_name` is the **port**, `port0` and `port1` — not the interface id the
  configuration document names (`dataplane-0`). `if_snaplen` is the sink's snap length: **128 bytes**
  on the log recording, **2048** on the capture recording.
- **One Enhanced Packet Block per observation**, carrying the frame **as it arrived** — the tap is
  taken between the router's decision and the forwarding rewrite, so a recorded frame is what the
  wire delivered, not what the appliance sent on. Captured length is the snap length or the frame,
  whichever is smaller; original length is always the frame's true length, so a truncated record
  still states what it truncated. Each carries:

  | option | what it holds |
  |---|---|
  | `epb_flags` | direction. Only *inbound* is emitted today — see below |
  | `epb_dropcount` | tap-ring observations lost before this record. **Always `0` today** — the field is emitted and nothing feeds it, so a recording does *not* yet state its own gaps in-band (the [recording design](../design/recording.md) requires that it does). Reconcile against `/metrics` instead |
  | `epb_packetid` | the appliance-wide packet identity |
  | `epb_verdict` | verdict kind `0xFF` and one byte: `0` forwarded, `1` dropped |
  | custom option, PEN-tagged | 16 bytes: layout version, verdict, drop reason, interface id, direction, and the **configuration generation** the decision was made under |

- **A Custom Block of padding** closes a sealed segment, so every write to the device is a whole
  sector. It is skipped by any reader that does not know the PEN, and by `tcpdump`.
- **The PEN is `0xFFFFFFFF`, a placeholder.** GROPYUS holds no registered Private Enterprise Number.
  The value is IANA-reserved so it can never collide with a real assignment, but it is not ours, and
  a reader must not treat a PEN-tagged option in these files as a stable identifier until a
  registered number replaces it.
- **No Interface Statistics Block is emitted yet**, and no Decryption Secrets Block. Between that and
  the unfed `epb_dropcount`, **a recording reports none of its own loss in-band**: a file that a burst
  outran looks exactly like one that lost nothing. Until both land, the loss families under
  [the two recordings, and the downloads served out of
  them](metrics.md#the-two-recordings-and-the-downloads-served-out-of-them) are the only account of
  it, and a recording must be read beside a scrape rather than alone.

## What the two recordings currently differ by

**Only the snap length.** The [recording design](../design/recording.md) defines the log sink as
connection lifecycle and policy events anchored to their causing packet, and the capture sink as
filtered full content. Neither is what exists: there is no connection tracking and no filtering, so
**both recordings hold every dataplane observation**, one keeping the first 128 bytes and the other
up to 2048. An operator should read `/logs.pcapng` today as "the capture, truncated to headers", not
as an event log. The annotation carries a version byte precisely so the record can grow when the
events land.

Three further limits an operator will otherwise infer wrongly:

- **Only the dataplane is recorded.** The management port is not tapped, so nothing on it — including
  the download itself — appears in either file.
- **One observation per frame.** The design's paired ingress and egress observation of a forwarded
  frame is not made; `epb_packetid` is minted and monotone, but there is only ever one record to
  relate. Every `epb_flags` therefore reads inbound.
- **Some frames are counted and deliberately absent.** A frame no routing decision was reached about,
  one routed out of a port the stage is not wired to, and one recorded as forwarded that a later
  refusal lost are all counted on the dataplane families and encoded in no recording, because the tap
  ABI mirrors the router's drop reasons exactly and has none for them. See
  [the two recordings, and the downloads served out of
  them](metrics.md#the-two-recordings-and-the-downloads-served-out-of-them) for the reconciliation.
