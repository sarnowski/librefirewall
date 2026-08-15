# Recordings

**Purpose:** hand an analyst the appliance's own record of the traffic it handled, in a format their
tools already open. This is the evidence half of the debug dump, and the one surface that carries the
traffic itself.

**Where they are:** two ring extents on the appliance's own block device (see the
[recording design](../design/recording.md)) — the same encoder and the same ring machinery. What
differs is **what each one records**: the **connection history** holds a record where the appliance
reached a connection lifecycle or policy event, and the **capture** holds every observation with the
verdict on it.

**How they leave the appliance:** over the mutually-authenticated
[management channel](../design/management.md) and by no other route. Each is shipped upstream
continuously from a cursor the management server acknowledges, and an operator asks for a byte
extent of either with a range read over the same connection. There is no HTTP download; the two that
existed have been removed.

> **These carry packet payloads.** They are the single named exception to the no-payload rule
> stated under the conventions in [Observability surfaces](observability.md), and nothing else on
> any surface carries a byte of traffic. The authorization the exception is conditioned on is the
> channel's: a recording reaches a management server that presented a certificate this appliance's
> own delivered anchor accepts, and reaches nobody else.

## How a recording reaches a reader

Two paths over the one channel, and neither has a format of its own: both carry the recording's own
pcapng bytes, at the ring position they were read from.

- **Shipping** is continuous and in order. The appliance reads its own cursor into each ring and
  sends the bytes upstream frame by frame, each frame stating the recording and the absolute append
  position it starts at, so a frame is self-locating whatever its size. The cursor moves only on a
  frame the far end answered, so a shipment may cross twice and can never be lost. A management
  server states, per recording, how far it has durably ingested — in its greeting, which is where a
  session resumes from, and in acknowledgements as the session runs — and that position is written
  into the recording's own superblock, so a reboot resumes rather than restarts.
- **A range read** answers a question. An operator names a recording, a start and a length, and the
  answer is a sequence of frames at strictly advancing positions, or a status saying why the extent
  cannot be served: `Overwritten` where the ring has rolled past it, `MediumRefused` where the
  medium refused. It is never a short read dressed as a complete one, and it moves no cursor.

**Every bound on either path is this appliance's own.** A range request is capped at one mebibyte
and 1024 answer frames, with one answer in flight per session; a second request under one is a
protocol violation that closes the connection. The medium is shared out between the two shipping
cursors and one range answer in turn, so neither a peer asking for extent after extent starves the
channel's own purpose, nor the traffic starves an operator's request.

**A recording is read a window at a time and never held whole.** The recorder answers up to 32 KiB
per round trip out of its staging window, and no domain holds a second copy of a megabyte. Nothing
between the medium and the wire parses the recording.

**An extent taken off the disk never describes itself further than it was written.** This matters to
anyone who reads the medium directly rather than downloading — a recovered disk, a forensic copy —
because such a reader has only the extent's own header to go by. Each extent carries a checkpoint
record stating where the recording durably ends, and that record is written **behind a device
barrier**: the appliance asks the block device to commit everything already written, waits for the
device to say it did, and only then writes the header claiming those bytes. So the two cannot appear
out of order however the device caches or reorders, and a power cut at any instant leaves a header
that either has not moved yet or names bytes that are genuinely there. It never names bytes that are
not.

Two consequences are worth stating plainly. Where the barrier fails, or the device refuses one, the
checkpoint is **not written**: the extent goes on holding an older statement of where the recording
ends, which understates it, rather than a newer one that might overstate it. And where the block
device never offered a flush feature at all, there is no barrier to take — the checkpoint is written
without one and its ordering is then the device's to decide, which is the weaker guarantee of the two
and the reason the feature is negotiated rather than assumed. What is never affected is the recording
itself: an unwritten checkpoint costs the extent its statement of where it ends, never a record.

## When it goes wrong

A read the recorder cannot answer ends the frame sequence with a status rather than with short
bytes, and the cause that the wire cannot carry is put on the console instead — the wire has three
statuses and the recorder has six refusals, so the mapping is lossy by construction and the console
is where the lost cause goes.

| condition | what it means | counted as |
|---|---|---|
| `Overrun` | the writer wrapped past the point being read: traffic outran the reader mid-read. Answers `Overwritten` to a range read, and moves a shipping cursor to where the medium now begins | `librefirewall_recording_download_overruns_total{sink}` |
| `DeviceError` | the block device refused the read, or completed it having moved fewer bytes than were asked for — a short read is an error here and never bytes to serve | `librefirewall_recording_downloads_total{outcome="refused"}` |
| `NotReady` / `OutOfRange` / `NoSuchSink` / `NoSuchReader` | the recorder has nothing to serve for that request; the last two are this appliance's own defect, since it composes the request | `librefirewall_recording_downloads_total{outcome="refused"}` |

None is retried in place: none is a state a retry improves. A shipping cursor comes back to the same
position on the next turn and loses nothing; a range answer ends, saying which of the two statuses
it ended on. A recorder that says nothing at all inside the reply timeout gives its slot back and is
reported on the console under a token of its own, distinct from a recorder that said no.


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
  on the connection history, **2048** on the capture.
- **One Enhanced Packet Block per record**, carrying the frame **as it arrived** — the tap is
  taken between the router's decision and the forwarding rewrite, so a recorded frame is what the
  wire delivered, not what the appliance sent on. Captured length is the snap length or the frame,
  whichever is smaller; original length is always the frame's true length, so a truncated record
  still states what it truncated. Each carries:

  | option | what it holds |
  |---|---|
  | `epb_flags` | direction; every record reads *inbound* — see below. **Absent** on the one record that is about no frame, a direction being a property of a packet on a wire |
  | `epb_dropcount` | tap-ring observations lost before this record, and any `u64`. The recorder differences the forwarder's own tap-drop count on every pass and holds the rise as a debt until there is a record to carry it, so the number belongs to the gap before this block and not to the packet in it. It accounts for the tap ring **and nothing else**: what a sink could not encode, or could not write, is in a [metric reading](metrics.md) and not in the packet blocks |
  | `epb_packetid` | the appliance-wide packet identity. It is the same number on the connection history's record of an event and on the capture's record of the packet that caused it, so the two files relate to each other by it |
  | `epb_verdict` | verdict kind `0xFF` and one byte: `0` forwarded, `1` dropped, `2` neither — a conversation the appliance ended itself |
  | custom option, PEN-tagged | 24 bytes carrying the whole decision — see below |

### The annotation: what the appliance decided

The PEN-tagged custom option is where the firewall's own state rides, pcapng having no standard
field for it. It is 24 bytes, little-endian, at these offsets:

| at | width | what it holds |
|---|---|---|
| 0 | 1 | **layout version**, currently `3`. A reader keys on this and not on the length it happens to see |
| 1 | 1 | verdict: `0` forwarded, `1` dropped, `2` a conversation the appliance ended — the same value `epb_verdict` carries |
| 2 | 1 | drop reason, or `0` where no frame was dropped. The numbering is the [`reason` label's](metrics.md) order, counting from one |
| 3 | 1 | interface id, the same value the block's own `interface_id` names |
| 4 | 1 | direction: `0` inbound, `1` outbound |
| 5 | 1 | flow classification: `0` no flow, `1` new, `2` established, `3` related |
| 6 | 1 | the event, `0` for none — the vocabulary below |
| 7 | 1 | the flow's state after the packet, `0` where there is no flow. The numbering is the [`state` label's](metrics.md), counting from one |
| 8 | 4 | the **configuration generation** the decision was made under |
| 12 | 4 | the flow's slot |
| 16 | 4 | which occupant of that slot |
| 20 | 2 | the matched rule's **position** plus one, or `0` for no rule matched |
| 22 | 2 | zero |

**A flow is named by the pair, never by the slot alone.** Slots are reused as connections come and
go, so across a recording holding hours of history a bare index would silently merge two unrelated
conversations that happened to occupy one slot at different times — and the merged record would look
ordinary and be wrong. Fold records by the pair.

**The rule is a position, not the id you wrote.** Position is what the dataplane has: it is the
rule's precedence and the slot its counter occupies. `librefirewall_rule_hits_total` is labelled with
the id from the configuration document, and the document's own order is what joins the two — the
rule at position 0 is the first rule the document declares.

**Which combinations occur, and which cannot.** These hold on every record, and a reader may rely on
them:

- a forwarded record carries no drop reason, and a dropped one always carries one;
- an open, an advance, a close and a revocation always name a flow; a refusal and a policy decision
  may not;
- a **close always names a state a conversation does not leave** — `time_wait` or `closed` — so a
  close always says *how* it closed;
- an open is classified `new`; an advance and a close are classified `established`;
- **a rule appears on exactly two events**, an open and a policy deny, because the filter is
  consulted once per conversation — on the packet that opens it. An advance, a close and a refusal
  all happened with no rule involved, and a rule on one of them would credit a hit to a rule that
  never ran.

### The event vocabulary

| event | value | what it means |
|---|---|---|
| — | 0 | no event; the record belongs to the capture alone |
| `flow-opened` | 1 | a conversation was opened and the filter admitted the packet that opened it. The rule that admitted it is named |
| `flow-advanced` | 2 | an existing conversation changed state without ending |
| `flow-closed` | 3 | it reached a state it does not leave. The state says how: `time_wait` for a completed close, `closed` for a reset |
| `policy-denied` | 4 | a rule matched the packet the filter was asked about and its action is to drop. Where that packet opened a conversation, the flow it had just opened was withdrawn |
| `policy-no-match` | 5 | no rule was about the packet the filter was asked about, so the default deny refused it. Where that packet opened a conversation, the flow it had just opened was withdrawn |
| `flow-refused` | 6 | the connection tracker refused the packet outright, so it never reached the filter. The drop reason says which refusal |
| `flow-revoked` | 7 | a policy commit no longer admits a conversation it had admitted, so the appliance ended it. **The one record that is about no frame** — see below |

**The two policy records are not only about openings.** Two things reach the filter: a conversation
opening, and traffic an existing conversation is the reason for without belonging to it — today an
ICMP error quoting one of its datagrams. Both are refused under the same two records, so a
`policy-no-match` may be a conversation the policy would not start *or* an error it will not carry.
The record's classification tells them apart: `new` for the first, `related` for the second. An
error opens no conversation, so nothing is withdrawn when one is refused and the conversation it
reported on is untouched.

A related packet the policy **admits** is a different matter: it changes no conversation, so the
connection history holds no record of it at all and the capture is where it appears — with its
`related` classification and its forwarded verdict, and the rule that admitted it named in
`librefirewall_rule_hits_total`.

Three things the vocabulary does not say, and an operator will otherwise infer wrongly.

**A revocation is about a conversation and about no packet, and says so in every field pcapng has
for one.** Nothing was on a wire, so the block carries no captured bytes, states a wire length of
zero — which no frame the appliance reaches a verdict on can have, having parsed as IPv4 over
Ethernet — carries no `epb_flags` and no classification, and names no rule. What it *does* carry is
the flow it ended and the state that conversation was in when the commit reached it, so it folds onto
the record that opened the conversation by the same (slot, occupant) pair every other record is
folded by. It appears in the connection history alone: a capture is the frames themselves, and this one was
on no wire.

That is the honest shape rather than the convenient one. Writing a plausible frame into the block
would have put a fabricated cause into an artifact that is evidence; omitting the record would have
left the connection history silent about the one way a conversation ends that an operator asked
for. A reader that does not know this layout sees a zero-length packet, which is what "no packet"
looks like in a format whose every record is a packet.

**A refusal names no flow.** A packet the tracker refused is one it keeps no state for, so there is
no conversation to name — including for the two refusals that are *about* an existing flow, a
segment outside its window and one its state does not admit. What locates such a record is the
five-tuple in the causing packet's own headers, which the record carries.

**A conversation that times out produces no close.** Almost every record is anchored to the packet
that caused it, and a flow reclaimed by its idle timeout has no such packet. What states a timeout is
`librefirewall_flow_expired_total` in a [metric reading](metrics.md). A revocation is the one record with no
causing packet that *is* written, and the paragraph above says how it is written honestly; a timeout
has no such record.

- **A Custom Block of padding** fills whatever the encoder must leave empty to keep every write to
  the device a whole sector: the rest of a segment when one is sealed, and the rest of the open
  sector behind every counter block and every
  console-transcript block below. A recording therefore carries padding in its interior and
  not only at a segment's end — in the connection history, one block of it after each of those two, which is
  why that file holds roughly a sector per console line. It is skipped by any reader that does not
  know the PEN, and by `tcpdump`.
- **Why those two are padded and a packet is not.** The header each extent carries states how far
  the recording is durably written, and it can only state a whole sector, because a sector is what
  the device takes. A block ends where its length ends. So a reader working from a recovered disk —
  which has nothing but the extent and that header — can be pointed at a byte inside a block, and
  meet a final block claiming more bytes than are there. Padding the two blocks that are written
  when nothing else is happening keeps the header pointing at a block boundary in the case that
  would otherwise be the common one. It does **not** hold generally: a packet block is not padded,
  one sector per frame being a cost a capture cannot carry, so between those points the position
  the header states can still fall inside a packet block. A reader following the recording upstream
  is not exposed to this, being handed the bytes as a stream. It is the direct reader of the medium
  — a recovered disk, a forensic copy — who must be prepared for a short final block.
- **A Custom Block of counters** appears in the connection history about once a second, carrying the whole
  metric surface as it stood at one instant. It shares the block type and the enterprise number with
  the padding above and is told apart by the first byte of its data: **empty data, or a leading zero
  byte, is padding**, `1` is a metric reading and `2` is a console transcript. Its layout is in
  [the channel framing contract](../contracts/channel-framing.md#metric-snapshots), which is where
  the management server reads it from. What it holds is exactly the closed catalogue —
  [every counter and gauge series of the twelve shards](metrics.md), in the order that page lists
  them — and not the two families whose members depend on the running configuration: there is no
  per-interface information and no per-rule hit count in a recording, because neither has a fixed
  place in the catalogue to occupy. A reader that does not recognise the PEN skips these exactly as
  it skips the padding, so a recording carrying them opens in `tcpdump` unchanged.
- **A Custom Block of console lines** appears in the connection history carrying a batch of the lines the
  appliance printed on its serial console, byte for byte as it printed them, each with the
  protection-domain ring it was drained from and the instant it was emitted at. Its kind byte is `2`
  and its layout is in
  [the channel framing contract](../contracts/channel-framing.md#console-transcript). It is what a
  management server stores as this appliance's log, and it is the same text an operator watching the
  console reads — the appliance renders each record once and puts the bytes on both surfaces. A
  recorded transcript is a **subset** of a printed one: the console never waits on the domain that
  writes the medium, so lines it cannot take are dropped and counted on
  `librefirewall_console_transcript_lines_total`, and the earliest lines of a boot are the ones most
  likely to be missing.
- **The PEN is `0xFFFFFFFF`, and it is nobody's.** No registered Private Enterprise Number stands
  behind these annotations. The value is IANA-reserved so it can never collide with a real
  assignment, but it identifies no one, and a reader must not treat a PEN-tagged option in these
  files as a stable identifier until a registered number replaces it.
- **Neither an Interface Statistics Block nor a Decryption Secrets Block appears.** `epb_dropcount`
  is therefore the whole of what a file says about its own loss, and it says one thing: what the tap
  ring dropped. A recording the encoder or the medium lost records from reads exactly like one that
  lost none, so the loss families under [the two recordings, and the reads served out of
  them](metrics.md#the-two-recordings-and-the-reads-served-out-of-them) are the other half of
  the account, and a recording is read beside the readings inside it rather than by its packet
  blocks alone.

## What the two recordings hold

**the capture holds every observation of a frame, with its verdict.** Every frame the appliance
reached a decision about is a record, and every record carries the annotation above: allow or deny, the reason,
the rule where one matched, and the conversation it belongs to. It keeps up to 2048 bytes of each
frame, which is the whole of every frame a dataplane link carries at a standard MTU.

**the connection history holds a record only where the appliance reached a lifecycle or policy event** — a
conversation opened, advanced, closed or revoked, a policy refusal, a tracker refusal. Its records of
*frames* are therefore a subset of the capture's, relatable to them one for one by `epb_packetid`, and
it holds **no record for a packet that caused no event**: traffic on a conversation already accounted
for, and frames refused by admission or routing, are in the capture alone. The revocation runs the
other way — it is in the connection history and in no capture, there being no frame to capture.

That selection is the point of there being two files, and the reason is a rate. A record per
connection admitted is three to four orders of magnitude below a record per packet, so a connection
history stays usable under exactly the conditions it is wanted in — a flood that produced a record
per packet would evict the whole history in seconds and blind the file at the moment of the attack.

**It keeps 128 bytes of each causing packet, and that number is derived.** It is the whole L2–L4
header chain and nothing of the payload: the longest chain this appliance ever decides on is an
Ethernet header, an 802.1Q tag, an IPv4 header (options are refused, not skipped) and a TCP header
with a full option area — 98 bytes. A record is evidence about a *decision*, and carrying traffic is
the capture's job.

Four further limits an operator will otherwise infer wrongly:

- **Only the dataplane is recorded.** The management port is not tapped, so nothing on it —
  including the channel carrying the recordings themselves — appears in either file.
- **One observation per frame.** A forwarded frame is recorded once and not once per direction, so
  every `epb_flags` reads inbound. `epb_packetid` is minted and monotone, and there is never a
  second record of one frame to relate within a file — the pairing it serves is between the two files.
- **Some frames are counted and deliberately absent from both.** A frame no routing decision was
  reached about, one routed out of a port the stage is not wired to, and one recorded as forwarded
  that a later refusal lost are all counted on the dataplane families and encoded in no recording,
  because the tap ABI mirrors the router's drop reasons exactly and has none for them. See
  [the two recordings, and the reads served out of
  them](metrics.md#the-two-recordings-and-the-reads-served-out-of-them) for the reconciliation.
- **A connection's history reduces from its events, and a reader performs that fold.** The rings are
  append-only, so the appliance keeps no one-row-per-connection table; every record carries the flow
  identity and the state as then known, so a conversation whose earlier records have already been
  evicted still reduces to a usable one.
