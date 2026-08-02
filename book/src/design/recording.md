# Recording and persistent storage

The appliance keeps its own durable record of the traffic it handled, on block storage it owns, in a
format an analyst opens without conversion. For the connection and policy events of the
[management plane](management.md) this is not a second copy beside the log transport but the source
beneath it: what is written here is what the exporters ship onward, and it is what remains when
nothing is listening.

## Two sinks, one format

Two independent pcapng streams are written, and the split between them is the design:

- **The log sink** is always on, covers every interface, and applies no filter. It records
  connection lifecycle and policy decisions — a connection opening, each refinement of its protocol
  and application identity, notable events on it such as a threat or a policy deny, and its close —
  and anchors every one of them to the packet that caused it, carrying that packet's L2–L4 headers
  and nothing beyond them. It is **breadth**: every connection the appliance saw, for as long as its
  ring holds.
- **The capture sink** is filtered and records full packet content. It is **depth**: everything about
  a little.

Anchoring a log record to its causing packet, rather than composing an abstract event beside it, is
what makes the log open natively in a pcapng reader: the record renders as a packet list with real
addresses and ports, sortable and filterable with the tools an analyst already has, and needing no
bespoke viewer. A policy may raise the evidence length for the events it generates, up to the full
frame, where what was decided is worth more than the headers it was decided on.

The two sinks are the same encoder, the same ring machinery, and the same download path; only the
ring differs. They are **separate rings because their rates differ by three to four orders of
magnitude** — one record per connection against one per packet — and a traffic burst must not be
able to evict connection history.

## pcapng as the internal representation

pcapng is the representation on the medium, not a format the appliance converts to on export. It is
chosen because it carries more than packets, and a format that carried only packets would force a
second, parallel record beside them that no reader could relate back:

- An **Interface Description Block per NIC** lets one file record every interface, so a single
  artifact holds both sides of a forwarded flow rather than one file per port.
- **`epb_packetid`** correlates the ingress and egress observations of one forwarded frame, so the
  rewrite the appliance applied —
  [translation](architecture.md#address-translation),
  [re-origination](architecture.md#two-data-paths) — is a relation between two records instead of
  something an analyst infers by comparing tuples.
- **`epb_flags`** carries direction and **`epb_verdict`** the verdict, so what the appliance decided
  sits on the packet it decided about.
- A **PEN-tagged Custom Option** carries the structured firewall state for which the format has no
  standard field: zone pair, flow identity, policy identity, application protocol stack, decryption
  status, and risk. A reader that does not know the option ignores it and still sees a valid capture.
- **`epb_dropcount`** and the **Interface Statistics Block** report the sink's own loss in-band, so
  a file is self-describing about what it did not record. A capture that silently omits is worse
  than one that states how much it omitted, because only the second can be reasoned about.
- A **Decryption Secrets Block** carries the TLS key material for the flows in the file, so an
  inspected capture is ciphertext plus keylog rather than plaintext at rest — which is what keeps
  the payload exception of the [management plane](management.md) as narrow as it can be made.

**A mirror port is not a substitute for this, and neither replaces the other** (see
[Port roles](deployment.md#port-roles)). A mirror emits copies of frames and can annotate none of
them: it cannot say within one artifact which interface a frame crossed, cannot attach the verdict
or the flow's application identity, and cannot report what it dropped. It also costs a spare port
and a dedicated machine able to absorb the mirrored rate. The two are complementary — the mirror
for full-rate capture off the box onto hardware built for it, the sinks for annotated recording on
the box with no additional equipment.

## Append-only events, and reduction as a reader's view

The rings are **append-only**: a record, once written, is never rewritten. That is what makes the
writer sequential and cheap and lets a reader work from any point without coordinating with it, and
it dictates how the appliance represents a thing that changes.

A connection's identity is discovered progressively — first the transport, then that it is TLS, then
HTTP/2, then the application protocol carried over it. Each refinement is **a new event carrying the
complete protocol stack as then known**, never a delta against an earlier one. Two properties are
worth that duplication: every event is interpretable on its own, without the reader having seen its
predecessors; and the refinement history is itself evidence, because *when* the appliance learned
what a connection was is frequently the question being asked.

The merged one-row-per-connection view an operator usually wants is therefore **a fold over the
events sharing a flow identity, performed by a reader** — never a mutable table the appliance
maintains. Such a table would have to be updated in place, which an append-only medium does not do
and a partly-evicted ring could not reconcile. Because every event carries the five-tuple and the
stack current at the time, **a flow whose earlier events have already been evicted still reduces to
a usable record**, and a periodic state event re-anchors long-lived connections so a reader's
reconstruction window is bounded rather than growing with a connection's age.

**Flow identity is an (index, generation) pair, never a bare connection-table index.** Slots in the
connection table are reused as connections come and go; across a ring holding hours of history a
bare index would silently merge two unrelated connections that happened to occupy one slot at
different times — and the merge would be invisible, since the reduced record would look ordinary and
be wrong. The generation counter makes reuse explicit and the merge impossible.

**Log events derive from connection-state transitions, not from packet arrival.** The log's rate is
therefore bounded by the rate at which connections are admitted rather than by the packet rate,
which is what keeps it usable under exactly the conditions it is wanted in: a SYN flood that
produced a record per packet would evict the entire connection history in seconds and blind the log
at the moment of the attack. Policy denies create no connection and so have no transition to hang
on; they are **coalesced at their source into counted per-bucket events** for the same reason — a
port scan must cost a bounded number of records, not one per probe.

## One writer, many readers

Each ring has **exactly one writer and any number of independent readers**, each holding its own
cursor. The ring is the single durable copy; a reader is a position in it, not a copy of it. The
readers are the pcapng download of the [management API](management.md), the OpenTelemetry exporter
that ships connection events onward, and a live event stream for an operator console. None is
privileged; adding one adds a cursor and nothing else.

Three properties follow, and they are the reason for the shape:

- **A collector that was unreachable catches up rather than losing data.** External collection is
  routinely delayed and can be unavailable outright (see
  [Management plane](management.md)); with the ring as the durable copy an exporter resumes from
  its cursor instead of dropping what it could not send.
- **A slow or dead reader costs the dataplane nothing.** The writer always wins: it never waits, and
  a reader that has been overtaken detects this on its next read and reports a gap. Loss is
  therefore not merely bounded but *measurable* — the gap is the distance by which the cursor was
  overtaken, a number rather than a suspicion.
- **Delivery to an external collector is at-least-once.** A cursor advances only after the data is
  accepted, so a failure between the two replays rather than skips. Exactly-once would require the
  collector to participate in the appliance's commit, which is not a dependency an inline firewall
  takes on for the sake of avoiding a duplicate.

**Reader cursors live in the ring's own superblock**, so the medium carries the data and the delivery
state together. A node that restarts, or one that
[falls back to its other slot](updates.md#boot-manager-and-slot-selection), resumes every reader
where it stood without a separate store that could disagree with the ring.

**Rings are segmented** into fixed-size units, each beginning with its own Section Header Block and
the full interface set. Any one segment is independently parseable; any contiguous run of segments
is itself a valid pcapng file; a reader that has lost its place resynchronises at the next boundary
instead of scanning; and wrap replaces a whole segment rather than tearing one. The operational
consequence is that **a download of a time range is a byte-range read off the device with no
transformation** — the appliance does not parse, re-encode, or reassemble to serve one, so an
analyst pulling a window costs what reading it costs.

## Storage devices and binding

Block devices are reached by a **first-party virtio-blk driver protection domain, one instance per
device** — the same pattern as the [NIC drivers](deployment.md#nic-drivers-all-rust), where one
driver binary serves several ports as separate PDs. A ring's **extent** is either a whole device or
a named partition on one, resolved at boot.

**How many devices exist, and the capabilities each driver PD holds over them, is fixed in the
system description** and is therefore a per-deployment-target image variant, exactly as the
[NIC count](deployment.md#nic-configurations) is (see
[Configuration](configuration.md#static-hardware-dynamic-configuration)). Which object lives on
which extent is runtime configuration.

**Rate classes are deliberately not mixed.** Configuration and identity are written in bytes per day
and belong on the [boot medium](updates.md#on-disk-layout), so that a node is self-contained. A
capture ring rewrites its device continuously and wants a device to itself: a single sequential
writer per device is what obtains that device's bandwidth, and the write-endurance profiles of the
two workloads are not comparable — sizing a medium for one says nothing about its life under the
other.

**Storage binding is the first configuration item that is not hot-swappable.** Moving a ring to a
different extent invalidates the contents of the one it leaves, so the binding is committed like any
other configuration item but takes effect at the next boot (see
[Configuration](configuration.md#static-hardware-dynamic-configuration)). The exception is confined
to this one item: which sinks are enabled, what the capture sink filters, the evidence length a
policy raises, and retention all apply through the ordinary commit workflow.
