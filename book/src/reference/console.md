# Console records

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
frame is counted in memory instead (see [Prometheus metrics](metrics.md)).

One record sits at the edge of that and is stated here rather than left to be discovered: the
management port's `frames=`/`bytes=` pair is a *cumulative count of traffic*, emitted per drain and
never per frame. It is on this surface because it is the only evidence **the console** offers that
the management port is receiving at all. It carries no address, no port, no length of any
individual frame and no byte of one, so nothing about a packet is observable through it; what it
says is "this port is up and taking traffic", which is system state. The same counts are scrapable
as `librefirewall_endpoint_frames_total` and `librefirewall_endpoint_bytes_total` in the
[metric inventory](metrics.md).

Everything below is what the renderer writes, field for field. Every record of the grammars below is
one line of at most **228 bytes**, and a line is never truncated — see *Reading records off the
wire* for the two ways a line can nevertheless fail to be one record.

## `LFW-PD` — protection-domain lifecycle

```
LFW-PD time=<rfc3339|unsynchronized> domain=<domain> state=<state>[ features=0x<hex>][ rx-posted=<n>][ tsc-hz=<n> utc=<rfc3339>][ frames=<n> bytes=<n>][ sectors=<n> leading=0x<hex>][ start=<n> sectors=<n>][ aes=proven pclmul=proven preemptions=<n> iterations=<n>][ primitive=<primitive> vectors=<n>][ primitive=<primitive> milli-cycles-per-byte=<n>][ device=<32 hex> generation=<n> onboarded=<true|false>][ fingerprint=<64 hex>][ cleared-generation=<n> cleared-documents=<n> was-owned=<true|false>][[ cause=<token>] signalled=<true|false>[ detail=0x<hex>[,0x<hex>]]]
```

At most one optional group appears, decided by the state. `domain=` is one of **`forwarder`**,
**`nic-driver`**, **`config`**, **`console`**, **`clock`**, **`management`**, **`recorder`**,
**`hardware-probe`**, **`crypto`**, **`store`** — the domain names in the Microkit system
description, ten tokens against twelve domains because the driver runs as three instances that
share one token. **A `nic-driver` record therefore does not say
which port it is about**, and nothing on this surface does: three instances publish into three rings
the console interleaves, so the driver's records are not one port's transcript. `/metrics` is where
the instances are separate, as `domain="nic_driver0"`, `1` and `2` (see
[Prometheus metrics](metrics.md)). `state=` is one of **`starting`**, **`negotiated`**, **`ready`**,
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
| `management` | `starting`, then `ready`, then a further `ready` on **every drain that took at least one frame** — and **never** `refused`. It additionally emits `LFW-CFG rejected=` for a committed configuration it will not read | the repeated `ready` carries `frames=` and `bytes=`; the first carries no tail. A `ready` carrying the refusal group instead is one of the three narrow refusals this domain reports without declining to start |
| `recorder` | `starting`, `negotiated`, then **three** `ready` records — or `starting` then `refused` | `negotiated` carries `features=`; the first `ready` carries `sectors=` and `leading=`, and the two after it carry `start=` and `sectors=`, one per recording, which is the only place an operator learns where a recording is |
| `hardware-probe` | `starting`, then `ready` **or** `refused` | `ready` carries `aes=proven pclmul=proven preemptions=` and `iterations=` — the first domain compiled with the SIMD target reporting that AES-NI and PCLMULQDQ answered their known answers on every pass and that a live XMM value survived that many preemptions; `refused` carries the refusal group |
| `store` | `starting`, `negotiated`, then **two** `ready` records — or `starting` then `refused`. A boot that honoured a **factory-reset request** emits a second `negotiated` between them | the first `negotiated` carries `features=`; a second, where there is one, carries `cleared-generation=`, `cleared-documents=` and `was-owned=`, which is what a reset destroyed. Then the first `ready` carries `device=`, `generation=` and `onboarded=`, and the second carries `fingerprint=`. Those two are the only place an operator learns which appliance this is and which key it authenticates with, there being no shell and no CLI. `refused` carries the refusal group |
| `crypto` | `starting`, then a run of `negotiated` records, then `ready` — or `starting` then `refused` | the first `negotiated` carries `features=`, the CPUID words the part was accepted on; then one per primitive carrying `primitive=` and `vectors=`; one per per-byte measured primitive carrying `primitive=` and `milli-cycles-per-byte=`; one per per-operation measured primitive carrying `primitive=` and `cycles-per-operation=`; then the session it established against itself, as `tls-version=` with `tls-suite=`, `tls-group=` with `tls-echoed=`, and `peer-device=`; then two `arena-bytes=` with `arena-bound=` records, the first the peak a session held against what the arena has and the second what a deliberately starved session was left with against what one phase needs. The single `ready` carries no tail: what it means is that every record before it held. `refused` carries the refusal group |

`console` is the domain that owns the serial device and renders every other domain's records, which
makes its two records mean something different from the rest: they are the console reporting that it
can report. Both are written *through the device it has just programmed*, so the first of them is
also the proof that there is a console at all. The absence of `refused` is not an omission — it is
the shape of the failure. A console that cannot program its controller has no way to say so, the
reporting mechanism being what failed, so **a node whose console never came up is silent rather than
apologetic**: no `LFW-PD domain=console` record, and no other record either, because nothing drains
the rings the other domains are publishing into.

An entirely empty serial line after the boot manager's `LFW-BOOT` record is therefore ambiguous, and
not in the way it first reads: the same silence is what a node that never reached userspace at all
looks like, because on the release kernel nothing between GRUB and the console domain can print. The
two are not distinguishable **on this surface**. A [`/metrics`](metrics.md) scrape is what separates
them, and it separates three cases rather than two:

- **It answers, and `librefirewall_uart_init_failures_total` is non-zero.** The controller refused
  its initialisation. The domain got far enough to say so — its shard is its own to write even when
  the line is not — so a refused console is a reading rather than a silence. What it does not say is
  *which* refusal: the driver distinguishes six ways for the register sequence to fail and the one
  counter holds none of them apart.
- **It answers, and the whole console shard is zero.** Nothing was refused and nothing was printed.
  Two states look like that and the shard cannot part them: an I/O-port capability that was not what
  the domain expected, where no controller was addressed and so nothing truthful can be written, and
  a domain that never ran at all.
- **It does not answer.** Userspace is not up, or the management port is not, and every possibility
  above is still open.

Parting the states a zero shard cannot part is an external act — attaching a debugger, or booting the
debug profile, whose kernel narrates its own start-up. In the QEMU gate that act is automated: a
scenario that fails on the release image is re-run once on the debug kernel by `xtask`'s diagnostic
re-run, which reports the empty release capture as the expected silence of a kernel built without
`CONFIG_PRINTING` rather than as a second fault, and surfaces the debug boot's serial output beside
it. That is a harness convenience for the project's own test scenarios, not a channel on a deployed
node: an operator holding a silent appliance still has only the external act.

- `time=<rfc3339|unsynchronized>` — when the emitting domain emitted this record, or that it had no
  time to give it. Every record of this channel and of `LFW-CFG` carries it, first among the fields;
  [Ordering and time](observability.md#ordering-and-time) says what it is worth and what it is not.
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
  the domain's life**. They are the management port's, and they are counts of what arrived — never
  any part of a frame, no payload byte ever reaching this surface. The pair travels together because
  a frame count with no byte count cannot be told from one carrying nothing.

  **This is a record about system state, not a traffic log.** It says "this port is receiving" and
  the numbers are the evidence; it is emitted once per *drain* that moved a frame, never once per
  frame, so a burst of a hundred frames produces as few records as the scheduler allows and a reader
  must not infer a frame boundary from a record. The same counts are scrapable as
  `librefirewall_endpoint_frames_total` and `librefirewall_endpoint_bytes_total` on
  [`/metrics`](metrics.md).

  **Everything else that port knows about itself bypasses this surface**, and the list grew when the
  port became an addressed endpoint: descriptors naming a span outside the pool, returns the pool
  owner's ring would not take, and every outcome the endpoint distinguishes — ARP replies and echo
  replies sent, frames not addressed to it, each reason a frame went unhandled, malformed frames, and
  replies it composed and could not send. So `frames=` and `bytes=` say the port is *receiving* and
  nothing on the **console** says whether it is *answering*: that is readable on
  [`/metrics`](metrics.md) — the `librefirewall_endpoint_*` families — and asserted by the QEMU gate
  against the wire.

  `management` never reports `refused`, and unlike the console's silence that is not the shape of a
  failure: the domain has no device to answer it and no build datum to judge, so there is no third
  outcome for a refusal to name. It reaches its event loop or it faults, and a fault is the Microkit
  monitor's to report. **An unaddressed port is not a refusal either** — before the first commit, and
  under a configuration that disables the interface, the port takes frames and answers nothing, which
  is `ready` with a rising count and no reply on the wire.
- `sectors=<n> leading=<0x…>` — what a domain established about the **block medium** under it:
  the capacity the device claimed, in 512-byte sectors and decimal, and the first eight bytes it
  actually returned from sector 0, little-endian and hexadecimal. The pair travels together because
  either alone proves less — a capacity is volunteered before a byte crosses, and eight bytes say
  nothing without the size of what claims to hold them — so together they are the one line saying
  the path to the medium works rather than merely that a device answered a handshake.

  **The eight bytes are an integer and never rendered as text** — no payload byte ever reaches this
  surface. They are a sector this appliance did not write, so they are not its data; they are
  carried at all because an operator reading a partition signature or a filesystem magic off them
  can tell a device that answered from one that returned a driver's own untouched buffer. Nothing in
  the appliance reads them back.

  This is the **device** under the recordings and not a recording: it is emitted once, on the first
  `recorder state=ready`, and the two records after it name the extents. It is not the payload
  exception — no byte of a recording reaches the console, on which nothing about recorded *traffic*
  ever appears.
- `start=<n> sectors=<n>` — where one of a domain's **recordings** lives on that medium: the first
  512-byte sector of its extent and how many sectors it spans, both decimal. One record per
  recording, in the order the domain brings them up — log first, then capture — and they follow the
  `sectors=`/`leading=` record on the same `state=ready`.

  This is **the only way an operator learns where a recording is.** There is no shell and no CLI,
  the extents are compiled in rather than configured, and nothing else on any surface
  states them: `/metrics` says how much a recording has written, never where. A reader taking an
  extent off a decommissioned disk needs these two numbers and gets them nowhere else.

  The key is `sectors=` on both records and it means two different things — a capacity on the first,
  an extent length on the rest — which is exactly why the pairing rule at the top of this section
  matters: read `sectors=` with the key beside it, `leading=` or `start=`, never alone.
- `device=<32 hex> generation=<n> onboarded=<true|false>` — **which appliance this is**, and how
  far its persistent state has advanced. The identifier is 128 bits the appliance drew for itself
  on its first boot, rendered as exactly 32 lowercase hexadecimal characters — the certificate
  profile's one rendering, the same string that is the subject common name of everything this
  appliance's identity appears in. `generation=` is the state record's own counter, which advances
  by one on every durable commit and never goes backwards; `onboarded=` says whether a management
  plane has adopted the node.

  The three travel together because none of them answers the operator's question alone: an
  identifier without a generation cannot say whether the appliance came back or was just minted,
  and a generation without the owner flag cannot say whether it has been adopted. **The same
  identifier on two boots is the appliance having survived the reboot**, and it is the only place
  that shows: nothing else on any surface carries the identifier, `/metrics` reporting whether there
  *is* an identity and never which one.
- `fingerprint=<64 hex>` — **the key this appliance authenticates with**: SHA-256 over the
  DER-encoded `SubjectPublicKeyInfo` of its public key, rendered as exactly 64 lowercase hexadecimal
  characters with no separators. It follows the `device=` record on the same `state=ready`.

  This is the **one** rendering of a fingerprint anywhere: the onboarding page and the management
  application display the same 64 characters, and an administrator compares two of them character
  for character. A second rendering — colons, upper case, a truncation, or the digest split across
  two records — is a defect and not a formatting choice, because two fingerprints that have to be
  mentally normalised before comparing are two fingerprints that will be compared carelessly.

  It is over the public *key* and not over a certificate, so the fingerprint verified at first
  contact still names the appliance after a certificate is issued to it. **No private key material
  appears here or on any other surface.**
- `cleared-generation=<n> cleared-documents=<n> was-owned=<true|false>` — **a factory reset
  happened, and this is what it destroyed.** The record is written in the past tense throughout and
  says nothing about the appliance that replaced the one it describes; the `device=` and
  `fingerprint=` records that follow are that. It appears on no other boot at all, so a node showing
  it is a node somebody asked to give up its owner — the request is one sector of a medium, and
  writing it needs the medium in hand.

  `cleared-generation=` is the generation the destroyed record stood at, which is where that
  appliance's state history ends. `cleared-documents=` is how many configuration versions went with
  it. `was-owned=` says whether there was an owner to give up, and so whether a delivered
  certificate, a trust anchor and an endpoint were among the bytes destroyed — an unowned
  appliance's reset destroys only what it minted for itself.

  **All three read zero and `false` where the medium carried no record this build could read**, which
  is a state a reset is honoured over rather than refused for: a record the appliance will not act on
  is exactly the case an operator reaches for a reset to fix. The count describes the versions that
  were lost and not the sectors that were written — the whole slot array is overwritten either way,
  because deciding which sectors held a secret from the record being destroyed would be trusting it
  one last time.
- `cause=<token> signalled=<true|false>[ detail=…]` — the refusal. **`cause=` may be absent**: a
  domain may refuse without naming a token, and an empty token takes its whole key with it rather
  than writing `cause=` with nothing after it, which is the one shape a reader looking keys up
  cannot read. `signalled=` is always written, so the refusal group is recognised by that key and
  never by `cause=`. `signalled` says whether the device was told to stop (`STATUS_FAILED` written)
  or was left decoding nothing, which depends on whether its BAR had been placed when the rejection
  happened. `detail=` carries up to two numbers, hexadecimal, in the order the token names them, and
  is omitted where the token is the whole of the fault. Two is the line's budget rather than an
  arbitrary cut: a refusal with more to say keeps the pair that identifies it, and what it left out
  is recorded at the code that dropped it.
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

## `LFW-PD` refusal causes

Every `cause=` token is listed below and the seven tables together are the complete set: 23 the
`nic-driver` domain raises, 25 the `clock` domain raises, 6 the `management` domain raises, 39
the `recorder` domain raises, 11 the `hardware-probe` domain raises, 33 the `crypto` domain
raises, and 51 the `store` domain raises. A token outside all seven is a defect, not an extension.
The `forwarder` and `console` domains raise none, having no
`refused` record.

**`nic-driver` and `recorder` share eighteen tokens, and `domain=` is what tells them apart.** Both
are virtio 1.0 PCI device classes and both run the same handshake in the same order, so a
capability chain that is malformed, a BAR that is not 64-bit, a reset that is not acknowledged and
a doorbell outside the window are the same fault twice — described by two independent crates
(`nic_driver_core::bringup` and `lfw_blk::bringup`, which share no code) that arrived at the same
names because the names are the specification's. Renaming one side to make the sets disjoint would
make a reader learn two vocabularies for one fault. **Read the token with the domain**, never
alone: `not-virtio-net` and `not-virtio-blk` are the two that already differ, and they differ
because the *identity* being checked differs.

A shared token is the same fault, and **`detail=` under it need not be the same pair**: the operands
are each domain's own, listed against the token in that domain's table. `queue-absent` is the one to
watch — the index of the missing queue on `nic-driver`, the offered and required queue counts on
`recorder` — so read the numbers against the table for the domain the record names, never against
the other one.

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

**`management`.** Five tokens, and the three groups differ in what they mean for the domain.

The first two are a **`state=refused` record and the domain's last act**: without a per-boot secret
its transport's initial sequence numbers would be predictable, and a predictable one lets an off-path
attacker inject into a connection it cannot see (RFC 6528). So the domain refuses to start rather
than answering a connection weakly, and the management port stays unaddressed for the boot. Read
either of them as "this node has no management port at all until it is rebooted on hardware that
answers".

The next two ride on a **`state=ready`** record instead, and mean something much narrower: the clock
domain published a calibration this domain will not convert readings with, so the port answers ARP
and ICMP echo — neither needs a time — and refuses TCP, counting each segment as unclocked. They are
reported once per calibration rather than once per frame.

The fifth also rides on **`state=ready`**, and is narrower still: the endpoint's streamed-target
table would not take both recording targets, so `GET /logs.pcapng` and `GET /capture.pcapng` answer
`404` while everything else on the port — ARP, ICMP echo, TCP, `GET /metrics` — serves normally. It
is a **build fact rather than a run-time condition** (the table is a fixed size), so it is stated
once at bring-up and never again, and the port carries on rather than refusing to start. An operator
seeing it should read it as "this image cannot serve its recordings", not as a fault in the recorder,
which is unaffected and still writing them to the medium.

`signalled=` is always `false` on all five: no device was told to stop, because none was told
anything.

| group | tokens |
|---|---|
| the per-boot secret (a `refused` record; the domain does not start) | `rdrand-not-supported` (the `CPUID.01H:ECX` word read), `rdrand-exhausted` (which of the two 64-bit draws failed) |
| the published calibration (a `ready` record; TCP alone is refused) | `clock-not-published` (no `detail=`), `clock-implausible-frequency` (the hertz refused), `clock-implausible-epoch` (the nanoseconds refused) |
| the recording targets (a `ready` record, no `detail=`; the port serves everything else) | `recording-targets-unregistered` |

**`recorder`.** Its first token is the domain's own, raised before the device is touched at all. The
four groups after it are `lfw_blk`'s bring-up tree, which is `nic-driver`'s with the differences a
block device makes: `not-virtio-blk` for the identity, `device-read-only` and `capacity-zero` for
two facts only a block device has, the `device-cfg-` tokens for the structure `capacity` is read
from, `queue-size-zero` where a NIC names an absent queue by index, and no transmit queue at all.
Then comes the boot-time proof of the path to the medium, which has no counterpart on any other
domain; and last the two recordings, refused after the device is up and running.

`signalled=` is `true` where the bring-up tree wrote `STATUS_FAILED`, exactly as on `nic-driver`.
Every token in the proof group carries `signalled=false`: the device is past `DRIVER_OK` by then and
is deliberately left running, so a later milestone can retry it without a reset. **The two recording
tokens are the exception to read carefully** — they carry `signalled=true` while leaving the device
running exactly as the proof group does, so on those two the flag is not a statement about the
controller's status byte and there is nothing in it for an operator to act on. The token is the
whole of the refusal there.

| group | tokens |
|---|---|
| staging region (`signalled=false`; `detail=` is the rejected address, `0x0` meaning the `setvar` is missing or misspelled in the system description) | `staging-region-dma-base` |
| capability chain (no `detail=`) | `no-capability-list`, `malformed-capability-list`, `structures-across-bars`, `invalid-structure-bar`, `missing-virtio-structure` |
| identity and BAR placement | `not-virtio-blk` (vendor, device), `structures-outside-bar` (window), `common-cfg-misaligned` (offset, required), `device-cfg-outside-bar` (offset, window), `device-cfg-misaligned` (offset, required), `bar-not-64-bit` (bar), `bar-index-out-of-range` (bar), `bar-has-no-high-half` (bar), `bar-target-unusable` (paddr) |
| handshake | `reset-not-acknowledged` (status), `no-virtio-1` (offered features), `device-read-only` (offered features), `features-rejected` (status), `capacity-zero` |
| the queue and its doorbell | `dma-region-unusable` (paddr), `queue-absent` (offered, required), `queue-size-zero` (index), `queue-too-small` (device maximum, required), `doorbell-outside-bar` (slot end, BAR size — or BAR size alone where the offset overflowed), `doorbell-misaligned` (offset) |
| the proof of the medium (`signalled=false` throughout; `detail=` numbers are hexadecimal like every other refusal's, so a byte count reads as `0x200`) | `block-device-too-small` (capacity, sectors needed), `block-probe-refused` / `block-witness-refused` (which submit refusal, as a small code), `block-probe-silent` / `block-witness-silent` (the poll budget spent), `block-probe-misattributed` / `block-witness-misattributed` (no `detail=`), `block-probe-failed` / `block-witness-failed` (the outcome, `0x1` device error, `0x2` unsupported, `0x1nn` an undefined status byte `nn`), `block-probe-short` / `block-witness-short` (bytes moved, bytes asked for) |
| the recordings on it (`signalled=true` throughout, and see above for what that does not mean) | `recording-extent-unusable` (the numbers the geometry rule that refused names: the extent's first sector and the device's capacity, or one count of sectors, bytes or segments), `recording-sink-unusable` (no `detail=`) |

**`hardware-probe`.** The first three groups are the CPUID feature gate, run before the first probe
instruction: a part below the product's compile-time CPU baseline refuses with the feature word an
operator compares against the part's documentation, rather than taking an invalid-opcode fault on
first use. The gate is best effort by nature — the compiler may place a compile-time-enabled
instruction before it, and such a part faults instead of refusing — so a refusal here is the
orderly form of the same diagnosis. The last group is the probe itself: an instruction that
executed and answered wrongly, or a live XMM value that did not survive a context switch, each
carrying the observed 128-bit value as its two 64-bit halves, low half first. `signalled=` is
always `false` on this domain: there is no device here to be told anything.

| group | tokens |
|---|---|
| the XMM feature gate (`detail=` is `CPUID.01H:ECX`, except `sse2-not-supported`, whose word is `CPUID.01H:EDX`) | `ssse3-not-supported`, `sse41-not-supported`, `sse42-not-supported`, `aes-not-supported`, `pclmulqdq-not-supported`, `sse2-not-supported` |
| the structured-feature leaf (`detail=` is `CPUID.0H:EAX` for the first and `CPUID.07H.0H:EBX` for the second) | `cpuid-leaf-seven-unavailable`, `adx-not-supported` |
| the probe (`detail=` is the observed value's two 64-bit halves, low first) | `aes-known-answer-mismatch`, `pclmul-known-answer-mismatch`, `xmm-pattern-corrupted` |

**`crypto`.** The first two groups are the same CPUID feature gate the hardware probe runs, for the
same reason and on the same best-effort terms: this domain is compiled with the same SIMD target, so
a part below the baseline must be refused rather than faulted on. The third is a primitive that
disagreed with a published test vector on this hardware — the gravest refusal this appliance has,
because it means an adopted cryptography library is wrong here whatever it does elsewhere — and its
`detail=` is the position of the row in that primitive's committed table, which is where to look
first. The fourth is the hardware entropy source. `signalled=` is always `false` on this domain:
there is no device here to be told anything, and no refusal here carries a byte of key material or
of a vector's contents.

| group | tokens |
|---|---|
| the XMM feature gate (`detail=` is `CPUID.01H:ECX`, except `sse2-not-supported`, whose word is `CPUID.01H:EDX`) | `ssse3-not-supported`, `sse41-not-supported`, `sse42-not-supported`, `aes-not-supported`, `pclmulqdq-not-supported`, `sse2-not-supported` |
| the structured-feature leaf (`detail=` is `CPUID.0H:EAX` for the first and `CPUID.07H.0H:EBX` for the second) | `cpuid-leaf-seven-unavailable`, `adx-not-supported` |
| a published vector this build does not answer (`detail=` is the row's position in that primitive's table) | `sha-256-vector-mismatch`, `hmac-sha-256-vector-mismatch`, `hkdf-sha-256-vector-mismatch`, `chacha20-vector-mismatch`, `chacha20-poly1305-vector-mismatch`, `aes-256-gcm-vector-mismatch`, `chacha20-drbg-vector-mismatch`, `ecdsa-p256-vector-mismatch`, `x25519-vector-mismatch`, `ml-kem-768-vector-mismatch` |
| the hardware entropy source (`detail=` is the CPUID word for the first and the failing draw's index for the next two; the last carries none) | `rdrand-not-supported`, `rdrand-exhausted`, `rdrand-output-stuck`, `generator-repeated-a-draw` |
| the session the domain establishes against itself (none carries a `detail=`) | `tls-handshake-refused`, `tls-session-stalled`, `tls-peer-unauthenticated`, `tls-peer-certificate-wrong`, `tls-application-data-lost`, `tls-session-not-closed`, `tls-identity-unbuildable`, `tls-arena-exhausted` |
| the bounded allocator's own proof (`detail=` is the refusal count for the first and the headroom that was left for the last; the middle carries none) | `arena-allocation-refused`, `arena-starvation-unreachable`, `starved-session-established` |

**The last two groups are what a boot's TLS proof says when it does not hold**, and they divide the
same way the proof does. A `tls-*` token means the session itself did not establish or did not stay
established — a handshake the library refused, a peer whose certificate was not the one this domain
issued it, application data that did not come back, a stream that ended without its closing alert.
An `arena-*` token means the *bound* did not behave: `arena-allocation-refused` says an allocation
was answered no, which the session's own headroom check exists to make unreachable;
`starved-session-established` says a session ran to completion on an arena that should not have
admitted it, which would mean the guard is not guarding; and `arena-starvation-unreachable` says
the domain could not set up that starved case at all. All three are findings about the mechanism
rather than about a cipher.

**`store`.** Grouped by the step that refused, and the token's own prefix names it: `staging-` and
`store-medium-` the device and the grant under it, `state-` a transfer of the record, `reset-` a step
of a factory reset, `stored-` a record the medium carried that this build will not act on, `rdrand-`
and `generator-` the randomness a key would descend from, and the rest the identity holding to
itself. `signalled=` is `false` only on the first — every other refusal happens with the device live,
having been told to run.

| group | tokens |
|---|---|
| the staging grant (`detail=` is the rejected address, `0x0` meaning the `setvar` is missing or misspelled in the system description) | `staging-region-dma-base` |
| the medium itself (`detail=` is the claimed capacity and the sectors this build's layout needs) | `store-medium-too-small` |
| reading the record (`detail=` is the byte count on the short case and absent on the rest) | `state-read-refused`, `state-read-misattributed`, `state-read-failed`, `state-read-short`, `state-read-unanswered` |
| writing it (same `detail=` rule) | `state-write-refused`, `state-write-misattributed`, `state-write-failed`, `state-write-short`, `state-write-unanswered` |
| the barrier that makes a write durable — **every flush this domain waits for**, whether it orders a minted record or a step of a factory reset (same `detail=` rule) | `state-barrier-refused`, `state-barrier-misattributed`, `state-barrier-failed`, `state-barrier-short`, `state-barrier-unanswered` |
| reading the factory-reset request sector (same `detail=` rule) | `reset-read-refused`, `reset-read-misattributed`, `reset-read-failed`, `reset-read-short`, `reset-read-unanswered` |
| clearing that request, which everything irreversible sits behind (same `detail=` rule) | `reset-clear-refused`, `reset-clear-misattributed`, `reset-clear-failed`, `reset-clear-short`, `reset-clear-unanswered` |
| overwriting what the medium held (same `detail=` rule) | `reset-overwrite-refused`, `reset-overwrite-misattributed`, `reset-overwrite-failed`, `reset-overwrite-short`, `reset-overwrite-unanswered` |
| a record this build will not act on (`detail=` is the length, the slot index, or the stored slot count and slot size, as the token names) | `stored-layout-mismatch`, `stored-certificate-too-long`, `stored-document-too-long`, `stored-slot-named-twice`, `stored-slot-outside-array`, `stored-named-slot-empty`, `stored-record-unusable` |
| an identity that does not hold to itself (none carries a `detail=`) | `stored-scalar-unusable`, `stored-public-key-mismatch`, `stored-certificate-key-mismatch`, `stored-certificate-absent` |
| minting one (none carries a `detail=`) | `device-key-ungenerable`, `onboarding-certificate-unwritable`, `public-key-unencodable`, `certificate-too-long-for-record` |
| the hardware entropy source (`detail=` is the CPUID word for the first and the failing draw's index for the next two; the last carries none) | `rdrand-not-supported`, `rdrand-exhausted`, `rdrand-output-stuck`, `generator-repeated-a-draw` |

Every `stored-` token is a **physically present attacker's**, or a previous deployment's. This is the
one domain whose input arrives on a disk somebody could have written at leisure, so a record that
decodes is not yet a record this appliance may act on: it is checked against the layout this build
compiles against, and then held to itself as an identity. A node refusing here is a node that
declined to sign under a key it cannot prove is its own, which is the outcome to want.

**`store` shares its four entropy tokens with `crypto` and `rdrand-exhausted` with `management`**,
on the terms `nic-driver` and `recorder` share eighteen: each domain seeds its own generator from
the same hardware by the same rules, so a broken `RDRAND` is the same fault in three places and
renaming it per domain would make a reader learn three vocabularies for one part. **Read the token
with the domain.** What differs is the consequence, and it is not the same at all: for `management`
it is a per-boot sequence-number secret, for `crypto` the generator a session keys from, and for
`store` the key this appliance's whole identity descends from.

The three `state-*` groups are one fault three times and the group is what tells them apart, for the
same reason. A refusal under `read` is a boot that learned nothing about the medium; under `write`, a
boot that minted an identity and could not put it down; under `barrier`, one that put it down and
could not make it durable — which is the case that would leave a power cut costing the identity, and
the reason a barrier is issued and waited for rather than implied by the next transfer.

The three `reset-*` groups are the same shape and the difference between them is what an operator is
left holding. `reset-read-*` is a boot that could not learn whether a reset was even asked for, and
it changed nothing: the appliance still has its identity and the request, if there was one, is still
on the medium. `reset-clear-*` is the same — the request is still there, so the reset can simply be
retried — and it is the group whose *absence of consequence* is the point, because the clearing write
is what everything irreversible sits behind. `reset-overwrite-*` is the one that has cost something:
the request is gone and the appliance keeps whatever of its identity survived, so it will not reset
again on the next boot and the medium is to be replaced rather than re-onboarded. There is no
`reset-barrier-*` group; a flush is one kind of failure whatever it orders, and the flushes a reset
waits for report under `state-barrier-*` above.

The primitive names in `primitive=` are `sha-256`, `hmac-sha-256`, `hkdf-sha-256`, `chacha20`,
`chacha20-poly1305`, `aes-256-gcm`, `chacha20-drbg`, `ecdsa-p256`, `x25519` and `ml-kem-768`. What
each is proved against, and what the measured numbers mean, is in the
[cryptography profile](crypto-profile.md).

## `LFW-CFG` — configuration

Three shapes, distinguished by their third key:

```
LFW-CFG time=<rfc3339|unsynchronized> generation=<n> seq=<n> change=<kind> object=<kind> key=<id> field=<name>[ from=<value>][ to=<value>]
LFW-CFG time=<rfc3339|unsynchronized> generation=<n> outcome=<applied|refused|unchanged> changes=<n>
LFW-CFG time=<rfc3339|unsynchronized> generation=<n> rejected=<reason> offset=<n>
```

**Change record** — one per configuration value that moved. An unchanged value produces nothing, so
the volume of a commit is the size of its diff.

- `change=` is **`added`**, **`removed`** or **`modified`**.
- `object=` is **`interface`**, **`neighbour`**, **`management`** or **`rule`**.
- `key=` is the object's `id` from the document — its stable identity, so reordering the document
  produces no records at all. The `<management>` element has none, a document holding exactly one, so
  a record about it reads `key=management`: the two keys are the same word and neither is derived from
  the other. A **`rule`** is the exception and is keyed by its **position**, `key=0` upward.
- `field=` is spelled as the document's own attribute, and is one of **`port`**, **`enabled`**,
  **`mac`**, **`address`**, **`prefix-length`**, **`interface`**, **`id`**, **`ingress`**,
  **`egress`**, **`source`**, **`destination`**, **`protocol`**, **`source-port`**,
  **`destination-port`**, **`icmp-type`**, **`tracking`** or **`action`**. Not every field belongs to
  every object: an `interface` carries `port`, `enabled`, `mac`, `address`, `prefix-length`; a
  `neighbour` carries `mac`, `address`, `interface`; `management` carries `enabled`, `mac`, `address`,
  `prefix-length` — it has no `port`, being no part of the router's port set; and a `rule` carries the
  remaining eleven, which are its `id` and its ten criteria. A pairing outside those is not written.
- **A `rule` reports its own `id` as a field**, which no other object does. Its records are filed
  under its position, because a policy is an ordered list and position is precedence — so the id is
  something a rule *says* rather than what it is, and renaming one is a change to report like any
  other.
- `from=` is absent exactly when the object was added, `to=` exactly when it was removed. A
  `modified` record carries both.
- Values render by their type: `port` and `prefix-length` decimal, `enabled` `true|false`, `mac` as
  `52:54:00:12:34:50` (lower case), `address` as a dotted quad, `interface` as the referenced id.
- Records are ordered interfaces first, then neighbours, then the `management` object, by id within
  each, then by the field order listed above. Two runs over one pair of configurations produce
  byte-identical output.

**Generation outcome** — what a commit or a switch did. `outcome=` is **`applied`** (the generation
is now in force; `changes=` is the size of its whole diff, even where more records were produced
than a buffer could hold), **`unchanged`** (the content was already running, so no generation was
assigned and no change record was written) or **`refused`** (the commit itself could not happen —
nothing was staged, or the counter is exhausted). `refused` carries no reason token because nothing
about the configuration is wrong; a *document* that is wrong is the third shape.

**Rejection** — a document or an offered image was refused, naming where and why and never the
bytes. `rejected=` is one of 36 reasons:

| group | reasons |
|---|---|
| document syntax and hardening bounds (17) | `malformed`, `doctype`, `entity-declaration`, `unknown-entity-reference`, `invalid-character-reference`, `document-too-large`, `depth-exceeded`, `too-many-attributes`, `name-too-long`, `value-too-long`, `unexpected-character-data`, `duplicate-attribute`, `unknown-element`, `unknown-attribute`, `missing-element`, `missing-attribute`, `malformed-value` |
| semantic validation over the parsed model (13) | `duplicate-identifier`, `duplicate-port`, `port-out-of-range`, `prefix-length-out-of-range`, `address-not-a-host-address`, `address-not-unicast`, `mac-not-unicast`, `overlapping-prefixes`, `unknown-interface-reference`, `neighbour-outside-prefix`, `neighbour-is-interface-address`, `duplicate-neighbour-address`, `capacity-exceeded` |
| a filter rule that would match nothing (4) | `prefix-not-canonical`, `port-range-reversed`, `port-criterion-on-icmp`, `icmp-type-on-non-icmp` |
| a configuration the appliance could not state back (1) | `rendering-too-large` |
| an offered image that is not one publication (1) | `handover-not-one-publication` |

`capacity-exceeded` sits in the second group and not the first, which is where a reader expects a
bound to be: a document naming more interfaces, neighbours or rules than the handover image holds
passed every bound its *bytes* are held to, and does not fit the model they parse into.

The third group is its own because those four refusals are not about a value being wrong but about
a rule being *inert*. A port range whose ends run backwards, a port criterion on a rule that names
ICMP, an ICMP type on a rule that names TCP, a block written `10.0.0.5/24` when it covers
`10.0.0.0/24` — each is a line an operator wrote believing it was in force. On an appliance that
denies what no rule matched, the dangerous half of that belief is the `accept` that quietly matches
nothing, so the document is refused rather than committed with a rule that cannot fire.

**The fifth group is the one reason that is not about the operator's document at all**, and it is
its own group for that reason rather than for its size. `handover-not-one-publication` says the bytes
offered in the handover region do not fold to the digest they carry — so they are not one
publication: either the domain that sealed them sealed them wrongly, or the reader's copy was taken
across two of them. The document that was submitted may be perfectly correct, and editing it will not
help. Every other reason on this page is something to go and fix in a document; this one is something
to suspect in the node, and a console vocabulary that filed it under `malformed-value` would be
issuing the wrong instruction rather than merely a coarse one.

The fourth group has one reason and is about neither a value nor a rule but the configuration as a
whole. Reading the running configuration is the first step of changing it, so a configuration whose
own canonical form is longer than a document may be would commit and then be unreadable — an
operator could see it and not edit it. It is therefore refused, and `rendering-too-large` is the one
refusal whose `offset=` is not a position in the document: the number is the length the canonical form
would have taken, and the object it names is `configuration` rather than any entry.

The vocabulary is deliberately coarser than the reader's own fault tree: eighteen distinct
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

**A submitted document produces the same records as the one a build embeds.** Nothing on this channel
says where a document came from, and that is deliberate: what the console carries is the system's
state, and a generation is the same fact however it arrived. So a `POST /config` that commits reads as
its change records, the publisher's `outcome=applied`, and the consumer's `outcome=applied changes=0`
when the dataplane switches — the same three shapes a boot produces, under the next generation number.
A refused submission reads as one `rejected=` record and moves nothing. What distinguishes a submitted
generation from a booted one is the number: generation 1 is the document the image carries, and every
higher one arrived over the management API.

**A configuration change does not change a domain's state.** A refused *submission* leaves the
configuration domain reporting nothing on `LFW-PD`: it is the document that was refused and not the
domain, which is running perfectly well and has just said so by refusing. `config state=refused`
belongs to a domain that could not come up under the document its image carries, and reading it as a
refused submission would be reading a healthy node as a broken one.

## Two things an operator will otherwise read wrong

**A first boot produces two `outcome=applied` records for generation 1.** `LFW-CFG` carries no
domain field, so the pair looks like a duplicate and is not. The publishing domain commits the
document and reports the diff it moved (`changes=<n>`); the forwarding domain later switches to that
generation at a poll boundary and reports only that it is now carrying traffic (`changes=0`). The
diff is the publisher's record; the switch is the consumer's. Seeing only the first means a
generation was committed and never reached the dataplane, which is a fault; seeing both is a
healthy boot. The forwarding domain additionally reports `generation=0 outcome=applied changes=0`
from its own start-up, and that is not a third copy of anything — it is the node stating that it is
running the fail-closed empty table and forwarding nothing until a generation arrives. On the
shipped document the whole sequence is 20 change records — two interfaces of five fields, two
neighbours of three, and the management object's four —
`generation=1 outcome=applied changes=20`, the fail-closed `generation=0 outcome=applied changes=0`,
and `generation=1 outcome=applied changes=0`.

**`offset=` is not always a byte offset.** It is the one number the reason names, and which number
that is depends on which reader refused:

| refused by | `offset=` means |
|---|---|
| the document reader (syntax, hardening bounds) | a **byte offset** into the configuration document |
| semantic validation over the parsed model | always **0** — the refusal names an object, not a position, and a byte offset for it would point at the XML declaration |
| the forwarding domain, over an offered handover image | the **entry index** within the image; for `capacity-exceeded`, either the count the image claimed or the generation number itself, depending on which capacity was exceeded |

Only six reasons can come from the third row — `capacity-exceeded`, `malformed-value`,
`port-out-of-range`, `prefix-length-out-of-range`, `mac-not-unicast`,
`handover-not-one-publication` — the image being an already-validated model rather than text. For
`handover-not-one-publication` the number is neither an entry index nor a count but **the digest the
image declared**, there being no entry to point at in bytes that are not one publication: it is what
a reader comparing two domains' views of the same region has to go on. There is no field distinguishing the rows; what
distinguishes them is that a document refusal is emitted before any generation is offered.

## Reading records off the wire

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
  re-run of a failed scenario (`datad/build/image/*-debug.log`), by `make run`, or from a `make
  image-debug` build, and it is those captures the caveat is about. The kernel prints on boot and on
  faults, never per record, so the interleaving is bounded and occasional rather than routine.
- **What no reader can recover** is a record whose own bytes were split. Nothing in the release
  profile splits one; in debug, a kernel fault report arriving mid-line leaves a fragment with no
  marker on its continuation, and such a fragment matches no grammar above. That is the whole of the
  guarantee available: a torn record fails to parse rather than parsing into something false.
- **A record that will not render is dropped and counted, not reported.** There is no
  `LFW-PD unrendered=…` line and no other escape hatch: a record whose bytes the ABI refuses, whose
  vocabulary token this build does not know, or that will not fit the 228-byte line is counted and
  discarded silently. Those counters are described below and are scrapable on
  [`/metrics`](metrics.md), so an operator reading the console alone cannot tell a record that was
  never emitted from one that was emitted and lost — the metrics endpoint is what can.

## What the console loses, and what counts it

The path from a call site to the line is bounded at every step — encoding the event, publishing it
into a ring, decoding it, rendering it, handing the bytes to the device — and every one of those
bounds is lossy. Each has its own counter, because they accuse different parties. Every counter
below follows the counter semantics stated in [Prometheus metrics](metrics.md) — monotonic for its
domain's life, saturating, no reset — and follows the **attribution** rule stated there: a drop
names who misbehaved, and the three classes never merge. **Every one of them is scrapable**: the
writer-side pair as `librefirewall_log_records_dropped_total` and
`librefirewall_log_records_refused_total`, the console's outcomes as
`librefirewall_console_records_total{outcome=…}`, and the UART's as the `librefirewall_uart_*`
families. None of them appears on the console itself, so the short names below are the metric side's
— underscored, as everything on `/metrics` is, and not tokens of the hyphenated console vocabulary.

| counter | kept by | accuses | what it means |
|---|---|---|---|
| `dropped` | each writing domain | itself, or the console | the ring had no slot, so the **newest** record was refused. A flood, or a console that is not draining |
| `refused` | each writing domain | *our own* invariant | a record this domain minted and never put in its ring: an event the record ABI cannot carry, or a sink already borrowed further up the same stack. Expected to read zero forever |
| `malformed` | the console | the **peer that sent it** | the bytes in the slot are no record at all — the writing domain published something the ABI cannot carry, or wrote a slot it had not been given |
| `unknown` | the console | the **peer that sent it** | the record decoded, but its vocabulary token names no variant this build has: the two halves of the ABI have parted, which means the two domains are different builds |
| `unrenderable` | the console | *our own* invariant | the event decoded and would not fit the 228-byte line. No peer can cause this; it is a defect in this build's renderer, and it is an alert rather than a statistic |
| `write_failed` | the console | the **device** | the controller would not take the line. Console output has been lost, and this is the one counter with nowhere to be reported *to* — the console is the reporting mechanism |
| `printed` | the console | — | lines rendered and handed to the device in full |
| `bytes_written`, `transmitter_timeouts`, `init_failures` | the UART driver | the **device** | bytes handed to the transmitter; bytes dropped because it never reported itself empty; refused initialisations. A non-zero `init_failures` is the one reading a node with no console can still produce — see the silence procedure above |

Two properties of a full ring are worth stating because they are the opposite of what a log buffer
usually does:

- **A full ring refuses the newest record, not the oldest.** The ring carries the boot transcript,
  and when a domain parks the *earliest* records are the ones that say why; dropping the oldest
  would discard exactly those and keep the repetitive tail. This is the opposite bias from the
  `GET /logs` retention buffer (see the
  [local log buffer](observability.md#local-log-buffer)), which drops the oldest because it answers
  "what is this node doing *right now*". Both are bounded and lossy and each counts what it dropped.
- **A writer's drop count is that writer's claim about itself.** It lives in the region that writer
  owns, so it is a number to expose and never one to decide under, and it restarts at zero when that
  domain does — the one discontinuity the counter semantics admit.

## Boot-manager records (pre-kernel)

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
below the seL4 kernel (see the [status page](../status.md)). Both are terminal and both need the
same external action, which is why they share a state; the prose line beside the record says which.
