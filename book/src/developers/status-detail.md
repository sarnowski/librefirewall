# Implementation status in detail

What each partial capability in the [status tables](../status.md) already has, and what
specifically remains to finish it — so the work can be picked up without re-deriving it from the
code. The [Engineering foundations](#engineering-foundations) section at the end covers the
machinery every capability lands through.

Every section states what exists and then what is missing. None of them says *done*, and that is
not modesty: the word belongs to the status tables, it is earned by an empty *Missing* here, and no
capability below has one yet.

**Test counts are deliberately not written down here.** A number nobody re-runs is a claim with a
delayed fuse, and this page carried several of them wrong at once. The suite states its own count
whenever it runs and `make coverage` states the current coverage; what a section says instead is
*what* holds a claim up — which tests, which fuzz target, which scenario.

## Routed IPv4 forwarding

**What exists.** Three host-tested `no_std` crates carry the whole decision. `datad/crates/net-headers`
parses Ethernet, one optional 802.1Q tag, IPv4, and the UDP, TCP or ICMP header behind it, and
applies the four edits a hop requires — both MACs, the TTL decrement, and the header checksum —
as one operation that cannot be performed in part. `datad/crates/routing` holds the forwarding table and
answers lookups against it — which interface a port has, which prefix covers a destination, which
neighbour holds a MAC, which addresses are the appliance's own — and reaches no verdict itself.
`datad/crates/pipeline` is the chain that does: link-layer admission first, then the forwarding decision,
then the filter, each a concrete stage called in a fixed order, ending in a verdict that is either a
forward out of a named port under a named MAC pair or one of thirteen named drop reasons, each with
its own counter. The middle stage is no longer terminal: it attaches the egress port and the MAC
pair it worked out to the frame under inspection and defers, so the stage behind it can read where a
frame *would* go without re-deriving it, and the forwarding verdict is composed once, at the end of
the chain, out of a decision taken in the middle of it.
The order is compiled in and the tables the stages consult are data. `pd_runtime::RouteStage` joins
all three to the dataplane — snapshot the frame out of the pool, put it through the chain, rewrite,
and write back the 34 header bytes — and marks every frame it refuses `Verdict::Discard` so the
transmitting driver returns the buffer instead of transmitting it. The table is data rather than
code: the const parameters are capacities, the lengths are runtime values, and the domain is handed
one table and later handed another (see *[Configuration management](#configuration-management)*).

The chain is one value per domain, not one per direction. A `RouteStage` is per direction because
its rings, its pool and its scratch are; the pipeline is owned by the forwarder itself and lent to
each poll, because a stage whose state must span both directions of a flow cannot live inside a
stage that sees one.

Held by unit and property tests across the two crates, by the stage's own tests in
`datad/crates/pd-runtime` — including one that drives an arbitrary mix of routable, unroutable, malformed
and garbage traffic through it and asserts the pool comes back whole — and by a persistent fuzz
target (`route_frame`) whose input is the frame itself.

**Missing.**

- **No ARP and no ICMP on the dataplane.** Both now exist — `datad/crates/net-headers` parses and builds
  them and `datad/crates/ip-endpoint` answers them — but only for a port that answers *for itself*: the
  management port (see *[Full port role model](#full-port-role-model)*). On a dataplane port
  neighbours are still a static table and a drop is still silent, because a dataplane frame can only
  leave the port opposite the one it arrived on: the pools are owned by the receiving drivers, so no
  domain on that path can originate a frame at all. Giving a dataplane port an ARP cache and an ICMP
  responder means giving the forwarder a pool it owns, which is a capability change and not a code
  one.
- **Interfaces, neighbours, the management port and the filter rules are all that is
  configurable.** They come from
  `datad/systems/qemu-x86_64/configuration.xml` and no longer from a `const` table, and that document is
  now the single source of the appliance's addressing: the MAC QEMU gives each guest NIC and the
  endpoints the system test states its contract between are both read out of it
  (`datad/tools/xtask/src/topology.rs`), so the three literals that used to have to agree — and that
  nothing compared — are one literal and two derivations. Everything else a hop depends on is still
  compiled in: which ports exist, which pipeline joins which pair, and the pool and ring extents.
- **Connected routes only.** A destination is routable exactly when an interface prefix covers it;
  no route table and no gateway indirection. There is no default route and there cannot be one: an
  interface whose prefix length is 0 is never selected as an egress, so a document cannot express
  one by writing `/0` — the address is still one the appliance holds and the port is still a usable
  ingress, and traffic that would have needed the default route is `no_route`.
- **IPv4 only, and no options**: `IHL != 5` is refused rather than skipped, IPv6 is absent, and a
  VLAN tag is parsed but never acted on — a tagged frame is dropped for want of a sub-interface.
- **The L4 header is read by the filter and validated by nobody.** The UDP, TCP and ICMP headers
  behind IPv4 are parsed — ports, TCP flags, sequence and data offset, ICMP type and code — and
  every field reaches a caller exactly as it was sent. The filter now consumes the ports and the
  ICMP type (see *[Stateful filtering](#stateful-filtering)*); the flags, the sequence number and
  the code reach nothing. Nothing is validated: a TCP data offset below five or naming more than the
  segment carries, a UDP length contradicting the datagram, an ICMP checksum that does not verify
  are all surfaced rather than refused, and a datagram too short for the header it claims reports
  how few bytes there were. None of them can make a frame unroutable, because judging them would
  perform the receiving endpoint's check for it.
- **No fragment reassembly.** A non-initial fragment is forwarded without a transport header being
  read, which is correct for routing and insufficient for anything that must see the whole datagram.

## Stateful filtering

**What exists.** A `<rules>` section in the configuration document, and a terminal stage at the end
of `datad/crates/pipeline` that decides every frame against it. A rule names ten things — an id, the
ingress and egress interface, the source and destination CIDR block, the protocol, the source and
destination port or inclusive port range, the ICMP type, and `accept` or `drop` — and every one of
them is **required**, with the wildcard written `any`. Nothing is optional, because on a device whose
whole job is to decide what may pass, a criterion that widened itself by being left out is the one
defaulting mistake worth designing the schema around.

**Default deny is a property of the code, not of a document.** The stage answers a frame no rule
matched by dropping it, and there is no `<rules>` section an operator can write that changes that:
the fallthrough is not a rule, so it cannot be reordered, matched around, or overridden. An empty
`<rules/>` forwards nothing, and that is the posture a node runs in on generation 0 — before any
document has been committed and after one has been refused.

**The two refusals stay separate findings.** `policy_denied` is a rule that said drop and
`no_policy_match` is the fallthrough, each with its own drop reason, its own counter, and its own
encoding in the recording tap — so an operator reading a refusal can tell "your rule did this" from
"nothing you wrote covered this", which are different things to go and fix.

**First match wins in document order**, so a rule's line number is its precedence and the `<rules>`
section is the one element of the document whose order means something. The walk is bounded by the
rules the running generation declared rather than by the 256 slots the ABI holds, so an eight-rule
policy costs eight comparisons.

**A criterion cannot be satisfied by a header nobody read.** A truncated UDP, TCP or ICMP header, a
non-initial fragment, and a protocol this build does not break down all carry no port and no ICMP
type — and a rule *stating* a port or type criterion matches none of them, however wide the range.
That is the direction that matters on a default-deny appliance: such a packet falls to the next rule
and past the last of them to the deny, rather than being carried through an `accept` written for a
port that was never parsed. It is a single exhaustive match over the parsed transport with no
fallthrough arm, so a transport shape added to the parser stops compiling here rather than silently
joining the group that answers nothing.

**Twelve of the forty-one configuration rules are the filter's**, and four of them exist because a
rule that matches nothing is more dangerous than a rule that is wrong: a port range whose ends run
backwards, a port criterion on a rule naming ICMP, an ICMP type on a rule naming another protocol,
and a block written with host bits set are each refused rather than committed, because each is a
line an operator wrote believing it was in force — and the dangerous half of that belief is the
`accept` that quietly matches nothing. The other eight are the shapes: the count against the ABI's
256 slots, a well-formed and unique id, a known action, every criterion stated, an ingress and an
egress that resolve to a configured port, and a prefix length inside 32. All twelve are re-decided
over the byte image by the forwarder itself, like every other rule.

**Every rule carries its own hit counter on `/metrics`**, labelled with the id the document gave
it — one series per rule the running generation declares and none for a slot it does not. The count
comes from the forwarding domain's own shard and the label from the configuration the management
domain maps read-only, joined on the rule's position, so a hit is a number only the forwarder could
have written under a name only an operator could have chosen. Beside them the filter publishes what
it decided in total, packets and datagram bytes, split by verdict.

Held by unit and property tests in `datad/crates/pipeline` covering every criterion against a matching and
a neighbouring value, both refusals, precedence, the inclusive ends of a port range, the mask a
prefix length names, and all five unreadable transport shapes against all four port and type
criteria; by the differential configuration tests that put an image breaking each of the twelve rules
through both sides; and by two QEMU scenarios that inject three probes differing only in destination
port and hold the three outcomes apart on the wire, by drop reason, and by per-rule counter — one
against each of the two documents, whose policies name different ports under different ids.

**A rule about a protocol is demonstrated to decide both transports, on the image.** Those two
scenarios inject datagrams, so the ports a rule matched were UDP ports; the `connection-lifecycle`
scenario is where the other transport is decided, because it is the one bench whose rules say
`protocol="any"`. It injects two opening TCP segments that differ in their destination port and in
nothing else — same flags, same sequence, same addresses. The one the accepting rule names is
forwarded and opens a conversation; the one the *dropping* rule names is refused with
`librefirewall_route_drops_total{reason="policy_denied"}` and attributed to that rule by
`librefirewall_rule_hits_total{rule="lifecycle-deny"}`. On the other two benches the same segment is
refused for its protocol by the default deny, so no rule about a port ever decides one — which means
a filter that read a port criterion against a datagram's ports alone would have satisfied every other
scenario in the gate.

**A ruleset decides which conversations may open, and names related traffic where it admits it.** The
connection tracker settles an *established* packet before the filter is consulted, so the traffic
following an admitted conversation is carried by its flow. Two things do reach the filter, and the
`tracking` criterion tells them apart: `opening`, and `related` — traffic an existing conversation is
the reason for without belonging to it, which today means an ICMP error quoting one of its datagrams.
Such an error is composed by whoever sent it, with a source address of its choosing, so relating it to
a flow decides where it would go and never whether it may; the filter is asked, and a document
admitting no related traffic denies it. There is no third value: traffic inside a tracked conversation
never reaches the filter, so `established` would have no reachable meaning — an operator could write
it, watch the document be accepted, and watch the rule sit at zero forever — and it is refused at
commit rather than accepted and ignored. The
[configuration design](../design/configuration.md) records the model this follows — pf's, where a
tracked flow bypasses the ruleset — and names netfilter's, where the established-accept is a rule the
operator writes, as the alternative that was rejected. The one thing netfilter's model does buy is
made structural here instead: a `RELATED` accept an operator can forget is, on this appliance, a
`related` rule they must write to permit at all.

Held by unit and property tests in `datad/crates/pipeline` covering every criterion against a matching and
a neighbouring value, both refusals, precedence, the inclusive ends of a port range, the mask a
prefix length names, and all five unreadable transport shapes against all four port and type
criteria; by the differential configuration tests that put an image breaking each of the twelve rules
through both sides; and by six QEMU scenarios — two that inject three probes differing only in
destination port and hold the three filter outcomes apart on the wire, by drop reason and by per-rule
counter, one that does the same with two TCP segments and so decides a rule's port criterion on the
other transport, two that inject a request and its reply and hold the reply's arrival to the tracker
rather than to any rule, and one that puts the `related` criterion itself on a booted node.

**The related decision is observed on a running node and not only tested.** The `related-icmp`
scenario opens a conversation on the release image and then injects an ICMP destination-unreachable
from the far side quoting one of that conversation's datagrams — a quote built to satisfy every
agreement the tracker corroborates one by, so the frame really is related and is not merely refused
as unreadable. Under the shipped policy, whose rules are both about UDP, it falls to the default deny:
`librefirewall_route_drops_total{reason="no_policy_match"}` rises and the connection history carries
the refusal as a `policy-no-match` record on the packet that caused it. A document adding one
`tracking="related"` rule is then submitted over `POST /config`, and the same error on the same flow
crosses — attributed to that rule in `librefirewall_rule_hits_total{rule="probe-related"}`, with
`librefirewall_flow_packets_total{outcome="related"}` counting all three classifications. Both halves
are needed: a denial alone would leave "the policy refused it" and "the tracker never related it"
looking alike, and an admission alone would say nothing about the default.

An admitted related packet changes no conversation, so it has no connection-history record of its
own; it appears in the capture with its `related` classification and its forwarded verdict, and the
rule counter is what names the rule that let it through.

**A commit ends the conversations the new policy no longer admits.** Removing a rule used to leave
every connection it had already admitted running, which was a security gap rather than a rough edge —
a host found to be compromised kept every connection it had open. It is closed, and not by evaluating
the policy per packet: the *flow table* is re-decided on commit, and the flows the new policy would
not admit are taken back. Once per commit rather than once per packet, so the ruleset stays off the
hot path, and every flow the new policy still allows is left untouched — which is the whole reason the
appliance follows pf's model, and would have been destroyed by a sweep that flushed. The mechanism,
what it can decide from a flow's key alone, where it is conservative and what it costs are all in
*[Connection tracking](#connection-tracking)*; the operator-facing half is
`librefirewall_flow_lifecycle_total{event="revoked"}`, the three
`librefirewall_policy_sweep_*` families, and a `flow-revoked` record in the connection history.

**Missing.**

- **No `reject`.** A rule drops or accepts; it cannot answer an ICMP error. The forwarding domain
  owns no buffer pool it may allocate from — it forwards what arrived or it does not — so an action
  it could not carry out has no representation in the model rather than an unimplemented arm.
- **No zones and no interface groups.** A rule names one interface or `any`; there is no way to name
  a set of them, so a policy over six ports is written out per port.
- **No logging per rule.** A rule cannot ask for its matches to be recorded. Every decision reaches
  the recording tap regardless, with its reason, and the per-rule counters are the only per-rule
  signal.
- **Nothing is measured.** `datad/crates/pd-runtime`'s benchmarks now time a frame the filter permits, one
  it denies and one the router refuses, so the cost of consulting a policy is *measurable* — but the
  ruleset those benchmarks use is one wildcard rule, and no measurement exists of a realistic table
  or of how the walk scales across it.

## Connection tracking

**What exists.** A bounded connection table (`datad/crates/flow`) in a memory region of the forwarding
domain's own, and a stage in `datad/crates/pipeline` that classifies every routed packet against it. The
table holds a million flows in sixty-eight mebibytes, one entry to a cache line, keyed symmetrically
so a flow and its reply are the same bits. It tracks TCP with the four window comparisons of RFC 793
and a state machine that runs only on a segment that passed all four, UDP and ICMP echo as
pseudo-flows, and ICMP errors as related to the flow they quote — where the quote corroborates itself
against a flow the table holds, travelling away from the party being told, in a direction that flow
has carried.

**It is strict, and the strictness is the point.** A TCP flow opens on a bare `SYN` and on nothing
else: a segment from the middle of a conversation the appliance never saw begin is refused as
`mid_stream` rather than adopted, because adopting one is a way around default deny that costs an
attacker a single packet. A refused packet never touches a flow's timer, so nothing that can guess a
five-tuple can hold a slot open with garbage. What it costs is that connections do not survive a
restart of the forwarding domain, which is the right side of that trade for a firewall.

**The stage is two halves bracketing the filter, and both are load-bearing.**

In front, a packet an existing flow already accounts for is forwarded under the facts the routing
stage attached, and the filter is never consulted. That is what carries a reply no rule names, and it
is what keeps a policy edit from cutting a conversation already running *on the packet path*: the rule
that admitted it was consulted once, when it opened. What reaches such a conversation deliberately is
the pass a commit arms over the whole table, below.

Behind, a flow the classification *opened* is withdrawn where the filter then refused the packet that
opened it. Without that, a default-deny policy is a state-exhaustion amplifier — every rejected
opening packet holds a slot, and an attacker fills the table with connections the policy already
refused until legitimate ones are turned away. A property test drives a stream of denied openings and
asserts occupancy returns to zero after each, and a QEMU scenario observes the same thing on a
running node: six unsolicited packets refused by the default deny leave the table holding one flow,
the permitted request's.

**Eviction is fail-closed.** An assured flow is never displaced to admit a new one; when every slot
the bounded eviction scan reaches holds an assured flow, the *new* flow is refused and counted. A
flood of two hundred distinct tuples against a sixteen-slot table leaves every established flow
exactly where it was, and a property test says so. Every walk a packet can provoke is bounded by a
constant no peer chooses: a chain by thirty-two links, the eviction scan by sixty-four slots, the
timeout sweep by two hundred and fifty-six.

**A flood is observed on the release image, and the arithmetic is exact.** The `connection-flood`
scenario opens one conversation the shipped policy admits and, alongside it from the first injection
pass, sixty-four distinct five-tuples addressed to a port no rule is about. Each of those opens a flow
and is then refused by the default deny, so the appliance gives every slot back in the evaluation that
refused it. Four things hold together in the scrape that follows, and no three of them are enough:

- **The burst reached the table.** `librefirewall_flow_packets_total{outcome="new"}` counts at least
  the sixty-four openings, and the capture recording carries each of the sixty-four frames
  byte-identically, which is what says they were sixty-four *distinct* conversations and not one
  retransmitting.
- **Every one of them was given back.** `librefirewall_flow_lifecycle_total{event="withdrawn"}` counts
  at least the same sixty-four.
- **Occupancy stayed bounded.** `librefirewall_flow_table_entries{state="vacant"}` reads one below
  the table's capacity: it holds one flow, the conversation's, against a burst of sixty-four. And the
  accounting closes exactly: the openings, less the flows withdrawn, expired, evicted and revoked, are
  the flows the table is holding. A closed flow is deliberately *not* subtracted, because it keeps its
  slot until its idle timeout. That identity is now asserted on every scraped scenario, not only this
  one, and it is the only place a leaked slot is visible at all — a node holding a hundred stale flows
  publishes an occupancy that sums to the capacity perfectly well.
- **The established flow survived it.** The conversation's reply is deferred past the burst — it may
  only go out once the request has been observed crossing — and it crosses, carried by its flow under a
  policy that names nothing about the port it is addressed to. Beside it,
  `librefirewall_flow_lifecycle_total{event="evicted"}` and
  `librefirewall_flow_packets_refused_total{reason="table_full"}` both read zero, which the gate now
  requires of *every* scenario: nothing here injects enough distinct five-tuples to fill a million
  slots, so a rise either way would be a table holding flows nothing gave back.

**What remains host-level, precisely.** The one thing the image does not show is the behaviour at the
*capacity boundary*: `table_full` being answered, and an assured flow surviving a table with no room.
Reaching it needs 1 048 576 live flows, which no scenario can inject — and a scenario image built
around a smaller table is not the cheap change it looks like. `FLOW_CAPACITY` is one constant, but the
region holding the table is sized from it in the Microkit system description, and `xtask::sysdesc`
holds that description to the constants the domains compile against; a reduced-capacity image would
therefore need a second system description, the constant threaded through `lfw-flow`, `pd-runtime` and
every protection domain as a build feature, and a capability check that knows which description belongs
to which capacity. That is a second shippable authority topology to keep correct, for one assertion, so
it was not taken. The boundary is held instead by `datad/crates/flow`'s property tests against a sixteen-slot
table — a flood of two hundred distinct tuples, every established flow still in place, the new flow
refused as `TableFull` — and by the `flow_table` fuzz target. What the image proves is the property that
actually decides whether a default-deny appliance can be exhausted: that a refused opening costs no
state at all, so the boundary is not approached in the first place.

**Every outcome is a signal.** Each of the twelve refusals is its own drop reason on
`/metrics` — refused before the filter, so a frame the tracker turned away never reaches a rule — and
its own series in the tracker's own account beside the classified outcomes, the flow lifecycle, and
the occupancy of every slot by state. `vacant` is one of those states, so the values sum to the
table's capacity and a flood is watched as `vacant` falling.

**The one region a domain owns outright.** The table is mapped read-write into the forwarder and into
nothing else, which is what makes the `&mut` to it sound rather than merely uncontended: every other
region in the system is shared, so its type exposes no safe path to its own bytes. The region carries
no physical address, so Microkit allocates it from general-purpose untyped memory — the retyping seL4
zeroes — and that zeroing is what makes forming the reference defined at all, `Vacant` being
discriminant zero. The forwarder links the free list once at bring-up.

**Measured.** Walking the million slots at bring-up costs about 13 ms under QEMU's emulated CPU, and
every system scenario takes about 0.9 s more per boot than it would with a small table — the
loader creating and zeroing 17 409 page frames. Both are boot-time only and neither is on the packet
path.

Held by 140 unit and property tests in `datad/crates/flow` (whole handshakes, whole closes, every window
edge, both ICMP surfaces, floods against a small table, withdrawal, and the occupancy held to the
entries themselves), by a `cargo-fuzz` target that drives arbitrary packets at arbitrary instants
over a table already holding a handshaked connection, by tests in `datad/crates/pipeline` and
`datad/crates/pd-runtime` that drive the two halves through the real chain and the real ring plumbing, and
by two QEMU scenarios that hold a reply's arrival to the tracker rather than to a rule, and by the
`connection-flood` scenario above.

**A commit re-decides the whole table, and takes back what the new policy will not admit.** The
moment a generation commits, the forwarding domain arms a pass over its own connection table
(`pipeline::PolicySweep`). Each live flow's *opening* identity — the five-tuple in the orientation it
travelled in, plus the port it arrived on, which the entry records in the byte its layout held in
reserve — goes back through the same chain a frame does: the ingress interface must still exist and be
enabled, the destination must still route to a neighbour out of some other port, and the ruleset must
still match with an `accept`. A flow that fails any of those is taken back, and the caller is told so
it can record the end of the conversation.

**It is exact over every criterion a rule carries.** The addresses and the protocol are the key's; the
ports are the key's for TCP and UDP; the ICMP type is an echo request, because nothing else opens an
ICMP flow; the ingress is the recorded port; and the egress is resolved from the **new** routing table,
which is the right answer rather than a remembered one — a rule naming an egress is about where the
frame would now go. The two facts of the opening packet that are unrecoverable, its destination MAC and
its remaining lifetime, are properties of a packet rather than of a conversation and no rule can name
either.

**Where it is conservative, it is conservative towards ending flows.** An absent value never satisfies
a stated criterion, so the pass can only disown a flow the policy might have admitted and never keep
one it forbids. One case reaches that: a flow whose ingress interface the new configuration no longer
has or has disabled, or whose original destination it can no longer route to a neighbour, is taken back
even though packets in its *reply* direction might still have been forwarded. That is the honest
reading of the question — a packet opening the conversation now would be refused before the filter saw
it — and it is the safe direction either way.

**It is bounded per wakeup, and that is measured rather than assumed.** One window of the pass —
4096 bucket heads, which is exactly the bytes the timeout sweep's 256 entries already cost every
wakeup — is about 3.4 µs on the development machine, and about 6.7 µs where the window also has 256
live flows to re-decide, against about 110 ns for a forwarded frame (`pd-runtime`'s
`policy_sweep_window` and `route_forwarded` benchmarks). A whole pass over the million-slot index is
therefore several milliseconds, and a commit that stalled forwarding for that long would be a worse
defect than the one this closes. So a pass is carried across wakeups, and a wakeup works off the
greater of two budgets: what its own frame budget left unspent — a quiet wakeup pays four windows —
and what the table's occupancy needs. The pass walks the *index* and not the entries — four mebibytes
rather than sixty-four — and so reaches exactly the flows a packet can reach: one it cannot get to is
one no lookup can get to either, which can classify nothing and forward nothing.

**How long a pass takes does not depend on how many flows there are, and that is deliberate.** A
window crosses 4096 buckets *or* stops at 256 flows, whichever comes first, so a table with a flow in
every bucket crosses sixteen times less index per window than an empty one. Against the frame budget
alone a saturated wakeup bought one window either way, so a full million-flow table took sixteen times
as many wakeups as an empty one — the wrong direction on a security device, because the state is the
attacker's to create and the flows a narrowed policy forbids would go on forwarding longest exactly
when there are most of them. The budget is therefore scaled by occupancy: sixteen windows per wakeup
at a table entirely full, one at a sixteenth of it or less, in proportion in between. The arithmetic,
for the million-slot table this appliance builds: the index walk is 1048576 / 4096 = **256 windows**,
the flows are at most 1048576 / 256 = **4096 windows**, each window is limited by one bound or the
other so a pass is their sum, and dividing by the scaled budget leaves **at most 513 wakeups per pass
at any occupancy — 272 at a table entirely full**, where before the scaling a full table took 4096.

What that costs is that a wakeup can now spend more on re-deciding than a full drain costs: sixteen
windows is about 54 µs against a saturated drain's 14 µs, so forwarding runs about four times slower
while a pass over a full table is being worked off. It is bounded by a constant either way, the
table's width being fixed at compile time, and it is the trade: a revocation an operator asked for
finishes in a bounded number of wakeups, at the price of those wakeups being more expensive while it
does.

**A commit arriving mid-pass adds a pass rather than restarting one.** Continuing under the new
generation without going back is not available — the buckets behind the cursor were judged against the
document the commit replaces, so a flow the new policy forbids sitting behind the cursor would never be
re-decided at all. Restarting from the first bucket is sound, and is what a submission storm turns into
starvation: the party submitting documents is unauthenticated, so a pass could be restarted faster than
it completes and never finish. So the running pass is left to reach the last bucket and one fresh pass
over the whole table is queued behind it — one, however many commits arrive, since what is owed either
way is a single walk against the newest generation. Flows are judged against that newest generation
from the moment it commits, so nothing is ever taken back under a document already replaced. The delay
is therefore **at most two passes, 1026 wakeups on that table**, however fast documents are submitted.
`librefirewall_policy_sweep_total{outcome="deferred"}` counts the commits that queued one.

**What the window costs, stated plainly.** A flow the new policy forbids keeps forwarding until the
pass reaches it, which is up to that many wakeups. What bounds that is the flow itself:
a conversation forwards only when its packets arrive, every arriving frame wakes the domain, and every
wakeup advances the pass — so a forbidden flow that is *doing* anything is generating the wakeups that
end it. What that does not give is a bound in wall-clock time: a node forwarding nothing receives no
wakeups and does not finish its pass, and is also forwarding nothing.
`librefirewall_policy_sweep_running` reads 1 for exactly as long as that is true, which is the honest
answer rather than a fault.

Held by unit and property tests in `datad/crates/flow` (a pass that keeps every flow changes not one byte of
an entry; every live flow is offered exactly once; the opening reported is the one that was on the wire
in both orientations; one window is bounded in both of its two ways) and in `datad/crates/pipeline` (a
narrowing commit takes back exactly one of two conversations and leaves the other carrying traffic no
rule names; a widening or unchanged commit takes back nothing; a rule that matches with `drop` is not
an admission; each of five table changes the pass cannot place a flow under; an ICMP flow re-decided as
an echo request and under no port criterion; a commit mid-pass queuing a second pass rather than
abandoning the one running; a commit before every window unable to starve a pass; the window budget
scaling with occupancy so a full table is swept in no more wakeups than an empty one), by a property
that a
pass revokes exactly the flows a fresh opening packet would be denied under the committed policy, and
by the `policy-revocation` QEMU scenario, which opens two conversations differing in their source port
alone, submits a document narrowing the accept rule by that one attribute, works the pass off to
completion, and then holds the revoked conversation's next packet to being refused and the surviving
conversation's to still crossing — carried by its flow, which no rule of either document names.

**Missing.**

- **A conversation reclaimed by its idle timeout produces no close event.** Every record of the
  connection history is anchored to the packet that caused it, and a flow the sweep collected has no
  such packet, so its end is visible on `librefirewall_flow_expired_total` and in no recording. The
  design's answer is the periodic state event that re-anchors long-lived connections, and nothing
  emits one. See *[Recording and download](#recording-and-download)*.
- **A refusal names no flow.** The two refusals that are *about* an existing flow — a segment outside
  its window, and one its state does not admit — are recorded with their reason and not with the
  conversation they were refused against, because `lfw_flow::Refusal` carries the value that refused
  the packet and not the slot it resolved. A reader locates such a record by the five-tuple in the
  causing packet's own headers.
- **No NAT, so no translation state.** The table carries a flow's identity and its state, and nothing
  it would need to rewrite an address.
- **The hash is unkeyed.** An attacker who computes colliding tuples can fill one bucket's chain and
  have new flows whose keys land there refused. It cannot slow a lookup, reach another bucket, or
  displace anything established. Closing it needs a keyed pseudo-random function, and the one
  implementation in the workspace is private to `lfw_tcp::isn`.
- **One table, not one per core.** The multicore dataplane will want the symmetric key this table
  already has to shard by, and nothing wires that yet.
- **Nothing is measured on the packet path.** The bring-up walk is measured; the per-packet cost of a
  classification is not, and the benchmark that times the chain drives a sixteen-slot table.

## Zero-copy dataplane

**What exists.** The substrate exists as four host-tested `no_std` crates: `datad/crates/queue` (the
lock-free SPSC ring), `datad/crates/packet-buffer` (the shared buffer pool and its ownership ledger),
`datad/crates/wire` (the descriptor ABI shared across domains, pinned by static layout assertion) and
`datad/crates/pd-runtime` (the shared regions, pool owner and routing stage the protection domains are
assembled from).

Correctness is held by unit and property tests across those four crates — including hostile-peer
cases for forged and duplicate returns, forged cursors, exhausted rings and bounded drains — plus a
500,000-frame three-thread pipeline test that cycles every buffer through `rx → route → tx → free`
far more times than the pool holds, exchanging the forwarding table at poll boundaries as it goes.

A frame is copied twice per hop with the recorder switched out of the picture: once out of the pool
into the routing domain's own memory, because a decision made on bytes a peer may rewrite underneath
it is no decision at all, and once back — 34 bytes of header, never the payload.

**The tap makes it three, and adds a second parse.** Every frame the pipeline decides on is copied a
third time, out of the routing domain's scratch into the tap ring the recorder reads
([detail](#recording-and-download)) — up to 2048 bytes, the whole frame rather than its header. The
copy is taken between the decision and the forwarding rewrite, which is what makes a recorded frame
the one the wire delivered, and the cost of splitting the two is that the rewrite re-parses the frame
the decision already parsed. Neither cost is measured: `datad/crates/pd-runtime`'s Criterion routing bench
passes no tap, so what it measures is the path with recording off.

**Missing.**

- No batching API — one descriptor per call, and one notification per drain. The batched
  notifications the [architecture design](../design/architecture.md) intends are incidental today,
  not designed.
- Pool is 64 buffers of 2048 bytes; orders of magnitude short of a 10 Gbit/s working set.
- Fixed 2048-byte buffers: no jumbo frames, no scatter-gather, and no descriptor chaining **on this
  path** — `datad/crates/virtio` grew chaining for the block driver's three-segment requests, and no NIC
  pipeline uses it.
- Exactly two pipelines, hard-coded in the forwarder PD. No per-core sharding, no multi-queue.
- No backpressure policy beyond releasing the buffer. A peer that stalls a destination ring makes
  `RouteStage::poll` drop a descriptor it has already dequeued, and the buffer that descriptor
  named is then lost to its owner's ledger permanently. It is counted, and nothing is double-owned
  — but the pool shrinks, and no component reclaims it.

## virtio-net driver

**What exists.** A from-scratch modern virtio 1.0 PCI transport in `datad/crates/virtio` —
capability-list walk, BAR relocation, feature negotiation, queue programming, doorbells, and a
split-virtqueue driver half — held by unit and property tests and one compile-fail doctest. Every
transport entry point the device drives returns a typed error (`BarError`, `ResetError`,
`QueueSetupError`, `NotifyError`, `CapError`) instead of panicking.

`datad/crates/nic-driver-core` holds bring-up and the steady-state poll pass, tested the same way. Rx and
Tx clamp the device-reported length to the buffer behind it, drop runt frames, and validate every
peer transmit descriptor.

Twelve persistent fuzz targets cover this surface, the peer-facing one, the network-facing parser,
the addressed management port, the configuration document and the handover image, and the log
record and its ring (see *[Engineering foundations](#engineering-foundations)*).

**Missing.**

- **Interrupts.** Busy-poll only — no MSI-X, no INTx (deliberate for this milestone). The ISR
  capability's presence is still required of the device, but its offset is not retained and the
  status register is never read. This burns a core per port, and the three driver instances run at
  the same priority and never yield, so their mutual progress rests on seL4's round-robin
  scheduling alone.
- **Real hardware.** No PCI enumeration: the BDF and the BAR physical address are pinned in the
  system description, so the driver cannot bind a device it was not built for.
- **DMA confinement.** Bus-master DMA is granted against fixed physical addresses with no VT-d, so
  nothing bounds where the device writes. What the grant *is* ordered against is now right: the NIC
  driver enables bus mastering only after the device has acknowledged its reset (virtio 1.0
  §3.1.1's first step), so a device that will not reset never reaches bus-master authority at all.
  The block driver still takes it at BAR placement, before the handshake — an open defect, recorded
  under *[virtio-blk driver](#virtio-blk-driver)*.
- **Offloads.** No checksum offload, TSO/GSO, or mergeable receive buffers — prerequisites for
  10 Gbit/s. No feature but virtio 1.0 is accepted, precisely because accepting one would licence
  buffer shapes no code handles.
- No control virtqueue, no multi-queue, no link-status handling, and no MAC read-out — the device
  configuration structure's offset is bounded but never dereferenced.
- No packed virtqueue and no MMIO transport (PCI only).
- **No restart.** A rejected bring-up is a typed `BringUpError` the PD reports on the console and
  parks on, writing `STATUS_FAILED` back to the device wherever the register is reachable. The
  domain is left idle rather than faulted — but nothing restarts it, and the port stays down until
  the node is rebooted.

## virtio-blk driver

**What exists.** A ninth protection domain, `recorder` — the seventh binary, the driver's three
instances being one binary — owns a virtio-blk device at the pinned PCI function 00:05.0. It is no
longer the only domain that can put a byte on persistent storage: the store domain owns a **second**
such device at 00:06.0 (below), and the two are separate authorities — neither maps any part of the
other's ECAM page, BAR window, DMA region or staging window. The device class is
`datad/crates/blk`: PCI identification and the virtio 1.0 handshake (`bringup`), the request
state machine over one virtqueue (`request`), and the sector-addressed staging window every data
segment names (`io`). The split is `nic-driver-core`'s — every decision is in the library where a
host test can drive it against a stand-in device, and the protection domain is a thin adapter,
because correctness logic belongs in a host-testable crate rather than in a protection domain.

**What it proves today** is that the path reaches a real medium, and it proves it as a
machine-observable contract rather than as a console line — the end-to-end tests assert observable
contracts, never timing-sensitive log text. `lfw_blk::smoke` reads sector 0, then writes a 512-byte
pattern that names its own target sector to sector 2047, waiting for each completion before
starting the next. That sector is the last of the 1 MiB front the recording layout already reserves
for neither recording, and a build-time assertion ties the two together so the proof cannot come to
overwrite a recording. The QEMU harness creates a 64 MiB raw image per run, seeds a different
recognisable pattern into sector 0 before boot, and afterwards reads sector 2047 back and compares
it against `lfw_blk::smoke::witness_pattern` — the appliance's own definition, called rather than
copied. Every scenario that boots the appliance must show the pattern, and the two A/B halt
scenarios, where no
slot is bootable and no domain runs, must show the sector still zeroed. That pair is what makes
either verdict evidence. The one exception is the forced-emulation boot, which owes neither verdict:
it ends the moment the cryptography domain reports, and nothing orders that against the recorder's
own proof of the medium — so a witness asserted there would be asserted on a race, and the same
sector asserted untouched would be asserted against a domain that was running.

The console record carries what the device said and what came back:

```
LFW-PD time=… domain=recorder state=starting
LFW-PD time=… domain=recorder state=negotiated features=0x100000200
LFW-PD time=… domain=recorder state=ready sectors=131072 leading=0x444545532d57464c
```

`sectors` is the device's claimed capacity and `leading` is the first eight bytes it actually
returned — here the harness's `LFW-SEED` marker, little-endian, which is a second, independent sign
that the *read* crossed to the medium and not merely to the driver's own staging window.

**Missing.**

- **The checkpoint is ordered; the payload is not, and there is no retry.** `lfw_blk` now accepts
  `VIRTIO_BLK_F_FLUSH` where the device offers it, and the recording pass takes one
  `VIRTIO_BLK_T_FLUSH` between a recording's payload write completing and the checkpoint superblock
  that claims those bytes — so an extent read straight off the medium never names payload the device
  had not committed, whatever it cached or reordered. What is *not* ordered is the payload against
  itself: records within a segment are written as staging fills and nothing flushes between them, so
  a power cut still loses whatever the device was holding, and only the last checkpointed position is
  durable. Because the barrier costs a device round trip, the written prefix is routinely one flush
  ahead of the checkpoint — the harness reads and reports that lag off the disk rather than requiring
  the two to be equal. Where the barrier fails or the device refuses one, the checkpoint is abandoned
  rather than written unordered; where the device offered no flush feature, the checkpoint is written
  without a barrier and its ordering is the device's. The smoke proof refuses and parks rather than
  retrying a device that answered badly, and a recording whose write the medium failed
  **acknowledges the loss and advances**: stalling every later record behind a fault that retrying
  cannot clear would be the worse recording.
- **A failed transfer reaches no surface.** That loss is counted inside the recorder as
  `medium_failures`, and that counter is published nowhere — no metric family carries it, no console
  record states it, and the recording itself says nothing about the sectors it lost, because
  `epb_dropcount` accounts for what the tap ring lost and for nothing the *device* refused. A
  medium quietly failing every write is indistinguishable from one that is merely idle.
- **One device, one extent, no partition.** `datad/systems/qemu-x86_64` declares a single block device and
  the driver addresses the whole of it. The per-deployment device count and named-extent binding the
  [recording design](../design/recording.md) intends are untouched.
- **Nothing is measured.** The staging window is 256 KiB because that is a plausible amount to have
  in flight, not because a benchmark said so, and there is no Criterion bench on the block path.
- **Bus mastering is granted too early, and this is an open defect.** `Identified::place_bar`
  enables memory decoding and bus mastering together, so the device holds DMA authority from BAR
  placement — before the reset, the feature negotiation and the capacity check that follow. The NIC
  driver was moved to virtio 1.0 §3.1.1's order, where the grant comes after the device
  acknowledges its reset; the block driver was not, so a device that refuses its reset here has
  already been made a bus master. Nothing in the appliance depends on the early grant.

## Recording and download

**What exists.** Every frame the pipeline decides on is observed, both recordings are written to the
medium as pcapng, and either can be downloaded whole over HTTP.

The forwarder taps its own routing stage. `RouteStage` already snapshots each frame into private
scratch before deciding, so an observation costs one copy into a shared ring and no second read of
the pool. The copy is lifted after the verdict and before the hop's rewrite, which is the ordering
that makes a recording evidence about the wire rather than about this appliance's own output, and
the price of it is a second header parse on the forwarding path: the rewrite re-parses what the
decision already parsed. Three classes of frame are counted and deliberately absent from a
recording, because `wire::TapDropReason` mirrors `pipeline::DropReason` exactly and there is no
honest encoding for them: a frame no verdict was reached about (a malformed descriptor, a
refused snapshot, bytes that are not IPv4 over Ethernet), a frame routed out of a port the stage is
not wired to, and
a frame recorded as forwarded that a later refusal still lost. **The tap never backpressures
forwarding**: a full ring costs the newest observation and is counted — on both sides of the ring
and on `/metrics` — because a tap that could stall the dataplane would make an observability
feature a remote outage. That loss is also the one thing a recording states about itself: the
recorder differences the writer's drop count on every pass and carries the rise onto the next
record it places, so `epb_dropcount` is fed rather than written as a zero.

The recorder keeps two recordings on the one device, both `lfw_recorder::Sink` over
`lfw_capture_ring`. They differ by **what each records** — the selection is
`lfw_recorder::deck::Which::records` — and the extent and snap length follow from that:

| Recording | Records | Extent | Segment | Snap length |
|---|---|---|---|---|
| connection history (`/logs.pcapng`) | an observation carrying a lifecycle or policy event | sector 2048, 32768 sectors (16 MiB) | 1 MiB | 128 bytes |
| capture (`/capture.pcapng`) | every observation **of a frame** | sector 34816, 65536 sectors (32 MiB) | 1 MiB | 2048 bytes |

One record is in the history and in no capture, and it is the only one that is about
no frame: a conversation a policy commit ended. There was nothing on a wire, so it
carries no captured bytes, states a wire length of zero, omits `epb_flags` and names
no classification — every field pcapng has for a packet says there was none — while
carrying the flow it ended and the state that conversation was in. The alternative
would have been a fabricated frame in an artifact that is evidence, or a connection
history silent about the one way a conversation ends that an operator asked for.

The history's 128 bytes are derived rather than chosen: the longest L2–L4 header chain this appliance
reaches a decision on is 98 bytes — an Ethernet header, an 802.1Q tag, an IPv4 header whose options
the parser refuses rather than skips, and a TCP header with a full option area — and a record of a
decision carries the headers it was taken on and nothing of the payload.

Sectors 0–2047 are reserved and belong to neither, which is where the harness's seed and the smoke
proof's witness pattern live. Within each extent the **first segment holds the superblock** — the
ring's geometry and the cursor it has been written up to, doubled and CRC32'd, its two 512-byte
copies alternating by generation parity so a torn write never leaves the ring without a good one.
The cursor it records is the **durable** one and not the append one, so a resume cannot claim bytes
the medium never took; and a fresh ring's first checkpoint writes *both* copies, parity applying
only from the second, because otherwise a stale copy left by an older ring on the same medium could
outrank the new one. Payload therefore starts one segment in, giving the log recording 15 payload
segments and the capture recording 31. The 256 KiB `blk_io` staging window is carved into a
64 KiB log buffer, a 128 KiB capture buffer, a 32.5 KiB download read buffer (a 32 KiB window plus
one sector, so a window can start mid-sector) and a 1 KiB superblock buffer, each sector-aligned, and
every DMA address is `io_paddr` plus one of those offsets.

Each pass of the recorder's loop settles up to eight completions, drains up to sixteen tap records
into both recordings, hands the medium whatever is ready, and services at most one download. A
record a recording cannot take yet is **held**, not dropped: `wire::TapReader` consumes a slot
irrevocably, so the pass stops drawing new records until both recordings have taken the one in hand.
Every counter reading is converted to a wall-clock instant here, against the calibration the clock
domain publishes; before there is one, a record states no instant rather than a counter value
dressed as a time.

A download pins a snapshot: offset zero seals the named recording, flushes it, and answers with the
length the response commits to; later offsets are located against that same snapshot, read back off
the medium, and delivered a window at a time. A ring that wrapped past a reader answers `Overrun`, a
medium that refused answers `DeviceError`, and either ends the response rather than truncating it
silently. The management domain drives that from `EndpointStage`'s windowed body, so nothing holds
a second copy of a megabyte: the recorder answers up to 32 KiB per round trip, the endpoint copies
each into a 16 KiB sliding window sized above the transport's retransmit span, and a client that
stops reading abandons the stream. **The window the endpoint names is a bound and not a demand**,
which is the shape the segmented ring forces: a reader runs short at every 1 MiB extent boundary,
so a supplier handing back fewer bytes advances the response from where the bytes ended instead of
ending it. Two compile-time assertions tie the recorder's window and the endpoint's to each other.
Serving a body larger than the response staging buffer is what the windowed body exists for — a
scrape of `/metrics` fits in staging, a 12 KiB recording would too, and a 16 MiB one never will.

**What a recording contains.** Each segment opens with a Section Header Block naming
`librefirewall`, then one Interface Description Block per interface — Ethernet, microsecond
timestamps, `if_snaplen` the sink's own. Every observation is an Enhanced Packet Block carrying
`epb_flags` (direction), `epb_dropcount` (the tap-ring observations lost ahead of this record),
`epb_packetid`, `epb_verdict`, and a PEN-tagged custom option holding a layout version, the
verdict, the drop reason, the interface, the direction and the **configuration generation the
decision was made under**. A sealed segment is padded to a sector boundary with a Custom Block that
any reader skips. The [recording download endpoints reference](../reference/recordings.md) is the
operator-facing statement of all of it.

The console names both extents at bring-up. Nothing else states them: they are compiled in rather
than configured, `/metrics` says how much a recording has written and never where it sits, and
there is no shell to ask — so these two records are what an operator has:

```
LFW-PD time=… domain=recorder state=ready sectors=131072 leading=0x444545532d57464c
LFW-PD time=… domain=recorder state=ready start=2048 sectors=32768
LFW-PD time=… domain=recorder state=ready start=34816 sectors=65536
```

**What the gate proves.** Every scenario whose management port is reachable — 12 of the 20 system
scenarios — boots the release image on QEMU's user-mode stack, drives the same dataplane traffic every other
scenario drives, and then `curl`s `/metrics`, `/logs.pcapng` and `/capture.pcapng`, holding the
three to **each other** as well as to the wire (`datad/tools/xtask/src/surface_contract.rs`): every record
of the connection history *of a frame* pairs into the capture by `epb_packetid` and none of it names
no event, the one record that is about no frame is held instead to claiming none of the four things a
frame has, neither recording exceeds the record count the recorder publishes for that sink, every
injected probe appears in the capture byte-identically, and no block carries bytes the harness never
injected. On top
of that the decision each record carries is judged as bytes: every record carries the PEN-tagged
annotation at the layout version this build writes; the verdict it states agrees with what the harness
independently watched that probe do on the wire; a rule it names is one the exposition credits with a
hit under the id the document gave it; a refusal it names is one the exposition counted at least as
often; a close names a state a conversation does not leave and an earlier record opens the same
conversation; and the lifecycle or policy event each probe had to cause is in the history, on the
packet that caused it. A fault that hides inside any one surface shows up as a disagreement between
two. The harness walks the downloaded bytes block by block *by the lengths the file states* — the
discipline a reader actually depends on — and holds the capture to carrying at least as many packet
blocks as frames the harness put across the appliance, the history to at least as many as the events
its probes owe, and neither to a captured length past its sink's snap length. Afterwards it reads the two extents straight off the disk image and requires
each to carry a decodable superblock and a walkable recording. Two paths to one artifact, neither of
them the appliance's own account of itself.

**What the demonstration showed.** Separately from the gate, and by hand, the published release disk
was booted under OVMF with a 64 MiB virtio-blk data device attached at 00:05.0, and 14 routable
IPv4/UDP frames of 84 to 1384 bytes were injected on dataplane-0 for the appliance to route to
dataplane-1. This was a one-off: the script and its artifacts live under the ignored `datad/build/` tree
and are not in the repository, so what is *repeatable* is the `recording-download` scenario above and
this is corroboration beside it. Over the management port, `curl http://…/logs.pcapng` and
`curl http://…/capture.pcapng` each returned a whole number of 512-byte sectors — which is the
padding block doing its job — 3584 and 12288 bytes for that hand-run traffic.
`tcpdump -r` reads both natively and lists all 14 packets with their real addresses, ports, lengths
and wall-clock times. An independent parse of the two files established:

- **capture:** captured length equals original length for all 14, and **every frame is byte-identical
  to the bytes injected** — the whole point of tapping before the rewrite;
- **log:** captured length clamped to 128 while the original length (84…1384) is preserved, and each
  is a byte-exact prefix of what was sent;
- every packet carries `epb_flags`, `epb_packetid` (0…13), `epb_dropcount` (0 throughout) and
  `epb_verdict`, plus the PEN-tagged annotation, which reported configuration generation 1 — the
  generation the console had just recorded as applied;
- both files carry one Section Header Block, two Interface Description Blocks and a trailing padding
  Custom Block, and the padding is transparent to `tcpdump`;
- reading the two extents straight off the data-disk image after shutdown yields **exactly the bytes
  the downloads returned**, so the medium is proved independently of the download path.

**Missing.**

- **The connection history exists; three of the design's event kinds do not.** The
  [recording design](../design/recording.md)'s log sink records a conversation's open, each refinement
  of its protocol and application identity, notable events on it, and its close, each anchored to the
  causing packet. The open, the state advances, the close and both policy refusals are written, with
  the flow identity as the (slot, generation) pair the design requires. What is absent is what has no
  producer yet: **no protocol or application-identity refinement**, because nothing above L4 is
  parsed; **no deny coalescing**, so a port scan costs one record per probe rather than a counted
  per-bucket event; and **no periodic state event**, so a reader's reconstruction window grows with a
  long-lived conversation's age instead of being bounded. The annotation carries a version byte
  precisely so the record can grow when they land — it reads 3 today.
- **No recording selector.** The capture sink of the [recording design](../design/recording.md)
  records the flows a selector picks out; this one records everything the dataplane decided on, which
  is development state rather than a shipping posture: a deployed node would record every packet
  crossing it, indefinitely, with no way to say otherwise. The filter rules are not that selector and
  cannot stand in for one — they decide what the appliance *forwards*, and a packet a rule dropped is
  recorded with its refusal exactly as a forwarded one is.
- **No TLS and no authentication in front of either download.** The
  [management design](../design/management.md) now erases these downloads outright — a recording
  reaches the management server over the authenticated channel or not at all — and until that
  replacement exists the gap stands at its full width ([detail](#full-port-role-model)): anyone who
  can reach the management port is handed every packet the appliance recorded. The design makes
  authorization a *condition* of the exception that lets a recording carry packet payloads at all;
  the condition is unmet.
- **One observation per frame.** The paired ingress and egress observation of one forwarded frame
  that the [recording design](../design/recording.md) intends — the thing a mirror port cannot give
  you — is not emitted: the packet identity that would relate them is minted and monotone, and only
  the ingress observation is recorded, so every `epb_flags` reads inbound.
- **Only the dataplane is tapped.** The management port has no tap, so nothing on it — including the
  download itself — appears in either recording.
- **Some frames are counted and deliberately not recorded**, because `wire::TapDropReason` mirrors
  `pipeline::DropReason` exactly and there is no honest encoding for them: a frame no verdict
  was reached about, one routed out of a port the stage is not wired to, and one recorded as forwarded
  that a later refusal still lost. An operator reconciling a recording against `/metrics` subtracts
  those; the [recordings reference](../reference/recordings.md) states the reconciliation.
- **A recording states one of its three kinds of loss.** The
  [recording design](../design/recording.md) makes `epb_dropcount` and an Interface Statistics
  Block the in-band report of everything a sink did not record. `epb_dropcount` now carries the
  first of the three: the recorder reads the forwarder's tap-drop counter each pass, differences it,
  and holds the rise as a debt on both recordings until a record is placed to carry it — so the
  number belongs to the gap ahead of its block rather than to the packet in it, and it is cleared
  only by a successful placement. The other two are still out of band: a record the encoder refused
  and a write the medium lost are counted on `/metrics` and stated nowhere in the file, and no ISB
  is emitted at all. A file whose *sink* fell behind therefore still reads like one that lost
  nothing.
- **The PEN is a placeholder, and whose it will be is undecided.** Annotations are tagged
  `0xFFFF_FFFF`, IANA-reserved so it can never collide with a real assignment, and a registered
  Private Enterprise Number is needed before a recording leaves a customer's premises. The constant
  holding the placeholder is `lfw_pcapng::UNREGISTERED_PEN`, named for what the value is rather than
  for an owner, because who would register a number is itself unsettled — the question is not the
  code's to answer, and a constant that named a party would have answered it by implication.
- **The Interface Description Blocks name the port, not the interface.** They carry the literals
  `port0` and `port1` rather than the configured id `dataplane-0`, and closing that now costs a
  capability rather than a rename: the recorder's read-only mapping of the `cfg` region has been
  **withdrawn**. It was the one grant in the system no symbol addressed, which is authority no code
  in the domain could name, and `xtask::sysdesc` now fails the build on any mapping in that state —
  so giving the recorder the configured names means granting the region back and addressing it,
  deliberately, rather than finding it already there.
- **The extents are compiled in.** `lfw_recorder::deck` fixes both, and the device is the whole of one
  disk. The per-deployment device count and named-extent binding the
  [recording design](../design/recording.md) intends are untouched, and no configuration item names
  either.
- **No retention bound but the ring's size, and no zeroization.** The
  [recording design](../design/recording.md) requires a time bound as well; there is none, so how
  long a node holds traffic is whatever its ring yields at the offered rate. Nothing is erased when
  recording stops, and nothing erases an extent on decommission.
- **Nothing resumes, and nothing rotates or checkpoints on a schedule.** A superblock is written
  when the recorder decides to — at bring-up and after a segment closes — never on a clock; and no
  boot reads one back. `Sink::resume` is host-tested and correct as far as it can be shown to be —
  a resumed recording's download starts at the segment *this* boot opened rather than the previous
  boot's unsealed one, and there is no separate `open` for it to be called out of order with — but
  it is called by no protection domain, so a restart begins a fresh ring over the old bytes.
- **One reader, and it holds no durable cursor.** The superblock carries four reader-cursor slots
  and nothing registers one. The [management](../design/management.md) and
  [recording](../design/recording.md) designs make the channel the ring's cursor-holding reader —
  resuming from the server-acknowledged cursor after a reconnect — and no channel exists; the
  ring's only reader is the download path. That unregistered cursor is why no series says how much
  history a recording still holds: a wrap count states that a segment was evicted, and there is no
  cursor for it to have been evicted past.
- **A download is the whole recording.** No `Range`, no `If-Match`, no `ETag`, and no way to ask for
  one segment or a byte extent — the [management design](../design/management.md) serves recording
  range reads over the channel, and the download it replaces cannot even express one. A body over
  2 GiB is refused outright rather than served wrong.
- **Nothing is measured.** There is no Criterion bench on the tap or the recording path, nothing has
  been measured against the 10 Gbit/s target with recording on or off, and the segment size, the
  staging split and the two drain budgets are plausible numbers rather than measured ones. The tap
  adds a per-frame copy and a second header parse to the forwarding path
  ([detail](#zero-copy-dataplane)), and the size of that is unknown.

## Configuration management

**What exists.** A schema-validated XML document is the whole of the appliance's addressing, and it
reaches the dataplane through four stages that never mix. `datad/systems/qemu-x86_64/configuration.xml` is
the one a build embeds and it is the **first** generation rather than the only one: a document can be
submitted to a running node over the management API, and every later generation arrives that way.

`datad/crates/config` reads it. The reader is `no_std`, allocator-free and hardened against a
management-plane adversary rather than against a typo: `<!DOCTYPE`, entity declarations, CDATA,
processing instructions and markup declarations are refused outright, only the five predefined
entities and bounded numeric character references are expanded, and every dimension is a named
bound — 64 KiB of document, 8 levels of nesting, 16 attributes per element, 32-byte names and
values. The schema is closed: an unknown element or attribute is a refusal, not something skipped,
because a misspelling nobody can see is the failure an appliance with no shell cannot afford.
Parsing and semantic validation are separate passes over separate inputs — bytes, then a
model — so a syntax rule cannot come to depend on an address and a topology rule cannot come to
depend on where in the file something was written. Each configurable object is declared once —
its value, the attributes a reader accepts for it, the change records it produces and the bytes it
folds into a content hash all come from that one list, so an attribute cannot be added to the
reader and forgotten by the hash. Forty-two semantic rules then run over the
model: a duplicate interface id, neighbour id, port or interface MAC; a port the build does not
have; a prefix length past 32; an address that is its own prefix's network or broadcast address, on
an interface or on a neighbour; a non-unicast address or MAC on either object; overlapping
prefixes; a neighbour naming an unknown interface, or sitting outside its interface's prefix, or
equal to the interface's own address; a duplicate neighbour address on one interface; six over
the `<management>` element, which is held to the same field rules as an interface *and* to
colliding with no dataplane prefix and no dataplane MAC —
because one address reachable both by routing and by local termination is not something the grant set
can express; and twelve over the `<rules>` section, which are described with
*[Stateful filtering](#stateful-filtering)*. A document naming more objects than the handover ABI can carry is refused by the reader
rather than truncated. Every refusal is a typed error naming a **location** and never the offending
bytes, so attacker-supplied content never reaches an observability surface. A forty-second rule sits
beside them and is about the appliance rather than the document: a configuration whose canonical form
outgrows the document bound is refused, because the appliance must be able to state back what it is
running.

Those rules are decided **twice** — here over the model, and again over the byte image by the
domain that will forward under it — and which rules there are is now one list rather than two.
`wire::ConfigRule` names every rule once, and both sides answer for every one of them exhaustively:
a rule added to that list does not compile until each side has said whether it refuses a
configuration breaking it, cannot express one, or cannot decide it. The compiler holds the pairing;
that each answer is true of the code beneath it is held by a test that builds a configuration
breaking each rule in turn and puts it through both sides. Exactly two rules are undecidable on the
image side — two neighbours under one id, the image carrying no neighbour identity, and whether the
configuration can be stated back, which is a question about a document form the image is not one
of — and that count is itself a compile-time assertion. Both are admissible for the one reason that
ever makes an asymmetry admissible here: the consumer has no stake in either, so neither is a rule a
compromise of the reader could use to reach a frame.

`config::Datastore` versions what passed. A candidate is staged without touching what is running,
`validate_document` takes `&self` so "an operation that changes nothing" is carried by the signature
rather than by discipline, and a commit assigns the next monotonic generation and returns the diff —
or assigns no generation at all and reports `unchanged`. What recognises a commit of the content
already in force is a **comparison of the content**, object by object; the 32-bit hash held beside
the generation is a fast path in front of it and can only ever agree, because a digest short enough
to carry across the handover is short enough to collide, and a collision here would suppress a real
configuration with no generation, no record and nothing published. The diff is keyed by the
document's `id`, so reordering the document produces **zero** change records — a property test, not
an intention — and a modified object produces one record per changed field and nothing for the
rest. A diff hands each record to its caller as it produces one rather than filling a buffer, so
what a commit costs in memory does not grow with how many objects the ABI can hold.

`datad/pds/config` is a protection domain of its own holding no device capability, no buffer pool and no
dataplane ring, so the domain that parses attacker-supplied XML cannot reach a frame, a NIC, or the
memory either travels through. It writes a fixed-layout POD image of the already-validated model
into a shared region — the forwarder never parses XML, which is the entire point of the split — and
publishes it under an **offer/acknowledge handover**: offer, the consumer re-checks and
acknowledges, then commit. (It is a handover between two domains of one node and not a two-phase
commit: nothing is prepared that a later message could abort, and there is no coordinator.) The two
regions are separate and mirrored (`cfg` read-write here and read-only there, `cfgack` the reverse)
so neither domain can forge the other's half. Its layout — the `#[repr(C)]` value a reader copies
out, the atomic mirror a writer stores through, and the offset assertions that hold the two
byte-identical — comes from one declaration per object, so a mirror cannot drift from the image it
mirrors. `cfg` is reserved at eight pages rather than the four its 14,156 bytes need, because its
size is the one thing in the system description that cannot be changed locally: it is mapped at a
fixed virtual address in three domains, and everything behind it in that window moves when it grows.
The 256 rule slots are what took it from one page to four; the reservation was doubled at the same
time so the next object to be configured is a table entry rather than a re-lay of that window.

The image has **two readers with different authority**, which is the shape a second consumer takes
here. The forwarder is the *consumer* of that handover — it reads the offered generation,
stages a table and acknowledges, and a commit waits for that. The management domain reads the
**committed** generation alone (`pd_runtime::CommittedReader`) to learn its own addressing: it maps
`cfg` read-only, maps `cfgack` not at all, and therefore cannot delay a commit, refuse one on
anybody's behalf, or forge the acknowledgement that releases one.

`pd_runtime::ConfigurationSwitch` is the consumer. It treats the region as a byzantine peer's
claim — copies the image out before deciding on it, exactly as `RouteStage` snapshots a frame, and
then re-decides the rules itself, in `wire::ConfigImage::check`. **It now re-decides all 41**, at
the validating domain's own strength on all but the two named below, and in a stated order so an
image breaking several is attributed to the first: the two counts against capacity; then per
interface the `enabled` byte, a port this build has, a prefix length past 32, a unicast MAC, a
unicast address and one that is not its prefix's network or broadcast address; then between
interfaces one port each, one MAC each, and disjoint prefixes; then per neighbour a unicast MAC
and address, on the link its port names, not the interface's own address and not that link's
network or broadcast address; then one neighbour per port and address; and finally the management
entry under an interface's own field rules, plus the two that hold it apart from the dataplane — a
prefix disjoint from every interface prefix and a MAC distinct from every interface MAC. Those last
two matter most: they are what makes the isolation the design calls structurally unreachable
enforced on the *untrusted* path rather than only in the domain that parses the document.

**Two deviations, both deliberate and both about values the image does not carry.** A neighbour's
`id` is not in the image at all, so two neighbours sharing one is unrepresentable here — and
nothing downstream of the image consumes such an id. And a *disabled* management entry leaves every
other field of it uninterpreted, so there is no value for a rule to be about; that is also what
gives an unaddressed port one representation and makes a zeroed region the valid fail-closed image.
Both are now recorded in the shared rule list rather than in prose alone: the first is the one rule
the image side declares undecidable, the second is the six it declares conditional on the enable
flag, and both declarations are held to the running code by a test that puts a configuration
breaking each rule through both sides.

A refused image leaves the running configuration exactly as it was and is never acknowledged, so
the publisher never commits it. The switch happens **between two polls** and is provable rather
than claimed: a Microkit domain runs one entrypoint to completion, so a frame is decided entirely
under one generation with no lock involved.

Because the forwarder boots fail-closed on generation 0 and the document the image carries commits
as generation 1, **every boot performs a live configuration swap on a running forwarder**, and every
changed value reaches the console as a structured `LFW-CFG` record (see the
[console reference](../reference/console.md)).

Held by the tests in `datad/crates/config` and `datad/crates/log`, by the handover's own tests in
`datad/crates/pd-runtime` — arbitrary region contents read totally and bounded, forged counts, forged
`enabled` bytes, an image round-tripping through the region — and by the 500,000-frame pipeline
test, which now exchanges the forwarding table at poll boundaries throughout and asserts that no
frame is rewritten out of a blend of two, that the pool comes back whole across every commit
boundary, and that payloads arrive in order under those rewritten headers. Two of the 17 QEMU
system scenarios assert the console transcript, and one of those boots an image built from a second
document that shares no address and no MAC with the first.

**Submitting a document.** `POST /config` on the management port takes an XML document and commits it;
`GET /config` states the one in force. The path is four steps and the trust runs one way through it.

The **management** domain terminates the connection, refuses a `Content-Length` above the 64 KiB the
reader enforces with `413` before a byte of the body is accumulated, and accumulates what it does
accept into the endpoint's one staging array — the same array a `/metrics` exposition is composed in,
which is why a submission in progress answers a concurrent scrape `503` and why a `POST` costs no
second buffer anywhere. It then copies the body into a shared region and hands it on. **It never
parses it.** It holds two frame pipelines, so it is the domain an attacker reaches first and the last
that should be reading an attacker's XML.

**A body that never finishes has a deadline of its own, because that `503` is what one connection
can do to every other.** A peer may declare a body and then trickle it, and the transport's idle
timeout cannot end that: it is refreshed by each arriving byte, so one byte every few minutes keeps
the connection alive indefinitely and the staging array with it — and `/metrics`, `/config` and both
recording downloads answer `503` for as long as it does. **It is reachable with no adversary at all**:
an operator tool that dies mid-`POST` takes the management plane down, including the surfaces they
would use to find out why. So an accumulation that has not completed within thirty seconds is
answered `408`, the array is handed back before a byte of the answer is composed, and the connection
is **reset** rather than closed — a close would leave the peer's half open for it to go on refreshing
that same idle timer from, holding the connection slot instead of the array, which is the same denial
one table along. The span is a constant no peer chooses; a span derived from the declared
`Content-Length` would let a peer buy time by declaring a larger body. Thirty seconds is the whole
64 KiB at about 2 KiB/s and a tenth of the transport's own idle timeout, so this is the deadline that
binds rather than a second copy of that one. `librefirewall_http_bodies_timed_out_total` counts them,
and each one is a stretch in which the other body-bearing surfaces were refusing.

The two channels behind the endpoint carry the same bound for the same reason, because the array is
also held while a *neighbouring domain* decides. A configuration request unanswered for five seconds
is given up on with `503` — nothing about the document is known to be wrong, and what failed is the
node's own ability to decide about it — and a recording window unanswered for ten seconds abandons
the download. Both matter twice over: each domain holds one outstanding-request slot, so without a
deadline a single unanswered request would be the last configuration exchange or the last download
that domain ever completed. A reply arriving after either deadline answers a sequence number no
pending request is held against, which both requesters read as no answer at all, so a late answer
cannot be mistaken for the next request's.

**A deadline is checked on a wakeup, and there is no timer to run it on.** That is sufficient rather
than a compromise: a held array denies only the requests that arrive, and every arrival is a wakeup —
so what a quiet stretch delays is the reclamation of an array nothing is asking for. A stalled or
reversed clock fails in the direction that waits, never the one that fires early, so an operator's
submission is never refused for nothing.

**This is the one behaviour here that is tested and not observed on a running node, and that is a
decision rather than an oversight.** Four host tests pin it exactly — a body given up on at its
deadline and not before, the scrape that was refused being answered once it is, an arriving byte
unable to move the deadline, and the ending being a reset and not a close — and the endpoint-level
one drives a real transport and reads the `408` and the `RST` off the wire it composes. A QEMU
scenario would add thirty seconds of wall clock to every run of the full gate to re-prove what those
four already state, and a scenario that shortened the span to fit would be proving a different
constant from the one that ships. So the gap is recorded here: the deadline is not exercised on a
booted appliance, and a reader who wants it observed is choosing to pay that half-minute.

The **configuration** domain copies the bytes out of that region before looking at a field of them —
the region is peer-written, so a decision taken in place is a decision taken on bytes that may no
longer be there — stages them as the candidate, validates them, and commits. It answers with one line
in the field vocabulary the console's `LFW-CFG` records use: `generation=`, `outcome=`, and for a
refusal `rejected=` and `offset=`. A refusal is `400` and changes nothing; a commit is `200` and
publishes the new image to the forwarding domain, which switches tables at its next poll boundary.

The datastore now **outlives `init`**, which is the whole of what made a second generation possible;
it and one document of scratch are what took the configuration domain's stack from 256 KiB to 512 KiB,
held to those types by a host test rather than discovered as a boot that faults.

Two regions and one channel carry it, `cfg_request` and `cfg_reply`, mirrored so each domain writes
only the direction it speaks in. The management domain may not write the reply, because a management
domain that could would be able to answer `GET /config` with a policy the appliance is not running —
an operator would edit and resubmit that, so a fabricated statement about the policy in force is worse
than a wrong one. The channel is granted in **both** directions and it is the only send capability the
management domain holds in this system: the configuration domain has no polling loop, so a document
written into the region is invisible to it until it is woken.

`GET /config` answers a **rendering of the model in force** rather than the bytes that were
submitted — the bytes are not kept, and the rendering is the stronger answer, being the only one
available for the generation a node commits at boot. It follows that the appliance must be able to
state every configuration it accepts, which is a semantic rule: a document whose canonical form would
outgrow the document bound is refused with `rendering-too-large` rather than committed, because a
policy an operator can read and cannot resubmit is one they cannot edit.

**Held by** the host tests in `datad/crates/config` (the renderer round-trips the shipped document and both
sides of the statable bound), `datad/crates/http` (the body framing: one `Content-Length`, decimal, `POST`
only, no `Transfer-Encoding`, refused past the caller's bound), `datad/crates/ip-endpoint` (a body split
across segments, a peer that overruns its declared length, the method/target routing, a submission
holding the staging array, and the five that hold the body deadline — expiry at the deadline and not
before, the refused scrape answered once the array is back, a trickle unable to move the deadline, a
reset rather than a close, and a stalled or reversed clock expiring nothing), `datad/crates/pd-runtime`
(the channel driven from both ends, every answer shape, a commit that does not move the addressing
keeping the connections open on the port, both channel deadlines with a late answer that must not be
taken for the next request's, and a digest mismatch reported as a node that published incoherent
bytes rather than as a bad document), a fuzz target
over the whole path from the `POST` body to the commit, and the `configuration-submission` QEMU
scenario, which is the evidence that matters: it boots the release image, injects traffic the shipped
policy forwards and traffic it drops, submits a document that exchanges those two verdicts, reads the
running document back, refuses two documents (below), waits for the forwarding domain to report the
committed generation, and injects again — both verdicts reversed, with the totals rising across the
swap rather than resetting.

**Fail-closed is demonstrated on the image in all three of its clauses.** Each is a different thing
that must not happen, and each needed its own experiment.

*A refused document moves nothing.* The `configuration-submission` scenario submits a malformed
document — unterminated, so the *reader* stops it — and the endpoint answers
`400 … outcome=refused rejected=malformed offset=27` with the generation still reading the one that
was committed.

*A refused rule table does not half-apply.* That refusal is almost structural: a document the reader
stops never becomes a model, so there was nothing to commit. The interesting case is a document that
**parses cleanly** and a rule refuses — a whole model exists, its addressing sound, and the rules are
what fail — because that is the only case in which a configuration could half-apply at all. The same
scenario submits one: the shipped document with its two rules given one id. It is answered
`400 … outcome=refused rejected=duplicate-identifier offset=0`, a reason about an *object* rather than
a byte, and three things then hold together. The generation the answer names is the one still running;
`GET /config` still states the committed document as a configuration, so the store did not take part
of what it rejected; and the traffic injected afterwards still gets the committed policy's verdicts,
which is the dataplane's own statement that its table did not change. The refusal is compared against
the reason `config::load` gives the same bytes rather than against a literal, and against the *stage*
that produced it — the two vocabularies are one, so a rule's refusal answering a parse reason would
otherwise pass on the right token for the wrong reason.

*Generation 0 forwards nothing.* Every other scenario boots a document the gate has already proved
the appliance accepts, so none of them can reach the fail-closed generation. The `fail-closed-boot`
scenario builds its image around the same duplicate-id document and boots it. The node comes up, every
protection domain starts, the recorder puts its witness on the medium — and nothing crosses: the
probes it injects are the shipped document's own, between the same endpoints over the same ports, and
their absence is therefore the policy having never been committed rather than a missing route. What it
says about itself is on the console, which is the only surface it has:

```
LFW-CFG time=… generation=0 rejected=duplicate-identifier offset=0
LFW-PD  time=… domain=config state=refused
LFW-CFG time=… generation=0 outcome=applied changes=0
```

and, as the clause with teeth, no `outcome=` record for any generation above zero and no change record
at all. That the document is one the appliance refuses is **declared** rather than discovered: it is
registered as refused in the one list of every configuration document in the tree, and the fast gate
holds it to exactly that — a document listed as refused that every rule accepts fails the gate for
saying so, long before the boot, so the scenario cannot quietly come to prove the opposite of what it
claims.

**Missing.**

- **No authentication, no TLS, no authorization and no rate limit on any of it.** Anything that can
  reach the management port can read this appliance's policy and **replace** it, which is the
  authority to decide what it forwards. The [management design](../design/management.md) now closes
  this by erasing the surface: configuration travels the authenticated channel, and nothing listens
  on an onboarded appliance. Until that exists this is the largest gap in this document, and the
  port must not be exposed to an untrusted network.
- **No rollback.** The [configuration design](../design/configuration.md)'s return to an earlier
  version does not exist. The datastore holds the running configuration and at most one candidate, so
  there is no version history to roll back *to*, and with no persistence there is none worth holding:
  a generation cannot outlive a reboot. What is implemented of the design's versioning is monotonic
  generations and the content comparison beside them that makes re-committing what is already running
  an `unchanged` outcome rather than a new version.
- **No commit-confirm, and now it is a real gap rather than an unreachable one.** The
  candidate/commit half of the [configuration design](../design/configuration.md)'s transaction model
  exists; the confirm half does not, and it cannot be built here yet: an automatic revert needs a
  deadline, and the configuration domain holds no timer and no interrupt — the clock domain publishes
  an instant, not a wakeup. What has changed is the stakes. Until a document could be submitted there
  was no management channel to sever, so commit-confirm protected nothing; now a document that
  validates and moves the management address is a document that locks an operator out of the node it
  was committed on, with nothing to undo it.
- **A submission is answered when it is committed, not when the dataplane has switched.** The
  configuration domain holds no timer, so it cannot bound a wait on the forwarding domain's
  acknowledgement — and a refusal by that domain is the *absence* of one, so waiting would hang a
  client. What an operator confirms a change with is
  `librefirewall_configuration_generation{domain="forwarder"}`, which is why every generation is
  published per domain.
- **No persistence.** A block driver now exists and one domain holds a disk capability
  ([detail](#virtio-blk-driver)) — but it is the recorder, it writes recordings and nothing else, and
  it reaches a second data-only device rather than any partition of the boot disk. The configuration
  domain holds no disk capability, there is no path from it to a medium, and a generation still
  cannot outlive a reboot. The DATA partition, where configuration is meant to live, remains an empty
  unformatted GPT entry (see *[A/B image update](#ab-image-update)*).
- **No distributed rollout.** The staged commit across an HA pair that the
  [configuration design](../design/configuration.md) intends needs a pair; the handover protocol is
  written for exactly one consumer, and "every consumer has staged" is one comparison rather than a
  conjunction.
- **Only interfaces, neighbours, the management port and the filter rules are configurable.** No
  routes, no zones, no NAT — none of which exist to configure. Queue depths, pool sizes and buffer extents
  are deliberately *not* runtime configuration: they are memory-region extents fixed in the system
  description, which is where the [configuration design](../design/configuration.md) draws the line
  at hardware, and moving one would move a capability grant.
- **A refused *boot* document is still only visible on the console.** A node that rejected the
  document its image carries comes up forwarding nothing and says so on a serial line; its
  `librefirewall_configuration_submissions_total{outcome="refused"}` reads 1 and its generation reads
  0, which is a signal — but it has no address, so nothing can ask it for either. A submitted
  document's refusal is answered to the client that submitted it and counted in the same family.
  This is a property of the design rather than an omission, and the `fail-closed-boot` scenario is
  stated within it: the console and the absence of any forwarded frame are its whole evidence,
  because they are the whole of what such a node offers.

## Console device and log transport

**What exists.** The console is a device with exactly one owner. `datad/pds/console` holds the only
I/O-port capability that reaches it — `<ioport id="0" addr="0x3f8" size="8" />`, the PC-compatible
COM1 window — and is the sole writer of the line; every other domain publishes a typed record into
a single-producer ring of its own and that domain drains, renders and transmits it. A record is
therefore whole or absent rather than spliced with another domain's, which is a property of the
capability grant rather than of scheduling.

`datad/crates/uart-16550` carries the register protocol: interrupts off, 115200 8N1, FIFOs enabled and
emptied, each of the six steps confirmed by a readback before the next is attempted, so an absent
controller (`0xFF` everywhere) and one that took the divisor and then refused the word format are
two different typed errors rather than a node that prints nothing and says why nowhere. Every wait
is bounded by a named constant *of the crate's own* — 1,000 reads for the FIFO confirmation, 10,000
for the transmitter-empty poll — so a UART that never asserts THRE costs the domain its output and
never its liveness. It is driven on the host against a fake that misbehaves on demand, including the
property that initialisation and a write both terminate within their advertised operation bounds for
*any* sequence of device answers; a device that could make either spin would hang that test rather
than fail it, which is the failure being excluded.

Reaching a port is an **invocation of a capability**, not an `in`/`out` instruction: seL4 leaves the
TSS I/O permission bitmap denying every port and never edits it, so the `<ioport>` grant makes the
invocation legal and never the instruction. The first implementation read it the other way, held a
correct grant, and faulted with #GP on `out %al,(%dx)` against `0x3F9` at boot. The
`seL4_X86_IOPort_In8`/`Out8` invocations are the way through and `rust-sel4` exposes both as safe
Rust, so the driver and the domain each carry **zero** `unsafe` blocks — the gate's per-crate
`unsafe` budget records a 0 for both, and the clock domain's own port adapter carries zero for the
same reason. `Com1::claim` then reads every register the driver can address before the domain relies
on the capability, so a grant that no longer covers what the driver reaches is a named refusal
rather than a fault in the middle of a console line.

`datad/crates/wire` carries the transport: a 248-byte fixed-layout `LogRecord` whose every offset is a
static assertion, and a 64-slot ring laid across **two** regions with opposite permissions. The
record grew by the eight bytes of its instant and one discriminant byte taken out of existing
padding, and the slot count did not move: the ring is sized for a boot transcript whose first
generation alone is 20 change records, and 64 records of 248 bytes still fit the 16 KiB the region
already rounded to. The records region (slots, producer cursor, the writer's drop count) is
read-write to the writing domain and read-only to the console, so the console cannot forge a line
attributed to a domain that never emitted one — it is the domain whose output is read as testimony
about the others. The consume region (the console's cursor, one word) is read-write to the console
and read-only to the writer, so a writer cannot forge how much of its own ring has been read and
quietly reuse slots the console never rendered. Sixteen regions, 160 KiB, one pair for each of the
eight writing domains; no writer maps another writer's, and the console — which writes no ring of
its own — maps every records half read-only and every consume half read-write.

The console busy-polls and never leaves `init`, exactly as the NIC drivers do — Microkit has no
periodic wakeup, so a `notified`-driven console would stall a boot transcript longer than the
16-byte FIFO until some unrelated domain happened to log again. Its priority is 1, *equal* to the
drivers rather than above them, so a 115200-baud write cannot preempt the dataplane. Attention is
shared round-robin with a rotating start and at most eight records taken from any one ring per pass,
both constants of this build: a domain that fills its ring faster than the line drains costs the
others a delay and never their records.

Two persistent fuzz targets drive it (`log_record`, `log_ring`), the second modelling both sides as
independently hostile — a forged cursor arriving between two steps of one drain, a slot rewritten
one atomic at a time, which is the only granularity at which a torn record is expressible. One
asserts directly that no observability surface can be made to carry what it must not: no record the
ABI accepts can put a byte outside printable ASCII into a rendered console line, and no text value
can carry one outside `[a-z0-9-]`, so a hostile peer cannot paint terminal escape sequences onto an
operator's console.

Every end-to-end scenario now boots the **release** image, and two of the 20 system scenarios
assert the `LFW-CFG` console contract on it, against a transcript derived from the document the
image under test was built from; the same two hold the management port's `LFW-PD` count to the frames
the harness injected, the clock domain's record to the bands its own crates admit, and the hardware
probe's record to its proof — `aes=proven`, `pclmul=proven`, and at least one observed preemption. Both halves were needed to make the defect non-recurring: a missing
console went unnoticed because no gate on the push path booted a release artifact at all, and
because the one stage that did booted it against the forwarding contract alone — and a dataplane is
indifferent to whether anything is printed.

**Missing.**

- **No interrupt.** The transmitter is polled, and the domain never blocks, so the console burns a
  share of a core for as long as the node runs. An interrupt-driven transmitter would remove the
  polling entirely; it needs the system's first `<irq>` element — a second new capability class in
  one change — and was deliberately not bundled with the first `<ioport>`.
- **No `GET /logs` retention ring.** The log rings are a transport to the line, not storage: a
  record the console has rendered is gone. There is no second reader, no retention, and nothing to
  query after the fact — the transcript exists only in whatever captured the serial port.
- **No flow control, in either sense.** The link has none — nothing on either end asserts DTR/RTS,
  and a console that blocked on a peer's readiness would stop reporting exactly when the node is in
  trouble. Nor does the ring throttle a writer: a full ring refuses the *newest* record and counts
  it, so a domain that outruns the line loses records with nothing slowing it down.
- **One port, one baud, both compiled in.** `0x3F8` and a divisor of 1 (115200) are build-time
  constants matched to the `<ioport>` grant, because a runtime base is a value the capability could
  not follow. There is no second console, no second UART, and no way to move either without a
  rebuild.
- **The console is no longer the system's only port holder.** The clock domain holds the CMOS pair,
  so "an attacker reaching any other domain reaches no port instruction" is narrower than it was:
  what holds now is that the two windows are disjoint and each has exactly one holder.
- **No Azure hardware has ever run this.** Azure Serial Console attaches to "ttyS0 or COM1" and QEMU
  q35 exposes COM1 as a 16550A, so this is the same device *by documentation* — which is why there
  is one driver and not two. It is not the same device by test: nothing in this repository has ever
  booted on an Azure VM, and the differences Microsoft documents are about availability (boot
  diagnostics enabled; the serial console possibly unavailable after live-migrating a Generation 2
  Trusted Launch VM with Secure Boot) rather than about registers.
- **The I/O-port CNode slot is hand-rolled and unchecked at build time, now in two places.**
  Microkit publishes a base slot constant for every capability class a domain can hold *except* this
  one, so the slot number is written out in `datad/pds/console/src/com1.rs` and again in
  `datad/pds/clock/src/cmos.rs` as a cross-artifact fact — each read from its own domain's CNode in the
  generated report, the two happening to agree. Its only detection is the
  pinned SDK version (`MICROKIT_VERSION=2.3.0`, checksum-verified, moved only through the full gate)
  read against the generated capability report; nothing compares the two automatically. What limits
  the damage is enforcement rather than detection: `Com1::claim` invokes the capability first, so a
  slot the tool moved is refused by name.
- **The single-writer property is exact only in release.** The debug kernel is built with
  `CONFIG_PRINTING` and writes the *same* port for its boot banner and its fault reports — it is
  handed `debug_port = 0x3f8` on the Multiboot2 command line, which is visible in the capture of any
  debug boot (a diagnostic re-run's `datad/build/image/*-debug.log`, or `make run`) and in none of the
  captures the gate writes, those being release boots. That is accepted, the kernel printing on boot
  and on faults rather than per record, and it is why the claim is stated of the shipped profile.
- **The console cannot report its own failure to start *on the line*, and reports one bit of it
  elsewhere.** From entry into `init` until the register sequence returns, the reporting mechanism
  is what is being started, so nothing about the failure reaches the serial port. What it does reach
  is the metrics shard: the domain publishes from its refusal path, so a scrape that answers with
  `librefirewall_uart_init_failures_total` at 1 names a refused controller — where the counter was
  structurally always zero before. That is one bit against the six distinct errors the driver
  distinguishes, and it says nothing about a refused I/O-port *capability*, which is named only on
  the debug kernel's channel and so never in a release image. Closing the rest needs a reporting
  channel independent of the console.
- **Every counter here is now published rather than only tallied.** The UART's bytes written, THRE
  timeouts and init failures; the renderer's printed, malformed, unknown, unrenderable and
  write-failed; each writer's dropped and refused. All of them are now published and scrapable (see
  *[Prometheus metrics](#prometheus-metrics)*), so a console that is silently dropping records says
  so on the other surface — which is the whole of what closes this, since the console cannot report
  its own silence.
- **A record that will not render is now dropped, not reported.** It is counted as `unrenderable`
  and nothing is written. The previous transport wrote a `LFW-PD unrendered=<debug form>` line
  instead; that line is gone, and the [console reference](../reference/console.md) no longer
  promises it.

## Console system-state events

**What exists.** The five ad-hoc bring-up markers are gone. Call sites in all seven
protection-domain binaries emit **typed events** — a closed set of named fields — and rendering
happens once, in the console domain, so the attribute structure an OpenTelemetry record needs is
produced at the call site rather than thrown away in a format string, and the structure is what
crosses between domains rather than the text. Two channels of closed vocabulary reach the line,
`LFW-PD time=… domain=… state=…` for a domain's lifecycle and `LFW-CFG time=… generation=… …` for
configuration, both specified field for field in the [console reference](../reference/console.md)
and matching the existing `LFW-BOOT` convention, so a reader keys on the `LFW-` prefix alone. The
instant is the first field of both and is the emitting domain's own, taken at the moment of
emission; the pre-kernel `LFW-BOOT` channel has none, having no domain and no calibration behind it.

That the values are safe to print is structural rather than a rule to remember: an event's value
type is a closed set of already-parsed domain types with no arbitrary-bytes variant, and the one
route text takes from a configuration document to a console line is an identifier validated to
`[a-z0-9-]{1,16}` at parse time. Rendering is allocator-free into a caller's buffer and **refuses**
rather than truncates, a truncated line being one an operator reads as complete. The transcript is
a machine-checked contract, not prose: a QEMU scenario derives the records a document must produce
by running that document through the same two calls the domain makes and the same renderer its
console backend uses, then asserts the boot's `LFW-CFG` channel against it — record for record, less
each record's instant, which is the one field a build cannot predict and which a contract of its own
judges over every channel at once.

**Missing.**

- **The forwarder never reports its own outcome.** It emits `state=starting` and nothing further —
  no `ready`, no failure — so the [console reference](../reference/console.md)'s "each stage
  reporting healthy or the specific fault" holds for the driver, configuration, clock, management,
  recorder and hardware-probe domains and not for the one that carries traffic. (The management domain gained a
  refusal path with its transport: it refuses to start at all when the hardware will not produce a
  per-boot secret for its sequence numbers, reports a published calibration it will not use without
  refusing to run, and — new with the recordings — reports an endpoint that could not register both
  download targets, again without refusing to run. The recorder reports the medium it found and
  where each recording lives, which is the only place an operator learns an extent.)
- **Nothing orders one domain's records against another's.** Within a domain they are totally
  ordered — one writer per ring, drained in the order it wrote them, with non-decreasing instants —
  and a `generation`/`seq` pair totally orders one commit's change records. Across domains there is
  no order at all: which ring is served first is decided by where the console's rotation stood. The
  instant every record now carries does not repair that. Two domains' instants are comparable
  arithmetic, but nothing serialises two domains against each other, so a record printed first
  routinely carries the later instant. A boot capture shows the forwarding domain's
  `generation=1 outcome=applied` printed *before* the change records that generation is made of,
  which is not a fault. A reader that infers causality from console order is inferring it from the
  fairness rule.
- **Interleaving is prevented in the shipped profile only.** Records no longer tear: the port has one
  owner and one writer, so a line is whole or absent. That holds exactly in release. The debug
  kernel is built with `CONFIG_PRINTING` and writes the same port for its boot banner and fault
  reports, so a debug capture can still carry kernel prose across a record — which is why the
  [console reference](../reference/console.md) still obliges a reader to recover records by scanning
  for the `LFW-` prefix rather than by assuming one line is one record.
- **No fault or restart events**, because there is no fault handler and no PD restart to report.
- **A record that cannot be rendered or encoded is counted and lost**, where it used to be written
  out in a debug form. See *[Console device and log transport](#console-device-and-log-transport)*.
- **Nothing beyond the console.** These are the OTEL log stream's **System** category by
  construction, and they are the only category with call sites at all — Audit, Traffic and Subsystem
  have none, so three of the design's four categories are empty at the source and not merely at the
  transport. No transport, exporter or receiver exists either (see the
  [status table](../status.md)), so the records reach an operator only over a serial line, on a node
  they are already attached to.

## Full port role model

**What exists.** One of the four port roles the
[deployment design](../design/deployment.md#port-roles) names exists, and it is an **addressed IPv4
endpoint that terminates TCP connections**: a **dedicated management port** that answers for
itself, carries no forwarded traffic, and is isolated from the dataplane by a grant set. It is a
third `virtio-net-pci` device at 00:04.0, driven by a third instance of the same `nic-driver.elf`
the two dataplane ports use — the binary turned out to be port-agnostic already, so the third port
cost it no code change — and its frames end at a `management` protection domain.

That domain answers three protocols and counts everything: an **ARP request** for its own address is
answered with its own MAC; an **ICMP echo request** to it is answered with a reply carrying the same
identifier, sequence and payload and both checksums recomputed; and a **TCP connection** to port 80
is accepted, carried and closed by a first-party stack ([detail](#proxy-tcp-stack)), over which an
HTTP/1.1 server answers `GET /metrics` ([detail](#prometheus-metrics)), `GET /config`, both recording
downloads ([detail](#recording-and-download)) and `POST /config`
([detail](#configuration-management)). Everything else is refused
by name and counted — a frame addressed to somebody else, a VLAN tag, an EtherType or IP protocol it
does not speak, a fragment, a non-unicast or off-link sender, a malformed header.

The decision is three host-tested `no_std` crates. `datad/crates/net-headers` gained ARP (IPv4 over Ethernet
only; any other hardware type, protocol type, address length or operation is a typed error) and ICMP
echo, parsing into fixed-size chunks so no accessor has a panicking path, plus the two reply builders
and one checksum routine. `datad/crates/ip-endpoint` is the endpoint state machine — the appliance answering
*for itself*, as against `datad/crates/pipeline`, which decides what to forward for others — with zero `unsafe`, a closed
`Outcome` vocabulary, and a counter per outcome; it now owns a `datad/crates/tcp` stack and the HTTP
server above it, and keeps the transport's advertised window equal to that server's free
space. `pd_runtime::EndpointStage` joins it to the two pipelines: copy the frame out of the receive
pool, decide, and where a reply was composed take a transmit buffer, write the reply into it and lend
it to the driver.

The addressing is **configured, not compiled in**. `datad/systems/qemu-x86_64/configuration.xml` gained a
`<management mac= address= prefix-length= enabled=/>` element — a sibling of `<interfaces>`, because
the port is not a dataplane port and `config::PORT_COUNT` is still 2 — which the schema requires, the
validator holds to its own rules *and* to not colliding with any dataplane prefix or MAC, and the
handover image carries to the domain. QEMU takes that MAC for the guest NIC, and the harness derives
its own station address from that prefix, so no address on the bench is written down twice.

It also **reads two instructions and holds no capability for either**: `RDTSC`, for the instant its
transport's timers are stated against and for the one on every record it emits, and `RDRAND` once at
start-up, for the secret those connections' initial sequence numbers are derived from. Both are
unprivileged, so nothing in the system description grants or could withhold them; a part with no
`RDRAND` refuses the domain and names the cause on the console rather than answering a `SYN` with a
predictable number. `RDRAND` is now this domain's only `unsafe` block: the counter read moved into
`pd_runtime`, where one seam serves every domain that stamps a record.

The domain reads the **committed** generation only (`pd_runtime::CommittedReader`): it maps the
configuration region read-only, the calibration region read-only, and the acknowledgement region
**not at all**, and so cannot delay a commit, refuse one on anybody's behalf, or forge the
acknowledgement that releases one. That is strictly weaker than the forwarder's role, which is the
consumer of the offer/acknowledge handover. What it costs is stated where it lives: with no channel
to the configuration domain, the port picks up its address on the next frame that wakes it.

The isolation is a grant set, not a rule anybody has to remember. The management domain holds **no**
dataplane region, no device capability and no I/O port; the forwarder holds no management region; the
receive pool it reads is mapped **read-only**, because a frame this appliance was sent is parsed and
never altered; and `xtask::sysdesc` names the mapper set *and the perms* of every region exactly, so a
widened grant fails the gate at the point the edit is made. The management port is not in the router's
port set and no configuration document can put it there.

Its two pools are owned by different domains in opposite directions — the driver owns the receive
pool, the management domain owns the transmit pool it composes replies into — so each `free` ring has
one producer and one consumer and a forged return is refused by a ledger rather than believed. That is
`pd_runtime::EndpointStage`, host-tested against a byzantine driver: forged indices, unbelievable
spans, a stalled return ring, an exhausted transmit pool, a duplicate return on the reply pipeline,
and a pool-sized run proving every buffer comes back.

The QEMU gate asserts all of it on the release image. Every system scenario except the
forced-emulation boot — which injects nothing on that wire, its subject being the accelerator rather
than this port — puts six frames into the management port once the capture proves every port is up:
four opaque frames of four different lengths, an ARP request and an ICMP echo request. It then opens
a TCP connection with a minimal deterministic client of its own, and then requires:

- a **well-formed ARP reply** carrying the configured MAC, decoded and compared field by field;
- a **well-formed ICMP echo reply** with matching identifier, sequence and payload and a valid
  checksum, likewise decoded rather than matched as bytes;
- a **whole TCP exchange**, every step asserted as a field comparison: `SYN` → a `SYN-ACK` whose
  flags and acknowledgement number are checked and whose sequence number is *kept*, → `ACK` carrying
  a `GET /metrics` → the **response as a stream**, fifty-odd segments acknowledged one at a time and
  reassembled in order, its `Content-Length` held to the bytes that arrived → the appliance's `FIN`,
  `Connection: close` obliging it to close first → the client's `FIN` → the final `ACK`. Every
  segment's pseudo-header checksum is verified by the harness's own summation, and a segment arriving
  at a step it does not belong to is refused;
- **distinct initial sequence numbers across the boots**, compared between scenarios — two boots of
  one disk are separated only by the per-boot `RDRAND` secret and the time component, so an equal
  pair would mean one of the two is not reaching the generator (RFC 6528);
- **exactly one of each stateless reply**, since one request is one reply;
- **nothing else on that wire at all** — no opaque frame answered, no dataplane probe leaked;
- and the **mutual exclusion in both directions**: no frame the harness put on the management wire
  ever appears on a dataplane port, and no dataplane probe ever appears on the management port.

Two of the 20 system scenarios additionally hold the console's own record to the frames and the bytes
injected — every one of them, the TCP client's segments included, accumulated as the harness sends
them rather than tallied in advance — to the frame and to the byte; and one of the two boots a
*second* document whose management MAC, address and prefix all differ, so a compiled-in address could
not satisfy it.

**Missing.**

- **No TLS, and now that gap carries a write.** HTTP answers `GET /metrics`
  ([detail](#prometheus-metrics)), `GET /config`, both recordings
  ([detail](#recording-and-download)) and `POST /config` ([detail](#configuration-management)) — all
  in the clear, with no authentication and no authorization split, so **anything that can reach the
  port can scrape it, download every packet the appliance recorded, read its policy, and replace
  that policy** — which is the authority to decide what this firewall forwards. The
  [management design](../design/management.md) erases this surface in favor of onboarding and the
  authenticated channel; until that exists the port belongs on an isolated network. `/logs` does
  not exist, so of the debug dump the
  [observability reference](../reference/observability.md) describes, the state half, the running
  document and the two recordings are what a node can be asked for and the retained records cannot be.
- **A neighbour cache exists and nothing on the port uses it yet.** `lfw_ip_endpoint::neighbour`
  holds the hardware address of a next hop and decides when to ask for one, under three rules that
  each remove a poisoning primitive rather than narrowing one: only a reply this end asked for is
  ever learned, so an unsolicited or gratuitous reply is inert and a flood of distinct addresses
  cannot insert a single entry; a resolved entry is immutable for its lifetime, so no later answer
  can re-bind a live next hop, at the stated cost that a hardware address which genuinely changes
  goes unnoticed for up to a minute; and a hardware address no frame may be addressed to is refused
  before anything else is considered. The table is a fixed four entries, a resolution sends at most
  three requests a second apart and is then *reported* as unreachable rather than left waiting, and
  nothing is queued behind an unresolved next hop — a segment for one is dropped, because holding it
  would mean owning a buffer this crate owns nowhere and the transport already re-sends. Held by unit
  and property tests and by the `neighbour_cache` fuzz target, whose invariant is the poisoning one
  rather than the absence of a panic. **Missing:** the endpoint neither answers with a request nor
  feeds a reply into it, so no entry has ever been learned on a running node, and its counters reach
  no surface.
- **An ARP request can be written and nothing sends one yet.** `net_headers::ArpRequest` composes the
  question beside the reply that answers one, and the two are separate types rather than one carrying
  an operation field: a request is a frame this appliance originates on its own account, so it always
  goes to the broadcast address and names no target station — which makes the frame a caller writes by
  mistake, one addressed to a station it has not resolved yet, unrepresentable rather than merely
  wrong. **Missing:** the endpoint composes none, so no request has left a running node.
- **A route decision exists and nothing consults it yet.** `lfw_ip_endpoint::route` answers which
  station a datagram this appliance originates is handed to: the destination itself where it shares the
  port's prefix, the port's stated gateway where it does not, and a typed refusal otherwise. Every
  refusal is about this node's own configuration or its own choice of destination, never about a frame
  somebody sent — a destination or gateway no frame may be addressed towards, a destination that is
  this port's own address, a gateway off the port's link or equal to its address, and an off-link
  destination with no gateway at all, which is refused rather than asked about on-link anyway. Two
  properties are what the neighbour cache rests on and are held at property level: an address this
  decision hands back is always a unicast station other than this port's own, and it is always inside
  the port's own prefix — so no resolution can be started for a group address, and none can ask the
  wrong link. What it deliberately is not, each with a reason in the module: no route table and so no
  choice of interface, no metrics or route preference, no default-route election, no dynamic routing.
  **Missing:** nothing supplies a gateway — the configuration schema has none — and nothing calls it,
  so no route has been decided on a running node.
- **An RFC 5227 probe (sender address 0.0.0.0) is refused rather than answered**, so a second station
  claiming this address is not contradicted.
- **A reply is only ever composed for a neighbour**: the sender must share the port's prefix, because
  the route decision above is consulted by nothing and this endpoint holds no gateway. An off-link
  station is refused and counted.
- **The counters now reach a surface.** The console still carries only the port's cumulative
  `frames=`/`bytes=` pair, but every outcome the endpoint distinguishes — and every reply it could
  not send — is published as the `librefirewall_endpoint_*` families and scrapable; see
  [Prometheus metrics](../reference/metrics.md).
- **A change to the `management` object is audited like any other**, but only because the change
  records are keyed by a synthetic identifier: the element has no `id` of its own, so every record
  about it reads `object=management key=management`.
- **Nothing bounds the rate of requests to this port.** The
  [management design](../design/management.md) requires its onboarding endpoints rate-limited with
  backoff; the surface serving today is not those endpoints and bounds nothing. The only
  rate bound anywhere in the appliance is RFC 5961 §7's per-second budget on *unsolicited replies*,
  shared across the connection table — which caps what this node emits at a peer and caps nothing a
  peer sends at it. What does exist against a flood is bounded state rather than a bounded rate: a
  fixed connection table, reaped by timeout and under pressure ([detail](#proxy-tcp-stack)), and one
  response staged at a time.
- **No other role.** Session-replication, mirror and multiple port pairs are open, and so are the
  3/4/6/7-NIC hardware image variants: there is one system description with three ports in it. The
  `role` label on `librefirewall_interface_info` is closed at the two roles that have ports —
  `dataplane` and `management` — and gains a token when a port in another role exists, never
  before it.

## Proxy TCP stack

**What exists.** `datad/crates/tcp` is a first-party TCP implementation that completes a real handshake
with a real client, carries a byte stream, and closes cleanly — proven on the booting **release**
image by the gate performing a whole TCP exchange against the management port. It is not a
management-endpoint toy: it is the stack the dataplane proxy will run on, and every constraint below
comes from that.

It was chosen over smoltcp for one reason: smoltcp carries a stream through `RingBuffer` socket
buffers, and a copy per segment is what a zero-copy pool design cannot afford. So **the crate owns
no buffers at all.** A received segment arrives as `&[u8]` — in the appliance, a pool buffer a NIC
DMA'd into — and the in-order payload comes back out as a subslice of it; a segment to send is
composed into a `&mut [u8]` the caller supplies, at the offset it will finally occupy, and
`net_headers::Ipv4Frame` stamps the two headers in front of it afterwards, so a payload is written
exactly once. The cost is a real obligation, and it is in the type system rather than in prose:
`Timeout::Retransmit` names a sequence range the caller must supply the bytes of again, because the
stack did not keep them. That is where a send buffer belongs — with the application that produced
the bytes.

**State is per shard and nothing is shared.** A `TcpStack<CONNECTIONS>` owns its whole connection
table and reaches no `static`, no lock, no cell and no atomic; every method takes `&mut self`, so
several instances run on several cores with no coordination and the compiler is what says so. The
capacity is a const generic, so a shard's memory is fixed at compile time and sized by its caller.
There is no allocator and no `alloc`.

**One port, in both directions.** A stack answers on one port and dials from that same port: a
segment is matched to a connection by the peer's address and port alone, so a second local port
would be a second key the table does not carry, and a dial from an ephemeral one would arrive back
at a port the stack refuses. The appliance's outbound connection therefore carries its management
port's own number as its source port — unusual on the wire, entirely legal, and the price of a table
one number wide. A dial and an inbound connection coexist unless they name the same peer address and
port, which is the one case a dial refuses outright.

What the stack implements, completely:

- **RFC 793's state machine**, both ways it can be entered: `LISTEN` → `SYN_RECEIVED` and
  `SYN_SENT` → `ESTABLISHED` → `CLOSE_WAIT`/`LAST_ACK`, `FIN_WAIT_1`/`FIN_WAIT_2`, `CLOSING` (the
  simultaneous close), `TIME_WAIT` and `CLOSED`.
- **The active open.** A connect entry point composes a `SYN` and returns a connection in
  `SYN_SENT`; RFC 793 p.66's arrival processing follows that section's own order, and the order is
  the security property. An acknowledgement is checked before a reset is believed, so a reset a peer
  sends in the blind cannot cancel a dial; an answer acknowledging a number this end never sent
  draws a reset carrying that number and **leaves the dial standing**, because one forged segment
  must not be able to cancel this node's dial; and a `SYN` with no acknowledgement is the
  **simultaneous open**, which moves the connection to `SYN_RECEIVED` and re-uses the sequence
  number the outstanding record already covers, so the timer that was arming for the `SYN` arms for
  the `SYN-ACK` and nothing else moves. A `SYN` is retransmitted under the same RFC 6298 backoff as
  any other segment and an unanswered dial is abandoned at the retransmission limit — at least 31
  seconds — **in silence**: nothing at the far end ever answered, so there is no connection for a
  reset to end and a frame sent anyway would only confirm this node's presence to an address that
  said nothing. A dial never evicts, which is the eviction rule read from the other side: a table
  full of live connections is one an operator is using, and a peer flooding `SYN`s cannot evict a
  dial either, so neither end can cancel the other's half-open connections.
- **Sequence-number validation.** RFC 793 p.69's four-case acceptability test; an out-of-window
  segment is answered with an acknowledgement naming what was expected and never accepted, and a
  retransmission overlapping the window's left edge is trimmed rather than refused.
- **RFC 5961 in full**, applied in *every* state rather than only the synchronized ones. §3's `RST`
  is obeyed only at the exact next byte expected, and an in-window one that is not — like an
  in-window `SYN` — draws a challenge acknowledgement. §5's left-edge test
  (`SEG.ACK >= SND.UNA - MAX.SND.WND`) refuses an acknowledgement from too far behind. §7's
  **per-second challenge budget, shared across the whole table**, bounds every unsolicited reply the
  stack would emit — a challenge acknowledgement, and the reset a segment naming no connection would
  draw — so the node cannot be made an amplifier by a spoofed source. A `RST` that ends a connection
  is never withheld by it, and a suppression is counted rather than silent.
- **RFC 6298 retransmission**: SRTT and RTTVAR with the RFC's own α and β, the RFC's one-second
  floor, a 60-second ceiling, exponential backoff, and Karn's algorithm — a range that has been
  re-sent yields no round-trip sample. The `SYN-ACK` and the `FIN` the stack composes itself; data
  it asks the caller for.
- **RFC 6528 initial sequence numbers**: a 4-microsecond time component plus SipHash-2-4 of the
  4-tuple under a 128-bit per-boot secret. The hash is first-party and held to the published
  reference vectors, so it is checked against something other than itself. The secret comes from
  `RDRAND` in the protection domain; a part without it refuses the domain rather than answering with
  a predictable number, because a predictable one is an off-path injection primitive against exactly
  the party this port faces.
- **Bounded state under a flood.** A fixed table, reaped by timeout *and* by capacity pressure —
  the oldest reapable entry gives way, and a table of *established* connections refuses a new one
  rather than letting a peer that completes handshakes evict everybody else. Every connection
  becomes reapable in finite time, which is a property test rather than a claim. An eviction is
  reported to the layers above so they reconcile against the transport, a peer that closes without
  sending a byte is closed on rather than left holding a slot, and `TIME_WAIT` restarts only on a
  retransmitted remote `FIN` (RFC 793 §3.9) — three ways a slot used to be pinned by a peer's
  choice.
- **MSS clamping** (the peer's offer against this end's own limit, with RFC 1122's default and
  floor), **window scaling** (RFC 7323, negotiated at the `SYN` and clamped to shift 14), and
  correct pseudo-header checksums both ways.
- **The advertised window is the receiver's free space**, not a constant: `lfw_ip_endpoint`'s HTTP
  server keeps it equal to the room it has left, so a peer is never told it may send more than the
  endpoint can take.

Every outcome is counted, one field per cause — twenty-nine of them — under the
[metrics reference](../reference/metrics.md)'s attribution rule: what a peer sent that was refused,
and separately the one count that accuses this code (`write_refused`, storage too small, expected to
read zero forever). There is no device class here, because nothing in the crate reads a register.

Zero `unsafe` (`forbid(unsafe_code)`), zero panicking constructs on any path a segment reaches, and
sequence arithmetic that is modulo-2^32 by construction: `SeqNumber` exposes no `Add`, `Sub` or
`Ord`, because the derivable ones are all wrong across the wrap. Held by unit and property tests
over every state the machine has, plus a persistent fuzz target that drives arbitrary segments at
arbitrary instants — including a clock that moves backwards — against a listening stack and an
established one.

**Missing.**

- **No SACK.** Its value is retransmitting the holes in a reassembly queue, and there is no
  reassembly queue — that would be a buffer the crate owns. The SACK-permitted option is parsed and
  recorded, so adding it is a change to the state machine rather than to the parser.
- **No reassembly, so no out-of-order data.** In-window payload ahead of the next byte expected is
  dropped and re-requested by the acknowledgement that follows, counted as `refused_out_of_order`.
  On a lossless in-order link — a management port, a same-host proxy hop — the case does not arise;
  on a reordering path it costs a round trip per reorder.
- **No congestion control**, no delayed acknowledgement, no Nagle. The structural place for the
  first is `Connection::sendable`; the other two need a timer this stack is not driven by.
- **The urgent pointer is ignored.** `URG` data is delivered in band and counted.
- **No dataplane consumer.** The only caller is the management domain. Nothing proxies, nothing
  terminates TLS, and no throughput has been measured — the 10 Gbit/s target this design exists for
  is untouched (see the [status table](../status.md)).
- **`RDRAND` is now a hard hardware requirement.** A part whose `CPUID.01H:ECX[30]` is clear refuses
  the management domain outright, so that node has no management port for the boot. The QEMU bench had
  to be told to expose it (`datad/tools/xtask/src/qemu.rs`); every deployment target must have it. There is
  no software fallback and deliberately so — the alternative is a predictable sequence number, which
  is worse than no port.
- **Timers advance when the caller polls them.** The management domain is woken by a frame, so a
  `TIME_WAIT` on an otherwise silent port is reaped on the next frame rather than at its deadline.
  Bounded rather than unbounded — the table is also reaped under pressure — but not prompt.
- **The counters now reach a surface.** All twenty-seven are published as
  `librefirewall_tcp_*` and scrapable; see *[Prometheus metrics](#prometheus-metrics)* and the
  [metrics reference](../reference/metrics.md).

## Prometheus metrics

**What exists.** `GET /metrics` on the management port answers a real Prometheus exposition — 97
metric families and 350 counter and gauge series, plus one info series per configured interface and
one hit counter per rule the running policy declares — covering every one of the ten protection
domains. Its worst case is computed from the catalogue at build time (`MAX_EXPOSITION_LEN`,
81 075 bytes), which is what the response staging buffer behind the endpoint is sized from, so a
scrape can never be short. That bound is dominated by the rules: it covers a policy naming all 256
the configuration accepts, so it is sized by what an operator is entitled to write rather than by
what a node happens to be running. The end-to-end gate scrapes it with `curl` off a booted release
image and cross-checks two numbers in it against traffic the harness watched cross the wire
itself — the frames the appliance forwarded, and the hits against the rule that permitted them.

**A per-NIC series is joinable to the interface a configuration document names.** Every counter
family carries `domain`, the protection domain that produced it, and `domain="nic_driver0"` is a name
out of the Microkit system description that says nothing about what an operator configured. Closing
that took the conventional Prometheus info metric rather than more labels on the counters:
`librefirewall_interface_info` is a gauge whose value is always `1`, one series per configured
interface, carrying the document's own `id`, the port's `role`, its address, prefix length and MAC —
and carrying `domain` as the join key, so a query multiplies the two together
(`* on(domain) group_left(interface, role, address)`). Counter cardinality is unchanged and a
re-addressed interface does not fork every counter series it has. There is deliberately no `enabled`
label: a dataplane interface has a series whether or not it is enabled — its addressing is in the
image either way, because the router needs the row to refuse traffic on it — while a disabled
`<management>` element is indistinguishable from an absent one, so a truthful `enabled` would have to
be ragged across the two roles and nothing consumes it. The
[metrics reference](../reference/metrics.md) states the family, the worked join, the bound on its
cardinality and that asymmetry; the interface identity crosses to the management domain in the
configuration image it already reads, and the port-to-driver mapping the join key rests on is a fact
of the system description that `xtask::sysdesc` now checks at build time rather than a comment
delegating it to a caller.

**A per-rule series is joinable the same way, and by the same argument.** The per-rule hit counters
sit in the forwarding domain's own shard, indexed by a rule's position in the running generation, and
the `rule` label is the id out of the configuration image the management domain maps read-only —
joined on the position. So a hit is a number only the forwarder could have written under a name only
an operator could have chosen, which is the `domain` label's argument one level finer. A position no
generation declared reaches no series at all: a counter under nobody's name is not something to
expose.

The decision that shapes it is **one shared-memory counter shard per protection domain**, not one
shared table. A shard is a 3,136-byte, cache-line aligned array of 392 `AtomicU64` slots, mapped
read-write into the one domain that owns it and read-only into the management domain; slot order is
the catalogue's series order, asserted statically. Every shard is that wide because the widest set a
domain publishes — the forwarder's, whose per-rule block reserves one slot per rule the ABI admits —
is what the width is derived from, and it costs nothing: a shard is its own region and a region is a
page, so the reservation was already a page before the block existed. A second region carrying the
rule counters alone would have bought back no memory and added a mapping to the domain that faces the
management-plane attacker. So a domain publishes by relaxed store into memory
nobody else may write, and the management domain renders by reading nine regions — no lock, no
barrier, no seqlock, and nothing a dataplane domain does on a scrape. Counters are individually
meaningful, so a scrape that straddles two domains' publications is still exactly what each of them
last wrote; that is stated as a freshness boundary in the
[metrics reference](../reference/metrics.md) rather than papered over.

The exposition is rendered by `datad/crates/metrics` (`no_std`, panic-free, with a computed
`MAX_EXPOSITION_LEN` so the buffer can never be short) and the requests are parsed by `datad/crates/http`
(`no_std`, a bounded server-side HTTP/1.1 head parser that returns a typed error mapping onto one of
eight statuses). Both are fuzzed. The management domain's own shard is stored before the exposition
is composed rather than after, which is why a scrape is never one request behind its own surface —
stated as a freshness property in the [metrics reference](../reference/metrics.md).

**Missing.**

- **No TLS — the endpoint is plain HTTP with no client authentication, and no bound on how often it
  may be asked.** Anyone who can reach the port can scrape it as fast as they like, and the
  exposition names every domain, drop reason and fault class in the node. The
  [management design](../design/management.md) removes this endpoint outright — metrics become
  snapshots in the ring, shipped over the authenticated channel — and until then the gap is
  recorded here and in `lfw_ip_endpoint`'s crate header, and it gates any deployment on a network
  the management port is not already isolated on.
- **One response is staged at a time.** A scrape arriving while another is still going out is
  answered `503` and counted. A finished-but-not-yet-reaped connection's buffer is reclaimed rather
  than waited out, so a periodic scraper is never refused for the previous scrape — but two
  *concurrent* scrapers can refuse each other.
- **Coverage is what exists to be counted.** Per-core counters await the multicore dataplane, and
  log-buffer occupancy awaits the buffer. The connection table now publishes its own — its
  occupancy by state, its lifecycle and every refusal. Occupancy is the
  one that is now half here: `librefirewall_virtqueue_posted` publishes how many buffers each port
  has posted to its device and not yet had completed, which is the only reading that tells a
  stalled port from an idle link, while the dataplane's own queues and rings still publish none.
  None of the absences are oversights.
- **No `/config` and no `/logs`**, so of the debug dump only the state half and the two recordings
  can be asked for ([detail](#full-port-role-model)).

## Trusted time source

**What exists.** A node establishes a wall-clock time at boot, and the whole chain that does it is
host-tested library code driven by a thin domain. `datad/crates/clock` is the arithmetic — a tick delta
and a reference interval to a counter frequency, a counter reading to nanoseconds since boot or
since the epoch, an instant to a civil date and to an RFC 3339 line — with Hinnant's era
decomposition proved by an exhaustive round trip over every day a `u64` of nanoseconds can name.
`datad/crates/hpet` is the reference measurement: it decides whether the block at `0xFED00000` is an HPET,
starts its main counter and measures a bounded span of it, and it earns that role by being
*self-describing* — the capabilities register states its own tick period, so no frequency is
assumed anywhere. `datad/crates/rtc` is the epoch: the CMOS index/data protocol, two agreeing snapshots
before anything is decoded, and every field ranged.

`datad/pds/clock` joins them. It maps the HPET page (three `unsafe` volatile accesses, each naming the
`<memory_region>` row that guarantees it), holds an `<ioport>` for `0x70`–`0x71` and proves the
capability answers before relying on it, calibrates over a one-millisecond window, reads the part
once, and emits a single `LFW-PD domain=clock state=ready tsc-hz=… utc=…` record. Every stage that
can refuse does so with a typed error carrying what the device answered; the domain turns each into
one of 25 console cause tokens and parks. Two of the 19 QEMU system scenarios assert that record
on the release image — that it is `ready`, that its frequency is inside the band the calibration
accepts, and that its year is inside the band the RTC reader accepts. The counter reading and the
wall-clock instant are anchored to one moment, the counter being re-read after the RTC, so the
published clock does not run ahead by the cost of reading the part.

**Every domain consumes it, and every structured record carries an instant.** The calibration goes
into a shared region (`wire::ClockCalibration`, a seqlock: even settled, odd being written) that the
clock domain maps read-write and the other nine read-only. Each reads `RDTSC` itself — one
unprivileged instruction, behind the single `unsafe` seam in `pd_runtime::read_timestamp_counter` —
converts it with the published triple, and stamps the record it is about to emit, so an instant is
this node's own arithmetic over one counter rather than a value passed between domains. The console
renders it as a leading `time=` field in RFC 3339 with all nine fractional digits. A domain that has
no calibration yet emits `time=unsynchronized`: the absence is a case of the type all the way down
(`wire::CheckedStamp`, `lfw_log::Stamp`) rather than a zero, so no record can be dated 1970 by
accident. That is most of a boot transcript, the clock domain's own two records included — it
publishes *after* the record that states what it measured. The same two scenarios assert the whole
of this against the release image: that every record carries the field in one of its two forms, that
every instant is inside the RTC reader's year band, that no domain goes back to `unsynchronized`
after stamping, and that no domain's instants go backwards. The one-way transition is a fact about
*this* clock domain — it publishes once and parks — and not a property of the field: a reader
re-reads the region on every question by design, and answers `unsynchronized` again for a
calibration that is torn under the read or outside the band it accepts, having refused it.

**Missing** — and it is everything the word *trusted* covers:

- **The time is unauthenticated and unattested.** It comes from a battery-backed register file that
  any firmware, hypervisor or dead battery can make say anything plausible. There is no NTP, no
  Roughtime, no signed time source and no attestation, so a wrong-but-plausible instant is
  indistinguishable from a right one. The [threat model](../design/threat-model.md) now records a
  deliberate split over what may be judged against it: the management channel's certificate
  validity is judged against this clock, trusting the hardware; TLS-interception validation — the
  appliance judging upstream certificates on behalf of protected clients — may not be, and its
  trusted source remains open.
- **UTC is assumed, not discovered.** The CMOS carries no field saying whether it holds UTC or local
  time. A machine whose firmware set it to local time yields an epoch wrong by that zone's offset,
  detectably by nothing.
- **Accurate to about a second, and nothing checks that.** The epoch is one whole-second CMOS
  reading; the nanoseconds under it are elapsed counter ticks, which are precise and say nothing
  about how well the epoch was set. A record's instant is therefore good enough to line a node up
  against an external log to about a second, and is evidence of nothing.
- **No metric says which domain has taken the calibration up.** It is readable per record on the log
  stream (`time=unsynchronized` against an instant) and `/metrics` carries the gauge for the
  management domain alone; the other eight writing domains publish no such series (see the
  [metrics reference](../reference/metrics.md)).
- **No discipline and no monotonic guarantee across domains.** The part is read exactly once and
  never corrected; there is no timer, no interrupt, and no second reading to drift against.
- **Single-core assumption.** The calibration is a reading of one core's counter, with no check that
  the counter is invariant and no per-core anchoring — neither of which matters on the single vCPU
  this system runs on and both of which would on any multicore variant.
- **The measurement is biased high by its own overhead**, by one uncached timer read at each end of
  the window: parts in a thousand at worst, stated in `datad/pds/clock` rather than corrected, because
  subtracting an estimate would replace a bounded one-signed error with an unbounded one.

## Protection-domain decomposition

**What exists.** Twelve protection domains from ten binaries (one forwarder, one configuration
domain, one console, one clock, one management domain, one recorder, one hardware probe, one
cryptography domain, one store domain, three driver instances of one driver binary) with real,
verifiable least privilege: the forwarder holds no device capability
at all and neither dataplane pipeline's `free` ring — so it cannot hand a live DMA target back to
be issued a second time — and each driver sees only its own ECAM page, BAR, virtqueue region, and
its two pipelines. Each pipeline is three memory regions rather than one precisely so that those
grants can differ; the forwarder maps the buffer pools, because a domain that rewrites a header
must reach the bytes. It also maps the connection table, and that is the one region in the system a
domain holds **alone**: nothing else maps it in either direction, which is what makes the exclusive
borrow of it sound rather than merely uncontended, and it carries no physical address so no device
can be handed it either. The recorder is the mirror of that argument in the other direction: it is
the only domain that reaches its block device — its ECAM page, BAR, DMA region and staging window
are mapped by nothing else — and it maps no pool, no ring, no NIC region and no port, so the
domain that owns that disk reaches no frame and the domains that move frames reach no medium. **The
store domain is the same argument again, over a second block device**, and the pair of them is the
sharper claim: neither reaches any part of the other's device, so the domain that answers a download
cannot read the appliance's private key and the domain that holds the key cannot read a recording. What
crosses between them is the tap ring, carrying the forwarder's own bounded copy of each frame it
decided on and its decision about it — never a descriptor, a buffer index or any other way to reach
a frame still in flight — mirrored in perms so neither end can forge the other's half. The configuration domain's entire grant is six mappings —
`cfg` read-write, `cfgack` read-only, the calibration read-only, its own log ring's two halves and
its counter shard — and the negative half is what matters: no device, no pool, no ring, so the
domain that parses attacker-supplied XML cannot reach a frame or a NIC. The two handover regions
are one per direction and their perms are the argument — the forwarder maps the handover
**read-only**, so it cannot rewrite the configuration it is about to be judged by, and the
publisher maps the acknowledgement read-only, so it cannot forge the consent that releases its own
generation.

Five notification channels. The three driver channels are granted in **one direction only** — a driver
may signal its consumer, and that consumer's send capability on the driver does not exist rather
than merely going unexercised. The recorder's channel to the management domain is one-directional
too, and in the opposite sense: the recorder may announce a download window, and the management
domain may not signal back, because the recorder busy-polls its request region and a send capability
it does not need is one it must not hold. The fifth, between the configuration domain and the
forwarder, is the one granted in **both**, and stated as a decision at both ends rather than
inherited from Microkit's default: the offer/acknowledge handover has a step in each direction and
neither end can infer the other's. The forwarder therefore holds exactly one send capability in
the whole system, on the configuration domain alone, and the management domain holds none at all.
The console holds none in either direction — it never reaches the event loop, so a notification on
it would be authority granted for nothing. Zero IRQs. The capability grant is machine-checkable in
the Microkit capability/memory report the build generates.

Two **`<ioport>` grants**, on two domains, and they are the whole of the system's port authority.
Neither of the two instructions the management domain reads is one: `RDTSC` and `RDRAND` are
unprivileged, so no grant makes them available and none could withhold them — which is why a part
without `RDRAND` is a refusal that domain reports rather than a capability anybody could add.
The console holds eight ports (`0x3F8`–`0x3FF`, COM1) and the clock two (`0x70`–`0x71`, the CMOS
address and data registers); the other 65,526 are refused to every domain — notably the
`0xCF8`/`0xCFC` PCI configuration pair, which would be a second path to every device's configuration
space beside the ECAM mappings the drivers hold. The two windows are disjoint and neither domain
holds the other's, so the domain that renders an operator's only output cannot read or stop the
clock and the domain that reads a battery-backed register file cannot write the line its result
appears on. The drivers, the forwarder and the management domain hold zero ports between them. Each
of the two in turn holds no pool, no dataplane ring and no configuration region, and the clock
additionally holds no ECAM page and no BAR window beyond the single timer page it maps — so a
compromise of either reaches no frame, no NIC and no configuration.

The management domain's grant is its own port's two pipelines, the configuration and calibration
regions **read-only**, and its own log ring; what it withholds is the whole of the port isolation: no
dataplane region of any kind, no ECAM page, no BAR window, no virtqueue, no I/O port and no
acknowledgement region. Of the six pipeline regions the receive **pool** is read-only — a frame this
appliance was sent is parsed and never altered — while the transmit pool is read-write, because a
reply is a frame this domain originates into a buffer it owns. The two read-only grants are the
argument in each case: a domain that could write `cfg` would rewrite the addressing it is about to be
judged by, and one that could write the calibration would move this node's own idea of time — every
transport deadline on its port — from the one domain that answers the management-plane attacker. The
one region it is granted read-write that the forwarder is refused is the receive pipeline's `free`
ring, and it is the side of it that differs: a terminal port has no egress driver to return its
buffers, so this domain **produces** returns while the driver **consumes** them as the pool's owner —
the split the dataplane already has between its two drivers, which is what keeps a forged return
refused by the ledger rather than believed.

Reaching a port is an **invocation**, never an `in`/`out` instruction; that lesson was paid for once
on the console's first boot and `datad/pds/clock/src/cmos.rs` is written from it. Both domains prove the
capability answers before relying on it, so a slot the Microkit tool moved is a named refusal rather
than a fault mid-sequence.

**Missing.** Two of the component classes the [architecture design](../design/architecture.md)
offers as representative exist: the NIC driver PDs and the configuration validator PD. (That list
is explicitly representative rather than closed, so it is not a denominator and no count against it
is stated here.) The console, clock and
management domains are three further domains and *not* three further classes — the design names
neither, describing the console as a surface and leaving the trusted-time mechanism open — so they
add domains to the decomposition without closing any of the gap below; the management domain is
the endpoint of a port, not the management API PD, which needs the TLS and HTTP that do not exist
above the ARP, IP and TCP that now do. Absent: Rx/Tx
virtualisers, classifier, filter/connection-tracking, routing/ARP/ICMP, TLS-proxy, per-protocol L7
parsers, DPI engine, content scanner, CA signing PD, management API PD, HA state-sync PD, and the
update/health PD. The routing/ARP/ICMP class is the one that is neither: routing exists as one
*stage of the forwarder's verdict pipeline* rather than as a domain of its own, and ARP and ICMP do
not exist at all. That pipeline is where the classifier and the filter/connection-tracking classes
would go if they were domains of their own; today it is the seam and holds two stages.
There is no fault handler and no PD restart, one system description, and no SMP variant.

One grant is also wider than the code needs, and it is not closed:

- **The `-m 1G` QEMU memory size is load-bearing and unasserted.** It is what keeps the virtqueue
  and pipeline regions inside RAM while leaving the BAR window above RAM in the q35 PCI hole. The
  window either side is narrow, and each region added narrows it further: the store device's 256 KiB
  staging window was the last to do so, and RAM must now reach past 785.05 MiB where the recorder's
  device alone needed 784.80 MiB and the three ports alone 784.55 MiB. At 1280 MiB or more RAM
  swallows the BAR window instead. The reasoning is recorded in the system description; no code
  enforces either end of it.

## Untrusted-device hardening

**What exists.** Every byte the device writes — configuration-space ids, the capability chain, BAR
type bits, structure offsets, the feature bitmap, the `device_status` readback, the queue count,
each queue's `queue_notify_off`, and every used-ring completion — is treated as hostile input and
**rejected with a typed error or a counted drop, never by panicking**.

What remains of `assert!` and `expect` on these paths is a different thing and stays deliberately:
checks of a domain's *own* invariant, each stating the proof that no device value reaches it and
naming the component that establishes that. Every one of them is unconditional in every build
profile rather than a `debug_assert!`, and `overflow-checks` is on in the shipped profile, so the
arithmetic the property tests prove panic-free is the arithmetic that ships.

Held by the hostile-device cases in `datad/crates/virtio` and `datad/crates/nic-driver-core`, plus two
device-facing persistent fuzz targets (`find_virtio_caps`, `virtqueue_poll`) and a third
(`nic_driver_paths`) that drives a hostile device and a byzantine forwarder at once. Each models the
device's full authority over the shared region rather than a well-behaved subset of it.

`datad/crates/uart-16550` is the second device this applies to and the smaller one: every byte it reads
back is the controller's choice, a controller that never answers is indistinguishable from one that
answers wrongly, and both are met the same way — every wait bounded by a constant of the crate's
own, every refusal a typed error and a counter, and a property test asserting that initialisation
and a write each terminate within their advertised bound for *any* sequence of device answers.

**Missing.**

- **The device's DMA is not confined.** Bus-master DMA is enabled against fixed physical addresses
  with no IOMMU (the *IOMMU (VT-d) DMA confinement* row in the [status table](../status.md)). Every
  check listed here bounds what the driver *believes*; none of them bounds where the device can
  *write*. This is the single largest residual against the
  [threat model](../design/threat-model.md)'s hostile-device adversary, and no first-party code can
  substitute for VT-d.
- **No restart.** A device that fails bring-up leaves its port permanently down (see
  *[virtio-net driver](#virtio-net-driver)*).

## Untrusted-peer containment

**What exists.** Buffer ownership is accounted **by identity**, not by count:
`packet_buffer::FreeList` refuses to reclaim an index that is out of range or not outstanding, and
`pd_runtime::PoolOwner` refuses one this domain never lent. A *local* double return is not
representable, `pop` minting a non-`Copy`, non-`Clone` `OwnedBuffer` token.

Every rejection is a **counted drop**, never a fault: `PoolCounters` and `RouteCounters` record
them, the latter attributing every refused frame to one of the thirteen named pipeline reasons or to
the stage check that caught it. `ConfigCounters` does the same for the handover, so a publisher offering
images this domain will not run is distinguishable from one that has stopped offering any.
Descriptors from a peer are range-validated (`descriptor_in_bounds`, plus the transmit header-room
check) and checked against the driver's in-flight set before any span is touched. Every peer-fed
loop is bounded by `DRAIN_LIMIT`, which is a bound of this build and not of anything the peer
publishes. The two loops fed by a *device* rather than a peer — the receive drain and the transmit
reap — take the virtqueue size `Q` instead, for the same reason in the other direction: a
conformant device never has more than `Q` buffers outstanding, so the cap costs nothing, and one
that floods its used ring cannot park the domain in the loop.

The configuration handover is the same treatment applied to a second peer: the region is mapped
read-only, its image is copied out before anything is decided on it, and the consumer — the domain
that has to live with the result — then re-decides the rules rather than re-reading the fields. All
23 of them: the counts, the `enabled` byte, ports, prefix lengths, unicast and host addresses and
MACs on all three object kinds, one port and one MAC per interface, disjoint interface prefixes, a
neighbour on the link its port names and a host on that link, one neighbour per port and address,
and the management entry's prefix and MAC disjoint from every interface's
([detail](#configuration-management), where the two rules the image cannot represent are named).
A refused image is counted, leaves the running
configuration exactly as it was, and is never acknowledged, so the publisher cannot commit it.

The log ring is the same treatment applied to a third peer, and to a peer on **both** sides at once.
Every field of a record the console reads was chosen by another domain, so the record is decoded
before anything is rendered — a kind naming no event, a vocabulary token past its cardinality, a
text length past its own storage, a byte outside `[a-z0-9-]` are each a typed refusal and a counted
drop, never a line. Neither published cursor is ever read back by the side that owns it, so a peer
forging one costs that peer's own records and nobody else's; a drain is bounded by the console's own
burst constant and by the ring capacity rather than by anything a writer publishes; and a refusal on
one ring does not stop the pass, because the records worth reading when a domain fills its ring with
rubbish are the *other* domains'.

**Missing.**

- **A byzantine forwarder can still corrupt a frame in the shared pool.** It may name a buffer whose
  pool owner has it posted as that NIC's receive DMA target; the transmitting driver's 12-byte
  virtio-net header write then races the DMA. The damage stays inside the shared region, but
  exclusive ownership across domains is a protocol claim no single domain can verify. Closing it
  needs an IOMMU — the confinement the [threat model](../design/threat-model.md) calls for — or a
  cross-domain per-buffer ownership epoch; neither exists.
- **A verdict rests on a snapshot, not on the frame.** `RouteStage` puts a copy in its own
  memory, so a peer cannot change the frame under the decision — but it can change it *after*, and
  before the transmitting NIC reads it. What leaves the port may differ from what was decided on in
  every field the rewrite does not overwrite. The same IOMMU or ownership epoch is what would close
  it.
- **Buffer loss is not recovered.** A peer that stalls a destination ring costs the pool one buffer
  per dropped descriptor, permanently (see *[Zero-copy dataplane](#zero-copy-dataplane)*). It is
  counted, and nothing reclaims it.
- **A peer can still write pool bytes at any time.** No Rust type stops a domain mapping the region
  from scribbling a buffer it does not own; an IOMMU is what would confine it.
- **No PD fault handling.** A domain that a peer manages to wedge is not restarted.

## A/B image update

**What exists.** A GPT disk with ESP, STATE, SLOT_A, SLOT_B and DATA partitions; both slots carry
a signed kernel and system image. GRUB is built from pinned source as a standalone EFI binary with
an embedded public key, so it *enforces* detached-signature verification on everything it loads.
Its module set is a curated allowlist (`datad/third-party/grub/modules.txt`) rather than a default build:
every module in the core image is code inside the signed binary, so the list is the verified-boot
base's attack surface and each entry states which line of `grub.cfg` needs it.

The `OK`/`TRY`/`ORDER` selection scheme is implemented and covered by **eight** QEMU scenarios:
confirmed-A, try-pending-B, fallback-from-broken-B, skip-exhausted-B, confirmed-B, an `ORDER` naming
a slot that does not exist, and the two ways every slot can become unbootable — both payloads broken,
and boot state so torn that an attempt cannot be recorded. Each asserts *which slot was chosen*
against a structured boot channel, on which GRUB emits one `LFW-BOOT slot=… state=…` record per
selection decision, and each scenario declares the exact ordered sequence it must produce. Each then
asserts *that the chosen slot is healthy* through the system's real observable contract, frames
forwarded between the two NIC ports — or, for the two halt scenarios, its negative: no frame
forwarded and GRUB's halt record on the channel.

**Missing.**

- **The in-system update/health PD.** No component inside seL4 holds a capability on the **boot**
  disk, so the health flag (`*_OK`) is only ever set by the build seed or the test harness. The
  confirm half of the try/confirm cycle does not exist at runtime. The recorder's disk capability is
  no help here and deliberately so: it names a second, data-only device at a different PCI function,
  and nothing in the system can reach ESP, STATE, SLOT_A, SLOT_B or DATA once seL4 is running.
- No staged installation into the inactive slot.
- No multi-attempt counter (GRUB is single-attempt by design; the counter belongs to the missing PD).
- No redundant, torn-write-safe boot state — a single `grubenv` block. A torn block is *detected*
  and refused, but there is no second copy to fall back to, so the outcome is a halt.
- The DATA partition, where configuration, identity and secrets are meant to live, is an empty
  unformatted GPT entry with no consumer and no encryption — unchanged by the recorder, which writes
  to a separate device entirely.

## Signed boot chain

**What exists.** OVMF → GRUB → Multiboot2 → seL4/Microkit with enforced payload signature
verification; the corrupt-signature fallback and the both-slots-broken halt are proven by test. A
throwaway development key is generated per checkout and never committed, and the release manifest
records `trust_profile: development` with the key fingerprint so a development-signed image cannot
be
mistaken for a production one.

Signing is key-explicit and self-checked: each signature names the exact fingerprint embedded into
GRUB, and the build verifies what it just signed against that public key before anything is written
into a slot, so a mis-keyed payload fails the build rather than the appliance.

The hand-off also holds seL4's one unchecked expectation of its bootloader. seL4's x86 boot places
the userland image at `MAX(first available region's start, ROUND_UP(end of the last boot module))`,
and its available-region list is the firmware's — it still contains the memory the kernel image
occupies — so the end of the last boot module is the only thing keeping the userland image off the
running kernel. GRUB's relocator takes the lowest range that fits and, on `x86_64-efi`, the 640 KiB
below 1 MiB is free, so it will place the module *below* the kernel whenever the image is small
enough to fit there. `grub.cfg` therefore cuts conventional memory between 64 KiB and 1 MiB — 64 KiB
is left because GRUB allocates its own hand-off trampoline from low memory — and refuses to boot at
all if that reservation is itself refused. Because what remains is a window an image could still
shrink into, `xtask::grub::check_boot_module_placement` fails the **build** when the assembled system
image would fit it, reading the bound out of `grub.cfg` rather than restating it.

**Missing.** UEFI Secure Boot is not enrolled — the manifest hard-codes `secure_boot: false`, and
`BOOTX64.EFI` itself is unsigned in the Authenticode sense (no shim, MOK, or PK/KEK/db hierarchy).
There is no TPM anywhere: no vTPM in the QEMU harness, no measured boot, no PCR policy, and no
anti-rollback epoch. Production key management (HSM-backed signing) does not exist.

## The appliance identity

**What exists.** A tenth protection domain, `store` — the third built with the hardfloat SIMD target
— owns a **second** virtio-blk device at the pinned PCI function 00:06.0 and, on it, the one thing a
reboot must not change: which appliance this is.

`datad/crates/store` is the format and the identity, and all of it is host-testable. The
**state record** is two 4 KiB copies at fixed sectors, each carrying a magic, a version, a monotonic
generation, the onboarding state, the device identifier, the private scalar, the public point, the
management endpoint, the device certificate, the delivered trust anchor, the configuration slot table
and a SHA-256 digest over everything before it. A change composes the *whole* new state into the copy
the generation's parity selects, so the copy the appliance is relying on is never the copy being
written and a power cut costs the newer one while the older still decodes. Both copies invalid is a
fresh medium rather than an error, and `StateImage::check` is the typestate boundary: a record that
decoded is not yet a record this build may act on until its slot count and slot size agree with the
numbers this build compiled against.

`identity` mints and verifies. On a fresh medium the domain draws 128 bits of device identifier from
its **own** `RDRAND`-seeded generator, generates an ECDSA P-256 keypair, writes a self-signed
onboarding certificate binding the two through the first-party DER writer in `datad/crates/x509`, and
takes the SHA-256 over the DER `SubjectPublicKeyInfo` — all to the [certificate
profile](../contracts/certificate-profile.md), reached for rather than restated, so the management
server validates against the same page. On every later boot it holds the record to itself: the stored
scalar is a private key at all, the stored point is the one that scalar derives, and the stored
certificate binds that point. A record failing any of the three is **refused** with a typed cause
token — never repaired from whichever half looks right, because an appliance signing under a key
whose certificate names another cannot be authenticated and does not know it.

Each domain that holds key material seeds **its own** generator from the hardware. The draw, its
health check and the generator are `lfw-crypto`'s, so two domains do not each carry a copy of the
rule for what a broken `RDRAND` looks like; the generator itself is not shared, because a seed that
crossed a channel would let the domain at the other end reproduce the key. `RDRAND` and `CPUID` carry
no capability, so the system description can neither grant nor withhold them, and a domain seeding
itself is granted nothing.

**What the write buys.** `VIRTIO_BLK_F_FLUSH` is in `lfw_blk::ACCEPTED_FEATURES`, so a device that
does not offer it is refused at bring-up, and the store's commit is a whole-record write followed by
a flush the domain **waits for**. That is the difference between written and durable, and everything
a later boot believes about this appliance rests on it.

**Factory reset exists on this medium.** The request is one sector, written by somebody holding the
device, and it is the only path into a node with no shell and no input surface — the alternatives are
each either remote or absent, and the [store design](../design/updates.md#factory-reset) records why.
On boot the domain reads that sector before it judges the record, because a record the appliance
refuses is exactly the state a reset is the remedy for. It then clears the request **and waits for the
flush behind it** before destroying anything: a power cut in that order leaves a node an operator
re-onboards, and in the opposite order one that resets on every boot forever. Then it overwrites every
sector the layout claims — both copies of the record, the request sector, the whole slot array — rather
than the fields that hold a secret, because the answer to which sectors those are would come from the
record being destroyed; makes that durable on its own, so a boot whose generator turns out broken
refuses with the old key already gone; reports on the console what was lost; and mints afresh, because
a reset node is immediately onboardable and that is what unowned means.

**Reset is per-medium, and that follows from the isolation rather than weakening it.** The recordings
are on the recorder's device and this request is on the store's, owned by two domains neither of which
maps a byte of the other's — the property that keeps the domain holding the scalar unable to read a
recording. Reaching across from here would breach exactly that, so each medium holding an owner's data
carries its own request and its own overwrite, and the physical boundary stays exact because one visit
reaches every medium.

**What it proves today**, as a machine-observable contract rather than a console line an operator
reads: three QEMU scenarios share **one** store medium. The first finds it zeroed and mints; the second
attaches the same file and must report the same 32-hexadecimal-character device identifier and the
same 64-hexadecimal-character fingerprint under a generation that did not go backwards. A domain that
minted afresh on every boot satisfies every assertion the first boot makes and fails here, and that
defect is the whole reason a persistent identity exists. The third has a factory-reset request written
onto that medium between the boots and owes the inverse: a *different* identifier, a *different*
fingerprint, unowned, at the generation a mint starts from, and a console record naming the generation
it cleared — which must be the one the boot before it ran on.

What the gate compares is the consoles, which is what an administrator compares, and the host reads
the medium's first sixteen bytes besides to hold the magic and the version to `lfw_store`'s own
constants: a domain that composed a record and never got it past the staging window is caught by that
rather than believed. The reset scenario is the **one** place the host reads more, and it has to be:
the console cannot say the old key left the medium, and neither can the state record, because
re-minting rewrites it whatever happened to the sectors around it. So the scalar's window is captured
off the medium before that boot and required to occur at **no offset** of the file afterwards — every
byte searched, zero matches. That needle is a private key; it lives in the harness for the length of
one scenario, is never written anywhere, and a surviving occurrence is reported as an offset, so no
byte of it reaches a message. Everywhere else the rule holds unchanged: the medium's contents are not
read, because a harness that parsed them would be a second place trusted never to print a key.

**The capability topology is the substance.** One domain maps the store device and no other maps any
part of it — the recorder included, which owns the other block device. That domain holds no network
region, no configuration region, no tap, no download region, no `<ioport>` and **no channel in either
direction**, so there is no path from a packet to the private scalar whatever a compromise reaches.
The scalar is plaintext on the medium, deliberately and for want of anywhere to keep a wrapping key,
so physical possession of the store *is* identity theft — and this topology is what makes possession
the only way to it.

**No key material reaches any surface.** The scalar is drawn, folded into a certificate and written to
the medium, and that is the whole of where it goes. The console records carry a public name, a
public-key digest, and — after a reset — a generation, a count and a flag; `/metrics` says whether
there *is* an identity, whether this boot had to mint one, whether a reset was asked for and how far
the record has advanced, and never which identity it is; the committed fuzz corpus for the state
record carries only fixed byte patterns, two of which are deliberately not private keys at all.

**Missing, and in this order.** **Factory reset on the recorder's medium.** The store's half is
above; the recorder's is not a repeat of it, and that is why it is not here. The store device has a
fixed compiled-in layout with a spare sector between the record and the slot array, which is what the
request sector is; the recorder's extent may be a whole device or a named partition resolved at boot,
and its superblock occupies the first two sectors of whichever it turns out to be — so there is no
free sector to claim without first deciding where a request lives in a layout that is not fully known
until the extent is opened. That is a layout decision with a threat model attached (a sector an
attacker can write inside a recording extent), not an extension of the code above.

After that: the CSR this domain's key would sign, the device certificate and trust anchor an owner
delivers, the management endpoint beside them, and the configuration slot array — all four have a
place in the record and nothing writes them.

**The signing delegation is done, and it is what ended the domain's parking.** The domain keeps the
keypair after establishing it and answers `wire::signing`'s two regions: the cryptography domain
writes a request and reads an answer, this domain does the reverse, and there is no field a private
scalar fits in either direction. It parks in the Microkit event loop and is woken by the asking
domain, serving at most four demands per wakeup — `SignResponder::take` already yields one demand per
change of the requester's sequence, so a peer that storms the channel costs one reply each and never
a loop — and republishing its shard afterwards, which is why that shard now moves after `init` where
it used to be written once.

*Two counters and no console record.* `librefirewall_store_signatures_total` and
`librefirewall_store_sign_refusals_total` are the surface; a refusal produces no console line
deliberately, because this domain's log ring is bounded and single-producer, so a record per refusal
would let the asking domain choose the rate at which the identity and fingerprint records an
operator needs are pushed out of it. The domain that asked is the one that reports what it made of
the answer, and it is the one that can tell.

*Its priority moved from 1 to 3, and that was a capability decision.* A responder below its
requester cannot answer it: the cryptography domain reads for the reply in a bounded spin, because
`sign` is called synchronously inside a handshake and has no continuation a notification could
resume, so a holder at priority 1 would not be scheduled until that spin gave up and the delegation
would refuse on every boot. Above it, a notification preempts into this domain immediately and the
asker's next read finds the answer. What it costs is that while this domain polls its device it now
preempts the dataplane — at boot, during onboarding, and on a commit, each a bounded transfer — and
what still bounds it is `lfw_blk`'s own poll budget and nothing the device controls. It is not a
protected call and this system grows no message-passing IPC.

## Cryptography and TLS

**What exists.** Three crates and one protection domain, and the whole of it is proved on the
shipped image rather than only on the host.

`lfw-crypto` is the appliance's only door to cryptography, over pinned RustCrypto and dalek
implementations with `default-features = false` throughout: SHA-256, HMAC-SHA-256 (one-shot and
incremental), HKDF-SHA-256, ChaCha20, ChaCha20-Poly1305, AES-256-GCM, a ChaCha20 fast-key-erasure
generator, ECDSA over P-256 (sign and verify), X25519, and ML-KEM-768. Every refusal is typed;
nothing on any path panics, indexes bare, or clamps. It carries **154 published test vectors** as
one committed table both the host suite and the domain run — NIST CAVP, NIST ACVP for FIPS 203,
RFC 8439, RFC 6979 appendix A.2.5, and Wycheproof — of which 30 are forgeries or refusable inputs a
verifier must say no to.

`lfw-x509` writes the four certificate kinds of the [certificate profile](../contracts/certificate-profile.md)
and the PKCS#10 request, over a first-party bounded DER writer. It emits and never parses.

`lfw-tls` is the rustls crypto provider — hash, MAC, the key schedule over it, the record-layer
AEAD, the hybrid key exchange, the one signature algorithm — plus the bounded arena's bookkeeping
and a session driver over rustls' unbuffered API. It contains no `unsafe` at all.

`pds/crypto` gates the part on `CPUID`, re-runs all 154 vectors against the code as compiled for
the SIMD target, measures each primitive (per byte where it has a length, per operation where it
does not), seeds the generator from 32 `RDRAND` draws, and then establishes **one complete
mutually-authenticated TLS 1.3 session with itself** — `TLS_CHACHA20_POLY1305_SHA256` over
`X25519MLKEM768`, both chains validated against an anchor it issued, application data echoed both
ways, closed with an alert — before running a second, deliberately starved session that must be
refused. It holds the appliance's only allocator: a 2 MiB region mapped into it and nothing else.

**All of that is now proved on both accelerators, which it was not.** The harness prefers KVM and
falls back to emulation, printing and logging which it took, and the image used to come up only
under KVM: the SIMD target enabled BMI2, whose instructions are VEX-encoded, and an emulated
processor refuses that encoding unless the guest has enabled the vector state — which the pinned
kernel's XSAVE feature set, covering x87 and SSE only, never does. The fault was an invalid opcode
on a `shrx` inside the P-256 scalar multiplication, on a guest whose `CPUID` advertised BMI2 and
whose feature gate had passed, because hardware imposes no such condition on the general-purpose
subset. BMI2 is therefore disabled in the target, absent from the guest CPU model, and gated for by
neither domain; ADX remains, being legacy-encoded. What holds the decision is not the removed
feature but the encoding: `crypto_profile::check_image` reads the raw bytes of every decoded
instruction in the shipped protection domains and fails on a VEX or EVEX prefix, whatever the
mnemonic — the half that cannot go stale, beside the `%ymm` operand scan that refuses the register
file the kernel does not save. What it costs is a few per cent on X25519 and ML-KEM-768 and nothing
measurable on ECDSA P-256; the per-operation regression ceilings moved with it, from twenty, twenty
and sixty million cycles down to 5.5, 1.1 and 2.0 million, which is the four-times margin they were
always documented as having.

**And one scenario now boots on the emulator whatever the machine offers, which is why that class of
defect is no longer invisible.** The build-time check makes the particular cause impossible; what it
cannot do is make the next cause visible, and nothing in the gate ever ran the image on an emulator
on a machine that had acceleration — which is every machine this gate runs on. So the defect was
found by hand rather than by the gate, and a second one of its kind would have been too. The
seventeenth scenario is the answer: it reuses the shipped document and the published disk another
scenario already boots, forces emulation, and judges the cryptography domain alone — every primitive
against its published vectors and the session established. It asserts none of the measured costs, a
cycle count under emulation being a figure about the emulator, and none of the routed, transcript or
management contracts either: those are statements about the image, the accelerated boots make all of
them, and a second reading of the same fact is not worth a boot. The narrowness pays for itself twice:
measured on this bench the boot costs about **five seconds**, no more than an accelerated scenario
does, because it ends the moment the domain reports rather than waiting out the settle window, the
management burst, two scrapes and two downloads — so emulating every instruction in it costs the gate
almost nothing. On a machine with no usable KVM every boot is emulated already, and the run says so
rather than claiming a contrast it did not draw.

**Cargo does not fingerprint a custom target specification, and the build no longer depends on
anyone remembering that.** Editing `datad/support/targets/x86_64-sel4-simd.json` used to rebuild
nothing: cargo reported the tree up to date and went on linking object code compiled under the
withdrawn specification, so the edit reached the binaries only once that target's artifact
directory had been removed by hand — and the withdrawal above shipped a debug configuration nobody
had cleared, which no gate boots and which therefore stayed broken until someone ran it. That is now
mechanical. Every build that compiles for one of the two seL4 targets — both image configurations,
every scenario disk a QEMU run assembles, and the two-kernel-configuration Clippy pass — records the
specification text beside the artifacts it produced and compares the two before reusing them. A
directory built against a different specification, or one recording none at all, is discarded, and
the build says so on its output and names the lines that moved; an agreement is silent, so a warm
build pays nothing. The record is the specification itself rather than a digest of it: an exact
comparison needs no collision argument, and it is what lets the discard name what changed.

Two properties of that shape are the point of it. It is keyed per target, so an edit costs a cold
build of the edited target alone — the other seL4 target keeps its artifacts, and so do the
host-side build scripts and procedural macros sitting beside them, which matters in the debug
configuration because the image build writes into the same directory the host dev profile does. And
it is keyed on the specification rather than on either symptom, which is what covers both
directions: the disassembly check reads a binary still carrying instructions the specification no
longer enables, and nothing reads a binary quietly *missing* an acceleration the specification just
gained.

Two hazards of the same family are closed with it. Incremental compilation is off for every project
command: the compiler crashed twice on a stale incremental tree, in crates the change under test had
not touched, so a cache that may accelerate a build was deciding one. And `make ci` now assembles
the debug image — as a scenario disk under the build tree, never published over the release disk the
run just judged — so the configuration the diagnostic re-run needs is proved to assemble before a
failure asks it to. Nothing boots it, and nothing should: what it owes the gate is existence, not a
contract.

**Two library choices were settled by what the build found, and the design now names what shipped.**

*The post-quantum primitive is RustCrypto `ml-kem`.* `libcrux-ml-kem` — formally verified, and the
first choice while it was still a hypothesis — builds for this target: that assumption is resolved
and the answer is yes. What it costs is the dependency policy: a transitive crate of its own takes
an unconditional dependency on a random-number crate a major version ahead of the one the
elliptic-curve crates already use, which puts two versions in the graph, and it pulls a libc binding
into an appliance with no libc. RustCrypto `ml-kem` is audited and FIPS 203 final and costs no
exception at all, so it is what is adopted and what the architecture chapter now names. The
formal-verification assurance is the price paid, and recovering it needs upstream to loosen that
dependency.

*Certificate generation is first-party.* `rcgen`'s ASN.1 back end is enabled with that crate's `std`
feature unconditionally and no feature combination drops it, so it does not build for a target with
no operating system whatever signing back end it is driven with. The four DER structures the profile
fixes are written here instead; they carry no algorithm of their own.

**The delegation landed, and the substitution cost nothing above the seam.** `SignOperation` has a
second implementation — `pds/crypto`'s `Delegated` — which writes a request into a shared region,
wakes the store domain, and copies back the bytes it published. It lives in that protection domain
rather than in `wire` because it is the only place that sees both the TLS trait and the channel ABI,
and `wire`'s zero `unsafe` is worth keeping; it is `Sync` behind an `UnsafeCell` and an `AtomicBool`
whose SAFETY comment names the flag rather than the thread count, on `NodeEntropy`'s terms. The
provider's `KeyProvider` refusing to load a key from an encoding is what kept this a substitution:
nothing above the seam could have been holding one.

The boot proves it twice over. Directly: ask which key the holder has, have it sign a fixed
challenge, and verify that signature against that key — which settles the delegation rather than
ECDSA, the vector run having settled that already. And where it will actually be used: the session's
**server half runs under the delegated key**, so `sign` is reached synchronously deep inside the
handshake at the `CertificateVerify`. The gate holds the identifier this domain reports to the store
domain's own, and requires the holder's tally to have moved across the session — a number that
stayed put would mean the handshake signed some other way.

*The read is bounded rather than trusted.* 1024 reads of the reply region and then a typed refusal,
which is what keeps a handshake from becoming a domain that never returns. It terminates on the first
read in practice, and that is a scheduling fact: the holder sits at priority 3 and this domain at 2,
so a notification preempts into it immediately.

**Missing.** Nothing dials with any of this: the transport can open a connection but has no way to
resolve a next hop for one, and there is no channel and no onboarding server, and the cryptography domain holds no device. The session is proved
against this same build on both ends, so nothing about interoperating with a second implementation is
established — and the client end and the certification authority above both are still generated here,
standing in for a management server and an anchor this appliance has never seen. There is no CSR
served anywhere. SHA-NI stays unreachable for the reason the [status page](../status.md) records.

## Management server

**What exists.** Onboarding, end to end from the administrator's side. An administrator signs in
with a local account, uploads the certificate signing request an appliance produced, compares the
SPKI fingerprint the page renders against the one the appliance printed on its console, names the
appliance, settles its configuration document, and downloads the
[onboarding package](../contracts/configuration-package.md). That flow has been walked against a
running server over plain HTTP, and the package it produced was verified from the outside: `tar`
lists exactly the four members, and `openssl` confirms the device certificate chains to the
delivered anchor and matches the profile in every field.

- **The server is the certificate authority.** It creates its own authority and the channel
  endpoint's server certificate at first start, and signs device requests against the
  [certificate profile](../contracts/certificate-profile.md) — ECDSA P-256 with SHA-256, a random
  128-bit serial, ten years, the device identifier as the sole subject attribute, and the key usage,
  extended key usage and basic constraints the profile assigns each artifact. Everything issued
  comes from the profile and from the request's key: the request is a proof of key possession and a
  name, and one carrying an attribute is refused rather than honoured in part. Certificates are
  built with the runtime's own `:public_key` and `:crypto`; the server implements no cryptographic
  algorithm and links no native one.
- **Private keys are sealed.** AES-256-GCM under a base64 key from the environment, a fresh
  initialisation vector per record, and associated data naming the table, so a ciphertext moved
  between rows opens to nothing. The server refuses to start without a usable key, and no surface
  exports one.
- **The package writer is held to the contract by its own decoder.** The archive is written as
  ustar headers directly rather than through a tar library, and the suite decodes what comes out
  against every rule the contract states — the magic and version, the regular-file type flag, the
  four exact names with no path and an empty prefix field, each size field against the bytes
  present, every header checksum, the bounds, and the two closing zero blocks. That decoder is the
  mechanism holding this writer and the appliance's reader — two implementations of one format, in
  two languages — from drifting apart.
- **Postgres holds accounts and sessions, the authority and the endpoint certificate, the appliance
  inventory, configuration versions, and the audit trail.** Passwords are PBKDF2-HMAC-SHA512 with
  the work factor stored on each hash. Sessions are server-side tokens: the cookie carries the
  token, the database its digest, and signing out deletes the row. Every state-changing action
  writes an audit record, and issuance writes its record in the same transaction as the issuance.
- **The inventory is honest.** Status is derived from what the server can evidence, not stored:
  today "onboarded" and when the request arrived. Nothing renders reachability, and the page says
  why.
- **ClickHouse holds the telemetry schema** — flow events, log events and metric samples, with the
  fields the appliance's recording annotations, log records and metric samples actually carry — and
  a writer over ClickHouse's HTTP interface. The suite round-trips rows through a real ClickHouse.
- **The gate runs against real databases and stays offline.** Both are pinned by digest and run on
  a Podman network with no gateway; the gate container refuses to run if it holds a default route,
  and a database that does not answer fails the run rather than shrinking it. The
  [building chapter](building.md) describes it.

**Missing.** Everything the channel carries, and everything that comes after it.

- **No channel listener and no pcapng decoder.** Nothing has ever connected to this server: there
  is no ThousandIsland listener, no [framing](../contracts/channel-framing.md), and no decoder
  tested against bytes the appliance's encoder produced. The telemetry schema and its writer
  therefore have **no producer** — they are exercised only by the suite.
- **Online, offline and last seen do not exist**, and neither do the columns behind them; they
  arrive with the connection that establishes them.
- **No configuration operations.** Generation 1 is the document the package carried, and there is
  no staging, commit-confirm, rollback, or version beyond it — those are channel operations.
- **The web interface is plain HTTP**, a recorded deliberate temporary state: it will take an
  administrator-supplied certificate or ACME later. Until then a deployment terminates TLS in front
  of it or keeps it on a trusted network.
- **No revocation, no CA rollover, no identity federation.** Device certificates are long-lived and
  nothing withdraws one yet; the authority cannot be replaced without visiting every appliance; and
  authentication is local accounts only, with one role.
- **No live view of anything.** The inventory, the appliance page, the authority page and the audit
  trail are LiveViews that mount and render; nothing ever pushes an update to one, and PubSub fans
  out to nothing, because nothing produces events.

## Engineering foundations

Not product features, but the machinery every feature above lands through — and where most of what
is *done* currently sits.

| Foundation | Status | Notes |
|---|---|---|
| Hermetic, pinned build in a rootless OCI builder | **done** | base image by digest, dated Debian snapshot, exact version per apt package, checksum-verified SDK/toolchain/GRUB/syft, `--locked` throughout |
| Host gate: format, Clippy `-D warnings`, comment/`unsafe` ratchets, unit + property tests | **done** | run by the pre-commit hook; Clippy covers the library crates, `xtask`, and all ten protection-domain binaries — the hardware probe, the cryptography domain and the store domain against their own SIMD target, one cargo invocation each so a domain's feature set is the set its own manifest asks for — in each of the two seL4 kernel configurations — which, now that every end-to-end scenario boots the release image, is the **only** thing in any gate that still compiles the debug configuration, and so the only thing keeping it buildable for the diagnostic re-run that needs it. The ratchets (`datad/tools/xtask/src/budgets.rs` against `datad/tools/xtask/budgets.toml`) record a comment-line ratio per production file and an `unsafe` block/fn/impl count per crate, and fail the gate on any rise. Their reach is scoped rather than universal, and `Cargo.toml` now says so: the two `unsafe` denials are workspace lints and reach every member, while the ratchets read `datad/crates/` and `datad/pds/` alone — for `xtask` and the fuzz harnesses the discipline is review |
| Coverage floor | **done** | 94% combined and 90% per library crate, enforced in the gate as line coverage, over the 28 library crates. Every one of them is named in `LIBRARY_PACKAGES` (`datad/tools/xtask/src/host.rs`), and that list is what the count above is read from rather than restated beside — a number in prose that nothing compares is a number that goes stale. Every workspace member is either measured or carries a recorded reason from the closed list of allowed coverage exemptions (only observable under seL4, build orchestration, or test/benchmark harness) for being exempt, and a member in neither fails the build. **The headroom above the floor is not restated here**: the numbers a previous revision quoted predate four new crates, and `make coverage` reports the current per-crate figures |
| QEMU end-to-end gate (20 system scenarios, eight A/B scenarios) | **partial** | every scenario boots the **release** image — the configuration a deployment gets, so the shipped profile is the tested one — and a scenario that fails there is re-run once on the debug kernel to diagnose it, which never changes the verdict. Two raw disks are attached on every invocation — the recorder's at 00:05.0 and the appliance's own store medium at 00:06.0 — and the 12 scenarios that reach the management port judge all three of its surfaces against one another and read both extents off the first besides ([detail](#recording-and-download)). Three scenarios share ONE store medium: the second is held to the identity the first minted on it, which is the only shape a persistence claim has, and the third has a factory-reset request written onto that medium between the boots and must come back a different, unowned appliance with the previous scalar occurring nowhere on the medium. Single vCPU, two dataplane ports and one management port; the multi-node virtual-network E2E is open |
| Criterion benchmarks | **partial** | `queue`, `packet-buffer`, `virtio` and `pd-runtime` (the per-packet routing cost: snapshot, parse, decide, rewrite, write back — measured with the recording tap switched *off*, so the tap's own per-frame cost is unmeasured); `nic-driver-core`'s poll pass, the block request path and the recording path are all hot or newly hot with no benchmark, and nothing gates a regression |
| Fuzzing | **partial** | a persistent target for every crate that parses a *structure* it did not write — a descriptor, a ring, a document, a header, a record — including the block request path, the ring superblock and the recording pass added with this work. `datad/tools/xtask/src/host.rs` holds the authoritative target list. The register-protocol device crates (`uart-16550`, `hpet`, `rtc`) carry no target and do not need one: a single read admits one integer, which their property tests already sweep over the whole of its type. A sandbox that cannot start AddressSanitizer degrades the gate to build-plus-seed-corpus — see below |
| SBOM (SPDX 2.3), release manifest, checksums | **partial** | none of them are signed; no SLSA/in-toto attestation; and the SBOM's scope is narrower than the payload — see below |
| Reproducibility check | **partial** | `make verify-reproducible` covers kernel + system image, built in the release configuration so the claim is about the artifact that ships; part of no gate |
| Dependency and license policy (`cargo-deny`) | **done** | `bans licenses sources` in the offline gate; `advisories` needs the RustSec database and so is a deliberate manual networked run (`cargo deny check advisories`) that nothing runs automatically — not in `make test` or `make ci` |
| Build input pinning | **partial** | every apt package — QEMU and OVMF included — is pinned to an exact version against a dated snapshot, but no sha256 for one is recorded here, so apt's own archive signature is the integrity root; the `cargo install`ed developer tools are version-exact and `--locked`, but their integrity rests on the crates.io index rather than on a checksum in this repository |

Two of those rows deserve more than a table cell, and the fuzzing row deserves two.

**The SBOM does not describe the shipped payload.** syft catalogs the workspace *source tree*, with
`datad/build/`, `datad/dist/`, `target/`, `datad/fuzz/` and `datad/tools/` excluded, so a consumer must not read the document
as the boot payload's contents. Host-only crates that never enter an image — `criterion`, `proptest`,
and their trees — appear in the inventory. And the third-party components that genuinely *do* ship
inside the disk — the seL4 kernel from the Microkit SDK and the GRUB core image — are absent; they
are recorded as version-verified provenance in the release manifest instead.

**The two configuration harnesses assert semantics, not survival.** Absence of a panic is the
least interesting thing a validator can be shown to have, because the failure that reaches a
dataplane is an image *wrongly accepted* rather than one that crashed the reader.
`datad/fuzz/src/handover.rs` therefore carries its own statement of the handover ABI's rules and of the
order they are applied in, taken from the contract rather than read out of `wire`, and compares it
with `ConfigImage::check` on every input — so an image the reader admits and the contract refuses
fails exactly as loudly as a panic would. `datad/fuzz/src/document.rs` closes the same gap across a crate
boundary: every document `datad/crates/config` accepts must build a handover image the *consuming* domain
accepts, and a forwarding table carrying the entries the document named, which no test inside either
crate alone can observe. Both claims were checked by sabotage rather than by reading — deleting the
prefix-length rule from `ConfigImage::check`, and the port-range rule from `datad/crates/config`, each
fails the seed-corpus smoke test on the committed seed named after it, so the corpus alone catches a
lost rule with no live fuzzing at all.

**Live fuzzing is conditional.** Every target always builds under AddressSanitizer, and the
seed-corpus smoke tests always run. Whether libFuzzer can actually *execute* is established once per
run by an explicit probe, the hermetic builder being able to stop ASan before it starts. When the
probe passes, every subsequent non-zero exit is treated as a finding and fails the gate. When it
fails, the run reports loudly and proceeds with build-plus-seed coverage only — so a gate can go
green having done no live fuzzing at all.
