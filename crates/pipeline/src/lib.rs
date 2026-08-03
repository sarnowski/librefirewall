//! The verdict pipeline: the ordered chain of stages that turns the port a
//! frame arrived on and its parsed headers into a [`Verdict`] — forward it
//! under a named MAC pair, or drop it for a named reason.
//!
//! Faces untrusted network traffic. Every field a stage reads was
//! chosen by whatever is attached to a dataplane port, so the chain is total:
//! [`Pipeline::evaluate`] answers for every possible header, and the answer for
//! anything no stage recognises is a named [`DropReason`] rather than a
//! fallthrough.
//!
//! # The chain is fixed at build time; the policy is data
//!
//! Every stage is a concrete type and [`Pipeline::evaluate`] calls them in an
//! order written in one place — no trait object, no dynamic dispatch, no
//! allocation. Which stages exist is a build-time fact, the same way the set of
//! protection domains and the memory grants between them are; what an operator
//! changes at run time is the tables the stages decide against, which arrive as
//! [`Configuration`]. A pipeline whose shape were data would need a decision
//! about what a malformed shape means on the packet path, and there is no
//! answer to that a firewall should ever have to give.
//!
//! # Why the last stage does not answer with a [`Step`]
//!
//! A stage that may defer answers [`Step::Continue`]; the last one may not,
//! because there is nothing behind it to defer to. Typing it as a [`Step`] would
//! oblige [`Pipeline::evaluate`] to invent a verdict for a case the last stage
//! never produces — an unreachable branch on the packet path, and a drop reason
//! nothing can cause. So the deferring stages answer [`Step`] and the last one
//! answers [`Verdict`] outright, which makes "the chain always concludes" a fact
//! about the types rather than a comment.
//!
//! # Where policy sits, and why it is last
//!
//! The chain is admission, then routing, then connection tracking, then policy,
//! and the second one is the reason for the order. [`RoutingStage`] does not
//! settle a frame it can forward: it resolves the egress port and the next hop
//! and *attaches* them to the [`Inspection`], deferring to what follows. So
//! [`PolicyStage`] decides with the egress in hand, which is what makes a rule
//! able to name one — a zone-to-zone policy is the ordinary case and it is
//! unwritable if the filter runs before the forwarding decision. The converse is
//! the same fact: a packet with no route has no egress for an egress rule to be
//! about, so there is nothing for policy to say about it and routing settles it
//! first.
//!
//! # The one stage that is two halves
//!
//! [`ConnectionStage`] brackets the filter rather than preceding it, and both
//! halves are load-bearing. In front, a frame an *established* flow already
//! accounts for is forwarded without the filter being consulted at all — which is
//! what carries a reply no rule names, and what keeps an edit to the policy from
//! cutting a conversation that is already running. Behind, a flow the
//! classification *opened* is withdrawn where the filter then refused the packet
//! that opened it, because a slot held by a connection the policy rejected is
//! how default deny turns into a state-exhaustion amplifier.
//!
//! Two things reach the filter, therefore, and a [`Rule`] can name which: a
//! conversation **opening**, and traffic an existing conversation is the reason
//! for without belonging to it — today an ICMP error quoting one of its
//! datagrams. The second is composed by whoever sent it, with a source address of
//! its choosing, so relating it to a flow settles where it would go and never
//! whether it may: the filter decides it too, and a document that says nothing
//! about related traffic denies it. Traffic *within* a tracked conversation is the
//! one thing the filter never sees, which is why [`Tracked`] offers two values and
//! not three.
//!
//! # What closes the hole that leaves
//!
//! A conversation the filter admitted is carried by its flow, so narrowing a rule
//! stops new conversations and leaves the ones it already admitted running. That
//! is not a rough edge — a host found to be compromised keeps every connection it
//! had open — and the answer is [`PolicySweep`], which re-decides the **flow
//! table** against a newly committed configuration and takes back the flows it
//! would not admit. Once per commit rather than once per packet, so the ruleset
//! stays off the hot path and every flow the new policy still allows is left
//! exactly as it was. What it can decide from a flow's key alone, and where that
//! is conservative, is [`PolicySweep`]'s own header.
//!
//! A frame the tracker refuses never reaches the filter either, and each refusal
//! carries a [`DropReason`] of its own. That is a real narrowing of what this
//! appliance forwards: a protocol no flow can be kept for is one no rule can
//! honestly be written about, so it is refused rather than passed to a filter
//! that could only match it on addresses.
//!
//! [`PolicyStage`] is terminal and its default is to drop. A frame matching no
//! rule is refused under [`DropReason::NoPolicyMatch`], which is what makes an
//! empty ruleset deny everything rather than permit it — the same posture
//! generation 0 already has, arrived at from the other direction.
//!
//! # Connected routes only, and configured neighbours
//!
//! [`RoutingStage`] resolves against connected interface prefixes alone —
//! `routing`'s restriction, stated there — and against neighbours an operator
//! configured, because this chain cannot *originate* a frame: it owns no buffer
//! pool, and a frame leaves only the port opposite the one it arrived on.
//! Discovery, and the ICMP error an expiring packet earns, both need that
//! origination and belong to the routing/ARP/ICMP component. A drop here is
//! counted, never answered.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

use lfw_clock::Monotonic;
use lfw_flow::{Classification, FlowEntry, FlowId, FlowState, FlowTable, Outcome, RefusalKind};
use net_headers::{Frame, IcmpHeader, Ipv4Address, MacAddress, Protocol, Transport};
use routing::{PortId, Router};

/// Why a frame was not forwarded — the flat, operator-facing vocabulary every
/// stage refuses in, whichever stage refused.
///
/// Flat on purpose. A reason is what an operator acts on, and which stage
/// produced it is an implementation fact they neither see nor can use, so
/// nesting the vocabulary per stage would put a detail of this crate's
/// decomposition into the metric labels and the recordings. Each variant is one
/// counter in [`DropCounters`], so a drop is always attributable rather than
/// aggregated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DropReason {
    /// The ingress port has no configured interface, so the appliance has no
    /// address to route on behalf of.
    UnconfiguredIngressPort,
    /// The ingress interface is administratively down. Distinct from having no
    /// interface at all, because an operator acts on the two differently.
    InterfaceDisabled,
    /// The destination MAC is not this port's. A router forwards what was
    /// addressed to it; broadcast and multicast frames land here too, which is
    /// what makes ARP traverse nothing.
    NotAddressedToUs,
    /// An 802.1Q tag with no sub-interface to interpret it.
    VlanTagged,
    /// A source address that may not appear as one: multicast, broadcast,
    /// loopback, unspecified, or an address the appliance itself holds — the
    /// forged case, since nothing on a wire may claim to be this router.
    MartianSource,
    /// A destination no unicast routing decision may be made for.
    UnroutableDestination,
    /// Addressed to the appliance itself. Local delivery — ICMP echo,
    /// management traffic — is not implemented on the dataplane.
    AddressedToThisRouter,
    /// The packet cannot survive another hop.
    TtlExpired,
    /// No interface prefix covers the destination.
    NoRoute,
    /// The route resolves back out of the port the frame arrived on, which
    /// would be a loop.
    EgressIsIngress,
    /// A route exists but no configured neighbour holds the destination's MAC.
    /// With no ARP, this is the unresolvable case.
    NoNeighbour,
    /// A protocol the connection tracker holds no state for. It is a *drop*
    /// rather than a pass to the filter because this appliance decides
    /// statefully: a protocol no flow can be kept for is one no rule can be
    /// written about honestly, and forwarding it would be the one hole in
    /// default deny that no line of the document mentions.
    FlowUnsupportedProtocol,
    /// A non-initial fragment, which carries no transport header to key a flow
    /// by and which nothing here reassembles.
    FlowFragment,
    /// A datagram too short for the transport header it claims, or claiming a
    /// header longer than it carries. Distinct from the parse failures the
    /// stage around this chain counts: those are the frame, this is the
    /// transport inside a frame that parsed.
    FlowMalformed,
    /// A TCP flag combination no exchange produces.
    FlowInvalidFlags,
    /// A TCP segment for a five-tuple with no flow that was not a `SYN`. The
    /// count of attempts to walk around default deny by starting mid-stream.
    FlowMidStream,
    /// A packet the flow's own state does not admit.
    FlowInvalidState,
    /// A segment outside the window its peer authorised.
    FlowOutOfWindow,
    /// An ICMP echo reply or error naming a flow the table does not hold.
    FlowNoSuchFlow,
    /// An ICMP error whose quoted datagram did not corroborate its own claim.
    FlowQuotedInvalid,
    /// An ICMP type the tracker neither tracks nor relates.
    FlowUnsupportedIcmp,
    /// No slot: every slot the eviction scan reached holds a flow that may not
    /// be taken back. The fail-closed answer to a connection flood, and the one
    /// reason here that says legitimate new connections are being turned away.
    FlowTableFull,
    /// One bucket's chain is full, so this flow's key has nowhere to go even
    /// though the table has slots.
    FlowBucketFull,
    /// A rule matched and its action is to drop. The frame was routable: an
    /// operator asked for this one.
    PolicyDenied,
    /// No rule matched. Distinct from [`Self::PolicyDenied`] because the two
    /// are opposite things to go and do — one rule is doing what it says, and
    /// the other is a policy with nothing to say about this traffic — and
    /// because a node whose whole ruleset has stopped matching shows up here
    /// and nowhere else.
    NoPolicyMatch,
}

impl DropReason {
    /// Every variant, so a counter table and a report can be built by iteration
    /// rather than by a list that drifts from the enum.
    pub const ALL: [Self; 25] = [
        Self::UnconfiguredIngressPort,
        Self::InterfaceDisabled,
        Self::NotAddressedToUs,
        Self::VlanTagged,
        Self::MartianSource,
        Self::UnroutableDestination,
        Self::AddressedToThisRouter,
        Self::TtlExpired,
        Self::NoRoute,
        Self::EgressIsIngress,
        Self::NoNeighbour,
        Self::FlowUnsupportedProtocol,
        Self::FlowFragment,
        Self::FlowMalformed,
        Self::FlowInvalidFlags,
        Self::FlowMidStream,
        Self::FlowInvalidState,
        Self::FlowOutOfWindow,
        Self::FlowNoSuchFlow,
        Self::FlowQuotedInvalid,
        Self::FlowUnsupportedIcmp,
        Self::FlowTableFull,
        Self::FlowBucketFull,
        Self::PolicyDenied,
        Self::NoPolicyMatch,
    ];

    /// The reason a tracker refusal is reported as.
    ///
    /// The one place the tracker's vocabulary and this one are related, so a
    /// refusal kind added there without a reason here does not compile. Two
    /// vocabularies rather than one because they answer different questions: a
    /// [`RefusalKind`] says what the table decided about a packet, and a
    /// [`DropReason`] says why a frame did not leave — the same event seen from
    /// the tracker and from the pipeline around it, which is the pairing this
    /// surface already makes for the filter's own refusals.
    #[must_use]
    pub const fn of_refusal(kind: RefusalKind) -> Self {
        match kind {
            RefusalKind::UnsupportedProtocol => Self::FlowUnsupportedProtocol,
            RefusalKind::Fragment => Self::FlowFragment,
            RefusalKind::Malformed => Self::FlowMalformed,
            RefusalKind::InvalidFlags => Self::FlowInvalidFlags,
            RefusalKind::MidStream => Self::FlowMidStream,
            RefusalKind::InvalidState => Self::FlowInvalidState,
            RefusalKind::OutOfWindow => Self::FlowOutOfWindow,
            RefusalKind::NoSuchFlow => Self::FlowNoSuchFlow,
            RefusalKind::QuotedInvalid => Self::FlowQuotedInvalid,
            RefusalKind::UnsupportedIcmp => Self::FlowUnsupportedIcmp,
            RefusalKind::TableFull => Self::FlowTableFull,
            RefusalKind::BucketFull => Self::FlowBucketFull,
        }
    }

    /// A stable short name, for a metric label or a report line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::UnconfiguredIngressPort => "unconfigured_ingress_port",
            Self::InterfaceDisabled => "interface_disabled",
            Self::NotAddressedToUs => "not_addressed_to_us",
            Self::VlanTagged => "vlan_tagged",
            Self::MartianSource => "martian_source",
            Self::UnroutableDestination => "unroutable_destination",
            Self::AddressedToThisRouter => "addressed_to_this_router",
            Self::TtlExpired => "ttl_expired",
            Self::NoRoute => "no_route",
            Self::EgressIsIngress => "egress_is_ingress",
            Self::NoNeighbour => "no_neighbour",
            Self::FlowUnsupportedProtocol => "flow_unsupported_protocol",
            Self::FlowFragment => "flow_fragment",
            Self::FlowMalformed => "flow_malformed",
            Self::FlowInvalidFlags => "flow_invalid_flags",
            Self::FlowMidStream => "flow_mid_stream",
            Self::FlowInvalidState => "flow_invalid_state",
            Self::FlowOutOfWindow => "flow_out_of_window",
            Self::FlowNoSuchFlow => "flow_no_such_flow",
            Self::FlowQuotedInvalid => "flow_quoted_invalid",
            Self::FlowUnsupportedIcmp => "flow_unsupported_icmp",
            Self::FlowTableFull => "flow_table_full",
            Self::FlowBucketFull => "flow_bucket_full",
            Self::PolicyDenied => "policy_denied",
            Self::NoPolicyMatch => "no_policy_match",
        }
    }

    /// The index this reason occupies in [`DropCounters`], and so in `ALL`.
    #[must_use]
    const fn slot(self) -> usize {
        self as usize
    }
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One counter per [`DropReason`], indexed by the reason itself so a new
/// variant cannot be added without a slot to record it.
///
/// Saturating and never reset: the rate is attacker-controlled, and a scrape
/// differences successive reads, so a wrap would forge a negative rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DropCounters {
    counts: [u64; DropReason::ALL.len()],
}

impl DropCounters {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            counts: [0; DropReason::ALL.len()],
        }
    }

    pub fn record(&mut self, reason: DropReason) {
        if let Some(count) = self.counts.get_mut(reason.slot()) {
            *count = count.saturating_add(1);
        }
    }

    #[must_use]
    pub fn get(&self, reason: DropReason) -> u64 {
        match self.counts.get(reason.slot()) {
            Some(count) => *count,
            None => 0,
        }
    }

    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts
            .iter()
            .fold(0u64, |sum, count| sum.saturating_add(*count))
    }
}

impl Default for DropCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// What the pipeline concluded about one frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Rewrite the frame's MAC pair to `source`/`destination`, decrement its
    /// TTL, and transmit it on `egress`.
    Forward {
        egress: PortId,
        /// The egress interface's own MAC.
        source: MacAddress,
        /// The next hop's MAC.
        destination: MacAddress,
    },
    Drop(DropReason),
}

/// What one deferring stage concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// This stage has nothing to settle about the frame; the next one decides.
    Continue,
    /// The pipeline's answer. No later stage runs, and no later stage sees the
    /// frame — which is what makes the chain short-circuiting rather than a
    /// vote.
    Settled(Verdict),
}

/// One frame under inspection, and everything the stages ahead have worked out
/// about it.
///
/// Threaded through the chain by mutable reference so a stage can *attach* what
/// it derived rather than return it: a later stage reads a fact the earlier one
/// established without re-deriving it from the bytes, and adding such a fact
/// costs a field here instead of a parameter on every stage's signature.
///
/// It is also what an evaluation leaves behind for a caller outside the chain.
/// A [`Verdict`] says what to do with the frame and cannot say *why*: which
/// conversation it belongs to, what this packet did to that conversation, which
/// of the operator's rules decided it, and whether the tracker refused it before
/// the filter was reached. Those four are here, attached by the stages that
/// established them, and they are what lets an observer record a connection
/// history rather than a second copy of the traffic.
pub struct Inspection<'frame> {
    ingress: PortId,
    frame: Frame<'frame>,
    forwarding: Option<Forwarding>,
    flow: Option<FlowObservation>,
    refusal: Option<RefusalKind>,
    matched: Option<usize>,
}

/// What one packet did to the flow it belongs to.
///
/// Three values rather than a `previous`/`state` pair, because what a reader of
/// a recording asks is whether the connection *moved*: a packet that left the
/// state where it was is traffic on a conversation already accounted for, and a
/// history carrying one record per such packet would be the packet log the whole
/// point is not to keep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowTransition {
    /// The packet opened the flow. It is the one packet the filter is consulted
    /// about, so it is also the only transition a rule is named on.
    Opened,
    /// It moved the flow from one state to another.
    Advanced,
    /// It belonged to the flow and left its state where it was.
    Held,
}

/// What [`ConnectionStage`] worked out about the frame's place in a conversation.
///
/// Attached rather than returned, as [`Forwarding`] is: the tracker settles an
/// established frame in the middle of the chain, so the facts have to survive
/// past the stage that established them for anything behind — or outside — the
/// chain to read them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowObservation {
    /// The (slot, generation) handle, which is the only identity that does not
    /// silently merge two conversations that held one slot at different times.
    pub id: FlowId,
    pub classification: Classification,
    /// Where the flow stands *after* the frame.
    pub state: FlowState,
    pub transition: FlowTransition,
}

/// What [`RoutingStage`] worked out about a frame it did not settle: where the
/// frame would leave and under which MAC pair.
///
/// Attached rather than returned, which is the whole reason the routing stage
/// stopped being terminal. A later stage reads the egress port a rule names
/// without re-deriving it, and the forwarding verdict this becomes is composed
/// once, at the end of the chain, out of a decision made in the middle of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Forwarding {
    pub egress: PortId,
    /// The egress interface's own MAC.
    pub source: MacAddress,
    /// The next hop's MAC.
    pub destination: MacAddress,
}

impl<'frame> Inspection<'frame> {
    #[must_use]
    pub const fn new(ingress: PortId, frame: Frame<'frame>) -> Self {
        Self {
            ingress,
            frame,
            forwarding: None,
            flow: None,
            refusal: None,
            matched: None,
        }
    }

    /// The port the frame arrived on.
    #[must_use]
    pub const fn ingress(&self) -> PortId {
        self.ingress
    }

    /// The parsed headers. Shared rather than mutable: the chain decides, and
    /// the rewrite a [`Verdict::Forward`] authorises is the caller's, after the
    /// frame has been offered to whatever records it as it arrived.
    #[must_use]
    pub const fn frame(&self) -> &Frame<'frame> {
        &self.frame
    }

    /// Where the frame would leave, once a stage has worked it out.
    ///
    /// `None` before [`RoutingStage`] has run, and never `None` after it defers
    /// — a stage that cannot resolve a next hop settles the frame instead of
    /// passing it on, so every stage behind it sees a resolved one.
    #[must_use]
    pub const fn forwarding(&self) -> Option<Forwarding> {
        self.forwarding
    }

    /// Attach what this stage derived. Taken by the stage that resolved it, so
    /// the fact and its derivation stay in one place.
    pub const fn attach_forwarding(&mut self, forwarding: Forwarding) {
        self.forwarding = Some(forwarding);
    }

    /// The frame's place in a conversation, once the tracker has classified it.
    ///
    /// `None` before [`ConnectionStage::classify`] has run, and after it for a
    /// frame the tracker refused — a refusal is a statement that the packet
    /// belongs to no flow, which is why the two are separate answers rather than
    /// one enum: [`refusal`](Self::refusal) is what distinguishes it from a frame
    /// the tracker never saw.
    #[must_use]
    pub const fn flow(&self) -> Option<FlowObservation> {
        self.flow
    }

    /// Attach what the tracker resolved. Taken by the stage that resolved it, so
    /// the fact and its derivation stay in one place.
    pub const fn attach_flow(&mut self, flow: FlowObservation) {
        self.flow = Some(flow);
    }

    /// Why the tracker would keep no state for the frame, where it refused it.
    ///
    /// The one fact that tells a tracker refusal from an admission or routing
    /// drop: both leave no flow, and only this says the tracker was reached and
    /// answered.
    #[must_use]
    pub const fn refusal(&self) -> Option<RefusalKind> {
        self.refusal
    }

    pub const fn attach_refusal(&mut self, refusal: RefusalKind) {
        self.refusal = Some(refusal);
    }

    /// The position of the rule the filter matched, which is that rule's
    /// precedence and the slot its hit counter occupies.
    ///
    /// `None` where no rule was about the frame, and where the filter was never
    /// consulted at all — the two are told apart by whether the frame opened a
    /// flow, since the filter sees exactly the packets that do.
    #[must_use]
    pub const fn matched(&self) -> Option<usize> {
        self.matched
    }

    pub const fn attach_match(&mut self, position: usize) {
        self.matched = Some(position);
    }
}

/// The tables one evaluation decides against, and the generation that produced
/// them: one value, because a count attributed to a table that did not produce
/// it is worse than an unattributed one. The pairing is made where the
/// configuration is held, and an evaluation takes it whole or not at all.
#[derive(Clone, Copy, Debug)]
pub struct Configuration<'table, const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize> {
    generation: u32,
    table: &'table Router<MAX_INTERFACES, MAX_NEIGHBOURS>,
    rules: &'table Ruleset,
}

impl<'table, const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize>
    Configuration<'table, MAX_INTERFACES, MAX_NEIGHBOURS>
{
    #[must_use]
    pub const fn new(
        generation: u32,
        table: &'table Router<MAX_INTERFACES, MAX_NEIGHBOURS>,
        rules: &'table Ruleset,
    ) -> Self {
        Self {
            generation,
            table,
            rules,
        }
    }

    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    #[must_use]
    pub const fn table(&self) -> &'table Router<MAX_INTERFACES, MAX_NEIGHBOURS> {
        self.table
    }

    #[must_use]
    pub const fn rules(&self) -> &'table Ruleset {
        self.rules
    }
}

/// Link-layer admission: whether this appliance is the frame's addressee at all.
///
/// First in the chain, and separate from [`RoutingStage`], because it answers a
/// question about the *link* rather than about the packet: a frame this port
/// was not meant to receive has no L3 decision to make, and reporting it as
/// unroutable would name the second thing wrong with it. It is also what makes
/// every later stage's input meaningful — a policy or connection-tracking stage
/// asked about a broadcast frame is answering about traffic that is not ours.
pub struct AdmissionStage;

impl AdmissionStage {
    /// Refuse the frame, or defer to the rest of the chain.
    ///
    /// The order is the order these must be asked in, so the reason recorded is
    /// the first thing actually wrong: an interface that is not there or is
    /// down outranks anything about the frame, and a tag outranks the MAC
    /// comparison because a tagged frame's addressing is not this frame's to
    /// judge.
    pub fn evaluate<const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize>(
        &mut self,
        inspection: &mut Inspection<'_>,
        configuration: &Configuration<'_, MAX_INTERFACES, MAX_NEIGHBOURS>,
    ) -> Step {
        let Some(interface) = configuration.table().interface(inspection.ingress()) else {
            return Step::Settled(Verdict::Drop(DropReason::UnconfiguredIngressPort));
        };
        if !interface.enabled {
            return Step::Settled(Verdict::Drop(DropReason::InterfaceDisabled));
        }
        if inspection.frame().vlan().is_some() {
            return Step::Settled(Verdict::Drop(DropReason::VlanTagged));
        }
        if inspection.frame().destination_mac() != interface.mac {
            return Step::Settled(Verdict::Drop(DropReason::NotAddressedToUs));
        }
        Step::Continue
    }
}

/// The IPv4 forwarding decision: out of which port an admitted frame leaves,
/// and under which pair of MAC addresses.
///
/// It settles a frame it cannot forward and *defers* one it can, attaching the
/// egress and the MAC pair to the [`Inspection`] — see the crate header on why
/// the filter has to run behind it rather than in front of it.
pub struct RoutingStage;

impl RoutingStage {
    /// Resolve the frame's next hop, or name why it has none.
    ///
    /// The order is the order a router must use — source and destination
    /// sanity, then lifetime, then route, then resolution — so the reason
    /// recorded is the first thing actually wrong with the packet rather than
    /// whichever check ran last.
    pub fn evaluate<const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize>(
        &mut self,
        inspection: &mut Inspection<'_>,
        configuration: &Configuration<'_, MAX_INTERFACES, MAX_NEIGHBOURS>,
    ) -> Step {
        let settle = |reason| Step::Settled(Verdict::Drop(reason));
        let table = configuration.table();
        let ingress = inspection.ingress();
        let header = inspection.frame().ipv4();

        let source = header.source;
        if !source.is_unicast() || table.is_local_address(source) {
            return settle(DropReason::MartianSource);
        }
        let destination = header.destination;
        if !destination.is_unicast() {
            return settle(DropReason::UnroutableDestination);
        }
        if table.is_local_address(destination) {
            return settle(DropReason::AddressedToThisRouter);
        }
        // Before the route lookup, so an expiring packet is reported as such
        // rather than as whatever the lookup happens to say about it.
        if header.ttl <= 1 {
            return settle(DropReason::TtlExpired);
        }

        let Some(egress) = table.route(destination) else {
            return settle(DropReason::NoRoute);
        };
        // Looked up across every interface and only then compared with the
        // ingress, so a longer prefix on the ingress port beats a shorter one
        // elsewhere and the frame is dropped rather than carried by it. The
        // longest match is the most specific statement about where the
        // destination lives; if that is the link it arrived on, the sender
        // should have addressed the host directly, and carrying it out of a
        // less specific route would put it on the wrong link.
        if egress.port == ingress {
            return settle(DropReason::EgressIsIngress);
        }
        let Some(neighbour) = table.neighbour(egress.port, destination) else {
            return settle(DropReason::NoNeighbour);
        };

        inspection.attach_forwarding(Forwarding {
            egress: egress.port,
            source: egress.mac,
            destination: neighbour.mac,
        });
        Step::Continue
    }
}

/// The connection table one evaluation classifies against, and the instant it
/// is classified at.
///
/// Lent per evaluation rather than owned by the chain, for one reason that is
/// not style: at the appliance's capacity the table is sixty-eight mebibytes in
/// a memory region a protection domain maps, so a [`Pipeline`] that owned one
/// could not be constructed anywhere else — not in a test, not in a benchmark,
/// not before the region exists. The capacity is a parameter for the same
/// reason [`Configuration`]'s table sizes are: a host test drives a sixteen-slot
/// table through the identical code the appliance runs a million-slot one
/// through.
///
/// The clock is the caller's, as it is everywhere else this crate's dependencies
/// take one: reading one is a capability a protection domain is granted, and a
/// chain that reached for a clock could not be driven by a test at all.
pub struct Tracking<'table, const FLOWS: usize> {
    table: &'table mut FlowTable<FLOWS>,
    now: Monotonic,
}

impl<'table, const FLOWS: usize> Tracking<'table, FLOWS> {
    #[must_use]
    pub const fn new(table: &'table mut FlowTable<FLOWS>, now: Monotonic) -> Self {
        Self { table, now }
    }

    /// The table itself, for a caller reading what it has counted.
    #[must_use]
    pub const fn table(&self) -> &FlowTable<FLOWS> {
        self.table
    }
}

/// State: whether a frame belongs to a conversation the appliance already knows
/// about, and — where it does not — whether it may open one.
///
/// It is two halves bracketing [`PolicyStage`] rather than one stage, and the
/// split is the whole of what makes stateful filtering safe here.
///
/// # The half in front: an existing flow answers for its own packets
///
/// An [`Outcome::Established`] or an [`Outcome::Related`] **settles the frame**,
/// forwarding it under the facts [`RoutingStage`] attached, and the filter is
/// never consulted. Two things follow, and both are the point. A reply is carried
/// without a rule naming it, which is the entire value of tracking state — the
/// alternative is writing the reverse of every rule and opening the appliance in
/// both directions to permit one. And **no packet-path decision can break a live
/// connection**: the rule that admitted a conversation is consulted once, when it
/// opened, so an operator narrowing a rule stops *new* connections rather than
/// cutting established ones mid-stream. What does reach a running conversation is
/// [`PolicySweep`], on the commit rather than on a packet.
///
/// The consequence for [`Ruleset`] is worth stating here rather than leaving to
/// be worked out: **every frame that reaches the filter has just opened a flow**.
/// A ruleset is therefore a statement about which conversations may *start*, and
/// there is no criterion for a rule to name a connection's state with — such a
/// criterion would have exactly one reachable value and would read as a choice an
/// operator did not have.
///
/// An [`Outcome::New`] defers, because a flow the appliance has not seen before is
/// exactly the packet the filter exists to decide about. A refusal settles as a
/// drop under the reason [`DropReason::of_refusal`] names.
///
/// # The half behind: a refused opening costs no state
///
/// Classification commits the slot, so by the time the filter says no the flow
/// is already in the table. Left there, a default-deny policy becomes a
/// state-exhaustion amplifier — every rejected opening packet holds a slot, and
/// an attacker fills the table with connections the policy already refused
/// until legitimate ones are turned away with [`DropReason::FlowTableFull`]. So
/// the half behind the filter withdraws a flow this evaluation opened whenever
/// the verdict is to drop. It is a security property and not tidiness.
pub struct ConnectionStage;

impl ConnectionStage {
    /// Classify the frame, settling it where an existing flow already accounts
    /// for it and where the tracker refuses it outright.
    pub fn classify<const FLOWS: usize>(
        &mut self,
        inspection: &mut Inspection<'_>,
        tracking: &mut Tracking<'_, FLOWS>,
    ) -> Step {
        let header = inspection.frame().ipv4();
        let outcome = tracking.table.classify(
            tracking.now,
            &lfw_flow::Packet {
                ingress: inspection.ingress().0,
                source: header.source,
                destination: header.destination,
                transport: inspection.frame().transport(),
                transport_bytes: inspection.frame().payload(),
            },
        );
        match outcome {
            // Deferred so the filter decides, which is what an unrecognised
            // conversation is for; the observation is what the half behind it
            // needs if the filter then says no.
            Outcome::New { flow, state } => {
                inspection.attach_flow(FlowObservation {
                    id: flow,
                    classification: Classification::New,
                    state,
                    transition: FlowTransition::Opened,
                });
                Step::Continue
            }
            Outcome::Established {
                flow,
                previous,
                state,
                ..
            } => {
                inspection.attach_flow(FlowObservation {
                    id: flow,
                    classification: Classification::Established,
                    state,
                    transition: if previous == state {
                        FlowTransition::Held
                    } else {
                        FlowTransition::Advanced
                    },
                });
                Self::forward(inspection)
            }
            Outcome::Related { flow, .. } => {
                // An error never moves the flow it reports on, so the state is
                // the table's current one. The lookup cannot miss — the same
                // call resolved the slot — and where it did the frame is still
                // decided under a record that names no flow, which is a weaker
                // record rather than a wrong one.
                if let Some(state) = tracking.table().flow(flow).map(FlowEntry::state) {
                    inspection.attach_flow(FlowObservation {
                        id: flow,
                        classification: Classification::Related,
                        state,
                        transition: FlowTransition::Held,
                    });
                }
                // Deferred, not settled. The frame is one the sender composed
                // with a source address of its choosing, and it is delivered to
                // an endpoint of a conversation somebody else opened — so the
                // one thing that must not follow from "a flow accounts for it"
                // is that it crosses. The filter decides, and a document that
                // says nothing about related traffic denies it.
                Step::Continue
            }
            Outcome::Refused(refusal) => {
                inspection.attach_refusal(refusal.kind());
                Step::Settled(Verdict::Drop(DropReason::of_refusal(refusal.kind())))
            }
        }
    }

    /// Forward the frame under the facts [`RoutingStage`] attached, which is what
    /// a flow the tracker already accounts for is carried by.
    fn forward(inspection: &Inspection<'_>) -> Step {
        match inspection.forwarding() {
            Some(forwarding) => Step::Settled(Verdict::Forward {
                egress: forwarding.egress,
                source: forwarding.source,
                destination: forwarding.destination,
            }),
            // Unreachable: the stage in front settles every frame it cannot
            // resolve a next hop for. Deferred rather than asserted, and the
            // filter's own answer to the same absence is to deny — so the one
            // path that cannot tell where a frame would go does not forward it.
            None => Step::Continue,
        }
    }

    /// Give back a flow this evaluation opened, where the filter behind it
    /// refused the packet that opened it.
    ///
    /// Takes the verdict rather than reading one, because there is nothing to
    /// decide here: the caller has the answer and this is the consequence of it.
    pub fn settle<const FLOWS: usize>(
        &mut self,
        inspection: &Inspection<'_>,
        tracking: &mut Tracking<'_, FLOWS>,
        verdict: Verdict,
    ) {
        let opened = inspection
            .flow()
            .filter(|flow| flow.transition == FlowTransition::Opened);
        if let (Verdict::Drop(_), Some(flow)) = (verdict, opened) {
            tracking.table.withdraw(flow.id);
        }
    }
}

/// One address criterion: the block a rule compares an address against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    network: Ipv4Address,
    /// The mask the length names, precomputed: a match is one `&` and one
    /// comparison, and deriving the mask per packet per rule would be a shift
    /// on the hot path for a value that changes once per generation.
    mask: u32,
}

impl Prefix {
    /// `network` is expected to have no host bits set, which is a rule the
    /// configuration enforces on both sides; masking here anyway costs one
    /// instruction per generation and makes this total whatever it is handed.
    #[must_use]
    pub fn new(network: Ipv4Address, prefix_length: u8) -> Self {
        let mask = net_headers::prefix_mask(prefix_length);
        Self {
            network: Ipv4Address::from_octets((network.bits() & mask).to_be_bytes()),
            mask,
        }
    }

    #[must_use]
    fn covers(&self, address: Ipv4Address) -> bool {
        address.bits() & self.mask == self.network.bits()
    }
}

/// One port criterion, inclusive at both ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRange {
    pub low: u16,
    pub high: u16,
}

impl PortRange {
    #[must_use]
    const fn covers(&self, port: u16) -> bool {
        self.low <= port && port <= self.high
    }
}

/// What a rule does with a frame it matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleAction {
    Accept,
    Drop,
}

/// One filter rule as the dataplane matches it.
///
/// Every criterion is an `Option` and `None` is the wildcard, so a criterion an
/// operator wrote `any` for costs one `is_some` rather than a comparison
/// against a value standing in for "do not compare". It carries no id: what
/// identifies a rule on this side is its position, which is also its precedence
/// and the slot its counter occupies.
/// Which of the two things that reach the filter a rule is about.
///
/// Two values because two reach it. A frame belonging to a conversation the
/// tracker already accounts for is settled in front of the filter and never
/// arrives, so there is no value for it and a rule cannot name one: the
/// criterion offers exactly what a rule can decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tracked {
    /// The frame opens a conversation, which is what the filter is mostly about.
    Opening,
    /// The frame is one an existing conversation is the reason for without
    /// belonging to it: an ICMP error quoting one of its datagrams. Its source
    /// address is whatever the sender chose, so a rule that does not name this
    /// does not admit it.
    Related,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub ingress: Option<PortId>,
    pub egress: Option<PortId>,
    pub source: Option<Prefix>,
    pub destination: Option<Prefix>,
    pub protocol: Option<Protocol>,
    pub source_port: Option<PortRange>,
    pub destination_port: Option<PortRange>,
    pub icmp_type: Option<u8>,
    pub tracking: Option<Tracked>,
    pub action: RuleAction,
}

impl Rule {
    /// Whether this rule is about a packet with these criteria.
    ///
    /// The **only** matcher. A rule is asked about two things that are not the
    /// same object — a frame the chain is deciding on, and the opening of a flow
    /// the chain admitted earlier and is re-deciding on — and a second matcher
    /// for the second of them would be a policy engine with two answers, drifting
    /// apart one criterion at a time. So both are reduced to a [`FlowSelector`]
    /// first and this is what compares one.
    #[must_use]
    fn admits(&self, selector: &FlowSelector) -> bool {
        if self.ingress.is_some_and(|port| port != selector.ingress)
            || self.egress.is_some_and(|port| port != selector.egress)
        {
            return false;
        }
        if self
            .source
            .is_some_and(|block| !block.covers(selector.source))
            || self
                .destination
                .is_some_and(|block| !block.covers(selector.destination))
        {
            return false;
        }
        if self
            .protocol
            .is_some_and(|protocol| protocol != selector.protocol)
        {
            return false;
        }
        if self.source_port.is_some() || self.destination_port.is_some() {
            let Some((source, destination)) = selector.ports else {
                return false;
            };
            if self.source_port.is_some_and(|range| !range.covers(source))
                || self
                    .destination_port
                    .is_some_and(|range| !range.covers(destination))
            {
                return false;
            }
        }
        if let Some(wanted) = self.icmp_type
            && selector.icmp_type != Some(wanted)
        {
            return false;
        }
        if self
            .tracking
            .is_some_and(|wanted| wanted != selector.tracking)
        {
            return false;
        }
        true
    }
}

/// Everything a [`Rule`] compares, separated from whatever the values came out
/// of.
///
/// It exists because a rule is asked about a packet at two different moments: on
/// the frame that opens a conversation, and again — with no frame left — on a
/// conversation the policy already admitted, when [`PolicySweep`] re-decides one.
/// Reducing both to this value is what makes those two answers the same answer.
///
/// # Every absent field is a criterion that cannot be satisfied
///
/// `ports` and `icmp_type` are `None` wherever the value was not read, and a
/// stated criterion on an absent value does **not** match. That is the
/// fail-closed direction on a default-deny appliance in both of its uses: a
/// truncated transport header, a non-initial fragment or a protocol this build
/// does not break down cannot be carried through an `accept` written for a port,
/// and neither can a conversation whose opening a re-decision cannot fully
/// reconstruct. It falls to the next rule, and past the last of them to the
/// default deny.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowSelector {
    pub ingress: PortId,
    pub egress: PortId,
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub protocol: Protocol,
    /// The transport's source and destination ports, absent where no readable
    /// header carried them.
    pub ports: Option<(u16, u16)>,
    /// The ICMP message type, absent for anything that is not a readable ICMP
    /// header.
    pub icmp_type: Option<u8>,
    /// Which of the two things that reach the filter this is. Never absent: the
    /// tracker has already classified the frame by the time the filter is asked,
    /// so there is no case where this is unknown — and a criterion that could be
    /// unsatisfiable by absence would let related traffic through a rule written
    /// for an opening.
    pub tracking: Tracked,
}

impl FlowSelector {
    /// What a rule compares about one frame, under the forwarding decision the
    /// routing stage reached for it.
    #[must_use]
    pub fn of_frame(ingress: PortId, egress: PortId, frame: &Frame<'_>, tracking: Tracked) -> Self {
        let header = frame.ipv4();
        let transport = frame.transport();
        Self {
            ingress,
            egress,
            source: header.source,
            destination: header.destination,
            protocol: header.protocol,
            ports: transport_ports(transport),
            icmp_type: match transport {
                Transport::Icmp(icmp) => Some(icmp.message_type),
                _ => None,
            },
            tracking,
        }
    }
}

/// The two ports a transport carries, or `None` where none were read.
///
/// Exhaustive over [`Transport`] rather than a `match` with a fallthrough,
/// which is the point: a variant added to that enum stops compiling here rather
/// than silently joining the group that answers nothing — and on this path
/// "answers nothing" is what keeps a port criterion from matching a header that
/// was never parsed.
const fn transport_ports(transport: Transport) -> Option<(u16, u16)> {
    match transport {
        Transport::Udp(udp) => Some((udp.source_port, udp.destination_port)),
        Transport::Tcp(tcp) => Some((tcp.source_port, tcp.destination_port)),
        Transport::Icmp(_)
        | Transport::TruncatedUdp { .. }
        | Transport::TruncatedTcp { .. }
        | Transport::TruncatedIcmp { .. }
        | Transport::NonInitialFragment
        | Transport::Unparsed(_) => None,
    }
}

/// Rules one generation may carry, and so the counter slots a shard reserves
/// for them. The same number the configuration ABI holds, held equal to it
/// where both are visible.
pub const MAX_RULES: usize = 256;

/// The ruleset one generation states, in document order.
///
/// A fixed array rather than a growable one for the reason every other table
/// here is: there is no allocator, and a ruleset that could outgrow its storage
/// would need a decision on the packet path about what to do with the rules
/// that did not fit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ruleset {
    rules: [Option<Rule>; MAX_RULES],
    len: usize,
}

/// A ruleset a generation named more rules than this build holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RulesetFull {
    pub requested: usize,
    pub capacity: usize,
}

impl Ruleset {
    /// No rules, which under a default-deny filter forwards nothing — the same
    /// posture generation 0 has, and what a domain runs under until it is given
    /// something else.
    pub const EMPTY: Self = Self {
        rules: [None; MAX_RULES],
        len: 0,
    };

    /// Build a ruleset from `rules`, in the order they arrive, which is the
    /// order they are decided in.
    ///
    /// # Errors
    /// [`RulesetFull`] for more rules than [`MAX_RULES`], rather than a
    /// truncation: a policy silently missing its last rules is a policy that
    /// denies what it was written to allow, or worse.
    pub fn build(rules: impl Iterator<Item = Rule>) -> Result<Self, RulesetFull> {
        let mut built = Self::EMPTY;
        for rule in rules {
            let Some(slot) = built.rules.get_mut(built.len) else {
                return Err(RulesetFull {
                    requested: built.len.saturating_add(1),
                    capacity: MAX_RULES,
                });
            };
            *slot = Some(rule);
            built.len = built.len.saturating_add(1);
        }
        Ok(built)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The first rule that matches, and its position — which is its precedence
    /// and the slot its counter occupies.
    ///
    /// First match wins, so the walk stops at the first hit rather than
    /// collecting every rule that would have matched. Bounded by the rules the
    /// generation actually declared and not by [`MAX_RULES`], so an eight-rule
    /// document costs eight comparisons rather than two hundred and fifty-six.
    #[must_use]
    pub fn first_match(&self, selector: &FlowSelector) -> Option<(usize, Rule)> {
        self.rules
            .iter()
            .take(self.len)
            .flatten()
            .enumerate()
            .find(|(_, rule)| rule.admits(selector))
            .map(|(position, rule)| (position, *rule))
    }
}

impl Default for Ruleset {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// What the filter has counted, which is one hit counter per declared rule and
/// the four totals an operator reads first.
///
/// Saturating and never reset, on [`DropCounters`]' terms. The per-rule slots
/// are indexed by position, so a counter belongs to whichever rule sits at that
/// position in the running generation — which is what makes the label the
/// management domain joins to it the id of that same rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyCounters {
    hits: [u64; MAX_RULES],
    accepted_packets: u64,
    accepted_bytes: u64,
    denied_packets: u64,
    denied_bytes: u64,
}

impl PolicyCounters {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            hits: [0; MAX_RULES],
            accepted_packets: 0,
            accepted_bytes: 0,
            denied_packets: 0,
            denied_bytes: 0,
        }
    }

    /// Hits against the rule at `position`, or 0 for a position no generation
    /// has declared.
    #[must_use]
    pub fn hits(&self, position: usize) -> u64 {
        match self.hits.get(position) {
            Some(count) => *count,
            None => 0,
        }
    }

    /// Every hit slot, for a domain publishing them into its shard.
    #[must_use]
    pub const fn all_hits(&self) -> &[u64; MAX_RULES] {
        &self.hits
    }

    #[must_use]
    pub const fn accepted_packets(&self) -> u64 {
        self.accepted_packets
    }

    #[must_use]
    pub const fn accepted_bytes(&self) -> u64 {
        self.accepted_bytes
    }

    #[must_use]
    pub const fn denied_packets(&self) -> u64 {
        self.denied_packets
    }

    #[must_use]
    pub const fn denied_bytes(&self) -> u64 {
        self.denied_bytes
    }

    fn record(&mut self, position: Option<usize>, action: RuleAction, bytes: u64) {
        if let Some(count) = position.and_then(|position| self.hits.get_mut(position)) {
            *count = count.saturating_add(1);
        }
        let (packets, total) = match action {
            RuleAction::Accept => (&mut self.accepted_packets, &mut self.accepted_bytes),
            RuleAction::Drop => (&mut self.denied_packets, &mut self.denied_bytes),
        };
        *packets = packets.saturating_add(1);
        *total = total.saturating_add(bytes);
    }
}

impl Default for PolicyCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// The filter: which of the operator's rules is about this frame, and what it
/// says to do with it.
///
/// Terminal, and its answer for a frame no rule is about is to drop it. That is
/// the whole of the default-deny posture and it is a property of this function
/// rather than of any document: there is no ruleset an operator can write that
/// makes the fallthrough permit anything, because the fallthrough is not a rule.
pub struct PolicyStage {
    counters: PolicyCounters,
}

impl PolicyStage {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            counters: PolicyCounters::new(),
        }
    }

    #[must_use]
    pub const fn counters(&self) -> &PolicyCounters {
        &self.counters
    }

    /// Match the ruleset and answer with the first rule's action, or deny.
    ///
    /// The forwarding facts are [`RoutingStage`]'s, taken off the
    /// [`Inspection`] rather than re-derived. Their absence is unreachable —
    /// the stage in front settles every frame it cannot resolve — and it is
    /// answered as a denial rather than an assertion, because the one thing a
    /// filter must never do when it cannot tell is permit.
    pub fn evaluate<const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize>(
        &mut self,
        inspection: &mut Inspection<'_>,
        configuration: &Configuration<'_, MAX_INTERFACES, MAX_NEIGHBOURS>,
    ) -> Verdict {
        let Some(forwarding) = inspection.forwarding() else {
            return Verdict::Drop(DropReason::NoPolicyMatch);
        };
        // The datagram's own length, which is what the sender's L3 claims and
        // what a byte total an operator compares against a link's throughput
        // has to be stated in.
        let bytes = u64::from(inspection.frame().ipv4().total_length);
        // Whatever the tracker said about this frame, in the only two shapes
        // that reach here: a conversation opening, or traffic an existing one is
        // the reason for. An absent observation is an opening — the stage in
        // front attaches one to every frame it defers, and deciding an
        // unclassified frame as related would be admitting it under a rule
        // written for something else.
        let tracking = match inspection.flow().map(|flow| flow.classification) {
            Some(Classification::Related) => Tracked::Related,
            Some(Classification::New | Classification::Established) | None => Tracked::Opening,
        };
        let matched = configuration.rules().first_match(&FlowSelector::of_frame(
            inspection.ingress(),
            forwarding.egress,
            inspection.frame(),
            tracking,
        ));
        match matched {
            Some((position, rule)) => {
                self.counters.record(Some(position), rule.action, bytes);
                inspection.attach_match(position);
                match rule.action {
                    RuleAction::Accept => Verdict::Forward {
                        egress: forwarding.egress,
                        source: forwarding.source,
                        destination: forwarding.destination,
                    },
                    RuleAction::Drop => Verdict::Drop(DropReason::PolicyDenied),
                }
            }
            None => {
                self.counters.record(None, RuleAction::Drop, bytes);
                Verdict::Drop(DropReason::NoPolicyMatch)
            }
        }
    }
}

impl Default for PolicyStage {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether the configuration would admit a conversation opening the way this one
/// did, and under which rule.
///
/// The same chain a frame goes through, with the parts that are not about the flow
/// left out — see [`PolicySweep`] for which parts those are and why. The order is
/// [`AdmissionStage`]'s then [`RoutingStage`]'s, so a flow whose link or route the
/// new configuration no longer has is disowned before the filter is reached: with
/// no egress there is nothing for a rule naming one to be about, and the filter's
/// own answer to a frame it cannot place is to deny.
fn admits_opening<const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize>(
    configuration: &Configuration<'_, MAX_INTERFACES, MAX_NEIGHBOURS>,
    opening: &lfw_flow::FlowOpening,
) -> Option<usize> {
    let table = configuration.table();
    let ingress = PortId(opening.ingress);
    let interface = table.interface(ingress)?;
    if !interface.enabled {
        return None;
    }
    let source = opening.source.address;
    let destination = opening.destination.address;
    if !source.is_unicast() || table.is_local_address(source) {
        return None;
    }
    if !destination.is_unicast() || table.is_local_address(destination) {
        return None;
    }
    let egress = table.route(destination)?;
    if egress.port == ingress {
        return None;
    }
    table.neighbour(egress.port, destination)?;
    let protocol = opening.protocol;
    let selector = FlowSelector {
        ingress,
        egress: egress.port,
        source,
        destination,
        protocol,
        // An ICMP flow's endpoints carry the echo identifier where a port would
        // sit, so it is *not* offered as one: a port criterion answered from an
        // identifier would be a rule matching a number that is not what it names.
        // A document stating one on ICMP is refused before it commits, so the
        // absence costs nothing an operator can write.
        ports: (protocol != Protocol::ICMP)
            .then_some((opening.source.port, opening.destination.port)),
        // An echo request is the only ICMP message that opens a flow, so the type
        // the opening packet carried is recovered exactly rather than guessed.
        icmp_type: (protocol == Protocol::ICMP).then_some(IcmpHeader::ECHO_REQUEST),
        // The question a re-decision asks is whether a packet *opening* this
        // conversation would be admitted now, so it is asked under the opening
        // criterion. Related traffic opens nothing and holds no slot of its own,
        // so there is no flow for this pass to re-decide under that value.
        tracking: Tracked::Opening,
    };
    match configuration.rules().first_match(&selector) {
        Some((position, rule)) if matches!(rule.action, RuleAction::Accept) => Some(position),
        Some(_) | None => None,
    }
}

/// Frames one wakeup may drain, which is `pd_runtime::DRAIN_LIMIT`.
///
/// Restated rather than imported — that crate depends on this one, so the edge
/// cannot run the other way — and held equal to it by a const assertion there, the
/// way [`MAX_RULES`] and `wire::MAX_RULES` are held equal.
pub const WAKEUP_FRAME_BUDGET: usize = 128;

/// Frames whose forwarding costs about what one window of re-deciding costs.
///
/// Measured rather than chosen, from the two benchmarks in `pd-runtime`: one
/// window over an empty table is about 3.4 µs (`policy_sweep_window`) and a
/// forwarded frame is about 85 ns (`route_forwarded`), so a window is about forty
/// frames. It is a ratio between two costs on one machine, so it is a *scale* and
/// not a promise: both move together on faster hardware.
pub const FRAMES_PER_WINDOW: usize = 40;

/// Windows per wakeup at full occupancy, and the factor the occupancy budget
/// scales by.
///
/// Derived rather than chosen: a window walks [`lfw_flow::REVISIT_BUCKETS`]
/// buckets *or* stops at [`lfw_flow::REVISIT_FLOWS`] flows, whichever comes first,
/// so a table with a flow in every bucket needs that ratio more windows to cross
/// the same span of index than an empty one does. Paying the ratio is exactly what
/// makes the two take the same number of wakeups.
pub const OCCUPANCY_SCALE: usize = lfw_flow::REVISIT_BUCKETS / lfw_flow::REVISIT_FLOWS;

/// How many windows a wakeup works off: the greater of what the frame budget left
/// unspent and what the table's own occupancy needs.
///
/// Two budgets, because they answer different questions. The **slack** budget is
/// the original one: a wakeup's own work is bounded by [`WAKEUP_FRAME_BUDGET`]
/// frames and a quiet wakeup spends what that leaves, so a pass finishes in a
/// quarter of the wakeups when there is little traffic — which is when a commit
/// usually lands.
///
/// The **occupancy** budget is what stops a pass getting longer the more flows
/// there are to re-decide. A window stops at [`lfw_flow::REVISIT_FLOWS`] flows, so
/// a full table crosses [`OCCUPANCY_SCALE`] times less index per window than an
/// empty one — and against the slack budget alone a saturated wakeup pays one
/// window either way, so the pass over a full table took that factor more wakeups
/// than the pass over an empty one. That is the wrong direction on a security
/// device: the state is the attacker's to create, and the flows a narrowed policy
/// forbids would go on forwarding longest exactly when there are most of them.
/// Scaling by occupancy makes the pass length a property of the table's *width*,
/// which is a build constant, rather than of how much of it an attacker has
/// filled.
///
/// **What that costs is that a wakeup can now spend more on re-deciding than a
/// full drain costs** — up to [`OCCUPANCY_SCALE`] windows against a saturated
/// drain's one. It is bounded by a constant either way, `capacity` being fixed at
/// compile time, and it is the deliberate trade: a revocation an operator has
/// asked for completes in a bounded number of wakeups, at the price of those
/// wakeups being more expensive while it does.
///
/// At least one window always, so a pass cannot stall on a domain that is busy.
#[must_use]
pub const fn windows_for(forwarded: usize, occupied: usize, capacity: usize) -> usize {
    let spent = if forwarded > WAKEUP_FRAME_BUDGET {
        WAKEUP_FRAME_BUDGET
    } else {
        forwarded
    };
    let slack = 1 + (WAKEUP_FRAME_BUDGET - spent) / FRAMES_PER_WINDOW;
    let occupancy = windows_for_occupancy(occupied, capacity);
    if occupancy > slack { occupancy } else { slack }
}

/// The occupancy half of [`windows_for`]: the load factor times
/// [`OCCUPANCY_SCALE`], rounded up, and at least one.
///
/// Saturating, and the saturation is unreachable on any table this workspace
/// builds: `occupied` never exceeds `capacity`, so the product is twenty-four bits
/// for the appliance's own. A nonsense pair buys a larger budget, which is bounded
/// work and never a wider walk — `FlowTable::revisit` bounds itself.
const fn windows_for_occupancy(occupied: usize, capacity: usize) -> usize {
    if capacity == 0 {
        return 1;
    }
    let scaled = occupied.saturating_mul(OCCUPANCY_SCALE);
    let windows = scaled.div_ceil(capacity);
    if windows > 1 { windows } else { 1 }
}

/// What the re-decision has done, which is otherwise invisible: an operator who
/// has narrowed a policy needs to know both that flows were ended by it and that
/// the pass ending them has finished.
///
/// Monotonic and saturating, on [`DropCounters`]' terms.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolicySweepCounters {
    /// Passes that reached the last bucket, which is what says the window a commit
    /// opens has closed.
    pub completed: u64,
    /// Commits that arrived while a pass was already running, so a fresh pass over
    /// the whole table was queued behind it rather than the running one being
    /// abandoned. A number that climbs is commits arriving faster than the table is
    /// swept.
    pub deferred: u64,
    pub buckets: u64,
    pub examined: u64,
}

/// What one [`PolicySweep::advance`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Swept {
    /// The generation the flows were re-decided against.
    pub generation: u32,
    pub buckets: usize,
    pub examined: usize,
    pub revoked: usize,
    pub complete: bool,
}

/// The re-decision: on a newly committed configuration, the pass over the
/// connection table that takes back every flow the new policy would not admit.
///
/// # Why it is not per packet
///
/// [`ConnectionStage`]'s half in front settles an established frame before the
/// filter is consulted, which is what carries a reply no rule names and what keeps
/// an edit from cutting a conversation already running on the packet path. The cost
/// is that narrowing a rule reaches nothing it had already admitted — a host found
/// to be compromised keeps every connection it had open. Consulting the policy per
/// packet would close that and give up the guarantee the model exists for, so the
/// *table* is re-decided when the policy changes instead.
///
/// # What a re-decision can and cannot answer
///
/// A flow was admitted by a rule matching its opening packet, and that packet is
/// gone. What is left is [`lfw_flow::FlowOpening`] — the five-tuple in the
/// orientation it travelled in, and the port it arrived on — so the re-decision
/// is over a key and not over a packet. Every criterion a [`Rule`] carries is
/// recovered from it exactly: the addresses and the protocol are the key's, the
/// ports are the key's for TCP and UDP, the ICMP type is an echo request because
/// nothing else opens an ICMP flow, the ingress is the port the entry recorded,
/// and the egress is resolved from the **new** table — which is the right answer
/// rather than a remembered one, a rule naming an egress being about where the
/// frame would now go.
///
/// Two facts of the opening packet are unrecoverable and neither is a criterion:
/// its destination MAC and its remaining lifetime. Both are properties of a
/// packet rather than of a conversation — a rule cannot name either — so their
/// absence costs the re-decision nothing.
///
/// # Where it is conservative, and in which direction
///
/// Absent values never satisfy a criterion ([`FlowSelector`]), so the pass can
/// only ever disown a flow the policy might have admitted and never keep one it
/// forbids. It is conservative in exactly one place: a flow whose ingress
/// interface the new configuration no longer has or has disabled, or whose
/// original destination it can no longer route to a neighbour, is disowned — even
/// though packets in that flow's *reply* direction might still have been
/// forwarded. That is the safe direction and it is also the honest reading of the
/// question: a packet opening this conversation now would be refused before the
/// filter saw it, so the configuration no longer admits the conversation.
///
/// # It is bounded, and what that costs
///
/// A pass cannot run to completion in one wakeup: `pd-runtime`'s
/// `policy_sweep_window` benchmark times one window of
/// [`lfw_flow::REVISIT_BUCKETS`] buckets at about 3.4 µs over an empty table, so a
/// whole pass over the appliance's own index is nearly a millisecond — and a
/// commit that stalled forwarding for that long would be a worse defect than the
/// one re-deciding exists to fix. So a pass is carried across wakeups, and a
/// wakeup works off as many windows as [`windows_for`] gives it.
///
/// **How many wakeups a pass takes does not depend on how many flows there are.**
/// A window crosses `REVISIT_BUCKETS` of index or stops at
/// [`lfw_flow::REVISIT_FLOWS`] flows, so a full table needs
/// [`OCCUPANCY_SCALE`] times more windows to cross the same span than an empty one
/// — and the budget is scaled by occupancy to match, which is what keeps the
/// number of wakeups a property of the table's compile-time width rather than of
/// how much of it an attacker has filled. Two terms bound a pass: the index walk,
/// `CAPACITY / REVISIT_BUCKETS` windows, and the flows,
/// `occupied / REVISIT_FLOWS` windows; each window is limited by one or the other,
/// so the pass is their sum, and dividing by the scaled budget leaves each term at
/// most `CAPACITY / REVISIT_BUCKETS` wakeups whatever the occupancy. For the
/// appliance's own million-slot table that is at most 513 wakeups at any
/// occupancy — 272 at a table entirely full — where before the scaling a full
/// table took 4096.
///
/// A commit arriving mid-pass adds one more pass rather than restarting the one
/// running ([`arm`](Self::arm)), so **every flow the policy in force forbids is
/// gone within at most two passes** — 1026 wakeups on that table — however fast
/// documents are submitted.
///
/// A flow the new policy forbids therefore keeps forwarding for up to that many
/// wakeups. What bounds *that* is the flow itself: a conversation forwards only
/// when its packets arrive, every arriving frame wakes the domain, and every
/// wakeup advances the pass — so a forbidden flow that is *doing* anything is
/// generating the wakeups that end it.
///
/// What that argument does **not** give is a bound in wall-clock time. A node
/// forwarding nothing receives no wakeups and does not finish its pass; it is also
/// forwarding nothing, so no conversation the new policy forbids is crossing, and
/// the pass resumes with the traffic. [`PolicySweepCounters::completed`] and the
/// gauge beside it are what say which of the two a node is in, and reading 1 for a
/// long quiet stretch is the honest answer rather than a fault.
pub struct PolicySweep {
    /// The bucket the next call resumes at, or `None` while no pass is running.
    cursor: Option<usize>,
    /// The generation flows are judged against, which is always the newest one
    /// committed — a pass that went on judging against a document already replaced
    /// could take back a conversation the policy in force still admits.
    generation: u32,
    /// Set where a commit arrived while a pass was already running: that pass runs
    /// on to the last bucket and a fresh one over the whole table follows it.
    ///
    /// One flag and not a queue, because a second commit while one is already
    /// deferred needs nothing more: what is owed either way is one walk of the whole
    /// table against the newest generation, and that is what the flag buys.
    deferred: bool,
    counters: PolicySweepCounters,
}

impl PolicySweep {
    /// Nothing to re-decide, which is what a domain that has committed nothing
    /// is in.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cursor: None,
            generation: 0,
            deferred: false,
            counters: PolicySweepCounters {
                completed: 0,
                deferred: 0,
                buckets: 0,
                examined: 0,
            },
        }
    }

    #[must_use]
    pub const fn counters(&self) -> PolicySweepCounters {
        self.counters
    }

    /// Whether a pass is still owed, which is the window an operator watches a
    /// commit close over.
    #[must_use]
    pub const fn running(&self) -> bool {
        self.cursor.is_some()
    }

    /// Start a pass over the whole table, because `generation` is now in force.
    ///
    /// Called on every commit, including one that changed no rule: what a commit
    /// replaces is both tables at once, and a routing change moves which egress a
    /// rule is about.
    ///
    /// # Why arming a running pass queues rather than restarts
    ///
    /// A pass already running cannot simply continue under the new generation: the
    /// buckets behind its cursor were judged against the document this one replaces,
    /// so a flow the new policy forbids sitting behind the cursor would never be
    /// re-decided at all. Keeping the cursor is therefore not available — it is the
    /// one direction that can leave a forbidden conversation forwarding forever.
    ///
    /// Restarting from the first bucket is sound and was what this did, and it is
    /// what a submission storm turns into starvation: the party that submits
    /// documents is unauthenticated, so a pass could be restarted faster than it
    /// completes and never finish — again leaving the forbidden flows forwarding
    /// while the storm lasts. So the running pass is left to finish and a fresh one
    /// over the whole table is queued behind it, which bounds the delay at two
    /// passes however fast commits arrive.
    ///
    /// The generation itself moves at once, whichever of the two happens. A pass
    /// judging against a superseded document could take back a conversation the
    /// policy in force still admits, and the queued pass covers the prefix that
    /// was judged before the commit landed.
    pub fn arm(&mut self, generation: u32) {
        self.generation = generation;
        if self.cursor.is_some() {
            self.counters.deferred = self.counters.deferred.saturating_add(1);
            self.deferred = true;
            return;
        }
        self.cursor = Some(0);
    }

    /// Re-decide on one bounded window of the table, taking back the flows the
    /// configuration no longer admits and telling `observe` about each.
    ///
    /// `None` while no pass is running, which is every wakeup but the ones a commit
    /// is being worked off over.
    ///
    /// `observe` is called for exactly the flows this call revoked, before their
    /// slots are handed back — so a caller recording the end of a conversation
    /// still has its identity and its state. It is never consulted about a flow
    /// that is kept: a caller able to change that decision would be a second
    /// policy.
    /// `forwarded` is how many frames the wakeup drained, which is what
    /// [`windows_for`] sizes this call against.
    pub fn advance<const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize, const FLOWS: usize>(
        &mut self,
        configuration: &Configuration<'_, MAX_INTERFACES, MAX_NEIGHBOURS>,
        tracking: &mut Tracking<'_, FLOWS>,
        forwarded: usize,
        mut observe: impl FnMut(&lfw_flow::LiveFlow),
    ) -> Option<Swept> {
        let mut cursor = self.cursor?;
        let mut swept = Swept {
            generation: self.generation,
            buckets: 0,
            examined: 0,
            revoked: 0,
            complete: false,
        };
        let occupied = tracking.table.occupancy().occupied() as usize;
        for _ in 0..windows_for(forwarded, occupied, FLOWS) {
            let revisited = tracking.table.revisit(cursor, |flow| {
                if admits_opening(configuration, &flow.opening).is_some() {
                    return lfw_flow::Disposition::Keep;
                }
                observe(flow);
                lfw_flow::Disposition::Revoke
            });
            swept.buckets = swept.buckets.saturating_add(revisited.buckets);
            swept.examined = swept.examined.saturating_add(revisited.examined);
            swept.revoked = swept.revoked.saturating_add(revisited.revoked);
            cursor = revisited.next;
            if revisited.complete {
                swept.complete = true;
                break;
            }
        }
        self.counters.buckets = self.counters.buckets.saturating_add(swept.buckets as u64);
        self.counters.examined = self.counters.examined.saturating_add(swept.examined as u64);
        if swept.complete {
            self.counters.completed = self.counters.completed.saturating_add(1);
            // A commit that landed mid-pass queued a walk of the whole table, and
            // this is where it begins: at the first bucket, under the generation
            // `arm` already moved to.
            self.cursor = self.deferred.then_some(0);
            self.deferred = false;
        } else {
            self.cursor = Some(cursor);
        }
        Some(swept)
    }
}

impl Default for PolicySweep {
    fn default() -> Self {
        Self::new()
    }
}

/// The chain, and the state it carries between frames.
///
/// One instance serves every direction of the dataplane, which is not an
/// economy: state that must see *both* directions of a flow — a connection
/// tracker above all — cannot live in a per-direction stage without becoming
/// two half-views that agree about nothing. So the pipeline is owned once, at
/// the level that owns both directions, and lent to each of them per poll.
pub struct Pipeline {
    admission: AdmissionStage,
    routing: RoutingStage,
    connection: ConnectionStage,
    policy: PolicyStage,
}

impl Pipeline {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            admission: AdmissionStage,
            routing: RoutingStage,
            connection: ConnectionStage,
            policy: PolicyStage::new(),
        }
    }

    /// What the filter has counted since this domain started.
    #[must_use]
    pub const fn policy_counters(&self) -> &PolicyCounters {
        self.policy.counters()
    }

    /// Run the chain over one frame and answer with the first stage's verdict
    /// that settles it.
    ///
    /// This body is the whole of the pipeline's order; a stage inserted
    /// anywhere else is not in the pipeline.
    ///
    /// [`ConnectionStage`] brackets the filter rather than preceding it, and
    /// both halves are here rather than inside [`PolicyStage`] so that the
    /// order is readable in one place: what the tracker settles, the filter
    /// never sees, and what the filter refuses, the tracker gives the slot back
    /// for.
    pub fn evaluate<
        const MAX_INTERFACES: usize,
        const MAX_NEIGHBOURS: usize,
        const FLOWS: usize,
    >(
        &mut self,
        inspection: &mut Inspection<'_>,
        configuration: &Configuration<'_, MAX_INTERFACES, MAX_NEIGHBOURS>,
        tracking: &mut Tracking<'_, FLOWS>,
    ) -> Verdict {
        if let Step::Settled(verdict) = self.admission.evaluate(inspection, configuration) {
            return verdict;
        }
        // Behind routing, because a rule names an egress and a flow the tracker
        // short-circuits is forwarded under the facts routing attached; in
        // front of the filter, because the filter must not be consulted for a
        // frame an existing flow already accounts for.
        if let Step::Settled(verdict) = self.routing.evaluate(inspection, configuration) {
            return verdict;
        }
        if let Step::Settled(verdict) = self.connection.classify(inspection, tracking) {
            return verdict;
        }
        let verdict = self.policy.evaluate(inspection, configuration);
        self.connection.settle(inspection, tracking, verdict);
        verdict
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
