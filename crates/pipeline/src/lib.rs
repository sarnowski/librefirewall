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
//! The chain is admission, then routing, then policy, and the middle one is the
//! reason for the order. [`RoutingStage`] does not settle a frame it can
//! forward: it resolves the egress port and the next hop and *attaches* them to
//! the [`Inspection`], deferring to what follows. So [`PolicyStage`] decides
//! with the egress in hand, which is what makes a rule able to name one — a
//! zone-to-zone policy is the ordinary case and it is unwritable if the filter
//! runs before the forwarding decision. The converse is the same fact: a packet
//! with no route has no egress for an egress rule to be about, so there is
//! nothing for policy to say about it and routing settles it first.
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

use net_headers::{Frame, Ipv4Address, MacAddress, Protocol, Transport};
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
    pub const ALL: [Self; 13] = [
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
        Self::PolicyDenied,
        Self::NoPolicyMatch,
    ];

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
/// costs a field here instead of a parameter on every stage's signature. Today
/// that is the ingress port and the parsed frame; a flow handle and a matched
/// rule are the next two, and neither changes a signature to arrive.
pub struct Inspection<'frame> {
    ingress: PortId,
    frame: Frame<'frame>,
    forwarding: Option<Forwarding>,
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
    pub action: RuleAction,
}

impl Rule {
    /// Whether this rule is about this frame.
    ///
    /// # A truncated transport matches no port and no type
    ///
    /// The port and type criteria are answered from [`Transport`], and every
    /// variant of it that carries no readable field answers `false` rather than
    /// being skipped: a stated criterion on a frame whose transport header was
    /// cut short, arrived as a non-initial fragment, or is a protocol this
    /// build does not break down, does not match. That is the direction that
    /// matters on a default-deny appliance — a rule cannot be *satisfied* by a
    /// header nobody read, so a truncated packet cannot be carried through an
    /// `accept` written for a port. It falls to the next rule, and past the
    /// last of them to the default deny.
    #[must_use]
    fn matches(&self, ingress: PortId, egress: PortId, frame: &Frame<'_>) -> bool {
        if self.ingress.is_some_and(|port| port != ingress)
            || self.egress.is_some_and(|port| port != egress)
        {
            return false;
        }
        let header = frame.ipv4();
        if self
            .source
            .is_some_and(|block| !block.covers(header.source))
            || self
                .destination
                .is_some_and(|block| !block.covers(header.destination))
        {
            return false;
        }
        if self
            .protocol
            .is_some_and(|protocol| protocol != header.protocol)
        {
            return false;
        }
        let transport = frame.transport();
        if self.source_port.is_some() || self.destination_port.is_some() {
            let Some((source, destination)) = transport_ports(transport) else {
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
        if let Some(wanted) = self.icmp_type {
            let Transport::Icmp(icmp) = transport else {
                return false;
            };
            if icmp.message_type != wanted {
                return false;
            }
        }
        true
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
    fn first_match(
        &self,
        ingress: PortId,
        egress: PortId,
        frame: &Frame<'_>,
    ) -> Option<(usize, Rule)> {
        self.rules
            .iter()
            .take(self.len)
            .flatten()
            .enumerate()
            .find(|(_, rule)| rule.matches(ingress, egress, frame))
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
        let matched = configuration.rules().first_match(
            inspection.ingress(),
            forwarding.egress,
            inspection.frame(),
        );
        match matched {
            Some((position, rule)) => {
                self.counters.record(Some(position), rule.action, bytes);
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
    policy: PolicyStage,
}

impl Pipeline {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            admission: AdmissionStage,
            routing: RoutingStage,
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
    /// anywhere else is not in the pipeline. It takes `&mut self` though no
    /// stage yet holds state, because the stage that will — the connection
    /// tracker — must not change this signature to arrive.
    pub fn evaluate<const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize>(
        &mut self,
        inspection: &mut Inspection<'_>,
        configuration: &Configuration<'_, MAX_INTERFACES, MAX_NEIGHBOURS>,
    ) -> Verdict {
        if let Step::Settled(verdict) = self.admission.evaluate(inspection, configuration) {
            return verdict;
        }
        // A connection-tracking stage goes here, between the forwarding
        // decision and the filter: it needs the egress the one above attaches,
        // and the filter must not be consulted for a frame an established flow
        // already accounts for.
        if let Step::Settled(verdict) = self.routing.evaluate(inspection, configuration) {
            return verdict;
        }
        self.policy.evaluate(inspection, configuration)
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
