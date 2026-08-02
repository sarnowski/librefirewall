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

use net_headers::{Frame, MacAddress};
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
}

impl DropReason {
    /// Every variant, so a counter table and a report can be built by iteration
    /// rather than by a list that drifts from the enum.
    pub const ALL: [Self; 11] = [
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
}

impl<'frame> Inspection<'frame> {
    #[must_use]
    pub const fn new(ingress: PortId, frame: Frame<'frame>) -> Self {
        Self { ingress, frame }
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
}

/// The tables one evaluation decides against, and the generation that produced
/// them: one value, because a count attributed to a table that did not produce
/// it is worse than an unattributed one. The pairing is made where the
/// configuration is held, and an evaluation takes it whole or not at all.
#[derive(Clone, Copy, Debug)]
pub struct Configuration<'table, const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize> {
    generation: u32,
    table: &'table Router<MAX_INTERFACES, MAX_NEIGHBOURS>,
}

impl<'table, const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize>
    Configuration<'table, MAX_INTERFACES, MAX_NEIGHBOURS>
{
    #[must_use]
    pub const fn new(
        generation: u32,
        table: &'table Router<MAX_INTERFACES, MAX_NEIGHBOURS>,
    ) -> Self {
        Self { generation, table }
    }

    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    #[must_use]
    pub const fn table(&self) -> &'table Router<MAX_INTERFACES, MAX_NEIGHBOURS> {
        self.table
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
/// Last in the chain, and so total — see the crate header on why it answers a
/// [`Verdict`] and not a [`Step`].
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
    ) -> Verdict {
        let table = configuration.table();
        let ingress = inspection.ingress();
        let header = inspection.frame().ipv4();

        let source = header.source;
        if !source.is_unicast() || table.is_local_address(source) {
            return Verdict::Drop(DropReason::MartianSource);
        }
        let destination = header.destination;
        if !destination.is_unicast() {
            return Verdict::Drop(DropReason::UnroutableDestination);
        }
        if table.is_local_address(destination) {
            return Verdict::Drop(DropReason::AddressedToThisRouter);
        }
        // Before the route lookup, so an expiring packet is reported as such
        // rather than as whatever the lookup happens to say about it.
        if header.ttl <= 1 {
            return Verdict::Drop(DropReason::TtlExpired);
        }

        let Some(egress) = table.route(destination) else {
            return Verdict::Drop(DropReason::NoRoute);
        };
        // Looked up across every interface and only then compared with the
        // ingress, so a longer prefix on the ingress port beats a shorter one
        // elsewhere and the frame is dropped rather than carried by it. The
        // longest match is the most specific statement about where the
        // destination lives; if that is the link it arrived on, the sender
        // should have addressed the host directly, and carrying it out of a
        // less specific route would put it on the wrong link.
        if egress.port == ingress {
            return Verdict::Drop(DropReason::EgressIsIngress);
        }
        let Some(neighbour) = table.neighbour(egress.port, destination) else {
            return Verdict::Drop(DropReason::NoNeighbour);
        };

        Verdict::Forward {
            egress: egress.port,
            source: egress.mac,
            destination: neighbour.mac,
        }
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
}

impl Pipeline {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            admission: AdmissionStage,
            routing: RoutingStage,
        }
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
        self.routing.evaluate(inspection, configuration)
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
