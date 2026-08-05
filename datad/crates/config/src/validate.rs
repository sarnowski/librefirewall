//! Whether a well-formed configuration is one this appliance can hold.
//!
//! A pure function of the model, run after parsing rather than inside it. The
//! separation is what makes the rules readable as rules: none of them can reach
//! for a byte offset or an attribute order, so none of them can accidentally
//! come to depend on how the document was written rather than on what it says.
//!
//! Every rule refuses a configuration that is *internally* inconsistent or that
//! this build cannot express. Three of them are wider than the documented
//! contract states: a neighbour's address and MAC are held to the same unicast
//! and host-address rules as an interface's, because a multicast next-hop MAC
//! and a next-hop that is a link's own broadcast address are exactly as
//! unforwardable as their interface counterparts, and the vocabulary already
//! had the tokens for all three.
//!
//! Every rule here is re-decided by [`wire::ConfigImage::check`]. Not
//! redundancy: this crate runs in the domain that parses the document, so a
//! rule only enforced here is one a compromised parser does not enforce.
//!
//! Which rules those are is not a matter for either side to remember. They are
//! named once, in [`wire::ConfigRule`], and [`model_enforcement`] below answers
//! for every one of them — exhaustively, so a rule added to that list does not
//! compile until this side has been told what it does about it, and the same is
//! true of the image side. What the compiler holds is the pairing; that each
//! answer is true of the code beneath it is held by the differential properties
//! that put arbitrary images and arbitrary documents through both sides.

use lfw_log::{Identifier, RejectReason};
use net_headers::{Ipv4Address, Protocol, prefix_mask};
use wire::{ConfigRule, Enforcement, MAX_PREFIX_LENGTH, RuleCriterion};

use crate::{
    PORT_COUNT,
    model::Model,
    rule::{AddressMatch, IcmpTypeMatch, InterfaceMatch, PortMatch, ProtocolMatch},
};

// The image ABI and the address arithmetic each state the bound independently —
// `wire` depends on no domain crate — so the two are held equal here, the one
// place that depends on both.
const _: () = assert!(MAX_PREFIX_LENGTH == net_headers::MAX_PREFIX_LENGTH);

/// What this side does about one rule.
///
/// Exhaustive over [`ConfigRule`], which is the point: a rule added to that
/// list does not compile until this side has said what it does about it.
#[must_use]
pub const fn model_enforcement(rule: ConfigRule) -> Enforcement {
    match rule {
        // A model holding more objects than the image has slots for does not
        // exist: the arrays are fixed and `push` refuses past the last one, so
        // the document is refused where it is read rather than here.
        ConfigRule::InterfaceCountWithinCapacity
        | ConfigRule::NeighbourCountWithinCapacity
        // Parsed into a `bool` and an `Identifier`, neither of which has a
        // representation that breaks the rule.
        | ConfigRule::InterfaceEnabledIsBoolean
        | ConfigRule::InterfaceIdIsWellFormed
        | ConfigRule::ManagementEnabledIsBoolean
        // Parsed into a two-armed enum: a document either writes an address or
        // writes `none`, and neither reading leaves a third byte to refuse.
        | ConfigRule::ManagementGatewayIsStatedOrNot
        // A neighbour names an interface, never a port: the port it ends up on
        // is the one that interface holds, and that one is already a port this
        // build has by `InterfacePortExists`.
        | ConfigRule::NeighbourPortExists
        // A model holding more rules than the image has slots for does not
        // exist, on `InterfaceCountWithinCapacity`'s terms; and an action and a
        // criterion are each parsed into an enum with no arm outside the rule.
        | ConfigRule::RuleCountWithinCapacity
        | ConfigRule::RuleIdIsWellFormed
        | ConfigRule::RuleActionIsKnown
        | ConfigRule::RuleCriterionIsStatedOrNot => Enforcement::Unrepresentable,

        ConfigRule::InterfacePortExists
        | ConfigRule::InterfacePrefixLengthInRange
        | ConfigRule::InterfaceMacIsUnicast
        | ConfigRule::InterfaceAddressIsUnicast
        | ConfigRule::InterfaceAddressIsAHostAddress
        | ConfigRule::InterfaceIdIsUnique
        | ConfigRule::InterfacePortIsUnique
        | ConfigRule::InterfaceMacIsUnique
        | ConfigRule::InterfacePrefixesDoNotOverlap
        | ConfigRule::NeighbourInterfaceResolves
        | ConfigRule::NeighbourMacIsUnicast
        | ConfigRule::NeighbourAddressIsUnicast
        | ConfigRule::NeighbourAddressIsAHostAddress
        | ConfigRule::NeighbourIsInsideItsPrefix
        | ConfigRule::NeighbourIsNotTheInterfaceAddress
        | ConfigRule::NeighbourAddressIsUnique
        | ConfigRule::NeighbourIdIsUnique
        // Held to unconditionally, including of a disabled entry: the model
        // carries the values beside the flag, so there is something to judge
        // even where the image would have nothing left to look at.
        | ConfigRule::ManagementPrefixLengthInRange
        | ConfigRule::ManagementMacIsUnicast
        | ConfigRule::ManagementAddressIsUnicast
        | ConfigRule::ManagementAddressIsAHostAddress
        | ConfigRule::ManagementPrefixDoesNotCollideWithInterface
        | ConfigRule::ManagementMacDoesNotCollideWithInterface
        | ConfigRule::ManagementGatewayIsUnicast
        | ConfigRule::ManagementGatewayIsOnLink
        | ConfigRule::ManagementGatewayIsNotTheAddress
        | ConfigRule::RuleIdIsUnique
        | ConfigRule::RuleIngressResolves
        | ConfigRule::RuleEgressResolves
        | ConfigRule::RulePrefixLengthInRange
        | ConfigRule::RulePrefixIsCanonical
        | ConfigRule::RulePortRangeIsOrdered
        | ConfigRule::RuleNoPortCriterionOnIcmp
        | ConfigRule::RuleNoIcmpTypeOnAnotherProtocol
        | ConfigRule::ConfigurationIsStatable => Enforcement::Refuses,
    }
}

// This side decides every rule there is. It is the side that reads the
// document, so a rule it could not decide would be one nothing decides before
// an operator is told their configuration was accepted — and unlike the image
// side, which is missing the neighbour's identity by construction, nothing here
// is missing anything. A rule that became undecidable here is therefore a
// compile error rather than a line in a table.
const _: () = {
    let mut index = 0;
    while index < ConfigRule::ALL.len() {
        assert!(!matches!(
            model_enforcement(ConfigRule::ALL[index]),
            Enforcement::CannotDecide
        ));
        index += 1;
    }
};

/// Why a configuration cannot be held.
///
/// Every variant names the object at fault by the id an operator gave it, which
/// is the only handle they have: there is no line number here by design, the
/// model having deliberately forgotten where anything was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticError {
    DuplicateInterfaceId {
        id: Identifier,
    },
    DuplicateNeighbourId {
        id: Identifier,
    },
    /// Two interfaces on one port, which would make the ingress port ambiguous.
    DuplicatePort {
        id: Identifier,
        other: Identifier,
        port: u8,
    },
    /// A port this build does not have; see [`PORT_COUNT`].
    PortOutOfRange {
        id: Identifier,
        port: u8,
    },
    PrefixLengthOutOfRange {
        id: Identifier,
        prefix_length: u8,
    },
    /// An address no host may hold: the prefix's network or broadcast address.
    InterfaceAddressNotAHostAddress {
        id: Identifier,
    },
    InterfaceAddressNotUnicast {
        id: Identifier,
    },
    InterfaceMacNotUnicast {
        id: Identifier,
    },
    /// Two interfaces whose prefixes cover a common address, which would make
    /// the egress for that address ambiguous.
    OverlappingPrefixes {
        id: Identifier,
        other: Identifier,
    },
    /// Two dataplane ports answering to one L2 address, on the grounds
    /// [`Self::ManagementMacCollidesWithInterface`] states.
    DuplicateInterfaceMac {
        id: Identifier,
        other: Identifier,
    },
    UnknownInterfaceReference {
        id: Identifier,
        interface: Identifier,
    },
    NeighbourAddressNotUnicast {
        id: Identifier,
    },
    NeighbourMacNotUnicast {
        id: Identifier,
    },
    /// A neighbour outside its own interface's prefix, which is not a neighbour
    /// of it.
    NeighbourOutsidePrefix {
        id: Identifier,
    },
    /// A neighbour holding the appliance's own address on that link.
    NeighbourIsInterfaceAddress {
        id: Identifier,
    },
    /// Forwarding to one would unicast a frame to a directed subnet broadcast.
    NeighbourAddressNotAHostAddress {
        id: Identifier,
    },
    DuplicateNeighbourAddress {
        id: Identifier,
        other: Identifier,
    },
    /// The management element's own rules, each naming it by
    /// [`Identifier::MANAGEMENT`]: it has no id of its own.
    ManagementPrefixLengthOutOfRange {
        prefix_length: u8,
    },
    ManagementAddressNotUnicast,
    ManagementAddressNotAHostAddress,
    ManagementMacNotUnicast,
    /// One address reachable two ways: routed out of `other`'s port, and
    /// terminated off the dataplane.
    ManagementPrefixCollidesWithInterface {
        other: Identifier,
    },
    /// Two ports answering to one L2 address: a frame would be taken by
    /// whichever saw it first.
    ManagementMacCollidesWithInterface {
        other: Identifier,
    },
    /// A gateway no frame may be addressed towards, on
    /// [`Self::ManagementAddressNotUnicast`]'s terms.
    ManagementGatewayNotUnicast,
    /// A gateway equal to the management port's own address, which would hand
    /// every off-prefix datagram back to this node.
    ManagementGatewayIsTheAddress,
    /// A gateway outside the management port's prefix, which no station on that
    /// link can answer for.
    ManagementGatewayNotOnLink,
    DuplicateRuleId {
        id: Identifier,
    },
    /// An `ingress` or `egress` naming an interface the configuration has not.
    UnknownRuleInterfaceReference {
        id: Identifier,
        criterion: RuleCriterion,
        interface: Identifier,
    },
    RulePrefixLengthOutOfRange {
        id: Identifier,
        criterion: RuleCriterion,
        prefix_length: u8,
    },
    /// A block written with host bits set, which covers what its network covers
    /// while reading as something narrower.
    RulePrefixNotCanonical {
        id: Identifier,
        criterion: RuleCriterion,
    },
    /// A range whose low port is above its high one, which matches nothing.
    RulePortRangeReversed {
        id: Identifier,
        criterion: RuleCriterion,
    },
    /// A port criterion on a rule that names ICMP.
    RulePortCriterionOnIcmp {
        id: Identifier,
        criterion: RuleCriterion,
    },
    /// An ICMP type on a rule that names another protocol.
    RuleIcmpTypeOnNonIcmp {
        id: Identifier,
    },
    /// The configuration is sound and its canonical form is longer than a
    /// document may be, so the appliance could not state back what it would be
    /// running. It names no object: the fault is the whole configuration's size
    /// rather than any one entry's, and the number an operator acts on is the
    /// length.
    RenderingTooLarge {
        len: usize,
    },
}

impl SemanticError {
    /// The object an operator must go and edit.
    #[must_use]
    pub const fn id(self) -> Identifier {
        match self {
            Self::DuplicateInterfaceId { id }
            | Self::DuplicateNeighbourId { id }
            | Self::DuplicatePort { id, .. }
            | Self::PortOutOfRange { id, .. }
            | Self::PrefixLengthOutOfRange { id, .. }
            | Self::InterfaceAddressNotAHostAddress { id }
            | Self::InterfaceAddressNotUnicast { id }
            | Self::InterfaceMacNotUnicast { id }
            | Self::OverlappingPrefixes { id, .. }
            | Self::UnknownInterfaceReference { id, .. }
            | Self::NeighbourAddressNotUnicast { id }
            | Self::NeighbourMacNotUnicast { id }
            | Self::NeighbourOutsidePrefix { id }
            | Self::NeighbourIsInterfaceAddress { id }
            | Self::NeighbourAddressNotAHostAddress { id }
            | Self::DuplicateInterfaceMac { id, .. }
            | Self::DuplicateNeighbourAddress { id, .. }
            | Self::DuplicateRuleId { id }
            | Self::UnknownRuleInterfaceReference { id, .. }
            | Self::RulePrefixLengthOutOfRange { id, .. }
            | Self::RulePrefixNotCanonical { id, .. }
            | Self::RulePortRangeReversed { id, .. }
            | Self::RulePortCriterionOnIcmp { id, .. }
            | Self::RuleIcmpTypeOnNonIcmp { id } => id,
            // The whole configuration rather than an object in it, which is the
            // one place this vocabulary has nothing narrower to name.
            Self::RenderingTooLarge { .. } => Identifier::CONFIGURATION,
            Self::ManagementPrefixLengthOutOfRange { .. }
            | Self::ManagementAddressNotUnicast
            | Self::ManagementAddressNotAHostAddress
            | Self::ManagementMacNotUnicast
            | Self::ManagementPrefixCollidesWithInterface { .. }
            | Self::ManagementMacCollidesWithInterface { .. }
            | Self::ManagementGatewayNotUnicast
            | Self::ManagementGatewayIsTheAddress
            | Self::ManagementGatewayNotOnLink => Identifier::MANAGEMENT,
        }
    }

    #[must_use]
    pub const fn reason(self) -> RejectReason {
        match self {
            Self::DuplicateInterfaceId { .. }
            | Self::DuplicateNeighbourId { .. }
            | Self::DuplicateRuleId { .. } => RejectReason::DuplicateIdentifier,
            Self::DuplicatePort { .. } => RejectReason::DuplicatePort,
            Self::PortOutOfRange { .. } => RejectReason::PortOutOfRange,
            Self::PrefixLengthOutOfRange { .. } | Self::RulePrefixLengthOutOfRange { .. } => {
                RejectReason::PrefixLengthOutOfRange
            }
            Self::RulePrefixNotCanonical { .. } => RejectReason::PrefixNotCanonical,
            Self::RulePortRangeReversed { .. } => RejectReason::PortRangeReversed,
            Self::RulePortCriterionOnIcmp { .. } => RejectReason::PortCriterionOnIcmp,
            Self::RuleIcmpTypeOnNonIcmp { .. } => RejectReason::IcmpTypeOnNonIcmp,
            Self::InterfaceAddressNotAHostAddress { .. }
            | Self::NeighbourAddressNotAHostAddress { .. } => RejectReason::AddressNotAHostAddress,
            Self::InterfaceAddressNotUnicast { .. } | Self::NeighbourAddressNotUnicast { .. } => {
                RejectReason::AddressNotUnicast
            }
            Self::InterfaceMacNotUnicast { .. }
            | Self::NeighbourMacNotUnicast { .. }
            | Self::DuplicateInterfaceMac { .. } => RejectReason::MacNotUnicast,
            Self::OverlappingPrefixes { .. } => RejectReason::OverlappingPrefixes,
            Self::UnknownInterfaceReference { .. } | Self::UnknownRuleInterfaceReference { .. } => {
                RejectReason::UnknownInterfaceReference
            }
            Self::NeighbourOutsidePrefix { .. } => RejectReason::NeighbourOutsidePrefix,
            Self::NeighbourIsInterfaceAddress { .. } => RejectReason::NeighbourIsInterfaceAddress,
            Self::DuplicateNeighbourAddress { .. } => RejectReason::DuplicateNeighbourAddress,
            Self::ManagementPrefixLengthOutOfRange { .. } => RejectReason::PrefixLengthOutOfRange,
            Self::ManagementAddressNotUnicast => RejectReason::AddressNotUnicast,
            Self::ManagementAddressNotAHostAddress => RejectReason::AddressNotAHostAddress,
            Self::ManagementMacNotUnicast | Self::ManagementMacCollidesWithInterface { .. } => {
                RejectReason::MacNotUnicast
            }
            Self::ManagementPrefixCollidesWithInterface { .. } => RejectReason::OverlappingPrefixes,
            // The vocabulary already had the word for an address no frame may
            // be addressed towards, and a gateway is one; the other two are
            // about a gateway's relationship to its port and have no older
            // token that would point at the right edit.
            Self::ManagementGatewayNotUnicast => RejectReason::AddressNotUnicast,
            Self::ManagementGatewayIsTheAddress => RejectReason::GatewayIsTheLocalAddress,
            Self::ManagementGatewayNotOnLink => RejectReason::GatewayNotOnLink,
            Self::RenderingTooLarge { .. } => RejectReason::RenderingTooLarge,
        }
    }
}

/// Hold a parsed configuration to every rule, refusing at the first one broken.
///
/// First rather than all of them: there is no console to page through a list
/// on, and a configuration with two faults is refused either way.
///
/// # Errors
/// [`SemanticError`], naming the rule and the object that broke it.
pub fn validate(model: &Model) -> Result<(), SemanticError> {
    interface_identities(model)?;
    interface_fields(model)?;
    interface_topology(model)?;
    neighbour_identities(model)?;
    neighbour_fields(model)?;
    neighbour_addresses(model)?;
    management(model)?;
    rule_identities(model)?;
    rules(model)?;
    // Last, because it is the one rule about the configuration as a whole and
    // every rule above names something to go and fix: a document with a dangling
    // reference *and* an unstateable policy is worth reporting as the reference.
    statable(model)?;
    Ok(())
}

/// The appliance must be able to state back what it is running.
///
/// A configuration whose canonical form outgrows the document bound would commit
/// and then answer a read with a document no submission may carry, which breaks
/// the read/edit/submit loop the read exists for. It is refused here rather than
/// at the read, because a refusal an operator receives while submitting names
/// something they can still change.
fn statable(model: &Model) -> Result<(), SemanticError> {
    let len = crate::render::rendered_len(model);
    if len > crate::MAX_DOCUMENT_BYTES {
        return Err(SemanticError::RenderingTooLarge { len });
    }
    Ok(())
}

fn rule_identities(model: &Model) -> Result<(), SemanticError> {
    for (index, entry) in model.rules().enumerate() {
        if model
            .rules()
            .take(index)
            .any(|earlier| earlier.id == entry.id)
        {
            return Err(SemanticError::DuplicateRuleId { id: entry.id });
        }
    }
    Ok(())
}

/// Every rule's criteria, in the order the document writes them, then the two
/// that hold criteria to each other.
///
/// The last two are what stops a rule matching nothing while reading as though
/// it matched something: ICMP carries no ports and nothing else carries an ICMP
/// type, so either combination is a policy line an operator believes is in
/// force. On a default-deny appliance that belief is the dangerous half — the
/// rule they wrote to *allow* traffic is the one silently matching nothing.
fn rules(model: &Model) -> Result<(), SemanticError> {
    for entry in model.rules() {
        let id = entry.id;
        for (criterion, interface) in [
            (RuleCriterion::Ingress, entry.ingress),
            (RuleCriterion::Egress, entry.egress),
        ] {
            if let InterfaceMatch::Named(named) = interface
                && model.interface(named).is_none()
            {
                return Err(SemanticError::UnknownRuleInterfaceReference {
                    id,
                    criterion,
                    interface: named,
                });
            }
        }
        for (criterion, address) in [
            (RuleCriterion::Source, entry.source),
            (RuleCriterion::Destination, entry.destination),
        ] {
            let AddressMatch::Block {
                network,
                prefix_length,
            } = address
            else {
                continue;
            };
            if prefix_length > MAX_PREFIX_LENGTH {
                return Err(SemanticError::RulePrefixLengthOutOfRange {
                    id,
                    criterion,
                    prefix_length,
                });
            }
            if network.bits() & !prefix_mask(prefix_length) != 0 {
                return Err(SemanticError::RulePrefixNotCanonical { id, criterion });
            }
        }
        let ports = [
            (RuleCriterion::SourcePort, entry.source_port),
            (RuleCriterion::DestinationPort, entry.destination_port),
        ];
        for (criterion, port) in ports {
            if let PortMatch::Range { low, high } = port
                && low > high
            {
                return Err(SemanticError::RulePortRangeReversed { id, criterion });
            }
        }
        if entry.protocol == ProtocolMatch::Only(Protocol::ICMP) {
            for (criterion, port) in ports {
                if port != PortMatch::Any {
                    return Err(SemanticError::RulePortCriterionOnIcmp { id, criterion });
                }
            }
        }
        if entry.icmp_type != IcmpTypeMatch::Any
            && let ProtocolMatch::Only(protocol) = entry.protocol
            && protocol != Protocol::ICMP
        {
            return Err(SemanticError::RuleIcmpTypeOnNonIcmp { id });
        }
    }
    Ok(())
}

/// The management interface's own rules, then the two that hold it apart from
/// the dataplane: neither a shared prefix nor a shared MAC is representable in
/// the capability grants, so a document may not describe one.
fn management(model: &Model) -> Result<(), SemanticError> {
    let Some(entry) = model.management() else {
        return Ok(());
    };
    if entry.prefix_length > MAX_PREFIX_LENGTH {
        return Err(SemanticError::ManagementPrefixLengthOutOfRange {
            prefix_length: entry.prefix_length,
        });
    }
    if !entry.mac.is_unicast() {
        return Err(SemanticError::ManagementMacNotUnicast);
    }
    if !entry.address.is_unicast() {
        return Err(SemanticError::ManagementAddressNotUnicast);
    }
    if !is_host_address(entry.address, entry.prefix_length) {
        return Err(SemanticError::ManagementAddressNotAHostAddress);
    }
    for interface in model.interfaces() {
        if overlaps(
            interface.address,
            interface.prefix_length,
            entry.address,
            entry.prefix_length,
        ) {
            return Err(SemanticError::ManagementPrefixCollidesWithInterface {
                other: interface.id,
            });
        }
        if interface.mac == entry.mac {
            return Err(SemanticError::ManagementMacCollidesWithInterface {
                other: interface.id,
            });
        }
    }
    // Last, because every rule about a gateway is a rule about its
    // relationship to the address above: judging one against an address that
    // is not yet known to be a host address on a legal prefix would report the
    // gateway for a fault the address has.
    //
    // The route decision judges the same three again where it composes a frame,
    // and the duplication is deliberate — this is the early refusal, naming the
    // attribute an operator edits while they are still editing it, not the only
    // check standing between a bad gateway and a frame.
    if let Some(gateway) = entry.gateway.stated() {
        if !gateway.is_unicast() {
            return Err(SemanticError::ManagementGatewayNotUnicast);
        }
        if gateway == entry.address {
            return Err(SemanticError::ManagementGatewayIsTheAddress);
        }
        if !gateway.shares_prefix(entry.address, entry.prefix_length) {
            return Err(SemanticError::ManagementGatewayNotOnLink);
        }
    }
    Ok(())
}

fn interface_identities(model: &Model) -> Result<(), SemanticError> {
    for (index, entry) in model.interfaces().enumerate() {
        if model
            .interfaces()
            .take(index)
            .any(|earlier| earlier.id == entry.id)
        {
            return Err(SemanticError::DuplicateInterfaceId { id: entry.id });
        }
    }
    Ok(())
}

fn interface_fields(model: &Model) -> Result<(), SemanticError> {
    for entry in model.interfaces() {
        let id = entry.id;
        if entry.port >= PORT_COUNT {
            return Err(SemanticError::PortOutOfRange {
                id,
                port: entry.port,
            });
        }
        if entry.prefix_length > MAX_PREFIX_LENGTH {
            return Err(SemanticError::PrefixLengthOutOfRange {
                id,
                prefix_length: entry.prefix_length,
            });
        }
        if !entry.mac.is_unicast() {
            return Err(SemanticError::InterfaceMacNotUnicast { id });
        }
        if !entry.address.is_unicast() {
            return Err(SemanticError::InterfaceAddressNotUnicast { id });
        }
        if !is_host_address(entry.address, entry.prefix_length) {
            return Err(SemanticError::InterfaceAddressNotAHostAddress { id });
        }
    }
    Ok(())
}

fn interface_topology(model: &Model) -> Result<(), SemanticError> {
    for (index, entry) in model.interfaces().enumerate() {
        for earlier in model.interfaces().take(index) {
            if earlier.port == entry.port {
                return Err(SemanticError::DuplicatePort {
                    id: entry.id,
                    other: earlier.id,
                    port: entry.port,
                });
            }
            if earlier.mac == entry.mac {
                return Err(SemanticError::DuplicateInterfaceMac {
                    id: entry.id,
                    other: earlier.id,
                });
            }
            if overlaps(
                earlier.address,
                earlier.prefix_length,
                entry.address,
                entry.prefix_length,
            ) {
                return Err(SemanticError::OverlappingPrefixes {
                    id: entry.id,
                    other: earlier.id,
                });
            }
        }
    }
    Ok(())
}

fn neighbour_identities(model: &Model) -> Result<(), SemanticError> {
    for (index, entry) in model.neighbours().enumerate() {
        if model
            .neighbours()
            .take(index)
            .any(|earlier| earlier.id == entry.id)
        {
            return Err(SemanticError::DuplicateNeighbourId { id: entry.id });
        }
    }
    Ok(())
}

fn neighbour_fields(model: &Model) -> Result<(), SemanticError> {
    for entry in model.neighbours() {
        let id = entry.id;
        let Some(interface) = model.interface(entry.interface) else {
            return Err(SemanticError::UnknownInterfaceReference {
                id,
                interface: entry.interface,
            });
        };
        if !entry.mac.is_unicast() {
            return Err(SemanticError::NeighbourMacNotUnicast { id });
        }
        if !entry.address.is_unicast() {
            return Err(SemanticError::NeighbourAddressNotUnicast { id });
        }
        if entry.address == interface.address {
            return Err(SemanticError::NeighbourIsInterfaceAddress { id });
        }
        let mask = prefix_mask(interface.prefix_length);
        if entry.address.bits() & mask != interface.address.bits() & mask {
            return Err(SemanticError::NeighbourOutsidePrefix { id });
        }
        if !is_host_address(entry.address, interface.prefix_length) {
            return Err(SemanticError::NeighbourAddressNotAHostAddress { id });
        }
    }
    Ok(())
}

fn neighbour_addresses(model: &Model) -> Result<(), SemanticError> {
    for (index, entry) in model.neighbours().enumerate() {
        for earlier in model.neighbours().take(index) {
            if earlier.interface == entry.interface && earlier.address == entry.address {
                return Err(SemanticError::DuplicateNeighbourAddress {
                    id: entry.id,
                    other: earlier.id,
                });
            }
        }
    }
    Ok(())
}

/// A `/31` is a two-address point-to-point link and a `/32` is a host route, so
/// neither reserves a network or a broadcast address to exclude (RFC 3021).
fn is_host_address(address: Ipv4Address, prefix_length: u8) -> bool {
    if prefix_length >= MAX_PREFIX_LENGTH.saturating_sub(1) {
        return true;
    }
    let mask = prefix_mask(prefix_length);
    let network = address.bits() & mask;
    address.bits() != network && address.bits() != (network | !mask)
}

/// Whether two prefixes cover a common address, which is decided entirely by
/// the shorter of the two: if the longer prefix's network falls inside the
/// shorter one, every address the longer covers the shorter covers too.
fn overlaps(left: Ipv4Address, left_len: u8, right: Ipv4Address, right_len: u8) -> bool {
    let mask = prefix_mask(left_len.min(right_len));
    left.bits() & mask == right.bits() & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{InterfaceEntry, ManagementEntry, NeighbourEntry, RuleEntry};
    use crate::gateway::Gateway;
    use crate::rule::RuleAction;
    use net_headers::MacAddress;
    use proptest::prelude::*;

    fn id(text: &str) -> Identifier {
        Identifier::new(text.as_bytes()).expect("the test uses the identifier alphabet")
    }

    /// A configuration that passes every rule. Each test below breaks exactly
    /// one field of it, so what a test proves is that *that* change is caught.
    fn sound() -> Model {
        let mut model = Model::EMPTY;
        model
            .push_interface(InterfaceEntry {
                id: id("wan"),
                port: 0,
                enabled: true,
                mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]),
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
                prefix_length: 24,
            })
            .expect("capacity");
        model
            .push_interface(InterfaceEntry {
                id: id("lan"),
                port: 1,
                enabled: true,
                mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x51]),
                address: Ipv4Address::from_octets([10, 0, 1, 1]),
                prefix_length: 24,
            })
            .expect("capacity");
        model
            .push_neighbour(NeighbourEntry {
                id: id("gateway-a"),
                interface: id("wan"),
                address: Ipv4Address::from_octets([10, 0, 0, 2]),
                mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0a]),
            })
            .expect("capacity");
        model
            .push_neighbour(NeighbourEntry {
                id: id("host-b"),
                interface: id("lan"),
                address: Ipv4Address::from_octets([10, 0, 1, 2]),
                mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0b]),
            })
            .expect("capacity");
        model
            .push_rule(RuleEntry {
                id: id("allow-all"),
                ingress: InterfaceMatch::Any,
                egress: InterfaceMatch::Any,
                source: AddressMatch::Any,
                destination: AddressMatch::Any,
                protocol: ProtocolMatch::Any,
                source_port: PortMatch::Any,
                destination_port: PortMatch::Any,
                icmp_type: IcmpTypeMatch::Any,
                tracking: crate::rule::TrackingMatch::Any,
                action: crate::rule::RuleAction::Accept,
            })
            .expect("capacity");
        model
            .set_management(ManagementEntry {
                enabled: true,
                mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x52]),
                address: Ipv4Address::from_octets([192, 168, 42, 15]),
                prefix_length: 24,
                gateway: Gateway::Stated(Ipv4Address::from_octets([192, 168, 42, 1])),
            })
            .expect("one");
        model
    }

    /// The management entry `sound()` carries, on a prefix neither interface
    /// claims.
    fn management_entry() -> ManagementEntry {
        ManagementEntry {
            enabled: true,
            mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x52]),
            address: Ipv4Address::from_octets([192, 168, 42, 15]),
            prefix_length: 24,
            gateway: Gateway::Stated(Ipv4Address::from_octets([192, 168, 42, 1])),
        }
    }

    /// `sound()` with its management entry replaced by `entry`.
    fn with_management(entry: ManagementEntry) -> Model {
        let mut model = Model::EMPTY;
        for interface in sound().interfaces() {
            model.push_interface(*interface).expect("capacity");
        }
        model.set_management(entry).expect("one");
        model
    }

    /// `sound()` with its second interface replaced by `entry`.
    fn with_interface(entry: InterfaceEntry) -> Model {
        let mut model = Model::EMPTY;
        let first = *sound().interfaces().next().expect("the first interface");
        model.push_interface(first).expect("capacity");
        model.push_interface(entry).expect("capacity");
        model
    }

    /// `sound()`'s interfaces with a single neighbour, `entry`.
    fn with_neighbour(entry: NeighbourEntry) -> Model {
        let mut model = Model::EMPTY;
        for interface in sound().interfaces() {
            model.push_interface(*interface).expect("capacity");
        }
        model.push_neighbour(entry).expect("capacity");
        model
    }

    fn second_interface() -> InterfaceEntry {
        *sound().interfaces().nth(1).expect("the second interface")
    }

    fn first_neighbour() -> NeighbourEntry {
        *sound().neighbours().next().expect("the first neighbour")
    }

    fn refusal(model: &Model) -> SemanticError {
        validate(model).expect_err("expected exactly one rule to refuse this configuration")
    }

    #[test]
    fn a_sound_configuration_and_an_empty_one_are_both_accepted() {
        validate(&sound()).expect("every rule holds");
        validate(&Model::EMPTY).expect("the fail-closed configuration breaks no rule");
    }

    #[test]
    fn a_duplicate_interface_id_is_refused_and_names_it() {
        let mut duplicate = second_interface();
        duplicate.id = id("wan");
        let error = refusal(&with_interface(duplicate));
        assert_eq!(error, SemanticError::DuplicateInterfaceId { id: id("wan") });
        assert_eq!(error.id(), id("wan"));
        assert_eq!(error.reason(), RejectReason::DuplicateIdentifier);
    }

    #[test]
    fn a_duplicate_neighbour_id_is_refused_and_names_it() {
        let mut model = sound();
        let mut duplicate = first_neighbour();
        duplicate.address = Ipv4Address::from_octets([10, 0, 0, 3]);
        model.push_neighbour(duplicate).expect("capacity");
        let error = refusal(&model);
        assert_eq!(
            error,
            SemanticError::DuplicateNeighbourId {
                id: id("gateway-a")
            }
        );
        assert_eq!(error.reason(), RejectReason::DuplicateIdentifier);
    }

    #[test]
    fn two_interfaces_on_one_port_are_refused_and_both_named() {
        let mut clash = second_interface();
        clash.port = 0;
        let error = refusal(&with_interface(clash));
        assert_eq!(
            error,
            SemanticError::DuplicatePort {
                id: id("lan"),
                other: id("wan"),
                port: 0,
            }
        );
        assert_eq!(error.reason(), RejectReason::DuplicatePort);
    }

    #[test]
    fn a_port_this_build_does_not_have_is_refused() {
        let mut absent = second_interface();
        absent.port = PORT_COUNT;
        let error = refusal(&with_interface(absent));
        assert_eq!(
            error,
            SemanticError::PortOutOfRange {
                id: id("lan"),
                port: PORT_COUNT,
            }
        );
        assert_eq!(error.reason(), RejectReason::PortOutOfRange);
    }

    #[test]
    fn a_prefix_length_past_thirty_two_is_refused_and_thirty_two_itself_is_not() {
        let mut too_long = second_interface();
        too_long.prefix_length = MAX_PREFIX_LENGTH + 1;
        let error = refusal(&with_interface(too_long));
        assert_eq!(
            error,
            SemanticError::PrefixLengthOutOfRange {
                id: id("lan"),
                prefix_length: 33,
            }
        );
        assert_eq!(error.reason(), RejectReason::PrefixLengthOutOfRange);

        let mut host_route = second_interface();
        host_route.prefix_length = MAX_PREFIX_LENGTH;
        validate(&with_interface(host_route)).expect("a /32 is a host route, not a fault");
    }

    #[test]
    fn an_interface_holding_its_own_network_or_broadcast_address_is_refused() {
        for octets in [[10, 0, 1, 0], [10, 0, 1, 255]] {
            let mut reserved = second_interface();
            reserved.address = Ipv4Address::from_octets(octets);
            let error = refusal(&with_interface(reserved));
            assert_eq!(
                error,
                SemanticError::InterfaceAddressNotAHostAddress { id: id("lan") },
                "{octets:?}"
            );
            assert_eq!(error.reason(), RejectReason::AddressNotAHostAddress);
        }
    }

    #[test]
    fn a_point_to_point_link_reserves_no_addresses_to_exclude() {
        for (prefix_length, octets) in [(31u8, [10, 0, 1, 0]), (32, [10, 0, 1, 255])] {
            let mut entry = second_interface();
            entry.prefix_length = prefix_length;
            entry.address = Ipv4Address::from_octets(octets);
            validate(&with_interface(entry)).expect("RFC 3021 leaves both usable");
        }
    }

    #[test]
    fn an_interface_address_that_is_not_unicast_is_refused() {
        for octets in [
            [224, 0, 0, 1],
            [127, 0, 0, 1],
            [0, 0, 0, 0],
            [255, 255, 255, 255],
        ] {
            let mut wrong = second_interface();
            wrong.address = Ipv4Address::from_octets(octets);
            let error = refusal(&with_interface(wrong));
            assert_eq!(
                error,
                SemanticError::InterfaceAddressNotUnicast { id: id("lan") },
                "{octets:?}"
            );
            assert_eq!(error.reason(), RejectReason::AddressNotUnicast);
        }
    }

    #[test]
    fn an_interface_mac_that_is_multicast_or_all_zero_is_refused() {
        for octets in [[0x01, 0, 0, 0, 0, 1], [0xff; 6], [0; 6]] {
            let mut wrong = second_interface();
            wrong.mac = MacAddress(octets);
            let error = refusal(&with_interface(wrong));
            assert_eq!(
                error,
                SemanticError::InterfaceMacNotUnicast { id: id("lan") },
                "{octets:?}"
            );
            assert_eq!(error.reason(), RejectReason::MacNotUnicast);
        }
    }

    #[test]
    fn two_interfaces_whose_prefixes_overlap_are_refused() {
        let mut overlapping = second_interface();
        overlapping.address = Ipv4Address::from_octets([10, 0, 0, 9]);
        let error = refusal(&with_interface(overlapping));
        assert_eq!(
            error,
            SemanticError::OverlappingPrefixes {
                id: id("lan"),
                other: id("wan"),
            }
        );
        assert_eq!(error.reason(), RejectReason::OverlappingPrefixes);

        // The containment case: a shorter prefix swallowing a longer one is an
        // overlap even though neither address is in the other's block.
        let mut wider = second_interface();
        wider.address = Ipv4Address::from_octets([10, 128, 0, 1]);
        wider.prefix_length = 8;
        assert_eq!(
            refusal(&with_interface(wider)),
            SemanticError::OverlappingPrefixes {
                id: id("lan"),
                other: id("wan"),
            }
        );
    }

    /// Two dataplane ports under one L2 address, refused on the grounds the
    /// management/interface collision is: a frame would be taken by whichever
    /// saw it first, and the two ports are guaranteed different by
    /// [`SemanticError::DuplicatePort`].
    #[test]
    fn two_interfaces_answering_to_one_mac_are_refused_and_both_named() {
        let mut clash = second_interface();
        clash.mac = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]);
        let error = refusal(&with_interface(clash));
        assert_eq!(
            error,
            SemanticError::DuplicateInterfaceMac {
                id: id("lan"),
                other: id("wan"),
            }
        );
        assert_eq!(error.id(), id("lan"));
        assert_eq!(error.reason(), RejectReason::MacNotUnicast);
    }

    /// A neighbour at its link's network or broadcast address: `is_unicast`
    /// admits both, and forwarding to one would unicast a frame to a directed
    /// subnet broadcast address.
    #[test]
    fn a_neighbour_at_its_links_network_or_broadcast_address_is_refused() {
        for octets in [[10, 0, 0, 255], [10, 0, 0, 0]] {
            let mut reserved = first_neighbour();
            reserved.address = Ipv4Address::from_octets(octets);
            let error = refusal(&with_neighbour(reserved));
            assert_eq!(
                error,
                SemanticError::NeighbourAddressNotAHostAddress {
                    id: id("gateway-a")
                },
                "{octets:?}"
            );
            assert_eq!(error.reason(), RejectReason::AddressNotAHostAddress);
        }
    }

    /// The same two addresses on a point-to-point link, where RFC 3021 reserves
    /// neither: the rule is about what the prefix excludes, not about the
    /// octets.
    #[test]
    fn a_neighbour_on_a_point_to_point_link_may_hold_either_address() {
        let mut model = Model::EMPTY;
        model
            .push_interface(InterfaceEntry {
                id: id("wan"),
                port: 0,
                enabled: true,
                mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]),
                address: Ipv4Address::from_octets([10, 0, 0, 0]),
                prefix_length: 31,
            })
            .expect("capacity");
        model
            .push_neighbour(NeighbourEntry {
                id: id("gateway-a"),
                interface: id("wan"),
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
                mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0a]),
            })
            .expect("capacity");
        validate(&model).expect("RFC 3021 leaves both usable");
    }

    #[test]
    fn a_neighbour_naming_an_unknown_interface_is_refused() {
        let mut dangling = first_neighbour();
        dangling.interface = id("dmz");
        let error = refusal(&with_neighbour(dangling));
        assert_eq!(
            error,
            SemanticError::UnknownInterfaceReference {
                id: id("gateway-a"),
                interface: id("dmz"),
            }
        );
        assert_eq!(error.reason(), RejectReason::UnknownInterfaceReference);
    }

    #[test]
    fn a_neighbour_outside_its_interfaces_prefix_is_refused() {
        let mut elsewhere = first_neighbour();
        elsewhere.address = Ipv4Address::from_octets([10, 9, 9, 9]);
        let error = refusal(&with_neighbour(elsewhere));
        assert_eq!(
            error,
            SemanticError::NeighbourOutsidePrefix {
                id: id("gateway-a")
            }
        );
        assert_eq!(error.reason(), RejectReason::NeighbourOutsidePrefix);
    }

    #[test]
    fn a_neighbour_holding_the_interfaces_own_address_is_refused() {
        let mut ourselves = first_neighbour();
        ourselves.address = Ipv4Address::from_octets([10, 0, 0, 1]);
        let error = refusal(&with_neighbour(ourselves));
        assert_eq!(
            error,
            SemanticError::NeighbourIsInterfaceAddress {
                id: id("gateway-a")
            }
        );
        assert_eq!(error.reason(), RejectReason::NeighbourIsInterfaceAddress);
    }

    #[test]
    fn two_neighbours_at_one_address_on_one_interface_are_refused() {
        let mut model = sound();
        let mut clash = first_neighbour();
        clash.id = id("gateway-b");
        model.push_neighbour(clash).expect("capacity");
        let error = refusal(&model);
        assert_eq!(
            error,
            SemanticError::DuplicateNeighbourAddress {
                id: id("gateway-b"),
                other: id("gateway-a"),
            }
        );
        assert_eq!(error.reason(), RejectReason::DuplicateNeighbourAddress);
    }

    #[test]
    fn one_address_on_two_different_interfaces_is_not_a_duplicate() {
        // The rule is per interface: the same host number on two separate links
        // is two hosts, and only the prefixes overlapping would make it one.
        let mut model = sound();
        let mut second = first_neighbour();
        second.id = id("mirror");
        second.interface = id("lan");
        second.address = Ipv4Address::from_octets([10, 0, 1, 2]);
        model.push_neighbour(second).expect("capacity");
        assert_eq!(
            refusal(&model),
            SemanticError::DuplicateNeighbourAddress {
                id: id("mirror"),
                other: id("host-b"),
            },
            "the sound configuration already holds 10.0.1.2 on lan"
        );
    }

    #[test]
    fn a_neighbour_address_or_mac_that_is_not_unicast_is_refused() {
        let mut broadcast = first_neighbour();
        broadcast.address = Ipv4Address::from_octets([255, 255, 255, 255]);
        let error = refusal(&with_neighbour(broadcast));
        assert_eq!(
            error,
            SemanticError::NeighbourAddressNotUnicast {
                id: id("gateway-a")
            }
        );
        assert_eq!(error.reason(), RejectReason::AddressNotUnicast);

        let mut group = first_neighbour();
        group.mac = MacAddress::BROADCAST;
        let error = refusal(&with_neighbour(group));
        assert_eq!(
            error,
            SemanticError::NeighbourMacNotUnicast {
                id: id("gateway-a")
            }
        );
        assert_eq!(error.reason(), RejectReason::MacNotUnicast);
    }

    #[test]
    fn a_management_interface_that_cannot_be_answered_under_is_refused_by_its_own_rule() {
        let cases: [(ManagementEntry, SemanticError, RejectReason); 6] = [
            (
                ManagementEntry {
                    prefix_length: MAX_PREFIX_LENGTH + 1,
                    ..management_entry()
                },
                SemanticError::ManagementPrefixLengthOutOfRange { prefix_length: 33 },
                RejectReason::PrefixLengthOutOfRange,
            ),
            (
                ManagementEntry {
                    mac: MacAddress::BROADCAST,
                    ..management_entry()
                },
                SemanticError::ManagementMacNotUnicast,
                RejectReason::MacNotUnicast,
            ),
            (
                ManagementEntry {
                    address: Ipv4Address::from_octets([224, 0, 0, 1]),
                    ..management_entry()
                },
                SemanticError::ManagementAddressNotUnicast,
                RejectReason::AddressNotUnicast,
            ),
            (
                ManagementEntry {
                    address: Ipv4Address::from_octets([192, 168, 42, 0]),
                    ..management_entry()
                },
                SemanticError::ManagementAddressNotAHostAddress,
                RejectReason::AddressNotAHostAddress,
            ),
            (
                // Inside `wan`'s prefix: one address the appliance would both
                // route towards and terminate on.
                ManagementEntry {
                    address: Ipv4Address::from_octets([10, 0, 0, 9]),
                    ..management_entry()
                },
                SemanticError::ManagementPrefixCollidesWithInterface { other: id("wan") },
                RejectReason::OverlappingPrefixes,
            ),
            (
                ManagementEntry {
                    mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]),
                    ..management_entry()
                },
                SemanticError::ManagementMacCollidesWithInterface { other: id("wan") },
                RejectReason::MacNotUnicast,
            ),
        ];
        for (entry, expected, reason) in cases {
            let error = refusal(&with_management(entry));
            assert_eq!(error, expected);
            assert_eq!(error.id(), Identifier::MANAGEMENT);
            assert_eq!(error.reason(), reason);
        }
    }

    /// The gateway's three, each one about the gateway's relationship to the
    /// port that would use it rather than about the address on its own.
    #[test]
    fn a_gateway_the_management_port_could_not_reach_is_refused_by_its_own_rule() {
        // Stating none is the other legal answer, not a lesser one.
        validate(&with_management(ManagementEntry {
            gateway: Gateway::None,
            ..management_entry()
        }))
        .expect("a port that reaches only its own link");

        let cases: [(Ipv4Address, SemanticError, RejectReason); 5] = [
            (
                Ipv4Address::from_octets([224, 0, 0, 1]),
                SemanticError::ManagementGatewayNotUnicast,
                RejectReason::AddressNotUnicast,
            ),
            (
                Ipv4Address::from_octets([255, 255, 255, 255]),
                SemanticError::ManagementGatewayNotUnicast,
                RejectReason::AddressNotUnicast,
            ),
            (
                // The port's own address: every off-prefix datagram would come
                // straight back to this node.
                Ipv4Address::from_octets([192, 168, 42, 15]),
                SemanticError::ManagementGatewayIsTheAddress,
                RejectReason::GatewayIsTheLocalAddress,
            ),
            (
                Ipv4Address::from_octets([192, 168, 43, 1]),
                SemanticError::ManagementGatewayNotOnLink,
                RejectReason::GatewayNotOnLink,
            ),
            (
                // On a dataplane interface's link, which is no better: this
                // port cannot reach that one.
                Ipv4Address::from_octets([10, 0, 0, 1]),
                SemanticError::ManagementGatewayNotOnLink,
                RejectReason::GatewayNotOnLink,
            ),
        ];
        for (gateway, expected, reason) in cases {
            let error = refusal(&with_management(ManagementEntry {
                gateway: Gateway::Stated(gateway),
                ..management_entry()
            }));
            assert_eq!(error, expected, "{gateway}");
            assert_eq!(error.id(), Identifier::MANAGEMENT);
            assert_eq!(error.reason(), reason);
        }
    }

    /// A disabled management interface is held to every one of those rules: the
    /// port is unaddressed today and the document is what an operator will
    /// enable tomorrow, so a collision refused only when enabled is a collision
    /// discovered at the worst moment.
    #[test]
    fn a_disabled_management_interface_is_held_to_the_same_rules() {
        validate(&with_management(ManagementEntry {
            enabled: false,
            ..management_entry()
        }))
        .expect("a sound entry is sound either way");
        assert_eq!(
            refusal(&with_management(ManagementEntry {
                enabled: false,
                address: Ipv4Address::from_octets([10, 0, 1, 9]),
                ..management_entry()
            })),
            SemanticError::ManagementPrefixCollidesWithInterface { other: id("lan") }
        );
    }

    /// A configuration that describes no management port at all breaks no rule:
    /// generation 0 is one, and the schema is where a *document* is held to
    /// naming one.
    #[test]
    fn a_configuration_with_no_management_interface_breaks_no_rule() {
        let mut model = Model::EMPTY;
        for interface in sound().interfaces() {
            model.push_interface(*interface).expect("capacity");
        }
        assert_eq!(model.management(), None);
        validate(&model).expect("nothing to hold to a rule");
    }

    #[test]
    fn every_variant_names_the_object_it_refuses() {
        let one = id("one");
        let two = id("two");
        let variants = [
            SemanticError::DuplicateInterfaceId { id: one },
            SemanticError::DuplicateNeighbourId { id: one },
            SemanticError::DuplicatePort {
                id: one,
                other: two,
                port: 0,
            },
            SemanticError::PortOutOfRange { id: one, port: 9 },
            SemanticError::PrefixLengthOutOfRange {
                id: one,
                prefix_length: 33,
            },
            SemanticError::InterfaceAddressNotAHostAddress { id: one },
            SemanticError::InterfaceAddressNotUnicast { id: one },
            SemanticError::InterfaceMacNotUnicast { id: one },
            SemanticError::OverlappingPrefixes {
                id: one,
                other: two,
            },
            SemanticError::UnknownInterfaceReference {
                id: one,
                interface: two,
            },
            SemanticError::NeighbourAddressNotUnicast { id: one },
            SemanticError::NeighbourMacNotUnicast { id: one },
            SemanticError::NeighbourOutsidePrefix { id: one },
            SemanticError::NeighbourIsInterfaceAddress { id: one },
            SemanticError::NeighbourAddressNotAHostAddress { id: one },
            SemanticError::DuplicateInterfaceMac {
                id: one,
                other: two,
            },
            SemanticError::DuplicateNeighbourAddress {
                id: one,
                other: two,
            },
        ];
        for variant in variants {
            assert_eq!(variant.id(), one, "{variant:?}");
        }
        // The management variants carry no id of their own and name the element
        // by the key a change record uses.
        for variant in [
            SemanticError::ManagementPrefixLengthOutOfRange { prefix_length: 33 },
            SemanticError::ManagementAddressNotUnicast,
            SemanticError::ManagementAddressNotAHostAddress,
            SemanticError::ManagementMacNotUnicast,
            SemanticError::ManagementPrefixCollidesWithInterface { other: two },
            SemanticError::ManagementMacCollidesWithInterface { other: two },
            SemanticError::ManagementGatewayNotUnicast,
            SemanticError::ManagementGatewayIsTheAddress,
            SemanticError::ManagementGatewayNotOnLink,
        ] {
            assert_eq!(variant.id(), Identifier::MANAGEMENT, "{variant:?}");
            assert!(RejectReason::ALL.contains(&variant.reason()), "{variant:?}");
        }
    }

    /// A configuration that breaks exactly one rule, or `None` where the rule
    /// cannot be broken in a model at all.
    ///
    /// Exhaustive over [`ConfigRule`], which is what makes this the third thing
    /// a new rule has to be told to: the list, the two enforcement answers, and
    /// a configuration that actually breaks it. A rule can then be declared
    /// enforced only where something demonstrably refuses one that breaks it.
    fn breaking(rule: ConfigRule) -> Option<Model> {
        let first = *sound().interfaces().next().expect("the first interface");
        let mut second = second_interface();
        let mut neighbour = sound_neighbour();
        let mut management = management_entry();
        let mut filter = sound_rule();
        let model = match rule {
            // No model expresses these: the arrays are fixed, `enabled` is a
            // `bool`, an id is an `Identifier`, and a neighbour names an
            // interface rather than a port.
            ConfigRule::InterfaceCountWithinCapacity
            | ConfigRule::NeighbourCountWithinCapacity
            | ConfigRule::InterfaceEnabledIsBoolean
            | ConfigRule::InterfaceIdIsWellFormed
            | ConfigRule::ManagementEnabledIsBoolean
            | ConfigRule::ManagementGatewayIsStatedOrNot
            | ConfigRule::NeighbourPortExists => return None,

            ConfigRule::InterfacePortExists => {
                second.port = PORT_COUNT;
                with_interface(second)
            }
            ConfigRule::InterfacePrefixLengthInRange => {
                second.prefix_length = MAX_PREFIX_LENGTH + 1;
                with_interface(second)
            }
            ConfigRule::InterfaceMacIsUnicast => {
                second.mac = MacAddress([0x01, 0, 0, 0, 0, 1]);
                with_interface(second)
            }
            ConfigRule::InterfaceAddressIsUnicast => {
                second.address = Ipv4Address::from_octets([224, 0, 0, 1]);
                with_interface(second)
            }
            ConfigRule::InterfaceAddressIsAHostAddress => {
                second.address = Ipv4Address::from_octets([10, 0, 1, 255]);
                with_interface(second)
            }
            ConfigRule::InterfaceIdIsUnique => {
                second.id = first.id;
                with_interface(second)
            }
            ConfigRule::InterfacePortIsUnique => {
                second.port = first.port;
                with_interface(second)
            }
            ConfigRule::InterfaceMacIsUnique => {
                second.mac = first.mac;
                with_interface(second)
            }
            ConfigRule::InterfacePrefixesDoNotOverlap => {
                second.address = Ipv4Address::from_octets([10, 0, 0, 2]);
                with_interface(second)
            }

            ConfigRule::NeighbourInterfaceResolves => {
                neighbour.interface = id("nowhere");
                with_neighbour(neighbour)
            }
            ConfigRule::NeighbourMacIsUnicast => {
                neighbour.mac = MacAddress([0x01, 0, 0, 0, 0, 1]);
                with_neighbour(neighbour)
            }
            ConfigRule::NeighbourAddressIsUnicast => {
                neighbour.address = Ipv4Address::from_octets([224, 0, 0, 1]);
                with_neighbour(neighbour)
            }
            ConfigRule::NeighbourAddressIsAHostAddress => {
                neighbour.address = Ipv4Address::from_octets([10, 0, 0, 255]);
                with_neighbour(neighbour)
            }
            ConfigRule::NeighbourIsInsideItsPrefix => {
                neighbour.address = Ipv4Address::from_octets([10, 0, 5, 2]);
                with_neighbour(neighbour)
            }
            ConfigRule::NeighbourIsNotTheInterfaceAddress => {
                neighbour.address = first.address;
                with_neighbour(neighbour)
            }
            // The pair that needs two of them: one repeating the other's
            // address, and one repeating the other's id.
            ConfigRule::NeighbourAddressIsUnique | ConfigRule::NeighbourIdIsUnique => {
                let mut twin = neighbour;
                if rule == ConfigRule::NeighbourAddressIsUnique {
                    twin.id = id("twin");
                } else {
                    twin.address = Ipv4Address::from_octets([10, 0, 0, 3]);
                }
                let mut model = with_neighbour(neighbour);
                model.push_neighbour(twin).expect("capacity");
                model
            }

            ConfigRule::ManagementPrefixLengthInRange => {
                management.prefix_length = MAX_PREFIX_LENGTH + 1;
                with_management(management)
            }
            ConfigRule::ManagementMacIsUnicast => {
                management.mac = MacAddress([0x01, 0, 0, 0, 0, 1]);
                with_management(management)
            }
            ConfigRule::ManagementAddressIsUnicast => {
                management.address = Ipv4Address::from_octets([224, 0, 0, 1]);
                with_management(management)
            }
            ConfigRule::ManagementAddressIsAHostAddress => {
                management.address = Ipv4Address::from_octets([192, 168, 42, 255]);
                with_management(management)
            }
            ConfigRule::ManagementPrefixDoesNotCollideWithInterface => {
                management.address = first.address;
                with_management(management)
            }
            ConfigRule::ManagementGatewayIsUnicast => {
                management.gateway = Gateway::Stated(Ipv4Address::from_octets([224, 0, 0, 1]));
                with_management(management)
            }
            ConfigRule::ManagementGatewayIsOnLink => {
                management.gateway = Gateway::Stated(Ipv4Address::from_octets([10, 9, 9, 1]));
                with_management(management)
            }
            ConfigRule::ManagementGatewayIsNotTheAddress => {
                management.gateway = Gateway::Stated(management.address);
                with_management(management)
            }
            ConfigRule::ManagementMacDoesNotCollideWithInterface => {
                management.mac = first.mac;
                with_management(management)
            }

            // No model expresses these: the rules array is fixed and `push`
            // refuses past the last one, an id is an `Identifier`, an action is
            // an enum with two arms, and a criterion is an enum whose wildcard
            // is an arm rather than a byte.
            ConfigRule::RuleCountWithinCapacity
            | ConfigRule::RuleIdIsWellFormed
            | ConfigRule::RuleActionIsKnown
            | ConfigRule::RuleCriterionIsStatedOrNot => return None,

            ConfigRule::RuleIdIsUnique => {
                let mut twin = filter;
                twin.action = crate::rule::RuleAction::Drop;
                let mut model = with_rule(filter);
                model.push_rule(twin).expect("capacity");
                model
            }
            ConfigRule::RuleIngressResolves => {
                filter.ingress = InterfaceMatch::Named(id("nowhere"));
                with_rule(filter)
            }
            ConfigRule::RuleEgressResolves => {
                filter.egress = InterfaceMatch::Named(id("nowhere"));
                with_rule(filter)
            }
            ConfigRule::RulePrefixLengthInRange => {
                filter.source = AddressMatch::Block {
                    network: Ipv4Address::from_octets([10, 0, 0, 0]),
                    prefix_length: MAX_PREFIX_LENGTH + 1,
                };
                with_rule(filter)
            }
            ConfigRule::RulePrefixIsCanonical => {
                filter.destination = AddressMatch::Block {
                    network: Ipv4Address::from_octets([10, 0, 0, 5]),
                    prefix_length: 24,
                };
                with_rule(filter)
            }
            ConfigRule::RulePortRangeIsOrdered => {
                filter.source_port = PortMatch::Range {
                    low: 1024,
                    high: 100,
                };
                with_rule(filter)
            }
            ConfigRule::RuleNoPortCriterionOnIcmp => {
                filter.protocol = ProtocolMatch::Only(Protocol::ICMP);
                filter.destination_port = PortMatch::Range { low: 80, high: 80 };
                with_rule(filter)
            }
            ConfigRule::RuleNoIcmpTypeOnAnotherProtocol => {
                filter.protocol = ProtocolMatch::Only(Protocol::TCP);
                filter.icmp_type = IcmpTypeMatch::Only(8);
                with_rule(filter)
            }
            // A policy whose canonical form outgrows the document bound: the widest
            // rule the schema admits, repeated until it does. Built by growing
            // rather than at a chosen count, so the fixture follows the renderer
            // instead of being a number that goes stale the first time a criterion
            // is added to a rule.
            ConfigRule::ConfigurationIsStatable => unstateable(),
        };
        Some(model)
    }

    /// A sixteen-byte identifier — [`lfw_log::MAX_IDENTIFIER_LEN`], the widest the
    /// schema admits — distinguished by `index`.
    fn widest_id(stem: u8, index: usize) -> Identifier {
        let mut bytes = [stem; 16];
        for (cell, digit) in bytes
            .iter_mut()
            .rev()
            .zip(std::format!("{index:04}").bytes().rev())
        {
            *cell = digit;
        }
        Identifier::new(&bytes).expect("the alphabet accepts it")
    }

    /// A configuration the appliance could not state back: every object at its
    /// widest, and the widest rule the schema admits repeated until the canonical
    /// form outgrows the document bound.
    ///
    /// **Grown rather than counted.** What makes this reachable at all is that the
    /// canonical form is *longer* than the shortest document describing the same
    /// configuration — it indents, it writes a declaration, and it spells
    /// `protocol="6"` as `tcp` — so the fixture follows the renderer instead of
    /// being a count that goes stale the first time a criterion is added to a rule.
    fn unstateable() -> Model {
        let mut model = Model::EMPTY;
        for port in 0..PORT_COUNT {
            model
                .push_interface(InterfaceEntry {
                    id: widest_id(b'i', usize::from(port)),
                    port,
                    enabled: true,
                    mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50 + port]),
                    address: Ipv4Address::from_octets([10, 0, port, 1]),
                    prefix_length: 24,
                })
                .expect("capacity");
        }
        for index in 0..wire::MAX_NEIGHBOURS {
            let host = 2u8.saturating_add(index as u8);
            if model
                .push_neighbour(NeighbourEntry {
                    id: widest_id(b'n', index),
                    interface: widest_id(b'i', 0),
                    address: Ipv4Address::from_octets([10, 0, 0, host]),
                    mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, host]),
                })
                .is_err()
            {
                break;
            }
        }
        model
            .set_management(ManagementEntry {
                enabled: true,
                prefix_length: 24,
                mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x5f]),
                address: Ipv4Address::from_octets([192, 168, 42, 15]),
                gateway: Gateway::Stated(Ipv4Address::from_octets([192, 168, 42, 1])),
            })
            .expect("the first");
        loop {
            let mut candidate = model;
            let widest = RuleEntry {
                id: widest_id(b'r', candidate.rule_count()),
                ingress: InterfaceMatch::Named(widest_id(b'i', 0)),
                egress: InterfaceMatch::Named(widest_id(b'i', 1)),
                source: AddressMatch::Block {
                    network: Ipv4Address::from_octets([255, 255, 255, 254]),
                    prefix_length: 31,
                },
                destination: AddressMatch::Block {
                    network: Ipv4Address::from_octets([255, 255, 255, 252]),
                    prefix_length: 30,
                },
                protocol: ProtocolMatch::Only(Protocol::TCP),
                source_port: PortMatch::Range {
                    low: 10_000,
                    high: 65_535,
                },
                destination_port: PortMatch::Range {
                    low: 10_000,
                    high: 65_535,
                },
                icmp_type: IcmpTypeMatch::Any,
                tracking: crate::rule::TrackingMatch::Any,
                action: RuleAction::Accept,
            };
            if candidate.push_rule(widest).is_err() {
                // Every slot filled and the canonical form still inside the bound
                // would make this rule unreachable, which is a finding rather than
                // a fixture that quietly stops: the test above reports it as a rule
                // declared refused whose configuration was accepted.
                break model;
            }
            if crate::render::rendered_len(&candidate) > crate::MAX_DOCUMENT_BYTES {
                break candidate;
            }
            model = candidate;
        }
    }

    /// The rule `sound()` carries: every criterion at its widest, accepting.
    fn sound_rule() -> RuleEntry {
        *sound().rules().next().expect("the first rule")
    }

    /// `sound()`'s interfaces with a single rule, `entry`.
    fn with_rule(entry: RuleEntry) -> Model {
        let mut model = Model::EMPTY;
        for interface in sound().interfaces() {
            model.push_interface(*interface).expect("capacity");
        }
        model.push_rule(entry).expect("capacity");
        model
    }

    /// The neighbour `sound()` carries, on the first interface's link.
    fn sound_neighbour() -> NeighbourEntry {
        *sound().neighbours().next().expect("the first neighbour")
    }

    /// Both sides do what they said they would, rule by rule.
    ///
    /// This is what stops [`model_enforcement`] and
    /// [`ConfigRule::image_enforcement`] being two tables nobody ever compared
    /// against the code: a rule declared enforced whose configuration is
    /// accepted fails here, and so does a rule declared undecidable that turns
    /// out to be decided.
    #[test]
    fn every_rule_is_enforced_exactly_where_both_sides_say_it_is() {
        for rule in ConfigRule::ALL {
            let Some(model) = breaking(rule) else {
                assert_eq!(
                    model_enforcement(rule),
                    Enforcement::Unrepresentable,
                    "{rule:?} has no configuration that breaks it, so nothing here enforces it"
                );
                continue;
            };
            assert_eq!(
                model_enforcement(rule),
                Enforcement::Refuses,
                "{rule:?} is declared otherwise but a model can break it"
            );
            assert!(
                validate(&model).is_err(),
                "{rule:?} is declared refused here and this configuration was accepted"
            );

            // The image side, from the very model the rules just refused: what
            // it does with it must be what it said it would.
            let image = crate::image_from(&model, crate::store::Generation::ZERO);
            let accepted = match image {
                // A neighbour naming no interface has no port to be written
                // into an image, so the refusal lands one step earlier.
                Err(_) => false,
                Ok(image) => image.check(PORT_COUNT).is_ok(),
            };
            match rule.image_enforcement() {
                Enforcement::Refuses => assert!(
                    !accepted,
                    "{rule:?} is declared re-decided by the image and the image accepted it"
                ),
                Enforcement::CannotDecide => assert!(
                    accepted,
                    "{rule:?} is declared undecidable by the image, which decided it anyway"
                ),
                // The configurations above all carry an enabled entry, so a
                // conditional rule is an unconditional one here.
                Enforcement::RefusesWhenEnabled => assert!(
                    !accepted,
                    "{rule:?} is declared refused of an enabled entry and the image accepted one"
                ),
                Enforcement::Unrepresentable => panic!("{rule:?} is expressible in an image"),
            }
        }
    }

    /// The conditional half of the management rules, which the table above
    /// cannot reach: disabled, the image has nothing left to judge and the
    /// model still does.
    #[test]
    fn a_disabled_management_entry_is_judged_by_the_model_and_not_by_the_image() {
        let mut entry = management_entry();
        entry.enabled = false;
        entry.mac = MacAddress([0x01, 0, 0, 0, 0, 1]);
        let model = with_management(entry);

        assert_eq!(
            validate(&model),
            Err(SemanticError::ManagementMacNotUnicast),
            "the model carries the values beside the flag, so it judges them"
        );
        let image = crate::image_from(&model, crate::store::Generation::ZERO)
            .expect("a model with no dangling reference builds");
        assert!(
            image.check(PORT_COUNT).is_ok(),
            "a disabled entry leaves the image nothing to judge"
        );
        assert_eq!(
            ConfigRule::ManagementMacIsUnicast.image_enforcement(),
            Enforcement::RefusesWhenEnabled
        );
    }

    proptest! {
        /// Total, and a function of the model alone: whatever a model holds,
        /// validation answers rather than panicking, and answers the same way
        /// twice.
        #[test]
        fn validation_is_total_and_deterministic(
            port in any::<u8>(),
            prefix_length in any::<u8>(),
            address in proptest::array::uniform4(any::<u8>()),
            mac in proptest::array::uniform6(any::<u8>()),
            neighbour in proptest::array::uniform4(any::<u8>()),
        ) {
            let mut model = Model::EMPTY;
            model
                .push_interface(InterfaceEntry {
                    id: id("wan"),
                    port,
                    enabled: true,
                    mac: MacAddress(mac),
                    address: Ipv4Address::from_octets(address),
                    prefix_length,
                })
                .expect("capacity");
            model
                .push_neighbour(NeighbourEntry {
                    id: id("gw"),
                    interface: id("wan"),
                    address: Ipv4Address::from_octets(neighbour),
                    mac: MacAddress(mac),
                })
                .expect("capacity");
            prop_assert_eq!(validate(&model), validate(&model));
        }

        /// An accepted configuration really does satisfy every rule the
        /// forwarder later assumes, stated independently of the order the
        /// checks run in.
        #[test]
        fn an_accepted_configuration_satisfies_every_rule(
            ports in proptest::collection::vec(0u8..4, 0..4),
            thirds in proptest::collection::vec(0u8..4, 0..4),
        ) {
            let mut model = Model::EMPTY;
            for (index, (port, third)) in ports.iter().zip(thirds.iter()).enumerate() {
                let name = std::format!("i{index}");
                model
                    .push_interface(InterfaceEntry {
                        id: id(&name),
                        port: *port,
                        enabled: true,
                        mac: MacAddress([0x52, 0x54, 0, 0, 0, index as u8]),
                        address: Ipv4Address::from_octets([10, 0, *third, 1]),
                        prefix_length: 24,
                    })
                    .expect("capacity");
            }
            if validate(&model).is_ok() {
                for entry in model.interfaces() {
                    prop_assert!(entry.port < PORT_COUNT);
                    prop_assert!(entry.prefix_length <= MAX_PREFIX_LENGTH);
                    prop_assert!(entry.mac.is_unicast());
                    prop_assert!(entry.address.is_unicast());
                }
                for (index, entry) in model.interfaces().enumerate() {
                    for earlier in model.interfaces().take(index) {
                        prop_assert_ne!(earlier.port, entry.port);
                        prop_assert!(!overlaps(
                            earlier.address,
                            earlier.prefix_length,
                            entry.address,
                            entry.prefix_length
                        ));
                    }
                }
            }
        }
    }
}
