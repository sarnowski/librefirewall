//! Whether a well-formed configuration is one this appliance can hold.
//!
//! A pure function of the model, run after parsing rather than inside it. The
//! separation is what makes the rules readable as rules: none of them can reach
//! for a byte offset or an attribute order, so none of them can accidentally
//! come to depend on how the document was written rather than on what it says.
//!
//! Every rule refuses a configuration that is *internally* inconsistent or that
//! this build cannot express. Two of them are wider than CONTRACTS.md §4c
//! states: a neighbour's address and MAC are held to the same unicast rules as
//! an interface's, because a multicast next-hop MAC and a broadcast next-hop
//! address are exactly as unforwardable as their interface counterparts, and
//! the vocabulary already had the tokens for both.

use lfw_log::{Identifier, RejectReason};
use net_headers::{Ipv4Address, prefix_mask};
use wire::MAX_PREFIX_LENGTH;

use crate::{PORT_COUNT, model::Model};

// The image ABI and the address arithmetic each state the bound independently —
// `wire` depends on no domain crate — so the two are held equal here, the one
// place that depends on both.
const _: () = assert!(MAX_PREFIX_LENGTH == net_headers::MAX_PREFIX_LENGTH);

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
    /// terminated off the dataplane (CONCEPT §9.1).
    ManagementPrefixCollidesWithInterface {
        other: Identifier,
    },
    /// Two ports answering to one L2 address: a frame would be taken by
    /// whichever saw it first.
    ManagementMacCollidesWithInterface {
        other: Identifier,
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
            | Self::DuplicateNeighbourAddress { id, .. } => id,
            Self::ManagementPrefixLengthOutOfRange { .. }
            | Self::ManagementAddressNotUnicast
            | Self::ManagementAddressNotAHostAddress
            | Self::ManagementMacNotUnicast
            | Self::ManagementPrefixCollidesWithInterface { .. }
            | Self::ManagementMacCollidesWithInterface { .. } => Identifier::MANAGEMENT,
        }
    }

    #[must_use]
    pub const fn reason(self) -> RejectReason {
        match self {
            Self::DuplicateInterfaceId { .. } | Self::DuplicateNeighbourId { .. } => {
                RejectReason::DuplicateIdentifier
            }
            Self::DuplicatePort { .. } => RejectReason::DuplicatePort,
            Self::PortOutOfRange { .. } => RejectReason::PortOutOfRange,
            Self::PrefixLengthOutOfRange { .. } => RejectReason::PrefixLengthOutOfRange,
            Self::InterfaceAddressNotAHostAddress { .. } => RejectReason::AddressNotAHostAddress,
            Self::InterfaceAddressNotUnicast { .. } | Self::NeighbourAddressNotUnicast { .. } => {
                RejectReason::AddressNotUnicast
            }
            Self::InterfaceMacNotUnicast { .. } | Self::NeighbourMacNotUnicast { .. } => {
                RejectReason::MacNotUnicast
            }
            Self::OverlappingPrefixes { .. } => RejectReason::OverlappingPrefixes,
            Self::UnknownInterfaceReference { .. } => RejectReason::UnknownInterfaceReference,
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
    Ok(())
}

/// The management interface's own rules, then the two that hold it apart from
/// the dataplane: neither a shared prefix nor a shared MAC is representable in
/// the grant set (CONCEPT §9.1), so a document may not describe one.
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
    use crate::model::{InterfaceEntry, ManagementEntry, NeighbourEntry};
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
            .set_management(ManagementEntry {
                enabled: true,
                mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x52]),
                address: Ipv4Address::from_octets([192, 168, 42, 15]),
                prefix_length: 24,
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
        ] {
            assert_eq!(variant.id(), Identifier::MANAGEMENT, "{variant:?}");
            assert!(RejectReason::ALL.contains(&variant.reason()), "{variant:?}");
        }
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
