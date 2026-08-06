use super::*;

use proptest::prelude::*;

const OURS: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 15]);
const GATEWAY: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 2]);

fn port(gateway: Option<Ipv4Address>) -> Port {
    Port {
        address: OURS,
        prefix_length: 24,
        gateway,
    }
}

fn address(octets: [u8; 4]) -> Ipv4Address {
    Ipv4Address::from_octets(octets)
}

#[test]
fn a_destination_on_this_link_is_reached_as_itself() {
    let station = address([10, 0, 2, 99]);
    // With a gateway configured and without: an on-link destination never
    // travels through one, which is the property that keeps a dial to a station
    // on this link from depending on a gateway being right.
    for gateway in [None, Some(GATEWAY)] {
        assert_eq!(
            next_hop(port(gateway), station),
            Ok(Hop {
                address: station,
                via: Via::Prefix
            })
        );
    }
}

#[test]
fn a_destination_off_this_link_is_reached_through_the_gateway() {
    let elsewhere = address([192, 168, 7, 4]);
    assert_eq!(
        next_hop(port(Some(GATEWAY)), elsewhere),
        Ok(Hop {
            address: GATEWAY,
            via: Via::Gateway
        })
    );
}

/// The two answers name themselves distinctly, because the name is what a
/// console line carries and a duplicate would collapse "reached on this link"
/// and "reached through the gateway" into one thing to go and look at.
#[test]
fn each_way_a_next_hop_is_chosen_names_itself_distinctly() {
    assert_ne!(Via::Prefix.name(), Via::Gateway.name());
    for via in [Via::Prefix, Via::Gateway] {
        assert_eq!(std::format!("{via}"), via.name());
        assert!(!via.name().is_empty());
    }
}

#[test]
fn a_destination_off_this_link_with_no_gateway_is_unroutable() {
    assert_eq!(
        next_hop(port(None), address([192, 168, 7, 4])),
        Err(RouteRefusal::Unroutable)
    );
}

/// The whole of what a next hop may not be, each refused under its own cause so
/// that a report says which one it was.
#[test]
fn a_destination_no_frame_may_be_addressed_towards_is_refused() {
    for destination in [
        address([224, 0, 0, 1]),
        address([255, 255, 255, 255]),
        address([0, 0, 0, 0]),
        address([127, 0, 0, 1]),
    ] {
        assert_eq!(
            next_hop(port(Some(GATEWAY)), destination),
            Err(RouteRefusal::DestinationNotUnicast),
            "{destination}"
        );
    }
}

#[test]
fn our_own_address_is_not_a_destination() {
    assert_eq!(
        next_hop(port(Some(GATEWAY)), OURS),
        Err(RouteRefusal::DestinationIsOurs)
    );
}

/// Each gateway refusal separately, and each only reachable through an off-link
/// destination: a gateway is not consulted at all for a destination on this
/// link, so a wrong one cannot break the link it is stated on.
#[test]
fn a_gateway_that_could_not_be_a_next_hop_is_refused_under_its_own_cause() {
    let elsewhere = address([192, 168, 7, 4]);
    for (gateway, refusal) in [
        (address([224, 0, 0, 1]), RouteRefusal::GatewayNotUnicast),
        (
            address([255, 255, 255, 255]),
            RouteRefusal::GatewayNotUnicast,
        ),
        (address([0, 0, 0, 0]), RouteRefusal::GatewayNotUnicast),
        (OURS, RouteRefusal::GatewayIsOurs),
        (address([10, 0, 9, 1]), RouteRefusal::GatewayOffLink),
    ] {
        assert_eq!(
            next_hop(port(Some(gateway)), elsewhere),
            Err(refusal),
            "{gateway}"
        );
    }
}

#[test]
fn a_prefix_length_no_address_can_be_judged_against_is_refused_rather_than_panicking() {
    for prefix_length in [33u8, 64, 255] {
        assert_eq!(
            next_hop(
                Port {
                    address: OURS,
                    prefix_length,
                    gateway: Some(GATEWAY),
                },
                address([10, 0, 2, 99]),
            ),
            Err(RouteRefusal::PrefixLengthOutOfRange)
        );
    }
}

/// A /32 port shares its prefix with nothing but itself, so every destination is
/// off-link — which is the one case where "on-link" and "our own address" would
/// answer the same question, and the second is the one that wins.
#[test]
fn a_host_prefix_reaches_everything_through_its_gateway_and_nothing_without_one() {
    let host = |gateway| Port {
        address: OURS,
        prefix_length: 32,
        gateway,
    };
    assert_eq!(
        next_hop(host(None), address([10, 0, 2, 99])),
        Err(RouteRefusal::Unroutable)
    );
    // And a gateway on a /32 is off-link by the same arithmetic, so the only
    // gateway such a port can state is refused. Stated as a test rather than
    // left implicit: it is what makes `/32` a port that reaches nothing.
    assert_eq!(
        next_hop(host(Some(GATEWAY)), address([10, 0, 2, 99])),
        Err(RouteRefusal::GatewayOffLink)
    );
}

/// A /0 port covers every address, so nothing is off-link and no gateway is ever
/// consulted.
#[test]
fn a_zero_prefix_reaches_everything_on_link() {
    let station = address([203, 0, 113, 9]);
    assert_eq!(
        next_hop(
            Port {
                address: OURS,
                prefix_length: 0,
                gateway: None,
            },
            station,
        ),
        Ok(Hop {
            address: station,
            via: Via::Prefix
        })
    );
}

proptest! {
    /// Total: every combination of a port and a destination yields a next hop or
    /// a typed refusal, and never a panic.
    #[test]
    fn deciding_a_route_is_total(
        address in any::<[u8; 4]>(),
        prefix_length in any::<u8>(),
        gateway in proptest::option::of(any::<[u8; 4]>()),
        destination in any::<[u8; 4]>(),
    ) {
        let _ = next_hop(
            Port {
                address: Ipv4Address::from_octets(address),
                prefix_length,
                gateway: gateway.map(Ipv4Address::from_octets),
            },
            Ipv4Address::from_octets(destination),
        );
    }

    /// The invariant the neighbour cache depends on: an address this decision
    /// hands back is always one a frame may be addressed towards, and never this
    /// port's own. Without it a resolution could be started for a group address,
    /// and one request would draw an answer from every station on the link.
    #[test]
    fn a_chosen_next_hop_is_always_a_unicast_station_that_is_not_ourselves(
        address in any::<[u8; 4]>(),
        prefix_length in 0u8..=32,
        gateway in proptest::option::of(any::<[u8; 4]>()),
        destination in any::<[u8; 4]>(),
    ) {
        let port = Port {
            address: Ipv4Address::from_octets(address),
            prefix_length,
            gateway: gateway.map(Ipv4Address::from_octets),
        };
        if let Ok(hop) = next_hop(port, Ipv4Address::from_octets(destination)) {
            prop_assert!(hop.address.is_unicast());
            prop_assert_ne!(hop.address, port.address);
        }
    }

    /// A next hop is always on the link the frame leaves by. On-link it is the
    /// destination, off-link it is the gateway, and both are inside the port's
    /// prefix — so nothing this decision produces is an address the neighbour
    /// cache would ask the wrong link about.
    #[test]
    fn a_chosen_next_hop_is_always_on_this_ports_own_link(
        address in any::<[u8; 4]>(),
        prefix_length in 0u8..=32,
        gateway in proptest::option::of(any::<[u8; 4]>()),
        destination in any::<[u8; 4]>(),
    ) {
        let port = Port {
            address: Ipv4Address::from_octets(address),
            prefix_length,
            gateway: gateway.map(Ipv4Address::from_octets),
        };
        if let Ok(hop) = next_hop(port, Ipv4Address::from_octets(destination)) {
            prop_assert!(hop.address.shares_prefix(port.address, prefix_length));
            // And the answer says which of the two chose it, which is the half
            // the address alone cannot carry: a gateway equal to the
            // destination reads exactly like an on-link destination.
            prop_assert_eq!(
                hop.via == Via::Prefix,
                Ipv4Address::from_octets(destination)
                    .shares_prefix(port.address, prefix_length)
            );
        }
    }

    /// A port with no gateway routes exactly its own link and nothing else,
    /// which is what makes a stated gateway the only way off it.
    #[test]
    fn a_port_with_no_gateway_reaches_only_its_own_link(
        prefix_length in 0u8..=32,
        destination in any::<[u8; 4]>(),
    ) {
        let port = Port {
            address: OURS,
            prefix_length,
            gateway: None,
        };
        let destination = Ipv4Address::from_octets(destination);
        match next_hop(port, destination) {
            Ok(hop) => {
                prop_assert_eq!(hop.address, destination);
                prop_assert_eq!(hop.via, Via::Prefix);
                prop_assert!(destination.shares_prefix(OURS, prefix_length));
            }
            Err(refusal) => prop_assert_ne!(refusal, RouteRefusal::GatewayOffLink),
        }
    }

    /// Deciding is a function of its inputs alone: it reads no clock, no
    /// counter and nothing outside the two values it is given.
    #[test]
    fn deciding_a_route_is_deterministic(
        prefix_length in 0u8..=32,
        gateway in proptest::option::of(any::<[u8; 4]>()),
        destination in any::<[u8; 4]>(),
    ) {
        let port = Port {
            address: OURS,
            prefix_length,
            gateway: gateway.map(Ipv4Address::from_octets),
        };
        let destination = Ipv4Address::from_octets(destination);
        prop_assert_eq!(next_hop(port, destination), next_hop(port, destination));
    }
}
