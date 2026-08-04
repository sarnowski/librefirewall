//! The forwarding table: the appliance's own presence on the subnets attached
//! to its ports, the neighbours it can resolve on them, and the lookups a
//! forwarding decision is built out of.
//!
//! Faces untrusted network traffic. Every address a lookup is asked
//! about was chosen by whatever is attached to a dataplane port, so every
//! lookup is total and answers in its return value.
//!
//! It answers questions and reaches no verdict: what to do with a frame belongs
//! to the crate that chains the stages, so nothing here names a refusal or
//! counts one, and the dependency runs one way.
//!
//! Routes are connected and neighbours configured: a destination is routable
//! exactly when some interface's prefix covers it, the next hop is then the
//! destination itself, and there is no discovery state because nothing here can
//! originate a frame to discover with.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use net_headers::{Ipv4Address, MacAddress};

/// Which dataplane port. The number is the index the system description gives
/// the port's driver instance, so it is the same identity the capability
/// topology uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortId(pub u8);

/// One routed interface: the appliance's own presence on a directly attached
/// subnet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interface {
    pub port: PortId,
    /// The MAC this port answers to, and the source MAC it forwards under.
    pub mac: MacAddress,
    pub address: Ipv4Address,
    /// Bits of `address` that form the network. `Ipv4Address::shares_prefix`
    /// saturates rather than rejecting, so every `u8` behaves.
    pub prefix_length: u8,
    /// Administratively up. A disabled interface is neither a valid ingress
    /// nor a selectable egress.
    pub enabled: bool,
}

impl Interface {
    /// What a slot past the configured length holds: disabled, and covering
    /// only an address no packet may be destined for.
    pub const UNUSED: Self = Self {
        port: PortId(0),
        mac: MacAddress([0; 6]),
        address: Ipv4Address::from_octets([0, 0, 0, 0]),
        prefix_length: 32,
        enabled: false,
    };

    #[must_use]
    pub const fn covers(&self, destination: Ipv4Address) -> bool {
        destination.shares_prefix(self.address, self.prefix_length)
    }
}

/// A statically configured link-layer address for a directly attached host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Neighbour {
    pub port: PortId,
    pub address: Ipv4Address,
    pub mac: MacAddress,
}

impl Neighbour {
    pub const UNUSED: Self = Self {
        port: PortId(0),
        address: Ipv4Address::from_octets([0, 0, 0, 0]),
        mac: MacAddress([0; 6]),
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityError {
    Interfaces { requested: usize, capacity: usize },
    Neighbours { requested: usize, capacity: usize },
}

/// The forwarding configuration: the appliance's interfaces and the neighbours
/// it can resolve.
///
/// The const parameters are capacities and the lengths are data, because the
/// configuration is data: a domain is handed one table and later handed
/// another, and what it must have room for is not what it currently holds.
/// Capacity stays a build-time number because there is no allocator to grow
/// one, and holding both in a plain value is what lets a domain keep a running
/// configuration beside a staged one and swap between them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Router<const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize> {
    interfaces: [Interface; MAX_INTERFACES],
    interface_count: usize,
    neighbours: [Neighbour; MAX_NEIGHBOURS],
    neighbour_count: usize,
}

impl<const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize>
    Router<MAX_INTERFACES, MAX_NEIGHBOURS>
{
    /// No interfaces and no neighbours, which forwards nothing: what a domain
    /// runs under before it is given a configuration, and after one is refused.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            interfaces: [Interface::UNUSED; MAX_INTERFACES],
            interface_count: 0,
            neighbours: [Neighbour::UNUSED; MAX_NEIGHBOURS],
            neighbour_count: 0,
        }
    }

    /// Build from tables whose lengths are known only at runtime.
    ///
    /// Refused rather than truncated: a table cut to fit is a configuration
    /// nobody wrote, and the traffic it silently stopped carrying would be
    /// attributable to nothing.
    pub fn from_slices(
        interfaces: &[Interface],
        neighbours: &[Neighbour],
    ) -> Result<Self, CapacityError> {
        if interfaces.len() > MAX_INTERFACES {
            return Err(CapacityError::Interfaces {
                requested: interfaces.len(),
                capacity: MAX_INTERFACES,
            });
        }
        if neighbours.len() > MAX_NEIGHBOURS {
            return Err(CapacityError::Neighbours {
                requested: neighbours.len(),
                capacity: MAX_NEIGHBOURS,
            });
        }
        let mut router = Self::empty();
        for (slot, entry) in router.interfaces.iter_mut().zip(interfaces) {
            *slot = *entry;
        }
        router.interface_count = interfaces.len();
        for (slot, entry) in router.neighbours.iter_mut().zip(neighbours) {
            *slot = *entry;
        }
        router.neighbour_count = neighbours.len();
        Ok(router)
    }

    /// The configured interfaces and nothing past them, bounded by `take`
    /// rather than by a range that could be asked to slice past the array.
    fn configured_interfaces(&self) -> impl Iterator<Item = &Interface> {
        self.interfaces.iter().take(self.interface_count)
    }

    #[must_use]
    pub fn interface(&self, port: PortId) -> Option<&Interface> {
        self.configured_interfaces()
            .find(|entry| entry.port == port)
    }

    /// The interface whose connected prefix covers `destination`: the longest
    /// prefix, and among equal-length prefixes the lowest port, then address,
    /// then MAC.
    ///
    /// Prefix length alone does not decide it — two enabled interfaces of equal
    /// length can both cover one destination — so the key continues over the
    /// fields a verdict is built from. That is a total order and table position
    /// is not in it, which is what makes any permutation of the same interfaces
    /// answer the same way. Which of two equal-length prefixes wins is
    /// arbitrary; that it is the same one every time is not.
    ///
    /// Two kinds of interface are not candidates, this being where an egress is
    /// chosen. A disabled one, because a route out of a link that is down is not
    /// a route. And one whose prefix length is zero, because its prefix covers
    /// every destination: selecting it would be a default route. Neither ceases
    /// to be an address the appliance holds, which [`Self::is_local_address`]
    /// still answers for; the narrowing is to route selection alone. Refusing
    /// such a table outright would be this crate rejecting a configuration the
    /// layer that validates one accepts, and it is that layer's rule to add.
    #[must_use]
    pub fn route(&self, destination: Ipv4Address) -> Option<&Interface> {
        self.configured_interfaces()
            .filter(|entry| entry.enabled && entry.prefix_length > 0 && entry.covers(destination))
            .min_by_key(|entry| {
                (
                    core::cmp::Reverse(entry.prefix_length),
                    entry.port,
                    entry.address,
                    entry.mac,
                )
            })
    }

    #[must_use]
    pub fn neighbour(&self, port: PortId, address: Ipv4Address) -> Option<&Neighbour> {
        self.neighbours
            .iter()
            .take(self.neighbour_count)
            .find(|entry| entry.port == port && entry.address == address)
    }

    /// Whether `address` is one the appliance itself holds — a disabled
    /// interface's too, since a down link does not make traffic aimed at the
    /// appliance something to forward onward.
    #[must_use]
    pub fn is_local_address(&self, address: Ipv4Address) -> bool {
        self.configured_interfaces()
            .any(|entry| entry.address == address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::vec::Vec;

    const PORT0: PortId = PortId(0);
    const PORT1: PortId = PortId(1);
    const GATEWAY0_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]);
    const GATEWAY1_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x51]);
    const HOST_A_MAC: MacAddress = MacAddress([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]);
    const HOST_B_MAC: MacAddress = MacAddress([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02]);

    fn host_a() -> Ipv4Address {
        Ipv4Address::from_octets([10, 0, 0, 2])
    }

    fn host_b() -> Ipv4Address {
        Ipv4Address::from_octets([10, 0, 1, 2])
    }

    fn interfaces() -> [Interface; 2] {
        [
            Interface {
                port: PORT0,
                mac: GATEWAY0_MAC,
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
                prefix_length: 24,
                enabled: true,
            },
            Interface {
                port: PORT1,
                mac: GATEWAY1_MAC,
                address: Ipv4Address::from_octets([10, 0, 1, 1]),
                prefix_length: 24,
                enabled: true,
            },
        ]
    }

    fn neighbours() -> [Neighbour; 2] {
        [
            Neighbour {
                port: PORT0,
                address: host_a(),
                mac: HOST_A_MAC,
            },
            Neighbour {
                port: PORT1,
                address: host_b(),
                mac: HOST_B_MAC,
            },
        ]
    }

    fn router() -> Router<2, 2> {
        Router::from_slices(&interfaces(), &neighbours()).expect("two of each fit in two")
    }

    #[test]
    fn a_configured_port_answers_with_its_own_interface_and_an_unconfigured_one_with_nothing() {
        let table = router();
        assert_eq!(table.interface(PORT0), Some(&interfaces()[0]));
        assert_eq!(table.interface(PORT1), Some(&interfaces()[1]));
        assert_eq!(table.interface(PortId(7)), None);
    }

    #[test]
    fn a_neighbour_is_held_per_port_rather_than_per_address() {
        let table = router();
        assert_eq!(table.neighbour(PORT1, host_b()), Some(&neighbours()[1]));
        assert_eq!(
            table.neighbour(PORT0, host_b()),
            None,
            "a neighbour answered on a port it was not configured on"
        );
        assert_eq!(
            table.neighbour(PORT1, Ipv4Address::from_octets([10, 0, 1, 77])),
            None
        );
    }

    #[test]
    fn every_configured_interface_address_is_the_appliances_own() {
        let table = router();
        assert!(table.is_local_address(Ipv4Address::from_octets([10, 0, 0, 1])));
        assert!(table.is_local_address(Ipv4Address::from_octets([10, 0, 1, 1])));
        assert!(!table.is_local_address(host_a()));
    }

    #[test]
    fn a_disabled_interfaces_address_is_still_the_appliances_own() {
        // A down link does not make traffic aimed at the appliance something to
        // forward onward, so the address survives the interface being disabled.
        let mut down = interfaces();
        down[1].enabled = false;
        let table = Router::<2, 2>::from_slices(&down, &neighbours()).expect("two fit in two");
        assert!(table.is_local_address(Ipv4Address::from_octets([10, 0, 1, 1])));
    }

    #[test]
    fn two_equal_length_covering_prefixes_choose_the_same_egress_in_either_order() {
        let low = Interface {
            port: PORT0,
            mac: GATEWAY0_MAC,
            address: Ipv4Address::from_octets([10, 0, 0, 0]),
            prefix_length: 8,
            enabled: true,
        };
        let high = Interface {
            port: PORT1,
            mac: GATEWAY1_MAC,
            address: Ipv4Address::from_octets([10, 0, 0, 0]),
            prefix_length: 8,
            enabled: true,
        };
        let target = Ipv4Address::from_octets([10, 0, 1, 2]);
        assert!(low.covers(target) && high.covers(target), "both must cover");

        let in_order = Router::<2, 0>::from_slices(&[low, high], &[]).expect("two fit in two");
        let reversed = Router::<2, 0>::from_slices(&[high, low], &[]).expect("two fit in two");
        assert_eq!(in_order.route(target), Some(&low));
        assert_eq!(
            reversed.route(target),
            Some(&low),
            "the egress followed the table position rather than the interfaces"
        );
    }

    #[test]
    fn an_interface_with_a_zero_prefix_length_is_never_a_route() {
        // A /0 covers every destination, so selecting it would be a default
        // route. It stays an address the appliance holds and an ingress it
        // receives on; what it never is, is an egress.
        let mut with_default = interfaces();
        with_default[1].prefix_length = 0;
        let table = Router::<2, 2>::from_slices(&with_default, &neighbours()).expect("two fit");

        let far = Ipv4Address::from_octets([203, 0, 113, 4]);
        assert!(
            with_default[1].covers(far),
            "the /0 must cover the destination, or this proves nothing"
        );
        assert_eq!(table.route(far), None, "a /0 became a default route");
        assert!(table.is_local_address(with_default[1].address));
        assert_eq!(
            table.interface(PORT1),
            Some(&with_default[1]),
            "a /0 interface must still be reachable as an ingress"
        );
    }

    #[test]
    fn a_port_with_no_interface_has_no_entry_and_no_neighbour() {
        let table = router();
        assert_eq!(table.interface(PortId(7)), None);
        assert_eq!(table.neighbour(PortId(7), host_a()), None);
    }

    #[test]
    fn the_longest_matching_prefix_wins_regardless_of_table_order() {
        let wide = Interface {
            port: PORT0,
            mac: GATEWAY0_MAC,
            address: Ipv4Address::from_octets([10, 0, 0, 0]),
            prefix_length: 8,
            enabled: true,
        };
        let narrow = Interface {
            port: PORT1,
            mac: GATEWAY1_MAC,
            address: Ipv4Address::from_octets([10, 0, 1, 0]),
            prefix_length: 24,
            enabled: true,
        };
        let target = Ipv4Address::from_octets([10, 0, 1, 2]);

        let in_order = Router::<2, 0>::from_slices(&[wide, narrow], &[]).expect("two fit in two");
        let reversed = Router::<2, 0>::from_slices(&[narrow, wide], &[]).expect("two fit in two");
        assert_eq!(in_order.route(target), Some(&narrow));
        assert_eq!(reversed.route(target), Some(&narrow));
    }

    #[test]
    fn a_configuration_naming_more_entries_than_the_capacity_is_refused() {
        let mut three = [interfaces()[0]; 3];
        three[1].port = PORT1;
        three[2].port = PortId(2);
        assert_eq!(
            Router::<2, 2>::from_slices(&three, &neighbours()),
            Err(CapacityError::Interfaces {
                requested: 3,
                capacity: 2,
            })
        );

        let five = [neighbours()[0]; 5];
        assert_eq!(
            Router::<2, 4>::from_slices(&interfaces(), &five),
            Err(CapacityError::Neighbours {
                requested: 5,
                capacity: 4,
            })
        );
    }

    #[test]
    fn a_disabled_interface_is_never_selected_as_an_egress() {
        let mut down = interfaces();
        down[1].enabled = false;
        let table = Router::<2, 2>::from_slices(&down, &neighbours()).expect("two fit in two");
        assert_eq!(table.route(host_b()), None);
    }

    #[test]
    fn an_empty_router_holds_no_address_and_resolves_nothing() {
        let table = Router::<8, 32>::empty();
        for port in [PORT0, PORT1, PortId(7), PortId(255)] {
            assert_eq!(table.interface(port), None);
        }
        assert_eq!(table.route(host_b()), None);
        assert_eq!(table.neighbour(PORT0, host_a()), None);
        assert!(!table.is_local_address(Ipv4Address::from_octets([10, 0, 0, 1])));
    }

    #[test]
    fn spare_capacity_resolves_as_an_exactly_sized_table_does() {
        let roomy = Router::<8, 32>::from_slices(&interfaces(), &neighbours())
            .expect("two of each fit in eight and thirty-two");
        let exact = router();
        for destination in [
            host_a(),
            host_b(),
            Ipv4Address::from_octets([192, 0, 2, 9]),
            Ipv4Address::from_octets([10, 0, 1, 77]),
        ] {
            assert_eq!(roomy.route(destination), exact.route(destination));
            assert_eq!(
                roomy.is_local_address(destination),
                exact.is_local_address(destination)
            );
            for port in [PORT0, PORT1] {
                assert_eq!(
                    roomy.neighbour(port, destination),
                    exact.neighbour(port, destination)
                );
            }
        }
    }

    /// An address out of a small space, so a generated neighbour and a
    /// generated destination coincide often enough for the resolving branch to
    /// be reached rather than merely declared reachable.
    fn any_address() -> impl Strategy<Value = Ipv4Address> {
        (0u8..4, 0u8..8).prop_map(|(subnet, host)| Ipv4Address::from_octets([10, 0, subnet, host]))
    }

    fn any_interface() -> impl Strategy<Value = Interface> {
        (
            0u8..4,
            any::<[u8; 6]>(),
            any_address(),
            0u8..=32,
            any::<bool>(),
        )
            .prop_map(|(port, mac, address, prefix_length, enabled)| Interface {
                port: PortId(port),
                mac: MacAddress(mac),
                address,
                prefix_length,
                enabled,
            })
    }

    fn any_neighbour() -> impl Strategy<Value = Neighbour> {
        (0u8..4, any_address(), any::<[u8; 6]>()).prop_map(|(port, address, mac)| Neighbour {
            port: PortId(port),
            address,
            mac: MacAddress(mac),
        })
    }

    /// A configuration a validator would accept: one interface per port, which
    /// is the rule that makes "the interface on this port" a single entry.
    fn any_configuration() -> impl Strategy<Value = (Vec<Interface>, Vec<Neighbour>)> {
        (
            prop::collection::vec(any_interface(), 0..=4),
            prop::collection::vec(any_neighbour(), 0..=4),
        )
            .prop_map(|(interfaces, neighbours)| {
                let mut ports = Vec::new();
                let unique = interfaces
                    .into_iter()
                    .filter(|entry| {
                        let first = !ports.contains(&entry.port);
                        ports.push(entry.port);
                        first
                    })
                    .collect();
                (unique, neighbours)
            })
    }

    proptest! {
        /// The egress a destination resolves to does not depend on the order
        /// the interfaces were written in: every rotation of one table answers
        /// the same way, equal-length covering prefixes included.
        #[test]
        fn the_route_is_the_same_under_every_table_order(
            (interfaces, neighbours) in any_configuration(),
            destination in any_address(),
            rotation in 0usize..5,
        ) {
            let written = Router::<4, 4>::from_slices(&interfaces, &neighbours)
                .expect("the strategy generates tables of at most the capacity");
            let mut rotated = interfaces.clone();
            let steps = rotation.checked_rem(rotated.len()).unwrap_or(0);
            rotated.rotate_left(steps);
            let permuted = Router::<4, 4>::from_slices(&rotated, &neighbours)
                .expect("a rotation holds the same entries");
            prop_assert_eq!(written.route(destination), permuted.route(destination));

            let mut reversed = interfaces;
            reversed.reverse();
            let backwards = Router::<4, 4>::from_slices(&reversed, &neighbours)
                .expect("a reversal holds the same entries");
            prop_assert_eq!(written.route(destination), backwards.route(destination));
        }

        /// Whatever the table holds and wherever a zero prefix length sits in
        /// it, the interface it names is never the route: a default route cannot
        /// be reached through a configuration this crate accepts.
        #[test]
        fn a_zero_prefix_length_is_never_the_route(
            (interfaces, neighbours) in any_configuration(),
            at in 0usize..5,
            port in 0u8..4,
            destination in any::<[u8; 4]>(),
        ) {
            let mut with_default = interfaces;
            let at = at.min(with_default.len());
            with_default.insert(at, Interface {
                port: PortId(port),
                mac: MacAddress([0; 6]),
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
                prefix_length: 0,
                enabled: true,
            });
            let table = Router::<8, 8>::from_slices(&with_default, &neighbours)
                .expect("six entries fit in eight");
            let destination = Ipv4Address::from_octets(destination);
            if let Some(egress) = table.route(destination) {
                prop_assert!(
                    egress.prefix_length > 0,
                    "a zero prefix length was selected as the route for {}",
                    destination,
                );
            }
        }

        /// A selected route is always one the table holds, enabled, and
        /// genuinely covering the destination.
        #[test]
        fn a_selected_route_is_an_enabled_covering_interface(
            (interfaces, neighbours) in any_configuration(),
            destination in any_address(),
        ) {
            let table = Router::<4, 4>::from_slices(&interfaces, &neighbours)
                .expect("the strategy generates tables of at most the capacity");
            if let Some(egress) = table.route(destination) {
                prop_assert!(egress.enabled);
                prop_assert!(egress.covers(destination));
                prop_assert_eq!(table.interface(egress.port), Some(egress));
            }
        }

        /// Prefix coverage agrees with an independently computed mask, for
        /// every length and every address.
        #[test]
        fn coverage_matches_a_reference_mask(
            network in any::<[u8; 4]>(),
            probe in any::<[u8; 4]>(),
            prefix_length in 0u8..=32,
        ) {
            let interface = Interface {
                port: PORT0,
                mac: GATEWAY0_MAC,
                address: Ipv4Address::from_octets(network),
                prefix_length,
                enabled: true,
            };
            let reference = if prefix_length == 0 {
                true
            } else {
                let shift = 32 - u32::from(prefix_length);
                (u32::from_be_bytes(probe) >> shift) == (u32::from_be_bytes(network) >> shift)
            };
            prop_assert_eq!(interface.covers(Ipv4Address::from_octets(probe)), reference);
        }
    }
}
