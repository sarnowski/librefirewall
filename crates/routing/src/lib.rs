//! The IPv4 forwarding decision: given the port a frame arrived on and its
//! parsed headers, whether to forward it, out of which port, and under which
//! pair of MAC addresses.
//!
//! Faces untrusted network traffic. Every field it reads was
//! chosen by whatever is attached to a dataplane port, so a decision is total:
//! [`Router::decide`] returns a verdict for every possible header, and the
//! verdict for anything it does not recognise is a named [`DropReason`] rather
//! than a fallthrough.
//!
//! # Connected routes only, and configured neighbours
//!
//! There is no route table separate from the interfaces: a destination is
//! routable exactly when some interface's prefix covers it, and the next hop is
//! then the destination itself. That is a real restriction — no default route,
//! no gateway indirection — and it is what a two-port appliance between two
//! directly attached subnets needs, and [`Router::route`] holds it: a prefix
//! length of zero would cover every destination, so such an interface is never
//! a route. It stays an address the appliance holds — an ingress, and a
//! destination that is not forwarded onward — and nothing is routed through it.
//!
//! Neighbours are configured, never learned: this crate carries no discovery
//! state. Resolution stays a table because the forwarder cannot *originate* a
//! frame — it owns no buffer pool, and a frame leaves only the port opposite the
//! one it arrived on; answering is the routing/ARP/ICMP component's job.
//!
//! A drop is counted, never answered. An ICMP error — time exceeded,
//! destination unreachable — needs that same origination.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

use net_headers::{Frame, Ipv4Address, MacAddress};

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
    /// saturates rather than rejecting, so every `u8` behaves; zero makes the
    /// interface a default route, which [`Router::route`] does not select.
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

/// Why a frame was not forwarded. Each variant is one counter in
/// [`DropCounters`], so a drop is always attributable to a reason an operator
/// can act on rather than to an aggregate.
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

/// What to do with one frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
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
    /// fields the verdict is built from. That is a total order and table
    /// position is not in it, which is what makes any permutation of the same
    /// interfaces answer the same way. Which of two equal-length prefixes wins
    /// is arbitrary; that it is the same one every time is not.
    ///
    /// Two kinds of interface are not candidates, this being where an egress is
    /// chosen. A disabled one, because a route out of a link that is down is not
    /// a route. And one whose prefix length is zero, because its prefix covers
    /// every destination: selecting it would be a default route, and this crate
    /// forwards on connected prefixes alone. Such an interface is still an
    /// address the appliance holds, so traffic *to* it is still refused as its
    /// own and traffic *through* it is refused as having no route — which is a
    /// named, counted reason rather than a silent default hop. Refusing the
    /// whole table instead would be this crate rejecting a configuration the
    /// layer that validates one accepts, and it is that layer's rule to add.
    #[must_use]
    pub fn route(&self, destination: Ipv4Address) -> Option<&Interface> {
        self.configured_interfaces()
            .filter(|entry| entry.enabled && entry.prefix_length > 0 && entry.covers(destination))
            .min_by_key(|entry| {
                (
                    // Longest prefix first, inside an otherwise ascending key.
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

    /// The forwarding verdict for `frame` arriving on `ingress`.
    ///
    /// Total by construction: every path ends in a [`Decision`], and every
    /// rejection names a [`DropReason`]. The order is the order a router must
    /// use — link layer, then source and destination sanity, then lifetime,
    /// then route, then resolution — so the reason recorded is the first thing
    /// actually wrong with the packet rather than whichever check ran last.
    #[must_use]
    pub fn decide(&self, ingress: PortId, frame: &Frame<'_>) -> Decision {
        let Some(interface) = self.interface(ingress) else {
            return Decision::Drop(DropReason::UnconfiguredIngressPort);
        };
        if !interface.enabled {
            return Decision::Drop(DropReason::InterfaceDisabled);
        }
        if frame.vlan().is_some() {
            return Decision::Drop(DropReason::VlanTagged);
        }
        if frame.destination_mac() != interface.mac {
            return Decision::Drop(DropReason::NotAddressedToUs);
        }

        let header = frame.ipv4();
        let source = header.source;
        if !source.is_unicast() || self.is_local_address(source) {
            return Decision::Drop(DropReason::MartianSource);
        }
        let destination = header.destination;
        if !destination.is_unicast() {
            return Decision::Drop(DropReason::UnroutableDestination);
        }
        if self.is_local_address(destination) {
            return Decision::Drop(DropReason::AddressedToThisRouter);
        }
        // Before the route lookup, so an expiring packet is reported as such
        // rather than as whatever the lookup happens to say about it.
        if header.ttl <= 1 {
            return Decision::Drop(DropReason::TtlExpired);
        }

        let Some(egress) = self.route(destination) else {
            return Decision::Drop(DropReason::NoRoute);
        };
        // Looked up across every interface and only then compared with the
        // ingress, so a longer prefix on the ingress port beats a shorter one
        // elsewhere and the frame is dropped rather than carried by it. The
        // longest match is the most specific statement about where the
        // destination lives; if that is the link it arrived on, the sender
        // should have addressed the host directly, and carrying it out of a
        // less specific route would put it on the wrong link.
        if egress.port == ingress {
            return Decision::Drop(DropReason::EgressIsIngress);
        }
        let Some(neighbour) = self.neighbour(egress.port, destination) else {
            return Decision::Drop(DropReason::NoNeighbour);
        };

        Decision::Forward {
            egress: egress.port,
            source: egress.mac,
            destination: neighbour.mac,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_headers::{EtherType, IPV4_HEADER_LEN, Protocol, UDP_HEADER_LEN};
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

    struct FrameSpec {
        destination_mac: MacAddress,
        source_mac: MacAddress,
        source: Ipv4Address,
        destination: Ipv4Address,
        ttl: u8,
        vlan: Option<u16>,
    }

    impl FrameSpec {
        fn a_to_b() -> Self {
            Self {
                destination_mac: GATEWAY0_MAC,
                source_mac: HOST_A_MAC,
                source: host_a(),
                destination: host_b(),
                ttl: 64,
                vlan: None,
            }
        }

        fn build(&self) -> Vec<u8> {
            let mut frame = Vec::new();
            frame.extend_from_slice(&self.destination_mac.0);
            frame.extend_from_slice(&self.source_mac.0);
            if let Some(tci) = self.vlan {
                frame.extend_from_slice(&EtherType::VLAN.0.to_be_bytes());
                frame.extend_from_slice(&tci.to_be_bytes());
            }
            frame.extend_from_slice(&EtherType::IPV4.0.to_be_bytes());

            let payload = b"routed";
            let total_length = (IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len()) as u16;
            let mut ip = [0u8; IPV4_HEADER_LEN];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&total_length.to_be_bytes());
            ip[8] = self.ttl;
            ip[9] = Protocol::UDP.0;
            ip[12..16].copy_from_slice(&self.source.octets());
            ip[16..20].copy_from_slice(&self.destination.octets());
            let checksum = ipv4_checksum(&ip);
            ip[10..12].copy_from_slice(&checksum.to_be_bytes());
            frame.extend_from_slice(&ip);

            frame.extend_from_slice(&4444u16.to_be_bytes());
            frame.extend_from_slice(&5000u16.to_be_bytes());
            frame.extend_from_slice(&((UDP_HEADER_LEN + payload.len()) as u16).to_be_bytes());
            frame.extend_from_slice(&0u16.to_be_bytes());
            frame.extend_from_slice(payload);
            frame
        }
    }

    /// The reference implementation the crate under test is checked against:
    /// deliberately written the naive way rather than reusing `net_headers`.
    fn ipv4_checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
        let mut sum = 0u32;
        for (index, pair) in header.chunks(2).enumerate() {
            if index == 5 {
                continue;
            }
            let value = match pair {
                [high, low] => u16::from_be_bytes([*high, *low]),
                [high] => u16::from_be_bytes([*high, 0]),
                _ => 0,
            };
            sum += u32::from(value);
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn decide_on<const I: usize, const N: usize>(
        table: &Router<I, N>,
        spec: &FrameSpec,
        ingress: PortId,
    ) -> Decision {
        let mut bytes = spec.build();
        let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
        table.decide(ingress, &frame)
    }

    fn decide(spec: &FrameSpec, ingress: PortId) -> Decision {
        decide_on(&router(), spec, ingress)
    }

    fn expect_drop(spec: &FrameSpec, ingress: PortId, reason: DropReason) {
        assert_eq!(decide(spec, ingress), Decision::Drop(reason));
    }

    fn expect_drop_on<const I: usize, const N: usize>(
        table: &Router<I, N>,
        spec: &FrameSpec,
        ingress: PortId,
        reason: DropReason,
    ) {
        assert_eq!(decide_on(table, spec, ingress), Decision::Drop(reason));
    }

    #[test]
    fn a_packet_from_one_subnet_to_the_other_is_forwarded_to_the_far_neighbour() {
        assert_eq!(
            decide(&FrameSpec::a_to_b(), PORT0),
            Decision::Forward {
                egress: PORT1,
                source: GATEWAY1_MAC,
                destination: HOST_B_MAC,
            }
        );
    }

    #[test]
    fn the_reverse_direction_is_forwarded_symmetrically() {
        let spec = FrameSpec {
            destination_mac: GATEWAY1_MAC,
            source_mac: HOST_B_MAC,
            source: host_b(),
            destination: host_a(),
            ..FrameSpec::a_to_b()
        };
        assert_eq!(
            decide(&spec, PORT1),
            Decision::Forward {
                egress: PORT0,
                source: GATEWAY0_MAC,
                destination: HOST_A_MAC,
            }
        );
    }

    #[test]
    fn a_frame_addressed_to_another_station_is_not_routed() {
        for destination_mac in [
            MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            MacAddress::BROADCAST,
            MacAddress([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]),
        ] {
            let spec = FrameSpec {
                destination_mac,
                ..FrameSpec::a_to_b()
            };
            expect_drop(&spec, PORT0, DropReason::NotAddressedToUs);
        }
    }

    #[test]
    fn a_tagged_frame_is_dropped_for_want_of_a_sub_interface() {
        let spec = FrameSpec {
            vlan: Some(0x0064),
            ..FrameSpec::a_to_b()
        };
        expect_drop(&spec, PORT0, DropReason::VlanTagged);
    }

    #[test]
    fn a_packet_the_appliance_holds_the_address_of_is_not_forwarded() {
        let spec = FrameSpec {
            destination: Ipv4Address::from_octets([10, 0, 1, 1]),
            ..FrameSpec::a_to_b()
        };
        expect_drop(&spec, PORT0, DropReason::AddressedToThisRouter);
    }

    #[test]
    fn a_ttl_that_cannot_survive_a_hop_is_dropped_before_the_route_lookup() {
        for ttl in [0, 1] {
            let spec = FrameSpec {
                ttl,
                // Unroutable as well, to prove the TTL check runs first.
                destination: Ipv4Address::from_octets([192, 0, 2, 9]),
                ..FrameSpec::a_to_b()
            };
            expect_drop(&spec, PORT0, DropReason::TtlExpired);
        }
    }

    #[test]
    fn a_destination_no_prefix_covers_has_no_route() {
        let spec = FrameSpec {
            destination: Ipv4Address::from_octets([192, 0, 2, 9]),
            ..FrameSpec::a_to_b()
        };
        expect_drop(&spec, PORT0, DropReason::NoRoute);
    }

    #[test]
    fn a_packet_routed_back_out_of_its_ingress_port_is_dropped() {
        let spec = FrameSpec {
            destination_mac: GATEWAY0_MAC,
            destination: Ipv4Address::from_octets([10, 0, 0, 9]),
            ..FrameSpec::a_to_b()
        };
        expect_drop(&spec, PORT0, DropReason::EgressIsIngress);
    }

    #[test]
    fn a_routable_destination_with_no_neighbour_entry_is_unresolvable() {
        let spec = FrameSpec {
            destination: Ipv4Address::from_octets([10, 0, 1, 77]),
            ..FrameSpec::a_to_b()
        };
        expect_drop(&spec, PORT0, DropReason::NoNeighbour);
    }

    #[test]
    fn martian_and_unroutable_addresses_are_named_separately() {
        for source in [
            Ipv4Address::from_octets([224, 0, 0, 1]),
            Ipv4Address::from_octets([255, 255, 255, 255]),
            Ipv4Address::from_octets([127, 0, 0, 1]),
            Ipv4Address::from_octets([0, 0, 0, 0]),
        ] {
            let spec = FrameSpec {
                source,
                ..FrameSpec::a_to_b()
            };
            expect_drop(&spec, PORT0, DropReason::MartianSource);
        }
        for destination in [
            Ipv4Address::from_octets([224, 0, 0, 1]),
            Ipv4Address::from_octets([255, 255, 255, 255]),
            Ipv4Address::from_octets([127, 0, 0, 1]),
            Ipv4Address::from_octets([0, 0, 0, 0]),
        ] {
            let spec = FrameSpec {
                destination,
                ..FrameSpec::a_to_b()
            };
            expect_drop(&spec, PORT0, DropReason::UnroutableDestination);
        }
    }

    #[test]
    fn a_frame_claiming_one_of_the_appliances_own_addresses_as_its_source_is_martian() {
        // Both interfaces' addresses: a forgery aimed at either link is refused
        // on the port it arrived on, not only the one that holds the address.
        for source in [
            Ipv4Address::from_octets([10, 0, 0, 1]),
            Ipv4Address::from_octets([10, 0, 1, 1]),
        ] {
            let spec = FrameSpec {
                source,
                ..FrameSpec::a_to_b()
            };
            expect_drop(&spec, PORT0, DropReason::MartianSource);
        }
    }

    #[test]
    fn a_source_of_a_disabled_interfaces_address_is_still_martian() {
        let mut down = interfaces();
        down[1].enabled = false;
        let table = Router::<2, 2>::from_slices(&down, &neighbours()).expect("two fit in two");
        let spec = FrameSpec {
            source: Ipv4Address::from_octets([10, 0, 1, 1]),
            ..FrameSpec::a_to_b()
        };
        expect_drop_on(&table, &spec, PORT0, DropReason::MartianSource);
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
        let spec = FrameSpec {
            destination: far,
            ..FrameSpec::a_to_b()
        };
        expect_drop_on(&table, &spec, PORT0, DropReason::NoRoute);

        // Still the appliance's own address, and still a usable ingress: the
        // narrowing is to route selection alone.
        assert!(table.is_local_address(with_default[1].address));
        let onto_the_default_port = FrameSpec {
            destination_mac: GATEWAY1_MAC,
            source: host_b(),
            destination: host_a(),
            ..FrameSpec::a_to_b()
        };
        assert_eq!(
            decide_on(&table, &onto_the_default_port, PORT1),
            Decision::Forward {
                egress: PORT0,
                source: GATEWAY0_MAC,
                destination: HOST_A_MAC,
            },
            "a /0 interface must still receive"
        );
    }

    #[test]
    fn a_port_with_no_interface_routes_nothing() {
        let spec = FrameSpec::a_to_b();
        expect_drop(&spec, PortId(7), DropReason::UnconfiguredIngressPort);
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
    fn a_frame_arriving_on_a_disabled_interface_is_refused_before_anything_about_the_frame() {
        let mut down = interfaces();
        down[0].enabled = false;
        let table = Router::<2, 2>::from_slices(&down, &neighbours()).expect("two fit in two");

        // Also tagged, also addressed elsewhere, also martian: whichever of
        // those would otherwise be reported, the interface state outranks it.
        let spec = FrameSpec {
            destination_mac: MacAddress::BROADCAST,
            source: Ipv4Address::from_octets([224, 0, 0, 1]),
            vlan: Some(0x0064),
            ..FrameSpec::a_to_b()
        };
        assert_eq!(
            decide_on(&table, &spec, PORT0),
            Decision::Drop(DropReason::InterfaceDisabled)
        );
    }

    #[test]
    fn a_disabled_interface_is_never_selected_as_an_egress() {
        let mut down = interfaces();
        down[1].enabled = false;
        let table = Router::<2, 2>::from_slices(&down, &neighbours()).expect("two fit in two");

        assert_eq!(table.route(host_b()), None);
        expect_drop_on(&table, &FrameSpec::a_to_b(), PORT0, DropReason::NoRoute);
        // Still the appliance's own address, so still not forwardable.
        let spec = FrameSpec {
            destination: Ipv4Address::from_octets([10, 0, 1, 1]),
            ..FrameSpec::a_to_b()
        };
        expect_drop_on(&table, &spec, PORT0, DropReason::AddressedToThisRouter);
    }

    #[test]
    fn an_empty_router_has_no_port_to_receive_on() {
        let table = Router::<8, 32>::empty();
        for port in [PORT0, PORT1, PortId(7), PortId(255)] {
            expect_drop_on(
                &table,
                &FrameSpec::a_to_b(),
                port,
                DropReason::UnconfiguredIngressPort,
            );
        }
        assert_eq!(table.route(host_b()), None);
        assert_eq!(table.neighbour(PORT0, host_a()), None);
        assert!(!table.is_local_address(Ipv4Address::from_octets([10, 0, 0, 1])));
    }

    #[test]
    fn spare_capacity_reaches_the_same_verdict_as_an_exactly_sized_table() {
        let roomy = Router::<8, 32>::from_slices(&interfaces(), &neighbours())
            .expect("two of each fit in eight and thirty-two");
        let exact = router();

        for spec in [
            FrameSpec::a_to_b(),
            FrameSpec {
                destination: Ipv4Address::from_octets([192, 0, 2, 9]),
                ..FrameSpec::a_to_b()
            },
            FrameSpec {
                destination: Ipv4Address::from_octets([10, 0, 1, 77]),
                ..FrameSpec::a_to_b()
            },
            FrameSpec {
                destination_mac: MacAddress::BROADCAST,
                ..FrameSpec::a_to_b()
            },
        ] {
            for ingress in [PORT0, PORT1, PortId(7)] {
                assert_eq!(
                    decide_on(&roomy, &spec, ingress),
                    decide_on(&exact, &spec, ingress),
                );
            }
        }
    }

    #[test]
    fn every_drop_reason_has_its_own_counter_slot() {
        let mut counters = DropCounters::new();
        for (bumps, reason) in DropReason::ALL.into_iter().enumerate() {
            for _ in 0..=bumps {
                counters.record(reason);
            }
        }
        for (bumps, reason) in DropReason::ALL.into_iter().enumerate() {
            assert_eq!(counters.get(reason), bumps as u64 + 1, "{reason}");
        }
        let expected = (1..=DropReason::ALL.len() as u64).sum::<u64>();
        assert_eq!(counters.total(), expected);
    }

    #[test]
    fn drop_reason_names_are_distinct() {
        for reason in DropReason::ALL {
            assert_eq!(
                std::format!("{reason}"),
                reason.name(),
                "a rendered reason is not the name a counter is keyed by"
            );
        }
        let mut names: Vec<&str> = DropReason::ALL.iter().map(|reason| reason.name()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two reasons share a metric name");
    }

    #[test]
    fn a_counter_saturates_rather_than_wrapping() {
        let mut counters = DropCounters::new();
        for _ in 0..3 {
            counters.counts[DropReason::NoRoute.slot()] = u64::MAX;
            counters.record(DropReason::NoRoute);
        }
        assert_eq!(counters.get(DropReason::NoRoute), u64::MAX);
    }

    /// An address out of a small space, so a generated neighbour and a
    /// generated destination coincide often enough for the forwarding branch to
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
        /// Whatever configuration is loaded and whatever arrives, a verdict is
        /// either a named reason or a forward the configuration itself backs:
        /// out of a configured, enabled interface that is not the ingress,
        /// under that interface's MAC, to a configured neighbour's.
        #[test]
        fn every_configuration_yields_a_verdict_its_own_tables_support(
            (interfaces, neighbours) in any_configuration(),
            destination_mac in any::<[u8; 6]>(),
            source in any_address(),
            destination in any_address(),
            ttl in any::<u8>(),
            ingress_port in 0u8..5,
        ) {
            let table = Router::<4, 4>::from_slices(&interfaces, &neighbours)
                .expect("the strategy generates at most the capacity of each table");
            let ingress = PortId(ingress_port);
            let spec = FrameSpec {
                destination_mac: MacAddress(destination_mac),
                source_mac: HOST_A_MAC,
                source,
                destination,
                ttl,
                vlan: None,
            };

            match decide_on(&table, &spec, ingress) {
                Decision::Drop(reason) => prop_assert!(
                    DropReason::ALL.contains(&reason),
                    "a reason outside the counted set",
                ),
                Decision::Forward { egress, source: from, destination: to } => {
                    prop_assert_ne!(egress, ingress);
                    let interface = table.interface(egress)
                        .expect("a named egress is a configured interface");
                    prop_assert!(interface.enabled, "forwarded out of a disabled interface");
                    prop_assert_eq!(from, interface.mac);
                    prop_assert!(
                        table.neighbour(egress, destination)
                            .is_some_and(|entry| entry.mac == to),
                        "the next-hop MAC is not a configured neighbour's",
                    );
                }
            }
        }

        /// The decision is total: whatever the header fields, a verdict comes
        /// back and nothing panics.
        #[test]
        fn every_header_yields_a_verdict(
            destination_mac in any::<[u8; 6]>(),
            source_mac in any::<[u8; 6]>(),
            source in any::<[u8; 4]>(),
            destination in any::<[u8; 4]>(),
            ttl in any::<u8>(),
            port in any::<u8>(),
        ) {
            let spec = FrameSpec {
                destination_mac: MacAddress(destination_mac),
                source_mac: MacAddress(source_mac),
                source: Ipv4Address::from_octets(source),
                destination: Ipv4Address::from_octets(destination),
                ttl,
                vlan: None,
            };
            let mut bytes = spec.build();
            let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
            let _ = router().decide(PortId(port), &frame);
        }

        /// A forward verdict is never self-contradictory: it never names the
        /// ingress port, its source MAC is always the egress interface's own,
        /// and its destination MAC is always a configured neighbour's.
        #[test]
        fn a_forward_verdict_is_internally_consistent(
            source in any::<[u8; 4]>(),
            destination in any::<[u8; 4]>(),
            ttl in any::<u8>(),
            from_port_one in any::<bool>(),
        ) {
            let ingress = if from_port_one { PORT1 } else { PORT0 };
            let table = router();
            let interface = table.interface(ingress).expect("both ports are configured");
            let spec = FrameSpec {
                destination_mac: interface.mac,
                source_mac: HOST_A_MAC,
                source: Ipv4Address::from_octets(source),
                destination: Ipv4Address::from_octets(destination),
                ttl,
                vlan: None,
            };
            let mut bytes = spec.build();
            let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");

            if let Decision::Forward { egress, source: from, destination: to } =
                table.decide(ingress, &frame)
            {
                prop_assert_ne!(egress, ingress);
                prop_assert!(ttl > 1, "a forwarded packet always had a survivable TTL");
                let egress_interface = table.interface(egress).expect("a named egress is configured");
                prop_assert_eq!(from, egress_interface.mac);
                prop_assert!(
                    table.neighbour(egress, Ipv4Address::from_octets(destination))
                        .is_some_and(|entry| entry.mac == to),
                    "the next-hop MAC is not a configured neighbour's",
                );
            }
        }

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
