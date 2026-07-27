//! The IPv4 forwarding decision: given the port a frame arrived on and its
//! parsed headers, whether to forward it, out of which port, and under which
//! pair of MAC addresses.
//!
//! Faces untrusted network traffic (CONCEPT §7.1). Every field it reads was
//! chosen by whatever is attached to a dataplane port, so a decision is total:
//! [`Router::decide`] returns a verdict for every possible header, and the
//! verdict for anything it does not recognise is a named [`DropReason`] rather
//! than a fallthrough.
//!
//! # Connected routes only, and static neighbours
//!
//! There is no route table separate from the interfaces: a destination is
//! routable exactly when some interface's prefix covers it, and the next hop is
//! then the destination itself. That is a real restriction — no default route,
//! no gateway indirection — and it is what a two-port appliance between two
//! directly attached subnets needs.
//!
//! Neighbours are configured, never learned. ARP is not implemented anywhere in
//! the system, and it cannot be until a domain can *originate* a frame: the
//! buffer pools are owned by the receiving drivers, the forwarder owns none, and
//! a frame can only leave the port opposite the one it arrived on. Resolution
//! therefore stays a table until that topology changes (CONCEPT §6.3's
//! Routing/ARP/ICMP component), and this crate carries no discovery state.
//!
//! # No ICMP
//!
//! A drop is counted, never answered. Every reason below would, in a complete
//! router, generate an ICMP error — time exceeded, destination unreachable —
//! and generating one needs the same frame origination ARP does.

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
    /// Bits of `address` that form the network. Values above 32 are treated as
    /// 32 and 0 matches everything, so no value is invalid; see
    /// [`prefix_mask`].
    pub prefix_length: u8,
}

impl Interface {
    /// Whether this interface's connected prefix covers `destination`.
    #[must_use]
    pub const fn covers(&self, destination: Ipv4Address) -> bool {
        let mask = prefix_mask(self.prefix_length);
        destination.bits() & mask == self.address.bits() & mask
    }
}

/// A statically configured link-layer address for a directly attached host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Neighbour {
    pub port: PortId,
    pub address: Ipv4Address,
    pub mac: MacAddress,
}

/// The network mask for a prefix length, saturating rather than rejecting: a
/// length above 32 is a host route and 0 matches everything, so every `u8` maps
/// to a mask and no invalid configuration is representable.
#[must_use]
pub const fn prefix_mask(prefix_length: u8) -> u32 {
    if prefix_length == 0 {
        0
    } else if prefix_length >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_length)
    }
}

/// Why a frame was not forwarded. Each variant is one counter in
/// [`DropCounters`], so a drop is always attributable to a reason an operator
/// can act on rather than to an aggregate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DropReason {
    /// The ingress port has no configured interface, so the appliance has no
    /// address to route on behalf of.
    UnconfiguredIngressPort,
    /// The destination MAC is not this port's. A router forwards what was
    /// addressed to it; broadcast and multicast frames land here too, which is
    /// what makes ARP traverse nothing.
    NotAddressedToUs,
    /// An 802.1Q tag with no sub-interface to interpret it.
    VlanTagged,
    /// A source address that may not appear as one: multicast, broadcast,
    /// loopback, or unspecified.
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
    pub const ALL: [Self; 10] = [
        Self::UnconfiguredIngressPort,
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

/// The static forwarding configuration: the appliance's interfaces and the
/// neighbours it can resolve.
///
/// Const-generic in both table sizes rather than bounded by a maximum, so the
/// configuration a protection domain compiles in is exactly as large as it is
/// and the tables carry no empty slots to skip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Router<const INTERFACES: usize, const NEIGHBOURS: usize> {
    interfaces: [Interface; INTERFACES],
    neighbours: [Neighbour; NEIGHBOURS],
}

impl<const INTERFACES: usize, const NEIGHBOURS: usize> Router<INTERFACES, NEIGHBOURS> {
    #[must_use]
    pub const fn new(
        interfaces: [Interface; INTERFACES],
        neighbours: [Neighbour; NEIGHBOURS],
    ) -> Self {
        Self {
            interfaces,
            neighbours,
        }
    }

    #[must_use]
    pub fn interface(&self, port: PortId) -> Option<&Interface> {
        self.interfaces.iter().find(|entry| entry.port == port)
    }

    /// The interface whose connected prefix covers `destination`, longest
    /// prefix first. Ordering by prefix length rather than by table position is
    /// what keeps the result independent of how the configuration was written.
    #[must_use]
    pub fn route(&self, destination: Ipv4Address) -> Option<&Interface> {
        self.interfaces
            .iter()
            .filter(|entry| entry.covers(destination))
            .max_by_key(|entry| entry.prefix_length)
    }

    #[must_use]
    pub fn neighbour(&self, port: PortId, address: Ipv4Address) -> Option<&Neighbour> {
        self.neighbours
            .iter()
            .find(|entry| entry.port == port && entry.address == address)
    }

    /// Whether `address` is one the appliance itself holds.
    #[must_use]
    pub fn is_local_address(&self, address: Ipv4Address) -> bool {
        self.interfaces.iter().any(|entry| entry.address == address)
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
        if frame.vlan().is_some() {
            return Decision::Drop(DropReason::VlanTagged);
        }
        if frame.destination_mac() != interface.mac {
            return Decision::Drop(DropReason::NotAddressedToUs);
        }

        let header = frame.ipv4();
        let source = header.source;
        if source.is_multicast()
            || source.is_broadcast()
            || source.is_loopback()
            || source.is_unspecified()
        {
            return Decision::Drop(DropReason::MartianSource);
        }
        let destination = header.destination;
        if destination.is_multicast()
            || destination.is_broadcast()
            || destination.is_loopback()
            || destination.is_unspecified()
        {
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

    fn router() -> Router<2, 2> {
        Router::new(
            [
                Interface {
                    port: PORT0,
                    mac: GATEWAY0_MAC,
                    address: Ipv4Address::from_octets([10, 0, 0, 1]),
                    prefix_length: 24,
                },
                Interface {
                    port: PORT1,
                    mac: GATEWAY1_MAC,
                    address: Ipv4Address::from_octets([10, 0, 1, 1]),
                    prefix_length: 24,
                },
            ],
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
            ],
        )
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

    fn decide(spec: &FrameSpec, ingress: PortId) -> Decision {
        let mut bytes = spec.build();
        let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
        router().decide(ingress, &frame)
    }

    fn expect_drop(spec: &FrameSpec, ingress: PortId, reason: DropReason) {
        assert_eq!(decide(spec, ingress), Decision::Drop(reason));
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
        };
        let narrow = Interface {
            port: PORT1,
            mac: GATEWAY1_MAC,
            address: Ipv4Address::from_octets([10, 0, 1, 0]),
            prefix_length: 24,
        };
        let target = Ipv4Address::from_octets([10, 0, 1, 2]);

        let in_order = Router::<2, 0>::new([wide, narrow], []);
        let reversed = Router::<2, 0>::new([narrow, wide], []);
        assert_eq!(in_order.route(target), Some(&narrow));
        assert_eq!(reversed.route(target), Some(&narrow));
    }

    #[test]
    fn prefix_masks_saturate_at_both_ends() {
        assert_eq!(prefix_mask(0), 0);
        assert_eq!(prefix_mask(1), 0x8000_0000);
        assert_eq!(prefix_mask(24), 0xffff_ff00);
        assert_eq!(prefix_mask(32), u32::MAX);
        assert_eq!(prefix_mask(255), u32::MAX);
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

    proptest! {
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
