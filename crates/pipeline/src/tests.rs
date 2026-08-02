use super::*;
use net_headers::{EtherType, IPV4_HEADER_LEN, Ipv4Address, Protocol, UDP_HEADER_LEN};
use proptest::prelude::*;
use routing::{Interface, Neighbour};
use std::vec::Vec;

const PORT0: PortId = PortId(0);
const PORT1: PortId = PortId(1);
const GATEWAY0_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]);
const GATEWAY1_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x51]);
const HOST_A_MAC: MacAddress = MacAddress([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]);
const HOST_B_MAC: MacAddress = MacAddress([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02]);

/// Nothing in the chain reads it, so every case that is not about the
/// generation uses one number and says so once here.
const GENERATION: u32 = 7;

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

fn evaluate_on<const I: usize, const N: usize>(
    table: &Router<I, N>,
    spec: &FrameSpec,
    ingress: PortId,
) -> Verdict {
    let mut bytes = spec.build();
    let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
    let mut inspection = Inspection::new(ingress, frame);
    Pipeline::new().evaluate(&mut inspection, &Configuration::new(GENERATION, table))
}

fn evaluate(spec: &FrameSpec, ingress: PortId) -> Verdict {
    evaluate_on(&router(), spec, ingress)
}

fn expect_drop(spec: &FrameSpec, ingress: PortId, reason: DropReason) {
    assert_eq!(evaluate(spec, ingress), Verdict::Drop(reason));
}

fn expect_drop_on<const I: usize, const N: usize>(
    table: &Router<I, N>,
    spec: &FrameSpec,
    ingress: PortId,
    reason: DropReason,
) {
    assert_eq!(evaluate_on(table, spec, ingress), Verdict::Drop(reason));
}

// ── The chain's own shape ───────────────────────────────────────────────────

#[test]
fn an_admissible_frame_is_deferred_to_the_stage_behind_admission() {
    let table = router();
    let configuration = Configuration::new(GENERATION, &table);
    let spec = FrameSpec::a_to_b();
    let mut bytes = spec.build();
    let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
    let mut inspection = Inspection::new(PORT0, frame);

    assert_eq!(
        AdmissionStage.evaluate(&mut inspection, &configuration),
        Step::Continue,
        "a frame this port was addressed by must reach the rest of the chain"
    );
    assert_eq!(
        RoutingStage.evaluate(&mut inspection, &configuration),
        Verdict::Forward {
            egress: PORT1,
            source: GATEWAY1_MAC,
            destination: HOST_B_MAC,
        }
    );
}

#[test]
fn the_first_stage_that_settles_ends_the_chain() {
    // Tagged *and* unroutable: admission settles it, so the routing stage never
    // sees the destination it would otherwise have named.
    let table = router();
    let configuration = Configuration::new(GENERATION, &table);
    let spec = FrameSpec {
        vlan: Some(0x0064),
        destination: Ipv4Address::from_octets([192, 0, 2, 9]),
        ..FrameSpec::a_to_b()
    };
    let mut bytes = spec.build();
    let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
    let mut inspection = Inspection::new(PORT0, frame);

    assert_eq!(
        AdmissionStage.evaluate(&mut inspection, &configuration),
        Step::Settled(Verdict::Drop(DropReason::VlanTagged))
    );
    assert_eq!(
        RoutingStage.evaluate(&mut inspection, &configuration),
        Verdict::Drop(DropReason::NoRoute),
        "the stage behind admission would have named a different reason"
    );
    assert_eq!(
        evaluate(&spec, PORT0),
        Verdict::Drop(DropReason::VlanTagged),
        "the chain reported the later stage's reason"
    );
}

#[test]
fn an_inspection_carries_the_port_and_the_frame_the_stages_read() {
    let spec = FrameSpec::a_to_b();
    let mut bytes = spec.build();
    let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
    let inspection = Inspection::new(PORT1, frame);

    assert_eq!(inspection.ingress(), PORT1);
    assert_eq!(inspection.frame().destination_mac(), GATEWAY0_MAC);
    assert_eq!(inspection.frame().ipv4().destination, host_b());
}

#[test]
fn a_configuration_carries_the_generation_that_produced_its_table() {
    let table = router();
    let configuration = Configuration::new(19, &table);
    assert_eq!(configuration.generation(), 19);
    assert_eq!(
        configuration.table().interface(PORT0),
        Some(&interfaces()[0])
    );
}

#[test]
fn a_default_pipeline_decides_as_a_new_one_does() {
    let table = router();
    let configuration = Configuration::new(GENERATION, &table);
    let spec = FrameSpec::a_to_b();
    let mut bytes = spec.build();
    let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
    let mut inspection = Inspection::new(PORT0, frame);

    assert_eq!(
        Pipeline::default().evaluate(&mut inspection, &configuration),
        Verdict::Forward {
            egress: PORT1,
            source: GATEWAY1_MAC,
            destination: HOST_B_MAC,
        }
    );
}

// ── The verdicts themselves ─────────────────────────────────────────────────

#[test]
fn a_packet_from_one_subnet_to_the_other_is_forwarded_to_the_far_neighbour() {
    assert_eq!(
        evaluate(&FrameSpec::a_to_b(), PORT0),
        Verdict::Forward {
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
        evaluate(&spec, PORT1),
        Verdict::Forward {
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
fn a_port_with_no_interface_routes_nothing() {
    let spec = FrameSpec::a_to_b();
    expect_drop(&spec, PortId(7), DropReason::UnconfiguredIngressPort);
}

#[test]
fn an_interface_with_a_zero_prefix_length_still_receives_but_is_never_an_egress() {
    let mut with_default = interfaces();
    with_default[1].prefix_length = 0;
    let table = Router::<2, 2>::from_slices(&with_default, &neighbours()).expect("two fit");

    let far = Ipv4Address::from_octets([203, 0, 113, 4]);
    let spec = FrameSpec {
        destination: far,
        ..FrameSpec::a_to_b()
    };
    expect_drop_on(&table, &spec, PORT0, DropReason::NoRoute);

    let onto_the_default_port = FrameSpec {
        destination_mac: GATEWAY1_MAC,
        source: host_b(),
        destination: host_a(),
        ..FrameSpec::a_to_b()
    };
    assert_eq!(
        evaluate_on(&table, &onto_the_default_port, PORT1),
        Verdict::Forward {
            egress: PORT0,
            source: GATEWAY0_MAC,
            destination: HOST_A_MAC,
        },
        "a /0 interface must still receive"
    );
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
                evaluate_on(&roomy, &spec, ingress),
                evaluate_on(&exact, &spec, ingress),
            );
        }
    }
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
    expect_drop_on(&table, &spec, PORT0, DropReason::InterfaceDisabled);
}

#[test]
fn a_disabled_interface_is_never_selected_as_an_egress() {
    let mut down = interfaces();
    down[1].enabled = false;
    let table = Router::<2, 2>::from_slices(&down, &neighbours()).expect("two fit in two");

    expect_drop_on(&table, &FrameSpec::a_to_b(), PORT0, DropReason::NoRoute);
    // Still the appliance's own address, so still not forwardable.
    let spec = FrameSpec {
        destination: Ipv4Address::from_octets([10, 0, 1, 1]),
        ..FrameSpec::a_to_b()
    };
    expect_drop_on(&table, &spec, PORT0, DropReason::AddressedToThisRouter);
}

// ── The refusal vocabulary ──────────────────────────────────────────────────

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
    assert_eq!(DropCounters::default(), DropCounters::new());
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
    assert_eq!(counters.total(), u64::MAX);
}

// ── Properties ──────────────────────────────────────────────────────────────

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

        match evaluate_on(&table, &spec, ingress) {
            Verdict::Drop(reason) => prop_assert!(
                DropReason::ALL.contains(&reason),
                "a reason outside the counted set",
            ),
            Verdict::Forward { egress, source: from, destination: to } => {
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

    /// The chain is total: whatever the header fields, a verdict comes back
    /// and nothing panics.
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
        let _ = evaluate(&spec, PortId(port));
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

        if let Verdict::Forward { egress, source: from, destination: to } =
            evaluate_on(&table, &spec, ingress)
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

    /// Admission never forwards and routing never refuses for an admission
    /// reason: the two stages own disjoint halves of the vocabulary, which is
    /// what makes the chain's reason attributable to a stage.
    #[test]
    fn each_stage_refuses_only_in_its_own_half_of_the_vocabulary(
        (interfaces, neighbours) in any_configuration(),
        destination_mac in any::<[u8; 6]>(),
        source in any_address(),
        destination in any_address(),
        ttl in any::<u8>(),
        ingress_port in 0u8..5,
        tagged in any::<bool>(),
    ) {
        const ADMISSION: [DropReason; 4] = [
            DropReason::UnconfiguredIngressPort,
            DropReason::InterfaceDisabled,
            DropReason::VlanTagged,
            DropReason::NotAddressedToUs,
        ];

        let table = Router::<4, 4>::from_slices(&interfaces, &neighbours)
            .expect("the strategy generates at most the capacity of each table");
        let configuration = Configuration::new(GENERATION, &table);
        let spec = FrameSpec {
            destination_mac: MacAddress(destination_mac),
            source_mac: HOST_A_MAC,
            source,
            destination,
            ttl,
            vlan: tagged.then_some(0x0064),
        };
        let mut bytes = spec.build();
        let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
        let mut inspection = Inspection::new(PortId(ingress_port), frame);

        match AdmissionStage.evaluate(&mut inspection, &configuration) {
            Step::Settled(Verdict::Drop(reason)) => {
                prop_assert!(ADMISSION.contains(&reason), "{reason} is not an admission reason");
            }
            Step::Settled(Verdict::Forward { .. }) => {
                prop_assert!(false, "admission forwarded a frame it cannot route");
            }
            Step::Continue => {
                if let Verdict::Drop(reason) =
                    RoutingStage.evaluate(&mut inspection, &configuration)
                {
                    prop_assert!(
                        !ADMISSION.contains(&reason),
                        "{reason} is admission's to name",
                    );
                }
            }
        }
    }
}
