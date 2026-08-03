use super::*;
use lfw_clock::Monotonic;

/// A ruleset that accepts whatever the routing stage resolves.
///
/// Most of the tests below are about admission and routing, and the filter
/// behind them denies by default: under an empty ruleset each would pass for
/// the wrong reason. The filter's own behaviour is tested against rulesets
/// written for it.
fn allow_all() -> Ruleset {
    Ruleset::build(core::iter::once(Rule {
        ingress: None,
        egress: None,
        source: None,
        destination: None,
        protocol: None,
        source_port: None,
        destination_port: None,
        icmp_type: None,
        action: RuleAction::Accept,
    }))
    .expect("one rule is inside any capacity")
}
use net_headers::{
    EtherType, ICMP_HEADER_LEN, IPV4_HEADER_LEN, Ipv4Address, Protocol, TCP_HEADER_LEN,
    UDP_HEADER_LEN,
};
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

/// What a frame carries behind its IPv4 header, which is the whole of what a
/// port or ICMP-type criterion can be answered from.
///
/// The five shapes that carry *nothing* readable are here beside the two that do
/// because that is the property the filter is built around: a criterion cannot be
/// satisfied by a header nobody read, and on a default-deny appliance the
/// dangerous direction is an `accept` matching one.
#[derive(Clone, Copy, Debug)]
enum TransportSpec {
    Udp {
        source: u16,
        destination: u16,
    },
    Tcp {
        source: u16,
        destination: u16,
    },
    Icmp {
        message_type: u8,
    },
    /// A datagram claiming `protocol` with two bytes behind its IPv4 header: too
    /// few for any of the three headers, so no port and no type was read.
    Truncated(Protocol),
    /// The second piece of a fragmented datagram, which carries no transport
    /// header at its offset whatever the protocol says.
    NonInitialFragment,
    /// A protocol this build does not break down. A router forwards it; a filter
    /// can say nothing about its ports.
    Unparsed(Protocol),
}

impl TransportSpec {
    /// The IPv4 `protocol` byte this shape claims.
    fn protocol(self) -> Protocol {
        match self {
            Self::Udp { .. } => Protocol::UDP,
            Self::Tcp { .. } => Protocol::TCP,
            Self::Icmp { .. } => Protocol::ICMP,
            Self::Truncated(protocol) | Self::Unparsed(protocol) => protocol,
            Self::NonInitialFragment => Protocol::UDP,
        }
    }

    /// The bytes behind the IPv4 header.
    fn bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Udp {
                source,
                destination,
            } => {
                out.extend_from_slice(&source.to_be_bytes());
                out.extend_from_slice(&destination.to_be_bytes());
                out.extend_from_slice(&((UDP_HEADER_LEN + 6) as u16).to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(b"routed");
            }
            Self::Tcp {
                source,
                destination,
            } => {
                out.extend_from_slice(&source.to_be_bytes());
                out.extend_from_slice(&destination.to_be_bytes());
                out.resize(TCP_HEADER_LEN, 0);
                // A plausible data offset, so the header reads as one rather
                // than as a length the parser refuses.
                out[12] = 0x50;
                // A bare `SYN`. The connection tracker in front of the filter
                // opens a flow on one and on nothing else, so a segment with no
                // flags would be settled as mid-stream before any criterion
                // here was read — and these cases are about the criteria.
                out[13] = 0x02;
            }
            Self::Icmp { message_type } => {
                out.push(message_type);
                out.resize(ICMP_HEADER_LEN, 0);
            }
            // Two bytes: past no header's length, so every one of the three
            // reports itself truncated.
            Self::Truncated(_) => out.extend_from_slice(&[0xab, 0xcd]),
            // A whole UDP header's worth of bytes, which the parser must not
            // read as one because the fragment offset says they are payload.
            Self::NonInitialFragment => out.resize(UDP_HEADER_LEN + 6, 0x5a),
            Self::Unparsed(_) => out.resize(16, 0x5a),
        }
        out
    }
}

struct FrameSpec {
    destination_mac: MacAddress,
    source_mac: MacAddress,
    source: Ipv4Address,
    destination: Ipv4Address,
    ttl: u8,
    vlan: Option<u16>,
    transport: TransportSpec,
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
            transport: TransportSpec::Udp {
                source: 4444,
                destination: 5000,
            },
        }
    }

    /// The same frame carrying `transport`, which is the one axis every filter
    /// case below moves.
    fn carrying(transport: TransportSpec) -> Self {
        Self {
            transport,
            ..Self::a_to_b()
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

        let payload = self.transport.bytes();
        let total_length = (IPV4_HEADER_LEN + payload.len()) as u16;
        let mut ip = [0u8; IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&total_length.to_be_bytes());
        if matches!(self.transport, TransportSpec::NonInitialFragment) {
            // A non-zero fragment offset, in eight-byte units, with no
            // more-fragments flag: the last piece of a fragmented datagram.
            ip[6..8].copy_from_slice(&1u16.to_be_bytes());
        }
        ip[8] = self.ttl;
        ip[9] = self.transport.protocol().0;
        ip[12..16].copy_from_slice(&self.source.octets());
        ip[16..20].copy_from_slice(&self.destination.octets());
        let checksum = ipv4_checksum(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&payload);
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

/// A connection table small enough to hold, and a fresh one per evaluation.
///
/// Every test about admission, routing or the filter states what *one* packet
/// earns, and a table carried between two identical packets would make the
/// second one `Established` and settle it in front of the filter. That is the
/// tracker's own behaviour and it is tested where it belongs, below; here a
/// fresh table keeps each case about the stage it names.
type Flows = FlowTable<16>;

fn flows() -> Flows {
    FlowTable::new()
}

/// An instant, built the way this crate's callers build one.
fn at(nanos: u64) -> Monotonic {
    use core::num::NonZeroU64;
    use lfw_clock::{Calibration, Ticks};
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(nanos))
}

fn evaluate_on<const I: usize, const N: usize>(
    table: &Router<I, N>,
    spec: &FrameSpec,
    ingress: PortId,
) -> Verdict {
    let mut bytes = spec.build();
    let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
    let mut inspection = Inspection::new(ingress, frame);
    let mut table_of_flows = flows();
    Pipeline::new().evaluate(
        &mut inspection,
        &Configuration::new(GENERATION, table, &allow_all()),
        &mut Tracking::new(&mut table_of_flows, at(0)),
    )
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
    let rules = allow_all();
    let configuration = Configuration::new(GENERATION, &table, &rules);
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
        Step::Continue,
        "a frame it can resolve is deferred to the filter behind it"
    );
    assert_eq!(
        inspection.forwarding(),
        Some(Forwarding {
            egress: PORT1,
            source: GATEWAY1_MAC,
            destination: HOST_B_MAC,
        }),
        "and what it resolved is attached for that filter to read"
    );
}

#[test]
fn the_first_stage_that_settles_ends_the_chain() {
    // Tagged *and* unroutable: admission settles it, so the routing stage never
    // sees the destination it would otherwise have named.
    let table = router();
    let rules = allow_all();
    let configuration = Configuration::new(GENERATION, &table, &rules);
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
        Step::Settled(Verdict::Drop(DropReason::NoRoute)),
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
    let rules = allow_all();
    let configuration = Configuration::new(19, &table, &rules);
    assert_eq!(configuration.generation(), 19);
    assert_eq!(
        configuration.table().interface(PORT0),
        Some(&interfaces()[0])
    );
}

#[test]
fn a_default_pipeline_decides_as_a_new_one_does() {
    let table = router();
    let rules = allow_all();
    let configuration = Configuration::new(GENERATION, &table, &rules);
    let spec = FrameSpec::a_to_b();
    let mut bytes = spec.build();
    let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
    let mut inspection = Inspection::new(PORT0, frame);

    let mut table_of_flows = flows();
    assert_eq!(
        Pipeline::default().evaluate(
            &mut inspection,
            &configuration,
            &mut Tracking::new(&mut table_of_flows, at(0))
        ),
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

// ── The filter ──────────────────────────────────────────────────────────────

/// One rule with every criterion a wildcard, which each case below narrows by
/// exactly one field: what a test proves is then the criterion it set and not the
/// shape of the rule around it.
fn wildcard(action: RuleAction) -> Rule {
    Rule {
        ingress: None,
        egress: None,
        source: None,
        destination: None,
        protocol: None,
        source_port: None,
        destination_port: None,
        icmp_type: None,
        action,
    }
}

fn ruleset(rules: impl IntoIterator<Item = Rule>) -> Ruleset {
    Ruleset::build(rules.into_iter()).expect("the cases here are far inside the capacity")
}

fn prefix(octets: [u8; 4], prefix_length: u8) -> Prefix {
    Prefix::new(Ipv4Address::from_octets(octets), prefix_length)
}

fn port(single: u16) -> PortRange {
    PortRange {
        low: single,
        high: single,
    }
}

/// Put one frame through the whole chain under `rules` and answer with the
/// verdict and what the filter counted.
///
/// Through the chain rather than into [`PolicyStage`] directly, because the stage
/// reads facts the stage in front of it attaches: a filter tested on an
/// inspection somebody assembled by hand would be tested on forwarding nothing
/// derived.
fn filter(rules: &Ruleset, spec: &FrameSpec) -> (Verdict, PolicyCounters) {
    let table = router();
    let mut bytes = spec.build();
    let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
    let mut inspection = Inspection::new(PORT0, frame);
    let mut pipeline = Pipeline::new();
    let mut table_of_flows = flows();
    let verdict = pipeline.evaluate(
        &mut inspection,
        &Configuration::new(GENERATION, &table, rules),
        &mut Tracking::new(&mut table_of_flows, at(0)),
    );
    (verdict, *pipeline.policy_counters())
}

fn verdict_under(rules: &Ruleset, spec: &FrameSpec) -> Verdict {
    filter(rules, spec).0
}

/// The forwarding verdict the routed frame earns when a rule permits it, which
/// every accepting case below is the same value.
fn forwarded() -> Verdict {
    Verdict::Forward {
        egress: PORT1,
        source: GATEWAY1_MAC,
        destination: HOST_B_MAC,
    }
}

/// Default deny is a property of the fallthrough and not of any document: there
/// is no ruleset an operator can write that makes an unmatched frame pass.
#[test]
fn a_frame_no_rule_is_about_is_denied_by_the_fallthrough() {
    let (verdict, counters) = filter(&Ruleset::EMPTY, &FrameSpec::a_to_b());
    assert_eq!(verdict, Verdict::Drop(DropReason::NoPolicyMatch));
    assert_eq!(counters.denied_packets, 1);
    // No rule was matched, so no rule's counter may have moved: the fallthrough
    // is not a rule and has none of its own.
    assert!(counters.all_hits().iter().all(|hits| *hits == 0));

    // The same under a policy that exists and is about something else, so the
    // reason is the fallthrough rather than the absence of a document.
    let elsewhere = ruleset([Rule {
        destination_port: Some(port(9999)),
        ..wildcard(RuleAction::Accept)
    }]);
    let (verdict, counters) = filter(&elsewhere, &FrameSpec::a_to_b());
    assert_eq!(verdict, Verdict::Drop(DropReason::NoPolicyMatch));
    assert_eq!(counters.hits(0), 0);
}

/// The two refusals a filter can reach are two facts, not one: a rule that says
/// drop names itself, and the fallthrough cannot.
#[test]
fn a_rule_that_drops_and_the_fallthrough_are_different_findings() {
    let denying = ruleset([wildcard(RuleAction::Drop)]);
    let (verdict, counters) = filter(&denying, &FrameSpec::a_to_b());
    assert_eq!(verdict, Verdict::Drop(DropReason::PolicyDenied));
    assert_eq!(counters.hits(0), 1);
    assert_eq!(counters.denied_packets, 1);
    assert_ne!(DropReason::PolicyDenied, DropReason::NoPolicyMatch);
}

/// First match wins in document order, so a rule's line number is its
/// precedence and a later rule cannot undo an earlier one's verdict.
#[test]
fn the_first_matching_rule_decides_and_the_rest_are_not_consulted() {
    for (first, second, expected, hit) in [
        (RuleAction::Accept, RuleAction::Drop, forwarded(), 0),
        (
            RuleAction::Drop,
            RuleAction::Accept,
            Verdict::Drop(DropReason::PolicyDenied),
            0,
        ),
    ] {
        let rules = ruleset([wildcard(first), wildcard(second)]);
        let (verdict, counters) = filter(&rules, &FrameSpec::a_to_b());
        assert_eq!(verdict, expected, "{first:?} before {second:?}");
        assert_eq!(counters.hits(hit), 1, "the rule that decided it");
        assert_eq!(counters.hits(1 - hit), 0, "a rule that was never reached");
    }
}

/// Every criterion, each one narrowing a wildcard rule by itself: the matching
/// value permits the frame and a neighbouring value leaves it to the default
/// deny. One case per field, so a criterion compared against the wrong header
/// field fails here rather than in a scenario.
#[test]
fn each_criterion_matches_its_own_field_and_nothing_else() {
    let matching = FrameSpec::a_to_b();
    for (what, hits, misses) in [
        (
            "ingress",
            Rule {
                ingress: Some(PORT0),
                ..wildcard(RuleAction::Accept)
            },
            Rule {
                ingress: Some(PORT1),
                ..wildcard(RuleAction::Accept)
            },
        ),
        (
            "egress",
            Rule {
                egress: Some(PORT1),
                ..wildcard(RuleAction::Accept)
            },
            Rule {
                egress: Some(PORT0),
                ..wildcard(RuleAction::Accept)
            },
        ),
        (
            "source",
            Rule {
                source: Some(prefix([10, 0, 0, 0], 24)),
                ..wildcard(RuleAction::Accept)
            },
            Rule {
                source: Some(prefix([10, 0, 1, 0], 24)),
                ..wildcard(RuleAction::Accept)
            },
        ),
        (
            "destination",
            Rule {
                destination: Some(prefix([10, 0, 1, 0], 24)),
                ..wildcard(RuleAction::Accept)
            },
            Rule {
                destination: Some(prefix([10, 0, 0, 0], 24)),
                ..wildcard(RuleAction::Accept)
            },
        ),
        (
            "protocol",
            Rule {
                protocol: Some(Protocol::UDP),
                ..wildcard(RuleAction::Accept)
            },
            Rule {
                protocol: Some(Protocol::TCP),
                ..wildcard(RuleAction::Accept)
            },
        ),
        (
            "source port",
            Rule {
                source_port: Some(port(4444)),
                ..wildcard(RuleAction::Accept)
            },
            Rule {
                source_port: Some(port(4445)),
                ..wildcard(RuleAction::Accept)
            },
        ),
        (
            "destination port",
            Rule {
                destination_port: Some(port(5000)),
                ..wildcard(RuleAction::Accept)
            },
            Rule {
                destination_port: Some(port(5001)),
                ..wildcard(RuleAction::Accept)
            },
        ),
    ] {
        assert_eq!(
            verdict_under(&ruleset([hits]), &matching),
            forwarded(),
            "the {what} criterion did not match the value it names"
        );
        assert_eq!(
            verdict_under(&ruleset([misses]), &matching),
            Verdict::Drop(DropReason::NoPolicyMatch),
            "the {what} criterion matched a value it does not name"
        );
    }
}

/// A range is inclusive at both ends, and one port past either end is outside
/// it. An off-by-one here is an `accept` covering a port an operator did not
/// write, which is the direction that matters.
#[test]
fn a_port_range_covers_its_ends_and_nothing_past_them() {
    let rules = ruleset([Rule {
        destination_port: Some(PortRange {
            low: 5000,
            high: 5002,
        }),
        ..wildcard(RuleAction::Accept)
    }]);
    for (destination, permitted) in [
        (4999, false),
        (5000, true),
        (5001, true),
        (5002, true),
        (5003, false),
    ] {
        let spec = FrameSpec::carrying(TransportSpec::Udp {
            source: 4444,
            destination,
        });
        let expected = if permitted {
            forwarded()
        } else {
            Verdict::Drop(DropReason::NoPolicyMatch)
        };
        assert_eq!(verdict_under(&rules, &spec), expected, "port {destination}");
    }
}

/// A prefix compares the bits its length names and no others, and a block written
/// with host bits set covers the same addresses as its canonical form: the
/// configuration refuses one either way, and the dataplane is total whatever it
/// is handed.
#[test]
fn a_prefix_compares_the_bits_its_length_names() {
    for (network, length, permitted) in [
        ([10, 0, 1, 0], 24, true),
        // The same block written with a host bit set, which masks to the same
        // network — so it must decide the frame the same way.
        ([10, 0, 1, 99], 24, true),
        ([10, 0, 1, 2], 32, true),
        ([10, 0, 1, 3], 32, false),
        ([10, 0, 0, 0], 16, true),
        // Two lengths that are not byte-aligned, so the mask is exercised rather
        // than the octet comparison a wrong implementation would agree with:
        // 10.0.0.0/23 reaches 10.0.1.255 and covers the destination, and
        // 10.0.1.128/25 starts above it and does not.
        ([10, 0, 0, 0], 23, true),
        ([10, 0, 1, 128], 25, false),
        // A zero-length prefix covers everything, which is the one length that
        // makes a stated criterion equivalent to the wildcard.
        ([0, 0, 0, 0], 0, true),
    ] {
        let rules = ruleset([Rule {
            destination: Some(prefix(network, length)),
            ..wildcard(RuleAction::Accept)
        }]);
        let expected = if permitted {
            forwarded()
        } else {
            Verdict::Drop(DropReason::NoPolicyMatch)
        };
        assert_eq!(
            verdict_under(&rules, &FrameSpec::a_to_b()),
            expected,
            "{network:?}/{length}"
        );
    }
}

/// The property the whole filter rests on: a criterion cannot be satisfied by a
/// header nobody read.
///
/// Five transport shapes carry no port and no ICMP type — two truncations short
/// of any header's length, a non-initial fragment, and a protocol this build does
/// not break down — and a port or type criterion must match none of them. On an
/// appliance that denies what nothing matched, the dangerous half of getting this
/// wrong is the `accept` written for a port carrying a packet whose port was
/// never parsed.
#[test]
fn a_transport_nobody_read_matches_no_port_and_no_type() {
    let unreadable = [
        TransportSpec::Truncated(Protocol::UDP),
        TransportSpec::Truncated(Protocol::TCP),
        TransportSpec::Truncated(Protocol::ICMP),
        TransportSpec::NonInitialFragment,
        TransportSpec::Unparsed(Protocol(99)),
    ];
    let criteria = [
        Rule {
            source_port: Some(port(4444)),
            ..wildcard(RuleAction::Accept)
        },
        Rule {
            destination_port: Some(port(5000)),
            ..wildcard(RuleAction::Accept)
        },
        Rule {
            icmp_type: Some(8),
            ..wildcard(RuleAction::Accept)
        },
        // A wildcard port range, which is the widest a stated criterion can be:
        // even it must not match, because the criterion is *stated* and there is
        // no port to compare.
        Rule {
            destination_port: Some(PortRange {
                low: 0,
                high: u16::MAX,
            }),
            ..wildcard(RuleAction::Accept)
        },
    ];
    for transport in unreadable {
        let spec = FrameSpec::carrying(transport);
        let mut bytes = spec.build();
        let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
        for rule in criteria {
            assert!(
                !rule.matches(PORT0, PORT1, &frame),
                "{transport:?} satisfied a criterion nothing could be read for: {rule:?}"
            );
        }
        // And the criterion is what refused it, not the frame: the same rule
        // without the port matches the same bytes.
        assert!(
            wildcard(RuleAction::Accept).matches(PORT0, PORT1, &frame),
            "{transport:?} was refused by a rule that states no criterion"
        );
        // Through the whole chain none of them reaches the filter at all, which
        // is the stronger posture the tracker added in front of it: a datagram
        // whose transport nobody could read is not one a flow can be kept for,
        // so it is settled before a rule is consulted rather than forwarded by
        // a rule that states no port. The reason names which shape it was.
        let expected = match transport {
            TransportSpec::Truncated(_) => DropReason::FlowMalformed,
            TransportSpec::NonInitialFragment => DropReason::FlowFragment,
            TransportSpec::Unparsed(_) => DropReason::FlowUnsupportedProtocol,
            TransportSpec::Udp { .. } | TransportSpec::Tcp { .. } | TransportSpec::Icmp { .. } => {
                unreachable!("every shape here is one nobody could read")
            }
        };
        assert_eq!(
            verdict_under(&ruleset([wildcard(RuleAction::Accept)]), &spec),
            Verdict::Drop(expected),
            "{transport:?} reached the filter"
        );
    }
}

/// An ICMP type criterion answers from the ICMP header and from no other
/// protocol's first byte, which is where a naive implementation reads it from.
#[test]
fn an_icmp_type_criterion_matches_only_icmp() {
    let rules = ruleset([Rule {
        icmp_type: Some(8),
        ..wildcard(RuleAction::Accept)
    }]);
    assert_eq!(
        verdict_under(
            &rules,
            &FrameSpec::carrying(TransportSpec::Icmp { message_type: 8 })
        ),
        forwarded()
    );
    // The same echo request under a rule stating a different type. An echo
    // *reply* would say the same thing about the criterion and never reach the
    // filter to say it: with no flow to answer, the tracker settles it first.
    assert_eq!(
        verdict_under(
            &ruleset([Rule {
                icmp_type: Some(0),
                ..wildcard(RuleAction::Accept)
            }]),
            &FrameSpec::carrying(TransportSpec::Icmp { message_type: 8 })
        ),
        Verdict::Drop(DropReason::NoPolicyMatch)
    );
    // A TCP segment whose first header byte happens to be 8: the criterion must
    // not be answered from it.
    assert_eq!(
        verdict_under(
            &rules,
            &FrameSpec::carrying(TransportSpec::Tcp {
                source: 8,
                destination: 5000,
            })
        ),
        Verdict::Drop(DropReason::NoPolicyMatch)
    );
}

/// A TCP segment's ports are read from the TCP header, so a rule written for a
/// port is about both transports that carry one and neither is mistaken for the
/// other.
#[test]
fn a_tcp_segments_ports_are_matched_as_tcps() {
    let rules = ruleset([Rule {
        protocol: Some(Protocol::TCP),
        destination_port: Some(port(443)),
        ..wildcard(RuleAction::Accept)
    }]);
    assert_eq!(
        verdict_under(
            &rules,
            &FrameSpec::carrying(TransportSpec::Tcp {
                source: 4444,
                destination: 443,
            })
        ),
        forwarded()
    );
    // The same port over UDP, which the protocol criterion excludes.
    assert_eq!(
        verdict_under(
            &rules,
            &FrameSpec::carrying(TransportSpec::Udp {
                source: 4444,
                destination: 443,
            })
        ),
        Verdict::Drop(DropReason::NoPolicyMatch)
    );
}

/// Byte totals are the datagram's own IPv4 total length, split by verdict — what
/// a link's throughput is comparable against, and not the frame length, which
/// carries whatever padding a driver added.
#[test]
fn the_filter_counts_packets_and_datagram_bytes_by_verdict() {
    let permissive = ruleset([wildcard(RuleAction::Accept)]);
    let spec = FrameSpec::a_to_b();
    let datagram = u64::from((IPV4_HEADER_LEN + UDP_HEADER_LEN + 6) as u16);

    let table = router();
    let mut pipeline = Pipeline::new();
    for _ in 0..3 {
        let mut bytes = spec.build();
        let frame = Frame::parse(&mut bytes).expect("well formed");
        let mut inspection = Inspection::new(PORT0, frame);
        let mut table_of_flows = flows();
        pipeline.evaluate(
            &mut inspection,
            &Configuration::new(GENERATION, &table, &permissive),
            &mut Tracking::new(&mut table_of_flows, at(0)),
        );
    }
    let counters = pipeline.policy_counters();
    assert_eq!(counters.accepted_packets(), 3);
    assert_eq!(counters.accepted_bytes(), 3 * datagram);
    assert_eq!(counters.denied_packets(), 0);
    assert_eq!(counters.denied_bytes(), 0);
    assert_eq!(counters.hits(0), 3);

    let denying = ruleset([wildcard(RuleAction::Drop)]);
    let (_, counters) = filter(&denying, &spec);
    assert_eq!(counters.denied_packets, 1);
    assert_eq!(counters.denied_bytes, datagram);
    assert_eq!(counters.accepted_packets, 0);
    assert_eq!(counters.accepted_bytes, 0);
}

/// A counter belongs to the position its rule sits at, which is what makes the id
/// the management domain joins to it that rule's own.
#[test]
fn a_hit_is_counted_against_the_position_of_the_rule_that_matched() {
    let rules = ruleset([
        Rule {
            destination_port: Some(port(5001)),
            ..wildcard(RuleAction::Drop)
        },
        Rule {
            destination_port: Some(port(5002)),
            ..wildcard(RuleAction::Drop)
        },
        Rule {
            destination_port: Some(port(5000)),
            ..wildcard(RuleAction::Accept)
        },
    ]);
    let (verdict, counters) = filter(&rules, &FrameSpec::a_to_b());
    assert_eq!(verdict, forwarded());
    assert_eq!(counters.hits(0), 0);
    assert_eq!(counters.hits(1), 0);
    assert_eq!(counters.hits(2), 1);
    // A position past the running policy, and one past the array: both answer
    // zero rather than panicking, a counter being nothing to fault a domain over.
    assert_eq!(counters.hits(3), 0);
    assert_eq!(counters.hits(MAX_RULES), 0);
    assert_eq!(counters.hits(usize::MAX), 0);
}

/// Every counter saturates, on `DropCounters`' terms: a wrap forges a negative
/// rate between two scrapes.
#[test]
fn a_policy_counter_saturates_rather_than_wrapping() {
    let mut counters = PolicyCounters::new();
    counters.hits[0] = u64::MAX;
    counters.accepted_packets = u64::MAX;
    counters.accepted_bytes = u64::MAX;
    for _ in 0..3 {
        counters.record(Some(0), RuleAction::Accept, 1500);
    }
    assert_eq!(counters.hits(0), u64::MAX);
    assert_eq!(counters.accepted_packets(), u64::MAX);
    assert_eq!(counters.accepted_bytes(), u64::MAX);

    counters.denied_packets = u64::MAX;
    counters.denied_bytes = u64::MAX;
    counters.record(None, RuleAction::Drop, 1500);
    assert_eq!(counters.denied_packets(), u64::MAX);
    assert_eq!(counters.denied_bytes(), u64::MAX);
    assert_eq!(PolicyCounters::default(), PolicyCounters::new());
}

/// A ruleset refuses the rule past its capacity rather than truncating: a policy
/// silently missing its last rules denies what it was written to allow, or worse.
#[test]
fn a_ruleset_refuses_one_rule_past_its_capacity() {
    assert!(Ruleset::EMPTY.is_empty());
    assert_eq!(Ruleset::EMPTY.len(), 0);
    assert_eq!(Ruleset::default(), Ruleset::EMPTY);

    let full = ruleset(core::iter::repeat_n(
        wildcard(RuleAction::Accept),
        MAX_RULES,
    ));
    assert_eq!(full.len(), MAX_RULES);
    assert!(!full.is_empty());
    assert_eq!(
        Ruleset::build(core::iter::repeat_n(
            wildcard(RuleAction::Accept),
            MAX_RULES + 1
        )),
        Err(RulesetFull {
            requested: MAX_RULES + 1,
            capacity: MAX_RULES,
        })
    );
}

/// The filter is consulted only for a frame the stage in front of it resolved, so
/// a frame the routing stage settles is refused under *its* reason and never
/// reaches a rule.
#[test]
fn a_frame_the_routing_stage_settles_never_reaches_a_rule() {
    let permissive = ruleset([wildcard(RuleAction::Accept)]);
    let unroutable = FrameSpec {
        destination: Ipv4Address::from_octets([192, 0, 2, 9]),
        ..FrameSpec::a_to_b()
    };
    let (verdict, counters) = filter(&permissive, &unroutable);
    assert_eq!(verdict, Verdict::Drop(DropReason::NoRoute));
    assert_eq!(counters.hits(0), 0, "a rule was consulted for it");
    assert_eq!(counters.denied_packets, 0, "the filter counted it");
    assert_eq!(counters.accepted_packets, 0);
}

/// The one thing a filter must never do when it cannot tell: permit.
///
/// Unreachable through the chain — the stage in front settles every frame whose
/// forwarding it cannot resolve — so the stage is driven directly, which is the
/// only way to hand it an inspection with nothing attached.
#[test]
fn a_filter_asked_about_a_frame_with_no_forwarding_denies_it() {
    let table = router();
    let permissive = ruleset([wildcard(RuleAction::Accept)]);
    let spec = FrameSpec::a_to_b();
    let mut bytes = spec.build();
    let frame = Frame::parse(&mut bytes).expect("well formed");
    let mut inspection = Inspection::new(PORT0, frame);
    assert_eq!(inspection.forwarding(), None);

    let mut stage = PolicyStage::new();
    assert_eq!(
        stage.evaluate(
            &mut inspection,
            &Configuration::new(GENERATION, &table, &permissive)
        ),
        Verdict::Drop(DropReason::NoPolicyMatch)
    );
    // Nothing was counted: there was no packet the filter could attribute a
    // verdict to, and a default stage reports as a new one does.
    assert_eq!(*stage.counters(), PolicyCounters::new());
    assert_eq!(
        *PolicyStage::default().counters(),
        *PolicyStage::new().counters()
    );
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

// ── Connection tracking: the two halves that bracket the filter ─────────────

/// One appliance across several frames: the connection table persists, which is
/// the whole point, so a test can send a request and then its reply.
struct Bench {
    table: Router<2, 2>,
    pipeline: Pipeline,
    flows: Flows,
    nanos: u64,
}

impl Bench {
    fn new() -> Self {
        Self {
            table: router(),
            pipeline: Pipeline::new(),
            flows: FlowTable::new(),
            nanos: 0,
        }
    }

    /// Put one frame through the whole chain under `rules`, advancing the clock
    /// by a microsecond so successive packets are ordered without ever
    /// approaching a timeout.
    fn send(&mut self, rules: &Ruleset, spec: &FrameSpec, ingress: PortId) -> Verdict {
        self.nanos += 1_000;
        let mut bytes = spec.build();
        let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
        let mut inspection = Inspection::new(ingress, frame);
        self.pipeline.evaluate(
            &mut inspection,
            &Configuration::new(GENERATION, &self.table, rules),
            &mut Tracking::new(&mut self.flows, at(self.nanos)),
        )
    }

    /// The same, keeping the facts the chain attached rather than the verdict
    /// alone — which is what an observer outside the chain reads.
    fn decide(&mut self, rules: &Ruleset, spec: &FrameSpec, ingress: PortId) -> Decided {
        self.nanos += 1_000;
        let mut bytes = spec.build();
        let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
        let mut inspection = Inspection::new(ingress, frame);
        let verdict = self.pipeline.evaluate(
            &mut inspection,
            &Configuration::new(GENERATION, &self.table, rules),
            &mut Tracking::new(&mut self.flows, at(self.nanos)),
        );
        Decided {
            verdict,
            flow: inspection.flow(),
            refusal: inspection.refusal(),
            matched: inspection.matched(),
        }
    }

    fn counters(&self) -> &lfw_flow::FlowCounters {
        self.flows.counters()
    }
}

/// What one evaluation left behind.
#[derive(Debug)]
struct Decided {
    verdict: Verdict,
    flow: Option<FlowObservation>,
    refusal: Option<lfw_flow::RefusalKind>,
    matched: Option<usize>,
}

/// **An evaluation says why, not only what.** A [`Verdict`] cannot carry which
/// conversation a frame belonged to, what the packet did to it, or which rule
/// decided it, and those three are the whole of what makes a recording a
/// connection history rather than a second copy of the traffic.
///
/// One request and its reply, which is the smallest exchange that reaches two
/// different transitions and shows the rule appearing on exactly one of them.
#[test]
fn an_evaluation_leaves_the_flow_the_transition_and_the_rule_behind_it() {
    let rules = ruleset([Rule {
        destination_port: Some(port(5000)),
        ..wildcard(RuleAction::Accept)
    }]);
    let mut bench = Bench::new();

    let opening = bench.decide(&rules, &request(5000), PORT0);
    assert_eq!(opening.verdict, forwarded());
    let flow = opening.flow.expect("the request opened a conversation");
    assert_eq!(flow.classification, Classification::New);
    assert_eq!(flow.state, FlowState::UdpUnreplied);
    assert_eq!(flow.transition, FlowTransition::Opened);
    assert_eq!(opening.refusal, None);
    // The filter is consulted on the packet that opens a conversation, and this
    // is the rule it matched.
    assert_eq!(opening.matched, Some(0));

    let answered = bench.decide(&rules, &reply(5000), PORT1);
    assert_eq!(answered.verdict, forwarded_back());
    let advanced = answered
        .flow
        .expect("the reply belongs to the conversation");
    assert_eq!(advanced.id, flow.id, "the same conversation, by identity");
    assert_eq!(advanced.classification, Classification::Established);
    assert_eq!(advanced.state, FlowState::UdpAssured);
    assert_eq!(advanced.transition, FlowTransition::Advanced);
    // And no rule: the tracker settled it in front of the filter.
    assert_eq!(answered.matched, None);

    // A second reply moves nothing, which is the transition that keeps a
    // connection history from becoming a packet log.
    let again = bench.decide(&rules, &reply(5000), PORT1);
    assert_eq!(
        again.flow.map(|flow| flow.transition),
        Some(FlowTransition::Held)
    );
    assert_eq!(again.matched, None);
}

/// A tracker refusal and a routing refusal both leave no conversation, and the
/// refusal is what tells them apart — which is what an observer needs, the two
/// being different things to go and do.
#[test]
fn a_tracker_refusal_is_distinguishable_from_a_routing_refusal() {
    let rules = allow_all();
    let mut bench = Bench::new();

    // A protocol the tracker holds no state for: refused before the filter, so
    // there is no conversation to name.
    let unsupported = bench.decide(
        &rules,
        &FrameSpec::carrying(TransportSpec::Unparsed(Protocol(89))),
        PORT0,
    );
    assert_eq!(
        unsupported.verdict,
        Verdict::Drop(DropReason::FlowUnsupportedProtocol)
    );
    assert_eq!(unsupported.flow, None);
    assert_eq!(
        unsupported.refusal,
        Some(lfw_flow::RefusalKind::UnsupportedProtocol)
    );

    let expiring = bench.decide(
        &rules,
        &FrameSpec {
            ttl: 1,
            ..request(5000)
        },
        PORT0,
    );
    assert_eq!(expiring.verdict, Verdict::Drop(DropReason::TtlExpired));
    assert_eq!(expiring.flow, None);
    assert_eq!(
        expiring.refusal, None,
        "the tracker was never reached, so it answered nothing"
    );
    assert_eq!(expiring.matched, None);
}

/// A denied opening still names the conversation it opened and the rule that
/// denied it, although the flow has been withdrawn — so a reader sees the slot
/// was given back rather than held by traffic the policy refused.
#[test]
fn a_denied_opening_names_the_flow_it_withdrew_and_the_rule_that_denied_it() {
    let rules = ruleset([Rule {
        destination_port: Some(port(5000)),
        ..wildcard(RuleAction::Drop)
    }]);
    let mut bench = Bench::new();

    let denied = bench.decide(&rules, &request(5000), PORT0);
    assert_eq!(denied.verdict, Verdict::Drop(DropReason::PolicyDenied));
    assert_eq!(
        denied.flow.map(|flow| flow.transition),
        Some(FlowTransition::Opened)
    );
    assert_eq!(denied.matched, Some(0));
    assert_eq!(bench.counters().flows_withdrawn, 1);

    // And the fallthrough, which names no rule at all.
    let unmatched = bench.decide(&Ruleset::EMPTY, &request(5000), PORT0);
    assert_eq!(unmatched.verdict, Verdict::Drop(DropReason::NoPolicyMatch));
    assert_eq!(
        unmatched.flow.map(|flow| flow.transition),
        Some(FlowTransition::Opened)
    );
    assert_eq!(unmatched.matched, None);
    assert_eq!(bench.counters().flows_withdrawn, 2);
}

/// A request from A to B on `destination_port`, and the reply B sends back to
/// the port the request came from — the ordinary shape of a conversation, and
/// the one a stateless filter cannot carry without a rule for each half.
fn request(destination_port: u16) -> FrameSpec {
    FrameSpec {
        transport: TransportSpec::Udp {
            source: 4444,
            destination: destination_port,
        },
        ..FrameSpec::a_to_b()
    }
}

fn reply(destination_port: u16) -> FrameSpec {
    FrameSpec {
        destination_mac: GATEWAY1_MAC,
        source_mac: HOST_B_MAC,
        source: host_b(),
        destination: host_a(),
        transport: TransportSpec::Udp {
            source: destination_port,
            destination: 4444,
        },
        ..FrameSpec::a_to_b()
    }
}

/// The verdict a frame from B to A earns when it is forwarded.
fn forwarded_back() -> Verdict {
    Verdict::Forward {
        egress: PORT0,
        source: GATEWAY0_MAC,
        destination: HOST_A_MAC,
    }
}

/// **The property the whole landing exists for.** A reply is forwarded although
/// no rule permits it: the only rule is about the forward direction, and the
/// reply is carried because the tracker recognises the conversation it belongs
/// to. The counters say which mechanism did it — the flow was advanced, and the
/// filter was never asked.
#[test]
fn a_reply_is_carried_by_the_flow_and_not_by_a_rule() {
    let rules = ruleset([Rule {
        destination_port: Some(port(5000)),
        ..wildcard(RuleAction::Accept)
    }]);
    let mut bench = Bench::new();

    assert_eq!(bench.send(&rules, &request(5000), PORT0), forwarded());
    assert_eq!(bench.counters().flows_created, 1);

    // No rule is about a datagram to port 4444, in either direction.
    assert_eq!(bench.send(&rules, &reply(5000), PORT1), forwarded_back());
    assert_eq!(
        bench.counters().packets_established,
        1,
        "the reply was not classified as belonging to the flow"
    );
    // And the filter counted it under neither verdict, because it was never
    // consulted: one accepted packet, which is the request.
    assert_eq!(bench.pipeline.policy_counters().accepted_packets(), 1);
    assert_eq!(bench.pipeline.policy_counters().denied_packets(), 0);
    assert_eq!(bench.pipeline.policy_counters().hits(0), 1);
}

/// The same reply with no request in front of it is denied, and the two are
/// distinguishable: one is `Established` and forwarded, the other opens a flow
/// nothing permits and is dropped by the default deny.
#[test]
fn an_unsolicited_reply_direction_packet_is_denied() {
    let rules = ruleset([Rule {
        destination_port: Some(port(5000)),
        ..wildcard(RuleAction::Accept)
    }]);
    let mut bench = Bench::new();

    assert_eq!(
        bench.send(&rules, &reply(5000), PORT1),
        Verdict::Drop(DropReason::NoPolicyMatch)
    );
    assert_eq!(bench.counters().packets_established, 0);
    assert_eq!(bench.pipeline.policy_counters().denied_packets(), 1);
}

/// **The withdrawal, end to end.** A denied opening packet leaves no state: the
/// slot the classification took is given back, so a stream of them cannot fill
/// the table. Without it, a default-deny policy is a state-exhaustion
/// amplifier.
#[test]
fn a_denied_opening_leaves_no_flow_behind() {
    let rules = ruleset([Rule {
        destination_port: Some(port(5000)),
        ..wildcard(RuleAction::Accept)
    }]);
    let mut bench = Bench::new();

    // Far more attempts than the table has slots.
    for index in 0..64u16 {
        let spec = FrameSpec {
            transport: TransportSpec::Udp {
                source: 40_000 + index,
                destination: 5001,
            },
            ..FrameSpec::a_to_b()
        };
        assert_eq!(
            bench.send(&rules, &spec, PORT0),
            Verdict::Drop(DropReason::NoPolicyMatch)
        );
        assert_eq!(bench.flows.len(), 0, "a denied opening kept its slot");
    }
    assert_eq!(bench.counters().flows_created, 64);
    assert_eq!(bench.counters().flows_withdrawn, 64);
    assert_eq!(
        bench.counters().refused_table_full,
        0,
        "the table filled with connections the policy had refused"
    );
    // And the appliance still admits a permitted connection afterwards, which
    // is what the exhaustion would have cost.
    assert_eq!(bench.send(&rules, &request(5000), PORT0), forwarded());
}

/// A permitted opening keeps its flow: withdrawal is the refusal's consequence
/// and not something every classification pays.
#[test]
fn a_permitted_opening_keeps_its_flow() {
    let rules = ruleset([Rule {
        destination_port: Some(port(5000)),
        ..wildcard(RuleAction::Accept)
    }]);
    let mut bench = Bench::new();
    assert_eq!(bench.send(&rules, &request(5000), PORT0), forwarded());
    assert_eq!(bench.flows.len(), 1);
    assert_eq!(bench.counters().flows_withdrawn, 0);
}

/// **A rule change does not break a live connection.** The rule that admitted
/// the conversation is withdrawn entirely and the reply still arrives, because
/// the filter is not consulted for a packet an existing flow accounts for. What
/// the edit stops is the *next* connection.
#[test]
fn narrowing_the_policy_does_not_cut_a_live_connection() {
    let permits = ruleset([Rule {
        destination_port: Some(port(5000)),
        ..wildcard(RuleAction::Accept)
    }]);
    let mut bench = Bench::new();
    assert_eq!(bench.send(&permits, &request(5000), PORT0), forwarded());

    let nothing = Ruleset::EMPTY;
    assert_eq!(bench.send(&nothing, &reply(5000), PORT1), forwarded_back());
    assert_eq!(
        bench.send(&nothing, &request(5000), PORT0),
        forwarded(),
        "the forward direction of a live flow is carried too"
    );
    // A conversation that has not started yet is refused under the new policy.
    assert_eq!(
        bench.send(&nothing, &request(5002), PORT0),
        Verdict::Drop(DropReason::NoPolicyMatch)
    );
}

/// A mid-stream TCP segment for a five-tuple nothing opened is refused as such
/// rather than adopted. Adopting one is a way around default deny that costs an
/// attacker a single packet, and the reason it earns says which shape it was.
#[test]
fn a_mid_stream_segment_for_an_unknown_flow_is_refused() {
    let permissive = ruleset([wildcard(RuleAction::Accept)]);
    let mut bench = Bench::new();
    let spec = FrameSpec::carrying(TransportSpec::Tcp {
        source: 4444,
        destination: 443,
    });
    let mut bytes = spec.build();
    // Clear the `SYN` the spec sets, leaving a bare `ACK`: a segment from the
    // middle of a conversation this appliance never saw begin.
    let offset = bytes.len() - TCP_HEADER_LEN + 13;
    bytes[offset] = 0x10;
    let frame = Frame::parse(&mut bytes).expect("the spec builds a well-formed frame");
    let mut inspection = Inspection::new(PORT0, frame);
    let verdict = bench.pipeline.evaluate(
        &mut inspection,
        &Configuration::new(GENERATION, &bench.table, &permissive),
        &mut Tracking::new(&mut bench.flows, at(1_000)),
    );
    assert_eq!(verdict, Verdict::Drop(DropReason::FlowMidStream));
    assert_eq!(bench.counters().refused_mid_stream, 1);
    assert_eq!(bench.flows.len(), 0);
}

/// Every refusal the tracker can reach is reported as a drop reason of its own,
/// and no two share one: a refusal an operator sees is attributable to what the
/// packet did rather than to a category.
#[test]
fn every_tracker_refusal_has_its_own_drop_reason() {
    let reasons: Vec<DropReason> = lfw_flow::RefusalKind::ALL
        .into_iter()
        .map(DropReason::of_refusal)
        .collect();
    for (position, reason) in reasons.iter().enumerate() {
        assert!(
            DropReason::ALL.contains(reason),
            "{reason} is not in the reason vocabulary"
        );
        assert!(
            reasons
                .iter()
                .enumerate()
                .all(|(other, candidate)| other == position || candidate != reason),
            "{reason} is named by two refusals"
        );
    }
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
            transport: FrameSpec::a_to_b().transport,
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
            transport: FrameSpec::a_to_b().transport,
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
            transport: FrameSpec::a_to_b().transport,
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
        let rules = allow_all();
        let configuration = Configuration::new(GENERATION, &table, &rules);
        let spec = FrameSpec {
            destination_mac: MacAddress(destination_mac),
            source_mac: HOST_A_MAC,
            source,
            destination,
            ttl,
            vlan: tagged.then_some(0x0064),
            transport: FrameSpec::a_to_b().transport,
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
                if let Step::Settled(Verdict::Drop(reason)) =
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
