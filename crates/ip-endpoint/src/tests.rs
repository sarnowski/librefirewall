use super::*;

use net_headers::{
    ARP_FRAME_LEN, ARP_PAYLOAD_LEN, ETHERNET_HEADER_LEN, ICMP_ECHO_HEADER_LEN, IPV4_HEADER_LEN,
    MAC_PAIR_LEN, MIN_ECHO_REPLY_LEN,
};
use proptest::prelude::*;
use std::{vec, vec::Vec};

const OUR_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x52]);
const OUR_ADDRESS: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 15]);
const PREFIX: u8 = 24;
const STATION_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0c]);
const STATION_ADDRESS: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 2]);
const OFF_LINK: Ipv4Address = Ipv4Address::from_octets([10, 0, 9, 2]);

/// Storage a reply always fits in, so a test that did not set out to exercise
/// the refusal path does not.
const ROOMY: usize = 2048;

/// A per-boot secret for the initial sequence numbers. Fixed here so a test is
/// deterministic; in the protection domain it comes from `RDRAND`.
const SECRET: [u8; 16] = [
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

fn secret() -> IsnSecret {
    IsnSecret::from_bytes(SECRET)
}

fn endpoint() -> Endpoint {
    Endpoint::new(OUR_MAC, OUR_ADDRESS, PREFIX, secret()).expect("a unicast pair on a /24")
}

/// An instant, built the way this crate's callers build one: a `Monotonic` is
/// only reachable through a `Calibration`.
fn at(nanos: u64) -> Monotonic {
    use core::num::NonZeroU64;
    use lfw_clock::{Calibration, Ticks};
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(nanos))
}

/// An ARP request as a station puts one on the wire: broadcast, 42 bytes.
fn arp_request(
    destination: MacAddress,
    sender_mac: MacAddress,
    sender_address: Ipv4Address,
    target: Ipv4Address,
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&destination.0);
    frame.extend_from_slice(&sender_mac.0);
    frame.extend_from_slice(&EtherType::ARP.0.to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&EtherType::IPV4.0.to_be_bytes());
    frame.push(6);
    frame.push(4);
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&sender_mac.0);
    frame.extend_from_slice(&sender_address.octets());
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&target.octets());
    frame
}

/// The request every ARP test below is one edit from.
fn arp() -> Vec<u8> {
    arp_request(
        MacAddress::BROADCAST,
        STATION_MAC,
        STATION_ADDRESS,
        OUR_ADDRESS,
    )
}

/// The RFC 1071 sum, written independently of the crate under test.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for index in 0..bytes.len().div_ceil(2) {
        let high = bytes[index * 2];
        let low = bytes.get(index * 2 + 1).copied().unwrap_or(0);
        sum += u32::from(u16::from_be_bytes([high, low]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One IPv4 frame as fields, so every test below edits exactly the field it is
/// about and the checksums are always right.
struct Datagram {
    destination_mac: MacAddress,
    source_mac: MacAddress,
    source: Ipv4Address,
    destination: Ipv4Address,
    protocol: Protocol,
    fragment_offset: u16,
    message_type: u8,
    code: u8,
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
    /// Whether the ICMP checksum is the right one, so a corrupt message is a
    /// deliberate edit rather than a side effect of another.
    seal_icmp: bool,
}

impl Datagram {
    /// An echo request from the station to us: what the endpoint exists to
    /// answer.
    fn echo() -> Self {
        Self {
            destination_mac: OUR_MAC,
            source_mac: STATION_MAC,
            source: STATION_ADDRESS,
            destination: OUR_ADDRESS,
            protocol: Protocol::ICMP,
            fragment_offset: 0,
            message_type: 8,
            code: 0,
            identifier: 0x1234,
            sequence: 9,
            payload: b"echo-payload".to_vec(),
            seal_icmp: true,
        }
    }

    fn build(&self) -> Vec<u8> {
        let mut icmp = Vec::new();
        icmp.push(self.message_type);
        icmp.push(self.code);
        icmp.extend_from_slice(&[0, 0]);
        icmp.extend_from_slice(&self.identifier.to_be_bytes());
        icmp.extend_from_slice(&self.sequence.to_be_bytes());
        icmp.extend_from_slice(&self.payload);
        let sum = if self.seal_icmp {
            checksum(&icmp)
        } else {
            0x1234
        };
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());

        let mut frame = Vec::new();
        frame.extend_from_slice(&self.destination_mac.0);
        frame.extend_from_slice(&self.source_mac.0);
        frame.extend_from_slice(&EtherType::IPV4.0.to_be_bytes());
        let mut ip = [0u8; IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((IPV4_HEADER_LEN + icmp.len()) as u16).to_be_bytes());
        ip[6..8].copy_from_slice(&self.fragment_offset.to_be_bytes());
        ip[8] = 64;
        ip[9] = self.protocol.0;
        ip[12..16].copy_from_slice(&self.source.octets());
        ip[16..20].copy_from_slice(&self.destination.octets());
        let sum = checksum(&ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&icmp);
        frame
    }
}

/// Hand one frame to a fresh endpoint, with roomy storage.
fn handle(frame: &[u8]) -> (Outcome, Vec<u8>, EndpointCounters) {
    let mut endpoint = endpoint();
    let mut out = vec![0u8; ROOMY];
    let outcome = endpoint.handle(Some(at(0)), frame, &mut out);
    if let Some(len) = outcome.reply() {
        out.truncate(len);
    } else {
        out.clear();
    }
    (outcome, out, endpoint.counters())
}

#[test]
fn a_configured_pair_no_endpoint_can_answer_under_is_refused() {
    assert_eq!(
        Endpoint::new(MacAddress::BROADCAST, OUR_ADDRESS, PREFIX, secret()).err(),
        Some(EndpointError::MacNotUnicast {
            mac: MacAddress::BROADCAST
        })
    );
    assert_eq!(
        Endpoint::new(MacAddress([0; 6]), OUR_ADDRESS, PREFIX, secret()).err(),
        Some(EndpointError::MacNotUnicast {
            mac: MacAddress([0; 6])
        })
    );
    for octets in [
        [224, 0, 0, 1],
        [255, 255, 255, 255],
        [127, 0, 0, 1],
        [0, 0, 0, 0],
    ] {
        let address = Ipv4Address::from_octets(octets);
        assert_eq!(
            Endpoint::new(OUR_MAC, address, PREFIX, secret()).err(),
            Some(EndpointError::AddressNotUnicast { address })
        );
    }
    for prefix_length in [33u8, 64, 255] {
        assert_eq!(
            Endpoint::new(OUR_MAC, OUR_ADDRESS, prefix_length, secret()).err(),
            Some(EndpointError::PrefixLengthOutOfRange { prefix_length })
        );
    }
    let endpoint =
        Endpoint::new(OUR_MAC, OUR_ADDRESS, 32, secret()).expect("a host route is a prefix");
    assert_eq!(endpoint.mac(), OUR_MAC);
    assert_eq!(endpoint.address(), OUR_ADDRESS);
    assert_eq!(endpoint.prefix_length(), 32);
    assert_eq!(endpoint.counters(), EndpointCounters::new());
    assert_eq!(EndpointCounters::default(), EndpointCounters::new());
}

#[test]
fn an_arp_request_for_our_address_is_answered_with_our_mac() {
    let (outcome, reply, counters) = handle(&arp());
    assert_eq!(outcome, Outcome::ArpReply { len: ARP_FRAME_LEN });
    assert_eq!(counters.arp_replies, 1);
    assert_eq!(counters.replies(), 1);
    assert_eq!(counters.total(), 1);

    let ethernet = Ethernet::parse(&reply).expect("a reply is a frame");
    assert_eq!(ethernet.header.destination, STATION_MAC);
    assert_eq!(ethernet.header.source, OUR_MAC);
    assert_eq!(ethernet.header.ether_type, EtherType::ARP);
    let packet = ArpPacket::parse(ethernet.payload).expect("an ARP packet");
    assert_eq!(packet.operation, ArpOperation::Reply);
    assert_eq!(packet.sender_mac, OUR_MAC);
    assert_eq!(packet.sender_address, OUR_ADDRESS);
    assert_eq!(packet.target_mac, STATION_MAC);
    assert_eq!(packet.target_address, STATION_ADDRESS);
}

/// A request addressed to our own MAC rather than to broadcast is still ours:
/// a station that already knows the answer may re-ask.
#[test]
fn a_unicast_arp_request_is_answered_too() {
    let frame = arp_request(OUR_MAC, STATION_MAC, STATION_ADDRESS, OUR_ADDRESS);
    assert_eq!(handle(&frame).0, Outcome::ArpReply { len: ARP_FRAME_LEN });
}

#[test]
fn an_arp_request_for_somebody_elses_address_is_not_ours_to_answer() {
    let frame = arp_request(
        MacAddress::BROADCAST,
        STATION_MAC,
        STATION_ADDRESS,
        Ipv4Address::from_octets([10, 0, 2, 99]),
    );
    let (outcome, reply, counters) = handle(&frame);
    assert_eq!(outcome, Outcome::NotForUs);
    assert!(reply.is_empty());
    assert_eq!(counters.not_for_us, 1);
    assert_eq!(counters.replies(), 0);
}

/// A frame addressed to another station's MAC is another station's, whatever it
/// carries — the one exception being the broadcast a request uses.
#[test]
fn a_frame_addressed_to_another_station_is_never_answered() {
    let foreign = MacAddress([0x52, 0x54, 0x00, 0x99, 0x99, 0x99]);
    let arp = arp_request(foreign, STATION_MAC, STATION_ADDRESS, OUR_ADDRESS);
    assert_eq!(handle(&arp).0, Outcome::NotForUs);

    let echo = Datagram {
        destination_mac: foreign,
        ..Datagram::echo()
    }
    .build();
    assert_eq!(handle(&echo).0, Outcome::NotForUs);

    // Nor is a broadcast datagram delivered locally, unlike a broadcast ARP.
    let broadcast = Datagram {
        destination_mac: MacAddress::BROADCAST,
        ..Datagram::echo()
    }
    .build();
    assert_eq!(handle(&broadcast).0, Outcome::NotForUs);
}

#[test]
fn an_arp_reply_is_not_a_request_and_is_answered_by_nothing() {
    let mut frame = arp();
    frame[ETHERNET_HEADER_LEN + 6..ETHERNET_HEADER_LEN + 8].copy_from_slice(&2u16.to_be_bytes());
    let (outcome, reply, counters) = handle(&frame);
    assert_eq!(outcome, Outcome::Unhandled(Unhandled::ArpNotARequest));
    assert!(reply.is_empty());
    assert_eq!(counters.unhandled(Unhandled::ArpNotARequest), 1);
    assert_eq!(counters.unhandled_total(), 1);
}

#[test]
fn an_arp_request_naming_a_sender_other_than_its_own_source_is_answered_by_nothing() {
    // Found by the `ip_endpoint` fuzz target: the reply was aimed at the
    // payload's `sender_mac`, so a station could name a third one and have this
    // port emit a frame to it.
    let mut frame = arp();
    frame[MAC_PAIR_LEN / 2..MAC_PAIR_LEN].copy_from_slice(&[0x52, 0x54, 0x10, 0x00, 0x00, 0x0c]);
    let (outcome, reply, counters) = handle(&frame);
    assert_eq!(outcome, Outcome::Unhandled(Unhandled::ArpSenderMacMismatch));
    assert!(reply.is_empty());
    assert_eq!(counters.unhandled(Unhandled::ArpSenderMacMismatch), 1);
    assert_eq!(counters.unhandled_total(), 1);
}

#[test]
fn an_echo_request_for_our_address_is_answered_with_the_same_echo() {
    let request = Datagram::echo();
    let (outcome, reply, counters) = handle(&request.build());
    assert_eq!(
        outcome,
        Outcome::EchoReply {
            len: MIN_ECHO_REPLY_LEN + request.payload.len(),
        }
    );
    assert_eq!(counters.echo_replies, 1);

    let ethernet = Ethernet::parse(&reply).expect("a reply is a frame");
    assert_eq!(ethernet.header.destination, STATION_MAC);
    assert_eq!(ethernet.header.source, OUR_MAC);
    let packet = Ipv4Packet::parse(ethernet.payload).expect("a valid datagram");
    assert_eq!(packet.header().source, OUR_ADDRESS);
    assert_eq!(packet.header().destination, STATION_ADDRESS);
    assert_eq!(packet.header().protocol, Protocol::ICMP);
    let message = packet.payload();
    assert_eq!(checksum(message), 0, "the reply's own sum validates");
    assert_eq!(message[0], 0, "an echo reply is type 0");
    assert_eq!(u16::from_be_bytes([message[4], message[5]]), 0x1234);
    assert_eq!(u16::from_be_bytes([message[6], message[7]]), 9);
    assert_eq!(&message[ICMP_ECHO_HEADER_LEN..], &request.payload[..]);
}

#[test]
fn an_echo_request_for_somebody_elses_address_is_not_ours_to_answer() {
    let frame = Datagram {
        destination: Ipv4Address::from_octets([10, 0, 2, 99]),
        ..Datagram::echo()
    }
    .build();
    assert_eq!(handle(&frame).0, Outcome::NotForUs);
}

#[test]
fn a_frame_this_endpoint_does_not_answer_names_the_reason_it_did_not() {
    let cases: Vec<(Unhandled, Vec<u8>)> = vec![
        (
            Unhandled::Protocol(Protocol::UDP),
            Datagram {
                protocol: Protocol::UDP,
                ..Datagram::echo()
            }
            .build(),
        ),
        (
            Unhandled::Fragmented,
            Datagram {
                fragment_offset: 1,
                ..Datagram::echo()
            }
            .build(),
        ),
        (
            Unhandled::NotAnEchoRequest,
            Datagram {
                message_type: 0,
                ..Datagram::echo()
            }
            .build(),
        ),
        (
            Unhandled::NotAnEchoRequest,
            Datagram {
                code: 1,
                ..Datagram::echo()
            }
            .build(),
        ),
        (
            Unhandled::SourceOffLink,
            Datagram {
                source: OFF_LINK,
                ..Datagram::echo()
            }
            .build(),
        ),
        (
            Unhandled::SourceNotUnicast,
            Datagram {
                source: Ipv4Address::from_octets([224, 0, 0, 1]),
                ..Datagram::echo()
            }
            .build(),
        ),
        (
            Unhandled::SourceNotUnicast,
            Datagram {
                source_mac: MacAddress::BROADCAST,
                ..Datagram::echo()
            }
            .build(),
        ),
        (
            Unhandled::SourceOffLink,
            arp_request(MacAddress::BROADCAST, STATION_MAC, OFF_LINK, OUR_ADDRESS),
        ),
        (
            // The RFC 5227 probe the crate header records as refused.
            Unhandled::SourceNotUnicast,
            arp_request(
                MacAddress::BROADCAST,
                STATION_MAC,
                Ipv4Address::from_octets([0, 0, 0, 0]),
                OUR_ADDRESS,
            ),
        ),
    ];
    for (reason, frame) in cases {
        let (outcome, reply, counters) = handle(&frame);
        assert_eq!(outcome, Outcome::Unhandled(reason), "{reason}");
        assert!(reply.is_empty(), "{reason}");
        assert_eq!(counters.unhandled(reason), 1, "{reason}");
    }
}

#[test]
fn an_ethertype_this_endpoint_does_not_speak_is_named_rather_than_guessed_at() {
    let mut frame = arp();
    for ether_type in [EtherType::IPV6, EtherType(0x88b5)] {
        frame[MAC_PAIR_LEN..ETHERNET_HEADER_LEN].copy_from_slice(&ether_type.0.to_be_bytes());
        assert_eq!(
            handle(&frame).0,
            Outcome::Unhandled(Unhandled::EtherType(ether_type))
        );
    }
    frame[MAC_PAIR_LEN..ETHERNET_HEADER_LEN].copy_from_slice(&EtherType::VLAN.0.to_be_bytes());
    assert_eq!(handle(&frame).0, Outcome::Unhandled(Unhandled::VlanTagged));
}

#[test]
fn a_frame_that_is_not_what_it_claims_is_refused_by_the_parser_that_read_it() {
    // Too short for an Ethernet header at all.
    let (outcome, _, counters) = handle(&[0u8; 8]);
    assert!(matches!(
        outcome,
        Outcome::Malformed(Malformed::Frame(ParseError::FrameTooShort { .. }))
    ));
    assert_eq!(counters.malformed, 1);

    // An ARP EtherType with a truncated payload.
    let mut short_arp = arp();
    short_arp.truncate(ETHERNET_HEADER_LEN + ARP_PAYLOAD_LEN - 1);
    assert!(matches!(
        handle(&short_arp).0,
        Outcome::Malformed(Malformed::Arp(ArpError::PayloadTooShort { .. }))
    ));

    // An ARP packet for a hardware type this crate does not read.
    let mut wrong_hardware = arp();
    wrong_hardware[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + 2]
        .copy_from_slice(&6u16.to_be_bytes());
    assert!(matches!(
        handle(&wrong_hardware).0,
        Outcome::Malformed(Malformed::Arp(ArpError::HardwareTypeUnsupported { .. }))
    ));

    // An IPv4 header whose checksum does not match.
    let mut corrupt = Datagram::echo().build();
    corrupt[ETHERNET_HEADER_LEN + 10] ^= 0xff;
    assert!(matches!(
        handle(&corrupt).0,
        Outcome::Malformed(Malformed::Frame(ParseError::Ipv4ChecksumInvalid { .. }))
    ));

    // An echo request whose own checksum does not match.
    let broken_icmp = Datagram {
        seal_icmp: false,
        ..Datagram::echo()
    }
    .build();
    assert!(matches!(
        handle(&broken_icmp).0,
        Outcome::Malformed(Malformed::Icmp(IcmpError::ChecksumInvalid { .. }))
    ));

    // An ICMP header the datagram is too short to hold.
    let mut truncated_icmp = Datagram {
        payload: Vec::new(),
        ..Datagram::echo()
    }
    .build();
    truncated_icmp.truncate(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + 4);
    let ip_at = ETHERNET_HEADER_LEN;
    let total = (IPV4_HEADER_LEN + 4) as u16;
    truncated_icmp[ip_at + 2..ip_at + 4].copy_from_slice(&total.to_be_bytes());
    let header: [u8; IPV4_HEADER_LEN] = truncated_icmp[ip_at..ip_at + IPV4_HEADER_LEN]
        .try_into()
        .expect("a 20-byte window");
    let mut zeroed = header;
    zeroed[10] = 0;
    zeroed[11] = 0;
    let sum = checksum(&zeroed);
    truncated_icmp[ip_at + 10..ip_at + 12].copy_from_slice(&sum.to_be_bytes());
    assert!(matches!(
        handle(&truncated_icmp).0,
        Outcome::Malformed(Malformed::Icmp(IcmpError::HeaderTruncated { .. }))
    ));
}

/// Storage too short is the caller's failure and is reported as one: no reply
/// is claimed, and the count that moves is not a count about the wire.
#[test]
fn a_reply_that_does_not_fit_the_callers_storage_is_refused_and_counted_apart() {
    let mut endpoint = endpoint();
    let mut out = [0u8; ARP_FRAME_LEN - 1];
    let outcome = endpoint.handle(Some(at(0)), &arp(), &mut out);
    assert_eq!(
        outcome,
        Outcome::ReplyRefused(ReplyError::DoesNotFit {
            needed: ARP_FRAME_LEN,
            capacity: ARP_FRAME_LEN - 1,
        })
    );
    assert_eq!(outcome.reply(), None);
    assert_eq!(endpoint.counters().reply_refused, 1);
    assert_eq!(endpoint.counters().arp_replies, 0);

    let request = Datagram::echo().build();
    let mut small = [0u8; MIN_ECHO_REPLY_LEN];
    assert!(matches!(
        endpoint.handle(Some(at(0)), &request, &mut small),
        Outcome::ReplyRefused(ReplyError::DoesNotFit { .. })
    ));
    assert_eq!(endpoint.counters().reply_refused, 2);
}

#[test]
fn every_outcome_moves_exactly_one_count_and_the_total_is_the_frames_handled() {
    let mut endpoint = endpoint();
    let mut out = [0u8; ROOMY];
    let frames: Vec<Vec<u8>> = vec![
        arp(),
        Datagram::echo().build(),
        arp_request(
            MacAddress::BROADCAST,
            STATION_MAC,
            STATION_ADDRESS,
            Ipv4Address::from_octets([10, 0, 2, 99]),
        ),
        Datagram {
            protocol: Protocol::UDP,
            ..Datagram::echo()
        }
        .build(),
        vec![0u8; 3],
        // A TCP segment: too short to be one, so the transport refuses it — which
        // is still a segment this endpoint handed over and counted.
        Datagram {
            protocol: Protocol::TCP,
            ..Datagram::echo()
        }
        .build(),
    ];
    for frame in &frames {
        endpoint.handle(Some(at(0)), frame, &mut out);
    }
    let counters = endpoint.counters();
    assert_eq!(counters.arp_replies, 1);
    assert_eq!(counters.echo_replies, 1);
    assert_eq!(counters.not_for_us, 1);
    assert_eq!(counters.unhandled_total(), 1);
    assert_eq!(counters.malformed, 1);
    assert_eq!(counters.tcp_segments, 1);
    assert_eq!(counters.total(), frames.len() as u64);

    // And a segment with no clock is counted apart from every refusal a peer can
    // cause: it is this node not having finished booting.
    let segment = frames.last().expect("the TCP frame");
    assert_eq!(endpoint.handle(None, segment, &mut out), Outcome::Unclocked);
    assert_eq!(endpoint.counters().unclocked, 1);
    assert_eq!(endpoint.counters().total(), frames.len() as u64 + 1);
    // Restored, so the totals below are about the loop rather than about this.
    let base = endpoint.counters().total();

    // Nothing is reset, and a second pass adds to the first.
    for frame in &frames {
        endpoint.handle(Some(at(0)), frame, &mut out);
    }
    assert_eq!(endpoint.counters().total(), base + frames.len() as u64);
}

#[test]
fn every_unhandled_reason_has_its_own_counter_slot() {
    let mut counters = EndpointCounters::new();
    for reason in Unhandled::ALL {
        counters.record(Outcome::Unhandled(reason));
    }
    for reason in Unhandled::ALL {
        assert_eq!(counters.unhandled(reason), 1, "{reason}");
    }
    assert_eq!(counters.unhandled_total(), Unhandled::ALL.len() as u64);

    let mut names: Vec<&str> = Unhandled::ALL.iter().map(|reason| reason.name()).collect();
    names.sort_unstable();
    let count = names.len();
    names.dedup();
    assert_eq!(names.len(), count, "two reasons share a name");

    // The payload-carrying variants render the value they refused.
    assert!(
        Unhandled::EtherType(EtherType::IPV6)
            .to_string()
            .contains("0x86dd")
    );
    assert!(Unhandled::Protocol(Protocol::TCP).to_string().contains('6'));
    assert_eq!(Unhandled::Fragmented.to_string(), "fragmented");
}

#[test]
fn every_refusal_renders_as_the_value_that_caused_it() {
    assert!(
        EndpointError::MacNotUnicast {
            mac: MacAddress::BROADCAST
        }
        .to_string()
        .contains("ff:ff:ff:ff:ff:ff")
    );
    assert!(
        EndpointError::AddressNotUnicast {
            address: Ipv4Address::from_octets([224, 0, 0, 1])
        }
        .to_string()
        .contains("224.0.0.1")
    );
    assert!(
        EndpointError::PrefixLengthOutOfRange { prefix_length: 33 }
            .to_string()
            .contains("33")
    );
    assert!(
        Malformed::Frame(ParseError::FrameTooShort { needed: 14, got: 3 })
            .to_string()
            .contains("14")
    );
    assert!(
        Malformed::Arp(ArpError::PayloadTooShort { got: 7 })
            .to_string()
            .contains('7')
    );
    assert!(
        Malformed::Icmp(IcmpError::HeaderTruncated { got: 2 })
            .to_string()
            .contains('2')
    );
}

/// A `/31` endpoint has one neighbour and a `/32` has none: the prefix rule is
/// the same one at both ends of its range.
#[test]
fn a_point_to_point_endpoint_answers_only_the_station_its_prefix_admits() {
    let mut endpoint = Endpoint::new(
        OUR_MAC,
        Ipv4Address::from_octets([10, 0, 2, 14]),
        31,
        secret(),
    )
    .expect("a /31");
    let mut out = [0u8; ROOMY];
    let neighbour = arp_request(
        MacAddress::BROADCAST,
        STATION_MAC,
        Ipv4Address::from_octets([10, 0, 2, 15]),
        Ipv4Address::from_octets([10, 0, 2, 14]),
    );
    assert!(matches!(
        endpoint.handle(Some(at(0)), &neighbour, &mut out),
        Outcome::ArpReply { .. }
    ));
    let elsewhere = arp_request(
        MacAddress::BROADCAST,
        STATION_MAC,
        Ipv4Address::from_octets([10, 0, 2, 16]),
        Ipv4Address::from_octets([10, 0, 2, 14]),
    );
    assert_eq!(
        endpoint.handle(Some(at(0)), &elsewhere, &mut out),
        Outcome::Unhandled(Unhandled::SourceOffLink)
    );

    let mut host_route = Endpoint::new(OUR_MAC, OUR_ADDRESS, 32, secret()).expect("a /32");
    assert_eq!(
        host_route.handle(Some(at(0)), &arp(), &mut out),
        Outcome::Unhandled(Unhandled::SourceOffLink),
        "no address but our own shares a /32 with us"
    );
}

proptest! {
    /// The headline property: arbitrary bytes off a wire are answered or
    /// refused, never crash the endpoint, and never produce a reply longer than
    /// the storage the caller handed over.
    #[test]
    fn arbitrary_frames_never_panic_and_never_overrun_the_reply_storage(
        frame in prop::collection::vec(any::<u8>(), 0..2048),
        capacity in 0usize..2048,
    ) {
        let mut endpoint = endpoint();
        let mut out = vec![0xffu8; capacity];
        let outcome = endpoint.handle(Some(at(0)), &frame, &mut out);
        if let Some(len) = outcome.reply() {
            prop_assert!(len <= capacity);
            prop_assert!(len >= ARP_FRAME_LEN);
        }
        prop_assert_eq!(endpoint.counters().total(), 1);
    }

    /// A reply is only ever produced for a frame addressed to us, at both
    /// layers: the property the management port's isolation rests on.
    #[test]
    fn a_reply_is_only_ever_produced_for_a_frame_addressed_to_this_endpoint(
        frame in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut endpoint = endpoint();
        let mut out = vec![0u8; ROOMY];
        let outcome = endpoint.handle(Some(at(0)), &frame, &mut out);
        let Some(len) = outcome.reply() else {
            return Ok(());
        };
        let received = Ethernet::parse(&frame).expect("a reply needs a header");
        let addressed_to_us = received.header.destination == OUR_MAC
            || received.header.destination.is_broadcast();
        prop_assert!(addressed_to_us);

        // And the reply leaves as us, to the station that asked.
        let sent = Ethernet::parse(&out[..len]).expect("a reply is a frame");
        prop_assert_eq!(sent.header.source, OUR_MAC);
        prop_assert_eq!(sent.header.destination, received.header.source);
        prop_assert!(sent.header.destination.is_unicast());
        match outcome {
            Outcome::ArpReply { .. } => {
                let packet = ArpPacket::parse(sent.payload).expect("an ARP reply");
                prop_assert_eq!(packet.operation, ArpOperation::Reply);
                prop_assert_eq!(packet.sender_address, OUR_ADDRESS);
            }
            Outcome::EchoReply { .. } => {
                let packet = Ipv4Packet::parse(sent.payload).expect("a datagram");
                prop_assert_eq!(packet.header().source, OUR_ADDRESS);
                prop_assert_eq!(checksum(packet.payload()), 0);
            }
            other => prop_assert!(false, "{other:?} carried a reply"),
        }
    }

    /// Handling one frame is a function of that frame: two identical frames
    /// produce identical replies, and the endpoint carries nothing between them.
    #[test]
    fn handling_one_frame_carries_nothing_into_the_next(
        payload in prop::collection::vec(any::<u8>(), 0..256),
        identifier in any::<u16>(),
    ) {
        let request = Datagram {
            identifier,
            payload,
            ..Datagram::echo()
        }
        .build();
        let mut endpoint = endpoint();
        let mut first = vec![0u8; ROOMY];
        let mut second = vec![0u8; ROOMY];
        let left = endpoint.handle(Some(at(0)), &request, &mut first);
        let right = endpoint.handle(Some(at(0)), &request, &mut second);
        prop_assert_eq!(left, right);
        let len = left.reply().expect("an echo request is answered");
        prop_assert_eq!(&first[..len], &second[..len]);
        prop_assert_eq!(endpoint.counters().echo_replies, 2);
    }
}

/// A scripted TCP station on the management port: it composes whole frames and
/// reads back whole frames, so the exchange below is the one that crosses a wire.
struct Station {
    port: u16,
    next: lfw_tcp::SeqNumber,
    expect: lfw_tcp::SeqNumber,
    window: u16,
}

impl Station {
    fn new(port: u16, iss: u32) -> Self {
        Self {
            port,
            next: lfw_tcp::SeqNumber::new(iss),
            expect: lfw_tcp::SeqNumber::new(0),
            window: 4096,
        }
    }

    /// A frame carrying one segment from this station.
    fn frame(&mut self, flags: lfw_tcp::Flags, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; ROOMY];
        let syn = flags.contains(lfw_tcp::Flags::SYN);
        let len = lfw_tcp::Outgoing {
            source_port: self.port,
            destination_port: MANAGEMENT_PORT,
            sequence: self.next,
            acknowledgement: self.expect,
            flags,
            window: self.window,
            mss: syn.then_some(TCP_MSS),
            window_scale: None,
            payload,
        }
        .write(
            STATION_ADDRESS,
            OUR_ADDRESS,
            out.get_mut(Ipv4Frame::PAYLOAD_AT..).expect("room"),
        )
        .expect("room for a segment");
        let total = Ipv4Frame {
            destination_mac: OUR_MAC,
            source_mac: STATION_MAC,
            source: STATION_ADDRESS,
            destination: OUR_ADDRESS,
            protocol: Protocol::TCP,
        }
        .write(&mut out, len)
        .expect("room for a frame");
        out.truncate(total);
        // Lossless: a payload here is far below 2^32.
        let occupied =
            payload.len() as u32 + u32::from(syn) + u32::from(flags.contains(lfw_tcp::Flags::FIN));
        self.next = self.next.add(occupied);
        out
    }

    /// Read a frame the endpoint sent, learning what to acknowledge from it and
    /// answering its segment's fields.
    fn read(&mut self, frame: &[u8]) -> (lfw_tcp::Flags, lfw_tcp::SeqNumber, Vec<u8>) {
        let ethernet = Ethernet::parse(frame).expect("a frame");
        assert_eq!(ethernet.header.source, OUR_MAC);
        assert_eq!(ethernet.header.destination, STATION_MAC);
        assert_eq!(ethernet.header.ether_type, EtherType::IPV4);
        let packet = Ipv4Packet::parse(ethernet.payload).expect("a datagram");
        assert_eq!(packet.header().protocol, Protocol::TCP);
        assert_eq!(packet.header().source, OUR_ADDRESS);
        assert_eq!(packet.header().destination, STATION_ADDRESS);
        let segment = lfw_tcp::Segment::parse(OUR_ADDRESS, STATION_ADDRESS, packet.payload())
            .expect("a segment whose checksum verifies");
        assert_eq!(segment.source_port, MANAGEMENT_PORT);
        assert_eq!(segment.destination_port, self.port);
        self.expect = segment.sequence.add(segment.sequence_length());
        (
            segment.flags,
            segment.acknowledgement,
            segment.payload.to_vec(),
        )
    }
}

/// The exchange the end-to-end gate performs, driven here through the endpoint's
/// own surface: a handshake, a payload echoed byte for byte, and a clean close.
#[test]
fn a_whole_tcp_exchange_crosses_the_endpoint() {
    let mut endpoint = endpoint();
    let mut station = Station::new(40000, 0x1234_5678);
    let mut out = vec![0u8; ROOMY];

    // SYN -> SYN-ACK.
    let syn = station.frame(lfw_tcp::Flags::SYN, &[]);
    let outcome = endpoint.handle(Some(at(0)), &syn, &mut out);
    let len = outcome.reply().expect("a SYN-ACK");
    assert_eq!(outcome.tcp(), Some(lfw_tcp::Outcome::Accepted));
    let (flags, _, _) = station.read(&out[..len]);
    assert!(flags.contains(lfw_tcp::Flags::SYN));
    assert!(flags.contains(lfw_tcp::Flags::ACK));
    assert_eq!(endpoint.connections(), 1);

    // ACK completes it, and provokes nothing.
    let ack = station.frame(lfw_tcp::Flags::ACK, &[]);
    let outcome = endpoint.handle(Some(at(1_000)), &ack, &mut out);
    assert_eq!(outcome.reply(), None);
    assert_eq!(outcome.tcp(), Some(lfw_tcp::Outcome::Advanced));

    // A payload comes back as itself, in the same call: the echo replaces the
    // bare acknowledgement with a segment carrying the same acknowledgement
    // number and the bytes.
    let payload = b"GET /metrics HTTP/1.1\r\nHost: appliance\r\n\r\n";
    let data = station.frame(lfw_tcp::Flags::ACK.with(lfw_tcp::Flags::PSH), payload);
    let outcome = endpoint.handle(Some(at(2_000)), &data, &mut out);
    let len = outcome.reply().expect("an echo");
    let (flags, acknowledgement, echoed) = station.read(&out[..len]);
    assert_eq!(echoed, payload, "the echo is not what was sent");
    assert!(flags.contains(lfw_tcp::Flags::ACK));
    assert!(flags.contains(lfw_tcp::Flags::PSH));
    assert_eq!(
        acknowledgement,
        lfw_tcp::SeqNumber::new(0x1234_5678 + 1 + payload.len() as u32)
    );
    assert_eq!(endpoint.echo_counters().bytes_echoed, payload.len() as u64);
    assert_eq!(endpoint.echo_counters().bytes_overrun, 0);

    // The window shrank by what the echo is still holding, which is what keeps a
    // peer from sending more than it can take.

    let ack = station.frame(lfw_tcp::Flags::ACK, &[]);
    let outcome = endpoint.handle(Some(at(3_000)), &ack, &mut out);
    assert_eq!(outcome.reply(), None, "an acknowledgement was answered");

    // FIN -> FIN-ACK, because the echo has nothing left to send.
    let fin = station.frame(lfw_tcp::Flags::FIN.with(lfw_tcp::Flags::ACK), &[]);
    let outcome = endpoint.handle(Some(at(4_000)), &fin, &mut out);
    let len = outcome.reply().expect("a FIN-ACK");
    let (flags, _, _) = station.read(&out[..len]);
    assert!(flags.contains(lfw_tcp::Flags::FIN));
    assert!(flags.contains(lfw_tcp::Flags::ACK));
    assert_eq!(endpoint.echo_counters().closes, 1);

    // The final acknowledgement closes it, and the connection's state goes with
    // it — table slot, return path and held bytes together.
    let ack = station.frame(lfw_tcp::Flags::ACK, &[]);
    let outcome = endpoint.handle(Some(at(5_000)), &ack, &mut out);
    assert_eq!(outcome.reply(), None);
    assert_eq!(endpoint.connections(), 0);
    assert!(endpoint.paths.iter().all(Option::is_none));
    assert_eq!(endpoint.tcp_counters().connections_closed, 1);
    assert_eq!(endpoint.tcp_counters().bytes_received, payload.len() as u64);
}

/// The window this endpoint advertises is the echo's free space, so a peer is
/// never told it may send more than the endpoint can hold — which is what makes
/// `bytes_overrun` a number that reads zero.
#[test]
fn the_advertised_window_follows_the_echos_free_space() {
    let mut endpoint = endpoint();
    let mut station = Station::new(40000, 0x99);
    let mut out = vec![0u8; ROOMY];

    let syn = station.frame(lfw_tcp::Flags::SYN, &[]);
    let len = endpoint
        .handle(Some(at(0)), &syn, &mut out)
        .reply()
        .expect("a SYN-ACK");
    station.read(&out[..len]);
    let ack = station.frame(lfw_tcp::Flags::ACK, &[]);
    endpoint.handle(Some(at(0)), &ack, &mut out);

    // A payload the echo holds, unacknowledged: the window that comes back with
    // it is the room left.
    let payload = [0x5au8; 300];
    let data = station.frame(lfw_tcp::Flags::ACK.with(lfw_tcp::Flags::PSH), &payload);
    let len = endpoint
        .handle(Some(at(1_000)), &data, &mut out)
        .reply()
        .expect("an echo");
    let window = window_of(&out[..len]);
    assert_eq!(
        u32::from(window),
        (ECHO_CAPACITY - payload.len()) as u32,
        "the window did not shrink by what the echo holds"
    );

    // Read, so the station's next acknowledgement covers the echo: an
    // acknowledgement that did not is what leaves the bytes held.
    station.read(&out[..len]);
    let ack = station.frame(lfw_tcp::Flags::ACK, &[]);
    endpoint.handle(Some(at(2_000)), &ack, &mut out);
    let probe = station.frame(lfw_tcp::Flags::ACK.with(lfw_tcp::Flags::PSH), b"x");
    let len = endpoint
        .handle(Some(at(3_000)), &probe, &mut out)
        .reply()
        .expect("an echo");
    assert_eq!(
        u32::from(window_of(&out[..len])),
        (ECHO_CAPACITY - 1) as u32
    );
}

/// A bare transport on the management port, for the echo's own tests: they drive
/// it directly, because a refusal the endpoint's own flow control makes
/// unreachable is one only a direct call reaches.
fn tcp_stack() -> lfw_tcp::TcpStack<TCP_CONNECTIONS> {
    lfw_tcp::TcpStack::new(
        OUR_ADDRESS,
        MANAGEMENT_PORT,
        TCP_MSS,
        ECHO_CAPACITY as u32,
        secret(),
    )
}

/// Open one connection on `stack` as far as `SYN_RECEIVED`, answering its handle.
fn open(
    stack: &mut lfw_tcp::TcpStack<TCP_CONNECTIONS>,
    port: u16,
    out: &mut [u8],
) -> lfw_tcp::ConnectionId {
    let mut station = Station::new(port, u32::from(port) * 0x1000);
    let frame = station.frame(lfw_tcp::Flags::SYN, &[]);
    let ethernet = Ethernet::parse(&frame).expect("a frame");
    let packet = Ipv4Packet::parse(ethernet.payload).expect("a datagram");
    stack
        .receive(at(0), STATION_ADDRESS, packet.payload(), out)
        .connection
        .expect("a connection")
}

/// The window a frame's segment advertises.
fn window_of(frame: &[u8]) -> u16 {
    let ethernet = Ethernet::parse(frame).expect("a frame");
    let packet = Ipv4Packet::parse(ethernet.payload).expect("a datagram");
    lfw_tcp::Segment::parse(OUR_ADDRESS, STATION_ADDRESS, packet.payload())
        .expect("a segment")
        .window
}

/// A retransmission is served out of the echo's own held bytes, because the
/// transport never kept them. This is the crate's central trade, end to end.
#[test]
fn a_retransmission_is_served_from_the_echos_held_bytes() {
    let mut endpoint = endpoint();
    let mut station = Station::new(40000, 0xabcd);
    let mut out = vec![0u8; ROOMY];

    let syn = station.frame(lfw_tcp::Flags::SYN, &[]);
    let len = endpoint
        .handle(Some(at(0)), &syn, &mut out)
        .reply()
        .expect("a SYN-ACK");
    station.read(&out[..len]);
    let ack = station.frame(lfw_tcp::Flags::ACK, &[]);
    endpoint.handle(Some(at(0)), &ack, &mut out);

    let payload = b"echo me";
    let data = station.frame(lfw_tcp::Flags::ACK.with(lfw_tcp::Flags::PSH), payload);
    let len = endpoint
        .handle(Some(at(1_000)), &data, &mut out)
        .reply()
        .expect("an echo");
    let (_, _, first) = station.read(&out[..len]);
    assert_eq!(first, payload);

    // The station never acknowledges, so the timer asks for the range again and
    // the echo supplies it.
    let due = at(1_000).saturating_add(lfw_tcp::INITIAL_RTO);
    let len = endpoint
        .poll_timeouts(due, &mut out)
        .expect("a retransmission");
    let ethernet = Ethernet::parse(&out[..len]).expect("a frame");
    let packet = Ipv4Packet::parse(ethernet.payload).expect("a datagram");
    let segment =
        lfw_tcp::Segment::parse(OUR_ADDRESS, STATION_ADDRESS, packet.payload()).expect("a segment");
    assert_eq!(segment.payload, payload, "a different range was re-sent");
    assert_eq!(endpoint.echo_counters().retransmits_served, 1);
    assert_eq!(endpoint.tcp_counters().retransmits, 1);
    // And it went to the pair the connection's frames arrive from, which is the
    // only address this endpoint has for it.
    assert_eq!(ethernet.header.destination, STATION_MAC);
    assert_eq!(packet.header().destination, STATION_ADDRESS);
}

/// Every connection is eventually reaped, and its return path and held bytes go
/// with it: a port that is spoken to and abandoned holds nothing afterwards.
#[test]
fn an_abandoned_connection_leaves_nothing_behind() {
    let mut endpoint = endpoint();
    let mut station = Station::new(40000, 0x4444);
    let mut out = vec![0u8; ROOMY];

    let syn = station.frame(lfw_tcp::Flags::SYN, &[]);
    endpoint.handle(Some(at(0)), &syn, &mut out);
    assert_eq!(endpoint.connections(), 1);
    assert!(endpoint.paths.iter().any(Option::is_some));

    // Far past every deadline the transport holds.
    let far = at(lfw_tcp::IDLE_TIMEOUT.as_nanos() + lfw_tcp::TIME_WAIT_DURATION.as_nanos() + 1);
    let mut drained = 0;
    while endpoint.poll_timeouts(far, &mut out).is_some() || endpoint.connections() > 0 {
        drained += 1;
        assert!(drained <= 64, "the timers did not settle");
        if endpoint.connections() == 0 {
            break;
        }
    }
    assert_eq!(endpoint.connections(), 0);
    assert!(
        endpoint.paths.iter().all(Option::is_none),
        "a return path outlived its connection"
    );
}

/// Storage too small for the two headers is refused rather than written into,
/// which is the one thing the transport cannot judge for itself.
#[test]
fn a_segment_with_no_room_for_its_headers_is_refused() {
    let mut endpoint = endpoint();
    let mut station = Station::new(40000, 0x7777);
    let syn = station.frame(lfw_tcp::Flags::SYN, &[]);
    let mut tiny = [0u8; 8];
    assert!(matches!(
        endpoint.handle(Some(at(0)), &syn, &mut tiny),
        Outcome::ReplyRefused(_)
    ));
    // And a poll into storage that cannot hold a frame answers nothing.
    assert_eq!(endpoint.poll_timeouts(at(0), &mut tiny), None);
}

proptest! {
    /// Arbitrary bytes as a TCP payload, over an endpoint with a clock: every one
    /// is answered, nothing panics, and no frame leaves that is not addressed to
    /// the station that sent it.
    #[test]
    fn arbitrary_tcp_bytes_are_answered(
        bytes in prop::collection::vec(any::<u8>(), 0..120),
        nanos in any::<u32>(),
    ) {
        let mut endpoint = endpoint();
        let mut out = vec![0u8; ROOMY];
        let frame = Datagram {
            protocol: Protocol::TCP,
            payload: bytes,
            ..Datagram::echo()
        }
        .build();
        let outcome = endpoint.handle(Some(at(u64::from(nanos))), &frame, &mut out);
        prop_assert_eq!(endpoint.counters().total(), 1);
        if let Some(len) = outcome.reply() {
            let ethernet = Ethernet::parse(&out[..len]).expect("a frame");
            prop_assert_eq!(ethernet.header.source, OUR_MAC);
            prop_assert_eq!(ethernet.header.destination, STATION_MAC);
        }
    }
}

/// A response that spans more than the peer's window goes out over several
/// segments, one per wakeup, and the echo holds what it has not sent. That is the
/// shift path — the held prefix moving down as it is acknowledged — which the
/// gate's single round trip never reaches.
#[test]
fn a_response_larger_than_the_window_leaves_over_several_segments() {
    let mut endpoint = endpoint();
    let mut station = Station::new(40000, 0x2222);
    // A window of 100 bytes, so a 250-byte echo takes three segments.
    station.window = 100;
    let mut out = vec![0u8; ROOMY];

    let syn = station.frame(lfw_tcp::Flags::SYN, &[]);
    let len = endpoint
        .handle(Some(at(0)), &syn, &mut out)
        .reply()
        .expect("a SYN-ACK");
    station.read(&out[..len]);
    let ack = station.frame(lfw_tcp::Flags::ACK, &[]);
    endpoint.handle(Some(at(0)), &ack, &mut out);

    let payload: Vec<u8> = (0..250u32).map(|index| (index % 251) as u8).collect();
    let data = station.frame(lfw_tcp::Flags::ACK.with(lfw_tcp::Flags::PSH), &payload);
    let mut echoed: Vec<u8> = Vec::new();
    let len = endpoint
        .handle(Some(at(1_000)), &data, &mut out)
        .reply()
        .expect("the first chunk");
    let (_, _, chunk) = station.read(&out[..len]);
    assert_eq!(chunk.len(), 100, "more than the window went out at once");
    echoed.extend_from_slice(&chunk);

    // Each acknowledgement frees the chunk it covers and provokes the next.
    for round in 0..8u64 {
        let ack = station.frame(lfw_tcp::Flags::ACK, &[]);
        let outcome = endpoint.handle(Some(at(2_000 + round)), &ack, &mut out);
        let Some(len) = outcome.reply() else { break };
        let (_, _, chunk) = station.read(&out[..len]);
        echoed.extend_from_slice(&chunk);
    }
    assert_eq!(echoed, payload, "the stream did not come back whole");
    assert_eq!(endpoint.echo_counters().bytes_echoed, payload.len() as u64);
}

/// A peer that sends past the window it was given has the excess counted and
/// dropped rather than written past the echo's array. It cannot happen while the
/// window is the room — which is why the count reads zero — and the array is what
/// makes it safe when it does.
#[test]
fn a_peer_that_overruns_the_window_is_counted_rather_than_believed() {
    let mut echo: Echo<2> = Echo::new();
    let mut stack = tcp_stack();
    let mut out = vec![0u8; ROOMY];
    let connection = open(&mut stack, 40000, &mut out);
    echo.take(connection, &[0x11; ECHO_CAPACITY]);
    assert_eq!(echo.counters().bytes_taken, ECHO_CAPACITY as u64);
    assert_eq!(echo.counters().bytes_overrun, 0);

    echo.take(connection, b"one byte too many");
    assert_eq!(echo.counters().bytes_taken, ECHO_CAPACITY as u64);
    assert_eq!(echo.counters().bytes_overrun, 17);
}

/// One slot per connection, so a connection that exists always has one. A third
/// connection against a two-slot echo is what proves the refusal is counted
/// rather than silently overwriting somebody's bytes.
#[test]
fn an_echo_with_no_slot_left_counts_the_refusal() {
    let mut echo: Echo<2> = Echo::new();
    let mut stack = tcp_stack();
    let mut out = vec![0u8; ROOMY];
    let ids: Vec<lfw_tcp::ConnectionId> = (0..3u16)
        .map(|index| open(&mut stack, 40000 + index, &mut out))
        .collect();

    for id in ids.iter().take(2) {
        echo.take(*id, b"held");
    }
    assert_eq!(echo.counters().slots_exhausted, 0);
    echo.take(ids[2], b"nowhere to go");
    assert_eq!(echo.counters().slots_exhausted, 1);
    assert_eq!(echo.counters().bytes_taken, 8);

    // Nothing to drive on a connection with no slot, and nothing to serve.
    assert_eq!(echo.drive(&mut stack, at(0), ids[2], &mut out), None);
    assert_eq!(
        echo.answer(
            &mut stack,
            at(0),
            lfw_tcp::Timeout::Retransmit {
                connection: ids[2],
                sequence: lfw_tcp::SeqNumber::new(0),
                len: 4,
            },
            &mut out,
        ),
        None
    );
    assert_eq!(echo.counters().retransmits_unavailable, 0);

    // A range no slot holds is a disagreement between this endpoint and the
    // transport, and it is counted as ours.
    assert_eq!(
        echo.answer(
            &mut stack,
            at(0),
            lfw_tcp::Timeout::Retransmit {
                connection: ids[0],
                sequence: lfw_tcp::SeqNumber::new(0x9999),
                len: 4,
            },
            &mut out,
        ),
        None
    );
    assert_eq!(echo.counters().retransmits_unavailable, 1);

    // The two timeouts that only release a slot, and the one that is already a
    // composed segment.
    assert_eq!(
        echo.answer(
            &mut stack,
            at(0),
            lfw_tcp::Timeout::Resent {
                connection: ids[0],
                len: 40
            },
            &mut out,
        ),
        Some(40)
    );
    assert_eq!(
        echo.answer(
            &mut stack,
            at(0),
            lfw_tcp::Timeout::Abandoned {
                connection: ids[0],
                len: 40
            },
            &mut out,
        ),
        Some(40)
    );
    assert_eq!(
        echo.answer(
            &mut stack,
            at(0),
            lfw_tcp::Timeout::Reaped { connection: ids[1] },
            &mut out,
        ),
        None
    );
    // Both slots are free again, so the third connection now has one.
    echo.take(ids[2], b"room at last");
    assert_eq!(echo.counters().slots_exhausted, 1);
    assert_eq!(Echo::<2>::default().counters(), EchoCounters::new());
}

/// A close the transport refuses — because this end has already closed — is held
/// rather than counted as a close, and a send into storage too small likewise.
#[test]
fn a_refused_close_or_send_leaves_the_echo_holding() {
    let mut echo: Echo<2> = Echo::new();
    let mut stack = tcp_stack();
    let mut out = vec![0u8; ROOMY];
    let id = open(&mut stack, 40000, &mut out);

    // A connection still in `SYN_RECEIVED` can neither send nor close, so both
    // arms of `drive` are refused and the bytes stay held.
    echo.take(id, b"held");
    echo.note_peer_closed(id);
    assert_eq!(echo.drive(&mut stack, at(0), id, &mut out), None);
    assert_eq!(echo.counters().bytes_echoed, 0);
    assert_eq!(echo.counters().closes, 0);

    // A peer that closed with nothing held, on a connection that cannot close:
    // the close arm is reached and refused.
    let other = open(&mut stack, 40001, &mut out);
    echo.note_peer_closed(other);
    assert_eq!(echo.drive(&mut stack, at(0), other, &mut out), None);
    assert_eq!(echo.counters().closes, 0);
}

/// A retransmission the transport asks for and this endpoint cannot write —
/// storage too small — is counted as unavailable rather than reported as served.
#[test]
fn a_retransmission_that_does_not_fit_is_counted_as_unavailable() {
    let mut endpoint = endpoint();
    let mut station = Station::new(40000, 0x5555);
    let mut out = vec![0u8; ROOMY];

    let syn = station.frame(lfw_tcp::Flags::SYN, &[]);
    let len = endpoint
        .handle(Some(at(0)), &syn, &mut out)
        .reply()
        .expect("a SYN-ACK");
    station.read(&out[..len]);
    let ack = station.frame(lfw_tcp::Flags::ACK, &[]);
    endpoint.handle(Some(at(0)), &ack, &mut out);
    let data = station.frame(lfw_tcp::Flags::ACK.with(lfw_tcp::Flags::PSH), b"echo me");
    endpoint.handle(Some(at(1_000)), &data, &mut out);

    // Storage that holds the two headers and nothing like a segment.
    let mut cramped = [0u8; Ipv4Frame::PAYLOAD_AT + 8];
    let due = at(1_000).saturating_add(lfw_tcp::INITIAL_RTO);
    assert_eq!(endpoint.poll_timeouts(due, &mut cramped), None);
    assert_eq!(endpoint.echo_counters().retransmits_unavailable, 1);
    assert_eq!(endpoint.echo_counters().retransmits_served, 0);
}

/// The two outcomes that are not a TCP segment answer `None` when asked what the
/// transport made of them, so a caller has one question per outcome.
#[test]
fn only_a_tcp_outcome_carries_a_transport_verdict() {
    assert_eq!(Outcome::NotForUs.tcp(), None);
    assert_eq!(Outcome::Unclocked.tcp(), None);
    assert_eq!(Outcome::ArpReply { len: 42 }.tcp(), None);
    assert_eq!(Outcome::Unclocked.reply(), None);
    assert_eq!(
        Outcome::Tcp {
            len: 0,
            outcome: lfw_tcp::Outcome::Advanced
        }
        .reply(),
        None
    );
    assert_eq!(
        Outcome::Tcp {
            len: 40,
            outcome: lfw_tcp::Outcome::Advanced
        }
        .tcp(),
        Some(lfw_tcp::Outcome::Advanced)
    );
}

/// Every timeout names the connection it concerns, which is how the return path
/// for it is found — including for the two that arrive after the transport has
/// already forgotten the connection.
#[test]
fn every_timeout_names_its_connection() {
    let mut stack = tcp_stack();
    let mut out = vec![0u8; ROOMY];
    let id = open(&mut stack, 40000, &mut out);
    for timeout in [
        Timeout::Resent {
            connection: id,
            len: 1,
        },
        Timeout::Retransmit {
            connection: id,
            sequence: lfw_tcp::SeqNumber::new(0),
            len: 1,
        },
        Timeout::Abandoned {
            connection: id,
            len: 1,
        },
        Timeout::Reaped { connection: id },
    ] {
        assert_eq!(timeout_connection(timeout), id);
    }
}

/// A count for a reason outside the table answers zero rather than indexing past
/// it. Unreachable through `Unhandled::ALL`, and driven directly because a
/// defensive path nothing exercises is one nobody knows the shape of.
#[test]
fn a_count_for_no_slot_answers_zero() {
    let counters = EndpointCounters::new();
    assert_eq!(counters.unhandled(Unhandled::VlanTagged), 0);
    assert_eq!(counters.unhandled_total(), 0);
}

/// A return path is remembered per connection and bounded by the table: an
/// endpoint whose paths are all taken remembers no more rather than overwriting
/// one somebody else needs.
#[test]
fn the_return_path_table_is_bounded_by_the_connection_table() {
    let mut endpoint = endpoint();
    let mut out = vec![0u8; ROOMY];
    for index in 0..TCP_CONNECTIONS as u16 {
        let mut station = Station::new(40000 + index, u32::from(index) * 0x1000 + 1);
        let syn = station.frame(lfw_tcp::Flags::SYN, &[]);
        endpoint.handle(Some(at(u64::from(index) * 1_000_000_000)), &syn, &mut out);
    }
    assert_eq!(endpoint.connections(), TCP_CONNECTIONS);
    assert!(endpoint.paths.iter().all(Option::is_some));

    // A ninth connection evicts a table slot, and the path table has no room for
    // its own entry until the evicted connection's path is released — which the
    // transport's next timeout does. Nothing is overwritten in the meantime.
    let mut newcomer = Station::new(50000, 0x9_9999);
    let syn = newcomer.frame(lfw_tcp::Flags::SYN, &[]);
    let far = at(u64::from(TCP_CONNECTIONS as u32) * 1_000_000_000);
    endpoint.handle(Some(far), &syn, &mut out);
    assert_eq!(endpoint.connections(), TCP_CONNECTIONS);
    assert_eq!(
        endpoint.paths.iter().flatten().count(),
        TCP_CONNECTIONS,
        "the path table grew past the connection table"
    );
}
