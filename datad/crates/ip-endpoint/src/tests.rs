use super::*;

use crate::neighbour::{ENTRY_LIFETIME, MAX_REQUESTS, NEIGHBOURS, REQUEST_TIMEOUT};
use net_headers::{
    ARP_FRAME_LEN, ARP_PAYLOAD_LEN, ETHERNET_HEADER_LEN, ICMP_HEADER_LEN, IPV4_HEADER_LEN,
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
/// The next hop this port hands everything off its own prefix to, and the MAC
/// the station holding it answers with.
const GATEWAY: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 1]);
const GATEWAY_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x01]);

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
    Endpoint::new(OUR_MAC, OUR_ADDRESS, PREFIX, Some(GATEWAY), secret())
        .expect("a unicast pair on a /24")
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

/// One ARP reply, unicast to the station that asked, as the wire carries it.
fn arp_reply(
    destination: MacAddress,
    sender_mac: MacAddress,
    sender_address: Ipv4Address,
    target: Ipv4Address,
) -> Vec<u8> {
    let mut frame = arp_request(destination, sender_mac, sender_address, target);
    frame[ETHERNET_HEADER_LEN + 6..ETHERNET_HEADER_LEN + 8].copy_from_slice(&2u16.to_be_bytes());
    frame[ETHERNET_HEADER_LEN + 18..ETHERNET_HEADER_LEN + 24].copy_from_slice(&destination.0);
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
        Endpoint::new(
            MacAddress::BROADCAST,
            OUR_ADDRESS,
            PREFIX,
            Some(GATEWAY),
            secret()
        )
        .err(),
        Some(EndpointError::MacNotUnicast {
            mac: MacAddress::BROADCAST
        })
    );
    assert_eq!(
        Endpoint::new(
            MacAddress([0; 6]),
            OUR_ADDRESS,
            PREFIX,
            Some(GATEWAY),
            secret()
        )
        .err(),
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
            Endpoint::new(OUR_MAC, address, PREFIX, Some(GATEWAY), secret()).err(),
            Some(EndpointError::AddressNotUnicast { address })
        );
    }
    for prefix_length in [33u8, 64, 255] {
        assert_eq!(
            Endpoint::new(OUR_MAC, OUR_ADDRESS, prefix_length, Some(GATEWAY), secret()).err(),
            Some(EndpointError::PrefixLengthOutOfRange { prefix_length })
        );
    }
    let endpoint = Endpoint::new(OUR_MAC, OUR_ADDRESS, 32, Some(GATEWAY), secret())
        .expect("a host route is a prefix");
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

/// An ARP reply is taken rather than answered, and one nothing asked for
/// changes nothing at all — which is what makes the classic unsolicited reply
/// inert here rather than merely suspicious.
#[test]
fn an_unsolicited_arp_reply_is_taken_and_learns_nothing() {
    let mut endpoint = endpoint();
    let mut out = [0u8; ROOMY];
    let outcome = endpoint.handle(
        Some(at(0)),
        &arp_reply(OUR_MAC, STATION_MAC, STATION_ADDRESS, OUR_ADDRESS),
        &mut out,
    );
    assert_eq!(outcome, Outcome::Neighbour(Learned::Unsolicited));
    assert_eq!(outcome.reply(), None);
    assert_eq!(endpoint.counters().neighbour_replies, 1);
    assert_eq!(endpoint.counters().unhandled_total(), 0);
    assert_eq!(endpoint.neighbour_counters().unsolicited, 1);
    assert_eq!(endpoint.neighbour_counters().learned, 0);
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
    assert_eq!(&message[ICMP_HEADER_LEN..], &request.payload[..]);
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
            Unhandled::Protocol(Some(Protocol::UDP)),
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
            Outcome::Unhandled(Unhandled::EtherType(Some(ether_type)))
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

    // The payload-carrying variants render the value they refused, and the
    // table's own entries — which stand for a slot and not for a frame — render
    // as the bare name.
    assert!(
        Unhandled::EtherType(Some(EtherType::IPV6))
            .to_string()
            .contains("0x86dd")
    );
    assert!(
        Unhandled::Protocol(Some(Protocol::TCP))
            .to_string()
            .contains('6')
    );
    assert_eq!(
        Unhandled::EtherType(None).to_string(),
        "ethertype_not_handled"
    );
    assert_eq!(
        Unhandled::Protocol(None).to_string(),
        "protocol_not_handled"
    );
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
        None,
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

    let mut host_route =
        Endpoint::new(OUR_MAC, OUR_ADDRESS, 32, Some(GATEWAY), secret()).expect("a /32");
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
    /// Which of the endpoint's two listening ports this station is addressing.
    /// A field rather than a constant, because the two are two transports and a
    /// station that could only reach one of them would leave the other's
    /// demultiplexing untested.
    destination: u16,
    next: lfw_tcp::SeqNumber,
    expect: lfw_tcp::SeqNumber,
    window: u16,
}

impl Station {
    fn new(port: u16, iss: u32) -> Self {
        Self {
            port,
            destination: MANAGEMENT_PORT,
            next: lfw_tcp::SeqNumber::new(iss),
            expect: lfw_tcp::SeqNumber::new(0),
            window: 4096,
        }
    }

    /// A station addressing the onboarding port instead.
    fn onboarding(port: u16, iss: u32) -> Self {
        Self {
            destination: ONBOARDING_PORT,
            ..Self::new(port, iss)
        }
    }

    /// A frame carrying one segment from this station.
    fn frame(&mut self, flags: lfw_tcp::Flags, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; ROOMY];
        let syn = flags.contains(lfw_tcp::Flags::SYN);
        let len = lfw_tcp::Outgoing {
            source_port: self.port,
            destination_port: self.destination,
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

    /// A frame acknowledging `acknowledgement` rather than what this station has
    /// really read, for the cases about what a peer may claim.
    ///
    /// What it has read is left alone, so the claim is one segment's and the
    /// station goes on acknowledging honestly afterwards.
    fn acknowledging(
        &mut self,
        acknowledgement: lfw_tcp::SeqNumber,
        flags: lfw_tcp::Flags,
        payload: &[u8],
    ) -> Vec<u8> {
        let honest = self.expect;
        self.expect = acknowledgement;
        let frame = self.frame(flags, payload);
        self.expect = honest;
        frame
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
        assert_eq!(segment.source_port, self.destination);
        assert_eq!(segment.destination_port, self.port);
        self.expect = segment.sequence.add(segment.sequence_length());
        (
            segment.flags,
            segment.acknowledgement,
            segment.payload.to_vec(),
        )
    }
}

/// The sequence number a frame's segment carries, which is the name a
/// retransmission has to re-send its range under.
fn sequence_of(frame: &[u8]) -> lfw_tcp::SeqNumber {
    let ethernet = Ethernet::parse(frame).expect("a frame");
    let packet = Ipv4Packet::parse(ethernet.payload).expect("a datagram");
    lfw_tcp::Segment::parse(OUR_ADDRESS, STATION_ADDRESS, packet.payload())
        .expect("a segment")
        .sequence
}

use crate::outbound::{
    DialFacts, Ended, OpenError, Phase, RECEIVE_CAPACITY, Resolutions, SEND_CAPACITY,
};
use crate::route::{Hop, RouteRefusal, Via};

/// The port the appliance dials, and a run of bytes the consumer above it hands
/// down. Both stand in for the first-party pair a management channel is built
/// on: neither is anything a peer chooses, and the crate reads neither.
const PEER_PORT: u16 = 4433;
const GREETING: &[u8] = b"librefirewall-greeting";

/// `base` plus `elapsed`, built through the one path a `Monotonic` is reachable
/// by, so a test states an instant the way a caller of this crate would.
fn after(base: Monotonic, elapsed: lfw_clock::Duration) -> Monotonic {
    at(base
        .since(at(0))
        .as_nanos()
        .saturating_add(elapsed.as_nanos()))
}

/// `unit` taken `count` times, `Duration` having no multiplication of its own.
fn times(unit: lfw_clock::Duration, count: u64) -> lfw_clock::Duration {
    lfw_clock::Duration::from_nanos(unit.as_nanos().saturating_mul(count))
}

/// Drive the outbound half until it has nothing left to do, answering with every
/// frame it composed in order.
///
/// Bounded rather than looped to a fixed point: each answer either moves a phase
/// or hands a range to the transport, so a pass that did not settle inside the
/// bound is a defect this reports rather than a test that hangs.
fn pump(endpoint: &mut Endpoint, now: Monotonic) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    for _ in 0..64 {
        let mut out = vec![0u8; ROOMY];
        match endpoint.poll_outbound(now, &mut out) {
            Polled::Frame { len } => {
                out.truncate(len);
                frames.push(out);
            }
            Polled::Handled => {}
            Polled::Idle => return frames,
        }
    }
    panic!("the outbound poll did not settle inside its own bound")
}

/// The address an ARP request asks about, and the station it was sent from.
fn asked_about(frame: &[u8]) -> Ipv4Address {
    let ethernet = Ethernet::parse(frame).expect("a frame");
    assert_eq!(ethernet.header.destination, MacAddress::BROADCAST);
    assert_eq!(ethernet.header.source, OUR_MAC);
    assert_eq!(ethernet.header.ether_type, EtherType::ARP);
    let request = ArpPacket::parse(ethernet.payload).expect("an ARP packet");
    assert_eq!(request.operation, ArpOperation::Request);
    assert_eq!(request.sender_mac, OUR_MAC);
    assert_eq!(request.sender_address, OUR_ADDRESS);
    assert_eq!(request.target_mac, MacAddress([0; 6]));
    request.target_address
}

/// Answer for `address` at `mac`, then let the port install what it learned and
/// take the `SYN` its own retransmission owes.
///
/// Two steps rather than one: the return path is installed from the resolution,
/// so a poll of the outbound half has to run between the answer arriving and the
/// transport being asked for the segment it is holding.
fn resolve_and_take_syn(
    endpoint: &mut Endpoint,
    now: Monotonic,
    mac: MacAddress,
    address: Ipv4Address,
) -> Vec<u8> {
    endpoint.handle(
        Some(now),
        &arp_reply(OUR_MAC, mac, address, OUR_ADDRESS),
        &mut vec![0u8; ROOMY],
    );
    assert!(
        pump(endpoint, now).is_empty(),
        "nothing composes a second SYN"
    );
    let mut out = vec![0u8; ROOMY];
    let len = endpoint
        .poll_timeouts(after(now, lfw_tcp::INITIAL_RTO), &mut out)
        .frame()
        .expect("the transport re-sends the SYN it was holding");
    out.truncate(len);
    out
}

/// Answer the station's segment into the endpoint, returning what came back.
fn deliver(endpoint: &mut Endpoint, now: Monotonic, frame: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; ROOMY];
    let outcome = endpoint.handle(Some(now), frame, &mut out);
    outcome.reply().map(|len| {
        out.truncate(len);
        out
    })
}

/// A whole session against a station that answers everything: the one path a
/// management channel takes when nothing goes wrong.
#[test]
fn a_dial_asks_for_its_next_hop_and_carries_a_stream_once_the_answer_arrives() {
    let mut endpoint = endpoint();
    let now = at(0);
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    assert_eq!(
        endpoint.outbound().map(Session::phase),
        Some(Phase::Resolving)
    );

    // The port asks about the destination itself, it being on this port's own
    // prefix, and the SYN it composed alongside is dropped for want of an
    // address rather than queued.
    let asked = pump(&mut endpoint, now);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked_about(&asked[0]), STATION_ADDRESS);
    assert_eq!(endpoint.outbound_counters().dropped_unresolved, 1);
    assert_eq!(endpoint.outbound_counters().dialled, 1);
    assert_eq!(endpoint.neighbour_counters().requested, 1);

    // The station answers for itself, and the entry resolves.
    let outcome = endpoint.handle(
        Some(now),
        &arp_reply(OUR_MAC, STATION_MAC, STATION_ADDRESS, OUR_ADDRESS),
        &mut vec![0u8; ROOMY],
    );
    assert_eq!(outcome, Outcome::Neighbour(Learned::Resolved));
    assert_eq!(endpoint.neighbour_counters().learned, 1);

    // The dropped SYN is the transport's to re-send, and it now has somewhere to
    // go. Nothing here composes a second one.
    assert!(pump(&mut endpoint, now).is_empty());
    let later = after(now, lfw_tcp::INITIAL_RTO);
    let mut out = vec![0u8; ROOMY];
    let polled = endpoint.poll_timeouts(later, &mut out);
    let len = polled.frame().expect("the SYN is re-sent");
    out.truncate(len);

    let mut station = Station::new(PEER_PORT, 0x5000_0000);
    let (flags, _, _) = station.read(&out);
    assert!(flags.contains(lfw_tcp::Flags::SYN));
    assert!(!flags.contains(lfw_tcp::Flags::ACK));

    // The handshake. The connection is then **up and held**: nothing is owed and
    // nothing is composed, because a stream has no opening message and this end
    // closes nothing the consumer above it has not ended.
    let synack = station.frame(lfw_tcp::Flags::SYN.with(lfw_tcp::Flags::ACK), &[]);
    deliver(&mut endpoint, later, &synack);
    assert!(
        pump(&mut endpoint, later).is_empty(),
        "an established stream with nothing to say composes nothing"
    );
    assert_eq!(
        endpoint.outbound().map(Session::phase),
        Some(Phase::Established)
    );
    assert_eq!(endpoint.outbound_counters().established, 1);
    assert_eq!(endpoint.outbound_counters().ended, 0);

    // What the consumer above hands down goes out, and what the station answers
    // with is held for it to take.
    assert_eq!(endpoint.push_outbound(GREETING), GREETING.len());
    let sent = pump(&mut endpoint, later);
    assert_eq!(sent.len(), 1, "the greeting goes out in one segment");
    let (flags, _, payload) = station.read(&sent[0]);
    assert!(flags.contains(lfw_tcp::Flags::ACK));
    assert_eq!(payload, GREETING);

    let answer = b"librefirewall-answer";
    let reply = station.frame(
        lfw_tcp::Flags::ACK
            .with(lfw_tcp::Flags::PSH)
            .with(lfw_tcp::Flags::FIN),
        answer,
    );
    deliver(&mut endpoint, later, &reply);
    assert_eq!(
        endpoint.outbound().map(Session::received),
        Some(&answer[..])
    );
    // Taken once and gone: the consumer reads a prefix of the stream and says
    // how much of it it took.
    endpoint.consume_outbound(answer.len());
    assert_eq!(endpoint.outbound().map(Session::received), Some(&[][..]));

    // The peer has hung up, and **this end closes only because the consumer
    // above says so**: a stream has no length off which this crate could read
    // an end for it.
    assert!(
        pump(&mut endpoint, later).is_empty(),
        "a peer's half-close ends nothing on its own"
    );
    endpoint.end_outbound_session();
    let closing = pump(&mut endpoint, later);
    assert_eq!(closing.len(), 1);
    let (flags, _, _) = station.read(&closing[0]);
    assert!(flags.contains(lfw_tcp::Flags::FIN));
    let last = station.frame(lfw_tcp::Flags::ACK, &[]);
    deliver(&mut endpoint, later, &last);
    pump(&mut endpoint, later);

    assert_eq!(
        endpoint.outbound().map(Session::phase),
        Some(Phase::Ended(Ended::ClosedByPeer))
    );
    assert_eq!(endpoint.outbound_counters().ended, 1);
    // The session came up once and is still recorded as having come up: the fact
    // is the event rather than the phase, so an ending does not take it back and
    // the passes in between do not count it again.
    assert_eq!(endpoint.outbound_counters().established, 1);
    assert_eq!(endpoint.outbound().map(Session::established), Some(true));
    assert_eq!(endpoint.outbound_counters().sent, GREETING.len() as u64);
    assert_eq!(endpoint.outbound_counters().received, answer.len() as u64);
    assert!(endpoint.close_outbound());
    assert!(endpoint.outbound().is_none());
}

/// The room this end keeps for what the consumer above it answers with is a
/// bound of this appliance's own, and what outgrows it is **refused and
/// counted** rather than silently cut: a stream missing a run of its middle is
/// no stream at all, and the caller is told exactly how much it may still say.
#[test]
fn a_consumers_answer_past_the_room_for_one_is_refused_and_counted() {
    let mut endpoint = endpoint();
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    let flood = vec![0xa5u8; SEND_CAPACITY + 64];
    assert_eq!(endpoint.push_outbound(&flood), SEND_CAPACITY);
    assert_eq!(endpoint.outbound_counters().refused, 64);
    // And nothing more fits, the room being taken rather than reused.
    assert_eq!(endpoint.push_outbound(b"more"), 0);
    assert_eq!(endpoint.outbound_counters().refused, 68);

    // A push with no session at all is refused whole rather than kept for one:
    // a consumer whose bytes arrived after the session they belonged to was
    // gone has nowhere to put them.
    let mut idle = Endpoint::new(OUR_MAC, OUR_ADDRESS, PREFIX, Some(GATEWAY), secret())
        .expect("a port that reaches its own link");
    assert_eq!(idle.push_outbound(b"orphan"), 0);
    assert_eq!(idle.outbound_counters().refused, 6);
}

/// A destination off this port's prefix is reached *through the gateway*: the
/// question on the wire is about the gateway, and the datagram still names the
/// destination.
#[test]
fn a_destination_off_this_ports_prefix_is_asked_about_as_the_gateway() {
    let mut endpoint = endpoint();
    endpoint
        .open_outbound(OFF_LINK, PEER_PORT)
        .expect("a gateway is stated");
    assert_eq!(
        endpoint.outbound().map(Session::next_hop),
        Some(Hop {
            address: GATEWAY,
            via: Via::Gateway
        }),
        "the next hop is the gateway and not the destination, and says so"
    );
    let asked = pump(&mut endpoint, at(0));
    assert_eq!(asked_about(&asked[0]), GATEWAY);

    let out = resolve_and_take_syn(&mut endpoint, at(0), GATEWAY_MAC, GATEWAY);
    let ethernet = Ethernet::parse(&out).expect("a frame");
    assert_eq!(
        ethernet.header.destination, GATEWAY_MAC,
        "the frame is addressed to the gateway"
    );
    let packet = Ipv4Packet::parse(ethernet.payload).expect("a datagram");
    assert_eq!(
        packet.header().destination,
        OFF_LINK,
        "and the datagram still names the destination"
    );
}

/// Every open refused before a frame leaves, and each under its own reason.
#[test]
fn an_open_this_port_cannot_honour_is_refused_before_anything_is_composed() {
    let mut without = Endpoint::new(OUR_MAC, OUR_ADDRESS, PREFIX, None, secret())
        .expect("a port that reaches its own link");
    assert_eq!(
        without.open_outbound(OFF_LINK, PEER_PORT),
        Err(OpenError::Unroutable(RouteRefusal::Unroutable))
    );
    assert_eq!(without.outbound_counters().open_refused, 1);
    assert!(without.outbound().is_none());
    assert!(pump(&mut without, at(0)).is_empty());

    let mut endpoint = endpoint();
    assert_eq!(
        endpoint.open_outbound(OUR_ADDRESS, PEER_PORT),
        Err(OpenError::Unroutable(RouteRefusal::DestinationIsOurs))
    );
    assert_eq!(
        endpoint.open_outbound(Ipv4Address::from_octets([255, 255, 255, 255]), PEER_PORT),
        Err(OpenError::Unroutable(RouteRefusal::DestinationNotUnicast))
    );
    assert_eq!(endpoint.outbound_counters().opened, 0);
    assert_eq!(endpoint.outbound_counters().open_refused, 2);

    // And a second open while one runs names the session that already exists,
    // so a caller that lost track of one does not start a second channel.
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("the first opens");
    assert_eq!(
        endpoint.open_outbound(STATION_ADDRESS, PEER_PORT + 1),
        Err(OpenError::Busy {
            destination: STATION_ADDRESS,
            port: PEER_PORT
        })
    );
    assert!(
        !endpoint.close_outbound(),
        "a running session is not dropped"
    );
}

/// A next hop nothing on the link answers for ends the session under its own
/// reason, rather than leaving a caller waiting on a channel that will never
/// come up.
#[test]
fn a_next_hop_nothing_answers_for_ends_the_session_naming_the_neighbour() {
    let mut endpoint = endpoint();
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    // One request per timeout, and the budget is this end's own.
    let mut asked = 0usize;
    for step in 0..=u64::from(MAX_REQUESTS) {
        let now = after(at(0), times(REQUEST_TIMEOUT, step));
        asked += pump(&mut endpoint, now).len();
    }
    assert_eq!(asked, MAX_REQUESTS as usize);
    assert_eq!(endpoint.neighbour_counters().requested, MAX_REQUESTS as u64);
    assert_eq!(endpoint.neighbour_counters().abandoned, 1);
    assert_eq!(
        endpoint.outbound().map(Session::phase),
        Some(Phase::Ended(Ended::NextHopUnreachable))
    );
    assert_eq!(endpoint.outbound_counters().ended, 1);
    // Nothing was ever put on the wire but the requests themselves: a segment
    // that could not be addressed was dropped rather than sent somewhere.
    assert!(endpoint.outbound_counters().dropped_unresolved >= 1);
    assert!(endpoint.close_outbound());
}

/// The one thing the cache exists to refuse, driven through the endpoint: a
/// reply for the address this end asked about, from a station that is not the
/// frame's own source, is not learned — and the dial then reports the next hop
/// unreachable rather than trusting it.
#[test]
fn a_reply_from_a_sender_the_frame_contradicts_is_never_learned() {
    let mut endpoint = endpoint();
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    pump(&mut endpoint, at(0));

    // The payload claims the address this end asked about; the frame that
    // carried it says somebody else sent it.
    let mut forged = arp_reply(OUR_MAC, STATION_MAC, STATION_ADDRESS, OUR_ADDRESS);
    forged[MAC_PAIR_LEN / 2..MAC_PAIR_LEN].copy_from_slice(&[0x52, 0x54, 0x00, 0xbe, 0xef, 0x01]);
    let outcome = endpoint.handle(Some(at(0)), &forged, &mut vec![0u8; ROOMY]);
    assert_eq!(outcome, Outcome::Unhandled(Unhandled::ArpSenderMacMismatch));
    assert_eq!(endpoint.neighbour_counters().learned, 0);

    // A reply addressed to the whole link is not ours either: it is the
    // gratuitous announcement, and this end asked nobody for it.
    let gratuitous = arp_reply(
        MacAddress::BROADCAST,
        STATION_MAC,
        STATION_ADDRESS,
        OUR_ADDRESS,
    );
    assert_eq!(
        endpoint.handle(Some(at(0)), &gratuitous, &mut vec![0u8; ROOMY]),
        Outcome::NotForUs
    );
    assert_eq!(endpoint.neighbour_counters().learned, 0);

    for step in 1..=u64::from(MAX_REQUESTS) {
        pump(&mut endpoint, after(at(0), times(REQUEST_TIMEOUT, step)));
    }
    assert_eq!(
        endpoint.outbound().map(Session::phase),
        Some(Phase::Ended(Ended::NextHopUnreachable)),
        "an unlearned reply leaves the next hop unresolved rather than trusted"
    );
}

/// A reply arriving before this node has a time is refused rather than learned:
/// a node with no clock has sent no request, so such a reply answers nothing.
#[test]
fn an_arp_reply_with_no_clock_is_refused_and_learns_nothing() {
    let mut endpoint = endpoint();
    let outcome = endpoint.handle(
        None,
        &arp_reply(OUR_MAC, STATION_MAC, STATION_ADDRESS, OUR_ADDRESS),
        &mut vec![0u8; ROOMY],
    );
    assert_eq!(outcome, Outcome::Unclocked);
    assert_eq!(endpoint.counters().unclocked, 1);
    assert_eq!(endpoint.neighbour_counters().learned, 0);
    // An ARP *request* is unaffected, needing no clock to answer.
    assert!(matches!(
        endpoint.handle(None, &arp(), &mut vec![0u8; ROOMY]),
        Outcome::ArpReply { .. }
    ));
}

/// The room this end keeps for a peer's bytes is a bound of this appliance's
/// own, and **the window is what enforces it**: the window advertised is the
/// room actually left, so a peer that keeps to it can fill the array and reach
/// no further, and the transport refuses the rest out of window rather than
/// letting it displace what came before it.
///
/// That is why the session's own overflow count stays at zero here: it is the
/// guard behind the window rather than the mechanism, and a number in it would
/// be a peer the transport had let past one.
#[test]
fn a_peer_filling_the_room_for_it_is_held_there_by_the_window_it_was_given() {
    let mut endpoint = endpoint();
    let now = at(0);
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    pump(&mut endpoint, now);
    let syn = resolve_and_take_syn(&mut endpoint, now, STATION_MAC, STATION_ADDRESS);
    let mut station = Station::new(PEER_PORT, 0x6000_0000);
    station.read(&syn);
    deliver(
        &mut endpoint,
        now,
        &station.frame(lfw_tcp::Flags::SYN.with(lfw_tcp::Flags::ACK), &[]),
    );
    // The handshake alone composes nothing on a stream, so the window is set on
    // the pass that follows it.
    pump(&mut endpoint, now);

    // More than the session keeps, in segments the transport will take, and the
    // consumer above takes none of them.
    let flood: Vec<u8> = (0..RECEIVE_CAPACITY + 64).map(|byte| byte as u8).collect();
    for chunk in flood.chunks(TCP_MSS as usize) {
        let frame = station.frame(lfw_tcp::Flags::ACK.with(lfw_tcp::Flags::PSH), chunk);
        deliver(&mut endpoint, now, &frame);
        pump(&mut endpoint, now);
    }
    let kept = endpoint
        .outbound()
        .map(Session::received)
        .unwrap_or_default();
    assert_eq!(kept.len(), RECEIVE_CAPACITY);
    assert_eq!(kept, &flood[..RECEIVE_CAPACITY]);
    assert_eq!(
        endpoint.outbound_counters().received,
        RECEIVE_CAPACITY as u64
    );
    // The room the window advertises is what is genuinely left, which by here is
    // none at all — and the excess never reached the array to be dropped there,
    // the transport having held the peer to the window it was given.
    assert_eq!(endpoint.outbound().map(Session::room), Some(0));
    assert_eq!(endpoint.outbound_counters().overflowed, 0);

    // And the consumer taking a run of it opens the window again, which is what
    // makes this a stream rather than a bucket.
    endpoint.consume_outbound(1024);
    assert_eq!(endpoint.outbound().map(Session::room), Some(1024));
}

/// Run an unanswered dial's whole retransmission budget out, answering with the
/// instant it was exhausted at.
///
/// The budget is the transport's, so the deadlines are read off its own
/// backoff rather than guessed: a fixed step would either stop short of the
/// abandonment or step past a retransmission the test is counting.
fn exhaust_the_dial(endpoint: &mut Endpoint, from: Monotonic, answer: impl Fn(&[u8]) -> Vec<u8>) {
    let mut now = from;
    // One pass more than the budget: the last is the one that abandons, and a
    // pass that produced nothing is the poll settling rather than a step lost.
    for _ in 0..=lfw_tcp::MAX_RETRANSMITS {
        now = after(now, times(lfw_tcp::MAX_RTO, 1));
        let mut out = vec![0u8; ROOMY];
        while let Some(len) = endpoint.poll_timeouts(now, &mut out).frame() {
            let reply = answer(&out[..len]);
            if !reply.is_empty() {
                deliver(endpoint, now, &reply);
            }
            out = vec![0u8; ROOMY];
        }
        pump(endpoint, now);
    }
}

/// A station that answers the resolution and never the `SYN` ends the session as
/// **unanswered** — not as a connection that "was lost", which is what a station
/// that refused it produces and is a different thing to go and look at.
///
/// The counts beside the token are what make it actionable without the wire: the
/// handshakes this end composed, and the fact that nothing at all came back.
#[test]
fn a_station_that_answers_nothing_ends_the_session_as_unanswered() {
    let mut endpoint = endpoint();
    let now = at(0);
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    pump(&mut endpoint, now);
    resolve_and_take_syn(&mut endpoint, now, STATION_MAC, STATION_ADDRESS);
    exhaust_the_dial(&mut endpoint, now, |_| Vec::new());
    pump(&mut endpoint, now);

    assert_eq!(
        endpoint.outbound().map(Session::phase),
        Some(Phase::Ended(Ended::Unanswered)),
        "silence and a refusal must not read alike"
    );
    let facts = endpoint.outbound().map(Session::facts).expect("a session");
    assert!(
        !facts.answered,
        "a session nothing answered reported an answer"
    );
    assert_eq!(facts.resets_received, 0);
    assert_eq!(facts.resets_sent, 0);
    // The whole budget: the dial itself and every re-send of it. Stated as the
    // transport's own constant rather than as a number, so a budget that moves
    // moves this too.
    assert_eq!(facts.syns, u64::from(lfw_tcp::MAX_RETRANSMITS) + 1);
    // And the resolution's own half, which says the link was fine: one request,
    // one answer. It is the port's account rather than the session's, because a
    // resolved entry outlives the session that learned it.
    let resolutions = endpoint.resolutions();
    assert_eq!(resolutions.requested, 1);
    assert_eq!(resolutions.learned, 1);
}

/// A station that answers the `SYN` by acknowledging a number that was never
/// sent ends the session as **that**, carrying both numbers — and the dial is
/// not cancelled by it, so the session runs its budget out exactly as a silent
/// one does. The two are told apart by the token and by the counts, and by
/// nothing on the wire.
#[test]
fn a_station_acknowledging_what_was_never_sent_ends_the_session_naming_both_numbers() {
    let mut endpoint = endpoint();
    let now = at(0);
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    pump(&mut endpoint, now);
    let syn = resolve_and_take_syn(&mut endpoint, now, STATION_MAC, STATION_ADDRESS);
    let mut station = Station::new(PEER_PORT, 0x7200_0000);
    station.read(&syn);
    // What this end really sent — its `SYN`, so one past its initial sequence
    // number — and a claim five hundred past that, which acknowledges nothing.
    let expected = station.expect.raw();
    let claimed = station.expect.add(500).raw();

    // Answer every handshake this end composes with the same bogus one, which
    // is what a station of this kind does.
    exhaust_the_dial(&mut endpoint, now, |frame| {
        // A fresh station per answer: the number it claims is fixed, so nothing
        // it learned from the last handshake is carried into the next.
        let mut answering = Station::new(PEER_PORT, 0x7200_0000);
        answering.read(frame);
        answering.expect = lfw_tcp::SeqNumber::new(claimed);
        answering.frame(lfw_tcp::Flags::SYN.with(lfw_tcp::Flags::ACK), &[])
    });
    pump(&mut endpoint, now);

    assert_eq!(
        endpoint.outbound().map(Session::phase),
        Some(Phase::Ended(Ended::UnacceptableAcknowledgement {
            claimed,
            expected
        })),
        "the peer's claim and this end's own number are the diagnosis"
    );
    let facts = endpoint.outbound().map(Session::facts).expect("a session");
    assert!(facts.answered, "something did arrive, and it was refused");
    assert_eq!(facts.resets_received, 0, "this end's dial was cancelled");
    assert!(
        facts.resets_sent > 0,
        "a refusal RFC 793 answers with a reset composed none"
    );
    assert_eq!(facts.syns, u64::from(lfw_tcp::MAX_RETRANSMITS) + 1);
}

/// A reset carries the counts that separate it from the two above: something
/// arrived, it was a reset, and this end composed none in answer.
#[test]
fn a_reset_session_reports_the_reset_it_received_and_none_it_sent() {
    let mut endpoint = endpoint();
    let now = at(0);
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    pump(&mut endpoint, now);
    let syn = resolve_and_take_syn(&mut endpoint, now, STATION_MAC, STATION_ADDRESS);
    let mut station = Station::new(PEER_PORT, 0x7300_0000);
    let (_, acknowledgement, _) = station.read(&syn);
    station.next = acknowledgement;
    let reset = station.frame(lfw_tcp::Flags::RST.with(lfw_tcp::Flags::ACK), &[]);
    deliver(&mut endpoint, now, &reset);
    pump(&mut endpoint, now);

    let facts = endpoint.outbound().map(Session::facts).expect("a session");
    assert!(facts.answered);
    assert_eq!(facts.resets_received, 1);
    assert_eq!(
        facts.resets_sent, 0,
        "RFC 793 section 3.4 forbids answering a reset with another"
    );
    // Two handshakes and no more: the first was composed before the next hop
    // resolved and dropped for want of an address, the transport re-sent it, and
    // the station refused that one at once. A refusal is the fastest ending
    // there is, and this count beside a budget-length one is what says so.
    assert_eq!(facts.syns, 2);
}

/// A next hop nothing answers for carries the resolution's own story: every
/// request this end spent, and nothing learned from any of them. That pair is
/// what an operator reads instead of going to the wire.
#[test]
fn an_unreachable_next_hop_reports_the_requests_it_spent_and_nothing_learned() {
    let mut endpoint = endpoint();
    endpoint
        .open_outbound(OFF_LINK, PEER_PORT)
        .expect("a gateway is stated");
    for step in 0..=u64::from(MAX_REQUESTS) {
        pump(&mut endpoint, after(at(0), times(REQUEST_TIMEOUT, step)));
    }
    assert_eq!(
        endpoint.outbound().map(Session::phase),
        Some(Phase::Ended(Ended::NextHopUnreachable))
    );
    let session = endpoint.outbound().expect("a session");
    // The station the frames were really handed to, and which of the port's two
    // answers chose it: an operator reading `gateway` goes to the gateway line
    // of the document and not to the address or the prefix.
    assert_eq!(
        session.next_hop(),
        Hop {
            address: GATEWAY,
            via: Via::Gateway
        }
    );
    let facts = session.facts();
    // A handshake was composed and dropped for want of an address, which is why
    // the count is one and not zero: the transport held it and nothing on this
    // link could carry it.
    assert_eq!(facts.syns, 1);
    assert!(!facts.answered);
    // Every request the budget allows, and nothing learned from any of them.
    let resolutions = endpoint.resolutions();
    assert_eq!(resolutions.requested, u64::from(MAX_REQUESTS));
    assert_eq!(resolutions.learned, 0);
}

/// The replies a port turned away, gathered by reason, and the subtraction that
/// makes them a channel's story rather than a boot's.
#[test]
fn the_replies_a_port_refused_are_counted_by_reason_and_read_as_a_difference() {
    let mut endpoint = endpoint();
    let before = endpoint.resolutions();
    assert_eq!(before, Resolutions::new());

    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    pump(&mut endpoint, at(0));

    // A reply for an address nobody asked about: nothing was waiting on it.
    endpoint.handle(
        Some(at(0)),
        &arp_reply(OUR_MAC, GATEWAY_MAC, GATEWAY, OUR_ADDRESS),
        &mut vec![0u8; ROOMY],
    );
    // And one the frame that carried it contradicts.
    let mut forged = arp_reply(OUR_MAC, STATION_MAC, STATION_ADDRESS, OUR_ADDRESS);
    forged[MAC_PAIR_LEN / 2..MAC_PAIR_LEN].copy_from_slice(&[0x52, 0x54, 0x00, 0xbe, 0xef, 0x01]);
    endpoint.handle(Some(at(0)), &forged, &mut vec![0u8; ROOMY]);

    let after_two = endpoint.resolutions();
    assert_eq!(after_two.requested, 1, "the session's own request");
    assert_eq!(after_two.learned, 0);
    assert_eq!(after_two.unsolicited, 1);
    assert_eq!(after_two.contradicted, 1);
    assert_eq!(after_two.rebinding, 0);
    assert_eq!(after_two.not_unicast, 0);
    // The difference is the channel's, and a reading taken twice with nothing
    // between is zero rather than a repetition of the total.
    assert_eq!(after_two.since(before), after_two);
    assert_eq!(after_two.since(after_two), Resolutions::new());
    // A later reading behind an earlier one is zero and never a complement,
    // which is what keeps a caller holding the pair the wrong way round from
    // reading an enormous count.
    assert_eq!(before.since(after_two), Resolutions::new());
}

/// The counts one attempt carries are **that attempt's own**, and a fresh
/// session starts them from nothing.
///
/// A channel spends one attempt after another and each is reported as itself, so
/// nothing here folds: an attempt whose counts carried a previous attempt's
/// share would report handshakes this session never composed. The resolution's
/// counts are the port's for the same reason turned around — an entry outlives
/// the session that learned it, so those are read as a difference across one
/// attempt's life rather than summed.
#[test]
fn each_attempts_facts_are_its_own_and_start_from_nothing() {
    let mut endpoint = endpoint();
    assert_eq!(
        spend_a_session_on_an_unanswered_next_hop(&mut endpoint, at(0)),
        Ended::NextHopUnreachable
    );
    // One handshake composed and dropped for want of an address, and nothing
    // answered — this attempt's own account and no boot's.
    let later = after(at(0), ENTRY_LIFETIME);
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    let facts = endpoint.outbound().map(Session::facts).expect("a session");
    assert_eq!(
        facts,
        DialFacts::new(),
        "a fresh attempt begins with an empty account rather than the last one's"
    );
    for step in 0..=u64::from(MAX_REQUESTS) {
        pump(&mut endpoint, after(later, times(REQUEST_TIMEOUT, step)));
    }
    let facts = endpoint.outbound().map(Session::facts).expect("a session");
    assert_eq!(facts.syns, 1, "this attempt's handshake and not both");
    assert!(!facts.answered);
}

/// A peer that resets ends the session under a reason of its own, and the port
/// goes on answering everything else — a channel that failed is not a port that
/// stopped.
#[test]
fn a_reset_ends_the_session_and_leaves_the_port_answering() {
    let mut endpoint = endpoint();
    let now = at(0);
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    pump(&mut endpoint, now);
    let syn = resolve_and_take_syn(&mut endpoint, now, STATION_MAC, STATION_ADDRESS);
    let mut station = Station::new(PEER_PORT, 0x7000_0000);
    let (_, acknowledgement, _) = station.read(&syn);
    // A reset that acknowledges what this end sent is the one a dial believes.
    station.next = acknowledgement;
    let reset = station.frame(lfw_tcp::Flags::RST.with(lfw_tcp::Flags::ACK), &[]);
    deliver(&mut endpoint, now, &reset);
    pump(&mut endpoint, now);
    // The reset is its own ending and not a connection that "was lost": a
    // station that refuses this port and one that was never there are two
    // different places to go and look.
    assert_eq!(
        endpoint.outbound().map(Session::phase),
        Some(Phase::Ended(Ended::ResetByPeer))
    );
    assert_eq!(endpoint.outbound_counters().ended, 1);

    // The port is unchanged: an ARP request for its own address is still
    // answered, and a station can still open a connection to it.
    assert!(matches!(
        endpoint.handle(Some(now), &arp(), &mut vec![0u8; ROOMY]),
        Outcome::ArpReply { .. }
    ));
    assert!(endpoint.close_outbound());
}

/// Carry one session to its end against a station that never answers for the
/// next hop, and answer with the phase it ended in.
///
/// The exact shape a management channel re-dialling under a backoff produces:
/// nothing on the link claims the next hop, so every request goes unanswered and
/// the `SYN` composed beside them is dropped for want of an address.
fn spend_a_session_on_an_unanswered_next_hop(endpoint: &mut Endpoint, base: Monotonic) -> Ended {
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    for step in 0..=u64::from(MAX_REQUESTS) {
        pump(endpoint, after(base, times(REQUEST_TIMEOUT, step)));
    }
    let ended = endpoint
        .outbound()
        .and_then(|session| session.phase().ended())
        .expect("the session ends inside its own request budget");
    assert!(endpoint.close_outbound());
    ended
}

/// **The defect this test exists for**: a session that ended at the resolution
/// used to leave behind the connection its unaddressable `SYN` was composed on,
/// so the dial after it was refused by this node's own table and reported a
/// fault of this appliance's where the fault was on the link.
///
/// Two successive sessions to the same destination and port, and both must reach
/// the far end of the resolution and end there. A channel that re-dials under a
/// backoff is the caller this is for: every attempt after the first would
/// otherwise fail for a reason no peer chose.
#[test]
fn a_session_that_ended_at_the_resolution_leaves_no_connection_behind() {
    let mut endpoint = endpoint();
    assert_eq!(
        spend_a_session_on_an_unanswered_next_hop(&mut endpoint, at(0)),
        Ended::NextHopUnreachable
    );
    assert_eq!(
        endpoint.connections(),
        0,
        "the connection the dropped SYN was composed on outlived its session"
    );
    assert_eq!(endpoint.return_paths(), 0);
    assert_eq!(endpoint.tcp_counters().connections_dialled, 1);

    // The cache's entry for a next hop nothing answered for expires, so the
    // second session asks afresh rather than reading a refusal it recorded.
    let later = after(at(0), ENTRY_LIFETIME);
    assert_eq!(
        spend_a_session_on_an_unanswered_next_hop(&mut endpoint, later),
        Ended::NextHopUnreachable,
        "the second dial reports the link rather than this node's own table"
    );
    assert_eq!(endpoint.connections(), 0);
    assert_eq!(
        endpoint.tcp_counters().connections_dialled,
        2,
        "the second session opened a connection of its own"
    );
    assert_eq!(endpoint.outbound_counters().ended, 2);
    assert_eq!(endpoint.outbound_counters().opened, 2);
    assert_eq!(
        endpoint.outbound_counters().open_refused,
        0,
        "no attempt was refused before a frame was composed"
    );
}

/// The other two ways a session ends, held to the same rule: whichever way it
/// went, the transport is left holding nothing for it.
///
/// A reset the transport processed frees the slot itself, so the release finds
/// nothing to give back; a clean close ends with the slot already reaped. Both
/// are stated because a release that got either wrong — answering a `RST` with a
/// second one, or tearing down a connection the peer still believed in — would
/// trade this node's false signal for a protocol fault.
#[test]
fn a_session_that_was_reset_and_one_that_closed_leave_no_connection_behind() {
    let now = at(0);

    let mut refused = endpoint();
    refused
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    pump(&mut refused, now);
    let syn = resolve_and_take_syn(&mut refused, now, STATION_MAC, STATION_ADDRESS);
    let mut station = Station::new(PEER_PORT, 0x7100_0000);
    let (_, acknowledgement, _) = station.read(&syn);
    station.next = acknowledgement;
    let reset = station.frame(lfw_tcp::Flags::RST.with(lfw_tcp::Flags::ACK), &[]);
    assert_eq!(
        deliver(&mut refused, now, &reset),
        None,
        "a reset the transport accepted is never answered with another"
    );
    pump(&mut refused, now);
    assert_eq!(
        refused.outbound().map(Session::phase),
        Some(Phase::Ended(Ended::ResetByPeer))
    );
    assert_eq!(refused.connections(), 0);
    assert_eq!(refused.return_paths(), 0);
    // The reset the peer sent, and none this end composed in answer to it.
    assert_eq!(refused.tcp_counters().resets_received, 1);
    assert_eq!(refused.tcp_counters().resets_sent, 0);
    assert!(refused.close_outbound());
    // And the four-tuple is free: a second dial to it opens rather than being
    // refused for a connection the first left behind.
    assert_eq!(refused.open_outbound(STATION_ADDRESS, PEER_PORT), Ok(()));
    let redialled = pump(&mut refused, now);
    assert_eq!(redialled.len(), 1, "the next hop is known, so the SYN goes");
    let (flags, _, _) = Station::new(PEER_PORT, 0x7300_0000).read(&redialled[0]);
    assert!(flags.contains(lfw_tcp::Flags::SYN));
    assert_eq!(refused.tcp_counters().connections_dialled, 2);
    assert_eq!(
        refused.outbound().map(Session::phase),
        Some(Phase::Dialling),
        "the second SYN went out rather than being refused for the four-tuple"
    );

    let mut answered = endpoint();
    answered
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    pump(&mut answered, now);
    let syn = resolve_and_take_syn(&mut answered, now, STATION_MAC, STATION_ADDRESS);
    let mut station = Station::new(PEER_PORT, 0x7200_0000);
    station.read(&syn);
    deliver(
        &mut answered,
        now,
        &station.frame(lfw_tcp::Flags::SYN.with(lfw_tcp::Flags::ACK), &[]),
    );
    pump(&mut answered, now);
    deliver(
        &mut answered,
        now,
        &station.frame(
            lfw_tcp::Flags::ACK
                .with(lfw_tcp::Flags::PSH)
                .with(lfw_tcp::Flags::FIN),
            b"answer",
        ),
    );
    // The peer hung up; this end answers by ending the session, which is what
    // puts its own close on the wire. A stream has no length that would let
    // this crate decide that for the consumer above it.
    answered.end_outbound_session();
    let closing = pump(&mut answered, now);
    station.read(&closing[0]);
    deliver(&mut answered, now, &station.frame(lfw_tcp::Flags::ACK, &[]));
    pump(&mut answered, now);
    assert_eq!(
        answered.outbound().map(Session::phase),
        Some(Phase::Ended(Ended::ClosedByPeer))
    );
    assert_eq!(answered.connections(), 0);
    assert_eq!(answered.return_paths(), 0);
    assert_eq!(
        answered.tcp_counters().resets_sent,
        0,
        "a close both halves completed was ended again with a reset"
    );
    assert!(answered.close_outbound());
    assert_eq!(answered.open_outbound(STATION_ADDRESS, PEER_PORT), Ok(()));
    assert_eq!(pump(&mut answered, now).len(), 1);
    assert_eq!(answered.tcp_counters().connections_dialled, 2);
    assert_eq!(
        answered.outbound().map(Session::phase),
        Some(Phase::Dialling)
    );
}

/// Every way a session can end has a name of its own, and every phase does too.
///
/// The names are what a metric label and a report line are built from, so a
/// duplicate would collapse two different things for an operator to go and look
/// at into one — and the underscored spelling is what tells a label value apart
/// from the hyphenated console token beside it.
#[test]
fn each_ending_and_each_phase_names_itself_distinctly() {
    let endings = [
        Ended::ClosedByPeer,
        Ended::NextHopUnreachable,
        Ended::NoRoomToResolve,
        Ended::Unanswered,
        Ended::ResetByPeer,
        Ended::UnacceptableAcknowledgement {
            claimed: 0,
            expected: 0,
        },
        Ended::Lost,
        Ended::NoRoomToDial,
        Ended::ConnectionAlreadyOpen,
        Ended::SynDidNotFit,
    ];
    let mut names: Vec<&str> = endings.iter().map(|ended| ended.name()).collect();
    names.sort_unstable();
    let count = names.len();
    names.dedup();
    assert_eq!(names.len(), count, "two endings read alike");
    assert!(
        names.iter().all(|name| !name.contains('-')),
        "a label value is underscored, a console token hyphenated"
    );
    // **None of the ten is a success**, and that is the shape rather than an
    // omission: a channel that came up is a connection this end is still
    // holding rather than a session that ended, so an ending is always a thing
    // to go and look at — a far end that hung up on a channel meant to persist
    // included.
    // The two numbers an unacceptable acknowledgement carries do not change what
    // it is called: the token names the fault and the numbers are the evidence
    // beside it.
    assert_eq!(
        Ended::UnacceptableAcknowledgement {
            claimed: 0,
            expected: 0
        }
        .name(),
        Ended::UnacceptableAcknowledgement {
            claimed: u32::MAX,
            expected: 7
        }
        .name()
    );
    // And each of the transport's three refusals is its own ending rather than
    // one carrying a cause a reader has to open: an operator reading the name
    // knows whether to look at a flood, a four-tuple, or this build.
    // The third, `AlreadyOpen`, names a connection and so cannot be built
    // without one; it is proved end to end by
    // `a_four_tuple_another_connection_holds_refuses_the_dial_and_opens_nothing`,
    // which reaches it through a table that really holds one.
    let refusals = [
        (lfw_tcp::DialError::TableFull, Ended::NoRoomToDial),
        (
            lfw_tcp::DialError::Write(lfw_tcp::WriteError::DoesNotFit {
                needed: 1,
                capacity: 0,
            }),
            Ended::SynDidNotFit,
        ),
    ];
    for (error, expected) in refusals {
        assert_eq!(Ended::refused(error), expected, "{error:?}");
    }

    let phases = [
        Phase::Resolving,
        Phase::Dialling,
        Phase::Established,
        Phase::Closing,
        Phase::Ended(Ended::ClosedByPeer),
    ];
    let mut names: Vec<&str> = phases.iter().map(|phase| phase.name()).collect();
    names.sort_unstable();
    let count = names.len();
    names.dedup();
    assert_eq!(names.len(), count, "two phases read alike");
    assert_eq!(
        phases
            .iter()
            .filter(|phase| phase.ended().is_some())
            .count(),
        1,
        "exactly one phase is an ending"
    );
}

/// The four-tuple a dial wants cannot be taken from under it, because nothing
/// on this port can be opened by a peer at all.
///
/// The station knocks on the very port and four-tuple the dial will use — the
/// one case the transport's table could not tell two connections apart in — and
/// the transport refuses it as `not_listening` rather than accepting it. The
/// dial then goes out as though the station had never spoken, which is the
/// whole of what withdrawing the passive open buys.
#[test]
fn a_station_cannot_take_the_four_tuple_the_dial_wants() {
    let mut endpoint = endpoint();
    let now = at(0);

    let mut station = Station::new(PEER_PORT, 0x7400_0000);
    let syn = station.frame(lfw_tcp::Flags::SYN, &[]);
    assert!(
        deliver(&mut endpoint, now, &syn).is_none(),
        "a SYN for the port that dials only was answered"
    );
    assert_eq!(endpoint.connections(), 0, "a SYN opened a connection");
    assert_eq!(endpoint.return_paths(), 0);
    assert_eq!(endpoint.tcp_counters().connections_accepted, 0);
    assert_eq!(endpoint.tcp_counters().refused_not_listening, 1);
    // Dropped in silence, so the station learns nothing about what is behind
    // the port — not even that something refused it.
    assert_eq!(endpoint.tcp_counters().resets_sent, 0);

    // And the dial proceeds, taking the four-tuple the station tried to hold.
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    pump(&mut endpoint, now);
    resolve_and_take_syn(&mut endpoint, now, STATION_MAC, STATION_ADDRESS);
    assert_eq!(endpoint.connections(), 1);
    assert_eq!(endpoint.outbound_counters().dialled, 1);
    assert!(matches!(
        endpoint.outbound().map(Session::phase),
        Some(Phase::Dialling)
    ));
}

proptest! {
    /// A resolved entry is immutable for its lifetime, so no later reply — from
    /// any station, claiming any hardware address — re-binds a next hop this port
    /// is using.
    #[test]
    fn a_resolved_next_hop_is_never_rebound_by_a_later_reply(
        octets in prop::array::uniform6(any::<u8>()),
    ) {
        let mut endpoint = endpoint();
        let now = at(0);
        endpoint
            .open_outbound(STATION_ADDRESS, PEER_PORT)
            .expect("an on-link destination");
        pump(&mut endpoint, now);
        endpoint.handle(
            Some(now),
            &arp_reply(OUR_MAC, STATION_MAC, STATION_ADDRESS, OUR_ADDRESS),
            &mut vec![0u8; ROOMY],
        );
        prop_assert_eq!(endpoint.neighbour_counters().learned, 1);

        let claimed = MacAddress(octets);
        let second = arp_reply(OUR_MAC, claimed, STATION_ADDRESS, OUR_ADDRESS);
        let outcome = endpoint.handle(Some(now), &second, &mut vec![0u8; ROOMY]);
        // Whatever the second reply was refused for, it was refused: a
        // non-unicast claimant never reaches the cache at all, and a unicast one
        // meets an entry that is already resolved.
        prop_assert_ne!(outcome, Outcome::Neighbour(Learned::Resolved));
        prop_assert_eq!(endpoint.neighbour_counters().learned, 1);

        // And the frame the session sends still goes to the station that
        // answered first.
        prop_assert!(pump(&mut endpoint, now).is_empty());
        let mut out = vec![0u8; ROOMY];
        let len = endpoint
            .poll_timeouts(after(now, lfw_tcp::INITIAL_RTO), &mut out)
            .frame()
            .expect("the SYN is re-sent");
        let ethernet = Ethernet::parse(&out[..len]).expect("a frame");
        prop_assert_eq!(ethernet.header.destination, STATION_MAC);
    }

    /// Whatever a station puts on this wire, a session only ever stands in a
    /// phase a session can reach, the cache never holds more than it has room
    /// for, and nothing panics.
    #[test]
    fn an_arbitrary_frame_stream_never_moves_a_session_where_it_cannot_go(
        frames in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..80), 0..24),
        elapsed in prop::collection::vec(0u64..4_000, 0..24),
    ) {
        let mut endpoint = endpoint();
        endpoint
            .open_outbound(STATION_ADDRESS, PEER_PORT)
            .expect("an on-link destination");
        let mut clock = 0u64;
        for (index, frame) in frames.iter().enumerate() {
            clock = clock.saturating_add(elapsed.get(index).copied().unwrap_or(0));
            let now = at(clock * 1_000_000);
            let mut out = vec![0u8; ROOMY];
            endpoint.handle(Some(now), frame, &mut out);
            for _ in 0..8 {
                let mut scratch = vec![0u8; ROOMY];
                if !endpoint.poll_outbound(now, &mut scratch).goes_on() {
                    break;
                }
            }
            for _ in 0..8 {
                let mut scratch = vec![0u8; ROOMY];
                if !endpoint.poll_timeouts(now, &mut scratch).goes_on() {
                    break;
                }
            }
            let phase = endpoint.outbound().map(Session::phase);
            prop_assert!(phase.is_some(), "a session nobody closed disappeared");
            // A session that never reached a hardware address cannot have got
            // as far as a peer closing its half.
            if matches!(phase, Some(Phase::Ended(Ended::ClosedByPeer))) {
                prop_assert_eq!(endpoint.neighbour_counters().learned, 1);
            }
            prop_assert!(endpoint.return_paths() <= endpoint.connections());
            prop_assert_eq!(
                endpoint.counters().total(),
                (index + 1) as u64,
                "every frame handed over is counted exactly once"
            );
        }
    }
}

/// The cache holds what this end asked about and nothing a peer chose, so a link
/// full of stations announcing themselves cannot fill it.
#[test]
fn unsolicited_replies_cannot_fill_the_neighbour_table() {
    let mut endpoint = endpoint();
    for last in 100u8..(100 + NEIGHBOURS as u8 * 4) {
        let address = Ipv4Address::from_octets([10, 0, 2, last]);
        let mac = MacAddress([0x52, 0x54, 0x00, 0x00, 0x01, last]);
        endpoint.handle(
            Some(at(0)),
            &arp_reply(OUR_MAC, mac, address, OUR_ADDRESS),
            &mut vec![0u8; ROOMY],
        );
    }
    assert_eq!(endpoint.neighbour_counters().learned, 0);
    assert_eq!(endpoint.neighbour_counters().no_room, 0);
    // And a dial opened afterwards still finds room to ask.
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    let asked = pump(&mut endpoint, at(0));
    assert_eq!(asked_about(&asked[0]), STATION_ADDRESS);
}

/// An entry is used for its lifetime and no longer, which is what bounds the
/// cost of a resolved entry being immutable: a next hop whose hardware address
/// genuinely moved is followed once the old answer has expired.
#[test]
fn a_resolved_entry_stops_being_an_answer_once_its_lifetime_runs_out() {
    let mut endpoint = endpoint();
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    pump(&mut endpoint, at(0));
    endpoint.handle(
        Some(at(0)),
        &arp_reply(OUR_MAC, STATION_MAC, STATION_ADDRESS, OUR_ADDRESS),
        &mut vec![0u8; ROOMY],
    );
    assert_eq!(endpoint.neighbour_counters().learned, 1);
    assert_eq!(endpoint.neighbour_counters().requested, 1);

    // Inside the lifetime the entry is the answer, so a second reply for it is
    // refused as a rebinding rather than taken.
    let inside = after(at(0), lfw_tcp::INITIAL_RTO);
    assert_eq!(
        endpoint.handle(
            Some(inside),
            &arp_reply(OUR_MAC, STATION_MAC, STATION_ADDRESS, OUR_ADDRESS),
            &mut vec![0u8; ROOMY],
        ),
        Outcome::Neighbour(Learned::AlreadyResolved)
    );
    assert_eq!(endpoint.neighbour_counters().rebinding_refused, 1);

    // Past it the entry is gone: the same reply answers nothing, and the next
    // question about the address is a fresh request rather than a stale answer.
    let past = after(at(0), ENTRY_LIFETIME);
    assert_eq!(
        endpoint.handle(
            Some(past),
            &arp_reply(OUR_MAC, STATION_MAC, STATION_ADDRESS, OUR_ADDRESS),
            &mut vec![0u8; ROOMY],
        ),
        Outcome::Neighbour(Learned::Unsolicited)
    );
    assert_eq!(endpoint.neighbour_counters().expired, 1);
    let asked = pump(&mut endpoint, past);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked_about(&asked[0]), STATION_ADDRESS);
    assert_eq!(endpoint.neighbour_counters().requested, 2);
}

// ---------------------------------------------------------------------------
// The send window: what the peer acknowledges leaves, and the room comes back

/// A session up against a station that answered everything, which is where every
/// case about the send window starts. `iss` is the station's own initial
/// sequence number, so a case can put the origin anywhere in the space —
/// including where moving it wraps.
fn established_dial(iss: u32) -> (Endpoint, Station, Monotonic) {
    let mut endpoint = endpoint();
    let now = at(0);
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    assert_eq!(pump(&mut endpoint, now).len(), 1, "the resolution is asked");
    let syn = resolve_and_take_syn(&mut endpoint, now, STATION_MAC, STATION_ADDRESS);
    let later = after(now, lfw_tcp::INITIAL_RTO);
    let mut station = Station::new(PEER_PORT, iss);
    let (flags, _, _) = station.read(&syn);
    assert!(flags.contains(lfw_tcp::Flags::SYN));
    let synack = station.frame(lfw_tcp::Flags::SYN.with(lfw_tcp::Flags::ACK), &[]);
    deliver(&mut endpoint, later, &synack);
    assert!(pump(&mut endpoint, later).is_empty());
    (endpoint, station, later)
}

/// Offer `bytes` to the session and carry them across to `station`, which
/// acknowledges every segment it reads, answering the payload that crossed in
/// order.
///
/// The rounds are bounded by the bytes offered and not by a clock: each one
/// hands the window whatever room it has, takes every segment the peer's window
/// allows, and acknowledges them — so a round that moved nothing with bytes
/// still in hand is the stall this reports rather than a test that spins.
fn stream_acknowledged(
    endpoint: &mut Endpoint,
    station: &mut Station,
    now: Monotonic,
    bytes: &[u8],
) -> Vec<u8> {
    let mut crossed = Vec::new();
    let mut offered = 0usize;
    for _ in 0..bytes.len().div_ceil(64) + 8 {
        // Only what the window says it has room for, which is what a consumer
        // that asks first does — and what makes a refusal here a defect rather
        // than this helper over-offering. That the answer is exact is pinned
        // on the way past.
        let want = bytes
            .len()
            .saturating_sub(offered)
            .min(endpoint.outbound_send_room());
        let taken = endpoint.push_outbound(bytes.get(offered..offered + want).unwrap_or_default());
        assert_eq!(taken, want, "the room answered was the room there was");
        offered += taken;
        let frames = pump(endpoint, now);
        if frames.is_empty() {
            break;
        }
        for frame in &frames {
            let (_, _, payload) = station.read(frame);
            crossed.extend_from_slice(&payload);
        }
        let ack = station.frame(lfw_tcp::Flags::ACK, &[]);
        deliver(endpoint, now, &ack);
    }
    assert_eq!(offered, bytes.len(), "every byte was taken by the window");
    crossed
}

/// A run of `len` bytes no two of which are equal by position, so a byte served
/// from the wrong offset is visible rather than merely plausible.
fn marked(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| {
            // Two bytes of the index folded into one, which repeats every 65536
            // — far past any run these cases stream.
            let index = index as u32;
            ((index & 0xff) ^ ((index >> 8) & 0xff) ^ 0x5a) as u8
        })
        .collect()
}

proptest! {
    /// **The window drains, so the session is not bounded by it.** A run many
    /// times the window's own size crosses whole, byte for byte and in order,
    /// and not one byte of it is ever refused: what the peer acknowledges leaves
    /// the array and the room it occupied takes the bytes behind it.
    ///
    /// The multiple is the property. At one window's worth this would pass
    /// against an array that never drained at all, which is exactly the defect
    /// it exists to catch.
    #[test]
    fn a_run_many_windows_long_crosses_whole_and_is_never_refused(
        windows in 2usize..=6,
        trailing in 0usize..1024,
    ) {
        let (mut endpoint, mut station, now) = established_dial(0x5000_0000);
        let bytes = marked(SEND_CAPACITY * windows + trailing);
        let crossed = stream_acknowledged(&mut endpoint, &mut station, now, &bytes);
        prop_assert_eq!(crossed.len(), bytes.len());
        prop_assert!(crossed == bytes, "the stream crossed in order and unaltered");
        prop_assert_eq!(endpoint.outbound_counters().refused, 0);
        prop_assert_eq!(endpoint.outbound_counters().sent, bytes.len() as u64);
        // And the window is empty again, so the next run has the whole of it.
        prop_assert_eq!(endpoint.outbound_send_room(), SEND_CAPACITY);
    }
}

/// **A retransmission after the origin has moved serves the bytes it names.**
/// The whole hazard of a sliding window is here: offset zero is no longer stream
/// byte zero, so a range asked for again must be found relative to where the
/// window now starts and not to where it once did.
#[test]
fn a_retransmission_across_a_moved_origin_serves_the_bytes_it_names() {
    let (mut endpoint, mut station, now) = established_dial(0x6000_0000);
    // First, a run the station acknowledges, which moves the origin off byte
    // zero. Nothing about the case works if this does not happen, so it is
    // asserted rather than assumed.
    let first = marked(3000);
    assert_eq!(
        stream_acknowledged(&mut endpoint, &mut station, now, &first),
        first
    );
    assert_eq!(endpoint.outbound_send_room(), SEND_CAPACITY);

    // Then a run the station reads and never acknowledges.
    let second: Vec<u8> = marked(4096).into_iter().map(|byte| !byte).collect();
    assert_eq!(endpoint.push_outbound(&second), second.len());
    let sent = pump(&mut endpoint, now);
    assert!(!sent.is_empty(), "the second run goes out");
    let mut across = Vec::new();
    let mut sequences = Vec::new();
    for frame in &sent {
        let (_, _, payload) = station.read(frame);
        sequences.push(sequence_of(frame));
        across.extend_from_slice(&payload);
    }

    // The transport asks for the oldest of them again, and what comes back must
    // be that very range under that very number.
    let mut out = vec![0u8; ROOMY];
    let len = endpoint
        .poll_timeouts(after(now, times(lfw_tcp::INITIAL_RTO, 4)), &mut out)
        .frame()
        .expect("the oldest unacknowledged range is re-sent");
    out.truncate(len);
    let (_, _, again) = station.read(&out);
    assert_eq!(
        sequence_of(&out),
        sequences[0],
        "the retransmission names the range it is re-sending"
    );
    assert_eq!(
        again,
        second.get(..again.len()).expect("a prefix of the run"),
        "and carries that range's own bytes, not the ones that used to sit there"
    );
}

/// **An acknowledgement landing inside a segment releases nothing of it.** A peer
/// may acknowledge any byte boundary it likes, and one in the middle of a segment
/// advances the transport's acknowledgement while leaving that whole segment on
/// its books — so a window released to the acknowledgement would drop bytes a
/// retransmission is still owed and then have nothing to answer it with. The
/// boundary is therefore the oldest range the transport may still ask for, not the
/// number the peer named.
#[test]
fn an_acknowledgement_inside_a_segment_leaves_that_segment_retransmittable() {
    let (mut endpoint, mut station, now) = established_dial(0x9000_0000);
    let bytes = marked(1200);
    assert_eq!(endpoint.push_outbound(&bytes), bytes.len());
    let sent = pump(&mut endpoint, now);
    assert_eq!(sent.len(), 1, "the run fits one segment");
    let first = sequence_of(&sent[0]);
    let (_, _, payload) = station.read(&sent[0]);
    assert_eq!(payload, bytes);

    // Half of that segment, which is a boundary the peer is entitled to name and
    // which retires nothing.
    let half = station.acknowledging(first.add(600), lfw_tcp::Flags::ACK, &[]);
    deliver(&mut endpoint, now, &half);
    assert_eq!(
        endpoint.outbound_send_room(),
        SEND_CAPACITY - bytes.len(),
        "nothing left the window, the whole segment still being owed"
    );

    // And the retransmission still has every byte it names.
    let mut out = vec![0u8; ROOMY];
    let len = endpoint
        .poll_timeouts(after(now, times(lfw_tcp::INITIAL_RTO, 4)), &mut out)
        .frame()
        .expect("the segment is re-sent");
    out.truncate(len);
    assert_eq!(sequence_of(&out), first);
    let (_, _, again) = station.read(&out);
    assert_eq!(again, bytes, "and carries the whole of what it named");

    // Once the peer acknowledges the segment's end, it leaves.
    let whole = station.acknowledging(first.add(1200), lfw_tcp::Flags::ACK, &[]);
    deliver(&mut endpoint, now, &whole);
    assert_eq!(endpoint.outbound_send_room(), SEND_CAPACITY);
}

/// **A peer that acknowledges nothing fills the window and leaves it full**, and
/// that is backpressure rather than a failure: the session is still established,
/// nothing is counted as lost, and the moment one acknowledgement arrives the
/// room comes back.
#[test]
fn a_peer_that_acknowledges_nothing_fills_the_window_and_that_is_not_a_failure() {
    let (mut endpoint, mut station, now) = established_dial(0x7000_0000);
    let bytes = marked(SEND_CAPACITY);
    assert_eq!(endpoint.push_outbound(&bytes), SEND_CAPACITY);
    assert_eq!(endpoint.outbound_send_room(), 0);
    // Everything the peer's window allows goes out and is never acknowledged.
    let sent = pump(&mut endpoint, now);
    assert!(!sent.is_empty());
    for frame in &sent {
        station.read(frame);
    }
    // A full window refuses what will not fit and says how much, and the session
    // is untouched by it.
    assert_eq!(endpoint.push_outbound(b"more"), 0);
    assert_eq!(endpoint.outbound_counters().refused, 4);
    assert_eq!(
        endpoint.outbound().map(Session::phase),
        Some(Phase::Established)
    );
    assert_eq!(endpoint.outbound_counters().ended, 0);
    assert_eq!(endpoint.outbound_send_room(), 0);

    // And one acknowledgement is all it takes for the room to come back.
    let ack = station.frame(lfw_tcp::Flags::ACK, &[]);
    deliver(&mut endpoint, now, &ack);
    let freed = endpoint.outbound_send_room();
    assert!(freed > 0, "the acknowledged bytes left the window");
    assert_eq!(endpoint.push_outbound(b"more"), 4);
}

/// **A peer cannot make the window give up a byte it has not acknowledged.** A
/// duplicate acknowledgement, one behind the origin, and one past everything
/// sent are the three shapes it has, and none of them moves the window further
/// than the transport's own boundary — which the transport refuses to put past
/// what went out.
#[test]
fn no_acknowledgement_a_peer_can_send_releases_a_byte_it_did_not_cover() {
    let (mut endpoint, mut station, now) = established_dial(0x8000_0000);
    let bytes = marked(2048);
    assert_eq!(endpoint.push_outbound(&bytes), bytes.len());
    let sent = pump(&mut endpoint, now);
    assert!(!sent.is_empty());
    let first = sequence_of(&sent[0]);
    for frame in &sent {
        station.read(frame);
    }
    let room_before = endpoint.outbound_send_room();

    // An acknowledgement of the very first byte's number acknowledges nothing:
    // it is where the window already starts.
    let stale = station.acknowledging(first, lfw_tcp::Flags::ACK, &[]);
    deliver(&mut endpoint, now, &stale);
    assert_eq!(endpoint.outbound_send_room(), room_before);

    // One behind that is a number this end has never held. It releases nothing
    // either, rather than reading as an enormous run of released bytes.
    let behind = station.acknowledging(first.sub(64), lfw_tcp::Flags::ACK, &[]);
    deliver(&mut endpoint, now, &behind);
    assert_eq!(endpoint.outbound_send_room(), room_before);

    // And one far past everything sent is refused by the transport — the same
    // refusal a station claiming a number that was never sent has always drawn
    // — so the window never sees it at all, and the session records it as the
    // thing an operator has to go and look at.
    let ahead = station.acknowledging(first.add(1 << 20), lfw_tcp::Flags::ACK, &[]);
    deliver(&mut endpoint, now, &ahead);
    assert_eq!(endpoint.outbound_send_room(), room_before);
    assert!(
        matches!(
            endpoint.outbound().map(Session::ending),
            Some(Ended::UnacceptableAcknowledgement { .. })
        ),
        "the claim of a number never sent is the refusal it has always been"
    );

    // What the peer really acknowledged is still what leaves, and only that.
    let honest = station.frame(lfw_tcp::Flags::ACK, &[]);
    deliver(&mut endpoint, now, &honest);
    assert!(endpoint.outbound_send_room() > room_before);
}

/// **The origin moves correctly across the wrap, and no number a peer can name
/// takes more than the window holds.** Sequence space is a circle, so an origin
/// just below 2^32 releases bytes whose numbers are on the other side of it, and
/// the arithmetic that finds them must be the sequence space's rather than an
/// integer's.
///
/// Driven on the session directly, because this end's own initial sequence
/// number is the generator's: no dial can be steered to the wrap from outside,
/// so a case that only asked a station for one would prove nothing about the
/// side of the space the origin is on.
#[test]
fn a_window_whose_origin_crosses_the_wrap_releases_and_finds_the_right_bytes() {
    let mut session = Session::new(
        STATION_ADDRESS,
        PEER_PORT,
        Hop {
            address: STATION_ADDRESS,
            via: Via::Prefix,
        },
    );
    let bytes = marked(600);
    assert_eq!(session.push(&bytes), (600, 0));
    // The window starts 100 short of the top of the space, so releasing 200 puts
    // the origin 100 past it.
    let base = lfw_tcp::SeqNumber::new(u32::MAX - 99);
    session.note_base(base);
    session.took(600);
    assert_eq!(session.release(base.add(200)), 200);

    // Offset zero is now the stream's 200th byte, whose number is on the far
    // side of the wrap, and every held byte is found at its own number.
    assert_eq!(session.offset_of(base.add(200)), Some(0));
    assert_eq!(session.range(0, 8), bytes.get(200..208));
    assert_eq!(session.offset_of(base.add(599)), Some(399));
    assert_eq!(session.range(399, 1), bytes.get(599..600));

    // What left is gone rather than hidden: the numbers it occupied answer
    // nothing, which is what keeps a retransmission from serving a byte that has
    // been acknowledged and overwritten.
    assert_eq!(session.offset_of(base), None);
    assert_eq!(session.offset_of(base.add(199)), None);

    // A number behind the origin releases nothing. This is the one way unsigned
    // sequence arithmetic can hand a peer the whole window — a distance measured
    // backwards is the enormous complement — and the ordering test in front of it
    // is what stops it.
    assert_eq!(session.release(base.add(199)), 0);
    assert_eq!(session.offset_of(base.add(200)), Some(0));

    // And a number past everything sent takes what was sent and not one byte
    // more, which is both the close acknowledged along with the bytes in front
    // of it and the bound that keeps a release inside the array.
    assert_eq!(session.release(base.add(1 << 20)), 400);
    assert_eq!(session.send_room(), SEND_CAPACITY);
    assert_eq!(session.offset_of(base.add(600)), None);
}

// ---------------------------------------------------------------------------
// The onboarding port: the second listening port, and the byte stream on it.

use crate::onboard::{Ended as OnboardEnded, INBOUND_CAPACITY, OUTBOUND_CAPACITY};

/// Drive the onboarding half to exhaustion, collecting every frame it composed.
///
/// A loop rather than one call for the reason the caller in the protection
/// domain has one: a step that produced no frame is not a pass with nothing
/// left to do, and stopping there would leave the close behind the bytes.
fn drain_onboarding(endpoint: &mut Endpoint, now: Monotonic) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    for _ in 0..16 {
        let mut out = vec![0u8; ROOMY];
        match endpoint.poll_onboarding(now, &mut out) {
            Polled::Frame { len } => {
                out.truncate(len);
                frames.push(out);
            }
            Polled::Handled => {}
            Polled::Idle => break,
        }
    }
    frames
}

/// Open a connection on the onboarding port and answer its `SYN-ACK`, leaving
/// the station established.
fn onboarding_station(endpoint: &mut Endpoint) -> Station {
    let mut station = Station::onboarding(0xc351, 0x1234_0000);
    let syn = station.frame(lfw_tcp::Flags::SYN, &[]);
    let mut out = vec![0u8; ROOMY];
    let outcome = endpoint.handle(Some(at(0)), &syn, &mut out);
    let len = outcome.reply().expect("a SYN-ACK");
    let (flags, _, _) = station.read(&out[..len]);
    assert!(flags.contains(lfw_tcp::Flags::SYN) && flags.contains(lfw_tcp::Flags::ACK));
    let ack = station.frame(lfw_tcp::Flags::ACK, &[]);
    endpoint.handle(Some(at(1)), &ack, &mut out);
    station
}

#[test]
fn a_segment_for_the_onboarding_port_reaches_the_other_transport() {
    let mut endpoint = endpoint();
    let station = onboarding_station(&mut endpoint);
    assert_eq!(station.destination, ONBOARDING_PORT);
    let counters = endpoint.counters();
    // Two segments on the onboarding port and none on the HTTP one: the demux
    // is what this states, and a total over both would state nothing.
    assert_eq!(counters.onboarding_segments, 2);
    assert_eq!(counters.tcp_segments, 0);
    assert_eq!(endpoint.tcp_counters().connections_accepted, 0);
    assert_eq!(endpoint.onboarding_counters().connections_accepted, 1);
    assert!(endpoint.stream().connection().is_some());
    assert_eq!(endpoint.stream_counters().accepted, 1);
}

#[test]
fn bytes_on_the_onboarding_port_are_held_for_the_consumer_and_never_answered() {
    let mut endpoint = endpoint();
    let mut station = onboarding_station(&mut endpoint);
    let data = station.frame(lfw_tcp::Flags::ACK.with(lfw_tcp::Flags::PSH), b"records");
    let mut out = vec![0u8; ROOMY];
    endpoint.handle(Some(at(2)), &data, &mut out);
    assert_eq!(endpoint.stream().received(), b"records");
    assert_eq!(endpoint.stream_counters().received, 7);
    // Nothing is composed in answer beyond the transport's own acknowledgement:
    // this crate never decides what a record means.
    assert!(drain_onboarding(&mut endpoint, at(3)).is_empty());
    assert_eq!(endpoint.stream_counters().sent, 0);
}

#[test]
fn what_the_consumer_answers_with_goes_out_and_the_close_follows_it() {
    let mut endpoint = endpoint();
    let mut station = onboarding_station(&mut endpoint);
    endpoint.stream_mut().push(b"server hello");
    let session = endpoint.stream().connection().expect("an accepted session");
    assert!(endpoint.stream_mut().end_session(session));
    let frames = drain_onboarding(&mut endpoint, at(2));
    assert_eq!(frames.len(), 2, "the bytes, and then the close behind them");
    let (flags, _, payload) = station.read(&frames[0]);
    assert_eq!(payload, b"server hello");
    assert!(!flags.contains(lfw_tcp::Flags::FIN));
    let (flags, _, _) = station.read(&frames[1]);
    assert!(flags.contains(lfw_tcp::Flags::FIN));
    assert_eq!(endpoint.stream_counters().sent, 12);
    assert_eq!(endpoint.stream_counters().closed_by_consumer, 1);
}

#[test]
fn a_peer_that_closes_is_reported_as_the_end_that_finished_the_session() {
    let mut endpoint = endpoint();
    let mut station = onboarding_station(&mut endpoint);
    let fin = station.frame(lfw_tcp::Flags::FIN.with(lfw_tcp::Flags::ACK), &[]);
    let mut out = vec![0u8; ROOMY];
    endpoint.handle(Some(at(2)), &fin, &mut out);
    assert!(endpoint.stream().peer_closed());
    assert_eq!(endpoint.stream().ending(), OnboardEnded::ByPeer);
    // The consumer answers the close, and the order the two happened in is what
    // the ending keeps: the peer hung up first.
    let session = endpoint.stream().connection().expect("an accepted session");
    assert!(endpoint.stream_mut().end_session(session));
    assert_eq!(endpoint.stream().ending(), OnboardEnded::ByPeer);
    let frames = drain_onboarding(&mut endpoint, at(3));
    let (flags, _, _) = station.read(frames.last().expect("this end's own close"));
    assert!(flags.contains(lfw_tcp::Flags::FIN));
    // And once the transport has given the connection back, the ending is there
    // to be taken exactly once. A reset gets it there in one frame; the
    // ordinary path is the same reconciliation a `TIME_WAIT` reaches later.
    let reset = station.frame(lfw_tcp::Flags::RST, &[]);
    endpoint.handle(Some(at(4)), &reset, &mut out);
    assert_eq!(
        endpoint.stream_mut().take_ending(),
        Some(OnboardEnded::ByPeer)
    );
    assert_eq!(endpoint.stream_mut().take_ending(), None);
}

#[test]
fn a_second_connection_while_one_is_running_is_dropped_in_silence() {
    let mut endpoint = endpoint();
    let _running = onboarding_station(&mut endpoint);
    // A different peer port, so it is a second connection rather than a
    // retransmitted `SYN`. The table holds one and an established connection is
    // not evictable, so there is no room and no answer.
    let mut second = Station::onboarding(0xc352, 0x5678_0000);
    let syn = second.frame(lfw_tcp::Flags::SYN, &[]);
    let mut out = vec![0u8; ROOMY];
    let outcome = endpoint.handle(Some(at(2)), &syn, &mut out);
    assert_eq!(outcome.reply(), None);
    assert_eq!(
        outcome.tcp(),
        Some(lfw_tcp::Outcome::Rejected(lfw_tcp::Rejection::TableFull))
    );
    assert_eq!(endpoint.stream_counters().accepted, 1);
    // Silent on the wire and not silent on the surfaces, which is the whole
    // reason the two transports are counted apart: the refusal is this port's,
    // and the HTTP server's own table — eight connections, none of them this —
    // must not have been charged for it.
    assert_eq!(endpoint.onboarding_counters().refused_table_full, 1);
    assert_eq!(endpoint.tcp_counters().refused_table_full, 0);
}

#[test]
fn a_consumer_answer_past_the_room_for_one_is_refused_rather_than_truncated() {
    let mut endpoint = endpoint();
    let _station = onboarding_station(&mut endpoint);
    let answer = vec![0xa5u8; OUTBOUND_CAPACITY + 16];
    let kept = endpoint.stream_mut().push(&answer);
    assert_eq!(kept, OUTBOUND_CAPACITY);
    assert_eq!(endpoint.stream_counters().refused, 16);
}

#[test]
fn a_peer_past_the_window_it_was_given_is_counted_rather_than_believed() {
    let mut endpoint = endpoint();
    let _station = onboarding_station(&mut endpoint);
    // Handed straight to the stream, which is the only way past the window: the
    // transport would refuse the segment carrying it long before this.
    let flood = vec![0x5au8; INBOUND_CAPACITY + 8];
    endpoint.stream_mut().take(&flood);
    assert_eq!(endpoint.stream().received().len(), INBOUND_CAPACITY);
    assert_eq!(endpoint.stream_counters().overflowed, 8);
    assert_eq!(endpoint.stream().room(), 0);
    // And what the consumer takes is given back to the window.
    endpoint.stream_mut().consumed(1024);
    assert_eq!(endpoint.stream().room(), 1024);
    assert_eq!(endpoint.stream().received().len(), INBOUND_CAPACITY - 1024);
}

#[test]
fn a_connection_the_transport_gives_back_ends_the_session_as_forgotten() {
    let mut endpoint = endpoint();
    let mut station = onboarding_station(&mut endpoint);
    let reset = station.frame(lfw_tcp::Flags::RST, &[]);
    let mut out = vec![0u8; ROOMY];
    endpoint.handle(Some(at(2)), &reset, &mut out);
    assert!(endpoint.stream().connection().is_none());
    assert_eq!(
        endpoint.stream_mut().take_ending(),
        Some(OnboardEnded::Forgotten)
    );
    assert_eq!(endpoint.stream_counters().forgotten, 1);
    assert_eq!(OnboardEnded::Forgotten.name(), "forgotten");
    assert_eq!(OnboardEnded::ByPeer.name(), "peer");
    assert_eq!(OnboardEnded::ByConsumer.name(), "consumer");
}

#[test]
fn an_onboarding_segment_with_no_clock_is_refused_like_every_other() {
    let mut endpoint = endpoint();
    let mut station = Station::onboarding(0xc353, 0x9999_0000);
    let syn = station.frame(lfw_tcp::Flags::SYN, &[]);
    let mut out = vec![0u8; ROOMY];
    assert_eq!(endpoint.handle(None, &syn, &mut out), Outcome::Unclocked);
    assert_eq!(endpoint.counters().unclocked, 1);
    assert_eq!(endpoint.counters().onboarding_segments, 0);
}

#[test]
fn a_segment_too_short_to_name_a_port_goes_to_the_management_stack_and_is_counted() {
    let mut endpoint = endpoint();
    // Three bytes: the destination-port field is not whole, so nothing can
    // choose a stack by it and the segment must still be counted somewhere.
    let frame = Datagram {
        protocol: Protocol::TCP,
        payload: vec![0u8; 3],
        seal_icmp: false,
        ..Datagram::echo()
    }
    .build();
    let mut out = vec![0u8; ROOMY];
    let outcome = endpoint.handle(Some(at(0)), &frame, &mut out);
    assert!(matches!(outcome, Outcome::Tcp { .. }));
    assert_eq!(endpoint.counters().tcp_segments, 1);
    assert_eq!(endpoint.counters().onboarding_segments, 0);
}

#[test]
fn the_two_ports_compose_different_initial_sequence_numbers() {
    let mut endpoint = endpoint();
    let mut out = vec![0u8; ROOMY];
    // The dialling port's own number, off the `SYN` it composes: this port
    // answers no handshake, so the only sequence space it ever states is the
    // one it opens itself.
    endpoint
        .open_outbound(STATION_ADDRESS, PEER_PORT)
        .expect("an on-link destination");
    pump(&mut endpoint, at(0));
    let syn = resolve_and_take_syn(&mut endpoint, at(0), STATION_MAC, STATION_ADDRESS);
    let dialled = sequence_of(&syn).raw();
    // The listening port's, off the `SYN-ACK` it answers with. The same peer
    // address, the same instant and the same secret.
    let mut onboarding = Station::onboarding(PEER_PORT, 0x1111_0000);
    let syn = onboarding.frame(lfw_tcp::Flags::SYN, &[]);
    let len = endpoint
        .handle(Some(at(0)), &syn, &mut out)
        .reply()
        .expect("a SYN-ACK");
    let accepted = sequence_of(&out[..len]).raw();
    // What makes the two numbers differ is the local port in the derivation,
    // which is what keeps one port's sequence space from being readable off the
    // other's.
    assert_ne!(dialled, accepted);
}
