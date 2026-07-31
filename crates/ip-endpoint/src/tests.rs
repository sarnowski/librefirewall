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

fn endpoint() -> Endpoint {
    Endpoint::new(OUR_MAC, OUR_ADDRESS, PREFIX).expect("a unicast pair on a /24")
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
    let outcome = endpoint.handle(frame, &mut out);
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
        Endpoint::new(MacAddress::BROADCAST, OUR_ADDRESS, PREFIX),
        Err(EndpointError::MacNotUnicast {
            mac: MacAddress::BROADCAST
        })
    );
    assert_eq!(
        Endpoint::new(MacAddress([0; 6]), OUR_ADDRESS, PREFIX),
        Err(EndpointError::MacNotUnicast {
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
            Endpoint::new(OUR_MAC, address, PREFIX),
            Err(EndpointError::AddressNotUnicast { address })
        );
    }
    for prefix_length in [33u8, 64, 255] {
        assert_eq!(
            Endpoint::new(OUR_MAC, OUR_ADDRESS, prefix_length),
            Err(EndpointError::PrefixLengthOutOfRange { prefix_length })
        );
    }
    let endpoint = Endpoint::new(OUR_MAC, OUR_ADDRESS, 32).expect("a host route is a prefix");
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
    let outcome = endpoint.handle(&arp(), &mut out);
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
        endpoint.handle(&request, &mut small),
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
            protocol: Protocol::TCP,
            ..Datagram::echo()
        }
        .build(),
        vec![0u8; 3],
    ];
    for frame in &frames {
        endpoint.handle(frame, &mut out);
    }
    let counters = endpoint.counters();
    assert_eq!(counters.arp_replies, 1);
    assert_eq!(counters.echo_replies, 1);
    assert_eq!(counters.not_for_us, 1);
    assert_eq!(counters.unhandled_total(), 1);
    assert_eq!(counters.malformed, 1);
    assert_eq!(counters.total(), frames.len() as u64);

    // Nothing is reset, and a second pass adds to the first.
    for frame in &frames {
        endpoint.handle(frame, &mut out);
    }
    assert_eq!(endpoint.counters().total(), 2 * frames.len() as u64);
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
    let mut endpoint =
        Endpoint::new(OUR_MAC, Ipv4Address::from_octets([10, 0, 2, 14]), 31).expect("a /31");
    let mut out = [0u8; ROOMY];
    let neighbour = arp_request(
        MacAddress::BROADCAST,
        STATION_MAC,
        Ipv4Address::from_octets([10, 0, 2, 15]),
        Ipv4Address::from_octets([10, 0, 2, 14]),
    );
    assert!(matches!(
        endpoint.handle(&neighbour, &mut out),
        Outcome::ArpReply { .. }
    ));
    let elsewhere = arp_request(
        MacAddress::BROADCAST,
        STATION_MAC,
        Ipv4Address::from_octets([10, 0, 2, 16]),
        Ipv4Address::from_octets([10, 0, 2, 14]),
    );
    assert_eq!(
        endpoint.handle(&elsewhere, &mut out),
        Outcome::Unhandled(Unhandled::SourceOffLink)
    );

    let mut host_route = Endpoint::new(OUR_MAC, OUR_ADDRESS, 32).expect("a /32");
    assert_eq!(
        host_route.handle(&arp(), &mut out),
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
        let outcome = endpoint.handle(&frame, &mut out);
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
        let outcome = endpoint.handle(&frame, &mut out);
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
        let left = endpoint.handle(&request, &mut first);
        let right = endpoint.handle(&request, &mut second);
        prop_assert_eq!(left, right);
        let len = left.reply().expect("an echo request is answered");
        prop_assert_eq!(&first[..len], &second[..len]);
        prop_assert_eq!(endpoint.counters().echo_replies, 2);
    }
}
