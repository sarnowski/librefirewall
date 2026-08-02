//! `lfw_ip_endpoint` and the `net_headers` parsers beneath it, under the two
//! adversaries that reach an addressed management port.
//!
//! # The adversary and the surface
//!
//! Whatever is attached to the management port chooses every byte of a frame
//! (untrusted network traffic **and** the management-plane
//! attacker), so the input here *is* the frame: no length prefix, no operation
//! selector, no structure this harness imposes. A corpus entry is a packet, which
//! is what makes a capture off a real wire a usable seed.
//!
//! What makes this surface different from [`crate::frame`]'s is the direction:
//! the routed dataplane reaches a *verdict* on a frame, and this one composes a
//! *reply* to it. Every byte of that reply is derived from bytes the adversary
//! chose, so the questions are about what leaves rather than only about what is
//! accepted.
//!
//! # What is asserted
//!
//! * **Totality.** Every byte string is answered — a reply, a refusal, or a
//!   parse error — and nothing panics, indexes past a bound, or overflows.
//! * **Containment of the reply.** A reply never exceeds the storage the caller
//!   handed over, and the bytes past its length are never touched. This is the
//!   claim the protection domain rests on: it writes that many bytes into a pool
//!   buffer.
//! * **A reply is only ever produced for a frame addressed to us**, at L2 and at
//!   L3, and it always leaves *as* us and *to* the station that asked. A reply to
//!   a group address would make the port a reflector; a reply from an address
//!   nobody configured would be a frame no station answers.
//! * **Every outcome is counted, exactly once.** The counters are the only
//!   evidence a port with an address is doing anything, so their total is
//!   asserted equal to the number of frames handed over.
//! * **A reply re-parses**, which is both checksums asserted the way the station
//!   that receives one tests them.
//! * **Nothing is carried between frames.** The same frame twice yields the same
//!   reply byte for byte: an endpoint holds three configured values and no state
//!   an adversary can move — for the two stateless protocols. A TCP segment is
//!   deliberately excluded, a transport being state by definition.
//! * **What the endpoint holds per connection is bounded and never leaked.** One
//!   frame cannot reach that: random bytes never compose a segment whose
//!   checksum verifies, so a single-frame harness never opens a connection and
//!   never fills the table. A second phase therefore floods one endpoint with
//!   *well-formed* handshakes from more sources than the table holds, injecting
//!   the adversary's own frame between them, and holds the endpoint to the
//!   invariant an eviction breaks: one return path per live connection, no more
//!   and no fewer, and never a request slot the server could not find.

use lfw_clock::{Calibration, Monotonic, Ticks};
use lfw_ip_endpoint::{
    Endpoint, Flags, IsnSecret, MANAGEMENT_PORT, Malformed, Outcome, Outgoing, SeqNumber, TCP_MSS,
    TCP_CONNECTIONS, Unhandled,
};
use net_headers::{
    ARP_FRAME_LEN, ArpOperation, ArpPacket, EtherType, Ethernet, Ipv4Address, Ipv4Frame,
    Ipv4Packet, MIN_ECHO_REPLY_LEN, MacAddress, Protocol,
};
use std::num::NonZeroU64;

/// The shortest frame this endpoint composes: an ARP reply's 42 bytes, still
/// below the 54 a bare TCP segment takes behind its two headers. It is what a
/// reply's length is held above, and the assertion is what keeps the bound a real
/// one as the endpoint gains protocols.
const MIN_REPLY_LEN: usize = ARP_FRAME_LEN;

const _: () = assert!(MIN_REPLY_LEN <= Ipv4Frame::PAYLOAD_AT + 20);

/// The management port's own addressing, as `systems/qemu-x86_64/configuration.xml`
/// gives it: a verdict here is one the appliance would reach.
const OUR_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x52]);
const OUR_ADDRESS: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 15]);
const PREFIX_LENGTH: u8 = 24;

/// The per-boot secret the transport's initial sequence numbers are derived from.
/// Fixed here because this harness is about the endpoint's *framing* decisions:
/// the transport's own surface, the secret included, is
/// [`crate::tcp`](crate::tcp)'s.
const SECRET: [u8; 16] = [0x5a; 16];

/// The instant every frame here arrives at. One reading, because nothing this
/// harness asserts is about a timer: `crate::tcp` is what drives those.
fn now() -> Monotonic {
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(1_000_000))
}

/// Storage the caller hands the endpoint to compose into, and the byte it is
/// filled with so a reply's own bytes are distinguishable from untouched ones.
const REPLY_CAPACITY: usize = 2048;
const UNTOUCHED: u8 = 0xa5;

/// Hold one frame's answer, and then the endpoint's own bounded state, to
/// everything the crate promises of them.
pub fn ip_endpoint_harness(data: &[u8]) {
    assert_one_frame_is_answered(data);
    assert_state_stays_bounded_under_a_connection_flood(data);
}

/// Hand one frame to an addressed endpoint and hold both the reply and the
/// counters to everything the crate promises of them.
fn assert_one_frame_is_answered(data: &[u8]) {
    let mut endpoint = Endpoint::new(
        OUR_MAC,
        OUR_ADDRESS,
        PREFIX_LENGTH,
        IsnSecret::from_bytes(SECRET),
    )
    .expect("a unicast pair on a /24");
    let mut out = [UNTOUCHED; REPLY_CAPACITY];
    let outcome = endpoint.handle(Some(now()), data, &mut out);
    // A body of stated bytes rather than the appliance's own renderer: this
    // harness is about the frame path, and the exposition has a target of its
    // own. Supplied so a request that reached the server does not leave a
    // connection waiting on one for ever.
    if endpoint.body_wanted() {
        endpoint.supply_body(|out| {
            let body = b"# HELP x y\n# TYPE x counter\nx 1\n";
            out.get_mut(..body.len())?.copy_from_slice(body);
            Some(body.len())
        });
    }

    // One frame, one recorded outcome: the counters are what a scrape reads, so a
    // path that answered without recording would be invisible.
    let counters = endpoint.counters();
    assert_eq!(
        counters.total(),
        1,
        "one frame moved {} counts",
        counters.total()
    );

    let Some(len) = outcome.reply() else {
        assert!(out.iter().all(|byte| *byte == UNTOUCHED));
        assert_outcome_has_no_reply(&outcome, data);
        return;
    };

    assert!(
        len <= REPLY_CAPACITY,
        "a reply overran the caller's storage"
    );
    assert!(len >= MIN_REPLY_LEN, "a reply shorter than any frame");
    assert!(
        out[len..].iter().all(|byte| *byte == UNTOUCHED),
        "a reply wrote past the length it reported"
    );

    // A reply is only ever composed for a frame this endpoint was addressed by,
    // and it always leaves as this endpoint to the station that asked.
    let received = Ethernet::parse(data).expect("a reply needs a header to have come from");
    assert!(
        received.header.destination == OUR_MAC || received.header.destination.is_broadcast(),
        "a frame addressed to somebody else was answered"
    );
    assert!(
        received.header.source.is_unicast(),
        "a reply was addressed to a group"
    );

    let sent = Ethernet::parse(&out[..len]).expect("a reply is a frame");
    assert_eq!(sent.header.source, OUR_MAC);
    assert_eq!(sent.header.destination, received.header.source);

    match outcome {
        Outcome::ArpReply { .. } => {
            assert_eq!(len, ARP_FRAME_LEN);
            assert_eq!(sent.header.ether_type, EtherType::ARP);
            let reply = ArpPacket::parse(sent.payload).expect("an ARP reply re-parses");
            assert_eq!(reply.operation, ArpOperation::Reply);
            assert_eq!(reply.sender_mac, OUR_MAC);
            assert_eq!(reply.sender_address, OUR_ADDRESS);
            // The request it answers is the frame that arrived, and the answer
            // names that requester rather than anything of the endpoint's own.
            let request = ArpPacket::parse(received.payload).expect("a request was parsed");
            assert_eq!(reply.target_mac, request.sender_mac);
            assert_eq!(reply.target_address, request.sender_address);
            assert!(
                request
                    .sender_address
                    .shares_prefix(OUR_ADDRESS, PREFIX_LENGTH),
                "a station off the link was answered"
            );
            assert_eq!(endpoint.counters().arp_replies, 1);
        }
        Outcome::EchoReply { .. } => {
            assert!(len >= MIN_ECHO_REPLY_LEN);
            assert_eq!(sent.header.ether_type, EtherType::IPV4);
            // Re-parsing is both checksums asserted the way the station that
            // receives the reply tests them.
            let packet = Ipv4Packet::parse(sent.payload).expect("a valid datagram");
            assert_eq!(packet.header().source, OUR_ADDRESS);
            let request = Ipv4Packet::parse(received.payload).expect("a request was parsed");
            assert_eq!(packet.header().destination, request.header().source);
            assert_eq!(fold(packet.payload()), u16::MAX, "the ICMP sum validates");

            // The echo is repeated whole: identifier, sequence and payload are
            // the sender's only way to match a reply to its request (RFC 792).
            let echoed = &packet.payload()[2..];
            let asked = &request.payload()[2..];
            assert_eq!(echoed[2..], asked[2..], "the echo was not repeated");
            assert_eq!(endpoint.counters().echo_replies, 1);
        }
        // A segment the transport composed: framed as this endpoint, addressed to
        // the station that sent it, and carrying TCP. Everything *inside* it is
        // `crate::tcp`'s surface, driven there over whole operation streams
        // rather than one frame at a time.
        Outcome::Tcp { .. } => {
            assert_eq!(sent.header.ether_type, EtherType::IPV4);
            let packet = Ipv4Packet::parse(sent.payload).expect("a datagram re-parses");
            assert_eq!(packet.header().source, OUR_ADDRESS);
            assert_eq!(packet.header().protocol, Protocol::TCP);
            assert_eq!(endpoint.counters().tcp_segments, 1);
        }
        other => panic!("{other:?} carried a reply"),
    }

    if matches!(outcome, Outcome::Tcp { .. }) {
        // A transport *is* state: the same segment twice is a retransmission, and
        // the second answer is legitimately different from the first. Held to
        // nothing more here, and to a great deal in `crate::tcp`.
        return;
    }

    // Nothing about ARP or ICMP is carried between frames: the same bytes twice
    // compose the same reply, and the counters advance by exactly one more. A TCP
    // segment is deliberately not held to this — a transport *is* state, and
    // `crate::tcp` is where that is driven — so the outcome above having been a
    // reply means it was one of the two stateless kinds.
    let mut again = [UNTOUCHED; REPLY_CAPACITY];
    let second = endpoint.handle(Some(now()), data, &mut again);
    assert_eq!(second, outcome);
    assert_eq!(again[..len], out[..len]);
    assert_eq!(endpoint.counters().total(), 2);
}

/// The station the flood below sends from, which is one peer: the whole point is
/// that a single unauthenticated neighbour reaches the table's edge.
const STATION_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0c]);
const STATION_ADDRESS: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 2]);

/// Drive one endpoint through more connections than its table holds, injecting
/// `frame` between them, and hold what it keeps per connection to its bound.
///
/// An eviction is the release nothing announces — the transport takes a slot back
/// while answering a `SYN` and produces no timeout for it — so a return path or a
/// request slot left behind is leaked for the life of the domain. It does not
/// decay and nothing restarts the protection domain: the port simply stops
/// retransmitting.
fn assert_state_stays_bounded_under_a_connection_flood(frame: &[u8]) {
    let mut endpoint = Endpoint::new(
        OUR_MAC,
        OUR_ADDRESS,
        PREFIX_LENGTH,
        IsnSecret::from_bytes(SECRET),
    )
    .expect("a unicast pair on a /24");
    let mut out = [UNTOUCHED; REPLY_CAPACITY];

    let hold = |endpoint: &Endpoint, where_: &str| {
        assert!(
            endpoint.connections() <= TCP_CONNECTIONS,
            "the connection table exceeded its capacity {where_}"
        );
        assert_eq!(
            endpoint.return_paths(),
            endpoint.connections(),
            "a return path outlived its connection {where_}"
        );
        assert_eq!(
            endpoint.http_counters().slots_exhausted,
            0,
            "the server had no slot for a connection the transport made room for {where_}"
        );
    };

    // Twice the table's capacity of half-open connections, so every newcomer
    // past the first `TCP_CONNECTIONS` evicts one.
    for index in 0..(2 * TCP_CONNECTIONS) {
        // Lossless: the loop is bounded by twice a small table.
        let port = 40_000u16.wrapping_add(index as u16);
        let at = tick(index as u64);
        let syn = syn_frame(port, 0x1000u32.wrapping_mul(index as u32).wrapping_add(1));
        endpoint.handle(Some(at), &syn, &mut out);
        hold(&endpoint, "while the table was filling");
        // And the adversary's own frame between every pair, so whatever it is
        // reaches an endpoint in every state the flood puts it through.
        endpoint.handle(Some(at), frame, &mut out);
        hold(&endpoint, "after the frame under test");
    }

    // Draining the timers holds it too, including past every deadline the
    // transport keeps: that is where reapings and abandonments are answered.
    for step in 0..4 {
        let at = tick(1_000 + step * lfw_clock::NANOS_PER_SECOND * 400);
        for _ in 0..(8 * TCP_CONNECTIONS) {
            if !endpoint.poll_timeouts(at, &mut out).goes_on() {
                break;
            }
            hold(&endpoint, "while the timers were draining");
        }
        for _ in 0..(8 * TCP_CONNECTIONS) {
            if !endpoint.poll_output(at, &mut out).goes_on() {
                break;
            }
            hold(&endpoint, "while the output was draining");
        }
    }
    hold(&endpoint, "once everything had settled");
}

/// An instant `nanos` after boot.
fn tick(nanos: u64) -> Monotonic {
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(nanos))
}

/// A well-formed `SYN` from the flooding station, in a whole Ethernet frame.
///
/// Composed rather than taken from the input, because a checksum a fuzzer
/// stumbled on is a state this harness would reach once in the life of the
/// universe — and the connection table's behaviour under pressure is what is
/// being asserted, not the parser's.
fn syn_frame(port: u16, iss: u32) -> Vec<u8> {
    let mut frame = vec![0u8; 256];
    let len = Outgoing {
        source_port: port,
        destination_port: MANAGEMENT_PORT,
        sequence: SeqNumber::new(iss),
        acknowledgement: SeqNumber::new(0),
        flags: Flags::SYN,
        window: 4096,
        mss: Some(TCP_MSS),
        window_scale: None,
        payload: &[],
    }
    .write(
        STATION_ADDRESS,
        OUR_ADDRESS,
        frame
            .get_mut(Ipv4Frame::PAYLOAD_AT..)
            .expect("room for a segment"),
    )
    .expect("room for a segment");
    let total = Ipv4Frame {
        destination_mac: OUR_MAC,
        source_mac: STATION_MAC,
        source: STATION_ADDRESS,
        destination: OUR_ADDRESS,
        protocol: Protocol::TCP,
    }
    .write(&mut frame, len)
    .expect("room for a frame");
    frame.truncate(total);
    frame
}

/// The RFC 1071 sum over a block that carries its own checksum, folded to 16
/// bits: all ones when the block validates. Written here rather than reached for,
/// so the assertion is independent of the crate that produced the value.
fn fold(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for index in 0..bytes.len().div_ceil(2) {
        let high = bytes[index * 2];
        let low = bytes.get(index * 2 + 1).copied().unwrap_or(0);
        sum += u32::from(u16::from_be_bytes([high, low]));
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    // Lossless: the fold above leaves at most 16 significant bits.
    sum as u16
}

/// What an outcome that composed nothing must be consistent with.
///
/// The point is that a *refusal* is attributable: a frame refused for not being
/// ours really is not ours, and one refused as malformed really does not parse.
/// An endpoint that answered nothing for the wrong reason would count the wrong
/// thing, and the counters are what an operator will read.
fn assert_outcome_has_no_reply(outcome: &Outcome, data: &[u8]) {
    match outcome {
        Outcome::Malformed(Malformed::Frame(_)) => {
            // Either the Ethernet header did not parse, or the IPv4 header
            // behind it did not.
            if let Ok(ethernet) = Ethernet::parse(data) {
                assert!(
                    Ipv4Packet::parse(ethernet.payload).is_err(),
                    "a frame that parses was reported malformed"
                );
            }
        }
        Outcome::Malformed(Malformed::Arp(_)) => {
            let ethernet = Ethernet::parse(data).expect("an ARP refusal needs a header");
            assert_eq!(ethernet.header.ether_type, EtherType::ARP);
            assert!(ArpPacket::parse(ethernet.payload).is_err());
        }
        Outcome::Malformed(Malformed::Icmp(_)) => {
            let ethernet = Ethernet::parse(data).expect("an ICMP refusal needs a header");
            assert_eq!(ethernet.header.ether_type, EtherType::IPV4);
        }
        Outcome::NotForUs => {
            let ethernet = Ethernet::parse(data).expect("a refusal at L2 or L3 needs a header");
            let ours = ethernet.header.destination == OUR_MAC
                || ethernet.header.destination.is_broadcast();
            if ours {
                // Then it was refused at L3, so the address it names is not this
                // endpoint's.
                match ethernet.header.ether_type {
                    EtherType::ARP => {
                        let request = ArpPacket::parse(ethernet.payload).expect("a parsed request");
                        assert_ne!(request.target_address, OUR_ADDRESS);
                    }
                    EtherType::IPV4 => {
                        let refused_at_l2 = ethernet.header.destination != OUR_MAC;
                        if !refused_at_l2 {
                            let packet =
                                Ipv4Packet::parse(ethernet.payload).expect("a parsed datagram");
                            assert_ne!(packet.header().destination, OUR_ADDRESS);
                        }
                    }
                    other => panic!("{other} reached the addressed paths"),
                }
            }
        }
        Outcome::Unhandled(Unhandled::VlanTagged) => {
            let ethernet = Ethernet::parse(data).expect("a tagged frame has a header");
            assert_eq!(ethernet.header.ether_type, EtherType::VLAN);
        }
        // The refusal names the value it refused; the `None` this variant also
        // admits belongs to the counter table and never to a frame.
        Outcome::Unhandled(Unhandled::EtherType(ether_type)) => {
            let ethernet = Ethernet::parse(data).expect("an EtherType refusal has a header");
            let refused = ether_type.expect("a refused frame names the ethertype it carried");
            assert_eq!(ethernet.header.ether_type, refused);
            assert_ne!(refused, EtherType::ARP);
            assert_ne!(refused, EtherType::IPV4);
        }
        // The remaining reasons are properties of an already-parsed header that
        // the counters attribute; there is nothing to re-derive from the bytes
        // that would not restate the endpoint's own decision.
        Outcome::Unhandled(_) | Outcome::ReplyRefused(_) => {}
        // A segment the transport answered nothing for, and one that arrived with
        // no clock. Both are ordinary and neither has a framing decision to
        // re-derive: what the transport made of the bytes is `crate::tcp`'s
        // surface, and this harness always supplies a clock.
        Outcome::Tcp { .. } => {
            let ethernet = Ethernet::parse(data).expect("a segment needs a header");
            assert_eq!(ethernet.header.ether_type, EtherType::IPV4);
        }
        Outcome::Unclocked => panic!("a clock was supplied"),
        Outcome::ArpReply { .. } | Outcome::EchoReply { .. } => {
            panic!("a reply outcome reported no reply")
        }
    }
}
