//! `net_headers`, `routing` and `pipeline` under untrusted network traffic.
//!
//! # The adversary and the surface
//!
//! Whatever is attached to a dataplane port chooses every byte of a
//! frame, so the input here *is* the frame: no length prefix, no
//! operation selector, no structure this harness imposes. A corpus entry is a
//! packet, which is also what makes a capture off a real wire a usable seed.
//!
//! The three crates are driven together because that is how the dataplane uses
//! them and because none is interesting alone: a parse that returns is only
//! safe if what it returns cannot then be turned into a forwarding decision the
//! topology does not support, and a decision is only safe if the rewrite it
//! authorises leaves a frame the next hop will accept.
//!
//! # What is asserted
//!
//! * **Totality.** Every byte string is answered — a parse error, or a verdict.
//!   Nothing panics, and no length or header field reaches an index or an
//!   arithmetic operation that could.
//! * **Consistency of a forward verdict.** It never names the port the frame
//!   arrived on, its source MAC is the egress interface's own, and its
//!   destination MAC belongs to a configured neighbour. A verdict failing any
//!   of these would put a frame on a wire with an address nobody there answers
//!   to, or loop it.
//! * **Conservation across the rewrite.** The frame's length never changes, the
//!   bytes past the two rewritten headers are byte-identical, and both IPv4
//!   addresses survive. The rewrite is four fields; a rewrite that moved a
//!   fifth would be a router editing traffic it was asked to carry.
//! * **The rewrite leaves a valid packet.** The result re-parses — which is the
//!   header checksum asserted the way the next hop tests it — with a TTL
//!   exactly one lower.
//! * **The appliance's own address is never a source.** A frame claiming to come
//!   from an address this router holds is forged or looped, and is refused as a
//!   martian rather than carried.
//! * **The transport header decides nothing.** Rewriting the two bytes behind
//!   the IPv4 header leaves both the parse and the verdict exactly as they were:
//!   a router forwards a datagram because the datagram is well formed, and a UDP
//!   length that contradicts it is the receiving endpoint's to refuse.
//! * **The transport annotation says what the datagram says.** Which variant is
//!   reported follows from the protocol number and the bytes the IPv4 total
//!   length leaves behind the header, and from nothing else. A variant that
//!   disagreed with either would be a filtering stage handed a header the
//!   datagram does not carry.
//! * **The egress does not depend on how the table was written.** Two enabled
//!   interfaces of equal prefix length covering the frame's own destination
//!   resolve to the same one in either order.
//! * **A zero prefix length is never the route.** It covers every destination,
//!   so selecting it would be a default route; a real prefix wins instead.

use std::sync::LazyLock;

use net_headers::{
    ETHERNET_HEADER_LEN, Frame, ICMP_HEADER_LEN, IPV4_HEADER_LEN, Ipv4Address, Ipv4Packet,
    MacAddress, Protocol, TCP_HEADER_LEN, Transport, UDP_HEADER_LEN,
};
use pipeline::{Configuration, DropReason, Inspection, Pipeline, Verdict};
use routing::{Interface, Neighbour, PortId, Router};

const PORT0: PortId = PortId(0);
const PORT1: PortId = PortId(1);

/// The bytes a forwarding rewrite may touch: the Ethernet and IPv4 headers.
/// Everything past them is the sender's and must survive untouched.
const REWRITTEN_HEADER_LEN: usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;

/// A two-port topology of the shape the appliance is configured into at run
/// time, so a verdict here is a verdict it would reach.
static ROUTER: LazyLock<Router<2, 2>> = LazyLock::new(|| {
    Router::from_slices(
        &[
            Interface {
                port: PORT0,
                mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]),
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
                prefix_length: 24,
                enabled: true,
            },
            Interface {
                port: PORT1,
                mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x51]),
                address: Ipv4Address::from_octets([10, 0, 1, 1]),
                prefix_length: 24,
                enabled: true,
            },
        ],
        &[
            Neighbour {
                port: PORT0,
                address: Ipv4Address::from_octets([10, 0, 0, 2]),
                mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0a]),
            },
            Neighbour {
                port: PORT1,
                address: Ipv4Address::from_octets([10, 0, 1, 2]),
                mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0b]),
            },
        ],
    )
    .expect("two of each fit in two")
});

/// The rewritable parser and the read-only one are one validator, so a header
/// either passes both or neither — and where both pass, they agree field for
/// field.
///
/// Asserted here because the two are reached by different domains: the forwarder
/// rewrites through [`Frame`], and the addressed management endpoint reads
/// through [`Ipv4Packet`]. A divergence would mean one of them was routing on a
/// header the other had refused.
fn agree_on_the_ipv4_header(data: &[u8]) {
    let mut bytes = data.to_vec();
    let rewritable = Frame::parse(&mut bytes).map(|frame| frame.ipv4());
    let Some(after_l2) = data.get(ETHERNET_HEADER_LEN..) else {
        return;
    };
    let read_only = Ipv4Packet::parse(after_l2).map(|packet| packet.header());
    match (rewritable, read_only) {
        (Ok(left), Ok(right)) => assert_eq!(left, right, "two readings of one header"),
        // Either may refuse what the other accepts, but only for a reason that
        // is its own: `Frame` additionally reads a transport header, and
        // `Ipv4Packet` is reached here without the EtherType dispatch in front
        // of it. What must never happen is the same *header* rule answering two
        // ways, which is what the accepted case above pins.
        _ => {}
    }
}

/// The two bytes the UDP length field occupies in an untagged frame, which is
/// also the fifth and sixth byte of whatever else the datagram carries there.
const TRANSPORT_LENGTH_AT: usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + 4;

/// The verdict this appliance's topology reaches for one frame arriving on each
/// port in turn.
///
/// A fresh pipeline per call, because the two verdicts a caller compares must
/// not depend on which was asked for first.
fn verdicts_on_both_ports(bytes: &mut [u8]) -> [Verdict; 2] {
    [PORT0, PORT1].map(|ingress| {
        let frame = Frame::parse(bytes).expect("the caller parsed these bytes already");
        let mut inspection = Inspection::new(ingress, frame);
        Pipeline::new().evaluate(&mut inspection, &Configuration::new(0, &ROUTER))
    })
}

/// Rewriting the transport header changes neither the parse nor the verdict.
///
/// A router carries an IPv4 datagram because the datagram is well formed; what
/// the transport says about itself belongs to whoever receives it. Asserted by
/// overwriting the two bytes a UDP length field sits at — a TCP sequence
/// number's high half, an ICMP identifier, or ordinary payload, depending on
/// what the datagram claims to be — and demanding the same answer, so a rule
/// that crept back into the transport parser and refused a frame on those bytes
/// fails here rather than silently dropping traffic on the appliance.
///
/// Only untagged frames: an 802.1Q tag moves the transport header four bytes
/// along, and writing at the untagged offset would land in the IPv4 header,
/// where a changed byte legitimately changes the verdict.
fn the_transport_header_decides_nothing(data: &[u8]) {
    let mut original = data.to_vec();
    let Ok(frame) = Frame::parse(&mut original) else {
        return;
    };
    if frame.vlan().is_some() {
        return;
    }
    drop(frame);
    let baseline = verdicts_on_both_ports(&mut original);
    if data.len() < TRANSPORT_LENGTH_AT + 2 {
        return;
    }

    for length in [0u16, 1, 8, 0x0fff, u16::MAX] {
        let mut mutated = data.to_vec();
        let Some(field) = mutated.get_mut(TRANSPORT_LENGTH_AT..TRANSPORT_LENGTH_AT + 2) else {
            return;
        };
        field.copy_from_slice(&length.to_be_bytes());
        if Frame::parse(&mut mutated).is_err() {
            panic!("a transport length of {length} made a well-formed datagram unparsable");
        }
        assert_eq!(
            verdicts_on_both_ports(&mut mutated),
            baseline,
            "a transport length of {length} changed the routing verdict"
        );
    }
}

/// The transport annotation follows from the protocol number and the length the
/// IPv4 total length leaves, and from nothing else.
///
/// This is the reachability half of the property above it: that one proves a
/// transport field cannot change the verdict, and this proves the field was read
/// at all — that a datagram claiming TCP with room for a header reports one, and
/// that a datagram without the room reports exactly how few bytes there were.
/// Without it a parser answering `Unparsed` to everything would satisfy every
/// other assertion here.
fn the_transport_annotation_matches_the_datagram(data: &[u8]) {
    let mut bytes = data.to_vec();
    let Ok(frame) = Frame::parse(&mut bytes) else {
        return;
    };
    let header = frame.ipv4();
    // `Frame::parse` refuses a total length below its own header, so this is
    // that guarantee asserted rather than assumed.
    let available = usize::from(header.total_length)
        .checked_sub(IPV4_HEADER_LEN)
        .expect("an accepted datagram is at least as long as its header");

    if header.fragment_offset != 0 {
        assert_eq!(
            frame.transport(),
            Transport::NonInitialFragment,
            "a fragment at a non-zero offset had its payload read as a header"
        );
        return;
    }

    let fixed_header_len = match header.protocol {
        Protocol::UDP => UDP_HEADER_LEN,
        Protocol::TCP => TCP_HEADER_LEN,
        Protocol::ICMP => ICMP_HEADER_LEN,
        other => {
            assert_eq!(
                frame.transport(),
                Transport::Unparsed(other),
                "a protocol this crate does not read was broken down anyway"
            );
            return;
        }
    };

    match frame.transport() {
        Transport::Udp(_) | Transport::Tcp(_) | Transport::Icmp(_) => assert!(
            available >= fixed_header_len,
            "a header was read out of {available} bytes",
        ),
        Transport::TruncatedUdp { available: got }
        | Transport::TruncatedTcp { available: got }
        | Transport::TruncatedIcmp { available: got } => {
            assert!(
                available < fixed_header_len,
                "{available} bytes were reported truncated",
            );
            assert_eq!(got, available, "the reported shortfall is not the real one");
        }
        other => panic!("protocol {} was annotated {other:?}", header.protocol),
    }
}

/// Two enabled interfaces of equal prefix length, both covering the frame's own
/// destination, resolve to the same egress whichever order they were written in
/// — and a third table naming a zero prefix length is refused outright.
///
/// The addresses come from the frame, so the adversary chooses which destination
/// the overlap is built around. Both properties are about the table rather than
/// the packet, which is why they are asserted through `route` and `from_slices`
/// directly: reaching them through a verdict would need the frame to survive the
/// link-layer checks first, leaving them reachable only by accident.
fn the_table_answers_the_same_however_it_was_written(data: &[u8]) {
    let mut bytes = data.to_vec();
    let Ok(frame) = Frame::parse(&mut bytes) else {
        return;
    };
    let destination = frame.ipv4().destination;
    let [network, ..] = destination.octets();

    // One /8 per port, both covering the destination, differing in everything
    // the tie-break can see. Only the order they are written in is left.
    let first = Interface {
        port: PORT0,
        mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
        address: Ipv4Address::from_octets([network, 0, 0, 1]),
        prefix_length: 8,
        enabled: true,
    };
    let second = Interface {
        port: PORT1,
        mac: MacAddress([0x02, 0, 0, 0, 0, 2]),
        address: Ipv4Address::from_octets([network, 0, 0, 2]),
        prefix_length: 8,
        enabled: true,
    };
    let written = Router::<2, 0>::from_slices(&[first, second], &[]).expect("two fit in two");
    let reversed = Router::<2, 0>::from_slices(&[second, first], &[]).expect("two fit in two");
    assert_eq!(
        written.route(destination),
        reversed.route(destination),
        "the egress for {destination} followed the table order",
    );
    assert!(
        written.route(destination).is_some(),
        "both prefixes cover {destination}, so one of them must answer",
    );

    // And a zero prefix length is never the route, however the table is written:
    // it covers this destination and every other one, so selecting it would be a
    // default route.
    let default_route = Interface {
        prefix_length: 0,
        ..first
    };
    assert!(default_route.covers(destination), "a /0 covers everything");
    for table in [
        Router::<2, 0>::from_slices(&[default_route, second], &[]),
        Router::<2, 0>::from_slices(&[second, default_route], &[]),
    ] {
        let table = table.expect("two fit in two");
        assert_eq!(
            table.route(destination).map(|entry| entry.prefix_length),
            Some(second.prefix_length),
            "a zero prefix length was selected as a connected route",
        );
    }
}

/// Parse one frame, decide on it as if it had arrived on each port in turn, and
/// carry out whatever rewrite the decision authorises.
///
/// Both ports, because a frame is routable in at most one direction and which
/// one depends on bytes the adversary chose: driving a single port would leave
/// the whole `Forward` arm reachable only by accident.
pub fn frame_routing_harness(data: &[u8]) {
    agree_on_the_ipv4_header(data);
    the_transport_header_decides_nothing(data);
    the_transport_annotation_matches_the_datagram(data);
    the_table_answers_the_same_however_it_was_written(data);
    // One pipeline across both directions, as the forwarder holds it: a stage
    // whose state spans a flow must see the two halves through the same value.
    let mut pipeline = Pipeline::new();
    for ingress in [PORT0, PORT1] {
        let original = data.to_vec();
        let mut bytes = original.clone();
        let Ok(frame) = Frame::parse(&mut bytes) else {
            // A rejected frame is left byte-for-byte alone, which is what lets
            // a caller report it against the header it arrived with.
            assert_eq!(bytes, original, "a refused parse modified the frame");
            continue;
        };

        let mut inspection = Inspection::new(ingress, frame);
        // Generation 0: nothing in the chain reads it, and the table it names is
        // this harness's fixed topology rather than one an operator committed.
        let decision = pipeline.evaluate(&mut inspection, &Configuration::new(0, &ROUTER));
        // A frame claiming one of this router's own addresses as its source is
        // forged or looped and may never be carried. Asserted for a frame that
        // reaches the source check at all: the link-layer refusals in front of it
        // outrank it, and a tagged or misaddressed frame is refused there first.
        let addressed_to_us = ROUTER
            .interface(ingress)
            .is_some_and(|entry| entry.mac == inspection.frame().destination_mac());
        if ROUTER.is_local_address(inspection.frame().ipv4().source)
            && inspection.frame().vlan().is_none()
            && addressed_to_us
        {
            assert_eq!(
                decision,
                Verdict::Drop(DropReason::MartianSource),
                "a frame sourced from an address this appliance holds was not refused",
            );
        }
        let Verdict::Forward {
            egress,
            source,
            destination,
        } = decision
        else {
            continue;
        };
        // The decision is taken before a byte is rewritten and the frame is
        // parsed a second time to rewrite it, which is the order the dataplane
        // uses: the first borrow must end before anything can read the frame as
        // it arrived.
        drop(inspection);
        let mut frame = Frame::parse(&mut bytes).expect("the frame parsed a moment ago");

        assert_ne!(egress, ingress, "a forward verdict looped the frame back");
        let interface = ROUTER
            .interface(egress)
            .expect("a named egress port is a configured interface");
        assert_eq!(
            source, interface.mac,
            "the frame would leave under a source MAC no interface holds"
        );
        let next_hop = frame.ipv4().destination;
        assert!(
            ROUTER
                .neighbour(egress, next_hop)
                .is_some_and(|entry| entry.mac == destination),
            "the next-hop MAC is not a configured neighbour's"
        );

        let before = frame.ipv4();
        frame
            .rewrite_for_forwarding(source, destination)
            .expect("the router refuses a TTL that cannot survive a hop");

        assert_eq!(bytes.len(), original.len(), "the rewrite resized the frame");
        assert_eq!(
            bytes[REWRITTEN_HEADER_LEN..],
            original[REWRITTEN_HEADER_LEN..],
            "the rewrite reached past the two headers it may touch"
        );

        let rewritten =
            Frame::parse(&mut bytes).expect("a rewritten frame must still be a valid packet");
        let after = rewritten.ipv4();
        assert_eq!(after.ttl, before.ttl - 1);
        assert_eq!(after.source, before.source);
        assert_eq!(after.destination, before.destination);
        assert_eq!(after.total_length, before.total_length);
        assert_eq!(rewritten.source_mac(), source);
        assert_eq!(rewritten.destination_mac(), destination);
    }
}
