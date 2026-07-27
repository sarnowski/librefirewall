//! `net_headers` and `routing` under untrusted network traffic.
//!
//! # The adversary and the surface
//!
//! Whatever is attached to a dataplane port chooses every byte of a frame
//! (CONCEPT §7.1), so the input here *is* the frame: no length prefix, no
//! operation selector, no structure this harness imposes. A corpus entry is a
//! packet, which is also what makes a capture off a real wire a usable seed.
//!
//! The two crates are driven together because that is how the dataplane uses
//! them and because neither is interesting alone: a parse that returns is only
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

use std::sync::LazyLock;

use net_headers::{ETHERNET_HEADER_LEN, Frame, IPV4_HEADER_LEN, Ipv4Address, MacAddress};
use routing::{Decision, Interface, Neighbour, PortId, Router};

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

/// Parse one frame, decide on it as if it had arrived on each port in turn, and
/// carry out whatever rewrite the decision authorises.
///
/// Both ports, because a frame is routable in at most one direction and which
/// one depends on bytes the adversary chose: driving a single port would leave
/// the whole `Forward` arm reachable only by accident.
pub fn frame_routing_harness(data: &[u8]) {
    for ingress in [PORT0, PORT1] {
        let original = data.to_vec();
        let mut bytes = original.clone();
        let Ok(mut frame) = Frame::parse(&mut bytes) else {
            // A rejected frame is left byte-for-byte alone, which is what lets
            // a caller report it against the header it arrived with.
            assert_eq!(bytes, original, "a refused parse modified the frame");
            continue;
        };

        let decision = ROUTER.decide(ingress, &frame);
        let Decision::Forward {
            egress,
            source,
            destination,
        } = decision
        else {
            continue;
        };

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
