use super::*;
use proptest::prelude::*;

fn address(last: u8) -> Ipv4Address {
    Ipv4Address::from_octets([10, 0, 0, last])
}

fn endpoint(last: u8, port: u16) -> Endpoint {
    Endpoint::new(address(last), port)
}

#[test]
fn a_packet_and_its_reply_produce_one_key() {
    let client = endpoint(1, 40_000);
    let server = endpoint(2, 443);
    let (forward, forward_is_lower) = FlowKey::of(client, server, Protocol::TCP);
    let (reverse, reverse_is_lower) = FlowKey::of(server, client, Protocol::TCP);
    assert_eq!(forward, reverse);
    assert_eq!(forward.hash(), reverse.hash());
    assert!(forward_is_lower);
    assert!(!reverse_is_lower);
}

/// The protocol is part of the identity, so one host pair running TCP and UDP on
/// the same ports is two flows rather than one.
#[test]
fn the_protocol_separates_two_flows_on_one_port_pair() {
    let client = endpoint(1, 53);
    let server = endpoint(2, 53);
    let (tcp, _) = FlowKey::of(client, server, Protocol::TCP);
    let (udp, _) = FlowKey::of(client, server, Protocol::UDP);
    assert_ne!(tcp, udp);
    assert_ne!(tcp.hash(), udp.hash());
}

/// The port breaks a tie between two endpoints on one address, which is what
/// keeps two flows between one pair of addresses apart.
#[test]
fn the_port_orders_two_endpoints_on_one_address() {
    let low = endpoint(1, 80);
    let high = endpoint(1, 8080);
    let (key, source_is_lower) = FlowKey::of(high, low, Protocol::TCP);
    assert!(!source_is_lower);
    assert_eq!(key.lower(), low);
    assert_eq!(key.upper(), high);
}

/// An endpoint paired with itself has one orientation, and it is the forward
/// one: the comparison is inclusive so no packet is left without a direction.
#[test]
fn an_endpoint_paired_with_itself_travels_forward() {
    let same = endpoint(7, 7);
    let (key, source_is_lower) = FlowKey::of(same, same, Protocol::UDP);
    assert!(source_is_lower);
    assert_eq!(key.lower(), key.upper());
}

#[test]
fn a_direction_reverses() {
    assert_eq!(Direction::Original.reversed(), Direction::Reply);
    assert_eq!(Direction::Reply.reversed(), Direction::Original);
}

proptest! {
    /// The symmetry that the whole table rests on, over arbitrary tuples: a
    /// packet and its reply are one key with one hash, whatever the addresses
    /// and ports are.
    #[test]
    fn every_tuple_hashes_equal_in_both_orientations(
        source_address in any::<u32>(),
        destination_address in any::<u32>(),
        source_port in any::<u16>(),
        destination_port in any::<u16>(),
        protocol in any::<u8>(),
    ) {
        let source = Endpoint::new(Ipv4Address::from_octets(source_address.to_be_bytes()), source_port);
        let destination = Endpoint::new(
            Ipv4Address::from_octets(destination_address.to_be_bytes()),
            destination_port,
        );
        let protocol = Protocol(protocol);
        let (forward, forward_is_lower) = FlowKey::of(source, destination, protocol);
        let (reverse, reverse_is_lower) = FlowKey::of(destination, source, protocol);
        prop_assert_eq!(forward, reverse);
        prop_assert_eq!(forward.hash(), reverse.hash());
        // Both orientations agree which endpoint is lower, so exactly one of
        // them is "forward" unless the two endpoints are the same.
        if source != destination {
            prop_assert_ne!(forward_is_lower, reverse_is_lower);
        }
    }

    /// Distinct tuples are distinct keys: nothing is folded away before mixing,
    /// so a key collision is a hash collision and never an identity collision.
    #[test]
    fn distinct_tuples_are_distinct_keys(
        first_port in any::<u16>(),
        second_port in any::<u16>(),
        first_last in any::<u8>(),
        second_last in any::<u8>(),
    ) {
        let server = endpoint(200, 443);
        let (first, _) = FlowKey::of(endpoint(first_last, first_port), server, Protocol::TCP);
        let (second, _) = FlowKey::of(endpoint(second_last, second_port), server, Protocol::TCP);
        let same_tuple = first_port == second_port && first_last == second_last;
        prop_assert_eq!(first == second, same_tuple);
    }

    /// Distinct keys hash distinctly over the whole 64-bit output. Stated over
    /// the full word rather than over a bucket index, because a bucket index is
    /// 21 bits and collisions in it are expected — the table probes for exactly
    /// that reason.
    #[test]
    fn distinct_keys_hash_distinctly(first_port in any::<u16>(), second_port in any::<u16>()) {
        let server = endpoint(200, 443);
        let (first, _) = FlowKey::of(endpoint(1, first_port), server, Protocol::TCP);
        let (second, _) = FlowKey::of(endpoint(1, second_port), server, Protocol::TCP);
        prop_assert_eq!(first.hash() == second.hash(), first_port == second_port);
    }
}

/// Every bit of the key reaches the low bits a bucket index is masked out of.
///
/// Deterministic rather than a property, and stated over the *bucket index*
/// rather than the hash: flipping one port bit must move the bucket, and a
/// mixer that left the ports in the high bits — which is where the key puts
/// them before mixing — would leave all seventeen of these in one bucket while
/// still passing a whole-word inequality test.
#[test]
fn flipping_any_single_port_bit_moves_the_bucket_index() {
    /// The appliance's own bucket count, whose low bits are the index.
    const MASK: u64 = (1u64 << 21) - 1;
    let server = endpoint(200, 443);
    let base = 0x5a5au16;
    let mut indices = std::vec::Vec::new();
    let (unflipped, _) = FlowKey::of(endpoint(1, base), server, Protocol::TCP);
    indices.push(unflipped.hash() & MASK);
    for bit in 0..16u32 {
        let (key, _) = FlowKey::of(endpoint(1, base ^ (1u16 << bit)), server, Protocol::TCP);
        indices.push(key.hash() & MASK);
    }
    for (position, index) in indices.iter().enumerate() {
        for (other_position, other) in indices.iter().enumerate() {
            assert!(
                position == other_position || index != other,
                "bit patterns {position} and {other_position} share bucket {index}"
            );
        }
    }
}
