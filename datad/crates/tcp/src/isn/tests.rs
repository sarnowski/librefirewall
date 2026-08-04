use super::*;
use proptest::prelude::*;
use std::collections::BTreeSet;

/// The published SipHash-2-4 reference vectors: key `00 01 .. 0f`, message
/// `00 01 .. (len-1)`.
///
/// This is the one check the implementation cannot pass by agreeing with itself,
/// and it is why a published PRF was chosen over a hand-rolled mixer (module
/// header). A transcription error in a rotate constant or a round count changes
/// every one of these.
const REFERENCE: &[(usize, u64)] = &[
    (0, 0x726f_db47_dd0e_0e31),
    (1, 0x74f8_39c5_93dc_67fd),
    (2, 0x0d6c_8009_d9a9_4f5a),
    (3, 0x8567_6696_d7fb_7e2d),
    (7, 0xab02_00f5_8b01_d137),
    (8, 0x93f5_f579_9a93_2462),
    (12, 0x751e_8fbc_860e_e5fb),
    (15, 0xa129_ca61_49be_45e5),
    (16, 0x3f2a_cc7f_57c2_9bdb),
];

fn reference_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    for (index, byte) in key.iter_mut().enumerate() {
        // Lossless: the array is 16 long.
        *byte = index as u8;
    }
    key
}

fn secret(byte: u8) -> IsnSecret {
    IsnSecret::from_bytes([byte; 16])
}

fn address(last: u8) -> Ipv4Address {
    Ipv4Address::from_octets([10, 0, 2, last])
}

#[test]
fn the_hash_matches_the_published_vectors() {
    let key = reference_key();
    for (len, expected) in REFERENCE {
        let message: Vec<u8> = (0..*len).map(|index| index as u8).collect();
        assert_eq!(
            siphash24(&key, &message),
            *expected,
            "SipHash-2-4 over {len} bytes"
        );
    }
}

/// A tuple is twelve bytes, so the last-word path with a four-byte remainder is
/// the only one an ISN ever takes; the vectors above cover the others, and this
/// pins the length byte that distinguishes them.
#[test]
fn two_messages_differing_only_in_length_hash_differently() {
    let key = reference_key();
    assert_ne!(siphash24(&key, &[0, 0]), siphash24(&key, &[0, 0, 0]));
}

/// The whole 4-tuple reaches the hash, in a fixed order: a generator that
/// dropped one field would let a peer learn one connection's offset from
/// another's, and one that mixed the two addresses into one value would make
/// swapping them a collision.
#[test]
fn every_field_of_the_tuple_changes_the_result() {
    let generator = IsnGenerator::new(secret(0x5a));
    let now = monotonic(0);
    let base = generator.initial_sequence(now, address(1), 80, address(2), 40000);
    assert_ne!(
        base,
        generator.initial_sequence(now, address(9), 80, address(2), 40000)
    );
    assert_ne!(
        base,
        generator.initial_sequence(now, address(1), 81, address(2), 40000)
    );
    assert_ne!(
        base,
        generator.initial_sequence(now, address(1), 80, address(9), 40000)
    );
    assert_ne!(
        base,
        generator.initial_sequence(now, address(1), 80, address(2), 40001)
    );
    // The local and remote halves are not interchangeable.
    assert_ne!(
        base,
        generator.initial_sequence(now, address(2), 80, address(1), 40000)
    );
}

/// Two boots differ by their secret alone, and that must be enough: the secret
/// is what an attacker who has watched a previous boot does not have.
#[test]
fn the_secret_alone_separates_two_boots() {
    let now = monotonic(0);
    let first = IsnGenerator::new(secret(1));
    let second = IsnGenerator::new(secret(2));
    assert_ne!(
        first.initial_sequence(now, address(1), 80, address(2), 40000),
        second.initial_sequence(now, address(1), 80, address(2), 40000)
    );
}

/// RFC 6528's `M`: the time component advances one unit per 4 microseconds, so
/// two connections on the same 4-tuple far enough apart cannot collide.
#[test]
fn the_time_component_advances_in_four_microsecond_units() {
    let generator = IsnGenerator::new(secret(7));
    let tuple = |now| generator.initial_sequence(now, address(1), 80, address(2), 40000);
    let base = tuple(monotonic(0));
    // Below one tick, nothing moves.
    assert_eq!(base, tuple(monotonic(TIMER_TICK_NANOS - 1)));
    assert_eq!(base.add(1), tuple(monotonic(TIMER_TICK_NANOS)));
    assert_eq!(
        base.add(250_000),
        tuple(monotonic(TIMER_TICK_NANOS * 250_000))
    );
}

/// A generator holds a secret and nothing else, so one tuple always yields one
/// number: the state machine re-derives an ISN when it re-sends a `SYN-ACK`, and
/// a generator that answered differently would offer two sequence spaces for one
/// connection.
#[test]
fn the_same_inputs_yield_the_same_number() {
    let generator = IsnGenerator::new(secret(0x33));
    let now = monotonic(123_456_789);
    let first = generator.initial_sequence(now, address(1), 80, address(2), 40000);
    let second = generator.initial_sequence(now, address(1), 80, address(2), 40000);
    assert_eq!(first, second);
}

/// A `Monotonic` is only constructible from a `Calibration`, so a test that
/// needs an arbitrary one builds it the way the crate's own callers do.
fn monotonic(nanos: u64) -> Monotonic {
    use core::num::NonZeroU64;
    use lfw_clock::{Calibration, Ticks};
    // One tick per nanosecond, so the reading *is* the elapsed nanoseconds.
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(nanos))
}

proptest! {
    /// Distinct 4-tuples yield distinct numbers across a large sample. This is
    /// the property an off-path attacker attacks: a generator with a small
    /// effective range would collide here long before 2^32 tuples.
    #[test]
    fn distinct_tuples_do_not_collide(port in 1u16..=u16::MAX, octet in any::<u8>()) {
        let generator = IsnGenerator::new(secret(0xa5));
        let now = monotonic(1_000_000);
        let mut seen = BTreeSet::new();
        for step in 0..64u16 {
            let sequence = generator.initial_sequence(
                now,
                address(octet),
                80,
                address(octet.wrapping_add(1)),
                port.wrapping_add(step),
            );
            prop_assert!(seen.insert(sequence.raw()), "a tuple collided at step {step}");
        }
    }

    /// Two secrets that differ in one byte separate every tuple: the key is
    /// mixed into the state before the message, so a near-miss key is not a
    /// near-miss hash.
    #[test]
    fn one_byte_of_secret_separates_every_tuple(index in 0usize..16, port in any::<u16>()) {
        let mut bytes = [0x11u8; 16];
        let first = IsnGenerator::new(IsnSecret::from_bytes(bytes));
        // Bounded by the range the strategy draws from.
        if let Some(slot) = bytes.get_mut(index) {
            *slot ^= 0x80;
        }
        let second = IsnGenerator::new(IsnSecret::from_bytes(bytes));
        let now = monotonic(4_000_000);
        prop_assert_ne!(
            first.initial_sequence(now, address(1), 80, address(2), port),
            second.initial_sequence(now, address(1), 80, address(2), port)
        );
    }

    /// Arbitrary inputs, including the whole of the clock's range: nothing
    /// panics, nothing overflows, and the answer is total over the domain.
    #[test]
    fn any_input_yields_a_number(
        nanos in any::<u64>(),
        local in any::<[u8; 4]>(),
        remote in any::<[u8; 4]>(),
        local_port in any::<u16>(),
        remote_port in any::<u16>(),
        key in any::<[u8; 16]>(),
    ) {
        let generator = IsnGenerator::new(IsnSecret::from_bytes(key));
        let sequence = generator.initial_sequence(
            monotonic(nanos),
            Ipv4Address::from_octets(local),
            local_port,
            Ipv4Address::from_octets(remote),
            remote_port,
        );
        // Every `u32` is a legal sequence number, so what is asserted is that
        // the call returned at all — which under `overflow-checks` is the claim —
        // and that it is deterministic, which is the property a re-sent
        // `SYN-ACK` rests on.
        prop_assert_eq!(
            sequence,
            generator.initial_sequence(
                monotonic(nanos),
                Ipv4Address::from_octets(local),
                local_port,
                Ipv4Address::from_octets(remote),
                remote_port,
            )
        );
    }

    /// The hash is total over any message length, which is what makes the
    /// remainder path safe for a tuple that is not a multiple of eight bytes.
    #[test]
    fn the_hash_is_total_over_any_message(message in prop::collection::vec(any::<u8>(), 0..=64)) {
        let key = reference_key();
        prop_assert_eq!(siphash24(&key, &message), siphash24(&key, &message));
    }
}
