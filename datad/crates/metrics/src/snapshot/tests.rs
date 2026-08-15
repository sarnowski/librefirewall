use super::*;
use proptest::prelude::*;

extern crate alloc;
use alloc::{collections::BTreeSet, format, string::String, vec::Vec};

fn values() -> [u64; SNAPSHOT_SLOTS] {
    let mut values = [0u64; SNAPSHOT_SLOTS];
    for (slot, value) in values.iter_mut().enumerate() {
        *value = (slot as u64).wrapping_mul(7).wrapping_add(1);
    }
    values
}

#[test]
fn a_reading_round_trips_through_its_bytes() {
    let mut out = [0u8; SNAPSHOT_BYTES];
    let expected = values();
    let written = encode(&mut out, 1_785_443_220_000_000_000, &expected).expect("room");
    assert_eq!(written, SNAPSHOT_BYTES);

    let decoded = decode(&out).expect("its own bytes");
    assert_eq!(decoded.unix_nanos, 1_785_443_220_000_000_000);
    assert_eq!(decoded.values, expected);
}

/// The head of the block, byte for byte, because a management server reads these
/// offsets out of a file rather than out of this type.
#[test]
fn the_header_is_the_layout_a_reader_maps() {
    let mut out = [0u8; SNAPSHOT_BYTES];
    encode(&mut out, 0x0102_0304_0506_0708, &[0x1122_3344_5566_7788]).expect("room");

    assert_eq!(out[0], SNAPSHOT_KIND);
    assert_eq!(out[1], SNAPSHOT_VERSION);
    assert_eq!(&out[2..4], &[0, 0]);
    assert_eq!(
        u32::from_le_bytes(out[4..8].try_into().expect("four")),
        CATALOGUE_FINGERPRINT
    );
    assert_eq!(
        u64::from_le_bytes(out[8..16].try_into().expect("eight")),
        0x0102_0304_0506_0708
    );
    assert_eq!(
        u32::from_le_bytes(out[16..20].try_into().expect("four")) as usize,
        SNAPSHOT_SLOTS
    );
    assert_eq!(
        u64::from_le_bytes(out[20..28].try_into().expect("eight")),
        0x1122_3344_5566_7788
    );
    assert!(
        out[28..].iter().all(|byte| *byte == 0),
        "slots the reading did not reach carry something"
    );
}

/// The one property every recording ever written rests on: padding and a reading
/// share a block type and an enterprise number, and the leading byte is what
/// tells them apart. A padding block's data is zeroes — or nothing at all, the
/// smallest custom block carrying no data.
#[test]
fn padding_is_never_mistaken_for_a_reading() {
    assert_eq!(decode(&[]), Err(DecodeError::Padding));
    assert_eq!(decode(&[0]), Err(DecodeError::Padding));
    assert_eq!(decode(&[0; 4096]), Err(DecodeError::Padding));
}

#[test]
fn a_kind_this_build_does_not_read_is_named_rather_than_guessed() {
    let mut out = [0u8; SNAPSHOT_BYTES];
    encode(&mut out, 1, &values()).expect("room");
    out[0] = 9;
    assert_eq!(decode(&out), Err(DecodeError::UnknownKind { kind: 9 }));
}

#[test]
fn a_body_version_this_build_does_not_read_is_refused() {
    let mut out = [0u8; SNAPSHOT_BYTES];
    encode(&mut out, 1, &values()).expect("room");
    out[1] = 200;
    assert_eq!(
        decode(&out),
        Err(DecodeError::UnknownVersion { version: 200 })
    );
}

#[test]
fn a_reserved_byte_that_is_set_is_a_writer_this_build_does_not_share_a_layout_with() {
    for at in 2..4 {
        let mut out = [0u8; SNAPSHOT_BYTES];
        encode(&mut out, 1, &values()).expect("room");
        out[at] = 1;
        assert_eq!(decode(&out), Err(DecodeError::ReservedSet), "byte {at}");
    }
}

/// A recording written by another build maps its slots through another table, so
/// none of its numbers is reported rather than all of them being reported wrongly.
#[test]
fn a_reading_from_a_catalogue_this_build_cannot_map_is_refused_whole() {
    let mut out = [0u8; SNAPSHOT_BYTES];
    encode(&mut out, 1, &values()).expect("room");
    let foreign = CATALOGUE_FINGERPRINT ^ 0x5555_5555;
    out[4..8].copy_from_slice(&foreign.to_le_bytes());
    assert_eq!(
        decode(&out),
        Err(DecodeError::ForeignCatalogue {
            stated: foreign,
            held: CATALOGUE_FINGERPRINT
        })
    );
}

#[test]
fn a_slot_count_the_catalogue_does_not_have_is_refused() {
    let mut out = [0u8; SNAPSHOT_BYTES];
    encode(&mut out, 1, &values()).expect("room");
    out[16..20].copy_from_slice(&7u32.to_le_bytes());
    assert_eq!(
        decode(&out),
        Err(DecodeError::SlotCountMismatch {
            stated: 7,
            held: SNAPSHOT_SLOTS
        })
    );
}

#[test]
fn a_header_the_bytes_do_not_reach_is_refused_with_what_arrived() {
    let mut out = [0u8; SNAPSHOT_BYTES];
    encode(&mut out, 1, &values()).expect("room");
    for len in 1..SNAPSHOT_HEADER_BYTES {
        assert_eq!(
            decode(&out[..len]),
            Err(DecodeError::TooShort {
                len,
                needed: SNAPSHOT_HEADER_BYTES
            }),
            "{len} bytes"
        );
    }
}

#[test]
fn a_reading_cut_short_behind_its_header_is_refused_rather_than_read_as_zeroes() {
    let mut out = [0u8; SNAPSHOT_BYTES];
    encode(&mut out, 1, &values()).expect("room");
    for len in [SNAPSHOT_HEADER_BYTES, SNAPSHOT_BYTES - 1] {
        assert_eq!(
            decode(&out[..len]),
            Err(DecodeError::Truncated {
                len,
                needed: SNAPSHOT_BYTES
            }),
            "{len} bytes"
        );
    }
}

#[test]
fn an_output_shorter_than_a_reading_is_refused_and_nothing_partial_is_claimed() {
    let mut out = [0u8; SNAPSHOT_BYTES - 1];
    assert_eq!(
        encode(&mut out, 1, &values()),
        Err(EncodeError::OutOfSpace {
            needed: SNAPSHOT_BYTES,
            capacity: SNAPSHOT_BYTES - 1
        })
    );
    assert!(out.iter().all(|byte| *byte == 0), "a partial reading");
}

/// The slots are the catalogue laid end to end, so every one of them names a
/// series and one past the end names nothing.
#[test]
fn every_slot_names_the_series_the_catalogue_puts_there() {
    let mut expected = Vec::new();
    for spec in &crate::catalog::SHARDS {
        for series in spec.series {
            expected.push((spec.domain, series.metric.name));
        }
    }
    assert_eq!(expected.len(), SNAPSHOT_SLOTS);

    for (slot, (domain, name)) in expected.iter().enumerate() {
        let (found_domain, series) = MetricSnapshot::series(slot).expect("inside the catalogue");
        assert_eq!(found_domain, *domain, "slot {slot}");
        assert_eq!(series.metric.name, *name, "slot {slot}");
    }
    assert!(MetricSnapshot::series(SNAPSHOT_SLOTS).is_none());
    assert!(MetricSnapshot::series(usize::MAX).is_none());
}

/// The fingerprint has to move when the meaning of any slot moves, or a reader
/// would map an old table onto a new reading. Every field it covers is checked
/// to change it.
#[test]
fn the_fingerprint_separates_every_field_it_covers() {
    let base = fnv_field(FNV_OFFSET, b"forwarder");
    let mut seen = BTreeSet::new();
    for (left, right) in [
        (&b"ab"[..], &b"c"[..]),
        (b"a", b"bc"),
        (b"", b"abc"),
        (b"abc", b""),
    ] {
        seen.insert(fnv_field(fnv_field(base, left), right));
    }
    assert_eq!(
        seen.len(),
        4,
        "two tables differing only in where one string ends hash the same"
    );
}

/// The one number both ends of the ABI compare, so it is stated here as a fact
/// of this build: a change to any series table moves it, and this test is where
/// that is noticed.
#[test]
fn the_catalogue_is_the_size_and_shape_this_build_states() {
    assert_eq!(SNAPSHOT_SLOTS, 470);
    assert_eq!(SNAPSHOT_BYTES, 20 + 470 * 8);
    assert_ne!(CATALOGUE_FINGERPRINT, 0);
}

/// Names carry into the fingerprint, and a table whose entries were swapped is a
/// different catalogue: an operator reading a wrong number cannot tell.
#[test]
fn the_fingerprint_covers_the_order_the_slots_are_in() {
    let forward = fnv_field(fnv_field(FNV_OFFSET, b"one"), b"two");
    let reversed = fnv_field(fnv_field(FNV_OFFSET, b"two"), b"one");
    assert_ne!(forward, reversed);
}

/// Every refusal reads differently, because these are what a server reports when
/// a recording will not decode.
#[test]
fn each_refusal_reads_differently() {
    let mut messages: Vec<String> = [
        DecodeError::Padding,
        DecodeError::UnknownKind { kind: 3 },
        DecodeError::UnknownVersion { version: 3 },
        DecodeError::ReservedSet,
        DecodeError::TooShort { len: 1, needed: 20 },
        DecodeError::ForeignCatalogue { stated: 1, held: 2 },
        DecodeError::SlotCountMismatch { stated: 1, held: 2 },
        DecodeError::Truncated { len: 1, needed: 2 },
    ]
    .iter()
    .map(|error| format!("{error:?}"))
    .collect();
    let count = messages.len();
    messages.sort();
    messages.dedup();
    assert_eq!(messages.len(), count);
}

proptest! {
    /// Every bit pattern of every slot is a number a domain may have counted, so
    /// an arbitrary reading round-trips exactly and is never refused.
    #[test]
    fn an_arbitrary_reading_round_trips(
        unix_nanos in any::<u64>(),
        seed in any::<u64>(),
    ) {
        let mut expected = [0u64; SNAPSHOT_SLOTS];
        for (slot, value) in expected.iter_mut().enumerate() {
            *value = seed.wrapping_mul(slot as u64 + 1) ^ (slot as u64) << 33;
        }
        let mut out = [0u8; SNAPSHOT_BYTES];
        encode(&mut out, unix_nanos, &expected).expect("room");
        let decoded = decode(&out).expect("its own bytes");
        prop_assert_eq!(decoded.unix_nanos, unix_nanos);
        prop_assert_eq!(decoded.values, expected);
    }

    /// Arbitrary bytes out of a recording: an answer or a named refusal, never a
    /// fault and never a read past what arrived.
    #[test]
    fn arbitrary_bytes_are_answered_totally(
        data in prop::collection::vec(any::<u8>(), 0..=(SNAPSHOT_BYTES + 64)),
    ) {
        match decode(&data) {
            Ok(snapshot) => {
                prop_assert!(data.len() >= SNAPSHOT_BYTES);
                prop_assert_eq!(data.first().copied(), Some(SNAPSHOT_KIND));
                prop_assert_eq!(
                    snapshot.unix_nanos,
                    u64::from_le_bytes(data[8..16].try_into().expect("eight"))
                );
            }
            Err(DecodeError::Padding) => {
                prop_assert!(data.first().copied().unwrap_or(0) == 0);
            }
            Err(_named) => {}
        }
    }

    /// Encoding is total over any output length: a reading or a refusal naming
    /// what was offered, and never a partial write a caller could send.
    #[test]
    fn encoding_into_any_buffer_is_answered(capacity in 0..=(SNAPSHOT_BYTES + 8usize)) {
        let mut out = Vec::from_iter(core::iter::repeat_n(0u8, capacity));
        match encode(&mut out, 1, &values()) {
            Ok(written) => {
                prop_assert_eq!(written, SNAPSHOT_BYTES);
                prop_assert!(capacity >= SNAPSHOT_BYTES);
                prop_assert!(decode(&out).is_ok());
            }
            Err(EncodeError::OutOfSpace { needed, capacity: offered }) => {
                prop_assert_eq!(needed, SNAPSHOT_BYTES);
                prop_assert_eq!(offered, capacity);
                prop_assert!(out.iter().all(|byte| *byte == 0));
            }
        }
    }
}

/// The three build-time derivations, re-run at run time against the constants
/// they produced: a `const fn` nothing calls again is a derivation nothing has
/// ever executed, and the two must not be able to disagree.
#[test]
fn every_derived_constant_re_derives_to_itself() {
    assert_eq!(super::snapshot_slots(), SNAPSHOT_SLOTS);
    assert_eq!(super::fingerprint(), CATALOGUE_FINGERPRINT);
    assert_eq!(super::fnv_field(super::FNV_OFFSET, b""), {
        let empty = super::fnv(super::FNV_OFFSET, b"");
        super::fnv(empty, &[0x1f])
    });
}

/// A stated reading is the same value the codec produces from the same numbers,
/// which is what lets a test or a caller with no region hold one.
#[test]
fn a_stated_reading_is_the_one_its_bytes_decode_to() {
    let stated = MetricSnapshot::new(7, values());
    let mut out = [0u8; SNAPSHOT_BYTES];
    encode(&mut out, stated.unix_nanos, &stated.values).expect("room");
    assert_eq!(decode(&out).expect("its own bytes"), stated);
}
