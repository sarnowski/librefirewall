use super::*;
use proptest::prelude::*;
use std::vec::Vec;

const STATION: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 2]);
const APPLIANCE: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 15]);

/// The fields of a hand-built segment, so a test can leave one of them wrong on
/// purpose — which is the whole point of not building these through `Outgoing`.
struct Fields<'a> {
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
    data_offset: u8,
    flags: u8,
    window: u16,
    options: &'a [u8],
    payload: &'a [u8],
}

/// A segment with the checksum field left zero, so a test may fill it or leave
/// it wrong on purpose.
fn raw(fields: Fields<'_>) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&fields.source_port.to_be_bytes());
    segment.extend_from_slice(&fields.destination_port.to_be_bytes());
    segment.extend_from_slice(&fields.sequence.to_be_bytes());
    segment.extend_from_slice(&fields.acknowledgement.to_be_bytes());
    segment.push(fields.data_offset << 4);
    segment.push(fields.flags);
    segment.extend_from_slice(&fields.window.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0]);
    segment.extend_from_slice(fields.options);
    segment.extend_from_slice(fields.payload);
    segment
}

/// A segment carrying the six fields a test usually varies, with the rest at
/// their commonest values.
fn plain<'a>(
    sequence: u32,
    acknowledgement: u32,
    data_offset: u8,
    flags: u8,
    options: &'a [u8],
    payload: &'a [u8],
) -> Fields<'a> {
    Fields {
        source_port: 1,
        destination_port: 80,
        sequence,
        acknowledgement,
        data_offset,
        flags,
        window: 0,
        options,
        payload,
    }
}

/// Stamp the correct checksum into a segment built by [`raw`], computed by this
/// module's own summation rather than by the code under test.
fn sealed(source: Ipv4Address, destination: Ipv4Address, mut segment: Vec<u8>) -> Vec<u8> {
    let value = independent_checksum(source, destination, &segment);
    segment[16..18].copy_from_slice(&value.to_be_bytes());
    segment
}

/// The RFC 793 section 3.1 checksum, written from the specification rather than reused
/// from the crate: agreement between two independent summations is what makes
/// the round-trip tests below evidence.
fn independent_checksum(source: Ipv4Address, destination: Ipv4Address, segment: &[u8]) -> u16 {
    let mut block = Vec::new();
    block.extend_from_slice(&source.octets());
    block.extend_from_slice(&destination.octets());
    block.push(0);
    block.push(6);
    block.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    block.extend_from_slice(segment);
    // The field itself is summed as zero, which `raw` leaves it as; a caller
    // sealing an already-sealed segment would therefore get a different answer,
    // and no test does that.
    if block.len() % 2 == 1 {
        block.push(0);
    }
    let mut sum: u32 = 0;
    for pair in block.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

/// A known-answer vector, computed outside this workspace: a 22-byte
/// acknowledgement carrying two payload bytes checksums to 0x6173.
#[test]
fn the_checksum_matches_a_value_computed_outside_this_workspace() {
    let segment = raw(Fields {
        source_port: 40000,
        window: 8192,
        ..plain(0x1122_3344, 0x5566_7788, 5, 0x10, &[], b"hi")
    });
    assert_eq!(segment.len(), 22);
    assert_eq!(independent_checksum(STATION, APPLIANCE, &segment), 0x6173);

    // And the writer arrives at the same value from the fields.
    let mut out = [0u8; 64];
    let len = Outgoing {
        source_port: 40000,
        destination_port: 80,
        sequence: SeqNumber::new(0x1122_3344),
        acknowledgement: SeqNumber::new(0x5566_7788),
        flags: Flags::ACK,
        window: 8192,
        mss: None,
        window_scale: None,
        payload: b"hi",
    }
    .write(STATION, APPLIANCE, &mut out)
    .expect("room for a 22-byte segment");
    assert_eq!(len, 22);
    assert_eq!(&out[16..18], &0x6173u16.to_be_bytes());
}

/// The same for a `SYN-ACK` with both options, which is the one segment shape
/// this stack composes options on.
#[test]
fn a_syn_ack_with_options_matches_a_value_computed_outside_this_workspace() {
    let mut out = [0u8; 64];
    let len = Outgoing {
        source_port: 80,
        destination_port: 40000,
        sequence: SeqNumber::new(0xaabb_ccdd),
        acknowledgement: SeqNumber::new(0x1122_3345),
        flags: Flags::SYN.with(Flags::ACK),
        window: 8192,
        mss: Some(1024),
        window_scale: Some(7),
        payload: &[],
    }
    .write(APPLIANCE, STATION, &mut out)
    .expect("room for a 28-byte segment");
    assert_eq!(len, 28);
    // Data offset seven words, then MSS, then a NOP-padded window scale.
    assert_eq!(out[12] >> 4, 7);
    assert_eq!(&out[20..28], &[2, 4, 4, 0, 1, 3, 3, 7]);
    assert_eq!(&out[16..18], &0xf51au16.to_be_bytes());
}

#[test]
fn a_well_formed_segment_parses_to_its_fields() {
    let bytes = sealed(
        STATION,
        APPLIANCE,
        raw(Fields {
            source_port: 40000,
            window: 4096,
            ..plain(7, 9, 5, 0x18, &[], b"body")
        }),
    );
    let segment = Segment::parse(STATION, APPLIANCE, &bytes).expect("a well-formed segment");
    assert_eq!(segment.source_port, 40000);
    assert_eq!(segment.destination_port, 80);
    assert_eq!(segment.sequence, SeqNumber::new(7));
    assert_eq!(segment.acknowledgement, SeqNumber::new(9));
    assert!(segment.flags.contains(Flags::ACK));
    assert!(segment.flags.contains(Flags::PSH));
    assert!(!segment.flags.contains(Flags::SYN));
    assert_eq!(segment.window, 4096);
    assert_eq!(segment.payload, b"body");
    assert_eq!(segment.sequence_length(), 4);
    assert_eq!(segment.options, Options::default());
}

/// `SYN` and `FIN` each occupy one sequence number beside the payload, which is
/// what every window computation is stated in.
#[test]
fn the_sequence_length_counts_the_phantom_bytes() {
    let cases = [
        (0x02u8, 0usize, 1u32),
        (0x01, 0, 1),
        (0x03, 0, 2),
        (0x10, 0, 0),
        (0x11, 5, 6),
    ];
    for (flags, payload_len, expected) in cases {
        let payload = std::vec![0xabu8; payload_len];
        let bytes = sealed(
            STATION,
            APPLIANCE,
            raw(plain(0, 0, 5, flags, &[], &payload)),
        );
        let segment = Segment::parse(STATION, APPLIANCE, &bytes).expect("a well-formed segment");
        assert_eq!(segment.sequence_length(), expected, "flags {flags:#04x}");
    }
}

#[test]
fn every_option_this_stack_reads_is_read() {
    let options = [
        2, 4, 0x05, 0xb4, // MSS 1460
        1,    // NOP
        3, 3, 9, // window scale 9
        4, 2, // SACK permitted
        0, // end of option list
        0, // padding past the end, ignored
    ];
    let bytes = sealed(STATION, APPLIANCE, raw(plain(0, 0, 8, 0x02, &options, &[])));
    let segment = Segment::parse(STATION, APPLIANCE, &bytes).expect("a well-formed segment");
    assert_eq!(segment.options.mss, Some(1460));
    assert_eq!(segment.options.window_scale, Some(9));
    assert!(segment.options.sack_permitted);
}

/// RFC 7323 section 2.3: a shift above the maximum is clamped rather than refused.
#[test]
fn an_oversized_window_scale_is_clamped_rather_than_refused() {
    for offered in [15u8, 32, 200, 255] {
        let bytes = sealed(
            STATION,
            APPLIANCE,
            raw(plain(0, 0, 6, 0x02, &[3, 3, offered, 1], &[])),
        );
        let segment = Segment::parse(STATION, APPLIANCE, &bytes).expect("a clamped scale");
        assert_eq!(segment.options.window_scale, Some(MAX_WINDOW_SCALE));
    }
}

/// An option this stack has never heard of is stepped over rather than refused,
/// which is the whole of forward compatibility for a receiver.
#[test]
fn an_unknown_option_is_skipped_by_its_own_length() {
    // Kind 8 (timestamps) is ten bytes, and nothing here reads it. Padded to the
    // sixteen a data offset of nine names.
    let options = [8, 10, 1, 2, 3, 4, 5, 6, 7, 8, 2, 4, 0x02, 0x18, 1, 0];
    let bytes = sealed(STATION, APPLIANCE, raw(plain(0, 0, 9, 0x02, &options, &[])));
    let segment = Segment::parse(STATION, APPLIANCE, &bytes).expect("an unknown option is skipped");
    assert_eq!(segment.options.mss, Some(536));
}

#[test]
fn a_segment_shorter_than_a_header_is_refused_by_its_length() {
    for len in 0..TCP_HEADER_LEN {
        let bytes = std::vec![0u8; len];
        assert_eq!(
            Segment::parse(STATION, APPLIANCE, &bytes),
            Err(SegmentError::TooShort { got: len })
        );
    }
}

#[test]
fn a_data_offset_below_five_words_is_refused() {
    for data_offset in 0..5u8 {
        let bytes = sealed(
            STATION,
            APPLIANCE,
            raw(plain(0, 0, data_offset, 0x10, &[], &[])),
        );
        assert_eq!(
            Segment::parse(STATION, APPLIANCE, &bytes),
            Err(SegmentError::DataOffsetTooSmall { data_offset })
        );
    }
}

#[test]
fn a_data_offset_past_the_segment_is_refused() {
    // Six words of header claimed, twenty bytes present.
    let bytes = sealed(STATION, APPLIANCE, raw(plain(0, 0, 6, 0x10, &[], &[])));
    assert_eq!(
        Segment::parse(STATION, APPLIANCE, &bytes),
        Err(SegmentError::DataOffsetExceedsSegment {
            data_offset: 6,
            got: 20
        })
    );
}

#[test]
fn a_checksum_that_does_not_verify_is_refused_and_names_both_values() {
    let mut bytes = sealed(STATION, APPLIANCE, raw(plain(0, 0, 5, 0x10, &[], b"x")));
    let correct = u16::from_be_bytes([bytes[16], bytes[17]]);
    bytes[16] ^= 0xff;
    let found = u16::from_be_bytes([bytes[16], bytes[17]]);
    assert_eq!(
        Segment::parse(STATION, APPLIANCE, &bytes),
        Err(SegmentError::ChecksumInvalid {
            found,
            computed: correct
        })
    );
}

/// The pseudo-header is what makes a checksum a statement about which connection
/// a segment belongs to: the same bytes read under a different address pair must
/// not verify.
#[test]
fn a_segment_does_not_verify_under_a_different_address_pair() {
    let bytes = sealed(STATION, APPLIANCE, raw(plain(0, 0, 5, 0x10, &[], b"x")));
    assert!(Segment::parse(STATION, APPLIANCE, &bytes).is_ok());
    let elsewhere = Ipv4Address::from_octets([10, 0, 2, 99]);
    assert!(matches!(
        Segment::parse(elsewhere, APPLIANCE, &bytes),
        Err(SegmentError::ChecksumInvalid { .. })
    ));
    assert!(matches!(
        Segment::parse(STATION, elsewhere, &bytes),
        Err(SegmentError::ChecksumInvalid { .. })
    ));
}

#[test]
fn an_option_whose_length_walks_off_the_end_is_refused() {
    // Kind 8 claiming ten bytes inside a four-byte option area.
    let bytes = sealed(
        STATION,
        APPLIANCE,
        raw(plain(0, 0, 6, 0x02, &[8, 10, 0, 0], &[])),
    );
    assert_eq!(
        Segment::parse(STATION, APPLIANCE, &bytes),
        Err(SegmentError::OptionTruncated {
            kind: 8,
            len: 10,
            remaining: 4
        })
    );
}

#[test]
fn an_option_with_no_length_byte_at_all_is_refused() {
    let bytes = sealed(
        STATION,
        APPLIANCE,
        raw(plain(0, 0, 6, 0x02, &[1, 1, 1, 8], &[])),
    );
    assert_eq!(
        Segment::parse(STATION, APPLIANCE, &bytes),
        Err(SegmentError::OptionTruncated {
            kind: 8,
            len: 0,
            remaining: 1
        })
    );
}

#[test]
fn an_option_length_below_two_is_refused() {
    for len in [0u8, 1] {
        let bytes = sealed(
            STATION,
            APPLIANCE,
            raw(plain(0, 0, 6, 0x02, &[8, len, 0, 0], &[])),
        );
        assert_eq!(
            Segment::parse(STATION, APPLIANCE, &bytes),
            Err(SegmentError::OptionLengthInvalid { kind: 8, len })
        );
    }
}

/// A fixed-length option carrying the wrong length is refused rather than read
/// from whatever bytes happen to follow.
#[test]
fn a_known_option_with_the_wrong_length_is_refused() {
    for (kind, len) in [(2u8, 6u8), (3, 4), (4, 3)] {
        let mut options = std::vec![kind, len];
        options.resize(8, 0);
        let bytes = sealed(STATION, APPLIANCE, raw(plain(0, 0, 7, 0x02, &options, &[])));
        assert_eq!(
            Segment::parse(STATION, APPLIANCE, &bytes),
            Err(SegmentError::OptionLengthInvalid { kind, len }),
            "kind {kind} length {len}"
        );
    }
}

/// The reserved and ECN bits are dropped rather than read as control flags: a
/// peer negotiating ECN must not have its bits arrive as a `FIN`.
#[test]
fn the_reserved_and_ecn_bits_are_dropped() {
    let bytes = sealed(STATION, APPLIANCE, raw(plain(0, 0, 5, 0xd0, &[], &[])));
    let segment = Segment::parse(STATION, APPLIANCE, &bytes).expect("a well-formed segment");
    assert_eq!(segment.flags.bits(), 0x10);
}

#[test]
fn writing_into_storage_too_small_refuses_and_writes_nothing() {
    let outgoing = Outgoing {
        source_port: 80,
        destination_port: 1,
        sequence: SeqNumber::new(0),
        acknowledgement: SeqNumber::new(0),
        flags: Flags::ACK,
        window: 0,
        mss: None,
        window_scale: None,
        payload: b"abcd",
    };
    assert_eq!(outgoing.encoded_len(), Ok(24));
    for capacity in 0..24 {
        let mut out = std::vec![0xa5u8; capacity];
        assert_eq!(
            outgoing.write(STATION, APPLIANCE, &mut out),
            Err(WriteError::DoesNotFit {
                needed: 24,
                capacity
            })
        );
        assert!(out.iter().all(|byte| *byte == 0xa5), "storage was written");
    }
}

/// Options are only written on a `SYN`, which is the only segment RFC 793
/// permits the maximum-segment-size option on.
#[test]
fn options_are_written_only_on_a_syn() {
    let mut out = [0u8; 64];
    let len = Outgoing {
        source_port: 80,
        destination_port: 1,
        sequence: SeqNumber::new(0),
        acknowledgement: SeqNumber::new(0),
        flags: Flags::ACK,
        window: 0,
        mss: Some(1460),
        window_scale: Some(3),
        payload: &[],
    }
    .write(STATION, APPLIANCE, &mut out)
    .expect("room");
    assert_eq!(len, TCP_HEADER_LEN);
    assert_eq!(out[12] >> 4, 5);
}

/// A `SYN` with only one of the two options is a five-plus-one-word header,
/// which is what keeps the option area a whole number of words either way.
#[test]
fn each_option_alone_keeps_the_header_a_whole_number_of_words() {
    let base = Outgoing {
        source_port: 80,
        destination_port: 1,
        sequence: SeqNumber::new(0),
        acknowledgement: SeqNumber::new(0),
        flags: Flags::SYN,
        window: 0,
        mss: None,
        window_scale: None,
        payload: &[],
    };
    for (mss, scale, words) in [
        (None, None, 5u8),
        (Some(1460), None, 6),
        (None, Some(4), 6),
        (Some(1460), Some(4), 7),
    ] {
        let mut out = [0u8; 64];
        let len = Outgoing {
            mss,
            window_scale: scale,
            ..base
        }
        .write(STATION, APPLIANCE, &mut out)
        .expect("room");
        assert_eq!(len, usize::from(words) * 4, "mss {mss:?} scale {scale:?}");
        assert_eq!(out[12] >> 4, words);
        // And it parses back to what was written.
        let parsed = Segment::parse(STATION, APPLIANCE, &out[..len]).expect("a written segment");
        assert_eq!(parsed.options.mss, mss);
        assert_eq!(parsed.options.window_scale, scale);
    }
}

/// The option area is built by value, one arm per combination, and its length is
/// what the data offset is derived from. Driven directly so every arm is read as
/// the table it is meant to be.
#[test]
fn the_option_area_is_one_arm_per_combination() {
    let base = Outgoing {
        source_port: 80,
        destination_port: 1,
        sequence: SeqNumber::new(0),
        acknowledgement: SeqNumber::new(0),
        flags: Flags::SYN,
        window: 0,
        mss: None,
        window_scale: None,
        payload: &[],
    };
    /// One combination of the two options, with the length and the bytes it must
    /// produce: named because the tuple is what the table is for.
    type Case = (Option<u16>, Option<u8>, usize, &'static [u8]);

    let cases: [Case; 4] = [
        (Some(1460), Some(7), 8, &[2, 4, 0x05, 0xb4, 1, 3, 3, 7]),
        (Some(1460), None, 4, &[2, 4, 0x05, 0xb4]),
        (None, Some(7), 4, &[1, 3, 3, 7]),
        (None, None, 0, &[]),
    ];
    for (mss, window_scale, len, expected) in cases {
        let outgoing = Outgoing {
            mss,
            window_scale,
            ..base
        };
        let (area, area_len) = outgoing.option_area();
        assert_eq!(area_len, len, "mss {mss:?} scale {window_scale:?}");
        assert_eq!(&area[..area_len], expected);
        assert_eq!(outgoing.option_len(), len);
    }

    // And nothing is written on a segment that carries no `SYN`, whatever was
    // asked for.
    let (_, len) = Outgoing {
        flags: Flags::ACK,
        mss: Some(1460),
        window_scale: Some(7),
        ..base
    }
    .option_area();
    assert_eq!(len, 0);
}

/// The pseudo-header length is bounded before it is reached, and the saturation
/// is what keeps the one caller branch-free.
#[test]
fn a_length_no_field_can_carry_saturates() {
    assert_eq!(needed_len(40), 40);
    assert_eq!(needed_len(usize::from(u16::MAX) + 1), u16::MAX);
}

/// `recomputed` is only reached from a failed verification, and a segment too
/// long for a pseudo-header length has none to report.
#[test]
fn recomputing_over_an_impossible_length_answers_zero() {
    let oversized = std::vec![0u8; usize::from(u16::MAX) + 1];
    assert_eq!(recomputed(STATION, APPLIANCE, &oversized), 0);
}

/// A segment longer than any IPv4 datagram has no pseudo-header length to be
/// summed under, so it is refused as the wrong shape rather than summed at a
/// truncated length.
///
/// The data offset is a valid five words, so the refusal is the length check
/// rather than the offset check that precedes it.
#[test]
fn a_segment_longer_than_a_datagram_is_refused() {
    let mut oversized = std::vec![0u8; usize::from(u16::MAX) + 1];
    oversized[12] = 5 << 4;
    assert_eq!(
        Segment::parse(STATION, APPLIANCE, &oversized),
        Err(SegmentError::DataOffsetExceedsSegment {
            data_offset: 5,
            got: oversized.len()
        })
    );
}

/// A payload no IPv4 total length can name is refused rather than truncated.
#[test]
fn a_payload_too_long_for_a_datagram_is_refused() {
    let payload = std::vec![0u8; usize::from(u16::MAX)];
    let outgoing = Outgoing {
        source_port: 80,
        destination_port: 1,
        sequence: SeqNumber::new(0),
        acknowledgement: SeqNumber::new(0),
        flags: Flags::ACK,
        window: 0,
        mss: None,
        window_scale: None,
        payload: &payload,
    };
    assert_eq!(
        outgoing.encoded_len(),
        Err(WriteError::PayloadTooLong { len: payload.len() })
    );
    let mut out = std::vec![0u8; usize::from(u16::MAX) + 64];
    assert!(matches!(
        outgoing.write(STATION, APPLIANCE, &mut out),
        Err(WriteError::PayloadTooLong { .. })
    ));
}

proptest! {
    /// Arbitrary bytes under an arbitrary address pair: every input is answered
    /// with a segment or a typed error, and nothing panics, indexes past a bound
    /// or overflows.
    #[test]
    fn arbitrary_bytes_are_answered(
        bytes in prop::collection::vec(any::<u8>(), 0..200),
        source in any::<[u8; 4]>(),
        destination in any::<[u8; 4]>(),
    ) {
        let source = Ipv4Address::from_octets(source);
        let destination = Ipv4Address::from_octets(destination);
        if let Ok(segment) = Segment::parse(source, destination, &bytes) {
            // A parsed segment's payload is inside the bytes handed over, and its
            // length is what the data offset left.
            prop_assert!(segment.payload.len() <= bytes.len());
            prop_assert!(segment.sequence_length() >= segment.payload.len() as u32);
        }
    }

    /// Anything this crate writes, it reads back to the same fields. The
    /// round trip is what proves the writer and the reader agree about the
    /// checksum, the data offset and the option layout at once.
    #[test]
    fn what_is_written_parses_back_to_itself(
        source_port in any::<u16>(),
        destination_port in any::<u16>(),
        sequence in any::<u32>(),
        acknowledgement in any::<u32>(),
        flag_bits in any::<u8>(),
        window in any::<u16>(),
        mss in prop::option::of(any::<u16>()),
        scale in prop::option::of(0u8..=MAX_WINDOW_SCALE),
        payload in prop::collection::vec(any::<u8>(), 0..64),
        addresses in any::<([u8; 4], [u8; 4])>(),
    ) {
        let source = Ipv4Address::from_octets(addresses.0);
        let destination = Ipv4Address::from_octets(addresses.1);
        // The reserved bits are dropped by the parser, so a round trip is stated
        // over the six flags that survive it.
        let flags = Flags::default().with(Flags(flag_bits & 0x3f));
        let outgoing = Outgoing {
            source_port,
            destination_port,
            sequence: SeqNumber::new(sequence),
            acknowledgement: SeqNumber::new(acknowledgement),
            flags,
            window,
            mss,
            window_scale: scale,
            payload: &payload,
        };
        let mut out = [0u8; 256];
        let len = outgoing.write(source, destination, &mut out).expect("room for 256 bytes");
        prop_assert_eq!(len, outgoing.encoded_len().expect("a bounded payload"));

        let parsed = Segment::parse(source, destination, &out[..len])
            .expect("a segment this crate wrote");
        prop_assert_eq!(parsed.source_port, source_port);
        prop_assert_eq!(parsed.destination_port, destination_port);
        prop_assert_eq!(parsed.sequence, SeqNumber::new(sequence));
        prop_assert_eq!(parsed.acknowledgement, SeqNumber::new(acknowledgement));
        prop_assert_eq!(parsed.flags, flags);
        prop_assert_eq!(parsed.window, window);
        prop_assert_eq!(parsed.payload, &payload[..]);
        // Options survive only on a `SYN`, which is where they are written.
        if flags.contains(Flags::SYN) {
            prop_assert_eq!(parsed.options.mss, mss);
            prop_assert_eq!(parsed.options.window_scale, scale);
        } else {
            prop_assert_eq!(parsed.options, Options::default());
        }
    }

    /// One bit flipped anywhere in a segment is refused. That is the property the
    /// pseudo-header checksum is for, and the reason it is verified before a
    /// field is read.
    ///
    /// *Which* refusal is not asserted, because one byte does not choose it: a
    /// flip in the data-offset nibble is refused as a bad offset before the
    /// checksum is reached, and refusing it earlier is not a weaker answer. The
    /// checksum path is asserted on its own in
    /// `a_checksum_that_does_not_verify_is_refused_and_names_both_values`.
    #[test]
    fn a_single_flipped_bit_is_refused(index in 0usize..24, bit in 0u32..8) {
        let sound = sealed(
            STATION,
            APPLIANCE,
            raw(Fields {
                source_port: 40000,
                window: 8192,
                ..plain(0x1234, 0x5678, 5, 0x10, &[], b"abcd")
            }),
        );
        prop_assume!(index < sound.len());
        prop_assert!(Segment::parse(STATION, APPLIANCE, &sound).is_ok());
        let mut corrupted = sound.clone();
        corrupted[index] ^= 1 << bit;
        prop_assert!(Segment::parse(STATION, APPLIANCE, &corrupted).is_err());
    }

    /// Every option area a peer can compose is walked in bounded time and
    /// answered: the loop consumes at least one byte per iteration, so the header
    /// bounds it.
    #[test]
    fn any_option_area_terminates(options in prop::collection::vec(any::<u8>(), 0..40)) {
        // Padded to a whole number of words, as a data offset can only name one.
        let mut options = options;
        while options.len() % 4 != 0 {
            options.push(0);
        }
        let words = 5 + options.len() / 4;
        prop_assume!(words <= 15);
        // Lossless: bounded to fifteen by the assumption above.
        let bytes = sealed(
            STATION,
            APPLIANCE,
            raw(plain(0, 0, words as u8, 0x02, &options, &[])),
        );
        // Either a segment or a typed error; never a hang and never a panic.
        let _ = Segment::parse(STATION, APPLIANCE, &bytes);
    }

    /// The writer never touches a byte past the length it reports, which is what
    /// the protection domain relies on when it lends the buffer onward.
    #[test]
    fn nothing_is_written_past_the_reported_length(
        payload in prop::collection::vec(any::<u8>(), 0..64),
        flag_bits in any::<u8>(),
    ) {
        let mut out = [0xa5u8; 256];
        let len = Outgoing {
            source_port: 80,
            destination_port: 1,
            sequence: SeqNumber::new(0),
            acknowledgement: SeqNumber::new(0),
            flags: Flags(flag_bits & 0x3f),
            window: 0,
            mss: Some(1460),
            window_scale: Some(7),
            payload: &payload,
        }
        .write(STATION, APPLIANCE, &mut out)
        .expect("room");
        prop_assert!(out[len..].iter().all(|byte| *byte == 0xa5));
    }
}
