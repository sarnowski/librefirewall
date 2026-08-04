use super::*;

use proptest::prelude::*;
use std::{string::String, vec, vec::Vec};

/// A buffer byte no encoder output contains, so a test can tell a byte that was
/// written from one that was left alone.
const UNTOUCHED: u8 = 0xAA;

fn scratch(len: usize) -> Vec<u8> {
    vec![UNTOUCHED; len]
}

fn ethernet_interface() -> InterfaceDescription<'static> {
    InterfaceDescription {
        link_type: LinkType::ETHERNET,
        snap_len: 262_144,
        name: None,
        description: None,
        speed: None,
        timestamp_resolution: TimestampResolution::MICROSECONDS,
    }
}

fn bare_packet(captured: &[u8]) -> EnhancedPacket<'_> {
    EnhancedPacket {
        interface_id: 0,
        timestamp: 0x0000_0001_0000_0002,
        captured,
        original_len: u32::try_from(captured.len()).expect("test payloads are small"),
        flags: None,
        drop_count: None,
        packet_id: None,
        queue: None,
        verdict: None,
        custom: None,
        comment: None,
    }
}

/// Encode one block into a buffer sized by the matching `*_len`, answering the
/// exact bytes it wrote.
fn encoded<T>(
    value: &T,
    len: fn(&T) -> Result<usize, EncodeError>,
    write: fn(&mut [u8], &T) -> Result<usize, EncodeError>,
) -> Vec<u8> {
    let predicted = len(value).expect("the block is encodable");
    let mut out = scratch(predicted);
    let written = write(&mut out, value).expect("a buffer of the predicted size is enough");
    assert_eq!(written, predicted, "the writer disagreed with the measurer");
    out
}

// ---------------------------------------------------------------------------
// Byte-exact vectors, hand-computed from draft-ietf-opsawg-pcapng.
// ---------------------------------------------------------------------------

#[test]
fn a_section_header_without_options_is_twenty_eight_bytes() {
    let bytes = encoded(
        &SectionHeader::default(),
        section_header_len,
        write_section_header,
    );

    #[rustfmt::skip]
    let expected: [u8; 28] = [
        0x0A, 0x0D, 0x0D, 0x0A,                         // Block Type
        0x1C, 0x00, 0x00, 0x00,                         // Block Total Length = 28
        0x4D, 0x3C, 0x2B, 0x1A,                         // Byte-Order Magic
        0x01, 0x00,                                     // Major Version = 1
        0x00, 0x00,                                     // Minor Version = 0
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Section Length = unspecified
        0x1C, 0x00, 0x00, 0x00,                         // Block Total Length, repeated
    ];
    assert_eq!(bytes, expected);
}

#[test]
fn a_section_header_carries_its_four_options_in_ascending_code_order() {
    let header = SectionHeader {
        hardware: Some("x86_64"),
        os: Some("librefirewall"),
        application: Some("lfw-pcapng"),
        schema: Some(CustomBinary {
            pen: UNREGISTERED_PEN,
            data: &[0x01],
        }),
    };
    let bytes = encoded(&header, section_header_len, write_section_header);

    #[rustfmt::skip]
    let expected: [u8; 92] = [
        0x0A, 0x0D, 0x0D, 0x0A,
        0x5C, 0x00, 0x00, 0x00,                         // Block Total Length = 92
        0x4D, 0x3C, 0x2B, 0x1A,
        0x01, 0x00,
        0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        // shb_hardware = "x86_64", 6 bytes, 2 of padding
        0x02, 0x00, 0x06, 0x00,
        0x78, 0x38, 0x36, 0x5F, 0x36, 0x34, 0x00, 0x00,
        // shb_os = "librefirewall", 13 bytes, 3 of padding
        0x03, 0x00, 0x0D, 0x00,
        0x6C, 0x69, 0x62, 0x72, 0x65, 0x66, 0x69, 0x72,
        0x65, 0x77, 0x61, 0x6C, 0x6C, 0x00, 0x00, 0x00,
        // shb_userappl = "lfw-pcapng", 10 bytes, 2 of padding
        0x04, 0x00, 0x0A, 0x00,
        0x6C, 0x66, 0x77, 0x2D, 0x70, 0x63, 0x61, 0x70,
        0x6E, 0x67, 0x00, 0x00,
        // custom 2989 = 0x0BAD: PEN then one octet, 3 of padding
        0xAD, 0x0B, 0x05, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00,
        // opt_endofopt
        0x00, 0x00, 0x00, 0x00,
        0x5C, 0x00, 0x00, 0x00,
    ];
    assert_eq!(bytes, expected);
}

#[test]
fn an_interface_description_always_states_its_timestamp_resolution() {
    let bytes = encoded(
        &ethernet_interface(),
        interface_description_len,
        write_interface_description,
    );

    #[rustfmt::skip]
    let expected: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00,                         // Block Type
        0x20, 0x00, 0x00, 0x00,                         // Block Total Length = 32
        0x01, 0x00,                                     // LinkType = Ethernet
        0x00, 0x00,                                     // Reserved
        0x00, 0x00, 0x04, 0x00,                         // SnapLen = 262144
        // if_tsresol = 6 (microseconds), one byte, 3 of padding
        0x09, 0x00, 0x01, 0x00,
        0x06, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,                         // opt_endofopt
        0x20, 0x00, 0x00, 0x00,
    ];
    assert_eq!(bytes, expected);
}

#[test]
fn an_interface_description_carries_name_description_and_speed() {
    let idb = InterfaceDescription {
        link_type: LinkType::ETHERNET,
        snap_len: 0,
        name: Some("eth0"),
        description: Some("wan"),
        speed: Some(10_000_000_000),
        timestamp_resolution: TimestampResolution::NANOSECONDS,
    };
    let bytes = encoded(&idb, interface_description_len, write_interface_description);

    #[rustfmt::skip]
    let expected: [u8; 60] = [
        0x01, 0x00, 0x00, 0x00,
        0x3C, 0x00, 0x00, 0x00,                         // Block Total Length = 60
        0x01, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,                         // SnapLen = 0, no limit
        // if_name = "eth0", 4 bytes, no padding
        0x02, 0x00, 0x04, 0x00,
        0x65, 0x74, 0x68, 0x30,
        // if_description = "wan", 3 bytes, 1 of padding
        0x03, 0x00, 0x03, 0x00,
        0x77, 0x61, 0x6E, 0x00,
        // if_speed = 10 Gbit/s
        0x08, 0x00, 0x08, 0x00,
        0x00, 0xE4, 0x0B, 0x54, 0x02, 0x00, 0x00, 0x00,
        // if_tsresol = 9 (nanoseconds)
        0x09, 0x00, 0x01, 0x00,
        0x09, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x3C, 0x00, 0x00, 0x00,
    ];
    assert_eq!(bytes, expected);
}

#[test]
fn an_enhanced_packet_without_options_writes_no_option_area_at_all() {
    let bytes = encoded(
        &bare_packet(&[0xDE, 0xAD, 0xBE, 0xEF]),
        enhanced_packet_len,
        write_enhanced_packet,
    );

    #[rustfmt::skip]
    let expected: [u8; 36] = [
        0x06, 0x00, 0x00, 0x00,                         // Block Type
        0x24, 0x00, 0x00, 0x00,                         // Block Total Length = 36
        0x00, 0x00, 0x00, 0x00,                         // Interface ID
        0x01, 0x00, 0x00, 0x00,                         // Timestamp, high half
        0x02, 0x00, 0x00, 0x00,                         // Timestamp, low half
        0x04, 0x00, 0x00, 0x00,                         // Captured Packet Length
        0x04, 0x00, 0x00, 0x00,                         // Original Packet Length
        0xDE, 0xAD, 0xBE, 0xEF,                         // packet data, already aligned
        0x24, 0x00, 0x00, 0x00,
    ];
    assert_eq!(bytes, expected);
}

#[test]
fn an_enhanced_packet_carries_every_option_it_was_given() {
    let epb = EnhancedPacket {
        interface_id: 2,
        timestamp: 0x0000_000A_0000_000B,
        captured: &[0x01, 0x02, 0x03],
        original_len: 5,
        flags: Some(1),
        drop_count: Some(7),
        packet_id: Some(8),
        queue: Some(3),
        verdict: Some(Verdict {
            kind: VerdictKind::LINUX_EBPF_TC,
            data: &[0xAA],
        }),
        custom: Some(CustomBinary {
            pen: UNREGISTERED_PEN,
            data: &[0xBB, 0xCC],
        }),
        comment: Some("hi"),
    };
    let bytes = encoded(&epb, enhanced_packet_len, write_enhanced_packet);

    #[rustfmt::skip]
    let expected: [u8; 108] = [
        0x06, 0x00, 0x00, 0x00,
        0x6C, 0x00, 0x00, 0x00,                         // Block Total Length = 108
        0x02, 0x00, 0x00, 0x00,                         // Interface ID = 2
        0x0A, 0x00, 0x00, 0x00,                         // Timestamp, high half
        0x0B, 0x00, 0x00, 0x00,                         // Timestamp, low half
        0x03, 0x00, 0x00, 0x00,                         // Captured = 3
        0x05, 0x00, 0x00, 0x00,                         // Original = 5, the sink truncated
        0x01, 0x02, 0x03, 0x00,                         // packet data plus one pad byte
        // opt_comment = "hi"
        0x01, 0x00, 0x02, 0x00,
        0x68, 0x69, 0x00, 0x00,
        // epb_flags
        0x02, 0x00, 0x04, 0x00,
        0x01, 0x00, 0x00, 0x00,
        // epb_dropcount
        0x04, 0x00, 0x08, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // epb_packetid
        0x05, 0x00, 0x08, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // epb_queue
        0x06, 0x00, 0x04, 0x00,
        0x03, 0x00, 0x00, 0x00,
        // epb_verdict: the kind octet, then its data
        0x07, 0x00, 0x02, 0x00,
        0x01, 0xAA, 0x00, 0x00,
        // custom 2989: PEN then two octets
        0xAD, 0x0B, 0x06, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xBB, 0xCC, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x6C, 0x00, 0x00, 0x00,
    ];
    assert_eq!(bytes, expected);
}

#[test]
fn interface_statistics_write_their_two_timestamps_as_split_halves() {
    let isb = InterfaceStatistics {
        interface_id: 1,
        timestamp: 0x0000_0003_0000_0004,
        start_time: 0x0000_0005_0000_0006,
        end_time: 0x0000_0007_0000_0008,
        received: 0x1122_3344_5566_7788,
        dropped: 9,
    };
    let bytes = encoded(&isb, interface_statistics_len, write_interface_statistics);

    #[rustfmt::skip]
    let expected: [u8; 76] = [
        0x05, 0x00, 0x00, 0x00,                         // Block Type
        0x4C, 0x00, 0x00, 0x00,                         // Block Total Length = 76
        0x01, 0x00, 0x00, 0x00,                         // Interface ID
        0x03, 0x00, 0x00, 0x00,                         // Timestamp, high half
        0x04, 0x00, 0x00, 0x00,                         // Timestamp, low half
        // isb_starttime: high half then low half, NOT a little-endian u64
        0x02, 0x00, 0x08, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        // isb_endtime
        0x03, 0x00, 0x08, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
        // isb_ifrecv: a plain little-endian u64
        0x04, 0x00, 0x08, 0x00,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        // isb_ifdrop
        0x05, 0x00, 0x08, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x4C, 0x00, 0x00, 0x00,
    ];
    assert_eq!(bytes, expected);
}

#[test]
fn a_custom_block_without_data_is_sixteen_bytes() {
    let body = CustomBinary {
        pen: UNREGISTERED_PEN,
        data: &[],
    };
    let bytes = encoded(&body, custom_block_len, write_custom_block);

    #[rustfmt::skip]
    let expected: [u8; MIN_CUSTOM_BLOCK_LEN] = [
        0xAD, 0x0B, 0x00, 0x00,                         // Block Type = 0x0BAD
        0x10, 0x00, 0x00, 0x00,                         // Block Total Length = 16
        0xFF, 0xFF, 0xFF, 0xFF,                         // Private Enterprise Number
        0x10, 0x00, 0x00, 0x00,                         // Block Total Length, repeated
    ];
    assert_eq!(bytes, expected);
}

#[test]
fn a_custom_block_pads_its_data_to_the_boundary() {
    // An enterprise number that is not the placeholder, to show the field is
    // the caller's and is written in the section's byte order like every other.
    let pen = 0x0403_0201;
    let data = [0x11, 0x22, 0x33, 0x44];

    for len in 1..=data.len() {
        let body = CustomBinary {
            pen,
            data: data.get(..len).expect("inside the array"),
        };
        let bytes = encoded(&body, custom_block_len, write_custom_block);

        let mut expected = vec![0xAD, 0x0B, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00];
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        expected.extend_from_slice(data.get(..len).expect("inside the array"));
        // One to three zero bytes carry the data to the boundary; four leave
        // it there already, so this adds nothing.
        expected.resize(MIN_CUSTOM_BLOCK_LEN, 0);
        expected.extend_from_slice(&[0x14, 0x00, 0x00, 0x00]);
        assert_eq!(bytes, expected, "{len} bytes of data");
    }
}

#[test]
fn a_custom_block_carries_data_no_option_could_hold() {
    // One byte past what an Option Length can express: a Custom Block's data
    // is bounded by the Block Total Length alone, and this is the difference.
    let data = vec![0x5A; usize::from(u16::MAX) + 1];
    let body = CustomBinary {
        pen: UNREGISTERED_PEN,
        data: &data,
    };
    let bytes = encoded(&body, custom_block_len, write_custom_block);

    let total = u32::try_from(MIN_CUSTOM_BLOCK_LEN + data.len()).expect("small enough");
    let mut expected = vec![0xAD, 0x0B, 0x00, 0x00];
    expected.extend_from_slice(&total.to_le_bytes());
    expected.extend_from_slice(&UNREGISTERED_PEN.to_le_bytes());
    expected.extend_from_slice(&data);
    expected.extend_from_slice(&total.to_le_bytes());
    assert_eq!(total, 65_552);
    assert_eq!(bytes, expected);
}

#[test]
fn a_padding_block_is_a_custom_block_of_exactly_the_slack_it_fills() {
    // 16 is the whole block and nothing else; 20 adds one word of data; 508 is
    // the slack behind a 4-byte block at the end of a 512-byte sector.
    for len in [MIN_CUSTOM_BLOCK_LEN, 20, 508] {
        let mut out = scratch(len);
        assert_eq!(write_padding_block(&mut out, len), Ok(len));

        let total = u32::try_from(len).expect("small enough");
        let mut expected = vec![0xAD, 0x0B, 0x00, 0x00];
        expected.extend_from_slice(&total.to_le_bytes());
        expected.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        expected.resize(len - 4, 0);
        expected.extend_from_slice(&total.to_le_bytes());
        assert_eq!(out, expected, "a {len}-byte padding block");
    }
}

#[test]
fn a_minimal_file_is_a_section_an_interface_and_a_packet() {
    let packet = [0xDE, 0xAD, 0xBE, 0xEF];
    let mut file = scratch(96);

    let mut at = 0;
    at += write_section_header(&mut file, &SectionHeader::default()).expect("section fits");
    at += write_interface_description(
        file.get_mut(at..).expect("the section left room"),
        &ethernet_interface(),
    )
    .expect("interface fits");
    at += write_enhanced_packet(
        file.get_mut(at..).expect("the interface left room"),
        &bare_packet(&packet),
    )
    .expect("packet fits");

    assert_eq!(at, 96, "28 + 32 + 36");

    #[rustfmt::skip]
    let expected: [u8; 96] = [
        // Section Header Block
        0x0A, 0x0D, 0x0D, 0x0A, 0x1C, 0x00, 0x00, 0x00,
        0x4D, 0x3C, 0x2B, 0x1A, 0x01, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x1C, 0x00, 0x00, 0x00,
        // Interface Description Block
        0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
        0x09, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        // Enhanced Packet Block
        0x06, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        0x24, 0x00, 0x00, 0x00,
    ];
    assert_eq!(file, expected);
}

// ---------------------------------------------------------------------------
// Padding and alignment boundaries.
// ---------------------------------------------------------------------------

#[test]
fn padding_carries_every_remainder_to_the_next_boundary() {
    assert_eq!(padding_for(0), 0);
    assert_eq!(padding_for(1), 3);
    assert_eq!(padding_for(2), 2);
    assert_eq!(padding_for(3), 1);
    assert_eq!(padding_for(4), 0);
    assert_eq!(padding_for(usize::MAX), 1);
}

#[test]
fn a_payload_is_padded_to_the_next_boundary_and_no_further() {
    for (captured_len, expected_total) in [(0, 32), (1, 36), (2, 36), (3, 36), (4, 36), (5, 40)] {
        let packet = vec![0x5A; captured_len];
        let bytes = encoded(
            &bare_packet(&packet),
            enhanced_packet_len,
            write_enhanced_packet,
        );
        assert_eq!(
            bytes.len(),
            expected_total,
            "a {captured_len}-byte payload should occupy {expected_total} bytes"
        );
        assert!(bytes.len().is_multiple_of(4));
    }
}

#[test]
fn padding_bytes_are_written_as_zero_over_whatever_was_there() {
    let bytes = encoded(
        &bare_packet(&[0x11]),
        enhanced_packet_len,
        write_enhanced_packet,
    );

    // 8 bytes of framing, 20 of body, then the single payload byte.
    assert_eq!(bytes.get(28..32), Some([0x11, 0x00, 0x00, 0x00].as_slice()));
}

#[test]
fn an_option_of_zero_length_occupies_only_its_header() {
    let mut epb = bare_packet(&[]);
    epb.comment = Some("");
    let bytes = encoded(&epb, enhanced_packet_len, write_enhanced_packet);

    // 12 framing + 20 body + 4 for the empty option + 4 for opt_endofopt.
    assert_eq!(bytes.len(), 40);
    // The option area sits behind 8 bytes of leading framing and the 20-byte
    // body: an option header with no value at all, then opt_endofopt.
    assert_eq!(
        bytes.get(28..36),
        Some([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].as_slice()),
    );
}

#[test]
fn the_largest_option_a_sixteen_bit_length_holds_is_accepted() {
    let comment = String::from_utf8(vec![b'x'; usize::from(u16::MAX)]).expect("ascii");
    let mut epb = bare_packet(&[]);
    epb.comment = Some(&comment);

    // 12 framing + 20 body + (4 + 65535 + 1 padding) + 4 for opt_endofopt.
    assert_eq!(enhanced_packet_len(&epb), Ok(65_576));
    let bytes = encoded(&epb, enhanced_packet_len, write_enhanced_packet);
    assert_eq!(bytes.len(), 65_576);
    assert!(bytes.len().is_multiple_of(4));
}

#[test]
fn a_custom_option_counts_its_enterprise_number_towards_the_length() {
    let data = vec![0x00; usize::from(u16::MAX) - PEN_LEN];
    let mut epb = bare_packet(&[]);
    epb.custom = Some(CustomBinary {
        pen: UNREGISTERED_PEN,
        data: &data,
    });
    assert!(
        enhanced_packet_len(&epb).is_ok(),
        "65531 + 4 is exactly the limit"
    );

    let one_too_many = vec![0x00; usize::from(u16::MAX) - PEN_LEN + 1];
    epb.custom = Some(CustomBinary {
        pen: UNREGISTERED_PEN,
        data: &one_too_many,
    });
    assert_eq!(
        enhanced_packet_len(&epb),
        Err(EncodeError::OptionTooLong {
            code: CUSTOM_BINARY_COPYABLE,
            len: 65_536,
        }),
    );
}

// ---------------------------------------------------------------------------
// Every error variant.
// ---------------------------------------------------------------------------

#[test]
fn a_buffer_one_byte_short_is_refused_with_the_length_it_lacked() {
    let header = SectionHeader::default();
    let needed = section_header_len(&header).expect("encodable");
    let mut out = scratch(needed - 1);

    assert_eq!(
        write_section_header(&mut out, &header),
        Err(EncodeError::OutOfSpace {
            needed,
            capacity: needed - 1,
        }),
    );
    assert!(
        out.iter().all(|&byte| byte == UNTOUCHED),
        "a refusal must leave the caller's buffer alone",
    );
}

#[test]
fn every_writer_refuses_a_short_buffer_without_touching_it() {
    let idb = ethernet_interface();
    let epb = bare_packet(&[1, 2, 3]);
    let isb = InterfaceStatistics {
        interface_id: 0,
        timestamp: 1,
        start_time: 2,
        end_time: 3,
        received: 4,
        dropped: 5,
    };

    /// One block's writer with its arguments already bound, so the four can be
    /// held side by side and driven through the same loop.
    type BoundWriter<'a> = &'a dyn Fn(&mut [u8]) -> Result<usize, EncodeError>;

    let custom = CustomBinary {
        pen: UNREGISTERED_PEN,
        data: &[0xAB],
    };

    let cases: [(usize, BoundWriter<'_>); 6] = [
        (
            section_header_len(&SectionHeader::default()).expect("encodable"),
            &|out| write_section_header(out, &SectionHeader::default()),
        ),
        (custom_block_len(&custom).expect("encodable"), &|out| {
            write_custom_block(out, &custom)
        }),
        (24, &|out| write_padding_block(out, 24)),
        (
            interface_description_len(&idb).expect("encodable"),
            &|out| write_interface_description(out, &idb),
        ),
        (enhanced_packet_len(&epb).expect("encodable"), &|out| {
            write_enhanced_packet(out, &epb)
        }),
        (interface_statistics_len(&isb).expect("encodable"), &|out| {
            write_interface_statistics(out, &isb)
        }),
    ];

    for (needed, write) in cases {
        for capacity in 0..needed {
            let mut out = scratch(capacity);
            let refused = write(&mut out);
            // The variant matters as much as the buffer: `OutOfSpace` is the one
            // a caller retries against, and it is only ever decided before a
            // byte is emitted. The one outcome that can leave part of a block
            // behind carries its own name.
            assert_eq!(refused, Err(EncodeError::OutOfSpace { needed, capacity }));
            assert!(out.iter().all(|&byte| byte == UNTOUCHED));
        }
    }
}

#[test]
fn more_captured_bytes_than_the_frame_had_is_refused() {
    let mut epb = bare_packet(&[1, 2, 3, 4]);
    epb.original_len = 3;

    let expected = Err(EncodeError::CapturedExceedsOriginal {
        captured: 4,
        original: 3,
    });
    assert_eq!(enhanced_packet_len(&epb), expected);
    assert_eq!(write_enhanced_packet(&mut scratch(1024), &epb), expected);
}

#[test]
fn a_payload_beyond_a_thirty_two_bit_length_is_refused() {
    // Reached through the helper rather than through a slice: no test can
    // allocate the four gibibytes the public path would need to get here.
    let len = usize::try_from(u64::from(u32::MAX) + 1).expect("a 64-bit host");
    assert_eq!(
        captured_length(len, u32::MAX),
        Err(EncodeError::PayloadTooLong { len }),
    );
}

#[test]
fn a_padding_block_refuses_a_length_it_could_not_frame() {
    let mut out = scratch(512);

    // A length that is both misaligned and too short is refused for the
    // alignment: that is the fault the caller fixes by rounding, and rounding
    // 1 up reaches a length that is still refused for the other reason.
    for len in [1, 2, 3, 17, 18, 19, 509, usize::MAX] {
        assert_eq!(
            write_padding_block(&mut out, len),
            Err(EncodeError::BlockNotAligned { len }),
        );
    }
    for len in [0, 4, 8, 12] {
        assert_eq!(
            write_padding_block(&mut out, len),
            Err(EncodeError::BlockTooShort { len }),
        );
    }
    assert!(
        out.iter().all(|&byte| byte == UNTOUCHED),
        "a refusal must leave the caller's buffer alone",
    );
}

#[test]
fn a_block_beyond_a_thirty_two_bit_total_length_is_refused() {
    assert_eq!(
        Measured::new(usize::MAX).err(),
        Some(EncodeError::BlockTooLong)
    );

    let largest = Measured::new(usize::try_from(u32::MAX).expect("a 64-bit host"))
        .expect("exactly the limit is encodable");
    assert_eq!(largest.field, u32::MAX);
}

#[test]
fn the_largest_block_a_thirty_two_bit_length_holds_is_measured_and_not_refused() {
    // Four gibibytes of data, reached without allocating any: a padding block
    // states its data's length instead of carrying it, and the measurement it
    // is then held to is the one `custom_block_len` makes of a slice no test
    // could hold. Refusal comes from the block's length, never from the buffer.
    let largest = usize::try_from(u32::MAX).expect("a 64-bit host") & !3;
    assert_eq!(
        write_padding_block(&mut [], largest),
        Err(EncodeError::OutOfSpace {
            needed: largest,
            capacity: 0,
        }),
    );
    assert_eq!(
        write_padding_block(&mut [], largest + 4),
        Err(EncodeError::BlockTooLong),
    );
}

#[test]
fn an_option_beyond_a_sixteen_bit_length_is_refused_by_name() {
    let comment = String::from_utf8(vec![b'x'; usize::from(u16::MAX) + 1]).expect("ascii");
    let mut epb = bare_packet(&[]);
    epb.comment = Some(&comment);

    let expected = Err(EncodeError::OptionTooLong {
        code: OPT_COMMENT,
        len: 65_536,
    });
    assert_eq!(enhanced_packet_len(&epb), expected);
    assert_eq!(write_enhanced_packet(&mut scratch(1 << 20), &epb), expected);

    assert_eq!(
        section_header_len(&SectionHeader {
            os: Some(&comment),
            ..SectionHeader::default()
        }),
        Err(EncodeError::OptionTooLong {
            code: SHB_OS,
            len: 65_536,
        }),
    );
}

#[test]
fn a_counter_that_would_wrap_reports_rather_than_wrapping() {
    let mut counter = Counter { bytes: usize::MAX };
    assert!(counter.push(&[0]).is_err());
    assert!(counter.zeros(1).is_err());
}

#[test]
fn a_filler_never_writes_past_the_room_it_was_given() {
    let mut out = [UNTOUCHED; 2];
    let mut filler = Filler {
        out: &mut out,
        at: 0,
    };
    assert!(filler.push(&[1, 2, 3]).is_err());
    assert!(filler.zeros(3).is_err());
    assert_eq!(filler.at, 0, "a refused write advances nothing");

    assert!(filler.push(&[1, 2]).is_ok());
    // The offset plus the length wraps, so the addition is refused before a
    // slice is ever asked for a range that would look plausible.
    assert!(filler.take(usize::MAX).is_err());
    assert_eq!(out, [1, 2], "only the accepted push landed");
}

#[test]
fn every_error_renders_a_distinct_sentence() {
    let rendered = [
        EncodeError::OutOfSpace {
            needed: 36,
            capacity: 8,
        },
        EncodeError::PayloadTooLong { len: 1 << 33 },
        EncodeError::OptionTooLong {
            code: 1,
            len: 65_536,
        },
        EncodeError::CapturedExceedsOriginal {
            captured: 4,
            original: 3,
        },
        EncodeError::BlockTooLong,
        EncodeError::BlockNotAligned { len: 17 },
        EncodeError::BlockTooShort { len: 12 },
        EncodeError::MeasureDisagreed { measured: 44 },
    ]
    .map(|error| std::format!("{error}"));

    for (index, text) in rendered.iter().enumerate() {
        assert!(!text.is_empty());
        assert!(
            !rendered.iter().skip(index + 1).any(|other| other == text),
            "two errors render alike: {text}",
        );
    }
}

// ---------------------------------------------------------------------------
// Types that exist to make a wrong encoding unrepresentable.
// ---------------------------------------------------------------------------

#[test]
fn a_timestamp_resolution_refuses_the_power_of_two_form() {
    assert_eq!(
        TimestampResolution::from_decimal_digits(6),
        Some(TimestampResolution::MICROSECONDS),
    );
    assert_eq!(
        TimestampResolution::from_decimal_digits(0x7F).map(TimestampResolution::decimal_digits),
        Some(0x7F),
    );
    assert_eq!(TimestampResolution::from_decimal_digits(0x80), None);
    assert_eq!(TimestampResolution::from_decimal_digits(0xFF), None);

    assert_eq!(TimestampResolution::MILLISECONDS.decimal_digits(), 3);
    assert_eq!(TimestampResolution::NANOSECONDS.decimal_digits(), 9);
}

#[test]
fn a_timestamp_splits_into_the_two_halves_the_format_writes() {
    assert_eq!(split_timestamp(0), (0, 0));
    assert_eq!(split_timestamp(u64::MAX), (u32::MAX, u32::MAX));
    assert_eq!(
        split_timestamp(0x0123_4567_89AB_CDEF),
        (0x0123_4567, 0x89AB_CDEF),
    );
}

#[test]
fn an_inline_value_reports_the_width_it_emits() {
    assert_eq!(Inline::None.len(), 0);
    assert_eq!(Inline::from_u8(1).len(), 1);
    assert_eq!(Inline::from_u32(1).len(), 4);
    assert_eq!(Inline::from_u64(1).len(), 8);
    assert_eq!(Inline::from_timestamp(1).len(), 8);

    assert_eq!(Inline::None.as_slice(), &[] as &[u8]);
    assert_eq!(Inline::from_u8(0x7F).as_slice(), &[0x7F]);
    assert_eq!(Inline::from_u32(1).as_slice(), &[1, 0, 0, 0]);
    assert_eq!(Inline::from_u64(1).as_slice(), &[1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        Inline::from_timestamp(0x0000_0001_0000_0002).as_slice(),
        &[1, 0, 0, 0, 2, 0, 0, 0],
    );

    for inline in [
        Inline::None,
        Inline::from_u8(0),
        Inline::from_u32(0),
        Inline::from_u64(0),
    ] {
        assert_eq!(usize::from(inline.len()), inline.as_slice().len());
    }
}

#[test]
fn the_named_link_and_verdict_kinds_are_the_registered_numbers() {
    assert_eq!(LinkType::ETHERNET, LinkType(1));
    assert_eq!(VerdictKind::HARDWARE, VerdictKind(0));
    assert_eq!(VerdictKind::LINUX_EBPF_TC, VerdictKind(1));
    assert_eq!(VerdictKind::LINUX_EBPF_XDP, VerdictKind(2));
}

// ---------------------------------------------------------------------------
// An independent reader, used only to check the encoder against something that
// is not the encoder. It walks by the lengths a real reader walks by and reads
// nothing it was not pointed at by them.
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct ReadBlock<'a> {
    block_type: u32,
    body: &'a [u8],
}

/// Split a stream into blocks, insisting on the framing every reader navigates
/// by: a total length that is present, aligned, at least the framing itself,
/// and repeated identically at the block's end.
fn read_blocks(stream: &[u8]) -> Option<Vec<ReadBlock<'_>>> {
    let mut blocks = Vec::new();
    let mut rest = stream;
    while !rest.is_empty() {
        let block_type = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?);
        let total = usize::try_from(u32::from_le_bytes(rest.get(4..8)?.try_into().ok()?)).ok()?;
        if total < BLOCK_FRAMING_LEN || !total.is_multiple_of(4) || total > rest.len() {
            return None;
        }
        let trailing = u32::from_le_bytes(rest.get(total - 4..total)?.try_into().ok()?);
        if usize::try_from(trailing).ok()? != total {
            return None;
        }
        blocks.push(ReadBlock {
            block_type,
            body: rest.get(8..total - 4)?,
        });
        rest = rest.get(total..)?;
    }
    Some(blocks)
}

#[derive(Debug, PartialEq, Eq)]
struct ReadOption<'a> {
    code: u16,
    value: &'a [u8],
}

/// Decode an option area up to `opt_endofopt`, insisting that every value is
/// present in full and followed by its padding.
fn read_options(area: &[u8]) -> Option<Vec<ReadOption<'_>>> {
    let mut options = Vec::new();
    let mut rest = area;
    loop {
        if rest.is_empty() {
            return Some(options);
        }
        let code = u16::from_le_bytes(rest.get(0..2)?.try_into().ok()?);
        let len = usize::from(u16::from_le_bytes(rest.get(2..4)?.try_into().ok()?));
        if code == OPT_END_OF_OPT {
            return if len == 0 && rest.len() == 4 {
                Some(options)
            } else {
                None
            };
        }
        let value = rest.get(4..4 + len)?;
        options.push(ReadOption { code, value });
        rest = rest.get(4 + len + padding_for(len)..)?;
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ReadPacket<'a> {
    interface_id: u32,
    timestamp: u64,
    captured: &'a [u8],
    original_len: u32,
    options: Vec<ReadOption<'a>>,
}

fn read_enhanced_packet<'a>(block: &ReadBlock<'a>) -> Option<ReadPacket<'a>> {
    if block.block_type != BLOCK_ENHANCED_PACKET {
        return None;
    }
    let body = block.body;
    let interface_id = u32::from_le_bytes(body.get(0..4)?.try_into().ok()?);
    let high = u32::from_le_bytes(body.get(4..8)?.try_into().ok()?);
    let low = u32::from_le_bytes(body.get(8..12)?.try_into().ok()?);
    let captured_len =
        usize::try_from(u32::from_le_bytes(body.get(12..16)?.try_into().ok()?)).ok()?;
    let original_len = u32::from_le_bytes(body.get(16..20)?.try_into().ok()?);
    let captured = body.get(20..20 + captured_len)?;
    let options = read_options(body.get(20 + captured_len + padding_for(captured_len)..)?)?;
    Some(ReadPacket {
        interface_id,
        timestamp: (u64::from(high) << 32) | u64::from(low),
        captured,
        original_len,
        options,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct ReadCustom<'a> {
    pen: u32,
    data: &'a [u8],
}

/// A Custom Block's enterprise number and everything behind it. The block
/// states no length for its data, so its padding is indistinguishable from
/// data to anyone who does not know the enterprise number — which is precisely
/// why a reader steps over the whole thing.
fn read_custom_block<'a>(block: &ReadBlock<'a>) -> Option<ReadCustom<'a>> {
    if block.block_type != CUSTOM_BLOCK_COPYABLE {
        return None;
    }
    Some(ReadCustom {
        pen: u32::from_le_bytes(block.body.get(0..4)?.try_into().ok()?),
        data: block.body.get(4..)?,
    })
}

#[test]
fn the_test_reader_rejects_framing_the_encoder_would_never_emit() {
    // A total length that overruns the stream.
    assert_eq!(read_blocks(&[6, 0, 0, 0, 0xFF, 0, 0, 0]), None);
    // A total length below the framing it must account for.
    assert_eq!(read_blocks(&[6, 0, 0, 0, 8, 0, 0, 0]), None);
    // A total length that is not aligned.
    assert_eq!(read_blocks(&[6, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0]), None);
    // A trailing total that disagrees with the leading one.
    assert_eq!(read_blocks(&[6, 0, 0, 0, 12, 0, 0, 0, 99, 0, 0, 0]), None,);
    // A truncated header.
    assert_eq!(read_blocks(&[6, 0, 0]), None);
    // An option whose value runs past the area.
    assert_eq!(read_options(&[1, 0, 0xFF, 0xFF]), None);
    // An option area with bytes after opt_endofopt.
    assert_eq!(read_options(&[0, 0, 0, 0, 0, 0, 0, 0]), None);

    let empty: &[u8] = &[];
    assert_eq!(read_blocks(empty), Some(Vec::new()));
    assert_eq!(read_options(empty), Some(Vec::new()));
}

#[test]
fn the_test_reader_recovers_a_packet_the_encoder_wrote() {
    let epb = EnhancedPacket {
        queue: Some(4),
        ..bare_packet(&[9, 8, 7])
    };
    let bytes = encoded(&epb, enhanced_packet_len, write_enhanced_packet);
    let blocks = read_blocks(&bytes).expect("well-framed");
    let read = read_enhanced_packet(blocks.first().expect("one block")).expect("an EPB");

    assert_eq!(read.interface_id, epb.interface_id);
    assert_eq!(read.timestamp, epb.timestamp);
    assert_eq!(read.captured, epb.captured);
    assert_eq!(read.original_len, epb.original_len);
    assert_eq!(
        read.options,
        vec![ReadOption {
            code: EPB_QUEUE,
            value: &[4, 0, 0, 0],
        }],
    );

    // A block of another type is not decoded as a packet.
    let section = encoded(
        &SectionHeader::default(),
        section_header_len,
        write_section_header,
    );
    let section_blocks = read_blocks(&section).expect("well-framed");
    assert_eq!(
        read_enhanced_packet(section_blocks.first().expect("one block")),
        None,
    );
    assert_eq!(
        read_custom_block(section_blocks.first().expect("one")),
        None
    );
    assert_eq!(read_custom_block(blocks.first().expect("one block")), None);
}

#[test]
fn the_test_reader_walks_past_a_padding_block_to_the_packet_behind_it() {
    let epb = bare_packet(&[9, 8, 7]);
    let mut stream = scratch(24 + 36);
    let mut at = write_padding_block(&mut stream, 24).expect("the padding fits");
    at += write_enhanced_packet(stream.get_mut(at..).expect("the padding left room"), &epb)
        .expect("the packet fits");
    assert_eq!(at, stream.len());

    let blocks = read_blocks(&stream).expect("well-framed");
    assert_eq!(
        read_custom_block(blocks.first().expect("the padding")),
        Some(ReadCustom {
            pen: UNREGISTERED_PEN,
            data: &[0; 8],
        }),
    );
    let read = read_enhanced_packet(blocks.get(1).expect("the packet")).expect("an EPB");
    assert_eq!(read.captured, epb.captured);
}

// ---------------------------------------------------------------------------
// Properties.
// ---------------------------------------------------------------------------

/// An [`EnhancedPacket`]'s fields, owned so a strategy can produce them; the
/// borrowed form is rebuilt inside the test body.
#[derive(Debug, Clone)]
struct OwnedPacket {
    interface_id: u32,
    timestamp: u64,
    captured: Vec<u8>,
    truncated_by: u32,
    flags: Option<u32>,
    drop_count: Option<u64>,
    packet_id: Option<u64>,
    queue: Option<u32>,
    verdict: Option<(u8, Vec<u8>)>,
    custom: Option<(u32, Vec<u8>)>,
    comment: Option<String>,
}

impl OwnedPacket {
    fn borrow(&self) -> EnhancedPacket<'_> {
        let captured_len = u32::try_from(self.captured.len()).expect("the strategy stays small");
        EnhancedPacket {
            interface_id: self.interface_id,
            timestamp: self.timestamp,
            captured: &self.captured,
            original_len: captured_len.saturating_add(self.truncated_by),
            flags: self.flags,
            drop_count: self.drop_count,
            packet_id: self.packet_id,
            queue: self.queue,
            verdict: self.verdict.as_ref().map(|(kind, data)| Verdict {
                kind: VerdictKind(*kind),
                data,
            }),
            custom: self
                .custom
                .as_ref()
                .map(|(pen, data)| CustomBinary { pen: *pen, data }),
            comment: self.comment.as_deref(),
        }
    }
}

fn any_packet() -> impl Strategy<Value = OwnedPacket> {
    (
        any::<u32>(),
        any::<u64>(),
        prop::collection::vec(any::<u8>(), 0..96),
        0u32..64,
        prop::option::of(any::<u32>()),
        prop::option::of(any::<u64>()),
        prop::option::of(any::<u64>()),
        prop::option::of(any::<u32>()),
        prop::option::of((any::<u8>(), prop::collection::vec(any::<u8>(), 0..16))),
        prop::option::of((any::<u32>(), prop::collection::vec(any::<u8>(), 0..16))),
        prop::option::of(any::<String>()),
    )
        .prop_map(
            |(
                interface_id,
                timestamp,
                captured,
                truncated_by,
                flags,
                drop_count,
                packet_id,
                queue,
                verdict,
                custom,
                comment,
            )| OwnedPacket {
                interface_id,
                timestamp,
                captured,
                truncated_by,
                flags,
                drop_count,
                packet_id,
                queue,
                verdict,
                custom,
                comment,
            },
        )
}

/// A [`SectionHeader`]'s fields, owned so a strategy can produce them.
#[derive(Debug, Clone)]
struct OwnedSection {
    hardware: Option<String>,
    os: Option<String>,
    application: Option<String>,
    schema: Option<(u32, Vec<u8>)>,
}

impl OwnedSection {
    fn borrow(&self) -> SectionHeader<'_> {
        SectionHeader {
            hardware: self.hardware.as_deref(),
            os: self.os.as_deref(),
            application: self.application.as_deref(),
            schema: self
                .schema
                .as_ref()
                .map(|(pen, data)| CustomBinary { pen: *pen, data }),
        }
    }
}

fn any_section_header() -> impl Strategy<Value = OwnedSection> {
    (
        prop::option::of(any::<String>()),
        prop::option::of(any::<String>()),
        prop::option::of(any::<String>()),
        prop::option::of((any::<u32>(), prop::collection::vec(any::<u8>(), 0..32))),
    )
        .prop_map(|(hardware, os, application, schema)| OwnedSection {
            hardware,
            os,
            application,
            schema,
        })
}

/// An [`InterfaceDescription`]'s fields, owned so a strategy can produce them.
#[derive(Debug, Clone)]
struct OwnedInterface {
    link_type: u16,
    snap_len: u32,
    name: Option<String>,
    description: Option<String>,
    speed: Option<u64>,
    digits: u8,
}

impl OwnedInterface {
    fn borrow(&self) -> InterfaceDescription<'_> {
        InterfaceDescription {
            link_type: LinkType(self.link_type),
            snap_len: self.snap_len,
            name: self.name.as_deref(),
            description: self.description.as_deref(),
            speed: self.speed,
            timestamp_resolution: TimestampResolution::from_decimal_digits(self.digits)
                .expect("the strategy stays inside the decimal form"),
        }
    }
}

fn any_interface() -> impl Strategy<Value = OwnedInterface> {
    (
        any::<u16>(),
        any::<u32>(),
        prop::option::of(any::<String>()),
        prop::option::of(any::<String>()),
        prop::option::of(any::<u64>()),
        0u8..=0x7F,
    )
        .prop_map(
            |(link_type, snap_len, name, description, speed, digits)| OwnedInterface {
                link_type,
                snap_len,
                name,
                description,
                speed,
                digits,
            },
        )
}

fn any_statistics() -> impl Strategy<Value = InterfaceStatistics> {
    (
        any::<u32>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(
            |(interface_id, timestamp, start_time, end_time, received, dropped)| {
                InterfaceStatistics {
                    interface_id,
                    timestamp,
                    start_time,
                    end_time,
                    received,
                    dropped,
                }
            },
        )
}

/// Check the contract shared by every block: the measured length is the written
/// length, the two Block Total Length fields agree with each other and with it,
/// and the whole is aligned.
fn check_block<T>(
    value: &T,
    len: fn(&T) -> Result<usize, EncodeError>,
    write: fn(&mut [u8], &T) -> Result<usize, EncodeError>,
) -> Result<Vec<u8>, TestCaseError> {
    let predicted = match len(value) {
        Ok(predicted) => predicted,
        Err(refused) => {
            // A block with no encoding must be refused the same way by both,
            // however much room the writer is offered.
            prop_assert_eq!(write(&mut scratch(1 << 18), value), Err(refused));
            return Ok(Vec::new());
        }
    };

    let mut out = scratch(predicted);
    let written = write(&mut out, value).map_err(|error| {
        TestCaseError::fail(std::format!(
            "a buffer of the predicted size was refused: {error}"
        ))
    })?;
    prop_assert_eq!(written, predicted);
    prop_assert!(written.is_multiple_of(4));
    prop_assert!(written >= BLOCK_FRAMING_LEN);

    let leading = u32::from_le_bytes(out.get(4..8).expect("framing").try_into().expect("four"));
    let trailing = u32::from_le_bytes(
        out.get(written - 4..written)
            .expect("framing")
            .try_into()
            .expect("four"),
    );
    prop_assert_eq!(leading, trailing);
    prop_assert_eq!(usize::try_from(leading), Ok(written));
    Ok(out)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The prediction is the whole point: a ring advanced by a length the
    /// writer did not produce corrupts every block after it.
    #[test]
    fn a_section_header_writes_exactly_what_it_measured(header in any_section_header()) {
        check_block(&header.borrow(), section_header_len, write_section_header)?;
    }

    #[test]
    fn an_interface_description_writes_exactly_what_it_measured(idb in any_interface()) {
        check_block(&idb.borrow(), interface_description_len, write_interface_description)?;
    }

    #[test]
    fn an_enhanced_packet_writes_exactly_what_it_measured(packet in any_packet()) {
        check_block(&packet.borrow(), enhanced_packet_len, write_enhanced_packet)?;
    }

    #[test]
    fn interface_statistics_write_exactly_what_they_measured(isb in any_statistics()) {
        check_block(&isb, interface_statistics_len, write_interface_statistics)?;
    }

    #[test]
    fn a_custom_block_writes_exactly_what_it_measured(
        pen in any::<u32>(),
        data in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        check_block(&CustomBinary { pen, data: &data }, custom_block_len, write_custom_block)?;
    }

    /// A padding block occupies the slack exactly: the caller has already
    /// committed those bytes to the sector, so one byte either way is a hole
    /// or an overrun rather than a block it can flush.
    #[test]
    fn a_padding_block_occupies_exactly_the_length_it_was_given(words in 0usize..256) {
        let len = MIN_CUSTOM_BLOCK_LEN + words * 4;
        let slack = 8;
        let mut out = scratch(len + slack);
        prop_assert_eq!(write_padding_block(&mut out, len), Ok(len));
        prop_assert!(
            out.get(len..).expect("the slack").iter().all(|&byte| byte == UNTOUCHED),
        );

        let blocks = read_blocks(out.get(..len).expect("the block")).expect("well-framed");
        prop_assert_eq!(blocks.len(), 1);
        let custom = read_custom_block(blocks.first().expect("one block")).expect("a Custom Block");
        prop_assert_eq!(custom.pen, UNREGISTERED_PEN);
        prop_assert_eq!(custom.data.len(), len - MIN_CUSTOM_BLOCK_LEN);
        prop_assert!(custom.data.iter().all(|&byte| byte == 0));
    }

    /// Arbitrary input is answered, never crashed — including the shapes the
    /// encoder must refuse.
    #[test]
    fn arbitrary_input_never_panics_the_encoder(
        packet in any_packet(),
        original_len in any::<u32>(),
        capacity in 0usize..512,
    ) {
        let mut epb = packet.borrow();
        epb.original_len = original_len;
        let mut out = scratch(capacity);

        let predicted = enhanced_packet_len(&epb);
        let written = write_enhanced_packet(&mut out, &epb);
        match (predicted, written) {
            (Ok(predicted), Ok(written)) => prop_assert_eq!(predicted, written),
            (Ok(predicted), Err(EncodeError::OutOfSpace { needed, capacity: got })) => {
                prop_assert_eq!(needed, predicted);
                prop_assert_eq!(got, capacity);
            }
            (Err(refused), Err(also)) => prop_assert_eq!(refused, also),
            (predicted, written) => prop_assert!(
                false,
                "measuring said {:?} and writing said {:?}",
                predicted,
                written,
            ),
        }
    }

    /// Every buffer smaller than the block is refused identically, and none of
    /// them is written into: a caller may try, fail, flush, and retry.
    #[test]
    fn a_short_buffer_is_refused_without_a_partial_write(packet in any_packet()) {
        let epb = packet.borrow();
        let needed = enhanced_packet_len(&epb).expect("the strategy stays encodable");

        for capacity in [0, 1, needed / 2, needed - 1] {
            let mut out = scratch(capacity);
            prop_assert_eq!(
                write_enhanced_packet(&mut out, &epb),
                Err(EncodeError::OutOfSpace { needed, capacity }),
            );
            prop_assert!(out.iter().all(|&byte| byte == UNTOUCHED));
        }
    }

    /// A buffer larger than the block keeps everything past the block as it
    /// was, so a caller may write into the middle of a ring it is reusing.
    #[test]
    fn a_write_touches_nothing_beyond_the_block(packet in any_packet()) {
        let epb = packet.borrow();
        let needed = enhanced_packet_len(&epb).expect("the strategy stays encodable");
        let slack = 64;
        let mut out = scratch(needed + slack);

        prop_assert_eq!(write_enhanced_packet(&mut out, &epb), Ok(needed));
        prop_assert!(
            out.get(needed..).expect("the slack").iter().all(|&byte| byte == UNTOUCHED),
        );
    }

    /// A stream of packets survives a genuine parse: every field the encoder
    /// was given comes back out of the bytes, read by something that shares no
    /// code with the encoder.
    ///
    /// A padding block sits behind every packet, because the property that
    /// matters about the filler is that it is not there: a reader walking the
    /// block lengths must recover the same packets, in the same order, out of
    /// a stream the padding runs all the way through.
    #[test]
    fn a_stream_of_packets_round_trips_through_an_independent_reader(
        packets in prop::collection::vec((any_packet(), 0usize..8), 1..6),
    ) {
        let borrowed: Vec<(EnhancedPacket<'_>, usize)> = packets
            .iter()
            .map(|(packet, words)| (packet.borrow(), MIN_CUSTOM_BLOCK_LEN + words * 4))
            .collect();
        let total: usize = borrowed
            .iter()
            .map(|(epb, slack)| {
                enhanced_packet_len(epb).expect("the strategy stays encodable") + slack
            })
            .sum();

        let mut stream = scratch(total);
        let mut at = 0;
        for (epb, slack) in &borrowed {
            let room = stream.get_mut(at..).expect("the total was measured");
            at += write_enhanced_packet(room, epb).expect("the total was measured");
            let room = stream.get_mut(at..).expect("the total was measured");
            at += write_padding_block(room, *slack).expect("the total was measured");
        }
        prop_assert_eq!(at, total);

        let blocks = read_blocks(&stream).expect("the encoder frames every block");
        prop_assert_eq!(blocks.len(), borrowed.len() * 2);

        // What a conforming reader does with a block type it does not handle:
        // check its framing, take nothing from it, and carry on.
        let mut packets_read = Vec::new();
        for block in &blocks {
            match read_custom_block(block) {
                Some(custom) => {
                    prop_assert_eq!(custom.pen, UNREGISTERED_PEN);
                    prop_assert!(custom.data.iter().all(|&byte| byte == 0));
                }
                None => packets_read.push(
                    read_enhanced_packet(block).expect("an Enhanced Packet Block"),
                ),
            }
        }
        prop_assert_eq!(packets_read.len(), borrowed.len());

        for (read, (epb, _)) in packets_read.iter().zip(&borrowed) {
            prop_assert_eq!(read.interface_id, epb.interface_id);
            prop_assert_eq!(read.timestamp, epb.timestamp);
            prop_assert_eq!(read.captured, epb.captured);
            prop_assert_eq!(read.original_len, epb.original_len);

            let mut expected: Vec<(u16, Vec<u8>)> = Vec::new();
            if let Some(comment) = epb.comment {
                expected.push((OPT_COMMENT, comment.as_bytes().to_vec()));
            }
            if let Some(flags) = epb.flags {
                expected.push((EPB_FLAGS, flags.to_le_bytes().to_vec()));
            }
            if let Some(count) = epb.drop_count {
                expected.push((EPB_DROPCOUNT, count.to_le_bytes().to_vec()));
            }
            if let Some(id) = epb.packet_id {
                expected.push((EPB_PACKETID, id.to_le_bytes().to_vec()));
            }
            if let Some(queue) = epb.queue {
                expected.push((EPB_QUEUE, queue.to_le_bytes().to_vec()));
            }
            if let Some(verdict) = epb.verdict {
                let mut value = vec![verdict.kind.0];
                value.extend_from_slice(verdict.data);
                expected.push((EPB_VERDICT, value));
            }
            if let Some(custom) = epb.custom {
                let mut value = custom.pen.to_le_bytes().to_vec();
                value.extend_from_slice(custom.data);
                expected.push((CUSTOM_BINARY_COPYABLE, value));
            }

            let found: Vec<(u16, Vec<u8>)> = read
                .options
                .iter()
                .map(|option| (option.code, option.value.to_vec()))
                .collect();
            prop_assert_eq!(found, expected);
        }
    }

    /// An interface's timestamp resolution reaches the file intact, because a
    /// reader that has the wrong one renders plausible times that are wrong.
    #[test]
    fn an_interface_reports_the_resolution_it_was_built_with(digits in 0u8..=0x7F) {
        let idb = InterfaceDescription {
            timestamp_resolution: TimestampResolution::from_decimal_digits(digits)
                .expect("inside the decimal form"),
            ..ethernet_interface()
        };
        let bytes = check_block(&idb, interface_description_len, write_interface_description)?;
        let blocks = read_blocks(&bytes).expect("well-framed");
        let options = read_options(
            blocks
                .first()
                .expect("one block")
                .body
                .get(INTERFACE_DESCRIPTION_BODY_LEN..)
                .expect("an option area"),
        )
        .expect("well-formed options");

        let value = [digits];
        prop_assert_eq!(
            options,
            vec![ReadOption { code: IF_TSRESOL, value: &value }],
        );
        prop_assert!(digits & 0x80 == 0, "the power-of-two form must be unreachable");
    }

    /// Padding is written, never left: a block carries no byte of whatever the
    /// ring held before it.
    #[test]
    fn padding_is_always_zero(captured in prop::collection::vec(any::<u8>(), 0..64)) {
        let epb = bare_packet(&captured);
        let needed = enhanced_packet_len(&epb).expect("encodable");
        let mut out = scratch(needed);
        prop_assert_eq!(write_enhanced_packet(&mut out, &epb), Ok(needed));

        let data_end = 8 + ENHANCED_PACKET_BODY_LEN + captured.len();
        let padding = out
            .get(data_end..data_end + padding_for(captured.len()))
            .expect("the padding is inside the block");
        prop_assert!(padding.iter().all(|&byte| byte == 0));
    }
}
