//! The framing held to the wire it describes, from both ends.
//!
//! Three kinds of claim, and the order below is the order they matter in.
//!
//! * **The bytes are the bytes.** A frame's header and payload are written out
//!   here as literal numbers, so a field that moved, a length that became
//!   little-endian or a reserved byte that stopped being zero fails against a
//!   transcript rather than against a second copy of the encoder.
//! * **Every frame round-trips**, in the direction it travels, through a decoder
//!   fed one delivery at a time — so a frame that encodes and cannot be read
//!   back, or reads back as something else, fails.
//! * **Every rule has a refusal and every refusal has a test.** One adversarial
//!   shape per variant of `Violation`, composed byte by byte, plus one per
//!   variant of `EncodeRefusal`.
//!
//! The decoder's buffer is a megabyte, so every test that needs one takes it off
//! a heap rather than a stack — `held()` below is that, and it is the only reason
//! this module allocates.

use proptest::prelude::*;

use crate::{
    APPLIANCE_HELLO_LEN, Decoded, EncodeRefusal, Frame, FrameDecoder, FrameType, HEADER_LEN, Hello,
    MAX_DOCUMENT_BYTES, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, RangeStatus, Ring, SERVER_HELLO_LEN, Side,
    VERSION, Violation, encode, encoded_len,
};

/// A decoder's reassembly buffer, on the heap.
///
/// A megabyte is past what a spawned test thread's stack can be relied on to
/// hold, and the borrowed buffer is exactly what lets a caller decide that.
fn held() -> Box<[u8; MAX_FRAME_LEN]> {
    vec![0_u8; MAX_FRAME_LEN]
        .into_boxed_slice()
        .try_into()
        .expect("a run of exactly one frame's worth")
}

/// Encode `frame` as `sender` into a fresh buffer.
fn encoded(sender: Side, frame: &Frame<'_>) -> Vec<u8> {
    let mut out = vec![0_u8; encoded_len(frame)];
    let len = encode(sender, frame, &mut out).expect("a frame this end may send");
    assert_eq!(len, out.len(), "the length written is the length counted");
    out
}

/// The greeting each end opens with.
fn hello(sender: Side) -> Frame<'static> {
    match sender {
        Side::Appliance => Frame::Hello(Hello::Appliance),
        Side::Server => Frame::Hello(Hello::Server { log: 0, capture: 0 }),
    }
}

/// Drive a decoder for `sender` over `stream`, delivering `chunk` bytes at a
/// time, and collect what it produced.
///
/// The chunking is the point: a frame arrives in as many pieces as the record
/// layer under it produces, so a decoder that only worked on whole frames would
/// pass a test that handed it whole frames.
fn drive(sender: Side, stream: &[u8], chunk: usize) -> (Vec<FrameType>, Option<Violation>) {
    let mut buffer = held();
    let mut decoder = FrameDecoder::new(sender, &mut buffer);
    let mut frames = Vec::new();
    let mut at = 0_usize;
    loop {
        let end = at.saturating_add(chunk.max(1)).min(stream.len());
        let delivery = stream.get(at..end).unwrap_or_default();
        let took = decoder.absorb(delivery);
        at = at.saturating_add(took);
        match decoder.next_frame() {
            Decoded::Partial => {
                if at >= stream.len() && took == 0 {
                    return (frames, None);
                }
            }
            Decoded::Frame(frame) => frames.push(frame.frame_type()),
            Decoded::Violated(violation) => return (frames, Some(violation)),
        }
    }
}

/// The stream a well-behaved `sender` puts on the wire: its greeting, then
/// `frames`.
fn stream(sender: Side, frames: &[Frame<'_>]) -> Vec<u8> {
    let mut bytes = encoded(sender, &hello(sender));
    for frame in frames {
        bytes.extend_from_slice(&encoded(sender, frame));
    }
    bytes
}

/// Decode exactly one frame out of `stream` after the greeting, byte by byte.
///
/// One byte at a time deliberately: every field of every frame is therefore
/// assembled across deliveries at least once in this suite.
fn one_frame_after_hello<T>(
    sender: Side,
    frame: &Frame<'_>,
    with: impl FnOnce(Frame<'_>) -> T,
) -> T {
    let bytes = stream(sender, core::slice::from_ref(frame));
    let mut buffer = held();
    let mut decoder = FrameDecoder::new(sender, &mut buffer);
    let mut at = 0_usize;
    let mut seen = 0;
    loop {
        let end = at.saturating_add(1).min(bytes.len());
        let took = decoder.absorb(bytes.get(at..end).unwrap_or_default());
        at = at.saturating_add(took);
        match decoder.next_frame() {
            Decoded::Partial => assert!(at < bytes.len(), "the stream ran out mid-frame"),
            Decoded::Frame(decoded) => {
                seen += 1;
                if seen == 2 {
                    return with(decoded);
                }
            }
            Decoded::Violated(violation) => {
                panic!("a well-formed stream was refused: {violation:?}")
            }
        }
    }
}

/// What a decoder for `sender` makes of `bytes`, which is expected to end in a
/// refusal.
///
/// Frames before it are the greeting and whatever else the shape under test needs
/// in front of it; the refusal is the answer this returns.
fn refusal(sender: Side, bytes: &[u8]) -> Violation {
    let mut buffer = held();
    let mut decoder = FrameDecoder::new(sender, &mut buffer);
    let mut at = 0_usize;
    loop {
        let end = at.saturating_add(64).min(bytes.len());
        let took = decoder.absorb(bytes.get(at..end).unwrap_or_default());
        at = at.saturating_add(took);
        match decoder.next_frame() {
            Decoded::Partial => {
                assert!(
                    at < bytes.len() || took > 0,
                    "these bytes were not refused at all"
                );
            }
            Decoded::Frame(_) => {}
            Decoded::Violated(violation) => {
                // A violation is final: the decoder answers it and nothing else,
                // whatever arrives afterwards.
                assert_eq!(decoder.violation(), Some(violation));
                assert_eq!(
                    decoder.absorb(&[0; 32]),
                    0,
                    "a dead decoder took more bytes"
                );
                assert_eq!(decoder.next_frame(), Decoded::Violated(violation));
                return violation;
            }
        }
    }
}

/// A header with a stated length, a type byte and the three reserved bytes as
/// given, for composing shapes an encoder will not produce.
fn header(len: u32, kind: u8, reserved: [u8; 3]) -> Vec<u8> {
    let [a, b, c, d] = len.to_be_bytes();
    let [r0, r1, r2] = reserved;
    vec![a, b, c, d, kind, r0, r1, r2]
}

/// A frame composed out of a header and a payload, bypassing the encoder.
fn raw(kind: FrameType, payload: &[u8]) -> Vec<u8> {
    let mut bytes = header(
        u32::try_from(payload.len()).expect("a test payload inside a u32"),
        kind.to_byte(),
        [0; 3],
    );
    bytes.extend_from_slice(payload);
    bytes
}

// ---------------------------------------------------------------------------
// The bytes on the wire
// ---------------------------------------------------------------------------

#[test]
fn the_header_is_eight_bytes_a_big_endian_length_a_type_and_three_zeros() {
    // An ACK's payload is two cursors, so its header states 16 and its bytes are
    // the two `u64`s most significant byte first.
    let bytes = encoded(
        Side::Server,
        &Frame::Ack {
            log: 0x0102_0304_0506_0708,
            capture: 0x1112_1314_1516_1718,
        },
    );
    assert_eq!(
        bytes,
        vec![
            // payload length, big-endian
            0x00, 0x00, 0x00, 0x10, // type
            0x04, // reserved
            0x00, 0x00, 0x00, // log cursor
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // capture cursor
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ]
    );
}

#[test]
fn the_two_greetings_carry_the_version_and_the_servers_two_cursors() {
    assert_eq!(
        encoded(Side::Appliance, &Frame::Hello(Hello::Appliance)),
        vec![0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01]
    );
    assert_eq!(
        encoded(
            Side::Server,
            &Frame::Hello(Hello::Server {
                log: 0x2a,
                capture: 0xff_ff,
            })
        ),
        vec![
            0x00, 0x00, 0x00, 0x12, 0x01, 0x00, 0x00, 0x00, //
            0x00, 0x01, // version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, // log
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, // capture
        ]
    );
    assert_eq!(APPLIANCE_HELLO_LEN, 2);
    assert_eq!(SERVER_HELLO_LEN, 18);
    assert_eq!(VERSION, 1);
}

#[test]
fn the_ring_selector_is_zero_for_the_log_ring_and_one_for_the_capture_ring() {
    assert_eq!(Ring::Log.to_byte(), 0);
    assert_eq!(Ring::Capture.to_byte(), 1);
    assert_eq!(Ring::from_byte(0), Some(Ring::Log));
    assert_eq!(Ring::from_byte(1), Some(Ring::Capture));
    assert_eq!(Ring::from_byte(2), None);
    let bytes = encoded(
        Side::Server,
        &Frame::DownRangeRead {
            ring: Ring::Capture,
            start: 1,
            length: 2,
        },
    );
    assert_eq!(bytes.get(HEADER_LEN), Some(&1_u8));
}

#[test]
fn the_range_status_is_zero_for_data_one_for_overwritten_and_two_for_refused() {
    assert_eq!(RangeStatus::Data.to_byte(), 0);
    assert_eq!(RangeStatus::Overwritten.to_byte(), 1);
    assert_eq!(RangeStatus::MediumRefused.to_byte(), 2);
    assert_eq!(RangeStatus::from_byte(3), None);
    assert!(!RangeStatus::Data.ends_the_answer());
    assert!(RangeStatus::Overwritten.ends_the_answer());
    assert!(RangeStatus::MediumRefused.ends_the_answer());
}

#[test]
fn the_type_bytes_are_one_through_ten_and_nothing_else_decodes() {
    for (at, frame) in FrameType::ALL.into_iter().enumerate() {
        let byte = u8::try_from(at + 1).expect("ten frames");
        assert_eq!(frame.to_byte(), byte);
        assert_eq!(FrameType::from_byte(byte), Some(frame));
    }
    assert_eq!(FrameType::from_byte(0), None);
    assert_eq!(FrameType::from_byte(0x0B), None);
    assert_eq!(FrameType::from_byte(0xFF), None);
}

#[test]
fn the_directions_are_the_protocols() {
    for frame in FrameType::ALL {
        let appliance = frame.may_travel_from(Side::Appliance);
        let server = frame.may_travel_from(Side::Server);
        let expected = match frame {
            FrameType::Hello => (true, true),
            FrameType::UpRecords
            | FrameType::UpCapture
            | FrameType::UpConfigValidateResult
            | FrameType::UpRangeData => (true, false),
            FrameType::Ack
            | FrameType::DownConfigStage
            | FrameType::DownConfigCommit
            | FrameType::DownCommitConfirm
            | FrameType::DownRangeRead => (false, true),
        };
        assert_eq!((appliance, server), expected, "{frame:?}");
    }
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

#[test]
fn every_frame_round_trips_in_the_direction_it_travels() {
    let ring_bytes = [0xAA_u8; 300];
    let document = [b'<'; 64];
    let appliance: Vec<Frame<'_>> = vec![
        Frame::Hello(Hello::Appliance),
        Frame::UpRecords {
            position: 0x1234_5678_9ABC_DEF0,
            bytes: &ring_bytes,
        },
        Frame::UpCapture {
            position: u64::MAX,
            bytes: &[],
        },
        Frame::UpConfigValidateResult {
            line: b"generation=7 outcome=accepted",
        },
        Frame::UpRangeData {
            ring: Ring::Capture,
            status: RangeStatus::Data,
            position: 4096,
            bytes: &ring_bytes,
        },
        Frame::UpRangeData {
            ring: Ring::Log,
            status: RangeStatus::Overwritten,
            position: 0,
            bytes: &[],
        },
        Frame::UpRangeData {
            ring: Ring::Log,
            status: RangeStatus::MediumRefused,
            position: 9,
            bytes: &[],
        },
    ];
    let server: Vec<Frame<'_>> = vec![
        Frame::Hello(Hello::Server { log: 1, capture: 2 }),
        Frame::Ack {
            log: u64::MAX,
            capture: 0,
        },
        Frame::DownConfigStage {
            document: &document,
        },
        Frame::DownConfigCommit {
            generation: 42,
            confirm_deadline_secs: 300,
        },
        Frame::DownCommitConfirm { generation: 42 },
        Frame::DownRangeRead {
            ring: Ring::Capture,
            start: 1 << 40,
            length: 1 << 20,
        },
    ];

    // Every frame type appears in one of the two lists, so this suite covers the
    // protocol rather than a subset of it.
    let mut covered: Vec<FrameType> = appliance
        .iter()
        .chain(&server)
        .map(Frame::frame_type)
        .collect();
    covered.sort_unstable_by_key(|frame| frame.to_byte());
    covered.dedup();
    assert_eq!(covered, FrameType::ALL.to_vec());

    for (sender, frames) in [(Side::Appliance, appliance), (Side::Server, server)] {
        for frame in &frames {
            // Delivered a byte at a time, so every field crosses a delivery
            // boundary.
            let read = one_frame_after_hello(sender, frame, |decoded| {
                assert_eq!(decoded.frame_type(), frame.frame_type());
                // Compared field by field rather than by rendering, so a
                // failure names the frame and not a megabyte of payload.
                assert_eq!(&decoded, frame, "{:?}", frame.frame_type());
                true
            });
            assert!(read);
        }
        // And the whole stream at once, in order. The greeting heads each list,
        // and `stream` puts one in front of what it is given, so what follows it
        // here is the rest of the list.
        let rest = frames.get(1..).unwrap_or_default();
        let bytes = stream(sender, rest);
        let (seen, violation) = drive(sender, &bytes, 4096);
        assert_eq!(violation, None);
        let expected: Vec<FrameType> = core::iter::once(FrameType::Hello)
            .chain(rest.iter().map(Frame::frame_type))
            .collect();
        assert_eq!(seen, expected);
    }
}

#[test]
fn a_maximal_frame_is_reassembled_out_of_record_sized_deliveries() {
    // One byte short of the bound once the position is counted: the largest
    // upstream frame there is.
    let ring_bytes = vec![0x5A_u8; MAX_PAYLOAD_LEN - 8];
    let frame = Frame::UpRecords {
        position: 1 << 33,
        bytes: &ring_bytes,
    };
    assert_eq!(encoded_len(&frame), MAX_FRAME_LEN);
    let bytes = stream(Side::Appliance, core::slice::from_ref(&frame));

    let mut buffer = held();
    let mut decoder = FrameDecoder::new(Side::Appliance, &mut buffer);
    let mut at = 0_usize;
    let mut seen = 0;
    let mut deliveries = 0;
    loop {
        // A little over a maximal TLS record, which is the shape the layer below
        // hands over.
        let end = at.saturating_add(16_384).min(bytes.len());
        let took = decoder.absorb(bytes.get(at..end).unwrap_or_default());
        at = at.saturating_add(took);
        deliveries += 1;
        assert!(
            decoder.held() <= MAX_FRAME_LEN,
            "the decoder held more than one frame's worth"
        );
        match decoder.next_frame() {
            Decoded::Partial => assert!(at < bytes.len(), "the stream ran out mid-frame"),
            Decoded::Frame(decoded) => {
                seen += 1;
                if seen == 2 {
                    assert_eq!(decoded, frame);
                    break;
                }
            }
            Decoded::Violated(violation) => panic!("refused: {violation:?}"),
        }
        assert!(deliveries < 1024, "the loop is not making progress");
    }
    assert!(deliveries > 60, "a megabyte arrived in {deliveries} pieces");
}

#[test]
fn absorb_stops_at_a_frame_boundary_so_the_buffer_holds_one_frame() {
    let frames = [
        Frame::Ack { log: 1, capture: 2 },
        Frame::DownCommitConfirm { generation: 3 },
    ];
    let bytes = stream(Side::Server, &frames);
    let mut buffer = held();
    let mut decoder = FrameDecoder::new(Side::Server, &mut buffer);
    // The whole stream offered at once: the decoder takes the greeting and stops.
    let took = decoder.absorb(&bytes);
    assert_eq!(took, HEADER_LEN + SERVER_HELLO_LEN);
    assert_eq!(decoder.held(), took);
    // Offering more while a whole frame is waiting takes nothing.
    assert_eq!(decoder.absorb(bytes.get(took..).unwrap_or_default()), 0);
    assert!(matches!(decoder.next_frame(), Decoded::Frame(_)));
    assert!(decoder.greeted());
    // A frame handed out is still held: it is borrowed out of the buffer, so it
    // cannot be dropped until the caller is done with it. The next call is when
    // that happens, and it empties the buffer rather than moving anything down
    // it — the next frame's bytes are still with the caller.
    assert_eq!(decoder.held(), took);
    let next = decoder.absorb(bytes.get(took..).unwrap_or_default());
    assert_eq!(
        next,
        HEADER_LEN + 16,
        "the ACK, and not a byte of what follows"
    );
    assert_eq!(decoder.held(), next);
}

#[test]
fn a_greeting_is_owed_before_anything_else_and_the_flag_says_when_it_arrived() {
    let mut buffer = held();
    let mut decoder = FrameDecoder::new(Side::Server, &mut buffer);
    assert!(!decoder.greeted());
    let bytes = encoded(Side::Server, &hello(Side::Server));
    // One call takes the whole frame: the header first, then the payload its
    // length names.
    assert_eq!(decoder.absorb(&bytes), bytes.len());
    assert!(!decoder.greeted(), "nothing has been decoded yet");
    assert_eq!(
        decoder.next_frame(),
        Decoded::Frame(Frame::Hello(Hello::Server { log: 0, capture: 0 }))
    );
    assert!(decoder.greeted());
}

#[test]
fn a_second_greeting_decodes_because_the_protocol_binds_only_the_first_frame() {
    // The rule is that the *first* frame is the greeting; a later one is not a
    // violation this protocol names, so it is decoded and what to do with it is
    // the session's above. Recorded as a test because it is a deliberate
    // non-decision rather than an oversight.
    let bytes = stream(Side::Server, &[hello(Side::Server)]);
    let (seen, violation) = drive(Side::Server, &bytes, 7);
    assert_eq!(violation, None);
    assert_eq!(seen, vec![FrameType::Hello, FrameType::Hello]);
}

#[test]
fn an_empty_delivery_takes_nothing_and_produces_nothing() {
    let mut buffer = held();
    let mut decoder = FrameDecoder::new(Side::Server, &mut buffer);
    assert_eq!(decoder.absorb(&[]), 0);
    assert_eq!(decoder.next_frame(), Decoded::Partial);
    assert_eq!(decoder.violation(), None);
}

// ---------------------------------------------------------------------------
// Every rule broken
// ---------------------------------------------------------------------------

#[test]
fn a_nonzero_reserved_byte_is_refused_wherever_it_sits() {
    for at in 0..3_usize {
        let mut reserved = [0_u8; 3];
        if let Some(slot) = reserved.get_mut(at) {
            *slot = 0x99;
        }
        let mut bytes = header(
            SERVER_HELLO_LEN as u32,
            FrameType::Hello.to_byte(),
            reserved,
        );
        bytes.extend_from_slice(&[0; SERVER_HELLO_LEN]);
        assert_eq!(
            refusal(Side::Server, &bytes),
            Violation::ReservedNonZero {
                at: u8::try_from(at).expect("three reserved bytes"),
                byte: 0x99
            }
        );
    }
}

#[test]
fn a_type_byte_naming_no_frame_is_refused() {
    for byte in [0x00_u8, 0x0B, 0x7F, 0xFF] {
        let bytes = header(0, byte, [0; 3]);
        assert_eq!(
            refusal(Side::Server, &bytes),
            Violation::UnknownType { byte }
        );
    }
}

#[test]
fn a_length_past_the_bound_is_refused_before_a_byte_behind_it_is_held() {
    let stated = u32::try_from(MAX_PAYLOAD_LEN + 1).expect("the bound plus one inside a u32");
    let bytes = header(stated, FrameType::UpRecords.to_byte(), [0; 3]);
    let mut buffer = held();
    let mut decoder = FrameDecoder::new(Side::Appliance, &mut buffer);
    assert_eq!(decoder.absorb(&bytes), HEADER_LEN);
    // The bound is refused off the header alone, and nothing behind it is taken:
    // a peer cannot make this end buffer on a length it has already lost the
    // connection over.
    assert_eq!(decoder.absorb(&[0xFF; 4096]), 0);
    assert_eq!(decoder.held(), HEADER_LEN);
    assert_eq!(
        decoder.next_frame(),
        Decoded::Violated(Violation::PayloadTooLong { stated })
    );
    // And at the extreme the field can state.
    let bytes = header(u32::MAX, FrameType::UpRecords.to_byte(), [0; 3]);
    assert_eq!(
        refusal(Side::Appliance, &bytes),
        Violation::PayloadTooLong { stated: u32::MAX }
    );
}

#[test]
fn a_length_exactly_at_the_bound_is_not_refused() {
    let stated = u32::try_from(MAX_PAYLOAD_LEN).expect("the bound inside a u32");
    let mut bytes = stream(Side::Appliance, &[]);
    bytes.extend_from_slice(&header(stated, FrameType::UpRecords.to_byte(), [0; 3]));
    bytes.extend_from_slice(&vec![0_u8; MAX_PAYLOAD_LEN]);
    let mut buffer = held();
    let mut decoder = FrameDecoder::new(Side::Appliance, &mut buffer);
    let mut at = 0_usize;
    let mut seen = 0;
    loop {
        let end = at.saturating_add(64 * 1024).min(bytes.len());
        at = at.saturating_add(decoder.absorb(bytes.get(at..end).unwrap_or_default()));
        match decoder.next_frame() {
            Decoded::Partial => assert!(at < bytes.len(), "the stream ran out mid-frame"),
            Decoded::Frame(frame) => {
                seen += 1;
                if seen == 2 {
                    assert_eq!(frame.frame_type(), FrameType::UpRecords);
                    // A whole frame at the bound was held, which is the largest
                    // the buffer is ever asked for.
                    assert_eq!(decoder.held(), MAX_FRAME_LEN);
                    return;
                }
            }
            Decoded::Violated(violation) => panic!("refused: {violation:?}"),
        }
    }
}

#[test]
fn a_frame_from_the_wrong_end_is_refused_in_both_directions() {
    // A server sending what only an appliance sends.
    let bytes = raw(FrameType::UpRecords, &[0; 8]);
    assert_eq!(
        refusal(Side::Server, &bytes),
        Violation::WrongDirection {
            frame: FrameType::UpRecords,
            sender: Side::Server
        }
    );
    // And an appliance sending what only a server sends.
    let bytes = raw(FrameType::DownConfigCommit, &[0; 10]);
    assert_eq!(
        refusal(Side::Appliance, &bytes),
        Violation::WrongDirection {
            frame: FrameType::DownConfigCommit,
            sender: Side::Appliance
        }
    );
    // The direction is judged before the greeting rule, so a wrong-direction
    // first frame is reported as the wrong direction: it is the more specific
    // fact, and the frame could not have been a greeting either way.
    let bytes = raw(FrameType::Ack, &[0; 16]);
    assert_eq!(
        refusal(Side::Appliance, &bytes),
        Violation::WrongDirection {
            frame: FrameType::Ack,
            sender: Side::Appliance
        }
    );
}

#[test]
fn a_first_frame_that_is_not_the_greeting_is_refused() {
    for frame in [FrameType::Ack, FrameType::DownCommitConfirm] {
        let bytes = raw(frame, &[0; 16]);
        assert_eq!(
            refusal(Side::Server, &bytes),
            Violation::FirstFrameNotHello { frame }
        );
    }
}

#[test]
fn a_greeting_naming_another_version_is_refused_whatever_shape_it_has() {
    for theirs in [0_u16, 2, 0xFFFF] {
        let mut payload = theirs.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0; 16]);
        assert_eq!(
            refusal(Side::Server, &raw(FrameType::Hello, &payload)),
            Violation::VersionMismatch { theirs }
        );
        // Read before the shape is judged, so a greeting of the wrong version
        // *and* the wrong length still names the version.
        assert_eq!(
            refusal(Side::Server, &raw(FrameType::Hello, &theirs.to_be_bytes())),
            Violation::VersionMismatch { theirs }
        );
    }
}

#[test]
fn a_payload_that_is_not_the_frames_shape_is_refused_short_or_long() {
    // Short of the fields it needs.
    let cases: &[(Side, FrameType, usize, usize)] = &[
        (Side::Server, FrameType::Ack, 15, 16),
        (Side::Server, FrameType::DownConfigCommit, 9, 10),
        (Side::Server, FrameType::DownCommitConfirm, 7, 8),
        (Side::Appliance, FrameType::UpRecords, 7, 8),
        (Side::Appliance, FrameType::UpCapture, 0, 8),
        (Side::Appliance, FrameType::UpRangeData, 9, 10),
    ];
    for (sender, frame, len, needed) in cases.iter().copied() {
        let mut bytes = stream(sender, &[]);
        bytes.extend_from_slice(&raw(frame, &vec![0_u8; len]));
        assert_eq!(
            refusal(sender, &bytes),
            Violation::PayloadLength { frame, len, needed },
            "{frame:?} with {len} bytes"
        );
    }
    // And with trailing bytes, for the frames that have nothing variable in
    // them: a peer that could append to a fixed frame would have somewhere to
    // put bytes this end reads past.
    let trailing: &[(Side, FrameType, usize, usize)] = &[
        (Side::Server, FrameType::Ack, 17, 16),
        (Side::Server, FrameType::DownConfigCommit, 11, 10),
        (Side::Server, FrameType::DownCommitConfirm, 9, 8),
        (Side::Server, FrameType::DownRangeRead, 18, 17),
        (Side::Server, FrameType::Hello, 19, 18),
        (Side::Appliance, FrameType::Hello, 3, 2),
    ];
    for (sender, frame, len, needed) in trailing.iter().copied() {
        let mut payload = vec![0_u8; len];
        if frame == FrameType::Hello {
            // A greeting's version is read first, so it has to be the one this
            // end speaks for the length to be what is judged.
            let [high, low] = VERSION.to_be_bytes();
            if let Some(slot) = payload.get_mut(..2) {
                slot.copy_from_slice(&[high, low]);
            }
        }
        let mut bytes = if frame == FrameType::Hello {
            Vec::new()
        } else {
            stream(sender, &[])
        };
        bytes.extend_from_slice(&raw(frame, &payload));
        assert_eq!(
            refusal(sender, &bytes),
            Violation::PayloadLength { frame, len, needed },
            "{frame:?} with {len} bytes"
        );
    }
}

#[test]
fn a_ring_selector_naming_neither_ring_is_refused_in_both_frames_that_carry_one() {
    for byte in [2_u8, 0x80, 0xFF] {
        let mut bytes = stream(Side::Server, &[]);
        let mut payload = vec![byte];
        payload.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&raw(FrameType::DownRangeRead, &payload));
        assert_eq!(
            refusal(Side::Server, &bytes),
            Violation::UnknownRing { byte }
        );

        let mut bytes = stream(Side::Appliance, &[]);
        let mut payload = vec![byte, 0];
        payload.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&raw(FrameType::UpRangeData, &payload));
        assert_eq!(
            refusal(Side::Appliance, &bytes),
            Violation::UnknownRing { byte }
        );
    }
}

#[test]
fn a_range_status_naming_no_status_is_refused() {
    for byte in [3_u8, 0x0A, 0xFF] {
        let mut bytes = stream(Side::Appliance, &[]);
        let mut payload = vec![Ring::Log.to_byte(), byte];
        payload.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&raw(FrameType::UpRangeData, &payload));
        assert_eq!(
            refusal(Side::Appliance, &bytes),
            Violation::UnknownRangeStatus { byte }
        );
    }
}

#[test]
fn a_range_answer_that_ends_the_answer_and_carries_bytes_is_refused() {
    for status in [RangeStatus::Overwritten, RangeStatus::MediumRefused] {
        let mut bytes = stream(Side::Appliance, &[]);
        let mut payload = vec![Ring::Capture.to_byte(), status.to_byte()];
        payload.extend_from_slice(&[0; 8]);
        payload.extend_from_slice(&[0xAB; 5]);
        bytes.extend_from_slice(&raw(FrameType::UpRangeData, &payload));
        assert_eq!(
            refusal(Side::Appliance, &bytes),
            Violation::BytesOnEndedRange { status, len: 5 }
        );
    }
}

#[test]
fn a_staged_document_past_its_own_bound_is_refused_as_a_document_and_not_as_a_frame() {
    // Off the header alone, and that is the point: a peer stating a mebibyte of
    // document must not make this end hold one, so the refusal comes before a
    // byte behind the header is taken.
    let stated = u32::try_from(MAX_DOCUMENT_BYTES + 1).expect("the bound plus one inside a u32");
    let mut bytes = stream(Side::Server, &[]);
    bytes.extend_from_slice(&header(
        stated,
        FrameType::DownConfigStage.to_byte(),
        [0; 3],
    ));
    let mut buffer = held();
    let mut decoder = FrameDecoder::new(Side::Server, &mut buffer);
    let mut at = 0_usize;
    while at < bytes.len() {
        let took = decoder.absorb(bytes.get(at..).unwrap_or_default());
        at = at.saturating_add(took);
        if took == 0 {
            assert!(matches!(decoder.next_frame(), Decoded::Frame(_)));
        }
    }
    assert_eq!(decoder.absorb(&[b' '; 4096]), 0);
    assert_eq!(decoder.held(), HEADER_LEN);
    assert_eq!(
        decoder.next_frame(),
        Decoded::Violated(Violation::ConfigDocumentTooLong {
            len: MAX_DOCUMENT_BYTES + 1
        })
    );
    // And a payload past the frame bound on the same frame is the frame's bound
    // rather than the document's: an operator meeting the one is looking at a
    // document somebody composed, and the other at a framing fault.
    let stated = u32::try_from(MAX_PAYLOAD_LEN + 1).expect("the bound plus one inside a u32");
    let mut bytes = stream(Side::Server, &[]);
    bytes.extend_from_slice(&header(
        stated,
        FrameType::DownConfigStage.to_byte(),
        [0; 3],
    ));
    assert_eq!(
        refusal(Side::Server, &bytes),
        Violation::PayloadTooLong { stated }
    );
    // At the bound exactly it is a frame.
    let document = vec![b' '; MAX_DOCUMENT_BYTES];
    let read = one_frame_after_hello(
        Side::Server,
        &Frame::DownConfigStage {
            document: &document,
        },
        |decoded| decoded.frame_type(),
    );
    assert_eq!(read, FrameType::DownConfigStage);
}

#[test]
fn a_result_line_carrying_a_byte_that_is_not_printable_ascii_is_refused() {
    // A newline included: the payload is one line and the frame is what
    // delimits it.
    for (at, byte) in [
        (0_usize, 0x00_u8),
        (7, b'\n'),
        (3, 0x7F),
        (1, 0x80),
        (2, 0xFF),
    ] {
        let mut line = b"generation=1 outcome=accepted".to_vec();
        if let Some(slot) = line.get_mut(at) {
            *slot = byte;
        }
        let mut bytes = stream(Side::Appliance, &[]);
        bytes.extend_from_slice(&raw(FrameType::UpConfigValidateResult, &line));
        assert_eq!(
            refusal(Side::Appliance, &bytes),
            Violation::ResultLineNotPrintable { at, byte }
        );
    }
    // And an empty line is not a line at all, which is a length question.
    let mut bytes = stream(Side::Appliance, &[]);
    bytes.extend_from_slice(&raw(FrameType::UpConfigValidateResult, &[]));
    assert_eq!(
        refusal(Side::Appliance, &bytes),
        Violation::PayloadLength {
            frame: FrameType::UpConfigValidateResult,
            len: 0,
            needed: 1
        }
    );
}

#[test]
fn the_result_lines_printable_range_is_space_through_tilde() {
    let line: Vec<u8> = (0x20_u8..=0x7E).collect();
    let read = one_frame_after_hello(
        Side::Appliance,
        &Frame::UpConfigValidateResult { line: &line },
        |decoded| decoded == Frame::UpConfigValidateResult { line: &line },
    );
    assert!(read);
}

// ---------------------------------------------------------------------------
// The encoder's own refusals
// ---------------------------------------------------------------------------

#[test]
fn a_frame_the_composing_end_may_not_send_is_refused() {
    let mut out = [0_u8; 64];
    assert_eq!(
        encode(
            Side::Appliance,
            &Frame::Ack { log: 0, capture: 0 },
            &mut out
        ),
        Err(EncodeRefusal::WrongDirection {
            frame: FrameType::Ack,
            sender: Side::Appliance
        })
    );
    // The greeting's two shapes are told apart the same way: an appliance has no
    // resume cursors to offer.
    assert_eq!(
        encode(
            Side::Appliance,
            &Frame::Hello(Hello::Server { log: 0, capture: 0 }),
            &mut out
        ),
        Err(EncodeRefusal::WrongDirection {
            frame: FrameType::Hello,
            sender: Side::Appliance
        })
    );
    assert_eq!(
        encode(Side::Server, &Frame::Hello(Hello::Appliance), &mut out),
        Err(EncodeRefusal::WrongDirection {
            frame: FrameType::Hello,
            sender: Side::Server
        })
    );
}

#[test]
fn a_payload_past_the_frame_bound_is_refused_rather_than_written() {
    let bytes = vec![0_u8; MAX_PAYLOAD_LEN];
    let frame = Frame::UpRecords {
        position: 0,
        bytes: &bytes,
    };
    // The position pushes it one word past the bound.
    assert_eq!(encoded_len(&frame), MAX_FRAME_LEN + 8);
    let mut out = vec![0_u8; MAX_FRAME_LEN + 16];
    assert_eq!(
        encode(Side::Appliance, &frame, &mut out),
        Err(EncodeRefusal::PayloadTooLong {
            len: MAX_PAYLOAD_LEN + 8
        })
    );
    // Nothing was written: a refusal leaves the caller's output alone.
    assert!(out.iter().all(|byte| *byte == 0));
}

#[test]
fn an_output_too_small_for_the_frame_is_refused_with_the_length_it_needed() {
    let frame = Frame::Ack { log: 1, capture: 2 };
    let needed = encoded_len(&frame);
    for room in 0..needed {
        let mut out = vec![0_u8; room];
        assert_eq!(
            encode(Side::Server, &frame, &mut out),
            Err(EncodeRefusal::OutputTooSmall { needed, room }),
            "room {room}"
        );
        assert!(out.iter().all(|byte| *byte == 0), "room {room}");
    }
    let mut out = vec![0_u8; needed];
    assert_eq!(encode(Side::Server, &frame, &mut out), Ok(needed));
}

#[test]
fn the_encoder_refuses_the_three_contradictions_the_types_leave_expressible() {
    let mut out = vec![0_u8; MAX_FRAME_LEN];
    let document = vec![b' '; MAX_DOCUMENT_BYTES + 1];
    assert_eq!(
        encode(
            Side::Server,
            &Frame::DownConfigStage {
                document: &document
            },
            &mut out
        ),
        Err(EncodeRefusal::ConfigDocumentTooLong {
            len: MAX_DOCUMENT_BYTES + 1
        })
    );
    assert_eq!(
        encode(
            Side::Appliance,
            &Frame::UpConfigValidateResult { line: &[] },
            &mut out
        ),
        Err(EncodeRefusal::EmptyResultLine)
    );
    assert_eq!(
        encode(
            Side::Appliance,
            &Frame::UpConfigValidateResult {
                line: b"outcome=ok\n"
            },
            &mut out
        ),
        Err(EncodeRefusal::ResultLineNotPrintable {
            at: 10,
            byte: b'\n'
        })
    );
    assert_eq!(
        encode(
            Side::Appliance,
            &Frame::UpRangeData {
                ring: Ring::Log,
                status: RangeStatus::Overwritten,
                position: 0,
                bytes: &[0xAB; 3]
            },
            &mut out
        ),
        Err(EncodeRefusal::BytesOnEndedRange {
            status: RangeStatus::Overwritten,
            len: 3
        })
    );
}

#[test]
fn encoded_len_is_the_length_encode_writes_for_every_frame() {
    let payload = [0x11_u8; 17];
    let frames: &[(Side, Frame<'_>)] = &[
        (Side::Appliance, Frame::Hello(Hello::Appliance)),
        (
            Side::Server,
            Frame::Hello(Hello::Server { log: 5, capture: 6 }),
        ),
        (
            Side::Appliance,
            Frame::UpRecords {
                position: 1,
                bytes: &payload,
            },
        ),
        (
            Side::Appliance,
            Frame::UpCapture {
                position: 2,
                bytes: &payload,
            },
        ),
        (Side::Server, Frame::Ack { log: 3, capture: 4 }),
        (Side::Server, Frame::DownConfigStage { document: &payload }),
        (
            Side::Appliance,
            Frame::UpConfigValidateResult {
                line: b"outcome=ok",
            },
        ),
        (
            Side::Server,
            Frame::DownConfigCommit {
                generation: 9,
                confirm_deadline_secs: 1,
            },
        ),
        (Side::Server, Frame::DownCommitConfirm { generation: 9 }),
        (
            Side::Server,
            Frame::DownRangeRead {
                ring: Ring::Log,
                start: 7,
                length: 8,
            },
        ),
        (
            Side::Appliance,
            Frame::UpRangeData {
                ring: Ring::Log,
                status: RangeStatus::Data,
                position: 11,
                bytes: &payload,
            },
        ),
    ];
    assert_eq!(
        frames.len(),
        11,
        "ten frames and the greeting's second shape"
    );
    for (sender, frame) in frames {
        let mut out = vec![0_u8; MAX_FRAME_LEN];
        let written = encode(*sender, frame, &mut out).expect("a frame this end may send");
        assert_eq!(written, encoded_len(frame), "{:?}", frame.frame_type());
        assert_eq!(written, HEADER_LEN + expected_payload_len(frame));
    }
}

/// The payload length each frame owes, written out rather than taken from the
/// encoder: a length compared against the code that produced it is not compared
/// at all.
fn expected_payload_len(frame: &Frame<'_>) -> usize {
    match frame {
        Frame::Hello(Hello::Appliance) => 2,
        Frame::Hello(Hello::Server { .. }) => 18,
        Frame::UpRecords { bytes, .. } | Frame::UpCapture { bytes, .. } => 8 + bytes.len(),
        Frame::Ack { .. } => 16,
        Frame::DownConfigStage { document } => document.len(),
        Frame::UpConfigValidateResult { line } => line.len(),
        Frame::DownConfigCommit { .. } => 10,
        Frame::DownCommitConfirm { .. } => 8,
        Frame::DownRangeRead { .. } => 17,
        Frame::UpRangeData { bytes, .. } => 10 + bytes.len(),
    }
}

// ---------------------------------------------------------------------------
// Arbitrary input
// ---------------------------------------------------------------------------

proptest! {
    /// Arbitrary bytes, cut arbitrarily, drive the decoder to an answer and
    /// never past its buffer.
    #[test]
    fn arbitrary_bytes_are_decoded_or_refused_and_never_overrun(
        stream in prop::collection::vec(any::<u8>(), 0..4096),
        chunk in 1_usize..512,
        server in any::<bool>(),
    ) {
        let sender = if server { Side::Server } else { Side::Appliance };
        let mut buffer = held();
        let mut decoder = FrameDecoder::new(sender, &mut buffer);
        let mut at = 0_usize;
        let mut steps = 0;
        loop {
            let end = at.saturating_add(chunk).min(stream.len());
            let took = decoder.absorb(stream.get(at..end).unwrap_or_default());
            at = at.saturating_add(took);
            prop_assert!(decoder.held() <= MAX_FRAME_LEN);
            match decoder.next_frame() {
                Decoded::Partial => {
                    if at >= stream.len() && took == 0 {
                        break;
                    }
                }
                Decoded::Frame(_) => {}
                Decoded::Violated(_) => break,
            }
            steps += 1;
            // One step per frame plus one per delivery, so a stream this short
            // cannot need this many: a loop that does not terminate fails here
            // rather than hanging the suite.
            prop_assert!(steps <= 2 * stream.len() + 8, "the loop is not making progress");
        }
        // A refusal, if there was one, is the one the decoder keeps.
        let settled = decoder.violation();
        prop_assert_eq!(decoder.violation(), settled);
    }

    /// Every frame this codec can compose reads back as itself.
    #[test]
    fn an_arbitrary_frame_round_trips(
        which in 0_usize..11,
        a in any::<u64>(),
        b in any::<u64>(),
        deadline in any::<u16>(),
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
        line in "[ -~]{1,64}",
        ring in any::<bool>(),
    ) {
        let ring = if ring { Ring::Capture } else { Ring::Log };
        let (sender, frame) = match which {
            0 => (Side::Appliance, Frame::Hello(Hello::Appliance)),
            1 => (Side::Server, Frame::Hello(Hello::Server { log: a, capture: b })),
            2 => (Side::Appliance, Frame::UpRecords { position: a, bytes: &bytes }),
            3 => (Side::Appliance, Frame::UpCapture { position: a, bytes: &bytes }),
            4 => (Side::Server, Frame::Ack { log: a, capture: b }),
            5 => (Side::Server, Frame::DownConfigStage { document: &bytes }),
            6 => (Side::Appliance, Frame::UpConfigValidateResult { line: line.as_bytes() }),
            7 => (Side::Server, Frame::DownConfigCommit { generation: a, confirm_deadline_secs: deadline }),
            8 => (Side::Server, Frame::DownCommitConfirm { generation: a }),
            9 => (Side::Server, Frame::DownRangeRead { ring, start: a, length: b }),
            _ => (Side::Appliance, Frame::UpRangeData { ring, status: RangeStatus::Data, position: a, bytes: &bytes }),
        };
        let mut out = vec![0_u8; encoded_len(&frame)];
        let written = encode(sender, &frame, &mut out).expect("a frame this end may send");
        prop_assert_eq!(written, out.len());

        let mut buffer = held();
        let mut decoder = FrameDecoder::new(sender, &mut buffer);
        // The greeting comes first in a real stream; for a frame that *is* the
        // greeting the decoder is already looking at one.
        if frame.frame_type() != FrameType::Hello {
            let opening = encoded(sender, &hello(sender));
            let mut at = 0_usize;
            while at < opening.len() {
                at += decoder.absorb(opening.get(at..).unwrap_or_default());
                prop_assert!(matches!(decoder.next_frame(), Decoded::Frame(_) | Decoded::Partial));
            }
        }
        let mut at = 0_usize;
        loop {
            let took = decoder.absorb(out.get(at..).unwrap_or_default());
            at = at.saturating_add(took);
            match decoder.next_frame() {
                Decoded::Partial => prop_assert!(at < out.len()),
                Decoded::Frame(decoded) => {
                    prop_assert_eq!(decoded, frame);
                    break;
                }
                Decoded::Violated(violation) => {
                    prop_assert!(false, "a composed frame was refused: {:?}", violation);
                    break;
                }
            }
        }
    }
}
