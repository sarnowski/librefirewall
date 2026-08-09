//! `lfw_channel`'s framing: the management channel's frames read out of a byte
//! stream a hostile peer composed and paced, and written back out of what was
//! read.
//!
//! # Adversary
//!
//! A **management-plane attacker up to and including a compromised management
//! server**. Everything here is that party's: every header, every stated length,
//! every reserved byte, every ring selector and status byte, every cursor — and
//! the *pacing*, which is the half a whole-frame test cannot reach. A frame
//! carries up to a mebibyte and the record layer below hands over tens of
//! kibibytes at a time, so where the pieces fall is the adversary's choice and
//! the reassembly is what has to survive it.
//!
//! That the peer is authenticated by the session underneath is not a reason to
//! model it as well-behaved: a compromised server holds a valid certificate, and
//! what bounds it is the arithmetic in the decoder rather than the handshake.
//!
//! The direction is drawn from the input too. Both ends' frames are one crate's,
//! and the decoder's refusal of a frame the *other* end had no business sending
//! only exists in one direction at a time — so a harness fixed to one side would
//! leave half the direction table unreached.
//!
//! # What is asserted, beyond not crashing
//!
//! * **Boundedness.** The decoder never holds more than one frame's worth, at
//!   any point in the run, and never takes more bytes than it was offered. A
//!   header stating a payload past the bound must cost nothing at all: that is
//!   the shape where a peer would otherwise pace this end into holding whatever
//!   it liked.
//! * **The stream's own bytes are the frame's.** Every frame decoded is
//!   re-encoded and held to **exactly** the bytes it was decoded from. That is
//!   the strongest claim here and it catches the whole class of decode/encode
//!   disagreement — a field read at the wrong offset, a length believed but not
//!   written, an endianness that differs between the two halves — which a test
//!   comparing a frame against a frame cannot see.
//! * **Containment.** Every encode goes into a guarded buffer, so a write past
//!   what the encoder was given fails here rather than becoming a byte of
//!   something else, and the length it reports is held to what it actually
//!   touched.
//! * **A refusal leaves the output alone.** An encode that refuses must not have
//!   written a byte: half a frame on a length-prefixed stream is worse than
//!   none.
//! * **Nothing decodes before the greeting.** Whatever a peer sends, the first
//!   frame this end reads out of it is the greeting or the connection is over.
//! * **A violation is final and settles once.** The first rule broken is the one
//!   that stays, because it is what an operator goes and looks at; and a decoder
//!   that has answered one takes no further byte and answers nothing else.
//! * **Direction is a property of the frame.** Every frame but the greeting is
//!   refused by an encoder for the other end, which is the same table the
//!   decoder enforces read from the writing side.
//!
//! # What this target cannot reach, and what covers it instead
//!
//! Four encoder refusals are unreachable from a stream of bytes, because each is
//! a frame **this end composed wrongly** rather than one a peer sent: a payload
//! past the frame bound, a document past its own bound, an empty or unprintable
//! result line, and a range answer that ends the answer while carrying bytes. A
//! decoded frame is by construction none of those — the decoder refused every one
//! of them on the way in — so they are held in `lfw_channel`'s own suite, one
//! test per refusal, and stated here rather than left to read as coverage.
//!
//! # The buffer is reused across inputs, deliberately
//!
//! A decoder's reassembly buffer is a mebibyte and belongs to whoever placed it,
//! so allocating one per input would spend the run in `memset` rather than in the
//! state machine. It is held in thread-local storage and handed to a fresh
//! decoder each time, which also drives the claim the decoder makes about reuse:
//! a buffer carrying one connection's bytes must contribute nothing to the next.

use std::{cell::RefCell, vec, vec::Vec};

use arbitrary::{Arbitrary, Unstructured};
use lfw_channel::{
    Decoded, EncodeRefusal, Frame, FrameDecoder, FrameType, MAX_FRAME_LEN, Side, Violation, encode,
    encoded_len,
};

use crate::{any_u16, guard::Guarded};

/// Cut points one input may place in the stream, at most.
///
/// A libFuzzer time budget and not a bound on the adversary's authority: the cut
/// *positions* are arbitrary and every prefix reaches the decoder regardless, so
/// no arrival pattern is excluded by it.
const MAX_CUTS: usize = 8;

/// The most room an encode is ever offered on the short-buffer arm.
const ANSWER_ROOM: usize = 4096;

thread_local! {
    /// One reassembly buffer for the whole run — see this module's header.
    static BUFFER: RefCell<Box<[u8; MAX_FRAME_LEN]>> = RefCell::new(zeroed());
}

fn zeroed() -> Box<[u8; MAX_FRAME_LEN]> {
    vec![0_u8; MAX_FRAME_LEN]
        .into_boxed_slice()
        .try_into()
        .expect("a run of exactly one frame's worth")
}

pub fn channel_frames_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let flags = u8::arbitrary(&mut unstructured).unwrap_or(0);
    // Which end's frames these are. Both, over a run, because the direction table
    // only refuses in one direction at a time.
    let sender = if flags & 1 == 0 {
        Side::Server
    } else {
        Side::Appliance
    };
    let room = usize::from(u8::arbitrary(&mut unstructured).unwrap_or(0))
        .saturating_mul(ANSWER_ROOM / 256)
        .min(ANSWER_ROOM);
    let count = usize::from(u8::arbitrary(&mut unstructured).unwrap_or(0)) % (MAX_CUTS + 1);
    let mut cuts: Vec<usize> = (0..count)
        .map(|_| usize::from(any_u16(&mut unstructured)))
        .collect();
    let stream = unstructured.take_rest();
    cuts.sort_unstable();

    BUFFER.with_borrow_mut(|buffer| drive(sender, room, &cuts, stream, buffer));
}

fn drive(
    sender: Side,
    room: usize,
    cuts: &[usize],
    stream: &[u8],
    buffer: &mut [u8; MAX_FRAME_LEN],
) {
    let mut decoder = FrameDecoder::new(sender, buffer);
    // Where the frame currently being assembled began in the stream, so a decoded
    // frame can be held to the bytes it came out of.
    let mut frame_start = 0_usize;
    let mut at = 0_usize;
    let mut settled: Option<Violation> = None;
    let mut decoded = 0_usize;
    // Every cut, then the end: a delivery is the run between two of them, and the
    // last reaches whatever is left.
    let boundaries = cuts
        .iter()
        .copied()
        .chain(core::iter::once(stream.len()))
        .map(|cut| cut.min(stream.len()));
    for boundary in boundaries {
        // Each boundary is offered until it stops being taken, so a frame that
        // ends inside a delivery is decoded rather than waiting for the next one.
        loop {
            let end = boundary.max(at);
            let delivery = stream.get(at..end).unwrap_or_default();
            let took = decoder.absorb(delivery);
            assert!(
                took <= delivery.len(),
                "the decoder took {took} of a delivery of {}",
                delivery.len()
            );
            at = at.saturating_add(took);
            assert!(
                decoder.held() <= MAX_FRAME_LEN,
                "the decoder held {} bytes, past one frame's worth",
                decoder.held()
            );
            if let Some(previous) = settled {
                assert_eq!(
                    decoder.violation(),
                    Some(previous),
                    "a later consequence displaced the cause"
                );
                assert_eq!(took, 0, "a decoder that has refused took more bytes");
            }
            match decoder.next_frame() {
                Decoded::Partial => {
                    if took == 0 {
                        break;
                    }
                }
                Decoded::Frame(frame) => {
                    decoded += 1;
                    if decoded == 1 {
                        assert_eq!(
                            frame.frame_type(),
                            FrameType::Hello,
                            "a frame decoded before the greeting"
                        );
                    }
                    let wire = stream.get(frame_start..at).unwrap_or_default();
                    check_reencode(sender, &frame, wire, room);
                    frame_start = at;
                }
                Decoded::Violated(violation) => {
                    assert_eq!(decoder.violation(), Some(violation));
                    assert_eq!(
                        decoder.absorb(&[0xFF; 64]),
                        0,
                        "a decoder that has refused took more bytes"
                    );
                    assert_eq!(
                        decoder.next_frame(),
                        Decoded::Violated(violation),
                        "a refusal did not stay the answer"
                    );
                    settled = Some(violation);
                    // Not a return: the deliveries left over are offered to a
                    // decoder that has already refused, which is how the
                    // assertions at the head of this loop come to hold *after*
                    // the connection was lost as well as before.
                    break;
                }
            }
        }
    }
}

/// Hold `frame` to the `wire` bytes it was decoded from, and to what an encoder
/// offered too little room does.
fn check_reencode(sender: Side, frame: &Frame<'_>, wire: &[u8], room: usize) {
    let needed = encoded_len(frame);
    assert_eq!(
        needed,
        wire.len(),
        "a decoded {:?} claims a different length from the bytes it came out of",
        frame.frame_type()
    );
    assert!(
        needed <= MAX_FRAME_LEN,
        "a decoded frame re-encodes past one frame's worth"
    );

    let mut guarded = Guarded::new(needed);
    let written = encode(sender, frame, guarded.out()).expect("a frame this end just received");
    guarded.assert_margins_intact("the channel framing's encoder");
    assert_eq!(written, needed, "the length written is not the length owed");
    assert!(
        guarded.touched_len() <= written,
        "the encoder wrote further into the buffer than the length it reported"
    );
    assert_eq!(
        guarded.written(written),
        wire,
        "a decoded {:?} did not re-encode to the bytes it came out of",
        frame.frame_type()
    );

    // The same frame into whatever room the input chose: either the whole of it
    // or a refusal that wrote nothing.
    let mut short = Guarded::new(room);
    match encode(sender, frame, short.out()) {
        Ok(len) => {
            assert_eq!(len, needed);
            assert_eq!(short.written(len), wire);
        }
        Err(refusal) => {
            assert_eq!(
                refusal,
                EncodeRefusal::OutputTooSmall { needed, room },
                "a frame this end received was refused for something other than room"
            );
            assert!(
                short.is_untouched(),
                "a refused encode wrote into the caller's output"
            );
        }
    }
    short.assert_margins_intact("the channel framing's encoder under too little room");

    // Direction read from the writing side: every frame but the greeting belongs
    // to one end, and the other end cannot compose it.
    if frame.frame_type() != FrameType::Hello {
        let other = match sender {
            Side::Appliance => Side::Server,
            Side::Server => Side::Appliance,
        };
        let mut out = vec![0_u8; needed];
        assert_eq!(
            encode(other, frame, &mut out),
            Err(EncodeRefusal::WrongDirection {
                frame: frame.frame_type(),
                sender: other
            }),
            "a frame composed for the end that may not send it"
        );
        assert!(
            out.iter().all(|byte| *byte == 0),
            "a refused encode wrote into the caller's output"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use lfw_channel::{
        Decoded, FrameDecoder, FrameType, HEADER_LEN, MAX_DOCUMENT_BYTES, MAX_FRAME_LEN,
        MAX_PAYLOAD_LEN, RangeStatus, Ring, Side, VERSION, Violation,
    };

    use super::zeroed;

    const TARGET: &str = "channel_frames";

    /// The stream a seed carries, and how it is delivered: the harness's input format
    /// as a value, so the committed corpus is built rather than hand-assembled.
    struct Composed {
        side: Side,
        room: u8,
        cuts: Vec<u16>,
        wire: Vec<u8>,
    }

    impl Composed {
        /// The input bytes a fuzzer would read: the three selectors, the cut
        /// positions, then the stream.
        fn input(&self) -> Vec<u8> {
            let mut input = vec![
                match self.side {
                    Side::Server => 0,
                    Side::Appliance => 1,
                },
                self.room,
                u8::try_from(self.cuts.len()).unwrap_or(u8::MAX),
            ];
            for cut in &self.cuts {
                input.extend_from_slice(&cut.to_le_bytes());
            }
            input.extend_from_slice(&self.wire);
            input
        }
    }

    /// What a decoder for a seed's own side must make of it.
    ///
    /// The whole reason the corpus is built here rather than assembled by hand: a
    /// seed named for a rule that no longer reaches it is a corpus entry claiming
    /// coverage of an arm nothing touches, which is the one failure a seed file
    /// cannot show on its own.
    enum Reaches {
        /// Exactly these frames decode, and nothing is refused.
        Frames(&'static [FrameType]),
        /// This rule is broken.
        Refused(Violation),
    }

    fn header(stated: u32, kind: u8, reserved: [u8; 3]) -> Vec<u8> {
        let [a, b, c, d] = stated.to_be_bytes();
        let [r0, r1, r2] = reserved;
        vec![a, b, c, d, kind, r0, r1, r2]
    }

    /// A frame whose header states the length of the payload behind it.
    fn frame(kind: FrameType, payload: &[u8]) -> Vec<u8> {
        let stated = u32::try_from(payload.len()).expect("a seed payload inside a u32");
        let mut bytes = header(stated, kind.to_byte(), [0; 3]);
        bytes.extend_from_slice(payload);
        bytes
    }

    /// A header stating a length the bytes behind it do not have, which is how a
    /// length rule is reached without committing the payload it claims.
    fn header_stating(kind: FrameType, stated: usize) -> Vec<u8> {
        header(
            u32::try_from(stated).expect("a stated length inside a u32"),
            kind.to_byte(),
            [0; 3],
        )
    }

    fn hello(side: Side) -> Vec<u8> {
        let mut payload = VERSION.to_be_bytes().to_vec();
        if matches!(side, Side::Server) {
            payload.extend_from_slice(&0_u64.to_be_bytes());
            payload.extend_from_slice(&0_u64.to_be_bytes());
        }
        frame(FrameType::Hello, &payload)
    }

    /// A ring position followed by a run of bytes, which is what the two upstream
    /// ring frames carry.
    fn at(position: u64, bytes: &[u8]) -> Vec<u8> {
        let mut payload = position.to_be_bytes().to_vec();
        payload.extend_from_slice(bytes);
        payload
    }

    /// A range answer's payload: the ring, the status, the position, the bytes.
    fn range_answer(ring: Ring, status: RangeStatus, position: u64, bytes: &[u8]) -> Vec<u8> {
        let mut payload = vec![ring.to_byte(), status.to_byte()];
        payload.extend_from_slice(&position.to_be_bytes());
        payload.extend_from_slice(bytes);
        payload
    }

    /// Every committed seed, as the stream it stands for and the arm it reaches.
    ///
    /// One per frame type in the direction it travels, one per rule a peer can
    /// break, and three for the *pacing* — which is the half of this surface a
    /// whole-frame seed cannot reach.
    #[expect(
        clippy::too_many_lines,
        reason = "one table entry per protocol frame and per violation; splitting it would hide \
                  the coverage claim it makes"
    )]
    fn demonstrations() -> Vec<(&'static str, Composed, Reaches)> {
        let one = |name: &'static str, side: Side, wire: Vec<u8>, reaches: Reaches| {
            (
                name,
                Composed {
                    side,
                    room: 0xFF,
                    cuts: Vec::new(),
                    wire,
                },
                reaches,
            )
        };
        let appliance = |name: &'static str, tail: Vec<u8>, reaches: Reaches| {
            let mut wire = hello(Side::Appliance);
            wire.extend_from_slice(&tail);
            one(name, Side::Appliance, wire, reaches)
        };
        let server = |name: &'static str, tail: Vec<u8>, reaches: Reaches| {
            let mut wire = hello(Side::Server);
            wire.extend_from_slice(&tail);
            one(name, Side::Server, wire, reaches)
        };
        let pcapng = [0x0a_u8, 0x0d, 0x0d, 0x0a].repeat(16);

        let mut every = vec![
            // One per frame type, behind the greeting its direction owes.
            one(
                "hello_appliance",
                Side::Appliance,
                hello(Side::Appliance),
                Reaches::Frames(&[FrameType::Hello]),
            ),
            one(
                "hello_server",
                Side::Server,
                hello(Side::Server),
                Reaches::Frames(&[FrameType::Hello]),
            ),
            appliance(
                "up_records",
                frame(FrameType::UpRecords, &at(4096, &pcapng)),
                Reaches::Frames(&[FrameType::Hello, FrameType::UpRecords]),
            ),
            appliance(
                "up_capture",
                frame(FrameType::UpCapture, &at(1 << 40, &pcapng)),
                Reaches::Frames(&[FrameType::Hello, FrameType::UpCapture]),
            ),
            server(
                "ack",
                frame(FrameType::Ack, &at(8192, &65_536_u64.to_be_bytes())),
                Reaches::Frames(&[FrameType::Hello, FrameType::Ack]),
            ),
            server(
                "config_stage",
                frame(
                    FrameType::DownConfigStage,
                    b"<configuration generation=\"3\"/>",
                ),
                Reaches::Frames(&[FrameType::Hello, FrameType::DownConfigStage]),
            ),
            appliance(
                "validate_result",
                frame(
                    FrameType::UpConfigValidateResult,
                    b"generation=3 outcome=accepted",
                ),
                Reaches::Frames(&[FrameType::Hello, FrameType::UpConfigValidateResult]),
            ),
            server(
                "config_commit",
                frame(FrameType::DownConfigCommit, &{
                    let mut payload = 3_u64.to_be_bytes().to_vec();
                    payload.extend_from_slice(&300_u16.to_be_bytes());
                    payload
                }),
                Reaches::Frames(&[FrameType::Hello, FrameType::DownConfigCommit]),
            ),
            server(
                "commit_confirm",
                frame(FrameType::DownCommitConfirm, &3_u64.to_be_bytes()),
                Reaches::Frames(&[FrameType::Hello, FrameType::DownCommitConfirm]),
            ),
            server(
                "range_read",
                frame(FrameType::DownRangeRead, &{
                    let mut payload = vec![Ring::Capture.to_byte()];
                    payload.extend_from_slice(&(1_u64 << 20).to_be_bytes());
                    payload.extend_from_slice(&(1_u64 << 16).to_be_bytes());
                    payload
                }),
                Reaches::Frames(&[FrameType::Hello, FrameType::DownRangeRead]),
            ),
            appliance(
                "range_data",
                frame(
                    FrameType::UpRangeData,
                    &range_answer(Ring::Capture, RangeStatus::Data, 1 << 20, &[0xAB; 64]),
                ),
                Reaches::Frames(&[FrameType::Hello, FrameType::UpRangeData]),
            ),
            appliance(
                "range_data_overwritten",
                frame(
                    FrameType::UpRangeData,
                    &range_answer(Ring::Log, RangeStatus::Overwritten, 0, &[]),
                ),
                Reaches::Frames(&[FrameType::Hello, FrameType::UpRangeData]),
            ),
            appliance(
                "range_data_medium_refused",
                frame(
                    FrameType::UpRangeData,
                    &range_answer(Ring::Capture, RangeStatus::MediumRefused, 7, &[]),
                ),
                Reaches::Frames(&[FrameType::Hello, FrameType::UpRangeData]),
            ),
            // One per rule a peer can break.
            one(
                "reserved_nonzero",
                Side::Server,
                {
                    let mut wire = header(18, FrameType::Hello.to_byte(), [0, 0x99, 0]);
                    wire.extend_from_slice(&[0; 18]);
                    wire
                },
                Reaches::Refused(Violation::ReservedNonZero { at: 1, byte: 0x99 }),
            ),
            one(
                "unknown_type",
                Side::Server,
                header(0, 0xFF, [0; 3]),
                Reaches::Refused(Violation::UnknownType { byte: 0xFF }),
            ),
            one(
                "payload_over_the_bound",
                Side::Appliance,
                {
                    let mut wire = header_stating(FrameType::UpRecords, MAX_PAYLOAD_LEN + 1);
                    wire.extend_from_slice(&[0; 32]);
                    wire
                },
                Reaches::Refused(Violation::PayloadTooLong {
                    stated: u32::try_from(MAX_PAYLOAD_LEN + 1).expect("the bound plus one"),
                }),
            ),
            one(
                "wrong_direction",
                Side::Server,
                frame(FrameType::UpRecords, &0_u64.to_be_bytes()),
                Reaches::Refused(Violation::WrongDirection {
                    frame: FrameType::UpRecords,
                    sender: Side::Server,
                }),
            ),
            one(
                "first_frame_not_hello",
                Side::Server,
                frame(FrameType::Ack, &[0; 16]),
                Reaches::Refused(Violation::FirstFrameNotHello {
                    frame: FrameType::Ack,
                }),
            ),
            one(
                "version_mismatch",
                Side::Server,
                {
                    let mut payload = 2_u16.to_be_bytes().to_vec();
                    payload.extend_from_slice(&[0; 16]);
                    frame(FrameType::Hello, &payload)
                },
                Reaches::Refused(Violation::VersionMismatch { theirs: 2 }),
            ),
            server(
                "payload_short",
                frame(FrameType::Ack, &[0; 15]),
                Reaches::Refused(Violation::PayloadLength {
                    frame: FrameType::Ack,
                    len: 15,
                    needed: 16,
                }),
            ),
            server(
                "payload_trailing",
                frame(FrameType::DownCommitConfirm, &[0; 9]),
                Reaches::Refused(Violation::PayloadLength {
                    frame: FrameType::DownCommitConfirm,
                    len: 9,
                    needed: 8,
                }),
            ),
            server(
                "unknown_ring",
                frame(FrameType::DownRangeRead, &{
                    let mut payload = vec![2];
                    payload.extend_from_slice(&[0; 16]);
                    payload
                }),
                Reaches::Refused(Violation::UnknownRing { byte: 2 }),
            ),
            appliance(
                "unknown_range_status",
                frame(FrameType::UpRangeData, &{
                    let mut payload = vec![Ring::Log.to_byte(), 9];
                    payload.extend_from_slice(&[0; 8]);
                    payload
                }),
                Reaches::Refused(Violation::UnknownRangeStatus { byte: 9 }),
            ),
            appliance(
                "bytes_on_ended_range",
                frame(
                    FrameType::UpRangeData,
                    &range_answer(Ring::Log, RangeStatus::Overwritten, 0, &[0xFF; 4]),
                ),
                Reaches::Refused(Violation::BytesOnEndedRange {
                    status: RangeStatus::Overwritten,
                    len: 4,
                }),
            ),
            server(
                "document_over_the_bound",
                {
                    let mut wire =
                        header_stating(FrameType::DownConfigStage, MAX_DOCUMENT_BYTES + 1);
                    wire.extend_from_slice(&[b' '; 32]);
                    wire
                },
                Reaches::Refused(Violation::ConfigDocumentTooLong {
                    len: MAX_DOCUMENT_BYTES + 1,
                }),
            ),
            appliance(
                "result_line_not_printable",
                frame(FrameType::UpConfigValidateResult, b"outcome=ok\n"),
                Reaches::Refused(Violation::ResultLineNotPrintable {
                    at: 10,
                    byte: b'\n',
                }),
            ),
            // Two frames inside one delivery, so a boundary is crossed rather
            // than delivered.
            server(
                "two_frames_one_delivery",
                {
                    let mut wire = frame(FrameType::Ack, &at(1, &2_u64.to_be_bytes()));
                    wire.extend_from_slice(&frame(
                        FrameType::DownCommitConfirm,
                        &3_u64.to_be_bytes(),
                    ));
                    wire
                },
                Reaches::Frames(&[
                    FrameType::Hello,
                    FrameType::Ack,
                    FrameType::DownCommitConfirm,
                ]),
            ),
        ];

        // The pacing. A frame far larger than one delivery, cut at eight points:
        // the maximal frame is a mebibyte and is held by `lfw_channel`'s own suite
        // rather than committed here, and this is the same reassembly over enough
        // deliveries to drive it.
        let ring: Vec<u8> = (0..40 * 1024)
            .map(|at| u8::try_from(at % 251).unwrap_or(0))
            .collect();
        let mut wire = hello(Side::Appliance);
        wire.extend_from_slice(&frame(FrameType::UpRecords, &at(1 << 32, &ring)));
        every.push((
            "reassembled_over_deliveries",
            Composed {
                side: Side::Appliance,
                room: 0xFF,
                cuts: vec![13, 40, 1000, 4096, 9999, 16_384, 30_000, 41_000],
                wire,
            },
            Reaches::Frames(&[FrameType::Hello, FrameType::UpRecords]),
        ));
        // A greeting a byte at a time, into an encoder with no room at all: the
        // two smallest steps this surface has.
        every.push((
            "greeting_dribbled",
            Composed {
                side: Side::Server,
                room: 0,
                cuts: vec![1, 2, 3, 4, 5, 6, 7, 8],
                wire: hello(Side::Server),
            },
            Reaches::Frames(&[FrameType::Hello]),
        ));
        every
    }

    fn seed(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(TARGET)
            .join(name);
        fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    /// Rewrite every committed seed from the demonstration of the same name.
    ///
    /// Ignored by default and run by hand — `cargo test --manifest-path
    /// fuzz/Cargo.toml -- --ignored rewrite_the_committed_channel_frame_seeds` —
    /// after a deliberate change to the framing, which moves the bytes every seed
    /// carries. The test below is what holds the corpus to the demonstrations
    /// afterwards, so this is a regeneration step and never a substitute for it.
    #[test]
    #[ignore = "regenerates the committed corpus; run by hand after a framing change"]
    fn rewrite_the_committed_channel_frame_seeds() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(TARGET);
        fs::create_dir_all(&dir).expect("create the corpus directory");
        for (name, composed, _) in demonstrations() {
            fs::write(dir.join(name), composed.input()).expect("write the seed");
        }
    }

    #[test]
    fn every_demonstration_is_the_committed_seed_of_its_name() {
        for (name, composed, _) in demonstrations() {
            assert_eq!(
                seed(name),
                composed.input(),
                "seed {name} is not the stream it stands for"
            );
        }
    }

    /// What a decoder for `side` makes of `wire`, delivered whole.
    fn outcome(side: Side, wire: &[u8]) -> (Vec<FrameType>, Option<Violation>) {
        let mut buffer = zeroed();
        let mut decoder = FrameDecoder::new(side, &mut buffer);
        let mut frames = Vec::new();
        let mut at = 0_usize;
        loop {
            let took = decoder.absorb(wire.get(at..).unwrap_or_default());
            at = at.saturating_add(took);
            match decoder.next_frame() {
                Decoded::Partial => {
                    if took == 0 {
                        return (frames, None);
                    }
                }
                Decoded::Frame(frame) => frames.push(frame.frame_type()),
                Decoded::Violated(violation) => return (frames, Some(violation)),
            }
        }
    }

    /// The claim the corpus makes: each seed reaches the arm its name says.
    ///
    /// Without this the corpus is a set of byte strings that once reached
    /// something. Every entry names a frame of the protocol or a rule a peer can
    /// break, and this is what keeps that true as the framing changes.
    #[test]
    fn every_seed_reaches_the_arm_its_name_says() {
        for (name, composed, reaches) in demonstrations() {
            let (frames, violation) = outcome(composed.side, &composed.wire);
            match reaches {
                Reaches::Frames(expected) => {
                    assert_eq!(violation, None, "seed {name} was refused");
                    assert_eq!(frames, expected, "seed {name} decoded other frames");
                }
                Reaches::Refused(expected) => {
                    assert_eq!(violation, Some(expected), "seed {name} broke another rule");
                }
            }
        }
    }

    /// Every frame the protocol has, and every rule it names, is somewhere in the
    /// corpus. A target seeded with a subset of its own surface starts cold on the
    /// rest.
    #[test]
    fn the_corpus_covers_every_frame_and_every_rule() {
        let mut frames: Vec<FrameType> = demonstrations()
            .iter()
            .filter_map(|(_, _, reaches)| match reaches {
                Reaches::Frames(frames) => Some(frames.iter().copied()),
                Reaches::Refused(_) => None,
            })
            .flatten()
            .collect();
        frames.sort_unstable_by_key(|frame| frame.to_byte());
        frames.dedup();
        assert_eq!(
            frames,
            FrameType::ALL.to_vec(),
            "the corpus decodes some frames of this protocol and not others"
        );

        // Thirteen rules, one seed each. Compared as the set of shapes rather
        // than as a count, so a rule that gained a second seed and lost its own
        // still fails.
        let refused: Vec<Violation> = demonstrations()
            .iter()
            .filter_map(|(_, _, reaches)| match reaches {
                Reaches::Refused(violation) => Some(*violation),
                Reaches::Frames(_) => None,
            })
            .collect();
        for owed in [
            Violation::ReservedNonZero { at: 1, byte: 0x99 },
            Violation::UnknownType { byte: 0xFF },
            Violation::PayloadTooLong {
                stated: u32::try_from(MAX_PAYLOAD_LEN + 1).expect("the bound plus one"),
            },
            Violation::WrongDirection {
                frame: FrameType::UpRecords,
                sender: Side::Server,
            },
            Violation::FirstFrameNotHello {
                frame: FrameType::Ack,
            },
            Violation::VersionMismatch { theirs: 2 },
            Violation::PayloadLength {
                frame: FrameType::Ack,
                len: 15,
                needed: 16,
            },
            Violation::UnknownRing { byte: 2 },
            Violation::UnknownRangeStatus { byte: 9 },
            Violation::BytesOnEndedRange {
                status: RangeStatus::Overwritten,
                len: 4,
            },
            Violation::ConfigDocumentTooLong {
                len: MAX_DOCUMENT_BYTES + 1,
            },
            Violation::ResultLineNotPrintable {
                at: 10,
                byte: b'\n',
            },
        ] {
            assert!(
                refused.contains(&owed),
                "no committed seed reaches {owed:?}"
            );
        }
    }

    /// The reassembly seed really does span deliveries, which is the property it
    /// is in the corpus for.
    #[test]
    fn the_pacing_seeds_carry_a_frame_larger_than_any_one_delivery() {
        let (_, composed, _) = demonstrations()
            .into_iter()
            .find(|(name, _, _)| *name == "reassembled_over_deliveries")
            .expect("the reassembly seed");
        assert!(
            composed.wire.len() > 32 * 1024,
            "the reassembly seed is small enough to arrive whole"
        );
        assert!(composed.wire.len() < MAX_FRAME_LEN);
        assert!(composed.cuts.len() >= 8, "too few cut points to pace it");
        // Long enough that the frame's own header is nowhere near its end, which
        // is what makes the reassembly the thing under test.
        assert!(composed.wire.len() > 4 * HEADER_LEN);
    }
}
