//! The protocol's vocabulary: the ten frames, the three closed byte
//! vocabularies inside their payloads, and the reasons a peer's bytes are not a
//! frame at all.
//!
//! Every type here is closed and every byte-to-value conversion answers an
//! `Option`. That is not a style: a peer writes these bytes, so a value outside
//! a vocabulary is input to refuse and never one to coerce, and a `from_byte`
//! that returned a default would invent the fact the vocabulary exists to carry.

use crate::{APPLIANCE_HELLO_LEN, SERVER_HELLO_LEN};

/// Which end of the channel sent, or is about to send, a frame.
///
/// The parameter that turns this crate's one codec into either end's: a decoder
/// is told whose frames it is reading and refuses one that end may not send, and
/// an encoder is told who is writing and refuses to compose one for the wrong
/// direction.
///
/// Only the appliance dials and the server never connects to an appliance, so
/// which side a given deployment is is fixed for the life of the process — but
/// it is a parameter rather than a build choice, because both ends' frames are
/// this crate's and a codec that could only read one direction could not be
/// tested against what it writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Appliance,
    Server,
}

/// Which recording ring a position, a request or an answer is about.
///
/// A byte on the wire with two values and no third. A selector outside it is a
/// violation rather than a ring chosen for the peer: which ring's bytes are
/// being asked for decides which medium extent is read, so guessing would be
/// answering a question nobody asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ring {
    Log,
    Capture,
}

impl Ring {
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Log => 0,
            Self::Capture => 1,
        }
    }

    /// `None` for every other byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Log),
            1 => Some(Self::Capture),
            _ => None,
        }
    }
}

/// How a range answer went: bytes, or the reason there are none.
///
/// The two failures **end the answer** and carry no bytes, which is the
/// recording discipline arriving on the wire: a reader that cannot serve an
/// extent says so rather than returning a short one, because a truncated answer
/// and a complete one would be indistinguishable to whoever ingests it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeStatus {
    /// The frame carries the extent's bytes from the stated position.
    Data,
    /// The extent has been overwritten — the ring rolled past it — so it no
    /// longer exists to be read.
    Overwritten,
    /// The medium refused the read.
    MediumRefused,
}

impl RangeStatus {
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Overwritten => 1,
            Self::MediumRefused => 2,
        }
    }

    /// `None` for every other byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Data),
            1 => Some(Self::Overwritten),
            2 => Some(Self::MediumRefused),
            _ => None,
        }
    }

    /// Whether this status ends the answer, and so may carry no bytes.
    #[must_use]
    pub const fn ends_the_answer(self) -> bool {
        !matches!(self, Self::Data)
    }
}

/// The ten frames, as the type byte numbers them.
///
/// A closed set, and closed is the point: a type byte outside it is a violation,
/// so this protocol has no room for an extension a peer can introduce by
/// choosing a number. What it does instead is add a frame in a version both ends
/// ship together, which is what the greeting's version field is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    /// The greeting, sent by both ends and first in each direction.
    Hello,
    /// Log-ring bytes, verbatim, from a stated position.
    UpRecords,
    /// Capture-ring bytes, verbatim, from a stated position.
    UpCapture,
    /// The cursors the server has durably ingested each ring up to.
    Ack,
    /// A whole configuration document, to stage as the candidate.
    DownConfigStage,
    /// What validating the staged document produced.
    UpConfigValidateResult,
    /// Commit the named generation, and arm a confirmation deadline.
    DownConfigCommit,
    /// The confirmation, which arrives on a session opened after the commit.
    DownCommitConfirm,
    /// A byte extent of one ring, asked for.
    DownRangeRead,
    /// One frame of the answer to that.
    UpRangeData,
}

impl FrameType {
    /// Every frame this protocol has, in the order the type byte numbers them.
    ///
    /// Exposed so a caller that must cover the protocol — a test, a fuzz
    /// harness — enumerates it rather than restating it.
    pub const ALL: [Self; 10] = [
        Self::Hello,
        Self::UpRecords,
        Self::UpCapture,
        Self::Ack,
        Self::DownConfigStage,
        Self::UpConfigValidateResult,
        Self::DownConfigCommit,
        Self::DownCommitConfirm,
        Self::DownRangeRead,
        Self::UpRangeData,
    ];

    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Hello => 0x01,
            Self::UpRecords => 0x02,
            Self::UpCapture => 0x03,
            Self::Ack => 0x04,
            Self::DownConfigStage => 0x05,
            Self::UpConfigValidateResult => 0x06,
            Self::DownConfigCommit => 0x07,
            Self::DownCommitConfirm => 0x08,
            Self::DownRangeRead => 0x09,
            Self::UpRangeData => 0x0A,
        }
    }

    /// `None` for every other byte, zero included: there is no frame numbered
    /// zero, so a run of zeroed bytes is a violation rather than a greeting.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::UpRecords),
            0x03 => Some(Self::UpCapture),
            0x04 => Some(Self::Ack),
            0x05 => Some(Self::DownConfigStage),
            0x06 => Some(Self::UpConfigValidateResult),
            0x07 => Some(Self::DownConfigCommit),
            0x08 => Some(Self::DownCommitConfirm),
            0x09 => Some(Self::DownRangeRead),
            0x0A => Some(Self::UpRangeData),
            _ => None,
        }
    }

    /// Whether `side` is an end this frame may travel from.
    ///
    /// The greeting travels both ways; every other frame travels one way only,
    /// and the direction is what makes a great deal of this protocol safe by
    /// construction. An appliance that would act on a `DownConfigCommit` it
    /// received from *itself* is not a shape the wire can express, and an
    /// appliance's own decoder refuses a peer that tries: a server sending
    /// `UpRecords` is either a confused peer or one probing which frames this
    /// end will dispatch on without checking who sent them.
    #[must_use]
    pub const fn may_travel_from(self, side: Side) -> bool {
        match self {
            Self::Hello => true,
            Self::UpRecords
            | Self::UpCapture
            | Self::UpConfigValidateResult
            | Self::UpRangeData => matches!(side, Side::Appliance),
            Self::Ack
            | Self::DownConfigStage
            | Self::DownConfigCommit
            | Self::DownCommitConfirm
            | Self::DownRangeRead => matches!(side, Side::Server),
        }
    }

    /// Bytes of payload this frame needs before any variable part of it — and, for
    /// the frames with no variable part, the payload's exact length.
    ///
    /// One number for both readings, because it is only ever reported: it is the
    /// `needed` a "the payload is not this frame's shape" refusal carries beside
    /// the length the peer actually sent. What *decides* the shape is the reader
    /// that walks the fields, which runs out of bytes on a short payload and
    /// finds bytes left over on a long one.
    #[must_use]
    pub const fn payload_floor(self, side: Side) -> usize {
        match self {
            // The one frame whose shape depends on which end sent it: the
            // appliance's carries a version and nothing else, the server's
            // carries the version and its two resume cursors.
            Self::Hello => match side {
                Side::Appliance => APPLIANCE_HELLO_LEN,
                Side::Server => SERVER_HELLO_LEN,
            },
            // A ring position, then as many verbatim ring bytes as fit.
            Self::UpRecords | Self::UpCapture => 8,
            // Two cursors, log then capture.
            Self::Ack => 16,
            // The whole document and nothing else, so no floor at all: an empty
            // payload is a document the configuration reader refuses, and it
            // refuses it with an offset a bare length here could not give.
            Self::DownConfigStage => 0,
            // One line, so at least one character of one.
            Self::UpConfigValidateResult => 1,
            // A generation and a deadline in seconds.
            Self::DownConfigCommit => 10,
            // A generation.
            Self::DownCommitConfirm => 8,
            // A ring, a start and a length.
            Self::DownRangeRead => 17,
            // A ring, a status and a position, then the bytes.
            Self::UpRangeData => 10,
        }
    }
}

/// A greeting's payload, decoded.
///
/// The version is not in here, and its absence is the point: a greeting that
/// carried a version this end does not speak never becomes a value at all, it
/// becomes [`Violation::VersionMismatch`]. So a `Hello` in hand is a greeting in
/// the one version this protocol has, and no caller has to check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hello {
    /// The appliance's, which carries nothing besides the version.
    Appliance,
    /// The server's, which carries the positions it has durably ingested each
    /// ring up to. Those are the appliance's resume points.
    Server { log: u64, capture: u64 },
}

impl Hello {
    /// The end a greeting of this shape comes from.
    #[must_use]
    pub const fn side(self) -> Side {
        match self {
            Self::Appliance => Side::Appliance,
            Self::Server { .. } => Side::Server,
        }
    }
}

/// One frame, decoded — or one to encode.
///
/// The payload-bearing variants **borrow** their bytes. For the three that carry
/// up to a megabyte that is not an optimisation but the whole shape of the
/// crate: a decoded frame is a view into the decoder's own reassembly buffer, so
/// no ring byte is copied on the way in, and the encoder writes a caller's bytes
/// straight into the caller's own output, so none is copied on the way out
/// either. The verbatim upstream direction means exactly that — the ring bytes
/// are the wire bytes.
///
/// The derived `Debug` renders those borrowed bytes, and they are a peer's or a
/// customer's recording. It exists for a failing assertion in a test to be
/// readable and nothing formats one anywhere else; whatever eventually reports a
/// frame on a surface reports its **type** and the numbers beside it, never its
/// payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame<'bytes> {
    /// The first frame in each direction.
    Hello(Hello),
    /// Log-ring bytes from `position`, verbatim.
    UpRecords { position: u64, bytes: &'bytes [u8] },
    /// Capture-ring bytes from `position`, verbatim.
    UpCapture { position: u64, bytes: &'bytes [u8] },
    /// The cursors the server has durably ingested up to.
    Ack { log: u64, capture: u64 },
    /// A whole configuration document to stage as the candidate.
    DownConfigStage { document: &'bytes [u8] },
    /// One line saying what validating the staged document produced.
    ///
    /// Printable ASCII, and handed over as bytes rather than parsed: the fields
    /// in it are the configuration records' closed vocabulary, which lives with
    /// those records. A parser here would be a second reading of a vocabulary
    /// this protocol deliberately does not own — so what this crate holds the
    /// line to is that it *is* one line, of characters that can be read.
    UpConfigValidateResult { line: &'bytes [u8] },
    /// Commit the staged `generation`, confirming within `confirm_deadline` of
    /// it.
    DownConfigCommit {
        generation: u64,
        confirm_deadline_secs: u16,
    },
    /// The confirmation for `generation`, which arrives on a session opened
    /// after the commit.
    DownCommitConfirm { generation: u64 },
    /// Ask for `length` bytes of `ring` from `start`.
    ///
    /// The two numbers are carried and judged nowhere here. What a position
    /// means is the ring's — an extent past its head or behind its tail is
    /// answered by the reader that has the geometry, with the status that says
    /// which — so a codec that refused one would be refusing on a geometry it
    /// cannot see.
    DownRangeRead { ring: Ring, start: u64, length: u64 },
    /// One frame of the answer: `bytes` of `ring` starting at `position`, or the
    /// status saying why there are none.
    UpRangeData {
        ring: Ring,
        status: RangeStatus,
        position: u64,
        bytes: &'bytes [u8],
    },
}

impl Frame<'_> {
    /// Which frame this is.
    #[must_use]
    pub const fn frame_type(&self) -> FrameType {
        match self {
            Self::Hello(_) => FrameType::Hello,
            Self::UpRecords { .. } => FrameType::UpRecords,
            Self::UpCapture { .. } => FrameType::UpCapture,
            Self::Ack { .. } => FrameType::Ack,
            Self::DownConfigStage { .. } => FrameType::DownConfigStage,
            Self::UpConfigValidateResult { .. } => FrameType::UpConfigValidateResult,
            Self::DownConfigCommit { .. } => FrameType::DownConfigCommit,
            Self::DownCommitConfirm { .. } => FrameType::DownCommitConfirm,
            Self::DownRangeRead { .. } => FrameType::DownRangeRead,
            Self::UpRangeData { .. } => FrameType::UpRangeData,
        }
    }
}

/// Why a peer's bytes are not a frame of this protocol.
///
/// One variant per broken rule. A violation closes the connection and nothing
/// else happens — there is no recovery, no resynchronisation and no skipping to
/// the next frame, because a stream whose framing is wrong has no next frame:
/// where the following header starts is exactly what has been lost.
///
/// **Never a panic.** Every one of these is an ordinary value on an ordinary
/// return path, on the same terms as any other externally driven refusal in this
/// appliance: the peer is external input, and input does not get to end a
/// process.
///
/// The context each variant carries — a byte, a length, a frame type — is for a
/// human reading a bug report. Whatever eventually renders one of these on the
/// console renders the **discriminant**, because the context is a peer's own
/// bytes and a console line is not a place to repeat them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    /// One of the three reserved header bytes is not zero. `at` is which of the
    /// three, counted from the first.
    ///
    /// The first thing checked, because it is the one that says the peer is not
    /// speaking this protocol at all rather than speaking it wrongly: the bytes
    /// carry no meaning to get wrong.
    ReservedNonZero { at: u8, byte: u8 },
    /// The type byte names no frame this protocol has.
    UnknownType { byte: u8 },
    /// The header states a payload longer than a frame may carry.
    ///
    /// Nothing past such a header is ever held: the decoder stops taking bytes
    /// the moment it can read the length, so a peer cannot make this end buffer
    /// on the strength of a number it will refuse.
    PayloadTooLong { stated: u32 },
    /// A frame the end that sent it may not send.
    WrongDirection { frame: FrameType, sender: Side },
    /// The first frame in this direction is not the greeting.
    FirstFrameNotHello { frame: FrameType },
    /// A greeting naming a protocol version this end does not speak.
    ///
    /// Read before the rest of the greeting's shape is judged, and deliberately:
    /// a peer speaking another version will have another greeting shape too, and
    /// "your version is not mine" is the fact that sends somebody to the right
    /// place, where "your payload is the wrong length" would send them looking
    /// for a corrupted frame.
    VersionMismatch { theirs: u16 },
    /// The payload is not the length this frame's fields need: `len` arrived and
    /// `needed` was owed — exactly, for a frame with nothing variable in it, and
    /// at least, for one with a variable tail.
    PayloadLength {
        frame: FrameType,
        len: usize,
        needed: usize,
    },
    /// A ring selector byte naming neither ring.
    UnknownRing { byte: u8 },
    /// A range-answer status byte naming no status.
    UnknownRangeStatus { byte: u8 },
    /// A range answer whose status ends the answer, carrying bytes anyway.
    ///
    /// A frame contradicting itself, and the contradiction matters: an ingest
    /// that believed the bytes would be writing an extent the answer just said
    /// does not exist.
    BytesOnEndedRange { status: RangeStatus, len: usize },
    /// A staged configuration document longer than one may be.
    ///
    /// Separate from [`Self::PayloadTooLong`] because it is a different bound
    /// broken for a different reason: the frame bound is this protocol's, and
    /// this one is the configuration stage's, so an operator meeting it is
    /// looking at a document somebody composed rather than at a framing fault.
    ConfigDocumentTooLong { len: usize },
    /// A validate-result line carrying a byte that is not a printable ASCII
    /// character. `at` is its offset in the payload.
    ///
    /// Which includes a newline: the payload is *one* line, so the frame
    /// delimits it and a byte that would delimit it again is not part of it.
    ResultLineNotPrintable { at: usize, byte: u8 },
}

// The type bytes are the protocol's and no two frames may share one, which is
// what makes the byte a name. Checked here rather than trusted to a reading of
// the match above.
const _: () = {
    let mut i = 0;
    while i < FrameType::ALL.len() {
        let frame = FrameType::ALL[i];
        // Every frame round-trips through its byte, so `from_byte` cannot fall
        // out of step with `to_byte`.
        assert!(FrameType::from_byte(frame.to_byte()).is_some());
        // The type bytes run 1 through 10 with no gap, so the vocabulary's
        // extent is a fact about this array rather than about a reading of the
        // match.
        assert!(frame.to_byte() as usize == i + 1);
        // Every frame travels from at least one end. A frame no end may send
        // would be one this codec can name and neither end can use.
        assert!(frame.may_travel_from(Side::Appliance) || frame.may_travel_from(Side::Server));
        i += 1;
    }
    assert!(FrameType::from_byte(0).is_none());
    assert!(FrameType::from_byte(FrameType::ALL.len() as u8 + 1).is_none());
    // The greeting is the only frame both ends send, which is what makes "the
    // first frame in each direction" one rule rather than two.
    assert!(FrameType::Hello.may_travel_from(Side::Appliance));
    assert!(FrameType::Hello.may_travel_from(Side::Server));
    // The two closed byte vocabularies end where they end.
    assert!(Ring::from_byte(2).is_none());
    assert!(RangeStatus::from_byte(3).is_none());
    // Only the greeting's shape depends on which end sent it, so the floor for
    // every other frame is one number.
    assert!(
        FrameType::Ack.payload_floor(Side::Appliance) == FrameType::Ack.payload_floor(Side::Server)
    );
};
