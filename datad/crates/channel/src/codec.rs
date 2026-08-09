//! Frames onto bytes and bytes back into frames.
//!
//! Two halves with two different jobs, and the asymmetry is the whole shape of
//! this module.
//!
//! [`encode`] writes a frame this end composed. Its input is first-party — a
//! value of a closed type, built by the code above it — so what can go wrong is
//! a bug here or a caller offering too little room, and both are answered with
//! an [`EncodeRefusal`] rather than a malformed frame put on the wire.
//!
//! [`FrameDecoder`] reads a frame **the peer** composed, and every byte of it is
//! hostile. So it is incremental, because a frame arrives in as many pieces as
//! the record layer under it produces; it is bounded, because it holds one
//! frame's worth of a peer's bytes and never two; and it refuses with a
//! [`Violation`] naming the rule broken, because the connection is over and the
//! console is the only place anybody will look.
//!
//! # The length is written from a count of the same walk that writes the bytes
//!
//! A header states its payload's length, and a length derived from a second
//! traversal is a length that goes stale the first time one of the two changes —
//! which for a length prefix means two ends that disagree about where the next
//! frame starts. So [`encoded_len`] runs the *same* walk [`encode`] runs, into a
//! sink that counts instead of writing.
//!
//! # Nothing here can panic on a peer's bytes
//!
//! Every read is a total function answering an `Option`: no slice is indexed, no
//! length is subtracted without a floor, no peer's number is added to another
//! without a bound already over it. A payload that runs out mid-field is a
//! refusal like any other, which is what makes the decoder's answer to a
//! truncated frame the same kind of thing as its answer to a wrong one.

use crate::{
    HEADER_LEN, MAX_DOCUMENT_BYTES, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, VERSION,
    frame::{Frame, FrameType, Hello, RangeStatus, Ring, Side, Violation},
};

/// The lowest byte a validate-result line may carry: a space.
const FIRST_PRINTABLE: u8 = 0x20;

/// The highest: a tilde. Above it is `DEL` and then the bytes that are not ASCII
/// at all; below the first are the controls, the newline among them — which
/// matters, because the payload is *one* line and the frame is what delimits it.
const LAST_PRINTABLE: u8 = 0x7E;

/// Why a frame this end composed was not written.
///
/// Every one is either a bug above this crate or a caller that offered too
/// little room — never a peer's doing, which is what separates this vocabulary
/// from [`Violation`]. There is no variant that means "written partially": a
/// refusal leaves the caller's output untouched, because half a frame on a
/// length-prefixed stream is worse than none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeRefusal {
    /// A frame the composing end may not send. For a greeting this is the two
    /// shapes being told apart: an appliance cannot send the server's greeting,
    /// carrying resume cursors it has no business having.
    WrongDirection { frame: FrameType, sender: Side },
    /// The payload would be longer than a frame may carry.
    PayloadTooLong { len: usize },
    /// A configuration document longer than one may be. Its own refusal because
    /// its own bound was broken — the frame bound is far above it.
    ConfigDocumentTooLong { len: usize },
    /// A validate-result line with no characters in it. A result that says
    /// nothing is not a result, and the receiving end refuses one.
    EmptyResultLine,
    /// A validate-result line carrying a byte that is not printable ASCII, at
    /// this offset in the line.
    ResultLineNotPrintable { at: usize, byte: u8 },
    /// A range answer whose status ends the answer, given bytes to carry.
    BytesOnEndedRange { status: RangeStatus, len: usize },
    /// The output offered cannot hold the whole frame. `needed` is the length it
    /// would have taken.
    OutputTooSmall { needed: usize, room: usize },
}

/// Somewhere a frame's bytes go: the slice a caller offered, or nothing but a
/// tally.
///
/// One walk writes both, which is what keeps a stated length and the bytes
/// behind it from drifting apart.
trait Sink {
    /// Take `bytes`, or refuse where there is no room for them.
    fn put(&mut self, bytes: &[u8]) -> Result<(), NoRoom>;

    fn put_u8(&mut self, value: u8) -> Result<(), NoRoom> {
        self.put(&[value])
    }

    fn put_u16(&mut self, value: u16) -> Result<(), NoRoom> {
        self.put(&value.to_be_bytes())
    }

    fn put_u64(&mut self, value: u64) -> Result<(), NoRoom> {
        self.put(&value.to_be_bytes())
    }
}

/// The sink ran out. It carries nothing, and there is nothing for it to carry:
/// the one thing that can go wrong is the caller's capacity, which the caller
/// knows.
struct NoRoom;

/// A caller's output and how much of it has been filled.
struct Filled<'out> {
    out: &'out mut [u8],
    at: usize,
}

impl Sink for Filled<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), NoRoom> {
        let end = self.at.checked_add(bytes.len()).ok_or(NoRoom)?;
        // The range's own length is `bytes.len()`, so the copy below is between
        // two runs of equal length by construction.
        let room = self.out.get_mut(self.at..end).ok_or(NoRoom)?;
        room.copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }
}

/// A tally, which accepts everything.
struct Counted {
    len: usize,
}

impl Sink for Counted {
    fn put(&mut self, bytes: &[u8]) -> Result<(), NoRoom> {
        // Saturating rather than checked: this counts a length that is about to
        // be compared against a bound far below `usize::MAX`, so a count that
        // stops rising is a count that still fails that comparison.
        self.len = self.len.saturating_add(bytes.len());
        Ok(())
    }
}

/// Bytes `frame` occupies on the wire, header included.
///
/// The length a caller sizes its output by. For a frame whose payload is past
/// [`MAX_PAYLOAD_LEN`] this is the length it *would* occupy; [`encode`] refuses
/// such a frame rather than writing it.
#[must_use]
pub fn encoded_len(frame: &Frame<'_>) -> usize {
    HEADER_LEN.saturating_add(payload_len(frame))
}

/// Bytes of payload `frame` carries, counted by the walk that writes it.
fn payload_len(frame: &Frame<'_>) -> usize {
    let mut counted = Counted { len: 0 };
    // Cannot fail: a tally accepts every byte.
    let _ = write_payload(frame, &mut counted);
    counted.len
}

/// Write `frame` into the front of `out` as `sender`, answering its length.
///
/// # Errors
/// [`EncodeRefusal`], one variant per way a frame is not one this end can put on
/// the wire. Nothing is written on any of those paths.
pub fn encode(sender: Side, frame: &Frame<'_>, out: &mut [u8]) -> Result<usize, EncodeRefusal> {
    let kind = frame.frame_type();
    // Direction first, because it is the question about the frame rather than
    // about its contents — and for a greeting it is also the question of which
    // of the two shapes this end has any business sending.
    let travels = match frame {
        Frame::Hello(hello) => hello.side() == sender,
        _ => kind.may_travel_from(sender),
    };
    if !travels {
        return Err(EncodeRefusal::WrongDirection {
            frame: kind,
            sender,
        });
    }
    // Then the three contradictions the types leave expressible. Each has the
    // decoder's matching violation on the other side, so a frame this refuses is
    // exactly a frame the far end would have closed the connection over.
    match frame {
        Frame::DownConfigStage { document } if document.len() > MAX_DOCUMENT_BYTES => {
            return Err(EncodeRefusal::ConfigDocumentTooLong {
                len: document.len(),
            });
        }
        Frame::UpConfigValidateResult { line } => {
            if line.is_empty() {
                return Err(EncodeRefusal::EmptyResultLine);
            }
            if let Some((at, byte)) = first_unprintable(line) {
                return Err(EncodeRefusal::ResultLineNotPrintable { at, byte });
            }
        }
        Frame::UpRangeData { status, bytes, .. }
            if status.ends_the_answer() && !bytes.is_empty() =>
        {
            return Err(EncodeRefusal::BytesOnEndedRange {
                status: *status,
                len: bytes.len(),
            });
        }
        _ => {}
    }
    let payload = payload_len(frame);
    // The bound and the header's own field width in one step: a length past
    // either is a frame that cannot be described by a header of this protocol.
    let stated = match u32::try_from(payload) {
        Ok(stated) if payload <= MAX_PAYLOAD_LEN => stated,
        _ => return Err(EncodeRefusal::PayloadTooLong { len: payload }),
    };
    let needed = HEADER_LEN.saturating_add(payload);
    let room = out.len();
    // The room is settled before a byte is written, so a refusal leaves the
    // caller's output untouched: half a frame on a length-prefixed stream is
    // worse than none, and a caller that ignored the refusal would put one there.
    let Some((header, rest)) = out.split_first_chunk_mut::<HEADER_LEN>() else {
        return Err(EncodeRefusal::OutputTooSmall { needed, room });
    };
    let Some(slot) = rest.get_mut(..payload) else {
        return Err(EncodeRefusal::OutputTooSmall { needed, room });
    };
    let mut filled = Filled { out: slot, at: 0 };
    if write_payload(frame, &mut filled).is_err() {
        return Err(EncodeRefusal::OutputTooSmall { needed, room });
    }
    let [length_0, length_1, length_2, length_3] = stated.to_be_bytes();
    // Written last, so a refused payload leaves no header claiming a frame
    // follows it. The three reserved bytes are zero here and nowhere else in
    // this crate is a nonzero one written.
    *header = [
        length_0,
        length_1,
        length_2,
        length_3,
        kind.to_byte(),
        0,
        0,
        0,
    ];
    Ok(needed)
}

/// The walk both [`encode`] and [`payload_len`] run: every payload field, in
/// order, big-endian.
fn write_payload(frame: &Frame<'_>, sink: &mut impl Sink) -> Result<(), NoRoom> {
    match frame {
        Frame::Hello(Hello::Appliance) => sink.put_u16(VERSION),
        Frame::Hello(Hello::Server { log, capture }) => {
            sink.put_u16(VERSION)?;
            sink.put_u64(*log)?;
            sink.put_u64(*capture)
        }
        Frame::UpRecords { position, bytes } | Frame::UpCapture { position, bytes } => {
            sink.put_u64(*position)?;
            sink.put(bytes)
        }
        Frame::Ack { log, capture } => {
            sink.put_u64(*log)?;
            sink.put_u64(*capture)
        }
        Frame::DownConfigStage { document } => sink.put(document),
        Frame::UpConfigValidateResult { line } => sink.put(line),
        Frame::DownConfigCommit {
            generation,
            confirm_deadline_secs,
        } => {
            sink.put_u64(*generation)?;
            sink.put_u16(*confirm_deadline_secs)
        }
        Frame::DownCommitConfirm { generation } => sink.put_u64(*generation),
        Frame::DownRangeRead {
            ring,
            start,
            length,
        } => {
            sink.put_u8(ring.to_byte())?;
            sink.put_u64(*start)?;
            sink.put_u64(*length)
        }
        Frame::UpRangeData {
            ring,
            status,
            position,
            bytes,
        } => {
            sink.put_u8(ring.to_byte())?;
            sink.put_u8(status.to_byte())?;
            sink.put_u64(*position)?;
            sink.put(bytes)
        }
    }
}

/// The first byte of `line` that is not a printable ASCII character, and where.
fn first_unprintable(line: &[u8]) -> Option<(usize, u8)> {
    line.iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| !(FIRST_PRINTABLE..=LAST_PRINTABLE).contains(byte))
}

/// What one look at a decoder found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "a frame nothing looks at is a frame the peer sent for nothing"]
pub enum Decoded<'held> {
    /// Nothing whole yet. More bytes are needed, and where none are coming the
    /// session is simply over with a frame half-arrived.
    Partial,
    /// One frame, borrowed out of the decoder's own reassembly buffer. It is
    /// dropped — and the buffer emptied — by the next call on the decoder, so a
    /// caller keeps what it needs and not the frame.
    Frame(Frame<'held>),
    /// The peer broke a rule of the protocol. The connection closes and nothing
    /// else happens: the decoder answers this and only this from here on, since
    /// a stream whose framing is wrong has no next frame to find.
    Violated(Violation),
}

/// The peer's byte stream, one frame at a time.
///
/// # The megabyte is the caller's, and the type says exactly how big
///
/// A frame carries up to [`MAX_PAYLOAD_LEN`], so reassembling one needs
/// [`MAX_FRAME_LEN`] of somewhere to put it. That somewhere is **borrowed**:
/// `&mut [u8; MAX_FRAME_LEN]`, exactly sized by the type, so there is no runtime
/// length to check and no way to hand over a buffer that is nearly big enough. A
/// protection domain places it where it places every other region of that order
/// — its own static storage — and a test places it on a heap; either way this
/// crate owns no allocator and asks for none, and how much memory the framing
/// costs is a constant of the protocol rather than something a peer's lengths
/// decide.
///
/// The borrow lasts the decoder's whole life, which is what makes one buffer and
/// one decoder a pairing the type keeps rather than a rule a caller does: there
/// is no second call that could be handed a different buffer, and nothing else
/// can read the buffer while a decoder holds it.
///
/// # One frame's worth, and never two
///
/// [`Self::absorb`] takes no byte past the end of the frame it is assembling, so
/// the buffer holds a prefix of exactly one frame at every instant. That is what
/// makes handing a completed frame out as a borrow both safe and cheap: there is
/// nothing behind it to preserve, so dropping it empties the buffer rather than
/// copying a megabyte down it.
///
/// It is also what bounds the peer. A header stating a payload past the bound is
/// refused before a single byte behind it is taken, so no length a peer invents
/// makes this end hold anything.
pub struct FrameDecoder<'buf> {
    /// Which end's frames these are. Fixed for the life of the decoder: a
    /// connection has two ends and neither becomes the other.
    sender: Side,
    /// The frame in progress: its header, and as much of its payload as has
    /// arrived.
    held: &'buf mut [u8; MAX_FRAME_LEN],
    held_len: usize,
    /// Whether the frame at the front of `held` was handed out and is to be
    /// dropped before anything else happens.
    handed: bool,
    /// Whether a frame has been decoded in this direction yet. The whole of what
    /// makes "the first frame is the greeting" a rule this end enforces.
    greeted: bool,
    /// The rule the peer broke, once it has broken one.
    violation: Option<Violation>,
}

impl<'buf> FrameDecoder<'buf> {
    /// A decoder for the frames `sender` sends, reassembling them in `held`: on
    /// an appliance, [`Side::Server`].
    ///
    /// Whatever `held` already contains is ignored and overwritten as bytes
    /// arrive, so a buffer reused across connections carries nothing of the last
    /// one into the next.
    #[must_use]
    pub const fn new(sender: Side, held: &'buf mut [u8; MAX_FRAME_LEN]) -> Self {
        Self {
            sender,
            held,
            held_len: 0,
            handed: false,
            greeted: false,
            violation: None,
        }
    }

    /// Take as much of `bytes` as the frame in progress still needs, answering
    /// how many were taken.
    ///
    /// Never more than that: the rest of `bytes` belongs to frames after this
    /// one and stays with the caller, so the caller advances by the answer and
    /// comes back. Zero means either that `bytes` is empty, that a whole frame
    /// is waiting to be taken by [`Self::next_frame`], or that the peer has
    /// already broken the protocol and nothing more will be read from it.
    ///
    /// The pair terminates: while a frame is incomplete and `bytes` is not
    /// empty, this takes at least one byte.
    pub fn absorb(&mut self, bytes: &[u8]) -> usize {
        self.discard();
        if self.violation.is_some() {
            return 0;
        }
        let mut took = 0;
        // Two steps at most, and that is the whole of the loop: the first
        // completes the header, and only a complete header says how long the
        // payload behind it is. A third step could only follow a length this end
        // has already refused.
        for _ in 0..2 {
            let step = self.take(bytes.get(took..).unwrap_or_default());
            if step == 0 {
                break;
            }
            took = took.saturating_add(step);
        }
        took
    }

    /// Take as much of `bytes` as the frame in progress wants *right now*, which
    /// is a header's worth until there is a header.
    fn take(&mut self, bytes: &[u8]) -> usize {
        let wanted = self.wanted().saturating_sub(self.held_len);
        let Some(room) = self.held.get_mut(self.held_len..) else {
            return 0;
        };
        let mut took = 0;
        // `zip` walks the shorter of the three bounds — what the frame still
        // wants, what the buffer has left, and what the caller offered — so no
        // index is taken and no length is trusted.
        for (cell, byte) in room.iter_mut().take(wanted).zip(bytes) {
            *cell = *byte;
            took += 1;
        }
        self.held_len = self.held_len.saturating_add(took);
        took
    }

    /// Look once at what has accumulated.
    ///
    /// Drops the frame the previous call handed out, so a caller loops on
    /// [`Self::absorb`] and this without a third call between them.
    pub fn next_frame(&mut self) -> Decoded<'_> {
        self.discard();
        if let Some(violation) = self.violation {
            return Decoded::Violated(violation);
        }
        let Some(header) = self.header() else {
            return Decoded::Partial;
        };
        let (frame_type, len) = match read_header(&header, self.sender, self.greeted) {
            Ok(read) => read,
            Err(violation) => return self.violated(violation),
        };
        let end = HEADER_LEN.saturating_add(len);
        if self.held_len < end {
            return Decoded::Partial;
        }
        let sender = self.sender;
        let Some(payload) = self.held.get(HEADER_LEN..end) else {
            return Decoded::Partial;
        };
        // From here on the payload is borrowed, so the two mutations below reach
        // the decoder's other fields by name rather than through a method: a
        // frame handed out borrows this buffer for as long as the caller holds
        // it.
        match decode_payload(frame_type, sender, payload) {
            Ok(frame) => {
                self.greeted = true;
                self.handed = true;
                Decoded::Frame(frame)
            }
            Err(violation) => {
                self.violation = Some(violation);
                Decoded::Violated(violation)
            }
        }
    }

    /// The rule the peer broke, once it has broken one.
    #[must_use]
    pub const fn violation(&self) -> Option<Violation> {
        self.violation
    }

    /// Whether a greeting has been decoded in this direction.
    #[must_use]
    pub const fn greeted(&self) -> bool {
        self.greeted
    }

    /// Bytes of a frame currently held, which is at most one frame's worth.
    #[must_use]
    pub const fn held(&self) -> usize {
        self.held_len
    }

    /// The header of the frame in progress, once the whole of it has arrived.
    ///
    /// Answered **by value**, which is what lets the checks over it run while the
    /// buffer is free to be written and read: eight bytes copied out beats a
    /// borrow that has to be released before anything happens.
    fn header(&self) -> Option<[u8; HEADER_LEN]> {
        if self.held_len < HEADER_LEN {
            return None;
        }
        self.held.first_chunk::<HEADER_LEN>().copied()
    }

    /// Bytes the frame in progress needs before it is whole.
    ///
    /// A header's worth until there is a header, then what the header states —
    /// and a header's worth again where the header is one this end refuses. That
    /// last case is the load-bearing one: **nothing behind a header that has
    /// already lost the connection is ever taken**, so a peer cannot pace this
    /// end into holding a mebibyte on the strength of a length, a type byte or a
    /// direction it will be refused for.
    fn wanted(&self) -> usize {
        let Some(header) = self.header() else {
            return HEADER_LEN;
        };
        match read_header(&header, self.sender, self.greeted) {
            Ok((_, len)) => HEADER_LEN.saturating_add(len),
            Err(_) => HEADER_LEN,
        }
    }

    /// Empty the buffer where the frame in it has been handed out.
    ///
    /// A whole frame and nothing behind it, so this is an assignment rather than
    /// a move: [`Self::absorb`] never took a byte past its end.
    fn discard(&mut self) {
        if self.handed {
            self.handed = false;
            self.held_len = 0;
        }
    }

    fn violated(&mut self, violation: Violation) -> Decoded<'_> {
        self.violation = Some(violation);
        Decoded::Violated(violation)
    }
}

/// What a complete header names: the frame and its payload's length, or the rule
/// the header broke.
///
/// Read in the order the protocol lists its violations, and the order matters
/// only where a header breaks several rules at once — each cause has a value of
/// its own, so what the order decides is which of them an operator is sent after
/// first.
///
/// One function, called from two places, and that is the point: the decoder asks
/// it what a frame *is*, and asks it again to decide how many bytes to take. A
/// second copy of these checks would be a header this end refused after holding a
/// mebibyte on the strength of it.
fn read_header(
    header: &[u8; HEADER_LEN],
    sender: Side,
    greeted: bool,
) -> Result<(FrameType, usize), Violation> {
    let [
        length_0,
        length_1,
        length_2,
        length_3,
        kind,
        reserved_0,
        reserved_1,
        reserved_2,
    ] = *header;
    // The reserved bytes first. They are the one part of a header that carries no
    // meaning to get wrong, so a nonzero one says the peer is not speaking this
    // protocol rather than speaking it badly — and that sends an operator
    // somewhere entirely different from every refusal below.
    if reserved_0 != 0 {
        return Err(Violation::ReservedNonZero {
            at: 0,
            byte: reserved_0,
        });
    }
    if reserved_1 != 0 {
        return Err(Violation::ReservedNonZero {
            at: 1,
            byte: reserved_1,
        });
    }
    if reserved_2 != 0 {
        return Err(Violation::ReservedNonZero {
            at: 2,
            byte: reserved_2,
        });
    }
    let frame = FrameType::from_byte(kind).ok_or(Violation::UnknownType { byte: kind })?;
    let stated = u32::from_be_bytes([length_0, length_1, length_2, length_3]);
    let len = stated as usize;
    if len > MAX_PAYLOAD_LEN {
        return Err(Violation::PayloadTooLong { stated });
    }
    if !frame.may_travel_from(sender) {
        return Err(Violation::WrongDirection { frame, sender });
    }
    if !greeted && frame != FrameType::Hello {
        return Err(Violation::FirstFrameNotHello { frame });
    }
    // The one frame with a length bound of its own, and it is read off the header
    // for the same reason the frame bound is: a document past its bound is
    // refused before a byte of it is held, so a peer cannot make this end buffer
    // a mebibyte for a stage that would take a sixteenth of it.
    if frame == FrameType::DownConfigStage && len > MAX_DOCUMENT_BYTES {
        return Err(Violation::ConfigDocumentTooLong { len });
    }
    Ok((frame, len))
}

/// One payload's fields, in order, or the rule its bytes broke.
///
/// Every field is read through a total function, so a payload that runs out
/// mid-field is [`Violation::PayloadLength`] and never a panic — and the same
/// refusal covers trailing bytes on a frame with nothing variable in it, both
/// being "the payload is not this frame's shape". The refusals with a cause of
/// their own are raised where they are found, which is why they are read in
/// field order rather than checked up front: a selector byte that names no ring
/// is a more useful answer than the length of a payload that also happens to be
/// short.
fn decode_payload<'held>(
    frame: FrameType,
    sender: Side,
    payload: &'held [u8],
) -> Result<Frame<'held>, Violation> {
    let shape = || Violation::PayloadLength {
        frame,
        len: payload.len(),
        needed: frame.payload_floor(sender),
    };
    match frame {
        FrameType::Hello => {
            let (version, rest) = u16_at(payload).ok_or_else(shape)?;
            // Before the rest of the shape is judged. A peer speaking another
            // version has another greeting too, so "your version is not mine"
            // is the answer that sends somebody to an update, where "your
            // payload is the wrong length" would send them looking for a
            // corrupted frame.
            if version != VERSION {
                return Err(Violation::VersionMismatch { theirs: version });
            }
            match sender {
                Side::Appliance => {
                    if !rest.is_empty() {
                        return Err(shape());
                    }
                    Ok(Frame::Hello(Hello::Appliance))
                }
                Side::Server => {
                    let (log, rest) = u64_at(rest).ok_or_else(shape)?;
                    let (capture, rest) = u64_at(rest).ok_or_else(shape)?;
                    if !rest.is_empty() {
                        return Err(shape());
                    }
                    Ok(Frame::Hello(Hello::Server { log, capture }))
                }
            }
        }
        FrameType::UpRecords => {
            let (position, bytes) = u64_at(payload).ok_or_else(shape)?;
            Ok(Frame::UpRecords { position, bytes })
        }
        FrameType::UpCapture => {
            let (position, bytes) = u64_at(payload).ok_or_else(shape)?;
            Ok(Frame::UpCapture { position, bytes })
        }
        FrameType::Ack => {
            let (log, rest) = u64_at(payload).ok_or_else(shape)?;
            let (capture, rest) = u64_at(rest).ok_or_else(shape)?;
            if !rest.is_empty() {
                return Err(shape());
            }
            Ok(Frame::Ack { log, capture })
        }
        // The document's own bound was read off the header, so what arrives here
        // is a document of an admissible length and every byte of it is the
        // configuration stage's to judge.
        FrameType::DownConfigStage => Ok(Frame::DownConfigStage { document: payload }),
        FrameType::UpConfigValidateResult => {
            if payload.is_empty() {
                return Err(shape());
            }
            if let Some((at, byte)) = first_unprintable(payload) {
                return Err(Violation::ResultLineNotPrintable { at, byte });
            }
            Ok(Frame::UpConfigValidateResult { line: payload })
        }
        FrameType::DownConfigCommit => {
            let (generation, rest) = u64_at(payload).ok_or_else(shape)?;
            let (confirm_deadline_secs, rest) = u16_at(rest).ok_or_else(shape)?;
            if !rest.is_empty() {
                return Err(shape());
            }
            Ok(Frame::DownConfigCommit {
                generation,
                confirm_deadline_secs,
            })
        }
        FrameType::DownCommitConfirm => {
            let (generation, rest) = u64_at(payload).ok_or_else(shape)?;
            if !rest.is_empty() {
                return Err(shape());
            }
            Ok(Frame::DownCommitConfirm { generation })
        }
        FrameType::DownRangeRead => {
            let (selector, rest) = u8_at(payload).ok_or_else(shape)?;
            let ring =
                Ring::from_byte(selector).ok_or(Violation::UnknownRing { byte: selector })?;
            let (start, rest) = u64_at(rest).ok_or_else(shape)?;
            let (length, rest) = u64_at(rest).ok_or_else(shape)?;
            if !rest.is_empty() {
                return Err(shape());
            }
            // The two numbers are carried and judged nowhere here: what a
            // position means is the ring's, and an extent past its head or
            // behind its tail is answered with the status that says which, by
            // the reader that has the geometry.
            Ok(Frame::DownRangeRead {
                ring,
                start,
                length,
            })
        }
        FrameType::UpRangeData => {
            let (selector, rest) = u8_at(payload).ok_or_else(shape)?;
            let ring =
                Ring::from_byte(selector).ok_or(Violation::UnknownRing { byte: selector })?;
            let (code, rest) = u8_at(rest).ok_or_else(shape)?;
            let status =
                RangeStatus::from_byte(code).ok_or(Violation::UnknownRangeStatus { byte: code })?;
            let (position, bytes) = u64_at(rest).ok_or_else(shape)?;
            if status.ends_the_answer() && !bytes.is_empty() {
                return Err(Violation::BytesOnEndedRange {
                    status,
                    len: bytes.len(),
                });
            }
            Ok(Frame::UpRangeData {
                ring,
                status,
                position,
                bytes,
            })
        }
    }
}

/// The byte at the front of `bytes`, and what follows it.
fn u8_at(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let (head, rest) = bytes.split_first()?;
    Some((*head, rest))
}

/// The big-endian `u16` at the front of `bytes`, and what follows it.
fn u16_at(bytes: &[u8]) -> Option<(u16, &[u8])> {
    let (head, rest) = bytes.split_first_chunk::<2>()?;
    Some((u16::from_be_bytes(*head), rest))
}

/// The big-endian `u64` at the front of `bytes`, and what follows it.
fn u64_at(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (head, rest) = bytes.split_first_chunk::<8>()?;
    Some((u64::from_be_bytes(*head), rest))
}
