//! The fixed-layout log record a writing domain hands the console domain, and
//! the decode that turns peer-written bytes back into one.
//!
//! Faces the byzantine neighbour protection domain. The console maps
//! a region a writing domain also maps, so every byte of a record it reads was
//! chosen by another domain: the discriminants that say which fields mean
//! anything, the tokens that name a vocabulary, and the text that reaches a
//! console line.
//!
//! This is `lfw_log::Event` as POD and deliberately not that type. `wire`
//! depends on nothing, so a record cannot hold an `Identifier`, a `Value` or a
//! `&'static str`; the vocabularies cross as integers and the text as fixed
//! arrays, and the log crate owns the mapping in both directions. The
//! alternative would be `wire` depending on `log`, which reverses the direction
//! the dependency already runs in: `log` is where a region's bytes are turned
//! into an event, and a layout defined in terms of its own consumer is a cycle
//! rather than an ABI.
//!
//! Where the split of responsibility falls, and why it falls there:
//!
//! * **Record shape is this crate's.** Which variant a record is, which detail
//!   it carries, how many operands that detail names, and which kind a value
//!   slot holds are all statements about what the other bytes *mean*, so an
//!   undecodable one is refused here rather than passed on.
//! * **Text is this crate's**, because the console writes it to a UART. A byte
//!   a hostile writer put in an identifier reaches an operator's terminal
//!   unless something between the two refuses it, and this decode is that
//!   something. `lfw_log::Identifier` checks the same alphabet on the
//!   way in; the two checks face different adversaries and neither stands in
//!   for the other.
//! * **Vocabulary cardinality is shared.** A token is bounded here by the
//!   `LOG_*_COUNT` consts and mapped to a variant there, so a variant added to
//!   a console vocabulary moves its count here in the same change.

use core::{
    fmt,
    mem::{align_of, offset_of, size_of},
    num::NonZeroU64,
};

/// Bytes an identifier occupies in a record, and so the longest one that
/// crosses. Equal to `lfw_log::MAX_IDENTIFIER_LEN` by construction: the log
/// crate asserts the two agree, because a record that cannot carry the longest
/// identifier the configuration schema admits would drop one silently.
pub const LOG_IDENTIFIER_BYTES: usize = 16;

/// As [`LOG_IDENTIFIER_BYTES`], for the refusal cause token, against
/// `lfw_log::MAX_CAUSE_LEN`.
pub const LOG_CAUSE_BYTES: usize = 40;

/// How many protection domains a record may name — `lfw_log::Domain::ALL`.
pub const LOG_DOMAIN_COUNT: u8 = 10;

/// How many of [`LogRecord::operands`] a detail may name.
///
/// Four rather than two because a 256-bit digest is the widest single value any
/// surface renders: an appliance's public-key fingerprint is compared character
/// for character by an administrator, so it crosses whole and is rendered as one
/// field. Splitting it over two records would make the administrator concatenate
/// before comparing, which is exactly the second rendering the certificate
/// profile refuses.
pub const LOG_OPERANDS: usize = 4;

/// How many cryptographic primitives a record may name —
/// `lfw_log::Primitive::ALL`. A token rather than a name on the wire, on
/// `LOG_DOMAIN_COUNT`'s terms: the console spells it, the region carries an
/// index, and a value outside the set is refused rather than rendered as a
/// number an operator would have to look up.
pub const LOG_PRIMITIVE_COUNT: u8 = 10;

/// How many outcomes a dialled connection may report —
/// `lfw_log::DialOutcome::ALL`, carried as a token for
/// [`LOG_PRIMITIVE_COUNT`]'s reason.
pub const LOG_DIAL_OUTCOME_COUNT: u8 = 13;

/// How many ways a next hop may have been chosen — `lfw_log::NextHopVia::ALL`,
/// on [`LOG_DIAL_OUTCOME_COUNT`]'s terms.
pub const LOG_NEXT_HOP_VIA_COUNT: u8 = 3;

/// Lifecycle points a domain reports — `lfw_log::DomainState::ALL`.
pub const LOG_DOMAIN_STATE_COUNT: u8 = 4;

/// `lfw_log::ChangeKind::ALL`.
pub const LOG_CHANGE_KIND_COUNT: u8 = 3;

/// `lfw_log::ObjectKind::ALL`.
pub const LOG_OBJECT_KIND_COUNT: u8 = 4;

/// `lfw_log::Field::ALL`.
pub const LOG_FIELD_COUNT: u8 = 18;

/// `lfw_log::GenerationOutcome::ALL`.
pub const LOG_GENERATION_OUTCOME_COUNT: u8 = 3;

/// `lfw_log::RejectReason::ALL`.
pub const LOG_REJECT_REASON_COUNT: u8 = 38;

/// Whether a record's instant is one or is the absence of one.
///
/// A discriminant rather than a reserved value of [`LogRecord::stamp_nanos`]:
/// zero is a real instant, so a sentinel would date 1970 every record emitted
/// before this node established a time — most of a boot transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogStampKind {
    Unsynchronized,
    Utc,
}

impl LogStampKind {
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::Unsynchronized => 0,
            Self::Utc => 1,
        }
    }

    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::Unsynchronized),
            1 => Some(Self::Utc),
            _ => None,
        }
    }
}

/// Which shape a [`LogRecord`] is, and so which of its fields name anything.
///
/// One variant per `lfw_log::Event` variant. Unlike the vocabularies, this is
/// not a token this crate merely bounds: the decode below reads different
/// fields for each, so a value with no variant is a record nothing can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogKind {
    Domain,
    ConfigChange,
    ConfigGeneration,
    ConfigRejected,
}

impl LogKind {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Domain => 0,
            Self::ConfigChange => 1,
            Self::ConfigGeneration => 2,
            Self::ConfigRejected => 3,
        }
    }

    /// `None` for every other bit pattern, on [`crate::Verdict::from_bits`]'s
    /// terms: the field is peer-written, so an undecodable value is input to
    /// reject rather than one to coerce.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Domain),
            1 => Some(Self::ConfigChange),
            2 => Some(Self::ConfigGeneration),
            3 => Some(Self::ConfigRejected),
            _ => None,
        }
    }
}

/// What a [`LogKind::Domain`] record carries beyond its own state —
/// `lfw_log::DomainDetail` without the payloads, which live in the record's
/// own fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogDetailKind {
    None,
    Features,
    ReceivePosted,
    Refusal,
    Established,
    Received,
    Medium,
    Extent,
    Proven,
    Proved,
    Measured,
    Session,
    Exchange,
    Peer,
    Arena,
    Operation,
    /// Appended, never inserted: a discriminant is the ABI, and one placed among
    /// the existing values would re-read every record a peer already wrote.
    Identity,
    Fingerprint,
    Reset,
    Delegated,
    Dialled,
    /// The three that follow a [`Self::Dialled`] naming a channel that failed.
    /// Appended, never inserted, on [`Self::Identity`]'s terms — and three
    /// discriminants rather than one wider operand array, because widening that
    /// array grows every log region by a page and would still not carry these
    /// facts in one record.
    DialRoute,
    DialUnlearned,
    DialSegments,
    /// The fourth, which only an unacceptable acknowledgement produces.
    DialSequence,
}

impl LogDetailKind {
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Features => 1,
            Self::ReceivePosted => 2,
            Self::Refusal => 3,
            Self::Established => 4,
            Self::Received => 5,
            Self::Medium => 6,
            Self::Extent => 7,
            Self::Proven => 8,
            Self::Proved => 9,
            Self::Measured => 10,
            Self::Session => 11,
            Self::Exchange => 12,
            Self::Peer => 13,
            Self::Arena => 14,
            Self::Operation => 15,
            Self::Identity => 16,
            Self::Fingerprint => 17,
            Self::Reset => 18,
            Self::Delegated => 19,
            Self::Dialled => 20,
            Self::DialRoute => 21,
            Self::DialUnlearned => 22,
            Self::DialSegments => 23,
            Self::DialSequence => 24,
        }
    }

    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::None),
            1 => Some(Self::Features),
            2 => Some(Self::ReceivePosted),
            3 => Some(Self::Refusal),
            4 => Some(Self::Established),
            5 => Some(Self::Received),
            6 => Some(Self::Medium),
            7 => Some(Self::Extent),
            8 => Some(Self::Proven),
            9 => Some(Self::Proved),
            10 => Some(Self::Measured),
            11 => Some(Self::Session),
            12 => Some(Self::Exchange),
            13 => Some(Self::Peer),
            14 => Some(Self::Arena),
            15 => Some(Self::Operation),
            16 => Some(Self::Identity),
            17 => Some(Self::Fingerprint),
            18 => Some(Self::Reset),
            19 => Some(Self::Delegated),
            20 => Some(Self::Dialled),
            21 => Some(Self::DialRoute),
            22 => Some(Self::DialUnlearned),
            23 => Some(Self::DialSegments),
            24 => Some(Self::DialSequence),
            _ => None,
        }
    }
}

/// Which `lfw_log::Value` a [`ValueImage`] holds, with [`Self::Absent`] for the
/// `None` a `from`/`to` slot may be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogValueKind {
    Absent,
    Port,
    Ipv4,
    Mac,
    PrefixLength,
    Bool,
    Generation,
    Count,
    Id,
    /// A filter rule's match criterion as its own token, in `id`.
    Selector,
    /// A filter rule's address criterion: the block's network in the first four
    /// `octets` and its prefix length in `number`.
    Prefix,
}

impl LogValueKind {
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::Absent => 0,
            Self::Port => 1,
            Self::Ipv4 => 2,
            Self::Mac => 3,
            Self::PrefixLength => 4,
            Self::Bool => 5,
            Self::Generation => 6,
            Self::Count => 7,
            Self::Id => 8,
            Self::Selector => 9,
            Self::Prefix => 10,
        }
    }

    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::Absent),
            1 => Some(Self::Port),
            2 => Some(Self::Ipv4),
            3 => Some(Self::Mac),
            4 => Some(Self::PrefixLength),
            5 => Some(Self::Bool),
            6 => Some(Self::Generation),
            7 => Some(Self::Count),
            8 => Some(Self::Id),
            9 => Some(Self::Selector),
            10 => Some(Self::Prefix),
            _ => None,
        }
    }
}

/// Which text field of a record an error or a decoded value belongs to, so a
/// refusal is attributable to a position rather than to a category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogText {
    /// The object key of a [`LogKind::ConfigChange`].
    Key,
    /// The `from` value of a [`LogKind::ConfigChange`].
    From,
    /// Its `to` value.
    To,
    /// The refusal cause token of a [`LogDetailKind::Refusal`].
    Cause,
}

impl fmt::Display for LogText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Key => "key",
            Self::From => "from",
            Self::To => "to",
            Self::Cause => "cause",
        })
    }
}

/// Text in a record: `N` bytes of storage and how many of them are the value.
/// The padding is explicit rather than implied, so these offsets are the ones a
/// writer in another language computes for the same declaration.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextImage<const N: usize> {
    /// The value in `bytes[..len]`. Peer-written, so the alphabet is what
    /// [`LogRecord::check`] holds it to rather than a property it arrives with.
    pub bytes: [u8; N],
    /// How many of `bytes` are the value, as raw bits: it may name more than
    /// the array holds.
    pub len: u8,
    pub _pad: [u8; 3],
}

impl<const N: usize> TextImage<N> {
    pub const ZERO: Self = Self {
        bytes: [0; N],
        len: 0,
        _pad: [0; 3],
    };

    /// Lay `text` out as this image carries it. The copy is bounded by the array
    /// and the length narrows saturatingly, so text this image cannot carry
    /// produces a length [`check_bounded_text`] refuses rather than one that
    /// indexes past the bytes.
    #[must_use]
    pub fn from_text(text: &[u8]) -> Self {
        let mut image = Self::ZERO;
        for (slot, &byte) in image.bytes.iter_mut().zip(text) {
            *slot = byte;
        }
        image.len = u8::try_from(text.len()).unwrap_or(u8::MAX);
        image
    }

    /// Fold every byte of this image into `hash`, for the digest a declared
    /// image carries an `identifier` field into.
    pub(crate) fn fold(&self, hash: u32) -> u32 {
        let hash = crate::image::fold_bytes(hash, &self.bytes);
        let hash = crate::image::fold_bytes(hash, &[self.len]);
        crate::image::fold_bytes(hash, &self._pad)
    }
}

/// An identifier as it crosses: a configuration object's stable name.
pub type IdentifierImage = TextImage<LOG_IDENTIFIER_BYTES>;

/// A refusal cause token as it crosses.
pub type CauseImage = TextImage<LOG_CAUSE_BYTES>;

/// One optional `lfw_log::Value` as it crosses.
///
/// One shape for every variant rather than a union, because a union in shared
/// memory is a second reading of the same bytes and the writer picks which one
/// applies.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueImage {
    /// The numeric payload of [`LogValueKind::Port`],
    /// [`LogValueKind::PrefixLength`], [`LogValueKind::Bool`],
    /// [`LogValueKind::Generation`], [`LogValueKind::Count`] and the prefix
    /// length of [`LogValueKind::Prefix`]. All but two are narrower than the
    /// field, so a value that does not fit is refused.
    pub number: u32,
    /// Which [`LogValueKind`] this slot holds, as raw bits.
    pub kind: u8,
    /// The address of [`LogValueKind::Ipv4`] or the network of
    /// [`LogValueKind::Prefix`] in the first four bytes, or the address of
    /// [`LogValueKind::Mac`] in all six. Network order, as the address appears
    /// in a header.
    pub octets: [u8; 6],
    pub _pad: u8,
    /// The text of [`LogValueKind::Id`] and of [`LogValueKind::Selector`].
    pub id: IdentifierImage,
}

impl ValueImage {
    /// The absent value, which is what a `from` or `to` slot holds when the
    /// change added or removed the object.
    pub const ZERO: Self = Self {
        number: 0,
        kind: 0,
        octets: [0; 6],
        _pad: 0,
        id: IdentifierImage::ZERO,
    };
}

/// One `lfw_log::Event` as bytes in a shared region.
///
/// Every field is always present whatever the record says, so the record is one
/// fixed-size object: a ring slot is reserved once at build time and a variant
/// that fills it is the same shape as a variant that does not. A field the
/// record's [`LogKind`] does not name is read by nothing, so the bytes a peer
/// leaves there mean nothing — the same treatment the configuration image gives
/// the entries beyond its counts.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogRecord {
    /// The feature bits a driver and its device settled on, under
    /// [`LogDetailKind::Features`]. Which bit means what is `virtio`'s
    /// vocabulary and is not decoded anywhere on this path.
    pub features: u64,
    /// The numbers a detail names positionally: a refusal's, with
    /// `operand_count` saying how many are the value, or an extent's first
    /// sector and length. Shared, a record being one or the other, which keeps
    /// this ABI's size — and every log region — unchanged by a detail added.
    ///
    /// [`LOG_OPERANDS`] wide, which is what carries a 256-bit digest whole.
    /// Every detail below four words reads the words it names and leaves the rest
    /// as storage this record does not claim, the same treatment a refusal's
    /// `operand_count` already gave the second word.
    ///
    /// **A flag is always the fourth word.** Both details that carry one put it
    /// there — [`LogDetailKind::Identity`]'s owner flag and
    /// [`LogDetailKind::Reset`]'s — so this ABI has one rule for a boolean in an
    /// operand rather than one per detail, and one place a decode refuses a word
    /// that is neither 0 nor 1. It is the reason a detail's words are not always
    /// the leading run.
    pub operands: [u64; LOG_OPERANDS],
    /// The counter frequency in hertz, under [`LogDetailKind::Established`].
    /// Zero is refused: it is the divisor every later reading is scaled by.
    pub tsc_hz: u64,
    /// Nanoseconds since the Unix epoch, under the same detail, and unranged —
    /// every `u64` names a civil time, so believability is a reader's question.
    pub unix_nanos: u64,
    /// Frames a terminal endpoint has taken off its pipeline, under
    /// [`LogDetailKind::Received`], and unranged: it is the emitting domain's
    /// claim about itself, comparable only against an earlier such record.
    pub frames: u64,
    /// Bytes those frames carried. `frame_bytes` rather than `bytes` so it
    /// cannot read as a size of this record.
    pub frame_bytes: u64,
    /// Under [`LogDetailKind::Medium`]: a device's claimed capacity in 512-byte
    /// sectors, and the first eight bytes read off it — a number, not payload.
    pub capacity_sectors: u64,
    pub leading_word: u64,
    /// Nanoseconds since the Unix epoch at which the writing domain emitted
    /// this record, read by nothing unless `stamp_kind` says so.
    pub stamp_nanos: u64,
    /// Which [`LogKind`] this record is, as raw bits.
    pub kind: u32,
    /// The configuration generation of a [`LogKind::ConfigChange`],
    /// [`LogKind::ConfigGeneration`] or [`LogKind::ConfigRejected`].
    pub generation: u32,
    /// Position within the generation's records, for a
    /// [`LogKind::ConfigChange`]. Nothing is timestamped, so this and
    /// `generation` order a record and nothing else does.
    pub sequence: u32,
    /// How many values a [`LogKind::ConfigGeneration`] commit changed.
    pub changes: u32,
    /// Byte offset into the refused document, for a [`LogKind::ConfigRejected`].
    /// Named so it cannot read as a position in this record.
    pub reject_offset: u32,
    /// Receive descriptors primed before a driver entered its poll loop, under
    /// [`LogDetailKind::ReceivePosted`].
    pub receive_posted: u32,
    /// `lfw_log::Domain` as a token below [`LOG_DOMAIN_COUNT`].
    pub domain: u8,
    /// `lfw_log::DomainState` as a token below [`LOG_DOMAIN_STATE_COUNT`].
    pub state: u8,
    /// Which [`LogDetailKind`] a [`LogKind::Domain`] record carries, as raw bits.
    pub detail: u8,
    /// How many of `operands` a refusal names: 0, 1 or 2, and refused otherwise. A
    /// refusal names at most two even though the record holds [`LOG_OPERANDS`]:
    /// the console line's budget is the pair, and the wider storage exists for a
    /// digest rather than for a longer refusal.
    pub operand_count: u8,
    /// Whether the device was told to stop, or was left decoding nothing. 0 or
    /// 1 as raw bits, refused otherwise.
    pub signalled: u8,
    /// `lfw_log::ChangeKind` as a token below [`LOG_CHANGE_KIND_COUNT`].
    pub change: u8,
    /// `lfw_log::ObjectKind` as a token below [`LOG_OBJECT_KIND_COUNT`].
    pub object: u8,
    /// `lfw_log::Field` as a token below [`LOG_FIELD_COUNT`].
    pub field: u8,
    /// `lfw_log::GenerationOutcome` as a token below
    /// [`LOG_GENERATION_OUTCOME_COUNT`].
    pub outcome: u8,
    /// `lfw_log::RejectReason` as a token below [`LOG_REJECT_REASON_COUNT`].
    pub reason: u8,
    /// Which [`LogStampKind`] `stamp_nanos` is, as raw bits.
    pub stamp_kind: u8,
    /// Explicit rather than implied, so the whole record is fields.
    pub _pad: [u8; 5],
    /// What was refused, under [`LogDetailKind::Refusal`]. A literal on the
    /// writing side and arbitrary bytes on this one, so the decode holds it to
    /// the same alphabet an identifier is held to.
    pub cause: CauseImage,
    /// The changed object's stable name, for a [`LogKind::ConfigChange`].
    pub key: IdentifierImage,
    /// The value before the change. Absent exactly when the object was added.
    pub from: ValueImage,
    /// The value after it. Absent exactly when the object was removed.
    pub to: ValueImage,
}

impl LogRecord {
    /// A zeroed record, which is a [`LogKind::Domain`] one with no detail. A
    /// zeroed region is therefore already a well-formed slot, which is what
    /// lets a reader come up against one before anything has been written.
    pub const ZERO: Self = Self {
        features: 0,
        operands: [0; LOG_OPERANDS],
        tsc_hz: 0,
        unix_nanos: 0,
        frames: 0,
        frame_bytes: 0,
        capacity_sectors: 0,
        leading_word: 0,
        stamp_nanos: 0,
        kind: 0,
        generation: 0,
        sequence: 0,
        changes: 0,
        reject_offset: 0,
        receive_posted: 0,
        domain: 0,
        state: 0,
        detail: 0,
        operand_count: 0,
        signalled: 0,
        change: 0,
        object: 0,
        field: 0,
        outcome: 0,
        reason: 0,
        stamp_kind: 0,
        _pad: [0; 5],
        cause: CauseImage::ZERO,
        key: IdentifierImage::ZERO,
        from: ValueImage::ZERO,
        to: ValueImage::ZERO,
    };

    /// Decodes the instant and the fields this record's [`LogKind`] names,
    /// refusing it on the first one that cannot be a value.
    ///
    /// # Errors
    /// [`LogRecordError`], naming the field and the value that refused it.
    pub fn check(&self) -> Result<CheckedRecord, LogRecordError> {
        Ok(CheckedRecord {
            at: self.check_stamp()?,
            body: self.check_body()?,
        })
    }

    /// The instant, before any body field: a record whose stamp discriminant
    /// names neither case is one no line can be dated by, and a body rendered
    /// without one would silently read as having no time.
    fn check_stamp(&self) -> Result<CheckedStamp, LogRecordError> {
        match LogStampKind::from_bits(self.stamp_kind) {
            None => Err(LogRecordError::StampKindUnknown {
                kind: self.stamp_kind,
            }),
            Some(LogStampKind::Unsynchronized) => Ok(CheckedStamp::Unsynchronized),
            Some(LogStampKind::Utc) => Ok(CheckedStamp::Utc(self.stamp_nanos)),
        }
    }

    fn check_body(&self) -> Result<CheckedBody, LogRecordError> {
        match LogKind::from_bits(self.kind) {
            None => Err(LogRecordError::KindUnknown { kind: self.kind }),
            Some(LogKind::Domain) => self.check_domain(),
            Some(LogKind::ConfigChange) => self.check_config_change(),
            Some(LogKind::ConfigGeneration) => Ok(CheckedBody::ConfigGeneration {
                generation: self.generation,
                outcome: token(
                    self.outcome,
                    LOG_GENERATION_OUTCOME_COUNT,
                    LogRecordError::GenerationOutcomeUnknown {
                        outcome: self.outcome,
                    },
                )?,
                changes: self.changes,
            }),
            Some(LogKind::ConfigRejected) => Ok(CheckedBody::ConfigRejected {
                generation: self.generation,
                reason: token(
                    self.reason,
                    LOG_REJECT_REASON_COUNT,
                    LogRecordError::RejectReasonUnknown {
                        reason: self.reason,
                    },
                )?,
                offset: self.reject_offset,
            }),
        }
    }

    fn check_domain(&self) -> Result<CheckedBody, LogRecordError> {
        let domain = token(
            self.domain,
            LOG_DOMAIN_COUNT,
            LogRecordError::DomainUnknown {
                domain: self.domain,
            },
        )?;
        let state = token(
            self.state,
            LOG_DOMAIN_STATE_COUNT,
            LogRecordError::DomainStateUnknown { state: self.state },
        )?;
        let detail = match LogDetailKind::from_bits(self.detail) {
            None => {
                return Err(LogRecordError::DetailKindUnknown {
                    detail: self.detail,
                });
            }
            Some(LogDetailKind::None) => CheckedDetail::None,
            Some(LogDetailKind::Features) => CheckedDetail::Features(self.features),
            Some(LogDetailKind::ReceivePosted) => CheckedDetail::ReceivePosted(self.receive_posted),
            Some(LogDetailKind::Refusal) => CheckedDetail::Refusal {
                cause: check_text(&self.cause, LogText::Cause, true)?,
                operands: self.check_operands()?,
                signalled: boolean(self.signalled).ok_or(LogRecordError::SignalledNotBoolean {
                    signalled: self.signalled,
                })?,
            },
            Some(LogDetailKind::Established) => CheckedDetail::Established {
                tsc_hz: NonZeroU64::new(self.tsc_hz).ok_or(LogRecordError::ClockFrequencyZero)?,
                unix_nanos: self.unix_nanos,
            },
            // Nothing to refuse: every `u64` pair is a pair of counts, and
            // whether they are *plausible* counts is a question only a reader
            // holding an earlier record of the same pair can ask.
            Some(LogDetailKind::Received) => CheckedDetail::Received {
                frames: self.frames,
                bytes: self.frame_bytes,
            },
            // Nothing to refuse either: every bit pattern is one a medium makes.
            Some(LogDetailKind::Medium) => CheckedDetail::Medium {
                capacity_sectors: self.capacity_sectors,
                leading_word: self.leading_word,
            },
            Some(LogDetailKind::Extent) => CheckedDetail::Extent {
                start_sector: self.operands[0],
                sectors: self.operands[1],
            },
            // Nothing to refuse, on `Received`'s terms: both are counts the
            // emitting domain claims about its own run.
            Some(LogDetailKind::Proven) => CheckedDetail::Proven {
                preemptions: self.operands[0],
                iterations: self.operands[1],
            },
            // The one detail pair whose first word is a token and not a
            // count: it names a primitive, so a value outside the set names
            // nothing a console line could spell and is refused for it. The
            // second word is a count and unranged, on `Received`'s terms.
            Some(LogDetailKind::Proved) => CheckedDetail::Proved {
                primitive: primitive_token(self.operands[0])?,
                vectors: self.operands[1],
            },
            Some(LogDetailKind::Measured) => CheckedDetail::Measured {
                primitive: primitive_token(self.operands[0])?,
                milli_cycles_per_byte: self.operands[1],
            },
            // The four below carry numbers a peer chose and nothing that names
            // a vocabulary, so there is nothing here to refuse: a protocol
            // code point is a sixteen-bit registry value and a wrong one is a
            // wrong number rather than an undecodable record. The two that
            // must fit sixteen bits are ranged, because a wider value would
            // render as a code point no registry has.
            Some(LogDetailKind::Session) => CheckedDetail::Session {
                version: code_point(self.operands[0])?,
                suite: code_point(self.operands[1])?,
            },
            Some(LogDetailKind::Exchange) => CheckedDetail::Exchange {
                group: code_point(self.operands[0])?,
                echoed: self.operands[1],
            },
            Some(LogDetailKind::Peer) => CheckedDetail::Peer {
                high: self.operands[0],
                low: self.operands[1],
            },
            Some(LogDetailKind::Arena) => CheckedDetail::Arena {
                bytes: self.operands[0],
                bound: self.operands[1],
            },
            Some(LogDetailKind::Operation) => CheckedDetail::Operation {
                primitive: primitive_token(self.operands[0])?,
                cycles: self.operands[1],
            },
            // Three unranged numbers: an identifier that is 128 bits of
            // randomness, a generation, and a flag. The flag alone has a shape
            // to refuse, and it is refused for the reason `signalled` is —
            // anything but 0 or 1 is a word this writer would not have written.
            Some(LogDetailKind::Identity) => CheckedDetail::Identity {
                high: self.operands[0],
                low: self.operands[1],
                generation: self.operands[2],
                onboarded: flag(self.operands[3])?,
            },
            // Four words of digest, and nothing to refuse: every bit pattern of
            // a SHA-256 output is a digest, so a range check here would refuse a
            // fingerprint the appliance really computed.
            Some(LogDetailKind::Fingerprint) => CheckedDetail::Fingerprint {
                words: self.operands,
            },
            // A position, a count and a flag. The flag is refused on `Identity`'s
            // terms and in the same word, which is what keeps one rule for a
            // flag in this ABI rather than one per detail.
            Some(LogDetailKind::Reset) => CheckedDetail::Reset {
                generation: self.operands[0],
                documents: self.operands[1],
                was_owned: flag(self.operands[3])?,
            },
            // An identifier in its two halves and a count, on `Identity`'s terms
            // for the halves and with nothing to refuse: a count of signatures a
            // peer produced is unranged, and the fourth word is not a flag here,
            // so this detail names three words and leaves the last unclaimed.
            Some(LogDetailKind::Delegated) => CheckedDetail::Delegated {
                high: self.operands[0],
                low: self.operands[1],
                signatures: self.operands[2],
            },
            // A token, an address, a port and a count. The token names a closed
            // set and is refused outside it on `Proved`'s terms, which is why it
            // takes the first word; the address and the port are ranged because a
            // wider word would render as an address or a port no wire has, and
            // the attempt count is unranged because every bit pattern of it is a
            // tally this end could have kept.
            Some(LogDetailKind::Dialled) => CheckedDetail::Dialled {
                outcome: dial_outcome_token(self.operands[0])?,
                destination: address_bits(self.operands[1])?,
                port: code_point(self.operands[2])?,
                attempts: self.operands[3],
            },
            // A token, an address and two counts, ruled on in that order for
            // `Dialled`'s reason: the token takes the leading word wherever a
            // detail's first word names a vocabulary.
            Some(LogDetailKind::DialRoute) => CheckedDetail::DialRoute {
                via: next_hop_via_token(self.operands[0])?,
                next_hop: address_bits(self.operands[1])?,
                requests: self.operands[2],
                learned: self.operands[3],
            },
            // Four unranged counts of replies this port turned away, so there
            // is nothing here a rule can refuse: every bit pattern of each is a
            // tally a link under a flood could have produced.
            Some(LogDetailKind::DialUnlearned) => CheckedDetail::DialUnlearned {
                unsolicited: self.operands[0],
                rebinding: self.operands[1],
                not_unicast: self.operands[2],
                contradicted: self.operands[3],
            },
            // Three unranged counts and, in the fourth word, the one flag this
            // detail carries — refused there on `Identity`'s terms, which is
            // what keeps one rule in this ABI for a boolean in an operand.
            Some(LogDetailKind::DialSegments) => CheckedDetail::DialSegments {
                syns: self.operands[0],
                resets_received: self.operands[1],
                resets_sent: self.operands[2],
                answered: flag(self.operands[3])?,
            },
            // Two sequence numbers, each ranged to the thirty-two bits TCP
            // numbers one in: a wider word would render as a number no wire
            // carries, and one of the two is the peer's own claim.
            Some(LogDetailKind::DialSequence) => CheckedDetail::DialSequence {
                claimed: sequence_bits(self.operands[0])?,
                expected: sequence_bits(self.operands[1])?,
            },
        };
        Ok(CheckedBody::Domain {
            domain,
            state,
            detail,
        })
    }

    /// Reads `operands` positionally rather than by a length the writer may
    /// inflate: a refusal names at most the leading pair, so a count outside
    /// `0..=2` names more than the console line can carry and is refused for
    /// being one. The words past the pair are storage a refusal does not claim,
    /// exactly as the second word is under a count of one.
    fn check_operands(&self) -> Result<CheckedOperands, LogRecordError> {
        let (first, second) = (self.operands[0], self.operands[1]);
        match self.operand_count {
            0 => Ok(CheckedOperands::None),
            1 => Ok(CheckedOperands::One(first)),
            2 => Ok(CheckedOperands::Two(first, second)),
            operands => Err(LogRecordError::OperandCountUnknown { operands }),
        }
    }

    fn check_config_change(&self) -> Result<CheckedBody, LogRecordError> {
        Ok(CheckedBody::ConfigChange {
            generation: self.generation,
            sequence: self.sequence,
            change: token(
                self.change,
                LOG_CHANGE_KIND_COUNT,
                LogRecordError::ChangeKindUnknown {
                    change: self.change,
                },
            )?,
            object: token(
                self.object,
                LOG_OBJECT_KIND_COUNT,
                LogRecordError::ObjectKindUnknown {
                    object: self.object,
                },
            )?,
            key: check_text(&self.key, LogText::Key, false)?,
            field: token(
                self.field,
                LOG_FIELD_COUNT,
                LogRecordError::FieldUnknown { field: self.field },
            )?,
            from: check_value(&self.from, LogText::From)?,
            to: check_value(&self.to, LogText::To)?,
        })
    }
}

impl Default for LogRecord {
    fn default() -> Self {
        Self::ZERO
    }
}

/// Refuses a vocabulary token at or beyond its cardinality, returning the
/// caller's error for it. The bound is this ABI's, and a token inside it is
/// still one the log crate may not map — the two questions are different and
/// only the crate that owns the vocabulary answers the second.
/// A primitive token carried in an operand word: it must name a member of the
/// set, and it arrives as a `u64` because that is the width an operand has.
fn primitive_token(raw: u64) -> Result<u8, LogRecordError> {
    match u8::try_from(raw) {
        Ok(narrow) if narrow < LOG_PRIMITIVE_COUNT => Ok(narrow),
        _ => Err(LogRecordError::PrimitiveUnknown { primitive: raw }),
    }
}

/// A boolean carried in an operand word rather than in a byte field.
///
/// Refused rather than coerced for `boolean`'s reason: the word is peer-written,
/// and picking `false` for every other pattern would silently report an
/// unowned appliance as unowned when the record said something else entirely.
fn flag(raw: u64) -> Result<bool, LogRecordError> {
    match raw {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(LogRecordError::OperandFlagNotBoolean { value }),
    }
}

/// A dial outcome token carried in an operand word, on `primitive_token`'s
/// terms: it must name a member of the set, and it arrives as a `u64` because
/// that is the width an operand has.
fn dial_outcome_token(raw: u64) -> Result<u8, LogRecordError> {
    match u8::try_from(raw) {
        Ok(narrow) if narrow < LOG_DIAL_OUTCOME_COUNT => Ok(narrow),
        _ => Err(LogRecordError::DialOutcomeUnknown { outcome: raw }),
    }
}

/// A next-hop-choice token carried in an operand word, on
/// `dial_outcome_token`'s terms.
fn next_hop_via_token(raw: u64) -> Result<u8, LogRecordError> {
    match u8::try_from(raw) {
        Ok(narrow) if narrow < LOG_NEXT_HOP_VIA_COUNT => Ok(narrow),
        _ => Err(LogRecordError::NextHopViaUnknown { via: raw }),
    }
}

/// A TCP sequence number carried in an operand word. Every one of the
/// thirty-two bits is a sequence number — including the peer's own claim, which
/// is reported rather than judged — so what is refused is only a word too wide
/// to be one.
fn sequence_bits(raw: u64) -> Result<u32, LogRecordError> {
    u32::try_from(raw).map_err(|_| LogRecordError::SequenceTooWide { value: raw })
}

/// An IPv4 address carried in an operand word. Every one of the thirty-two bits
/// is an address, so what is refused is only a word too wide to be one — which
/// would otherwise render as an address truncated into a different one.
fn address_bits(raw: u64) -> Result<u32, LogRecordError> {
    u32::try_from(raw).map_err(|_| LogRecordError::AddressTooWide { value: raw })
}

/// A protocol registry code point, which is sixteen bits wide wherever TLS
/// names one. A wider value is a record whose renderer would print something
/// no registry has, so it is refused here rather than truncated.
fn code_point(raw: u64) -> Result<u16, LogRecordError> {
    u16::try_from(raw).map_err(|_| LogRecordError::CodePointTooWide { value: raw })
}

fn token(raw: u8, count: u8, error: LogRecordError) -> Result<u8, LogRecordError> {
    if raw < count { Ok(raw) } else { Err(error) }
}

/// `None` for anything but 0 or 1, which no `bool` can be coerced from without
/// picking a meaning the writer did not choose.
const fn boolean(raw: u8) -> Option<bool> {
    match raw {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

/// The alphabet `lfw_log::Identifier` admits, which is what makes a byte safe
/// to put on a console at all.
const fn in_alphabet(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-')
}

/// Why a byte string in a shared region is not text this ABI carries. Names a
/// length or a position, never the peer-chosen byte at it. Separate from
/// [`LogRecordError`] because two ABIs check one alphabet — a record's key and an
/// interface id — and each maps this onto its own refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextFault {
    /// More bytes than the array holds: the length a writer stated in a shared
    /// region, or the length of a slice a caller offered.
    TooLong {
        len: usize,
    },
    Empty,
    NotInAlphabet {
        offset: usize,
    },
}

impl fmt::Display for TextFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { len } => write!(f, "length {len} exceeds the storage"),
            Self::Empty => f.write_str("is empty"),
            Self::NotInAlphabet { offset } => write!(f, "byte {offset} is outside [a-z0-9-]"),
        }
    }
}

/// Copies out `len` bytes of already-checked text, leaving the tail zero so two
/// values that read the same compare the same however the writer filled it.
pub(crate) fn check_bounded_text<const N: usize>(
    raw: &TextImage<N>,
    allow_empty: bool,
) -> Result<CheckedText<N>, TextFault> {
    let len = usize::from(raw.len);
    let value = raw.bytes.get(..len).ok_or(TextFault::TooLong { len })?;
    check_slice(value, allow_empty)
}

/// The same rule over a slice a caller holds rather than a region a peer wrote.
fn check_slice<const N: usize>(
    value: &[u8],
    allow_empty: bool,
) -> Result<CheckedText<N>, TextFault> {
    let len = value.len();
    if len > N {
        return Err(TextFault::TooLong { len });
    }
    if value.is_empty() && !allow_empty {
        return Err(TextFault::Empty);
    }
    let mut bytes = [0; N];
    for (slot, (offset, &byte)) in bytes.iter_mut().zip(value.iter().enumerate()) {
        if !in_alphabet(byte) {
            return Err(TextFault::NotInAlphabet { offset });
        }
        *slot = byte;
    }
    Ok(CheckedText {
        bytes,
        // Bounded by `N` above, and `N` is 16 or 40, so this cannot lose a byte.
        len: u8::try_from(len).unwrap_or(u8::MAX),
    })
}

/// [`check_bounded_text`] in the record's own vocabulary, which names the field.
fn check_text<const N: usize>(
    raw: &TextImage<N>,
    text: LogText,
    allow_empty: bool,
) -> Result<CheckedText<N>, LogRecordError> {
    check_bounded_text(raw, allow_empty).map_err(|fault| match fault {
        // Out of the image's own `u8`, so it narrows back exactly.
        TextFault::TooLong { len } => LogRecordError::TextTooLong {
            text,
            len: u8::try_from(len).unwrap_or(u8::MAX),
        },
        TextFault::Empty => LogRecordError::TextEmpty { text },
        TextFault::NotInAlphabet { offset } => LogRecordError::TextNotInAlphabet { text, offset },
    })
}

/// Decodes the fields this slot's [`LogValueKind`] names and no others.
fn check_value(raw: &ValueImage, text: LogText) -> Result<Option<CheckedValue>, LogRecordError> {
    let Some(kind) = LogValueKind::from_bits(raw.kind) else {
        return Err(LogRecordError::ValueKindUnknown {
            text,
            kind: raw.kind,
        });
    };
    let narrow = || {
        u8::try_from(raw.number).map_err(|_| LogRecordError::ValueNumberTooLarge {
            text,
            number: raw.number,
        })
    };
    let [a, b, c, d, e, f] = raw.octets;
    Ok(match kind {
        LogValueKind::Absent => None,
        LogValueKind::Port => Some(CheckedValue::Port(narrow()?)),
        LogValueKind::Ipv4 => Some(CheckedValue::Ipv4([a, b, c, d])),
        LogValueKind::Mac => Some(CheckedValue::Mac([a, b, c, d, e, f])),
        LogValueKind::PrefixLength => Some(CheckedValue::PrefixLength(narrow()?)),
        LogValueKind::Bool => Some(CheckedValue::Bool(boolean(narrow()?).ok_or(
            LogRecordError::ValueBoolNotBoolean {
                text,
                number: raw.number,
            },
        )?)),
        LogValueKind::Generation => Some(CheckedValue::Generation(raw.number)),
        LogValueKind::Count => Some(CheckedValue::Count(raw.number)),
        LogValueKind::Id => Some(CheckedValue::Id(check_text(&raw.id, text, false)?)),
        LogValueKind::Selector => Some(CheckedValue::Selector(check_text(&raw.id, text, false)?)),
        LogValueKind::Prefix => Some(CheckedValue::Prefix {
            network: [a, b, c, d],
            prefix_length: narrow()?,
        }),
    })
}

/// Text that survived [`LogRecord::check`]. Its fields are private and it has
/// no public constructor, so the only way to hold one is to have checked it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedText<const N: usize> {
    bytes: [u8; N],
    len: u8,
}

impl<const N: usize> CheckedText<N> {
    /// Check `text` and hold it — the only way to obtain one outside this crate's
    /// own region readers.
    ///
    /// # Errors
    /// [`TextFault`], naming a length or a position and never a byte.
    pub fn new(text: &[u8]) -> Result<Self, TextFault> {
        check_slice(text, false)
    }

    /// The fallback is unreachable: [`LogRecord::check`] is what sets `len`,
    /// and it does so only after indexing the array with it. An empty slice
    /// rather than a panic because a branch safe Rust cannot delete is not a
    /// failure to surface.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or_default()
    }

    /// Unreachable for the same reason plus one step: the check admits
    /// `[a-z0-9-]` alone, every byte of which is a single-byte UTF-8 sequence.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or_default()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<const N: usize> fmt::Display for CheckedText<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An identifier that survived the check.
pub type CheckedIdentifier = CheckedText<LOG_IDENTIFIER_BYTES>;

impl CheckedIdentifier {
    /// The identity of the `<management>` element, which carries no `id` of its own
    /// — a document holds exactly one. `lfw_log` holds this equal to its own
    /// `Identifier::MANAGEMENT`, so the two spellings are one fact.
    pub const MANAGEMENT: Self = Self {
        bytes: *b"management\0\0\0\0\0\0",
        len: 10,
    };
}

const _: () = {
    let CheckedText { bytes, len } = CheckedIdentifier::MANAGEMENT;
    assert!(len > 0 && (len as usize) <= LOG_IDENTIFIER_BYTES);
    let mut offset = 0;
    while offset < LOG_IDENTIFIER_BYTES {
        let byte = bytes[offset];
        if offset < len as usize {
            assert!(in_alphabet(byte));
        } else {
            assert!(byte == 0);
        }
        offset += 1;
    }
};

/// A refusal cause token that survived it.
pub type CheckedCause = CheckedText<LOG_CAUSE_BYTES>;

/// One decoded `lfw_log::Value`. A mirror of that enum rather than the enum
/// itself, because this crate depends on nothing: it is the set of values this
/// ABI admits, which the log crate maps onto its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckedValue {
    Port(u8),
    /// Network order, as the address appears in a header.
    Ipv4([u8; 4]),
    Mac([u8; 6]),
    PrefixLength(u8),
    Bool(bool),
    Generation(u32),
    Count(u32),
    Id(CheckedIdentifier),
    /// A filter rule's match criterion, as the token the document wrote it as.
    Selector(CheckedIdentifier),
    /// A filter rule's address criterion, network order as a header carries it.
    Prefix {
        network: [u8; 4],
        prefix_length: u8,
    },
}

/// The numbers a refusal carries, as many as its `operand_count` named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckedOperands {
    None,
    One(u64),
    Two(u64, u64),
}

/// What a decoded lifecycle point carries beyond its own name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckedDetail {
    None,
    Features(u64),
    ReceivePosted(u32),
    Refusal {
        cause: CheckedCause,
        operands: CheckedOperands,
        signalled: bool,
    },
    /// A [`NonZeroU64`]: a divisor in any other shape leaves a zero to re-check.
    Established {
        tsc_hz: NonZeroU64,
        unix_nanos: u64,
    },
    /// What a terminal endpoint has taken off its pipeline, cumulatively.
    Received {
        frames: u64,
        bytes: u64,
    },
    /// What a domain established about the block medium under it.
    Medium {
        capacity_sectors: u64,
        leading_word: u64,
    },
    /// Where one of a domain's recordings lives on that medium.
    Extent {
        start_sector: u64,
        sectors: u64,
    },
    /// The protocol version and cipher suite a session settled on, as the
    /// registries number them.
    Session {
        version: u16,
        suite: u16,
    },
    /// The key exchange group that session used, and how many bytes of
    /// application data made the round trip under it.
    Exchange {
        group: u16,
        echoed: u64,
    },
    /// The 128-bit device identifier of the peer that authenticated, most
    /// significant half first.
    Peer {
        high: u64,
        low: u64,
    },
    /// A number of bytes about the bounded allocator, against the bound it is
    /// judged by. Which pair it is follows from the record's position, the
    /// domain emitting them in a fixed order.
    Arena {
        bytes: u64,
        bound: u64,
    },
    /// What one operation of a primitive cost, where a per-byte figure would
    /// mean nothing: a signature and a key exchange have one size.
    Operation {
        primitive: u8,
        cycles: u64,
    },
    /// What the hardware probe proved: both instruction known answers held and
    /// the XMM pattern survived every preemption it observed while running.
    Proven {
        preemptions: u64,
        iterations: u64,
    },
    /// One cryptographic primitive answered every published vector this image
    /// carries for it. The count travels with the token because a primitive
    /// named without one would claim a proof whose size nobody can see.
    Proved {
        primitive: u8,
        vectors: u64,
    },
    /// What one primitive cost on this part, in thousandths of a cycle per
    /// byte. Fixed point rather than a ratio of two counts: the two would
    /// invite a reader to divide them and get a different answer from the
    /// domain that measured them.
    Measured {
        primitive: u8,
        milli_cycles_per_byte: u64,
    },
    /// What a domain established about the appliance's own identity: the 128-bit
    /// device identifier as its two halves, most significant first, the state
    /// record's generation, and whether the appliance has an owner.
    Identity {
        high: u64,
        low: u64,
        generation: u64,
        onboarded: bool,
    },
    /// A 256-bit digest as its four words, most significant first — the whole of
    /// what a fingerprint is, so a renderer writes one field rather than two an
    /// administrator would have to join.
    Fingerprint {
        words: [u64; LOG_OPERANDS],
    },
    /// What a factory reset destroyed: the generation of the record it
    /// overwrote, how many configuration documents that record named, and
    /// whether the appliance had an owner.
    Reset {
        generation: u64,
        documents: u64,
        was_owned: bool,
    },
    /// Which appliance a domain that holds no key was told it signs for, and how
    /// many signatures the holder has produced. The identifier crosses in its two
    /// halves, on [`Self::Identity`]'s terms.
    Delegated {
        high: u64,
        low: u64,
        signatures: u64,
    },
    /// Where a connection this appliance originated went, and what became of
    /// it: the outcome token, the destination address and port, and how many
    /// attempts were spent on it.
    Dialled {
        outcome: u8,
        destination: u32,
        port: u16,
        attempts: u64,
    },
    /// The station a failed channel's frames were handed to, which of the
    /// port's two answers chose it, and what the asking produced.
    DialRoute {
        via: u8,
        next_hop: u32,
        requests: u64,
        learned: u64,
    },
    /// Replies that reached the port during that channel and became no entry,
    /// one count per reason.
    DialUnlearned {
        unsolicited: u64,
        rebinding: u64,
        not_unicast: u64,
        contradicted: u64,
    },
    /// What that channel's own connections did: handshakes composed, resets in
    /// both directions, and whether anything arrived at all.
    DialSegments {
        syns: u64,
        resets_received: u64,
        resets_sent: u64,
        answered: bool,
    },
    /// The two sequence numbers behind an unacceptable acknowledgement, both
    /// thirty-two bits wide wherever TCP names one.
    DialSequence {
        claimed: u32,
        expected: u32,
    },
}

/// When a [`LogRecord`] says it was emitted.
///
/// A sum type rather than a number with a reserved value, so an absent instant
/// has no `u64` in it to be mistaken for a reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckedStamp {
    Unsynchronized,
    /// Nanoseconds since the Unix epoch, unranged: every `u64` names a civil
    /// time, so believability is a reader's question and not this decode's.
    Utc(u64),
}

/// A whole decoded record: when it was emitted, and what it said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedRecord {
    pub at: CheckedStamp,
    pub body: CheckedBody,
}

/// Everything a [`LogRecord`] said, decoded and owned.
///
/// Owned rather than borrowed because the record it came from may be the shared
/// region itself, and a view into bytes the writer can still change is not an
/// event anybody can render. Each variant carries exactly the fields its
/// [`LogKind`] names, so a consumer cannot read one the record did not set.
///
/// The vocabulary tokens stay `u8`. Whether token 2 is `lfw_log::Field::Mac` is
/// a question about that crate's vocabulary, so only the crate that owns it can
/// answer — the same division [`crate::Descriptor`] makes with its verdict word.
/// What this crate guarantees is that the token is below the matching
/// `LOG_*_COUNT`, so the mapping is an array lookup rather than a bounds check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckedBody {
    Domain {
        domain: u8,
        state: u8,
        detail: CheckedDetail,
    },
    ConfigChange {
        generation: u32,
        sequence: u32,
        change: u8,
        object: u8,
        key: CheckedIdentifier,
        field: u8,
        from: Option<CheckedValue>,
        to: Option<CheckedValue>,
    },
    ConfigGeneration {
        generation: u32,
        outcome: u8,
        changes: u32,
    },
    ConfigRejected {
        generation: u32,
        reason: u8,
        offset: u32,
    },
}

/// Why a [`LogRecord`] was refused. Every variant carries the value that made
/// it one, so a refusal is attributable to a field rather than to a category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogRecordError {
    /// The stamp discriminant is neither of the two [`LogStampKind`] admits.
    StampKindUnknown {
        kind: u8,
    },
    KindUnknown {
        kind: u32,
    },
    PrimitiveUnknown {
        primitive: u64,
    },
    /// A protocol code point wider than the sixteen bits every TLS registry
    /// numbers one in.
    CodePointTooWide {
        value: u64,
    },
    DialOutcomeUnknown {
        outcome: u64,
    },
    NextHopViaUnknown {
        via: u64,
    },
    /// An operand carrying a TCP sequence number wider than the thirty-two bits
    /// one has.
    SequenceTooWide {
        value: u64,
    },
    /// An operand carrying an IPv4 address wider than the thirty-two bits one
    /// has.
    AddressTooWide {
        value: u64,
    },
    DomainUnknown {
        domain: u8,
    },
    DomainStateUnknown {
        state: u8,
    },
    DetailKindUnknown {
        detail: u8,
    },
    /// An operand word carrying a flag held neither 0 nor 1.
    OperandFlagNotBoolean {
        value: u64,
    },
    OperandCountUnknown {
        operands: u8,
    },
    SignalledNotBoolean {
        signalled: u8,
    },
    /// An established frequency of zero. Alone among these it carries no value.
    ClockFrequencyZero,
    ChangeKindUnknown {
        change: u8,
    },
    ObjectKindUnknown {
        object: u8,
    },
    FieldUnknown {
        field: u8,
    },
    GenerationOutcomeUnknown {
        outcome: u8,
    },
    RejectReasonUnknown {
        reason: u8,
    },
    ValueKindUnknown {
        text: LogText,
        kind: u8,
    },
    /// A `Port`, `PrefixLength` or `Bool` whose word does not fit the byte the
    /// value is, refused rather than truncated to one the writer did not pick.
    ValueNumberTooLarge {
        text: LogText,
        number: u32,
    },
    ValueBoolNotBoolean {
        text: LogText,
        number: u32,
    },
    TextEmpty {
        text: LogText,
    },
    TextTooLong {
        text: LogText,
        len: u8,
    },
    TextNotInAlphabet {
        text: LogText,
        offset: usize,
    },
}

impl fmt::Display for LogRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StampKindUnknown { kind } => {
                write!(
                    f,
                    "stamp kind {kind} says neither a time nor the lack of one"
                )
            }
            Self::KindUnknown { kind } => write!(f, "record kind {kind} names no event"),
            Self::PrimitiveUnknown { primitive } => write!(
                f,
                "primitive token {primitive} is not below {LOG_PRIMITIVE_COUNT}"
            ),
            Self::CodePointTooWide { value } => {
                write!(f, "protocol code point {value} does not fit sixteen bits")
            }
            Self::DialOutcomeUnknown { outcome } => write!(
                f,
                "dial outcome token {outcome} is not below {LOG_DIAL_OUTCOME_COUNT}"
            ),
            Self::NextHopViaUnknown { via } => write!(
                f,
                "next hop choice token {via} is not below {LOG_NEXT_HOP_VIA_COUNT}"
            ),
            Self::SequenceTooWide { value } => {
                write!(f, "sequence word {value} does not fit thirty-two bits")
            }
            Self::AddressTooWide { value } => {
                write!(f, "address word {value} does not fit thirty-two bits")
            }
            Self::OperandFlagNotBoolean { value } => {
                write!(f, "operand flag {value} is neither 0 nor 1")
            }
            Self::DomainUnknown { domain } => {
                write!(f, "domain token {domain} is not below {LOG_DOMAIN_COUNT}")
            }
            Self::DomainStateUnknown { state } => write!(
                f,
                "state token {state} is not below {LOG_DOMAIN_STATE_COUNT}"
            ),
            Self::DetailKindUnknown { detail } => {
                write!(f, "detail kind {detail} names no payload")
            }
            Self::OperandCountUnknown { operands } => {
                write!(
                    f,
                    "operand count {operands} exceeds the 2 a refusal may name"
                )
            }
            Self::SignalledNotBoolean { signalled } => {
                write!(f, "signalled byte {signalled} is not 0 or 1")
            }
            Self::ClockFrequencyZero => {
                f.write_str("the established counter frequency is zero, which scales no reading")
            }
            Self::ChangeKindUnknown { change } => write!(
                f,
                "change token {change} is not below {LOG_CHANGE_KIND_COUNT}"
            ),
            Self::ObjectKindUnknown { object } => write!(
                f,
                "object token {object} is not below {LOG_OBJECT_KIND_COUNT}"
            ),
            Self::FieldUnknown { field } => {
                write!(f, "field token {field} is not below {LOG_FIELD_COUNT}")
            }
            Self::GenerationOutcomeUnknown { outcome } => write!(
                f,
                "outcome token {outcome} is not below {LOG_GENERATION_OUTCOME_COUNT}"
            ),
            Self::RejectReasonUnknown { reason } => write!(
                f,
                "reason token {reason} is not below {LOG_REJECT_REASON_COUNT}"
            ),
            Self::ValueKindUnknown { text, kind } => {
                write!(f, "{text} value kind {kind} names no value")
            }
            Self::ValueNumberTooLarge { text, number } => {
                write!(f, "{text} value {number} does not fit a byte")
            }
            Self::ValueBoolNotBoolean { text, number } => {
                write!(f, "{text} value {number} is not 0 or 1")
            }
            Self::TextEmpty { text } => write!(f, "{text} text is empty"),
            Self::TextTooLong { text, len } => {
                write!(f, "{text} text length {len} exceeds its storage")
            }
            Self::TextNotInAlphabet { text, offset } => {
                write!(f, "{text} text byte {offset} is outside [a-z0-9-]")
            }
        }
    }
}

// The record crosses protection domains byte for byte, so a field reorder or a
// width change must be a compile error here rather than a silent break of the
// image the console domain reads.
const _: () = {
    assert!(size_of::<IdentifierImage>() == 20);
    assert!(align_of::<IdentifierImage>() == 1);
    assert!(offset_of!(IdentifierImage, bytes) == 0);
    assert!(offset_of!(IdentifierImage, len) == 16);
    assert!(offset_of!(IdentifierImage, _pad) == 17);

    assert!(size_of::<CauseImage>() == 44);
    assert!(align_of::<CauseImage>() == 1);
    assert!(offset_of!(CauseImage, bytes) == 0);
    assert!(offset_of!(CauseImage, len) == 40);
    assert!(offset_of!(CauseImage, _pad) == 41);

    assert!(size_of::<ValueImage>() == 32);
    assert!(align_of::<ValueImage>() == 4);
    assert!(offset_of!(ValueImage, number) == 0);
    assert!(offset_of!(ValueImage, kind) == 4);
    assert!(offset_of!(ValueImage, octets) == 5);
    assert!(offset_of!(ValueImage, _pad) == 11);
    assert!(offset_of!(ValueImage, id) == 12);

    assert!(size_of::<LogRecord>() == 264);
    assert!(align_of::<LogRecord>() == 8);
    assert!(offset_of!(LogRecord, features) == 0);
    assert!(offset_of!(LogRecord, operands) == 8);
    assert!(offset_of!(LogRecord, tsc_hz) == 40);
    assert!(offset_of!(LogRecord, unix_nanos) == 48);
    assert!(offset_of!(LogRecord, frames) == 56);
    assert!(offset_of!(LogRecord, frame_bytes) == 64);
    assert!(offset_of!(LogRecord, capacity_sectors) == 72);
    assert!(offset_of!(LogRecord, leading_word) == 80);
    assert!(offset_of!(LogRecord, stamp_nanos) == 88);
    assert!(offset_of!(LogRecord, kind) == 96);
    assert!(offset_of!(LogRecord, generation) == 100);
    assert!(offset_of!(LogRecord, sequence) == 104);
    assert!(offset_of!(LogRecord, changes) == 108);
    assert!(offset_of!(LogRecord, reject_offset) == 112);
    assert!(offset_of!(LogRecord, receive_posted) == 116);
    assert!(offset_of!(LogRecord, domain) == 120);
    assert!(offset_of!(LogRecord, state) == 121);
    assert!(offset_of!(LogRecord, detail) == 122);
    assert!(offset_of!(LogRecord, operand_count) == 123);
    assert!(offset_of!(LogRecord, signalled) == 124);
    assert!(offset_of!(LogRecord, change) == 125);
    assert!(offset_of!(LogRecord, object) == 126);
    assert!(offset_of!(LogRecord, field) == 127);
    assert!(offset_of!(LogRecord, outcome) == 128);
    assert!(offset_of!(LogRecord, reason) == 129);
    assert!(offset_of!(LogRecord, stamp_kind) == 130);
    assert!(offset_of!(LogRecord, _pad) == 131);
    assert!(offset_of!(LogRecord, cause) == 136);
    assert!(offset_of!(LogRecord, key) == 180);
    assert!(offset_of!(LogRecord, from) == 200);
    assert!(offset_of!(LogRecord, to) == 232);

    // Every byte of the record belongs to a declared field: the fields sum to
    // the whole size, so the compiler inserted no padding of its own. That is
    // what makes an arbitrary value of every field the same input space as
    // arbitrary region bytes, which is what the hostile-writer property rests
    // on.
    assert!(
        size_of::<LogRecord>()
            == size_of::<[u64; 8 + LOG_OPERANDS]>()
                + 6 * size_of::<u32>()
                + 11
                + 5
                + size_of::<CauseImage>()
                + size_of::<IdentifierImage>()
                + 2 * size_of::<ValueImage>()
    );

    // A zeroed region must already be a decodable record, which is what lets a
    // reader come up against one before anything has been written — and, for
    // the stamp, what stops an untouched slot reading as the epoch.
    assert!(LogKind::Domain.to_bits() == 0);
    assert!(LogDetailKind::None.to_bits() == 0);
    assert!(LogValueKind::Absent.to_bits() == 0);
    assert!(LogStampKind::Unsynchronized.to_bits() == 0);
};

#[cfg(test)]
mod tests;
