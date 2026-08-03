//! An [`Event`] as the fixed-layout record it crosses a domain boundary as, and
//! back.
//!
//! # Adversary
//!
//! Decoding faces the byzantine peer protection domain. A record
//! reaching [`Event::decode`] was assembled from bytes another domain wrote, so
//! every vocabulary token in it was chosen by that domain. `wire` has already
//! refused the shapes it owns — an unreadable variant, a length past its
//! storage, a byte outside the console alphabet — and what is left is the
//! question only this crate can answer: whether a token `wire` bounded against
//! its `LOG_*_COUNT` names a variant this crate actually has. That is a typed
//! refusal here, never a panic and never a coerced variant.
//!
//! Encoding faces nobody. It runs in the domain that minted the event.
//!
//! # Why the vocabulary widths are asserted rather than trusted
//!
//! The two crates each hold a copy of every vocabulary's cardinality: `wire` as
//! a `LOG_*_COUNT` it bounds a token against, this crate as the length of an
//! `ALL` array the macro derives from the variant list. A variant added here
//! without moving the count there would leave a token this crate can emit and
//! `wire` refuses; moving the count without adding the variant would leave one
//! `wire` admits and this crate cannot name. Neither shows up in a type. The
//! block at the foot of this file is what makes both a build failure, and it
//! lives here because this is the only place that has seen both numbers.
//!
//! # What the record cannot carry, and where that is caught
//!
//! [`Refusal::cause`] is a literal at every minting call site and so is bounded
//! by nothing the compiler checks, while the ABI carries `LOG_CAUSE_BYTES` of
//! the console alphabet. [`Event<Cause>`] is the form that has been held to
//! that bound, [`Event::encode`] is defined on it alone and is therefore total,
//! and the `TryFrom` below is the one place a literal is measured against it.
//! A literal that does not fit is this domain's own defect rather than a
//! peer's, and it is refused with the value that made it one rather than
//! truncated into a token an operator would read as whole.

use wire::{
    CheckedBody, CheckedDetail, CheckedIdentifier, CheckedOperands, CheckedRecord, CheckedValue,
    LogDetailKind, LogKind, LogRecord, LogStampKind, LogText, LogValueKind, LogWriter, ValueImage,
};

use crate::detail::{Cause, CauseError, DomainDetail, Refusal, RefusalDetail};
use crate::event::{
    ChangeKind, Domain, DomainState, Event, Field, GenerationOutcome, ObjectKind, RejectReason,
    Value,
};
use crate::identifier::{Identifier, IdentifierError};
use crate::stamp::{Clock, Stamp};

use core::fmt;
use lfw_clock::UtcNanos;

/// Why a record decoded to no [`Event`].
///
/// Each variant carries the token that refused it, so a console domain counting
/// these can say *what* its peer sent rather than only that it sent something.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// A vocabulary token inside `wire`'s bound for it but past the variants
    /// this crate has. Unreachable while the assertion at the foot of this file
    /// holds and a record came through `wire`'s own check — but a
    /// [`CheckedBody`] is a public value with public fields, so this is the
    /// answer for one built by hand, and it is a typed refusal rather than an
    /// index into the variant table.
    Vocabulary { vocabulary: Vocabulary, token: u8 },
    /// Text `wire` passed that this crate's own identifier rules refuse. The
    /// two alphabets are separate copies facing different adversaries, so their
    /// disagreement is a value to report and not one to assume away.
    Identifier {
        text: LogText,
        error: IdentifierError,
    },
    /// As [`Self::Identifier`], for a refusal cause token.
    Cause { error: CauseError },
}

/// Which closed vocabulary a [`DecodeError::Vocabulary`] token was read against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vocabulary {
    Domain,
    DomainState,
    ChangeKind,
    ObjectKind,
    Field,
    GenerationOutcome,
    RejectReason,
}

impl Vocabulary {
    /// How many variants this crate has for it — the number a token is refused
    /// against, and the one the assertion below holds `wire`'s to.
    #[must_use]
    pub const fn count(self) -> usize {
        match self {
            Self::Domain => Domain::ALL.len(),
            Self::DomainState => DomainState::ALL.len(),
            Self::ChangeKind => ChangeKind::ALL.len(),
            Self::ObjectKind => ObjectKind::ALL.len(),
            Self::Field => Field::ALL.len(),
            Self::GenerationOutcome => GenerationOutcome::ALL.len(),
            Self::RejectReason => RejectReason::ALL.len(),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::DomainState => "state",
            Self::ChangeKind => "change",
            Self::ObjectKind => "object",
            Self::Field => "field",
            Self::GenerationOutcome => "outcome",
            Self::RejectReason => "reason",
        }
    }
}

impl fmt::Display for Vocabulary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vocabulary { vocabulary, token } => write!(
                f,
                "{vocabulary} token {token} names none of the {} this build has",
                vocabulary.count()
            ),
            Self::Identifier { text, error } => write!(f, "{text} text is no identifier: {error}"),
            Self::Cause { error } => write!(f, "cause text is no cause token: {error}"),
        }
    }
}

/// Reads a token as the variant it indexes, refusing one past the end rather
/// than indexing the array with it.
fn variant<T: Copy, const N: usize>(
    all: [T; N],
    vocabulary: Vocabulary,
    token: u8,
) -> Result<T, DecodeError> {
    all.get(usize::from(token))
        .copied()
        .ok_or(DecodeError::Vocabulary { vocabulary, token })
}

fn identifier(text: &CheckedIdentifier, which: LogText) -> Result<Identifier, DecodeError> {
    Identifier::new(text.as_bytes()).map_err(|error| DecodeError::Identifier { text: which, error })
}

/// `Identifier` is bounded by `MAX_IDENTIFIER_LEN`, which the assertion at the
/// foot of this file holds equal to the image's storage, so this cannot narrow.
fn identifier_image(id: &Identifier) -> wire::IdentifierImage {
    wire::IdentifierImage::from_text(id.as_bytes())
}

fn cause_image(cause: &Cause) -> wire::CauseImage {
    wire::CauseImage::from_text(cause.as_bytes())
}

/// One optional [`Value`] as the ABI carries it: a kind naming which of the
/// fields below mean anything, and those fields.
fn value_image(value: Option<Value>) -> ValueImage {
    let mut image = ValueImage::ZERO;
    let Some(value) = value else {
        return image;
    };
    let kind = match value {
        Value::Port(port) => {
            image.number = u32::from(port);
            LogValueKind::Port
        }
        Value::Ipv4(address) => {
            let octets = address.octets();
            for (slot, &byte) in image.octets.iter_mut().zip(octets.iter()) {
                *slot = byte;
            }
            LogValueKind::Ipv4
        }
        Value::Mac(mac) => {
            image.octets = mac.0;
            LogValueKind::Mac
        }
        Value::PrefixLength(length) => {
            image.number = u32::from(length);
            LogValueKind::PrefixLength
        }
        Value::Bool(flag) => {
            image.number = u32::from(flag);
            LogValueKind::Bool
        }
        Value::Generation(generation) => {
            image.number = generation;
            LogValueKind::Generation
        }
        Value::Count(count) => {
            image.number = count;
            LogValueKind::Count
        }
        Value::Id(id) => {
            image.id = identifier_image(&id);
            LogValueKind::Id
        }
        Value::Selector(token) => {
            image.id = identifier_image(&token);
            LogValueKind::Selector
        }
        Value::Prefix {
            network,
            prefix_length,
        } => {
            let octets = network.octets();
            for (slot, &byte) in image.octets.iter_mut().zip(octets.iter()) {
                *slot = byte;
            }
            image.number = u32::from(prefix_length);
            LogValueKind::Prefix
        }
    };
    image.kind = kind.to_bits();
    image
}

fn decode_value(value: Option<CheckedValue>, which: LogText) -> Result<Option<Value>, DecodeError> {
    let Some(value) = value else {
        return Ok(None);
    };
    Ok(Some(match value {
        CheckedValue::Port(port) => Value::Port(port),
        CheckedValue::Ipv4(octets) => Value::Ipv4(net_headers::Ipv4Address::from_octets(octets)),
        CheckedValue::Mac(octets) => Value::Mac(net_headers::MacAddress(octets)),
        CheckedValue::PrefixLength(length) => Value::PrefixLength(length),
        CheckedValue::Bool(flag) => Value::Bool(flag),
        CheckedValue::Generation(generation) => Value::Generation(generation),
        CheckedValue::Count(count) => Value::Count(count),
        CheckedValue::Id(id) => Value::Id(identifier(&id, which)?),
        CheckedValue::Selector(token) => Value::Selector(identifier(&token, which)?),
        CheckedValue::Prefix {
            network,
            prefix_length,
        } => Value::Prefix {
            network: net_headers::Ipv4Address::from_octets(network),
            prefix_length,
        },
    }))
}

impl<C> Event<C> {
    /// This event's vocabulary tokens and numbers, which no cause text reaches.
    ///
    /// Shared by both encode paths so the fields that do not depend on `C` are
    /// written once.
    fn encode_common(&self, record: &mut LogRecord) {
        match self {
            Self::Domain { domain, state, .. } => {
                record.kind = LogKind::Domain.to_bits();
                record.domain = *domain as u8;
                record.state = *state as u8;
            }
            Self::ConfigChange {
                generation,
                sequence,
                change,
                object,
                key,
                field,
                from,
                to,
            } => {
                record.kind = LogKind::ConfigChange.to_bits();
                record.generation = *generation;
                record.sequence = *sequence;
                record.change = *change as u8;
                record.object = *object as u8;
                record.key = identifier_image(key);
                record.field = *field as u8;
                record.from = value_image(*from);
                record.to = value_image(*to);
            }
            Self::ConfigGeneration {
                generation,
                outcome,
                changes,
            } => {
                record.kind = LogKind::ConfigGeneration.to_bits();
                record.generation = *generation;
                record.outcome = *outcome as u8;
                record.changes = *changes;
            }
            Self::ConfigRejected {
                generation,
                reason,
                offset,
            } => {
                record.kind = LogKind::ConfigRejected.to_bits();
                record.generation = *generation;
                record.reason = *reason as u8;
                record.reject_offset = *offset;
            }
        }
    }
}

impl Event<Cause> {
    /// This event, stamped `at`, as the record a peer domain reads.
    ///
    /// Total: every variant and every field of every variant has a place in the
    /// ABI, and [`Cause`] is bounded by construction, so there is nothing here
    /// that can fail. What a record leaves untouched is what its own
    /// [`LogKind`] does not name, which is exactly what `wire` reads back.
    #[must_use]
    pub fn encode(&self, at: Stamp) -> LogRecord {
        let mut record = LogRecord::ZERO;
        match at {
            Stamp::Unsynchronized => record.stamp_kind = LogStampKind::Unsynchronized.to_bits(),
            Stamp::Utc(utc) => {
                record.stamp_kind = LogStampKind::Utc.to_bits();
                record.stamp_nanos = utc.as_nanos();
            }
        }
        self.encode_common(&mut record);
        if let Self::Domain { detail, .. } = self {
            match detail {
                DomainDetail::None => record.detail = LogDetailKind::None.to_bits(),
                DomainDetail::Features(bits) => {
                    record.detail = LogDetailKind::Features.to_bits();
                    record.features = *bits;
                }
                DomainDetail::ReceivePosted(count) => {
                    record.detail = LogDetailKind::ReceivePosted.to_bits();
                    record.receive_posted = *count;
                }
                DomainDetail::Established { tsc_hz, utc } => {
                    record.detail = LogDetailKind::Established.to_bits();
                    record.tsc_hz = tsc_hz.get();
                    record.unix_nanos = utc.as_nanos();
                }
                DomainDetail::Received { frames, bytes } => {
                    record.detail = LogDetailKind::Received.to_bits();
                    record.frames = *frames;
                    record.frame_bytes = *bytes;
                }
                DomainDetail::Medium {
                    capacity_sectors,
                    leading_word,
                } => {
                    record.detail = LogDetailKind::Medium.to_bits();
                    record.capacity_sectors = *capacity_sectors;
                    record.leading_word = *leading_word;
                }
                DomainDetail::Extent {
                    start_sector,
                    sectors,
                } => {
                    record.detail = LogDetailKind::Extent.to_bits();
                    record.operands = [*start_sector, *sectors];
                }
                DomainDetail::Refusal(Refusal {
                    cause,
                    detail,
                    signalled,
                }) => {
                    record.detail = LogDetailKind::Refusal.to_bits();
                    record.cause = cause_image(cause);
                    record.signalled = u8::from(*signalled);
                    match detail {
                        RefusalDetail::None => record.operand_count = 0,
                        RefusalDetail::One(value) => {
                            record.operand_count = 1;
                            record.operands = [*value, 0];
                        }
                        RefusalDetail::Two(first, second) => {
                            record.operand_count = 2;
                            record.operands = [*first, *second];
                        }
                    }
                }
            }
        }
        record
    }

    /// The instant and the event a checked record says happened.
    ///
    /// # Errors
    /// [`DecodeError`], naming the token or the text that refused it. `wire`
    /// has already refused every shape it owns; what is refused here is a token
    /// this build has no variant for.
    pub fn decode(record: &CheckedRecord) -> Result<(Stamp, Self), DecodeError> {
        Ok((
            Stamp::from_checked(record.at),
            Self::decode_body(&record.body)?,
        ))
    }

    fn decode_body(body: &CheckedBody) -> Result<Self, DecodeError> {
        Ok(match *body {
            CheckedBody::Domain {
                domain,
                state,
                detail,
            } => Self::Domain {
                domain: variant(Domain::ALL, Vocabulary::Domain, domain)?,
                state: variant(DomainState::ALL, Vocabulary::DomainState, state)?,
                detail: decode_detail(&detail)?,
            },
            CheckedBody::ConfigChange {
                generation,
                sequence,
                change,
                object,
                key,
                field,
                from,
                to,
            } => Self::ConfigChange {
                generation,
                sequence,
                change: variant(ChangeKind::ALL, Vocabulary::ChangeKind, change)?,
                object: variant(ObjectKind::ALL, Vocabulary::ObjectKind, object)?,
                key: identifier(&key, LogText::Key)?,
                field: variant(Field::ALL, Vocabulary::Field, field)?,
                from: decode_value(from, LogText::From)?,
                to: decode_value(to, LogText::To)?,
            },
            CheckedBody::ConfigGeneration {
                generation,
                outcome,
                changes,
            } => Self::ConfigGeneration {
                generation,
                outcome: variant(
                    GenerationOutcome::ALL,
                    Vocabulary::GenerationOutcome,
                    outcome,
                )?,
                changes,
            },
            CheckedBody::ConfigRejected {
                generation,
                reason,
                offset,
            } => Self::ConfigRejected {
                generation,
                reason: variant(RejectReason::ALL, Vocabulary::RejectReason, reason)?,
                offset,
            },
        })
    }
}

fn decode_detail(detail: &CheckedDetail) -> Result<DomainDetail<Cause>, DecodeError> {
    Ok(match detail {
        CheckedDetail::None => DomainDetail::None,
        CheckedDetail::Features(bits) => DomainDetail::Features(*bits),
        CheckedDetail::ReceivePosted(count) => DomainDetail::ReceivePosted(*count),
        // Total: `wire` refused the zero frequency and every `u64` of
        // nanoseconds names a civil time, so nothing is left to judge here.
        CheckedDetail::Established { tsc_hz, unix_nanos } => DomainDetail::Established {
            tsc_hz: *tsc_hz,
            utc: UtcNanos::from_unix_nanos(*unix_nanos),
        },
        CheckedDetail::Received { frames, bytes } => DomainDetail::Received {
            frames: *frames,
            bytes: *bytes,
        },
        // Total for the same reason: two numbers, every bit pattern of which a
        // real medium could produce.
        CheckedDetail::Medium {
            capacity_sectors,
            leading_word,
        } => DomainDetail::Medium {
            capacity_sectors: *capacity_sectors,
            leading_word: *leading_word,
        },
        // And here: a start and a length are two numbers a configuration
        // produced, both readable whatever they are.
        CheckedDetail::Extent {
            start_sector,
            sectors,
        } => DomainDetail::Extent {
            start_sector: *start_sector,
            sectors: *sectors,
        },
        CheckedDetail::Refusal {
            cause,
            operands,
            signalled,
        } => DomainDetail::Refusal(Refusal {
            cause: Cause::new(cause.as_bytes()).map_err(|error| DecodeError::Cause { error })?,
            detail: match operands {
                CheckedOperands::None => RefusalDetail::None,
                CheckedOperands::One(value) => RefusalDetail::One(*value),
                CheckedOperands::Two(first, second) => RefusalDetail::Two(*first, *second),
            },
            signalled: *signalled,
        }),
    })
}

impl<'a> TryFrom<Event<&'a str>> for Event<Cause> {
    type Error = CauseError;

    /// The one place a minted cause literal is measured against what the ABI
    /// carries. Every other field of an event is already a bounded type, so the
    /// cause is the whole of what can refuse this.
    fn try_from(event: Event<&'a str>) -> Result<Self, Self::Error> {
        Ok(match event {
            Event::Domain {
                domain,
                state,
                detail,
            } => Self::Domain {
                domain,
                state,
                detail: match detail {
                    DomainDetail::None => DomainDetail::None,
                    DomainDetail::Features(bits) => DomainDetail::Features(bits),
                    DomainDetail::ReceivePosted(count) => DomainDetail::ReceivePosted(count),
                    DomainDetail::Established { tsc_hz, utc } => {
                        DomainDetail::Established { tsc_hz, utc }
                    }
                    DomainDetail::Received { frames, bytes } => {
                        DomainDetail::Received { frames, bytes }
                    }
                    DomainDetail::Medium {
                        capacity_sectors,
                        leading_word,
                    } => DomainDetail::Medium {
                        capacity_sectors,
                        leading_word,
                    },
                    DomainDetail::Extent {
                        start_sector,
                        sectors,
                    } => DomainDetail::Extent {
                        start_sector,
                        sectors,
                    },
                    DomainDetail::Refusal(Refusal {
                        cause,
                        detail,
                        signalled,
                    }) => DomainDetail::Refusal(Refusal {
                        cause: Cause::new(cause.as_bytes())?,
                        detail,
                        signalled,
                    }),
                },
            },
            Event::ConfigChange {
                generation,
                sequence,
                change,
                object,
                key,
                field,
                from,
                to,
            } => Self::ConfigChange {
                generation,
                sequence,
                change,
                object,
                key,
                field,
                from,
                to,
            },
            Event::ConfigGeneration {
                generation,
                outcome,
                changes,
            } => Self::ConfigGeneration {
                generation,
                outcome,
                changes,
            },
            Event::ConfigRejected {
                generation,
                reason,
                offset,
            } => Self::ConfigRejected {
                generation,
                reason,
                offset,
            },
        })
    }
}

/// Writes an event into a [`LogWriter`], which is the whole of what a
/// [`RingSink`](crate::RingSink) does that a test cannot do without a ring.
///
/// # Errors
/// [`SendError`], distinguishing a flood from this domain's own defect.
pub(crate) fn send(
    writer: &mut LogWriter<'_>,
    clock: &dyn Clock,
    event: &Event,
) -> Result<(), SendError> {
    let bounded = Event::<Cause>::try_from(*event).map_err(SendError::Unencodable)?;
    writer
        .write(&bounded.encode(clock.now()))
        .map_err(|full| SendError::Full {
            dropped: full.dropped,
        })
}

/// Why an event did not reach the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendError {
    /// The ring had no free slot: a flood, or a console domain that has not
    /// started draining yet. The writer's running total comes with it.
    Full { dropped: u32 },
    /// The event carries a cause literal the ABI cannot hold, which is a defect
    /// in the domain that minted it rather than anything a peer did.
    Unencodable(CauseError),
}

// The two crates each hold a copy of every vocabulary's cardinality and of
// every text field's width. Neither copy is derived from the other, so only a
// place that has seen both can hold them equal — and the widths below are what
// let a token be read as an array index and a bounded text be copied whole.
const _: () = {
    assert!(Domain::ALL.len() == wire::LOG_DOMAIN_COUNT as usize);
    assert!(DomainState::ALL.len() == wire::LOG_DOMAIN_STATE_COUNT as usize);
    assert!(ChangeKind::ALL.len() == wire::LOG_CHANGE_KIND_COUNT as usize);
    assert!(ObjectKind::ALL.len() == wire::LOG_OBJECT_KIND_COUNT as usize);
    assert!(Field::ALL.len() == wire::LOG_FIELD_COUNT as usize);
    assert!(GenerationOutcome::ALL.len() == wire::LOG_GENERATION_OUTCOME_COUNT as usize);
    assert!(RejectReason::ALL.len() == wire::LOG_REJECT_REASON_COUNT as usize);

    assert!(crate::MAX_IDENTIFIER_LEN == wire::LOG_IDENTIFIER_BYTES);
    assert!(crate::MAX_CAUSE_LEN == wire::LOG_CAUSE_BYTES);

    // A token is read as an index into `ALL`, and a length is written into a
    // `u8` field of the image: a vocabulary or a text wider than that field
    // would be a silent narrowing at every crossing.
    assert!(wire::LOG_IDENTIFIER_BYTES <= u8::MAX as usize);
    assert!(wire::LOG_CAUSE_BYTES <= u8::MAX as usize);
};

#[cfg(test)]
mod tests;
