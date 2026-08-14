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
    LOG_OPERANDS, LogDetailKind, LogKind, LogRecord, LogStampKind, LogText, LogValueKind,
    LogWriter, ValueImage,
};

/// Bytes of the one digest this ABI carries, `lfw_crypto::DIGEST_LEN` restated
/// rather than depended on: this crate reaches for no cryptography, and the
/// assertion at the foot of the file is what holds the two numbers together
/// through the type that does carry the digest.
const DIGEST_BYTES: usize = 32;

use crate::detail::{Cause, CauseError, DomainDetail, Refusal, RefusalDetail};
use crate::event::{
    ChangeKind, ChannelOutcome, DialOutcome, Domain, DomainState, Event, Field, GenerationOutcome,
    NextHopVia, ObjectKind, OnboardEnd, OnboardOutcome, OnboardRefusal, OnboardRoute, Ownership,
    Primitive, RejectReason, TlsCertificateRefusal, TlsIncompatible, TlsRefusal, Value,
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
    Primitive,
    DialOutcome,
    NextHopVia,
    OnboardEnd,
    OnboardOutcome,
    TlsIncompatible,
    TlsRefusal,
    OnboardRoute,
    OnboardRefusal,
    Ownership,
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
            Self::Primitive => Primitive::ALL.len(),
            Self::DialOutcome => DialOutcome::ALL.len(),
            Self::NextHopVia => NextHopVia::ALL.len(),
            Self::OnboardEnd => OnboardEnd::ALL.len(),
            Self::OnboardOutcome => OnboardOutcome::ALL.len(),
            Self::TlsIncompatible => TlsIncompatible::ALL.len(),
            Self::TlsRefusal => TlsRefusal::ALL.len(),
            Self::OnboardRoute => OnboardRoute::ALL.len(),
            Self::OnboardRefusal => OnboardRefusal::ALL.len(),
            Self::Ownership => Ownership::ALL.len(),
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
            Self::Primitive => "primitive",
            // Two words rather than a hyphenated token: this is the noun a decode
            // refusal is written with ("dial outcome token 9 …") and not a
            // console `cause=`, and the spelling is what keeps the two apart.
            Self::DialOutcome => "dial outcome",
            Self::NextHopVia => "next hop choice",
            Self::OnboardEnd => "onboarding session end",
            Self::OnboardOutcome => "onboarding handshake outcome",
            Self::TlsIncompatible => "TLS incompatibility",
            Self::TlsRefusal => "TLS refusal",
            Self::OnboardRoute => "onboarding resource",
            Self::OnboardRefusal => "onboarding request refusal",
            Self::Ownership => "ownership",
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

/// A primitive token as the member it selects. `wire` already ranged it, so
/// this reaches the refusal only if the two crates' sets ever disagreed — and
/// the assertion at the foot of this file is what stops them.
fn primitive_of(token: u8) -> Result<Primitive, DecodeError> {
    variant(Primitive::ALL, Vocabulary::Primitive, token)
}

/// An ownership token as the member it selects, on [`primitive_of`]'s terms.
fn ownership_of(token: u8) -> Result<Ownership, DecodeError> {
    variant(Ownership::ALL, Vocabulary::Ownership, token)
}

/// A dial outcome token as the member it selects, on [`primitive_of`]'s terms.
fn dial_outcome_of(token: u8) -> Result<DialOutcome, DecodeError> {
    variant(DialOutcome::ALL, Vocabulary::DialOutcome, token)
}

/// A next-hop-choice token as the member it selects, on the same terms.
fn next_hop_via_of(token: u8) -> Result<NextHopVia, DecodeError> {
    variant(NextHopVia::ALL, Vocabulary::NextHopVia, token)
}

/// A session-end token as the member it selects, on the same terms.
fn onboard_end_of(token: u8) -> Result<OnboardEnd, DecodeError> {
    variant(OnboardEnd::ALL, Vocabulary::OnboardEnd, token)
}

/// A handshake-outcome token as the member it selects, on the same terms.
fn onboard_outcome_of(token: u8) -> Result<OnboardOutcome, DecodeError> {
    variant(OnboardOutcome::ALL, Vocabulary::OnboardOutcome, token)
}

/// An incompatibility token as the member it selects, on the same terms.
fn tls_incompatible_of(token: u8) -> Result<TlsIncompatible, DecodeError> {
    variant(TlsIncompatible::ALL, Vocabulary::TlsIncompatible, token)
}

/// A refusal token as the member it selects, on the same terms.
fn tls_refusal_of(token: u8) -> Result<TlsRefusal, DecodeError> {
    variant(TlsRefusal::ALL, Vocabulary::TlsRefusal, token)
}

/// A resource token as the member it selects, on the same terms.
fn onboard_route_of(token: u8) -> Result<OnboardRoute, DecodeError> {
    variant(OnboardRoute::ALL, Vocabulary::OnboardRoute, token)
}

/// A request-refusal token as the member it selects, on the same terms.
fn onboard_refusal_of(token: u8) -> Result<OnboardRefusal, DecodeError> {
    variant(OnboardRefusal::ALL, Vocabulary::OnboardRefusal, token)
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
                    record.operands = [*start_sector, *sectors, 0, 0];
                }
                DomainDetail::RecordingResumed {
                    start_sector,
                    generation,
                    sequence,
                    offset,
                } => {
                    record.detail = LogDetailKind::RecordingResumed.to_bits();
                    record.operands = [*start_sector, *generation, *sequence, *offset];
                }
                DomainDetail::RecordingFresh {
                    start_sector,
                    rebound,
                } => {
                    record.detail = LogDetailKind::RecordingFresh.to_bits();
                    // The flag in the fourth word, where this ABI puts every one.
                    record.operands = [*start_sector, 0, 0, u64::from(*rebound)];
                }
                DomainDetail::Proven {
                    preemptions,
                    iterations,
                } => {
                    record.detail = LogDetailKind::Proven.to_bits();
                    record.operands = [*preemptions, *iterations, 0, 0];
                }
                DomainDetail::Proved { primitive, vectors } => {
                    record.detail = LogDetailKind::Proved.to_bits();
                    record.operands = [*primitive as u64, *vectors, 0, 0];
                }
                DomainDetail::Measured {
                    primitive,
                    milli_cycles_per_byte,
                } => {
                    record.detail = LogDetailKind::Measured.to_bits();
                    record.operands = [*primitive as u64, *milli_cycles_per_byte, 0, 0];
                }
                DomainDetail::Session { version, suite } => {
                    record.detail = LogDetailKind::Session.to_bits();
                    record.operands = [u64::from(*version), u64::from(*suite), 0, 0];
                }
                DomainDetail::Exchange { group, echoed } => {
                    record.detail = LogDetailKind::Exchange.to_bits();
                    record.operands = [u64::from(*group), *echoed, 0, 0];
                }
                DomainDetail::Peer { device } => {
                    record.detail = LogDetailKind::Peer.to_bits();
                    // The identifier is wider than an operand, so it crosses
                    // as its two halves, most significant first.
                    record.operands = [(*device >> 64) as u64, *device as u64, 0, 0];
                }
                DomainDetail::Arena { bytes, bound } => {
                    record.detail = LogDetailKind::Arena.to_bits();
                    record.operands = [*bytes, *bound, 0, 0];
                }
                DomainDetail::Operation { primitive, cycles } => {
                    record.detail = LogDetailKind::Operation.to_bits();
                    record.operands = [*primitive as u64, *cycles, 0, 0];
                }
                DomainDetail::Identity {
                    device,
                    generation,
                    onboarded,
                } => {
                    record.detail = LogDetailKind::Identity.to_bits();
                    // The identifier is wider than an operand, so it crosses as
                    // its two halves, most significant first — the same order
                    // `Peer` carries one in.
                    record.operands = [
                        (*device >> 64) as u64,
                        *device as u64,
                        *generation,
                        u64::from(*onboarded),
                    ];
                }
                DomainDetail::Fingerprint(digest) => {
                    record.detail = LogDetailKind::Fingerprint.to_bits();
                    record.operands = digest_words(digest);
                }
                DomainDetail::AnchorFingerprint(digest) => {
                    record.detail = LogDetailKind::AnchorFingerprint.to_bits();
                    record.operands = digest_words(digest);
                }
                DomainDetail::Ownership(ownership) => {
                    record.detail = LogDetailKind::Ownership.to_bits();
                    record.operands = [*ownership as u64, 0, 0, 0];
                }
                // The flag takes the FOURTH word, where this ABI puts the one
                // flag a detail may carry — `Identity`'s owner word and
                // `Reset`'s sit there too — so a reader of the encoding has one
                // position to know rather than one per detail.
                DomainDetail::DelegatedAnchor { delivered, anchor } => {
                    record.detail = LogDetailKind::DelegatedAnchor.to_bits();
                    record.operands = [*anchor, 0, 0, u64::from(*delivered)];
                }
                DomainDetail::Published {
                    destination,
                    port,
                    published,
                } => {
                    record.detail = LogDetailKind::Published.to_bits();
                    record.operands = [
                        u64::from(destination.bits()),
                        u64::from(*port),
                        0,
                        u64::from(*published),
                    ];
                }
                DomainDetail::Adopted {
                    destination,
                    port,
                    generation,
                } => {
                    record.detail = LogDetailKind::Adopted.to_bits();
                    record.operands = [
                        u64::from(destination.bits()),
                        u64::from(*port),
                        *generation,
                        0,
                    ];
                }
                DomainDetail::Reset {
                    generation,
                    documents,
                    was_owned,
                } => {
                    record.detail = LogDetailKind::Reset.to_bits();
                    // The flag in the fourth word, which is where this ABI
                    // carries every flag an operand holds.
                    record.operands = [*generation, *documents, 0, u64::from(*was_owned)];
                }
                DomainDetail::Dialled {
                    destination,
                    port,
                    attempts,
                    outcome,
                } => {
                    record.detail = LogDetailKind::Dialled.to_bits();
                    // The token first, where every detail whose leading word
                    // names a vocabulary carries it.
                    record.operands = [
                        *outcome as u64,
                        u64::from(destination.bits()),
                        u64::from(*port),
                        *attempts,
                    ];
                }
                DomainDetail::DialRoute {
                    next_hop,
                    via,
                    requests,
                    learned,
                } => {
                    record.detail = LogDetailKind::DialRoute.to_bits();
                    // The token first, where every detail whose leading word
                    // names a vocabulary carries it — `Dialled`'s own order.
                    record.operands =
                        [*via as u64, u64::from(next_hop.bits()), *requests, *learned];
                }
                DomainDetail::DialUnlearned {
                    unsolicited,
                    rebinding,
                    not_unicast,
                    contradicted,
                } => {
                    record.detail = LogDetailKind::DialUnlearned.to_bits();
                    record.operands = [*unsolicited, *rebinding, *not_unicast, *contradicted];
                }
                DomainDetail::DialSegments {
                    syns,
                    resets_received,
                    resets_sent,
                    answered,
                } => {
                    record.detail = LogDetailKind::DialSegments.to_bits();
                    // The flag in the fourth word, which is where this ABI
                    // carries every flag an operand holds.
                    record.operands = [*syns, *resets_received, *resets_sent, u64::from(*answered)];
                }
                DomainDetail::DialSequence { claimed, expected } => {
                    record.detail = LogDetailKind::DialSequence.to_bits();
                    record.operands = [u64::from(*claimed), u64::from(*expected), 0, 0];
                }
                DomainDetail::DialRetry {
                    delay_millis,
                    bound_millis,
                } => {
                    record.detail = LogDetailKind::DialRetry.to_bits();
                    record.operands = [*delay_millis, *bound_millis, 0, 0];
                }
                // The management channel's eight, on the onboarding port's
                // seven's terms exactly: the outcome takes the leading word
                // wherever a detail's first word names a vocabulary.
                DomainDetail::ChannelHandshake {
                    outcome,
                    version,
                    suite,
                    group,
                } => {
                    record.detail = LogDetailKind::ChannelHandshake.to_bits();
                    record.operands = [
                        *outcome as u64,
                        u64::from(*version),
                        u64::from(*suite),
                        u64::from(*group),
                    ];
                }
                DomainDetail::ChannelEnded { outcome } => {
                    record.detail = LogDetailKind::ChannelEnded.to_bits();
                    record.operands = [*outcome as u64, 0, 0, 0];
                }
                DomainDetail::ChannelIncompatible {
                    outcome,
                    incompatible,
                } => {
                    record.detail = LogDetailKind::ChannelIncompatible.to_bits();
                    record.operands = [*outcome as u64, *incompatible as u64, 0, 0];
                }
                DomainDetail::ChannelRefused { outcome, refusal } => {
                    record.detail = LogDetailKind::ChannelRefused.to_bits();
                    record.operands = [*outcome as u64, *refusal as u64, 0, 0];
                }
                DomainDetail::ChannelCertificate { outcome, refusal } => {
                    record.detail = LogDetailKind::ChannelCertificate.to_bits();
                    record.operands = [*outcome as u64, *refusal as u64, 0, 0];
                }
                DomainDetail::ChannelAlert { outcome, alert } => {
                    record.detail = LogDetailKind::ChannelAlert.to_bits();
                    record.operands = [*outcome as u64, u64::from(*alert), 0, 0];
                }
                DomainDetail::ChannelBacklogged { outcome, held } => {
                    record.detail = LogDetailKind::ChannelBacklogged.to_bits();
                    record.operands = [*outcome as u64, *held, 0, 0];
                }
                DomainDetail::ChannelFrames {
                    agreed,
                    version,
                    sent,
                    received,
                } => {
                    record.detail = LogDetailKind::ChannelFrames.to_bits();
                    record.operands = [u64::from(*agreed), u64::from(*version), *sent, *received];
                }
                DomainDetail::ChannelShipping {
                    log_position,
                    log_pending,
                    capture_position,
                    capture_pending,
                } => {
                    record.detail = LogDetailKind::ChannelShipping.to_bits();
                    record.operands = [
                        *log_position,
                        *log_pending,
                        *capture_position,
                        *capture_pending,
                    ];
                }
                DomainDetail::ChannelAcked {
                    log_acked,
                    log_sent,
                    capture_acked,
                    capture_sent,
                } => {
                    record.detail = LogDetailKind::ChannelAcked.to_bits();
                    record.operands = [*log_acked, *log_sent, *capture_acked, *capture_sent];
                }
                DomainDetail::Onboarded {
                    relayed,
                    received,
                    sent,
                    ended,
                } => {
                    record.detail = LogDetailKind::Onboarded.to_bits();
                    // The token first, where every detail whose leading word
                    // names a vocabulary carries it — `Dialled`'s own order.
                    record.operands = [*ended as u64, *relayed, *received, *sent];
                }
                DomainDetail::OnboardingPort {
                    accepted,
                    forgotten,
                    overflowed,
                    refused,
                } => {
                    record.detail = LogDetailKind::OnboardingPort.to_bits();
                    record.operands = [*accepted, *forgotten, *overflowed, *refused];
                }
                // The seven a handshake on the onboarding port produces. The
                // outcome token takes the leading word, where every detail whose
                // first word names a vocabulary carries it — `Dialled`'s own
                // order — and what follows is the fact that outcome holds.
                DomainDetail::OnboardingHandshake {
                    outcome,
                    version,
                    suite,
                    group,
                } => {
                    record.detail = LogDetailKind::OnboardingHandshake.to_bits();
                    record.operands = [
                        *outcome as u64,
                        u64::from(*version),
                        u64::from(*suite),
                        u64::from(*group),
                    ];
                }
                DomainDetail::OnboardingEnded { outcome } => {
                    record.detail = LogDetailKind::OnboardingEnded.to_bits();
                    record.operands = [*outcome as u64, 0, 0, 0];
                }
                DomainDetail::OnboardingIncompatible {
                    outcome,
                    incompatible,
                } => {
                    record.detail = LogDetailKind::OnboardingIncompatible.to_bits();
                    record.operands = [*outcome as u64, *incompatible as u64, 0, 0];
                }
                DomainDetail::OnboardingRefused { outcome, refusal } => {
                    record.detail = LogDetailKind::OnboardingRefused.to_bits();
                    record.operands = [*outcome as u64, *refusal as u64, 0, 0];
                }
                DomainDetail::OnboardingAlert { outcome, alert } => {
                    record.detail = LogDetailKind::OnboardingAlert.to_bits();
                    record.operands = [*outcome as u64, u64::from(*alert), 0, 0];
                }
                DomainDetail::OnboardingBacklogged { outcome, held } => {
                    record.detail = LogDetailKind::OnboardingBacklogged.to_bits();
                    record.operands = [*outcome as u64, *held, 0, 0];
                }
                // The two offer records, whose points are wider than an operand
                // and so cross packed four to a word, most significant first —
                // the order a digest and an identifier already cross in.
                DomainDetail::OnboardingSuites { points, offered } => {
                    record.detail = LogDetailKind::OnboardingSuites.to_bits();
                    record.operands = offer_words(points, *offered);
                }
                DomainDetail::OnboardingGroups { points, offered } => {
                    record.detail = LogDetailKind::OnboardingGroups.to_bits();
                    record.operands = offer_words(points, *offered);
                }
                // The three the request surface above the record layer
                // produces. Each leads with its own vocabulary's token, on
                // `OnboardingHandshake`'s order, and what follows is the fact
                // that token holds.
                DomainDetail::OnboardingServed { route, bytes } => {
                    record.detail = LogDetailKind::OnboardingServed.to_bits();
                    record.operands = [*route as u64, *bytes, 0, 0];
                }
                DomainDetail::OnboardingRequest {
                    refusal,
                    status,
                    held,
                } => {
                    record.detail = LogDetailKind::OnboardingRequest.to_bits();
                    record.operands = [*refusal as u64, u64::from(*status), *held, 0];
                }
                DomainDetail::OnboardingThrottled {
                    strikes,
                    wait_millis,
                } => {
                    record.detail = LogDetailKind::OnboardingThrottled.to_bits();
                    record.operands = [*strikes, *wait_millis, 0, 0];
                }
                DomainDetail::OnboardingInstalled { bytes } => {
                    record.detail = LogDetailKind::OnboardingInstalled.to_bits();
                    record.operands = [*bytes, 0, 0, 0];
                }
                DomainDetail::Delegated {
                    device,
                    signatures,
                    certificate,
                } => {
                    record.detail = LogDetailKind::Delegated.to_bits();
                    // The identifier in its two halves, most significant first,
                    // exactly as `Identity` and `Peer` carry one: three
                    // renderings of one value must not be three orders. The
                    // certificate's length takes the fourth word, which this
                    // detail is the one in the ABI not to carry a flag in.
                    record.operands = [
                        (*device >> 64) as u64,
                        *device as u64,
                        *signatures,
                        *certificate,
                    ];
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
                            record.operands = [*value, 0, 0, 0];
                        }
                        RefusalDetail::Two(first, second) => {
                            record.operand_count = 2;
                            record.operands = [*first, *second, 0, 0];
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
        // And here: a sector, a generation and two segment sequences, every bit
        // pattern of which a medium could hold. Whether the stored state is
        // *this* ring's is settled where the geometry is, not where the record
        // is read.
        CheckedDetail::RecordingResumed {
            start_sector,
            generation,
            sequence,
            offset,
        } => DomainDetail::RecordingResumed {
            start_sector: *start_sector,
            generation: *generation,
            sequence: *sequence,
            offset: *offset,
        },
        // The flag was ranged when the record was checked, so what is left is a
        // sector nothing can make unreadable.
        CheckedDetail::RecordingFresh {
            start_sector,
            rebound,
        } => DomainDetail::RecordingFresh {
            start_sector: *start_sector,
            rebound: *rebound,
        },
        // And here: two counts the emitting domain claims about its own run.
        CheckedDetail::Proven {
            preemptions,
            iterations,
        } => DomainDetail::Proven {
            preemptions: *preemptions,
            iterations: *iterations,
        },
        // The token was ranged against the set when the record was checked, so
        // what is left here is naming the member it selected.
        CheckedDetail::Proved { primitive, vectors } => DomainDetail::Proved {
            primitive: primitive_of(*primitive)?,
            vectors: *vectors,
        },
        CheckedDetail::Session { version, suite } => DomainDetail::Session {
            version: *version,
            suite: *suite,
        },
        CheckedDetail::Exchange { group, echoed } => DomainDetail::Exchange {
            group: *group,
            echoed: *echoed,
        },
        CheckedDetail::Peer { high, low } => DomainDetail::Peer {
            device: (u128::from(*high) << 64) | u128::from(*low),
        },
        CheckedDetail::Arena { bytes, bound } => DomainDetail::Arena {
            bytes: *bytes,
            bound: *bound,
        },
        CheckedDetail::Operation { primitive, cycles } => DomainDetail::Operation {
            primitive: primitive_of(*primitive)?,
            cycles: *cycles,
        },
        CheckedDetail::Measured {
            primitive,
            milli_cycles_per_byte,
        } => DomainDetail::Measured {
            primitive: primitive_of(*primitive)?,
            milli_cycles_per_byte: *milli_cycles_per_byte,
        },
        // Total: `wire` ranged the flag, and an identifier and a generation are
        // numbers every bit pattern of which a minted state could carry.
        CheckedDetail::Identity {
            high,
            low,
            generation,
            onboarded,
        } => DomainDetail::Identity {
            device: (u128::from(*high) << 64) | u128::from(*low),
            generation: *generation,
            onboarded: *onboarded,
        },
        // And here: every bit pattern of four words is a digest.
        CheckedDetail::Fingerprint { words } => DomainDetail::Fingerprint(digest_bytes(words)),
        CheckedDetail::AnchorFingerprint { words } => {
            DomainDetail::AnchorFingerprint(digest_bytes(words))
        }
        // The token was ranged against the set when the record was checked, so
        // what is left is naming the member it selected.
        CheckedDetail::Ownership { ownership } => {
            DomainDetail::Ownership(ownership_of(*ownership)?)
        }
        // Total: `wire` ranged the flag, and a size is a number every bit pattern
        // of which the holder could have handed over.
        CheckedDetail::DelegatedAnchor { delivered, anchor } => DomainDetail::DelegatedAnchor {
            delivered: *delivered,
            anchor: *anchor,
        },
        // Total on `Adopted`'s terms, with the flag ranged beside the two values
        // it qualifies.
        CheckedDetail::Published {
            destination,
            port,
            published,
        } => DomainDetail::Published {
            destination: net_headers::Ipv4Address::from_octets(destination.to_be_bytes()),
            port: *port,
            published: *published,
        },
        // Total: `wire` ranged the address and the port, and a generation is a
        // position every bit pattern of which a record could stand at.
        CheckedDetail::Adopted {
            destination,
            port,
            generation,
        } => DomainDetail::Adopted {
            destination: net_headers::Ipv4Address::from_octets(destination.to_be_bytes()),
            port: *port,
            generation: *generation,
        },
        // Total for `Identity`'s reason: `wire` ranged the flag, and a generation
        // and a count are numbers every bit pattern of which a reset could have
        // found.
        CheckedDetail::Reset {
            generation,
            documents,
            was_owned,
        } => DomainDetail::Reset {
            generation: *generation,
            documents: *documents,
            was_owned: *was_owned,
        },
        // Total: `wire` ranged the token, the address and the port, and an
        // attempt count is a tally every bit pattern of which this end could
        // have kept.
        CheckedDetail::Dialled {
            outcome,
            destination,
            port,
            attempts,
        } => DomainDetail::Dialled {
            destination: net_headers::Ipv4Address::from_octets(destination.to_be_bytes()),
            port: *port,
            attempts: *attempts,
            outcome: dial_outcome_of(*outcome)?,
        },
        // The token was ranged when the record was checked, as was the address,
        // so what is left is naming the member the token selected.
        CheckedDetail::DialRoute {
            via,
            next_hop,
            requests,
            learned,
        } => DomainDetail::DialRoute {
            next_hop: net_headers::Ipv4Address::from_octets(next_hop.to_be_bytes()),
            via: next_hop_via_of(*via)?,
            requests: *requests,
            learned: *learned,
        },
        // Total: four counts of replies this port turned away, every bit
        // pattern of each a tally a link under a flood could have produced.
        CheckedDetail::DialUnlearned {
            unsolicited,
            rebinding,
            not_unicast,
            contradicted,
        } => DomainDetail::DialUnlearned {
            unsolicited: *unsolicited,
            rebinding: *rebinding,
            not_unicast: *not_unicast,
            contradicted: *contradicted,
        },
        // Total for `Reset`'s reason: `wire` ranged the flag, and three counts
        // of segments are tallies whatever they hold.
        CheckedDetail::DialSegments {
            syns,
            resets_received,
            resets_sent,
            answered,
        } => DomainDetail::DialSegments {
            syns: *syns,
            resets_received: *resets_received,
            resets_sent: *resets_sent,
            answered: *answered,
        },
        // Total: both words were ranged to the width a sequence number has, and
        // every value inside it is one — the peer's claim included, which is
        // reported and never judged.
        CheckedDetail::DialSequence { claimed, expected } => DomainDetail::DialSequence {
            claimed: *claimed,
            expected: *expected,
        },
        // Total: two spans in milliseconds, and every bit pattern of each is a
        // span the schedule could have drawn or climbed to. Neither is ranged
        // against the schedule's own cap, because a record is what a domain
        // said rather than what a reader wishes it had said.
        CheckedDetail::DialRetry {
            delay_millis,
            bound_millis,
        } => DomainDetail::DialRetry {
            delay_millis: *delay_millis,
            bound_millis: *bound_millis,
        },
        // Every token below was ranged to its own vocabulary by `wire`, so the
        // indexes are in bounds by construction; the counts beside them are
        // tallies the emitting domain kept about its own session.
        CheckedDetail::ChannelHandshake {
            outcome,
            version,
            suite,
            group,
        } => DomainDetail::ChannelHandshake {
            outcome: ChannelOutcome::ALL[*outcome as usize],
            version: *version,
            suite: *suite,
            group: *group,
        },
        CheckedDetail::ChannelEnded { outcome } => DomainDetail::ChannelEnded {
            outcome: ChannelOutcome::ALL[*outcome as usize],
        },
        CheckedDetail::ChannelIncompatible {
            outcome,
            incompatible,
        } => DomainDetail::ChannelIncompatible {
            outcome: ChannelOutcome::ALL[*outcome as usize],
            incompatible: TlsIncompatible::ALL[*incompatible as usize],
        },
        CheckedDetail::ChannelRefused { outcome, refusal } => DomainDetail::ChannelRefused {
            outcome: ChannelOutcome::ALL[*outcome as usize],
            refusal: TlsRefusal::ALL[*refusal as usize],
        },
        CheckedDetail::ChannelCertificate { outcome, refusal } => {
            DomainDetail::ChannelCertificate {
                outcome: ChannelOutcome::ALL[*outcome as usize],
                refusal: TlsCertificateRefusal::ALL[*refusal as usize],
            }
        }
        CheckedDetail::ChannelAlert { outcome, alert } => DomainDetail::ChannelAlert {
            outcome: ChannelOutcome::ALL[*outcome as usize],
            alert: *alert,
        },
        CheckedDetail::ChannelBacklogged { outcome, held } => DomainDetail::ChannelBacklogged {
            outcome: ChannelOutcome::ALL[*outcome as usize],
            held: *held,
        },
        CheckedDetail::ChannelFrames {
            agreed,
            version,
            sent,
            received,
        } => DomainDetail::ChannelFrames {
            agreed: *agreed,
            version: *version,
            sent: *sent,
            received: *received,
        },
        // Four positions, none ranged: `wire` accepted every bit pattern of each
        // because each is a byte position or a count the reading domain held.
        CheckedDetail::ChannelShipping {
            log_position,
            log_pending,
            capture_position,
            capture_pending,
        } => DomainDetail::ChannelShipping {
            log_position: *log_position,
            log_pending: *log_pending,
            capture_position: *capture_position,
            capture_pending: *capture_pending,
        },
        // Four positions, none ranged, on `ChannelShipping`'s terms exactly.
        CheckedDetail::ChannelAcked {
            log_acked,
            log_sent,
            capture_acked,
            capture_sent,
        } => DomainDetail::ChannelAcked {
            log_acked: *log_acked,
            log_sent: *log_sent,
            capture_acked: *capture_acked,
            capture_sent: *capture_sent,
        },
        // The token was ranged to the vocabulary by `wire`; the three counts are
        // tallies the emitting domain kept about its own session, so every bit
        // pattern of each is one it could have written.
        CheckedDetail::Onboarded {
            ended,
            relayed,
            received,
            sent,
        } => DomainDetail::Onboarded {
            relayed: *relayed,
            received: *received,
            sent: *sent,
            ended: onboard_end_of(*ended)?,
        },
        // Four tallies and no token, so nothing is ranged: every bit pattern of
        // each is a count the port could have kept about itself.
        CheckedDetail::OnboardingPort {
            accepted,
            forgotten,
            overflowed,
            refused,
        } => DomainDetail::OnboardingPort {
            accepted: *accepted,
            forgotten: *forgotten,
            overflowed: *overflowed,
            refused: *refused,
        },
        // The seven a handshake produces. Each carries a token `wire` ranged to
        // the vocabulary this crate then maps, so the only refusal any of them
        // can earn is that mapping's — a token inside the ABI's bound naming no
        // variant this build has.
        CheckedDetail::OnboardingHandshake {
            outcome,
            version,
            suite,
            group,
        } => DomainDetail::OnboardingHandshake {
            outcome: onboard_outcome_of(*outcome)?,
            version: *version,
            suite: *suite,
            group: *group,
        },
        CheckedDetail::OnboardingEnded { outcome } => DomainDetail::OnboardingEnded {
            outcome: onboard_outcome_of(*outcome)?,
        },
        CheckedDetail::OnboardingIncompatible {
            outcome,
            incompatible,
        } => DomainDetail::OnboardingIncompatible {
            outcome: onboard_outcome_of(*outcome)?,
            incompatible: tls_incompatible_of(*incompatible)?,
        },
        CheckedDetail::OnboardingRefused { outcome, refusal } => DomainDetail::OnboardingRefused {
            outcome: onboard_outcome_of(*outcome)?,
            refusal: tls_refusal_of(*refusal)?,
        },
        CheckedDetail::OnboardingAlert { outcome, alert } => DomainDetail::OnboardingAlert {
            outcome: onboard_outcome_of(*outcome)?,
            alert: *alert,
        },
        CheckedDetail::OnboardingBacklogged { outcome, held } => {
            DomainDetail::OnboardingBacklogged {
                outcome: onboard_outcome_of(*outcome)?,
                held: *held,
            }
        }
        // Total: `wire` unpacked eight code points out of two words, which every
        // bit pattern of them is, and ranged the count to the width one has.
        CheckedDetail::OnboardingSuites { points, offered } => DomainDetail::OnboardingSuites {
            points: *points,
            offered: *offered,
        },
        CheckedDetail::OnboardingGroups { points, offered } => DomainDetail::OnboardingGroups {
            points: *points,
            offered: *offered,
        },
        // The request surface's three, on the handshake records' terms: `wire`
        // ranged the token to the vocabulary's width and this crate maps it, so
        // the only refusal any of them can earn is a token inside that bound
        // naming no variant this build has.
        CheckedDetail::OnboardingServed { route, bytes } => DomainDetail::OnboardingServed {
            route: onboard_route_of(*route)?,
            bytes: *bytes,
        },
        CheckedDetail::OnboardingRequest {
            refusal,
            status,
            held,
        } => DomainDetail::OnboardingRequest {
            refusal: onboard_refusal_of(*refusal)?,
            status: *status,
            held: *held,
        },
        CheckedDetail::OnboardingThrottled {
            strikes,
            wait_millis,
        } => DomainDetail::OnboardingThrottled {
            strikes: *strikes,
            wait_millis: *wait_millis,
        },
        CheckedDetail::OnboardingInstalled { bytes } => {
            DomainDetail::OnboardingInstalled { bytes: *bytes }
        }
        // Total for the same reason with nothing ranged at all: an identifier is
        // 128 bits of randomness and both counts are tallies, so every bit pattern
        // of the four words is one a delegating domain could have read.
        CheckedDetail::Delegated {
            high,
            low,
            signatures,
            certificate,
        } => DomainDetail::Delegated {
            device: (u128::from(*high) << 64) | u128::from(*low),
            signatures: *signatures,
            certificate: *certificate,
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
                    DomainDetail::RecordingResumed {
                        start_sector,
                        generation,
                        sequence,
                        offset,
                    } => DomainDetail::RecordingResumed {
                        start_sector,
                        generation,
                        sequence,
                        offset,
                    },
                    DomainDetail::RecordingFresh {
                        start_sector,
                        rebound,
                    } => DomainDetail::RecordingFresh {
                        start_sector,
                        rebound,
                    },
                    DomainDetail::Proven {
                        preemptions,
                        iterations,
                    } => DomainDetail::Proven {
                        preemptions,
                        iterations,
                    },
                    DomainDetail::Proved { primitive, vectors } => {
                        DomainDetail::Proved { primitive, vectors }
                    }
                    DomainDetail::Ownership(ownership) => DomainDetail::Ownership(ownership),
                    DomainDetail::Session { version, suite } => {
                        DomainDetail::Session { version, suite }
                    }
                    DomainDetail::Exchange { group, echoed } => {
                        DomainDetail::Exchange { group, echoed }
                    }
                    DomainDetail::Peer { device } => DomainDetail::Peer { device },
                    DomainDetail::Arena { bytes, bound } => DomainDetail::Arena { bytes, bound },
                    DomainDetail::OnboardingHandshake {
                        outcome,
                        version,
                        suite,
                        group,
                    } => DomainDetail::OnboardingHandshake {
                        outcome,
                        version,
                        suite,
                        group,
                    },
                    DomainDetail::OnboardingEnded { outcome } => {
                        DomainDetail::OnboardingEnded { outcome }
                    }
                    DomainDetail::OnboardingIncompatible {
                        outcome,
                        incompatible,
                    } => DomainDetail::OnboardingIncompatible {
                        outcome,
                        incompatible,
                    },
                    DomainDetail::OnboardingRefused { outcome, refusal } => {
                        DomainDetail::OnboardingRefused { outcome, refusal }
                    }
                    DomainDetail::OnboardingAlert { outcome, alert } => {
                        DomainDetail::OnboardingAlert { outcome, alert }
                    }
                    DomainDetail::OnboardingBacklogged { outcome, held } => {
                        DomainDetail::OnboardingBacklogged { outcome, held }
                    }
                    DomainDetail::OnboardingSuites { points, offered } => {
                        DomainDetail::OnboardingSuites { points, offered }
                    }
                    DomainDetail::OnboardingGroups { points, offered } => {
                        DomainDetail::OnboardingGroups { points, offered }
                    }
                    DomainDetail::OnboardingServed { route, bytes } => {
                        DomainDetail::OnboardingServed { route, bytes }
                    }
                    DomainDetail::OnboardingRequest {
                        refusal,
                        status,
                        held,
                    } => DomainDetail::OnboardingRequest {
                        refusal,
                        status,
                        held,
                    },
                    DomainDetail::OnboardingThrottled {
                        strikes,
                        wait_millis,
                    } => DomainDetail::OnboardingThrottled {
                        strikes,
                        wait_millis,
                    },
                    DomainDetail::OnboardingInstalled { bytes } => {
                        DomainDetail::OnboardingInstalled { bytes }
                    }
                    DomainDetail::Operation { primitive, cycles } => {
                        DomainDetail::Operation { primitive, cycles }
                    }
                    DomainDetail::Identity {
                        device,
                        generation,
                        onboarded,
                    } => DomainDetail::Identity {
                        device,
                        generation,
                        onboarded,
                    },
                    DomainDetail::Fingerprint(digest) => DomainDetail::Fingerprint(digest),
                    DomainDetail::AnchorFingerprint(digest) => {
                        DomainDetail::AnchorFingerprint(digest)
                    }
                    DomainDetail::Adopted {
                        destination,
                        port,
                        generation,
                    } => DomainDetail::Adopted {
                        destination,
                        port,
                        generation,
                    },
                    DomainDetail::DelegatedAnchor { delivered, anchor } => {
                        DomainDetail::DelegatedAnchor { delivered, anchor }
                    }
                    DomainDetail::Published {
                        destination,
                        port,
                        published,
                    } => DomainDetail::Published {
                        destination,
                        port,
                        published,
                    },
                    DomainDetail::Reset {
                        generation,
                        documents,
                        was_owned,
                    } => DomainDetail::Reset {
                        generation,
                        documents,
                        was_owned,
                    },
                    DomainDetail::Delegated {
                        device,
                        signatures,
                        certificate,
                    } => DomainDetail::Delegated {
                        device,
                        signatures,
                        certificate,
                    },
                    DomainDetail::DialRoute {
                        next_hop,
                        via,
                        requests,
                        learned,
                    } => DomainDetail::DialRoute {
                        next_hop,
                        via,
                        requests,
                        learned,
                    },
                    DomainDetail::DialUnlearned {
                        unsolicited,
                        rebinding,
                        not_unicast,
                        contradicted,
                    } => DomainDetail::DialUnlearned {
                        unsolicited,
                        rebinding,
                        not_unicast,
                        contradicted,
                    },
                    DomainDetail::DialSegments {
                        syns,
                        resets_received,
                        resets_sent,
                        answered,
                    } => DomainDetail::DialSegments {
                        syns,
                        resets_received,
                        resets_sent,
                        answered,
                    },
                    DomainDetail::DialSequence { claimed, expected } => {
                        DomainDetail::DialSequence { claimed, expected }
                    }
                    DomainDetail::DialRetry {
                        delay_millis,
                        bound_millis,
                    } => DomainDetail::DialRetry {
                        delay_millis,
                        bound_millis,
                    },
                    DomainDetail::ChannelHandshake {
                        outcome,
                        version,
                        suite,
                        group,
                    } => DomainDetail::ChannelHandshake {
                        outcome,
                        version,
                        suite,
                        group,
                    },
                    DomainDetail::ChannelEnded { outcome } => {
                        DomainDetail::ChannelEnded { outcome }
                    }
                    DomainDetail::ChannelIncompatible {
                        outcome,
                        incompatible,
                    } => DomainDetail::ChannelIncompatible {
                        outcome,
                        incompatible,
                    },
                    DomainDetail::ChannelRefused { outcome, refusal } => {
                        DomainDetail::ChannelRefused { outcome, refusal }
                    }
                    DomainDetail::ChannelCertificate { outcome, refusal } => {
                        DomainDetail::ChannelCertificate { outcome, refusal }
                    }
                    DomainDetail::ChannelAlert { outcome, alert } => {
                        DomainDetail::ChannelAlert { outcome, alert }
                    }
                    DomainDetail::ChannelBacklogged { outcome, held } => {
                        DomainDetail::ChannelBacklogged { outcome, held }
                    }
                    DomainDetail::ChannelFrames {
                        agreed,
                        version,
                        sent,
                        received,
                    } => DomainDetail::ChannelFrames {
                        agreed,
                        version,
                        sent,
                        received,
                    },
                    DomainDetail::ChannelShipping {
                        log_position,
                        log_pending,
                        capture_position,
                        capture_pending,
                    } => DomainDetail::ChannelShipping {
                        log_position,
                        log_pending,
                        capture_position,
                        capture_pending,
                    },
                    DomainDetail::ChannelAcked {
                        log_acked,
                        log_sent,
                        capture_acked,
                        capture_sent,
                    } => DomainDetail::ChannelAcked {
                        log_acked,
                        log_sent,
                        capture_acked,
                        capture_sent,
                    },
                    DomainDetail::Onboarded {
                        relayed,
                        received,
                        sent,
                        ended,
                    } => DomainDetail::Onboarded {
                        relayed,
                        received,
                        sent,
                        ended,
                    },
                    DomainDetail::OnboardingPort {
                        accepted,
                        forgotten,
                        overflowed,
                        refused,
                    } => DomainDetail::OnboardingPort {
                        accepted,
                        forgotten,
                        overflowed,
                        refused,
                    },
                    DomainDetail::Dialled {
                        destination,
                        port,
                        attempts,
                        outcome,
                    } => DomainDetail::Dialled {
                        destination,
                        port,
                        attempts,
                        outcome,
                    },
                    DomainDetail::Measured {
                        primitive,
                        milli_cycles_per_byte,
                    } => DomainDetail::Measured {
                        primitive,
                        milli_cycles_per_byte,
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

/// A 256-bit digest as the four operand words it crosses in, most significant
/// first — the order a hexadecimal rendering reads in, so the words are the
/// string's own halves rather than an encoding a reader has to undo.
///
/// Total over the array: `chunks_exact` yields whole eight-byte chunks and the
/// zip stops at the shorter side, so neither index can leave either buffer.
fn digest_words(digest: &[u8; DIGEST_BYTES]) -> [u64; LOG_OPERANDS] {
    let mut words = [0_u64; LOG_OPERANDS];
    for (word, chunk) in words.iter_mut().zip(digest.chunks_exact(8)) {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        *word = u64::from_be_bytes(bytes);
    }
    words
}

/// An offer as the operand words it crosses in: eight code points packed four
/// to a word, most significant first, and the number really offered in the
/// third.
///
/// Total over the array: the zip stops at the shorter side and the shift is
/// derived from the slot's own position, so no index can leave either.
fn offer_words(points: &[u16; crate::MAX_OFFERED_POINTS], offered: u16) -> [u64; LOG_OPERANDS] {
    let mut words = [0_u64; LOG_OPERANDS];
    for (index, point) in points.iter().enumerate() {
        let word = if index < 4 { 0 } else { 1 };
        let shift = 48 - 16 * (index % 4);
        if let Some(slot) = words.get_mut(word) {
            *slot |= u64::from(*point) << shift;
        }
    }
    if let Some(slot) = words.get_mut(2) {
        *slot = u64::from(offered);
    }
    words
}

/// [`digest_words`]'s inverse, on the same terms.
fn digest_bytes(words: &[u64; LOG_OPERANDS]) -> [u8; DIGEST_BYTES] {
    let mut digest = [0_u8; DIGEST_BYTES];
    for (chunk, word) in digest.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

// The two crates each hold a copy of every vocabulary's cardinality and of
// every text field's width. Neither copy is derived from the other, so only a
// place that has seen both can hold them equal — and the widths below are what
// let a token be read as an array index and a bounded text be copied whole.
const _: () = {
    assert!(Domain::ALL.len() == wire::LOG_DOMAIN_COUNT as usize);
    // And the relay a printed line crosses to the recording on must carry the
    // widest line this grammar renders. A relay one byte narrower would drop
    // exactly the refusal lines a recording is read for.
    assert!(crate::render::MAX_LINE_LEN == wire::RELAY_LINE_BYTES);
    assert!(DomainState::ALL.len() == wire::LOG_DOMAIN_STATE_COUNT as usize);
    assert!(ChangeKind::ALL.len() == wire::LOG_CHANGE_KIND_COUNT as usize);
    assert!(ObjectKind::ALL.len() == wire::LOG_OBJECT_KIND_COUNT as usize);
    assert!(Field::ALL.len() == wire::LOG_FIELD_COUNT as usize);
    assert!(GenerationOutcome::ALL.len() == wire::LOG_GENERATION_OUTCOME_COUNT as usize);
    assert!(RejectReason::ALL.len() == wire::LOG_REJECT_REASON_COUNT as usize);
    assert!(Primitive::ALL.len() == wire::LOG_PRIMITIVE_COUNT as usize);
    assert!(DialOutcome::ALL.len() == wire::LOG_DIAL_OUTCOME_COUNT as usize);
    assert!(NextHopVia::ALL.len() == wire::LOG_NEXT_HOP_VIA_COUNT as usize);
    assert!(OnboardEnd::ALL.len() == wire::LOG_ONBOARD_END_COUNT as usize);
    assert!(OnboardOutcome::ALL.len() == wire::LOG_ONBOARD_OUTCOME_COUNT as usize);
    assert!(TlsIncompatible::ALL.len() == wire::LOG_TLS_INCOMPATIBLE_COUNT as usize);
    assert!(TlsRefusal::ALL.len() == wire::LOG_TLS_REFUSAL_COUNT as usize);
    assert!(OnboardRoute::ALL.len() == wire::LOG_ONBOARD_ROUTE_COUNT as usize);
    assert!(OnboardRefusal::ALL.len() == wire::LOG_ONBOARD_REFUSAL_COUNT as usize);
    assert!(Ownership::ALL.len() == wire::LOG_OWNERSHIP_COUNT as usize);
    assert!(crate::MAX_OFFERED_POINTS == wire::LOG_OFFERED_POINTS);

    assert!(crate::MAX_IDENTIFIER_LEN == wire::LOG_IDENTIFIER_BYTES);
    assert!(crate::MAX_CAUSE_LEN == wire::LOG_CAUSE_BYTES);

    // A token is read as an index into `ALL`, and a length is written into a
    // `u8` field of the image: a vocabulary or a text wider than that field
    // would be a silent narrowing at every crossing.
    assert!(wire::LOG_IDENTIFIER_BYTES <= u8::MAX as usize);
    assert!(wire::LOG_CAUSE_BYTES <= u8::MAX as usize);

    // A digest crosses as whole operand words, so its width must divide them
    // exactly: a remainder would be bytes the record silently drops off a
    // fingerprint an administrator is about to compare character for character.
    assert!(DIGEST_BYTES == LOG_OPERANDS * 8);
};

#[cfg(test)]
mod tests;
