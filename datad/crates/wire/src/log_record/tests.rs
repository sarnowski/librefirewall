use super::*;
use proptest::prelude::*;
use std::{format, string::String, vec::Vec};

/// The whole record as bytes, which is what a writing domain leaves in the
/// region and the console domain reads back out of it.
const RECORD_BYTES: usize = size_of::<LogRecord>();

/// Every bit pattern is a valid record — the fields are integers and integer
/// arrays only — so this is the region's whole input space, and a property over
/// it is a property over anything a byzantine writer can leave behind.
fn record_from_bytes(bytes: [u8; RECORD_BYTES]) -> LogRecord {
    // SAFETY: `LogRecord` is `#[repr(C)]`, `Copy`, and asserted above to be
    // exactly the sum of its fields' sizes, so it has no padding and every one
    // of its `RECORD_BYTES` bytes belongs to an integer field that admits any
    // bit pattern.
    unsafe { core::mem::transmute(bytes) }
}

fn record_to_bytes(record: LogRecord) -> [u8; RECORD_BYTES] {
    // SAFETY: the same size-and-no-padding guarantee in reverse.
    unsafe { core::mem::transmute(record) }
}

impl LogRecord {
    /// The body a record decodes to. Most assertions below are about a body,
    /// and the stamp in front of it is exercised by the tests that name one, so
    /// this keeps a case's `Err` the body's own rather than the stamp's.
    fn body(&self) -> Result<CheckedBody, LogRecordError> {
        self.check().map(|checked| checked.body)
    }
}

fn text<const N: usize>(value: &[u8]) -> TextImage<N> {
    let mut image = TextImage::<N>::ZERO;
    for (slot, &byte) in image.bytes.iter_mut().zip(value) {
        *slot = byte;
    }
    image.len = value.len() as u8;
    image
}

fn domain_record() -> LogRecord {
    LogRecord {
        kind: LogKind::Domain.to_bits(),
        domain: 1,
        state: 2,
        ..LogRecord::ZERO
    }
}

fn refusal_record() -> LogRecord {
    LogRecord {
        detail: LogDetailKind::Refusal.to_bits(),
        cause: text(b"not-virtio-net"),
        operands: [0x1af4, 0x1000, 0, 0],
        operand_count: 2,
        signalled: 1,
        ..domain_record()
    }
}

fn change_record() -> LogRecord {
    LogRecord {
        kind: LogKind::ConfigChange.to_bits(),
        generation: 7,
        sequence: 3,
        change: 2,
        object: 0,
        key: text(b"wan"),
        field: 4,
        from: ValueImage {
            number: 24,
            kind: LogValueKind::PrefixLength.to_bits(),
            ..ValueImage::ZERO
        },
        to: ValueImage {
            number: 25,
            kind: LogValueKind::PrefixLength.to_bits(),
            ..ValueImage::ZERO
        },
        ..LogRecord::ZERO
    }
}

#[test]
fn the_layout_the_console_domain_maps_is_the_recorded_one() {
    assert_eq!(size_of::<IdentifierImage>(), 20);
    assert_eq!(size_of::<CauseImage>(), 44);
    assert_eq!(size_of::<ValueImage>(), 32);
    assert_eq!(size_of::<LogRecord>(), 264);
    assert_eq!(align_of::<LogRecord>(), 8);
    assert_eq!(
        [
            offset_of!(LogRecord, features),
            offset_of!(LogRecord, operands),
            offset_of!(LogRecord, tsc_hz),
            offset_of!(LogRecord, unix_nanos),
            offset_of!(LogRecord, frames),
            offset_of!(LogRecord, frame_bytes),
            offset_of!(LogRecord, capacity_sectors),
            offset_of!(LogRecord, leading_word),
            offset_of!(LogRecord, stamp_nanos),
            offset_of!(LogRecord, kind),
            offset_of!(LogRecord, stamp_kind),
            offset_of!(LogRecord, cause),
            offset_of!(LogRecord, key),
            offset_of!(LogRecord, from),
            offset_of!(LogRecord, to),
        ],
        [
            0, 8, 40, 48, 56, 64, 72, 80, 88, 96, 130, 136, 180, 200, 232
        ]
    );
}

/// The exact on-wire image the console domain reads, beyond size and offsets:
/// a field lands at its offset in the byte order x86_64 gives it.
#[test]
fn a_record_has_a_stable_little_endian_byte_image() {
    let record = LogRecord {
        features: 0x1122_3344_5566_7788,
        stamp_nanos: 0x0102_0304_0506_0708,
        kind: 0x0000_00ff,
        stamp_kind: LogStampKind::Utc.to_bits(),
        ..LogRecord::ZERO
    };
    let bytes = record_to_bytes(record);
    assert_eq!(
        &bytes[0..8],
        &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
    );
    assert_eq!(
        &bytes[88..96],
        &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
    );
    assert_eq!(&bytes[96..100], &[0xff, 0x00, 0x00, 0x00]);
    assert_eq!(&bytes[130..131], &[0x01]);
    assert_eq!(record_from_bytes(bytes), record);
}

#[test]
fn a_zeroed_region_is_already_a_decodable_record() {
    assert_eq!(LogRecord::default(), LogRecord::ZERO);
    assert_eq!(
        LogRecord::ZERO.body(),
        Ok(CheckedBody::Domain {
            domain: 0,
            state: 0,
            detail: CheckedDetail::None,
        })
    );
}

#[test]
fn a_domain_record_carries_each_detail_shape() {
    assert_eq!(
        domain_record().body(),
        Ok(CheckedBody::Domain {
            domain: 1,
            state: 2,
            detail: CheckedDetail::None,
        })
    );

    let features = LogRecord {
        detail: LogDetailKind::Features.to_bits(),
        features: 0x8000_0000_0000_0001,
        ..domain_record()
    };
    assert!(matches!(
        features.body(),
        Ok(CheckedBody::Domain {
            detail: CheckedDetail::Features(0x8000_0000_0000_0001),
            ..
        })
    ));

    let posted = LogRecord {
        detail: LogDetailKind::ReceivePosted.to_bits(),
        receive_posted: 256,
        ..domain_record()
    };
    assert!(matches!(
        posted.body(),
        Ok(CheckedBody::Domain {
            detail: CheckedDetail::ReceivePosted(256),
            ..
        })
    ));

    let established = LogRecord {
        detail: LogDetailKind::Established.to_bits(),
        tsc_hz: 2_999_998_000,
        unix_nanos: u64::MAX,
        ..domain_record()
    };
    let Ok(CheckedBody::Domain {
        detail: CheckedDetail::Established { tsc_hz, unix_nanos },
        ..
    }) = established.body()
    else {
        panic!("an established clock decodes to one");
    };
    assert_eq!(tsc_hz.get(), 2_999_998_000);
    assert_eq!(unix_nanos, u64::MAX);

    let received = LogRecord {
        detail: LogDetailKind::Received.to_bits(),
        frames: 4,
        frame_bytes: 352,
        ..domain_record()
    };
    assert!(matches!(
        received.body(),
        Ok(CheckedBody::Domain {
            detail: CheckedDetail::Received {
                frames: 4,
                bytes: 352,
            },
            ..
        })
    ));

    let proven = LogRecord {
        detail: LogDetailKind::Proven.to_bits(),
        operands: [3, 90_000, 0, 0],
        ..domain_record()
    };
    assert!(matches!(
        proven.body(),
        Ok(CheckedBody::Domain {
            detail: CheckedDetail::Proven {
                preemptions: 3,
                iterations: 90_000,
            },
            ..
        })
    ));

    let proved = LogRecord {
        detail: LogDetailKind::Proved.to_bits(),
        operands: [5, 22, 0, 0],
        ..domain_record()
    };
    assert!(matches!(
        proved.body(),
        Ok(CheckedBody::Domain {
            detail: CheckedDetail::Proved {
                primitive: 5,
                vectors: 22,
            },
            ..
        })
    ));

    let measured = LogRecord {
        detail: LogDetailKind::Measured.to_bits(),
        operands: [0, 11_740, 0, 0],
        ..domain_record()
    };
    assert!(matches!(
        measured.body(),
        Ok(CheckedBody::Domain {
            detail: CheckedDetail::Measured {
                primitive: 0,
                milli_cycles_per_byte: 11_740,
            },
            ..
        })
    ));

    let identity = LogRecord {
        detail: LogDetailKind::Identity.to_bits(),
        operands: [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210, 7, 1],
        ..domain_record()
    };
    assert!(matches!(
        identity.body(),
        Ok(CheckedBody::Domain {
            detail: CheckedDetail::Identity {
                high: 0x0123_4567_89ab_cdef,
                low: 0xfedc_ba98_7654_3210,
                generation: 7,
                onboarded: true,
            },
            ..
        })
    ));

    // The one detail that reads all four words, and the reason the array is
    // four wide: a digest crosses whole rather than as two records a reader
    // would have to join.
    let fingerprint = LogRecord {
        detail: LogDetailKind::Fingerprint.to_bits(),
        operands: [1, 2, 3, 4],
        ..domain_record()
    };
    assert!(matches!(
        fingerprint.body(),
        Ok(CheckedBody::Domain {
            detail: CheckedDetail::Fingerprint {
                words: [1, 2, 3, 4],
            },
            ..
        })
    ));

    let Ok(CheckedBody::Domain {
        detail:
            CheckedDetail::Refusal {
                cause,
                operands,
                signalled,
            },
        ..
    }) = refusal_record().body()
    else {
        panic!("a refusal decodes to a refusal");
    };
    assert_eq!(cause.as_str(), "not-virtio-net");
    assert_eq!(cause.len(), 14);
    assert!(!cause.is_empty());
    assert_eq!(operands, CheckedOperands::Two(0x1af4, 0x1000));
    assert!(signalled);
}

/// The identity detail's one refusable field: a flag word holding neither 0 nor
/// 1 is a record this writer would not have written, so it is refused rather
/// than read as "unowned" — which would report an appliance as having no owner
/// on the strength of a word that said something else.
#[test]
fn an_identity_flag_outside_the_two_it_admits_is_refused() {
    for value in [2, 3, u64::MAX] {
        let record = LogRecord {
            detail: LogDetailKind::Identity.to_bits(),
            operands: [1, 2, 3, value],
            ..domain_record()
        };
        assert_eq!(
            record.body(),
            Err(LogRecordError::OperandFlagNotBoolean { value })
        );
    }
    for (value, onboarded) in [(0, false), (1, true)] {
        let record = LogRecord {
            detail: LogDetailKind::Identity.to_bits(),
            operands: [1, 2, 3, value],
            ..domain_record()
        };
        assert!(matches!(
            record.body(),
            Ok(CheckedBody::Domain {
                detail: CheckedDetail::Identity { onboarded: got, .. },
                ..
            }) if got == onboarded
        ));
    }
}

/// A refusal names at most the leading pair whatever the array holds, so the
/// two words past it are storage the record does not claim: a value in them
/// cannot move what a refusal decodes to.
#[test]
fn the_operand_words_past_a_refusals_pair_are_storage_it_does_not_claim() {
    let claimed = refusal_record().body();
    let scribbled = LogRecord {
        operands: [0x1af4, 0x1000, u64::MAX, u64::MAX],
        ..refusal_record()
    };
    assert_eq!(scribbled.body(), claimed);
}

#[test]
fn a_refusal_carries_as_many_operands_as_it_named() {
    for (count, expected) in [
        (0, CheckedOperands::None),
        (1, CheckedOperands::One(0x1af4)),
        (2, CheckedOperands::Two(0x1af4, 0x1000)),
    ] {
        let record = LogRecord {
            operand_count: count,
            ..refusal_record()
        };
        assert!(matches!(
            record.body(),
            Ok(CheckedBody::Domain { detail: CheckedDetail::Refusal { operands, .. }, .. })
                if operands == expected
        ));
    }
}

/// A refusal with nothing to say still decodes: the writing side's field is a
/// `&'static str`, which may be empty, so refusing one here would put a record
/// the log crate can produce outside what this ABI accepts.
#[test]
fn a_refusal_cause_may_be_empty_where_an_identifier_may_not() {
    let record = LogRecord {
        cause: CauseImage::ZERO,
        ..refusal_record()
    };
    assert!(matches!(
        record.body(),
        Ok(CheckedBody::Domain { detail: CheckedDetail::Refusal { cause, .. }, .. })
            if cause.is_empty() && cause.as_str().is_empty()
    ));
    assert_eq!(
        LogRecord {
            key: IdentifierImage::ZERO,
            ..change_record()
        }
        .body(),
        Err(LogRecordError::TextEmpty { text: LogText::Key })
    );
}

#[test]
fn a_change_record_carries_its_key_field_and_both_values() {
    let Ok(CheckedBody::ConfigChange {
        generation,
        sequence,
        change,
        object,
        key,
        field,
        from,
        to,
    }) = change_record().body()
    else {
        panic!("the record is well formed");
    };
    assert_eq!((generation, sequence), (7, 3));
    assert_eq!((change, object, field), (2, 0, 4));
    assert_eq!(key.as_str(), "wan");
    assert_eq!(key.as_bytes(), b"wan");
    assert_eq!(from, Some(CheckedValue::PrefixLength(24)));
    assert_eq!(to, Some(CheckedValue::PrefixLength(25)));
}

/// An added object has no `from` and a removed one no `to`, which the absent
/// value kind is what carries.
#[test]
fn an_absent_value_decodes_to_none() {
    let record = LogRecord {
        from: ValueImage::ZERO,
        ..change_record()
    };
    assert!(matches!(
        record.body(),
        Ok(CheckedBody::ConfigChange {
            from: None,
            to: Some(_),
            ..
        })
    ));
}

#[test]
fn every_value_kind_decodes_to_its_own_shape() {
    let id = ValueImage {
        kind: LogValueKind::Id.to_bits(),
        id: text(b"lan-0"),
        ..ValueImage::ZERO
    };
    let cases: [(ValueImage, CheckedValue); 7] = [
        (
            ValueImage {
                number: 1,
                kind: LogValueKind::Port.to_bits(),
                ..ValueImage::ZERO
            },
            CheckedValue::Port(1),
        ),
        (
            ValueImage {
                kind: LogValueKind::Ipv4.to_bits(),
                octets: [10, 0, 0, 1, 0xff, 0xff],
                ..ValueImage::ZERO
            },
            CheckedValue::Ipv4([10, 0, 0, 1]),
        ),
        (
            ValueImage {
                kind: LogValueKind::Mac.to_bits(),
                octets: [0x52, 0x54, 0x00, 0x12, 0x34, 0x50],
                ..ValueImage::ZERO
            },
            CheckedValue::Mac([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]),
        ),
        (
            ValueImage {
                number: 32,
                kind: LogValueKind::PrefixLength.to_bits(),
                ..ValueImage::ZERO
            },
            CheckedValue::PrefixLength(32),
        ),
        (
            ValueImage {
                number: 1,
                kind: LogValueKind::Bool.to_bits(),
                ..ValueImage::ZERO
            },
            CheckedValue::Bool(true),
        ),
        (
            ValueImage {
                number: u32::MAX,
                kind: LogValueKind::Generation.to_bits(),
                ..ValueImage::ZERO
            },
            CheckedValue::Generation(u32::MAX),
        ),
        (
            ValueImage {
                number: 9,
                kind: LogValueKind::Count.to_bits(),
                ..ValueImage::ZERO
            },
            CheckedValue::Count(9),
        ),
    ];
    for (image, expected) in cases {
        let record = LogRecord {
            from: image,
            ..change_record()
        };
        assert!(
            matches!(record.body(), Ok(CheckedBody::ConfigChange { from: Some(value), .. }) if value == expected),
            "{expected:?}"
        );
    }

    let record = LogRecord {
        from: id,
        ..change_record()
    };
    let Ok(CheckedBody::ConfigChange {
        from: Some(CheckedValue::Id(name)),
        ..
    }) = record.body()
    else {
        panic!("an identifier value decodes to one");
    };
    assert_eq!(name.as_str(), "lan-0");
    assert_eq!(format!("{name}"), "lan-0");
}

#[test]
fn the_two_configuration_summary_records_carry_their_own_fields() {
    let generation = LogRecord {
        kind: LogKind::ConfigGeneration.to_bits(),
        generation: 4,
        outcome: 2,
        changes: 11,
        ..LogRecord::ZERO
    };
    assert_eq!(
        generation.body(),
        Ok(CheckedBody::ConfigGeneration {
            generation: 4,
            outcome: 2,
            changes: 11,
        })
    );

    let rejected = LogRecord {
        kind: LogKind::ConfigRejected.to_bits(),
        generation: 5,
        reason: 29,
        reject_offset: 4096,
        ..LogRecord::ZERO
    };
    assert_eq!(
        rejected.body(),
        Ok(CheckedBody::ConfigRejected {
            generation: 5,
            reason: 29,
            offset: 4096,
        })
    );
}

/// A field the record's kind does not name is read by nothing, so the bytes a
/// peer leaves there cannot refuse a record that is otherwise well formed.
#[test]
fn a_field_the_kind_does_not_name_is_read_by_nothing() {
    let noise = LogRecord {
        domain: 0xff,
        state: 0xff,
        detail: 0xff,
        change: 0xff,
        object: 0xff,
        field: 0xff,
        reason: 0xff,
        operand_count: 0xff,
        signalled: 0xff,
        key: text(b"NOT AN ID"),
        from: ValueImage {
            kind: 0xff,
            ..ValueImage::ZERO
        },
        cause: text(b"NOT A CAUSE"),
        _pad: [0xff; 5],
        kind: LogKind::ConfigGeneration.to_bits(),
        generation: 4,
        outcome: 2,
        changes: 11,
        ..LogRecord::ZERO
    };
    assert_eq!(
        noise.body(),
        Ok(CheckedBody::ConfigGeneration {
            generation: 4,
            outcome: 2,
            changes: 11,
        })
    );
}

/// The stamp is the one field every shape carries, and its zero must be the
/// *absence* of a time: a zeroed slot that decoded to the epoch would date every
/// untouched record 1970-01-01, a silently wrong value.
#[test]
fn a_zeroed_stamp_is_no_time_rather_than_the_epoch() {
    assert_eq!(
        LogRecord::ZERO.check().map(|checked| checked.at),
        Ok(CheckedStamp::Unsynchronized)
    );
}

#[test]
fn a_stamped_record_carries_the_instant_it_was_given() {
    let record = LogRecord {
        stamp_kind: LogStampKind::Utc.to_bits(),
        stamp_nanos: 1_785_443_220_123_456_789,
        ..domain_record()
    };
    assert_eq!(
        record.check().map(|checked| checked.at),
        Ok(CheckedStamp::Utc(1_785_443_220_123_456_789))
    );
    // The nanoseconds a record carries under the unsynchronized discriminant
    // are read by nothing, exactly as a field the kind does not name.
    let unstamped = LogRecord {
        stamp_kind: LogStampKind::Unsynchronized.to_bits(),
        ..record
    };
    assert_eq!(
        unstamped.check().map(|checked| checked.at),
        Ok(CheckedStamp::Unsynchronized)
    );
}

/// Every discriminant a peer can write outside the two, refused with the value
/// that made it one — and refused *before* the body, so a record whose stamp is
/// undecodable never reaches a line attributed to no time.
#[test]
fn a_stamp_discriminant_outside_its_set_is_refused_ahead_of_the_body() {
    for kind in 2..=u8::MAX {
        let record = LogRecord {
            stamp_kind: kind,
            domain: LOG_DOMAIN_COUNT,
            ..domain_record()
        };
        assert_eq!(
            record.check(),
            Err(LogRecordError::StampKindUnknown { kind }),
            "stamp kind {kind}"
        );
    }
}

#[test]
fn every_token_at_its_cardinality_is_refused_and_one_below_it_accepted() {
    let cases: [(LogRecord, LogRecordError); 6] = [
        (
            LogRecord {
                domain: LOG_DOMAIN_COUNT,
                ..domain_record()
            },
            LogRecordError::DomainUnknown {
                domain: LOG_DOMAIN_COUNT,
            },
        ),
        (
            LogRecord {
                state: LOG_DOMAIN_STATE_COUNT,
                ..domain_record()
            },
            LogRecordError::DomainStateUnknown {
                state: LOG_DOMAIN_STATE_COUNT,
            },
        ),
        (
            LogRecord {
                change: LOG_CHANGE_KIND_COUNT,
                ..change_record()
            },
            LogRecordError::ChangeKindUnknown {
                change: LOG_CHANGE_KIND_COUNT,
            },
        ),
        (
            LogRecord {
                object: LOG_OBJECT_KIND_COUNT,
                ..change_record()
            },
            LogRecordError::ObjectKindUnknown {
                object: LOG_OBJECT_KIND_COUNT,
            },
        ),
        (
            LogRecord {
                field: LOG_FIELD_COUNT,
                ..change_record()
            },
            LogRecordError::FieldUnknown {
                field: LOG_FIELD_COUNT,
            },
        ),
        (
            LogRecord {
                kind: LogKind::ConfigRejected.to_bits(),
                reason: LOG_REJECT_REASON_COUNT,
                ..LogRecord::ZERO
            },
            LogRecordError::RejectReasonUnknown {
                reason: LOG_REJECT_REASON_COUNT,
            },
        ),
    ];
    for (record, expected) in cases {
        assert_eq!(record.body(), Err(expected), "{expected:?}");
    }

    // The boundary from the other side: the highest token each vocabulary
    // actually has decodes, so the bound is the cardinality and not one less.
    assert!(
        LogRecord {
            domain: LOG_DOMAIN_COUNT - 1,
            state: LOG_DOMAIN_STATE_COUNT - 1,
            ..domain_record()
        }
        .body()
        .is_ok()
    );
    assert!(
        LogRecord {
            kind: LogKind::ConfigGeneration.to_bits(),
            outcome: LOG_GENERATION_OUTCOME_COUNT - 1,
            ..LogRecord::ZERO
        }
        .body()
        .is_ok()
    );
}

#[test]
fn every_shape_discriminant_outside_its_set_is_refused() {
    let cases: [(LogRecord, LogRecordError); 23] = [
        (
            LogRecord {
                kind: 4,
                ..LogRecord::ZERO
            },
            LogRecordError::KindUnknown { kind: 4 },
        ),
        (
            LogRecord {
                kind: u32::MAX,
                ..LogRecord::ZERO
            },
            LogRecordError::KindUnknown { kind: u32::MAX },
        ),
        (
            LogRecord {
                detail: 58,
                ..domain_record()
            },
            LogRecordError::DetailKindUnknown { detail: 58 },
        ),
        // The dialled channel's own two token words, on the onboarding port's
        // terms: an outcome or a certificate refusal past its set names nothing
        // a console line can spell.
        (
            LogRecord {
                detail: LogDetailKind::ChannelEnded.to_bits(),
                operands: [u64::from(LOG_CHANNEL_OUTCOME_COUNT), 0, 0, 0],
                ..domain_record()
            },
            LogRecordError::ChannelOutcomeUnknown {
                outcome: u64::from(LOG_CHANNEL_OUTCOME_COUNT),
            },
        ),
        (
            LogRecord {
                detail: LogDetailKind::ChannelCertificate.to_bits(),
                operands: [0, u64::from(LOG_TLS_CERTIFICATE_REFUSAL_COUNT), 0, 0],
                ..domain_record()
            },
            LogRecordError::TlsCertificateRefusalUnknown {
                refusal: u64::from(LOG_TLS_CERTIFICATE_REFUSAL_COUNT),
            },
        ),
        // The handshake details' own token words, on the session end's terms:
        // an outcome, an incompatibility or a refusal past its set names
        // nothing a console line can spell.
        (
            LogRecord {
                detail: LogDetailKind::OnboardingEnded.to_bits(),
                operands: [u64::from(LOG_ONBOARD_OUTCOME_COUNT), 0, 0, 0],
                ..domain_record()
            },
            LogRecordError::OnboardOutcomeUnknown {
                outcome: u64::from(LOG_ONBOARD_OUTCOME_COUNT),
            },
        ),
        (
            LogRecord {
                detail: LogDetailKind::OnboardingIncompatible.to_bits(),
                operands: [0, u64::from(LOG_TLS_INCOMPATIBLE_COUNT), 0, 0],
                ..domain_record()
            },
            LogRecordError::TlsIncompatibleUnknown {
                incompatible: u64::from(LOG_TLS_INCOMPATIBLE_COUNT),
            },
        ),
        (
            LogRecord {
                detail: LogDetailKind::OnboardingRefused.to_bits(),
                operands: [0, u64::from(LOG_TLS_REFUSAL_COUNT), 0, 0],
                ..domain_record()
            },
            LogRecordError::TlsRefusalUnknown {
                refusal: u64::from(LOG_TLS_REFUSAL_COUNT),
            },
        ),
        // And the code points beside them, which are refused for being wider
        // than any registry numbers one.
        (
            LogRecord {
                detail: LogDetailKind::OnboardingHandshake.to_bits(),
                operands: [0, u64::from(u16::MAX) + 1, 0, 0],
                ..domain_record()
            },
            LogRecordError::CodePointTooWide {
                value: u64::from(u16::MAX) + 1,
            },
        ),
        // The onboarding session's own token word, on the dial's terms: an end
        // past the set names nothing a console line can spell.
        (
            LogRecord {
                detail: LogDetailKind::Onboarded.to_bits(),
                operands: [u64::from(LOG_ONBOARD_END_COUNT), 0, 0, 0],
                ..domain_record()
            },
            LogRecordError::OnboardEndUnknown {
                end: u64::from(LOG_ONBOARD_END_COUNT),
            },
        ),
        // The dial's own token word, on the primitive's terms: an outcome past
        // the set names nothing a console line can spell.
        (
            LogRecord {
                detail: LogDetailKind::Dialled.to_bits(),
                operands: [u64::from(LOG_DIAL_OUTCOME_COUNT), 0, 0, 0],
                ..domain_record()
            },
            LogRecordError::DialOutcomeUnknown {
                outcome: u64::from(LOG_DIAL_OUTCOME_COUNT),
            },
        ),
        // The route detail's own token word, on the dial outcome's terms, and
        // its address word beside it: the two the channel's first extra record
        // can be refused for.
        (
            LogRecord {
                detail: LogDetailKind::DialRoute.to_bits(),
                operands: [u64::from(LOG_NEXT_HOP_VIA_COUNT), 0, 0, 0],
                ..domain_record()
            },
            LogRecordError::NextHopViaUnknown {
                via: u64::from(LOG_NEXT_HOP_VIA_COUNT),
            },
        ),
        (
            LogRecord {
                detail: LogDetailKind::DialRoute.to_bits(),
                operands: [0, u64::from(u32::MAX) + 1, 0, 0],
                ..domain_record()
            },
            LogRecordError::AddressTooWide {
                value: u64::from(u32::MAX) + 1,
            },
        ),
        // The segment detail's fourth word, which is a flag and is refused on
        // the identity's terms — one rule in this ABI for a boolean in an
        // operand, and this detail is held to it like the rest.
        (
            LogRecord {
                detail: LogDetailKind::DialSegments.to_bits(),
                operands: [0, 0, 0, 2],
                ..domain_record()
            },
            LogRecordError::OperandFlagNotBoolean { value: 2 },
        ),
        // And the two sequence words, each thirty-two bits wide wherever TCP
        // names one — including the peer's own claim, which is ranged for being
        // rendered rather than for being believed.
        (
            LogRecord {
                detail: LogDetailKind::DialSequence.to_bits(),
                operands: [u64::from(u32::MAX) + 1, 0, 0, 0],
                ..domain_record()
            },
            LogRecordError::SequenceTooWide {
                value: u64::from(u32::MAX) + 1,
            },
        ),
        (
            LogRecord {
                detail: LogDetailKind::DialSequence.to_bits(),
                operands: [0, u64::from(u32::MAX) + 1, 0, 0],
                ..domain_record()
            },
            LogRecordError::SequenceTooWide {
                value: u64::from(u32::MAX) + 1,
            },
        ),
        // And its address word, which is thirty-two bits wide wherever IPv4
        // names one: a wider word would render as a different address.
        (
            LogRecord {
                detail: LogDetailKind::Dialled.to_bits(),
                operands: [0, u64::from(u32::MAX) + 1, 0, 0],
                ..domain_record()
            },
            LogRecordError::AddressTooWide {
                value: u64::from(u32::MAX) + 1,
            },
        ),
        // The one operand word that is a token: a primitive past the set names
        // nothing a console line can spell, so it is refused rather than
        // rendered as a bare index.
        (
            LogRecord {
                detail: LogDetailKind::Proved.to_bits(),
                operands: [u64::from(LOG_PRIMITIVE_COUNT), 0, 0, 0],
                ..domain_record()
            },
            LogRecordError::PrimitiveUnknown {
                primitive: u64::from(LOG_PRIMITIVE_COUNT),
            },
        ),
        (
            LogRecord {
                detail: LogDetailKind::Measured.to_bits(),
                operands: [u64::MAX, 0, 0, 0],
                ..domain_record()
            },
            LogRecordError::PrimitiveUnknown {
                primitive: u64::MAX,
            },
        ),
        // The one detail whose own field can refuse it: a frequency of zero
        // scales no reading, so it is refused rather than carried on as a
        // divisor every later consumer would have to re-check.
        (
            LogRecord {
                detail: LogDetailKind::Established.to_bits(),
                tsc_hz: 0,
                ..domain_record()
            },
            LogRecordError::ClockFrequencyZero,
        ),
        (
            LogRecord {
                operand_count: 3,
                ..refusal_record()
            },
            LogRecordError::OperandCountUnknown { operands: 3 },
        ),
        (
            LogRecord {
                signalled: 2,
                ..refusal_record()
            },
            LogRecordError::SignalledNotBoolean { signalled: 2 },
        ),
        (
            LogRecord {
                kind: LogKind::ConfigGeneration.to_bits(),
                outcome: LOG_GENERATION_OUTCOME_COUNT,
                ..LogRecord::ZERO
            },
            LogRecordError::GenerationOutcomeUnknown {
                outcome: LOG_GENERATION_OUTCOME_COUNT,
            },
        ),
    ];
    for (record, expected) in cases {
        assert_eq!(record.body(), Err(expected), "{expected:?}");
    }
}

#[test]
fn a_value_slot_the_writer_filled_wrongly_is_refused_at_its_own_position() {
    let cases: [(ValueImage, LogRecordError); 3] = [
        (
            ValueImage {
                kind: 11,
                ..ValueImage::ZERO
            },
            LogRecordError::ValueKindUnknown {
                text: LogText::From,
                kind: 11,
            },
        ),
        (
            ValueImage {
                number: 256,
                kind: LogValueKind::Port.to_bits(),
                ..ValueImage::ZERO
            },
            LogRecordError::ValueNumberTooLarge {
                text: LogText::From,
                number: 256,
            },
        ),
        (
            ValueImage {
                number: 2,
                kind: LogValueKind::Bool.to_bits(),
                ..ValueImage::ZERO
            },
            LogRecordError::ValueBoolNotBoolean {
                text: LogText::From,
                number: 2,
            },
        ),
    ];
    for (image, expected) in cases {
        let record = LogRecord {
            from: image,
            ..change_record()
        };
        assert_eq!(record.body(), Err(expected), "{expected:?}");

        // The same value in the other slot is refused against that slot, so a
        // refusal names which of the two the writer got wrong.
        let record = LogRecord {
            to: image,
            ..change_record()
        };
        assert!(matches!(
            record.body(),
            Err(LogRecordError::ValueKindUnknown {
                text: LogText::To,
                ..
            } | LogRecordError::ValueNumberTooLarge {
                text: LogText::To,
                ..
            } | LogRecordError::ValueBoolNotBoolean {
                text: LogText::To,
                ..
            })
        ));
    }
}

#[test]
fn a_prefix_length_word_that_does_not_fit_a_byte_is_refused_rather_than_truncated() {
    let record = LogRecord {
        from: ValueImage {
            number: 0x0000_0118,
            kind: LogValueKind::PrefixLength.to_bits(),
            ..ValueImage::ZERO
        },
        ..change_record()
    };
    assert_eq!(
        record.body(),
        Err(LogRecordError::ValueNumberTooLarge {
            text: LogText::From,
            number: 280,
        })
    );
}

/// The console-safety boundary: text a hostile writer put in the region reaches an
/// operator's terminal unless this decode refuses it, so the alphabet is held
/// on every text field a record has.
#[test]
fn text_outside_the_console_alphabet_is_refused_wherever_it_appears() {
    let hostile: [&[u8]; 5] = [b"WAN", b"wan 0", b"wan\n", b"\x1b[2J", b"wan.0"];
    for bytes in hostile {
        let key = LogRecord {
            key: text(bytes),
            ..change_record()
        };
        assert!(
            matches!(
                key.body(),
                Err(LogRecordError::TextNotInAlphabet {
                    text: LogText::Key,
                    ..
                })
            ),
            "{bytes:?}"
        );

        let value = LogRecord {
            from: ValueImage {
                kind: LogValueKind::Id.to_bits(),
                id: text(bytes),
                ..ValueImage::ZERO
            },
            ..change_record()
        };
        assert!(
            matches!(
                value.body(),
                Err(LogRecordError::TextNotInAlphabet {
                    text: LogText::From,
                    ..
                })
            ),
            "{bytes:?}"
        );

        let cause = LogRecord {
            cause: text(bytes),
            ..refusal_record()
        };
        assert!(
            matches!(
                cause.body(),
                Err(LogRecordError::TextNotInAlphabet {
                    text: LogText::Cause,
                    ..
                })
            ),
            "{bytes:?}"
        );
    }
}

#[test]
fn a_text_length_beyond_its_storage_is_refused_for_being_one() {
    for len in [
        LOG_IDENTIFIER_BYTES as u8 + 1,
        LOG_CAUSE_BYTES as u8,
        u8::MAX,
    ] {
        let mut record = change_record();
        record.key.len = len;
        assert_eq!(
            record.body(),
            Err(LogRecordError::TextTooLong {
                text: LogText::Key,
                len
            })
        );
    }

    // At capacity is accepted: the bound is the storage, not one short of it.
    let mut record = change_record();
    record.key = text(b"abcdefghijklmnop");
    assert!(matches!(
        record.body(),
        Ok(CheckedBody::ConfigChange { key, .. }) if key.len() == LOG_IDENTIFIER_BYTES
    ));
}

/// Two identifiers that read the same compare the same, whatever the writer
/// left in the unused tail: the check copies out the value and zeroes the rest.
#[test]
fn text_compares_by_content_not_by_the_tail_the_writer_left() {
    let mut noisy = change_record();
    noisy.key = text(b"wan");
    noisy.key.bytes[3] = b'x';
    noisy.key.bytes[15] = b'z';
    noisy.key._pad = [0xff; 3];
    assert_eq!(noisy.body(), change_record().body());
}

#[test]
fn every_refusal_names_the_field_and_the_value() {
    let rendered: Vec<String> = [
        LogRecordError::KindUnknown { kind: 9 },
        LogRecordError::DomainUnknown { domain: 4 },
        LogRecordError::DomainStateUnknown { state: 4 },
        LogRecordError::DetailKindUnknown { detail: 7 },
        LogRecordError::DialOutcomeUnknown { outcome: 99 },
        LogRecordError::NextHopViaUnknown { via: 9 },
        LogRecordError::OnboardOutcomeUnknown { outcome: 99 },
        LogRecordError::TlsIncompatibleUnknown { incompatible: 99 },
        LogRecordError::TlsRefusalUnknown { refusal: 99 },
        LogRecordError::SequenceTooWide { value: u64::MAX },
        LogRecordError::AddressTooWide { value: u64::MAX },
        LogRecordError::ClockFrequencyZero,
        LogRecordError::OperandCountUnknown { operands: 3 },
        LogRecordError::SignalledNotBoolean { signalled: 2 },
        LogRecordError::ChangeKindUnknown { change: 3 },
        LogRecordError::ObjectKindUnknown { object: 3 },
        LogRecordError::FieldUnknown { field: 6 },
        LogRecordError::GenerationOutcomeUnknown { outcome: 3 },
        LogRecordError::RejectReasonUnknown { reason: 30 },
        LogRecordError::ValueKindUnknown {
            text: LogText::From,
            kind: 9,
        },
        LogRecordError::ValueNumberTooLarge {
            text: LogText::To,
            number: 256,
        },
        LogRecordError::ValueBoolNotBoolean {
            text: LogText::From,
            number: 2,
        },
        LogRecordError::TextEmpty { text: LogText::Key },
        LogRecordError::TextTooLong {
            text: LogText::Cause,
            len: 41,
        },
        LogRecordError::TextNotInAlphabet {
            text: LogText::Key,
            offset: 2,
        },
    ]
    .iter()
    .map(|error| format!("{error}"))
    .collect();

    assert_eq!(
        rendered,
        [
            "record kind 9 names no event",
            "domain token 4 is not below 10",
            "state token 4 is not below 4",
            "detail kind 7 names no payload",
            "dial outcome token 99 is not below 13",
            "next hop choice token 9 is not below 3",
            "onboarding handshake outcome token 99 is not below 10",
            "TLS incompatibility token 99 is not below 23",
            "TLS refusal token 99 is not below 23",
            "sequence word 18446744073709551615 does not fit thirty-two bits",
            "address word 18446744073709551615 does not fit thirty-two bits",
            "the established counter frequency is zero, which scales no reading",
            "operand count 3 exceeds the 2 a refusal may name",
            "signalled byte 2 is not 0 or 1",
            "change token 3 is not below 3",
            "object token 3 is not below 4",
            "field token 6 is not below 18",
            "outcome token 3 is not below 6",
            "reason token 30 is not below 38",
            "from value kind 9 names no value",
            "to value 256 does not fit a byte",
            "from value 2 is not 0 or 1",
            "key text is empty",
            "cause text length 41 exceeds its storage",
            "key text byte 2 is outside [a-z0-9-]",
        ]
    );
}

/// Every discriminant this crate owns decodes exactly what it encodes, and
/// nothing else — the totality `Verdict::from_bits` holds for its own word.
#[test]
fn each_shape_discriminant_decodes_exactly_what_it_encodes() {
    for kind in [
        LogKind::Domain,
        LogKind::ConfigChange,
        LogKind::ConfigGeneration,
        LogKind::ConfigRejected,
    ] {
        assert_eq!(LogKind::from_bits(kind.to_bits()), Some(kind));
    }
    assert_eq!(LogKind::from_bits(4), None);

    for detail in [
        LogDetailKind::None,
        LogDetailKind::Features,
        LogDetailKind::ReceivePosted,
        LogDetailKind::Refusal,
        LogDetailKind::Established,
        LogDetailKind::Received,
        LogDetailKind::Medium,
        LogDetailKind::Extent,
        LogDetailKind::Proven,
        LogDetailKind::Proved,
        LogDetailKind::Measured,
        LogDetailKind::Session,
        LogDetailKind::Exchange,
        LogDetailKind::Peer,
        LogDetailKind::Arena,
        LogDetailKind::Operation,
        LogDetailKind::Identity,
        LogDetailKind::Fingerprint,
        LogDetailKind::Reset,
        LogDetailKind::Delegated,
        LogDetailKind::Dialled,
        LogDetailKind::DialRoute,
        LogDetailKind::DialUnlearned,
        LogDetailKind::DialSegments,
        LogDetailKind::DialSequence,
        LogDetailKind::Onboarded,
        LogDetailKind::OnboardingPort,
        LogDetailKind::OnboardingHandshake,
        LogDetailKind::OnboardingEnded,
        LogDetailKind::OnboardingIncompatible,
        LogDetailKind::OnboardingRefused,
        LogDetailKind::OnboardingAlert,
        LogDetailKind::OnboardingBacklogged,
        LogDetailKind::OnboardingSuites,
        LogDetailKind::OnboardingGroups,
        LogDetailKind::OnboardingServed,
        LogDetailKind::OnboardingRequest,
        LogDetailKind::OnboardingThrottled,
        LogDetailKind::Adopted,
        LogDetailKind::AnchorFingerprint,
        LogDetailKind::OnboardingInstalled,
        LogDetailKind::Ownership,
        LogDetailKind::DelegatedAnchor,
        LogDetailKind::Published,
        LogDetailKind::DialRetry,
        LogDetailKind::ChannelHandshake,
        LogDetailKind::ChannelEnded,
        LogDetailKind::ChannelIncompatible,
        LogDetailKind::ChannelRefused,
        LogDetailKind::ChannelCertificate,
        LogDetailKind::ChannelAlert,
        LogDetailKind::ChannelBacklogged,
        LogDetailKind::ChannelFrames,
        LogDetailKind::RecordingResumed,
        LogDetailKind::RecordingFresh,
        LogDetailKind::ChannelShipping,
        LogDetailKind::ChannelAcked,
        LogDetailKind::Configured,
    ] {
        assert_eq!(LogDetailKind::from_bits(detail.to_bits()), Some(detail));
    }
    assert_eq!(LogDetailKind::from_bits(58), None);

    for value in [
        LogValueKind::Absent,
        LogValueKind::Port,
        LogValueKind::Ipv4,
        LogValueKind::Mac,
        LogValueKind::PrefixLength,
        LogValueKind::Bool,
        LogValueKind::Generation,
        LogValueKind::Count,
        LogValueKind::Id,
        LogValueKind::Selector,
        LogValueKind::Prefix,
    ] {
        assert_eq!(LogValueKind::from_bits(value.to_bits()), Some(value));
    }
    assert_eq!(LogValueKind::from_bits(11), None);
}

#[test]
fn a_text_position_reads_as_its_own_name() {
    let names: Vec<String> = [LogText::Key, LogText::From, LogText::To, LogText::Cause]
        .iter()
        .map(|text| format!("{text}"))
        .collect();
    assert_eq!(names, ["key", "from", "to", "cause"]);
}

/// Whole-record bytes, weighted so that decodable records are reached as often
/// as refused ones. Uniform bytes alone are not enough: a `kind` word drawn
/// over `u32` names an event four times in four billion, so every record would
/// be refused at the first field and the rules about what is *yielded* would
/// never be exercised.
fn plausible_record() -> BoxedStrategy<LogRecord> {
    (
        prop_oneof![9 => 0u32..=3, 1 => any::<u32>()],
        prop_oneof![9 => 0u8..=3, 1 => any::<u8>()],
        prop_oneof![9 => 0u8..=8, 1 => any::<u8>()],
        prop_oneof![9 => 0u8..=8, 1 => any::<u8>()],
        prop_oneof![9 => 0u8..=8, 1 => any::<u8>()],
        prop_oneof![7 => 1u8..=16, 2 => 0u8..=40, 1 => any::<u8>()],
        prop_oneof![9 => 0u8..=1, 1 => any::<u8>()],
        prop_oneof![9 => 0u8..=2, 1 => any::<u8>()],
        proptest::collection::vec(prop_oneof![9 => 0x61u8..=0x7a, 1 => any::<u8>()], 16),
        any::<[u8; 6]>(),
        // Zero as often as anything else: it is the one value of this field
        // that refuses the record, and a frequency drawn over `u64` would
        // never be it.
        prop_oneof![1 => Just(0u64), 1 => 1u64..=u64::MAX],
    )
        .prop_map(
            |(
                kind,
                token,
                detail,
                from_kind,
                to_kind,
                len,
                signalled,
                operand_count,
                letters,
                octets,
                tsc_hz,
            )| {
                let mut key = IdentifierImage::ZERO;
                for (slot, byte) in key.bytes.iter_mut().zip(letters) {
                    *slot = byte;
                }
                key.len = len;
                let mut cause = CauseImage::ZERO;
                cause.bytes[..16].copy_from_slice(&key.bytes);
                cause.len = len;
                LogRecord {
                    kind,
                    domain: token,
                    state: token,
                    change: token,
                    object: token,
                    field: token,
                    outcome: token,
                    reason: token,
                    detail,
                    signalled,
                    operand_count,
                    key,
                    cause,
                    from: ValueImage {
                        number: u32::from(token),
                        kind: from_kind,
                        octets,
                        id: key,
                        ..ValueImage::ZERO
                    },
                    to: ValueImage {
                        number: u32::from(token),
                        kind: to_kind,
                        octets,
                        id: key,
                        ..ValueImage::ZERO
                    },
                    tsc_hz,
                    unix_nanos: u64::from(token) * u64::from(len),
                    // Derived from the arbitrary frequency rather than drawn
                    // separately: `Received` has no field that can refuse a
                    // record, so what matters is that the arm is reached with
                    // two different values, and the tuple above is already at
                    // the width proptest generates for.
                    frames: tsc_hz,
                    frame_bytes: !tsc_hz,
                    ..LogRecord::ZERO
                }
            },
        )
        .boxed()
}

/// Everything a decoded record is allowed to be, restated independently of the
/// decode so the properties below pin what is yielded rather than merely that
/// something was.
fn assert_body_is_well_formed(body: &CheckedBody) -> Result<(), TestCaseError> {
    match body {
        CheckedBody::Domain {
            domain,
            state,
            detail,
        } => {
            prop_assert!(*domain < LOG_DOMAIN_COUNT);
            prop_assert!(*state < LOG_DOMAIN_STATE_COUNT);
            if let CheckedDetail::Refusal { cause, .. } = detail {
                assert_text_is_renderable(cause.as_bytes(), true)?;
            }
        }
        CheckedBody::ConfigChange {
            change,
            object,
            key,
            field,
            from,
            to,
            ..
        } => {
            prop_assert!(*change < LOG_CHANGE_KIND_COUNT);
            prop_assert!(*object < LOG_OBJECT_KIND_COUNT);
            prop_assert!(*field < LOG_FIELD_COUNT);
            assert_text_is_renderable(key.as_bytes(), false)?;
            for value in [from, to].into_iter().flatten() {
                if let CheckedValue::Id(id) = value {
                    assert_text_is_renderable(id.as_bytes(), false)?;
                }
            }
        }
        CheckedBody::ConfigGeneration { outcome, .. } => {
            prop_assert!(*outcome < LOG_GENERATION_OUTCOME_COUNT);
        }
        CheckedBody::ConfigRejected { reason, .. } => {
            prop_assert!(*reason < LOG_REJECT_REASON_COUNT);
        }
    }
    Ok(())
}

fn assert_text_is_renderable(bytes: &[u8], allow_empty: bool) -> Result<(), TestCaseError> {
    prop_assert!(allow_empty || !bytes.is_empty());
    prop_assert!(bytes.len() <= LOG_CAUSE_BYTES);
    for &byte in bytes {
        prop_assert!(in_alphabet(byte), "byte {byte} reached a console line");
    }
    Ok(())
}

proptest! {
    /// The byzantine-writer property over the region's whole input space: every
    /// byte of the record independently arbitrary, and every one of them a
    /// value the writer picked. The decode returns rather than panics, and what
    /// it yields satisfies every rule.
    #[test]
    fn a_wholly_arbitrary_record_decodes_without_panicking(
        bytes in proptest::collection::vec(any::<u8>(), RECORD_BYTES),
    ) {
        let mut image = [0u8; RECORD_BYTES];
        image.copy_from_slice(&bytes);
        let record = record_from_bytes(image);
        prop_assert_eq!(record_to_bytes(record), image);

        if let Ok(checked) = record.check() {
            // The stamp is a decoded case rather than the raw byte: whatever a
            // peer wrote, it reads as an instant or as the lack of one.
            prop_assert!(matches!(
                checked.at,
                CheckedStamp::Unsynchronized | CheckedStamp::Utc(_)
            ));
            assert_body_is_well_formed(&checked.body)?;
        }
    }

    /// The same region with each field weighted towards a value a well-behaved
    /// writer produces, so the accepted path is reached as often as the refused
    /// one and the rules about what is yielded are actually exercised.
    #[test]
    fn a_plausible_record_decodes_totally_and_yields_only_renderable_values(
        record in plausible_record(),
    ) {
        match record.body() {
            Ok(body) => assert_body_is_well_formed(&body)?,
            Err(error) => {
                // A refusal is attributable: it renders, and it names a field.
                let rendered = format!("{error}");
                prop_assert!(!rendered.is_empty());
            }
        }
    }

    /// Decoding is a pure function of the bytes, so the same region read twice
    /// yields the same answer — what makes a refusal reproducible from a
    /// captured record rather than a property of when it was read.
    #[test]
    fn decoding_is_a_function_of_the_bytes_alone(record in plausible_record()) {
        prop_assert_eq!(record.body(), record.body());
    }

    /// Text survives the decode verbatim: what a writer put in `bytes[..len]`
    /// is exactly what a console renders, neither truncated nor extended.
    #[test]
    fn admissible_text_round_trips_through_the_record(name in "[a-z0-9-]{1,16}") {
        let record = LogRecord {
            key: text(name.as_bytes()),
            ..change_record()
        };
        let Ok(CheckedBody::ConfigChange { key, .. }) = record.body() else {
            return Err(TestCaseError::fail("the identifier is admissible"));
        };
        prop_assert_eq!(key.as_str(), name.as_str());
        prop_assert_eq!(key.len(), name.len());
        prop_assert_eq!(key.as_bytes(), name.as_bytes());
    }
}
