use super::*;

use core::num::NonZeroU64;

use net_headers::{Ipv4Address, MacAddress};
use proptest::prelude::*;
use std::{format, string::String, vec::Vec};
use wire::{CauseImage, CheckedRecord, CheckedStamp, IdentifierImage, LogRecordError, TextImage};

use crate::detail::MAX_CAUSE_LEN;
use crate::identifier::MAX_IDENTIFIER_LEN;

fn id(text: &str) -> Identifier {
    Identifier::new(text.as_bytes()).expect("the fixture is within the alphabet")
}

fn cause(text: &str) -> Cause {
    Cause::new(text.as_bytes()).expect("the fixture is within the alphabet")
}

/// The whole crossing, as a console domain performs it: encode, hand the bytes
/// to `wire`'s own check exactly as a reader does, then decode.
fn round_trip(event: &Event<Cause>) -> Result<Event<Cause>, RoundTripError> {
    stamped_round_trip(Stamp::Unsynchronized, event).map(|(_, event)| event)
}

/// As [`round_trip`], keeping the instant, for the tests that are about it.
fn stamped_round_trip(
    at: Stamp,
    event: &Event<Cause>,
) -> Result<(Stamp, Event<Cause>), RoundTripError> {
    let record = event.encode(at).check().map_err(RoundTripError::Record)?;
    Event::decode(&record).map_err(RoundTripError::Decode)
}

/// A checked record around a body a test built by hand, which is the shape a
/// peer's region hands the console.
fn checked(body: CheckedBody) -> CheckedRecord {
    CheckedRecord {
        at: CheckedStamp::Unsynchronized,
        body,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RoundTripError {
    Record(LogRecordError),
    Decode(DecodeError),
}

// ---------------------------------------------------------------------------
// The vocabulary widths
// ---------------------------------------------------------------------------

/// The compile-time block at the foot of `record.rs` is the enforcement; this
/// is the same equality as a value, so a reader who does not know the assertion
/// exists still finds the two numbers held together.
#[test]
fn every_vocabulary_is_as_wide_here_as_the_abi_says() {
    let widths = [
        (Vocabulary::Domain, u32::from(wire::LOG_DOMAIN_COUNT)),
        (
            Vocabulary::DomainState,
            u32::from(wire::LOG_DOMAIN_STATE_COUNT),
        ),
        (
            Vocabulary::ChangeKind,
            u32::from(wire::LOG_CHANGE_KIND_COUNT),
        ),
        (
            Vocabulary::ObjectKind,
            u32::from(wire::LOG_OBJECT_KIND_COUNT),
        ),
        (Vocabulary::Field, u32::from(wire::LOG_FIELD_COUNT)),
        (
            Vocabulary::GenerationOutcome,
            u32::from(wire::LOG_GENERATION_OUTCOME_COUNT),
        ),
        (
            Vocabulary::RejectReason,
            u32::from(wire::LOG_REJECT_REASON_COUNT),
        ),
    ];
    for (vocabulary, abi) in widths {
        assert_eq!(
            vocabulary.count(),
            abi as usize,
            "{vocabulary} is a different width on the two sides of the region"
        );
    }
}

#[test]
fn every_domain_the_system_declares_is_in_the_vocabulary_the_abi_carries() {
    for (domain, token) in [
        (Domain::Console, "console"),
        (Domain::Management, "management"),
    ] {
        assert!(Domain::ALL.contains(&domain));
        assert_eq!(domain.name(), token);
        assert!((domain as usize) < usize::from(wire::LOG_DOMAIN_COUNT));
    }
}

#[test]
fn the_text_widths_match_the_abi() {
    assert_eq!(MAX_IDENTIFIER_LEN, wire::LOG_IDENTIFIER_BYTES);
    assert_eq!(MAX_CAUSE_LEN, wire::LOG_CAUSE_BYTES);
}

// ---------------------------------------------------------------------------
// Every token of every vocabulary
// ---------------------------------------------------------------------------

/// Each variant occupies the token the ABI reads it back as, for every
/// vocabulary a record carries. A variant reordered on one side only would show
/// up here as a record that decodes to a different one.
#[test]
fn every_vocabulary_token_encodes_and_decodes_as_itself() {
    for domain in Domain::ALL {
        for state in DomainState::ALL {
            let event = Event::Domain {
                domain,
                state,
                detail: DomainDetail::None,
            };
            assert_eq!(round_trip(&event), Ok(event));
        }
    }
    for change in ChangeKind::ALL {
        for object in ObjectKind::ALL {
            for field in Field::ALL {
                let event = Event::ConfigChange {
                    generation: 1,
                    sequence: 2,
                    change,
                    object,
                    key: id("wan"),
                    field,
                    from: None,
                    to: None,
                };
                assert_eq!(round_trip(&event), Ok(event));
            }
        }
    }
    for outcome in GenerationOutcome::ALL {
        let event = Event::ConfigGeneration {
            generation: 3,
            outcome,
            changes: 4,
        };
        assert_eq!(round_trip(&event), Ok(event));
    }
    for reason in RejectReason::ALL {
        let event = Event::ConfigRejected {
            generation: 5,
            reason,
            offset: 6,
        };
        assert_eq!(round_trip(&event), Ok(event));
    }
}

/// Every [`Value`] variant survives the crossing as itself, including the ones
/// the ABI narrows into a shared `number` field and the one that carries text.
#[test]
fn every_value_variant_survives_both_ends_of_a_change() {
    let values = [
        Value::Port(255),
        Value::Ipv4(Ipv4Address::from_octets([10, 0, 0, 1])),
        Value::Mac(MacAddress([0x52, 0x54, 0, 1, 2, 3])),
        Value::PrefixLength(32),
        Value::Bool(true),
        Value::Bool(false),
        Value::Generation(u32::MAX),
        Value::Count(u32::MAX),
        Value::Id(id("gateway-a")),
    ];
    for value in values {
        for (from, to) in [
            (Some(value), None),
            (None, Some(value)),
            (Some(value), Some(value)),
            (None, None),
        ] {
            let event = Event::ConfigChange {
                generation: 7,
                sequence: 8,
                change: ChangeKind::Modified,
                object: ObjectKind::Interface,
                key: id("lan"),
                field: Field::Address,
                from,
                to,
            };
            assert_eq!(round_trip(&event), Ok(event), "{value:?}");
        }
    }
}

/// Every detail shape and all three refusal widths, each with both
/// `signalled` values and with the empty cause the ABI admits.
#[test]
fn every_domain_detail_shape_survives_the_crossing() {
    let mut details = std::vec![
        DomainDetail::None,
        DomainDetail::Features(u64::MAX),
        DomainDetail::Features(0),
        DomainDetail::ReceivePosted(u32::MAX),
        established(1, 0),
        established(u64::MAX, u64::MAX),
        DomainDetail::Received {
            frames: 0,
            bytes: 0
        },
        DomainDetail::Received {
            frames: u64::MAX,
            bytes: u64::MAX,
        },
    ];
    for operands in [
        RefusalDetail::None,
        RefusalDetail::One(u64::MAX),
        RefusalDetail::Two(u64::MAX, 0),
    ] {
        for signalled in [false, true] {
            for token in ["", "a", "not-virtio-net", &"a".repeat(MAX_CAUSE_LEN)] {
                details.push(DomainDetail::Refusal(Refusal {
                    cause: cause(token),
                    detail: operands,
                    signalled,
                }));
            }
        }
    }
    for detail in details {
        let event = Event::Domain {
            domain: Domain::NicDriver,
            state: DomainState::Refused,
            detail,
        };
        assert_eq!(round_trip(&event), Ok(event), "{detail:?}");
    }
}

// ---------------------------------------------------------------------------
// An out-of-range token is a typed refusal, not a wrong variant
// ---------------------------------------------------------------------------

/// A `CheckedBody` is a public value with public fields, so a token past this
/// build's variants is reachable however tightly `wire` bounds its own. Every
/// one is a named refusal rather than an index into the array.
#[test]
fn a_token_past_the_last_variant_is_a_typed_refusal() {
    let detail = CheckedDetail::None;
    let cases: Vec<(CheckedBody, Vocabulary, u8)> = std::vec![
        (
            CheckedBody::Domain {
                domain: 200,
                state: 0,
                detail,
            },
            Vocabulary::Domain,
            200,
        ),
        (
            CheckedBody::Domain {
                domain: 0,
                state: u8::MAX,
                detail,
            },
            Vocabulary::DomainState,
            u8::MAX,
        ),
        (
            CheckedBody::ConfigGeneration {
                generation: 0,
                outcome: 9,
                changes: 0,
            },
            Vocabulary::GenerationOutcome,
            9,
        ),
        (
            CheckedBody::ConfigRejected {
                generation: 0,
                reason: 99,
                offset: 0,
            },
            Vocabulary::RejectReason,
            99,
        ),
    ];
    for (body, vocabulary, token) in cases {
        assert_eq!(
            Event::decode(&checked(body)),
            Err(DecodeError::Vocabulary { vocabulary, token }),
            "{body:?}"
        );
    }
}

/// The same for the three vocabularies a change record carries, which need a
/// checked key to reach — so they are built from a record `wire` accepted and
/// then have one token replaced.
#[test]
fn a_change_record_refuses_each_of_its_tokens_by_name() {
    let event = Event::ConfigChange {
        generation: 1,
        sequence: 0,
        change: ChangeKind::Added,
        object: ObjectKind::Interface,
        key: id("wan"),
        field: Field::Port,
        from: None,
        to: Some(Value::Port(1)),
    };
    let body = event
        .encode(Stamp::Unsynchronized)
        .check()
        .expect("the fixture is well formed")
        .body;
    let CheckedBody::ConfigChange {
        generation,
        sequence,
        key,
        from,
        to,
        ..
    } = body
    else {
        panic!("a change record decoded as another shape");
    };
    let rebuild = |change: u8, object: u8, field: u8| CheckedBody::ConfigChange {
        generation,
        sequence,
        change,
        object,
        key,
        field,
        from,
        to,
    };
    for (body, vocabulary, token) in [
        (rebuild(7, 0, 0), Vocabulary::ChangeKind, 7),
        (rebuild(0, 8, 0), Vocabulary::ObjectKind, 8),
        (rebuild(0, 0, 250), Vocabulary::Field, 250),
    ] {
        assert_eq!(
            Event::decode(&checked(body)),
            Err(DecodeError::Vocabulary { vocabulary, token })
        );
    }
}

/// The last variant of every vocabulary is accepted and the token immediately
/// past it is refused, so the boundary is exact rather than approximately
/// right — an off-by-one here would silently drop the newest variant of a
/// vocabulary, which is exactly what `Domain::Console` just became.
#[test]
fn the_boundary_of_each_vocabulary_is_exact() {
    macro_rules! check_boundary {
        ($all:expr, $vocabulary:expr) => {{
            let vocabulary = $vocabulary;
            let count = u8::try_from(vocabulary.count()).expect("a vocabulary fits a byte");
            let last = count.checked_sub(1).expect("a vocabulary has variants");
            assert_eq!(
                variant($all, vocabulary, last),
                Ok($all[usize::from(last)]),
                "{vocabulary} refused its own last variant"
            );
            assert_eq!(
                variant($all, vocabulary, count),
                Err(DecodeError::Vocabulary {
                    vocabulary,
                    token: count
                }),
                "{vocabulary} accepted a token past its last variant"
            );
            assert_eq!(
                variant($all, vocabulary, u8::MAX),
                Err(DecodeError::Vocabulary {
                    vocabulary,
                    token: u8::MAX
                })
            );
        }};
    }
    check_boundary!(Domain::ALL, Vocabulary::Domain);
    check_boundary!(DomainState::ALL, Vocabulary::DomainState);
    check_boundary!(ChangeKind::ALL, Vocabulary::ChangeKind);
    check_boundary!(ObjectKind::ALL, Vocabulary::ObjectKind);
    check_boundary!(Field::ALL, Vocabulary::Field);
    check_boundary!(GenerationOutcome::ALL, Vocabulary::GenerationOutcome);
    check_boundary!(RejectReason::ALL, Vocabulary::RejectReason);
}

#[test]
fn each_decode_refusal_reads_differently_and_names_its_token() {
    let mut messages: Vec<String> = std::vec![
        DecodeError::Vocabulary {
            vocabulary: Vocabulary::Domain,
            token: 9,
        },
        DecodeError::Vocabulary {
            vocabulary: Vocabulary::RejectReason,
            token: 9,
        },
        DecodeError::Identifier {
            text: LogText::Key,
            error: IdentifierError::Empty,
        },
        DecodeError::Identifier {
            text: LogText::From,
            error: IdentifierError::NotInAlphabet { offset: 1 },
        },
        DecodeError::Cause {
            error: CauseError::TooLong { len: 99 },
        },
    ]
    .iter()
    .map(|error| format!("{error}"))
    .collect();
    assert!(messages.iter().any(|message| message.contains('9')));
    let count = messages.len();
    messages.sort();
    messages.dedup();
    assert_eq!(messages.len(), count);

    for vocabulary in [
        Vocabulary::Domain,
        Vocabulary::DomainState,
        Vocabulary::ChangeKind,
        Vocabulary::ObjectKind,
        Vocabulary::Field,
        Vocabulary::GenerationOutcome,
        Vocabulary::RejectReason,
    ] {
        assert!(!format!("{vocabulary}").is_empty());
    }
}

// ---------------------------------------------------------------------------
// The literal-to-bounded seam
// ---------------------------------------------------------------------------

#[test]
fn a_minted_event_becomes_its_bounded_form_field_for_field() {
    let minted = Event::Domain {
        domain: Domain::NicDriver,
        state: DomainState::Refused,
        detail: DomainDetail::Refusal(Refusal {
            cause: "not-virtio-net",
            detail: RefusalDetail::Two(0x1af4, 0x1000),
            signalled: true,
        }),
    };
    assert_eq!(
        Event::<Cause>::try_from(minted),
        Ok(Event::Domain {
            domain: Domain::NicDriver,
            state: DomainState::Refused,
            detail: DomainDetail::Refusal(Refusal {
                cause: cause("not-virtio-net"),
                detail: RefusalDetail::Two(0x1af4, 0x1000),
                signalled: true,
            }),
        })
    );
}

/// The shapes that carry no cause convert without one, so the seam is not a
/// refusal waiting to happen for the records that make up most of a transcript.
#[test]
fn a_shape_with_no_cause_crosses_the_seam_unconditionally() {
    let events: [Event; 6] = [
        Event::Domain {
            domain: Domain::Console,
            state: DomainState::Ready,
            detail: DomainDetail::None,
        },
        Event::Domain {
            domain: Domain::Forwarder,
            state: DomainState::Negotiated,
            detail: DomainDetail::Features(7),
        },
        Event::Domain {
            domain: Domain::NicDriver,
            state: DomainState::Ready,
            detail: DomainDetail::ReceivePosted(64),
        },
        Event::ConfigGeneration {
            generation: 1,
            outcome: GenerationOutcome::Applied,
            changes: 2,
        },
        Event::ConfigRejected {
            generation: 1,
            reason: RejectReason::Doctype,
            offset: 3,
        },
        Event::ConfigChange {
            generation: 1,
            sequence: 0,
            change: ChangeKind::Added,
            object: ObjectKind::Neighbour,
            key: id("gw"),
            field: Field::Mac,
            from: None,
            to: Some(Value::Mac(MacAddress([1, 2, 3, 4, 5, 6]))),
        },
    ];
    for event in events {
        let bounded = Event::<Cause>::try_from(event).expect("no cause to bound");
        assert_eq!(round_trip(&bounded), Ok(bounded));
    }
}

/// A cause literal past what the ABI carries is refused with the value that made
/// it one, rather than truncated into a token an operator would read as whole.
#[test]
fn a_cause_literal_the_abi_cannot_carry_is_refused_with_its_measurement() {
    let too_long: &'static str = "a-cause-token-far-longer-than-the-abi-carries-for-one";
    let refusal = |cause: &'static str| Event::Domain {
        domain: Domain::NicDriver,
        state: DomainState::Refused,
        detail: DomainDetail::Refusal(Refusal {
            cause,
            detail: RefusalDetail::None,
            signalled: false,
        }),
    };
    assert_eq!(
        Event::<Cause>::try_from(refusal(too_long)),
        Err(CauseError::TooLong {
            len: too_long.len()
        })
    );
    assert_eq!(
        Event::<Cause>::try_from(refusal("Not Virtio")),
        Err(CauseError::NotInAlphabet { offset: 0 })
    );
}

// ---------------------------------------------------------------------------
// The record `wire` reads
// ---------------------------------------------------------------------------

/// An encoded record leaves every field its own `LogKind` does not name at the
/// zero a fresh region already holds, so a peer reading one cannot be handed a
/// number from an unrelated shape.
#[test]
fn a_record_writes_only_the_fields_its_kind_names() {
    let record = Event::ConfigGeneration {
        generation: 3,
        outcome: GenerationOutcome::Refused,
        changes: 4,
    }
    .encode(Stamp::Unsynchronized);
    assert_eq!(record.kind, LogKind::ConfigGeneration.to_bits());
    assert_eq!(record.generation, 3);
    assert_eq!(record.changes, 4);
    assert_eq!(record.features, 0);
    assert_eq!(record.operands, [0, 0]);
    assert_eq!(record.sequence, 0);
    assert_eq!(record.reject_offset, 0);
    assert_eq!(record.receive_posted, 0);
    assert_eq!(record.key, IdentifierImage::ZERO);
    assert_eq!(record.cause, CauseImage::ZERO);
    assert_eq!(record.from, ValueImage::ZERO);
    assert_eq!(record.to, ValueImage::ZERO);
}

/// A zeroed region is already a well-formed record, and it is the one every
/// domain's first slot holds before anything is written.
#[test]
fn the_zeroed_record_decodes_to_the_first_variant_of_everything() {
    let record = LogRecord::ZERO
        .check()
        .expect("a zeroed region is readable");
    assert_eq!(
        Event::decode(&record),
        Ok((
            Stamp::Unsynchronized,
            Event::Domain {
                domain: Domain::Forwarder,
                state: DomainState::Starting,
                detail: DomainDetail::None,
            }
        ))
    );
}

/// The two ends of a change are independent: an addition carries no `from` and a
/// removal no `to`, and the ABI's `Absent` kind is what keeps them apart from a
/// present value that happens to be zero.
#[test]
fn an_absent_end_and_a_zero_valued_one_do_not_encode_alike() {
    let change = |from, to| {
        Event::ConfigChange {
            generation: 0,
            sequence: 0,
            change: ChangeKind::Modified,
            object: ObjectKind::Interface,
            key: id("wan"),
            field: Field::Port,
            from,
            to,
        }
        .encode(Stamp::Unsynchronized)
    };
    let absent = change(None, None);
    let zero = change(Some(Value::Port(0)), Some(Value::Count(0)));
    assert_ne!(absent.from, zero.from);
    assert_ne!(absent.to, zero.to);
    assert_eq!(absent.from.kind, LogValueKind::Absent.to_bits());
    assert_eq!(zero.from.kind, LogValueKind::Port.to_bits());
    assert_eq!(zero.to.kind, LogValueKind::Count.to_bits());
}

/// Text shorter than its storage leaves the tail zero, so two records carrying
/// the same value are the same bytes whatever was in the slot before.
#[test]
fn text_shorter_than_its_storage_leaves_no_tail() {
    let record = Event::Domain {
        domain: Domain::Config,
        state: DomainState::Refused,
        detail: DomainDetail::Refusal(Refusal {
            cause: cause("abc"),
            detail: RefusalDetail::None,
            signalled: false,
        }),
    }
    .encode(Stamp::Unsynchronized);
    assert_eq!(record.cause.len, 3);
    assert_eq!(&record.cause.bytes[..3], b"abc");
    assert!(record.cause.bytes[3..].iter().all(|&byte| byte == 0));
}

// ---------------------------------------------------------------------------
// The headline property
// ---------------------------------------------------------------------------

fn any_cause() -> impl Strategy<Value = Cause> {
    "[a-z0-9-]{0,40}"
        .prop_map(|text| Cause::new(text.as_bytes()).expect("the pattern is the alphabet"))
}

fn any_identifier() -> impl Strategy<Value = Identifier> {
    "[a-z0-9-]{1,16}"
        .prop_map(|text| Identifier::new(text.as_bytes()).expect("the pattern is the alphabet"))
}

fn any_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<u8>().prop_map(Value::Port),
        any::<[u8; 4]>().prop_map(|octets| Value::Ipv4(Ipv4Address::from_octets(octets))),
        any::<[u8; 6]>().prop_map(|octets| Value::Mac(MacAddress(octets))),
        any::<u8>().prop_map(Value::PrefixLength),
        any::<bool>().prop_map(Value::Bool),
        any::<u32>().prop_map(Value::Generation),
        any::<u32>().prop_map(Value::Count),
        any_identifier().prop_map(Value::Id),
    ]
}

/// The established-time detail, from the two numbers the ABI carries. A helper
/// rather than a literal at each site: the frequency has to clear zero to exist
/// at all, and every test that builds one would otherwise restate that.
fn established(tsc_hz: u64, unix_nanos: u64) -> DomainDetail<Cause> {
    DomainDetail::Established {
        tsc_hz: NonZeroU64::new(tsc_hz).expect("a frequency above zero"),
        utc: UtcNanos::from_unix_nanos(unix_nanos),
    }
}

fn any_detail() -> impl Strategy<Value = DomainDetail<Cause>> {
    prop_oneof![
        Just(DomainDetail::None),
        any::<u64>().prop_map(DomainDetail::Features),
        any::<u32>().prop_map(DomainDetail::ReceivePosted),
        any::<(u64, u64)>().prop_map(|(frames, bytes)| DomainDetail::Received { frames, bytes }),
        (1..=u64::MAX, any::<u64>()).prop_map(|(hz, nanos)| established(hz, nanos)),
        (
            any_cause(),
            prop_oneof![
                Just(RefusalDetail::None),
                any::<u64>().prop_map(RefusalDetail::One),
                any::<(u64, u64)>().prop_map(|(a, b)| RefusalDetail::Two(a, b)),
            ],
            any::<bool>(),
        )
            .prop_map(|(cause, detail, signalled)| DomainDetail::Refusal(Refusal {
                cause,
                detail,
                signalled,
            })),
    ]
}

fn pick<T: Copy + core::fmt::Debug, const N: usize>(
    all: [T; N],
) -> impl Strategy<Value = T> + Clone {
    (0..N).prop_map(move |index| all[index])
}

/// Every variant, every vocabulary token, every numeric field over its whole
/// range, both ends of a change present and absent, and every cause the ABI can
/// carry — the whole of what an `Event<Cause>` can be.
fn any_event() -> impl Strategy<Value = Event<Cause>> {
    prop_oneof![
        (pick(Domain::ALL), pick(DomainState::ALL), any_detail()).prop_map(
            |(domain, state, detail)| Event::Domain {
                domain,
                state,
                detail,
            }
        ),
        (
            any::<u32>(),
            any::<u32>(),
            pick(ChangeKind::ALL),
            pick(ObjectKind::ALL),
            any_identifier(),
            pick(Field::ALL),
            proptest::option::of(any_value()),
            proptest::option::of(any_value()),
        )
            .prop_map(
                |(generation, sequence, change, object, key, field, from, to)| {
                    Event::ConfigChange {
                        generation,
                        sequence,
                        change,
                        object,
                        key,
                        field,
                        from,
                        to,
                    }
                }
            ),
        (any::<u32>(), pick(GenerationOutcome::ALL), any::<u32>()).prop_map(
            |(generation, outcome, changes)| Event::ConfigGeneration {
                generation,
                outcome,
                changes,
            }
        ),
        (any::<u32>(), pick(RejectReason::ALL), any::<u32>()).prop_map(
            |(generation, reason, offset)| Event::ConfigRejected {
                generation,
                reason,
                offset,
            }
        ),
    ]
}

proptest! {
    /// The headline: an arbitrary event crosses the ABI and comes back as
    /// itself. `wire`'s own check sits in the middle rather than a direct read
    /// of the record's fields, so this is the path a console domain takes and
    /// not a shortcut around it. Failure means the ABI cannot carry some
    /// variant or field — which is precisely what a fixed-layout record with
    /// one field per shape is at risk of.
    #[test]
    fn an_arbitrary_event_survives_the_crossing_unchanged(event in any_event()) {
        prop_assert_eq!(round_trip(&event), Ok(event));
    }

    /// Encoding is total: no event has a shape the record cannot hold, so the
    /// only thing that can refuse a crossing is a peer's bytes.
    #[test]
    fn encoding_never_refuses_and_always_produces_a_readable_record(event in any_event()) {
        prop_assert!(event.encode(Stamp::Unsynchronized).check().is_ok());
    }

    /// A record that survived `wire` and this decode renders, so the console
    /// domain's whole path is closed: bytes to event to line.
    #[test]
    fn a_decoded_event_renders_within_the_advertised_maximum(event in any_event()) {
        let decoded = round_trip(&event).expect("the crossing is lossless");
        let mut buffer = [0u8; crate::MAX_LINE_LEN];
        let written = crate::render(Stamp::Unsynchronized, &decoded, &mut buffer)
            .expect("MAX_LINE_LEN holds every line");
        prop_assert!(written <= crate::MAX_LINE_LEN);
        prop_assert!(buffer[..written].starts_with(b"LFW-"));
    }

    /// A minted event and its bounded form render identically, which is what
    /// makes the cause parameter a change of storage rather than of meaning: an
    /// operator cannot tell which side of the region a line came from.
    #[test]
    fn a_bounded_event_renders_exactly_as_the_literal_it_came_from(
        text in "[a-z0-9-]{0,40}",
        signalled in any::<bool>(),
    ) {
        // Leaked so the fixture is the `&'static str` a minting call site has;
        // this is a host test with an allocator and nothing in a protection
        // domain reaches this path.
        let literal: &'static str = std::boxed::Box::leak(text.clone().into_boxed_str());
        let minted = Event::Domain {
            domain: Domain::NicDriver,
            state: DomainState::Refused,
            detail: DomainDetail::Refusal(Refusal {
                cause: literal,
                detail: RefusalDetail::One(1),
                signalled,
            }),
        };
        let bounded = Event::<Cause>::try_from(minted).expect("the pattern is the alphabet");
        let mut minted_line = [0u8; crate::MAX_LINE_LEN];
        let mut bounded_line = [0u8; crate::MAX_LINE_LEN];
        let a = crate::render(Stamp::Unsynchronized, &minted, &mut minted_line).expect("fits");
        let b =
            crate::render(Stamp::Unsynchronized, &bounded, &mut bounded_line).expect("fits");
        prop_assert_eq!(&minted_line[..a], &bounded_line[..b]);
    }

    /// Arbitrary region bytes: whatever a byzantine writer puts in a record,
    /// the pair of checks is a decoded event or a typed refusal, and never a
    /// panic.
    #[test]
    fn arbitrary_record_bytes_decode_or_refuse(
        features in any::<u64>(),
        operands in any::<[u64; 2]>(),
        kind in any::<u32>(),
        numbers in any::<[u32; 5]>(),
        tokens in any::<[u8; 10]>(),
        cause_bytes in any::<[u8; MAX_CAUSE_LEN]>(),
        cause_len in any::<u8>(),
        key_bytes in any::<[u8; MAX_IDENTIFIER_LEN]>(),
        key_len in any::<u8>(),
        tsc_hz in any::<u64>(),
        unix_nanos in any::<u64>(),
        counts in any::<[u64; 4]>(),
        stamp_kind in any::<u8>(),
        stamp_nanos in any::<u64>(),
    ) {
        let [generation, sequence, changes, reject_offset, receive_posted] = numbers;
        let [frames, frame_bytes, capacity_sectors, leading_word] = counts;
        let [domain, state, detail, operand_count, signalled, change, object, field, outcome, reason] =
            tokens;
        let record = LogRecord {
            features,
            operands,
            kind,
            generation,
            sequence,
            changes,
            reject_offset,
            receive_posted,
            domain,
            state,
            detail,
            operand_count,
            signalled,
            change,
            object,
            field,
            outcome,
            reason,
            stamp_kind,
            _pad: [0; 5],
            cause: TextImage { bytes: cause_bytes, len: cause_len, _pad: [0; 3] },
            key: TextImage { bytes: key_bytes, len: key_len, _pad: [0; 3] },
            from: ValueImage::ZERO,
            to: ValueImage::ZERO,
            tsc_hz,
            unix_nanos,
            stamp_nanos,
            frames,
            frame_bytes,
            capacity_sectors,
            leading_word,
        };
        match record.check() {
            Err(_) => {}
            Ok(checked) => match Event::decode(&checked) {
                Err(_) => {}
                Ok((at, event)) => {
                    // Anything that decodes must also render, or the console
                    // domain would hold an event it cannot put on the wire —
                    // and the widest instant is exactly as bounded as the
                    // narrowest, so the stamp cannot be what overruns the line.
                    let mut buffer = [0u8; crate::MAX_LINE_LEN];
                    prop_assert!(crate::render(at, &event, &mut buffer).is_ok());
                }
            },
        }
    }
}
