//! `wire`'s log record, and the console line a decoded one becomes, under a
//! byzantine neighbour PD.
//!
//! # The adversary and the surface
//!
//! A writing domain owns the records region and the console domain maps it
//! read-only, so every byte of every slot was chosen by another domain —
//! a byzantine neighbour. [`LogRecord::check`] is the console's whole defence against
//! the *shape* of those bytes, [`lfw_log::Event::decode`] its defence against
//! the vocabulary tokens inside them, and [`lfw_log::render`] is what turns
//! what survives into bytes on an operator's terminal. All three are driven
//! here, in that order, because that is the order the console domain drives
//! them (`crates/log/src/console.rs`, `ConsolePrinter::print_record`).
//!
//! # What the adversary may express here
//!
//! The record is a fixed-layout POD with no implicit padding — the `const _`
//! block at the foot of `crates/wire/src/log_record.rs` asserts the fields sum
//! to the whole [`RECORD_BYTES`] — so the fuzzer's bytes *are* the region.
//! [`record_from_region`] lays the input over the ABI field for field and
//! zeroes what the input does not reach, which is what a partially written
//! region holds. Nothing is reduced into a plausible range on the way:
//! record kinds that name no event, vocabulary tokens past their cardinality,
//! value-type tags that name no value, text lengths past the storage the record
//! carries, text bytes that are ESC, newline or anything else outside
//! `[a-z0-9-]`, an operand count naming storage that does not exist, `signalled`
//! bytes that are no boolean, a counter frequency of zero, an instant past any
//! date a node will see, a stamp discriminant that says neither a time nor the
//! lack of one, and arbitrary padding are all ordinary inputs.
//!
//! # Why three records are checked and not one
//!
//! `kind` is a `u32` with four admissible values, so a uniform record-sized blob is
//! `KindUnknown` for all but four of the 2^32 values that one field can take,
//! and the rules behind it would never be reached by chance.
//! [`derivations`] therefore checks, **in addition to** the
//! unmodified record and never instead of it, two records derived from the same
//! bytes: one folding every discriminant and vocabulary token into the band
//! around its cardinality, and one folding the text bytes into the console
//! alphabet as well, which is what makes an *accepted* record — and so the
//! render path below — common rather than astronomically rare.
//!
//! This widens what is reached without narrowing what is reachable — the
//! distinction that matters: the first check still carries the
//! adversary's full authority on every input, and the committed seeds carry the
//! ESC, the newline and the over-long text explicitly so those shapes do not
//! depend on the fuzzer rediscovering them.
//!
//! # What is asserted
//!
//! * **Exact semantics, against an independent model.** [`refusal`] restates
//!   the ABI's acceptance rules **and their order** from the record contract
//!   rather than from the code, and every outcome is compared with it. A
//!   *wrongly accepted* record — the failure that actually reaches the operator
//!   — fails here as loudly as a panic, which a harness checking only for
//!   panics would have passed.
//! * **Determinism.** Checking one record twice yields one answer.
//! * **A body carries only the fields its kind names.** Every field the
//!   record's kind does not name is rewritten to a value nothing admits and the
//!   record re-checked: the answer must not move. That covers the operands
//!   past `operand_count` and the sub-fields of a value slot its own kind does
//!   not name — the count is a bound, not a hint.
//! * **Every accepted text is within its bound and its alphabet**, which is the
//!   property the next one rests on.
//! * **The console line is printable.** The accepted body is decoded
//!   and rendered exactly as `ConsolePrinter` does it, and every byte of the
//!   line is asserted to be printable ASCII: no control character, no ESC, no
//!   CR and no LF. This is what stops a hostile writing domain painting
//!   terminal escape sequences onto the operator's console through a log line,
//!   and it is asserted over the whole path rather than over `Identifier`'s
//!   alphabet alone, because the alphabet is only one of the two checks between
//!   the region and the UART.
//! * **A checked record always decodes.** `wire` bounds a token against its
//!   `LOG_*_COUNT` and `lfw_log` maps it onto a variant; the two crates hold
//!   separate copies of every cardinality and of both text alphabets, and a
//!   `DecodeError` out of a record `wire` accepted is those copies having
//!   parted — a console silently counting `unknown` and printing nothing.
//! * **A decoded event re-encodes to a record the check accepts**, decodes
//!   again to the same event, and renders to the same line.

use arbitrary::{Arbitrary as _, Unstructured};
use lfw_log::{Cause, Event, MAX_LINE_LEN, Stamp, render};
use wire::{
    CauseImage, CheckedBody, CheckedDetail, CheckedText, CheckedValue, IdentifierImage,
    LOG_CAUSE_BYTES, LOG_CHANGE_KIND_COUNT, LOG_DOMAIN_COUNT, LOG_DOMAIN_STATE_COUNT,
    LOG_FIELD_COUNT, LOG_GENERATION_OUTCOME_COUNT, LOG_IDENTIFIER_BYTES, LOG_OBJECT_KIND_COUNT,
    LOG_REJECT_REASON_COUNT, LogRecord, LogRecordError, LogText, TextImage, ValueImage,
};

/// Bytes one record occupies, and so what one corpus entry is.
///
/// Restated from the ABI contract rather than taken from `size_of`, so a record
/// that changed size would show up as a seed that no longer means what it was
/// committed for rather than as a silently re-laid-out input.
pub const RECORD_BYTES: usize = 248;

/// The four record kinds, as the ABI numbers them. Restated here rather than
/// reached for through `LogKind::to_bits`, which is the code under test.
const KIND_DOMAIN: u32 = 0;
const KIND_CONFIG_CHANGE: u32 = 1;
const KIND_CONFIG_GENERATION: u32 = 2;
const KIND_CONFIG_REJECTED: u32 = 3;
/// One past the last kind: the smallest `kind` no event has.
const KIND_COUNT: u32 = 4;

/// The two stamp discriminants and one past them, on [`KIND_COUNT`]'s terms.
const STAMP_UNSYNCHRONIZED: u8 = 0;
const STAMP_UTC: u8 = 1;
const STAMP_KIND_COUNT: u8 = 2;

/// The eight `LogDetailKind` discriminants, restated on `KIND_DOMAIN`'s terms.
const DETAIL_NONE: u8 = 0;
const DETAIL_FEATURES: u8 = 1;
const DETAIL_RECEIVE_POSTED: u8 = 2;
const DETAIL_REFUSAL: u8 = 3;
const DETAIL_ESTABLISHED: u8 = 4;
const DETAIL_RECEIVED: u8 = 5;
const DETAIL_MEDIUM: u8 = 6;
const DETAIL_EXTENT: u8 = 7;
const DETAIL_COUNT: u8 = 8;

/// The eleven `LogValueKind` discriminants, restated on `KIND_DOMAIN`'s terms.
const VALUE_ABSENT: u8 = 0;
const VALUE_PORT: u8 = 1;
const VALUE_IPV4: u8 = 2;
const VALUE_MAC: u8 = 3;
const VALUE_PREFIX_LENGTH: u8 = 4;
const VALUE_BOOL: u8 = 5;
const VALUE_GENERATION: u8 = 6;
const VALUE_COUNT_KIND: u8 = 7;
const VALUE_ID: u8 = 8;
/// A filter rule's criterion token, carried in the identifier field.
const VALUE_SELECTOR: u8 = 9;
/// A filter rule's address block: the network in the first four octets and the
/// prefix length in `number`.
const VALUE_PREFIX: u8 = 10;
const VALUE_KIND_COUNT: u8 = 11;

/// How many operands the record's array holds, which is what an
/// `operand_count` past it names storage beyond.
const MAX_OPERANDS: u8 = 2;

/// Octets of an IPv4 address, the prefix of the six a value slot carries.
const IPV4_OCTETS: usize = 4;

/// Drive the record check, the decode above it and the console line above that,
/// against a record a byzantine writing domain left in a slot.
pub fn log_record_harness(data: &[u8]) {
    for record in derivations(data) {
        check_one(&record);
    }
}

/// The records one input is checked as: the region verbatim, then two
/// derivations of it that reach past the discriminant. See this module's
/// header for why the last two exist and why they are additive.
fn derivations(data: &[u8]) -> [LogRecord; 3] {
    let raw = record_from_region(data);
    let narrowed = narrow_discriminants(raw);
    let mut alphabetised = narrowed;
    alphabetised.cause = into_alphabet(&narrowed.cause);
    alphabetised.key = into_alphabet(&narrowed.key);
    alphabetised.from.id = into_alphabet(&narrowed.from.id);
    alphabetised.to.id = into_alphabet(&narrowed.to.id);
    [raw, narrowed, alphabetised]
}

/// Fold every discriminant and vocabulary token into the band around its own
/// cardinality, so the rules *behind* the token check are reached.
///
/// One past the end is deliberately inside every band: the off-by-one is the
/// interesting value, and a fold that produced only admissible tokens would
/// leave every `…Unknown` refusal unreachable on a derived record.
fn narrow_discriminants(record: LogRecord) -> LogRecord {
    let mut narrowed = record;
    narrowed.kind = record.kind % (KIND_COUNT + 1);
    narrowed.stamp_kind = record.stamp_kind % (STAMP_KIND_COUNT + 1);
    narrowed.domain = record.domain % (LOG_DOMAIN_COUNT + 2);
    narrowed.state = record.state % (LOG_DOMAIN_STATE_COUNT + 2);
    narrowed.detail = record.detail % (DETAIL_COUNT + 1);
    narrowed.operand_count = record.operand_count % (MAX_OPERANDS + 2);
    narrowed.signalled = record.signalled % 3;
    // Zero is the one value of this field a rule refuses and is unreachable by
    // chance over `u64`; one is the narrowest accepted frequency. The
    // unmodified record still carries the whole of `u64` on every input.
    narrowed.tsc_hz = record.tsc_hz % 2;
    narrowed.change = record.change % (LOG_CHANGE_KIND_COUNT + 2);
    narrowed.object = record.object % (LOG_OBJECT_KIND_COUNT + 2);
    narrowed.field = record.field % (LOG_FIELD_COUNT + 2);
    narrowed.outcome = record.outcome % (LOG_GENERATION_OUTCOME_COUNT + 2);
    narrowed.reason = record.reason % (LOG_REJECT_REASON_COUNT + 2);
    narrowed.cause.len = record.cause.len % (LOG_CAUSE_BYTES as u8 + 3);
    narrowed.key.len = record.key.len % (LOG_IDENTIFIER_BYTES as u8 + 3);
    narrowed.from = narrow_value(record.from);
    narrowed.to = narrow_value(record.to);
    narrowed
}

/// [`narrow_discriminants`] for one value slot.
fn narrow_value(value: ValueImage) -> ValueImage {
    let mut narrowed = value;
    narrowed.kind = value.kind % (VALUE_KIND_COUNT + 2);
    // The narrow-to-a-byte rule and the boolean rule both live just above 1,
    // and an unreduced `u32` would reach neither: 1 is `true`, 2 is a `Bool`
    // that is no boolean, and 256 is the first that does not fit the byte a
    // port is. Folding to that band leaves the whole decision boundary
    // reachable on a derived record; the unmodified record still carries the
    // full `u32` on every input.
    narrowed.number = value.number % 258;
    narrowed.id.len = value.id.len % (LOG_IDENTIFIER_BYTES as u8 + 3);
    narrowed
}

/// The console alphabet, restated from the ABI contract rather than reached for
/// in `wire` or `lfw_log`, which are the two copies under test.
const ALPHABET: &[u8; 37] = b"abcdefghijklmnopqrstuvwxyz0123456789-";

/// Fold a text's bytes into [`ALPHABET`], leaving its length alone.
///
/// Additive on this module's terms: the unmodified and discriminant-narrowed
/// records still carry arbitrary text bytes on every input, and the committed
/// seeds carry an ESC sequence and a newline explicitly. What this buys is that
/// an *accepted* record — the only kind that reaches `decode` and `render` —
/// stops being astronomically rare, so the printable-line property is
/// exercised rather than merely present.
fn into_alphabet<const N: usize>(text: &TextImage<N>) -> TextImage<N> {
    let mut folded = *text;
    for byte in &mut folded.bytes {
        *byte = ALPHABET[usize::from(*byte) % ALPHABET.len()];
    }
    folded
}

/// Check one record against the model, and drive everything above an accepted
/// one.
fn check_one(record: &LogRecord) {
    let outcome = record.check();
    assert_eq!(
        outcome,
        record.check(),
        "checking one record twice gave two answers"
    );
    assert_eq!(
        outcome.err(),
        refusal(record),
        "the record check and the ABI contract disagree about this record"
    );

    let Ok(checked) = outcome else {
        return;
    };
    let body = checked.body;

    assert_body_carries_only_what_its_kind_names(record, &body);
    assert_texts_are_within_their_bounds(&body);

    // The console's own path, in the console's own order: `wire` has ruled on
    // the shape, `lfw_log` rules on the vocabulary, and what survives both is
    // rendered onto a line.
    let (at, event) = Event::<Cause>::decode(&checked).unwrap_or_else(|error| {
        panic!(
            "a record the ABI accepted decoded to no event ({error}); the two crates' copies of a \
             vocabulary cardinality or of a text alphabet have parted, and a console would count \
             this `unknown` and print nothing"
        )
    });
    let line = assert_console_line_is_printable(at, &event);

    // Round trip: the event the console holds is one the ABI can carry back,
    // and carrying it back changes neither the record, the event, the instant,
    // nor the line an operator reads.
    let re_encoded = event.encode(at);
    assert_eq!(
        re_encoded.check(),
        Ok(checked),
        "an event re-encoded to a record the check no longer accepts as the same record"
    );
    let (re_at, re_decoded) =
        Event::<Cause>::decode(&checked).expect("the same record decoded once already");
    assert_eq!(
        event, re_decoded,
        "decoding one record twice gave two events"
    );
    assert_eq!(at, re_at, "decoding one record twice gave two instants");
    assert_eq!(
        line,
        assert_console_line_is_printable(re_at, &re_decoded),
        "one event rendered two different lines"
    );
}

/// Render an event the way `ConsolePrinter::print` does and assert every byte
/// of the resulting console line is one a terminal prints rather than obeys.
///
/// This is the printable-line property, and it is the reason this harness chains three
/// crates instead of stopping at the check: the bytes came out of a region a
/// hostile domain owns, and between that region and the UART there is nothing
/// but the alphabet check in `wire` and the one in `lfw_log`. A byte that
/// escaped both would reach a terminal as an instruction — cursor movement,
/// screen clear, a title-bar rewrite — and the record that carried it would be
/// the last thing an operator could believe.
///
/// Returns the line so a caller can compare two renderings of one event.
fn assert_console_line_is_printable(at: Stamp, event: &Event<Cause>) -> Vec<u8> {
    let mut buffer = [0u8; MAX_LINE_LEN];
    let written = render(at, event, &mut buffer).unwrap_or_else(|error| {
        panic!(
            "an event decoded out of a record did not fit MAX_LINE_LEN ({error}); no peer can \
             cause that, so the renderer and the buffer have parted"
        )
    });
    assert!(
        written <= MAX_LINE_LEN,
        "render reported {written} bytes into a {MAX_LINE_LEN}-byte buffer"
    );
    let line = buffer
        .get(..written)
        .expect("render reported what it wrote");

    for (offset, &byte) in line.iter().enumerate() {
        assert!(
            (0x20..=0x7E).contains(&byte),
            "console line byte {offset} is {byte:#04x}, which is not printable ASCII: a hostile \
             writing domain reached the operator's terminal with something it obeys"
        );
    }
    // Stated separately from the range above rather than inferred from it: these
    // three are what the property is *for*, and a future widening of the range
    // must fail here rather than quietly admit them.
    assert!(!line.contains(&0x1B), "an ESC reached the console line");
    assert!(!line.contains(&b'\n'), "an LF reached the console line");
    assert!(!line.contains(&b'\r'), "a CR reached the console line");
    assert!(
        line.starts_with(b"LFW-"),
        "a console line without the prefix a reader keys on"
    );

    // The line as the console domain actually puts it on the wire: `render`
    // writes no terminator and `ConsolePrinter` appends CRLF, so the whole
    // transmitted line carries exactly one of each and both at the end. That is
    // the form in which "no newline other than a single terminator" is a claim
    // about what a terminal receives rather than about an intermediate buffer.
    let mut transmitted = line.to_vec();
    transmitted.extend_from_slice(b"\r\n");
    assert_eq!(
        transmitted.iter().filter(|&&byte| byte == b'\r').count(),
        1,
        "the transmitted line carries more than one carriage return"
    );
    assert_eq!(
        transmitted.iter().filter(|&&byte| byte == b'\n').count(),
        1,
        "the transmitted line carries more than one newline"
    );
    assert!(transmitted.ends_with(b"\r\n"));

    line.to_vec()
}

/// Assert every text an accepted body carries is inside the storage the record
/// holds and inside the console alphabet.
///
/// The bound and the alphabet are restated here rather than taken from the
/// checked text's own accessors: `CheckedText` has no public constructor, so
/// holding one is supposed to *be* the evidence, and this is what turns that
/// into a checked claim rather than a naming convention.
fn assert_texts_are_within_their_bounds(body: &CheckedBody) {
    match body {
        CheckedBody::Domain { detail, .. } => {
            if let CheckedDetail::Refusal { cause, .. } = detail {
                assert_text(cause, true);
            }
        }
        CheckedBody::ConfigChange { key, from, to, .. } => {
            assert_text(key, false);
            for value in [from, to].into_iter().flatten() {
                if let CheckedValue::Id(id) = value {
                    assert_text(id, false);
                }
            }
        }
        CheckedBody::ConfigGeneration { .. } | CheckedBody::ConfigRejected { .. } => {}
    }
}

/// One accepted text: within its own storage, empty only where the ABI admits
/// it, and every byte in the console alphabet.
fn assert_text<const N: usize>(text: &CheckedText<N>, may_be_empty: bool) {
    assert!(
        text.len() <= N,
        "an accepted text is {} bytes of {N} storage",
        text.len()
    );
    let len = text.len();
    assert_eq!(len, text.as_bytes().len());
    assert_eq!(text.is_empty(), len == 0);
    assert!(
        may_be_empty || !text.is_empty(),
        "an empty text was accepted where the ABI requires one"
    );
    for (offset, &byte) in text.as_bytes().iter().enumerate() {
        assert!(
            ALPHABET.contains(&byte),
            "accepted text byte {offset} is {byte:#04x}, outside the console alphabet"
        );
    }
    // The alphabet is single-byte UTF-8 throughout, which is what lets the
    // renderer write the text without asking.
    assert_eq!(text.as_str().as_bytes(), text.as_bytes());
}

/// Rewrite every field the record's kind does not name to a value nothing
/// admits, re-check, and assert the answer does not move.
///
/// A body that changed would be one assembled partly out of bytes its own kind
/// never claimed — the log-transport form of a reader walking its arrays
/// instead of its counts. It covers two claims a per-field comparison would
/// not: the operands past `operand_count` are storage the record does not name,
/// and a value slot's sub-fields belong to its own kind alone.
fn assert_body_carries_only_what_its_kind_names(record: &LogRecord, body: &CheckedBody) {
    let scribbled = keep_only_named_fields(record);
    assert_eq!(
        scribbled.check().map(|checked| checked.body),
        Ok(*body),
        "rewriting the fields this record's kind does not name changed what the check decoded"
    );
}

/// A record whose every field is a value some rule refuses, so reading one
/// would be visible in the outcome whatever else the record held.
const POISON: LogRecord = LogRecord {
    features: 0xAAAA_AAAA_AAAA_AAAA,
    operands: [0xAAAA_AAAA_AAAA_AAAA; 2],
    kind: 0xAAAA_AAAA,
    generation: 0xAAAA_AAAA,
    sequence: 0xAAAA_AAAA,
    changes: 0xAAAA_AAAA,
    reject_offset: 0xAAAA_AAAA,
    receive_posted: 0xAAAA_AAAA,
    domain: 0xAA,
    state: 0xAA,
    detail: 0xAA,
    operand_count: 0xAA,
    signalled: 0xAA,
    change: 0xAA,
    object: 0xAA,
    field: 0xAA,
    outcome: 0xAA,
    reason: 0xAA,
    stamp_kind: 0xAA,
    _pad: [0xAA; 5],
    cause: POISON_CAUSE,
    key: POISON_IDENTIFIER,
    from: POISON_VALUE,
    to: POISON_VALUE,
    // Zero rather than the 0xAA pattern the rest carries: zero is the value the
    // frequency rule refuses, and 0xAA… is one it admits. Poison is whatever a
    // rule says no to, which for this field is the opposite of "unlikely".
    tsc_hz: 0,
    // And no value of this one is refused, so the pattern is only here to be
    // visible if a decode read it under a detail that never named it.
    unix_nanos: 0xAAAA_AAAA_AAAA_AAAA,
    // Nor of these four: neither `Received` nor `Medium` refuses anything, so
    // the pattern is here for the same reason.
    frames: 0xAAAA_AAAA_AAAA_AAAA,
    frame_bytes: 0xAAAA_AAAA_AAAA_AAAA,
    capacity_sectors: 0xAAAA_AAAA_AAAA_AAAA,
    leading_word: 0xAAAA_AAAA_AAAA_AAAA,
    // Nor of this one, under either discriminant: an instant is unranged and an
    // unsynchronized record reads the field not at all.
    stamp_nanos: 0xAAAA_AAAA_AAAA_AAAA,
};

/// A text nothing admits: a length past its own storage, and every byte an ESC
/// so a length that somehow passed would still be refused by the alphabet.
const POISON_CAUSE: CauseImage = CauseImage {
    bytes: [0x1B; LOG_CAUSE_BYTES],
    len: u8::MAX,
    _pad: [0xAA; 3],
};

/// As [`POISON_CAUSE`], for an identifier.
const POISON_IDENTIFIER: IdentifierImage = IdentifierImage {
    bytes: [0x1B; LOG_IDENTIFIER_BYTES],
    len: u8::MAX,
    _pad: [0xAA; 3],
};

/// A value slot nothing admits: a kind that names no value, and every field it
/// could have named poisoned behind it.
const POISON_VALUE: ValueImage = ValueImage {
    number: 0xAAAA_AAAA,
    kind: 0xAA,
    octets: [0xAA; 6],
    _pad: 0xAA,
    id: POISON_IDENTIFIER,
};

/// [`POISON`] with exactly the fields this record's kind names copied back.
fn keep_only_named_fields(record: &LogRecord) -> LogRecord {
    let mut kept = POISON;
    kept.kind = record.kind;
    // The stamp belongs to every shape rather than to a kind, so it is kept
    // whatever the kind is — and its nanoseconds only under the discriminant
    // that names them, which is the same rule the body's fields are held to.
    kept.stamp_kind = record.stamp_kind;
    if record.stamp_kind == STAMP_UTC {
        kept.stamp_nanos = record.stamp_nanos;
    }
    match record.kind {
        KIND_DOMAIN => {
            kept.domain = record.domain;
            kept.state = record.state;
            kept.detail = record.detail;
            match record.detail {
                DETAIL_FEATURES => kept.features = record.features,
                DETAIL_RECEIVE_POSTED => kept.receive_posted = record.receive_posted,
                DETAIL_ESTABLISHED => {
                    kept.tsc_hz = record.tsc_hz;
                    kept.unix_nanos = record.unix_nanos;
                }
                DETAIL_RECEIVED => {
                    kept.frames = record.frames;
                    kept.frame_bytes = record.frame_bytes;
                }
                DETAIL_MEDIUM => {
                    kept.capacity_sectors = record.capacity_sectors;
                    kept.leading_word = record.leading_word;
                }
                // The two words a refusal would carry, read here as an extent:
                // whole, not to `operand_count`, because this detail names both
                // unconditionally.
                DETAIL_EXTENT => kept.operands = record.operands,
                DETAIL_REFUSAL => {
                    kept.cause = record.cause;
                    kept.operand_count = record.operand_count;
                    kept.signalled = record.signalled;
                    // Positionally, and only as many as the count names: an
                    // operand past it is storage this record did not claim.
                    for index in 0..usize::from(record.operand_count.min(MAX_OPERANDS)) {
                        kept.operands[index] = record.operands[index];
                    }
                }
                _ => {}
            }
        }
        KIND_CONFIG_CHANGE => {
            kept.generation = record.generation;
            kept.sequence = record.sequence;
            kept.change = record.change;
            kept.object = record.object;
            kept.key = record.key;
            kept.field = record.field;
            kept.from = keep_only_named_value_fields(&record.from);
            kept.to = keep_only_named_value_fields(&record.to);
        }
        KIND_CONFIG_GENERATION => {
            kept.generation = record.generation;
            kept.outcome = record.outcome;
            kept.changes = record.changes;
        }
        KIND_CONFIG_REJECTED => {
            kept.generation = record.generation;
            kept.reason = record.reason;
            kept.reject_offset = record.reject_offset;
        }
        _ => {}
    }
    kept
}

/// [`keep_only_named_fields`] for one value slot: the kind, and behind it only
/// what that kind reads.
fn keep_only_named_value_fields(value: &ValueImage) -> ValueImage {
    let mut kept = POISON_VALUE;
    kept.kind = value.kind;
    match value.kind {
        VALUE_ABSENT => {}
        VALUE_PORT | VALUE_PREFIX_LENGTH | VALUE_BOOL | VALUE_GENERATION | VALUE_COUNT_KIND => {
            kept.number = value.number
        }
        // Four octets and not six: an address decoded out of the two a MAC adds
        // would be an address nobody configured.
        VALUE_IPV4 => kept.octets[..IPV4_OCTETS].copy_from_slice(&value.octets[..IPV4_OCTETS]),
        VALUE_MAC => kept.octets = value.octets,
        VALUE_ID | VALUE_SELECTOR => kept.id = value.id,
        // Both halves of a block, and neither of the two octets a MAC adds: a
        // network decoded out of those would be a block nobody wrote.
        VALUE_PREFIX => {
            kept.number = value.number;
            kept.octets[..IPV4_OCTETS].copy_from_slice(&value.octets[..IPV4_OCTETS]);
        }
        _ => {}
    }
    kept
}

/// What the ABI contract says this record is refused for, derived from the
/// record alone — restated here so the harness is not checking the code against
/// itself. `None` is a record every rule admits.
///
/// The order is part of the contract and not an accident of the implementation:
/// the kind is decided before any field, and within a kind the fields are ruled
/// on in the order the record declares them. A check that refused a different
/// field first would still be refusing, and an operator reading the console's
/// `malformed` attribution would be sent to the wrong field of the wrong
/// domain's record.
fn refusal(record: &LogRecord) -> Option<LogRecordError> {
    // The stamp is ruled on before any body field, so a record that is wrong in
    // both places is refused for the stamp. The order is part of the contract:
    // a body rendered without an instant would silently read as having no time.
    if let Some(refusal) = stamp_refusal(record) {
        return Some(refusal);
    }
    match record.kind {
        KIND_DOMAIN => domain_refusal(record),
        KIND_CONFIG_CHANGE => config_change_refusal(record),
        KIND_CONFIG_GENERATION => vocabulary(
            record.outcome,
            LOG_GENERATION_OUTCOME_COUNT,
            LogRecordError::GenerationOutcomeUnknown {
                outcome: record.outcome,
            },
        ),
        KIND_CONFIG_REJECTED => vocabulary(
            record.reason,
            LOG_REJECT_REASON_COUNT,
            LogRecordError::RejectReasonUnknown {
                reason: record.reason,
            },
        ),
        kind => Some(LogRecordError::KindUnknown { kind }),
    }
}

/// The instant: two admissible discriminants and nothing else. The nanoseconds
/// beside them are unranged in both cases — every `u64` names a civil time, and
/// under the unsynchronized discriminant nothing reads the field at all.
fn stamp_refusal(record: &LogRecord) -> Option<LogRecordError> {
    match record.stamp_kind {
        STAMP_UNSYNCHRONIZED | STAMP_UTC => None,
        kind => Some(LogRecordError::StampKindUnknown { kind }),
    }
}

/// A `Domain` record: the domain, then its state, then the detail — and, for a
/// refusal, its cause, then its operand count, then `signalled`; for an
/// established clock, its frequency.
fn domain_refusal(record: &LogRecord) -> Option<LogRecordError> {
    vocabulary(
        record.domain,
        LOG_DOMAIN_COUNT,
        LogRecordError::DomainUnknown {
            domain: record.domain,
        },
    )
    .or_else(|| {
        vocabulary(
            record.state,
            LOG_DOMAIN_STATE_COUNT,
            LogRecordError::DomainStateUnknown {
                state: record.state,
            },
        )
    })
    .or_else(|| match record.detail {
        // `Received`, `Medium` and `Extent` join these: two unranged numbers
        // each, so the detail carries nothing a rule can refuse it for.
        DETAIL_NONE
        | DETAIL_FEATURES
        | DETAIL_RECEIVE_POSTED
        | DETAIL_RECEIVED
        | DETAIL_MEDIUM
        | DETAIL_EXTENT => None,
        // The instant is unranged on purpose: every `u64` of nanoseconds names
        // a civil time, so the frequency is the whole of what this detail can
        // be refused for.
        DETAIL_ESTABLISHED => (record.tsc_hz == 0).then_some(LogRecordError::ClockFrequencyZero),
        DETAIL_REFUSAL => text_refusal(&record.cause, LogText::Cause, true)
            .or_else(|| {
                (record.operand_count > MAX_OPERANDS).then_some(
                    LogRecordError::OperandCountUnknown {
                        operands: record.operand_count,
                    },
                )
            })
            .or_else(|| {
                (record.signalled > 1).then_some(LogRecordError::SignalledNotBoolean {
                    signalled: record.signalled,
                })
            }),
        detail => Some(LogRecordError::DetailKindUnknown { detail }),
    })
}

/// A `ConfigChange` record: change, object, key, field, `from`, `to`.
fn config_change_refusal(record: &LogRecord) -> Option<LogRecordError> {
    vocabulary(
        record.change,
        LOG_CHANGE_KIND_COUNT,
        LogRecordError::ChangeKindUnknown {
            change: record.change,
        },
    )
    .or_else(|| {
        vocabulary(
            record.object,
            LOG_OBJECT_KIND_COUNT,
            LogRecordError::ObjectKindUnknown {
                object: record.object,
            },
        )
    })
    .or_else(|| text_refusal(&record.key, LogText::Key, false))
    .or_else(|| {
        vocabulary(
            record.field,
            LOG_FIELD_COUNT,
            LogRecordError::FieldUnknown {
                field: record.field,
            },
        )
    })
    .or_else(|| value_refusal(&record.from, LogText::From))
    .or_else(|| value_refusal(&record.to, LogText::To))
}

/// A vocabulary token at or beyond its cardinality is refused with the caller's
/// error; anything below it is this ABI's business no further.
fn vocabulary(raw: u8, count: u8, error: LogRecordError) -> Option<LogRecordError> {
    (raw >= count).then_some(error)
}

/// One text field: the length against the storage, then emptiness where the
/// field forbids it, then the alphabet from the first byte outside it.
fn text_refusal<const N: usize>(
    text: &TextImage<N>,
    which: LogText,
    may_be_empty: bool,
) -> Option<LogRecordError> {
    let len = usize::from(text.len);
    if len > N {
        return Some(LogRecordError::TextTooLong {
            text: which,
            len: text.len,
        });
    }
    if len == 0 && !may_be_empty {
        return Some(LogRecordError::TextEmpty { text: which });
    }
    text.bytes
        .iter()
        .enumerate()
        .take(len)
        .find(|&(_, &byte)| !ALPHABET.contains(&byte))
        .map(|(offset, _)| LogRecordError::TextNotInAlphabet {
            text: which,
            offset,
        })
}

/// One value slot: the kind, then only what that kind reads.
fn value_refusal(value: &ValueImage, which: LogText) -> Option<LogRecordError> {
    match value.kind {
        VALUE_ABSENT | VALUE_IPV4 | VALUE_MAC | VALUE_GENERATION | VALUE_COUNT_KIND => None,
        // A prefix's length is narrowed exactly as a standalone one is: the same
        // byte on the console, so the same refusal for a word that does not fit.
        VALUE_PORT | VALUE_PREFIX_LENGTH | VALUE_PREFIX => {
            narrowing_refusal(value.number, which)
        }
        // The narrowing first and the boolean second: 256 does not fit the byte
        // a `Bool` is carried in, and 2 fits it and is still no boolean.
        VALUE_BOOL => narrowing_refusal(value.number, which).or_else(|| {
            (value.number > 1).then_some(LogRecordError::ValueBoolNotBoolean {
                text: which,
                number: value.number,
            })
        }),
        VALUE_ID | VALUE_SELECTOR => text_refusal(&value.id, which, false),
        kind => Some(LogRecordError::ValueKindUnknown { text: which, kind }),
    }
}

/// A value word that does not fit the byte its kind is carried in, refused
/// rather than truncated into one the writer did not pick.
fn narrowing_refusal(number: u32, which: LogText) -> Option<LogRecordError> {
    (number > u32::from(u8::MAX)).then_some(LogRecordError::ValueNumberTooLarge {
        text: which,
        number,
    })
}

/// Lay the input over the record's ABI, field for field, zeroing whatever the
/// input does not reach.
///
/// Positional rather than derived through [`arbitrary`]'s own layout, for
/// `handover::image_from_region`'s two reasons: a corpus entry is then literally
/// the slot a writing domain left behind, so a seed can be authored and read as
/// one; and the mapping stays fixed whatever `arbitrary` does internally, so a
/// curated regression seed keeps meaning the record it was committed for.
/// Little-endian because the target is x86_64 and nothing else.
#[must_use]
pub fn record_from_region(data: &[u8]) -> LogRecord {
    let mut unstructured = Unstructured::new(data);
    read_record(&mut unstructured)
}

/// One record's worth of the region, from wherever the input now stands.
///
/// Separate from [`record_from_region`] so the ring harness can lay several
/// consecutive records out of one input without re-deriving the field order.
pub(crate) fn read_record(unstructured: &mut Unstructured<'_>) -> LogRecord {
    LogRecord {
        features: quad(unstructured),
        operands: [quad(unstructured), quad(unstructured)],
        tsc_hz: quad(unstructured),
        unix_nanos: quad(unstructured),
        frames: quad(unstructured),
        frame_bytes: quad(unstructured),
        capacity_sectors: quad(unstructured),
        leading_word: quad(unstructured),
        stamp_nanos: quad(unstructured),
        kind: word(unstructured),
        generation: word(unstructured),
        sequence: word(unstructured),
        changes: word(unstructured),
        reject_offset: word(unstructured),
        receive_posted: word(unstructured),
        domain: byte(unstructured),
        state: byte(unstructured),
        detail: byte(unstructured),
        operand_count: byte(unstructured),
        signalled: byte(unstructured),
        change: byte(unstructured),
        object: byte(unstructured),
        field: byte(unstructured),
        outcome: byte(unstructured),
        reason: byte(unstructured),
        stamp_kind: byte(unstructured),
        _pad: bytes(unstructured),
        cause: text(unstructured),
        key: text(unstructured),
        from: value(unstructured),
        to: value(unstructured),
    }
}

/// One text image: its storage, its length byte and its padding, in that order.
fn text<const N: usize>(unstructured: &mut Unstructured<'_>) -> TextImage<N> {
    TextImage {
        bytes: bytes(unstructured),
        len: byte(unstructured),
        _pad: bytes(unstructured),
    }
}

/// One value image, on [`text`]'s terms.
fn value(unstructured: &mut Unstructured<'_>) -> ValueImage {
    ValueImage {
        number: word(unstructured),
        kind: byte(unstructured),
        octets: bytes(unstructured),
        _pad: byte(unstructured),
        id: text(unstructured),
    }
}

/// The next region quadword, zero once the input is spent — which is what an
/// unwritten part of a freshly mapped region holds.
fn quad(unstructured: &mut Unstructured<'_>) -> u64 {
    u64::arbitrary(unstructured).unwrap_or(0)
}

/// The next region word; see [`quad`].
fn word(unstructured: &mut Unstructured<'_>) -> u32 {
    crate::any_u32(unstructured)
}

/// The next region byte; see [`quad`].
fn byte(unstructured: &mut Unstructured<'_>) -> u8 {
    u8::arbitrary(unstructured).unwrap_or(0)
}

/// The next `N` region bytes; see [`quad`].
fn bytes<const N: usize>(unstructured: &mut Unstructured<'_>) -> [u8; N] {
    let mut out = [0u8; N];
    for slot in &mut out {
        *slot = byte(unstructured);
    }
    out
}

/// Serialise a record back into the region bytes [`record_from_region`] reads,
/// so a seed can be authored as the record it stands for.
///
/// Only the seed builders need this, but it lives beside the reader it is the
/// inverse of: a field added to one and not the other would put a seed's
/// remaining fields one position out, and `the_region_round_trips_through_its_own_seed_encoding`
/// is what fails when it does.
#[cfg(test)]
pub(crate) fn region_from_record(record: &LogRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECORD_BYTES);
    out.extend_from_slice(&record.features.to_le_bytes());
    for operand in record.operands {
        out.extend_from_slice(&operand.to_le_bytes());
    }
    out.extend_from_slice(&record.tsc_hz.to_le_bytes());
    out.extend_from_slice(&record.unix_nanos.to_le_bytes());
    out.extend_from_slice(&record.frames.to_le_bytes());
    out.extend_from_slice(&record.frame_bytes.to_le_bytes());
    out.extend_from_slice(&record.capacity_sectors.to_le_bytes());
    out.extend_from_slice(&record.leading_word.to_le_bytes());
    out.extend_from_slice(&record.stamp_nanos.to_le_bytes());
    for word in [
        record.kind,
        record.generation,
        record.sequence,
        record.changes,
        record.reject_offset,
        record.receive_posted,
    ] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.extend_from_slice(&[
        record.domain,
        record.state,
        record.detail,
        record.operand_count,
        record.signalled,
        record.change,
        record.object,
        record.field,
        record.outcome,
        record.reason,
        record.stamp_kind,
    ]);
    out.extend_from_slice(&record._pad);
    push_text(&mut out, &record.cause);
    push_text(&mut out, &record.key);
    push_value(&mut out, &record.from);
    push_value(&mut out, &record.to);
    out
}

#[cfg(test)]
fn push_text<const N: usize>(out: &mut Vec<u8>, text: &TextImage<N>) {
    out.extend_from_slice(&text.bytes);
    out.push(text.len);
    out.extend_from_slice(&text._pad);
}

#[cfg(test)]
fn push_value(out: &mut Vec<u8>, value: &ValueImage) {
    out.extend_from_slice(&value.number.to_le_bytes());
    out.push(value.kind);
    out.extend_from_slice(&value.octets);
    out.push(value._pad);
    push_text(out, &value.id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// The corpus directory these seeds live in.
    const TARGET: &str = "log_record";

    /// The committed seed of that name, so a demonstration and the corpus entry
    /// that preserves it cannot drift apart.
    fn seed(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(TARGET)
            .join(name);
        fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    /// A text image holding `value`, with the length the value really has.
    fn text_of<const N: usize>(value: &[u8]) -> TextImage<N> {
        let mut image = TextImage {
            bytes: [0; N],
            len: u8::try_from(value.len()).expect("a fixture text fits a length byte"),
            _pad: [0; 3],
        };
        image.bytes[..value.len()].copy_from_slice(value);
        image
    }

    /// A value slot carrying a number under the kind that reads one.
    fn number_value(kind: u8, number: u32) -> ValueImage {
        ValueImage {
            number,
            kind,
            ..ValueImage::ZERO
        }
    }

    /// A `Domain` refusal record every rule admits: the shape that carries the
    /// most fields, so a seed built from it exercises the cause text, the
    /// operand count and the boolean at once.
    fn domain_record() -> LogRecord {
        LogRecord {
            operands: [0x1af4, 0x1000],
            kind: KIND_DOMAIN,
            domain: 1,
            state: 1,
            detail: DETAIL_REFUSAL,
            operand_count: 2,
            signalled: 0,
            cause: text_of(b"not-virtio-net"),
            ..LogRecord::ZERO
        }
    }

    /// A `ConfigChange` record every rule admits.
    fn config_change_record() -> LogRecord {
        LogRecord {
            kind: KIND_CONFIG_CHANGE,
            generation: 4,
            sequence: 2,
            change: 2,
            object: 0,
            key: text_of(b"wan"),
            field: 4,
            from: number_value(VALUE_PREFIX_LENGTH, 24),
            to: number_value(VALUE_PREFIX_LENGTH, 25),
            ..LogRecord::ZERO
        }
    }

    /// A `Domain` record carrying a measured clock, which every rule admits.
    fn established_record() -> LogRecord {
        LogRecord {
            detail: DETAIL_ESTABLISHED,
            tsc_hz: 2_999_998_000,
            unix_nanos: 1_785_443_220_123_456_789,
            ..domain_record()
        }
    }

    /// A `ConfigGeneration` record every rule admits.
    fn config_generation_record() -> LogRecord {
        LogRecord {
            kind: KIND_CONFIG_GENERATION,
            generation: 7,
            changes: 3,
            outcome: 0,
            ..LogRecord::ZERO
        }
    }

    /// A `ConfigRejected` record every rule admits.
    fn config_rejected_record() -> LogRecord {
        LogRecord {
            kind: KIND_CONFIG_REJECTED,
            generation: 2,
            reject_offset: 38,
            reason: 1,
            ..LogRecord::ZERO
        }
    }

    /// Every committed seed, as the record or the raw bytes it stands for.
    ///
    /// One list so a seed cannot be committed without a demonstration that says
    /// what it is, and a demonstration cannot be written without a seed that
    /// preserves it for a cold fuzz run.
    fn demonstrations() -> Vec<(&'static str, Vec<u8>)> {
        let mut seeds: Vec<(&'static str, Vec<u8>)> = vec![
            // A zeroed region is already a decodable record — the state a
            // reader meets before a writing domain has published anything.
            ("zeroed_region", region_from_record(&LogRecord::ZERO)),
            ("valid_domain_refusal", region_from_record(&domain_record())),
            (
                "valid_config_change",
                region_from_record(&config_change_record()),
            ),
            (
                "valid_config_generation",
                region_from_record(&config_generation_record()),
            ),
            (
                "valid_config_rejected",
                region_from_record(&config_rejected_record()),
            ),
            // The console-safety cases, committed rather than left to the
            // fuzzer to rediscover: a key holding the escape sequence that
            // clears a terminal, and a cause holding a newline that would
            // forge a second console line out of one record.
            (
                "key_holds_an_escape_sequence",
                region_from_record(&LogRecord {
                    key: text_of(b"\x1b[2Jwan"),
                    ..config_change_record()
                }),
            ),
            (
                "cause_holds_a_newline",
                region_from_record(&LogRecord {
                    cause: text_of(b"lfw-pd\ndomain-forwarder"),
                    ..domain_record()
                }),
            ),
            // A length naming storage the record does not carry.
            (
                "key_length_past_its_storage",
                region_from_record(&LogRecord {
                    key: TextImage {
                        len: u8::try_from(LOG_IDENTIFIER_BYTES + 1).expect("fits a byte"),
                        ..text_of(b"wan")
                    },
                    ..config_change_record()
                }),
            ),
            // The measured clock, in both of the shapes its own field decides:
            // a frequency and an instant the ABI carries, and the zero
            // frequency that is the only thing this detail can be refused for.
            // Committed rather than left to be rediscovered, for the reason the
            // two above are: a zero drawn over `u64` never happens.
            (
                "valid_domain_established",
                region_from_record(&established_record()),
            ),
            (
                "established_frequency_zero",
                region_from_record(&LogRecord {
                    tsc_hz: 0,
                    ..established_record()
                }),
            ),
            // The management port's counts, which no rule refuses — so the
            // seed is here for the render path rather than for a refusal, and
            // for the same reason the two above are: a pair of interesting
            // `u64`s is not something a uniform draw produces.
            (
                "valid_domain_received",
                region_from_record(&LogRecord {
                    detail: DETAIL_RECEIVED,
                    frames: 4,
                    frame_bytes: 352,
                    ..domain_record()
                }),
            ),
            // Every byte the writer could set, set.
            ("every_byte_set", vec![0xFF; RECORD_BYTES]),
        ];
        seeds.extend(vocabulary_boundary_seeds());
        seeds
    }

    /// Each closed vocabulary at its last admissible token and one past it.
    ///
    /// Both halves matter and for opposite reasons: the token at the boundary
    /// is the one a check that used `>` instead of `>=` would wrongly refuse,
    /// and the one past it is what a check that lost its bound altogether would
    /// wrongly accept. A seed for only one of the two would leave the other
    /// direction of the same off-by-one uncovered.
    fn vocabulary_boundary_seeds() -> Vec<(&'static str, Vec<u8>)> {
        let mut seeds = Vec::new();
        let mut pair = |name_at: &'static str,
                        name_past: &'static str,
                        count: u8,
                        build: &dyn Fn(u8) -> LogRecord| {
            seeds.push((name_at, region_from_record(&build(count - 1))));
            seeds.push((name_past, region_from_record(&build(count))));
        };
        pair(
            "domain_at_its_last_token",
            "domain_one_past_its_last_token",
            LOG_DOMAIN_COUNT,
            &|token| LogRecord {
                domain: token,
                ..domain_record()
            },
        );
        pair(
            "state_at_its_last_token",
            "state_one_past_its_last_token",
            LOG_DOMAIN_STATE_COUNT,
            &|token| LogRecord {
                state: token,
                ..domain_record()
            },
        );
        pair(
            "change_at_its_last_token",
            "change_one_past_its_last_token",
            LOG_CHANGE_KIND_COUNT,
            &|token| LogRecord {
                change: token,
                ..config_change_record()
            },
        );
        pair(
            "object_at_its_last_token",
            "object_one_past_its_last_token",
            LOG_OBJECT_KIND_COUNT,
            &|token| LogRecord {
                object: token,
                ..config_change_record()
            },
        );
        pair(
            "field_at_its_last_token",
            "field_one_past_its_last_token",
            LOG_FIELD_COUNT,
            &|token| LogRecord {
                field: token,
                ..config_change_record()
            },
        );
        pair(
            "outcome_at_its_last_token",
            "outcome_one_past_its_last_token",
            LOG_GENERATION_OUTCOME_COUNT,
            &|token| LogRecord {
                outcome: token,
                ..config_generation_record()
            },
        );
        pair(
            "reason_at_its_last_token",
            "reason_one_past_its_last_token",
            LOG_REJECT_REASON_COUNT,
            &|token| LogRecord {
                reason: token,
                ..config_rejected_record()
            },
        );
        seeds
    }

    /// Each demonstration is committed as the seed of the same name, byte for
    /// byte, so a cold fuzz run starts from the shapes above and an edit that
    /// changed the region encoding could not leave the corpus silently meaning
    /// something else.
    /// Rewrite every committed seed from the demonstration of the same name.
    ///
    /// Ignored by default and run by hand — `cargo test --manifest-path
    /// fuzz/Cargo.toml -- --ignored rewrite_the_committed_seeds` — after a
    /// deliberate change to the record ABI, which shifts every field a seed's
    /// byte image places. The test below is what holds the corpus to the
    /// demonstrations afterwards, so this is a regeneration step and never a
    /// substitute for it.
    #[test]
    #[ignore = "regenerates the committed corpus; run by hand after an ABI change"]
    fn rewrite_the_committed_seeds() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(TARGET);
        for (name, built) in demonstrations() {
            fs::write(dir.join(name), &built).expect("write the seed");
        }
    }

    #[test]
    fn every_demonstration_is_the_committed_seed_of_its_name() {
        for (name, built) in demonstrations() {
            assert_eq!(
                built.len(),
                RECORD_BYTES,
                "seed {name} is not one record's worth of region"
            );
            assert_eq!(
                seed(name),
                built,
                "seed {name} is not the record it stands for"
            );
        }
    }

    /// The seed encoding and the region reader are inverses, so a seed authored
    /// as a record is read back as that record. Without this a field added to
    /// one and not the other would shift every later field of every seed and
    /// the corpus would go on passing while meaning something else.
    #[test]
    fn the_region_round_trips_through_its_own_seed_encoding() {
        for (name, bytes) in demonstrations() {
            let record = record_from_region(&bytes);
            assert_eq!(
                region_from_record(&record),
                bytes,
                "seed {name} did not survive the region encoding"
            );
        }
    }

    /// The four shapes are accepted, decode, and render into a printable line.
    #[test]
    fn every_valid_shape_is_accepted_and_reaches_a_console_line() {
        for record in [
            LogRecord::ZERO,
            domain_record(),
            config_change_record(),
            config_generation_record(),
            config_rejected_record(),
        ] {
            let checked = record.check().expect("the fixture is a well-formed record");
            let (at, event) = Event::<Cause>::decode(&checked).expect("a checked record decodes");
            let line = assert_console_line_is_printable(at, &event);
            assert!(line.starts_with(b"LFW-"));
        }
    }

    /// The seed that carries the whole reason this harness chains three crates:
    /// a key holding the escape sequence that clears a terminal is refused by
    /// the alphabet, at the offset the escape sits at.
    #[test]
    fn an_escape_sequence_in_a_key_is_refused_at_its_own_offset() {
        let record = record_from_region(&seed("key_holds_an_escape_sequence"));
        assert_eq!(
            record.check(),
            Err(LogRecordError::TextNotInAlphabet {
                text: LogText::Key,
                offset: 0,
            })
        );
    }

    /// As above, for the newline that would forge a second console line out of
    /// one record. The refusal names the position of the newline within the
    /// cause and never the byte, which must not reach a console.
    #[test]
    fn a_newline_in_a_cause_is_refused_at_its_own_offset() {
        let record = record_from_region(&seed("cause_holds_a_newline"));
        assert_eq!(
            record.check(),
            Err(LogRecordError::TextNotInAlphabet {
                text: LogText::Cause,
                offset: 6,
            })
        );
    }

    /// A length past the storage is refused for being one, with the length that
    /// made it one — before any byte of the text is consulted.
    #[test]
    fn a_length_past_the_storage_is_refused_with_the_length_it_named() {
        let record = record_from_region(&seed("key_length_past_its_storage"));
        assert_eq!(
            record.check(),
            Err(LogRecordError::TextTooLong {
                text: LogText::Key,
                len: u8::try_from(LOG_IDENTIFIER_BYTES + 1).expect("fits a byte"),
            })
        );
    }

    /// Each vocabulary's last token is admitted and the next one is not. This
    /// is the positive half of the boundary claim: an assertion that the token
    /// past the end is refused proves nothing on its own, because a check that
    /// refused *everything* would satisfy it.
    #[test]
    fn every_vocabulary_admits_its_last_token_and_refuses_the_next() {
        for (name, bytes) in vocabulary_boundary_seeds() {
            let outcome = record_from_region(&bytes).check();
            if name.ends_with("_at_its_last_token") {
                assert!(
                    outcome.is_ok(),
                    "{name} was refused: {:?}",
                    outcome.expect_err("a refusal carries its cause")
                );
            } else {
                assert!(outcome.is_err(), "{name} was accepted");
            }
        }
    }

    /// The all-bytes-set record: refused, and refused for the field the ABI
    /// contract rules on first.
    #[test]
    fn a_record_of_every_byte_set_is_refused_for_its_stamp() {
        // The stamp is ruled on ahead of the kind, so the all-bytes-set image
        // never reaches the `u32::MAX` kind behind it. Both refusals are
        // asserted, which is what makes the *order* of the two checks a
        // property rather than an accident.
        let record = record_from_region(&seed("every_byte_set"));
        assert_eq!(
            record.check(),
            Err(LogRecordError::StampKindUnknown { kind: u8::MAX })
        );
        assert_eq!(
            LogRecord {
                stamp_kind: STAMP_UNSYNCHRONIZED,
                ..record
            }
            .check(),
            Err(LogRecordError::KindUnknown { kind: u32::MAX })
        );
    }

    /// The derivations are additive: whatever else one input is checked as, the
    /// unmodified region is always among them, so the adversary's full
    /// authority is exercised on every input rather than only on the ones the
    /// narrowing happens to leave alone.
    #[test]
    fn the_unmodified_region_is_always_among_the_records_checked() {
        for (name, bytes) in demonstrations() {
            let derived = derivations(&bytes);
            assert_eq!(
                derived[0],
                record_from_region(&bytes),
                "the first derivation of {name} is not the region itself"
            );
        }
    }

    /// The narrowing reaches past the discriminant it folds: over the committed
    /// seeds and a sweep of synthetic regions, every one of the four record
    /// kinds is checked and at least one record is accepted. A fold that
    /// produced only refusals would leave the decode and render path — where
    /// the printable-line property lives — permanently unreached, and nothing else here
    /// would say so.
    #[test]
    fn the_narrowing_reaches_every_kind_and_accepts_some_of_them() {
        let mut kinds = [false; KIND_COUNT as usize];
        let mut accepted = 0usize;
        let mut inputs: Vec<Vec<u8>> = demonstrations().into_iter().map(|(_, seed)| seed).collect();
        for stamp in 0..512u32 {
            // A cheap spread rather than a random one: the point is to walk the
            // region bytes through many shapes deterministically, so a failure
            // here reproduces.
            inputs.push(
                (0..RECORD_BYTES)
                    .map(|offset| {
                        (stamp
                            .wrapping_mul(0x9E37_79B9)
                            .wrapping_add(offset as u32)
                            .rotate_left(offset as u32 % 32)
                            & 0xFF) as u8
                    })
                    .collect(),
            );
        }
        for input in &inputs {
            for record in derivations(input) {
                if let Some(seen) = kinds.get_mut(record.kind as usize) {
                    *seen = true;
                }
                if record.check().is_ok() {
                    accepted += 1;
                }
            }
            // The harness itself must survive every one of them.
            log_record_harness(input);
        }
        assert!(
            kinds.iter().all(|seen| *seen),
            "the narrowing never produced some record kind: {kinds:?}"
        );
        assert!(accepted > 0, "the narrowing accepted no record at all");
    }
}
