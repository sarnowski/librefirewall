use super::*;
use proptest::prelude::*;
use std::string::String;

/// Render one result line as the text it is, which is what every assertion below
/// is about.
fn line(
    generation: u32,
    outcome: Outcome,
    changes: u32,
    rejection: Option<(RejectReason, u32)>,
) -> String {
    let mut out = [0u8; MAX_ANSWER_LEN];
    let len = write_result_line(&mut out, generation, outcome, changes, rejection);
    assert!(len <= MAX_ANSWER_LEN, "{len} bytes");
    core::str::from_utf8(out.get(..len).expect("in range"))
        .expect("ASCII")
        .into()
}

/// Every outcome the grammar can name, and the two shapes a line takes.
///
/// The vocabulary is the console's: `generation=`, `outcome=`, `changes=`,
/// `rejected=` and `offset=` are the fields `LFW-CFG` carries, so an operator
/// reading a result in the channel's own record and one in the serial log reads
/// one thing.
#[test]
fn every_outcome_names_itself_in_the_consoles_own_words() {
    let cases: [(Outcome, &str); 6] = [
        (Outcome::Applied, "generation=7 outcome=applied changes=12"),
        (Outcome::Refused, "generation=7 outcome=refused changes=12"),
        (
            Outcome::Unchanged,
            "generation=7 outcome=unchanged changes=12",
        ),
        (Outcome::Staged, "generation=7 outcome=staged changes=12"),
        (
            Outcome::Confirmed,
            "generation=7 outcome=confirmed changes=12",
        ),
        (
            Outcome::Reverted,
            "generation=7 outcome=reverted changes=12",
        ),
    ];
    for (outcome, owed) in cases {
        assert_eq!(line(7, outcome, 12, None), owed, "{outcome:?}");
    }
}

/// A rejection replaces the change count with the reason and where it was found,
/// which is the whole of the second shape.
#[test]
fn a_rejection_names_its_reason_and_where_it_was_found() {
    assert_eq!(
        line(7, Outcome::Refused, 0, Some((RejectReason::Doctype, 21))),
        "generation=7 outcome=refused rejected=doctype offset=21"
    );
    assert_eq!(
        line(
            0,
            Outcome::Refused,
            0,
            Some((RejectReason::RenderingTooLarge, 0))
        ),
        "generation=0 outcome=refused rejected=rendering-too-large offset=0"
    );
}

/// The reason word is peer-written, so a value naming no reason is rendered as a
/// token an operator can look up rather than as a number they cannot.
#[test]
fn a_reason_naming_nothing_is_rendered_as_a_reason_that_exists() {
    for bits in [RejectReason::ALL.len() as u32, u32::MAX, 1_000_000] {
        assert_eq!(reason_of(bits), RejectReason::Malformed);
        assert_eq!(reject_reason_of(bits), RejectReason::Malformed);
    }
    for (index, reason) in RejectReason::ALL.iter().enumerate() {
        assert_eq!(reason_of(index as u32), *reason);
        assert_eq!(reject_reason_of(index as u32), *reason);
    }
}

/// The line's bound is derived from the vocabulary, so the longest line the
/// grammar can produce fits — and a reason appended to the vocabulary moves the
/// number rather than truncating a line into a different outcome.
#[test]
fn the_longest_line_the_grammar_can_produce_fits_its_bound() {
    let longest = RejectReason::ALL
        .iter()
        .map(|reason| {
            let mut out = [0u8; MAX_ANSWER_LEN];
            write_result_line(
                &mut out,
                u32::MAX,
                Outcome::Refused,
                0,
                Some((*reason, u32::MAX)),
            )
        })
        .max()
        .expect("the vocabulary is not empty");
    assert!(longest <= MAX_ANSWER_LEN, "{longest} bytes");
    // And the bound is not wildly loose: it is the grammar's own worst case plus
    // the field names and the line ending a caller may add, so a reader can tell
    // it was derived.
    assert!(
        MAX_ANSWER_LEN - longest < 16,
        "{MAX_ANSWER_LEN} vs {longest}"
    );

    assert_eq!(
        line(u32::MAX, Outcome::Applied, u32::MAX, None),
        "generation=4294967295 outcome=applied changes=4294967295"
    );
}

proptest! {
    /// Whatever the numbers, a result is one line of the grammar: it fits, it
    /// carries no line ending of its own, and every byte of it is one a console
    /// line could carry.
    #[test]
    fn every_result_is_one_renderable_line(
        generation in any::<u32>(),
        changes in any::<u32>(),
        detail in any::<u32>(),
        reason in 0usize..RejectReason::ALL.len(),
        rejected in any::<bool>(),
    ) {
        let mut out = [0u8; MAX_ANSWER_LEN];
        let rejection = rejected
            .then(|| (RejectReason::ALL[reason], detail));
        let len = write_result_line(&mut out, generation, Outcome::Refused, changes, rejection);
        prop_assert!(len <= MAX_ANSWER_LEN);
        let rendered = out.get(..len).expect("in range");
        prop_assert!(!rendered.contains(&b'\n'));
        prop_assert!(
            rendered.iter().all(|byte| byte.is_ascii_graphic() || *byte == b' '),
            "{rendered:?}"
        );
        let text = core::str::from_utf8(rendered).expect("ASCII");
        prop_assert!(text.starts_with("generation="));
        prop_assert!(text.contains(" outcome=refused"));
        prop_assert_eq!(text.contains(" rejected="), rejected);
    }

    /// A reason word out of the reply region names a reason this build holds, or
    /// the one an unreadable answer amounts to — for every `u32` a peer can
    /// write, and never a panic.
    #[test]
    fn any_reason_word_a_peer_can_write_names_a_reason(bits in any::<u32>()) {
        let reason = reject_reason_of(bits);
        prop_assert!(RejectReason::ALL.contains(&reason));
        let rendered = line(0, Outcome::Refused, 0, Some((reason, bits)));
        prop_assert!(rendered.len() <= MAX_ANSWER_LEN);
    }
}
