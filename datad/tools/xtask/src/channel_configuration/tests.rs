use super::*;

/// The result grammar this module reads is `pd_runtime::configuration`'s, so the
/// two are held together here: a field renamed there and not here would leave a
/// scenario reading `None` and reporting "names no generation" for a line that
/// named one.
#[test]
fn the_result_grammar_is_read_field_by_field() {
    let staged = "generation=2 outcome=staged changes=0";
    assert_eq!(field(staged, "generation"), Some(2));
    assert_eq!(token(staged, "outcome").as_deref(), Some("staged"));
    assert_eq!(field(staged, "changes"), Some(0));
    assert_eq!(token(staged, "rejected"), None);

    let refused = "generation=1 outcome=refused rejected=malformed offset=48";
    assert_eq!(field(refused, "generation"), Some(1));
    assert_eq!(token(refused, "outcome").as_deref(), Some("refused"));
    assert_eq!(token(refused, "rejected").as_deref(), Some("malformed"));
    assert_eq!(field(refused, "offset"), Some(48));

    // A field that is not there, and one whose value is not a number: both answer
    // `None` rather than a wrong number, which is what makes the verdict above
    // report the line rather than a plausible value read out of it.
    assert_eq!(field("generation=x outcome=staged", "generation"), None);
    assert_eq!(token("outcome=staged", "generation"), None);
    assert_eq!(token("", "generation"), None);
}

/// The two outcome tokens this transaction turns on are the console's own, so a
/// vocabulary renamed under this module is a compile-time fact rather than a
/// scenario that stops recognising an answer it is given.
#[test]
fn the_outcome_vocabulary_is_the_consoles_own() {
    assert_eq!(lfw_log::GenerationOutcome::Staged.name(), "staged");
    assert_eq!(REFUSED, "refused");
    assert_eq!(APPLIED, "applied");
}

/// Every reason the console vocabulary carries is one this module accepts in a
/// `rejected=` field, and nothing else is.
#[test]
fn the_reject_vocabulary_is_the_consoles_own() {
    for reason in lfw_log::RejectReason::ALL {
        let line = format!("generation=1 outcome=refused rejected={reason} offset=0");
        assert_eq!(token(&line, "rejected").as_deref(), Some(reason.name()));
    }
    assert!(
        !lfw_log::RejectReason::ALL
            .iter()
            .any(|reason| reason.name() == "not-a-reason")
    );
}

/// The two documents this transaction refuses are refused at the two different
/// stages it tells apart, which is what makes the pair one statement rather than
/// the same one twice.
#[test]
fn the_two_refused_documents_are_refused_at_the_two_different_stages() {
    assert!(matches!(
        config::load(MALFORMED),
        Err(config::ConfigError::Document(_))
    ));
    assert!(matches!(
        config::load(REFUSED_BY_RULE),
        Err(config::ConfigError::Semantic(_))
    ));
    // And they name different reasons, so a verdict about one cannot be read as a
    // verdict about the other.
    let reader = match config::load(MALFORMED) {
        Err(config::ConfigError::Document(fault)) => fault.reason(),
        _ => unreachable!("held above"),
    };
    let rule = match config::load(REFUSED_BY_RULE) {
        Err(config::ConfigError::Semantic(fault)) => fault.reason(),
        _ => unreachable!("held above"),
    };
    assert_ne!(reader.name(), rule.name());
}

/// Every document a scenario pushes is one this appliance accepts, so a refusal
/// seen on a booted node is the node's finding and never the harness's.
#[test]
fn every_pushed_document_is_one_this_appliance_accepts() {
    for document in [SUBMITTED, NARROWED, RELATED] {
        assert!(config::load(document).is_ok());
    }
}

/// The generation a scenario waits for is the **forwarding** domain's, read out of
/// a capture's real shape: one commit puts two `outcome=applied` records on the
/// console and the configuration domain writes its own first, so a reader that
/// took either would stop waiting before the dataplane had switched.
#[test]
fn the_generation_read_is_the_one_the_dataplane_switched_to() {
    /// One record as the console writes it, so a case below reads as the line an
    /// operator would see rather than as an escape sequence.
    fn record(fields: &str) -> String {
        format!("LFW-CFG time=unsynchronized {fields}\r\n")
    }

    // The boot: the forwarder's fail-closed record, then generation 1 committed by
    // the publisher and taken up by the forwarder.
    let mut capture = record("generation=0 outcome=applied changes=0");
    capture.push_str(&record("generation=1 outcome=applied changes=16"));
    capture.push_str(&record("generation=1 outcome=applied changes=0"));
    assert_eq!(switched_generation(capture.as_bytes()), 1);

    // The commit: the publisher has committed generation 2 and the forwarder
    // has not switched yet. This is the window the wait exists for, and reading
    // the publisher's record here is exactly the race.
    capture.push_str(&record("generation=2 outcome=applied changes=2"));
    assert_eq!(switched_generation(capture.as_bytes()), 1);

    // A record still being written is not one either: the capture is read while
    // the guest is running, so its last line is routinely half a record.
    let torn = format!("{capture}LFW-CFG time=unsynchronized generation=2 outcome=applied chan");
    assert_eq!(switched_generation(torn.as_bytes()), 1);

    // And the record that closes the window.
    capture.push_str(&record("generation=2 outcome=applied changes=0"));
    assert_eq!(switched_generation(capture.as_bytes()), 2);

    // A refusal names a generation too and is not a switch: a reader matching on
    // the number alone would take a refused document's generation for one that is
    // carrying traffic.
    capture.push_str(&record("generation=3 rejected=doctype offset=38"));
    assert_eq!(switched_generation(capture.as_bytes()), 2);

    // A capture with nothing on this channel is the fail-closed empty table, which
    // is what the appliance runs until it says otherwise.
    assert_eq!(switched_generation(b"Bootstrapping kernel\r\n"), 0);
    assert_eq!(switched_generation(b""), 0);
}

/// The two documents this scenario is stated between: the shipped policy and the
/// swap. Held here because the whole contract rests on them differing in the
/// action alone — a swap that also moved an address would prove a reconfiguration
/// happened and not that the *policy* is what changed the verdict.
#[test]
fn the_pushed_document_differs_from_the_shipped_one_in_the_actions_alone() {
    const SHIPPED: &str = include_str!("../../../../systems/qemu-x86_64/configuration.xml");

    let shipped = config::load(SHIPPED.as_bytes()).expect("the shipped document");
    let swapped = config::load(SUBMITTED).expect("the pushed document");
    assert!(
        !shipped.has_same_content(&swapped),
        "the pushed document is the running one, so nothing could reverse"
    );

    // Same interfaces and neighbours, so no address, MAC or port moved.
    assert_eq!(shipped.interface_count(), swapped.interface_count());
    for (before, after) in shipped.interfaces().zip(swapped.interfaces()) {
        assert_eq!(before, after);
    }
    for (before, after) in shipped.neighbours().zip(swapped.neighbours()) {
        assert_eq!(before, after);
    }
    assert_eq!(shipped.management(), swapped.management());

    // Same rules under the same ids, in the same order, differing in the action of
    // each and in nothing else.
    assert_eq!(shipped.rule_count(), 2);
    assert_eq!(swapped.rule_count(), 2);
    for (before, after) in shipped.rules().zip(swapped.rules()) {
        assert_eq!(before.id, after.id);
        assert_eq!(before.destination_port, after.destination_port);
        assert_eq!(before.protocol, after.protocol);
        assert_ne!(
            before.action, after.action,
            "rule {} takes the same action in both documents",
            before.id
        );
    }
}
