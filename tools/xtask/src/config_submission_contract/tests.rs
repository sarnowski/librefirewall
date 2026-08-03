use super::*;

/// The answer grammar this module reads is `pd_runtime::configuration`'s, so the
/// two are held together here: a field renamed there and not here would leave a
/// scenario reading `None` and reporting "names no generation" for an answer that
/// named one.
#[test]
fn the_answer_grammar_is_read_field_by_field() {
    let applied = "generation=2 outcome=applied changes=4";
    assert_eq!(field(applied, "generation"), Some(2));
    assert_eq!(token(applied, "outcome").as_deref(), Some("applied"));
    assert_eq!(field(applied, "changes"), Some(4));
    assert_eq!(token(applied, "rejected"), None);

    let refused = "generation=2 outcome=refused rejected=malformed offset=48";
    assert_eq!(field(refused, "generation"), Some(2));
    assert_eq!(token(refused, "outcome").as_deref(), Some("refused"));
    assert_eq!(token(refused, "rejected").as_deref(), Some("malformed"));
    assert_eq!(field(refused, "offset"), Some(48));

    // A field that is not there, and one whose value is not a number: both answer
    // `None` rather than a wrong number, which is what makes the verdict above
    // report the line rather than a plausible value read out of it.
    assert_eq!(field("generation=x outcome=applied", "generation"), None);
    assert_eq!(token("outcome=applied", "generation"), None);
    assert_eq!(token("", "generation"), None);
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

/// The generation a scenario waits for is the **forwarding** domain's, read out of
/// a real exposition's shape: the configuration domain publishes the same family
/// and moves first, so a reader that took the first match would stop waiting
/// before the dataplane had switched.
#[test]
fn the_generation_read_is_the_one_the_dataplane_decides_under() {
    let exposition = concat!(
        "# HELP librefirewall_configuration_generation The configuration generation.\n",
        "# TYPE librefirewall_configuration_generation gauge\n",
        "librefirewall_configuration_generation{domain=\"config\"} 2\n",
        "librefirewall_configuration_generation{domain=\"forwarder\"} 1\n",
        "librefirewall_configuration_generation{domain=\"management\"} 2\n",
    );
    assert_eq!(forwarder_generation(exposition), Some(1));

    let switched = exposition.replace("domain=\"forwarder\"} 1", "domain=\"forwarder\"} 2");
    assert_eq!(forwarder_generation(&switched), Some(2));

    // An exposition with no such series at all — a node that published nothing —
    // is absent rather than zero, and the caller treats it as not yet switched.
    assert_eq!(
        forwarder_generation("librefirewall_tcp_segments_total 4\n"),
        None
    );
    assert_eq!(forwarder_generation(""), None);
}

/// The two documents this scenario is stated between: the shipped policy and the
/// swap. Held here because the whole contract rests on them differing in the
/// action alone — a swap that also moved an address would prove a reconfiguration
/// happened and not that the *policy* is what changed the verdict.
#[test]
fn the_submitted_document_differs_from_the_shipped_one_in_the_actions_alone() {
    const SHIPPED: &str = include_str!("../../../../systems/qemu-x86_64/configuration.xml");
    const SWAPPED: &str = include_str!("../../scenarios/reconfiguration-swap.xml");

    let shipped = config::load(SHIPPED.as_bytes()).expect("the shipped document");
    let swapped = config::load(SWAPPED.as_bytes()).expect("the submitted document");
    assert!(
        !shipped.has_same_content(&swapped),
        "the submitted document is the running one, so nothing could reverse"
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

/// A body cut for a verdict is cut and marked, so a reader can tell a truncated
/// document from a short one.
#[test]
fn a_long_body_is_truncated_with_a_mark() {
    let short = "<configuration/>";
    assert_eq!(truncate(short), short);
    let long = "x".repeat(400);
    let cut = truncate(&long);
    assert!(cut.ends_with('…'));
    assert!(cut.len() < long.len());
}

/// The deciding domain's own counts are read off its own shard and matched on the
/// label the outcome carries: a reader that took the first family match would read
/// another domain's series, and one that ignored the label would read `applied` for
/// `refused`.
#[test]
fn the_submission_counts_are_read_per_outcome_and_per_domain() {
    let exposition = concat!(
        "# TYPE librefirewall_configuration_submissions_total counter\n",
        "librefirewall_configuration_submissions_total{domain=\"config\",outcome=\"applied\"} 2\n",
        "librefirewall_configuration_submissions_total{domain=\"config\",outcome=\"refused\"} 1\n",
        "librefirewall_configuration_submissions_total{domain=\"config\",outcome=\"unchanged\"} 0\n",
        "librefirewall_configuration_reads_total{domain=\"config\"} 2\n",
    );
    assert_eq!(counted(exposition, SUBMISSIONS, Some("applied")), Some(2));
    assert_eq!(counted(exposition, SUBMISSIONS, Some("refused")), Some(1));
    assert_eq!(counted(exposition, SUBMISSIONS, Some("unchanged")), Some(0));
    assert_eq!(counted(exposition, READS, None), Some(2));
    assert_eq!(counted(exposition, SUBMISSIONS, Some("nonesuch")), None);
    assert_eq!(counted("", READS, None), None);

    // A series published by another domain is not this one's, whatever the family.
    let foreign = "librefirewall_configuration_reads_total{domain=\"management\"} 9\n";
    assert_eq!(counted(foreign, READS, None), None);
}
