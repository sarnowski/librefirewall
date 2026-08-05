//! The comparison, exercised against synthetic pages and synthetic minting
//! sites.
//!
//! Each case perturbs exactly one side of one contract, so a test that fires
//! proves the direction it is named for. The two that matter most are the pair
//! at the top: a token added to the code and a token removed from the book are
//! the two shapes of drift this module exists to catch, and each must fail on
//! its own.

use super::*;

/// A minimal console chapter: the intro sentence, one domain heading and one
/// token table per domain, and the `rejected=` table read from the code so the
/// unrelated halves of the check stay quiet.
fn console_page(tokens: &[(&str, &[&str])]) -> String {
    let mut page = String::from(
        "# Console\n\n## `LFW-PD` refusal causes\n\nEvery `cause=` token \
                                 is listed below and the ",
    );
    let _ = write!(
        page,
        "{} tables together are the complete set: ",
        spell(tokens.len())
    );
    let mut first = true;
    for (domain, listed) in tokens {
        if !first {
            page.push_str(", ");
        }
        first = false;
        let _ = write!(page, "{} the `{domain}` domain raises", listed.len());
    }
    page.push_str(".\n");
    for (domain, listed) in tokens {
        let _ = write!(
            page,
            "\n**`{domain}`.** Its tokens.\n\n| group | tokens |\n|---|---|\n"
        );
        let cell = listed
            .iter()
            .map(|token| format!("`{token}` (a number)"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(page, "| everything | {cell} |");
    }
    page.push_str(&reject_table());
    page
}

/// The `rejected=` half, rendered from the appliance's own vocabulary so the
/// cause cases above are the only thing under test.
fn reject_table() -> String {
    let names: Vec<&str> = RejectReason::ALL.iter().map(|r| r.name()).collect();
    let cell = names
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "\n**Rejection.** `rejected=` is one of {} reasons:\n\n| group | reasons |\n|---|---|\n| \
         everything ({}) | {cell} |\n",
        names.len(),
        names.len()
    )
}

/// A synthetic literal map: one file per entry, holding the given literals.
fn minted(files: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
    files
        .iter()
        .map(|(path, literals)| {
            (
                (*path).to_owned(),
                literals.iter().map(|text| (*text).to_owned()).collect(),
            )
        })
        .collect()
}

/// The six domains' sites as they are declared, each holding one token, so a
/// case can add or remove exactly one thing.
fn sound_sites() -> Vec<(&'static str, &'static [&'static str])> {
    vec![
        ("crates/nic-driver-core/src/bringup.rs", &["not-virtio-net"]),
        ("pds/nic-driver/src/main.rs", &["receive-pool-dma-base"]),
        ("crates/blk/src/bringup.rs", &["not-virtio-blk"]),
        ("crates/blk/src/smoke.rs", &["block-probe-silent"]),
        ("pds/recorder/src/main.rs", &["staging-region-dma-base"]),
        ("pds/clock/src/main.rs", &["hpet-not-present"]),
        ("pds/management/src/main.rs", &["rdrand-exhausted"]),
        ("pds/hardware-probe/src/main.rs", &["aes-not-supported"]),
        ("pds/crypto/src/main.rs", &["rdrand-output-stuck"]),
        ("pds/crypto/src/delegate.rs", &["delegated-key-refused"]),
        ("pds/store/src/main.rs", &["store-medium-too-small"]),
        ("crates/store/src/identity.rs", &["stored-scalar-unusable"]),
        ("crates/log/src/event.rs", &["duplicate-port"]),
        ("crates/wire/src/lib.rs", &["source-port"]),
        ("crates/tcp/src/connection.rs", &["close-wait"]),
        ("crates/http/src/request.rs", &["content-length"]),
        ("crates/crypto/src/vectors.rs", &["cavp-shavs-0"]),
        ("crates/crypto/src/drbg.rs", &["librefirewall-drbg-seed-v1"]),
    ]
}

fn sound_console() -> String {
    console_page(&[
        ("nic-driver", &["not-virtio-net", "receive-pool-dma-base"]),
        ("clock", &["hpet-not-present"]),
        ("management", &["rdrand-exhausted"]),
        (
            "recorder",
            &[
                "not-virtio-blk",
                "block-probe-silent",
                "staging-region-dma-base",
            ],
        ),
        ("hardware-probe", &["aes-not-supported"]),
        ("crypto", &["rdrand-output-stuck", "delegated-key-refused"]),
        (
            "store",
            &["store-medium-too-small", "stored-scalar-unusable"],
        ),
    ])
}

fn cause_findings(sites: &[(&str, &[&str])], console: &str) -> Vec<String> {
    let literals = minted(sites);
    let mut findings = Vec::new();
    check_literal_sites(&literals, &mut findings);
    check_causes(&literals, console, &mut findings);
    check_reject_reasons(console, &mut findings);
    findings
}

#[test]
fn a_sound_pair_of_sides_reports_nothing() {
    let findings = cause_findings(&sound_sites(), &sound_console());
    assert!(findings.is_empty(), "{findings:#?}");
}

/// The first of the two shapes this module exists to catch.
#[test]
fn a_token_added_to_the_code_and_not_to_the_book_is_a_finding() {
    let mut sites = sound_sites();
    sites[4] = (
        "pds/recorder/src/main.rs",
        &["staging-region-dma-base", "recording-sink-unusable"],
    );
    let findings = cause_findings(&sites, &sound_console());
    let joined = findings.join("\n");
    assert!(
        joined.contains("cause token `recording-sink-unusable`"),
        "{joined}"
    );
    assert!(joined.contains("does not list it"), "{joined}");
    assert!(joined.contains("`recorder` domain"), "{joined}");
}

/// And the second: a listed token nothing emits, which is the same drift read
/// from the other end.
#[test]
fn a_token_removed_from_the_code_and_left_in_the_book_is_a_finding() {
    let mut sites = sound_sites();
    sites[5] = ("pds/clock/src/main.rs", &["hpet-not-enabled"]);
    let console = console_page(&[
        ("nic-driver", &["not-virtio-net", "receive-pool-dma-base"]),
        ("clock", &["hpet-not-present", "hpet-not-enabled"]),
        ("management", &["rdrand-exhausted"]),
        (
            "recorder",
            &[
                "not-virtio-blk",
                "block-probe-silent",
                "staging-region-dma-base",
            ],
        ),
    ]);
    let findings = cause_findings(&sites, &console);
    let joined = findings.join("\n");
    assert!(
        joined.contains("cause token `hpet-not-present`"),
        "{joined}"
    );
    assert!(
        joined.contains("no code in that domain emits it"),
        "{joined}"
    );
}

/// The same token under two domains is not drift: two device classes run one
/// handshake, so the comparison is per domain and a shared token must pass.
#[test]
fn a_token_two_domains_share_is_not_a_finding() {
    let mut sites = sound_sites();
    sites[0] = (
        "crates/nic-driver-core/src/bringup.rs",
        &["not-virtio-net", "queue-too-small"],
    );
    sites[2] = (
        "crates/blk/src/bringup.rs",
        &["not-virtio-blk", "queue-too-small"],
    );
    let console = console_page(&[
        (
            "nic-driver",
            &["not-virtio-net", "receive-pool-dma-base", "queue-too-small"],
        ),
        ("clock", &["hpet-not-present"]),
        ("management", &["rdrand-exhausted"]),
        (
            "recorder",
            &[
                "not-virtio-blk",
                "block-probe-silent",
                "staging-region-dma-base",
                "queue-too-small",
            ],
        ),
        ("hardware-probe", &["aes-not-supported"]),
        ("crypto", &["rdrand-output-stuck", "delegated-key-refused"]),
        (
            "store",
            &["store-medium-too-small", "stored-scalar-unusable"],
        ),
    ]);
    let findings = cause_findings(&sites, &console);
    assert!(findings.is_empty(), "{findings:#?}");
}

/// The completeness half: a file nobody attributed. Without it the code side is
/// only as exhaustive as the last person to remember this table.
#[test]
fn a_minting_file_no_row_attributes_is_a_finding() {
    let mut sites = sound_sites();
    sites.push(("pds/forwarder/src/main.rs", &["route-table-unusable"]));
    let findings = cause_findings(&sites, &sound_console());
    let joined = findings.join("\n");
    assert!(joined.contains("pds/forwarder/src/main.rs"), "{joined}");
    assert!(
        joined.contains("does not know which console vocabulary"),
        "{joined}"
    );
    assert!(joined.contains("route-table-unusable"), "{joined}");
}

/// And its mirror: a row that covers nothing, which is how a moved site leaves
/// a table claiming reach it no longer has.
#[test]
fn a_row_whose_file_mints_nothing_is_a_finding() {
    let sites: Vec<(&str, &[&str])> = sound_sites()
        .into_iter()
        .filter(|(path, _)| *path != "crates/blk/src/smoke.rs")
        .collect();
    let console = console_page(&[
        ("nic-driver", &["not-virtio-net", "receive-pool-dma-base"]),
        ("clock", &["hpet-not-present"]),
        ("management", &["rdrand-exhausted"]),
        ("recorder", &["not-virtio-blk", "staging-region-dma-base"]),
    ]);
    let findings = cause_findings(&sites, &console);
    let joined = findings.join("\n");
    assert!(joined.contains("crates/blk/src/smoke.rs"), "{joined}");
    assert!(joined.contains("covers nothing"), "{joined}");
}

/// The count the chapter states about itself, against the table it states it
/// about — the class of claim nothing could previously check.
#[test]
fn a_stated_per_domain_count_that_disagrees_with_its_own_table_is_a_finding() {
    let console =
        sound_console().replace("1 the `clock` domain raises", "9 the `clock` domain raises");
    let findings = cause_findings(&sound_sites(), &console);
    let joined = findings.join("\n");
    assert!(
        joined.contains("says \"9 the `clock` domain raises\""),
        "{joined}"
    );
    assert!(joined.contains("lists 1"), "{joined}");
}

#[test]
fn a_stated_table_count_that_disagrees_with_the_tables_present_is_a_finding() {
    let console = sound_console().replace(
        "seven tables together are the complete set",
        "eight tables together are the complete set",
    );
    let findings = cause_findings(&sound_sites(), &console);
    let joined = findings.join("\n");
    assert!(joined.contains("7 refusal-cause table(s)"), "{joined}");
    assert!(
        joined.contains("the seven tables together are the complete set"),
        "{joined}"
    );
}

#[test]
fn a_rejected_reason_the_book_omits_is_a_finding() {
    let dropped = RejectReason::ALL[0].name();
    let console = sound_console().replace(&format!("`{dropped}`, "), "");
    let findings = cause_findings(&sound_sites(), &console);
    let joined = findings.join("\n");
    assert!(
        joined.contains(&format!("rejected reason `{dropped}`")),
        "{joined}"
    );
    assert!(joined.contains("does not list it"), "{joined}");
}

#[test]
fn a_rejected_reason_the_code_does_not_carry_is_a_finding() {
    let first = RejectReason::ALL[0].name();
    let console = sound_console().replace(
        &format!("`{first}`,"),
        &format!("`{first}`, `invented-reason`,"),
    );
    let findings = cause_findings(&sound_sites(), &console);
    let joined = findings.join("\n");
    assert!(joined.contains("`invented-reason`"), "{joined}");
    assert!(joined.contains("no such variant"), "{joined}");
}

// ---------------------------------------------------------------------------
// The metrics half
// ---------------------------------------------------------------------------

/// The chapter as the catalogue itself would write it, which is the sound case
/// every perturbation below starts from.
fn metrics_page() -> String {
    let code = catalogued();
    let series: usize = SHARDS.iter().map(|shard| shard.series.len()).sum();
    let mut page = format!(
        "# Prometheus metrics\n\n{} families; the rest of the sentence. {series} counter and gauge \
         series from the {} shards.\n\n| Metric | Type | `domain` | Other labels | Meaning |\n\
         |---|---|---|---|---|\n",
        code.len(),
        spell(SHARD_COUNT)
    );
    for (name, family) in &code {
        let labels = if *name == INTERFACE_INFO.name {
            String::from("`interface`, `role`&nbsp;(`dataplane`)")
        } else if family.labels.is_empty() {
            String::from("—")
        } else {
            family
                .labels
                .iter()
                .map(|label| format!("`{label}`&nbsp;(`a`, `b`)"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let domains = family
            .domains
            .iter()
            .map(|domain| format!("`{domain}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            page,
            "| `{name}` | {} | {domains} | {labels} | What it means. |",
            family.kind
        );
    }
    page
}

fn metric_findings(page: &str) -> Vec<String> {
    let mut findings = Vec::new();
    check_metric_families(page, &mut findings);
    findings
}

#[test]
fn the_catalogue_rendered_as_the_chapter_reports_nothing() {
    let findings = metric_findings(&metrics_page());
    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn a_family_the_book_does_not_list_is_a_finding() {
    let page = metrics_page();
    let name = INTERFACE_INFO.name;
    let dropped: String = page
        .lines()
        .filter(|line| !line.contains(name))
        .collect::<Vec<_>>()
        .join("\n");
    let findings = metric_findings(&dropped);
    let joined = findings.join("\n");
    assert!(
        joined.contains(&format!("metric family `{name}`")),
        "{joined}"
    );
    assert!(joined.contains("does not list it"), "{joined}");
}

#[test]
fn a_family_the_book_invents_is_a_finding() {
    let page = metrics_page().replace(
        "|---|---|---|---|---|\n",
        "|---|---|---|---|---|\n| `librefirewall_invented_total` | counter | `forwarder` | — | \
         Nothing. |\n",
    );
    let findings = metric_findings(&page);
    let joined = findings.join("\n");
    assert!(
        joined.contains("`librefirewall_invented_total`"),
        "{joined}"
    );
    assert!(joined.contains("declares no such family"), "{joined}");
}

#[test]
fn a_family_typed_wrongly_is_a_finding() {
    let gauge = ALL_METRICS
        .iter()
        .find(|metric| matches!(metric.kind, lfw_metrics::Kind::Gauge))
        .expect("the catalogue carries a gauge");
    let page = metrics_page().replace(
        &format!("| `{}` | gauge |", gauge.name),
        &format!("| `{}` | counter |", gauge.name),
    );
    let findings = metric_findings(&page);
    let joined = findings.join("\n");
    assert!(
        joined.contains(&format!("metric family `{}`", gauge.name)),
        "{joined}"
    );
    assert!(joined.contains("declares it a gauge"), "{joined}");
}

#[test]
fn a_label_name_the_book_leaves_out_is_a_finding() {
    let code = catalogued();
    let (name, family) = code
        .iter()
        .find(|(name, family)| !family.labels.is_empty() && **name != INTERFACE_INFO.name)
        .expect("some family carries a label");
    let label = family.labels.iter().next().expect("one label");
    let page = metrics_page().replace(&format!("`{label}`&nbsp;(`a`, `b`)"), "—");
    let findings = metric_findings(&page);
    let joined = findings.join("\n");
    assert!(
        joined.contains(&format!("metric family `{name}`")),
        "{joined}"
    );
    assert!(joined.contains("label(s)"), "{joined}");
}

#[test]
fn a_domain_the_book_attributes_a_family_to_wrongly_is_a_finding() {
    let page = metrics_page().replace("| `forwarder` |", "| `forwarder`, `console` |");
    let findings = metric_findings(&page);
    let joined = findings.join("\n");
    assert!(joined.contains("published by the domain(s)"), "{joined}");
}

#[test]
fn a_stated_family_total_that_disagrees_with_the_catalogue_is_a_finding() {
    let code = catalogued();
    let page = metrics_page().replace(
        &format!("{} families;", code.len()),
        &format!("{} families;", code.len() + 1),
    );
    let findings = metric_findings(&page);
    let joined = findings.join("\n");
    assert!(
        joined.contains("families and `lfw_metrics::ALL_METRICS` declares"),
        "{joined}"
    );
}

#[test]
fn a_stated_series_total_that_disagrees_with_the_shards_is_a_finding() {
    let series: usize = SHARDS.iter().map(|shard| shard.series.len()).sum();
    let page = metrics_page().replace(
        &format!("{series} counter and gauge series"),
        &format!("{} counter and gauge series", series + 3),
    );
    let findings = metric_findings(&page);
    let joined = findings.join("\n");
    assert!(
        joined.contains("counter and gauge series from the"),
        "{joined}"
    );
}

// ---------------------------------------------------------------------------
// The Markdown reader
// ---------------------------------------------------------------------------

#[test]
fn a_tables_owner_is_the_bolded_subject_above_it() {
    let markdown = "**`clock`.** Words.\n\n| group | tokens |\n|---|---|\n| a | `x-y` |\n";
    let found = tables(markdown);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].owner.as_deref(), Some("clock"));
    assert_eq!(found[0].header, ["group", "tokens"]);
    assert_eq!(found[0].rows, [["a", "`x-y`"]]);
}

/// The habit that would otherwise put a hexadecimal number in the token set: an
/// operand is backticked inside parentheses, and a token never is.
#[test]
fn parenthesised_backticks_are_not_tokens() {
    let cell = "`block-probe-failed` (the outcome, `0x1` device error, `0x2` unsupported)";
    assert_eq!(
        backticked(&without_parentheses(cell)),
        ["block-probe-failed"]
    );
}

#[test]
fn a_stated_count_is_read_from_the_claim_itself() {
    assert_eq!(
        stated_count_before(
            "and 37 the `recorder` domain raises",
            "the `recorder` domain raises"
        ),
        Some(37)
    );
    assert_eq!(
        stated_count_before("one of 30 reasons:", "reasons:"),
        Some(30)
    );
    assert_eq!(stated_count_before("no number here:", "here:"), None);
}

/// The candidate filter: the token alphabet, a hyphen, and nothing else.
#[test]
fn only_hyphenated_lowercase_tokens_are_candidates() {
    assert!(is_candidate("not-virtio-net"));
    assert!(is_candidate("bar-not-64-bit"));
    // A single word says no more than the domain already does, and admitting one
    // would pull every lowercase literal in the workspace into the comparison.
    assert!(!is_candidate("malformed"));
    assert!(!is_candidate("Not-Virtio"));
    assert!(!is_candidate("content_length"));
    assert!(!is_candidate("-leading"));
    assert!(!is_candidate("trailing-"));
    assert!(!is_candidate("double--hyphen"));
    assert!(!is_candidate(""));
    assert!(!is_candidate(&"a-".repeat(MAX_CAUSE_LEN)));
}

/// The real chapters against the real catalogues. Not an assertion that they
/// agree — that is `check`'s job in the gate, and the pages may be mid-correction
/// — but that both sides are *readable*: a chapter whose tables this reader
/// cannot find would make the whole comparison vacuously green.
#[test]
fn the_shipped_chapters_present_the_tables_this_reader_needs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("the repository root is three levels above this crate")
        .to_owned();

    let console = read_page(&root, CONSOLE_PAGE).expect("the console chapter");
    let cause_tables = tables(&console)
        .into_iter()
        .filter(|table| table.header == ["group", "tokens"])
        .count();
    assert_eq!(cause_tables, REFUSING_DOMAINS.len(), "cause tables found");
    assert!(
        tables(&console)
            .iter()
            .any(|table| table.header == ["group", "reasons"]),
        "the `rejected=` table must be findable"
    );

    let metrics = read_page(&root, METRICS_PAGE).expect("the metrics chapter");
    let rows: Vec<Vec<String>> = tables(&metrics)
        .into_iter()
        .filter(|table| {
            table.header.first().map(String::as_str) == Some("Metric")
                && table.header.get(1).map(String::as_str) == Some("Type")
        })
        .flat_map(|table| table.rows)
        .collect();
    // How *many* rows there are is not asserted here, and deliberately: a
    // chapter listing fewer families than the catalogue declares is the finding
    // `check` reports, not a reader that failed. What must hold is that every row
    // the reader does find parses into the one family name it describes —
    // otherwise the comparison would be quietly reading nothing.
    assert!(!rows.is_empty(), "no family row was found at all");
    for row in &rows {
        let names = row.first().map(|cell| backticked(cell)).unwrap_or_default();
        assert_eq!(names.len(), 1, "one name per row: {row:?}");
        assert!(
            names[0].starts_with("librefirewall_"),
            "a family row's first cell is the metric name: {row:?}"
        );
        let kind = row.get(1).map(String::as_str);
        assert!(
            kind == Some("counter") || kind == Some("gauge"),
            "a family row's second cell is its type: {row:?}"
        );
    }
}

/// The chapters are hard-wrapped, so every claim this reads must survive a line
/// break falling inside it. This is the one that was wrong.
#[test]
fn a_count_claim_split_across_a_line_break_is_still_read() {
    let wrapped =
        "and the complete set: 23 the\n`nic-driver` domain raises, 25 the `clock`\ndomain raises.";
    let flat = flatten(wrapped);
    assert_eq!(
        stated_count_before(&flat, "the `nic-driver` domain raises"),
        Some(23)
    );
    assert_eq!(
        stated_count_before(&flat, "the `clock` domain raises"),
        Some(25)
    );
}

/// **Every count the status detail chapter states about the gate is compared, and
/// the phrase is the handle.** Three cases, because three things can go wrong with
/// a restated number: it can be right, it can be stale, and it can vanish.
#[test]
fn a_stated_count_about_the_gate_is_held_to_the_list_it_is_about() {
    let scenarios = crate::qemu::SCENARIOS.len();
    let sound = format!(
        "The gate boots {scenarios} system scenarios, and the {} scenarios that reach the \
         management port judge every surface. Coverage covers {} library crates.",
        crate::qemu::SCENARIOS
            .iter()
            .filter(|scenario| scenario.reaches_the_management_port())
            .count(),
        crate::host::library_crate_count(),
    );
    let mut findings = Vec::new();
    check_stated_counts(&sound, &mut findings);
    assert!(findings.is_empty(), "{findings:#?}");

    // Stale: the number moved and the page did not.
    let stale = sound.replace(
        &format!("{scenarios} system scenarios"),
        &format!("{} system scenarios", scenarios + 1),
    );
    let mut findings = Vec::new();
    check_stated_counts(&stale, &mut findings);
    let joined = findings.join("\n");
    assert!(
        joined.contains(&format!("\"{} system scenarios\"", scenarios + 1)),
        "{joined}"
    );
    assert!(joined.contains(&format!("holds {scenarios}")), "{joined}");

    // Gone: the claim was reworded out of reach, which must fail rather than pass in
    // silence — a check that only compares what it finds is one a rewording defeats.
    let mut findings = Vec::new();
    check_stated_counts("nothing here counts anything", &mut findings);
    assert_eq!(findings.len(), STATED_COUNTS.len(), "{findings:#?}");
    for finding in &findings {
        assert!(finding.contains("states no count before"), "{finding}");
    }
}

/// A mention with no number in front of it is prose, and prose is not this check's
/// to read: demanding a number in every sentence that names the scenarios would be
/// editing the chapter's English rather than holding its arithmetic.
#[test]
fn a_mention_that_states_no_number_is_left_alone() {
    let scenarios = crate::qemu::SCENARIOS.len();
    let mixed = format!(
        "Every system scenario boots the release image. The gate boots {scenarios} system \
         scenarios in all, and the {} scenarios that reach the management port are scraped. \
         Coverage runs over {} library crates, and the library crates are all `no_std`.",
        crate::qemu::SCENARIOS
            .iter()
            .filter(|scenario| scenario.reaches_the_management_port())
            .count(),
        crate::host::library_crate_count(),
    );
    let mut findings = Vec::new();
    check_stated_counts(&mixed, &mut findings);
    assert!(findings.is_empty(), "{findings:#?}");
}

/// The reader takes the number before *each* occurrence rather than before the
/// first, so a second place that went stale is found. The bug this pins is a real
/// one: a reader that re-searched from the start reported the first number twice
/// and never looked at the second.
#[test]
fn a_second_statement_of_one_count_is_compared_too() {
    let scenarios = crate::qemu::SCENARIOS.len();
    let phrase = "system scenarios";
    let text = format!("{scenarios} {phrase} exist, and 99 {phrase} is what a stale page says");
    assert_eq!(
        stated_counts_before(&text, phrase),
        [Some(scenarios), Some(99)]
    );

    let mut findings = Vec::new();
    check_stated_counts(&text, &mut findings);
    let joined = findings.join("\n");
    assert!(joined.contains("\"99 system scenarios\""), "{joined}");
    assert_eq!(
        findings.len(),
        // The two counts the text says nothing about, plus the stale one.
        STATED_COUNTS.len() - 1 + 1,
        "{findings:#?}"
    );
}
