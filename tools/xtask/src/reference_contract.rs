//! The reference chapters held to the code they describe.
//!
//! The book is not a build input and nothing in the gate rendered it, so every
//! sentence in the operator's interface definition was an untested assertion
//! about a catalogue that lives somewhere else. What that costs is not
//! hypothetical: two refusal tokens reached a shipping domain while the chapter
//! calling itself "the complete set" went stale, and every stage of the gate
//! stayed green. This module is the missing comparison.
//!
//! # It compares, it does not restate
//!
//! Nothing here holds a copy of a token, a family, a label or a count. Each
//! side is read where it lives:
//!
//! * The **closed vocabularies and the metric catalogue** are read as *data*
//!   through `lfw_log` and `lfw_metrics`, which this crate already depends on
//!   for exactly this kind of reason. `RejectReason::ALL`, `ALL_METRICS` and
//!   `SHARDS` are the appliance's own tables, not a transcription of them.
//! * The **refusal cause tokens** are not a closed vocabulary — they are
//!   `&'static str` literals minted at the sites that raise the refusals — so
//!   they are read out of those sites' own source, lexed by the one scanner in
//!   this build that already tells a literal from a sentence quoting one
//!   (`crate::budgets`).
//! * The **book** is read as Markdown tables, parsed as data.
//!
//! A third copy would be a third thing to drift, which is the defect this
//! closes rather than a shape to imitate.
//!
//! # The one table here, and why it names no tokens
//!
//! [`LITERAL_SITES`] attributes each *file* that mints a hyphen-bearing
//! lowercase literal to the vocabulary its literals belong to. It is a locator,
//! not a catalogue: adding a token to a listed file needs no edit here, and a
//! file that starts minting one and is not listed **fails**, which is what keeps
//! the code side exhaustive rather than merely current. A listed file that mints
//! none fails too, so a site that moved cannot leave a row behind claiming to
//! cover it.
//!
//! # What it cannot see
//!
//! Named rather than left to be discovered, because a checker's reach is part of
//! its result:
//!
//! * **Prose.** Every sentence outside the parsed tables and the parsed count
//!   claims, including a family's `help` text and every operator-facing
//!   explanation, is unchecked.
//! * **Label values.** A family's label *names* are compared; the value
//!   vocabularies in the same cell are not, because a shard's series carry the
//!   values a running node happens to publish and not the closed set.
//! * **`librefirewall_interface_info`'s label names**, which are byte literals
//!   inside the exposition writer rather than a table, so they are not reachable
//!   as data. Its name, type and domain set are compared.
//! * **Which group a token sits in.** A domain's tables are compared as one set
//!   per domain, so a token filed under the wrong group inside the right domain
//!   passes.
//!
//! # No adversary
//!
//! Two source-controlled inputs compared against each other on a developer's
//! machine; no threat-model adversary is named for it. What it defends against
//! is the ordinary edit that moves one side and not the other.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::Path,
};

use lfw_log::{MAX_CAUSE_LEN, RejectReason};
use lfw_metrics::{
    ALL_METRICS, INTERFACE_INFO, MANAGEMENT_PORT_DOMAIN, PORT_DOMAINS, SHARD_COUNT, SHARDS,
};

use crate::budgets;

/// The console reference chapter.
const CONSOLE_PAGE: &str = "book/src/reference/console.md";

/// The metrics reference chapter.
const METRICS_PAGE: &str = "book/src/reference/metrics.md";

/// Which console vocabulary a source file's hyphen-bearing lowercase literals
/// belong to.
enum Vocabulary {
    /// `cause=` tokens raised by the named domain, as `domain=` spells it.
    Causes(&'static str),
    /// Accounted for as data through an `ALL` array rather than by this scan, so
    /// the literals here are compared, just not from here. The reason names
    /// which array.
    AsData(&'static str),
    /// Not a console vocabulary at all. The reason says what the literals are,
    /// so a reader can tell a deliberate exclusion from an oversight.
    Other(&'static str),
}

/// Every production file under the measured trees that mints a hyphen-bearing
/// lowercase literal, and what those literals are.
///
/// Exhaustive by construction: [`check`] fails on a file that mints one and is
/// absent here, and on a row whose file mints none.
const LITERAL_SITES: &[(&str, Vocabulary)] = &[
    // The two virtio bring-up trees. They share eighteen tokens because they
    // run the same handshake against two device classes, which is why the
    // comparison below is per domain and not over one union.
    (
        "crates/nic-driver-core/src/bringup.rs",
        Vocabulary::Causes("nic-driver"),
    ),
    (
        "pds/nic-driver/src/main.rs",
        Vocabulary::Causes("nic-driver"),
    ),
    ("crates/blk/src/bringup.rs", Vocabulary::Causes("recorder")),
    // The boot-time proof of the path to the medium, which the recorder domain
    // raises and no other domain has a counterpart for.
    ("crates/blk/src/smoke.rs", Vocabulary::Causes("recorder")),
    ("pds/recorder/src/main.rs", Vocabulary::Causes("recorder")),
    ("pds/clock/src/main.rs", Vocabulary::Causes("clock")),
    (
        "pds/management/src/main.rs",
        Vocabulary::Causes("management"),
    ),
    // The closed vocabularies themselves: `RejectReason`'s tokens, plus
    // `Domain`'s and `Field`'s hyphenated ones. Every one of them is reachable
    // as an `ALL` array, so scanning this file would be the second copy.
    (
        "crates/log/src/event.rs",
        Vocabulary::AsData("lfw_log's closed_vocabulary! ALL arrays"),
    ),
    // Not console vocabularies.
    (
        "crates/tcp/src/connection.rs",
        Vocabulary::Other(
            "TCP connection state names, which no console record and no metric label carries today",
        ),
    ),
    (
        "crates/http/src/request.rs",
        Vocabulary::Other("HTTP header field names, which are wire syntax rather than a surface"),
    ),
];

/// The four domains whose refusal tokens the console chapter tabulates, in the
/// order it presents them. Derived from [`LITERAL_SITES`] would be circular —
/// the book's own headings are what this list is compared against.
const REFUSING_DOMAINS: &[&str] = &["nic-driver", "clock", "management", "recorder"];

/// Hold both reference chapters to the code.
///
/// Every finding is collected before anything is reported: a stale chapter is
/// stale in many places at once, and failing on the first would turn one
/// documentation pass into a dozen.
///
/// # Errors
/// Every disagreement found, one per line, each naming the exact token, family
/// or count and which side is missing it — plus anything that stopped a side
/// being read at all, which is a finding rather than a silent pass.
pub(crate) fn check(root: &Path) -> Result<(), String> {
    let console = read_page(root, CONSOLE_PAGE)?;
    let metrics = read_page(root, METRICS_PAGE)?;
    let literals = budgets::production_literals(root)?;

    let mut findings = Vec::new();
    check_literal_sites(&literals, &mut findings);
    check_causes(&literals, &console, &mut findings);
    check_reject_reasons(&console, &mut findings);
    check_metric_families(&metrics, &mut findings);

    if findings.is_empty() {
        // Said out loud, like every other stage of the gate. A check that passes
        // in silence is one a reader of the output cannot tell ran at all, which
        // is the same silence this comparison exists to end.
        println!(
            "reference: {CONSOLE_PAGE} and {METRICS_PAGE} agree with the code they describe: \
             every refusal cause token, every `rejected=` reason, and every metric family with \
             its type, labels and publishing domains"
        );
        return Ok(());
    }
    let mut report = format!(
        "the reference chapters and the code disagree in {} place(s). The code is the source of \
         truth, so each of these is a page to correct unless the code is what is wrong:",
        findings.len()
    );
    for finding in &findings {
        let _ = write!(report, "\n  - {finding}");
    }
    let _ = write!(
        report,
        "\n  ({CONSOLE_PAGE}, {METRICS_PAGE}; this comparison is `xtask::reference_contract`)"
    );
    Err(report)
}

fn read_page(root: &Path, page: &str) -> Result<String, String> {
    let path = root.join(page);
    fs::read_to_string(&path).map_err(|error| {
        format!(
            "read {}: {error}. The reference chapters are what this check compares against, so a \
             page that cannot be read is a failure rather than a check that passes",
            path.display()
        )
    })
}

// ---------------------------------------------------------------------------
// The code side of the cause tokens
// ---------------------------------------------------------------------------

/// Whether a literal could be a `cause=` token: the [`lfw_log::Cause`] alphabet,
/// at least one hyphen, and inside the length the record can carry.
///
/// The hyphen is what makes this a usable filter rather than a match on every
/// lowercase word in the workspace, and it costs nothing: every token in the
/// four tables carries one, a refusal naming a single word being a token that
/// says less than the domain already does.
fn is_candidate(literal: &str) -> bool {
    !literal.is_empty()
        && literal.len() <= MAX_CAUSE_LEN
        && literal.contains('-')
        && !literal.starts_with('-')
        && !literal.ends_with('-')
        && !literal.contains("--")
        && literal
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// The candidate literals each production file holds.
fn candidates<'a>(
    literals: &'a BTreeMap<String, Vec<String>>,
) -> BTreeMap<&'a str, BTreeSet<&'a str>> {
    let mut found: BTreeMap<&'a str, BTreeSet<&'a str>> = BTreeMap::new();
    for (path, texts) in literals {
        let hits: BTreeSet<&str> = texts
            .iter()
            .map(String::as_str)
            .filter(|text| is_candidate(text))
            .collect();
        if !hits.is_empty() {
            found.insert(path.as_str(), hits);
        }
    }
    found
}

/// Both directions of [`LITERAL_SITES`]: no unattributed minting file, and no
/// row that covers nothing.
fn check_literal_sites(literals: &BTreeMap<String, Vec<String>>, findings: &mut Vec<String>) {
    let found = candidates(literals);
    for (path, hits) in &found {
        if !LITERAL_SITES.iter().any(|(listed, _)| listed == path) {
            let mut named: Vec<&str> = hits.iter().copied().collect();
            named.sort_unstable();
            findings.push(format!(
                "{path} mints the hyphenated lowercase literal(s) {named:?} and this check does \
                 not know which console vocabulary they belong to. If they are `cause=` tokens, \
                 add the file to LITERAL_SITES under its domain and list them in the console \
                 chapter; if they are not, record that with its reason"
            ));
        }
    }
    for (path, vocabulary) in LITERAL_SITES {
        if !found.contains_key(path) {
            let what = match vocabulary {
                Vocabulary::Causes(domain) => format!("the {domain} domain's `cause=` tokens"),
                Vocabulary::AsData(source) => format!("literals accounted for by {source}"),
                Vocabulary::Other(reason) => reason.to_string(),
            };
            findings.push(format!(
                "LITERAL_SITES claims {path} holds {what} and it holds no such literal at all, so \
                 the row covers nothing — the site moved, or the file did"
            ));
        }
    }
}

/// The tokens each refusing domain's sites mint.
fn minted_causes<'a>(
    literals: &'a BTreeMap<String, Vec<String>>,
) -> BTreeMap<&'static str, BTreeSet<&'a str>> {
    let found = candidates(literals);
    let mut by_domain: BTreeMap<&'static str, BTreeSet<&'a str>> = REFUSING_DOMAINS
        .iter()
        .map(|domain| (*domain, BTreeSet::new()))
        .collect();
    for (path, vocabulary) in LITERAL_SITES {
        let Vocabulary::Causes(domain) = vocabulary else {
            continue;
        };
        if let Some(hits) = found.get(path) {
            by_domain
                .entry(*domain)
                .or_default()
                .extend(hits.iter().copied());
        }
    }
    by_domain
}

// ---------------------------------------------------------------------------
// The console chapter
// ---------------------------------------------------------------------------

/// Per domain, both directions, plus the counts the chapter states about itself.
fn check_causes(
    literals: &BTreeMap<String, Vec<String>>,
    console: &str,
    findings: &mut Vec<String>,
) {
    let flat = flatten(console);
    let tables = tables(console);
    let cause_tables: Vec<&Table> = tables
        .iter()
        .filter(|table| table.header == ["group", "tokens"])
        .collect();

    // "the four tables together are the complete set" — the spelled number and
    // the tables actually there.
    let spelled = spell(cause_tables.len());
    let claim = format!("the {spelled} tables together are the complete set");
    if !flat.contains(&claim) {
        findings.push(format!(
            "{CONSOLE_PAGE} carries {} refusal-cause table(s) and does not say \"{claim}\"",
            cause_tables.len()
        ));
    }

    let mut documented: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for table in &cause_tables {
        let Some(domain) = table.owner.clone() else {
            findings.push(format!(
                "{CONSOLE_PAGE} line {}: a refusal-cause table sits under no `**`domain`.**` \
                 heading, so its tokens belong to no domain a reader or this check can name",
                table.line
            ));
            continue;
        };
        let tokens = documented.entry(domain).or_default();
        for row in &table.rows {
            let Some(cell) = row.get(1) else { continue };
            tokens.extend(backticked(&without_parentheses(cell)));
        }
    }

    let minted = minted_causes(literals);
    for domain in REFUSING_DOMAINS {
        let empty = BTreeSet::new();
        let code = minted.get(domain).unwrap_or(&empty);
        let Some(book) = documented.get(*domain) else {
            findings.push(format!(
                "{CONSOLE_PAGE} has no refusal-cause table for the `{domain}` domain, which mints \
                 {} token(s)",
                code.len()
            ));
            continue;
        };
        for token in code {
            if !book.contains(*token) {
                findings.push(format!(
                    "cause token `{token}`: the `{domain}` domain can emit it and \
                     {CONSOLE_PAGE} does not list it"
                ));
            }
        }
        for token in book {
            if !code.contains(token.as_str()) {
                findings.push(format!(
                    "cause token `{token}`: {CONSOLE_PAGE} lists it under `{domain}` and no code \
                     in that domain emits it"
                ));
            }
        }
    }
    for domain in documented.keys() {
        if !REFUSING_DOMAINS.contains(&domain.as_str()) {
            findings.push(format!(
                "{CONSOLE_PAGE} tabulates refusal causes for a `{domain}` domain, which this \
                 check has no minting site for"
            ));
        }
    }

    // The four numbers the chapter's own intro sentence states.
    for domain in REFUSING_DOMAINS {
        let Some(book) = documented.get(*domain) else {
            continue;
        };
        let phrase = format!("the `{domain}` domain raises");
        match stated_count_before(&flat, &phrase) {
            Some(stated) if stated == book.len() => {}
            Some(stated) => findings.push(format!(
                "{CONSOLE_PAGE} says \"{stated} {phrase}\" and its own `{domain}` table lists {}",
                book.len()
            )),
            None => findings.push(format!(
                "{CONSOLE_PAGE} states no count before \"{phrase}\", so the chapter's own summary \
                 of its `{domain}` table cannot be checked"
            )),
        }
    }
}

/// `rejected=` reasons: `RejectReason::ALL` against the chapter's table, both
/// directions, plus the total and the per-group counts it states.
fn check_reject_reasons(console: &str, findings: &mut Vec<String>) {
    let code: BTreeSet<&str> = RejectReason::ALL
        .iter()
        .map(|reason| reason.name())
        .collect();

    let tables = tables(console);
    let Some(table) = tables
        .iter()
        .find(|table| table.header == ["group", "reasons"])
    else {
        findings.push(format!(
            "{CONSOLE_PAGE} carries no `| group | reasons |` table, so the {} `rejected=` reasons \
             the code can emit are compared against nothing",
            code.len()
        ));
        return;
    };

    let mut book: BTreeSet<String> = BTreeSet::new();
    for row in &table.rows {
        let Some(cell) = row.get(1) else { continue };
        let reasons = backticked(cell);
        book.extend(reasons.iter().cloned());
        // The count each group states in its own label, e.g. "(18)".
        if let Some(group) = row.first()
            && let Some(stated) = parenthesised_count(group)
            && stated != reasons.len()
        {
            findings.push(format!(
                "{CONSOLE_PAGE}: the `rejected=` group \"{}\" states ({stated}) and lists {}",
                strip_backticks(&without_parentheses(group)).trim(),
                reasons.len()
            ));
        }
    }

    for reason in &code {
        if !book.contains(*reason) {
            findings.push(format!(
                "rejected reason `{reason}`: `lfw_log::RejectReason` carries it and \
                 {CONSOLE_PAGE} does not list it"
            ));
        }
    }
    for reason in &book {
        if !code.contains(reason.as_str()) {
            findings.push(format!(
                "rejected reason `{reason}`: {CONSOLE_PAGE} lists it and \
                 `lfw_log::RejectReason` has no such variant"
            ));
        }
    }
    match stated_count_before(&flatten(console), "reasons:") {
        Some(stated) if stated == code.len() => {}
        Some(stated) => findings.push(format!(
            "{CONSOLE_PAGE} says `rejected=` is one of {stated} reasons and \
             `lfw_log::RejectReason` carries {}",
            code.len()
        )),
        None => findings.push(format!(
            "{CONSOLE_PAGE} states no total before \"reasons:\", so the size of the `rejected=` \
             vocabulary cannot be checked"
        )),
    }
}

// ---------------------------------------------------------------------------
// The metrics chapter
// ---------------------------------------------------------------------------

/// What the code says one metric family is.
struct Family {
    kind: &'static str,
    labels: BTreeSet<&'static str>,
    domains: BTreeSet<&'static str>,
}

/// The catalogue as data: every family with its type, the label names its series
/// carry beyond `domain`, and the domains that publish it.
fn catalogued() -> BTreeMap<&'static str, Family> {
    let mut families: BTreeMap<&'static str, Family> = ALL_METRICS
        .iter()
        .map(|metric| {
            (
                metric.name,
                Family {
                    kind: metric.kind.token(),
                    labels: BTreeSet::new(),
                    domains: BTreeSet::new(),
                },
            )
        })
        .collect();
    for shard in &SHARDS {
        for series in shard.series {
            if let Some(family) = families.get_mut(series.metric.name) {
                family.domains.insert(shard.domain);
                family
                    .labels
                    .extend(series.labels.iter().map(|label| label.name));
            }
        }
    }
    // The one family no shard holds: it is published from the committed
    // configuration, so its domains are the ports' driver domains and its label
    // names live in the exposition writer rather than in a table.
    if let Some(family) = families.get_mut(INTERFACE_INFO.name) {
        family.domains.extend(PORT_DOMAINS);
        family.domains.insert(MANAGEMENT_PORT_DOMAIN);
    }
    families
}

fn check_metric_families(metrics: &str, findings: &mut Vec<String>) {
    let code = catalogued();
    let tables = tables(metrics);
    let family_tables: Vec<&Table> = tables
        .iter()
        .filter(|table| {
            table.header.first().map(String::as_str) == Some("Metric")
                && table.header.get(1).map(String::as_str) == Some("Type")
        })
        .collect();
    if family_tables.is_empty() {
        findings.push(format!(
            "{METRICS_PAGE} carries no metric-family table, so the {} families the appliance \
             exposes are compared against nothing",
            code.len()
        ));
        return;
    }

    let mut book: BTreeMap<String, (String, BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    for table in &family_tables {
        for row in &table.rows {
            let names = row.first().map(|cell| backticked(cell)).unwrap_or_default();
            let [name] = &names[..] else {
                findings.push(format!(
                    "{METRICS_PAGE} line {}: a family row names {} metrics and a row describes \
                     exactly one",
                    table.line,
                    names.len()
                ));
                continue;
            };
            let kind = row.get(1).cloned().unwrap_or_default();
            let domains: BTreeSet<String> = row
                .get(2)
                .map(|cell| backticked(cell).into_iter().collect())
                .unwrap_or_default();
            let labels: BTreeSet<String> = row
                .get(3)
                .map(|cell| backticked(&without_parentheses(cell)).into_iter().collect())
                .unwrap_or_default();
            if book.insert(name.clone(), (kind, labels, domains)).is_some() {
                findings.push(format!(
                    "{METRICS_PAGE} lists the family `{name}` twice, so a reader cannot tell \
                     which row describes it"
                ));
            }
        }
    }

    for (name, family) in &code {
        let Some((kind, labels, domains)) = book.get(*name) else {
            findings.push(format!(
                "metric family `{name}`: `lfw_metrics::ALL_METRICS` declares it and \
                 {METRICS_PAGE} does not list it"
            ));
            continue;
        };
        if kind != family.kind {
            findings.push(format!(
                "metric family `{name}`: the catalogue declares it a {} and {METRICS_PAGE} calls \
                 it a {kind:?}",
                family.kind
            ));
        }
        let stated: BTreeSet<&str> = labels.iter().map(String::as_str).collect();
        // The one family whose label names are not reachable as data.
        if *name != INTERFACE_INFO.name && stated != family.labels {
            findings.push(format!(
                "metric family `{name}`: its series carry the label(s) {:?} and {METRICS_PAGE} \
                 states {:?}",
                family.labels, stated
            ));
        }
        let stated: BTreeSet<&str> = domains.iter().map(String::as_str).collect();
        if stated != family.domains {
            findings.push(format!(
                "metric family `{name}`: it is published by the domain(s) {:?} and \
                 {METRICS_PAGE} states {:?}",
                family.domains, stated
            ));
        }
    }
    for name in book.keys() {
        if !code.contains_key(name.as_str()) {
            findings.push(format!(
                "metric family `{name}`: {METRICS_PAGE} lists it and \
                 `lfw_metrics::ALL_METRICS` declares no such family"
            ));
        }
    }

    // The two totals the chapter states about itself.
    let flat = flatten(metrics);
    match stated_count_before(&flat, "families;") {
        Some(stated) if stated == code.len() => {}
        Some(stated) => findings.push(format!(
            "{METRICS_PAGE} says {stated} families and `lfw_metrics::ALL_METRICS` declares {}",
            code.len()
        )),
        None => findings.push(format!(
            "{METRICS_PAGE} states no family total before \"families;\", so the size of the \
             inventory cannot be checked"
        )),
    }
    let series: usize = SHARDS.iter().map(|shard| shard.series.len()).sum();
    let claim = format!(
        "{series} counter and gauge series from the {} shards",
        spell(SHARD_COUNT)
    );
    if !flat.contains(&claim) {
        findings.push(format!(
            "{METRICS_PAGE} does not say \"{claim}\", which is what the {SHARD_COUNT} shards of \
             `lfw_metrics::SHARDS` actually hold"
        ));
    }
}

// ---------------------------------------------------------------------------
// Markdown, read as data
// ---------------------------------------------------------------------------

/// One Markdown table: its header cells, its body rows, the line it starts on,
/// and the bolded subject that introduced it.
struct Table {
    header: Vec<String>,
    rows: Vec<Vec<String>>,
    line: usize,
    /// The backticked subject of the nearest preceding `**…**` lead-in, which is
    /// how the console chapter says which domain a table of tokens is about.
    owner: Option<String>,
}

/// Every pipe table in `markdown`.
///
/// A table is a `|`-led line followed by a delimiter row of nothing but `-`,
/// `:`, `|` and spaces — the shape mdBook renders and the only shape these
/// chapters use. Cells are split on `|` because no cell in either chapter
/// contains one; a cell that did would show up as a header this check does not
/// recognise rather than as a silently mis-split row.
fn tables(markdown: &str) -> Vec<Table> {
    let lines: Vec<&str> = markdown.lines().collect();
    let mut found = Vec::new();
    let mut owner: Option<String> = None;
    let mut at = 0;
    while at < lines.len() {
        let line = lines[at].trim();
        if line.starts_with("**") {
            owner = backticked(line).into_iter().next();
        }
        let is_delimiter = lines
            .get(at + 1)
            .map(|next| {
                let next = next.trim();
                next.starts_with('|')
                    && next.len() > 1
                    && next
                        .bytes()
                        .all(|byte| matches!(byte, b'-' | b':' | b'|' | b' '))
            })
            .unwrap_or(false);
        if !(line.starts_with('|') && is_delimiter) {
            at += 1;
            continue;
        }
        let header = cells(line);
        let mut rows = Vec::new();
        let mut row_at = at + 2;
        while let Some(row) = lines.get(row_at) {
            let row = row.trim();
            if !row.starts_with('|') {
                break;
            }
            rows.push(cells(row));
            row_at += 1;
        }
        found.push(Table {
            header,
            rows,
            line: at + 1,
            owner: owner.clone(),
        });
        at = row_at;
    }
    found
}

/// One table row's cells, the leading and trailing pipes discarded.
fn cells(row: &str) -> Vec<String> {
    let row = row.trim().trim_start_matches('|').trim_end_matches('|');
    row.split('|').map(|cell| cell.trim().to_owned()).collect()
}

/// Every `` `x` `` span's contents, in order.
fn backticked(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else { break };
        found.push(after[..close].to_owned());
        rest = &after[close + 1..];
    }
    found
}

/// `text` with every parenthesised span removed.
///
/// The chapters put a token in backticks and its operands or its label values in
/// parentheses after it, so this is what separates the two — and it is what keeps
/// a backticked `0x1` inside an explanation from reading as a refusal token.
fn without_parentheses(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut depth = 0_usize;
    for character in text.chars() {
        match character {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(character),
            _ => {}
        }
    }
    out
}

fn strip_backticks(text: &str) -> String {
    text.replace('`', "")
}

/// The number inside the last parenthesised span of `text`, where that span is a
/// number and nothing else — the `(18)` a group label ends with.
fn parenthesised_count(text: &str) -> Option<usize> {
    let mut found = None;
    let mut rest = text;
    while let Some(open) = rest.find('(') {
        let after = &rest[open + 1..];
        let close = after.find(')')?;
        if let Ok(number) = after[..close].trim().parse::<usize>() {
            found = Some(number);
        }
        rest = &after[close + 1..];
    }
    found
}

/// `text` with every run of whitespace collapsed to one space.
///
/// The chapters are hard-wrapped, so a claim about a count routinely straddles a
/// line break — "23 the\n`nic-driver` domain raises" — and a search for the
/// phrase as written would find nothing and report the claim as absent. Reading
/// it flattened is reading the sentence rather than the column it happens to end
/// in.
fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The decimal number immediately before `phrase`'s first occurrence.
///
/// This is how both chapters state a count about themselves — "23 the
/// `nic-driver` domain raises", "74 families", "one of 30 reasons" — so reading
/// the number back is reading the claim rather than a restatement of it.
fn stated_count_before(text: &str, phrase: &str) -> Option<usize> {
    let at = text.find(phrase)?;
    let before = text[..at].trim_end();
    let digits: String = before
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.chars().rev().collect::<String>().parse().ok()
}

/// A small count as the chapters spell it, for the claims that name a number in
/// words. Only the sizes these chapters actually state; anything else is a
/// finding rather than a guess at English.
fn spell(count: usize) -> String {
    match count {
        0 => String::from("no"),
        1 => String::from("one"),
        2 => String::from("two"),
        3 => String::from("three"),
        4 => String::from("four"),
        5 => String::from("five"),
        6 => String::from("six"),
        7 => String::from("seven"),
        8 => String::from("eight"),
        9 => String::from("nine"),
        10 => String::from("ten"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests;
