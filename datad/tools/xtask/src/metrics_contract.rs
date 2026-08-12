//! The `GET /metrics` contract, fetched with a real client and judged as fields.
//!
//! This is the one scenario where nothing the harness composed is on the wire.
//! `curl` opens a TCP connection to the management endpoint through QEMU's own
//! user-mode stack, and what comes back is judged here: the status line, the
//! headers, and a body this module **parses** as Prometheus exposition rather
//! than searching for substrings in.
//!
//! # Two scrapes, not one
//!
//! A single scrape cannot contain the response it *is*: the endpoint records a
//! response as it composes one, which is after the shard the exposition is
//! rendered from has been published. What one scrape can carry is its own
//! *request*, counted as the head completes. So the scenario takes two, and the
//! second is the one judged — it must report the first request and the first
//! 200, which is what proves the counters advance rather than merely exist.
//!
//! The second scrape also proves something no host test can: that the staging
//! buffer is free again a moment after the first connection closed. Its
//! `TIME_WAIT` has a minute to run, and an endpoint that held the buffer that
//! long would answer every scrape a real scraper made with `503`.
//!
//! # The cross-check is the point
//!
//! An exposition can be well formed, carry every name an operator expects, and
//! still be a set of numbers about nothing. So one value is held to a quantity
//! the harness measured **independently, in the same boot**: every frame the
//! appliance forwards leaves on a dataplane port, and the harness has a socket
//! on both, so the frames it counted there are exactly the frames the forwarder
//! forwarded. `librefirewall_forwarded_frames_total` — summed here across its
//! two `pipeline` series, because the node deliberately publishes no total —
//! must equal that count.
//!
//! That is what separates "the metric surface renders" from "the metric surface
//! reports reality". Everything else this module asserts would pass over a
//! renderer wired to a table of zeros.
//!
//! # Summing is the reader's job, and this is a reader
//!
//! The appliance exposes one series per `pipeline` and computes no total,
//! because a summed total is corrupted by a domain
//! restart. A scraper aggregates instead, and so does this — the sum below is
//! performed *here*, over the labelled series, which is exactly what a
//! Prometheus query would do.
//!
//! # No adversary
//!
//! As `crate::console_records`: this reads the appliance's own answer on a wire
//! only the harness is attached to.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use lfw_flow::FLOW_CAPACITY;
use lfw_http::{METRICS_CONTENT_TYPE, Status};

use crate::forward_harness::PolicyWitness;
use crate::topology::Topology;

/// How long `curl` may take, end to end. Generous because the guest may be
/// running under TCG on a loaded runner and the response spans twenty segments,
/// each of which the appliance sends only when a frame wakes it.
const SCRAPE_TIMEOUT: Duration = Duration::from_secs(60);

/// The info family, whose every label value is compared against the
/// configuration document the image under test was built from.
const INTERFACE_INFO: &str = "librefirewall_interface_info";

/// The per-rule family, on the same terms: its one label is the id the document
/// gave the rule, and its cardinality is the number of rules the document
/// declares.
const RULE_HITS: &str = "librefirewall_rule_hits_total";

/// The filter's own totals, which the per-rule counters must add up to.
const POLICY_PACKETS: &str = "librefirewall_policy_packets_total";

/// Where the two refusals are told apart: the fallthrough is not a rule and has
/// no counter, so the reason is the only place the default deny appears.
const ROUTE_DROPS: &str = "librefirewall_route_drops_total";

/// What each pipeline put on its egress ring under a forwarding verdict.
const FORWARDED_FRAMES: &str = "librefirewall_forwarded_frames_total";

/// What the connection tracker made of the packets it was offered.
const FLOW_PACKETS: &str = "librefirewall_flow_packets_total";

/// Packets it was offered at all, and what it turned away.
const FLOW_SEEN: &str = "librefirewall_flow_packets_seen_total";
const FLOW_REFUSED: &str = "librefirewall_flow_packets_refused_total";

/// Slots of the table, by the state of the flow in each.
const FLOW_ENTRIES: &str = "librefirewall_flow_table_entries";

/// What ended the flows that left the table, by cause.
const FLOW_LIFECYCLE: &str = "librefirewall_flow_lifecycle_total";

/// The one state that is not a flow: how much of the table is left.
const VACANT: &str = "vacant";

/// Metric families the scrape must carry, one per subsystem this change made
/// observable. Deliberately not the whole catalogue — `lfw_metrics`' own tests
/// hold that to itself — but one name from each shard kind, so a shard that
/// stopped being published fails here.
const REQUIRED: &[&str] = &[
    INTERFACE_INFO,
    RULE_HITS,
    POLICY_PACKETS,
    "librefirewall_policy_bytes_total",
    "librefirewall_forwarded_frames_total",
    ROUTE_DROPS,
    "librefirewall_receive_frames_total",
    "librefirewall_transmit_frames_total",
    "librefirewall_input_drops_total",
    "librefirewall_invariant_faults_total",
    "librefirewall_device_faults_total",
    "librefirewall_pool_returns_refused_total",
    "librefirewall_endpoint_frames_total",
    "librefirewall_endpoint_replies_total",
    "librefirewall_tcp_segments_total",
    "librefirewall_tcp_refused_total",
    "librefirewall_http_requests_total",
    "librefirewall_http_responses_total",
    "librefirewall_console_records_total",
    "librefirewall_uart_bytes_written_total",
    "librefirewall_configuration_generation",
    "librefirewall_clock_frequency_hertz",
    "librefirewall_log_records_dropped_total",
    STORE_SIGNATURES,
];

/// The store domain's signature tally, named here because it is the one series in
/// this contract whose value proves a *shard moved after `init`*.
///
/// Every other series in the exposition is written once by a domain that then
/// parks, or repeatedly by one that never stops. This one is written by a domain
/// that establishes an identity, publishes, blocks, and publishes again when it is
/// woken — so a scrape reading it above zero is the only evidence on this surface
/// that the second publish happens at all.
const STORE_SIGNATURES: &str = "librefirewall_store_signatures_total";

/// Every protection domain must appear as a `domain` label value, or one shard
/// is not reaching the exposition at all.
const DOMAINS: &[&str] = &[
    "forwarder",
    "nic_driver0",
    "nic_driver1",
    "nic_driver2",
    "management",
    "console",
    "config",
    "clock",
    "recorder",
    "hardware_probe",
    "store",
];

/// What a real client got out of the endpoint.
#[derive(Clone, Debug)]
pub struct Scrape {
    /// The command as it was run, verbatim, so the evidence in a run log can be
    /// re-run by hand.
    pub command: String,
    /// `HTTP/1.1 200 OK`, as it came off the wire.
    pub status_line: String,
    /// Every header line, in order and unmodified.
    pub headers: Vec<String>,
    pub body: String,
}

impl Scrape {
    /// The value of one header field, matched case-insensitively on the name.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}

/// Run `curl` against the forwarded port and split what it answered.
///
/// # Errors
/// A `curl` that could not be started, one that failed, or an answer that is not
/// an HTTP message.
pub fn fetch(host_port: u16) -> Result<Scrape, String> {
    let url = format!("http://127.0.0.1:{host_port}/metrics");
    let arguments = [
        "--silent",
        "--show-error",
        "--http1.1",
        "--include",
        "--max-time",
        // A string rather than the constant's `Debug`, so the printed command
        // is the command.
        "60",
        &url,
    ];
    let command = format!("curl {}", arguments.join(" "));
    // Stated so the two cannot drift: the argument above is the budget.
    debug_assert_eq!(SCRAPE_TIMEOUT.as_secs(), 60);

    let output = Command::new("curl")
        .args(arguments)
        .output()
        .map_err(|error| format!("run `{command}`: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "`{command}` failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let answered = String::from_utf8(output.stdout)
        .map_err(|error| format!("`{command}` answered bytes that are not UTF-8: {error}"))?;
    let (head, body) = answered.split_once("\r\n\r\n").ok_or_else(|| {
        format!(
            "`{command}` answered no HTTP head: {:?}",
            truncate(&answered)
        )
    })?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| format!("`{command}` answered an empty head"))?
        .to_owned();
    Ok(Scrape {
        command,
        status_line,
        headers: lines.map(ToOwned::to_owned).collect(),
        body: body.to_owned(),
    })
}

/// One sample line, read back into its parts.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Sample {
    name: String,
    /// Sorted, so a lookup is order-independent — the exposition's own order is
    /// the renderer's and is not part of the contract.
    labels: BTreeMap<String, String>,
    value: u64,
}

/// A parsed exposition: what families were declared, and every sample.
#[derive(Debug, Default)]
struct Exposition {
    families: BTreeMap<String, String>,
    samples: Vec<Sample>,
}

impl Exposition {
    /// Every sample of `name` whose labels include each of `matching`.
    fn select<'a>(&'a self, name: &str, matching: &[(&str, &str)]) -> Vec<&'a Sample> {
        self.samples
            .iter()
            .filter(|sample| sample.name == name)
            .filter(|sample| {
                matching
                    .iter()
                    .all(|(key, value)| sample.labels.get(*key).map(String::as_str) == Some(*value))
            })
            .collect()
    }
}

/// Read the exposition format: `# HELP`, `# TYPE`, and `name{labels} value`.
///
/// A parser rather than a regular expression, and rather than a search for
/// expected substrings: the thing under test is whether the appliance produced
/// a document a scraper can read, and only reading it that way answers that.
fn parse(body: &str) -> Result<Exposition, String> {
    let mut exposition = Exposition::default();
    let mut helps: BTreeMap<String, String> = BTreeMap::new();
    for (number, line) in body.lines().enumerate() {
        let at = number + 1;
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let (name, help) = rest
                .split_once(' ')
                .ok_or_else(|| format!("line {at}: a HELP line names no metric: {line:?}"))?;
            if helps.insert(name.to_owned(), help.to_owned()).is_some() {
                return Err(format!("line {at}: {name} is declared twice"));
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest
                .split_once(' ')
                .ok_or_else(|| format!("line {at}: a TYPE line names no metric: {line:?}"))?;
            if !matches!(kind, "counter" | "gauge") {
                return Err(format!("line {at}: {name} has type {kind:?}"));
            }
            let help = helps.get(name).ok_or_else(|| {
                format!("line {at}: {name} has a TYPE line and no HELP line before it")
            })?;
            exposition
                .families
                .insert(name.to_owned(), format!("{kind} {help}"));
            continue;
        }
        if line.starts_with('#') {
            return Err(format!("line {at}: an unexpected comment: {line:?}"));
        }
        if line.is_empty() {
            continue;
        }
        exposition.samples.push(sample(at, line)?);
    }
    if exposition.samples.is_empty() {
        return Err(String::from("the exposition carries no sample at all"));
    }
    Ok(exposition)
}

/// `name{key="value",…} 123`.
fn sample(at: usize, line: &str) -> Result<Sample, String> {
    let (head, raw) = line
        .rsplit_once(' ')
        .ok_or_else(|| format!("line {at}: a sample line carries no value: {line:?}"))?;
    let value: u64 = raw
        .parse()
        .map_err(|error| format!("line {at}: {raw:?} is no counter value: {error}"))?;
    let (name, labels) = match head.split_once('{') {
        None => (head.to_owned(), BTreeMap::new()),
        Some((name, rest)) => {
            let inner = rest
                .strip_suffix('}')
                .ok_or_else(|| format!("line {at}: an unterminated label set: {line:?}"))?;
            let mut labels = BTreeMap::new();
            for pair in inner.split(',') {
                let (key, quoted) = pair
                    .split_once('=')
                    .ok_or_else(|| format!("line {at}: {pair:?} is no label"))?;
                let value = quoted
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'))
                    .ok_or_else(|| format!("line {at}: {pair:?} has an unquoted value"))?;
                if labels.insert(key.to_owned(), value.to_owned()).is_some() {
                    return Err(format!("line {at}: {key} appears twice: {line:?}"));
                }
            }
            (name.to_owned(), labels)
        }
    };
    if name.is_empty() {
        return Err(format!("line {at}: a sample with no metric name: {line:?}"));
    }
    Ok(Sample {
        name,
        labels,
        value,
    })
}

/// Hold the interface info series to the configuration document the image was
/// built from, label by label.
///
/// This is what makes the family a *checked statement about the running
/// configuration* rather than a decorative label set. Nothing here is matched as
/// a substring and nothing is compared against a literal: the ids, addresses,
/// prefix lengths and MACs come out of the document through
/// [`Topology`](crate::topology::Topology), which is the same text the appliance
/// was compiled around — so a scrape from an image built from a *different*
/// document is judged against that document and cannot pass on the first one's
/// addressing.
///
/// The `domain` each series carries is the other half. It is the join key an
/// operator's query matches on, so it is asserted to be the domain that port's
/// driver publishes its counters under — read back from `lfw_metrics` rather than
/// written here, and held to the system description at build time by
/// `xtask::sysdesc`.
///
/// # Errors
/// The verdict, naming the label and the two values.
fn judge_interfaces<'a>(
    exposition: &'a Exposition,
    topology: &Topology,
) -> Result<Vec<&'a Sample>, String> {
    let series = exposition.select(INTERFACE_INFO, &[]);
    let configured = topology.interfaces();
    let expected = configured.len() + 1;
    if series.len() != expected {
        return Err(format!(
            "the exposition carries {} {INTERFACE_INFO} series and the document configures {} \
             dataplane interfaces and one management port. One series per configured interface is \
             the whole cardinality of this family, so a different count means an interface is \
             unreported or one is reported twice\n  found: {}",
            series.len(),
            configured.len(),
            render(&series)
        ));
    }

    let mut asserted = Vec::new();
    for (port, interface) in configured.iter().enumerate() {
        let domain = lfw_metrics::port_domain(port as u8)
            .ok_or_else(|| format!("lfw_metrics attributes port {port} to no protection domain"))?;
        asserted.push(judge_one_interface(
            exposition,
            domain,
            &[
                ("interface", interface.id.as_str().to_owned()),
                ("role", String::from("dataplane")),
                ("address", dotted(interface.address)),
                ("prefix_length", interface.prefix_length.to_string()),
                ("mac", colons(interface.mac)),
            ],
        )?);
    }

    let management = topology.management();
    asserted.push(judge_one_interface(
        exposition,
        lfw_metrics::MANAGEMENT_PORT_DOMAIN,
        &[
            // The `<management>` element carries no id, so the identity is the
            // word — the same one a console change record about it uses.
            ("interface", String::from("management")),
            ("role", String::from("management")),
            ("address", dotted(management.address)),
            ("prefix_length", management.prefix_length.to_string()),
            ("mac", colons(management.mac)),
        ],
    )?);
    Ok(asserted)
}

/// One info series, found by its `domain` and then compared field by field.
///
/// Selected by the join key alone and *then* judged, deliberately: selecting on
/// every label would find nothing when one is wrong and report "no such series",
/// which tells an operator neither which label moved nor what it moved to.
fn judge_one_interface<'a>(
    exposition: &'a Exposition,
    domain: &str,
    expected: &[(&str, String)],
) -> Result<&'a Sample, String> {
    let sample = one(exposition, INTERFACE_INFO, &[("domain", domain)])?;
    if sample.value != 1 {
        return Err(format!(
            "{INTERFACE_INFO}{{domain={domain:?}}} reports {}, and an info metric's value is \
             always 1 — everything it says is in its labels",
            sample.value
        ));
    }
    for (label, want) in expected {
        let got = sample.labels.get(*label).map(String::as_str);
        if got != Some(want.as_str()) {
            return Err(format!(
                "{INTERFACE_INFO}{{domain={domain:?}}} carries {label}={got:?} and the \
                 configuration document the image was built from says {want:?}. The labels of \
                 this family are the node's statement about its own running configuration, so a \
                 disagreement is the node reporting a configuration it is not running"
            ));
        }
    }
    // Exactly these labels and no others: an extra one would be an unbounded
    // dimension nothing in the metric inventory names.
    let mut names: Vec<&str> = sample.labels.keys().map(String::as_str).collect();
    names.sort_unstable();
    let mut wanted: Vec<&str> = expected.iter().map(|(label, _)| *label).collect();
    wanted.push("domain");
    wanted.sort_unstable();
    if names != wanted {
        return Err(format!(
            "{INTERFACE_INFO}{{domain={domain:?}}} carries labels {names:?} and the contract is \
             {wanted:?}"
        ));
    }
    Ok(sample)
}

/// Hold the filter's own counters to what the harness put on the wire, and to the
/// appliance's own second account of the same decisions.
///
/// This is the per-rule half of what makes the exposition a report about reality
/// rather than a well-formed set of numbers. It rests on one exact quantity
/// measured off the wire and two the node states about itself, which together
/// close the arithmetic.
///
/// **The accepting rule's hit counter is the forwarded-frame count.** There is one
/// `accept` rule in the policy, first match wins, and the appliance denies what
/// nothing matched — so every frame that left on a dataplane egress passed that
/// rule, and every frame that rule matched was forwarded. The harness holds a
/// socket on both ports and counted those frames itself, so this is the same
/// argument `librefirewall_forwarded_frames_total` rests on, made one level finer,
/// about a *named rule* rather than about a domain. It is also what would catch
/// the refusals being credited to the wrong rule: a policy denial counted here
/// would put this number above the wire's.
///
/// **The dropping rule's hit counter is the pipeline's own count of policy
/// denials.** The filter counts a rule's matches and the routing stage counts what
/// it discarded and why, and those are two accounts of one set of decisions taken
/// in two places — so their equality is a real cross-check even though both are
/// the appliance's. What it pins is attribution: a refusal the fallthrough made
/// has no rule to be credited to, so it must appear in
/// `route_drops{reason="no_policy_match"}` and in *neither* rule's counter.
///
/// **And the two refusals must have happened, or not, as the probe set decides.**
/// The routed probe set provokes neither — its four refusals are settled before
/// the filter is consulted — so both refusal counters must still read exactly
/// zero, which is as strong as a rise and only a set that provokes neither can
/// state. The filter set provokes one of each and both must have risen.
///
/// **The cardinality is the document's** — the one in force when the scrape was
/// taken. One series per rule it declares and not one more, each labelled with the
/// id that document gave it. A scrape from an image built around the *other* policy
/// is judged against its own document and cannot pass on this one's rule names, and
/// a scenario that submitted a document adding a rule is judged against the count
/// the submission left behind.
///
/// # Errors
/// The verdict, naming the rule and the two numbers.
fn judge_policy(
    exposition: &Exposition,
    forwarded_frames: u64,
    witness: PolicyWitness,
) -> Result<Vec<&Sample>, String> {
    let series = exposition.select(RULE_HITS, &[]);
    if series.len() != witness.rules {
        return Err(format!(
            "the exposition carries {} {RULE_HITS} series and the policy in force declares {} \
             rule(s). One series per declared rule is the whole cardinality of this family — a \
             position no rule occupies is a counter under no operator's name and must reach no \
             series\n  found: {}",
            series.len(),
            witness.rules,
            render(&series)
        ));
    }

    // The two refusal reasons, summed over the pipelines as a reader must: the
    // node publishes no total, and a check that read one pipeline would pass a
    // node that had counted the refusal on the other.
    let mut asserted = Vec::new();
    let refused = |reason: &str| -> Result<u64, String> {
        let per_pipeline = exposition.select(ROUTE_DROPS, &[("reason", reason)]);
        if per_pipeline.is_empty() {
            return Err(format!(
                "{ROUTE_DROPS}{{reason={reason:?}}} carries no series, so the filter's refusals \
                 cannot be told apart"
            ));
        }
        Ok(per_pipeline.iter().map(|sample| sample.value).sum())
    };
    let denied = refused("policy_denied")?;
    let unmatched = refused("no_policy_match")?;
    asserted.extend(exposition.select(ROUTE_DROPS, &[("reason", "policy_denied")]));
    asserted.extend(exposition.select(ROUTE_DROPS, &[("reason", "no_policy_match")]));

    // What the tracker carried **without the filter**, which is one outcome and not
    // two. An established packet is settled in front of the filter and reaches a
    // dataplane egress under a decision no rule made; a related one is put to the
    // filter like an opening — recognising it settles where it would go and never
    // whether it may — so it is counted with the openings below and never here. A
    // related packet is therefore not even evidence of a delivery: the policy may
    // have refused it, and `flow_packets_total{outcome="related"}` counts it either
    // way.
    let classified = |outcome: &str| -> Result<u64, String> {
        Ok(one(exposition, FLOW_PACKETS, &[("outcome", outcome)])?.value)
    };
    let carried_by_state = classified("established")?;
    asserted.extend(exposition.select(FLOW_PACKETS, &[("outcome", "established")]));
    asserted.extend(exposition.select(FLOW_PACKETS, &[("outcome", "related")]));
    // Frames the filter admitted: every frame that came back either belonged to an
    // established flow or was admitted by a rule.
    let opened = forwarded_frames.checked_sub(carried_by_state).ok_or_else(|| {
        format!(
            "the tracker reports {carried_by_state} packets carried by an existing flow and the \
             harness observed only {forwarded_frames} frames come back, so more was forwarded \
             under a flow than left the appliance at all"
        )
    })?;

    // Which per-rule statement is available depends on whether the boot ran one
    // policy or two. Under one, each rule's count is attributable and the two
    // statements below are the strongest available. Under two — a document
    // submitted while the node ran — the same two ids exchange their actions, so
    // each accrues hits under both generations and what stays exact is the sum.
    if witness.reconfigured {
        // Every rule the policy in force declares, and not the two port rules
        // alone: a submitted document may add one, and a frame it admitted is a
        // frame the filter decided. Summing the family is what keeps this an
        // equality over the filter's whole work rather than over a chosen pair.
        let total = series
            .iter()
            .fold(0u64, |total, sample| total.saturating_add(sample.value));
        asserted.extend(series.iter().copied());
        let expected = opened.saturating_add(denied);
        if total != expected {
            return Err(format!(
                "the rules report {total} matches between them and the contract is {expected}: \
                 the {opened} packets the FILTER ADMITTED ({forwarded_frames} frames observed \
                 less the {carried_by_state} an established flow carried) plus the {denied} the \
                 filter denied. This boot ran two policies — one it booted with and one submitted \
                 over the management API — so a rule's own count is not attributable across the \
                 commit and the sum over the family is what a filter that decided every packet \
                 exactly once must report"
            ));
        }
        // And the labels, on each of them, for the reason the single-policy path
        // states below: this family's cardinality is an operator's to set.
        for rule in [witness.policy.accepted, witness.policy.denied] {
            let id = rule.id.as_str();
            let sample = one(exposition, RULE_HITS, &[("rule", id)])?;
            let mut names: Vec<&str> = sample.labels.keys().map(String::as_str).collect();
            names.sort_unstable();
            if names != ["domain", "rule"] {
                return Err(format!(
                    "{RULE_HITS}{{rule={id:?}}} carries labels {names:?} and the contract is \
                     [\"domain\", \"rule\"]"
                ));
            }
        }
    }

    for (rule, expected, measured) in if witness.reconfigured {
        Vec::new()
    } else {
        Vec::from([
            (
                witness.policy.accepted,
                opened,
                format!(
                    "frames the harness observed coming back on its two dataplane sockets \
                 ({forwarded_frames}), less the {carried_by_state} the connection tracker carried \
                 without consulting the filter at all. What is left is the frames the FILTER \
                 ADMITTED, and every one of those passed this rule — which is the whole of what \
                 makes a stateful policy different from a stateless one: a reply is forwarded \
                 under no rule's name"
                ),
            ),
            (
                witness.policy.denied,
                denied,
                format!(
                    "policy denials the routing stage counted across its two pipelines, which is the \
                 same set of decisions this rule's matches are — {ROUTE_DROPS} and {RULE_HITS} \
                 count them in two places"
                ),
            ),
        ])
    } {
        let id = rule.id.as_str();
        let sample = one(exposition, RULE_HITS, &[("rule", id)])?;
        if sample.value != expected {
            return Err(format!(
                "{RULE_HITS}{{rule={id:?}}} reports {} and the contract is {expected}: \
                 {measured}. The label is the id the configuration document gave the rule and the \
                 count is the forwarding domain's, joined on the rule's position — so a \
                 disagreement is either the wrong rule's traffic under this rule's name or a \
                 filter that did not decide what it says it did",
                sample.value
            ));
        }
        // Exactly these labels: an extra one would be a dimension the metric
        // inventory does not name, and this family's cardinality is an
        // operator's to set.
        let mut names: Vec<&str> = sample.labels.keys().map(String::as_str).collect();
        names.sort_unstable();
        if names != ["domain", "rule"] {
            return Err(format!(
                "{RULE_HITS}{{rule={id:?}}} carries labels {names:?} and the contract is \
                 [\"domain\", \"rule\"]"
            ));
        }
        asserted.push(sample);
    }

    // Which of the filter's two outcomes this boot's probes reached at all. The
    // zero case is the routed set's and is the stronger half: it says the six
    // probes that have crossed this appliance since before it filtered are still
    // decided by admission, routing and one accepting rule, and by nothing else.
    for (what, reached, count, reason) in [
        (
            "a rule that says drop",
            witness.probed_the_denying_rule,
            denied,
            "policy_denied",
        ),
        (
            "the default deny",
            witness.probed_the_fallthrough,
            unmatched,
            "no_policy_match",
        ),
    ] {
        if reached && count == 0 {
            return Err(format!(
                "the boot injected a probe {reason:?} had to refuse and \
                 {ROUTE_DROPS}{{reason={reason:?}}} sums to zero, so {what} did not happen"
            ));
        }
        if !reached && count != 0 {
            return Err(format!(
                "{ROUTE_DROPS}{{reason={reason:?}}} sums to {count} and this boot injected \
                 nothing {what} could refuse — every probe it did inject is settled before the \
                 filter is consulted or is permitted by a rule, so a refusal here is a frame \
                 nobody put on the wire or a stage refusing in another stage's name"
            ));
        }
    }

    // The filter's own totals, against the same quantities: accepted against the
    // wire, denied against the two reasons it is the sum of. Summing is the
    // reader's job and this is a reader.
    for (labels, expected, what) in [
        (
            [("verdict", "accepted")],
            opened,
            String::from(
                "frames the harness observed forwarded, less the ones an existing flow accounted \
                 for — the filter is not consulted for those, so it counts neither of them",
            ),
        ),
        (
            [("verdict", "denied")],
            denied + unmatched,
            format!("refusals {ROUTE_DROPS} accounts for under the filter's two reasons"),
        ),
    ] {
        let sample = one(exposition, POLICY_PACKETS, &labels)?;
        if sample.value != expected {
            return Err(format!(
                "{POLICY_PACKETS}{labels:?} reports {} and the contract is {expected}: {what}",
                sample.value
            ));
        }
        asserted.push(sample);
    }
    asserted.extend(judge_flow_table(exposition, forwarded_frames, witness)?);
    Ok(asserted)
}

/// Hold the connection tracker's own account of itself together, and to the
/// wire.
///
/// Three things, and each of them is an arithmetic identity the appliance cannot
/// satisfy by accident:
///
/// **Every packet it was offered went exactly one way.** `packets_seen` is the
/// classified outcomes plus the refusals, summed over both vocabularies — so a
/// packet counted twice, or counted under no outcome at all, shows up here and
/// nowhere else.
///
/// **The table's slots sum to its capacity.** Occupancy is maintained as flows
/// move rather than scanned, so a state transition that moved a flow without
/// moving its count is a total that has drifted from the width of the array.
/// `vacant` is one of the states, which is what makes the sum a constant a
/// reader can check without a capacity series to compare against.
///
/// **It saw at least what came back.** Every frame the harness observed forwarded
/// passed through the tracker, so the packets it was offered cannot be fewer.
///
/// **Every flow it opened is either still there or accounted for by what ended
/// it.** The openings, less the flows withdrawn, expired, evicted and revoked, are
/// the flows the table is holding — and a flow that reached `Closed` or `TimeWait`
/// is *not* subtracted, because such a flow still occupies its slot until its idle
/// timeout takes it. That is the whole of what "bounded state" means as
/// arithmetic, and it is what a flood is judged by: a node that opened a slot per
/// refused connection attempt and left it behind satisfies every other identity
/// here and breaks this one.
///
/// # Errors
/// The verdict, naming the identity and the numbers that broke it.
fn judge_flow_table(
    exposition: &Exposition,
    forwarded_frames: u64,
    witness: PolicyWitness,
) -> Result<Vec<&Sample>, String> {
    let mut asserted = Vec::new();
    let seen = one(exposition, FLOW_SEEN, &[])?;

    let classified: u64 = exposition
        .select(FLOW_PACKETS, &[])
        .iter()
        .map(|sample| sample.value)
        .sum();
    let refused_series = exposition.select(FLOW_REFUSED, &[]);
    if refused_series.is_empty() {
        return Err(format!(
            "{FLOW_REFUSED} carries no series, so what the tracker turned away cannot be told \
             from what it classified"
        ));
    }
    let refused: u64 = refused_series.iter().map(|sample| sample.value).sum();
    if seen.value != classified.saturating_add(refused) {
        return Err(format!(
            "{FLOW_SEEN} reports {} and the outcomes account for {classified} classified plus \
             {refused} refused. Every packet offered to the tracker is one or the other, exactly \
             once, so a disagreement is a packet counted twice or a packet counted under nothing",
            seen.value
        ));
    }
    if seen.value < forwarded_frames {
        return Err(format!(
            "{FLOW_SEEN} reports {} and the harness observed {forwarded_frames} frames come back. \
             Every forwarded frame passed the tracker, so it cannot have seen fewer",
            seen.value
        ));
    }

    let entries = exposition.select(FLOW_ENTRIES, &[]);
    if entries.is_empty() {
        return Err(format!("{FLOW_ENTRIES} carries no series"));
    }
    let occupancy: u64 = entries.iter().map(|sample| sample.value).sum();
    if occupancy != FLOW_CAPACITY as u64 {
        return Err(format!(
            "{FLOW_ENTRIES} sums to {occupancy} over {} series and the table holds \
             {FLOW_CAPACITY} slots. `vacant` is one of the states, so the sum is the capacity \
             exactly — a smaller one is a flow whose state moved without its count",
            entries.len()
        ));
    }

    // And what this boot's probes oblige the tracker to have decided.
    //
    // The `established` half is one-directional on purpose: every set reaches it,
    // because a probe re-injected before its delivery was observed is a second
    // packet of the flow the first one opened. What the stateful set adds is a
    // packet no rule permits, so the rise is evidence rather than a side effect.
    let established = one(exposition, FLOW_PACKETS, &[("outcome", "established")])?;
    if witness.probed_an_established_flow && established.value == 0 {
        return Err(format!(
            "the boot injected a reply to a request that went first and \
             {FLOW_PACKETS}{{outcome=\"established\"}} reports zero, so nothing was carried by \
             the flow it belongs to — which is the only mechanism that could have carried it, no \
             rule of this document naming the port it is addressed to"
        ));
    }

    // The mid-stream refusal is asserted both ways: no probe in any other set is
    // a TCP segment at all, so a refusal on a boot that injected none is a frame
    // nobody put on the wire.
    let mid_stream = one(exposition, FLOW_REFUSED, &[("reason", "mid_stream")])?;
    if witness.probed_mid_stream && mid_stream.value == 0 {
        return Err(format!(
            "the boot injected a bare ACK for a five-tuple nothing opened and \
             {FLOW_REFUSED}{{reason=\"mid_stream\"}} reports zero, so the segment was adopted \
             into a flow rather than refused — which is a way around default deny that costs an \
             attacker one packet"
        ));
    }
    if !witness.probed_mid_stream && mid_stream.value != 0 {
        return Err(format!(
            "{FLOW_REFUSED}{{reason=\"mid_stream\"}} reports {} and this boot injected no TCP \
             segment at all, so the refusal is a frame nobody sent or a datagram refused under a \
             segment's reason",
            mid_stream.value
        ));
    }

    asserted.extend(judge_bounded_state(exposition, &entries, witness)?);
    asserted.push(seen);
    asserted.push(established);
    asserted.push(mid_stream);
    asserted.extend(entries);
    Ok(asserted)
}

/// Hold the table's occupancy to what opened and ended the flows in it, and — on
/// the boot that floods the appliance — to being bounded rather than growing with
/// the flood.
///
/// # The identity, which every boot owes
///
/// A flow enters the table by being opened and leaves it by being withdrawn,
/// expiring, being evicted, or being revoked. A flow that reached `Closed` or
/// `TimeWait` has *not* left: it holds its slot until its idle timeout, which is
/// why `closed` is counted and not subtracted here. So the flows the table is
/// holding are the openings less those four, exactly — and a node that opened a
/// slot per refused connection attempt and never gave one back satisfies every
/// other identity in this module and breaks this one.
///
/// # What the flood adds
///
/// The identity alone would hold on a quiet bench, so it is only evidence
/// alongside traffic that tests it. The flood set puts [`PolicyWitness`]'s
/// `flooded_tuples` distinct five-tuples across the appliance, every one of them
/// refused by the default deny, and four things then have to hold together: the
/// tracker opened at least that many flows, gave back at least that many, holds
/// *fewer* than that many, and turned no new connection away for want of room.
/// Three of the four would each be satisfied by a node that never saw the flood at
/// all; the first is what says it did.
///
/// Two of the clauses are asserted on **every** boot rather than only the flooding
/// one, because no scenario in this gate reaches the pressure that would justify
/// them moving: nothing may be evicted, and nothing may be refused for a full
/// table or a full bucket. A rise on a quiet bench is a defect wherever it happens.
///
/// # Errors
/// The verdict, naming the identity or the clause and the numbers that broke it.
fn judge_bounded_state<'a>(
    exposition: &'a Exposition,
    entries: &[&'a Sample],
    witness: PolicyWitness,
) -> Result<Vec<&'a Sample>, String> {
    let vacant = entries
        .iter()
        .find(|sample| sample.labels.get("state").map(String::as_str) == Some(VACANT))
        .ok_or_else(|| {
            format!(
                "{FLOW_ENTRIES}{{state=\"{VACANT}\"}} is not in the exposition, so how much of the \
                 table is left is not published and nothing about bounded state can be stated"
            )
        })?;
    let held = (FLOW_CAPACITY as u64)
        .checked_sub(vacant.value)
        .ok_or_else(|| {
            format!(
                "{FLOW_ENTRIES}{{state=\"{VACANT}\"}} reports {} slots free of a table that holds \
             {FLOW_CAPACITY}",
                vacant.value
            )
        })?;

    let opened = one(exposition, FLOW_PACKETS, &[("outcome", "new")])?;
    let mut ended = Vec::new();
    let mut left = 0u64;
    for event in ["withdrawn", "expired", "evicted", "revoked"] {
        let sample = one(exposition, FLOW_LIFECYCLE, &[("event", event)])?;
        // Nothing in this gate reaches the pressure that justifies an eviction,
        // and an assured conversation may never be the flow taken — so a rise
        // here is either a table that leaked slots or an eviction rule reaching a
        // flow it may not.
        if event == "evicted" && sample.value != 0 {
            return Err(format!(
                "{FLOW_LIFECYCLE}{{event=\"evicted\"}} reports {}, so a flow was taken back to \
                 make room for another. No scenario in this gate injects enough distinct \
                 five-tuples to reach that pressure",
                sample.value
            ));
        }
        left = left.saturating_add(sample.value);
        ended.push(sample);
    }
    if held.saturating_add(left) != opened.value {
        return Err(format!(
            "the tracker reports {} flow(s) opened and the table holds {held} with {left} \
             withdrawn, expired, evicted or revoked. A flow enters the table by being opened and \
             leaves it those four ways alone — a close leaves it holding its slot until the idle \
             timeout, which is why `closed` is not among them — so a disagreement is a slot \
             leaked or a slot returned twice",
            opened.value
        ));
    }
    let mut turned_away = Vec::new();
    for reason in ["table_full", "bucket_full"] {
        let sample = one(exposition, FLOW_REFUSED, &[("reason", reason)])?;
        if sample.value != 0 {
            return Err(format!(
                "{FLOW_REFUSED}{{reason={reason:?}}} reports {}, so a new connection was turned \
                 away for want of room. No scenario in this gate injects enough distinct \
                 five-tuples to fill a {FLOW_CAPACITY}-slot table, so this is a table holding \
                 flows nothing gave back rather than a table that is genuinely full",
                sample.value
            ));
        }
        turned_away.push(sample);
    }

    if witness.flooded_tuples > 0 {
        let flood = witness.flooded_tuples;
        if opened.value < flood {
            return Err(format!(
                "the boot flooded the appliance with {flood} distinct five-tuples and the tracker \
                 reports {} flow(s) opened, so the burst did not reach the table and every \
                 statement below it is about a bench nothing flooded",
                opened.value
            ));
        }
        if left < flood {
            return Err(format!(
                "the boot flooded the appliance with {flood} distinct five-tuples the default \
                 deny refuses and only {left} flow(s) left the table. Every refused opening must \
                 be given back in the evaluation that refused it, or a default-deny policy is a \
                 state-exhaustion amplifier: an attacker fills the table with connections the \
                 policy has already refused"
            ));
        }
        if held >= flood {
            return Err(format!(
                "the table holds {held} flow(s) after a flood of {flood} distinct five-tuples, so \
                 its occupancy grew with the burst rather than staying bounded by the \
                 conversations the policy admits"
            ));
        }
    }

    let mut asserted = vec![vacant, opened];
    asserted.extend(ended);
    asserted.extend(turned_away);
    Ok(asserted)
}

fn dotted(address: [u8; 4]) -> String {
    let [a, b, c, d] = address;
    format!("{a}.{b}.{c}.{d}")
}

fn colons(mac: [u8; 6]) -> String {
    let [a, b, c, d, e, f] = mac;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

/// Judge two consecutive scrapes, and cross-check one of their values against
/// traffic the harness observed itself.
///
/// Returns the evidence — the command, the status line, the matched headers and
/// the asserted metric lines — so a caller can print it verbatim and write it
/// beside the run log.
///
/// # Errors
/// The verdict, naming the field and the two values.
pub fn judge(
    scrapes: &[Scrape],
    booted_for: Duration,
    forwarded_frames: u64,
    witness: PolicyWitness,
    topology: &Topology,
) -> Result<String, String> {
    let [first, second] = scrapes else {
        return Err(format!(
            "the scenario took {} scrapes and the contract is stated over two: the second is \
             what carries the first's request and response",
            scrapes.len()
        ));
    };
    // Both must be answered, and the first identically to the second: a node
    // that answered one scrape and refused the next has a buffer it does not
    // release.
    judge_one(first, forwarded_frames, witness, topology)?;
    let judged = judge_one(second, forwarded_frames, witness, topology)?;
    let exposition = parse(&second.body)?;
    let requests = one(&exposition, "librefirewall_http_requests_total", &[])?;
    if requests.value < 2 {
        return Err(format!(
            "the second scrape reports {} HTTP requests and two have been made; a request is \
             counted as its head completes and the shard is published before the body is \
             rendered, so a scrape carries its own request",
            requests.value
        ));
    }
    let ok = one(
        &exposition,
        "librefirewall_http_responses_total",
        &[("status", Status::Ok.token())],
    )?;
    if ok.value < 1 {
        return Err(String::from(
            "the second scrape reports no 200 response and the first one was answered 200",
        ));
    }
    let bytes = one(&exposition, "librefirewall_http_response_bytes_total", &[])?;
    if bytes.value < first.body.len() as u64 {
        return Err(format!(
            "the second scrape reports {} response bytes and the first response alone was {}",
            bytes.value,
            first.body.len()
        ));
    }
    let refused = one(
        &exposition,
        "librefirewall_http_responses_total",
        &[("status", Status::ServiceUnavailable.token())],
    )?;
    if refused.value > 0 {
        return Err(format!(
            "the endpoint refused {} scrapes with 503, so its one staging buffer is not being \
             released between connections",
            refused.value
        ));
    }
    let ticks = judge_ticks(booted_for, first, second)?;
    Ok(format!(
        "{judged}\n{}\n  {ticks}",
        render(&[requests, ok, bytes, refused])
    ))
}

/// The appliance's periodic wakeup, judged from the outside.
///
/// **The counter being non-zero is the load-bearing half.** Nothing in this
/// system asks the clock domain for anything — it is woken by its own timer and
/// by nothing else — so a count above zero is a wakeup that happened on time
/// rather than on traffic, which is the whole property the schedules built on it
/// depend upon. A node whose timer could not be armed reports zero for ever, and
/// says why on its console.
///
/// **The ceiling beside it is what catches a shared interrupt input**, which is
/// a fault no other surface shows: the handler counts another device's
/// interrupts as its own, every schedule runs fast by whatever that device does,
/// and nothing anywhere is in an error state. It was found exactly this way, on
/// an input that looked free and carried the platform's interval timer. The
/// count is held against the time since QEMU started — an upper bound on the
/// appliance's uptime — so it costs the run nothing and asserts only in the
/// direction where an honest appliance has no headroom at all: a periodic
/// comparator cannot fire faster than the accumulator it was armed with.
///
/// The two scrapes are taken back to back, so nothing is stated about the
/// difference between them: at ten wakeups a second and a gap of milliseconds,
/// a counter that has not moved is an appliance behaving perfectly.
fn judge_ticks(booted_for: Duration, first: &Scrape, second: &Scrape) -> Result<String, String> {
    let before = one(&parse(&first.body)?, "librefirewall_clock_ticks_total", &[])?.value;
    let after = one(
        &parse(&second.body)?,
        "librefirewall_clock_ticks_total",
        &[],
    )?
    .value;
    if after < before {
        return Err(format!(
            "the periodic wakeup counted {after} on the second scrape and {before} on the first, \
             so a counter that only rises went backwards"
        ));
    }
    if after == 0 {
        return Err(String::from(
            "the appliance reports no periodic wakeup at all, so nothing is waking the domain \
             that holds this node's schedules: its reconnection backoff, its acknowledgement \
             cadence and its upstream flush would all advance only when a frame happened to \
             arrive. The clock domain's console record says whether it could arm its timer",
        ));
    }
    let ceiling = booted_for.as_secs() * pd_runtime::TICKS_PER_SECOND;
    if after > ceiling {
        return Err(format!(
            "the appliance reports {after} periodic wakeup(s) and its timer is armed for {} a \
             second, so {ceiling} is every wakeup it could have taken in the {:.1}s this machine \
             has existed — firmware and boot included. A count above that is an interrupt input \
             shared with another device, whose interrupts this appliance is taking for its own",
            pd_runtime::TICKS_PER_SECOND,
            booted_for.as_secs_f64()
        ));
    }
    Ok(format!(
        "the periodic wakeup reports {after} against a ceiling of {ceiling} for {:.1}s of machine \
         lifetime at {} a second",
        booted_for.as_secs_f64(),
        pd_runtime::TICKS_PER_SECOND
    ))
}

/// Hold an unowned appliance's exposition to the one thing it can say about
/// traffic: that it refused all of it, for the one reason that is about the
/// appliance rather than about a frame.
///
/// **Both halves, and the zero is the stronger one.** The rise says the frames the
/// harness injected were counted; the zeroes say nothing reached any later stage —
/// no TTL was consulted, no route resolved, no rule matched — which is what
/// "settled in front of admission" means and is the only place in this gate where
/// it can be read. A node that refused these frames for want of a route would
/// satisfy a check that only looked for the rise.
///
/// The rise is not held to a *number*. A probe owed a refusal is injected as often
/// as the settle window allows, so how many times the appliance refused it is the
/// harness's pacing rather than the appliance's contract — the same reason the
/// filter's own refusal counters are asserted as whether and not as how many.
///
/// # Errors
/// The verdict, naming the reason and what it reported.
fn judge_unowned_refusals(exposition: &Exposition) -> Result<Vec<&Sample>, String> {
    const UNOWNED: &str = "unowned";
    let refused = |reason: &str| -> Result<u64, String> {
        let series = exposition.select(ROUTE_DROPS, &[("reason", reason)]);
        if series.is_empty() {
            return Err(format!(
                "{ROUTE_DROPS}{{reason={reason:?}}} carries no series, so an appliance that \
                 refused everything cannot be told from one that refused nothing"
            ));
        }
        Ok(series.iter().map(|sample| sample.value).sum())
    };
    if refused(UNOWNED)? == 0 {
        return Err(format!(
            "this boot's appliance has no owner and the harness injected frames it therefore had \
             to refuse, and {ROUTE_DROPS}{{reason={UNOWNED:?}}} sums to zero across the \
             pipelines. Either the frames never reached the forwarding domain, or it forwarded \
             them — and a firewall that carries traffic for a management plane that has not \
             taken it is the whole of what this reason exists to prevent"
        ));
    }
    for reason in crate::surface_contract::DROP_REASONS {
        if reason == UNOWNED {
            continue;
        }
        let counted = refused(reason)?;
        if counted != 0 {
            return Err(format!(
                "{ROUTE_DROPS}{{reason={reason:?}}} sums to {counted} on a boot whose appliance \
                 has no owner. Ownership is settled in front of admission, routing, tracking and \
                 the filter, so no frame can have reached the stage that names this reason — a \
                 count here is a stage refusing in another stage's name, or an ownership check \
                 that is not first"
            ));
        }
    }
    Ok(exposition.select(ROUTE_DROPS, &[("reason", UNOWNED)]))
}

/// Judge one scrape on its own: the head, the document, and the cross-check.
///
/// # Errors
/// The verdict, naming the field and the two values.
fn judge_one(
    scrape: &Scrape,
    forwarded_frames: u64,
    witness: PolicyWitness,
    topology: &Topology,
) -> Result<String, String> {
    let expected_status = format!("HTTP/1.1 {} {}", Status::Ok.code(), Status::Ok.reason());
    if scrape.status_line != expected_status {
        return Err(format!(
            "the endpoint answered {:?} and a scrape is owed {expected_status:?}",
            scrape.status_line
        ));
    }
    let content_type = scrape.header("content-type").unwrap_or_default();
    if content_type != METRICS_CONTENT_TYPE {
        return Err(format!(
            "the response is typed {content_type:?} and a Prometheus exposition is \
             {METRICS_CONTENT_TYPE:?}"
        ));
    }
    let stated: usize = scrape
        .header("content-length")
        .ok_or("the response carries no Content-Length")?
        .parse()
        .map_err(|error| format!("the Content-Length is no number: {error}"))?;
    if stated != scrape.body.len() {
        return Err(format!(
            "the response states a Content-Length of {stated} and carries {} body bytes",
            scrape.body.len()
        ));
    }
    let connection = scrape.header("connection").unwrap_or_default();
    if !connection.eq_ignore_ascii_case("close") {
        return Err(format!(
            "the response states Connection: {connection:?} and this server answers one request \
             and closes"
        ));
    }

    let exposition = parse(&scrape.body)?;
    for name in REQUIRED {
        if !exposition.families.contains_key(*name) {
            return Err(format!(
                "the exposition declares no {name}, so the subsystem it belongs to is not \
                 reaching the endpoint"
            ));
        }
        if exposition.select(name, &[]).is_empty() {
            return Err(format!("{name} is declared and carries no sample"));
        }
    }
    for domain in DOMAINS {
        if !exposition
            .samples
            .iter()
            .any(|sample| sample.labels.get("domain").map(String::as_str) == Some(*domain))
        {
            return Err(format!(
                "no series carries domain={domain:?}, so that protection domain's shard is not \
                 being published or not being read"
            ));
        }
    }

    // The store domain's tally, which every scraped boot has already moved: the
    // cryptography domain proves the delegation and then runs a session under the
    // delegated key before it parks, so two signatures are behind any scrape. A
    // zero here is a store shard that was published once at the end of `init` and
    // never again, which would mean the domain is not serving the delegation at
    // all — a defect this surface would otherwise be silent about, the console
    // records being the cryptography domain's rather than this domain's.
    let signatures = one(&exposition, STORE_SIGNATURES, &[("domain", "store")])?;
    if signatures.value < 2 {
        return Err(format!(
            "{STORE_SIGNATURES} reads {} and a scraped boot has at least two signatures behind \
             it — the delegation's own proof and the session that ran under the delegated key. A \
             lower value means the store domain either is not answering the delegation or is not \
             republishing its shard after it does",
            signatures.value
        ));
    }

    // The cross-check. Summed *here*, over the two labelled series, because the
    // node publishes no total on purpose.
    let per_pipeline = exposition.select(FORWARDED_FRAMES, &[]);
    if per_pipeline.len() != 2 {
        return Err(format!(
            "the exposition carries {} forwarded-frame series and the appliance has two \
             pipelines; a node that summed them itself would carry one, which the no-total rule \
             forbids: a domain restart would corrupt a summed total",
            per_pipeline.len()
        ));
    }
    let forwarded: u64 = per_pipeline.iter().map(|sample| sample.value).sum();
    let mut asserted: Vec<&Sample> = Vec::new();
    if forwarded != forwarded_frames {
        return Err(format!(
            "the appliance reports {forwarded} forwarded frames and the harness observed \
             {forwarded_frames} coming back on its two dataplane sockets. Every frame the \
             forwarder forwards leaves on one of those ports and nothing else originates on \
             them, so the two are the same quantity measured twice — and a metric that agrees \
             with itself but not with the wire is the failure this cross-check exists for.\n  \
             per-pipeline: {}",
            render(&per_pipeline)
        ));
    }
    // Two zeroes prove nothing about forwarding — unless forwarding nothing is the
    // whole claim, which is what an appliance with no owner owes. Then the
    // statement moves to the refusals, where it is a rise under one reason and a
    // zero under all the others, and the two zeroes above are half of it: the
    // appliance and the wire agree that nothing crossed.
    if witness.unowned {
        asserted.extend(judge_unowned_refusals(&exposition)?);
    } else {
        if forwarded == 0 {
            return Err(String::from(
                "the appliance reports no forwarded frame and the harness observed none, so the \
                 cross-check compared two zeroes and proved nothing about either",
            ));
        }
        // And the mirror of it on a boot that did carry traffic: this appliance
        // has an owner, so the refusal that is about ownership must never have
        // been reached. The latch is what makes that sayable — a reader that
        // mirrored the word could be walked back to refusing mid-boot by the peer
        // that writes it, and the frames after that would land here.
        let ownership_refusals: u64 = exposition
            .select(ROUTE_DROPS, &[("reason", "unowned")])
            .iter()
            .map(|sample| sample.value)
            .sum();
        if ownership_refusals != 0 {
            return Err(format!(
                "{ROUTE_DROPS}{{reason=\"unowned\"}} sums to {ownership_refusals} on a boot \
                 whose appliance has an owner and which forwarded {forwarded} frame(s). The \
                 forwarding domain latches the first owned reading it sees, so a refusal here is \
                 either a frame decided before the domain that holds the identity had published \
                 anything, or a reader that can be walked back to forwarding nothing by the peer \
                 that writes the word"
            ));
        }
        asserted.extend(exposition.select(ROUTE_DROPS, &[("reason", "unowned")]));
    }

    asserted.extend(per_pipeline);
    asserted.push(signatures);
    // Beside it, the same traffic seen from the drivers: the two dataplane
    // ports' transmit totals must sum to the same number, which is the same
    // claim made by three different domains.
    let transmitted: Vec<&Sample> = ["nic_driver0", "nic_driver1"]
        .iter()
        .flat_map(|domain| {
            exposition.select("librefirewall_transmit_frames_total", &[("domain", domain)])
        })
        .collect();
    let transmitted_total: u64 = transmitted.iter().map(|sample| sample.value).sum();
    if transmitted_total != forwarded_frames {
        return Err(format!(
            "the two dataplane drivers report {transmitted_total} transmitted frames and the \
             harness observed {forwarded_frames}; the forwarder and its drivers count the same \
             frames one hop apart\n  per-driver: {}",
            render(&transmitted)
        ));
    }
    asserted.extend(transmitted);

    // And the endpoint's own view of the connection carrying this very scrape:
    // the request has been counted, because it is counted as the head completes
    // and the shard is published before the body is rendered.
    let requests = one(&exposition, "librefirewall_http_requests_total", &[])?;
    if requests.value == 0 {
        return Err(String::from(
            "the endpoint reports no HTTP request, having just answered one",
        ));
    }
    // Named down to the transport, because the management port carries two and
    // only one of them is under the server that answered this scrape. The
    // onboarding port's stack is quiet on a boot with no administrator on it, so
    // a selection that matched both would find two series and — if it took the
    // sum — would let a silent HTTP stack pass on the other's numbers.
    let segments = one(
        &exposition,
        "librefirewall_tcp_segments_total",
        &[("service", "http"), ("direction", "received")],
    )?;
    if segments.value == 0 {
        return Err(String::from(
            "the transport under the HTTP server reports no segment received, having just carried \
             a connection",
        ));
    }
    asserted.push(requests);
    asserted.push(segments);

    // And what the node says each of its ports *is*, against the document it was
    // built from. Last, because it is the one assertion that reads the appliance's
    // own statement of its configuration rather than a count of its traffic.
    asserted.extend(judge_interfaces(&exposition, topology)?);
    asserted.extend(judge_policy(&exposition, forwarded_frames, witness)?);

    Ok(format!(
        "{} families and {} series scraped with curl; {forwarded} forwarded frames reported and \
         {forwarded_frames} observed on the wire",
        exposition.families.len(),
        exposition.samples.len(),
    ) + &format!("\n{}", render(&asserted)))
}

/// The recorder's own count of what it encoded into one sink, read out of an
/// exposition body.
///
/// Exposed for [`crate::surface_contract`], which holds it against the packet
/// blocks the same boot's download actually carried. It is a function of the
/// body alone so that judgement stays pure: the parse is here, where the
/// exposition format lives, and the comparison is there, where the disagreement
/// between surfaces is stated.
///
/// # Errors
/// A body that is not an exposition, or one that carries no single
/// `librefirewall_recording_records_total` for that sink.
pub fn sink_records(body: &str, sink: &str) -> Result<u64, String> {
    let exposition = parse(body)?;
    one(
        &exposition,
        "librefirewall_recording_records_total",
        &[("sink", sink)],
    )
    .map(|sample| sample.value)
}

/// What `librefirewall_route_drops_total` reports for `reason`, summed over the
/// pipelines as a reader must — the node publishes no total, so a check that read
/// one pipeline would pass a node that counted the refusal on the other.
///
/// `None` where the family carries no series under that reason at all, which is a
/// reason the exposition does not know rather than one that has stayed at zero.
///
/// Exported for [`crate::surface_contract`], where the recordings' own account of
/// a refusal is held to this one. The exposition parser lives here.
///
/// # Errors
/// A body that is not an exposition.
pub fn drop_reason_total(body: &str, reason: &str) -> Result<Option<u64>, String> {
    let exposition = parse(body)?;
    let series = exposition.select(ROUTE_DROPS, &[("reason", reason)]);
    if series.is_empty() {
        return Ok(None);
    }
    Ok(Some(series.iter().map(|sample| sample.value).sum()))
}

/// What `librefirewall_rule_hits_total` reports for the rule the document calls
/// `id`, or `None` where no series carries that id.
///
/// # Errors
/// A body that is not an exposition.
pub fn rule_hits(body: &str, id: &str) -> Result<Option<u64>, String> {
    let exposition = parse(body)?;
    let series = exposition.select(RULE_HITS, &[("rule", id)]);
    match series.as_slice() {
        [] => Ok(None),
        samples => Ok(Some(samples.iter().map(|sample| sample.value).sum())),
    }
}

/// What `librefirewall_forwarded_frames_total` reports, summed over the
/// pipelines.
///
/// # Errors
/// A body that is not an exposition, or one carrying no such family.
pub fn forwarded_frames_total(body: &str) -> Result<u64, String> {
    let exposition = parse(body)?;
    let series = exposition.select(FORWARDED_FRAMES, &[]);
    if series.is_empty() {
        return Err(format!(
            "the exposition carries no {FORWARDED_FRAMES}, so the recordings' own count of \
             forwarded observations has nothing to be held to"
        ));
    }
    Ok(series.iter().map(|sample| sample.value).sum())
}

/// What one shard reports for the medium under it, in sectors.
///
/// # Errors
/// An exposition carrying no such series, or more than one.
pub fn capacity_sectors(body: &str, domain: &str) -> Result<u64, String> {
    one_value(
        body,
        "librefirewall_block_capacity_sectors",
        &[("domain", domain)],
    )
}

/// The one sample of `name` carrying `labels`, as a number.
///
/// The general form the two helpers above are special cases of, for a caller
/// naming a series this module has no reason to know about — the snapshot
/// contract names several, and a function per series would be a second copy of
/// the catalogue.
///
/// # Errors
/// An exposition where the labels match no series, or more than one.
pub fn one_value(body: &str, name: &str, labels: &[(&str, &str)]) -> Result<u64, String> {
    let exposition = parse(body)?;
    one(&exposition, name, labels).map(|sample| sample.value)
}

/// The one sample of `name` matching `labels`, or a verdict naming what was
/// found instead.
fn one<'a>(
    exposition: &'a Exposition,
    name: &str,
    labels: &[(&str, &str)],
) -> Result<&'a Sample, String> {
    let found = exposition.select(name, labels);
    match found.as_slice() {
        [sample] => Ok(sample),
        other => Err(format!(
            "{name}{labels:?} matched {} series and the contract names exactly one",
            other.len()
        )),
    }
}

/// The asserted samples as the lines they came off the wire as, for the evidence
/// a run log carries.
fn render(samples: &[&Sample]) -> String {
    samples
        .iter()
        .map(|sample| {
            let labels: Vec<String> = sample
                .labels
                .iter()
                .map(|(key, value)| format!("{key}=\"{value}\""))
                .collect();
            format!(
                "    {}{{{}}} {}",
                sample.name,
                labels.join(","),
                sample.value
            )
        })
        .collect::<Vec<String>>()
        .join("\n")
}

/// The evidence one scrape leaves, verbatim: the command, the status line, the
/// headers that were matched, and the metric lines that were asserted.
///
/// Printed into the gate's output and written beside the run log, so the proof
/// is legible rather than implied by a passing test.
pub fn evidence(scrapes: &[Scrape], judged: &str) -> String {
    let mut lines = Vec::new();
    for (index, scrape) in scrapes.iter().enumerate() {
        lines.push(format!("  scrape {} of {}:", index + 1, scrapes.len()));
        lines.push(format!("  $ {}", scrape.command));
        lines.push(format!("  {}", scrape.status_line));
        for name in ["Content-Type", "Content-Length", "Connection"] {
            if let Some(value) = scrape.header(name) {
                lines.push(format!("  {name}: {value}"));
            }
        }
        lines.push(format!("  ({} body bytes)", scrape.body.len()));
    }
    for line in judged.lines() {
        lines.push(format!("  {line}"));
    }
    lines.join("\n")
}

fn truncate(text: &str) -> &str {
    text.get(..200).unwrap_or(text)
}

#[cfg(test)]
mod tests;
