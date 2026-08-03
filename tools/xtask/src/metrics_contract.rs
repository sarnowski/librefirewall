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
];

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
/// **The cardinality is the document's.** One series per rule the document
/// declares and not one more, each labelled with the id the document gave it. A
/// scrape from an image built around the *other* policy is judged against its own
/// document and cannot pass on this one's rule names.
///
/// # Errors
/// The verdict, naming the rule and the two numbers.
fn judge_policy(
    exposition: &Exposition,
    forwarded_frames: u64,
    witness: PolicyWitness,
) -> Result<Vec<&Sample>, String> {
    let series = exposition.select(RULE_HITS, &[]);
    if series.len() != 2 {
        return Err(format!(
            "the exposition carries {} {RULE_HITS} series and the document declares two rules. \
             One series per declared rule is the whole cardinality of this family — a position no \
             rule occupies is a counter under no operator's name and must reach no series\n  \
             found: {}",
            series.len(),
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

    for (rule, expected, measured) in [
        (
            witness.policy.accepted,
            forwarded_frames,
            String::from(
                "frames the harness observed coming back on its two dataplane sockets, every one \
                 of which passed this rule",
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
    ] {
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
            forwarded_frames,
            String::from("frames the harness observed forwarded"),
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
    Ok(format!(
        "{judged}\n{}",
        render(&[requests, ok, bytes, refused])
    ))
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

    // The cross-check. Summed *here*, over the two labelled series, because the
    // node publishes no total on purpose.
    let per_pipeline = exposition.select("librefirewall_forwarded_frames_total", &[]);
    if per_pipeline.len() != 2 {
        return Err(format!(
            "the exposition carries {} forwarded-frame series and the appliance has two \
             pipelines; a node that summed them itself would carry one, which the no-total rule \
             forbids: a domain restart would corrupt a summed total",
            per_pipeline.len()
        ));
    }
    let forwarded: u64 = per_pipeline.iter().map(|sample| sample.value).sum();
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
    if forwarded == 0 {
        return Err(String::from(
            "the appliance reports no forwarded frame and the harness observed none, so the \
             cross-check compared two zeroes and proved nothing about either",
        ));
    }

    let mut asserted: Vec<&Sample> = per_pipeline;
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
    let segments = one(
        &exposition,
        "librefirewall_tcp_segments_total",
        &[("direction", "received")],
    )?;
    if segments.value == 0 {
        return Err(String::from(
            "the transport reports no segment received, having just carried a connection",
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
