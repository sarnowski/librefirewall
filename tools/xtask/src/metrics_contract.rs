//! The `GET /metrics` contract, fetched with a real client and judged as fields.
//!
//! This is the one scenario where nothing the harness composed is on the wire.
//! `curl` opens a TCP connection to the management endpoint through QEMU's own
//! user-mode stack, and what comes back is judged here: the status line, the
//! headers, and a body this module **parses** as Prometheus exposition rather
//! than searching for substrings in (TEST-13).
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
//! The appliance exposes one series per `pipeline` and computes no total, for
//! the reason MONITORING.md records: a summed total is corrupted by a domain
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

/// How long `curl` may take, end to end. Generous because the guest may be
/// running under TCG on a loaded runner and the response spans twenty segments,
/// each of which the appliance sends only when a frame wakes it.
const SCRAPE_TIMEOUT: Duration = Duration::from_secs(60);

/// Metric families the scrape must carry, one per subsystem this change made
/// observable. Deliberately not the whole catalogue — `lfw_metrics`' own tests
/// hold that to itself — but one name from each shard kind, so a shard that
/// stopped being published fails here.
const REQUIRED: &[&str] = &[
    "librefirewall_forwarded_frames_total",
    "librefirewall_route_drops_total",
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

/// Judge two consecutive scrapes, and cross-check one of their values against
/// traffic the harness observed itself.
///
/// Returns the evidence — the command, the status line, the matched headers and
/// the asserted metric lines — so a caller can print it verbatim and write it
/// beside the run log.
///
/// # Errors
/// The verdict, naming the field and the two values.
pub fn judge(scrapes: &[Scrape], forwarded_frames: u64) -> Result<String, String> {
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
    judge_one(first, forwarded_frames)?;
    let judged = judge_one(second, forwarded_frames)?;
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
fn judge_one(scrape: &Scrape, forwarded_frames: u64) -> Result<String, String> {
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
             pipelines; a node that summed them itself would carry one, which is what \
             MONITORING.md's no-total rule forbids",
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

    Ok(format!(
        "{} families and {} series scraped with curl; {forwarded} forwarded frames reported and \
         {forwarded_frames} observed on the wire",
        exposition.families.len(),
        exposition.samples.len(),
    ) + &format!("\n{}", render(&asserted)))
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
