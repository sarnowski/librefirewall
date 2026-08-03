//! The `POST /config` and `GET /config` contract, driven with a real client
//! against a running node and judged as fields.
//!
//! This is the one scenario that changes what the appliance is doing. Everything
//! else in the gate observes a node built around a document; this one boots a node
//! around one document, hands it another over HTTP, and holds the *dataplane* to
//! having reversed its verdict because of it. `curl` opens the connections through
//! QEMU's own user-mode stack, as [`crate::metrics_contract`] does, so nothing on
//! the wire is composed here.
//!
//! # What the four exchanges are for
//!
//! 1. **`GET /config` before anything** — the node states the document it booted
//!    with. Held to being a document this appliance would itself accept and to
//!    naming the shipped policy, which is what makes the read the first step of a
//!    change rather than a curiosity.
//! 2. **`POST /config` with the swapped policy** — answered `200` and one line of
//!    the console's own vocabulary, naming the generation it assigned. Held to
//!    assigning generation 2, because a node that answered `unchanged` would have
//!    committed nothing and every later assertion would be about the old policy.
//! 3. **`GET /config` after it** — the node states the *new* document. This is
//!    what says the commit reached the datastore rather than only the wire.
//! 4. **`POST /config` with a malformed document** — answered `400` and a
//!    `rejected=` token from the reject vocabulary, with the generation unmoved.
//!    The fail-closed half: a refusal must change nothing, and the only way to
//!    show that is to have something to lose.
//!
//! # Why the dataplane is waited for and not assumed
//!
//! The configuration domain answers a submission when *it* has committed; the
//! forwarding domain switches tables at its next poll boundary, which is the whole
//! point of the two-phase handover. So the scenario polls `/metrics` until the
//! forwarder's own `librefirewall_configuration_generation` reaches the committed
//! number, and only then injects the traffic whose verdict must have reversed. A
//! harness that injected immediately would be racing a protocol built to avoid
//! exactly that race, and would fail intermittently for the right reason and the
//! wrong evidence.
//!
//! # No adversary
//!
//! As [`crate::metrics_contract`]: this reads and writes the appliance's own
//! management surface on a wire only the harness is attached to. That the surface
//! has no authentication at all is what makes it reachable here — and is a
//! recorded deviation from the design, not a property to rely on.

use std::process::Command;
use std::time::{Duration, Instant};

use lfw_http::Status;

/// How long a `curl` may take, end to end. [`crate::metrics_contract`]'s budget,
/// for its reasons: the guest may be under TCG on a loaded runner.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the forwarding domain has to pick a committed generation up.
///
/// Generous, and bounded: it switches between two polls and is woken by the
/// configuration domain's notification, so a node that has not switched inside
/// this has not switched at all — which is the finding, reported as the generation
/// it is still on rather than as a timeout that says nothing.
const SWITCH_GRACE: Duration = Duration::from_secs(60);

/// The gauge the forwarding domain publishes its own generation under.
const GENERATION: &str = "librefirewall_configuration_generation";

/// What the deciding domain says it has decided, which is the independent half of
/// every claim below: the HTTP answer is one domain's account of a submission and
/// this is the same domain's account of it in a different place, joined on nothing
/// but having happened.
const SUBMISSIONS: &str = "librefirewall_configuration_submissions_total";
const READS: &str = "librefirewall_configuration_reads_total";

/// The document a **reconfiguration** scenario submits, compiled in rather than
/// read at run time.
///
/// `image::SUBMITTED_DOCUMENT` names the same file for the fast gate's sake — every
/// document in the tree goes through `config::load` there — and this is the copy the
/// scenario actually sends. Two references to one file rather than a path resolved
/// twice: a scenario that submitted a document the gate had not read would be the
/// hole that list closes.
pub const SUBMITTED: &[u8] = include_bytes!("../scenarios/reconfiguration-swap.xml");

/// The document a **revocation** scenario submits, on [`SUBMITTED`]'s terms:
/// `image::NARROWED_DOCUMENT` names the same file for the fast gate.
pub const NARROWED: &[u8] = include_bytes!("../scenarios/revocation-narrow.xml");

/// The gauge the connection table publishes its occupancy under, one series per
/// state.
const TABLE_ENTRIES: &str = "librefirewall_flow_table_entries";

/// What ended a flow, one series per cause.
const FLOW_LIFECYCLE: &str = "librefirewall_flow_lifecycle_total";

/// The passes over the connection table a commit arms, one series per outcome.
const POLICY_SWEEP: &str = "librefirewall_policy_sweep_total";

/// 1 while a commit's pass is still owed.
const POLICY_SWEEP_RUNNING: &str = "librefirewall_policy_sweep_running";

/// What the submission surface answered, and what the node said about itself
/// around it. Returned so the scenario can print it as evidence.
#[derive(Clone, Debug)]
pub struct Applied {
    /// The document the node stated before the change.
    pub before: String,
    /// The line `POST /config` answered with.
    pub answer: String,
    /// The generation the answer named.
    pub generation: u32,
    /// The document the node stated after the change.
    pub after: String,
    /// The line the malformed submission was refused with.
    pub refusal: String,
    /// The generation still running after that refusal.
    pub unmoved: u32,
}

impl Applied {
    /// The transcript a reader wants beside a scenario's verdict.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "  configuration submitted over HTTP and in force on the dataplane:\n\
             \x20   GET  /config before -> {} bytes, the document this node booted with\n\
             \x20   POST /config        -> 200 {}\n\
             \x20   GET  /config after  -> {} bytes, the document it now states\n\
             \x20   POST /config (bad)  -> 400 {}\n\
             \x20   the forwarding domain reports generation {}, which the refusal left it on",
            self.before.len(),
            self.answer,
            self.after.len(),
            self.refusal,
            self.unmoved,
        )
    }
}

/// One HTTP exchange's answer, split into what a contract judges.
#[derive(Clone, Debug)]
pub struct Answered {
    pub command: String,
    pub status: u16,
    pub body: String,
}

/// Run one `curl` and split what came back.
///
/// # Errors
/// A `curl` that could not be started, one that failed, or an answer that is not
/// an HTTP message.
fn request(
    host_port: u16,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
) -> Result<Answered, String> {
    let url = format!("http://127.0.0.1:{host_port}{target}");
    let mut arguments: Vec<String> = [
        "--silent",
        "--show-error",
        "--http1.1",
        "--include",
        "--max-time",
        // A string rather than the constant's `Debug`, so the printed command is
        // the command.
        "60",
        "--request",
        method,
    ]
    .iter()
    .map(|argument| (*argument).to_owned())
    .collect();
    debug_assert_eq!(REQUEST_TIMEOUT.as_secs(), 60);
    let document = body.map(|bytes| String::from_utf8_lossy(bytes).into_owned());
    if let Some(document) = &document {
        // `--data-binary` rather than `--data`: the latter strips newlines, which
        // would submit a document the harness did not author.
        arguments.push("--data-binary".to_owned());
        arguments.push(document.clone());
        // `curl` would otherwise announce a form encoding for a document that is
        // XML. Nothing in this appliance reads the type, and a header a client
        // must not have to send is one this harness must not depend on either —
        // it is set because a truthful request is what an operator would make.
        arguments.push("--header".to_owned());
        arguments.push("Content-Type: application/xml".to_owned());
        // And `Expect: 100-continue`, which curl adds for a body above 1 KiB and
        // this server does not implement, is suppressed: a client waiting for a
        // continuation nobody sends would stall for a second before sending the
        // body anyway, and the wait is not what is under test.
        arguments.push("--header".to_owned());
        arguments.push("Expect:".to_owned());
    }
    arguments.push(url);
    let command = format!("curl {}", arguments.join(" "));

    let output = Command::new("curl")
        .args(&arguments)
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
    let (head, body) = answered
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("`{command}` answered no HTTP head: {answered:?}"))?;
    let status_line = head
        .split("\r\n")
        .next()
        .ok_or_else(|| format!("`{command}` answered an empty head"))?;
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("`{command}` answered {status_line:?}, which names no status"))?;
    Ok(Answered {
        command,
        status,
        body: body.to_owned(),
    })
}

/// Submit `document` to a running node and hold every step of the transaction to
/// its contract, leaving the node running the submitted policy.
///
/// `booted_with` is the document the image under test was built from, so the read
/// before the change is judged against the node's own boot configuration rather
/// than against a literal. What is submitted is [`SUBMITTED`].
///
/// # Errors
/// The verdict, naming which exchange failed and what it answered.
pub fn apply(host_port: u16, booted_with: &[u8], document: &[u8]) -> Result<Applied, String> {
    let before = state(host_port, "before the change")?;
    // The node's own statement of what it booted with must be a document this
    // appliance would accept, and must be the *same configuration* as the file the
    // image was built from — not the same bytes, which it deliberately is not: the
    // answer is a rendering of the model in force.
    let booted = config::load(booted_with).map_err(|error| {
        format!("the document this image was built from does not read: {error:?}")
    })?;
    let stated = config::load(before.as_bytes()).map_err(|error| {
        format!(
            "the node stated a document it would not itself accept ({error:?}), so `GET /config` \
             is not the first step of a change:\n{before}"
        )
    })?;
    if !booted.has_same_content(&stated) {
        return Err(format!(
            "the node states a configuration that is not the one it booted with, so `GET /config` \
             is reporting something other than what is in force:\n{before}"
        ));
    }

    let answered = request(host_port, "POST", "/config", Some(document))?;
    if answered.status != Status::Ok.code() {
        return Err(format!(
            "`{}` answered {} rather than {}, so the document was not committed: {:?}",
            answered.command,
            answered.status,
            Status::Ok.code(),
            answered.body
        ));
    }
    let answer = answered.body.trim_end().to_owned();
    let generation = field(&answer, "generation")
        .ok_or_else(|| format!("the commit answered {answer:?}, which names no generation"))?;
    let outcome = token(&answer, "outcome");
    if outcome.as_deref() != Some("applied") {
        return Err(format!(
            "the commit answered {answer:?}: a submission that changed nothing leaves every \
             later assertion here about the previous policy"
        ));
    }
    if generation < 2 {
        return Err(format!(
            "the commit answered generation {generation}, and a node that booted a document is \
             already on 1: {answer:?}"
        ));
    }

    // The datastore's own account of the change, read back through the surface an
    // operator edits with. It must be the document that was submitted — as a
    // configuration, again, rather than byte for byte.
    let after = state(host_port, "after the change")?;
    let submitted = config::load(document)
        .map_err(|error| format!("the document this scenario submits does not read: {error:?}"))?;
    let running = config::load(after.as_bytes()).map_err(|error| {
        format!("the node states a document it would not itself accept ({error:?}):\n{after}")
    })?;
    if !submitted.has_same_content(&running) {
        return Err(format!(
            "the node committed generation {generation} and states a different configuration, so \
             the commit and the read disagree about what is running:\n{after}"
        ));
    }

    // And the fail-closed half, with something to lose: a malformed document must
    // be refused with a reason and must move nothing.
    let refusal = refuse(host_port, generation)?;

    // Only now is the dataplane waited for. The configuration domain answered when
    // *it* committed; the forwarding domain switches between two polls, and the
    // traffic whose verdict must reverse may not be injected before it has.
    let unmoved = await_dataplane(host_port, generation)?;

    // And the deciding domain's own account of what it has done, which no answer on
    // a connection could substitute for: two documents applied — the one this image
    // carries and the one just submitted — one refused, and two reads served.
    let exposition = crate::metrics_contract::fetch(host_port)
        .map_err(|error| format!("scraping for the configuration domain's own counts: {error}"))?
        .body;
    for (family, outcome, least) in [
        (SUBMISSIONS, Some("applied"), 2u64),
        (SUBMISSIONS, Some("refused"), 1),
        (READS, None, 2),
    ] {
        let reported = counted(&exposition, family, outcome).ok_or_else(|| {
            format!(
                "{family}{} is not in the exposition, so the domain that decided this submission \
                 publishes nothing about it",
                outcome.map_or(String::new(), |value| format!("{{outcome={value:?}}}"))
            )
        })?;
        if reported < least {
            return Err(format!(
                "{family}{} reports {reported} and at least {least} is owed: the answers on the \
                 wire said one thing about this node's submissions and the domain that decided \
                 them says another",
                outcome.map_or(String::new(), |value| format!("{{outcome={value:?}}}"))
            ));
        }
    }

    Ok(Applied {
        before,
        answer,
        generation,
        after,
        refusal,
        unmoved,
    })
}

/// What the re-decision a commit armed did, as the node's own numbers report it.
#[derive(Clone, Copy, Debug)]
pub struct Revoked {
    /// Two-way UDP conversations the table held before the submission.
    pub assured_before: u64,
    /// And after the pass finished.
    pub assured_after: u64,
    /// Flows the pass took back.
    pub revoked: u64,
    /// Passes that reached the last bucket.
    pub passes: u64,
    /// Wakeups the harness had to manufacture to get there.
    pub wakeups: usize,
}

impl Revoked {
    /// The transcript a reader wants beside a scenario's verdict.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "  the commit re-decided the connection table:\n\
             \x20   two-way conversations before -> {}, after -> {}\n\
             \x20   {} flow(s) taken back, {} pass(es) over the table completed\n\
             \x20   {} wakeup(s) manufactured to work the pass off, a pass advancing per wakeup",
            self.assured_before, self.assured_after, self.revoked, self.passes, self.wakeups,
        )
    }
}

/// How many two-way UDP conversations the table holds.
///
/// The occupancy gauge's `udp_assured` series and no other: a conversation the
/// harness has seen answered is in that state, and reading one state rather than
/// summing them keeps the number independent of the transient flows a refused
/// packet opens and the appliance withdraws in the same evaluation.
///
/// # Errors
/// The verdict, where the series is absent — a node publishing no occupancy is one
/// nothing below can be stated against.
pub fn assured_flows(host_port: u16) -> Result<u64, String> {
    let exposition = crate::metrics_contract::fetch(host_port)
        .map_err(|error| format!("scraping the connection table's occupancy: {error}"))?
        .body;
    labelled(&exposition, TABLE_ENTRIES, "state", "udp_assured")
        .ok_or_else(|| format!("{TABLE_ENTRIES}{{state=\"udp_assured\"}} is not in the exposition"))
}

/// Work the re-decision a commit armed off to completion, and hold what it did to
/// its contract.
///
/// `assured_before` is [`assured_flows`] taken before the submission, so the drop in
/// occupancy is measured across the change rather than asserted against a literal.
/// `drive` is called to manufacture one wakeup — see below on why the harness has
/// to.
///
/// # Why this waits at all, and why it makes wakeups to do it
///
/// The pass is bounded per wakeup, because a commit that walked a million-slot
/// index in one go would stall forwarding for a visible interval. It therefore
/// advances only when the forwarding domain is woken, and the forwarding domain is
/// woken by frames arriving on a dataplane port — not by a scrape, which reaches
/// the management domain alone. So a harness that only polled would wait forever on
/// a node whose dataplane is quiet, which is exactly the node a scenario is.
///
/// That is not a workaround for a defect: on a running appliance the flows that
/// matter are the ones carrying traffic, and their own frames are the wakeups that
/// end them. What the harness has to supply is the traffic a quiet bench does not
/// have.
///
/// The frames it supplies are **not IPv4**, deliberately. They wake the domain and
/// reach nothing else: the router's parser refuses them before any decision, so
/// they open no flow, move no policy counter and reach neither recording — which
/// keeps the occupancy, the lifecycle counts and the two recordings the scenario
/// judges free of the harness's own pacing.
///
/// # Errors
/// The verdict, naming what the node reported: a pass that never finished, a
/// re-decision that took back nothing, or one that took back more than the single
/// conversation the submitted document stops admitting.
pub fn await_revocation(
    host_port: u16,
    assured_before: u64,
    mut drive: impl FnMut(),
) -> Result<Revoked, String> {
    /// How many wakeups the harness will manufacture before calling the pass
    /// stalled. A pass takes at most `FLOW_CAPACITY / REVISIT_BUCKETS` windows and
    /// a quiet wakeup works off several, so this is generous by a wide margin — and
    /// bounded, so a pass that is not advancing is a finding rather than a hang.
    const WAKEUPS: usize = 4_096;
    /// How often the pass's own progress is read back. Every wakeup would spend
    /// the whole budget on HTTP round trips.
    const POLL_EVERY: usize = 64;

    let deadline = Instant::now();
    let mut wakeups = 0usize;
    while wakeups < WAKEUPS && deadline.elapsed() < SWITCH_GRACE {
        for _ in 0..POLL_EVERY {
            drive();
            wakeups += 1;
        }
        let exposition = crate::metrics_contract::fetch(host_port)
            .map_err(|error| format!("scraping the re-decision's progress: {error}"))?
            .body;
        let passes =
            labelled(&exposition, POLICY_SWEEP, "outcome", "completed").ok_or_else(|| {
                format!(
                    "{POLICY_SWEEP}{{outcome=\"completed\"}} is not in the exposition, so the \
                     node publishes nothing about re-deciding its table at all"
                )
            })?;
        if passes == 0 {
            continue;
        }
        // The pass has finished, so every number below is final.
        let running = plain(&exposition, POLICY_SWEEP_RUNNING)
            .ok_or_else(|| format!("{POLICY_SWEEP_RUNNING} is not in the exposition"))?;
        if running != 0 {
            return Err(format!(
                "{POLICY_SWEEP} reports {passes} completed pass(es) and {POLICY_SWEEP_RUNNING} \
                 still reads {running}: the window a commit opens is stated by both, and they \
                 disagree about whether it is closed"
            ));
        }
        let revoked = labelled(&exposition, FLOW_LIFECYCLE, "event", "revoked").ok_or_else(|| {
            format!(
                "{FLOW_LIFECYCLE}{{event=\"revoked\"}} is not in the exposition, so nothing says \
                 a commit ever ended a conversation"
            )
        })?;
        if revoked != 1 {
            return Err(format!(
                "the commit took back {revoked} flow(s) and exactly one was owed: the submitted \
                 document narrows one accept rule by one attribute, so of the two conversations \
                 the bench opened it stops admitting one. {} would be a table flushed rather \
                 than re-decided",
                if revoked == 0 {
                    "None"
                } else {
                    "More than one"
                }
            ));
        }
        let assured_after = labelled(&exposition, TABLE_ENTRIES, "state", "udp_assured")
            .ok_or_else(|| {
                format!("{TABLE_ENTRIES}{{state=\"udp_assured\"}} is not in the exposition")
            })?;
        if assured_after >= assured_before {
            return Err(format!(
                "the table held {assured_before} two-way conversation(s) before the commit and \
                 {assured_after} after it, so the slot the revoked flow held did not come back"
            ));
        }
        return Ok(Revoked {
            assured_before,
            assured_after,
            revoked,
            passes,
            wakeups,
        });
    }
    Err(format!(
        "the forwarding domain committed the submitted generation and no pass over its connection \
         table finished after {wakeups} manufactured wakeup(s) in {}s. A pass advances one bounded \
         window per wakeup, so this is a re-decision that is not progressing rather than one that \
         is slow",
        SWITCH_GRACE.as_secs()
    ))
}

/// One counter or gauge series' value, matched on its family and one label.
fn labelled(exposition: &str, family: &str, label: &str, value: &str) -> Option<u64> {
    exposition.lines().find_map(|line| {
        let rest = line.strip_prefix(family)?;
        let (labels, reading) = rest.rsplit_once(' ')?;
        (labels.contains(&format!("{label}=\"{value}\""))
            && labels.contains("domain=\"forwarder\""))
        .then(|| reading.trim().parse().ok())?
    })
}

/// One series with no label but the domain.
fn plain(exposition: &str, family: &str) -> Option<u64> {
    exposition.lines().find_map(|line| {
        let rest = line.strip_prefix(family)?;
        let (labels, reading) = rest.rsplit_once(' ')?;
        labels
            .contains("domain=\"forwarder\"")
            .then(|| reading.trim().parse().ok())?
    })
}

/// A malformed document, refused with a reason and changing nothing.
///
/// The document is unterminated rather than semantically wrong, so the refusal is
/// the *reader's* and the reason is one an operator can act on with no knowledge
/// of this appliance's capacities.
fn refuse(host_port: u16, running: u32) -> Result<String, String> {
    const MALFORMED: &[u8] = b"<configuration><interfaces><interface id=\"broken\"";
    let answered = request(host_port, "POST", "/config", Some(MALFORMED))?;
    if answered.status != Status::BadRequest.code() {
        return Err(format!(
            "a malformed document was answered {} rather than {}: {:?}",
            answered.status,
            Status::BadRequest.code(),
            answered.body
        ));
    }
    let line = answered.body.trim_end().to_owned();
    let reason = token(&line, "rejected").ok_or_else(|| {
        format!("a refused document was answered {line:?}, which names no reason")
    })?;
    if !lfw_log::RejectReason::ALL
        .iter()
        .any(|known| known.name() == reason)
    {
        return Err(format!(
            "a refused document named `{reason}`, which is not one of the {} reasons the console \
             vocabulary carries",
            lfw_log::RejectReason::ALL.len()
        ));
    }
    if token(&line, "outcome").as_deref() != Some("refused") {
        return Err(format!("a refused document was answered {line:?}"));
    }
    match field(&line, "generation") {
        Some(named) if named == running => Ok(line),
        Some(named) => Err(format!(
            "a refused document was answered generation {named} while {running} is running, so a \
             refusal moved the configuration: {line:?}"
        )),
        None => Err(format!("a refused document was answered {line:?}")),
    }
}

/// Read the running document, holding it to being non-empty and XML.
fn state(host_port: u16, when: &str) -> Result<String, String> {
    let answered = request(host_port, "GET", "/config", None)?;
    if answered.status != Status::Ok.code() {
        return Err(format!(
            "`{}` answered {} {when}, so the node states no configuration at all: {:?}",
            answered.command, answered.status, answered.body
        ));
    }
    if !answered.body.contains("<configuration>") {
        return Err(format!(
            "`{}` answered {} bytes {when} that are not a configuration document: {:?}",
            answered.command,
            answered.body.len(),
            truncate(&answered.body)
        ));
    }
    Ok(answered.body)
}

/// Wait until the forwarding domain reports `generation`, answering the number it
/// settled on.
///
/// # Errors
/// The verdict, naming the generation it was still on when the grace ran out —
/// which is the finding rather than a bare timeout.
fn await_dataplane(host_port: u16, generation: u32) -> Result<u32, String> {
    let deadline = Instant::now();
    let mut seen = 0u32;
    while deadline.elapsed() < SWITCH_GRACE {
        let scraped = crate::metrics_contract::fetch(host_port)
            .map_err(|error| format!("scraping for the forwarder's generation: {error}"))?;
        seen = forwarder_generation(&scraped.body).unwrap_or(0);
        if seen >= generation {
            return Ok(seen);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(format!(
        "the configuration domain committed generation {generation} and the forwarding domain is \
         still on {seen} after {}s. It switches tables between two polls and is notified when a \
         generation is released, so this is a handover that did not complete rather than one that \
         is slow",
        SWITCH_GRACE.as_secs()
    ))
}

/// The generation the *forwarding* domain publishes, which is the one the
/// dataplane decides under. Deliberately not the configuration domain's: that one
/// moves when a document commits, and what a probe's verdict depends on is the
/// table the forwarder switched to.
fn forwarder_generation(exposition: &str) -> Option<u32> {
    exposition.lines().find_map(|line| {
        let rest = line.strip_prefix(GENERATION)?;
        let (labels, value) = rest.rsplit_once(' ')?;
        labels
            .contains("domain=\"forwarder\"")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

/// One counter series' value, matched on its family and an optional label value.
fn counted(exposition: &str, family: &str, outcome: Option<&str>) -> Option<u64> {
    exposition.lines().find_map(|line| {
        let rest = line.strip_prefix(family)?;
        let (labels, value) = rest.rsplit_once(' ')?;
        let wanted = match outcome {
            Some(outcome) => labels.contains(&format!("outcome=\"{outcome}\"")),
            None => true,
        };
        // The config domain's own shard and no other's: this family is published by
        // one domain, and matching on it keeps that true rather than assumed.
        (wanted && labels.contains("domain=\"config\"")).then(|| value.trim().parse().ok())?
    })
}

/// One `key=<decimal>` field of an answer line.
fn field(line: &str, key: &str) -> Option<u32> {
    token(line, key)?.parse().ok()
}

/// One `key=<token>` field of an answer line.
fn token(line: &str, key: &str) -> Option<String> {
    line.split(' ').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then(|| value.to_owned())
    })
}

/// A body cut short for a verdict, so a failure names what came back without
/// pasting a whole document into a terminal.
fn truncate(body: &str) -> String {
    const LIMIT: usize = 200;
    match body.char_indices().nth(LIMIT) {
        Some((at, _)) => format!("{}…", &body[..at]),
        None => body.to_owned(),
    }
}

#[cfg(test)]
mod tests;
