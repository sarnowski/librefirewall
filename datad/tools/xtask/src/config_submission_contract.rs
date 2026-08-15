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
//! point of the two-phase handover. So the scenario waits for the forwarding
//! domain's own `LFW-CFG` record — the line that domain writes on the very wakeup
//! it switches on — and only then injects the traffic whose verdict must have
//! reversed. A harness that injected immediately would be racing a protocol built
//! to avoid exactly that race, and would fail intermittently for the right reason
//! and the wrong evidence.
//!
//! **The console is where that fact belongs.** The switch is an event, and the
//! appliance states it as one: a line written by the domain that made the switch,
//! at the moment it made it, kept in the capture for as long as the boot lasts. A
//! gauge is the same fact reshaped into a number a reader has to catch between two
//! polls, and reaching for one here meant asking the management domain about
//! something the forwarding domain had already said.
//!
//! # What this module does not judge
//!
//! **The numbers.** What the deciding domain's own counters say about these
//! submissions, and what the re-decision a commit arms did to the conversations
//! already running, are judged against the metric readings this boot's connection
//! history carries — [`crate::snapshot_contract`], which also carries why. This
//! module drives: it makes the exchanges, holds each answer to its contract, waits
//! for the dataplane, and manufactures the wakeups a quiet bench owes a pass. The
//! appliance ships everything else on a channel of its own, and a harness that
//! reached in to ask for it as well was asking a second surface to repeat what the
//! first had already sent.
//!
//! # No adversary
//!
//! As [`crate::metrics_contract`]: this reads and writes the appliance's own
//! management surface on a wire only the harness is attached to. That the surface
//! has no authentication at all is what makes it reachable here — and is a
//! recorded deviation from the design, not a property to rely on.

use std::process::Command;
use std::time::Duration;

use lfw_http::Status;

/// How long a `curl` may take, end to end. [`crate::metrics_contract`]'s budget,
/// for its reasons: the guest may be under TCG on a loaded runner.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// How many passes over the capture the forwarding domain is given to say it
/// switched, and how long the harness waits between two of them.
///
/// **A count of passes and never an elapsed budget.** What is bounded is how many
/// times the console is actually read, so a loaded machine costs passes that each
/// look for the record; a deadline would let a harness thread that was descheduled
/// spend its whole budget without having looked once, and report a domain that had
/// already spoken as one that never did.
///
/// Far more passes than a healthy boot needs — the switch happens on the wakeup
/// the configuration domain's notification provokes, which is the next one — for
/// the reason every wait here is generous: the cost of being wrong is asymmetric.
const SWITCH_POLLS: usize = 240;
const SWITCH_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// What the deciding domain owes on its own counters once [`apply`] has run,
/// which is the independent half of every claim it makes: the HTTP answers are one
/// domain's account of these submissions and the counters are the same domain's
/// account of them in a different place, joined on nothing but having happened.
///
/// Two documents applied — the one this image booted and the one just submitted —
/// two refused at the two stages, and three reads: before the change, after it,
/// and after both refusals. Floors rather than equalities, because a boot is free
/// to have done more; what they refuse is the two accounts disagreeing.
///
/// **Where they are judged is the connection history and not a scrape.** All three
/// series have a slot in the metric reading the recorder frames into the log ring,
/// so the claim is stated over the surface the appliance ships rather than over
/// one an operator has to reach in and ask for — see `crate::snapshot_contract`,
/// which also carries why a counter in a reading is read as a floor over the file.
pub const OWED_APPLIED: u64 = 2;
pub const OWED_REFUSED: u64 = 2;
pub const OWED_READS: u64 = 3;

/// The two outcomes those counters are read under, taken from the vocabulary the
/// console and the metric labels share rather than written down twice.
pub const APPLIED: &str = lfw_log::GenerationOutcome::Applied.name();
pub const REFUSED: &str = lfw_log::GenerationOutcome::Refused.name();

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

/// The shipped policy with one rule added, admitting the ICMP errors a live
/// conversation is the reason for. Submitted by the related-traffic scenario.
pub const RELATED: &[u8] = include_bytes!("../scenarios/related-icmp.xml");

/// The shipped document with its two rules given one id: a document that **parses
/// cleanly and a rule refuses**.
///
/// It is the second of the two refusals every reconfiguration scenario makes, and
/// the two are refused at different stages on purpose. [`MALFORMED`] is stopped by
/// the reader, which never builds a model at all, so "nothing moved" is almost
/// structural there. This one gets all the way through the reader: a whole model
/// exists, its interfaces and neighbours are sound, and the *rules* are what fail
/// — which is the case where a half-applied commit is actually conceivable, and so
/// the case worth showing on a booted node.
///
/// `image::DUPLICATE_RULE_ID_DOCUMENT` names the same file, registered there as one
/// the appliance refuses, so the fast gate holds it to being refused by a rule
/// rather than by the reader. The same bytes are booted into an image by the
/// fail-closed scenario, which is what makes the pair one statement: this document
/// is refused for the same reason whichever way it reaches a node.
pub const REFUSED_BY_RULE: &[u8] = include_bytes!("../scenarios/duplicate-rule-id.xml");

/// A document the **reader** refuses: unterminated, so the refusal is about a byte
/// and an operator can act on it with no knowledge of this appliance's capacities.
const MALFORMED: &[u8] = b"<configuration><interfaces><interface id=\"broken\"";

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
    /// The line the malformed submission was refused with — the reader's refusal.
    pub refusal: String,
    /// And the line the document a **rule** refused was refused with, which is the
    /// half a parse failure cannot show: a model existed and was thrown away whole.
    pub rule_refusal: String,
    /// The generation still running after both refusals.
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
             \x20   POST /config (rule) -> 400 {}\n\
             \x20   the forwarding domain reports generation {}, which neither refusal moved",
            self.before.len(),
            self.answer,
            self.after.len(),
            self.refusal,
            self.rule_refusal,
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
/// than against a literal. What is submitted is [`SUBMITTED`]. `console` answers
/// this boot's capture as it stands, for the one step here that waits on the
/// appliance saying something rather than on it answering a request.
///
/// # Errors
/// The verdict, naming which exchange failed and what it answered.
pub fn apply(
    host_port: u16,
    booted_with: &[u8],
    document: &[u8],
    console: impl FnMut() -> Vec<u8>,
) -> Result<Applied, String> {
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

    // And the fail-closed half, with something to lose: a refused document must be
    // answered with a reason and must move nothing. Twice, because the two
    // interesting refusals happen at different stages and only one of them is
    // structurally safe.
    //
    // First the reader's: an unterminated document that never becomes a model.
    let refusal = refuse(host_port, generation, MALFORMED, RefusedBy::Reader)?;
    // Then the one a parse failure cannot show. This document reads cleanly — a
    // whole model exists, its addressing sound — and a rule about the policy refuses
    // it, which is the only case in which a configuration could half-apply at all.
    let rule_refusal = refuse(host_port, generation, REFUSED_BY_RULE, RefusedBy::Rule)?;
    // And the half that makes that a statement about the *store* rather than about
    // the answer on the wire: the node still states the document it committed, byte
    // for byte as a configuration. A commit that had taken the refused document's
    // rules and kept its own interfaces would answer a refusal and read back as
    // something neither document describes.
    let after_the_refusals = state(host_port, "after both refusals")?;
    let still_running = config::load(after_the_refusals.as_bytes()).map_err(|error| {
        format!(
            "after two refusals the node states a document it would not itself accept ({error:?}), \
             so a refusal left the store holding something no document describes:\n\
             {after_the_refusals}"
        )
    })?;
    if !submitted.has_same_content(&still_running) {
        return Err(format!(
            "two documents were refused and the node now states a configuration that is not the \
             one it committed, so a refusal applied part of what it rejected:\n\
             {after_the_refusals}"
        ));
    }

    // Only now is the dataplane waited for. The configuration domain answered when
    // *it* committed; the forwarding domain switches between two polls, and the
    // traffic whose verdict must reverse may not be injected before it has.
    let unmoved = await_dataplane(generation, console)?;

    // The deciding domain's own account of what it has done is owed too, and is
    // judged where the appliance ships it: the metric reading inside this boot's
    // connection history carries all three series, and `crate::snapshot_contract`
    // holds them to [`OWED_APPLIED`], [`OWED_REFUSED`] and [`OWED_READS`] once the
    // medium can be read. Nothing is asked of the node here that it does not
    // already send.

    Ok(Applied {
        before,
        answer,
        generation,
        after,
        refusal,
        rule_refusal,
        unmoved,
    })
}

/// What the harness did to work the re-decision a commit armed off, so the
/// readings that say what it *did* can be read beside it.
///
/// The numbers the re-decision is judged on are not here: they are in the metric
/// readings this boot's connection history carries, and
/// `crate::snapshot_contract` states them. What this carries is the harness's own
/// half — how many wakeups it manufactured, and whose port they went to.
#[derive(Clone, Copy, Debug)]
pub struct Driven {
    /// Wakeups the harness manufactured.
    pub wakeups: usize,
    /// The shard of the driver whose port took them, so the appliance's own count
    /// of what arrived can be reported beside this count of what was written.
    pub driver_domain: &'static str,
}

/// Work the re-decision a commit armed off, by manufacturing the wakeups a quiet
/// bench does not have, and answer what was spent doing it.
///
/// `drive` is called to manufacture one wakeup. What the pass *did* is not read
/// here: it is in this boot's metric readings, and `crate::snapshot_contract`
/// states it once the medium can be read.
///
/// # Why the harness makes wakeups at all
///
/// The pass is bounded per wakeup, because a commit that walked a million-slot
/// index in one go would stall forwarding for a visible interval. It therefore
/// advances only when the forwarding domain is woken, and the forwarding domain is
/// woken by frames arriving on a dataplane port. So a bench whose dataplane is
/// quiet — which is exactly what a scenario is between its two waves — would leave
/// a pass armed and never advanced.
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
/// # Why the whole budget is spent, and why that is the simpler thing
///
/// The budget is the appliance's own arithmetic and it is spent unconditionally.
/// Nothing here reads progress back, so there is nothing to poll, nothing to stop
/// early on, and no surface to ask — the harness's job is to supply wakeups, and
/// whether they were enough is a question the readings answer afterwards. A driver
/// that also decided when to stop was reaching for a second surface to learn
/// something the first one it drove had no opinion about.
///
/// It cannot hang: the count is fixed before the first frame goes out, and every
/// iteration spends one of it.
///
/// # Why the frames are spaced out, and why nothing is timed
///
/// A manufactured wakeup is only worth a wakeup if the domain was quiet when it
/// arrived. `Pipeline::windows_for` sizes a pass's share of a wakeup against what
/// that wakeup's drain left of its frame budget: a quiet one works off four
/// windows and a saturated one exactly one. Frames written back to back do not
/// arrive back to back — they arrive coalesced into far fewer wakeups, some twenty
/// of them to a wakeup on an emulated guest — so a burst buys one wakeup's windows
/// between all of them and the budget below is spent at a fraction of its stated
/// rate. Spacing them leaves the domain quiet when each one lands, which is what
/// makes the count mean what it says.
///
/// That spacing is a **pace and never a bound**: nothing is asserted against it and
/// a machine on which it is too short costs more wakeups, not a failure. The bound
/// is the count, and the count comes from the appliance's arithmetic — so a pass
/// that is not advancing is a finding at any speed, and a slow machine is not one.
///
/// # Errors
/// A port this build publishes no driver shard for, which would leave the
/// appliance's own count of what arrived unreadable and the wakeups unaccounted
/// for.
pub fn drive_re_decision(driven_port: usize, mut drive: impl FnMut()) -> Result<Driven, String> {
    /// How many wakeups the harness manufactures.
    ///
    /// The appliance's own arithmetic, and the reason nothing here is timed. A
    /// pass crosses `FLOW_CAPACITY / REVISIT_BUCKETS` windows of index, a commit
    /// arriving mid-pass queues at most one more pass behind the one running, and
    /// a wakeup works off at least one window however saturated it is — so two
    /// passes are owed at worst and cost at most twice that many wakeups. This is
    /// eight times that figure, and a quiet wakeup works off four windows rather
    /// than one, so the margin over what the pass actually needs is wider still.
    const WAKEUPS: usize = 4_096;
    /// How long the harness waits between the wakeups it manufactures, so each
    /// lands on a domain that has finished with the one before it.
    const DRIVE_PACE: Duration = Duration::from_millis(5);

    let Some(driver_domain) = u8::try_from(driven_port)
        .ok()
        .and_then(lfw_metrics::port_domain)
    else {
        return Err(format!(
            "the re-decision is driven through port {driven_port}, which this build has no driver \
             domain for, so nothing can say whether the frames arrived"
        ));
    };

    for _ in 0..WAKEUPS {
        drive();
        std::thread::sleep(DRIVE_PACE);
    }
    Ok(Driven {
        wakeups: WAKEUPS,
        driver_domain,
    })
}

/// Which half of `config::load` a submitted document is expected to be refused by.
///
/// The distinction is the whole reason there are two refusals rather than one. A
/// document the **reader** stops never becomes a model, so "nothing was committed"
/// is nearly structural: there was nothing to commit. A document a **rule** stops
/// got all the way through the reader — a whole model existed, was judged, and was
/// thrown away entire — which is the only case where a *partly* applied
/// configuration is even conceivable, and therefore the case worth showing on a
/// booted node.
///
/// It is also what the reason token is checked against: a rule's refusal that
/// answered a parse reason, or the other way round, would name a token from the
/// right vocabulary for the wrong stage, and the token alone cannot tell them
/// apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefusedBy {
    Reader,
    Rule,
}

impl RefusedBy {
    fn describe(self) -> &'static str {
        match self {
            Self::Reader => "the reader",
            Self::Rule => "a semantic rule",
        }
    }
}

/// Submit a document this appliance refuses and hold the refusal to naming the
/// right reason, at the right stage, and to having moved nothing.
///
/// The expected reason is not written here: it comes from running the same
/// `config::load` the appliance runs over the same bytes, so a refusal is compared
/// against the crate under test rather than against a literal that could be wrong
/// about both sides at once. The stage is asserted the same way — `ConfigError`'s
/// two variants *are* the two stages — so a document that is not refused where this
/// case says it is fails here rather than being judged under the wrong claim.
///
/// # Errors
/// The verdict, naming what the endpoint answered and what was owed.
fn refuse(
    host_port: u16,
    running: u32,
    document: &[u8],
    stage: RefusedBy,
) -> Result<String, String> {
    let owed = match (stage, config::load(document)) {
        (RefusedBy::Reader, Err(config::ConfigError::Document(fault))) => fault.reason(),
        (RefusedBy::Rule, Err(config::ConfigError::Semantic(fault))) => fault.reason(),
        (_, Err(other)) => {
            return Err(format!(
                "this case submits a document {} must refuse and `config::load` refuses it \
                 elsewhere, as `{}`. The two stages answer reasons from one vocabulary, so a \
                 refusal judged under the wrong stage would pass on the right token for the wrong \
                 reason",
                stage.describe(),
                other.reason().name()
            ));
        }
        (_, Ok(_)) => {
            return Err(format!(
                "this case submits a document {} must refuse and `config::load` accepts it, so \
                 the node would commit it and the assertion that a refusal moves nothing would be \
                 stated about a commit",
                stage.describe()
            ));
        }
    };

    let answered = request(host_port, "POST", "/config", Some(document))?;
    if answered.status != Status::BadRequest.code() {
        return Err(format!(
            "a document {} refuses was answered {} rather than {}: {:?}",
            stage.describe(),
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
    if reason != owed.name() {
        return Err(format!(
            "a document {} refuses as `{}` was answered `{reason}`. The reason is what an operator \
             acts on, and one naming the wrong stage sends them to look at the wrong thing — a \
             byte offset for a rule about an object, or an object for a malformed byte: {line:?}",
            stage.describe(),
            owed.name()
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

/// Wait until the forwarding domain says it switched to `generation`, answering
/// the number it settled on.
///
/// `console` answers the capture as it stands and is called afresh every pass:
/// what this waits for is a record the appliance has not written yet, so a
/// snapshot taken before the submission could never carry one.
///
/// # Errors
/// The verdict, naming the generation the forwarding domain had last said it was
/// on — which is the finding rather than a bare timeout.
fn await_dataplane(generation: u32, mut console: impl FnMut() -> Vec<u8>) -> Result<u32, String> {
    for _ in 0..SWITCH_POLLS {
        let seen = switched_generation(&console());
        if seen >= generation {
            return Ok(seen);
        }
        std::thread::sleep(SWITCH_POLL_INTERVAL);
    }
    // One last read, so a record written while the final interval was being slept
    // through is not reported missing by a pass that never happened.
    let seen = switched_generation(&console());
    if seen >= generation {
        return Ok(seen);
    }
    Err(format!(
        "the configuration domain committed generation {generation} and the forwarding domain has \
         said it is on {seen} after {SWITCH_POLLS} passes over the console. It switches tables \
         between two polls, is notified when a generation is released, and writes this record on \
         the wakeup it switches on — so this is a handover that did not complete rather than one \
         that is slow"
    ))
}

/// The generation the **forwarding** domain last said it had switched to, or zero
/// where it has said nothing — which is the fail-closed empty table it starts on.
///
/// # How the two domains' records are told apart
///
/// One commit produces two `outcome=applied` records and the configuration
/// domain's comes first, so a reader that took either would stop waiting when the
/// document was *committed* rather than when the dataplane had taken it up — which
/// is the whole race this wait exists to avoid.
///
/// They are separated the way the boot transcript already separates them: the
/// publishing domain reports how many values its diff moved, and the forwarding
/// domain reports **no change count at all**, the diff being the publisher's
/// record and this one saying only which generation is now carrying traffic. That
/// holds because a commit is keyed by content — a candidate already running is
/// `unchanged` and writes no `applied` record — so a publisher's `applied` has
/// moved at least one value and never reads zero here.
///
/// The maximum rather than the last, because a generation only rises: it makes the
/// reading independent of where in the capture a record sits, on a console two
/// domains write and a debug kernel writes between them.
fn switched_generation(serial: &[u8]) -> u32 {
    let text = String::from_utf8_lossy(serial);
    crate::console_records::records_on(&text, crate::console_records::CONFIG_PREFIX)
        .into_iter()
        .filter(|record| {
            crate::console_records::value(record, "outcome")
                == Some(lfw_log::GenerationOutcome::Applied.name())
                && crate::console_records::value(record, "changes") == Some(FORWARDER_CHANGES)
        })
        .filter_map(|record| {
            crate::console_records::value(record, "generation")?
                .parse::<u32>()
                .ok()
        })
        .max()
        .unwrap_or(0)
}

/// The change count the forwarding domain's own generation record carries, which
/// is what tells it from the publisher's — see [`switched_generation`].
const FORWARDER_CHANGES: &str = "0";

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
