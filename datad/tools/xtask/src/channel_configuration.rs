//! Reconfiguring a node that is **already carrying traffic**, over the channel it
//! dialled, and holding every step of that transaction to its contract.
//!
//! This is the one thing in the gate that changes what the appliance is doing.
//! Everything else observes a node built around a document; these boots build a
//! node around one document, push it another down the connection it opened
//! outward, and hold the *dataplane* to having reversed its verdict because of
//! it. The bytes are frames written out by hand and handed to `openssl s_server`,
//! so nothing on the wire is composed by the code under test.
//!
//! # What the four frames are for
//!
//! 1. **A malformed document, staged** — refused by the reader, which never
//!    builds a model at all, and answered with a result frame naming the reason
//!    and the generation still running.
//! 2. **A document a rule refuses, staged** — the half a parse failure cannot
//!    show. A whole model exists, its interfaces and neighbours are sound, and the
//!    *rules* are what fail, which is the only case in which a configuration could
//!    half-apply.
//! 3. **The scenario's own document, staged** — answered with the generation
//!    committing it would assign. That number is what says the two refusals moved
//!    nothing: a refusal that had consumed a generation would leave the good
//!    document staged past it.
//! 4. **The commit** — which puts it in force and ends the session, a
//!    confirmation being admissible only over a connection opened afterwards.
//!
//! # And the transactions driven for their own sake
//!
//! Two boots have no dataplane wave to order against and are about the
//! transaction itself: one is judged on the generation its commit is *answered*
//! with, and the other goes on to **confirm** that commit. The confirmation is
//! why the second connection is a subject here rather than a detail — it is
//! admissible nowhere else, so that boot has to see the appliance close the
//! session it committed on and come back on one of its own.
//!
//! # Why nothing here is timed, and why the push cannot race
//!
//! The server is listening before QEMU starts, and the appliance dials when it is
//! ready. So the first thing this does is **wait for the appliance to greet** —
//! the server's own account of a session at this end, read off the transcript
//! `openssl` writes — and the frames go down the pipe only after it has. A push
//! written at spawn would reach an appliance whose dataplane had not yet decided
//! the probes the old policy is judged on, and the first wave's verdicts are half
//! of what these boots prove.
//!
//! Every wait is **a count of passes and never an elapsed budget**, on
//! [`await_dataplane`]'s terms: what is bounded is how many times the evidence is
//! actually looked at, so a loaded machine costs passes that each look. Every one
//! of them ends — the count is fixed before the first pass — so nothing here can
//! hang, and a step that never arrives is reported as the step it was.
//!
//! # Why the dataplane is waited for and not assumed
//!
//! The configuration domain answers a commit when *it* has committed; the
//! forwarding domain switches tables at its next poll boundary, which is the whole
//! point of the two-phase handover. So this waits for the forwarding domain's own
//! `LFW-CFG` record — the line that domain writes on the very wakeup it switches
//! on — and only then does the scenario inject the traffic whose verdict must have
//! reversed.
//!
//! # What this module does not judge
//!
//! **The numbers.** What the deciding domain's own counters say about these
//! documents, and what the re-decision a commit arms did to the conversations
//! already running, are judged against the metric readings this boot's connection
//! history carries — [`crate::snapshot_contract`], which also carries why.
//!
//! # Adversary
//!
//! None. The server is this run's own management plane, mutually authenticated
//! against the authority this run issued; what it exercises is the appliance
//! obeying the plane that owns it.

use std::time::Duration;

use crate::channel_contract::{
    PUSHED_GENERATION, Server, commit_frame, confirm_frame, server_greeting, stage_frame,
};

/// How many passes each step is given, and how long the harness waits between
/// two of them.
///
/// **A count of passes and never an elapsed budget.** What is bounded is how many
/// times the evidence is actually read, so a loaded machine costs passes that each
/// look for it; a deadline would let a harness thread that was descheduled spend
/// its whole budget without having looked once, and report an appliance that had
/// already answered as one that never did.
///
/// A session and a table switch are worth more passes than a result frame: the
/// first two wait on an appliance that has to get somewhere, and the third on one
/// round trip to a domain that runs at the highest priority in the system.
const SESSION_POLLS: usize = 240;
const RESULT_POLLS: usize = 120;
const SWITCH_POLLS: usize = 240;
const POLL_MILLIS: u64 = 250;
pub const POLL_INTERVAL: Duration = Duration::from_millis(POLL_MILLIS);

/// How many passes the **second** session is given, which is a different number
/// from the first for a reason of the appliance's own.
///
/// A commit ends the session by closing the connection from this appliance's end,
/// so the connection it closed sits in `TIME_WAIT` — and the endpoint above the
/// transport holds the session until the transport gives the slot back, which is
/// what keeps the ending it reports answerable for as long as anybody asks. Only
/// then does the redial schedule draw its next wait, below a bound the agreed
/// greeting has just reset to its floor. So the second connection is owed
/// `TIME_WAIT` plus at most one floor-length wait, and neither figure is a guess:
/// both are read out of the crates that hold them.
///
/// Twice that, so a boot is not decided by where in an interval it happened to
/// land and so the handshake the second connection still owes — which is neither
/// of the two intervals — is inside rather than beside the figure: the number is
/// the point past which the harness stops looking, and a run that reaches it has
/// found an appliance that never dialled again rather than a machine that was
/// slow. [`crate::forward_harness`] holds it to fitting inside a
/// boot's own budget, so the step that fails is this one and not the outer timer.
pub const RECONNECT_POLLS: usize = reconnect_polls();

/// The pass count above, from the appliance's own two intervals.
///
/// Milliseconds throughout: the two intervals are read out of the crates that
/// hold them and the pace is this file's own, so one unit for all three costs no
/// cast and leaves nothing to truncate.
const fn reconnect_polls() -> usize {
    /// The two intervals in the pace's own unit.
    const fn millis(nanos: u64) -> u64 {
        nanos / 1_000_000
    }
    let owed = millis(lfw_tcp::TIME_WAIT_DURATION.as_nanos())
        .saturating_add(millis(pd_runtime::INITIAL_BACKOFF.as_nanos()));
    (owed.saturating_mul(2) / POLL_MILLIS) as usize
}

// The divisor above, which is a literal of this file and reached by no peer. A
// zero pace would make the division the one panic a const evaluation can raise,
// so it is a build that does not happen rather than a check inside the function.
const _: () = assert!(POLL_MILLIS > 0);

/// The generation a node that booted a document is running before anything
/// reaches it over the channel.
///
/// One, and it is arithmetic rather than a choice: the document compiled into the
/// image is committed on every boot. The assertion below it is what keeps this and
/// the generation the push commits from drifting apart — the pushed one is the
/// next thing the datastore admits, and if it stopped being that then "a refusal
/// moved nothing" would be stated about the wrong number.
const RUNNING_GENERATION: u32 = 1;
const _: () = assert!(RUNNING_GENERATION as u64 + 1 == PUSHED_GENERATION);

/// The document a **reconfiguration** scenario pushes, compiled in rather than
/// read at run time.
///
/// `image::SUBMITTED_DOCUMENT` names the same file for the fast gate's sake —
/// every document in the tree goes through `config::load` there — and this is the
/// copy the scenario actually sends. Two references to one file rather than a path
/// resolved twice: a scenario that pushed a document the gate had not read would
/// be the hole that list closes.
pub const SUBMITTED: &[u8] = include_bytes!("../scenarios/reconfiguration-swap.xml");

/// The document a **revocation** scenario pushes, on [`SUBMITTED`]'s terms:
/// `image::NARROWED_DOCUMENT` names the same file for the fast gate.
pub const NARROWED: &[u8] = include_bytes!("../scenarios/revocation-narrow.xml");

/// The shipped policy with one rule added, admitting the ICMP errors a live
/// conversation is the reason for. Pushed by the related-traffic scenario.
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
/// `image::DUPLICATE_RULE_ID_DOCUMENT` names the same file, registered there as
/// one the appliance refuses, so the fast gate holds it to being refused by a rule
/// rather than by the reader. The same bytes are booted into an image by the
/// fail-closed scenario, which is what makes the pair one statement: this document
/// is refused for the same reason whichever way it reaches a node.
pub const REFUSED_BY_RULE: &[u8] = include_bytes!("../scenarios/duplicate-rule-id.xml");

/// A document the **reader** refuses: unterminated, so the refusal is about a byte
/// and an operator can act on it with no knowledge of this appliance's capacities.
const MALFORMED: &[u8] = b"<configuration><interfaces><interface id=\"broken\"";

/// What the deciding domain owes on its own counters once [`reconfigure`] has run,
/// which is the independent half of every claim the transaction makes: the result
/// frames are one domain's account of these documents and the counters are the
/// same domain's account of them in a different place, joined on nothing but
/// having happened.
///
/// Two documents applied — the one this image booted and the one just committed —
/// and two refused at the two staging failures. Floors rather than equalities,
/// because a boot is free to have done more; what they refuse is the two accounts
/// disagreeing.
///
/// **Where they are judged is the connection history.** Both series have a slot in
/// the metric reading the recorder frames into the log ring, so the claim is stated
/// over the surface the appliance ships rather than over one an operator has to
/// reach in and ask for — see `crate::snapshot_contract`, which also carries why a
/// counter in a reading is read as a floor over the file.
pub const OWED_APPLIED: u64 = 2;
pub const OWED_REFUSED: u64 = 2;

/// The two outcomes those counters are read under, taken from the vocabulary the
/// console, the result frames and the metric labels share rather than written down
/// twice.
pub const APPLIED: &str = lfw_log::GenerationOutcome::Applied.name();
pub const REFUSED: &str = lfw_log::GenerationOutcome::Refused.name();

/// What the transaction produced, and what the node said about itself along the
/// way. Returned so the scenario can print it as evidence.
#[derive(Clone, Debug)]
pub struct Reconfigured {
    /// The line the malformed document was refused with — the reader's refusal.
    pub refusal: String,
    /// And the line the document a **rule** refused was refused with, which is
    /// the half a parse failure cannot show: a model existed and was thrown away
    /// whole.
    pub rule_refusal: String,
    /// The line the scenario's own document was staged with.
    pub staged: String,
    /// The generation the commit put in force.
    pub generation: u32,
    /// The generation the forwarding domain reports it is deciding under, which
    /// is the one the second wave of probes is judged by.
    pub switched: u32,
}

impl Reconfigured {
    /// The transcript a reader wants beside a scenario's verdict.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "  configuration pushed over the channel and in force on the dataplane:\n\
             \x20   stage (bad)   -> {}\n\
             \x20   stage (rule)  -> {}\n\
             \x20   stage         -> {}, which neither refusal moved past\n\
             \x20   commit        -> generation {}\n\
             \x20   the forwarding domain reports generation {}",
            self.refusal, self.rule_refusal, self.staged, self.generation, self.switched,
        )
    }
}

/// Push `document` at a running node over the channel it dialled, and hold every
/// step of the transaction to its contract, leaving the node running it.
///
/// `console` answers this boot's capture as it stands and is called afresh on
/// every pass: what the last step waits for is a record the appliance has not
/// written yet, and calling it is also what keeps the guest's serial pipe draining
/// while this is under way.
///
/// # Errors
/// The verdict, naming which step failed and what the appliance answered.
pub fn reconfigure(
    server: &mut Server,
    document: &[u8],
    mut console: impl FnMut() -> Vec<u8>,
) -> Result<Reconfigured, String> {
    // The appliance's own greeting, reaching the server this run started. It is
    // what says there is a session at this end to write into — and it is the
    // server's account rather than the appliance's, a console record being the
    // far end speaking about a session that may since have gone.
    await_greetings(server, &mut console, 1, SESSION_POLLS, FIRST_SESSION)?;

    // The fail-closed half first, while the node is running the document its
    // image was built from and the first wave's verdicts have already been
    // reached under it. A refusal has something to lose here: the policy every
    // probe so far was decided by.
    //
    // Twice, because the two interesting refusals happen at different stages and
    // only one of them is structurally safe. First the reader's: an unterminated
    // document that never becomes a model.
    let refusal = refuse(server, &mut console, MALFORMED, RefusedBy::Reader)?;
    // Then the one a parse failure cannot show. This document reads cleanly — a
    // whole model exists, its addressing sound — and a rule about the policy
    // refuses it, which is the only case in which a configuration could
    // half-apply at all.
    let rule_refusal = refuse(server, &mut console, REFUSED_BY_RULE, RefusedBy::Rule)?;

    // And now the document the scenario is about. The generation it is staged at
    // is what makes the two refusals above a statement rather than a pair of
    // answers: a refusal that had consumed a generation, or left a candidate
    // behind, would put this one somewhere other than the very next number.
    let staged = stage(server, &mut console, document)?;
    let named = field(&staged, "generation")
        .ok_or_else(|| format!("the staging answered {staged:?}, which names no generation"))?;
    if token(&staged, "outcome").as_deref() != Some(lfw_log::GenerationOutcome::Staged.name()) {
        return Err(format!(
            "this scenario's own document was answered {staged:?} rather than staged, so there is \
             no candidate for the commit below to put in force"
        ));
    }
    let owed = u32::try_from(PUSHED_GENERATION).unwrap_or(u32::MAX);
    if named != owed {
        return Err(format!(
            "the document was staged at generation {named} and committing it assigns {owed} on a \
             node that booted one and refused two. A staging anywhere else means a refusal \
             consumed a generation, which is a refused document changing what is running: \
             {staged:?}"
        ));
    }

    // The commit, which puts it in force and ends the session: a confirmation is
    // admissible only over a connection opened after it. Nothing follows on this
    // one, and nothing needs to — the deadline the frame asks for is far past any
    // budget a boot in this gate takes, so what the commit put in force is still
    // in force when the guest stops.
    server.push(&commit_frame(PUSHED_GENERATION))?;

    // Only now is the dataplane waited for. The configuration domain commits when
    // *it* has committed; the forwarding domain switches between two polls, and
    // the traffic whose verdict must reverse may not be injected before it has.
    let switched = await_dataplane(owed, &mut console)?;

    Ok(Reconfigured {
        refusal,
        rule_refusal,
        staged,
        generation: owed,
        switched,
    })
}

/// What a wait for a greeting is about, for the verdict it leaves behind: the two
/// absences send a reader to different places, so each says which it is.
const FIRST_SESSION: &str = "It dials out, so a session it never opened is one nothing here can \
                             push a configuration down";
const FRESH_SESSION: &str = "The commit ended the session, which is the whole of how the \
                             fresh-connection rule is enforced, so the appliance owes a second \
                             connection of its own — it closed the first, waits for the transport \
                             to give that connection's slot back, and then draws the next wait off \
                             a schedule the agreed greeting reset. A confirmation is admissible \
                             nowhere else, so a node that does not come back is one whose commit \
                             can only revert";

/// Wait until `owed` appliance greetings have reached the server this run started.
///
/// The server's own account and never the appliance's, on
/// [`Server::sessions_greeted`]'s terms: what a push needs to know is that there
/// is a session at this end to write into.
///
/// # Errors
/// The verdict, naming how many greetings arrived, how many were owed, and — in
/// `absence` — what the missing one would have been.
fn await_greetings(
    server: &Server,
    console: &mut impl FnMut() -> Vec<u8>,
    owed: usize,
    polls: usize,
    absence: &str,
) -> Result<(), String> {
    for _ in 0..=polls {
        let _ = console();
        if server.sessions_greeted()? >= owed {
            return Ok(());
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    let seen = server.sessions_greeted()?;
    if seen >= owed {
        return Ok(());
    }
    Err(format!(
        "the management server this run started has seen {seen} appliance greeting(s) and this \
         step needs {owed}, after {polls} passes over its transcript. {absence}"
    ))
}

/// Stage `document` and answer the result line the appliance sent back.
///
/// The line is identified by *arrival* and not by content: how many results the
/// transcript already carried is read before the frame goes out, so the one this
/// call is about is the one that was not there before. A reader that matched on
/// text would take a previous step's answer for this step's the moment two steps
/// agreed.
///
/// # Errors
/// A push that failed, and an appliance that answered nothing.
fn stage(
    server: &mut Server,
    console: &mut impl FnMut() -> Vec<u8>,
    document: &[u8],
) -> Result<String, String> {
    let before = server.validate_results()?.len();
    server.push(&stage_frame(document)?)?;
    for _ in 0..=RESULT_POLLS {
        let _ = console();
        let results = server.validate_results()?;
        if results.len() > before
            && let Some(line) = results.last()
        {
            return Ok(line.clone());
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(format!(
        "the appliance answered no result frame for a document staged over the channel, after \
         {RESULT_POLLS} passes over the server's transcript. Every staging is owed one — a \
         document it could not even decide about is answered as refused rather than with silence \
         — so this is an appliance that stopped reading its channel"
    ))
}

/// Which half of `config::load` a staged document is expected to be refused by.
///
/// The distinction is the whole reason there are two refusals rather than one. A
/// document the **reader** stops never becomes a model, so "nothing was staged" is
/// nearly structural: there was nothing to stage. A document a **rule** stops got
/// all the way through the reader — a whole model existed, was judged, and was
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
    const fn describe(self) -> &'static str {
        match self {
            Self::Reader => "the reader",
            Self::Rule => "a semantic rule",
        }
    }
}

/// Stage a document this appliance refuses and hold the refusal to naming the
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
/// The verdict, naming what the appliance answered and what was owed.
fn refuse(
    server: &mut Server,
    console: &mut impl FnMut() -> Vec<u8>,
    document: &[u8],
    stage_of: RefusedBy,
) -> Result<String, String> {
    let owed = match (stage_of, config::load(document)) {
        (RefusedBy::Reader, Err(config::ConfigError::Document(fault))) => fault.reason(),
        (RefusedBy::Rule, Err(config::ConfigError::Semantic(fault))) => fault.reason(),
        (_, Err(other)) => {
            return Err(format!(
                "this case pushes a document {} must refuse and `config::load` refuses it \
                 elsewhere, as `{}`. The two stages answer reasons from one vocabulary, so a \
                 refusal judged under the wrong stage would pass on the right token for the wrong \
                 reason",
                stage_of.describe(),
                other.reason().name()
            ));
        }
        (_, Ok(_)) => {
            return Err(format!(
                "this case pushes a document {} must refuse and `config::load` accepts it, so the \
                 node would stage it and the assertion that a refusal moves nothing would be \
                 stated about a candidate",
                stage_of.describe()
            ));
        }
    };

    let line = stage(server, console, document)?;
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
            stage_of.describe(),
            owed.name()
        ));
    }
    if token(&line, "outcome").as_deref() != Some(lfw_log::GenerationOutcome::Refused.name()) {
        return Err(format!("a refused document was answered {line:?}"));
    }
    // And the generation it names, which is the node saying for itself that the
    // refusal changed nothing: a staging that failed is answered with the
    // configuration still running, and any other number here would be a refused
    // document having moved the one in force.
    match field(&line, "generation") {
        Some(named) if named == RUNNING_GENERATION => Ok(line),
        Some(named) => Err(format!(
            "a refused document was answered generation {named} while {RUNNING_GENERATION} is \
             running, so a refusal moved the configuration: {line:?}"
        )),
        None => Err(format!("a refused document was answered {line:?}")),
    }
}

/// Which transaction a boot drives down the channel it dialled: the generation it
/// commits, and whether it goes on to confirm that commit.
///
/// A descriptor rather than two predicates on the contract, because the two facts
/// are one decision — a boot that confirms is a boot whose commit is provisional,
/// and the generation is the number both halves are about. One value also means
/// the driver takes the whole transaction from its caller rather than deriving
/// half of it from a constant beside itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// The generation the staging is answered at and the commit puts in force.
    pub generation: u64,
    /// Whether a confirmation follows, over the connection the appliance dials
    /// after the commit ended the session.
    pub confirms: bool,
}

/// What the whole configuration transaction produced on a boot whose subject it is,
/// as evidence a reader wants beside the verdict.
#[derive(Clone, Debug)]
pub struct Transacted {
    /// The line the document was staged with.
    pub staged: String,
    /// The line the commit was answered with.
    pub committed: String,
    /// The line the confirmation was answered with, on a boot that confirms.
    /// `None` on one that leaves the commit provisional.
    pub confirmed: Option<String>,
    /// Appliance greetings the server had seen by the end, which is one per
    /// session.
    pub sessions: usize,
}

impl Transacted {
    /// The transcript a reader wants beside a scenario's verdict.
    #[must_use]
    pub fn render(&self) -> String {
        let confirmation = match &self.confirmed {
            Some(line) => format!(
                "\n\x20   confirm       -> {line}, over the connection the appliance dialled after \
                 the commit had ended the session"
            ),
            None => String::new(),
        };
        format!(
            "  the configuration transaction, driven step by step over the channel the appliance \
             dialled:\n\
             \x20   stage         -> {}\n\
             \x20   commit        -> {}{confirmation}\n\
             \x20   the server saw {} appliance greeting(s)",
            self.staged, self.committed, self.sessions,
        )
    }
}

/// Drive the transaction on a boot whose subject is the generation its commit is
/// numbered at, and hold every step to the outcome and the number it owes.
///
/// Nothing here is timed. Each step waits for the **result line** the appliance
/// answers it with, found by arrival rather than by content, which is what makes a
/// step's verdict the appliance's own statement about it.
///
/// # Errors
/// The verdict, naming which step failed and what the appliance answered.
pub fn transact(
    server: &mut Server,
    document: &[u8],
    transaction: Transaction,
    mut console: impl FnMut() -> Vec<u8>,
) -> Result<Transacted, String> {
    let Transaction {
        generation,
        confirms,
    } = transaction;
    await_greetings(server, &mut console, 1, SESSION_POLLS, FIRST_SESSION)?;

    let staged = stage(server, &mut console, document)?;
    expect(
        &staged,
        "stage",
        lfw_log::GenerationOutcome::Staged.name(),
        generation,
    )?;

    // The commit, which is answered like every other configuration operation: the
    // appliance may commit and then put the commit back where its medium will not
    // hold the version, so `applied` is read rather than inferred from anything.
    let committed = answered(server, &mut console, "commit", &commit_frame(generation))?;
    expect(
        &committed,
        "commit",
        lfw_log::GenerationOutcome::Applied.name(),
        generation,
    )?;

    let confirmed = if confirms {
        Some(confirm(server, &mut console, generation)?)
    } else {
        None
    };

    Ok(Transacted {
        staged,
        committed,
        confirmed,
        sessions: server.sessions_greeted()?,
    })
}

/// Confirm the commit `generation` names, over the connection the appliance
/// dialled **after** the commit ended the session.
///
/// The commit is what closed the first connection, so nothing can be pushed until
/// the appliance has come back: this waits for a **second** appliance greeting to
/// reach the server — the server's own account of there being a session at this
/// end to write into — and only then writes anything. A confirmation written
/// before that would go down a pipe whose reader is between connections, and the
/// appliance would be judged on a frame it was never sent.
///
/// The server's own greeting goes first, because the second session is a session
/// like the first: the appliance is owed the far end's protocol version and
/// cursors before a configuration frame arrives on it.
///
/// # Errors
/// The verdict, on an appliance that never dialled again and on a confirmation
/// answered as anything but kept.
fn confirm(
    server: &mut Server,
    console: &mut impl FnMut() -> Vec<u8>,
    generation: u64,
) -> Result<String, String> {
    await_greetings(server, console, 2, RECONNECT_POLLS, FRESH_SESSION)?;
    server.push(&server_greeting())?;
    let line = answered(server, console, "confirmation", &confirm_frame(generation))?;
    expect(
        &line,
        "confirmation",
        lfw_log::GenerationOutcome::Confirmed.name(),
        generation,
    )?;
    Ok(line)
}

/// Hold one result line to the outcome and the generation the step owes.
fn expect(line: &str, step: &str, outcome: &str, generation: u64) -> Result<(), String> {
    if token(line, "outcome").as_deref() != Some(outcome) {
        return Err(format!(
            "the {step} was answered {line:?} rather than `outcome={outcome}`"
        ));
    }
    let owed = u32::try_from(generation).unwrap_or(u32::MAX);
    match field(line, "generation") {
        Some(named) if named == owed => Ok(()),
        Some(named) => Err(format!(
            "the {step} was answered generation {named} and {owed} is the number this step is \
             about. A commit numbered below the newest version the appliance's own medium holds \
             is one that medium refuses as a version that does not advance, so it never becomes \
             durable: {line:?}"
        )),
        None => Err(format!(
            "the {step} was answered {line:?}, which names no generation"
        )),
    }
}

/// Push `frames` and answer the result line the appliance sends back, on
/// [`stage`]'s terms: the line is identified by arrival and never by content.
fn answered(
    server: &mut Server,
    console: &mut impl FnMut() -> Vec<u8>,
    step: &str,
    frames: &[u8],
) -> Result<String, String> {
    let before = server.validate_results()?.len();
    server.push(frames)?;
    for _ in 0..=RESULT_POLLS {
        let _ = console();
        let results = server.validate_results()?;
        if results.len() > before
            && let Some(line) = results.last()
        {
            return Ok(line.clone());
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(format!(
        "the appliance answered no result frame for the {step} sent over the channel, after \
         {RESULT_POLLS} passes over the server's transcript. Every configuration operation is \
         owed one, so this is an appliance that stopped reading its channel"
    ))
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

/// Wait until the forwarding domain says it switched to `generation`, answering
/// the number it settled on.
///
/// `console` answers the capture as it stands and is called afresh every pass:
/// what this waits for is a record the appliance has not written yet, so a
/// snapshot taken before the commit could never carry one.
///
/// # Errors
/// The verdict, naming the generation the forwarding domain had last said it was
/// on — which is the finding rather than a bare timeout.
fn await_dataplane(generation: u32, console: &mut impl FnMut() -> Vec<u8>) -> Result<u32, String> {
    // One pass more than the budget, so a record written while the final interval
    // was being slept through is not reported missing by a pass that never
    // happened.
    for _ in 0..=SWITCH_POLLS {
        let seen = switched_generation(&console());
        if seen >= generation {
            return Ok(seen);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
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

/// One `key=<decimal>` field of a result line.
fn field(line: &str, key: &str) -> Option<u32> {
    token(line, key)?.parse().ok()
}

/// One `key=<token>` field of a result line.
fn token(line: &str, key: &str) -> Option<String> {
    line.split(' ').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then(|| value.to_owned())
    })
}

#[cfg(test)]
mod tests;
