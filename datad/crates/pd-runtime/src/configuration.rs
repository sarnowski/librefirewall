//! The management domain's side of a configuration change: turning a `POST` of a
//! document into a submission the deciding domain answers, and a `GET` into the
//! document that domain says is running.
//!
//! # Adversary
//!
//! A **management-plane attacker** in front and a **byzantine neighbour
//! protection domain** behind. The attacker chooses the bytes and chooses when;
//! nothing here reads them, nothing allocates on their account, and a pass with
//! no answer yet does nothing and comes back. The deciding domain chooses every
//! byte of the answer: `wire::submission` refuses a reply that is not this
//! request's, that names a status outside the closed set, that answers the wrong
//! operation, or that claims more bytes than the region holds. What survives that
//! is a status this module renders and a byte range it hands to the transport
//! unread.
//!
//! # The trust boundary is this module, and it runs one way
//!
//! This domain **carries** a document and **decides nothing about it**. It never
//! parses the bytes, never validates them, never learns what they say — it copies
//! them into a region the deciding domain reads and waits to be told what
//! happened. That is the whole reason the configuration domain exists: it holds no
//! device, no pool and no dataplane ring, so the domain that reads an attacker's
//! XML cannot reach a frame. A parser here would put the two on one side of the
//! boundary and give the split nothing left to withhold.
//!
//! What comes back is equally narrow. The status is one of a closed set, the
//! reject reason is a number this module maps into the console's own vocabulary,
//! and the running document is a byte range copied into the response the transport
//! sends. Nothing here reads a byte of it either: an appliance that had to
//! understand its own configuration in order to state it would be parsing the same
//! document twice, in the two domains the split exists to keep apart.
//!
//! # Why a submission is a body and a read is a window
//!
//! The two directions are the same channel and different shapes. A document is
//! 64 KiB at most and the endpoint already holds one staging array that a body
//! claims, so a submission is copied out of that array in one call and a read is
//! copied into it in one call. There is no windowing here and no second buffer:
//! that machinery exists for a recording, which is megabytes, and a configuration
//! is not.

use lfw_clock::{Duration, Monotonic};
use lfw_ip_endpoint::{ContentType, Status};
use lfw_log::RejectReason;
use wire::{
    ConfigFault, ConfigPoll, ConfigReply, ConfigRequest, ConfigRequester, MAX_DOCUMENT_BYTES,
    PendingConfigRequest,
};

use crate::endpoint::EndpointStage;

// The body bound the endpoint refuses a submission against and the region that
// carries one, tied together where both are visible: a body the server would take
// and the channel could not carry would be a submission that answered `200` and
// changed nothing. Either constant moving apart from the other fails the build
// here rather than on an appliance.
const _: () = {
    assert!(lfw_ip_endpoint::http::MAX_BODY_LEN == MAX_DOCUMENT_BYTES);
    assert!(MAX_DOCUMENT_BYTES > 0);
};

/// The one target this module serves, on `GET` and on `POST`.
///
/// One path rather than two, because the two operations are one resource: what a
/// `GET` states is what a `POST` replaces, and an operator's read/edit/submit loop
/// is against a single URL.
pub const CONFIG_TARGET: &str = "/config";

/// What a stated document is served as.
const CONTENT_TYPE: ContentType = ContentType::Xml;

/// What a submission's answer is served as. `None`: the body is one short line of
/// the console's own field vocabulary, and a media type for it would be inventing
/// a format.
const ANSWER_CONTENT_TYPE: Option<ContentType> = None;

/// Bytes the answer to a submission occupies at most.
///
/// Derived from the vocabulary rather than chosen: the longest reject reason, the
/// widest generation, and the field names around them. A line that outgrew this
/// would be truncated into a different outcome, so the number moves with the
/// vocabulary.
pub const MAX_ANSWER_LEN: usize = answer_bound();

const fn answer_bound() -> usize {
    let mut longest = 0;
    let mut index = 0;
    while index < RejectReason::ALL.len() {
        let len = RejectReason::ALL[index].name().len();
        if len > longest {
            longest = len;
        }
        index += 1;
    }
    // "generation=" + 10 + " outcome=refused" + " rejected=" + reason +
    // " offset=" + 10 + "\n"
    11 + 10 + 16 + 10 + longest + 8 + 10 + 1
}

/// The endpoint half of a configuration change, as this module needs it.
///
/// A trait rather than the concrete stage for [`crate::download::Stream`]'s
/// reason: driving a real endpoint to a submitted body is a TCP handshake, a
/// parsed head and a body split across segments, so the interesting states are
/// hours of protocol away there and one call away against a fake.
pub trait Submissions {
    /// Whether a `GET` of the configuration is waiting on the document.
    fn document_wanted(&self) -> bool;
    /// The document a `POST` submitted, waiting on a decision.
    fn submission(&self) -> Option<&[u8]>;
    /// Answer the waiting `GET` with `document`.
    fn supply_document(&mut self, document: &[u8]);
    /// Answer the waiting submission with `status` and `answer`.
    fn answer_submission(&mut self, status: Status, answer: &[u8]);
    /// Give up on whichever of the two is waiting, with `status`.
    fn refuse(&mut self, status: Status);
}

impl Submissions for EndpointStage<'_> {
    fn document_wanted(&self) -> bool {
        Self::body_wanted(self) == Some(CONFIG_TARGET)
    }

    fn submission(&self) -> Option<&[u8]> {
        Self::submission(self)
    }

    fn supply_document(&mut self, document: &[u8]) {
        Self::supply_rendered(self, Status::Ok, Some(CONTENT_TYPE), document);
    }

    fn answer_submission(&mut self, status: Status, answer: &[u8]) {
        Self::supply_rendered(self, status, ANSWER_CONTENT_TYPE, answer);
    }

    fn refuse(&mut self, status: Status) {
        Self::supply_rendered(self, status, None, &[]);
    }
}

/// How long the deciding domain may take to answer before the request is given up
/// on and the client told the node could not answer.
///
/// It exists because the endpoint's staging array is claimed for the whole of an
/// exchange, and because the slot for an outstanding request here is single: one
/// unanswered request would otherwise be the last configuration exchange this
/// domain completes.
///
/// Five seconds, which is four orders above the work: the deciding domain runs at
/// the highest priority in the system and a commit is a parse and two table
/// builds. A bound on a domain that has stopped answering, not a latency target.
const ANSWER_TIMEOUT: Duration = Duration::from_millis(5_000);

/// A request out to the deciding domain, and what its answer is for.
struct Outstanding {
    pending: PendingConfigRequest,
    /// When this request is given up on, or `None` on a node whose clock has not
    /// been published yet — a state no client can reach, the endpoint refusing every
    /// TCP segment until a calibration has arrived, and carried rather than asserted
    /// away.
    deadline: Option<Monotonic>,
}

/// The configuration half of the management endpoint.
pub struct Configurations<'chan> {
    requester: ConfigRequester<'chan>,
    outstanding: Option<Outstanding>,
    /// The region-length buffer a reply is copied into before the transport takes
    /// it. A field rather than a local because it is 64 KiB and a protection
    /// domain's stack is not where that belongs.
    document: [u8; MAX_DOCUMENT_BYTES],
    /// The one line a submission is answered with, composed here so the endpoint's
    /// staging array holds only what goes on the wire.
    answer: [u8; MAX_ANSWER_LEN],
}

impl<'chan> Configurations<'chan> {
    /// Take the asking side of the channel — once per domain; a second would
    /// restart at sequence zero and reuse numbers the first has outstanding
    /// (`wire::ConfigRequest::requester`).
    #[must_use]
    pub const fn attach(request: &'chan ConfigRequest, reply: &'chan ConfigReply) -> Self {
        Self {
            requester: request.requester(reply),
            outstanding: None,
            document: [0; MAX_DOCUMENT_BYTES],
            answer: [0; MAX_ANSWER_LEN],
        }
    }

    /// Register the configuration target on both methods it answers, so a `GET` of
    /// it states a document and a `POST` to it is a body this domain carries rather
    /// than a `404`.
    ///
    /// Answers whether both were taken; a `false` means one of the endpoint's
    /// target tables is full, which is a build fact rather than a run-time
    /// condition.
    pub fn register(&self, stage: &mut EndpointStage<'_>) -> bool {
        stage.serve_rendered_at(CONFIG_TARGET) && stage.serve_body_at(CONFIG_TARGET)
    }

    /// Replies this domain refused, which is the deciding domain misbehaving. Not
    /// a metric of its own: a refused reply becomes a `503` the endpoint counts,
    /// and the disagreement between that and the config domain's own submission
    /// count is what an operator reads.
    #[must_use]
    pub const fn faults(&self) -> u32 {
        self.requester.faults()
    }

    /// One bounded pass: claim an answer if one has arrived, and issue the request
    /// whichever half of the endpoint is waiting needs.
    ///
    /// Answers **whether a request was issued**, which the caller must turn into a
    /// notification: the deciding domain has no polling loop — it blocks in the
    /// event loop, which is why it costs nothing at the highest priority in the
    /// system — so a document written into the region is invisible to it until it
    /// is woken. Returning the fact rather than sending the signal here is what
    /// keeps a capability out of a crate that has none: the protection domain owns
    /// the channel.
    ///
    /// Never blocks and never spins. A pass with nothing to do returns `false`
    /// having done nothing, which is the whole of the contract with the event loop.
    pub fn poll(&mut self, now: Option<Monotonic>, stage: &mut impl Submissions) -> bool {
        self.claim(now, stage);
        self.ask(now, stage)
    }

    /// Look once for the answer to the outstanding request, giving up on one that
    /// has outlived [`ANSWER_TIMEOUT`].
    fn claim(&mut self, now: Option<Monotonic>, stage: &mut impl Submissions) {
        let Some(Outstanding { pending, deadline }) = self.outstanding.take() else {
            return;
        };
        let Self {
            requester,
            document,
            answer,
            ..
        } = self;
        match requester.poll(pending, document) {
            ConfigPoll::Outstanding(pending) => {
                if expired(now, deadline) {
                    // The handle is dropped rather than re-parked, which is what
                    // frees this domain's one slot. A reply that lands afterwards
                    // answers a sequence no request is held against, and
                    // `ConfigRequester::poll` reads such a reply as no answer at
                    // all — so a late answer cannot be mistaken for the next
                    // request's.
                    //
                    // `503`, on `NoSuchOperation`'s terms exactly: nothing about
                    // the document is known to be wrong, and what failed is the
                    // node's own ability to decide about it.
                    stage.refuse(Status::ServiceUnavailable);
                    return;
                }
                self.outstanding = Some(Outstanding { pending, deadline });
            }
            ConfigPoll::Document { bytes, .. } => stage.supply_document(bytes),
            ConfigPoll::Applied {
                generation,
                changes,
            } => {
                let len = write_answer(answer, generation, Outcome::Applied, changes, None);
                stage.answer_submission(Status::Ok, answer.get(..len).unwrap_or_default());
            }
            ConfigPoll::Unchanged { generation } => {
                let len = write_answer(answer, generation, Outcome::Unchanged, 0, None);
                stage.answer_submission(Status::Ok, answer.get(..len).unwrap_or_default());
            }
            ConfigPoll::Rejected {
                generation,
                reason,
                detail,
            } => {
                let len = write_answer(
                    answer,
                    generation,
                    Outcome::Refused,
                    0,
                    Some((reason_of(reason), detail)),
                );
                // `400`, because the document is the client's and the appliance is
                // working: an operator whose submission is refused for a rule they
                // broke must not read it as a node that is unwell.
                stage.answer_submission(Status::BadRequest, answer.get(..len).unwrap_or_default());
            }
            ConfigPoll::Exhausted { generation } => {
                let len = write_answer(answer, generation, Outcome::Refused, 0, None);
                // `503`, because nothing about the document is wrong: the node has
                // no generation left to assign and resubmitting will not help.
                stage.answer_submission(
                    Status::ServiceUnavailable,
                    answer.get(..len).unwrap_or_default(),
                );
            }
            // Both are the deciding domain failing to answer the question that was
            // asked. Nothing a retry improves, and a client is told the node could
            // not answer rather than being told something about its document.
            ConfigPoll::NoSuchOperation => stage.refuse(Status::ServiceUnavailable),
            ConfigPoll::Faulted(fault) => {
                let _: ConfigFault = fault;
                stage.refuse(Status::ServiceUnavailable);
            }
            // The six answers to the four operations this half never issues,
            // unreachable rather than unexpected: `ConfigStatus::answers` refuses
            // each against a submission or a read before it becomes a poll.
            // Answered rather than asserted, on the two above's terms.
            ConfigPoll::Staged { .. }
            | ConfigPoll::Confirmed { .. }
            | ConfigPoll::RolledBack { .. }
            | ConfigPoll::NoCandidate { .. }
            | ConfigPoll::NotProvisional { .. }
            | ConfigPoll::GenerationMismatch { .. } => stage.refuse(Status::ServiceUnavailable),
        }
    }

    /// Issue whatever the endpoint is waiting on, if nothing is out.
    ///
    /// A submission before a read, because a submission has a client holding a
    /// connection open on it and a read can be asked again; only one of the two can
    /// be waiting in any case, the endpoint holding one staging array.
    ///
    /// Answers whether anything went out, which is what the caller notifies on.
    fn ask(&mut self, now: Option<Monotonic>, stage: &mut impl Submissions) -> bool {
        if self.outstanding.is_some() {
            return false;
        }
        let deadline = now.map(|now| now.saturating_add(ANSWER_TIMEOUT));
        if let Some(document) = stage.submission() {
            let pending = self.requester.submit(document);
            self.outstanding = Some(Outstanding { pending, deadline });
            return true;
        }
        if stage.document_wanted() {
            let pending = self.requester.read();
            self.outstanding = Some(Outstanding { pending, deadline });
            return true;
        }
        false
    }
}

/// Whether a deadline has passed at `now`.
///
/// False for either absence, and the two are different facts rather than one
/// default: an unarmed request has no deadline to miss, and a pass with no reading
/// of the clock cannot judge one. Both mean *not yet*, which is the direction that
/// cannot end an exchange early — a request given up on wrongly is an operator's
/// submission refused for nothing.
fn expired(now: Option<Monotonic>, deadline: Option<Monotonic>) -> bool {
    match (now, deadline) {
        (Some(now), Some(deadline)) => now >= deadline,
        _ => false,
    }
}

/// What a configuration operation became, in the console's own words.
///
/// The tokens are `lfw_log::GenerationOutcome`'s, so the console line, the line
/// out of `curl` and the line the management channel carries all say the same
/// thing about the same event — a second spelling of `unchanged` here is how the
/// three would come to disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Refused,
    Unchanged,
    /// The document is the candidate and nothing is committed.
    Staged,
    /// A provisional commit was made permanent.
    Confirmed,
    /// A provisional commit was undone and what it displaced is running again.
    Reverted,
}

impl Outcome {
    const fn token(self) -> &'static str {
        match self {
            Self::Applied => lfw_log::GenerationOutcome::Applied.name(),
            Self::Refused => lfw_log::GenerationOutcome::Refused.name(),
            Self::Unchanged => lfw_log::GenerationOutcome::Unchanged.name(),
            Self::Staged => lfw_log::GenerationOutcome::Staged.name(),
            Self::Confirmed => lfw_log::GenerationOutcome::Confirmed.name(),
            Self::Reverted => lfw_log::GenerationOutcome::Reverted.name(),
        }
    }
}

/// The reject reason a peer-written word names, for a caller outside this module
/// that has to render one. Re-exported rather than reimplemented: what an
/// undecodable value is substituted with is a decision, and it has one copy.
#[must_use]
pub fn reject_reason_of(bits: u32) -> RejectReason {
    reason_of(bits)
}

/// Compose the one line a configuration operation is reported with, **without a
/// line ending**, answering its length.
///
/// The management channel's result frame is exactly one line and the frame is
/// what delimits it, so a newline in the payload is a byte the far end refuses.
/// [`write_answer`] is this walk plus that ending, which is what keeps the HTTP
/// answer and the channel's result the same grammar rather than two.
pub fn write_result_line(
    out: &mut [u8; MAX_ANSWER_LEN],
    generation: u32,
    outcome: Outcome,
    changes: u32,
    rejection: Option<(RejectReason, u32)>,
) -> usize {
    let mut at = 0usize;
    put(out, &mut at, b"generation=");
    number(out, &mut at, generation);
    put(out, &mut at, b" outcome=");
    put(out, &mut at, outcome.token().as_bytes());
    match rejection {
        Some((reason, detail)) => {
            put(out, &mut at, b" rejected=");
            put(out, &mut at, reason.name().as_bytes());
            put(out, &mut at, b" offset=");
            number(out, &mut at, detail);
        }
        None => {
            put(out, &mut at, b" changes=");
            number(out, &mut at, changes);
        }
    }
    at
}

/// The reject reason a word out of the reply region names.
///
/// The word is peer-written, so a value naming no reason is refused rather than
/// coerced — and the substitute is `malformed`, which is what an unreadable answer
/// about a document amounts to. A reason this domain could not name would
/// otherwise have to be rendered as a number, which is a token an operator cannot
/// look up.
fn reason_of(bits: u32) -> RejectReason {
    let Ok(index) = usize::try_from(bits) else {
        return RejectReason::Malformed;
    };
    RejectReason::ALL
        .get(index)
        .copied()
        .unwrap_or(RejectReason::Malformed)
}

/// Compose the one line a submission is answered with, in the field vocabulary
/// `LFW-CFG` uses.
///
/// Answers the length written. It cannot overrun: [`MAX_ANSWER_LEN`] is derived
/// from this grammar, and every write below is bounded by the slice it is given.
fn write_answer(
    out: &mut [u8; MAX_ANSWER_LEN],
    generation: u32,
    outcome: Outcome,
    changes: u32,
    rejection: Option<(RejectReason, u32)>,
) -> usize {
    let mut at = write_result_line(out, generation, outcome, changes, rejection);
    put(out, &mut at, b"\n");
    at
}

/// Copy `bytes` in at `at`, advancing it. A `zip` rather than a slice, so nothing
/// here can index past the array; the bound is [`MAX_ANSWER_LEN`]'s derivation and
/// what would be lost is the tail of a line rather than memory safety.
fn put(out: &mut [u8; MAX_ANSWER_LEN], at: &mut usize, bytes: &[u8]) {
    for (cell, byte) in out.iter_mut().skip(*at).zip(bytes) {
        *cell = *byte;
        *at = at.saturating_add(1);
    }
}

fn number(out: &mut [u8; MAX_ANSWER_LEN], at: &mut usize, value: u32) {
    let mut digits = [b'0'; 10];
    let mut written = 0usize;
    let mut rest = value;
    loop {
        let digit = b'0'.saturating_add((rest % 10) as u8);
        // Written backwards into a ten-byte array, which holds every `u32`.
        if let Some(cell) = digits.get_mut(9usize.saturating_sub(written)) {
            *cell = digit;
        }
        written = written.saturating_add(1);
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    put(
        out,
        at,
        digits
            .get(10usize.saturating_sub(written)..)
            .unwrap_or_default(),
    );
}

#[cfg(test)]
mod tests;
