use super::*;
use proptest::prelude::*;
use std::boxed::Box;
use std::{string::String, vec::Vec};
use wire::{ConfigAnswer, ConfigOperation, ConfigResponder};

/// A reading of the clock, as a pass hands one to the module under test — built
/// the way a domain builds one, a `Monotonic` being reachable only through a
/// `Calibration`. Every exchange below completes inside one instant, so a test
/// that names zero is one whose deadline is armed and nowhere near reached.
fn at(nanos: u64) -> Option<Monotonic> {
    use core::num::NonZeroU64;
    use lfw_clock::{Calibration, Ticks};
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    Some(Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(nanos)))
}

/// The two regions one channel is, on the heap: 128 KiB of region is more than
/// belongs on a test stack, and a test drives both ends.
struct Channel {
    request: Box<ConfigRequest>,
    reply: Box<ConfigReply>,
}

impl Channel {
    fn zero() -> Self {
        Self {
            request: Box::new(ConfigRequest::zero()),
            reply: Box::new(ConfigReply::zero()),
        }
    }

    fn management(&self) -> Configurations<'_> {
        Configurations::attach(&self.request, &self.reply)
    }

    fn deciding(&self) -> ConfigResponder<'_> {
        self.reply.responder(&self.request)
    }
}

/// What the endpoint half did, recorded rather than performed.
///
/// The interesting states — a submission waiting, a read waiting, neither — are a
/// TCP handshake and a parsed head away against a real endpoint and one field away
/// here, which is the whole reason [`Submissions`] is a trait.
#[derive(Default)]
struct Endpoint {
    /// Set where a `GET` is waiting on the document.
    wants_document: bool,
    /// The body a `POST` submitted, waiting on a decision.
    submitted: Option<Vec<u8>>,
    /// Every answer this endpoint was handed, in order.
    answered: Vec<(Status, String)>,
    /// Every document it was handed.
    documents: Vec<Vec<u8>>,
}

impl Endpoint {
    fn submitting(document: &[u8]) -> Self {
        Self {
            submitted: Some(document.to_vec()),
            ..Self::default()
        }
    }

    fn reading() -> Self {
        Self {
            wants_document: true,
            ..Self::default()
        }
    }

    /// The one answer a pass produced, as the status and the line together.
    fn answer(&self) -> (Status, &str) {
        let (status, line) = self.answered.last().expect("an answer");
        (*status, line.as_str())
    }
}

impl Submissions for Endpoint {
    fn document_wanted(&self) -> bool {
        self.wants_document
    }

    fn submission(&self) -> Option<&[u8]> {
        self.submitted.as_deref()
    }

    fn supply_document(&mut self, document: &[u8]) {
        self.wants_document = false;
        self.documents.push(document.to_vec());
    }

    fn answer_submission(&mut self, status: Status, answer: &[u8]) {
        self.submitted = None;
        self.answered.push((
            status,
            String::from_utf8(answer.to_vec()).expect("the answer grammar is ASCII"),
        ));
    }

    fn refuse(&mut self, status: Status) {
        self.submitted = None;
        self.wants_document = false;
        self.answered.push((status, String::new()));
    }
}

/// One exchange: the management half asks, the deciding half answers with
/// `answer`, and the management half claims it.
fn exchange(endpoint: &mut Endpoint, answer: ConfigAnswer) {
    let channel = Channel::zero();
    let mut management = channel.management();
    let mut deciding = channel.deciding();

    assert!(management.poll(at(0), endpoint), "no request was issued");
    let demand = deciding.take().expect("a request was issued");
    assert_eq!(demand.operation(), Some(ConfigOperation::Submit));
    deciding.answer(demand, answer);
    management.poll(at(0), endpoint);
}

#[test]
fn a_submitted_document_crosses_unread_and_its_answer_comes_back() {
    let channel = Channel::zero();
    let mut management = channel.management();
    let mut deciding = channel.deciding();
    let mut endpoint = Endpoint::submitting(b"<configuration/>");

    management.poll(at(0), &mut endpoint);
    let demand = deciding.take().expect("a request");
    assert_eq!(demand.operation(), Some(ConfigOperation::Submit));
    let mut scratch = Box::new([0u8; MAX_DOCUMENT_BYTES]);
    assert_eq!(
        deciding.document(&demand, &mut scratch),
        b"<configuration/>",
        "the bytes reached the deciding domain unchanged"
    );
    // Nothing has been answered yet, and the submission is still the endpoint's.
    assert!(endpoint.answered.is_empty());
    assert!(endpoint.submitted.is_some());

    deciding.answer(
        demand,
        ConfigAnswer::Applied {
            generation: 2,
            changes: 3,
        },
    );
    management.poll(at(0), &mut endpoint);
    assert_eq!(
        endpoint.answer(),
        (Status::Ok, "generation=2 outcome=applied changes=3\n")
    );
    assert_eq!(management.faults(), 0);
}

/// Every answer shape, and the status each earns.
///
/// The vocabulary is the console's: `generation=`, `outcome=`, `changes=`,
/// `rejected=` and `offset=` are the fields `LFW-CFG` carries, so an operator
/// reading a refusal in a terminal and one in the serial log reads one thing.
#[test]
fn every_answer_names_its_outcome_in_the_consoles_own_words() {
    let cases: [(ConfigAnswer, Status, &str); 5] = [
        (
            ConfigAnswer::Applied {
                generation: 7,
                changes: 12,
            },
            Status::Ok,
            "generation=7 outcome=applied changes=12\n",
        ),
        (
            ConfigAnswer::Unchanged { generation: 7 },
            Status::Ok,
            "generation=7 outcome=unchanged changes=0\n",
        ),
        (
            ConfigAnswer::Rejected {
                generation: 7,
                reason: RejectReason::Doctype as u32,
                detail: 21,
            },
            Status::BadRequest,
            "generation=7 outcome=refused rejected=doctype offset=21\n",
        ),
        (
            ConfigAnswer::Rejected {
                generation: 0,
                reason: RejectReason::RenderingTooLarge as u32,
                detail: 0,
            },
            Status::BadRequest,
            "generation=0 outcome=refused rejected=rendering-too-large offset=0\n",
        ),
        (
            ConfigAnswer::Exhausted {
                generation: u32::MAX,
            },
            Status::ServiceUnavailable,
            "generation=4294967295 outcome=refused changes=0\n",
        ),
    ];
    for (answer, status, line) in cases {
        let mut endpoint = Endpoint::submitting(b"<configuration/>");
        exchange(&mut endpoint, answer);
        assert_eq!(endpoint.answer(), (status, line), "{answer:?}");
    }
}

/// A refused document is the *client's* fault and a spent counter is the node's,
/// and the two statuses say which: an operator whose document is refused for a
/// rule they broke must not read it as a node that is unwell.
#[test]
fn a_refused_document_is_a_client_error_and_a_spent_counter_is_not() {
    let mut endpoint = Endpoint::submitting(b"<configuration/>");
    exchange(
        &mut endpoint,
        ConfigAnswer::Rejected {
            generation: 1,
            reason: RejectReason::Malformed as u32,
            detail: 4,
        },
    );
    assert_eq!(endpoint.answer().0, Status::BadRequest);

    let mut endpoint = Endpoint::submitting(b"<configuration/>");
    exchange(&mut endpoint, ConfigAnswer::Exhausted { generation: 1 });
    assert_eq!(endpoint.answer().0, Status::ServiceUnavailable);
}

#[test]
fn a_read_answers_with_the_running_document() {
    let channel = Channel::zero();
    let mut management = channel.management();
    let mut deciding = channel.deciding();
    let mut endpoint = Endpoint::reading();

    management.poll(at(0), &mut endpoint);
    let demand = deciding.take().expect("a request");
    assert_eq!(demand.operation(), Some(ConfigOperation::Read));
    assert!(demand.is_empty(), "a read carries no document out");
    deciding.deliver(demand, 3, b"<configuration><rules/></configuration>");

    management.poll(at(0), &mut endpoint);
    assert_eq!(
        endpoint.documents,
        [b"<configuration><rules/></configuration>".to_vec()]
    );
    assert!(endpoint.answered.is_empty(), "a read is not an answer");
}

/// A whole document, so the copy is exercised at the region's own bound rather
/// than on a token fixture.
#[test]
fn a_document_the_size_of_the_region_crosses_both_ways() {
    let long: Vec<u8> = (0..MAX_DOCUMENT_BYTES)
        .map(|index| b'a'.wrapping_add((index % 26) as u8))
        .collect();
    let channel = Channel::zero();
    let mut management = channel.management();
    let mut deciding = channel.deciding();
    let mut endpoint = Endpoint::submitting(&long);

    management.poll(at(0), &mut endpoint);
    let demand = deciding.take().expect("a request");
    let mut scratch = Box::new([0u8; MAX_DOCUMENT_BYTES]);
    assert_eq!(deciding.document(&demand, &mut scratch), long.as_slice());
    deciding.answer(demand, ConfigAnswer::Unchanged { generation: 1 });
    management.poll(at(0), &mut endpoint);
    assert_eq!(endpoint.answer().0, Status::Ok);

    let mut endpoint = Endpoint::reading();
    management.poll(at(0), &mut endpoint);
    let demand = deciding.take().expect("a read");
    deciding.deliver(demand, 1, &long);
    management.poll(at(0), &mut endpoint);
    assert_eq!(endpoint.documents, [long]);
}

/// Nothing waiting, nothing asked: a pass with no work does none, which is the
/// whole of the contract with an event loop that wakes on any notification.
#[test]
fn a_pass_with_nothing_waiting_issues_nothing() {
    let channel = Channel::zero();
    let mut management = channel.management();
    let mut deciding = channel.deciding();
    let mut endpoint = Endpoint::default();

    for _ in 0..4 {
        assert!(
            !management.poll(at(0), &mut endpoint),
            "a pass with nothing waiting issued a request"
        );
    }
    assert_eq!(deciding.take(), None);
    assert!(endpoint.answered.is_empty());
    assert!(endpoint.documents.is_empty());
}

/// One request in flight at a time: a second is not issued until the first is
/// answered, which is what makes the sequence number the whole correlation.
#[test]
fn a_second_request_waits_for_the_first_to_be_answered() {
    let channel = Channel::zero();
    let mut management = channel.management();
    let mut deciding = channel.deciding();
    let mut endpoint = Endpoint::submitting(b"<configuration/>");

    management.poll(at(0), &mut endpoint);
    let first = deciding.take().expect("a request");
    assert_eq!(first.sequence(), 1);
    // A read arrives while the submission is out. Nothing new is issued for it:
    // the sequence the requester published has not moved, which is the whole of
    // what "one request in flight" means.
    endpoint.wants_document = true;
    for _ in 0..4 {
        assert!(
            !management.poll(at(0), &mut endpoint),
            "a second request was issued while the first was outstanding"
        );
    }
    assert_eq!(
        deciding.take().map(|again| again.sequence()),
        Some(1),
        "a second request was issued while the first was outstanding"
    );

    deciding.answer(first, ConfigAnswer::Unchanged { generation: 1 });
    management.poll(at(0), &mut endpoint);
    assert_eq!(endpoint.answer().0, Status::Ok);
    // And now the read goes out.
    let second = deciding.take().expect("the read");
    assert_eq!(second.operation(), Some(ConfigOperation::Read));
    deciding.deliver(second, 1, b"<configuration/>");
    management.poll(at(0), &mut endpoint);
    assert_eq!(endpoint.documents.len(), 1);
}

/// A submission before a read, because a submission has a client holding a
/// connection open on it.
#[test]
fn a_submission_is_asked_before_a_read() {
    let channel = Channel::zero();
    let mut management = channel.management();
    let mut deciding = channel.deciding();
    let mut endpoint = Endpoint::submitting(b"<configuration/>");
    endpoint.wants_document = true;

    management.poll(at(0), &mut endpoint);
    let demand = deciding.take().expect("a request");
    assert_eq!(demand.operation(), Some(ConfigOperation::Submit));
}

/// An answer that cannot be believed: the client is told the node could not
/// answer, and is told nothing about its document.
///
/// The misbehaviour is produced through the responder's own API rather than by
/// writing the region behind it — a deciding domain that answered a submission
/// with a document, and one that answered a read with a generation, are both one
/// call away and are the two crossings the protocol's one cross-field rule
/// forbids. Every other unbelievable reply is refused by the same arm, and
/// `wire::submission` is where each is enumerated.
#[test]
fn an_answer_that_cannot_be_believed_is_a_service_failure_and_not_a_verdict() {
    // A document answering a submission.
    let channel = Channel::zero();
    let mut management = channel.management();
    let mut deciding = channel.deciding();
    let mut endpoint = Endpoint::submitting(b"<configuration/>");
    management.poll(at(0), &mut endpoint);
    let demand = deciding.take().expect("a request");
    deciding.deliver(demand, 1, b"<configuration/>");
    management.poll(at(0), &mut endpoint);
    assert_eq!(endpoint.answer(), (Status::ServiceUnavailable, ""));
    assert_eq!(management.faults(), 1);
    assert!(
        endpoint.documents.is_empty(),
        "a document nobody asked for was served"
    );

    // And a generation answering a read.
    let channel = Channel::zero();
    let mut management = channel.management();
    let mut deciding = channel.deciding();
    let mut endpoint = Endpoint::reading();
    management.poll(at(0), &mut endpoint);
    let demand = deciding.take().expect("a read");
    deciding.answer(
        demand,
        ConfigAnswer::Applied {
            generation: 2,
            changes: 1,
        },
    );
    management.poll(at(0), &mut endpoint);
    assert_eq!(endpoint.answer(), (Status::ServiceUnavailable, ""));
    assert_eq!(management.faults(), 1);
}

/// An operation the deciding domain does not recognise. Not a fault — it is a
/// well-formed answer — and still not a verdict about the document.
#[test]
fn an_unrecognised_operation_is_answered_and_is_not_a_fault() {
    let channel = Channel::zero();
    let mut management = channel.management();
    let mut deciding = channel.deciding();
    let mut endpoint = Endpoint::submitting(b"<configuration/>");
    management.poll(at(0), &mut endpoint);
    let demand = deciding.take().expect("a request");
    deciding.answer(demand, ConfigAnswer::NoSuchOperation);
    management.poll(at(0), &mut endpoint);
    assert_eq!(endpoint.answer(), (Status::ServiceUnavailable, ""));
    assert_eq!(management.faults(), 0);
}

/// The reason word is peer-written, so a value naming no reason is rendered as a
/// token an operator can look up rather than as a number they cannot.
#[test]
fn a_reason_naming_nothing_is_rendered_as_a_reason_that_exists() {
    for bits in [RejectReason::ALL.len() as u32, u32::MAX, 1_000_000] {
        assert_eq!(reason_of(bits), RejectReason::Malformed);
    }
    for (index, reason) in RejectReason::ALL.iter().enumerate() {
        assert_eq!(reason_of(index as u32), *reason);
    }
}

/// The answer line's bound is derived from the vocabulary, so the longest line the
/// grammar can produce fits — and a reason appended to the vocabulary moves the
/// number rather than truncating a line into a different outcome.
#[test]
fn the_longest_answer_the_grammar_can_produce_fits_its_bound() {
    let longest = RejectReason::ALL
        .iter()
        .map(|reason| {
            let mut out = [0u8; MAX_ANSWER_LEN];
            write_answer(
                &mut out,
                u32::MAX,
                Outcome::Refused,
                0,
                Some((*reason, u32::MAX)),
            )
        })
        .max()
        .expect("the vocabulary is not empty");
    assert!(longest <= MAX_ANSWER_LEN, "{longest} bytes");
    // And the bound is not wildly loose: it is the grammar's own worst case plus
    // the field names, so a reader can tell it was derived.
    assert!(
        MAX_ANSWER_LEN - longest < 16,
        "{MAX_ANSWER_LEN} vs {longest}"
    );

    let mut out = [0u8; MAX_ANSWER_LEN];
    let len = write_answer(&mut out, u32::MAX, Outcome::Applied, u32::MAX, None);
    assert_eq!(
        core::str::from_utf8(out.get(..len).expect("in range")),
        Ok("generation=4294967295 outcome=applied changes=4294967295\n")
    );
}

proptest! {
    /// Whatever the numbers, an answer is one line of the grammar: it fits, it
    /// ends in a newline, and every byte of it is one a console line could
    /// carry.
    #[test]
    fn every_answer_is_one_renderable_line(
        generation in any::<u32>(),
        changes in any::<u32>(),
        detail in any::<u32>(),
        reason in 0usize..RejectReason::ALL.len(),
        rejected in any::<bool>(),
    ) {
        let mut out = [0u8; MAX_ANSWER_LEN];
        let rejection = rejected
            .then(|| (RejectReason::ALL[reason], detail));
        let len = write_answer(&mut out, generation, Outcome::Refused, changes, rejection);
        prop_assert!(len <= MAX_ANSWER_LEN);
        let line = out.get(..len).expect("in range");
        prop_assert_eq!(line.last(), Some(&b'\n'));
        prop_assert!(
            line.iter().all(|byte| byte.is_ascii_graphic() || *byte == b' ' || *byte == b'\n'),
            "{line:?}"
        );
        let text = core::str::from_utf8(line).expect("ASCII");
        prop_assert!(text.starts_with("generation="));
        prop_assert!(text.contains(" outcome=refused"));
        prop_assert_eq!(text.contains(" rejected="), rejected);
    }

    /// Any answer to any request produces a status from the closed set and a line
    /// inside its bound, whichever operation was asked and whichever shape came
    /// back — including the two crossings that are faults.
    #[test]
    fn any_answer_to_any_request_is_bounded_and_never_panics(
        read in any::<bool>(),
        document in any::<bool>(),
        generation in any::<u32>(),
        changes in any::<u32>(),
        reason in 0usize..RejectReason::ALL.len(),
    ) {
        let channel = Channel::zero();
        let mut management = channel.management();
        let mut deciding = channel.deciding();
        let mut endpoint = if read {
            Endpoint::reading()
        } else {
            Endpoint::submitting(b"<configuration/>")
        };
        management.poll(at(0), &mut endpoint);
        let demand = deciding.take().expect("a request");
        if document {
            deciding.deliver(demand, generation, b"<configuration/>");
        } else {
            deciding.answer(demand, ConfigAnswer::Rejected {
                generation,
                reason: RejectReason::ALL[reason] as u32,
                detail: changes,
            });
        }
        management.poll(at(0), &mut endpoint);
        for (status, line) in &endpoint.answered {
            prop_assert!(line.len() <= MAX_ANSWER_LEN);
            prop_assert!(Status::ALL.contains(status));
        }
        for served in &endpoint.documents {
            prop_assert!(served.len() <= MAX_DOCUMENT_BYTES);
        }
        // Exactly one of the two happened: the document was served, or the
        // submission was answered. Never both, and never neither.
        prop_assert_eq!(endpoint.answered.len() + endpoint.documents.len(), 1);
    }
}

/// A deciding domain that never answers does not hold this module's one
/// outstanding slot forever: the request is given up on at its deadline and the
/// client told the node could not answer.
///
/// Without the deadline the submission stays waiting, the endpoint's staging array
/// stays claimed, and every body-bearing surface answers 503 for the life of the
/// domain.
#[test]
fn a_deciding_domain_that_never_answers_is_given_up_on() {
    let channel = Channel::zero();
    let mut management = channel.management();
    let mut deciding = channel.deciding();
    let mut endpoint = Endpoint::submitting(b"<configuration/>");

    assert!(
        management.poll(at(0), &mut endpoint),
        "the request went out"
    );
    let demand = deciding.take().expect("a request was issued");
    assert_eq!(demand.operation(), Some(ConfigOperation::Submit));
    // And is never answered: `demand` is dropped without a reply.
    drop(demand);

    let deadline = ANSWER_TIMEOUT.as_nanos();
    management.poll(at(deadline - 1), &mut endpoint);
    assert!(endpoint.answered.is_empty(), "given up on early");

    management.poll(at(deadline), &mut endpoint);
    assert_eq!(
        endpoint.answer(),
        (Status::ServiceUnavailable, ""),
        "the client was not told the node could not answer"
    );

    // And the slot is free again, so the *next* submission is issued rather than
    // being the one this domain never gets to.
    let mut next = Endpoint::submitting(b"<configuration/>");
    assert!(
        management.poll(at(deadline), &mut next),
        "the outstanding slot was never given back"
    );
}

/// A late answer cannot be mistaken for the next request's. The abandoned request
/// left a sequence number behind, and the reply to it answers a number no pending
/// request is held against — which the requester reads as no answer at all.
#[test]
fn an_answer_that_arrives_after_the_deadline_answers_nothing() {
    let channel = Channel::zero();
    let mut management = channel.management();
    let mut deciding = channel.deciding();
    let mut endpoint = Endpoint::submitting(b"<configuration/>");

    assert!(management.poll(at(0), &mut endpoint));
    let stale = deciding.take().expect("a request was issued");
    let deadline = ANSWER_TIMEOUT.as_nanos();
    management.poll(at(deadline), &mut endpoint);
    assert_eq!(endpoint.answer().0, Status::ServiceUnavailable);

    // The deciding domain answers the request that was abandoned, and a fresh
    // submission is outstanding by now.
    let mut next = Endpoint::submitting(b"<configuration/>");
    assert!(management.poll(at(deadline), &mut next));
    deciding.answer(
        stale,
        ConfigAnswer::Applied {
            generation: 7,
            changes: 3,
        },
    );
    management.poll(at(deadline), &mut next);
    assert!(
        next.answered.is_empty(),
        "a reply to an abandoned request was taken for the new one's: {:?}",
        next.answered
    );
}

/// A node whose clock has not been published arms no deadline, and a pass with no
/// reading of the clock judges none. Both mean *not yet*, which is the direction
/// that cannot refuse an operator's submission for nothing.
#[test]
fn an_unclocked_pass_gives_up_on_nothing() {
    let channel = Channel::zero();
    let mut management = channel.management();
    let mut deciding = channel.deciding();
    let mut endpoint = Endpoint::submitting(b"<configuration/>");

    assert!(management.poll(None, &mut endpoint), "the request went out");
    let _demand = deciding.take().expect("a request was issued");
    for _ in 0..4 {
        management.poll(None, &mut endpoint);
    }
    assert!(endpoint.answered.is_empty());

    // A clock arriving afterwards arms nothing retroactively — the request was
    // parked without a deadline — so it is the *next* request that is bounded.
    management.poll(at(ANSWER_TIMEOUT.as_nanos() * 4), &mut endpoint);
    assert!(endpoint.answered.is_empty());
}
