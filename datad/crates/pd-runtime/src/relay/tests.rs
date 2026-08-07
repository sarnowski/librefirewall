use super::*;
use lfw_tcp::{IsnSecret, TcpStack};
use proptest::prelude::*;
use std::boxed::Box;
use std::{vec, vec::Vec};
use wire::RelayResponder;

/// A reading of the clock, as a pass hands one to the module under test — built
/// the way a domain builds one, a `Monotonic` being reachable only through a
/// `Calibration`.
fn at(nanos: u64) -> Option<Monotonic> {
    use core::num::NonZeroU64;
    use lfw_clock::{Calibration, Ticks};
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    Some(Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(nanos)))
}

/// The two regions one channel is, on the heap: a maximal record each way is
/// more than belongs on a test stack, and a test drives both ends.
struct Channel {
    request: Box<RelayRequest>,
    reply: Box<RelayReply>,
}

impl Channel {
    fn zero() -> Self {
        Self {
            request: Box::new(RelayRequest::zero()),
            reply: Box::new(RelayReply::zero()),
        }
    }

    fn network(&self) -> Relay<'_> {
        Relay::attach(&self.request, &self.reply)
    }

    fn terminating(&self) -> RelayResponder<'_> {
        self.reply.responder(&self.request)
    }
}

/// Two connection handles a transport really issued, which is the only way to
/// get a pair the pump can tell apart: the generation is the table's and a
/// handle invented here would compare equal to the one beside it.
fn handles() -> (ConnectionId, ConnectionId) {
    let mut stack: TcpStack<2> = TcpStack::new(
        net_headers::Ipv4Address::from_octets([10, 0, 0, 1]),
        4443,
        1460,
        4096,
        IsnSecret::from_bytes([7; 16]),
    );
    let mut out = vec![0u8; 128];
    let now = at(0).expect("a clock");
    let peer = net_headers::Ipv4Address::from_octets([10, 0, 0, 2]);
    let first = stack
        .connect(now, peer, 443, &mut out)
        .expect("a dial into an empty table")
        .connection;
    let second = stack
        .connect(now, peer, 444, &mut out)
        .expect("a second dial into a table with room")
        .connection;
    assert_ne!(first, second);
    (first, second)
}

/// The onboarding half, recorded rather than performed.
///
/// The interesting states — a session with bytes waiting, a peer that has
/// closed, a stream with no room left — are a handshake and several frames away
/// against a real endpoint and one field away here, which is the whole reason
/// [`Onboarding`] is a trait.
#[derive(Default)]
struct Stream {
    session: Option<ConnectionId>,
    waiting: Vec<u8>,
    peer_closed: bool,
    /// What the pump put on the wire, in order.
    pushed: Vec<u8>,
    /// How much of an offered run this stream will take. `None` takes all of it.
    room: Option<usize>,
    ended: bool,
    /// How the session running now would end, as the real stream records it the
    /// moment one of the two ends says so.
    ending: Option<Ended>,
    /// How the **last** session ended, waiting to be taken exactly once — the
    /// real stream's own shape, and what makes an ending left behind readable as
    /// the next session's.
    last_ending: Option<Ended>,
    /// Closes this stream refused for naming a session it no longer held.
    refused_closes: usize,
}

impl Stream {
    fn running() -> Self {
        Self {
            session: Some(handles().0),
            ..Self::default()
        }
    }

    /// The transport has given the connection back, which is what makes a
    /// session over: a real stream forgets it a frame or two after the close
    /// goes out, and the pump makes the account then.
    fn forgotten(&mut self) {
        self.session = None;
        self.last_ending = Some(self.ending.unwrap_or(Ended::Forgotten));
        self.ending = None;
    }

    /// The peer reset and reconnected, so the transport holds a **different**
    /// connection: everything the old session had is gone with it and the handle
    /// is one the table issued for the new one.
    fn reconnected(&mut self) {
        self.forgotten();
        self.session = Some(handles().1);
        self.ended = false;
    }
}

impl Onboarding for Stream {
    fn session(&self) -> Option<ConnectionId> {
        self.session
    }

    fn received(&self) -> &[u8] {
        &self.waiting
    }

    fn consumed(&mut self, bytes: usize) {
        self.waiting.drain(..bytes.min(self.waiting.len()));
    }

    fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    fn push(&mut self, bytes: &[u8]) -> usize {
        let kept = self.room.map_or(bytes.len(), |room| room.min(bytes.len()));
        self.pushed.extend_from_slice(&bytes[..kept]);
        self.room = self.room.map(|room| room.saturating_sub(kept));
        kept
    }

    /// The real stream refuses a name it does not hold, and so does this one: it
    /// is the property under test in
    /// [`a_close_for_a_session_that_is_gone_leaves_the_new_one_alone`], and a
    /// fake that ended whatever was running would prove the pump right whatever
    /// it did.
    fn end_session(&mut self, connection: ConnectionId) -> bool {
        if self.session != Some(connection) {
            self.refused_closes += 1;
            return false;
        }
        self.ended = true;
        self.ending.get_or_insert(Ended::ByConsumer);
        true
    }

    fn take_ending(&mut self) -> Option<Ended> {
        self.last_ending.take()
    }

    fn ending(&self) -> Ended {
        self.ending.unwrap_or(Ended::Forgotten)
    }
}

/// What the far end's protocol did with a turn, recorded rather than performed.
///
/// Behind a shared handle so a test can read it while the relay holds the
/// terminator: the real one is a TLS server the relay owns for the life of the
/// domain, and there is no borrow of it to take mid-session.
#[derive(Default)]
struct Spoken {
    opens: usize,
    closes: usize,
    turns: usize,
    /// Everything the protocol was handed, run together.
    heard: Vec<u8>,
    /// Finish the session on this turn, counting from one.
    finish_on: Option<usize>,
    /// Claim this many bytes written, whatever was written.
    overstate: Option<usize>,
}

/// The protocol the far end terminates with. It answers what it was handed, so
/// a test can follow one run of bytes all the way across and back.
#[derive(Clone, Default)]
struct Protocol(std::rc::Rc<core::cell::RefCell<Spoken>>);

impl Protocol {
    fn spoken(&self) -> core::cell::Ref<'_, Spoken> {
        self.0.borrow()
    }

    fn finish_on(&self, turn: usize) {
        self.0.borrow_mut().finish_on = Some(turn);
    }

    fn overstate(&self, sent: usize) {
        self.0.borrow_mut().overstate = Some(sent);
    }
}

impl Terminator for Protocol {
    fn opened(&mut self) {
        self.0.borrow_mut().opens += 1;
    }

    fn advance(&mut self, received: &[u8], answer: &mut [u8]) -> Answered {
        let mut spoken = self.0.borrow_mut();
        spoken.turns += 1;
        spoken.heard.extend_from_slice(received);
        let len = received.len().min(answer.len());
        answer[..len].copy_from_slice(&received[..len]);
        Answered {
            sent: spoken.overstate.unwrap_or(len),
            finished: spoken.finish_on == Some(spoken.turns),
        }
    }

    fn closed(&mut self) {
        self.0.borrow_mut().closes += 1;
    }
}

/// What the far end answered, and what it was asked.
fn serve(responder: &mut RelayResponder<'_>, records: &[u8], closed: bool) -> RelayOperation {
    let demand = responder.take().expect("an item to answer");
    let operation = demand.operation().expect("a decodable operation");
    responder.answered(demand, records, closed);
    operation
}

#[test]
fn a_session_opens_delivers_and_closes() {
    let channel = Channel::zero();
    let mut relay = channel.network();
    let mut far = channel.terminating();
    let mut stream = Stream::running();

    // The pass that finds a session issues an `Open` and asks for a wakeup.
    let pass = relay.poll(at(0), &mut stream);
    assert!(pass.notify);
    assert!(pass.report.is_none());
    assert_eq!(serve(&mut far, &[], false), RelayOperation::Open);

    // With nothing to deliver, the next pass polls once — and only once.
    let pass = relay.poll(at(1), &mut stream);
    assert!(pass.notify);
    assert_eq!(serve(&mut far, &[], false), RelayOperation::Poll);
    let pass = relay.poll(at(2), &mut stream);
    assert!(!pass.notify, "a second poll would answer its own answer");

    // Bytes off the wire cross whole, and the far end's answer goes back out.
    stream.waiting.extend_from_slice(b"client hello");
    let pass = relay.poll(at(3), &mut stream);
    assert!(pass.notify);
    assert!(stream.waiting.is_empty(), "the bytes were handed over");
    assert_eq!(
        serve(&mut far, b"server hello", false),
        RelayOperation::Deliver
    );
    let pass = relay.poll(at(4), &mut stream);
    assert_eq!(stream.pushed, b"server hello");
    assert!(pass.report.is_none());
    // Records came back, so the one poll between two events is due again.
    assert!(pass.notify);
    assert_eq!(serve(&mut far, &[], false), RelayOperation::Poll);

    // The peer hangs up; the far end is closed and the session reported once
    // the transport has given the connection back.
    stream.peer_closed = true;
    stream.ending = Some(Ended::ByPeer);
    let pass = relay.poll(at(5), &mut stream);
    assert!(pass.notify);
    // The close carries how the session ended, so the far end reports the same
    // party this end will.
    assert_eq!(
        serve(&mut far, &[], true),
        RelayOperation::Close(RelayEnding::Peer)
    );
    let pass = relay.poll(at(6), &mut stream);
    assert!(pass.report.is_none(), "the connection is still closing");
    stream.forgotten();
    let pass = relay.poll(at(7), &mut stream);
    let report = pass.report.expect("the session's account");
    assert_eq!(report.received, b"client hello".len() as u64);
    assert_eq!(report.sent, b"server hello".len() as u64);
    assert_eq!(report.ended, OnboardEnd::Peer);
    assert!(report.failure.is_none());
    assert!(report.relayed >= 4);
}

#[test]
fn the_far_end_may_end_the_session_itself() {
    let channel = Channel::zero();
    let mut relay = channel.network();
    let mut far = channel.terminating();
    let mut stream = Stream::running();

    relay.poll(at(0), &mut stream);
    serve(&mut far, &[], false);
    relay.poll(at(1), &mut stream);
    // The answer to the poll says the session is over and carries its last
    // records: both must reach the stream.
    serve(&mut far, b"alert", true);
    let pass = relay.poll(at(2), &mut stream);
    assert_eq!(stream.pushed, b"alert");
    assert!(stream.ended);
    assert!(pass.report.is_none(), "the connection is still closing");
    stream.forgotten();
    let pass = relay.poll(at(3), &mut stream);
    let report = pass.report.expect("the session's account");
    assert_eq!(report.ended, OnboardEnd::Consumer);
    assert!(report.failure.is_none());
}

#[test]
fn a_refusal_ends_the_session_and_names_itself() {
    let channel = Channel::zero();
    let mut relay = channel.network();
    let mut far = channel.terminating();
    let mut stream = Stream::running();

    relay.poll(at(0), &mut stream);
    let demand = far.take().expect("the open");
    far.refuse(demand, RelayRefusal::SessionFailed);
    relay.poll(at(1), &mut stream);
    assert!(stream.ended, "the connection is taken down at once");
    stream.forgotten();
    let pass = relay.poll(at(2), &mut stream);
    let report = pass.report.expect("the session's account");
    assert_eq!(
        report.failure,
        Some(RelayFailure::Refused(RelayRefusal::SessionFailed))
    );
    assert_eq!(report.ended, OnboardEnd::Refused);
    assert!(stream.ended, "the connection is taken down with it");
}

/// A second network end writing the same request region, which is what makes a
/// fault reachable at all: a responder keeping to the ABI echoes the operation
/// it was handed, so every fault in `wire::relay` is a region written by
/// something that is not keeping to it. Two requesters on one region is the
/// smallest honest way to be that thing — and it is precisely the confused or
/// compromised network end the fault vocabulary exists for.
///
/// It can corrupt the **first** item and no other: a requester that never polls
/// holds its own window open after one write, and a fresh one restarts at the
/// sequence the far end has already served. So the fault below lands on the
/// open, which is the one place a well-behaved far end can be made to answer a
/// question this end did not ask.
fn overwrite(channel: &Channel, operation: RelayOperation) {
    let mut second = channel.request.requester(&channel.reply);
    let _ = second.request(operation, &[]);
}

#[test]
fn a_reply_that_answers_the_wrong_question_is_a_fault() {
    let channel = Channel::zero();
    let mut relay = channel.network();
    let mut far = channel.terminating();
    let mut stream = Stream::running();

    // The open goes out and is overwritten with a deliver before the far end
    // reads it, so the answer echoes an operation this end never asked for.
    relay.poll(at(0), &mut stream);
    overwrite(&channel, RelayOperation::Deliver);
    assert_eq!(serve(&mut far, &[], false), RelayOperation::Deliver);

    let pass = relay.poll(at(1), &mut stream);
    assert!(pass.report.is_none(), "the connection is still closing");
    assert!(stream.ended, "the connection is taken down at once");
    assert_eq!(relay.faults(), 1);
    // Nothing is owed to the far end: it never confirmed a session, so there is
    // none there to close.
    assert!(!relay.outstanding());

    stream.forgotten();
    let pass = relay.poll(at(2), &mut stream);
    let report = pass.report.expect("the session's account");
    assert!(matches!(
        report.failure,
        Some(RelayFailure::Faulted(RelayFault::WrongOperation { .. }))
    ));
    assert_eq!(report.ended, OnboardEnd::Refused);
}

#[test]
fn a_far_end_that_never_answers_is_given_up_on() {
    let channel = Channel::zero();
    let mut relay = channel.network();
    let mut stream = Stream::running();

    relay.poll(at(0), &mut stream);
    // Well inside the bound: the item stands.
    let pass = relay.poll(at(1), &mut stream);
    assert!(pass.report.is_none());
    assert!(relay.outstanding());
    let past = ANSWER_TIMEOUT.as_nanos().saturating_add(1);
    relay.poll(at(past), &mut stream);
    assert!(!relay.outstanding(), "the one slot is free again");
    assert!(stream.ended, "the connection is taken down with it");
    stream.forgotten();
    let pass = relay.poll(at(past + 1), &mut stream);
    let report = pass.report.expect("the session's account");
    assert_eq!(report.failure, Some(RelayFailure::Unanswered));
}

#[test]
fn an_answer_the_stream_has_no_room_for_ends_the_session() {
    let channel = Channel::zero();
    let mut relay = channel.network();
    let mut far = channel.terminating();
    let mut stream = Stream {
        room: Some(2),
        ..Stream::running()
    };

    relay.poll(at(0), &mut stream);
    serve(&mut far, &[], false);
    relay.poll(at(1), &mut stream);
    serve(&mut far, b"four", false);
    relay.poll(at(2), &mut stream);
    stream.forgotten();
    let pass = relay.poll(at(3), &mut stream);
    let report = pass.report.expect("the session's account");
    assert_eq!(
        report.failure,
        Some(RelayFailure::AnswerTooLong { refused: 2 })
    );
    assert_eq!(report.sent, 2, "what did fit is still counted");
}

#[test]
fn a_connection_replaced_between_passes_closes_the_far_end_first() {
    let channel = Channel::zero();
    let mut relay = channel.network();
    let mut far = channel.terminating();
    let mut stream = Stream::running();

    relay.poll(at(0), &mut stream);
    serve(&mut far, &[], false);
    relay.poll(at(1), &mut stream);
    serve(&mut far, &[], false);

    // A different peer, on a handle the transport issued for a fresh
    // connection: the far end still holds the old session and must be told.
    stream.reconnected();
    let pass = relay.poll(at(2), &mut stream);
    assert!(pass.notify);
    // Neither end of the old session said it was over, which is what the close
    // carries — and the far end reports it as that rather than as a peer close.
    assert_eq!(
        serve(&mut far, &[], true),
        RelayOperation::Close(RelayEnding::Forgotten)
    );
    let pass = relay.poll(at(3), &mut stream);
    assert!(pass.report.is_some(), "the old session's account");
    // And only then is the new one opened.
    let pass = relay.poll(at(4), &mut stream);
    assert!(pass.notify);
    assert_eq!(serve(&mut far, &[], false), RelayOperation::Open);
}

/// The defect this exists for: a peer that resets and reconnects between the
/// pass that decided a close and the pass that acts on it must not have its
/// **new** session ended by the old one's close.
#[test]
fn a_close_for_a_session_that_is_gone_leaves_the_new_one_alone() {
    let channel = Channel::zero();
    let mut relay = channel.network();
    let mut far = channel.terminating();
    let mut stream = Stream::running();

    relay.poll(at(0), &mut stream);
    serve(&mut far, &[], false);
    relay.poll(at(1), &mut stream);

    // The far end says the session is over — and between that answer and the
    // pass that claims it the peer resets and opens another. One segment and a
    // handshake, which is a peer's own pacing rather than a race.
    serve(&mut far, &[], true);
    stream.reconnected();
    let pass = relay.poll(at(2), &mut stream);
    assert!(
        !stream.ended,
        "the old session's close ended the connection that replaced it"
    );
    assert_eq!(
        stream.refused_closes, 1,
        "the close was not named, so nothing could refuse it"
    );
    // The old session's account is the old session's: neither of its ends said
    // it was over, the far end's close having landed after it was gone.
    let report = pass.report.expect("the old session's account");
    assert_eq!(report.ended, OnboardEnd::Forgotten);
    assert!(report.failure.is_none());

    // And the new connection is then opened rather than inheriting anything.
    let pass = relay.poll(at(3), &mut stream);
    assert!(pass.notify);
    assert_eq!(serve(&mut far, &[], false), RelayOperation::Open);
    let pass = relay.poll(at(4), &mut stream);
    assert!(
        pass.report.is_none(),
        "the new session was reported at once"
    );
    assert!(!stream.ended, "the new session was ended before it began");
}

/// The same rule for the closes this end composes because it gave up: an
/// `Unanswered` names the session it was decided for, so a connection that
/// replaced it is untouched.
#[test]
fn a_failure_ends_the_session_it_was_about_and_no_other() {
    let channel = Channel::zero();
    let mut relay = channel.network();
    let mut stream = Stream::running();

    relay.poll(at(0), &mut stream);
    stream.reconnected();
    let past = ANSWER_TIMEOUT.as_nanos().saturating_add(1);
    let pass = relay.poll(at(past), &mut stream);
    assert!(
        !stream.ended,
        "a far end that went quiet took down the connection after it"
    );
    assert_eq!(stream.refused_closes, 1);
    let report = pass.report.expect("the abandoned session's account");
    assert_eq!(report.failure, Some(RelayFailure::Unanswered));
    assert_eq!(report.ended, OnboardEnd::Refused);
}

/// An answer this end dropped costs the session it was about **and nothing
/// after it**: the next connection's `Open` goes out, and this end asks for
/// nothing else first.
///
/// It is the pump's half of the rule the ABI states — an open is the beginning
/// of a session and ends any the far end still believes in — so there is no
/// refusal here to recover from and no reconciliation to perform. The far end's
/// half is [`Terminating`]'s, tested below.
#[test]
fn an_open_after_a_dropped_answer_begins_a_new_session() {
    let channel = Channel::zero();
    let mut relay = channel.network();
    let mut far = channel.terminating();
    let mut stream = Stream::running();

    // The open goes out and is never answered inside the bound, so this end
    // drops the handle and gives up on the session.
    relay.poll(at(0), &mut stream);
    let past = ANSWER_TIMEOUT.as_nanos().saturating_add(1);
    relay.poll(at(past), &mut stream);
    assert!(stream.ended);
    // And the far end answers it late, into a region nothing is polling: it now
    // holds a session this end has already given up on.
    serve(&mut far, &[], false);

    // The next connection. Nothing is owed to the far end first — the open is
    // itself the end of what it still believed in.
    stream.reconnected();
    let pass = relay.poll(at(past + 1), &mut stream);
    assert!(pass.report.is_some(), "the abandoned session's account");
    let pass = relay.poll(at(past + 2), &mut stream);
    assert!(pass.notify);
    assert_eq!(
        serve(&mut far, &[], false),
        RelayOperation::Open,
        "the next session opened with something other than an open"
    );
    let pass = relay.poll(at(past + 3), &mut stream);
    assert!(pass.report.is_none(), "the new session was refused");
    assert!(!stream.ended, "the new session was ended before it began");
}

#[test]
fn a_port_with_no_session_asks_for_nothing() {
    let channel = Channel::zero();
    let mut relay = channel.network();
    let mut stream = Stream::default();
    for tick in 0..4 {
        let pass = relay.poll(at(tick), &mut stream);
        assert_eq!(pass, RelayPass::default());
    }
    assert!(!relay.outstanding());
    assert_eq!(relay.faults(), 0);
}

#[test]
fn a_pass_with_no_clock_arms_no_deadline_and_still_carries_the_session() {
    let channel = Channel::zero();
    let mut relay = channel.network();
    let mut far = channel.terminating();
    let mut stream = Stream::running();

    let pass = relay.poll(None, &mut stream);
    assert!(pass.notify);
    serve(&mut far, &[], false);
    // No deadline was armed, so no pass can expire it however far it is from
    // the one before.
    let pass = relay.poll(None, &mut stream);
    assert!(pass.report.is_none());
    assert!(pass.notify);
}

// ---------------------------------------------------------------------------
// The terminating end: the same channel from the side that answers.

/// The far end over one channel, with a requester standing in for the network
/// end so both halves of a rule are driven by the code that really implements
/// them.
struct Ends<'chan> {
    near: RelayRequester<'chan>,
    far: Terminating<'chan, Protocol>,
    protocol: Protocol,
    /// What the last exchange's answer carried back.
    answered: Vec<u8>,
    closed: bool,
}

impl Channel {
    fn both(&self) -> Ends<'_> {
        let protocol = Protocol::default();
        Ends {
            near: self.request.requester(&self.reply),
            far: Terminating::attach(&self.request, &self.reply, protocol.clone()),
            protocol,
            answered: Vec::new(),
            closed: false,
        }
    }
}

impl Ends<'_> {
    /// Ask for one operation and let the far end answer it, giving back what
    /// that answer left the console owed.
    fn exchange(&mut self, operation: RelayOperation, payload: &[u8]) -> TerminatingPass {
        let pending = self
            .near
            .request(operation, payload)
            .expect("the window is free");
        let demand = self.far.take().expect("an item to answer");
        let pass = self.far.answer(demand);
        let mut into = std::boxed::Box::new([0_u8; MAX_RELAY_PAYLOAD]);
        // Claimed, so the window is free for the next item: an unclaimed answer
        // would make every exchange after the first a busy window rather than a
        // statement about the far end.
        self.answered.clear();
        self.closed = false;
        if let RelayPoll::Answered {
            records, closed, ..
        } = self.near.poll(pending, &mut into)
        {
            self.answered.extend_from_slice(records);
            self.closed = closed;
        }
        pass
    }
}

/// The far end's half of the rule the ABI states: an open **supersedes**. There
/// is no refusal for it, the superseded session is accounted for, and the new one
/// runs.
#[test]
fn an_open_supersedes_the_session_the_far_end_still_held() {
    let channel = Channel::zero();
    let mut ends = channel.both();

    let pass = ends.exchange(RelayOperation::Open, &[]);
    assert_eq!(pass, TerminatingPass::default());
    assert!(ends.far.holds_a_session());
    let pass = ends.exchange(RelayOperation::Deliver, b"client hello");
    assert_eq!(pass, TerminatingPass::default());

    // The network end gave up on that session without saying so — an answer it
    // dropped — and opens the next one. This end is the one that was left
    // believing, and the open is what ends that belief.
    let pass = ends.exchange(RelayOperation::Open, &[]);
    assert!(
        pass.refused.is_none(),
        "an open was refused for a session already open: {pass:?}"
    );
    let report = pass.report.expect("the superseded session's account");
    // Neither end of it ever said it was over, which is what the ending says.
    assert_eq!(report.ended, OnboardEnd::Forgotten);
    assert_eq!(report.received, b"client hello".len() as u64);
    assert_eq!(report.relayed, 2, "the open and the delivery");
    assert!(ends.far.holds_a_session(), "the new session did not begin");

    // And the new session is a new session: nothing of the old one's account is
    // in it.
    let pass = ends.exchange(RelayOperation::Close(RelayEnding::Peer), &[]);
    let report = pass.report.expect("the new session's account");
    assert_eq!(report.received, 0);
    assert_eq!(report.relayed, 2, "its own open and its own close");
    assert!(!ends.far.holds_a_session());
}

/// Fix D from the side that reports: each ending reaches the console as itself,
/// so a session the transport forgot is not read as one the peer closed.
#[test]
fn each_ending_a_close_carries_is_reported_as_itself() {
    for (ending, expected) in [
        (RelayEnding::Peer, OnboardEnd::Peer),
        (RelayEnding::Consumer, OnboardEnd::Consumer),
        (RelayEnding::Forgotten, OnboardEnd::Forgotten),
        (RelayEnding::Refused, OnboardEnd::Refused),
    ] {
        let channel = Channel::zero();
        let mut ends = channel.both();
        ends.exchange(RelayOperation::Open, &[]);
        let pass = ends.exchange(RelayOperation::Close(ending), &[]);
        let report = pass.report.expect("the session's account");
        assert_eq!(
            report.ended, expected,
            "a close carrying {ending:?} was reported as {:?}",
            report.ended
        );
        assert!(pass.refused.is_none());
        assert!(!ends.far.holds_a_session());
    }
}

/// The two ends' `relayed` counts are one number rather than two, which is what
/// makes a disagreement between the two records mean a relay that lost
/// something.
#[test]
fn both_ends_count_the_same_handovers_for_one_session() {
    let channel = Channel::zero();
    let mut relay = channel.network();
    let mut stream = Stream::running();
    let mut far = Terminating::attach(&channel.request, &channel.reply, Protocol::default());

    let mut far_report = None;
    // Driven to the end of a session: an open, a delivery, a poll, and the close
    // the peer's own hang-up provokes.
    for step in 0..8_u64 {
        if step == 3 {
            stream.waiting.extend_from_slice(b"records");
        }
        if step == 5 {
            stream.peer_closed = true;
            stream.ending = Some(Ended::ByPeer);
        }
        let pass = relay.poll(at(step), &mut stream);
        if pass.notify {
            let demand = far.take().expect("the item that was written");
            let answered = far.answer(demand);
            far_report = far_report.or(answered.report);
        }
        if let Some(report) = pass.report {
            let far_report = far_report.expect("the far end's own account");
            assert_eq!(
                (report.relayed, report.received, report.ended),
                (far_report.relayed, far_report.received, far_report.ended),
                "the two domains' accounts of one session disagree"
            );
            return;
        }
        if step == 6 {
            stream.forgotten();
        }
    }
    panic!("the session never finished");
}

/// Every refusal ends the session and reports it, and none of them counts as a
/// handover — the network end does not count a refusal either.
#[test]
fn a_refusal_reports_the_session_it_ended_and_is_not_counted() {
    let channel = Channel::zero();
    let mut ends = channel.both();
    ends.exchange(RelayOperation::Open, &[]);
    let pass = ends.exchange(RelayOperation::Deliver, b"one");
    assert_eq!(pass, TerminatingPass::default());

    // A payload longer than one item may carry: the length is refused rather
    // than the prefix that fitted being fed to a protocol.
    let long = vec![0x11_u8; MAX_RELAY_PAYLOAD + 1];
    let pass = ends.exchange(RelayOperation::Deliver, &long);
    assert_eq!(
        pass.refused,
        Some((
            RelayRefusal::PayloadTooLong,
            RefusalDetail::One(long.len() as u64)
        ))
    );
    let report = pass.report.expect("the refused session's account");
    assert_eq!(report.ended, OnboardEnd::Refused);
    assert_eq!(report.received, 3, "the delivery that did arrive");
    assert_eq!(report.relayed, 2, "the refused item is not a handover");
    assert!(!ends.far.holds_a_session());
}

/// An operation naming a session with none open is refused, and the refusal
/// names the word that did the naming.
///
/// The other refusal this end can raise — a word naming no operation at all,
/// which includes a close whose ending could not be read — is the ABI's own to
/// reach: only a region written outside `wire::RelayRequester::request` can carry
/// one, and `wire::relay` is where that is driven. This end's arm for it is the
/// delegation to `RelayDemand::operation`.
#[test]
fn an_operation_naming_a_session_there_is_none_of_is_refused() {
    let channel = Channel::zero();
    let mut ends = channel.both();
    let pass = ends.exchange(RelayOperation::Poll, &[]);
    assert_eq!(
        pass.refused,
        Some((
            RelayRefusal::NoConnection,
            RefusalDetail::One(u64::from(RelayOperation::Poll.to_bits()))
        ))
    );
    assert!(pass.report.is_none(), "there was no session to account for");
    assert!(!ends.far.holds_a_session());

    // And a close is no different: it names a session too, so one with none open
    // is refused rather than reported as a session that ended.
    let pass = ends.exchange(RelayOperation::Close(RelayEnding::Peer), &[]);
    assert_eq!(
        pass.refused.map(|(reason, _)| reason),
        Some(RelayRefusal::NoConnection)
    );
    assert!(pass.report.is_none());
}

/// The seam itself: what a delivery hands the protocol, and what the protocol
/// answers with, are the bytes that cross — in both directions and counted.
#[test]
fn a_delivery_reaches_the_protocol_and_its_answer_goes_back() {
    let channel = Channel::zero();
    let mut ends = channel.both();

    ends.exchange(RelayOperation::Open, &[]);
    assert_eq!(ends.protocol.spoken().opens, 1);
    assert!(
        ends.answered.is_empty(),
        "an open answered with something the protocol never said"
    );

    ends.exchange(RelayOperation::Deliver, b"client hello");
    assert_eq!(ends.protocol.spoken().heard, b"client hello");
    assert_eq!(ends.answered, b"client hello");

    // A poll is a turn with nothing delivered, which is how a protocol that
    // owes the wire more than one item's worth gets to finish saying it.
    let heard = ends.protocol.spoken().turns;
    ends.exchange(RelayOperation::Poll, &[]);
    assert_eq!(ends.protocol.spoken().turns, heard + 1);
    assert!(ends.answered.is_empty());

    let pass = ends.exchange(RelayOperation::Close(RelayEnding::Peer), &[]);
    let report = pass.report.expect("the session's account");
    assert_eq!(report.received, b"client hello".len() as u64);
    assert_eq!(report.sent, b"client hello".len() as u64);
    assert_eq!(ends.protocol.spoken().closes, 1);
}

/// A protocol that is finished ends the session **here**, on the item it
/// finished on: the closed word goes back, the account goes out naming this end
/// as the one that decided, and the protocol is told once.
#[test]
fn a_protocol_that_finishes_ends_the_session_and_says_so_on_the_channel() {
    let channel = Channel::zero();
    let mut ends = channel.both();
    ends.exchange(RelayOperation::Open, &[]);
    // The turn the delivery gives it.
    ends.protocol.finish_on(1);

    let pass = ends.exchange(RelayOperation::Deliver, b"alert");
    assert!(
        ends.closed,
        "the network end was not told the session ended"
    );
    assert_eq!(
        ends.answered, b"alert",
        "the answer was lost with the close"
    );
    let report = pass.report.expect("the finished session's account");
    assert_eq!(report.ended, OnboardEnd::Consumer);
    assert_eq!(report.relayed, 2, "the open and the item it finished on");
    assert_eq!(report.received, b"alert".len() as u64);
    assert_eq!(report.sent, b"alert".len() as u64);
    assert!(!ends.far.holds_a_session());
    assert_eq!(ends.protocol.spoken().closes, 1);
}

/// A protocol claiming more than it wrote is clamped rather than believed. Its
/// own defect and not the peer's, and no panic is admissible on a path a peer
/// paces.
#[test]
fn an_answer_longer_than_the_buffer_is_clamped_to_what_the_wire_has_room_for() {
    let channel = Channel::zero();
    let mut ends = channel.both();
    ends.exchange(RelayOperation::Open, &[]);
    ends.protocol.overstate(usize::MAX);

    let pass = ends.exchange(RelayOperation::Deliver, b"one");
    assert!(pass.refused.is_none());
    assert_eq!(ends.answered.len(), ANSWER_ROOM);
    let pass = ends.exchange(RelayOperation::Close(RelayEnding::Peer), &[]);
    let report = pass.report.expect("the session's account");
    assert_eq!(report.sent, ANSWER_ROOM as u64);
}

/// A refusal ends the session for the protocol too — and one with no session
/// behind it tells it nothing, because it was never told to open one.
#[test]
fn the_protocol_hears_about_exactly_the_sessions_it_was_told_to_open() {
    let channel = Channel::zero();
    let mut ends = channel.both();

    ends.exchange(RelayOperation::Poll, &[]);
    assert_eq!(ends.protocol.spoken().opens, 0);
    assert_eq!(ends.protocol.spoken().closes, 0);
    assert_eq!(
        ends.protocol.spoken().turns,
        0,
        "a turn was taken for a session there was none of"
    );

    ends.exchange(RelayOperation::Open, &[]);
    let long = vec![0x11_u8; MAX_RELAY_PAYLOAD + 1];
    let pass = ends.exchange(RelayOperation::Deliver, &long);
    assert_eq!(
        pass.refused.map(|(reason, _)| reason),
        Some(RelayRefusal::PayloadTooLong)
    );
    assert_eq!(ends.protocol.spoken().opens, 1);
    assert_eq!(ends.protocol.spoken().closes, 1);
    assert!(
        !ends.protocol.spoken().heard.contains(&0x11),
        "a payload the channel refused reached the protocol"
    );
}

proptest! {
    /// Every operation a requester can write, in whatever order: the far end
    /// answers each exactly once, never holds more than one session, and never
    /// reports one it did not hold.
    ///
    /// The words are generated as arbitrary `u32` and decoded, so the run covers
    /// the whole legal vocabulary — all four closes among them — in orders no
    /// well-behaved network end would produce.
    #[test]
    fn answering_an_arbitrary_run_of_operations_is_total(
        words in proptest::collection::vec(any::<u32>(), 1..24),
    ) {
        let channel = Channel::zero();
        let mut ends = channel.both();
        let mut reports = 0_usize;
        let mut opens = 0_usize;
        for word in words {
            // Undecodable words are the ABI's own case and are unreachable
            // through a requester, so a run steps over them rather than
            // pretending to write one.
            let Some(operation) = RelayOperation::from_bits(word) else {
                continue;
            };
            let held_before = ends.far.holds_a_session();
            let pass = ends.exchange(operation, &[]);
            if operation == RelayOperation::Open {
                opens += 1;
                prop_assert!(ends.far.holds_a_session(), "an open left no session");
                // The rule this run is really about: an open is never refused,
                // whatever this end still believed in.
                prop_assert!(pass.refused.is_none());
                prop_assert_eq!(pass.report.is_some(), held_before);
            }
            if pass.report.is_some() {
                reports += 1;
                prop_assert!(held_before, "a session was reported that was never held");
            }
            if pass.refused.is_some() {
                prop_assert!(!ends.far.holds_a_session());
            }
        }
        // Never more than one session at a time, so no run can report more
        // sessions than were begun.
        prop_assert!(reports <= opens);
    }
}
