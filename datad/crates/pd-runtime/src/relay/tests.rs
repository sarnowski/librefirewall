use super::*;
use lfw_tcp::{IsnSecret, TcpStack};
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
    ending: Option<Ended>,
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

    fn end_session(&mut self) {
        self.ended = true;
        self.ending.get_or_insert(Ended::ByConsumer);
    }

    fn take_ending(&mut self) -> Option<Ended> {
        self.ending.take()
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
    assert_eq!(serve(&mut far, &[], true), RelayOperation::Close);
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
    stream.session = Some(handles().1);
    let pass = relay.poll(at(2), &mut stream);
    assert!(pass.notify);
    assert_eq!(serve(&mut far, &[], true), RelayOperation::Close);
    let pass = relay.poll(at(3), &mut stream);
    assert!(pass.report.is_some(), "the old session's account");
    // And only then is the new one opened.
    let pass = relay.poll(at(4), &mut stream);
    assert!(pass.notify);
    assert_eq!(serve(&mut far, &[], false), RelayOperation::Open);
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
