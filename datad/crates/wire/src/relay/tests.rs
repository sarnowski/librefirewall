//! The relay channel held to its protocol, and to a peer that keeps to none of
//! it.

use proptest::prelude::*;
use std::{boxed::Box, vec};

use super::*;

/// One channel: both regions and the two handles over them.
///
/// The regions are leaked deliberately, on the same terms the protection domains
/// hold theirs: each handle borrows for `'static` because on the appliance the
/// mapping outlives every holder, and a fixture that dropped them would be
/// modelling a lifetime the system does not have.
struct Channel {
    requester: RelayRequester<'static>,
    responder: RelayResponder<'static>,
}

impl Channel {
    fn new() -> Self {
        let request: &'static RelayRequest = Box::leak(Box::new(RelayRequest::zero()));
        let reply: &'static RelayReply = Box::leak(Box::new(RelayReply::zero()));
        Self {
            requester: request.requester(reply),
            responder: reply.responder(request),
        }
    }
}

/// Issue one item, or fail the test naming what refused it.
fn ask(channel: &mut Channel, operation: RelayOperation, payload: &[u8]) -> PendingRelay {
    channel
        .requester
        .request(operation, payload)
        .expect("the window is free")
}

#[test]
fn a_zeroed_pair_of_regions_has_nothing_outstanding_and_no_session() {
    let mut channel = Channel::new();
    assert!(channel.responder.take().is_none());
    assert_eq!(channel.responder.served(), 0);
    assert_eq!(channel.responder.answers(), 0);
    assert_eq!(channel.requester.sequence(), 0);
    assert_eq!(channel.requester.faults(), 0);
    assert!(!channel.requester.outstanding());
}

#[test]
fn records_cross_in_both_directions_under_one_sequence() {
    let mut channel = Channel::new();
    let pending = ask(&mut channel, RelayOperation::Deliver, b"\x16\x03\x01hello");
    assert_eq!(pending.operation(), RelayOperation::Deliver);
    assert!(channel.requester.outstanding());

    let demand = channel.responder.take().expect("an item is outstanding");
    assert_eq!(demand.operation(), Some(RelayOperation::Deliver));
    assert_eq!(demand.stated_len(), 8);
    let mut scratch = [0_u8; MAX_RELAY_PAYLOAD];
    assert_eq!(
        demand.payload(&channel.responder, &mut scratch),
        Some(&b"\x16\x03\x01hello"[..])
    );
    assert_eq!(
        channel
            .responder
            .answered(demand, b"\x16\x03\x03back", false, false),
        7
    );
    assert_eq!(channel.responder.answers(), 1);

    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    match channel.requester.poll(pending, &mut into) {
        RelayPoll::Answered {
            records,
            closed,
            agreed: _,
            answered,
            acked: _,
            wanted,
        } => {
            assert_eq!(records, &b"\x16\x03\x03back"[..]);
            assert_eq!(
                wanted, None,
                "a responder that stated no extent is a channel owing none"
            );
            assert!(!closed);
            assert_eq!(answered, 1);
        }
        other => panic!("expected records: {other:?}"),
    }
    assert!(!channel.requester.outstanding());
}

#[test]
fn a_poll_answered_with_nothing_is_an_answer_and_not_a_refusal() {
    let mut channel = Channel::new();
    let pending = ask(&mut channel, RelayOperation::Poll, &[]);
    let demand = channel.responder.take().expect("outstanding");
    assert_eq!(channel.responder.answered(demand, &[], false, false), 0);
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    match channel.requester.poll(pending, &mut into) {
        RelayPoll::Answered {
            records, closed, ..
        } => {
            assert!(records.is_empty());
            assert!(!closed);
        }
        other => panic!("expected an empty answer: {other:?}"),
    }
    assert_eq!(channel.requester.faults(), 0);
}

#[test]
fn the_window_holds_one_item_and_a_second_is_refused_rather_than_overwriting() {
    let mut channel = Channel::new();
    let pending = ask(&mut channel, RelayOperation::Open(Half::Onboarding), &[]);
    // The bytes of the first item are still in the region and the responder may
    // be mid-read of them; a second write would be the corruption this refuses.
    assert_eq!(
        channel
            .requester
            .request(RelayOperation::Deliver, b"second"),
        Err(RelayBusy {
            sequence: pending.sequence(),
            operation: RelayOperation::Deliver,
        })
    );
    let demand = channel.responder.take().expect("outstanding");
    channel.responder.answered(demand, &[], false, false);
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    assert!(matches!(
        channel.requester.poll(pending, &mut into),
        RelayPoll::Answered { .. }
    ));
    // And the window is free again the moment the answer was claimed.
    assert!(
        channel
            .requester
            .request(RelayOperation::Deliver, b"second")
            .is_ok()
    );
}

#[test]
fn a_refusal_frees_the_window_so_the_connection_can_be_closed() {
    let mut channel = Channel::new();
    let pending = ask(&mut channel, RelayOperation::Deliver, b"records");
    let demand = channel.responder.take().expect("outstanding");
    channel.responder.refuse(demand, RelayRefusal::NoConnection);
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    assert_eq!(
        channel.requester.poll(pending, &mut into),
        RelayPoll::Refused(RelayRefusal::NoConnection)
    );
    assert_eq!(channel.requester.faults(), 0, "a refusal is not a fault");
    assert!(
        channel
            .requester
            .request(RelayOperation::Close(RelayEnding::Refused), &[])
            .is_ok(),
        "a refused item left the window taken"
    );
}

#[test]
fn a_fault_frees_the_window_too() {
    let request: &'static RelayRequest = Box::leak(Box::new(RelayRequest::zero()));
    let reply: &'static RelayReply = Box::leak(Box::new(RelayReply::zero()));
    let mut requester = request.requester(reply);
    let pending = requester
        .request(RelayOperation::Deliver, b"r")
        .expect("free");
    publish_raw(
        reply,
        pending.sequence(),
        99,
        RelayOperation::Deliver.to_bits(),
        0,
        0,
    );
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    assert_eq!(
        requester.poll(pending, &mut into),
        RelayPoll::Faulted(RelayFault::StatusUnknown { status: 99 })
    );
    assert!(
        requester
            .request(RelayOperation::Close(RelayEnding::Refused), &[])
            .is_ok(),
        "a faulted item left the window taken"
    );
}

#[test]
fn an_abandoned_item_frees_the_window_and_its_late_answer_is_ignored() {
    let mut channel = Channel::new();
    let pending = ask(&mut channel, RelayOperation::Open(Half::Onboarding), &[]);
    let given_up = pending.sequence();
    channel.requester.abandon(pending);
    assert!(
        !channel.requester.outstanding(),
        "an item given up on left the one slot taken, which is a dead channel"
    );

    // The far end answers it late, into a region nothing is polling.
    let demand = channel.responder.take().expect("the abandoned item");
    channel.responder.answered(demand, b"late", false, false);

    // And the next item is issued and answered on its own number. The late reply
    // carries a sequence no item is held against, so nothing about it is read.
    let next = channel
        .requester
        .request(RelayOperation::Open(Half::Onboarding), &[])
        .expect("the window was freed");
    assert_ne!(next.sequence(), given_up);
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    match channel.requester.poll(next, &mut into) {
        RelayPoll::Outstanding(_) => {}
        other => panic!("the abandoned item's answer was read as this one's: {other:?}"),
    }
    assert_eq!(channel.requester.faults(), 0);
}

#[test]
fn a_reply_carrying_another_sequence_is_ignored_entirely() {
    let request: &'static RelayRequest = Box::leak(Box::new(RelayRequest::zero()));
    let reply: &'static RelayReply = Box::leak(Box::new(RelayReply::zero()));
    let mut requester = request.requester(reply);
    let pending = requester
        .request(RelayOperation::Deliver, b"one")
        .expect("free");
    // A reply that would be believed but for its sequence: the right status, the
    // right operation, a plausible length. Nothing about it is read.
    publish_raw(
        reply,
        pending.sequence().wrapping_add(1),
        RelayStatus::Ok.to_bits(),
        RelayOperation::Deliver.to_bits(),
        8,
        0,
    );
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    match requester.poll(pending, &mut into) {
        RelayPoll::Outstanding(_) => {}
        other => panic!("a reply to another item was believed: {other:?}"),
    }
    assert_eq!(requester.faults(), 0, "ignoring is not faulting");
    assert!(requester.outstanding(), "the item is still in flight");
    assert!(into.iter().all(|byte| *byte == 0), "nothing was copied out");
}

#[test]
fn one_demand_is_taken_per_change_of_the_sequence() {
    let mut channel = Channel::new();
    let pending = ask(&mut channel, RelayOperation::Deliver, b"x");
    let demand = channel.responder.take().expect("outstanding");
    assert!(
        channel.responder.take().is_none(),
        "the same item produced a second demand"
    );
    channel.responder.answered(demand, &[9; 4], false, false);
    assert!(
        channel.responder.take().is_none(),
        "an answered item produced another demand"
    );
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    assert!(matches!(
        channel.requester.poll(pending, &mut into),
        RelayPoll::Answered { .. }
    ));
}

#[test]
fn every_refusal_reaches_the_requester_as_itself_carrying_no_bytes_and_closing() {
    for reason in [
        RelayRefusal::NoConnection,
        RelayRefusal::PayloadTooLong,
        RelayRefusal::NoSuchOperation,
        RelayRefusal::SessionFailed,
    ] {
        let mut channel = Channel::new();
        let pending = ask(&mut channel, RelayOperation::Deliver, b"m");
        let demand = channel.responder.take().expect("outstanding");
        channel.responder.refuse(demand, reason);
        let mut into = [0_u8; MAX_RELAY_PAYLOAD];
        assert_eq!(
            channel.requester.poll(pending, &mut into),
            RelayPoll::Refused(reason)
        );
        assert_eq!(channel.requester.faults(), 0, "a refusal is not a fault");
    }
}

#[test]
fn an_operation_word_the_far_end_does_not_know_is_refused_rather_than_ignored() {
    let request: &'static RelayRequest = Box::leak(Box::new(RelayRequest::zero()));
    let reply: &'static RelayReply = Box::leak(Box::new(RelayReply::zero()));
    let mut responder = reply.responder(request);
    let mut requester = request.requester(reply);
    let pending = requester
        .request(RelayOperation::Deliver, b"m")
        .expect("free");
    // A peer that writes a word neither side has a meaning for: the one past the
    // whole vocabulary, derived rather than written down so that adding an
    // operation moves it instead of quietly making this case a valid word.
    store_request_operation(
        request,
        RelayOperation::RANGE_BASE + RangeOutcome::COUNT as u32,
    );
    let demand = responder.take().expect("outstanding");
    assert_eq!(demand.operation(), None);
    responder.refuse(demand, RelayRefusal::NoSuchOperation);
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    assert_eq!(
        requester.poll(pending, &mut into),
        RelayPoll::Refused(RelayRefusal::NoSuchOperation)
    );
}

#[test]
fn a_payload_longer_than_a_request_holds_arrives_as_its_true_length() {
    let mut channel = Channel::new();
    let long = vec![0x11_u8; MAX_RELAY_PAYLOAD + 40];
    // The handle is dropped: what is under test is what the far end sees, and an
    // item nobody polls is exactly the shape a caller that gave up leaves.
    drop(ask(&mut channel, RelayOperation::Deliver, &long));
    let demand = channel.responder.take().expect("outstanding");
    // Unclamped, which is the whole point: the far end must refuse rather than
    // feed the prefix that happened to fit to a protocol.
    assert_eq!(demand.stated_len() as usize, long.len());
    let mut scratch = [0_u8; MAX_RELAY_PAYLOAD];
    assert!(
        demand.payload(&channel.responder, &mut scratch).is_none(),
        "a payload past the region was handed over as if it were whole"
    );
}

#[test]
fn a_payload_exactly_the_bound_crosses_whole() {
    let mut channel = Channel::new();
    let widest = vec![0x7E_u8; MAX_RELAY_PAYLOAD];
    drop(ask(&mut channel, RelayOperation::Deliver, &widest));
    let demand = channel.responder.take().expect("outstanding");
    let mut scratch = [0_u8; MAX_RELAY_PAYLOAD];
    assert_eq!(
        demand.payload(&channel.responder, &mut scratch),
        Some(&widest[..])
    );
}

#[test]
fn a_reply_answering_the_wrong_question_is_a_fault() {
    let mut channel = Channel::new();
    let pending = ask(&mut channel, RelayOperation::Deliver, b"m");
    let demand = channel.responder.take().expect("outstanding");
    // A responder that echoes some other operation: the demand's own word is
    // replaced under it, which is the only way to model a far end that answers
    // the wrong question.
    let mistaken = RelayDemand {
        sequence: demand.sequence(),
        operation: Some(RelayOperation::Poll),
        len: demand.stated_len(),
        position: 0,
    };
    channel.responder.answered(mistaken, &[1, 2], false, false);
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    assert_eq!(
        channel.requester.poll(pending, &mut into),
        RelayPoll::Faulted(RelayFault::WrongOperation {
            asked: RelayOperation::Deliver,
            answered: RelayOperation::Poll,
        })
    );
    assert_eq!(channel.requester.faults(), 1);
}

#[test]
fn a_status_or_operation_word_outside_its_vocabulary_is_a_fault() {
    for (status, operation, expected) in [
        (
            9_u32,
            RelayOperation::Deliver.to_bits(),
            RelayFault::StatusUnknown { status: 9 },
        ),
        (
            RelayStatus::Ok.to_bits(),
            RelayOperation::RANGE_BASE + RangeOutcome::COUNT as u32,
            RelayFault::OperationUnknown {
                operation: RelayOperation::RANGE_BASE + RangeOutcome::COUNT as u32,
            },
        ),
    ] {
        let request: &'static RelayRequest = Box::leak(Box::new(RelayRequest::zero()));
        let reply: &'static RelayReply = Box::leak(Box::new(RelayReply::zero()));
        let mut requester = request.requester(reply);
        let pending = requester
            .request(RelayOperation::Deliver, b"m")
            .expect("free");
        publish_raw(reply, pending.sequence(), status, operation, 0, 0);
        let mut into = [0_u8; MAX_RELAY_PAYLOAD];
        assert_eq!(
            requester.poll(pending, &mut into),
            RelayPoll::Faulted(expected)
        );
    }
}

#[test]
fn a_length_past_the_payload_region_is_refused_before_the_copy() {
    let request: &'static RelayRequest = Box::leak(Box::new(RelayRequest::zero()));
    let reply: &'static RelayReply = Box::leak(Box::new(RelayReply::zero()));
    let mut requester = request.requester(reply);
    let pending = requester
        .request(RelayOperation::Deliver, b"m")
        .expect("free");
    let len = (MAX_RELAY_PAYLOAD + 1) as u32;
    publish_raw(
        reply,
        pending.sequence(),
        RelayStatus::Ok.to_bits(),
        RelayOperation::Deliver.to_bits(),
        len,
        0,
    );
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    assert_eq!(
        requester.poll(pending, &mut into),
        RelayPoll::Faulted(RelayFault::LenPastPayload { len })
    );
}

#[test]
fn a_refusal_carrying_bytes_and_a_closed_word_outside_its_two_values_are_faults() {
    let cases: [(u32, u32, u32, RelayFault); 2] = [
        (
            RelayStatus::SessionFailed.to_bits(),
            4,
            1,
            RelayFault::BytesOnRefusal {
                status: RelayStatus::SessionFailed,
                len: 4,
            },
        ),
        (
            RelayStatus::Ok.to_bits(),
            0,
            2,
            RelayFault::ClosedUnknown { closed: 2 },
        ),
    ];
    for (status, len, closed, expected) in cases {
        let request: &'static RelayRequest = Box::leak(Box::new(RelayRequest::zero()));
        let reply: &'static RelayReply = Box::leak(Box::new(RelayReply::zero()));
        let mut requester = request.requester(reply);
        let pending = requester
            .request(RelayOperation::Deliver, b"m")
            .expect("free");
        publish_raw(
            reply,
            pending.sequence(),
            status,
            RelayOperation::Deliver.to_bits(),
            len,
            closed,
        );
        let mut into = [0_u8; MAX_RELAY_PAYLOAD];
        assert_eq!(
            requester.poll(pending, &mut into),
            RelayPoll::Faulted(expected)
        );
    }
}

#[test]
fn records_longer_than_the_region_publish_only_what_was_written() {
    let mut channel = Channel::new();
    let pending = ask(&mut channel, RelayOperation::Poll, &[]);
    let demand = channel.responder.take().expect("outstanding");
    let published =
        channel
            .responder
            .answered(demand, &vec![0xEE; MAX_RELAY_PAYLOAD + 16], false, false);
    assert_eq!(published, MAX_RELAY_PAYLOAD);
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    match channel.requester.poll(pending, &mut into) {
        RelayPoll::Answered { records, .. } => assert_eq!(records.len(), MAX_RELAY_PAYLOAD),
        other => panic!("expected records: {other:?}"),
    }
}

#[test]
fn a_closing_answer_carries_its_last_records_with_it() {
    let mut channel = Channel::new();
    let pending = ask(&mut channel, RelayOperation::Deliver, b"bye");
    let demand = channel.responder.take().expect("outstanding");
    channel
        .responder
        .answered(demand, b"\x15\x03\x03", true, false);
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    match channel.requester.poll(pending, &mut into) {
        RelayPoll::Answered {
            records, closed, ..
        } => {
            assert_eq!(records, &b"\x15\x03\x03"[..]);
            assert!(closed, "the far end said the session was over");
        }
        other => panic!("expected a closing answer: {other:?}"),
    }
}

#[test]
fn the_sequence_steps_over_zero_when_it_wraps() {
    let mut channel = Channel::new();
    for _ in 0..2 {
        let pending = ask(&mut channel, RelayOperation::Poll, &[]);
        let demand = channel.responder.take().expect("outstanding");
        channel.responder.answered(demand, &[], false, false);
        let mut into = [0_u8; MAX_RELAY_PAYLOAD];
        drop(channel.requester.poll(pending, &mut into));
    }
    assert_eq!(channel.requester.sequence(), 2);
    set_requester_sequence(&mut channel.requester, u32::MAX);
    let wrapped = ask(&mut channel, RelayOperation::Poll, &[]);
    assert_eq!(wrapped.sequence(), 1, "zero means no request");
}

#[test]
fn every_status_and_operation_bit_pattern_round_trips_or_is_refused() {
    for bits in 0_u32..10 {
        match RelayStatus::from_bits(bits) {
            Some(status) => assert_eq!(status.to_bits(), bits),
            None => assert!(bits >= 5),
        }
        match RelayOperation::from_bits(bits) {
            Some(operation) => assert_eq!(operation.to_bits(), bits),
            None => assert!(bits >= 8),
        }
        match RelayEnding::from_bits(bits) {
            Some(ending) => assert_eq!(ending.to_bits(), bits),
            None => assert!(bits >= 4),
        }
    }
    for status in [
        RelayStatus::NoConnection,
        RelayStatus::PayloadTooLong,
        RelayStatus::NoSuchOperation,
        RelayStatus::SessionFailed,
    ] {
        let refusal = RelayRefusal::from_status(status).expect("not the success");
        assert_eq!(refusal.to_status(), status);
    }
}

#[test]
fn every_close_ending_crosses_as_itself_and_is_echoed_as_itself() {
    for ending in [
        RelayEnding::Peer,
        RelayEnding::Consumer,
        RelayEnding::Forgotten,
        RelayEnding::Refused,
    ] {
        let mut channel = Channel::new();
        let pending = ask(&mut channel, RelayOperation::Close(ending), &[]);
        let demand = channel.responder.take().expect("outstanding");
        assert_eq!(
            demand.operation(),
            Some(RelayOperation::Close(ending)),
            "the far end read a close and lost how the session ended"
        );
        channel.responder.answered(demand, &[], true, false);
        let mut into = [0_u8; MAX_RELAY_PAYLOAD];
        // The echo is compared whole, ending included, so a responder that
        // answered a close with some other ending is a mismatched echo rather
        // than an accepted answer.
        match channel.requester.poll(pending, &mut into) {
            RelayPoll::Answered { closed, .. } => assert!(closed),
            other => panic!("expected a closing answer for {ending:?}: {other:?}"),
        }
        assert_eq!(channel.requester.faults(), 0);
    }
}

#[test]
fn a_close_answered_with_another_ending_is_a_mismatched_echo() {
    let mut channel = Channel::new();
    let pending = ask(&mut channel, RelayOperation::Close(RelayEnding::Peer), &[]);
    let demand = channel.responder.take().expect("outstanding");
    // A far end that answers the close it was handed as though the session had
    // ended some other way. It is a fault and not a detail: the ending is the
    // whole of what this operation adds, so an echo that changed it is an answer
    // to a different question.
    let mistaken = RelayDemand {
        sequence: demand.sequence(),
        operation: Some(RelayOperation::Close(RelayEnding::Forgotten)),
        len: demand.stated_len(),
        position: 0,
    };
    channel.responder.answered(mistaken, &[], true, false);
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    assert_eq!(
        channel.requester.poll(pending, &mut into),
        RelayPoll::Faulted(RelayFault::WrongOperation {
            asked: RelayOperation::Close(RelayEnding::Peer),
            answered: RelayOperation::Close(RelayEnding::Forgotten),
        })
    );
}

/// Store an operation word directly, modelling a peer that writes one this side
/// has no meaning for. The region's fields are private, so this is the only way a
/// test can be the adversary rather than a well-behaved requester.
fn store_request_operation(request: &RelayRequest, operation: u32) {
    request.operation.store(operation, Ordering::Relaxed);
}

/// Publish a reply field by field, modelling a far end that keeps to none of the
/// protocol.
fn publish_raw(
    reply: &RelayReply,
    sequence: u32,
    status: u32,
    operation: u32,
    len: u32,
    closed: u32,
) {
    reply.status.store(status, Ordering::Relaxed);
    reply.operation.store(operation, Ordering::Relaxed);
    reply.len.store(len, Ordering::Relaxed);
    reply.closed.store(closed, Ordering::Relaxed);
    reply.sequence.store(sequence, Ordering::Release);
}

/// Place the requester's private counter, so the wrap is reachable in a test.
fn set_requester_sequence(requester: &mut RelayRequester<'_>, sequence: u32) {
    requester.sequence = sequence;
}

proptest! {
    /// Whatever a hostile far end publishes, one poll is total: it answers,
    /// refuses, faults or stays outstanding, and never reads past the region.
    #[test]
    fn polling_an_arbitrary_reply_is_total(
        status in any::<u32>(),
        operation in any::<u32>(),
        len in any::<u32>(),
        closed in any::<u32>(),
        offset in 0_u32..3,
    ) {
        let request: &'static RelayRequest = Box::leak(Box::new(RelayRequest::zero()));
        let reply: &'static RelayReply = Box::leak(Box::new(RelayReply::zero()));
        let mut requester = request.requester(reply);
        let pending = requester
            .request(RelayOperation::Deliver, b"records")
            .expect("free");
        // Sometimes the right sequence, sometimes another one.
        let sequence = pending.sequence().wrapping_add(offset);
        publish_raw(reply, sequence, status, operation, len, closed);
        let mut into = [0_u8; MAX_RELAY_PAYLOAD];
        match requester.poll(pending, &mut into) {
            RelayPoll::Outstanding(_) => {
                prop_assert_ne!(offset, 0);
                prop_assert!(requester.outstanding());
            }
            RelayPoll::Answered { records, .. } => {
                prop_assert_eq!(offset, 0);
                prop_assert!(records.len() <= MAX_RELAY_PAYLOAD);
                prop_assert!(!requester.outstanding());
            }
            RelayPoll::Refused(_) => {
                prop_assert_eq!(offset, 0);
                prop_assert!(!requester.outstanding());
            }
            RelayPoll::Faulted(_) => {
                prop_assert_eq!(offset, 0);
                prop_assert_eq!(requester.faults(), 1);
                prop_assert!(!requester.outstanding());
            }
        }
    }

    /// Whatever a hostile network end writes, one take is total and the payload
    /// either arrives whole or is refused for its length.
    #[test]
    fn taking_an_arbitrary_request_is_total(
        operation in any::<u32>(),
        len in any::<u32>(),
        sequence in 1_u32..,
    ) {
        let request: &'static RelayRequest = Box::leak(Box::new(RelayRequest::zero()));
        let reply: &'static RelayReply = Box::leak(Box::new(RelayReply::zero()));
        let mut responder = reply.responder(request);
        request.operation.store(operation, Ordering::Relaxed);
        request.len.store(len, Ordering::Relaxed);
        request.sequence.store(sequence, Ordering::Release);
        let demand = responder.take().expect("a non-zero sequence is a request");
        prop_assert_eq!(demand.stated_len(), len);
        prop_assert_eq!(demand.operation(), RelayOperation::from_bits(operation));
        // A close arrives with an ending or does not arrive at all: the word is
        // decoded whole, so no close reaches the terminating end carrying an
        // ending this side invented.
        if let Some(RelayOperation::Close(ending)) = demand.operation() {
            prop_assert_eq!(RelayOperation::Close(ending).to_bits(), operation);
            prop_assert!(ending.to_bits() < RelayEnding::COUNT as u32);
        }
        // And an open arrives naming one of the two halves or does not arrive at
        // all: the half is decoded from the word rather than defaulted, so no
        // session begins on a half this side chose.
        if let Some(RelayOperation::Open(half)) = demand.operation() {
            prop_assert_eq!(RelayOperation::Open(half).to_bits(), operation);
            prop_assert!(matches!(half, Half::Onboarding | Half::Channel));
        }
        let mut scratch = std::boxed::Box::new([0_u8; MAX_RELAY_PAYLOAD]);
        let payload = demand.payload(&responder, &mut scratch);
        prop_assert_eq!(payload.is_some(), (len as usize) <= MAX_RELAY_PAYLOAD);
        if let Some(payload) = payload {
            prop_assert_eq!(payload.len(), len as usize);
        }
    }
}

// --- shipping ring bytes -----------------------------------------------------

#[test]
fn a_shipment_carries_its_recording_and_its_ring_position() {
    for recording in [DownloadSink::Log, DownloadSink::Capture] {
        let mut channel = Channel::new();
        let bytes = vec![0xA5_u8; 96];
        let pending = channel
            .requester
            .ship(recording, 0x1234_5678_9ABC_DEF0, &bytes)
            .expect("the window is free");
        assert_eq!(pending.operation(), RelayOperation::Ship(recording));
        let demand = channel.responder.take().expect("an item is outstanding");
        assert_eq!(demand.shipping(), Some((recording, 0x1234_5678_9ABC_DEF0)));
        let mut scratch = [0_u8; MAX_RELAY_PAYLOAD];
        assert_eq!(
            demand.payload(&channel.responder, &mut scratch),
            Some(bytes.as_slice())
        );
        channel.responder.answered(demand, &[], false, false);
        let mut into = [0_u8; MAX_RELAY_PAYLOAD];
        let _ = channel.requester.poll(pending, &mut into);
    }
}

#[test]
fn no_operation_but_a_shipment_carries_a_position() {
    let mut channel = Channel::new();
    // A ship first, so the word in the region is a real one rather than the
    // zero a fresh region holds: what is under test is that the next item
    // overwrites it rather than leaving the last one's position readable.
    let shipped = channel
        .requester
        .ship(DownloadSink::Capture, 4096, b"ring")
        .expect("the window is free");
    let demand = channel.responder.take().expect("an item is outstanding");
    assert_eq!(demand.shipping(), Some((DownloadSink::Capture, 4096)));
    channel.responder.answered(demand, &[], false, false);
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    let _ = channel.requester.poll(shipped, &mut into);

    let polled = ask(&mut channel, RelayOperation::Poll, &[]);
    let demand = channel.responder.take().expect("an item is outstanding");
    assert_eq!(demand.shipping(), None);
    channel.responder.answered(demand, &[], false, false);
    let _ = channel.requester.poll(polled, &mut into);
}

proptest! {
    /// Every operation word round-trips, and the ship words are the last two of
    /// the vocabulary — so a peer choosing a number cannot introduce an
    /// operation this appliance has none of.
    #[test]
    fn the_operation_vocabulary_ends_where_the_recordings_do(bits in any::<u32>()) {
        match RelayOperation::from_bits(bits) {
            Some(operation) => {
                prop_assert_eq!(operation.to_bits(), bits);
                prop_assert!(bits < RelayOperation::RANGE_BASE + RangeOutcome::COUNT as u32);
            }
            None => prop_assert!(
                bits >= RelayOperation::RANGE_BASE + RangeOutcome::COUNT as u32
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Recording range reads: the one direction the terminating end initiates, and
// the answer that comes back the other way.
// ---------------------------------------------------------------------------

/// An extent of the capture ring, used wherever the numbers themselves do not
/// matter.
const WANT: RangeWant = RangeWant {
    recording: DownloadSink::Capture,
    start: 0x1234_5678,
    length: 4096,
};

#[test]
fn every_range_outcome_round_trips_through_its_operation_word() {
    for outcome in [
        RangeOutcome::Data,
        RangeOutcome::Overwritten,
        RangeOutcome::MediumRefused,
    ] {
        let operation = RelayOperation::Range(outcome);
        assert_eq!(
            RelayOperation::from_bits(operation.to_bits()),
            Some(operation)
        );
        assert_eq!(RangeOutcome::from_bits(outcome.to_bits()), Some(outcome));
    }
}

#[test]
fn a_range_word_past_the_outcomes_names_no_operation() {
    let past = RelayOperation::Range(RangeOutcome::MediumRefused).to_bits() + 1;
    assert_eq!(
        RelayOperation::from_bits(past),
        None,
        "the vocabulary ends where the outcomes do, so a word past it is input \
         to reject rather than one to coerce"
    );
}

#[test]
fn a_want_round_trips_and_zero_is_nothing_wanted() {
    assert_eq!(
        RangeWanting::from_bits(RangeWanting::to_bits(None)),
        Some(None)
    );
    for recording in [DownloadSink::Log, DownloadSink::Capture] {
        let bits = RangeWanting::to_bits(Some(recording));
        assert_ne!(
            bits,
            RangeWanting::NOTHING,
            "a recording must not share the word that means no extent is owed"
        );
        assert_eq!(RangeWanting::from_bits(bits), Some(Some(recording)));
    }
}

#[test]
fn a_stated_want_reaches_the_network_end_on_every_answer() {
    let mut channel = Channel::new();
    channel.responder.want(Some(WANT));
    for _ in 0..3 {
        let pending = ask(&mut channel, RelayOperation::Poll, &[]);
        let demand = channel.responder.take().expect("outstanding");
        channel.responder.answered(demand, &[], false, true);
        let mut into = [0_u8; MAX_RELAY_PAYLOAD];
        match channel.requester.poll(pending, &mut into) {
            RelayPoll::Answered { wanted, .. } => assert_eq!(
                wanted,
                Some(WANT),
                "the want is a level and is stated on every answer, so a wakeup \
                 that coalesced with another cannot lose it"
            ),
            other => panic!("expected an answer: {other:?}"),
        }
    }
}

#[test]
fn a_refusal_states_no_want_however_one_was_left_standing() {
    let mut channel = Channel::new();
    channel.responder.want(Some(WANT));
    let pending = ask(&mut channel, RelayOperation::Poll, &[]);
    let demand = channel.responder.take().expect("outstanding");
    channel.responder.refuse(demand, RelayRefusal::NoConnection);
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    assert!(matches!(
        channel.requester.poll(pending, &mut into),
        RelayPoll::Refused(RelayRefusal::NoConnection)
    ));
    // And the next answer does not resurrect it: a refusal is this end saying it
    // never had a session, so an extent asked for over one is nobody's.
    let pending = ask(&mut channel, RelayOperation::Poll, &[]);
    let demand = channel.responder.take().expect("outstanding");
    channel.responder.answered(demand, &[], false, false);
    match channel.requester.poll(pending, &mut into) {
        RelayPoll::Answered { wanted, .. } => assert_eq!(wanted, None),
        other => panic!("expected an answer: {other:?}"),
    }
}

#[test]
fn a_want_word_naming_no_recording_is_a_fault_and_never_read_as_idle() {
    let request: &'static RelayRequest = Box::leak(Box::new(RelayRequest::zero()));
    let reply: &'static RelayReply = Box::leak(Box::new(RelayReply::zero()));
    let mut requester = request.requester(reply);
    let mut responder = reply.responder(request);
    let pending = requester
        .request(RelayOperation::Poll, &[])
        .expect("the window is free");
    let demand = responder.take().expect("outstanding");
    responder.answered(demand, &[], false, false);
    // A responder writing the region directly, which is what a byzantine
    // neighbour does.
    reply
        .wanted
        .store(0xDEAD_BEEF, core::sync::atomic::Ordering::Relaxed);
    let mut into = [0_u8; MAX_RELAY_PAYLOAD];
    assert_eq!(
        requester.poll(pending, &mut into),
        RelayPoll::Faulted(RelayFault::WantUnknown {
            wanted: 0xDEAD_BEEF
        }),
        "an extent silently dropped is an operator's request that answers nothing \
         and says nothing"
    );
    assert_eq!(requester.faults(), 1);
}

#[test]
fn a_range_answer_carries_its_position_and_only_a_range_answer_does() {
    let mut channel = Channel::new();
    let pending = channel
        .requester
        .range(RangeOutcome::Data, 0xABCD, b"extent")
        .expect("the window is free");
    assert_eq!(
        pending.operation(),
        RelayOperation::Range(RangeOutcome::Data)
    );
    let demand = channel.responder.take().expect("outstanding");
    assert_eq!(demand.ranging(), Some(0xABCD));
    assert_eq!(
        demand.shipping(),
        None,
        "a position is readable only off the operation that stated one"
    );
    let mut scratch = [0_u8; MAX_RELAY_PAYLOAD];
    assert_eq!(
        demand.payload(&channel.responder, &mut scratch),
        Some(&b"extent"[..])
    );
    channel.responder.answered(demand, &[], false, true);
}

#[test]
fn an_ended_range_answer_carries_no_bytes_however_many_were_offered() {
    for outcome in [RangeOutcome::Overwritten, RangeOutcome::MediumRefused] {
        let mut channel = Channel::new();
        let _pending = channel
            .requester
            .range(outcome, 512, b"bytes that must not travel")
            .expect("the window is free");
        let demand = channel.responder.take().expect("outstanding");
        assert_eq!(
            demand.stated_len(),
            0,
            "a frame contradicting itself is refused at the door it is issued \
             through, not composed and then refused"
        );
        assert_eq!(demand.ranging(), Some(512));
        channel.responder.answered(demand, &[], false, true);
    }
}

#[test]
fn a_ship_position_is_not_readable_as_a_range_position() {
    let mut channel = Channel::new();
    let _pending = channel
        .requester
        .ship(DownloadSink::Log, 4096, b"ring")
        .expect("the window is free");
    let demand = channel.responder.take().expect("outstanding");
    assert_eq!(demand.shipping(), Some((DownloadSink::Log, 4096)));
    assert_eq!(demand.ranging(), None);
    channel.responder.answered(demand, &[], false, true);
}

proptest! {
    /// Whatever a peer writes into the wanted words, the network end either reads
    /// an extent or raises the one fault for it — never a panic and never a
    /// silent idle channel.
    #[test]
    fn any_wanted_word_is_decoded_or_faulted(
        word in any::<u32>(),
        start in any::<u64>(),
        length in any::<u64>(),
    ) {
        let request: &'static RelayRequest = Box::leak(Box::new(RelayRequest::zero()));
        let reply: &'static RelayReply = Box::leak(Box::new(RelayReply::zero()));
        let mut requester = request.requester(reply);
        let mut responder = reply.responder(request);
        let pending = requester
            .request(RelayOperation::Poll, &[])
            .expect("the window is free");
        let demand = responder.take().expect("outstanding");
        responder.answered(demand, &[], false, false);
        let order = core::sync::atomic::Ordering::Relaxed;
        reply.wanted.store(word, order);
        reply.wanted_start.store(start, order);
        reply.wanted_length.store(length, order);
        let mut into = [0_u8; MAX_RELAY_PAYLOAD];
        match requester.poll(pending, &mut into) {
            RelayPoll::Answered { wanted, .. } => match RangeWanting::from_bits(word) {
                Some(None) => prop_assert_eq!(wanted, None),
                Some(Some(recording)) => prop_assert_eq!(
                    wanted,
                    Some(RangeWant { recording, start, length })
                ),
                None => prop_assert!(false, "an undecodable word answered an extent"),
            },
            RelayPoll::Faulted(RelayFault::WantUnknown { wanted }) => {
                prop_assert_eq!(wanted, word);
                prop_assert!(RangeWanting::from_bits(word).is_none());
            }
            other => prop_assert!(false, "unexpected: {:?}", other),
        }
    }
}
