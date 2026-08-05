//! The signing channel held to its protocol, and to a peer that keeps to none of
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
    requester: SignRequester<'static>,
    responder: SignResponder<'static>,
}

impl Channel {
    fn new() -> Self {
        let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
        let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
        Self {
            requester: request.requester(reply),
            responder: reply.responder(request),
        }
    }
}

fn identity() -> DeviceIdentity {
    let mut public_key = [0x5A_u8; PUBLIC_KEY_LEN];
    public_key[0] = 0x04;
    DeviceIdentity {
        public_key,
        device_id: [0xA5; DEVICE_ID_LEN],
    }
}

#[test]
fn a_zeroed_pair_of_regions_has_nothing_outstanding() {
    let mut channel = Channel::new();
    assert!(channel.responder.take().is_none());
    assert_eq!(channel.responder.served(), 0);
    assert_eq!(channel.requester.sequence(), 0);
    assert_eq!(channel.requester.faults(), 0);
}

#[test]
fn a_signature_crosses_the_channel_and_the_key_does_not() {
    let mut channel = Channel::new();
    let pending = channel
        .requester
        .request(SignOperation::Sign, b"transcript");
    assert_eq!(pending.operation(), SignOperation::Sign);

    let demand = channel.responder.take().expect("a request is outstanding");
    assert_eq!(demand.operation(), Some(SignOperation::Sign));
    assert_eq!(demand.stated_len(), 10);
    let mut scratch = [0_u8; MAX_SIGN_MESSAGE];
    assert_eq!(
        demand.message(&channel.responder, &mut scratch),
        Some(&b"transcript"[..])
    );
    assert_eq!(channel.responder.signed(demand, &[0xDE; 70]), 70);
    assert_eq!(channel.responder.signatures(), 1);

    let mut into = [0_u8; MAX_SIGNATURE_LEN];
    match channel.requester.poll(pending, &mut into) {
        SignPoll::Signed { signature, signed } => {
            assert_eq!(signature, &[0xDE; 70][..]);
            assert_eq!(signed, 1);
        }
        other => panic!("expected a signature: {other:?}"),
    }
}

#[test]
fn the_identity_request_answers_a_public_key_and_an_identifier() {
    let mut channel = Channel::new();
    let pending = channel.requester.request(SignOperation::PublicKey, &[]);
    let demand = channel.responder.take().expect("outstanding");
    channel.responder.identity(demand, &identity());
    let mut into = [0_u8; MAX_SIGNATURE_LEN];
    assert_eq!(
        channel.requester.poll(pending, &mut into),
        SignPoll::Identity(identity())
    );
    // Answering an identity is not signing, so the counter has not moved.
    assert_eq!(channel.responder.signatures(), 0);
}

#[test]
fn a_reply_carrying_another_sequence_is_ignored_entirely() {
    let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
    let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
    let mut requester = request.requester(reply);
    let pending = requester.request(SignOperation::Sign, b"one");
    // A reply that would be believed but for its sequence: the right status, the
    // right operation, a plausible signature length. Nothing about it is read.
    publish_raw(
        reply,
        pending.sequence().wrapping_add(1),
        SignStatus::Ok.to_bits(),
        SignOperation::Sign.to_bits(),
        8,
    );
    let mut into = [0_u8; MAX_SIGNATURE_LEN];
    match requester.poll(pending, &mut into) {
        SignPoll::Outstanding(_) => {}
        other => panic!("a reply to another request was believed: {other:?}"),
    }
    assert_eq!(requester.faults(), 0, "ignoring is not faulting");
    assert_eq!(into, [0; MAX_SIGNATURE_LEN], "nothing was copied out");
}

#[test]
fn two_requests_in_a_row_are_each_answered_under_their_own_sequence() {
    let mut channel = Channel::new();
    let mut into = [0_u8; MAX_SIGNATURE_LEN];
    for filler in [1_u8, 2] {
        let pending = channel.requester.request(SignOperation::Sign, &[filler]);
        let demand = channel.responder.take().expect("outstanding");
        channel.responder.signed(demand, &[filler; 8]);
        match channel.requester.poll(pending, &mut into) {
            SignPoll::Signed { signature, signed } => {
                assert_eq!(signature, &[filler; 8][..]);
                assert_eq!(signed, u64::from(filler));
            }
            other => panic!("expected an answer for {filler}: {other:?}"),
        }
    }
}

#[test]
fn one_demand_is_taken_per_change_of_the_sequence() {
    let mut channel = Channel::new();
    let pending = channel.requester.request(SignOperation::Sign, b"x");
    let demand = channel.responder.take().expect("outstanding");
    assert!(
        channel.responder.take().is_none(),
        "the same request produced a second demand"
    );
    channel.responder.signed(demand, &[9; 4]);
    assert!(
        channel.responder.take().is_none(),
        "an answered request produced another demand"
    );
    let mut into = [0_u8; MAX_SIGNATURE_LEN];
    assert!(matches!(
        channel.requester.poll(pending, &mut into),
        SignPoll::Signed { .. }
    ));
}

#[test]
fn every_refusal_reaches_the_requester_as_itself_and_carries_no_bytes() {
    for reason in [
        SignRefusal::NoIdentity,
        SignRefusal::SigningFailed,
        SignRefusal::MessageTooLong,
    ] {
        let mut channel = Channel::new();
        let pending = channel.requester.request(SignOperation::Sign, b"m");
        let demand = channel.responder.take().expect("outstanding");
        channel.responder.refuse(demand, reason);
        let mut into = [0_u8; MAX_SIGNATURE_LEN];
        assert_eq!(
            channel.requester.poll(pending, &mut into),
            SignPoll::Refused(reason)
        );
        assert_eq!(channel.requester.faults(), 0, "a refusal is not a fault");
    }
}

#[test]
fn an_operation_word_the_holder_does_not_know_is_refused_rather_than_ignored() {
    let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
    let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
    let mut responder = reply.responder(request);
    let mut requester = request.requester(reply);
    let pending = requester.request(SignOperation::Sign, b"m");
    // A peer that writes a word neither side has a meaning for.
    store_request_operation(request, 7);
    let demand = responder.take().expect("outstanding");
    assert_eq!(demand.operation(), None);
    responder.refuse(demand, SignRefusal::NoSuchOperation);
    let mut into = [0_u8; MAX_SIGNATURE_LEN];
    assert_eq!(
        requester.poll(pending, &mut into),
        SignPoll::Refused(SignRefusal::NoSuchOperation)
    );
}

#[test]
fn a_message_longer_than_a_request_holds_arrives_as_its_true_length() {
    let mut channel = Channel::new();
    let long = vec![0x11_u8; MAX_SIGN_MESSAGE + 40];
    // The handle is dropped: what is under test is what the holder sees, and a
    // request nobody polls is exactly the shape a caller that gave up leaves.
    drop(channel.requester.request(SignOperation::Sign, &long));
    let demand = channel.responder.take().expect("outstanding");
    // Unclamped, which is the whole point: the holder must refuse rather than
    // sign the prefix that happened to fit.
    assert_eq!(demand.stated_len() as usize, long.len());
    let mut scratch = [0_u8; MAX_SIGN_MESSAGE];
    assert!(
        demand.message(&channel.responder, &mut scratch).is_none(),
        "a message past the region was handed over as if it were whole"
    );
}

#[test]
fn a_message_exactly_the_bound_is_signed_whole() {
    let mut channel = Channel::new();
    let widest = vec![0x7E_u8; MAX_SIGN_MESSAGE];
    drop(channel.requester.request(SignOperation::Sign, &widest));
    let demand = channel.responder.take().expect("outstanding");
    let mut scratch = [0_u8; MAX_SIGN_MESSAGE];
    assert_eq!(
        demand.message(&channel.responder, &mut scratch),
        Some(&widest[..])
    );
}

#[test]
fn a_reply_answering_the_wrong_question_is_a_fault() {
    let mut channel = Channel::new();
    let pending = channel.requester.request(SignOperation::Sign, b"m");
    let demand = channel.responder.take().expect("outstanding");
    channel.responder.identity(demand, &identity());
    let mut into = [0_u8; MAX_SIGNATURE_LEN];
    assert_eq!(
        channel.requester.poll(pending, &mut into),
        SignPoll::Faulted(SignFault::WrongOperation {
            asked: SignOperation::Sign,
            answered: SignOperation::PublicKey,
        })
    );
    assert_eq!(channel.requester.faults(), 1);
}

#[test]
fn a_status_or_operation_word_outside_its_vocabulary_is_a_fault() {
    for (status, operation, expected) in [
        (
            9_u32,
            SignOperation::Sign.to_bits(),
            SignFault::StatusUnknown { status: 9 },
        ),
        (
            SignStatus::Ok.to_bits(),
            9,
            SignFault::OperationUnknown { operation: 9 },
        ),
    ] {
        let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
        let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
        let mut requester = request.requester(reply);
        let pending = requester.request(SignOperation::Sign, b"m");
        publish_raw(reply, pending.sequence(), status, operation, 0);
        let mut into = [0_u8; MAX_SIGNATURE_LEN];
        assert_eq!(
            requester.poll(pending, &mut into),
            SignPoll::Faulted(expected)
        );
    }
}

#[test]
fn a_length_past_the_signature_region_is_refused_before_the_copy() {
    let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
    let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
    let mut requester = request.requester(reply);
    let pending = requester.request(SignOperation::Sign, b"m");
    let len = (MAX_SIGNATURE_LEN + 1) as u32;
    publish_raw(
        reply,
        pending.sequence(),
        SignStatus::Ok.to_bits(),
        SignOperation::Sign.to_bits(),
        len,
    );
    let mut into = [0_u8; MAX_SIGNATURE_LEN];
    assert_eq!(
        requester.poll(pending, &mut into),
        SignPoll::Faulted(SignFault::LenPastSignature { len })
    );
}

#[test]
fn a_refusal_carrying_bytes_and_a_success_carrying_none_are_both_faults() {
    let cases: [(u32, u32, SignFault); 2] = [
        (
            SignStatus::SigningFailed.to_bits(),
            4,
            SignFault::BytesOnRefusal {
                status: SignStatus::SigningFailed,
                len: 4,
            },
        ),
        (SignStatus::Ok.to_bits(), 0, SignFault::EmptySignature),
    ];
    for (status, len, expected) in cases {
        let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
        let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
        let mut requester = request.requester(reply);
        let pending = requester.request(SignOperation::Sign, b"m");
        publish_raw(
            reply,
            pending.sequence(),
            status,
            SignOperation::Sign.to_bits(),
            len,
        );
        let mut into = [0_u8; MAX_SIGNATURE_LEN];
        assert_eq!(
            requester.poll(pending, &mut into),
            SignPoll::Faulted(expected)
        );
    }
}

#[test]
fn a_signature_longer_than_the_region_publishes_only_what_it_wrote() {
    let mut channel = Channel::new();
    let pending = channel.requester.request(SignOperation::Sign, b"m");
    let demand = channel.responder.take().expect("outstanding");
    let published = channel
        .responder
        .signed(demand, &[0xEE; MAX_SIGNATURE_LEN + 16]);
    assert_eq!(published, MAX_SIGNATURE_LEN);
    let mut into = [0_u8; MAX_SIGNATURE_LEN];
    match channel.requester.poll(pending, &mut into) {
        SignPoll::Signed { signature, .. } => assert_eq!(signature.len(), MAX_SIGNATURE_LEN),
        other => panic!("expected a signature: {other:?}"),
    }
}

#[test]
fn the_sequence_steps_over_zero_when_it_wraps() {
    let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
    let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
    let mut requester = request.requester(reply);
    // Walk the counter to its maximum without a region write per step: the value
    // is private, so the only way there is through `request`, and the wrap is what
    // is under test rather than the four billion steps before it.
    for _ in 0..2 {
        drop(requester.request(SignOperation::Sign, b"m"));
    }
    assert_eq!(requester.sequence(), 2);
    set_requester_sequence(&mut requester, u32::MAX);
    let wrapped = requester.request(SignOperation::Sign, b"m");
    assert_eq!(wrapped.sequence(), 1, "zero means no request");
}

#[test]
fn every_status_and_operation_bit_pattern_round_trips_or_is_refused() {
    for bits in 0_u32..8 {
        match SignStatus::from_bits(bits) {
            Some(status) => assert_eq!(status.to_bits(), bits),
            None => assert!(bits >= 5),
        }
        match SignOperation::from_bits(bits) {
            Some(operation) => assert_eq!(operation.to_bits(), bits),
            None => assert!(bits >= 2),
        }
    }
    for status in [
        SignStatus::NoIdentity,
        SignStatus::SigningFailed,
        SignStatus::NoSuchOperation,
        SignStatus::MessageTooLong,
    ] {
        let refusal = SignRefusal::from_status(status).expect("not the success");
        assert_eq!(refusal.to_status(), status);
    }
}

/// Store an operation word directly, modelling a peer that writes one this side
/// has no meaning for. The region's fields are private, so this is the only way a
/// test can be the adversary rather than a well-behaved requester.
fn store_request_operation(request: &SignRequest, operation: u32) {
    request.operation.store(operation, Ordering::Relaxed);
}

/// Publish a reply field by field, modelling a responder that keeps to none of
/// the protocol.
fn publish_raw(reply: &SignReply, sequence: u32, status: u32, operation: u32, len: u32) {
    reply.status.store(status, Ordering::Relaxed);
    reply.operation.store(operation, Ordering::Relaxed);
    reply.len.store(len, Ordering::Relaxed);
    reply.sequence.store(sequence, Ordering::Release);
}

/// Place the requester's private counter, so the wrap is reachable in a test.
fn set_requester_sequence(requester: &mut SignRequester<'_>, sequence: u32) {
    requester.sequence = sequence;
}

proptest! {
    /// Whatever a hostile responder publishes, one poll is total: it answers,
    /// refuses, faults or stays outstanding, and never reads past the region.
    #[test]
    fn polling_an_arbitrary_reply_is_total(
        status in any::<u32>(),
        operation in any::<u32>(),
        len in any::<u32>(),
        offset in 0_u32..3,
    ) {
        let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
        let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
        let mut requester = request.requester(reply);
        let pending = requester.request(SignOperation::Sign, b"message");
        // Sometimes the right sequence, sometimes another one.
        let sequence = pending.sequence().wrapping_add(offset);
        publish_raw(reply, sequence, status, operation, len);
        let mut into = [0_u8; MAX_SIGNATURE_LEN];
        match requester.poll(pending, &mut into) {
            SignPoll::Outstanding(_) => prop_assert_ne!(offset, 0),
            SignPoll::Signed { signature, .. } => {
                prop_assert_eq!(offset, 0);
                prop_assert!(!signature.is_empty());
                prop_assert!(signature.len() <= MAX_SIGNATURE_LEN);
            }
            SignPoll::Identity(_) | SignPoll::Refused(_) => prop_assert_eq!(offset, 0),
            SignPoll::Faulted(_) => {
                prop_assert_eq!(offset, 0);
                prop_assert_eq!(requester.faults(), 1);
            }
        }
    }

    /// Whatever a hostile requester writes, one take is total and the message
    /// either arrives whole or is refused for its length.
    #[test]
    fn taking_an_arbitrary_request_is_total(
        operation in any::<u32>(),
        len in any::<u32>(),
        sequence in 1_u32..,
    ) {
        let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
        let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
        let mut responder = reply.responder(request);
        request.operation.store(operation, Ordering::Relaxed);
        request.len.store(len, Ordering::Relaxed);
        request.sequence.store(sequence, Ordering::Release);
        let demand = responder.take().expect("a non-zero sequence is a request");
        prop_assert_eq!(demand.stated_len(), len);
        prop_assert_eq!(demand.operation(), SignOperation::from_bits(operation));
        let mut scratch = [0_u8; MAX_SIGN_MESSAGE];
        let message = demand.message(&responder, &mut scratch);
        prop_assert_eq!(
            message.is_some(),
            (len as usize) <= MAX_SIGN_MESSAGE
        );
        if let Some(message) = message {
            prop_assert_eq!(message.len(), len as usize);
        }
    }
}
