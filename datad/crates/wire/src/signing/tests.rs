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

/// An archive in the staging region and the token that names it, which is what a
/// cursor produces: the tests below care about the length a request states, not
/// about the pieces the region was written in.
fn staged(staging: &'static crate::InstallStaging, archive: &[u8]) -> crate::StagedUpload {
    let mut cursor = staging.upload().cursor();
    cursor.write(archive);
    cursor.finish()
}

fn identity() -> DeviceIdentity {
    let mut public_key = [0x5A_u8; PUBLIC_KEY_LEN];
    public_key[0] = 0x04;
    DeviceIdentity {
        public_key,
        device_id: [0xA5; DEVICE_ID_LEN],
        owned: false,
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

    let mut into = SignAnswerBuffer::zero();
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
    let mut into = SignAnswerBuffer::zero();
    assert_eq!(
        channel.requester.poll(pending, &mut into),
        SignPoll::Identity(identity())
    );
    // Answering an identity is not signing, so the counter has not moved.
    assert_eq!(channel.responder.signatures(), 0);
}

#[test]
fn the_certificate_request_answers_the_appliances_own_certificate() {
    let mut channel = Channel::new();
    let pending = channel.requester.request(SignOperation::Certificate, &[]);
    let demand = channel.responder.take().expect("outstanding");
    assert_eq!(demand.operation(), Some(SignOperation::Certificate));
    let der = vec![0x30_u8; 512];
    assert_eq!(channel.responder.certificate(demand, &der), der.len());
    let mut into = SignAnswerBuffer::zero();
    match channel.requester.poll(pending, &mut into) {
        SignPoll::Certificate { certificate } => assert_eq!(certificate, &der[..]),
        other => panic!("expected a certificate: {other:?}"),
    }
    // Handing over a certificate is not signing, so the tally has not moved: the
    // one counter on this channel counts private-key operations and nothing else.
    assert_eq!(channel.responder.signatures(), 0);
}

#[test]
fn a_certificate_exactly_the_bound_crosses_whole() {
    let mut channel = Channel::new();
    let pending = channel.requester.request(SignOperation::Certificate, &[]);
    let demand = channel.responder.take().expect("outstanding");
    let widest = vec![0xC5_u8; MAX_CERTIFICATE_LEN];
    assert_eq!(
        channel.responder.certificate(demand, &widest),
        MAX_CERTIFICATE_LEN
    );
    let mut into = SignAnswerBuffer::zero();
    match channel.requester.poll(pending, &mut into) {
        SignPoll::Certificate { certificate } => assert_eq!(certificate, &widest[..]),
        other => panic!("a certificate at the bound was not handed over whole: {other:?}"),
    }
}

#[test]
fn a_certificate_longer_than_the_region_publishes_only_what_it_wrote() {
    let mut channel = Channel::new();
    let pending = channel.requester.request(SignOperation::Certificate, &[]);
    let demand = channel.responder.take().expect("outstanding");
    let published = channel
        .responder
        .certificate(demand, &[0x44; MAX_CERTIFICATE_LEN + 96]);
    assert_eq!(published, MAX_CERTIFICATE_LEN);
    let mut into = SignAnswerBuffer::zero();
    match channel.requester.poll(pending, &mut into) {
        SignPoll::Certificate { certificate } => {
            assert_eq!(certificate.len(), MAX_CERTIFICATE_LEN);
        }
        other => panic!("expected a certificate: {other:?}"),
    }
}

#[test]
fn a_certificate_length_past_the_region_is_refused_before_the_copy() {
    let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
    let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
    let mut requester = request.requester(reply);
    let pending = requester.request(SignOperation::Certificate, &[]);
    let len = (MAX_CERTIFICATE_LEN + 1) as u32;
    publish_raw(
        reply,
        pending.sequence(),
        SignStatus::Ok.to_bits(),
        SignOperation::Certificate.to_bits(),
        len,
    );
    let mut into = SignAnswerBuffer::zero();
    // The certificate's own bound and not the signature's: a fault naming the
    // wrong field would leave a reader looking at the wrong number.
    assert_eq!(
        requester.poll(pending, &mut into),
        SignPoll::Faulted(SignFault::LenPastCertificate { len })
    );
}

#[test]
fn a_signature_length_inside_the_certificate_bound_is_still_past_the_signature() {
    let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
    let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
    let mut requester = request.requester(reply);
    let pending = requester.request(SignOperation::Sign, b"m");
    // A length the wider field would admit, on an answer whose field is the
    // narrow one: the bound each arm holds is its own.
    let len = (MAX_SIGNATURE_LEN + 1) as u32;
    publish_raw(
        reply,
        pending.sequence(),
        SignStatus::Ok.to_bits(),
        SignOperation::Sign.to_bits(),
        len,
    );
    let mut into = SignAnswerBuffer::zero();
    assert_eq!(
        requester.poll(pending, &mut into),
        SignPoll::Faulted(SignFault::LenPastSignature { len })
    );
}

#[test]
fn an_empty_certificate_and_a_measured_identity_are_both_faults() {
    let cases: [(SignOperation, u32, SignFault); 2] = [
        (SignOperation::Certificate, 0, SignFault::EmptyCertificate),
        (
            SignOperation::PublicKey,
            9,
            SignFault::BytesOnIdentity { len: 9 },
        ),
    ];
    for (operation, len, expected) in cases {
        let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
        let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
        let mut requester = request.requester(reply);
        let pending = requester.request(operation, &[]);
        publish_raw(
            reply,
            pending.sequence(),
            SignStatus::Ok.to_bits(),
            operation.to_bits(),
            len,
        );
        let mut into = SignAnswerBuffer::zero();
        assert_eq!(
            requester.poll(pending, &mut into),
            SignPoll::Faulted(expected)
        );
    }
}

/// The whole install exchange: a staged archive, a request stating exactly what
/// staging produced, and an answer that is the status word and nothing else.
#[test]
fn an_install_request_states_what_was_staged_and_is_answered_with_a_verdict() {
    let staging: &'static crate::InstallStaging =
        Box::leak(Box::new(crate::InstallStaging::zero()));
    let mut channel = Channel::new();

    let mut cursor = staging.upload().cursor();
    cursor.write(&[0x11; 3072]);
    let staged = cursor.finish();
    assert_eq!(staged.len(), 3072);
    let pending = channel.requester.install(staged);
    assert_eq!(pending.operation(), SignOperation::Install);

    let demand = channel.responder.take().expect("a demand was published");
    assert_eq!(demand.operation(), Some(SignOperation::Install));
    // The archive's length, taken from the request rather than from the region:
    // the region carries no length of its own, deliberately.
    assert_eq!(demand.stated_len(), 3072);
    channel.responder.installed(demand);

    let mut into = SignAnswerBuffer::zero();
    assert_eq!(
        channel.requester.poll(pending, &mut into),
        SignPoll::Installed
    );
}

/// A package the holder judged and would not take. It is a *refusal* on this
/// channel because it produces no bytes, and it is deliberately not a fault:
/// nothing about the exchange went wrong.
#[test]
fn a_refused_install_comes_back_as_a_refusal_and_not_as_a_fault() {
    let staging: &'static crate::InstallStaging =
        Box::leak(Box::new(crate::InstallStaging::zero()));
    let mut channel = Channel::new();
    let pending = channel.requester.install(staged(staging, &[0; 512]));
    let demand = channel.responder.take().expect("a demand was published");
    channel
        .responder
        .refuse(demand, SignRefusal::InstallRefused);

    let mut into = SignAnswerBuffer::zero();
    assert_eq!(
        channel.requester.poll(pending, &mut into),
        SignPoll::Refused(SignRefusal::InstallRefused)
    );
    assert_eq!(channel.requester.faults(), 0);
    assert_eq!(
        SignRefusal::InstallRefused.to_status(),
        SignStatus::InstallRefused
    );
}

/// An install answer has no field a length could be about, so a responder
/// stating one is answering a protocol other than this.
#[test]
fn an_install_answer_stating_a_length_is_a_fault_of_its_own() {
    let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
    let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
    let mut requester = request.requester(reply);
    let pending = requester.request(SignOperation::Install, &[]);
    publish_raw(
        reply,
        pending.sequence(),
        SignStatus::Ok.to_bits(),
        SignOperation::Install.to_bits(),
        4,
    );
    let mut into = SignAnswerBuffer::zero();
    assert_eq!(
        requester.poll(pending, &mut into),
        SignPoll::Faulted(SignFault::BytesOnInstall { len: 4 })
    );
}

/// The requester's own sequence advances for an install exactly as it does for
/// every other operation, so two installs cannot be answered by one reply.
#[test]
fn two_installs_take_two_sequence_numbers() {
    let staging: &'static crate::InstallStaging =
        Box::leak(Box::new(crate::InstallStaging::zero()));
    let mut channel = Channel::new();
    let first = channel.requester.install(staged(staging, &[1; 8]));
    let demand = channel.responder.take().expect("the first demand");
    channel.responder.installed(demand);
    let mut into = SignAnswerBuffer::zero();
    assert_eq!(
        channel.requester.poll(first, &mut into),
        SignPoll::Installed
    );

    let second = channel.requester.install(staged(staging, &[2; 16]));
    assert_ne!(second.sequence(), channel.responder.served());
    let demand = channel.responder.take().expect("the second demand");
    assert_eq!(demand.stated_len(), 16);
    channel.responder.installed(demand);
    assert_eq!(
        channel.requester.poll(second, &mut into),
        SignPoll::Installed
    );
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
    let mut into = SignAnswerBuffer::zero();
    match requester.poll(pending, &mut into) {
        SignPoll::Outstanding(_) => {}
        other => panic!("a reply to another request was believed: {other:?}"),
    }
    assert_eq!(requester.faults(), 0, "ignoring is not faulting");
    assert_eq!(
        into.signature, [0; MAX_SIGNATURE_LEN],
        "nothing was copied out"
    );
    assert_eq!(
        into.certificate, [0; MAX_CERTIFICATE_LEN],
        "nothing was copied out"
    );
}

#[test]
fn two_requests_in_a_row_are_each_answered_under_their_own_sequence() {
    let mut channel = Channel::new();
    let mut into = SignAnswerBuffer::zero();
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
    let mut into = SignAnswerBuffer::zero();
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
        let mut into = SignAnswerBuffer::zero();
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
    let mut into = SignAnswerBuffer::zero();
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
    let mut into = SignAnswerBuffer::zero();
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
        let mut into = SignAnswerBuffer::zero();
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
    let mut into = SignAnswerBuffer::zero();
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
        let mut into = SignAnswerBuffer::zero();
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
    let mut into = SignAnswerBuffer::zero();
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
            None => assert!(bits >= 3),
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

/// The operations a request may name, as a strategy.
///
/// Enumerated out of the vocabulary rather than listed here: the encoding is
/// contiguous from zero, so `from_bits` answering `None` is one past the last
/// operation. An operation appended to the ABI therefore joins this strategy — and
/// every property below — without either being edited.
fn any_operation() -> impl Strategy<Value = SignOperation> {
    let all: Vec<SignOperation> = (0_u32..).map_while(SignOperation::from_bits).collect();
    proptest::sample::select(all)
}

proptest! {
    /// Whatever a hostile responder publishes, one poll is total: it answers,
    /// refuses, faults or stays outstanding, and never reads past the region.
    ///
    /// The *asked* operation is drawn too, which is what puts the wrong-operation
    /// fault under the property rather than in one hand-written case: every pair
    /// of asked and answered operations is reachable here, and the poll must fault
    /// on each of the six that disagree.
    #[test]
    fn polling_an_arbitrary_reply_is_total(
        asked in any_operation(),
        status in any::<u32>(),
        operation in any::<u32>(),
        len in any::<u32>(),
        offset in 0_u32..3,
    ) {
        let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
        let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
        let mut requester = request.requester(reply);
        let pending = requester.request(asked, b"message");
        // Sometimes the right sequence, sometimes another one.
        let sequence = pending.sequence().wrapping_add(offset);
        publish_raw(reply, sequence, status, operation, len);
        let answered = SignOperation::from_bits(operation);
        let mut into = SignAnswerBuffer::zero();
        let poll = requester.poll(pending, &mut into);
        // A reply this request's own that answers some other question is a fault
        // by name, whatever else it carries: the status and the length are never
        // consulted, because a reply to another question has nothing to say about
        // this one.
        let disagreed = answered.filter(|answered| *answered != asked);
        if let (0, Some(answered)) = (offset, disagreed) {
            prop_assert_eq!(
                poll,
                SignPoll::Faulted(SignFault::WrongOperation { asked, answered })
            );
            prop_assert_eq!(requester.faults(), 1);
        } else {
            match poll {
                SignPoll::Outstanding(_) => prop_assert_ne!(offset, 0),
                SignPoll::Signed { signature, .. } => {
                    prop_assert_eq!(offset, 0);
                    prop_assert_eq!(asked, SignOperation::Sign);
                    prop_assert!(!signature.is_empty());
                    prop_assert!(signature.len() <= MAX_SIGNATURE_LEN);
                }
                SignPoll::Certificate { certificate } => {
                    prop_assert_eq!(offset, 0);
                    prop_assert_eq!(asked, SignOperation::Certificate);
                    prop_assert!(!certificate.is_empty());
                    prop_assert!(certificate.len() <= MAX_CERTIFICATE_LEN);
                }
                SignPoll::Identity(_) => {
                    prop_assert_eq!(offset, 0);
                    prop_assert_eq!(asked, SignOperation::PublicKey);
                }
                SignPoll::Installed => {
                    prop_assert_eq!(offset, 0);
                    prop_assert_eq!(asked, SignOperation::Install);
                    // An install answer carries nothing, so a stated length
                    // could never have reached this arm.
                    prop_assert_eq!(len, 0);
                }
                SignPoll::Refused(_) => prop_assert_eq!(offset, 0),
                SignPoll::Faulted(_) => {
                    prop_assert_eq!(offset, 0);
                    prop_assert_eq!(requester.faults(), 1);
                }
            }
        }
    }

    /// A certificate answer of any stated length either arrives at that length or
    /// is refused for it, and the bound it is held to is the certificate's own.
    ///
    /// The lengths either side of [`MAX_CERTIFICATE_LEN`] are what this is for: a
    /// bound written with `>=` instead of `>` would refuse the widest certificate
    /// the profile can produce, and one written against the signature's field
    /// would refuse almost every certificate there is.
    #[test]
    fn a_stated_certificate_length_either_arrives_or_is_refused_for_itself(
        len in 0_u32..(MAX_CERTIFICATE_LEN as u32 + 64),
    ) {
        let request: &'static SignRequest = Box::leak(Box::new(SignRequest::zero()));
        let reply: &'static SignReply = Box::leak(Box::new(SignReply::zero()));
        let mut requester = request.requester(reply);
        let pending = requester.request(SignOperation::Certificate, &[]);
        publish_raw(
            reply,
            pending.sequence(),
            SignStatus::Ok.to_bits(),
            SignOperation::Certificate.to_bits(),
            len,
        );
        let mut into = SignAnswerBuffer::zero();
        match requester.poll(pending, &mut into) {
            SignPoll::Certificate { certificate } => {
                prop_assert_eq!(certificate.len(), len as usize);
                prop_assert!(len != 0 && (len as usize) <= MAX_CERTIFICATE_LEN);
            }
            SignPoll::Faulted(SignFault::EmptyCertificate) => prop_assert_eq!(len, 0),
            SignPoll::Faulted(SignFault::LenPastCertificate { len: refused }) => {
                prop_assert_eq!(refused, len);
                prop_assert!((len as usize) > MAX_CERTIFICATE_LEN);
            }
            other => prop_assert!(false, "neither arrived nor refused for itself: {other:?}"),
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
