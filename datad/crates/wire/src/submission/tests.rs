use super::*;
use proptest::prelude::*;
use std::boxed::Box;
use std::vec::Vec;

/// The two regions one channel is, held together for a test that drives both
/// ends. On the heap: 128 KiB of region is more than belongs on a test stack.
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

    fn requester(&self) -> ConfigRequester<'_> {
        self.request.requester(&self.reply)
    }

    fn responder(&self) -> ConfigResponder<'_> {
        self.reply.responder(&self.request)
    }
}

/// A region-length buffer on the heap, for the same reason.
fn buffer() -> Box<[u8; MAX_DOCUMENT_BYTES]> {
    Box::new([0; MAX_DOCUMENT_BYTES])
}

/// Bytes derived from `tag`, so a document delivered for the wrong request is
/// visible rather than plausible.
fn document(tag: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| tag.wrapping_add(index as u8).wrapping_mul(31))
        .collect()
}

/// Publish a raw reply against `sequence`, which is what a responder that does
/// not keep to the protocol can do at any moment.
fn forge_reply(channel: &Channel, sequence: u32, status: u32, len: u32) {
    channel.reply.status.store(status, Ordering::Relaxed);
    channel.reply.len.store(len, Ordering::Relaxed);
    channel.reply.sequence.store(sequence, Ordering::Release);
}

#[test]
fn the_regions_the_system_description_reserves_are_the_recorded_ones() {
    assert_eq!(MAX_DOCUMENT_BYTES, 65_536);
    assert_eq!(size_of::<ConfigRequest>(), 16 + MAX_DOCUMENT_BYTES);
    assert_eq!(size_of::<ConfigReply>(), 32 + MAX_DOCUMENT_BYTES);
    assert_eq!(CONFIG_REQUEST_REGION_SIZE, 0x11000);
    assert_eq!(CONFIG_REPLY_REGION_SIZE, 0x11000);
    assert!(CONFIG_REQUEST_REGION_SIZE >= size_of::<ConfigRequest>());
    assert!(CONFIG_REPLY_REGION_SIZE >= size_of::<ConfigReply>());
}

#[test]
fn a_zeroed_pair_of_regions_has_nothing_outstanding_and_answers_nothing() {
    let channel = Channel::zero();
    let mut responder = channel.responder();
    assert_eq!(responder.take(), None);
    assert_eq!(responder.served(), 0);

    let requester = channel.requester();
    assert_eq!(requester.sequence(), 0);
    assert_eq!(requester.faults(), 0);
    assert_eq!(requester.document_capacity(), MAX_DOCUMENT_BYTES);
}

#[test]
fn a_submitted_document_crosses_whole_and_is_answered_under_its_own_sequence() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    let text = document(7, 4096);

    let pending = requester.submit(&text);
    assert_eq!(pending.sequence(), 1);
    assert_eq!(pending.operation(), ConfigOperation::Submit);

    let demand = responder.take().expect("a request");
    assert_eq!(demand.sequence(), 1);
    assert_eq!(demand.operation(), Some(ConfigOperation::Submit));
    assert_eq!(demand.len(), text.len());
    assert!(!demand.is_empty());
    let mut scratch = buffer();
    assert_eq!(responder.document(&demand, &mut scratch), text.as_slice());

    responder.answer(
        demand,
        ConfigAnswer::Applied {
            generation: 2,
            changes: 9,
        },
    );
    let mut into = buffer();
    assert_eq!(
        requester.poll(pending, &mut into),
        ConfigPoll::Applied {
            generation: 2,
            changes: 9
        }
    );
}

#[test]
fn a_read_carries_no_document_out_and_the_running_one_back() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    // Submitted first, so the length word holds something a read must clear:
    // a stale length would have the deciding domain copy out bytes no request
    // put there.
    let pending = requester.submit(&document(1, 512));
    let demand = responder.take().expect("a submission");
    responder.answer(demand, ConfigAnswer::Unchanged { generation: 1 });
    let mut into = buffer();
    assert_eq!(
        requester.poll(pending, &mut into),
        ConfigPoll::Unchanged { generation: 1 }
    );

    let pending = requester.read();
    assert_eq!(pending.operation(), ConfigOperation::Read);
    let demand = responder.take().expect("a read");
    assert!(demand.is_empty(), "a read carries no document out");
    let running = document(9, 2048);
    responder.deliver(demand, 1, &running);

    match requester.poll(pending, &mut into) {
        ConfigPoll::Document { generation, bytes } => {
            assert_eq!(generation, 1);
            assert_eq!(bytes, running.as_slice());
        }
        other => panic!("{other:?} is not the running document"),
    }
}

#[test]
fn every_answer_shape_survives_the_round_trip() {
    let cases = [
        (
            ConfigAnswer::Applied {
                generation: 4,
                changes: 3,
            },
            ConfigPoll::Applied {
                generation: 4,
                changes: 3,
            },
        ),
        (
            ConfigAnswer::Unchanged { generation: 4 },
            ConfigPoll::Unchanged { generation: 4 },
        ),
        (
            ConfigAnswer::Rejected {
                generation: 4,
                reason: 11,
                detail: 87,
            },
            ConfigPoll::Rejected {
                generation: 4,
                reason: 11,
                detail: 87,
            },
        ),
        (
            ConfigAnswer::Exhausted {
                generation: u32::MAX,
            },
            ConfigPoll::Exhausted {
                generation: u32::MAX,
            },
        ),
    ];
    for (answered, expected) in cases {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut responder = channel.responder();
        let pending = requester.submit(b"<configuration/>");
        let demand = responder.take().expect("a submission");
        responder.answer(demand, answered);
        let mut into = buffer();
        assert_eq!(requester.poll(pending, &mut into), expected);
        assert_eq!(requester.faults(), 0);
    }
}

/// The operation word is peer-written, so a value naming no operation is refused
/// rather than coerced — and answered, so the requester is never left unable to
/// tell a refusal from a hang.
#[test]
fn an_operation_word_naming_nothing_is_answered_rather_than_ignored() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    let pending = requester.submit(b"<configuration/>");
    channel.request.operation.store(7, Ordering::Relaxed);

    let demand = responder.take().expect("a request");
    assert_eq!(demand.operation(), None);
    responder.answer(demand, ConfigAnswer::NoSuchOperation);

    let mut into = buffer();
    assert_eq!(
        requester.poll(pending, &mut into),
        ConfigPoll::NoSuchOperation
    );
}

#[test]
fn a_reply_to_another_request_is_not_read_at_all() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let pending = requester.submit(b"<configuration/>");
    // A whole, well-formed answer, under a sequence nothing is waiting on.
    forge_reply(&channel, 99, ConfigStatus::Applied.to_bits(), 0);

    let mut into = buffer();
    match requester.poll(pending, &mut into) {
        ConfigPoll::Outstanding(pending) => assert_eq!(pending.sequence(), 1),
        other => panic!("{other:?} believed a reply to another request"),
    }
    assert_eq!(requester.faults(), 0, "a mismatch is not a fault");
}

#[test]
fn every_way_a_reply_can_be_unbelievable_is_a_counted_fault() {
    let sequence = 1;
    let cases: [(u32, u32, ConfigFault); 4] = [
        (
            ConfigStatus::ALL.len() as u32,
            0,
            ConfigFault::StatusUnknown {
                status: ConfigStatus::ALL.len() as u32,
            },
        ),
        (
            ConfigStatus::Applied.to_bits(),
            MAX_DOCUMENT_BYTES as u32 + 1,
            ConfigFault::LenPastRegion {
                len: MAX_DOCUMENT_BYTES as u32 + 1,
            },
        ),
        (
            ConfigStatus::Applied.to_bits(),
            8,
            ConfigFault::BytesWithoutADocument {
                status: ConfigStatus::Applied,
                len: 8,
            },
        ),
        (
            ConfigStatus::Document.to_bits(),
            0,
            ConfigFault::AnswersAnotherOperation {
                status: ConfigStatus::Document,
                operation: ConfigOperation::Submit,
            },
        ),
    ];
    for (status, len, expected) in cases {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let pending = requester.submit(b"<configuration/>");
        forge_reply(&channel, sequence, status, len);
        let mut into = buffer();
        assert_eq!(
            requester.poll(pending, &mut into),
            ConfigPoll::Faulted(expected)
        );
        assert_eq!(requester.faults(), 1);
    }
}

/// The mirror of the case above: a generation answering a *read* is the same
/// crossing in the other direction.
#[test]
fn a_generation_answering_a_read_is_a_fault() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let pending = requester.read();
    forge_reply(&channel, 1, ConfigStatus::Applied.to_bits(), 0);
    let mut into = buffer();
    assert_eq!(
        requester.poll(pending, &mut into),
        ConfigPoll::Faulted(ConfigFault::AnswersAnotherOperation {
            status: ConfigStatus::Applied,
            operation: ConfigOperation::Read,
        })
    );
}

/// A status naming no operation carrying bytes is refused too: it belongs to
/// neither operation, so the length is the only thing left to be wrong about it.
#[test]
fn no_such_operation_carrying_bytes_is_a_fault() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let pending = requester.read();
    forge_reply(&channel, 1, ConfigStatus::NoSuchOperation.to_bits(), 4);
    let mut into = buffer();
    assert_eq!(
        requester.poll(pending, &mut into),
        ConfigPoll::Faulted(ConfigFault::BytesWithoutADocument {
            status: ConfigStatus::NoSuchOperation,
            len: 4,
        })
    );
}

#[test]
fn a_document_longer_than_the_region_is_truncated_rather_than_refused() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    let text = document(3, MAX_DOCUMENT_BYTES + 4096);

    let pending = requester.submit(&text);
    let demand = responder.take().expect("a request");
    assert_eq!(demand.len(), MAX_DOCUMENT_BYTES);
    let mut scratch = buffer();
    assert_eq!(
        responder.document(&demand, &mut scratch),
        text.get(..MAX_DOCUMENT_BYTES).expect("the prefix")
    );
    responder.answer(
        demand,
        ConfigAnswer::Rejected {
            generation: 1,
            reason: 5,
            detail: 0,
        },
    );
    let mut into = buffer();
    assert!(matches!(
        requester.poll(pending, &mut into),
        ConfigPoll::Rejected { .. }
    ));
}

/// The length word is the requester's claim, so a length past the region names
/// bytes the region does not hold. Clamped where a copy is sized from it.
#[test]
fn a_claimed_length_past_the_region_is_clamped_before_anything_is_copied() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    let _pending = requester.submit(b"<configuration/>");
    channel.request.len.store(u32::MAX, Ordering::Relaxed);

    let demand = responder.take().expect("a request");
    assert_eq!(demand.len(), MAX_DOCUMENT_BYTES);
    let mut scratch = buffer();
    assert_eq!(
        responder.document(&demand, &mut scratch).len(),
        MAX_DOCUMENT_BYTES
    );
}

/// One request costs one answer, so a peer that rewrites the sequence produces
/// at most one demand per change rather than an unbounded run of them.
#[test]
fn a_request_answered_is_never_taken_again() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    let _pending = requester.submit(b"<configuration/>");

    let demand = responder.take().expect("the first look");
    responder.answer(demand, ConfigAnswer::Unchanged { generation: 1 });
    assert_eq!(responder.served(), 1);
    assert_eq!(responder.take(), None);
    // And the number moving again is one more demand and not two: what a
    // request storm costs is one reply each.
    channel.request.sequence.store(1, Ordering::Release);
    assert_eq!(
        responder.take(),
        None,
        "the same number is the same request"
    );
    channel.request.sequence.store(2, Ordering::Release);
    let second = responder.take().expect("a number that moved");
    assert_eq!(second.sequence(), 2);
    responder.answer(second, ConfigAnswer::Unchanged { generation: 1 });
    assert_eq!(responder.take(), None);
}

#[test]
fn a_sequence_that_wraps_steps_over_zero() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    // The last number before the wrap, reached by writing the private counter
    // through the only door there is: a request per step is 4 billion steps.
    requester.sequence = u32::MAX;
    let pending = requester.read();
    assert_eq!(pending.sequence(), 1, "zero is no request");
    assert_eq!(requester.sequence(), 1);
}

/// Two submissions in a row: the second abandons the first, and the first's
/// handle can then only ever come back outstanding.
#[test]
fn a_second_request_abandons_the_first() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    let first = requester.submit(&document(1, 64));
    let second = requester.submit(&document(2, 64));
    assert_eq!(second.sequence(), 2);

    let demand = responder.take().expect("a request");
    assert_eq!(demand.sequence(), 2, "the responder answers what is there");
    responder.answer(demand, ConfigAnswer::Unchanged { generation: 1 });

    let mut into = buffer();
    assert!(matches!(
        requester.poll(first, &mut into),
        ConfigPoll::Outstanding(_)
    ));
    assert!(matches!(
        requester.poll(second, &mut into),
        ConfigPoll::Unchanged { generation: 1 }
    ));
}

proptest! {
    /// The headline property: arbitrary bytes in either region produce a value
    /// from the closed set and never a panic, and nothing a peer can write
    /// makes a copy reach past the region.
    #[test]
    fn arbitrary_region_content_is_answered_and_never_faults_the_reader(
        status in any::<u32>(),
        len in any::<u32>(),
        sequence in any::<u32>(),
        operation in any::<u32>(),
        read in any::<bool>(),
    ) {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut responder = channel.responder();
        let pending = if read { requester.read() } else { requester.submit(b"<x/>") };

        channel.request.operation.store(operation, Ordering::Relaxed);
        channel.request.len.store(len, Ordering::Relaxed);
        channel.request.sequence.store(sequence, Ordering::Release);
        if let Some(demand) = responder.take() {
            prop_assert!(demand.len() <= MAX_DOCUMENT_BYTES);
            let mut scratch = buffer();
            prop_assert!(responder.document(&demand, &mut scratch).len() <= MAX_DOCUMENT_BYTES);
            responder.answer(demand, ConfigAnswer::NoSuchOperation);
        }

        forge_reply(&channel, pending.sequence(), status, len);
        let mut into = buffer();
        match requester.poll(pending, &mut into) {
            ConfigPoll::Document { bytes, .. } => {
                prop_assert!(bytes.len() <= MAX_DOCUMENT_BYTES);
            }
            ConfigPoll::Faulted(_) => prop_assert_eq!(requester.faults(), 1),
            _ => {}
        }
    }

    /// Whatever the length, a document that crosses is the prefix of what was
    /// submitted and nothing else — so a reader can never be handed bytes from
    /// a previous request beyond the length it was told.
    #[test]
    fn what_crosses_is_the_prefix_of_what_was_submitted(
        first in 0usize..2048,
        second in 0usize..2048,
    ) {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut responder = channel.responder();
        let long = document(5, first);
        let short = document(6, second);

        let _abandoned = requester.submit(&long);
        let pending = requester.submit(&short);
        let demand = responder.take().expect("a request");
        let mut scratch = buffer();
        prop_assert_eq!(responder.document(&demand, &mut scratch), short.as_slice());
        responder.answer(demand, ConfigAnswer::Unchanged { generation: 1 });
        let mut into = buffer();
        let polled = requester.poll(pending, &mut into);
        prop_assert!(matches!(polled, ConfigPoll::Unchanged { .. }), "{polled:?}");
    }
}

/// The four steps a management channel takes cross the channel and come back as
/// the answers they belong to, each carrying the generation it is about.
#[test]
fn the_channels_four_operations_round_trip_with_their_answers() {
    let cases: [(ConfigOperation, ConfigAnswer, ConfigPoll<'static>); 4] = [
        (
            ConfigOperation::Stage,
            ConfigAnswer::Staged { generation: 7 },
            ConfigPoll::Staged { generation: 7 },
        ),
        (
            ConfigOperation::Commit,
            ConfigAnswer::Applied {
                generation: 7,
                changes: 3,
            },
            ConfigPoll::Applied {
                generation: 7,
                changes: 3,
            },
        ),
        (
            ConfigOperation::Confirm,
            ConfigAnswer::Confirmed { generation: 7 },
            ConfigPoll::Confirmed { generation: 7 },
        ),
        (
            ConfigOperation::Rollback,
            ConfigAnswer::RolledBack { generation: 8 },
            ConfigPoll::RolledBack { generation: 8 },
        ),
    ];
    for (operation, answer, expected) in cases {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut responder = channel.responder();
        let pending = match operation {
            ConfigOperation::Stage => requester.stage(b"<configuration/>"),
            ConfigOperation::Commit => requester.commit(7),
            ConfigOperation::Confirm => requester.confirm(7),
            ConfigOperation::Rollback => requester.roll_back(),
            other => panic!("not a channel operation: {other:?}"),
        };
        let demand = responder.take().expect("a request");
        assert_eq!(demand.operation(), Some(operation));
        responder.answer(demand, answer);
        let mut into = buffer();
        assert_eq!(requester.poll(pending, &mut into), expected);
        assert_eq!(requester.faults(), 0);
    }
}

/// The generation word is the request's, and it reaches the deciding domain for
/// exactly the two operations that act on a commit already made.
#[test]
fn only_a_commit_and_a_confirmation_carry_a_generation() {
    for operation in ConfigOperation::ALL {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut responder = channel.responder();
        // Every issue path, with a generation where one is admissible. The handle
        // is dropped rather than polled: what this test reads is the demand the
        // far end takes, and the answer never comes.
        let _issued = match operation {
            ConfigOperation::Submit => requester.submit(b"<configuration/>"),
            ConfigOperation::Read => requester.read(),
            ConfigOperation::Stage => requester.stage(b"<configuration/>"),
            ConfigOperation::Commit => requester.commit(11),
            ConfigOperation::Confirm => requester.confirm(11),
            ConfigOperation::Rollback => requester.roll_back(),
        };
        let demand = responder.take().expect("a request");
        if operation.names_a_generation() {
            assert_eq!(demand.generation(), 11, "{operation:?}");
        } else {
            assert_eq!(demand.generation(), 0, "{operation:?}");
        }
    }
}

/// An operation that reads no document is issued with the length cleared, so a
/// stale one cannot have the deciding domain copy out bytes this request did not
/// put there.
#[test]
fn an_operation_carrying_no_document_clears_the_length_the_last_one_left() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();

    let _issued = requester.stage(&document(3, 512));
    let staged = responder.take().expect("a request");
    assert_eq!(staged.len(), 512);
    responder.answer(staged, ConfigAnswer::Staged { generation: 1 });

    for operation in ConfigOperation::ALL {
        if operation.carries_a_document() {
            continue;
        }
        let _issued = match operation {
            ConfigOperation::Read => requester.read(),
            ConfigOperation::Commit => requester.commit(1),
            ConfigOperation::Confirm => requester.confirm(1),
            ConfigOperation::Rollback => requester.roll_back(),
            other => panic!("carries a document: {other:?}"),
        };
        let demand = responder.take().expect("a request");
        assert!(demand.is_empty(), "{operation:?}");
        assert_eq!(demand.len(), 0, "{operation:?}");
        responder.answer(demand, ConfigAnswer::NoSuchOperation);
    }
}

/// The cross-field rule over the whole widened vocabulary: an answer belonging to
/// no operation asked is a counted fault, whichever pair is crossed.
#[test]
fn an_answer_that_belongs_to_another_operation_is_a_fault() {
    let crossings: [(ConfigOperation, ConfigAnswer); 5] = [
        (
            ConfigOperation::Stage,
            ConfigAnswer::Confirmed { generation: 1 },
        ),
        (
            ConfigOperation::Confirm,
            ConfigAnswer::Staged { generation: 1 },
        ),
        (
            ConfigOperation::Rollback,
            ConfigAnswer::Confirmed { generation: 1 },
        ),
        (
            ConfigOperation::Commit,
            ConfigAnswer::RolledBack { generation: 1 },
        ),
        (
            ConfigOperation::Submit,
            ConfigAnswer::NoCandidate { generation: 1 },
        ),
    ];
    for (operation, answer) in crossings {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut responder = channel.responder();
        let pending = match operation {
            ConfigOperation::Submit => requester.submit(b"<configuration/>"),
            ConfigOperation::Stage => requester.stage(b"<configuration/>"),
            ConfigOperation::Commit => requester.commit(1),
            ConfigOperation::Confirm => requester.confirm(1),
            ConfigOperation::Rollback => requester.roll_back(),
            other => panic!("not asked here: {other:?}"),
        };
        let demand = responder.take().expect("a request");
        responder.answer(demand, answer);
        let mut into = buffer();
        assert!(
            matches!(
                requester.poll(pending, &mut into),
                ConfigPoll::Faulted(ConfigFault::AnswersAnotherOperation { .. })
            ),
            "{operation:?} answered with {answer:?} was believed"
        );
        assert_eq!(requester.faults(), 1);
    }
}

/// The three refusals the channel's own steps carry, each reaching the requester
/// as itself and naming the generation the appliance holds.
#[test]
fn the_channels_refusals_reach_the_requester_as_themselves() {
    let cases: [(ConfigOperation, ConfigAnswer, ConfigPoll<'static>); 3] = [
        (
            ConfigOperation::Commit,
            ConfigAnswer::NoCandidate { generation: 4 },
            ConfigPoll::NoCandidate { generation: 4 },
        ),
        (
            ConfigOperation::Confirm,
            ConfigAnswer::NotProvisional { generation: 4 },
            ConfigPoll::NotProvisional { generation: 4 },
        ),
        (
            ConfigOperation::Commit,
            ConfigAnswer::GenerationMismatch { generation: 5 },
            ConfigPoll::GenerationMismatch { generation: 5 },
        ),
    ];
    for (operation, answer, expected) in cases {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut responder = channel.responder();
        let pending = match operation {
            ConfigOperation::Commit => requester.commit(5),
            ConfigOperation::Confirm => requester.confirm(5),
            other => panic!("not asked here: {other:?}"),
        };
        let demand = responder.take().expect("a request");
        responder.answer(demand, answer);
        let mut into = buffer();
        assert_eq!(requester.poll(pending, &mut into), expected);
        assert_eq!(requester.faults(), 0, "a refusal is not a fault");
    }
}

proptest! {
    /// Every status word a peer can write is either a status this build knows or a
    /// counted fault, and no value of it is ever read as an answer to an operation
    /// it does not belong to.
    #[test]
    fn no_status_word_answers_an_operation_it_does_not_belong_to(
        status in 0u32..40,
        which in 0usize..6,
    ) {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let operation = ConfigOperation::ALL[which % ConfigOperation::ALL.len()];
        let pending = match operation {
            ConfigOperation::Submit => requester.submit(b"<configuration/>"),
            ConfigOperation::Read => requester.read(),
            ConfigOperation::Stage => requester.stage(b"<configuration/>"),
            ConfigOperation::Commit => requester.commit(1),
            ConfigOperation::Confirm => requester.confirm(1),
            ConfigOperation::Rollback => requester.roll_back(),
        };
        forge_reply(&channel, pending.sequence(), status, 0);
        let mut into = buffer();
        let polled = requester.poll(pending, &mut into);
        match ConfigStatus::from_bits(status) {
            Some(decoded) if decoded.answers(operation) => {
                prop_assert!(!matches!(polled, ConfigPoll::Faulted(_)));
            }
            _ => prop_assert!(matches!(polled, ConfigPoll::Faulted(_) | ConfigPoll::NoSuchOperation)),
        }
    }
}
