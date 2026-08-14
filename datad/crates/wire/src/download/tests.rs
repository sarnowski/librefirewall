use super::*;
use core::mem::offset_of;
use proptest::prelude::*;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::vec::Vec;

/// The two regions one channel is, held together for a test that drives both
/// ends.
struct Channel {
    request: DownloadRequest,
    reply: DownloadReply,
}

impl Channel {
    fn zero() -> Self {
        Self {
            request: DownloadRequest::zero(),
            reply: DownloadReply::zero(),
        }
    }

    fn requester(&self) -> DownloadRequester<'_> {
        self.request.requester(&self.reply)
    }

    fn responder(&self) -> DownloadResponder<'_> {
        self.reply.responder(&self.request)
    }
}

/// A window-length buffer on the heap: 32 KiB is more than belongs on a test
/// stack, and a test may hold several.
fn buffer() -> Box<[u8; DOWNLOAD_WINDOW_LEN]> {
    Box::new([0; DOWNLOAD_WINDOW_LEN])
}

/// Bytes derived from `tag`, so a window delivered for the wrong request is
/// visible rather than plausible.
fn snapshot(tag: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| tag.wrapping_add(index as u8).wrapping_mul(31))
        .collect()
}

/// Publish a raw reply against `sequence`, which is what a responder that does
/// not keep to the protocol can do at any moment.
fn forge_reply(channel: &Channel, sequence: u32, status: u32, len: u32, total_len: u64) {
    channel.reply.status.store(status, Ordering::Relaxed);
    channel.reply.len.store(len, Ordering::Relaxed);
    channel.reply.total_len.store(total_len, Ordering::Relaxed);
    channel.reply.sequence.store(sequence, Ordering::Release);
}

/// Write a reader word into the request region, which is what a requester that
/// is not this crate's own can do and its own cannot.
fn forge_reader(channel: &Channel, reader: u32) {
    channel.request.reader.store(reader, Ordering::Relaxed);
}

#[test]
fn the_regions_the_system_description_reserves_are_the_recorded_ones() {
    assert_eq!(DOWNLOAD_WINDOW_LEN, 32_768);
    assert_eq!(size_of::<DownloadRequest>(), 40);
    assert_eq!(DOWNLOAD_REQUEST_REGION_SIZE, 0x1000);
    assert!(DOWNLOAD_REQUEST_REGION_SIZE >= size_of::<DownloadRequest>());
    assert!(DOWNLOAD_REQUEST_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));

    assert_eq!(size_of::<DownloadReply>(), 32 + 32_768);
    assert_eq!(size_of::<DownloadReply>(), 32_800);
    assert_eq!(DOWNLOAD_REPLY_REGION_SIZE, 36_864);
    assert!(DOWNLOAD_REPLY_REGION_SIZE >= size_of::<DownloadReply>());
    assert!(DOWNLOAD_REPLY_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
}

/// The byte layout two protection domains agree on, written out rather than
/// derived, so a reorder fails here as well as in the assertion block.
#[test]
fn the_two_headers_occupy_the_bytes_the_recorded_layout_names() {
    assert_eq!(offset_of!(DownloadRequest, sequence), 0);
    assert_eq!(offset_of!(DownloadRequest, sink), 4);
    assert_eq!(offset_of!(DownloadRequest, offset), 8);
    assert_eq!(offset_of!(DownloadRequest, len), 16);
    assert_eq!(offset_of!(DownloadRequest, reader), 20);
    assert_eq!(align_of::<DownloadRequest>(), 8);

    assert_eq!(offset_of!(DownloadReply, sequence), 0);
    assert_eq!(offset_of!(DownloadReply, status), 4);
    assert_eq!(offset_of!(DownloadReply, len), 8);
    assert_eq!(offset_of!(DownloadReply, _pad), 12);
    assert_eq!(offset_of!(DownloadReply, total_len), 16);
    assert_eq!(offset_of!(DownloadReply, first), 24);
    assert_eq!(offset_of!(DownloadReply, bytes), 32);
    assert_eq!(align_of::<DownloadReply>(), 8);
}

#[test]
fn zeroed_regions_are_an_idle_channel() {
    let request = DownloadRequest::default();
    let reply = DownloadReply::default();
    let requester = request.requester(&reply);
    let mut responder = reply.responder(&request);

    assert_eq!(requester.sequence(), 0);
    assert_eq!(requester.faults(), 0);
    assert_eq!(requester.window_len(), DOWNLOAD_WINDOW_LEN);
    assert_eq!(responder.served(), 0);
    assert_eq!(responder.window_len(), DOWNLOAD_WINDOW_LEN);
    assert!(
        responder.take().is_none(),
        "a zeroed request region asks for nothing"
    );
}

/// A zeroed reply region carries sequence zero, which no outstanding request
/// can ever be — so an idle channel cannot be mistaken for an answered one.
#[test]
fn a_zeroed_reply_answers_no_request() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut into = buffer();
    let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, 128);
    assert_eq!(pending.sequence(), 1);
    assert!(matches!(
        requester.poll(pending, &mut into),
        DownloadPoll::Outstanding(_)
    ));
    assert_eq!(requester.faults(), 0);
}

#[test]
fn a_request_crosses_and_its_answer_comes_back_whole() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    let mut into = buffer();
    let bytes = snapshot(7, 1000);

    let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Capture, 4096, 1000);
    let demand = responder.take().expect("a request is outstanding");
    assert_eq!(demand.sequence(), pending.sequence());
    assert_eq!(demand.sink(), Some(DownloadSink::Capture));
    assert_eq!(demand.offset(), 4096);
    assert_eq!(demand.len(), 1000);
    assert!(!demand.is_empty());
    assert_eq!(responder.deliver(demand, &bytes, 1_000_000, 0), 1000);
    assert_eq!(responder.served(), 1);

    match requester.poll(pending, &mut into) {
        DownloadPoll::Delivered {
            bytes: got,
            total_len,
            ..
        } => {
            assert_eq!(got, &bytes[..]);
            assert_eq!(total_len, 1_000_000);
        }
        other => panic!("the answer did not arrive: {other:?}"),
    }
    assert_eq!(requester.faults(), 0);
}

#[test]
fn a_full_window_crosses_byte_for_byte() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    let mut into = buffer();
    let bytes = snapshot(3, DOWNLOAD_WINDOW_LEN);

    let pending = requester.request(
        DownloadReader::Snapshot,
        DownloadSink::Log,
        0,
        DOWNLOAD_WINDOW_LEN,
    );
    let demand = responder.take().expect("outstanding");
    assert_eq!(demand.len(), DOWNLOAD_WINDOW_LEN);
    assert_eq!(
        responder.deliver(demand, &bytes, DOWNLOAD_WINDOW_LEN as u64, 0),
        DOWNLOAD_WINDOW_LEN
    );

    match requester.poll(pending, &mut into) {
        DownloadPoll::Delivered { bytes: got, .. } => assert_eq!(got, &bytes[..]),
        other => panic!("{other:?}"),
    }
}

/// Asking for more than a window is not an error but a download that takes more
/// than one round, and the clamp is what the handle then holds a reply to.
#[test]
fn a_request_larger_than_the_window_is_clamped_at_both_ends() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    let mut into = buffer();
    let bytes = snapshot(9, DOWNLOAD_WINDOW_LEN * 2);

    let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, usize::MAX);
    assert_eq!(pending.requested(), DOWNLOAD_WINDOW_LEN as u32);
    let demand = responder.take().expect("outstanding");
    assert_eq!(demand.len(), DOWNLOAD_WINDOW_LEN);
    // The responder hands over twice the window and only the window crosses.
    assert_eq!(
        responder.deliver(demand, &bytes, bytes.len() as u64, 0),
        DOWNLOAD_WINDOW_LEN
    );
    match requester.poll(pending, &mut into) {
        DownloadPoll::Delivered { bytes: got, .. } => {
            assert_eq!(got, &bytes[..DOWNLOAD_WINDOW_LEN]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_short_delivery_says_how_short_it_was() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    let mut into = buffer();
    let bytes = snapshot(5, 10);

    let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 990, 4096);
    let demand = responder.take().expect("outstanding");
    assert_eq!(responder.deliver(demand, &bytes, 1000, 0), 10);
    match requester.poll(pending, &mut into) {
        DownloadPoll::Delivered {
            bytes: got,
            total_len,
            ..
        } => {
            assert_eq!(got, &bytes[..]);
            assert_eq!(total_len, 1000);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_zero_length_request_delivers_nothing_and_is_not_a_fault() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    let mut into = buffer();
    let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, 0);
    let demand = responder.take().expect("outstanding");
    assert!(demand.is_empty());
    assert_eq!(responder.deliver(demand, &snapshot(1, 64), 64, 0), 0);
    match requester.poll(pending, &mut into) {
        DownloadPoll::Delivered {
            bytes, total_len, ..
        } => {
            assert!(bytes.is_empty());
            assert_eq!(total_len, 64);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(requester.faults(), 0);
}

#[test]
fn every_refusal_reaches_the_requester_with_the_snapshot_length() {
    for reason in [
        DownloadRefusal::NotReady,
        DownloadRefusal::OutOfRange,
        DownloadRefusal::Overrun,
        DownloadRefusal::DeviceError,
        DownloadRefusal::NoSuchSink,
    ] {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut responder = channel.responder();
        let mut into = buffer();
        let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 1 << 40, 512);
        let demand = responder.take().expect("outstanding");
        responder.refuse(demand, reason, 4096, 0);
        assert_eq!(
            requester.poll(pending, &mut into),
            DownloadPoll::Refused {
                reason,
                total_len: 4096,
                first: 0,
            }
        );
        assert_eq!(requester.faults(), 0);
    }
}

/// A sink word naming nothing is answered rather than ignored, so a requester
/// is never left unable to tell a refusal from a hang.
#[test]
fn an_unknown_sink_becomes_a_demand_the_recorder_can_refuse() {
    let channel = Channel::zero();
    let mut responder = channel.responder();
    channel.request.sink.store(0xdead_beef, Ordering::Relaxed);
    channel.request.len.store(64, Ordering::Relaxed);
    channel.request.sequence.store(9, Ordering::Release);

    let demand = responder.take().expect("a request is outstanding");
    assert_eq!(demand.sink(), None);
    responder.refuse(demand, DownloadRefusal::NoSuchSink, 0, 0);
    assert_eq!(channel.reply.sequence.load(Ordering::Relaxed), 9);
    assert_eq!(
        channel.reply.status.load(Ordering::Relaxed),
        DownloadStatus::NoSuchSink.to_bits()
    );
}

#[test]
fn the_responder_takes_each_request_exactly_once() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();

    assert!(responder.take().is_none());
    let first = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, 8);
    let demand = responder.take().expect("outstanding");
    assert!(
        responder.take().is_some(),
        "the sequence has not moved, but nothing has answered it yet"
    );
    responder.deliver(demand, &snapshot(1, 8), 8, 0);
    assert!(
        responder.take().is_none(),
        "an answered request is not taken again"
    );

    let second = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 8, 8);
    assert_ne!(first.sequence(), second.sequence());
    assert!(responder.take().is_some(), "a new request is taken");
}

#[test]
fn the_sequence_steps_over_zero_when_it_wraps() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    requester.sequence = u32::MAX;
    let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, 8);
    assert_eq!(pending.sequence(), 1, "zero is reserved for no request");
    assert_eq!(requester.sequence(), 1);
    assert_eq!(channel.request.sequence.load(Ordering::Relaxed), 1);
}

/// The correlation rule, stated as behaviour: only the reply carrying this
/// request's number is looked at, and the handle comes back untouched otherwise.
#[test]
fn a_reply_to_another_request_is_ignored_entirely() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut into = buffer();
    let mut pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, 64);

    for wrong in [0, 2, 7, u32::MAX] {
        forge_reply(&channel, wrong, DownloadStatus::Ok.to_bits(), 64, 64);
        match requester.poll(pending, &mut into) {
            DownloadPoll::Outstanding(handle) => pending = handle,
            other => panic!("a foreign reply was believed: {other:?}"),
        }
    }
    assert_eq!(requester.faults(), 0, "ignoring is not faulting");
    // The buffer was never touched.
    assert!(into.iter().all(|byte| *byte == 0));

    // And the right one is taken.
    forge_reply(
        &channel,
        pending.sequence(),
        DownloadStatus::Ok.to_bits(),
        0,
        64,
    );
    assert!(matches!(
        requester.poll(pending, &mut into),
        DownloadPoll::Delivered { .. }
    ));
}

/// A responder that answers the previous request after a new one was issued
/// cannot make the new handle accept it.
#[test]
fn a_stale_answer_never_matches_a_newer_request() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    let mut into = buffer();

    let first = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, 32);
    let demand = responder.take().expect("outstanding");
    // Management gives up on the first and asks again before the answer lands.
    let second = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 32, 32);
    responder.deliver(demand, &snapshot(1, 32), 64, 0);

    assert!(matches!(
        requester.poll(second, &mut into),
        DownloadPoll::Outstanding(_)
    ));
    // The abandoned handle would still match, which is why a caller keeps at
    // most one: the type prevents believing a reply you did not ask for, not
    // forgetting to drop a request you abandoned.
    assert!(matches!(
        requester.poll(first, &mut into),
        DownloadPoll::Delivered { .. }
    ));
}

// --- hostile responder ------------------------------------------------------

#[test]
fn a_status_outside_the_closed_set_is_a_fault() {
    for status in [7, 0x1000, u32::MAX] {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut into = buffer();
        let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, 64);
        forge_reply(&channel, pending.sequence(), status, 0, 0);
        assert_eq!(
            requester.poll(pending, &mut into),
            DownloadPoll::Faulted(DownloadFault::StatusUnknown { status })
        );
        assert_eq!(requester.faults(), 1);
    }
}

#[test]
fn a_length_past_the_window_is_a_fault() {
    for len in [DOWNLOAD_WINDOW_LEN as u32 + 1, 0x0010_0000, u32::MAX] {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut into = buffer();
        let pending = requester.request(
            DownloadReader::Snapshot,
            DownloadSink::Log,
            0,
            DOWNLOAD_WINDOW_LEN,
        );
        forge_reply(
            &channel,
            pending.sequence(),
            DownloadStatus::Ok.to_bits(),
            len,
            0,
        );
        assert_eq!(
            requester.poll(pending, &mut into),
            DownloadPoll::Faulted(DownloadFault::LenPastWindow { len })
        );
        assert_eq!(requester.faults(), 1);
    }
}

#[test]
fn a_length_past_what_was_asked_for_is_a_fault() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut into = buffer();
    let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, 100);
    forge_reply(
        &channel,
        pending.sequence(),
        DownloadStatus::Ok.to_bits(),
        101,
        0,
    );
    assert_eq!(
        requester.poll(pending, &mut into),
        DownloadPoll::Faulted(DownloadFault::LenPastRequest {
            len: 101,
            requested: 100,
        })
    );
    assert_eq!(requester.faults(), 1);
}

#[test]
fn a_refusal_carrying_bytes_is_a_fault() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut into = buffer();
    let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, 64);
    forge_reply(
        &channel,
        pending.sequence(),
        DownloadStatus::Overrun.to_bits(),
        64,
        0,
    );
    assert_eq!(
        requester.poll(pending, &mut into),
        DownloadPoll::Faulted(DownloadFault::BytesOnRefusal {
            status: DownloadStatus::Overrun,
            len: 64,
        })
    );
    assert_eq!(requester.faults(), 1);
}

#[test]
fn faults_accumulate_and_saturate() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut into = buffer();
    for expected in 1..=3 {
        let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, 8);
        forge_reply(&channel, pending.sequence(), 99, 0, 0);
        assert!(matches!(
            requester.poll(pending, &mut into),
            DownloadPoll::Faulted(_)
        ));
        assert_eq!(requester.faults(), expected);
    }
    requester.faults = u32::MAX;
    let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, 8);
    forge_reply(&channel, pending.sequence(), 99, 0, 0);
    let _ = requester.poll(pending, &mut into);
    assert_eq!(requester.faults(), u32::MAX, "the tally saturates");
}

/// A reply whose sequence never matches leaves the requester waiting forever
/// and reading nothing — which is a stall, never a corruption.
#[test]
fn a_sequence_that_never_matches_is_a_stall_and_not_a_read() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut into = buffer();
    // Fill the window with bytes a believed reply would hand over.
    for cell in &channel.reply.bytes {
        cell.store(0xff, Ordering::Relaxed);
    }
    let mut pending = requester.request(
        DownloadReader::Snapshot,
        DownloadSink::Log,
        0,
        DOWNLOAD_WINDOW_LEN,
    );
    for round in 0..200u32 {
        forge_reply(
            &channel,
            pending.sequence().wrapping_add(round).wrapping_add(1),
            DownloadStatus::Ok.to_bits(),
            DOWNLOAD_WINDOW_LEN as u32,
            0,
        );
        match requester.poll(pending, &mut into) {
            DownloadPoll::Outstanding(handle) => pending = handle,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(requester.faults(), 0);
    assert!(into.iter().all(|byte| *byte == 0), "nothing was copied out");
}

// --- hostile requester ------------------------------------------------------

#[test]
fn a_requested_length_past_the_window_cannot_size_the_recorders_read() {
    for len in [
        DOWNLOAD_WINDOW_LEN as u32,
        DOWNLOAD_WINDOW_LEN as u32 + 1,
        u32::MAX,
    ] {
        let channel = Channel::zero();
        let mut responder = channel.responder();
        channel.request.len.store(len, Ordering::Relaxed);
        channel.request.sequence.store(1, Ordering::Release);
        let demand = responder.take().expect("outstanding");
        assert_eq!(demand.len(), DOWNLOAD_WINDOW_LEN);
    }
}

/// A requester rewriting the sequence produces at most one demand per change,
/// so a request storm costs one reply each and never an unbounded loop.
#[test]
fn an_arbitrary_request_sequence_costs_one_answer_per_change() {
    let channel = Channel::zero();
    let mut responder = channel.responder();
    let mut answered = 0usize;
    let mut taken_none = 0usize;

    for sequence in [1u32, 1, 2, 2, 0, 0, u32::MAX, u32::MAX, 5, 5] {
        channel.request.sequence.store(sequence, Ordering::Release);
        match responder.take() {
            Some(demand) => {
                responder.refuse(demand, DownloadRefusal::NotReady, 0, 0);
                answered += 1;
            }
            None => taken_none += 1,
        }
    }
    assert_eq!(answered, 4, "one per distinct change, zero excluded");
    assert_eq!(taken_none, 6);
}

// --- neither side writes the other's region --------------------------------

fn reply_image(reply: &DownloadReply) -> (u32, u32, u32, u64, Vec<u8>) {
    (
        reply.sequence.load(Ordering::Relaxed),
        reply.status.load(Ordering::Relaxed),
        reply.len.load(Ordering::Relaxed),
        reply.total_len.load(Ordering::Relaxed),
        reply
            .bytes
            .iter()
            .map(|cell| cell.load(Ordering::Relaxed))
            .collect(),
    )
}

fn request_image(request: &DownloadRequest) -> (u32, u32, u64, u32) {
    (
        request.sequence.load(Ordering::Relaxed),
        request.sink.load(Ordering::Relaxed),
        request.offset.load(Ordering::Relaxed),
        request.len.load(Ordering::Relaxed),
    )
}

#[test]
fn the_requester_never_writes_the_reply_region() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut into = buffer();
    // A reply no correct recorder would publish, so a stray store would show.
    forge_reply(&channel, 0xa5a5_1234, 3, 0, 0x1234_5678_9abc_def0);
    for cell in channel.reply.bytes.iter().take(64) {
        cell.store(0x5a, Ordering::Relaxed);
    }
    let before = reply_image(&channel.reply);

    for round in 0..64u64 {
        let pending =
            requester.request(DownloadReader::Snapshot, DownloadSink::Capture, round, 128);
        let _ = requester.poll(pending, &mut into);
        let _ = requester.faults();
        let _ = requester.sequence();
        assert_eq!(
            reply_image(&channel.reply),
            before,
            "management stored into the recorder's region"
        );
    }
}

#[test]
fn the_responder_never_writes_the_request_region() {
    let channel = Channel::zero();
    let mut responder = channel.responder();
    channel.request.sink.store(1, Ordering::Relaxed);
    channel.request.offset.store(0xdead_beef, Ordering::Relaxed);
    channel.request.len.store(4096, Ordering::Relaxed);
    channel.request.sequence.store(11, Ordering::Release);
    let before = request_image(&channel.request);

    for round in 0..64u32 {
        channel
            .request
            .sequence
            .store(11 + round, Ordering::Release);
        if let Some(demand) = responder.take() {
            if round.is_multiple_of(2) {
                responder.deliver(demand, &snapshot(1, 200), 4096, 0);
            } else {
                responder.refuse(demand, DownloadRefusal::Overrun, 4096, 0);
            }
        }
        let _ = responder.served();
    }
    let after = request_image(&channel.request);
    assert_eq!(after.1, before.1, "the recorder rewrote the sink");
    assert_eq!(after.2, before.2, "the recorder rewrote the offset");
    assert_eq!(after.3, before.3, "the recorder rewrote the length");
}

// --- the wire encodings -----------------------------------------------------

#[test]
fn the_closed_sets_refuse_every_value_outside_them() {
    assert_eq!(DownloadSink::from_bits(0), Some(DownloadSink::Log));
    assert_eq!(DownloadSink::from_bits(1), Some(DownloadSink::Capture));
    assert_eq!(DownloadSink::from_bits(2), None);
    assert_eq!(DownloadSink::from_bits(u32::MAX), None);
    assert_eq!(DownloadSink::Capture.to_bits(), 1);

    let statuses = [
        DownloadStatus::Ok,
        DownloadStatus::NotReady,
        DownloadStatus::OutOfRange,
        DownloadStatus::Overrun,
        DownloadStatus::DeviceError,
        DownloadStatus::NoSuchSink,
        DownloadStatus::NoSuchReader,
    ];
    for (index, status) in statuses.iter().enumerate() {
        assert_eq!(status.to_bits(), index as u32);
        assert_eq!(DownloadStatus::from_bits(status.to_bits()), Some(*status));
    }
    assert_eq!(DownloadStatus::from_bits(7), None);
    assert_eq!(DownloadStatus::from_bits(u32::MAX), None);
}

#[test]
fn a_refusal_is_a_status_without_its_success() {
    assert_eq!(DownloadRefusal::from_status(DownloadStatus::Ok), None);
    for reason in [
        DownloadRefusal::NotReady,
        DownloadRefusal::OutOfRange,
        DownloadRefusal::Overrun,
        DownloadRefusal::DeviceError,
        DownloadRefusal::NoSuchSink,
        DownloadRefusal::NoSuchReader,
    ] {
        assert_eq!(
            DownloadRefusal::from_status(reason.to_status()),
            Some(reason)
        );
    }
    assert_eq!(
        DownloadRefusal::NoSuchSink.to_status(),
        DownloadStatus::NoSuchSink
    );
}

// --- concurrency -----------------------------------------------------------

/// The ordering the protocol rests on, exercised: the responder publishes the
/// window before the sequence and the requester reads the sequence before the
/// window, so a delivered window is never half of one answer and half of
/// another.
#[test]
fn a_requesting_and_an_answering_thread_never_splice_two_windows() {
    const ROUNDS: u8 = 100;
    let channel = Channel::zero();
    let done = AtomicBool::new(false);

    thread::scope(|scope| {
        scope.spawn(|| {
            let mut responder = channel.responder();
            while !done.load(Ordering::Relaxed) {
                if let Some(demand) = responder.take() {
                    // Every byte of the window carries the request's own
                    // number, so a spliced window is visible.
                    let tag = demand.sequence() as u8;
                    let bytes = snapshot(tag, demand.len());
                    responder.deliver(demand, &bytes, 1 << 20, 0);
                } else {
                    std::hint::spin_loop();
                }
            }
        });
        scope.spawn(|| {
            let mut requester = channel.requester();
            let mut into = buffer();
            for _ in 0..ROUNDS {
                let mut pending =
                    requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, 4096);
                loop {
                    let expected = snapshot(pending.sequence() as u8, 4096);
                    match requester.poll(pending, &mut into) {
                        DownloadPoll::Outstanding(handle) => {
                            pending = handle;
                            std::hint::spin_loop();
                        }
                        DownloadPoll::Delivered { bytes, .. } => {
                            assert_eq!(bytes, &expected[..], "a window was spliced");
                            break;
                        }
                        other => panic!("{other:?}"),
                    }
                }
            }
            assert_eq!(requester.faults(), 0);
            done.store(true, Ordering::Relaxed);
        });
    });
}

#[test]
fn a_thread_scribbling_both_regions_cannot_break_either_side() {
    const ROUNDS: u32 = 2_000;
    let channel = Channel::zero();
    let stop = AtomicBool::new(false);

    thread::scope(|scope| {
        let management = scope.spawn(|| {
            let mut requester = channel.requester();
            let mut into = buffer();
            for round in 0..ROUNDS {
                let pending = requester.request(
                    DownloadReader::Snapshot,
                    DownloadSink::Log,
                    u64::from(round),
                    1024,
                );
                match requester.poll(pending, &mut into) {
                    DownloadPoll::Delivered { bytes, .. } => {
                        assert!(bytes.len() <= DOWNLOAD_WINDOW_LEN);
                        assert!(bytes.len() <= 1024);
                    }
                    DownloadPoll::Outstanding(_)
                    | DownloadPoll::Refused { .. }
                    | DownloadPoll::Faulted(_) => {}
                }
            }
        });
        let recorder = scope.spawn(|| {
            let mut responder = channel.responder();
            let bytes = snapshot(2, DOWNLOAD_WINDOW_LEN);
            for _ in 0..ROUNDS {
                if let Some(demand) = responder.take() {
                    assert!(demand.len() <= DOWNLOAD_WINDOW_LEN);
                    responder.deliver(demand, &bytes, 1 << 30, 0);
                }
            }
        });
        let scribbler = scope.spawn(|| {
            let mut seed = 0x9e37_79b9u32;
            while !stop.load(Ordering::Relaxed) {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                // Both regions at once: on a booted node no single domain may
                // write both, so this is a strictly stronger adversary than
                // either mapping permits.
                channel.reply.len.store(seed, Ordering::Relaxed);
                channel
                    .reply
                    .status
                    .store(seed.rotate_left(9), Ordering::Relaxed);
                channel
                    .reply
                    .sequence
                    .store(seed.rotate_left(3), Ordering::Relaxed);
                channel
                    .request
                    .len
                    .store(seed.rotate_left(5), Ordering::Relaxed);
                channel
                    .request
                    .sink
                    .store(seed.rotate_left(7), Ordering::Relaxed);
                channel
                    .request
                    .sequence
                    .store(seed.rotate_left(17), Ordering::Relaxed);
            }
        });

        management.join().expect("management did not panic");
        recorder.join().expect("the recorder did not panic");
        stop.store(true, Ordering::Relaxed);
        scribbler.join().expect("the scribbler did not panic");
    });
}

// --- properties ------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The headline byzantine-responder property: every word of the reply is a
    /// value the recorder chose. Management must return, must never be handed a
    /// slice outside the buffer it gave, and must never take bytes under a
    /// status that says there are none.
    #[test]
    fn an_arbitrary_reply_region_is_polled_safely(
        replies in proptest::collection::vec(
            (any::<u32>(), any::<u32>(), any::<u32>(), any::<u64>()),
            1..=16,
        ),
        asked in 0usize..=(DOWNLOAD_WINDOW_LEN + 64),
    ) {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut into = buffer();

        for (sequence, status, len, total_len) in replies {
            let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Capture, 0, asked);
            let requested = pending.requested();
            forge_reply(&channel, sequence, status, len, total_len);

            match requester.poll(pending, &mut into) {
                DownloadPoll::Outstanding(handle) => {
                    prop_assert_ne!(sequence, handle.sequence());
                }
                DownloadPoll::Delivered { bytes, .. } => {
                    prop_assert!(bytes.len() <= DOWNLOAD_WINDOW_LEN);
                    prop_assert!(bytes.len() <= requested as usize);
                    prop_assert_eq!(bytes.len() as u32, len);
                    prop_assert_eq!(status, DownloadStatus::Ok.to_bits());
                }
                DownloadPoll::Refused { .. } => {
                    prop_assert_ne!(status, DownloadStatus::Ok.to_bits());
                    prop_assert_eq!(len, 0);
                }
                DownloadPoll::Faulted(_) => {}
            }
        }
        prop_assert!(requester.faults() as usize <= 16);
    }

    /// The same, over the request region: the recorder is handed arbitrary
    /// words and must produce a demand it can serve without reading past a
    /// window, or none at all.
    #[test]
    fn an_arbitrary_request_region_leaves_the_recorder_bounded(
        requests in proptest::collection::vec(
            (any::<u32>(), any::<u32>(), any::<u64>(), any::<u32>()),
            1..=16,
        ),
    ) {
        let channel = Channel::zero();
        let mut responder = channel.responder();
        let bytes = snapshot(4, DOWNLOAD_WINDOW_LEN);

        for (sequence, sink, offset, len) in requests {
            channel.request.sink.store(sink, Ordering::Relaxed);
            channel.request.offset.store(offset, Ordering::Relaxed);
            channel.request.len.store(len, Ordering::Relaxed);
            channel.request.sequence.store(sequence, Ordering::Release);

            let Some(demand) = responder.take() else { continue };
            prop_assert_ne!(demand.sequence(), 0);
            prop_assert!(demand.len() <= DOWNLOAD_WINDOW_LEN);
            prop_assert_eq!(demand.offset(), offset);
            prop_assert_eq!(demand.sink(), DownloadSink::from_bits(sink));
            let published = responder.deliver(demand, &bytes, u64::MAX, 0);
            prop_assert!(published <= DOWNLOAD_WINDOW_LEN);
            prop_assert_eq!(published, (len as usize).min(DOWNLOAD_WINDOW_LEN));
            prop_assert_eq!(responder.served(), sequence);
        }
    }

    /// The correlation property in full: a reply is either ignored or is
    /// exactly the bytes the responder wrote for that sequence. Never a
    /// prefix, never another request's window, never a splice.
    #[test]
    fn a_reply_is_ignored_or_is_exactly_what_was_written(
        rounds in proptest::collection::vec((any::<u8>(), 0usize..=2048, any::<bool>()), 1..=32),
    ) {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut responder = channel.responder();
        let mut into = buffer();

        for (tag, len, answer) in rounds {
            let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, len);
            let written = snapshot(tag, len);
            if answer {
                let demand = responder.take().expect("a request is outstanding");
                responder.deliver(demand, &written, len as u64, 0);
            }
            match requester.poll(pending, &mut into) {
                DownloadPoll::Delivered {
            bytes, total_len, ..
        } => {
                    prop_assert!(answer, "a window arrived that was never written");
                    prop_assert_eq!(bytes, &written[..]);
                    prop_assert_eq!(total_len, len as u64);
                }
                DownloadPoll::Outstanding(_) => prop_assert!(!answer),
                other => prop_assert!(false, "unexpected: {:?}", other),
            }
        }
        prop_assert_eq!(requester.faults(), 0);
    }

    /// Both regions hostile at once, which is the only shape that covers
    /// management and the recorder compromised together.
    #[test]
    fn both_regions_arbitrary_together_stay_bounded_and_panic_free(
        words in proptest::collection::vec((any::<u32>(), any::<u32>(), any::<u32>(), any::<u32>()), 1..=16),
    ) {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut responder = channel.responder();
        let mut into = buffer();
        let bytes = snapshot(6, 4096);

        for (reply_sequence, reply_len, request_sequence, request_len) in words {
            channel.reply.sequence.store(reply_sequence, Ordering::Relaxed);
            channel.reply.len.store(reply_len, Ordering::Relaxed);
            channel.request.sequence.store(request_sequence, Ordering::Relaxed);
            channel.request.len.store(request_len, Ordering::Relaxed);

            if let Some(demand) = responder.take() {
                prop_assert!(demand.len() <= DOWNLOAD_WINDOW_LEN);
                responder.deliver(demand, &bytes, 0, 0);
            }
            let pending = requester.request(DownloadReader::Snapshot, DownloadSink::Log, 0, 4096);
            if let DownloadPoll::Delivered { bytes: got, .. } = requester.poll(pending, &mut into) {
                prop_assert!(got.len() <= 4096);
            }
        }
    }
}

// --- the two readers ---------------------------------------------------------

#[test]
fn a_demand_carries_the_reader_the_request_was_made_for() {
    for reader in [DownloadReader::Snapshot, DownloadReader::Ring] {
        let channel = Channel::zero();
        let mut requester = channel.requester();
        let mut responder = channel.responder();
        let _pending = requester.request(reader, DownloadSink::Capture, 4096, 64);
        let demand = responder.take().expect("a request was just issued");
        assert_eq!(demand.reader(), Some(reader));
        assert_eq!(demand.offset(), 4096);
        responder.refuse(demand, DownloadRefusal::NotReady, 0, 0);
    }
}

#[test]
fn a_reader_word_the_recorder_does_not_know_is_readable_as_none() {
    let channel = Channel::zero();
    let mut requester = channel.requester();
    let mut responder = channel.responder();
    let _pending = requester.request(DownloadReader::Ring, DownloadSink::Log, 0, 64);
    // Written straight into the region, which is the only way a peer that is
    // not this crate's own requester can name a reader: what an operator would
    // be shown otherwise is bytes read in a coordinate nobody asked for.
    forge_reader(&channel, DownloadReader::Ring.to_bits() + 1);
    let demand = responder.take().expect("a request was just issued");
    assert_eq!(demand.reader(), None);
    assert_eq!(demand.sink(), Some(DownloadSink::Log));
    responder.refuse(demand, DownloadRefusal::NoSuchReader, 0, 0);
    let mut into = buffer();
    assert_eq!(
        requester.poll(_pending, &mut into),
        DownloadPoll::Refused {
            reason: DownloadRefusal::NoSuchReader,
            total_len: 0,
            first: 0,
        }
    );
}

proptest! {
    /// Every reader word round-trips, and every other one is refused rather
    /// than coerced to a coordinate the requester did not ask in.
    #[test]
    fn the_reader_vocabulary_ends_where_it_ends(bits in any::<u32>()) {
        match DownloadReader::from_bits(bits) {
            Some(reader) => prop_assert_eq!(reader.to_bits(), bits),
            None => prop_assert!(bits >= DownloadSink::COUNT as u32),
        }
    }
}
