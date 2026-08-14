use wire::{DownloadSink, RangeOutcome};

use super::{
    MAX_RANGE_FRAMES, MAX_RANGE_LENGTH, RANGE_ANSWER_BYTES, RangeRefusal, RangeRequest, RangeTaken,
};

/// Every extent in this file is of the log ring unless the capture ring is what
/// the property is about: the recording is carried and never judged here.
const RING: DownloadSink = DownloadSink::Log;

fn accepted(start: u64, length: u64) -> RangeRequest {
    match RangeRequest::accept(RING, start, length) {
        Ok(request) => request,
        Err(refusal) => panic!("an admissible extent was refused: {refusal:?}"),
    }
}

#[test]
fn an_extent_of_no_bytes_is_refused() {
    assert_eq!(
        RangeRequest::accept(RING, 0, 0),
        Err(RangeRefusal::Empty),
        "a request for no bytes is not an extent, and a data frame carrying none \
         would state a position and convey nothing"
    );
}

#[test]
fn an_extent_past_the_bound_is_refused_and_never_clamped() {
    let asked = MAX_RANGE_LENGTH + 1;
    assert_eq!(
        RangeRequest::accept(RING, 0, asked),
        Err(RangeRefusal::LengthTooLong { asked }),
        "the bound is a constant of this crate, and an extent past it is refused \
         outright: a clamped one would answer a question nobody asked"
    );
}

#[test]
fn an_extent_at_the_bound_is_accepted() {
    let request = accepted(0, MAX_RANGE_LENGTH);
    assert_eq!(request.remaining(), MAX_RANGE_LENGTH);
    assert_eq!(request.budget(), MAX_RANGE_FRAMES);
}

#[test]
fn an_extent_whose_end_leaves_the_coordinate_is_refused() {
    let start = u64::MAX - 3;
    let length = 8;
    assert_eq!(
        RangeRequest::accept(RING, start, length),
        Err(RangeRefusal::EndPastSpace { start, length }),
        "an extent whose end saturates has no end on any medium"
    );
}

#[test]
fn every_refusal_carries_a_token_of_its_own() {
    let tokens = [
        RangeRefusal::Empty.token(),
        RangeRefusal::LengthTooLong { asked: 1 }.token(),
        RangeRefusal::EndPastSpace {
            start: 0,
            length: 0,
        }
        .token(),
    ];
    for (at, token) in tokens.iter().enumerate() {
        assert!(!token.is_empty());
        assert!(
            !tokens[..at].contains(token),
            "a token covering two causes names neither, and the console is the \
             only place a deployed node is diagnosed from"
        );
    }
}

#[test]
fn one_frame_serves_an_extent_that_fits_one() {
    let mut request = accepted(4096, 100);
    let taken = request.took(RangeOutcome::Data, 100);
    assert_eq!(
        taken,
        RangeTaken {
            position: 4096,
            len: 100,
            status: RangeOutcome::Data,
            finished: true,
            token: None,
        }
    );
    assert_eq!(request.remaining(), 0);
}

#[test]
fn a_long_extent_is_answered_at_advancing_positions() {
    let length = (RANGE_ANSWER_BYTES as u64) * 3 + 17;
    let start = 1 << 20;
    let mut request = accepted(start, length);
    let mut at = start;
    let mut served = 0_u64;
    let mut frames = 0_u32;
    loop {
        // The reader hands back a whole frame's worth whenever that much is
        // asked for, which is what a well-behaved one does.
        let taken = request.took(RangeOutcome::Data, RANGE_ANSWER_BYTES);
        assert_eq!(taken.status, RangeOutcome::Data);
        assert_eq!(
            taken.position, at,
            "each frame states where its own bytes begin, so an ingest can place \
             them without holding the ones before"
        );
        assert!(taken.len <= RANGE_ANSWER_BYTES);
        at += taken.len as u64;
        served += taken.len as u64;
        frames += 1;
        if taken.finished {
            assert_eq!(taken.token, None);
            break;
        }
        assert!(frames < MAX_RANGE_FRAMES, "the answer did not terminate");
    }
    assert_eq!(
        served, length,
        "the whole extent is served and no byte past it"
    );
    assert_eq!(frames, 4);
    assert_eq!(request.remaining(), 0);
}

#[test]
fn a_frame_never_carries_more_than_was_owed() {
    let mut request = accepted(0, 10);
    // A neighbour answering with more than the extent asked for.
    let taken = request.took(RangeOutcome::Data, RANGE_ANSWER_BYTES * 4);
    assert_eq!(taken.len, 10, "the extent's own length is the bound");
    assert!(taken.finished);
}

#[test]
fn a_frame_never_carries_more_than_one_frame_holds() {
    let mut request = accepted(0, MAX_RANGE_LENGTH);
    let taken = request.took(RangeOutcome::Data, usize::MAX);
    assert_eq!(
        taken.len, RANGE_ANSWER_BYTES,
        "one frame's room is the second bound, and it is this crate's"
    );
    assert!(!taken.finished);
}

#[test]
fn an_overwritten_extent_ends_the_answer_and_carries_nothing() {
    let mut request = accepted(64, MAX_RANGE_LENGTH);
    let taken = request.took(RangeOutcome::Overwritten, 4096);
    assert_eq!(
        taken,
        RangeTaken {
            position: 64,
            len: 0,
            status: RangeOutcome::Overwritten,
            finished: true,
            token: Some("channel-range-overwritten"),
        },
        "the ring rolled past the extent, so there is nothing to carry and \
         nothing more to ask for"
    );
    assert_eq!(request.remaining(), 0);
}

#[test]
fn a_refused_medium_ends_the_answer_and_carries_nothing() {
    let mut request = accepted(64, MAX_RANGE_LENGTH);
    let taken = request.took(RangeOutcome::MediumRefused, 4096);
    assert_eq!(taken.len, 0);
    assert_eq!(taken.status, RangeOutcome::MediumRefused);
    assert!(taken.finished);
    assert_eq!(taken.token, Some("channel-range-medium-refused"));
}

#[test]
fn a_read_that_produced_nothing_ends_the_answer_rather_than_looping() {
    let mut request = accepted(0, 4096);
    let taken = request.took(RangeOutcome::Data, 0);
    assert!(
        taken.finished,
        "a chunk that advanced nothing must not be asked for again: a request \
         re-asked with no progress is a loop a neighbour paces"
    );
    assert_eq!(taken.len, 0);
    assert_eq!(
        taken.status,
        RangeOutcome::MediumRefused,
        "the wire has no status for a neighbour that would not advance, so the \
         one that fits is stated there"
    );
    assert_eq!(
        taken.token,
        Some("channel-range-no-progress"),
        "and the true cause is named where a node is diagnosed"
    );
}

#[test]
fn the_frame_budget_ends_an_answer_a_neighbour_will_not_advance() {
    let mut request = accepted(0, MAX_RANGE_LENGTH);
    let mut frames = 0_u32;
    let ended = loop {
        // One byte a frame: the shape a neighbour uses to make an answer cost
        // this appliance an unbounded number of reads.
        let taken = request.took(RangeOutcome::Data, 1);
        frames += 1;
        assert!(
            frames <= MAX_RANGE_FRAMES,
            "the frame budget is a constant of this crate and nothing a neighbour \
             sends may extend it"
        );
        if taken.finished {
            break taken;
        }
    };
    assert_eq!(frames, MAX_RANGE_FRAMES);
    assert_eq!(
        ended.status,
        RangeOutcome::MediumRefused,
        "the extent could not be served, so the answer says so"
    );
    assert_eq!(
        ended.len, 0,
        "and carries nothing: a data frame with nothing after it is a short \
         answer the requester cannot tell from a gap"
    );
    assert_eq!(ended.token, Some("channel-range-frames-exhausted"));
    assert_eq!(request.remaining(), 0);
}

#[test]
fn the_extent_the_reader_is_told_of_shrinks_as_it_is_served() {
    let start = 0x4000;
    let length = (RANGE_ANSWER_BYTES as u64) * 2;
    let mut request = accepted(start, length);
    let first = request.wanted();
    assert_eq!(first.recording, RING);
    assert_eq!(first.start, start);
    assert_eq!(first.length, length);
    let _ = request.took(RangeOutcome::Data, RANGE_ANSWER_BYTES);
    let second = request.wanted();
    assert_eq!(second.start, start + RANGE_ANSWER_BYTES as u64);
    assert_eq!(second.length, RANGE_ANSWER_BYTES as u64);
    assert_eq!(second.recording, RING);
}

#[test]
fn the_recording_is_the_one_that_was_asked_for() {
    let request = accepted(0, 1);
    assert_eq!(request.recording(), RING);
    let capture = match RangeRequest::accept(DownloadSink::Capture, 0, 1) {
        Ok(request) => request,
        Err(refusal) => panic!("refused: {refusal:?}"),
    };
    assert_eq!(
        capture.recording(),
        DownloadSink::Capture,
        "the ring is the asking end's, so a neighbour cannot answer a question \
         that was never put"
    );
}

#[test]
fn a_request_terminates_whatever_a_neighbour_answers() {
    // Every outcome and length a neighbour can offer, walked against every
    // starting extent shape, holding the one property that matters: the answer
    // ends inside the frame budget.
    let outcomes = [
        RangeOutcome::Data,
        RangeOutcome::Overwritten,
        RangeOutcome::MediumRefused,
    ];
    let lengths = [
        0,
        1,
        7,
        RANGE_ANSWER_BYTES - 1,
        RANGE_ANSWER_BYTES,
        usize::MAX,
    ];
    for extent in [1_u64, 4096, MAX_RANGE_LENGTH] {
        for outcome in outcomes {
            for len in lengths {
                let mut request = accepted(0, extent);
                let mut frames = 0_u32;
                loop {
                    let taken = request.took(outcome, len);
                    frames += 1;
                    assert!(
                        frames <= MAX_RANGE_FRAMES,
                        "extent {extent} under {outcome:?}/{len} did not terminate"
                    );
                    if taken.finished {
                        break;
                    }
                }
                assert_eq!(request.remaining(), 0);
            }
        }
    }
}
