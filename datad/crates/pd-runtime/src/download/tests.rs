use super::*;

use std::boxed::Box;
use std::{vec, vec::Vec};

use wire::{DownloadReply, DownloadRequest, DownloadResponder};

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

struct Channel {
    request: Box<DownloadRequest>,
    reply: Box<DownloadReply>,
}

impl Channel {
    fn new() -> Self {
        Self {
            request: Box::new(DownloadRequest::zero()),
            reply: Box::new(DownloadReply::zero()),
        }
    }

    fn downloads(&self) -> Downloads<'_> {
        Downloads::attach(&self.request, &self.reply)
    }

    fn responder(&self) -> DownloadResponder<'_> {
        self.reply.responder(&self.request)
    }
}

/// Answer whatever is outstanding with `body`.
fn answer(channel: &Channel, body: &[u8], total_len: u64) {
    let mut responder = channel.responder();
    let demand = responder.take().expect("a request is outstanding");
    responder.deliver(demand, body, total_len, 0);
}

/// One request is outstanding at a time, however many passes go by.
///
/// The recorder holds one staging area and this module one slot, so a reader that
/// asked again while an answer was outstanding would be a request storm against a
/// slow medium — and would take the sequence past the reply it is still waiting
/// for.
#[test]
fn only_one_request_is_ever_outstanding() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    // One responder for the whole test, because "how many requests were made" is
    // a question only a party that remembers what it has answered can ask.
    let mut responder = channel.responder();
    for _ in 0..8 {
        downloads.poll(at(0), true);
    }
    let demand = responder.take().expect("one request is outstanding");
    responder.deliver(demand, &[1u8; 8], 64, 0);
    assert!(
        responder.take().is_none(),
        "the sequence moved while the first request was unanswered"
    );
    downloads.poll(at(0), true);
    assert!(
        downloads.waiting().is_some(),
        "the answer to the one request was not taken"
    );
    assert!(
        responder.take().is_none(),
        "another read was made while a shipment was still in hand"
    );
}

/// A recorder that takes a read and never answers it gives the slot back at
/// [`REPLY_TIMEOUT`], so one silent reply does not stop this reader for the boot
/// — and a reply landing after that is not taken for the next read's.
///
/// Both directions in one case, because the observable is the same either way:
/// answering the held read is taken while the slot still holds it and ignored
/// once it does not, which is what the sequence a given-up request left behind
/// means.
#[test]
fn a_recorder_that_never_answers_is_given_up_on() {
    let deadline = REPLY_TIMEOUT.as_nanos();
    let bytes = vec![7_u8; 32];

    // Still held a nanosecond short of the deadline: the answer is taken.
    {
        let channel = Channel::new();
        let mut downloads = channel.downloads();
        downloads.poll(at(0), true);
        let held = channel
            .responder()
            .take()
            .expect("a request is outstanding");
        downloads.poll(at(deadline - 1), true);
        channel.responder().deliver(held, &bytes, 4096, 0);
        downloads.poll(at(deadline - 1), true);
        assert!(
            downloads.waiting().is_some(),
            "a read was given up on before its deadline"
        );
    }

    // And given up on at it: the same answer is now one no request is held
    // against, so nothing is shipped under it.
    {
        let channel = Channel::new();
        let mut downloads = channel.downloads();
        downloads.poll(at(0), true);
        let stale = channel
            .responder()
            .take()
            .expect("a request is outstanding");
        downloads.poll(at(deadline), true);
        channel.responder().deliver(stale, &bytes, 4096, 0);
        downloads.poll(at(deadline), true);
        assert!(
            downloads.waiting().is_none(),
            "a reply to a read that had been given up on was shipped anyway"
        );
    }
}

/// A node whose clock has not been published arms no deadline, and a pass with no
/// reading of the clock judges none. Both mean *not yet*, which is the direction
/// that cannot give a slot back under a read that was going to be answered.
#[test]
fn an_unclocked_pass_gives_up_on_nothing() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();

    downloads.poll(None, true);
    let held = channel
        .responder()
        .take()
        .expect("a request is outstanding");
    for _ in 0..4 {
        downloads.poll(None, true);
    }
    // Long past the deadline an armed request would have carried, on a request
    // that never armed one.
    downloads.poll(at(REPLY_TIMEOUT.as_nanos() * 4), true);
    channel.responder().deliver(held, &[3_u8; 16], 4096, 0);
    downloads.poll(at(REPLY_TIMEOUT.as_nanos() * 4), true);
    assert!(
        downloads.waiting().is_some(),
        "a request parked unarmed was given up on"
    );
}

// --- the channel's ring cursor ----------------------------------------------

/// The recorder's side, held for the life of a case.
///
/// One responder rather than a fresh one per look, because a responder *is* a
/// position: a second would restart at sequence zero and re-take the request the
/// first has already answered, which reads as a request that was never made.
struct Recorder<'chan> {
    responder: DownloadResponder<'chan>,
}

impl<'chan> Recorder<'chan> {
    fn new(channel: &'chan Channel) -> Self {
        Self {
            responder: channel.responder(),
        }
    }

    /// What was asked for, or `None` where nothing was.
    fn taken(&mut self) -> Option<(DownloadReader, DownloadSink, u64, usize)> {
        let demand = self.responder.take()?;
        let seen = (
            demand.reader()?,
            demand.sink()?,
            demand.offset(),
            demand.len(),
        );
        self.responder
            .refuse(demand, DownloadRefusal::NotReady, 0, 0);
        Some(seen)
    }

    /// Answer whatever is outstanding with `body`, and say what it was for.
    fn deliver(&mut self, body: &[u8], total_len: u64) -> (DownloadReader, DownloadSink, u64) {
        let demand = self.responder.take().expect("a request is outstanding");
        let seen = (
            demand.reader().expect("a reader"),
            demand.sink().expect("a sink"),
            demand.offset(),
        );
        self.responder.deliver(demand, body, total_len, 0);
        seen
    }

    /// Refuse whatever is outstanding, saying where the recording now begins.
    fn refuse(&mut self, reason: DownloadRefusal, total_len: u64, first: u64) -> DownloadSink {
        let demand = self.responder.take().expect("a request is outstanding");
        let sink = demand.sink().expect("a sink");
        self.responder.refuse(demand, reason, total_len, first);
        sink
    }

    fn quiet(&mut self) -> bool {
        self.responder.take().is_none()
    }
}

#[test]
fn nothing_is_read_for_a_channel_that_is_not_up() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();
    // Several passes, so a pass with nothing to do is shown to do nothing rather
    // than merely to have done nothing yet.
    for _ in 0..8 {
        downloads.poll(at(0), false);
    }
    assert!(
        recorder.quiet(),
        "a reader with no channel to ship up asked the recorder anyway"
    );
    assert!(downloads.waiting().is_none());
    assert!(
        downloads.range_waiting().is_none(),
        "a pass with nothing to do produced an answer frame"
    );
}

#[test]
fn a_ring_read_is_asked_in_the_ring_coordinate_and_held_until_it_is_shipped() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();

    downloads.poll(at(0), true);
    let bytes = vec![0xAB_u8; 512];
    assert_eq!(
        recorder.deliver(&bytes, 4096),
        (DownloadReader::Ring, DownloadSink::Log, 0),
        "the cursor starts at the beginning of the ring, in its own coordinate"
    );

    downloads.poll(at(1), true);
    let (recording, position, held) = downloads.waiting().expect("a shipment is held");
    assert_eq!(recording, DownloadSink::Log);
    assert_eq!(position, 0);
    assert_eq!(held, bytes.as_slice());
}

#[test]
fn the_cursor_moves_by_what_was_shipped_and_only_when_it_was() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();

    downloads.poll(at(0), true);
    recorder.deliver(&vec![1_u8; 300], 4096);
    downloads.poll(at(1), true);
    assert!(downloads.waiting().is_some());

    // A pass before the relay has said the shipment went reads nothing more:
    // there is one shipment buffer, and a second read over it would drop the
    // first.
    downloads.poll(at(2), true);
    assert!(recorder.quiet(), "a second read over a held one");

    downloads.shipped();
    assert!(downloads.waiting().is_none());
    downloads.poll(at(3), true);
    assert_eq!(
        recorder
            .taken()
            .map(|(_, recording, position, _)| (recording, position)),
        Some((DownloadSink::Capture, 0)),
        "the other ring is next, and its own cursor has not moved"
    );

    // And back to the ring that shipped, whose cursor moved by exactly what
    // went.
    downloads.poll(at(4), true);
    downloads.poll(at(5), true);
    assert_eq!(
        recorder
            .taken()
            .map(|(_, recording, position, _)| (recording, position)),
        Some((DownloadSink::Log, 300))
    );
}

/// Drive passes until `wanted` is asked for again, past its hold-off, and answer
/// the position it was asked at.
///
/// Bounded by a count of this test's own: a reader that never comes back is the
/// failure under test, not a loop to wait out.
fn asked_for(
    downloads: &mut Downloads<'_>,
    recorder: &mut Recorder<'_>,
    wanted: DownloadSink,
) -> Option<u64> {
    for step in 1..=8 {
        downloads.poll(at(RING_HOLDOFF.as_nanos() * step), true);
        if let Some((_, recording, offset, _)) = recorder.taken()
            && recording == wanted
        {
            return Some(offset);
        }
    }
    None
}

#[test]
fn a_ring_the_traffic_outran_resumes_where_the_medium_now_begins() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();

    // The first thing every cursor asks for is position zero, and a recorder
    // that resumed a medium serves nothing before the segment this boot opened.
    const BEGINS: u64 = 4 << 20;
    downloads.poll(at(0), true);
    let outrun = recorder.refuse(DownloadRefusal::Overrun, BEGINS + 512, BEGINS);
    downloads.poll(at(1), true);

    assert_eq!(
        downloads.take_shipped(),
        Some(Shipped::Resynchronised {
            recording: outrun,
            lost_from: 0,
            resumed_at: BEGINS,
        }),
        "the reader must say what it could not ship and where it carried on"
    );

    // And the recording goes on being read, from where the medium now begins.
    // A cursor given up on instead would be an appliance that stops shipping
    // that recording for the rest of its boot.
    let asked_again = asked_for(&mut downloads, &mut recorder, outrun);
    assert_eq!(
        asked_again,
        Some(BEGINS),
        "the outrun recording was never asked for again, or not from the position \
         the recorder said it now begins at"
    );
}

#[test]
fn a_resume_point_that_does_not_advance_moves_no_cursor() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();

    // A recorder answering an overrun with a position that is not past the one
    // it refused is a peer this reader cannot act on: taking it would have the
    // channel ship the same bytes forever.
    downloads.poll(at(0), true);
    let outrun = recorder.refuse(DownloadRefusal::Overrun, 512, 0);
    downloads.poll(at(1), true);
    assert_eq!(
        downloads.take_shipped(),
        None,
        "a resume point that does not advance was acted on"
    );

    let asked_again = asked_for(&mut downloads, &mut recorder, outrun);
    assert_eq!(asked_again, Some(0), "the cursor moved on a peer's say-so");
}

#[test]
fn a_caught_up_ring_is_left_alone_rather_than_asked_on_every_wakeup() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();

    // Both rings answer empty, which is what a cursor level with the medium
    // gets.
    for step in 0..2 {
        downloads.poll(at(step), true);
        recorder.deliver(&[], 0);
    }
    downloads.poll(at(2), true);
    assert!(
        recorder.quiet(),
        "a caught-up reader asked again inside its hold-off"
    );

    // And it comes back once the hold-off is out.
    downloads.poll(at(RING_HOLDOFF.as_nanos() * 2), true);
    assert!(
        recorder.taken().is_some(),
        "a caught-up reader never came back"
    );
}

#[test]
fn the_two_rings_take_turns_so_neither_starves_the_other() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();
    let mut seen = Vec::new();
    // A pass per hold-off, because every answer this recorder gives is a
    // refusal and a refused ring is left alone for one: a reader that came
    // straight back would be asking a recorder that has just said no at
    // whatever rate the port is woken.
    for step in 1..=4 {
        downloads.poll(at(RING_HOLDOFF.as_nanos() * step), true);
        if let Some((_, recording, _, _)) = recorder.taken() {
            seen.push(recording);
        }
    }
    assert_eq!(
        seen,
        vec![
            DownloadSink::Log,
            DownloadSink::Capture,
            DownloadSink::Log,
            DownloadSink::Capture
        ]
    );
}

#[test]
fn a_channel_that_is_shipping_says_where_it_has_got_to() {
    // The console is the whole of what a deployed appliance has, and a channel
    // that reports only how many frames one session carried cannot be told from
    // one that greeted its server and stopped: the framing record is written
    // once. This is the record that moves.
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();

    let mut positions = Vec::new();
    for step in 0..4_u64 {
        let now = at(SHIPPING_REPORT_PERIOD.as_nanos() * step);
        downloads.poll(now, true);
        recorder.deliver(&vec![7_u8; 512], 4096);
        downloads.poll(now, true);
        downloads.shipped();
        downloads.poll(now, true);
        while let Some(shipped) = downloads.take_shipped() {
            if let Shipped::Shipping { log, capture } = shipped {
                positions.push((log.position, capture.position));
            }
        }
    }

    assert!(
        positions.len() >= 2,
        "a shipping channel said nothing about where it had got to: {positions:?}"
    );
    for pair in positions.windows(2) {
        let (Some(earlier), Some(later)) = (pair.first(), pair.get(1)) else {
            continue;
        };
        assert!(
            later.0 > earlier.0 || later.1 > earlier.1,
            "two consecutive lines named the same place: {positions:?}"
        );
    }
}

#[test]
fn a_channel_with_records_behind_it_that_is_not_moving_says_so_once() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();

    // A shipment read and never shipped: the relay has room for nothing, or the
    // far end never answers. The reader has bytes in hand and a durable end well
    // past its cursor, and its cursor does not move.
    downloads.poll(at(0), true);
    recorder.deliver(&vec![3_u8; 512], 1 << 20);
    downloads.poll(at(1), true);
    assert!(downloads.waiting().is_some());
    while downloads.take_shipped().is_some() {}

    let overdue = SHIPPING_STALL_WINDOW.as_nanos() * 2;
    downloads.poll(at(overdue), true);
    let stalled: Vec<Shipped> = core::iter::from_fn(|| downloads.take_shipped())
        .filter(|shipped| matches!(shipped, Shipped::Stalled { .. }))
        .collect();
    assert_eq!(
        stalled,
        vec![Shipped::Stalled {
            recording: DownloadSink::Log,
            place: Place {
                position: 0,
                pending: 1 << 20,
            },
        }],
        "a channel holding records it is not shipping said nothing"
    );

    // And once: a token repeated every pass is a console an operator stops
    // reading.
    downloads.poll(at(overdue * 2), true);
    assert!(
        core::iter::from_fn(|| downloads.take_shipped())
            .all(|shipped| !matches!(shipped, Shipped::Stalled { .. })),
        "the stall was reported more than once"
    );
}

#[test]
fn a_channel_that_is_down_is_not_reported_as_a_stalled_reader() {
    // An appliance whose channel has not come up has a channel to go and look
    // at, and this token beside it would send an operator to the reader.
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();

    downloads.poll(at(0), true);
    recorder.deliver(&vec![3_u8; 512], 1 << 20);
    downloads.poll(at(1), false);
    downloads.poll(at(SHIPPING_STALL_WINDOW.as_nanos() * 4), false);
    assert!(
        core::iter::from_fn(|| downloads.take_shipped())
            .all(|shipped| !matches!(shipped, Shipped::Stalled { .. })),
        "a reader with nowhere to ship was reported as stalled"
    );
}

#[test]
fn a_recording_nobody_has_asked_about_is_not_reported_as_caught_up() {
    // A durable end of zero on a ring the recorder has never answered is
    // *unknown*, not *nothing behind the cursor*. Said as the latter, the very
    // first line of a boot claims a drained channel — and a reader that acts on
    // "caught up" would be acting on a recording nothing has looked at.
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();

    downloads.poll(at(0), true);
    recorder.deliver(&vec![5_u8; 512], 4_096);
    downloads.poll(at(1), true);
    downloads.shipped();
    downloads.poll(at(2), true);
    assert!(
        core::iter::from_fn(|| downloads.take_shipped())
            .all(|shipped| !matches!(shipped, Shipped::Shipping { .. })),
        "the channel said where it stood with one recording still unasked"
    );

    // And once the other has answered, it says so — for both.
    recorder.deliver(&[], 0);
    downloads.poll(at(SHIPPING_REPORT_PERIOD.as_nanos()), true);
    assert_eq!(
        core::iter::from_fn(|| downloads.take_shipped())
            .find(|shipped| matches!(shipped, Shipped::Shipping { .. })),
        Some(Shipped::Shipping {
            log: Place {
                position: 512,
                pending: 3_584,
            },
            capture: Place {
                position: 0,
                pending: 0,
            },
        })
    );
}

/// The reports a pass raised, drained as the domain drains them.
fn reports(downloads: &mut Downloads<'_>) -> Vec<Shipped> {
    let mut taken = Vec::new();
    while let Some(shipped) = downloads.take_shipped() {
        taken.push(shipped);
    }
    taken
}

#[test]
fn a_session_reads_each_recording_from_where_its_greeting_says_to() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();

    downloads.resume_from(Acknowledged {
        log: 8_192,
        capture: 4_096,
    });
    downloads.poll(at(0), true);
    assert_eq!(
        recorder.deliver(&[7_u8; 64], 65_536),
        (DownloadReader::Ring, DownloadSink::Log, 8_192),
        "the reader asked from the beginning of the ring rather than from the resume point"
    );
    downloads.poll(at(1), true);
    downloads.shipped();
    downloads.poll(at(2), true);
    assert_eq!(
        recorder.deliver(&[7_u8; 64], 65_536),
        (DownloadReader::Ring, DownloadSink::Capture, 4_096),
        "the other recording's own resume point was not honoured"
    );
}

/// A resume point behind where this appliance already shipped is honoured, not
/// refused: the server is asking for a run again, and every frame carries its
/// own position, so the repetition is harmless.
#[test]
fn a_resume_point_behind_the_cursor_moves_the_reader_back_to_it() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();

    downloads.poll(at(0), true);
    recorder.deliver(&[3_u8; 128], 65_536);
    downloads.poll(at(1), true);
    downloads.shipped();

    downloads.resume_from(Acknowledged::NONE);
    downloads.poll(at(2), true);
    let (_, _, offset, _) = recorder.taken().expect("a ring read");
    assert_eq!(offset, 0, "the reader did not go back to the resume point");
}

#[test]
fn a_resume_point_past_the_durable_end_is_cut_to_it_and_said_out_loud() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();

    // One answer apiece, so both recordings' durable ends are known: before
    // that an unstated end is *unknown* rather than *nothing*, and clamping
    // against it would place every reader at zero.
    downloads.poll(at(0), true);
    recorder.deliver(&[], 4_096);
    downloads.poll(at(1), true);
    downloads.poll(at(2_000_000_000), true);
    recorder.deliver(&[], 2_048);
    // A pass claims and then asks, so this one leaves a request outstanding for
    // whichever ring is out of hold-off. Answered and claimed here, so what the
    // resume point below is judged by is a reader with nothing in flight.
    downloads.poll(at(2_000_000_001), true);
    recorder.refuse(DownloadRefusal::NotReady, 4_096, 0);
    downloads.poll(at(2_000_000_002), true);
    assert!(recorder.quiet(), "the reader is asking during its hold-off");
    let _ = reports(&mut downloads);

    downloads.resume_from(Acknowledged {
        log: 1_000_000,
        capture: 0,
    });
    let raised = reports(&mut downloads);
    assert_eq!(
        raised,
        vec![Shipped::ResumeClamped {
            recording: DownloadSink::Log,
            claimed: 1_000_000,
            durable: 4_096,
        }],
        "a resume point past the durable end was taken whole, or was cut silently"
    );

    // Whichever ring the round-robin reaches first, the clamped one must be
    // asked for at the durable end and not at what the server named.
    let mut asked_log_at = None;
    for step in 0..4 {
        downloads.poll(at(4_000_000_000 + step * 2_000_000_000), true);
        let Some((_, sink, offset, _)) = recorder.taken() else {
            continue;
        };
        if sink == DownloadSink::Log {
            asked_log_at = Some(offset);
            break;
        }
    }
    assert_eq!(asked_log_at, Some(4_096));
}

/// The acknowledged position is not the reader's: it is what the far end holds,
/// it only ever grows, and it rides every later request to the recorder.
#[test]
fn what_the_far_end_holds_only_ever_grows_and_reaches_the_recorder() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();

    downloads.acknowledged(Acknowledged {
        log: 2_048,
        capture: 512,
    });
    downloads.acknowledged(Acknowledged {
        log: 1_024,
        capture: 4_096,
    });
    downloads.poll(at(0), true);
    let demand = recorder.responder.take().expect("a request is outstanding");
    assert_eq!(
        demand.acknowledged(),
        Acknowledged {
            log: 2_048,
            capture: 4_096,
        },
        "a later, smaller claim walked an acknowledged position backwards"
    );
    recorder
        .responder
        .refuse(demand, DownloadRefusal::NotReady, 0, 0);
}

// ---------------------------------------------------------------------------
// Recording range reads: the extent the composing domain asks for, the frames
// this reader produces, and the medium shared out between them and the rings.
// ---------------------------------------------------------------------------

/// An extent of the capture ring.
fn want(start: u64, length: u64) -> RangeWant {
    RangeWant {
        recording: DownloadSink::Capture,
        start,
        length,
    }
}

/// Answer whatever is outstanding as a demand for a range answer, and hand back
/// what it asked for.
fn range_asked(channel: &Channel) -> Option<(DownloadSink, DownloadReader, u64, usize)> {
    let mut responder = channel.responder();
    let demand = responder.take()?;
    let seen = (
        demand.sink()?,
        demand.reader()?,
        demand.offset(),
        demand.len(),
    );
    responder.refuse(demand, DownloadRefusal::NotReady, 0, 0);
    Some(seen)
}

/// Step the reader until the read it has outstanding is the one for `start`,
/// refusing whatever else it asks for on the way.
///
/// The medium is shared out in turn and the rotation starts on the first ring, so
/// a case about a range answer has to reach the answer's turn rather than assume
/// the first pass is it. Bounded by the rotation, which is what makes this a
/// helper and not a spin: if the read is not reached in that many passes the
/// reader is not asking for it at all, and the case says so.
fn advance_to_range(
    channel: &Channel,
    downloads: &mut Downloads<'_>,
    start: u64,
    from: u64,
) -> u64 {
    let mut nanos = from;
    for _ in 0..=MEDIUM_TURNS {
        downloads.poll(at(nanos), true);
        nanos += 1;
        // Peeked through a throwaway responder, which each of these fixtures is:
        // one starts at sequence zero, so leaving a demand unanswered leaves the
        // request outstanding in the region for the caller to answer.
        let peeked = {
            let mut responder = channel.responder();
            responder
                .take()
                .map(|demand| (demand.offset(), demand.reader()))
        };
        let Some((offset, reader)) = peeked else {
            continue;
        };
        if offset == start && matches!(reader, Some(DownloadReader::Ring)) {
            return nanos;
        }
        {
            let mut responder = channel.responder();
            if let Some(demand) = responder.take() {
                responder.refuse(demand, DownloadRefusal::NotReady, 0, 0);
            }
        }
        downloads.poll(at(nanos), true);
        nanos += 1;
        while downloads.take_shipped().is_some() {}
    }
    panic!("the reader never asked for the extent at {start}");
}

#[test]
fn an_extent_is_read_in_the_rings_own_coordinate_and_never_past_one_frame() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    // Larger than one frame carries, so the request must be cut by this crate's
    // own bound rather than by the number it was handed.
    downloads.wants(Some(want(0x4000, (RANGE_ANSWER_BYTES as u64) * 4)));
    advance_to_range(&channel, &mut downloads, 0x4000, 0);
    assert_eq!(
        range_asked(&channel),
        Some((
            DownloadSink::Capture,
            DownloadReader::Ring,
            0x4000,
            RANGE_ANSWER_BYTES
        )),
        "an extent is asked for in the ring's own append space — the coordinate \
         the framing's positions are in — and never more than one frame carries"
    );
}

#[test]
fn an_extent_shorter_than_a_frame_is_asked_for_at_its_own_length() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    downloads.wants(Some(want(64, 100)));
    advance_to_range(&channel, &mut downloads, 64, 0);
    assert_eq!(
        range_asked(&channel).map(|asked| (asked.2, asked.3)),
        Some((64, 100))
    );
}

#[test]
fn nothing_is_read_for_an_extent_while_no_channel_can_carry_the_answer() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    downloads.wants(Some(want(0, 4096)));
    downloads.poll(at(0), false);
    assert!(
        range_asked(&channel).is_none(),
        "a want with no session to answer over is an extent nobody is waiting for"
    );
    assert!(
        downloads.range_waiting().is_none(),
        "and a frame held from an ended session does not survive into the next"
    );
}

#[test]
fn a_read_that_brought_bytes_becomes_one_data_frame_at_the_position_asked_for() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    downloads.wants(Some(want(0x8000, 4096)));
    let now = advance_to_range(&channel, &mut downloads, 0x8000, 0);
    answer(&channel, &[0xAB; 512], 1 << 20);
    downloads.poll(at(now), true);
    let (outcome, position, bytes) = downloads.range_waiting().expect("one frame");
    assert_eq!(outcome, RangeOutcome::Data);
    assert_eq!(position, 0x8000);
    assert_eq!(bytes, &[0xAB_u8; 512][..]);
    // Retired on the answer, and no cursor moves with it.
    downloads.range_answered();
    assert!(downloads.range_waiting().is_none());
}

#[test]
fn an_overrun_becomes_an_overwritten_frame_carrying_nothing() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    downloads.wants(Some(want(0x100, 4096)));
    let now = advance_to_range(&channel, &mut downloads, 0x100, 0);
    {
        let mut responder = channel.responder();
        let demand = responder.take().expect("a request is out");
        responder.refuse(demand, DownloadRefusal::Overrun, 1 << 20, 0x9000);
    }
    downloads.poll(at(now), true);
    let (outcome, position, bytes) = downloads.range_waiting().expect("one frame");
    assert_eq!(
        outcome,
        RangeOutcome::Overwritten,
        "the ring rolled past the extent, which is the one refusal the wire has a \
         word of its own for"
    );
    assert_eq!(position, 0x100);
    assert!(bytes.is_empty(), "an ended answer carries no bytes");
}

#[test]
fn every_other_refusal_becomes_a_medium_refusal_and_names_its_cause_on_the_console() {
    for (reason, expected) in [
        (DownloadRefusal::DeviceError, RangeOutcome::MediumRefused),
        (DownloadRefusal::NotReady, RangeOutcome::MediumRefused),
        (DownloadRefusal::OutOfRange, RangeOutcome::MediumRefused),
        (DownloadRefusal::NoSuchSink, RangeOutcome::MediumRefused),
        (DownloadRefusal::NoSuchReader, RangeOutcome::MediumRefused),
    ] {
        let channel = Channel::new();
        let mut downloads = channel.downloads();
        downloads.wants(Some(want(0x200, 4096)));
        let now = advance_to_range(&channel, &mut downloads, 0x200, 0);
        {
            let mut responder = channel.responder();
            let demand = responder.take().expect("a request is out");
            responder.refuse(demand, reason, 0, 0);
        }
        downloads.poll(at(now), true);
        let (outcome, position, bytes) = downloads.range_waiting().expect("one frame");
        assert_eq!(outcome, expected, "{reason:?}");
        assert_eq!(position, 0x200);
        assert!(bytes.is_empty());
        // The cause the mapping threw away reaches the console.
        let mut reported = Vec::new();
        while let Some(shipped) = downloads.take_shipped() {
            reported.push(shipped);
        }
        assert!(
            reported.contains(&Shipped::RangeRefused {
                reason,
                offset: 0x200
            }),
            "the wire cannot carry {reason:?}, so the console must: {reported:?}"
        );
    }
}

#[test]
fn an_empty_read_becomes_a_data_frame_of_no_bytes_for_the_composer_to_end() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    downloads.wants(Some(want(0x300, 4096)));
    let now = advance_to_range(&channel, &mut downloads, 0x300, 0);
    answer(&channel, &[], 1 << 20);
    downloads.poll(at(now), true);
    let (outcome, position, bytes) = downloads.range_waiting().expect("one frame");
    assert_eq!(
        outcome,
        RangeOutcome::Data,
        "one place decides what a read that advanced nothing means, and it is the \
         domain holding the request"
    );
    assert_eq!(position, 0x300);
    assert!(bytes.is_empty());
}

#[test]
fn a_recorder_that_never_answered_a_range_read_ends_the_answer_and_says_so() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    downloads.wants(Some(want(0x400, 4096)));
    let now = advance_to_range(&channel, &mut downloads, 0x400, 0);
    // Nothing answers, and the deadline passes.
    downloads.poll(at(now + REPLY_TIMEOUT.as_nanos() + 1), true);
    let (outcome, position, bytes) = downloads.range_waiting().expect("one frame");
    assert_eq!(outcome, RangeOutcome::MediumRefused);
    assert_eq!(position, 0x400);
    assert!(bytes.is_empty());
    let mut reported = Vec::new();
    while let Some(shipped) = downloads.take_shipped() {
        reported.push(shipped);
    }
    assert!(
        reported.contains(&Shipped::RangeUnanswered { offset: 0x400 }),
        "a recorder that said nothing and one that said no are different faults: \
         {reported:?}"
    );
}

#[test]
fn a_second_read_is_not_made_while_a_frame_is_still_held() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    downloads.wants(Some(want(0x500, (RANGE_ANSWER_BYTES as u64) * 2)));
    let now = advance_to_range(&channel, &mut downloads, 0x500, 0);
    answer(&channel, &[1; 64], 1 << 20);
    downloads.poll(at(now), true);
    assert!(downloads.range_waiting().is_some());
    // Every remaining turn of the rotation, so the claim is that no pass reads a
    // second extent rather than that the next one happened not to.
    for step in 0..MEDIUM_TURNS as u64 {
        downloads.poll(at(now + 1 + step), true);
        assert!(
            range_asked(&channel).is_none_or(|asked| asked.2 != 0x500 + RANGE_ANSWER_BYTES as u64),
            "there is one answer buffer, and reading a second over it would drop \
             the first"
        );
    }
}

#[test]
fn the_medium_is_shared_out_between_both_rings_and_one_range_answer() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    downloads.wants(Some(want(0x600, (RANGE_ANSWER_BYTES as u64) * 8)));
    let mut readers = Vec::new();
    // Three passes, each answered so nothing is held, is one full rotation.
    for step in 0..3_u64 {
        downloads.poll(at(step * 2), true);
        {
            let mut responder = channel.responder();
            let demand = responder.take().expect("a request is out");
            let seen = (
                demand.sink().expect("a sink"),
                demand.reader().expect("a reader"),
                demand.offset(),
            );
            readers.push(seen);
            // Refused, so no cursor moves and nothing is held: what this case is
            // about is which participant was asked, not what came back.
            responder.refuse(demand, DownloadRefusal::NotReady, 0, 0);
        }
        downloads.poll(at(step * 2 + 1), true);
        // Drain whatever the refusal reported so the queue does not fill.
        while downloads.take_shipped().is_some() {}
        downloads.range_answered();
    }
    let ring_reads = readers
        .iter()
        .filter(|(_, reader, offset)| matches!(reader, DownloadReader::Ring) && *offset != 0x600)
        .count();
    let range_reads = readers
        .iter()
        .filter(|(_, _, offset)| *offset == 0x600)
        .count();
    assert_eq!(
        (ring_reads, range_reads),
        (2, 1),
        "two of every three reads are a ring's and one is the answer's, so \
         neither a peer starves the channel's own purpose nor the traffic \
         starves an operator's request: {readers:?}"
    );
}
