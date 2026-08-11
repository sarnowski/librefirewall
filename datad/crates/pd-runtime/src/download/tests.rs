use super::*;

use std::boxed::Box;
use std::{vec, vec::Vec};

use lfw_ip_endpoint::http::WINDOW_LEN;
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

/// The endpoint as a download sees it, with every state a real transport can
/// present and two a hostile or broken one can.
///
/// It **enforces the endpoint's own window contract** rather than taking whatever
/// it is handed: a window at another offset, or longer than the length it asked
/// for, is refused exactly as `lfw_ip_endpoint::http::Server::supply_window`
/// refuses one. A fake that accepted any window is what let this module ask for
/// bytes the endpoint would never take, and made every recording past the first
/// window a `200` with an empty body.
#[derive(Default)]
struct FakeStream {
    pending: Option<&'static str>,
    /// What the transport is waiting on: the body offset and the most the array
    /// will take there.
    wanted: Option<(u64, usize)>,
    begun: Option<(u64, ContentType)>,
    supplied: Vec<(u64, Vec<u8>)>,
    abandoned: usize,
    /// Refuse the next `begin_stream`.
    refuse_begin: bool,
    /// Refuse the next `supply_window`, as an endpoint whose place this module
    /// has lost track of does.
    refuse_window: bool,
    /// The counters the last pass handed over for the domain's shard.
    noted: Option<DownloadCounters>,
}

impl Stream for FakeStream {
    fn pending_stream(&self) -> Option<&'static str> {
        self.pending
    }

    fn begin_stream(&mut self, total: u64, content_type: ContentType) -> bool {
        if self.refuse_begin {
            self.refuse_begin = false;
            return false;
        }
        self.pending = None;
        self.begun = Some((total, content_type));
        // A committed response wants its first window at once, which is what the
        // real endpoint answers as soon as the head is written.
        self.wanted = (total > 0).then_some((0, WINDOW_LEN));
        true
    }

    fn stream_wanted(&self) -> Option<(u64, usize)> {
        self.wanted
    }

    fn supply_window(&mut self, start: u64, bytes: &[u8]) -> bool {
        if self.refuse_window {
            self.refuse_window = false;
            return false;
        }
        // The real endpoint's contract: the offset it asked for, at least one
        // byte, and no more than it said it would take.
        let Some((wanted, len)) = self.wanted else {
            return false;
        };
        if start != wanted || bytes.is_empty() || bytes.len() > len {
            return false;
        }
        self.wanted = None;
        self.supplied.push((start, bytes.to_vec()));
        true
    }

    fn abandon_stream(&mut self) {
        self.abandoned += 1;
        self.pending = None;
        self.wanted = None;
    }

    fn note_downloads(&mut self, counters: DownloadCounters) {
        self.noted = Some(counters);
    }
}

/// The recorder's side of the channel, driven by hand.
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

/// What the recorder was asked for, without answering it.
fn asked(channel: &Channel) -> Option<(DownloadSink, u64, usize)> {
    let mut responder = channel.responder();
    let demand = responder.take()?;
    let seen = (demand.sink()?, demand.offset(), demand.len());
    // Put the answer back so the demand is not silently swallowed: a test that
    // inspected and dropped one would leave the requester waiting forever,
    // which is the bug this whole channel is shaped to prevent.
    responder.refuse(demand, DownloadRefusal::NotReady, 0, 0);
    Some(seen)
}

#[test]
fn each_recording_has_exactly_one_target_and_nothing_else_does() {
    assert_eq!(sink_for(LOG_TARGET), Some(DownloadSink::Log));
    assert_eq!(sink_for(CAPTURE_TARGET), Some(DownloadSink::Capture));
    assert_eq!(sink_for("/metrics"), None);
    assert_eq!(sink_for("/logs.pcapng/"), None);
    assert_eq!(sink_for(""), None);
    assert_ne!(LOG_TARGET, CAPTURE_TARGET);
}

#[test]
fn a_get_of_a_recording_asks_the_recorder_for_its_first_window() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        pending: Some(CAPTURE_TARGET),
        ..FakeStream::default()
    };

    downloads.poll(at(0), &mut stream, false);

    assert_eq!(
        asked(&channel),
        Some((DownloadSink::Capture, 0, WINDOW_LEN)),
        "the opening request must fit the transport's own window, not the channel's"
    );
    assert!(stream.begun.is_none(), "nothing is committed to yet");
}

#[test]
fn the_first_reply_begins_the_stream_at_the_length_the_recorder_stated() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        pending: Some(LOG_TARGET),
        ..FakeStream::default()
    };

    downloads.poll(at(0), &mut stream, false);
    let body = vec![0xAB; 128];
    answer(&channel, &body, 4096);
    downloads.poll(at(0), &mut stream, false);

    let (total, content_type) = stream.begun.expect("the stream was begun");
    assert_eq!(total, 4096);
    assert_eq!(content_type, ContentType::OctetStream);
    assert_eq!(stream.supplied, vec![(0, body)]);
    assert_eq!(downloads.counters().started, 1);
    assert_eq!(downloads.counters().windows, 1);
    assert_eq!(downloads.counters().bytes, 128);
    assert_eq!(stream.abandoned, 0);
    assert_eq!(
        stream.noted,
        Some(downloads.counters()),
        "every pass hands the shard what it has done"
    );
}

#[test]
fn a_later_window_is_asked_for_at_the_offset_the_transport_named() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        pending: Some(LOG_TARGET),
        ..FakeStream::default()
    };
    downloads.poll(at(0), &mut stream, false);
    answer(&channel, &[1u8; 64], 4096);
    downloads.poll(at(0), &mut stream, false);

    stream.wanted = Some((64, WINDOW_LEN));
    downloads.poll(at(0), &mut stream, false);
    assert_eq!(
        asked(&channel),
        Some((DownloadSink::Log, 64, WINDOW_LEN)),
        "the same recording, at the offset the transport is waiting on"
    );
}

/// A transport that will take less than a whole window — one completing a window
/// an earlier short supply left unfinished — is asked for exactly that much and
/// no more. Asking for a whole window there would have the reply refused and the
/// download given up on.
#[test]
fn a_partly_filled_window_is_asked_for_at_the_length_it_can_still_take() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        pending: Some(LOG_TARGET),
        ..FakeStream::default()
    };
    downloads.poll(at(0), &mut stream, false);
    answer(&channel, &[1u8; 64], 4_096);
    downloads.poll(at(0), &mut stream, false);

    stream.wanted = Some((64, 300));
    downloads.poll(at(0), &mut stream, false);
    assert_eq!(
        asked(&channel),
        Some((DownloadSink::Log, 64, 300)),
        "the recorder was asked for more than the transport would take"
    );
}

#[test]
fn the_end_of_a_body_supplies_nothing_and_abandons_nothing() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        pending: Some(LOG_TARGET),
        ..FakeStream::default()
    };
    downloads.poll(at(0), &mut stream, false);
    answer(&channel, &[], 0);
    downloads.poll(at(0), &mut stream, false);

    assert_eq!(stream.begun.map(|(total, _)| total), Some(0));
    assert!(stream.supplied.is_empty());
    assert_eq!(stream.abandoned, 0);
}

#[test]
fn every_refusal_ends_the_response_rather_than_retrying_it() {
    for reason in [
        DownloadRefusal::Overrun,
        DownloadRefusal::DeviceError,
        DownloadRefusal::NotReady,
        DownloadRefusal::OutOfRange,
        DownloadRefusal::NoSuchSink,
    ] {
        let channel = Channel::new();
        let mut downloads = channel.downloads();
        let mut stream = FakeStream {
            pending: Some(LOG_TARGET),
            ..FakeStream::default()
        };
        downloads.poll(at(0), &mut stream, false);
        {
            let mut responder = channel.responder();
            let demand = responder.take().expect("a request is out");
            responder.refuse(demand, reason, 0, 0);
        }
        downloads.poll(at(0), &mut stream, false);

        assert_eq!(stream.abandoned, 1, "{reason:?} must end the response");
        assert!(stream.begun.is_none());
        assert_eq!(downloads.counters().abandoned, 1);
    }
}

#[test]
fn an_endpoint_that_will_not_begin_the_stream_ends_it() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        pending: Some(LOG_TARGET),
        refuse_begin: true,
        ..FakeStream::default()
    };
    downloads.poll(at(0), &mut stream, false);
    answer(&channel, &[1u8; 16], 16);
    downloads.poll(at(0), &mut stream, false);

    assert_eq!(stream.abandoned, 1);
    assert!(stream.supplied.is_empty());
}

#[test]
fn an_endpoint_that_refuses_the_window_it_asked_for_ends_the_stream() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        pending: Some(LOG_TARGET),
        refuse_window: true,
        ..FakeStream::default()
    };
    downloads.poll(at(0), &mut stream, false);
    answer(&channel, &[1u8; 16], 4096);
    downloads.poll(at(0), &mut stream, false);

    assert_eq!(stream.abandoned, 1);
    assert!(stream.supplied.is_empty());
}

#[test]
fn a_window_wanted_for_a_stream_this_domain_never_began_is_ended() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        wanted: Some((512, WINDOW_LEN)),
        ..FakeStream::default()
    };
    downloads.poll(at(0), &mut stream, false);

    assert_eq!(stream.abandoned, 1);
    assert!(
        asked(&channel).is_none(),
        "nothing was asked of the recorder"
    );
}

#[test]
fn a_pass_with_nothing_to_do_does_nothing_and_asks_nothing() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream::default();
    for _ in 0..8 {
        downloads.poll(at(0), &mut stream, false);
    }
    assert_eq!(stream.abandoned, 0);
    assert!(asked(&channel).is_none());
    assert_eq!(downloads.counters(), DownloadCounters::default());
}

#[test]
fn only_one_request_is_ever_outstanding() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        pending: Some(LOG_TARGET),
        ..FakeStream::default()
    };
    // One responder for the whole test, because "how many requests were made"
    // is a question only a party that remembers what it has answered can ask.
    let mut responder = channel.responder();
    // Several passes with no answer: the recorder must see one request, not one
    // per pass, or a slow medium would be a request storm.
    for _ in 0..8 {
        downloads.poll(at(0), &mut stream, false);
    }
    let demand = responder.take().expect("one request is outstanding");
    responder.deliver(demand, &[1u8; 8], 64, 0);
    assert!(
        responder.take().is_none(),
        "the sequence never moved while the first was unanswered"
    );
    downloads.poll(at(0), &mut stream, false);
    assert_eq!(stream.supplied.len(), 1);
    assert!(
        responder.take().is_none(),
        "and nothing more is asked until the transport wants a window"
    );
}

/// A recording several windows long arrives whole, through the channel and the
/// endpoint's own window contract.
///
/// The recorder here reads a ring of extents and can never answer past the extent
/// an offset falls in, so **every** window it serves is short — which is the
/// ordinary case for a recording longer than one extent, not an exceptional one.
/// A short window must advance the response: the transport then asks for the
/// remainder, and what the client reads is the body its head announced.
#[test]
fn a_recording_several_windows_long_is_delivered_whole() {
    const TOTAL: u64 = 3 * WINDOW_LEN as u64 + 777;
    /// Shorter than a window, so no reply ever fills one.
    const EXTENT: u64 = 5_000;

    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        pending: Some(CAPTURE_TARGET),
        ..FakeStream::default()
    };

    let mut delivered = 0u64;
    for _ in 0..4096 {
        downloads.poll(at(0), &mut stream, false);
        // The recorder answers whatever is outstanding, stopping at the extent
        // boundary and at the end of the snapshot.
        {
            let mut responder = channel.responder();
            if let Some(demand) = responder.take() {
                let offset = demand.offset();
                let reach = (EXTENT - offset % EXTENT).min(TOTAL.saturating_sub(offset));
                // Lossless: bounded by the demand, itself bounded by the window.
                let len = (demand.len() as u64).min(reach) as usize;
                let bytes: Vec<u8> = (offset..offset.saturating_add(len as u64))
                    .map(|at| (at % 251) as u8)
                    .collect();
                responder.deliver(demand, &bytes, TOTAL, 0);
            }
        }
        downloads.poll(at(0), &mut stream, false);
        // The transport sends what arrived and asks for the rest, which is what
        // the peer's acknowledgement makes it do.
        let taken: u64 = stream
            .supplied
            .iter()
            .map(|(_, bytes)| bytes.len() as u64)
            .sum();
        if taken > delivered {
            delivered = taken;
            stream.wanted = (delivered < TOTAL).then_some((delivered, WINDOW_LEN));
        }
        if delivered >= TOTAL {
            break;
        }
    }

    assert_eq!(stream.begun.map(|(total, _)| total), Some(TOTAL));
    assert_eq!(
        delivered, TOTAL,
        "the body was short of the length its head announced"
    );
    assert_eq!(stream.abandoned, 0, "a short window ended the download");
    assert_eq!(downloads.counters().bytes, TOTAL);
    assert_eq!(downloads.counters().started, 1);

    // Every window arrived at the offset the transport asked for and carried the
    // bytes that belong there: a window taken at the wrong offset would put a
    // recording's bytes where no client could tell they did not belong.
    let mut at = 0u64;
    for (start, bytes) in &stream.supplied {
        assert_eq!(*start, at, "a window arrived out of order");
        assert!(!bytes.is_empty(), "an empty window was taken");
        for (index, byte) in bytes.iter().enumerate() {
            assert_eq!(
                u64::from(*byte),
                at.saturating_add(index as u64) % 251,
                "the window at {at} carried another offset's bytes"
            );
        }
        at = at.saturating_add(bytes.len() as u64);
    }
    assert!(
        stream.supplied.len() as u64 > TOTAL / WINDOW_LEN as u64,
        "every window was served whole, so no short one was exercised"
    );
}

/// A recorder that never answers does not hold this module's one outstanding slot
/// forever: the window is given up on at its deadline and the download abandoned.
///
/// Without the deadline the stream stays committed, the endpoint's staging array
/// stays claimed, and every body-bearing surface answers 503 for the life of the
/// domain — a download being the *other* way that array is held.
#[test]
fn a_recorder_that_never_answers_is_given_up_on() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        pending: Some(LOG_TARGET),
        ..FakeStream::default()
    };

    downloads.poll(at(0), &mut stream, false);
    {
        // Taken and never answered, which is a recorder that has stopped.
        let mut responder = channel.responder();
        let demand = responder.take().expect("a request is outstanding");
        drop(demand);
    }

    let deadline = REPLY_TIMEOUT.as_nanos();
    downloads.poll(at(deadline - 1), &mut stream, false);
    assert_eq!(stream.abandoned, 0, "given up on early");

    downloads.poll(at(deadline), &mut stream, false);
    assert_eq!(stream.abandoned, 1, "the download was never given up on");
    assert_eq!(downloads.counters().abandoned, 1);

    // And the slot is free again, so the next `GET` of a recording is asked for
    // rather than being the one this domain never serves.
    stream.pending = Some(CAPTURE_TARGET);
    downloads.poll(at(deadline), &mut stream, false);
    assert_eq!(
        asked(&channel),
        Some((DownloadSink::Capture, 0, WINDOW_LEN)),
        "the outstanding slot was never given back"
    );
}

/// A window that lands after the deadline cannot be taken for the next request's.
/// The abandoned request left a sequence number behind, and a reply to it answers a
/// number no pending request is held against.
#[test]
fn a_window_that_arrives_after_the_deadline_supplies_nothing() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        pending: Some(LOG_TARGET),
        ..FakeStream::default()
    };

    downloads.poll(at(0), &mut stream, false);
    let stale = channel
        .responder()
        .take()
        .expect("a request is outstanding");
    let deadline = REPLY_TIMEOUT.as_nanos();
    downloads.poll(at(deadline), &mut stream, false);
    assert_eq!(stream.abandoned, 1);

    // A fresh download is outstanding by the time the recorder answers the old one.
    stream.pending = Some(CAPTURE_TARGET);
    downloads.poll(at(deadline), &mut stream, false);
    channel.responder().deliver(stale, b"stale bytes", 11, 0);
    downloads.poll(at(deadline), &mut stream, false);
    assert!(
        stream.begun.is_none() && stream.supplied.is_empty(),
        "a reply to an abandoned request was taken for the new one's"
    );
}

/// A node whose clock has not been published arms no deadline, and a pass with no
/// reading of the clock judges none. Both mean *not yet*, which is the direction
/// that cannot truncate a download that was going to complete.
#[test]
fn an_unclocked_pass_gives_up_on_nothing() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        pending: Some(LOG_TARGET),
        ..FakeStream::default()
    };

    downloads.poll(None, &mut stream, false);
    let _outstanding = channel
        .responder()
        .take()
        .expect("a request is outstanding");
    for _ in 0..4 {
        downloads.poll(None, &mut stream, false);
    }
    assert_eq!(stream.abandoned, 0);

    downloads.poll(at(REPLY_TIMEOUT.as_nanos() * 4), &mut stream, false);
    assert_eq!(
        stream.abandoned, 0,
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
    let mut stream = FakeStream::default();
    downloads.poll(at(0), &mut stream, false);
    assert!(
        recorder.quiet(),
        "a reader with no channel to ship up asked the recorder anyway"
    );
    assert!(downloads.waiting().is_none());
}

#[test]
fn a_ring_read_is_asked_in_the_ring_coordinate_and_held_until_it_is_shipped() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();
    let mut stream = FakeStream::default();

    downloads.poll(at(0), &mut stream, true);
    let bytes = vec![0xAB_u8; 512];
    assert_eq!(
        recorder.deliver(&bytes, 4096),
        (DownloadReader::Ring, DownloadSink::Log, 0),
        "the cursor starts at the beginning of the ring, in its own coordinate"
    );

    downloads.poll(at(1), &mut stream, true);
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
    let mut stream = FakeStream::default();

    downloads.poll(at(0), &mut stream, true);
    recorder.deliver(&vec![1_u8; 300], 4096);
    downloads.poll(at(1), &mut stream, true);
    assert!(downloads.waiting().is_some());

    // A pass before the relay has said the shipment went reads nothing more:
    // there is one shipment buffer, and a second read over it would drop the
    // first.
    downloads.poll(at(2), &mut stream, true);
    assert!(recorder.quiet(), "a second read over a held one");

    downloads.shipped();
    assert!(downloads.waiting().is_none());
    downloads.poll(at(3), &mut stream, true);
    assert_eq!(
        recorder
            .taken()
            .map(|(_, recording, position, _)| (recording, position)),
        Some((DownloadSink::Capture, 0)),
        "the other ring is next, and its own cursor has not moved"
    );

    // And back to the ring that shipped, whose cursor moved by exactly what
    // went.
    downloads.poll(at(4), &mut stream, true);
    downloads.poll(at(5), &mut stream, true);
    assert_eq!(
        recorder
            .taken()
            .map(|(_, recording, position, _)| (recording, position)),
        Some((DownloadSink::Log, 300))
    );
}

#[test]
fn a_download_takes_the_window_and_the_ring_cursor_waits_for_it() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        pending: Some(LOG_TARGET),
        ..FakeStream::default()
    };

    // An operator's `GET` and a channel that would ship, on the same pass.
    downloads.poll(at(0), &mut stream, true);
    let body = vec![9_u8; 64];
    assert_eq!(
        recorder.deliver(&body, 64),
        (DownloadReader::Snapshot, DownloadSink::Log, 0),
        "the ring cursor took the window from a download"
    );

    downloads.poll(at(1), &mut stream, true);
    assert_eq!(stream.supplied.len(), 1);
    assert!(
        downloads.waiting().is_none(),
        "nothing was read for the channel while a download held the window"
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
    stream: &mut FakeStream,
    wanted: DownloadSink,
) -> Option<u64> {
    for step in 1..=8 {
        downloads.poll(at(RING_HOLDOFF.as_nanos() * step), stream, true);
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
    let mut stream = FakeStream::default();

    // The first thing every cursor asks for is position zero, and a recorder
    // that resumed a medium serves nothing before the segment this boot opened.
    const BEGINS: u64 = 4 << 20;
    downloads.poll(at(0), &mut stream, true);
    let outrun = recorder.refuse(DownloadRefusal::Overrun, BEGINS + 512, BEGINS);
    downloads.poll(at(1), &mut stream, true);

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
    let asked_again = asked_for(&mut downloads, &mut recorder, &mut stream, outrun);
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
    let mut stream = FakeStream::default();

    // A recorder answering an overrun with a position that is not past the one
    // it refused is a peer this reader cannot act on: taking it would have the
    // channel ship the same bytes forever.
    downloads.poll(at(0), &mut stream, true);
    let outrun = recorder.refuse(DownloadRefusal::Overrun, 512, 0);
    downloads.poll(at(1), &mut stream, true);
    assert_eq!(
        downloads.take_shipped(),
        None,
        "a resume point that does not advance was acted on"
    );

    let asked_again = asked_for(&mut downloads, &mut recorder, &mut stream, outrun);
    assert_eq!(asked_again, Some(0), "the cursor moved on a peer's say-so");
}

#[test]
fn a_caught_up_ring_is_left_alone_rather_than_asked_on_every_wakeup() {
    let channel = Channel::new();
    let mut recorder = Recorder::new(&channel);
    let mut downloads = channel.downloads();
    let mut stream = FakeStream::default();

    // Both rings answer empty, which is what a cursor level with the medium
    // gets.
    for step in 0..2 {
        downloads.poll(at(step), &mut stream, true);
        recorder.deliver(&[], 0);
    }
    downloads.poll(at(2), &mut stream, true);
    assert!(
        recorder.quiet(),
        "a caught-up reader asked again inside its hold-off"
    );

    // And it comes back once the hold-off is out.
    downloads.poll(at(RING_HOLDOFF.as_nanos() * 2), &mut stream, true);
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
    let mut stream = FakeStream::default();
    let mut seen = Vec::new();
    // A pass per hold-off, because every answer this recorder gives is a
    // refusal and a refused ring is left alone for one: a reader that came
    // straight back would be asking a recorder that has just said no at
    // whatever rate the port is woken.
    for step in 1..=4 {
        downloads.poll(at(RING_HOLDOFF.as_nanos() * step), &mut stream, true);
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
    let mut stream = FakeStream::default();

    let mut positions = Vec::new();
    for step in 0..4_u64 {
        let now = at(SHIPPING_REPORT_PERIOD.as_nanos() * step);
        downloads.poll(now, &mut stream, true);
        recorder.deliver(&vec![7_u8; 512], 4096);
        downloads.poll(now, &mut stream, true);
        downloads.shipped();
        downloads.poll(now, &mut stream, true);
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
    let mut stream = FakeStream::default();

    // A shipment read and never shipped: the relay has room for nothing, or the
    // far end never answers. The reader has bytes in hand and a durable end well
    // past its cursor, and its cursor does not move.
    downloads.poll(at(0), &mut stream, true);
    recorder.deliver(&vec![3_u8; 512], 1 << 20);
    downloads.poll(at(1), &mut stream, true);
    assert!(downloads.waiting().is_some());
    while downloads.take_shipped().is_some() {}

    let overdue = SHIPPING_STALL_WINDOW.as_nanos() * 2;
    downloads.poll(at(overdue), &mut stream, true);
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
    downloads.poll(at(overdue * 2), &mut stream, true);
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
    let mut stream = FakeStream::default();

    downloads.poll(at(0), &mut stream, true);
    recorder.deliver(&vec![3_u8; 512], 1 << 20);
    downloads.poll(at(1), &mut stream, false);
    downloads.poll(at(SHIPPING_STALL_WINDOW.as_nanos() * 4), &mut stream, false);
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
    let mut stream = FakeStream::default();

    downloads.poll(at(0), &mut stream, true);
    recorder.deliver(&vec![5_u8; 512], 4_096);
    downloads.poll(at(1), &mut stream, true);
    downloads.shipped();
    downloads.poll(at(2), &mut stream, true);
    assert!(
        core::iter::from_fn(|| downloads.take_shipped())
            .all(|shipped| !matches!(shipped, Shipped::Shipping { .. })),
        "the channel said where it stood with one recording still unasked"
    );

    // And once the other has answered, it says so — for both.
    recorder.deliver(&[], 0);
    downloads.poll(at(SHIPPING_REPORT_PERIOD.as_nanos()), &mut stream, true);
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
