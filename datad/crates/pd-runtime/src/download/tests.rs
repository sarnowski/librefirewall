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
    responder.deliver(demand, body, total_len);
}

/// What the recorder was asked for, without answering it.
fn asked(channel: &Channel) -> Option<(DownloadSink, u64, usize)> {
    let mut responder = channel.responder();
    let demand = responder.take()?;
    let seen = (demand.sink()?, demand.offset(), demand.len());
    // Put the answer back so the demand is not silently swallowed: a test that
    // inspected and dropped one would leave the requester waiting forever,
    // which is the bug this whole channel is shaped to prevent.
    responder.refuse(demand, DownloadRefusal::NotReady, 0);
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

    downloads.poll(at(0), &mut stream);

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

    downloads.poll(at(0), &mut stream);
    let body = vec![0xAB; 128];
    answer(&channel, &body, 4096);
    downloads.poll(at(0), &mut stream);

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
    downloads.poll(at(0), &mut stream);
    answer(&channel, &[1u8; 64], 4096);
    downloads.poll(at(0), &mut stream);

    stream.wanted = Some((64, WINDOW_LEN));
    downloads.poll(at(0), &mut stream);
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
    downloads.poll(at(0), &mut stream);
    answer(&channel, &[1u8; 64], 4_096);
    downloads.poll(at(0), &mut stream);

    stream.wanted = Some((64, 300));
    downloads.poll(at(0), &mut stream);
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
    downloads.poll(at(0), &mut stream);
    answer(&channel, &[], 0);
    downloads.poll(at(0), &mut stream);

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
        downloads.poll(at(0), &mut stream);
        {
            let mut responder = channel.responder();
            let demand = responder.take().expect("a request is out");
            responder.refuse(demand, reason, 0);
        }
        downloads.poll(at(0), &mut stream);

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
    downloads.poll(at(0), &mut stream);
    answer(&channel, &[1u8; 16], 16);
    downloads.poll(at(0), &mut stream);

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
    downloads.poll(at(0), &mut stream);
    answer(&channel, &[1u8; 16], 4096);
    downloads.poll(at(0), &mut stream);

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
    downloads.poll(at(0), &mut stream);

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
        downloads.poll(at(0), &mut stream);
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
        downloads.poll(at(0), &mut stream);
    }
    let demand = responder.take().expect("one request is outstanding");
    responder.deliver(demand, &[1u8; 8], 64);
    assert!(
        responder.take().is_none(),
        "the sequence never moved while the first was unanswered"
    );
    downloads.poll(at(0), &mut stream);
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
        downloads.poll(at(0), &mut stream);
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
                responder.deliver(demand, &bytes, TOTAL);
            }
        }
        downloads.poll(at(0), &mut stream);
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

    downloads.poll(at(0), &mut stream);
    {
        // Taken and never answered, which is a recorder that has stopped.
        let mut responder = channel.responder();
        let demand = responder.take().expect("a request is outstanding");
        drop(demand);
    }

    let deadline = REPLY_TIMEOUT.as_nanos();
    downloads.poll(at(deadline - 1), &mut stream);
    assert_eq!(stream.abandoned, 0, "given up on early");

    downloads.poll(at(deadline), &mut stream);
    assert_eq!(stream.abandoned, 1, "the download was never given up on");
    assert_eq!(downloads.counters().abandoned, 1);

    // And the slot is free again, so the next `GET` of a recording is asked for
    // rather than being the one this domain never serves.
    stream.pending = Some(CAPTURE_TARGET);
    downloads.poll(at(deadline), &mut stream);
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

    downloads.poll(at(0), &mut stream);
    let stale = channel
        .responder()
        .take()
        .expect("a request is outstanding");
    let deadline = REPLY_TIMEOUT.as_nanos();
    downloads.poll(at(deadline), &mut stream);
    assert_eq!(stream.abandoned, 1);

    // A fresh download is outstanding by the time the recorder answers the old one.
    stream.pending = Some(CAPTURE_TARGET);
    downloads.poll(at(deadline), &mut stream);
    channel.responder().deliver(stale, b"stale bytes", 11);
    downloads.poll(at(deadline), &mut stream);
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

    downloads.poll(None, &mut stream);
    let _outstanding = channel
        .responder()
        .take()
        .expect("a request is outstanding");
    for _ in 0..4 {
        downloads.poll(None, &mut stream);
    }
    assert_eq!(stream.abandoned, 0);

    downloads.poll(at(REPLY_TIMEOUT.as_nanos() * 4), &mut stream);
    assert_eq!(
        stream.abandoned, 0,
        "a request parked unarmed was given up on"
    );
}
