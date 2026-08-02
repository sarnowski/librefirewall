use super::*;

use std::boxed::Box;
use std::{vec, vec::Vec};

use wire::{DownloadReply, DownloadRequest, DownloadResponder};

/// The endpoint as a download sees it, with every state a real transport can
/// present and two a hostile or broken one can.
#[derive(Default)]
struct FakeStream {
    pending: Option<&'static str>,
    wanted: Option<u64>,
    begun: Option<(u64, Vec<u8>)>,
    supplied: Vec<(u64, Vec<u8>)>,
    abandoned: usize,
    /// Refuse the next `begin_stream`.
    refuse_begin: bool,
    /// Refuse the next `supply_window`.
    refuse_window: bool,
    /// The counters the last pass handed over for the domain's shard.
    noted: Option<DownloadCounters>,
}

impl Stream for FakeStream {
    fn pending_stream(&self) -> Option<&'static str> {
        self.pending
    }

    fn begin_stream(&mut self, total: u64, content_type: &str) -> bool {
        if self.refuse_begin {
            self.refuse_begin = false;
            return false;
        }
        self.pending = None;
        self.begun = Some((total, content_type.as_bytes().to_vec()));
        true
    }

    fn stream_wanted(&self) -> Option<u64> {
        self.wanted
    }

    fn supply_window(&mut self, start: u64, bytes: &[u8]) -> bool {
        if self.refuse_window {
            self.refuse_window = false;
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

    downloads.poll(&mut stream);

    assert_eq!(
        asked(&channel),
        Some((DownloadSink::Capture, 0, DOWNLOAD_WINDOW_LEN))
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

    downloads.poll(&mut stream);
    let body = vec![0xAB; 128];
    answer(&channel, &body, 4096);
    downloads.poll(&mut stream);

    let (total, content_type) = stream.begun.clone().expect("the stream was begun");
    assert_eq!(total, 4096);
    assert_eq!(content_type, b"application/octet-stream");
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
    downloads.poll(&mut stream);
    answer(&channel, &[1u8; 64], 4096);
    downloads.poll(&mut stream);

    stream.wanted = Some(64);
    downloads.poll(&mut stream);
    assert_eq!(
        asked(&channel),
        Some((DownloadSink::Log, 64, DOWNLOAD_WINDOW_LEN)),
        "the same recording, at the offset the transport is waiting on"
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
    downloads.poll(&mut stream);
    answer(&channel, &[], 0);
    downloads.poll(&mut stream);

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
        downloads.poll(&mut stream);
        {
            let mut responder = channel.responder();
            let demand = responder.take().expect("a request is out");
            responder.refuse(demand, reason, 0);
        }
        downloads.poll(&mut stream);

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
    downloads.poll(&mut stream);
    answer(&channel, &[1u8; 16], 16);
    downloads.poll(&mut stream);

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
    downloads.poll(&mut stream);
    answer(&channel, &[1u8; 16], 4096);
    downloads.poll(&mut stream);

    assert_eq!(stream.abandoned, 1);
    assert!(stream.supplied.is_empty());
}

#[test]
fn a_window_wanted_for_a_stream_this_domain_never_began_is_ended() {
    let channel = Channel::new();
    let mut downloads = channel.downloads();
    let mut stream = FakeStream {
        wanted: Some(512),
        ..FakeStream::default()
    };
    downloads.poll(&mut stream);

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
        downloads.poll(&mut stream);
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
        downloads.poll(&mut stream);
    }
    let demand = responder.take().expect("one request is outstanding");
    responder.deliver(demand, &[1u8; 8], 64);
    assert!(
        responder.take().is_none(),
        "the sequence never moved while the first was unanswered"
    );
    downloads.poll(&mut stream);
    assert_eq!(stream.supplied.len(), 1);
    assert!(
        responder.take().is_none(),
        "and nothing more is asked until the transport wants a window"
    );
}
