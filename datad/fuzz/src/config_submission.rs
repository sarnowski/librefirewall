//! The whole submission path, from the bytes a client `POST`s to the generation
//! the appliance commits: the HTTP body the management server accumulates, the
//! region it crosses, the copy the deciding domain takes out of it, and the
//! answer that comes back.
//!
//! # The adversary and the surface
//!
//! The **management-plane attacker**, and this is the longest reach that party
//! has into the appliance. Every byte of the input is theirs, and it is used
//! twice over: as the body of a request the server frames and accumulates, and as
//! the document the deciding domain reads. So a single corpus entry is a
//! configuration document, which makes any real document a usable seed — and a
//! malformed one just as usable.
//!
//! Behind the requester sits the **byzantine neighbour protection domain** in
//! both directions: this harness drives the real channel handles rather than
//! calling the reader directly, so the length word, the operation word and the
//! sequence number are all crossed exactly as they are on an appliance.
//!
//! # What is asserted, beyond not crashing
//!
//! * **The bytes that were submitted are the bytes that were decided on.** The
//!   copy the deciding side takes out of the region equals the prefix of the input
//!   the server accepted — so a length word, a truncation, or an off-by-one in
//!   either direction of the channel fails here rather than committing a document
//!   nobody sent.
//! * **A refused document changes nothing.** The running generation and the model
//!   in force after a refusal are the ones from before it, every time. This is the
//!   fail-closed property the whole feature rests on.
//! * **An applied document is the one that was submitted.** The generation
//!   advances by exactly one and the model in force is the one the submitted bytes
//!   parse to.
//! * **Every answer is renderable.** The status is from the closed set, the line
//!   the management side composes is inside its bound and carries only bytes a
//!   console line may, and a refusal names a reason from the vocabulary.
//! * **The declared length is honoured.** A `Content-Length` naming fewer bytes
//!   than arrive submits only the ones declared; one naming more submits nothing at
//!   all, because a body that never completed is not a submission.
//! * **The other listening port is not a way in.** The appliance answers on two
//!   ports and only one of them carries the configuration surface, so the same
//!   document is also pushed at the **onboarding** port — where it must reach
//!   the byte stream and never the submission path. A harness that could only
//!   address the port that serves HTTP would model an attacker who cannot try
//!   the other one, which is not the attacker there is.
//! * **Nothing is unbounded.** The document that crosses is at most
//!   [`MAX_DOCUMENT_BYTES`], the answer at most `MAX_ANSWER_LEN`, and the number
//!   of commits at most the number of submissions.

use std::boxed::Box;
use std::vec::Vec;

use arbitrary::Unstructured;
use config::{CommitReport, Datastore, Generation, MAX_DOCUMENT_BYTES};
use lfw_clock::{Calibration, Monotonic, Ticks};
use lfw_ip_endpoint::{
    ConnectionId, Flags, IsnSecret, MANAGEMENT_PORT, Outgoing, SeqNumber, Status, TCP_MSS,
    http::Server,
};
use lfw_log::{RejectReason, Sink};
use net_headers::Ipv4Address;
use pd_runtime::{Configurations, MAX_ANSWER_LEN, Submissions};
use std::num::NonZeroU64;
use wire::{
    ConfigAnswer, ConfigOperation, ConfigReply, ConfigRequest, ConfigResponder, ConfigStatus,
};

use crate::{any_index, any_u16};

/// The management port's own addressing, as `systems/qemu-x86_64/configuration.xml`
/// gives it, and the station that submits to it.
const APPLIANCE: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 15]);
const STATION: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 2]);

/// The per-boot secret. Fixed, this harness being about the document rather than
/// about the transport's own surface, which is [`crate::tcp`]'s.
const SECRET: [u8; 16] = [0x3c; 16];

/// Statuses the management half can answer a submission with. A closed list
/// rather than `Status::ALL`, because the point is that a *submission* reaches
/// exactly these three and never, say, a `404`.
const SUBMISSION_STATUSES: [Status; 3] =
    [Status::Ok, Status::BadRequest, Status::ServiceUnavailable];

/// Documents one input may submit in a row, bounding the harness's own work. Not
/// a bound on the adversary: a longer run adds nothing this does not already
/// reach, one document per pass being what the channel admits at a time.
const MAX_SUBMISSIONS: usize = 4;

pub fn config_submission_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let submissions = any_index(&mut unstructured, MAX_SUBMISSIONS) + 1;
    // How each document's declared length differs from what is sent, so the two
    // fail-closed cases — a peer that sends more than it announced and one that
    // sends less — are reachable rather than modelled away.
    let skews: Vec<i32> = (0..submissions)
        .map(|_| i32::from(any_u16(&mut unstructured) as i16) / 4096)
        .collect();
    let stream = unstructured.take_rest();
    // The stream cut into that many documents. Cheap and arbitrary: a document is
    // a byte string and any split of the input is a set of them.
    let each = stream.len().div_ceil(submissions.max(1)).max(1);

    let channel = Channel::new();
    let mut management = channel.requester();
    let mut deciding = channel.responder();
    let mut store = Datastore::new();
    let mut scratch = Box::new([0u8; MAX_DOCUMENT_BYTES]);

    for (index, chunk) in stream.chunks(each).take(submissions).enumerate() {
        let skew = skews.get(index).copied().unwrap_or(0);
        assert_one_submission(
            &mut management,
            &mut deciding,
            &mut store,
            &mut scratch,
            chunk,
            skew,
        );
        assert_the_onboarding_port_submits_nothing(chunk);
    }
}

/// The same bytes at the appliance's **other** listening port, which must reach
/// the onboarding byte stream and nothing else.
///
/// It is the one claim a harness driving the HTTP server alone cannot make: the
/// configuration surface is a target on one port, and a document pushed at the
/// other must be ciphertext going to a domain that will not parse it rather
/// than a submission going to one that will.
fn assert_the_onboarding_port_submits_nothing(document: &[u8]) {
    let mut endpoint = lfw_ip_endpoint::Endpoint::new(
        net_headers::MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x52]),
        APPLIANCE,
        24,
        None,
        IsnSecret::from_bytes(SECRET),
    )
    .expect("a unicast pair on a /24");
    // The surface really is registered, so a submission that appeared would be
    // one this endpoint could have taken rather than one it had no target for.
    assert!(endpoint.serve_body_at(pd_runtime::CONFIG_TARGET));
    let now = instant();
    let mut out = vec![0u8; 2048];
    let mut sequence = 0x4000u32;
    let mut frames = Vec::new();
    frames.push(onboarding_frame(&mut sequence, Flags::SYN, &[]));
    for chunk in document.chunks(1024).take(4) {
        frames.push(onboarding_frame(
            &mut sequence,
            Flags::ACK.with(Flags::PSH),
            chunk,
        ));
    }
    for frame in &frames {
        endpoint.handle(Some(now), frame, &mut out);
        assert!(
            endpoint.submission_wanted().is_none(),
            "a document pushed at the onboarding port reached the configuration surface"
        );
        assert!(endpoint.submission().is_none());
    }
    // And what it did reach is the stream, bounded by the stream's own array
    // whatever the peer sent.
    assert!(endpoint.stream().received().len() <= lfw_ip_endpoint::onboard::INBOUND_CAPACITY);
    assert_eq!(endpoint.counters().tcp_segments, 0);
}

/// One frame from the station to the onboarding port, sequenced so a run of
/// them is a stream rather than a repeat.
fn onboarding_frame(sequence: &mut u32, flags: Flags, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; 2048];
    let len = Outgoing {
        source_port: 40001,
        destination_port: lfw_ip_endpoint::onboard::ONBOARDING_PORT,
        sequence: SeqNumber::new(*sequence),
        acknowledgement: SeqNumber::new(0),
        flags,
        window: 4096,
        mss: flags.contains(Flags::SYN).then_some(1460),
        window_scale: None,
        payload,
    }
    .write(
        STATION,
        APPLIANCE,
        frame
            .get_mut(net_headers::Ipv4Frame::PAYLOAD_AT..)
            .expect("room for a segment"),
    )
    .expect("room for a segment");
    let total = net_headers::Ipv4Frame {
        destination_mac: net_headers::MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x52]),
        source_mac: net_headers::MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0c]),
        source: STATION,
        destination: APPLIANCE,
        protocol: net_headers::Protocol::TCP,
    }
    .write(&mut frame, len)
    .expect("room for a frame");
    frame.truncate(total);
    // Lossless: a payload here is a chunk of at most a kilobyte.
    *sequence = sequence
        .wrapping_add(payload.len() as u32)
        .wrapping_add(u32::from(flags.contains(Flags::SYN)));
    frame
}

/// One document submitted, decided and answered, with every claim above held.
fn assert_one_submission(
    management: &mut Configurations<'_>,
    deciding: &mut ConfigResponder<'_>,
    store: &mut Datastore,
    scratch: &mut [u8; MAX_DOCUMENT_BYTES],
    document: &[u8],
    skew: i32,
) {
    // The HTTP half: a real head, a real accumulation, and the declared length
    // moved off what is actually sent by `skew` — which is exactly the authority a
    // client has over the framing.
    let declared = declared_length(document.len(), skew);
    let mut endpoint = Endpoint::post(document, declared);
    let taken = endpoint.submission().map(<[u8]>::to_vec);

    // A body that never completed is not a submission, and a body longer than it
    // announced submits only what it announced. Both are the framing rule the
    // caller's accumulation rests on.
    match taken.as_deref() {
        None => {
            assert!(
                declared > document.len() || declared > MAX_DOCUMENT_BYTES,
                "a body of {} bytes declaring {declared} produced no submission",
                document.len()
            );
            return;
        }
        Some(body) => {
            assert_eq!(body.len(), declared.min(MAX_DOCUMENT_BYTES));
            assert_eq!(
                body,
                document.get(..body.len()).unwrap_or_default(),
                "the body accumulated is not a prefix of what was sent"
            );
        }
    }

    let before = store.running();
    let before_model = *store.running_model();

    assert!(
        management.poll(Some(instant()), &mut endpoint),
        "no request was issued"
    );
    let demand = deciding.take().expect("a submission was issued");
    assert_eq!(demand.operation(), Some(ConfigOperation::Submit));
    let crossed = deciding.document(&demand, scratch).to_vec();
    assert_eq!(
        crossed,
        taken.expect("a submission"),
        "the bytes decided on are not the bytes submitted"
    );

    // The deciding domain's own step, exactly as `pds/config` performs it.
    let sink = Discard;
    let report = config::commit_and_report(store, &crossed, &sink);
    let answer = answer_of(report, store.running());
    deciding.answer(demand, answer);
    management.poll(Some(instant()), &mut endpoint);

    assert_report(report, store, before, &before_model, &crossed);
    assert_answer(&endpoint, answer, store.running());
}

/// What the deciding domain answers, on `pds/config`'s terms.
fn answer_of(report: CommitReport, running: Generation) -> ConfigAnswer {
    match report {
        CommitReport::Published { image, changes } => ConfigAnswer::Applied {
            generation: image.generation,
            changes,
        },
        CommitReport::Unchanged => ConfigAnswer::Unchanged {
            generation: running.to_bits(),
        },
        CommitReport::Rejected { reason, detail } => ConfigAnswer::Rejected {
            generation: running.to_bits(),
            reason: reason as u32,
            detail,
        },
        CommitReport::Exhausted => ConfigAnswer::Exhausted {
            generation: running.to_bits(),
        },
        CommitReport::NoCandidate => ConfigAnswer::NoCandidate {
            generation: running.to_bits(),
        },
    }
}

/// The fail-closed property, and the applied one beside it.
fn assert_report(
    report: CommitReport,
    store: &Datastore,
    before: Generation,
    before_model: &config::Model,
    document: &[u8],
) {
    match report {
        CommitReport::Published { image, changes } => {
            assert!(
                store.running() > before,
                "an applied document did not move the generation"
            );
            assert_eq!(image.generation, store.running().to_bits());
            assert!(changes > 0, "an applied generation moved nothing");
            let parsed = config::load(document).expect("it committed, so it reads");
            assert!(
                store.running_model().has_same_content(&parsed),
                "the configuration in force is not the document that was submitted"
            );
            // And the image the consumer is handed is one it will take: the
            // doubled validation is what makes a compromise of this domain
            // survivable, so a published image that failed the consumer's own
            // check would be the whole point defeated.
            assert!(
                image.check(config::PORT_COUNT).is_ok(),
                "a published image the consumer would refuse"
            );
            // And it is sealed, which is the half of that check no field of the
            // document can reach: the consumer refuses an image whose bytes do
            // not fold to the digest it carries, so a commit path that published
            // an unsealed image would reach the dataplane as a refusal on every
            // generation rather than as a defect anything else here can see.
            assert_eq!(
                image.digest,
                image.computed_digest(),
                "a published image was not sealed"
            );
        }
        CommitReport::Unchanged => {
            assert_eq!(store.running(), before);
            assert!(store.running_model().has_same_content(before_model));
        }
        CommitReport::Rejected { reason, .. } => {
            assert_eq!(
                store.running(),
                before,
                "a refused document moved the generation"
            );
            assert_eq!(
                store.running_model(),
                before_model,
                "a refused document changed the configuration in force"
            );
            assert!(RejectReason::ALL.contains(&reason));
            assert!(
                config::load(document).is_err(),
                "a document that reads was refused"
            );
        }
        // Unreachable from a fresh store: it takes 2^32 commits to spend the
        // counter. Asserted rather than ignored, so a store that reached it for
        // another reason is a finding.
        CommitReport::Exhausted => {
            assert_eq!(store.running(), Generation::from_bits(u32::MAX));
        }
        // Unreachable through the one-step path, which stages the document it is
        // given before committing it. Asserted rather than ignored, on
        // `Exhausted`'s terms.
        CommitReport::NoCandidate => {
            unreachable!("a submission stages before it commits");
        }
    }
}

/// Every answer the management half composes is one a client can be sent.
fn assert_answer(endpoint: &Endpoint, answer: ConfigAnswer, running: Generation) {
    let (status, line) = endpoint
        .answered
        .last()
        .expect("the submission was answered");
    assert!(
        SUBMISSION_STATUSES.contains(status),
        "a submission was answered {status:?}"
    );
    assert!(line.len() <= MAX_ANSWER_LEN, "the answer overran its bound");
    assert_eq!(line.last(), Some(&b'\n'));
    assert!(
        line.iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ' || *byte == b'\n'),
        "the answer carries a byte a console line could not"
    );
    let text = core::str::from_utf8(line).expect("the grammar is ASCII");
    assert!(text.starts_with("generation="));
    // The generation the client is told is the one that is running, whichever way
    // the submission went: a number that named anything else would have an
    // operator confirm a change against the wrong series.
    let expected = match answer {
        ConfigAnswer::Applied { generation, .. } => generation,
        _ => running.to_bits(),
    };
    assert!(
        text.contains(&std::format!("generation={expected} ")),
        "{text:?} does not name generation {expected}"
    );
    match answer {
        ConfigAnswer::Applied { .. } => assert!(text.contains(" outcome=applied ")),
        ConfigAnswer::Unchanged { .. } => assert!(text.contains(" outcome=unchanged ")),
        ConfigAnswer::Rejected { .. } | ConfigAnswer::Exhausted { .. } => {
            assert!(text.contains(" outcome=refused"));
        }
        // Every answer only the management channel's stepped path produces, and
        // the word an undecodable operation is answered with. This harness asks
        // one operation, and `assert_report` above has already refused a report
        // that could have produced any of them.
        ConfigAnswer::Staged { .. }
        | ConfigAnswer::Confirmed { .. }
        | ConfigAnswer::RolledBack { .. }
        | ConfigAnswer::NoCandidate { .. }
        | ConfigAnswer::NotProvisional { .. }
        | ConfigAnswer::GenerationMismatch { .. }
        | ConfigAnswer::NoSuchOperation => unreachable!("this harness asks one operation"),
    }
}

/// What a client declares, moved off what it sends so both fail-closed cases are
/// reachable: a length above what arrives never completes, and one below it
/// submits the prefix.
fn declared_length(sent: usize, skew: i32) -> usize {
    let declared = i64::from(skew).saturating_add(sent as i64);
    declared.clamp(0, MAX_DOCUMENT_BYTES as i64 + 1) as usize
}

/// The two regions one channel is, on the heap: 128 KiB does not belong on a
/// harness's stack, and libFuzzer's is the default one.
struct Channel {
    request: Box<ConfigRequest>,
    reply: Box<ConfigReply>,
}

impl Channel {
    fn new() -> Self {
        Self {
            request: Box::new(ConfigRequest::zero()),
            reply: Box::new(ConfigReply::zero()),
        }
    }

    fn requester(&self) -> Configurations<'_> {
        Configurations::attach(&self.request, &self.reply)
    }

    fn responder(&self) -> ConfigResponder<'_> {
        self.reply.responder(&self.request)
    }
}

/// The management server, driven the way a protection domain drives it: a real
/// `POST` head and a real accumulation, so the framing rules are the ones an
/// appliance applies rather than ones this harness restates.
struct Endpoint {
    server: Server<1>,
    answered: Vec<(Status, Vec<u8>)>,
}

impl Endpoint {
    /// Frame `body` as a `POST` declaring `declared` bytes and feed it in.
    ///
    /// The head goes in first and the body follows in pieces, which is what a TCP
    /// connection delivers: a body accumulated only when it arrived whole in one
    /// segment would be a body no real client sends.
    fn post(body: &[u8], declared: usize) -> Self {
        let mut server: Server<1> = Server::new();
        assert!(server.serve_body_at(pd_runtime::CONFIG_TARGET));
        assert!(server.serve_rendered_at(pd_runtime::CONFIG_TARGET));
        // A real connection handle, taken off a real transport: `ConnectionId` has
        // no constructor, and it has none deliberately — a slot index alone would
        // be a handle that addressed whatever connection took the slot over.
        let connection = open_connection();
        let head = std::format!(
            "POST {} HTTP/1.1\r\nHost: x\r\nContent-Length: {declared}\r\n\r\n",
            pd_runtime::CONFIG_TARGET
        );
        server.take(instant(), connection, head.as_bytes());
        for chunk in body.chunks(512.max(1)) {
            server.take(instant(), connection, chunk);
        }
        Self {
            server,
            answered: Vec::new(),
        }
    }
}

impl Submissions for Endpoint {
    fn document_wanted(&self) -> bool {
        false
    }

    fn submission(&self) -> Option<&[u8]> {
        self.server.submission()
    }

    fn supply_document(&mut self, _document: &[u8]) {
        unreachable!("this harness never asks for the running document");
    }

    fn answer_submission(&mut self, status: Status, answer: &[u8]) {
        self.answered.push((status, answer.to_vec()));
        self.server
            .supply(status, None, |out| copy_into(out, answer));
    }

    fn refuse(&mut self, status: Status) {
        self.answered.push((status, Vec::from(&b"\n"[..])));
        self.server
            .supply(status, None, |out| copy_into(out, b"\n"));
    }
}

/// Take one connection handle off a listening transport by shaking hands with it.
///
/// The server's own state is keyed by the handle, so a harness that could not
/// produce one could not reach the body path at all — and this is the shortest
/// honest way to one: the transport issues it, exactly as it does on an appliance.
/// The instant every pass in this target reads, built the way a domain builds one.
/// Fixed, and deliberately so: this target is about what an attacker's *bytes* can
/// do, and a deadline reached mid-exchange would answer a submission before the
/// deciding half ever saw it — testing the clock rather than the parser.
fn instant() -> Monotonic {
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(0))
}

fn open_connection() -> ConnectionId {
    let mut stack = lfw_tcp::TcpStack::<1>::new(
        APPLIANCE,
        MANAGEMENT_PORT,
        TCP_MSS,
        lfw_ip_endpoint::http::REQUEST_CAPACITY as u32,
        IsnSecret::from_bytes(SECRET),
    );
    let mut out = vec![0u8; 256];
    let now: Monotonic = instant();
    let mut syn = vec![0u8; 256];
    let len = Outgoing {
        source_port: 40000,
        destination_port: MANAGEMENT_PORT,
        sequence: SeqNumber::new(0x1000),
        acknowledgement: SeqNumber::new(0),
        flags: Flags::SYN,
        window: 4096,
        mss: Some(1460),
        window_scale: None,
        payload: &[],
    }
    .write(STATION, APPLIANCE, &mut syn)
    .expect("room for a bare segment");
    syn.truncate(len);
    stack
        .receive(now, STATION, &syn, &mut out)
        .connection
        .expect("a listening stack accepts a well-formed SYN")
}

fn copy_into(out: &mut [u8], bytes: &[u8]) -> Option<usize> {
    let target = out.get_mut(..bytes.len())?;
    target.copy_from_slice(bytes);
    Some(bytes.len())
}

/// A sink that keeps nothing: the console records a commit produces are
/// [`crate::log_record`]'s surface, and holding them here would bound this
/// harness by a record table rather than by a document.
struct Discard;

impl Sink for Discard {
    fn emit(&self, _event: &lfw_log::Event) {}
}

// The one status the harness above relies on being distinguishable: an answer's
// closed set must not have grown a value a submission can reach without this
// harness being told.
const _: () = assert!(SUBMISSION_STATUSES.len() == 3);
const _: () = assert!(ConfigStatus::Applied.to_bits() == 0);
