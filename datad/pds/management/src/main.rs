#![no_main]
#![no_std]

//! Management protection domain: the addressed endpoint of the dedicated
//! management port. It takes every frame that port receives off the pipeline,
//! answers the ones addressed to it — ARP requests for its own address, ICMP echo
//! requests to it, and TCP connections to its one listening port — and reports
//! what the port has received.
//!
//! # Adversary
//!
//! The **management-plane attacker**, reached through a **byzantine
//! neighbour PD**. Whatever is attached to the management port is the first, and
//! this is now the domain that *answers* it: a reply is a frame the appliance
//! originates because of something that party sent. Nothing it sends arrives
//! here directly — the driver instance that owns the port publishes a
//! descriptor, so every buffer index, span and verdict word read here is that
//! domain's choice. Both are answered in `pd_runtime::endpoint` and
//! `lfw_ip_endpoint`, where host tests drive them; this file maps regions and
//! calls functions.
//!
//! # The port carries no forwarded traffic, and that is a grant
//!
//! The design isolates the management port from the dataplane. This domain
//! holds no dataplane region, no device capability and no I/O port, and the
//! forwarder holds no management region — the mutual exclusion is stated in
//! `systems/qemu-x86_64/librefirewall.system` and checked in both directions by
//! `xtask::sysdesc`'s per-mapper grant set. What it does hold is both of the
//! management port's own pipelines, because answering needs a frame to leave as
//! well as arrive.
//!
//! # Why this domain returns buffers and owns the reply pool
//!
//! A terminal port has no egress driver to return a buffer, so this domain
//! produces the returns itself on the receive pipeline and is granted
//! `mgmt_rx_free` read-write; and a reply is a frame it originates, so it owns
//! the transmit pool and reclaims what the driver hands back. It is not the owner
//! of the receive pool: the driver is, and it alone decides whether a returned
//! index is one it lent.
//!
//! # It reads the configuration and acknowledges nothing
//!
//! The addressing comes from the configuration document, so this
//! domain maps `cfg` READ-ONLY and `cfgack` **not at all**. That asymmetry with
//! the forwarder is the point: the forwarder is the *consumer* of the two-phase
//! commit — it reads the offered generation, stages a table and acknowledges,
//! which is what a commit waits for — while this domain reads the **committed**
//! generation only. It cannot delay a commit, cannot refuse one on anybody's
//! behalf, and cannot forge the acknowledgement that releases one.
//! `pd_runtime::CommittedReader` is that weaker role, and it holds the whole of
//! it.
//!
//! What that costs is smaller than it was and is still real. This domain now holds
//! a channel to the configuration domain — it has to, being the only party that
//! knows a submitted document has arrived — but the channel carries *submissions*
//! and not the commit protocol: this domain still reads the committed generation
//! from `cfg` and takes no part in releasing one. So a commit somebody else
//! provoked still reaches it only when something wakes it.
//!
//! # It is woken by frames and by the passage of time
//!
//! Every deadline this domain holds — a retransmission, a reaping, and one day a
//! reconnection backoff and an acknowledgement cadence — is judged on a pass, and
//! a pass happens when this domain is woken. A silent link produces no frame, so
//! until the clock domain gained a timer those deadlines could not be reached at
//! all on the one condition they exist for. That domain now signals this one on a
//! period. **The signal carries nothing and is not distinguished from any other
//! wakeup**: a pass asks its questions of the regions rather than of whatever
//! woke it, and a tick that carried an instant would be a second source of the
//! one fact `RDTSC` and the calibration already answer.
//!
//! # Two instructions, and why they are here rather than in a crate
//!
//! Reading a counter and drawing a random number are capabilities, not logic:
//! neither can be exercised by a host test. So both live here, each in one
//! `unsafe` block naming what guarantees it, and everything done *with* the
//! numbers is in a crate.
//!
//! * **`RDTSC`**, once per wakeup. It is what makes a `Monotonic` out of the
//!   calibration this domain reads, and every transport timer is stated against
//!   one. There is no IPC for a timestamp: a reading costs one instruction, and
//!   asking another domain for one would cost a round trip on the path of every
//!   frame. The clock domain's tick says that time has passed and deliberately
//!   says nothing about *what* time it is, for that reason.
//! * **`RDRAND`**, once at start-up, for the secret the transport's initial
//!   sequence numbers are derived from (`entropy`). A predictable sequence number
//!   is an off-path injection primitive against the very attacker this port
//!   faces, so a part with no `RDRAND` — or one whose generator will not answer —
//!   refuses this domain rather than being answered with a weak secret.
//!
//! # It reads the clock and cannot set it
//!
//! The calibration region is mapped READ-ONLY, on the same footing as `cfg`. One
//! that could write it would be able to move this node's own idea of time —
//! every retransmission and reaping deadline, and one day every certificate's
//! validity window — from the domain that answers the
//! management-plane attacker. Every number in it is judged rather than believed
//! (`pd_runtime::calibration_from`), the clock domain having measured them
//! against a device; a triple this domain refuses leaves the port answering ARP
//! and ICMP and refusing TCP.
//!
//! # It answers `GET /metrics`, and it reads seven other domains to do it
//!
//! It maps **eight** stats shards: its own read-write, and one per other
//! protection domain READ-ONLY. That asymmetry is the whole argument — every
//! number it renders is a claim only the domain that made it could have written,
//! so a compromise of the domain that faces the management-plane attacker cannot
//! forge a clean line for a port that is dropping every frame. What stays
//! withheld is in `systems/qemu-x86_64/librefirewall.system` beside those rows.
//! Its own shard is the one region in this system with exactly one mapper, so
//! the renderer walks one uniform array rather than seven regions plus a live
//! read of its own counters.
//!
//! # Deviation from the design: the endpoint is plain HTTP, and it now takes writes
//!
//! The design requires the management API to carry encryption, authentication and
//! read/write authorization through an mTLS certificate pair. **None of it exists.**
//! There is no TLS in this appliance and this domain authenticates nobody, so
//! **anything that can reach the management port can read every metric this node
//! exposes, download every packet it has recorded, read its configuration, and
//! replace that configuration** — which is to say, decide what this firewall
//! forwards. The port must not be exposed to an untrusted network until the
//! required TLS termination and certificate handling exist. `GET /logs` is still
//! absent and answers 404 rather than being stubbed.
//!
//! # It carries an onboarding session's ciphertext and decides nothing about it
//!
//! The port answers on a second listening port, and what arrives there is not a
//! protocol this domain speaks. Every byte of it is moved into a region the
//! cryptography domain reads, and every byte that comes back is put on the
//! wire unread: TLS terminates where the keys are, and the keys are not here.
//! **This domain holds no key, no session secret and no plaintext**, and the
//! relay's ABI has no field for one in either direction — see
//! `pd_runtime::relay`, which is where the bounds on that handover live.
//!
//! What it costs is the second send capability named below, and what that buys
//! whoever reaches this domain is a wakeup on a domain holding no device, no
//! pool and no dataplane ring.
//!
//! # It carries a document and decides nothing about it
//!
//! A submitted document is copied into a region the configuration domain reads and
//! is never parsed here: that domain holds no frame buffer and this one holds two
//! pipelines, which is the whole of why the split exists. What comes back is a
//! status from a closed set and a byte range this domain hands to the transport
//! unread (`pd_runtime::configuration`).
//!
//! # What a console record says, and why not one per frame
//!
//! The console carries system state and never traffic, so nothing here
//! reports a frame. What it reports is the port's running total, on any pass
//! that moved at least one: "this port is receiving", which is a fact about the
//! node. Every count now also reaches `/metrics`, where the rest of what this
//! domain knows about itself lives.

mod entropy;

use entropy::EntropyError;
use lfw_clock::Monotonic;
use lfw_log::{
    DialOutcome, Domain, DomainDetail, DomainState, Event, NextHopVia, Refusal, RefusalDetail,
    RingSink, Sink,
};
use lfw_metrics::StatsShard;
use pd_runtime::{
    CalibrationRefused, ClockCalibration, ConfigHandover, ConfigReply, ConfigRequest,
    Configurations, DIAL_REQUEST_CAPACITY, DialFacts, Downloads, Ended, EndpointRegions,
    EndpointStage, ForwardRings, Ipv4Address, IsnSecret, ONBOARD_OUTBOUND_CAPACITY,
    OnboardCounters, OpenError, PdClock, Pool, RELAY_ANSWER_TIMEOUT, Relay, RelayFailure,
    RelayReport, Resolutions, ReturnRing, StatsRegions, Via, attach_region, log_sample,
    read_timestamp_counter,
};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, protection_domain};
use wire::{
    DownloadReply, DownloadRequest, LogConsume, LogRecords, ManagementEndpoint, RelayFault,
    RelayRefusal, RelayReply, RelayRequest,
};

/// How many dataplane ports the build has, and so the bound a committed image's
/// interface entries are checked against — the same build fact `pds/forwarder`
/// states. The management port is not among them, which is why this is 2 and not
/// 3: a document cannot put this port in the router's set.
///
/// A literal rather than `config::PORT_COUNT`, deliberately: linking that crate
/// would put an XML parser inside the domain that faces the management-plane
/// attacker, and this domain has no document to read.
const PORTS: u8 = 2;

/// The configuration domain, and one of the **two** send capabilities this domain
/// holds in this system. It blocks in the Microkit event loop and never polls, so
/// a document written into the submission region is invisible to it until it is
/// woken.
const CONFIG: Channel = Channel::new(2);

/// The cryptography domain, and the other one. It is woken for the same reason
/// and it is the same shape of reason: that domain blocks in the event loop, so
/// a record written into the relay's request region is invisible to it until it
/// is woken. What the capability is worth to whoever reaches this domain is a
/// wakeup at their chosen rate on a domain holding no device, no pool and no
/// dataplane ring — and one bounded answer per wakeup, which is what the other
/// end of that channel is built to give.
const CRYPTO: Channel = Channel::new(3);

/// What this domain calls each way an onboarding session can fail, one token per
/// cause.
///
/// **One arm per cause and no arm covering two**, which is the whole obligation
/// this function carries: a deployed node has no shell, so a token that folded
/// two causes together would send an operator to one of two domains with no way
/// to tell which. The refusals name the terminating domain's own judgement, the
/// faults name a reply this end could not believe, and the last three name this
/// appliance's own bounds.
fn relay_refusal(failure: RelayFailure) -> Refusal {
    // `signalled` is false throughout: no device was told to stop, because none
    // was told anything. What ends is a TCP connection and a session on it.
    let (cause, detail) = match failure {
        RelayFailure::Refused(RelayRefusal::NoConnection) => {
            ("relay-refused-no-connection", RefusalDetail::None)
        }
        RelayFailure::Refused(RelayRefusal::PayloadTooLong) => {
            ("relay-refused-payload-too-long", RefusalDetail::None)
        }
        RelayFailure::Refused(RelayRefusal::NoSuchOperation) => {
            ("relay-refused-no-such-operation", RefusalDetail::None)
        }
        RelayFailure::Refused(RelayRefusal::SessionFailed) => {
            ("relay-refused-session-failed", RefusalDetail::None)
        }
        RelayFailure::Faulted(RelayFault::StatusUnknown { status }) => (
            "relay-status-unknown",
            RefusalDetail::One(u64::from(status)),
        ),
        RelayFailure::Faulted(RelayFault::OperationUnknown { operation }) => (
            "relay-operation-unknown",
            RefusalDetail::One(u64::from(operation)),
        ),
        RelayFailure::Faulted(RelayFault::WrongOperation { asked, answered }) => (
            "relay-wrong-operation",
            RefusalDetail::Two(u64::from(asked.to_bits()), u64::from(answered.to_bits())),
        ),
        RelayFailure::Faulted(RelayFault::LenPastPayload { len }) => {
            ("relay-len-past-payload", RefusalDetail::One(u64::from(len)))
        }
        RelayFailure::Faulted(RelayFault::BytesOnRefusal { status, len }) => (
            "relay-bytes-on-refusal",
            RefusalDetail::Two(u64::from(status.to_bits()), u64::from(len)),
        ),
        RelayFailure::Faulted(RelayFault::ClosedUnknown { closed }) => (
            "relay-closed-unknown",
            RefusalDetail::One(u64::from(closed)),
        ),
        // The bound that was spent, in milliseconds, because the token alone
        // says a far end went quiet and not how long this end waited.
        RelayFailure::Unanswered => (
            "relay-unanswered",
            RefusalDetail::One(RELAY_ANSWER_TIMEOUT.as_nanos() / 1_000_000),
        ),
        RelayFailure::Busy => ("relay-window-busy", RefusalDetail::None),
        // What there was no room for, against the room there is: a byte count
        // with no bound beside it is a number nobody can read.
        RelayFailure::AnswerTooLong { refused } => (
            "relay-answer-too-long",
            RefusalDetail::Two(refused as u64, ONBOARD_OUTBOUND_CAPACITY as u64),
        ),
    };
    Refusal {
        cause,
        detail,
        signalled: false,
    }
}

/// The station this port reaches out to, and the port on it.
///
/// First-party constants: a management channel goes where this appliance was
/// told to take it and nowhere a peer names, and until the store holds an
/// endpoint of its own there is nowhere else to read one from. They are the
/// gateway the committed document states and a port of this appliance's own
/// choosing, so the dial leaves through the station the operator already
/// declared rather than through one this domain invented.
const DIAL_DESTINATION: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 2]);
const DIAL_PORT: u16 = 4433;

/// What the channel carries, fixed and first-party. It is a transport-level
/// probe and not a protocol: what belongs here is the greeting of the session
/// that will one day be negotiated over it, and the bytes are chosen so that a
/// station reading them can tell this appliance apart from anything else that
/// dialled it.
const DIAL_PROBE: &[u8] = b"LFW-DIAL/1";

/// The room a session holds for a request is a build fact, so a probe that did
/// not fit is a compile failure rather than an open refused at run time.
const _: () = assert!(DIAL_PROBE.len() <= DIAL_REQUEST_CAPACITY);

/// How many sessions this domain spends on the channel before it reports what
/// became of it.
///
/// A first-party bound and the whole of what ends a channel that never comes
/// up: every session under it leaves on something this end can observe, and
/// nothing here waits on a wall-clock gap. Three because a station that answered
/// none of three separate dials is one an operator has to go and look at, and a
/// fourth would say the same thing later.
const DIAL_ATTEMPTS: u64 = 3;

/// This domain's lifecycle record.
fn announce(sink: &dyn Sink, state: DomainState, detail: DomainDetail) {
    sink.emit(&Event::Domain {
        domain: Domain::Management,
        state,
        detail,
    });
}

/// Why this domain could not start.
///
/// One variant, because there is one thing it needs and cannot do without: a
/// per-boot secret for the transport's initial sequence numbers. Everything else
/// it needs is a mapping, and a wrong mapping is a fault rather than a refusal.
fn entropy_refusal(error: EntropyError) -> Refusal {
    // `signalled` is false because there is no device to be told to stop: the
    // instruction either answered or did not, and nothing was left mid-sequence.
    match error {
        EntropyError::NotSupported { feature_word } => Refusal {
            cause: "rdrand-not-supported",
            detail: RefusalDetail::One(u64::from(feature_word)),
            signalled: false,
        },
        EntropyError::Exhausted { word } => Refusal {
            cause: "rdrand-exhausted",
            detail: RefusalDetail::One(word as u64),
            signalled: false,
        },
    }
}

/// The channel this port reaches *out* with, and how far it has got.
///
/// It is a state machine rather than a call because nothing here may block: the
/// domain is woken, drains, and returns, so a session crosses several wakeups
/// and what carries it between them is this. Every transition below is driven by
/// something observable — a phase the endpoint reports, or this end's own
/// attempt count — and none of them by an elapsed time, so a channel that is
/// slow is a channel that is slow rather than a channel that failed.
struct Dial {
    /// Sessions opened so far, bounded by [`DIAL_ATTEMPTS`].
    attempts: u64,
    /// Whether one of them is running now.
    running: bool,
    /// Whether the outcome record this channel owes has been made. It is what
    /// makes that record exactly one: a channel is reported when it is decided,
    /// and a decided channel is never re-opened.
    reported: bool,
    /// Every session's frames, folded together. A channel spends more than one
    /// session and what an operator reads is the channel, so a station that
    /// answered none of them is reported as every handshake it ignored rather
    /// than as the last session's share of them.
    facts: DialFacts,
    /// The station the last session's frames were handed to, and which of the
    /// port's two answers chose it. The last rather than a fold: every session
    /// of one channel routes the same way, so there is one answer and not three,
    /// and `None` is a channel refused before a route was ever chosen.
    hop: Option<(Ipv4Address, Via)>,
    /// The port's resolution counts as they stood when this channel opened its
    /// first session. Subtracted at the report, which is what turns a running
    /// total of the port into an account of the channel.
    resolutions_before: Option<Resolutions>,
    /// The sequence numbers a station claimed against what this end had sent,
    /// where one did. Kept beside the outcome because the token names the fault
    /// and these two are the whole of what places it.
    acknowledged: Option<(u32, u32)>,
}

impl Dial {
    const fn new() -> Self {
        Self {
            attempts: 0,
            running: false,
            reported: false,
            facts: DialFacts::new(),
            hop: None,
            resolutions_before: None,
            acknowledged: None,
        }
    }

    /// Carry the channel forward by one wakeup.
    ///
    /// A pass either opens a session, moves the running one, or ends the
    /// channel; a pass over a port with no address yet does nothing at all,
    /// which is the ordinary state of a node between boot and its first commit.
    fn drive(&mut self, stage: &mut EndpointStage<'static>, now: Monotonic, sink: &dyn Sink) {
        if self.reported {
            return;
        }
        if !self.running {
            // Read before the first session opens anything, so the subtraction
            // at the report covers the channel and not the boot.
            if self.resolutions_before.is_none() {
                self.resolutions_before = Some(stage.resolutions());
            }
            match stage.open_dial(DIAL_DESTINATION, DIAL_PORT, DIAL_PROBE) {
                // Unaddressed: there is no source address to open a session
                // from, and one will arrive with the next committed generation.
                None => return,
                Some(Ok(())) => {
                    self.attempts = self.attempts.saturating_add(1);
                    self.running = true;
                }
                // This end refused before a frame was composed, and no further
                // attempt would be answered differently: nothing a peer does
                // changes a destination this node cannot route to, a probe this
                // node cannot fit, or a session this node is already running.
                Some(Err(error)) => {
                    self.report(stage, sink, refused_open(error));
                    return;
                }
            }
        }
        stage.drive_dial(now);
        let Some(ended) = stage.dial_ended() else {
            return;
        };
        // Before the close, which drops the session and everything it watched:
        // the counts are the evidence beside the token, and a token with no
        // evidence is the record this change exists to be rid of.
        if let Some((hop, facts)) = stage.dial_facts() {
            self.facts = self.facts.joined(facts);
            self.hop = Some((hop.address, hop.via));
        }
        // The two numbers travel with the ending that carries them and with no
        // other: a pair kept from a session that ended some other way would be
        // numbers reported beside a fault they did not belong to.
        if let Ended::UnacceptableAcknowledgement { claimed, expected } = ended {
            self.acknowledged = Some((claimed, expected));
        }
        stage.close_dial();
        self.running = false;
        if ended.succeeded() || self.attempts >= DIAL_ATTEMPTS {
            self.report(stage, sink, outcome_of(ended));
        }
    }

    /// What the channel owes the console, whichever way it went.
    ///
    /// **One record on a channel that came up, and four or five on one that did
    /// not.** A deployed node has no shell, so the counts that place a failure
    /// have to be on the console or nowhere — and they are more facts than the
    /// four operand words a record carries, which makes them further records
    /// rather than a wider one. A healthy boot stays quiet because there is
    /// nothing to place.
    ///
    /// The number of records is bounded by the shape of the outcome and never by
    /// anything that happened on the wire: a channel that spent every attempt it
    /// had and a great many handshakes reports the same lines as one that spent
    /// a single attempt and one handshake.
    fn report(&mut self, stage: &EndpointStage<'static>, sink: &dyn Sink, outcome: DialOutcome) {
        self.reported = true;
        announce(
            sink,
            DomainState::Ready,
            DomainDetail::Dialled {
                destination: DIAL_DESTINATION,
                port: DIAL_PORT,
                attempts: self.attempts,
                outcome,
            },
        );
        if outcome == DialOutcome::Answered {
            return;
        }
        // The route the frames really took. Where an open was refused before one
        // was chosen there is none, and the record says so rather than naming
        // one of the two real answers: the address then stands for where this
        // domain meant to go, and a next hop of zero would name a station.
        let (next_hop, via) = self
            .hop
            .map_or((DIAL_DESTINATION, NextHopVia::None), |(address, via)| {
                (address, chosen_via(via))
            });
        // The resolution's own account, over the life of the channel rather than
        // over the boot: the port asks about nothing else, but a subtraction says
        // so rather than assuming it.
        let resolutions = stage
            .resolutions()
            .since(self.resolutions_before.unwrap_or_default());
        announce(
            sink,
            DomainState::Ready,
            DomainDetail::DialRoute {
                next_hop,
                via,
                requests: resolutions.requested,
                learned: resolutions.learned,
            },
        );
        announce(
            sink,
            DomainState::Ready,
            DomainDetail::DialUnlearned {
                unsolicited: resolutions.unsolicited,
                rebinding: resolutions.rebinding,
                not_unicast: resolutions.not_unicast,
                contradicted: resolutions.contradicted,
            },
        );
        announce(
            sink,
            DomainState::Ready,
            DomainDetail::DialSegments {
                syns: self.facts.syns,
                resets_received: self.facts.resets_received,
                resets_sent: self.facts.resets_sent,
                answered: self.facts.answered,
            },
        );
        // Only where a station claimed one: the numbers exist exactly then, and
        // a record carrying two zeroes would be a pair this domain invented.
        if let Some((claimed, expected)) = self.acknowledged {
            announce(
                sink,
                DomainState::Ready,
                DomainDetail::DialSequence { claimed, expected },
            );
        }
    }
}

/// What one onboarding session owes the console: the account of what it
/// carried, the port's own totals beside it, and — where this appliance ended it
/// — the cause.
///
/// **Records rather than one wider one**, on the dialled channel's terms: a
/// record carries four operand words, the account fills them, the port's own
/// totals are a fifth through eighth fact, and a cause with its own two numbers
/// is a ninth and tenth. So a session that simply ended says so in two lines,
/// and one this appliance ended adds the cause.
///
/// The count is bounded by the shape of the outcome and never by anything that
/// happened on the wire: a session that carried one byte and one that carried
/// four thousand report the same lines.
fn announce_session(sink: &dyn Sink, report: &RelayReport, port: OnboardCounters) {
    announce(
        sink,
        DomainState::Ready,
        DomainDetail::Onboarded {
            relayed: report.relayed,
            received: report.received,
            sent: report.sent,
            ended: report.ended,
        },
    );
    // The port's own totals beside the session's account, because the account
    // can state a fault and not place it: a session that ended forgotten with
    // bytes refused past the window is a peer that overran it, and one accepted
    // connection more than there are session records is a connection that never
    // became a session at all. Neither fact is derivable from the record above.
    //
    // The port's running totals rather than this session's share of them: a
    // subtraction would be a number a reader cannot check against anything, and
    // the same four counts reach `/metrics`, where a scrape can see them move
    // without waiting for a session to end.
    announce(
        sink,
        DomainState::Ready,
        DomainDetail::OnboardingPort {
            accepted: port.accepted,
            forgotten: port.forgotten,
            overflowed: port.overflowed,
            refused: port.refused,
        },
    );
    if let Some(failure) = report.failure {
        announce(
            sink,
            DomainState::Ready,
            DomainDetail::Refusal(relay_refusal(failure)),
        );
    }
}

/// A finished session in the vocabulary a console line speaks. The two sets are
/// separate copies facing different readers — one is the transport's, one is the
/// operator's — and this is the single place that maps them.
///
/// One arm per ending and no arm covering two, which is the whole obligation
/// this function carries: a fold here would put back on the console exactly the
/// ambiguity the endpoint went to the trouble of resolving.
const fn outcome_of(ended: Ended) -> DialOutcome {
    match ended {
        Ended::Answered => DialOutcome::Answered,
        Ended::NextHopUnreachable => DialOutcome::NextHopUnreachable,
        Ended::NoRoomToResolve => DialOutcome::NoRoomToResolve,
        Ended::Unanswered => DialOutcome::Unanswered,
        Ended::ResetByPeer => DialOutcome::ResetByPeer,
        Ended::UnacceptableAcknowledgement { .. } => DialOutcome::UnacceptableAcknowledgement,
        Ended::Lost => DialOutcome::ConnectionLost,
        Ended::NoRoomToDial => DialOutcome::NoRoomToDial,
        Ended::ConnectionAlreadyOpen => DialOutcome::ConnectionAlreadyOpen,
        Ended::SynDidNotFit => DialOutcome::SynDidNotFit,
    }
}

/// An open this end refused before a frame was composed, in the same
/// vocabulary. Its own function because the two sets it maps from are different
/// — one is a session that ran and one is a session that never began — and each
/// of these three is a different line of this node's own configuration to go and
/// read.
const fn refused_open(error: OpenError) -> DialOutcome {
    match error {
        OpenError::Busy { .. } => DialOutcome::SessionAlreadyRunning,
        OpenError::Unroutable(_) => DialOutcome::DestinationUnroutable,
        OpenError::RequestTooLong { .. } => DialOutcome::ProbeTooLong,
    }
}

/// The route decision's answer in the console's own vocabulary, on
/// [`outcome_of`]'s terms.
const fn chosen_via(via: Via) -> NextHopVia {
    match via {
        Via::Prefix => NextHopVia::Prefix,
        Via::Gateway => NextHopVia::Gateway,
    }
}

/// The clock domain's refusals, in the vocabulary a console line speaks.
fn clock_refusal(refusal: CalibrationRefused) -> Refusal {
    match refusal {
        CalibrationRefused::NotPublished => Refusal {
            cause: "clock-not-published",
            detail: RefusalDetail::None,
            signalled: false,
        },
        CalibrationRefused::FrequencyImplausible { tsc_hz } => Refusal {
            cause: "clock-implausible-frequency",
            detail: RefusalDetail::One(tsc_hz),
            signalled: false,
        },
        CalibrationRefused::EpochImplausible { unix_nanos } => Refusal {
            cause: "clock-implausible-epoch",
            detail: RefusalDetail::One(unix_nanos),
            signalled: false,
        },
    }
}

#[protection_domain]
fn init() -> Management {
    // Before anything that could have something to say. The region is zeroed by
    // the kernel, so it is a valid empty ring the moment it is mapped, and the
    // console domain drains it whenever it comes up.
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let clock: &'static ClockCalibration = attach_region!(clock_vaddr: ClockCalibration);
    // Where the appliance dials, published by the domain that holds its record
    // and mapped read-only here. Attached and **not read**: this domain dials a
    // destination compiled into it, and nothing yet consults this region. The
    // attach is not optional even so — a domain granted a mapping whose image has
    // no symbol for it is a description the Microkit tool refuses to build — so
    // the binding this domain will use exists from the boot its grant does.
    let _endpoint: &'static ManagementEndpoint = attach_region!(endpoint_vaddr: ManagementEndpoint);
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(clock));
    announce(&sink, DomainState::Starting, DomainDetail::None);

    // First, because it is the one thing that can refuse: a port that came up and
    // then turned out to have no secret would have answered a `SYN` in the
    // meantime with a predictable sequence number.
    let secret = match entropy::secret_bytes() {
        Ok(bytes) => IsnSecret::from_bytes(bytes),
        Err(error) => {
            announce(
                &sink,
                DomainState::Refused,
                DomainDetail::Refusal(entropy_refusal(error)),
            );
            return Management::Refused;
        }
    };

    // In `lfw_metrics::SHARDS` order, which is the ABI: a snapshot reads slot 3
    // as `nic_driver2`'s, so a pair handed over out of order would attribute one
    // port's traffic to another.
    let stats = StatsRegions {
        shards: [
            attach_region!(stats_forwarder_vaddr: StatsShard),
            attach_region!(stats_nic_driver0_vaddr: StatsShard),
            attach_region!(stats_nic_driver1_vaddr: StatsShard),
            attach_region!(stats_nic_driver2_vaddr: StatsShard),
            attach_region!(stats_management_vaddr: StatsShard),
            attach_region!(stats_console_vaddr: StatsShard),
            attach_region!(stats_config_vaddr: StatsShard),
            attach_region!(stats_clock_vaddr: StatsShard),
            attach_region!(stats_recorder_vaddr: StatsShard),
            attach_region!(stats_hardware_probe_vaddr: StatsShard),
            attach_region!(stats_crypto_vaddr: StatsShard),
            attach_region!(stats_store_vaddr: StatsShard),
        ],
    };
    let stage = EndpointStage::attach(
        EndpointRegions {
            receive: attach_region!(mgmt_rx_fwd_vaddr: ForwardRings),
            receive_returns: attach_region!(mgmt_rx_free_vaddr: ReturnRing),
            receive_pool: attach_region!(mgmt_rx_pool_vaddr: Pool),
            transmit: attach_region!(mgmt_tx_fwd_vaddr: ForwardRings),
            transmit_returns: attach_region!(mgmt_tx_free_vaddr: ReturnRing),
            transmit_pool: attach_region!(mgmt_tx_pool_vaddr: Pool),
        },
        secret,
        stats,
    );
    let handover: &'static ConfigHandover = attach_region!(cfg_vaddr: ConfigHandover);
    let request: &'static DownloadRequest = attach_region!(dl_request_vaddr: DownloadRequest);
    let reply: &'static DownloadReply = attach_region!(dl_reply_vaddr: DownloadReply);
    let downloads = Downloads::attach(request, reply);
    let cfg_request: &'static ConfigRequest = attach_region!(cfg_request_vaddr: ConfigRequest);
    let cfg_reply: &'static ConfigReply = attach_region!(cfg_reply_vaddr: ConfigReply);
    let configurations = Configurations::attach(cfg_request, cfg_reply);
    // The relay's two regions, whose directions are the system description's:
    // the request is this domain's to write and the terminating domain's to
    // read, and the reply is the reverse. Nothing here restates that — the
    // handle `wire::relay` hands back reaches the reply through a view with no
    // store on it, so this domain cannot write the records it then puts on the
    // wire as though the other end had produced them.
    let relay_request: &'static RelayRequest = attach_region!(relay_request_vaddr: RelayRequest);
    let relay_reply: &'static RelayReply = attach_region!(relay_reply_vaddr: RelayReply);
    let relay = Relay::attach(relay_request, relay_reply);
    let mut stage = stage;
    // Both recordings and the configuration surface, before the first frame: a
    // target registered late would answer `404` to a client that asked at exactly
    // the wrong moment.
    let registered = downloads.register(&mut stage) && configurations.register(&mut stage);
    // The port is unaddressed until a generation is committed and unclocked until
    // the clock domain has published, and neither is a failure: both are states a
    // node passes through between boot and its first frame.
    announce(&sink, DomainState::Ready, DomainDetail::None);
    if !registered {
        // A build fact rather than a run-time condition — the endpoint's target
        // table is one size — so it is recorded and the port carries on serving
        // everything else.
        announce(
            &sink,
            DomainState::Ready,
            DomainDetail::Refusal(Refusal {
                cause: "recording-targets-unregistered",
                detail: RefusalDetail::None,
                signalled: false,
            }),
        );
    }

    Management::Running(Running {
        stage,
        downloads,
        configurations,
        relay,
        handover,
        clock,
        dial: Dial::new(),
        sink,
    })
}

/// A domain that started, or one that refused and holds only the channel it said
/// so on.
///
/// Two states rather than an `Option`, because the difference is what the event
/// loop does: a refused domain has no stage to drive and must not be woken into
/// pretending it has one. It still parks in the Microkit event loop, as
/// `pds/clock` does after a refusal — a domain that returned would take the
/// monitor's fault path, which is not what a *decided* refusal is.
#[expect(
    clippy::large_enum_variant,
    reason = "boxing needs an allocator; the running variant holds the two frame \
              buffers a reply is composed through, and one domain holds one value \
              of this for its whole life"
)]
enum Management {
    Running(Running),
    /// A domain that refused. It carries nothing: whatever it had to say is
    /// already in its ring, and there is no stage for a wakeup to drive.
    Refused,
}

struct Running {
    /// Kept for the domain's life, as the handles inside it are this domain's
    /// positions in four rings; a second stage would restart at slot zero.
    stage: EndpointStage<'static>,
    /// The recording downloads this port serves. Kept for the same reason: it
    /// holds this domain's position in the request channel's sequence.
    downloads: Downloads<'static>,
    /// The configuration surface this port serves, holding this domain's position
    /// in the submission channel's sequence for the same reason.
    configurations: Configurations<'static>,
    /// The onboarding port's relay, holding this domain's position in that
    /// channel's sequence for the same reason again.
    relay: Relay<'static>,
    handover: &'static ConfigHandover,
    clock: &'static ClockCalibration,
    /// The channel this port reaches out with, kept for the domain's life
    /// because a session crosses wakeups and the record it owes is made once.
    dial: Dial,
    sink: RingSink<'static, PdClock<'static>>,
}

impl Handler for Management {
    type Error = Infallible;

    /// A wakeup names no reason, so every question is asked of the regions: what
    /// the clock domain has published, what the configuration domain has
    /// committed, and what the driver has published. The two shared regions
    /// first, because a frame answered under the generation and the calibration
    /// that arrived with it is a frame answered correctly.
    ///
    /// **`channels` is deliberately unread.** Four things can wake this domain
    /// now — the driver, the recorder, the configuration domain and the clock
    /// domain's tick — and the pass is the same for all four, because none of
    /// them says anything a region does not. A tick that provoked a different
    /// pass from a frame would be a second code path over the same state, and
    /// the deadlines it exists to reach are exactly the ones a frame's pass
    /// judges.
    ///
    /// A refused domain does nothing at all here. It holds no stage, and a
    /// domain that refused is one that will never answer a frame however it is
    /// woken.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        let Self::Running(running) = self else {
            return Ok(());
        };
        if let Some(refusal) = running.stage.take_clock(running.clock) {
            announce(
                &running.sink,
                DomainState::Ready,
                DomainDetail::Refusal(clock_refusal(refusal)),
            );
        }
        if let Some(refused) = running.stage.take_configuration(running.handover, PORTS) {
            running.sink.emit(&Event::ConfigRejected {
                generation: refused.generation,
                reason: refused.reason,
                offset: refused.detail,
            });
        }
        // Read once per wakeup and used for the whole pass: every frame in one
        // drain is answered at one instant, which is what makes a retransmission
        // deadline a property of the pass rather than of a frame's position in it —
        // and what makes the two channel deadlines below judged against the same
        // instant the endpoint's own are.
        //
        // `None` until the clock domain has published, which is a state that arms
        // no deadline and refuses every segment in any case.
        let ticks = read_timestamp_counter();
        let now = running.stage.monotonic(ticks);
        // The log ring's own counts travel in with it, because the shard the
        // pass publishes carries them and this domain is the only thing that can
        // read them.
        // Before the frames, so a window the recorder answered between wakeups
        // is in the transport's hands by the time this pass composes a segment.
        // It never blocks: a pass with no reply yet does nothing.
        running.downloads.poll(now, &mut running.stage);
        // And the configuration channel, on the download channel's terms exactly:
        // an answer that landed between wakeups is in the endpoint's hands by the
        // time this pass composes a segment.
        if running.configurations.poll(now, &mut running.stage) {
            CONFIG.notify();
        }
        let log = log_sample(running.sink.dropped(), running.sink.refused());
        let moved = running.stage.poll(ticks, log);
        // And after them, because a request parsed in this very pass is what puts
        // a stream in `pending_stream` or a document in `submission`.
        running.downloads.poll(now, &mut running.stage);
        if running.configurations.poll(now, &mut running.stage) {
            CONFIG.notify();
        }
        // After the drain, so a resolution that arrived in this very pass is what
        // the session is carried forward on, and before the record below: the
        // shard is published again here, so a scrape reads the channel's own
        // counters as of this pass rather than the one before it.
        if let Some(now) = now {
            running.dial.drive(&mut running.stage, now, &running.sink);
            // The onboarding port, after the drain so a record that arrived in
            // this very pass is handed over in it, and before the send below so
            // an answer that came back goes out in it too. One item crosses per
            // pass — the channel's window is one — and the wakeup it owes is
            // sent here because the capability is this domain's.
            let pass = running.relay.poll(Some(now), &mut running.stage);
            if pass.notify {
                CRYPTO.notify();
            }
            if let Some(report) = pass.report {
                announce_session(&running.sink, &report, running.stage.onboard_counters());
            }
            running.stage.drive_onboarding(now);
            running.stage.publish(log);
        }
        if moved > 0 {
            let counters = running.stage.counters();
            announce(
                &running.sink,
                DomainState::Ready,
                DomainDetail::Received {
                    frames: counters.frames,
                    bytes: counters.bytes,
                },
            );
        }
        Ok(())
    }
}
