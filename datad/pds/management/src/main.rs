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
//! What that costs is real: a commit somebody else provoked reaches this domain
//! only when something wakes it.
//!
//! # It is woken by frames and by the passage of time
//!
//! Every deadline this domain holds — a retransmission, a reaping, the
//! reconnection backoff, and one day an acknowledgement cadence — is judged on a
//! pass, and
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
//! # It composes the node's metric reading, and it reads eleven other domains to do it
//!
//! It maps **twelve** stats shards: its own read-write, and one per other
//! protection domain READ-ONLY. That asymmetry is the whole argument — every
//! number in a reading is a claim only the domain that made it could have
//! written, so a compromise of the domain that faces the management-plane
//! attacker cannot forge a clean line for a port that is dropping every frame.
//! What stays withheld is in `systems/qemu-x86_64/librefirewall.system` beside
//! those rows. Its own shard is the one region in this system with exactly one
//! mapper, so the walk that composes a reading crosses one uniform array rather
//! than eleven regions plus a live read of its own counters.
//!
//! # Nothing on this port answers without authenticating
//!
//! The design requires the management plane to carry encryption, authentication
//! and read/write authorization through an mTLS certificate pair, and the two
//! connections this port carries both do: the onboarding session an
//! administrator opens, and the channel this appliance dials. Both terminate
//! where the keys are, which is not here.
//!
//! The management port itself serves nothing. Its transport is built to dial
//! only, so a `SYN` for it opens no connection and is counted as
//! `not_listening`; the number is kept because the channel's dial composes its
//! source port from it. This domain says so once at bring-up, that being a fact
//! about the build rather than about anything a peer did.
//!
//! # It carries two sessions' ciphertext and decides nothing about either
//!
//! The port answers on a listening port of its own, and it dials out on a
//! connection of its own; what crosses either is not a protocol this domain
//! speaks. Every byte is moved into a region the cryptography domain reads, and
//! every byte that comes back is put on the wire unread: TLS terminates where the
//! keys are, and the keys are not here. **This domain holds no key, no session
//! secret and no plaintext**, and the relay's ABI has no field for one in either
//! direction — see `pd_runtime::relay`, which is where the bounds on that
//! handover live.
//!
//! **One relay carries both, and never both at once.** Which half a pass carries
//! is this domain's to decide, because it owns both transports and is the only
//! domain that knows which of them a connection arrived on; it decides once per
//! session and states the answer on the open, and the domain that terminates the
//! session speaks the protocol it was told. A session keeps the relay until its
//! account is closed, an appliance taking an owner in the middle of the very
//! session that installs the package. The two halves are not two eras either: an
//! owned appliance goes on serving the onboarding surface, where what it serves
//! is the refusal saying it has an owner.
//!
//! What this domain learns back about the session is **one word**: whether the
//! protocol above agreed a greeting with the far end. It is the only thing that
//! starts the redial schedule afresh, and it has to come from up there — a
//! connection that came up is not an agreement, and a server that accepts every
//! connection and closes it is exactly the peer a reset on a completed handshake
//! would reward.
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
//! node. Every count also reaches the node's metric reading, where the rest of
//! what this domain knows about itself lives.

mod entropy;

use entropy::EntropyError;
use lfw_clock::Monotonic;
use lfw_log::{
    DialOutcome, Domain, DomainDetail, DomainState, Event, NextHopVia, Refusal, RefusalDetail,
    RingSink, Sink,
};
use lfw_metrics::StatsShard;
use pd_runtime::{
    CalibrationRefused, ChannelStream, ClockCalibration, ConfigHandover, DialFacts, Downloads,
    Ended, EndpointRegions, EndpointStage, ForwardRings, Half, Hop, Ipv4Address, IsnSecret,
    OnboardCounters, OpenError, PdClock, Pool, RELAY_ANSWER_TIMEOUT, Reconnect, Relay,
    RelayFailure, RelayReport, Resolutions, ReturnRing, Shipped, SnapshotSchedule, StatsRegions,
    Via, Wait, attach_region, log_sample, read_timestamp_counter,
};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, protection_domain};
use wire::{
    DownloadRefusal, DownloadReply, DownloadRequest, DownloadSink, LogConsume, LogRecords,
    ManagementDestination, ManagementEndpoint, RelayFault, RelayRefusal, RelayReply, RelayRequest,
    StatsRelay,
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

/// The cryptography domain, and the **one** send capability this domain holds in
/// this system. That domain blocks in the Microkit event loop and never polls, so
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
        // Its own token rather than the closed word's, because guessing costs
        // something different: read as agreed it would start a redial schedule
        // afresh that no far end earned, and read as not it would leave an
        // appliance whose channel is up backing off as though it were down.
        RelayFailure::Faulted(RelayFault::AgreedUnknown { agreed }) => (
            "relay-agreed-unknown",
            RefusalDetail::One(u64::from(agreed)),
        ),
        // Its own token for the reason above it has one: an extent read as not
        // wanted is an operator's request that answers nothing and says nothing,
        // which is the one outcome a request-response surface must not have.
        RelayFailure::Faulted(RelayFault::WantUnknown { wanted }) => (
            "relay-wanted-unknown",
            RefusalDetail::One(u64::from(wanted)),
        ),
        // The bound that was spent, in milliseconds, because the token alone
        // says a far end went quiet and not how long this end waited.
        RelayFailure::Unanswered => (
            "relay-unanswered",
            RefusalDetail::One(RELAY_ANSWER_TIMEOUT.as_nanos() / 1_000_000),
        ),
        RelayFailure::Busy => ("relay-window-busy", RefusalDetail::None),
        // What there was no room for against the room there was, neither readable alone.
        RelayFailure::AnswerTooLong { refused, room } => (
            "relay-answer-too-long",
            RefusalDetail::Two(refused as u64, room as u64),
        ),
    };
    Refusal {
        cause,
        detail,
        signalled: false,
    }
}

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
/// domain is woken, drains, and returns, so an attempt crosses several wakeups
/// and what carries it between them is this. Every transition below is driven by
/// something observable — a phase the endpoint reports, this end's own schedule,
/// or the destination the store domain published — and none of them by a
/// wall-clock gap on the wire, so an attempt that is slow is an attempt that is
/// slow rather than one that failed.
///
/// **It never gives up.** The channel is a persistent connection, so every close
/// is answered by another attempt under the schedule below, for as long as the
/// appliance is up. What was once a bounded run of attempts and a single verdict
/// is now a report per attempt: a verdict on a channel that has not finished
/// would be a line an operator was told and that later stopped being true.
struct OutboundChannel {
    /// Attempts opened this boot, counted from one. Not a bound — nothing bounds
    /// them — but the number an operator reads to tell a node's first try from
    /// its hundredth.
    attempts: u64,
    /// Whether one is running now.
    running: bool,
    /// Whether the attempt running now has already been reported as up. It is
    /// what makes that record one per attempt: a connection is announced when it
    /// comes up and not on every pass that finds it still up.
    established: bool,
    /// When the next attempt may open, and how long the wait after a failure
    /// may be. **The only thing that resets it is a greeting agreed with the far
    /// end** — the exchange the domain that terminates the session reports over
    /// the relay, and nothing else. A connection that came up is not one: a
    /// server that accepts every connection and closes it is exactly the peer a
    /// reset on a completed handshake would let invite a tight redial loop.
    schedule: Reconnect,
    /// Where the store domain published this appliance's management plane, as
    /// this domain last read it. It is what tells the two silences apart on the
    /// console: an appliance told nowhere, and one told somewhere it cannot
    /// reach.
    published: Option<ManagementDestination>,
    /// Whether the state above has been reported since it last changed. The
    /// region only ever gains a destination within a boot, so this is one record
    /// for an appliance nobody owns and none at all for one that was told where
    /// to go before its first pass.
    stated: bool,
    /// The port's resolution counts as they stood when the running attempt
    /// opened. Subtracted at the report, which is what turns a running total of
    /// the port into an account of one attempt.
    resolutions_before: Option<Resolutions>,
}

impl OutboundChannel {
    const fn new(jitter: u64) -> Self {
        Self {
            attempts: 0,
            running: false,
            established: false,
            schedule: Reconnect::new(jitter),
            published: None,
            stated: false,
            resolutions_before: None,
        }
    }

    /// Whether an attempt of this appliance's own is open, which is what claims
    /// the relay for the channel half. **The attempt and not its connection**: a
    /// claim made from the connection would leave the window between a `SYN` and
    /// the handshake open for the onboarding surface to take the relay and hold
    /// it while the channel sat established with nothing carrying it.
    const fn attempting(&self) -> bool {
        self.running
    }

    /// The greeting the far end agreed, which is the one thing that starts the
    /// schedule afresh.
    ///
    /// Reported by the domain that terminates the session, over the relay,
    /// because it is the only party that can know it: this domain carries the
    /// bytes and reads none of them. **A connection coming up is deliberately
    /// not this** — the contract's rule and not a simplification, since a server
    /// that accepts every connection and closes it is exactly what a reset on a
    /// completed handshake would hand a redial loop.
    fn agreed(&mut self) {
        self.schedule.established();
    }

    /// Carry the channel forward by one wakeup.
    ///
    /// A pass either opens an attempt, moves the running one, reports one that
    /// came up, or reports one that ended and schedules the next. A pass over a
    /// port with no address yet does nothing at all, which is the ordinary state
    /// of a node between boot and its first commit.
    ///
    /// `relayed` is whether the relay's account of a session is still open.
    /// **Both ends of an attempt wait on it**, and the reason is identity rather
    /// than tidiness: the transport numbers its connections independently of the
    /// relay's life, so an attempt opened before the last one's account was
    /// closed could carry the same connection id and be read there as the last
    /// session continuing — and the session the relay is closing is the one this
    /// domain would otherwise have dropped out from under it, taking the ending
    /// it reports with it. Both waits are bounded by the relay's own answer
    /// timeout whatever the far end does.
    fn drive(
        &mut self,
        stage: &mut EndpointStage<'static>,
        endpoint: &ManagementEndpoint,
        now: Monotonic,
        sink: &dyn Sink,
        relayed: bool,
    ) {
        if !self.running {
            if relayed {
                return;
            }
            self.open(stage, endpoint, now, sink);
        }
        if !self.running {
            return;
        }
        stage.drive_dial(now);
        // Before the ending is read, because an attempt can come up and go away
        // between two passes and the console owes both facts: a channel that was
        // up for a minute and one that never came up at all are different things
        // to go and look at, and only this record tells them apart.
        if !self.established && stage.dial_established() {
            self.established = true;
            self.announce_attempt(sink, DialOutcome::Established);
        }
        let Some(ended) = stage.dial_ended() else {
            return;
        };
        if relayed {
            return;
        }
        // Read before the close, which drops the session and everything it
        // watched: the counts are the evidence beside the token, and a token
        // with no evidence is a failure an operator cannot act on.
        let hop = stage.dial_facts();
        stage.close_dial();
        self.running = false;
        // The attempt is over. Whether the schedule goes on doubling or starts
        // afresh was decided when the far end agreed a greeting, or did not:
        // this draws the next wait from wherever the schedule now stands.
        let wait = self.schedule.failed(now);
        self.report(stage, sink, outcome_of(ended), hop, Some(ended), wait);
    }

    /// Open the next attempt, or say why there is none to open.
    fn open(
        &mut self,
        stage: &mut EndpointStage<'static>,
        endpoint: &ManagementEndpoint,
        now: Monotonic,
        sink: &dyn Sink,
    ) {
        // Read every pass and never cached across one: the store domain writes
        // this region while this domain runs, so an appliance that takes an
        // owner mid-boot dials on the pass after it rather than at the next
        // reboot.
        let published = endpoint.destination();
        if published != self.published {
            self.published = published;
            self.stated = false;
        }
        let Some(destination) = published else {
            // **Nowhere to dial is a state and not a failed attempt**, so
            // nothing is counted, nothing is scheduled, and the next attempt is
            // due the instant a destination appears. What it owes is one line:
            // a node that never dials and says nothing would be a node an
            // operator cannot tell from one whose channel is failing silently.
            if !self.stated {
                self.stated = true;
                announce(
                    sink,
                    DomainState::Ready,
                    DomainDetail::Refusal(Refusal {
                        cause: "dial-endpoint-unpublished",
                        detail: RefusalDetail::None,
                        signalled: false,
                    }),
                );
            }
            return;
        };
        self.stated = true;
        if !self.schedule.due(now) {
            return;
        }
        let address = Ipv4Address::from_octets(destination.address);
        // Read before this attempt opens anything, so the subtraction at the
        // report covers the attempt and not the boot.
        self.resolutions_before = Some(stage.resolutions());
        match stage.open_dial(address, destination.port) {
            // Unaddressed: there is no source address to open a session from,
            // and one will arrive with the next committed generation. Not an
            // attempt either, for the reason nowhere to dial is not one.
            None => (),
            Some(Ok(())) => {
                self.attempts = self.attempts.saturating_add(1);
                self.running = true;
                self.established = false;
            }
            // This end refused before a frame was composed. It is still an
            // attempt — it was this appliance's own turn and it produced
            // nothing — so it is counted, reported, and followed by a wait like
            // any other: a destination this node cannot route to is a
            // configuration an operator may fix while the node keeps trying.
            Some(Err(error)) => {
                self.attempts = self.attempts.saturating_add(1);
                let wait = self.schedule.failed(now);
                self.report(stage, sink, refused_open(error), None, None, wait);
            }
        }
    }

    /// The one record every attempt owes: where it went, which attempt it was,
    /// and how it stands.
    fn announce_attempt(&self, sink: &dyn Sink, outcome: DialOutcome) {
        // A default rather than a branch: this is only ever reached with a
        // destination in hand, and a zero address on a record nobody can produce
        // is a value rather than a panic on the path a peer's traffic paces.
        let (address, port) =
            self.published
                .map_or((Ipv4Address::from_octets([0, 0, 0, 0]), 0), |destination| {
                    (
                        Ipv4Address::from_octets(destination.address),
                        destination.port,
                    )
                });
        announce(
            sink,
            DomainState::Ready,
            DomainDetail::Dialled {
                destination: address,
                port,
                attempts: self.attempts,
                outcome,
            },
        );
    }

    /// What an attempt that failed owes the console.
    ///
    /// **One record on an attempt that came up, and five or six on one that did
    /// not.** A deployed node has no shell, so the counts that place a failure
    /// have to be on the console or nowhere — and they are more facts than the
    /// four operand words a record carries, which makes them further records
    /// rather than a wider one. An attempt that came up places nothing, because
    /// there is nothing to place.
    ///
    /// The number of records is bounded by the shape of the outcome and never by
    /// anything that happened on the wire: an attempt that spent a great many
    /// handshakes reports the same lines as one that spent a single one.
    fn report(
        &self,
        stage: &EndpointStage<'static>,
        sink: &dyn Sink,
        outcome: DialOutcome,
        hop: Option<(Hop, DialFacts)>,
        ended: Option<Ended>,
        wait: Wait,
    ) {
        self.announce_attempt(sink, outcome);
        // The route the frames really took. Where an open was refused before one
        // was chosen there is none, and the record says so rather than naming
        // one of the two real answers: the address then stands for where this
        // domain meant to go, and a next hop of zero would name a station.
        let intended = self
            .published
            .map_or(Ipv4Address::from_octets([0, 0, 0, 0]), |destination| {
                Ipv4Address::from_octets(destination.address)
            });
        let (next_hop, via) = hop.map_or((intended, NextHopVia::None), |(hop, _)| {
            (hop.address, chosen_via(hop.via))
        });
        // The resolution's own account, over the life of this attempt rather
        // than over the boot: the port asks about nothing else, but a
        // subtraction says so rather than assuming it.
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
        let facts = hop.map_or(DialFacts::new(), |(_, facts)| facts);
        announce(
            sink,
            DomainState::Ready,
            DomainDetail::DialSegments {
                syns: facts.syns,
                resets_received: facts.resets_received,
                resets_sent: facts.resets_sent,
                answered: facts.answered,
            },
        );
        // How long until the next attempt, and the bound it was drawn below.
        // Last of the group, because it is the only one that looks forward: an
        // operator reads what happened and then reads when the node will try
        // again.
        announce(
            sink,
            DomainState::Ready,
            DomainDetail::DialRetry {
                delay_millis: wait.delay_millis(),
                bound_millis: wait.bound_millis(),
            },
        );
        // Only where a station claimed one: the numbers exist exactly then, and
        // a record carrying two zeroes would be a pair this domain invented.
        if let Some(Ended::UnacceptableAcknowledgement { claimed, expected }) = ended {
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
    // the same four counts reach the node's metric reading, where a consumer can
    // see them move without waiting for a session to end.
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
        Ended::ClosedByPeer => DialOutcome::ClosedByPeer,
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
/// of these two is a different line of this node's own configuration to go and
/// read.
const fn refused_open(error: OpenError) -> DialOutcome {
    match error {
        OpenError::Busy { .. } => DialOutcome::SessionAlreadyRunning,
        OpenError::Unroutable(_) => DialOutcome::DestinationUnroutable,
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

/// A recording whose ring wrapped past the channel's own cursor, as a console
/// line spells it.
///
/// A token per recording rather than one carrying which: the log ring is this
/// appliance's connection history and the capture ring is the traffic itself, so
/// what goes missing from one is not what goes missing from the other, and an
/// operator acts on the two differently.
///
/// A **resynchronisation** is history this appliance can no longer ship: the ring
/// wrapped past the cursor, and the reader carried on from the oldest byte still
/// on the medium rather than stopping. The two positions say how much went with
/// it. Not a peer's doing — it is this node producing recorded bytes faster than
/// its channel shipped them, or a boot resuming a medium a previous one wrote.
///
/// A **stall** is the opposite fact and the more serious one: durable bytes are
/// standing behind a cursor that is not moving, with a session up that could
/// carry them. The position and the backlog are what an operator needs to see
/// whether it is growing.
///
/// A **clamped resume point** is neither: it is a management server naming a
/// position past the end of a recording this appliance has, which is a server
/// holding some other node's cursor or one that outlived the medium here. The
/// session goes on from the durable end, and the two numbers are what say how
/// far apart the two ends' ideas of this recording are.
const fn refusal_for(
    recording: DownloadSink,
    causes: (&'static str, &'static str),
    detail: RefusalDetail,
) -> Refusal {
    Refusal {
        cause: match recording {
            DownloadSink::Log => causes.0,
            DownloadSink::Capture => causes.1,
        },
        detail,
        signalled: false,
    }
}

/// What the channel's reader has to say, as a console record.
fn shipping_record(shipped: Shipped) -> DomainDetail {
    match shipped {
        Shipped::Shipping { log, capture } => DomainDetail::ChannelShipping {
            log_position: log.position,
            log_pending: log.pending,
            capture_position: capture.position,
            capture_pending: capture.pending,
        },
        Shipped::Resynchronised {
            recording,
            lost_from,
            resumed_at,
        } => DomainDetail::Refusal(refusal_for(
            recording,
            (
                "upstream-log-ring-resynchronised",
                "upstream-capture-ring-resynchronised",
            ),
            RefusalDetail::Two(lost_from, resumed_at),
        )),
        Shipped::Stalled { recording, place } => DomainDetail::Refusal(refusal_for(
            recording,
            ("upstream-log-ring-stalled", "upstream-capture-ring-stalled"),
            RefusalDetail::Two(place.position, place.pending),
        )),
        Shipped::ResumeClamped {
            recording,
            claimed,
            durable,
        } => DomainDetail::Refusal(refusal_for(
            recording,
            (
                "upstream-log-resume-past-durable",
                "upstream-capture-resume-past-durable",
            ),
            RefusalDetail::Two(claimed, durable),
        )),
        // One token per cause and none per recording, unlike the four above.
        // Which recording an extent was of is on the wire in the answer's own
        // ring byte and in the request the operator made; the cause the mapping
        // onto three wire statuses throws away is only here, so that is what the
        // token spends itself on.
        Shipped::RangeRefused { reason, offset } => DomainDetail::Refusal(Refusal {
            cause: match reason {
                DownloadRefusal::NotReady => "upstream-range-not-ready",
                DownloadRefusal::OutOfRange => "upstream-range-out-of-range",
                DownloadRefusal::Overrun => "upstream-range-overwritten",
                DownloadRefusal::DeviceError => "upstream-range-medium-error",
                DownloadRefusal::NoSuchSink => "upstream-range-no-such-recording",
                DownloadRefusal::NoSuchReader => "upstream-range-no-such-reader",
            },
            detail: RefusalDetail::One(offset),
            signalled: false,
        }),
        Shipped::RangeFaulted { offset } => DomainDetail::Refusal(Refusal {
            cause: "upstream-range-faulted",
            detail: RefusalDetail::One(offset),
            signalled: false,
        }),
        Shipped::RangeUnanswered { offset } => DomainDetail::Refusal(Refusal {
            cause: "upstream-range-unanswered",
            detail: RefusalDetail::One(offset),
            signalled: false,
        }),
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
    // and mapped read-only here. **Read every pass and never cached across one**:
    // the writer runs while this domain does, an appliance takes an owner within
    // a boot, and a reading held from start-up would leave a node that was just
    // adopted dialling nowhere until it was rebooted.
    let endpoint: &'static ManagementEndpoint = attach_region!(endpoint_vaddr: ManagementEndpoint);
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(clock));
    announce(&sink, DomainState::Starting, DomainDetail::None);

    // First, because it is the one thing that can refuse: a port that came up and
    // then turned out to have no secret would have answered a `SYN` in the
    // meantime with a predictable sequence number.
    let drawn = match entropy::draw_entropy() {
        Ok(drawn) => drawn,
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
        IsnSecret::from_bytes(drawn.secret),
        stats,
    );
    let handover: &'static ConfigHandover = attach_region!(cfg_vaddr: ConfigHandover);
    let request: &'static DownloadRequest = attach_region!(dl_request_vaddr: DownloadRequest);
    let reply: &'static DownloadReply = attach_region!(dl_reply_vaddr: DownloadReply);
    let downloads = Downloads::attach(request, reply);
    // The relay's two regions, whose directions are the system description's:
    // the request is this domain's to write and the terminating domain's to
    // read, and the reply is the reverse. Nothing here restates that — the
    // handle `wire::relay` hands back reaches the reply through a view with no
    // store on it, so this domain cannot write the records it then puts on the
    // wire as though the other end had produced them.
    // The one page this domain writes for the recorder: read-write here and
    // read-only there, which is what lets a whole metric reading cross without
    // the recorder mapping a single statistics shard.
    let stats_relay: &'static StatsRelay = attach_region!(stats_relay_vaddr: StatsRelay);
    let relay_request: &'static RelayRequest = attach_region!(relay_request_vaddr: RelayRequest);
    let relay_reply: &'static RelayReply = attach_region!(relay_reply_vaddr: RelayReply);
    let relay = Relay::attach(relay_request, relay_reply);
    // The port is unaddressed until a generation is committed and unclocked until
    // the clock domain has published, and neither is a failure: both are states a
    // node passes through between boot and its first frame.
    announce(&sink, DomainState::Ready, DomainDetail::None);
    // Once, here, and never again: it is a property of the build rather than of
    // anything that happens afterwards. An operator who reaches the management
    // port and gets nothing back reads this line and knows the node is up and
    // serving nothing, rather than guessing between that and a node that never
    // came up.
    announce(&sink, DomainState::Ready, DomainDetail::ListensForNothing);

    Management::Running(Running {
        stage,
        downloads,
        relay,
        handover,
        clock,
        endpoint,
        // Seeded from a draw of its own, never from the transport's secret: a
        // redial instant is observable from the wire, and a schedule seeded
        // from that secret would leak it through its own timing.
        channel: OutboundChannel::new(drawn.jitter),
        stats,
        stats_relay,
        snapshots: SnapshotSchedule::new(),
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
    /// The onboarding port's relay, holding this domain's position in that
    /// channel's sequence for the same reason again.
    relay: Relay<'static>,
    handover: &'static ConfigHandover,
    clock: &'static ClockCalibration,
    /// Where this appliance was told to dial, read afresh on every pass.
    endpoint: &'static ManagementEndpoint,
    /// The channel this port reaches out with, kept for the domain's life
    /// because an attempt crosses wakeups and the schedule between attempts
    /// outlives every one of them.
    channel: OutboundChannel,
    /// Every shard, kept beside the stage that also holds them: the reading
    /// published for the recorder is taken from here.
    stats: StatsRegions<'static>,
    /// Where that reading goes — read by the recorder, which maps no shard but
    /// its own.
    stats_relay: &'static StatsRelay,
    snapshots: SnapshotSchedule,
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
        // `shipping` says whether the dialled channel is up and greeted, which
        // is the only state in which reading ring bytes for it is worth a round
        // trip to the recorder.
        let shipping = running.relay.shipping();
        running.downloads.poll(now, shipping);
        let log = log_sample(running.sink.dropped(), running.sink.refused());
        let moved = running.stage.poll(ticks, log);
        // After the drain, so a resolution that arrived in this very pass is what
        // the session is carried forward on, and before the record below: the
        // shard is published again here, so a reading carries the channel's own
        // counters as of this pass rather than the one before it.
        if let Some(now) = now {
            running.channel.drive(
                &mut running.stage,
                running.endpoint,
                now,
                &running.sink,
                running.relay.carrying().is_some(),
            );
            // **Which of the two connections the relay carries this pass**: the
            // session already open for as long as its account lasts, and between
            // sessions the attempt this domain has open — the channel wherever
            // one is, the onboarding surface otherwise. Ownership is not
            // consulted, an owned appliance serving that surface too. What the
            // onboarding half can hold the relay for is bounded by the transport
            // rather than the peer: one connection at a time, reaped on the
            // endpoint's own idle timer.
            let half = running
                .relay
                .carrying()
                .unwrap_or(if running.channel.attempting() {
                    Half::Channel
                } else {
                    Half::Onboarding
                });
            // The relay, after the drain so a record that arrived in this very
            // pass is handed over in it, and before the sends below so an answer
            // that came back goes out in it too. One item crosses per pass — the
            // channel's window is one — and the wakeup it owes is sent here
            // because the capability is this domain's.
            let pass = match half {
                Half::Channel => running.relay.poll(
                    Some(now),
                    &mut ChannelStream(&mut running.stage),
                    &mut running.downloads,
                ),
                Half::Onboarding => {
                    running
                        .relay
                        .poll(Some(now), &mut running.stage, &mut running.downloads)
                }
            };
            if pass.notify {
                CRYPTO.notify();
            }
            // The one thing that starts the redial schedule afresh, and it
            // arrives here and nowhere else: the far end agreed a greeting with
            // the protocol this domain cannot read.
            if pass.agreed {
                running.channel.agreed();
            }
            if let Some(report) = pass.report {
                announce_session(&running.sink, &report, running.stage.onboard_counters());
            }
            // Where the channel's reader stands, what it had to skip, and
            // whether it has stopped. Drained whole on every pass, so nothing
            // accumulates in the reader's queue and every line reaches the
            // console on the pass that raised it.
            while let Some(shipped) = running.downloads.take_shipped() {
                announce(&running.sink, DomainState::Ready, shipping_record(shipped));
            }
            // Both halves, because the relay just pushed onto one of them and a
            // pass that drove only the other would leave the answer waiting for
            // the next wakeup.
            running.stage.drive_dial(now);
            running.stage.drive_onboarding(now);
            running.stage.publish(log);
        }
        // Last in the pass and outside the clocked block, so the reading carries
        // what every shard holds *after* this pass published its own — and so an
        // unclocked node publishes its one reading rather than none.
        running.snapshots.publish_due(
            now,
            running.stage.utc(ticks),
            &running.stats,
            running.stats_relay,
        );
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
