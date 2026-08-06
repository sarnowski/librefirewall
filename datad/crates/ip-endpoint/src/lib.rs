//! The terminal IPv4 endpoint: the appliance answering **for itself** on one
//! addressed port.
//!
//! `routing` decides what to do with a frame addressed to the appliance's MAC and
//! destined for somebody else. This crate is the other half of that sentence — a
//! frame destined for *us* — and answers three questions: "who holds this address"
//! (ARP), "are you there" (ICMP echo), and whatever is asked over a TCP connection
//! to its one listening port. Nothing here forwards.
//!
//! # Adversary
//!
//! Two adversaries at once.
//!
//! * **Untrusted network traffic.** Every byte handed to [`Endpoint::handle`] was
//!   put on a wire by whatever is attached to the port, so each is parsed through
//!   `net_headers` or `lfw_tcp` and refused by a typed error rather than believed.
//! * **The management-plane attacker.** The port this runs on is the management port,
//!   held out of the dataplane, so the station on it is the party the management API answers,
//!   and everything it sends arrives here. A reply is a frame the appliance
//!   originates, and what decides whether one is composed is entirely below.
//!
//! # Every reply is a decision, so every decision is counted
//!
//! An [`Outcome`] is returned *and* recorded in [`EndpointCounters`]: a station
//! probing an endpoint that silently refuses everything looks exactly like an
//! idle link. The counters follow `pipeline::DropCounters` — saturating, never
//! reset — because the rate is the attacker's to choose.
//!
//! # Two listening ports, and two different things on them
//!
//! [`MANAGEMENT_PORT`] carries the HTTP surface described below.
//! [`onboard::ONBOARDING_PORT`] carries a **byte stream** instead: an
//! [`onboard::Stream`] that accepts one connection, hands what arrives to a
//! consumer above this crate and puts what that consumer answers back on the
//! wire. It is where a session another domain terminates reaches the network,
//! and this crate never interprets a byte of it.
//!
//! Two transports rather than one, because a `lfw_tcp::TcpStack` answers on one
//! port and matches a segment to a connection by the peer's address and port
//! alone. So each port has its own table, its own sequence space and its own
//! challenge budget, and a segment is handed to exactly one of them —
//! `lfw_tcp::peeked_destination_port` reads the field before anything is
//! verified, purely to choose which stack verifies it, and a segment too short
//! to carry one goes to the HTTP stack, whose parse counts it as the malformed
//! segment it is.
//!
//! **The two stacks' connection handles are not comparable.** Each numbers its
//! own slots, so the same `ConnectionId` may name a connection in both; nothing
//! here holds one without knowing which table it came from, and the stream keeps
//! its own return path rather than sharing the table below.
//!
//! # The transport, and the service on it
//!
//! `lfw_tcp` is the stack; on it sits [`http::Server`], which reads one HTTP/1.1
//! request per connection and answers three shapes: a `GET` of a registered target
//! with a body its caller renders whole, `/metrics` among them; a `GET` of a target
//! registered through [`Endpoint::serve_stream_at`] out of a body supplied a window
//! at a time; and a `POST` to a target registered through
//! [`Endpoint::serve_body_at`] by accumulating the request body and handing it to
//! its caller to decide on. It holds the target strings and knows nothing behind
//! them, so an appliance serves a recording off a block device and commits a
//! configuration through an endpoint aware of neither. Everything else gets a
//! status, and then it closes. So an
//! endpoint carries state between frames and is not `Copy`, and it needs a
//! clock: with none, a segment is [`Outcome::Unclocked`] and ARP and ICMP go on
//! as before. A response outgrows one segment by an order of magnitude, so
//! [`Endpoint::poll_output`] is what a caller drives until a pass has nothing
//! left to send.
//!
//! # A known, deliberate gap in the target design: the service is plain HTTP
//!
//! The target design requires the management API to carry encryption, authentication
//! and read/write authorization through an mTLS certificate pair. None of it exists:
//! there is no TLS in this appliance, this endpoint authenticates nobody, and
//! **anything that can reach the management port can read every metric the node
//! exposes, read any registered stream, and submit a body to any registered
//! target** — which for the configuration surface is the authority to decide what
//! the appliance forwards. `GET /logs` is absent and answers 404 rather than being
//! stubbed. The gap is recorded.
//!
//! # It reaches out as well as answering
//!
//! One [`outbound::Session`] at a time, driven by [`Endpoint::poll_outbound`]:
//! the [`route`] decision picks the next hop out of this port's own address,
//! prefix and gateway, the [`neighbour`] cache learns that next hop's hardware
//! address by asking, and the transport dials. A segment for a next hop that is
//! not resolved yet is **dropped** under a typed reason rather than queued — the
//! transport recorded it and re-sends it under RFC 6298's backoff, and the
//! resolution runs while that timer is armed.
//!
//! An ARP *reply* is therefore taken as well as an ARP request answered, and the
//! cache's own three rules are what keep that from being a way to aim this
//! node's outbound traffic: only a reply this end asked for is learned, a
//! resolved entry is immutable for its lifetime, and the sender is judged before
//! the payload is read. The last of those is applied here, before anything
//! reaches the cache.
//!
//! # Deliberate narrowness, and what each exclusion costs
//!
//! Every refusal below is a variant of [`Unhandled`], where it is documented;
//! what the variants do not say is why the narrowness is deliberate. There is
//! **no address defence**: an RFC 5227 probe is refused rather than answered,
//! because contradicting a second station needs conflict state that does not
//! exist. **A reply is only ever composed for a neighbour and only for a unicast
//! one** — a reply to an off-link station would leave under a next hop nothing
//! chose, the gateway being for traffic this node *originates*, and a reply
//! addressed to a group is a reflector. And there are **two TCP ports and no
//! UDP**: one service each, and nothing listens anywhere else.
//!
//! # No allocator, and every buffer a fixed array
//!
//! [`Endpoint::handle`] writes its reply into storage the caller owns, so the
//! caller decides where a reply is composed — in the protection domain that runs
//! this, a buffer it has just taken from a pool. Nothing here is allocated and
//! nothing here is sized by anything a peer sends: the two connection tables,
//! each connection's request slot, the one response staging buffer, the outbound
//! session's request and answer and the onboarding stream's two directions are
//! fixed arrays sized by the constants below, in [`http`], in [`outbound`] and
//! in [`onboard`].

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

use lfw_clock::Monotonic;
use lfw_tcp::{
    Connection, Outcome as TcpOutcome, Refusal, Rejection, Released, TcpCounters, TcpStack, Timeout,
};

/// Re-exported rather than restated: the per-boot secret is obtained by the
/// protection domain and the segment types are what a *test* composes one out
/// of, and all reach this crate rather than the transport under it.
pub use lfw_tcp::{ConnectionId, Flags, IsnSecret, MAX_UNACKED, Outgoing, SeqNumber, State};
use net_headers::{
    ArpError, ArpOperation, ArpPacket, ArpReply, ArpRequest, EchoReply, EtherType, Ethernet,
    IcmpEcho, IcmpError, Ipv4Address, Ipv4Frame, Ipv4Packet, MAX_PREFIX_LENGTH, MacAddress,
    ParseError, Protocol, ReplyError,
};

pub mod http;
pub mod neighbour;
pub mod onboard;
pub mod outbound;
pub mod route;

use http::{HttpCounters, REQUEST_CAPACITY, Server};
use neighbour::{Learned, NeighbourCache, NeighbourCounters, Resolution};
use onboard::{INBOUND_CAPACITY, ONBOARD_CONNECTIONS, ONBOARDING_PORT, Stream, StreamCounters};
use outbound::{Ended, OpenError, OutboundCounters, Phase, Resolutions, Session};
use route::Port;

/// Re-exported because a caller committing to a streamed body names one, and
/// the bound behind it is `lfw_http`'s rather than this crate's.
pub use lfw_http::{ContentType, Status};

/// Connections one management port holds at once, and so the bound a connection
/// flood is answered by.
///
/// Eight rather than one, because a browser opens several at a time; rather than
/// many, because each carries a [`REQUEST_CAPACITY`] slot.
pub const TCP_CONNECTIONS: usize = 8;

/// The port this endpoint listens on: the management HTTP port. A constant rather
/// than a configured value because the service is the constant — the design puts
/// `/metrics`, `/config` and `/logs` on the management interface, and a port a
/// document could move is one a scraper could not find.
pub const MANAGEMENT_PORT: u16 = 80;

/// The largest payload this endpoint composes in one segment: the classic
/// Ethernet maximum, and it is the response side that fixes it — the round trips
/// a scrape costs are its length divided by this.
pub const TCP_MSS: u16 = 1460;

// Ethernet, IPv4 and a TCP header with no options, in front of a full segment,
// against the smallest storage any caller in this workspace offers.
const _: () = assert!(Ipv4Frame::PAYLOAD_AT + 20 + TCP_MSS as usize <= 2036);

/// Why a configured pair cannot be an endpoint's: the same three rules
/// `config::validate` holds a `<management>` element's address and prefix to,
/// re-checked because an image crosses a protection-domain boundary between the
/// two. The gateway beside them is not among these, and that is not an omission:
/// what makes a gateway usable depends on the destination as well as on the
/// gateway, so it is judged on every dial by [`route::next_hop`] rather than
/// once here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointError {
    MacNotUnicast { mac: MacAddress },
    AddressNotUnicast { address: Ipv4Address },
    PrefixLengthOutOfRange { prefix_length: u8 },
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MacNotUnicast { mac } => write!(f, "{mac} is not a unicast MAC"),
            Self::AddressNotUnicast { address } => write!(f, "{address} is not a unicast address"),
            Self::PrefixLengthOutOfRange { prefix_length } => {
                write!(
                    f,
                    "prefix length {prefix_length} exceeds {MAX_PREFIX_LENGTH}"
                )
            }
        }
    }
}

/// Why a well-formed frame addressed to this endpoint went unanswered. Every
/// variant is one it *could* have been built to answer and deliberately is not;
/// not ours is [`Outcome::NotForUs`] and not what it claims is
/// [`Outcome::Malformed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unhandled {
    /// An 802.1Q tag, with no sub-interface to interpret it.
    VlanTagged,
    /// Neither ARP nor IPv4. The value refused, or `None` where the reason
    /// stands for its counter slot rather than for a frame (see
    /// [`ALL`](Self::ALL)).
    EtherType(Option<EtherType>),
    /// IPv4, but not ICMP. `None` on [`ALL`](Self::ALL)'s terms.
    Protocol(Option<Protocol>),
    /// An ICMP message that is not an echo request.
    NotAnEchoRequest,
    /// A fragment, which no reply can be composed from.
    Fragmented,
    /// A source no reply may be addressed to.
    SourceNotUnicast,
    /// A source outside our prefix; see the crate header.
    SourceOffLink,
    /// An ARP request whose sender hardware address is not its Ethernet source:
    /// answering the payload's field lets a station aim this port at a third.
    ArpSenderMacMismatch,
}

impl Unhandled {
    /// One entry per counter slot, so a counter table is built by iteration
    /// rather than from a list that drifts from the enum.
    ///
    /// The two reasons that carry the value they refused appear here carrying
    /// **none**: a table entry names a slot, and an invented `EtherType(0)`
    /// would read as a frame somebody sent.
    pub const ALL: [Self; 8] = [
        Self::VlanTagged,
        Self::EtherType(None),
        Self::Protocol(None),
        Self::NotAnEchoRequest,
        Self::Fragmented,
        Self::SourceNotUnicast,
        Self::SourceOffLink,
        Self::ArpSenderMacMismatch,
    ];

    /// A stable short name, for a metric label or a report line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::VlanTagged => "vlan_tagged",
            Self::EtherType(_) => "ethertype_not_handled",
            Self::Protocol(_) => "protocol_not_handled",
            Self::NotAnEchoRequest => "not_an_echo_request",
            Self::Fragmented => "fragmented",
            Self::SourceNotUnicast => "source_not_unicast",
            Self::SourceOffLink => "source_off_link",
            Self::ArpSenderMacMismatch => "arp_sender_mac_mismatch",
        }
    }

    /// The slot this reason occupies in [`EndpointCounters`], and so in
    /// [`ALL`](Self::ALL). The two payload-carrying variants collapse onto their own
    /// slot, the payload being the value refused rather than a second reason.
    const fn slot(self) -> usize {
        match self {
            Self::VlanTagged => 0,
            Self::EtherType(_) => 1,
            Self::Protocol(_) => 2,
            Self::NotAnEchoRequest => 3,
            Self::Fragmented => 4,
            Self::SourceNotUnicast => 5,
            Self::SourceOffLink => 6,
            Self::ArpSenderMacMismatch => 7,
        }
    }
}

impl fmt::Display for Unhandled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EtherType(Some(ether_type)) => write!(f, "{} {ether_type}", self.name()),
            Self::Protocol(Some(protocol)) => write!(f, "{} {protocol}", self.name()),
            other => f.write_str(other.name()),
        }
    }
}

/// Which parser refused the frame, carrying its error whole: a rejection is
/// attributable to a byte rather than to a category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// Ethernet or IPv4.
    Frame(ParseError),
    Arp(ArpError),
    Icmp(IcmpError),
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "{error}"),
            Self::Arp(error) => write!(f, "arp: {error:?}"),
            Self::Icmp(error) => write!(f, "icmp: {error:?}"),
        }
    }
}

/// What one frame became. The vocabulary is closed and every variant counted, so
/// there is no outcome a caller can meet and not know about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// An ARP reply of `len` bytes was written into the caller's storage.
    ArpReply { len: usize },
    /// An ICMP echo reply of `len` bytes was written into the caller's storage.
    EchoReply { len: usize },
    /// An ARP reply was taken to the neighbour cache, and what the cache decided
    /// about it. Nothing is composed in answer: a reply is the end of an
    /// exchange this end began, and every refusal below is a reply this end did
    /// not begin one for.
    Neighbour(Learned),
    /// A TCP segment was processed. `len` is what the transport composed in answer,
    /// zero where it composed nothing; what became of the segment is in
    /// [`Outcome::tcp`] and every cause is counted in [`Endpoint::tcp_counters`].
    Tcp { len: usize, outcome: TcpOutcome },
    /// A TCP segment for the onboarding port was processed, on
    /// [`Outcome::Tcp`]'s terms and through the other transport. Its own
    /// variant rather than a field on that one, because the two carry different
    /// tables and different counters: folding them would make either port's
    /// numbers a total nobody can attribute.
    Onboarding { len: usize, outcome: TcpOutcome },
    /// A TCP segment or an ARP reply arrived before this node had established a
    /// time. **Ours**, not the sender's: a node that has not finished booting is
    /// not a peer misbehaving. An ARP reply is among them because a cache entry
    /// has a lifetime and an outstanding request has a deadline, neither of
    /// which a node with no clock can judge — and a node with no clock has sent
    /// no request either, so such a reply answers nothing in any case. An ARP
    /// *request* and an ICMP echo need no clock and are unaffected.
    Unclocked,
    /// Addressed to somebody else, at L2 or L3: the commonest outcome on a shared
    /// segment, and never a fault.
    NotForUs,
    /// Ours, well-formed, and not something this endpoint answers.
    Unhandled(Unhandled),
    /// Not the frame it claims to be.
    Malformed(Malformed),
    /// A reply this endpoint decided on could not be written — the caller's storage,
    /// and the caller this names.
    ReplyRefused(ReplyError),
}

impl Outcome {
    /// The reply written into the caller's storage, if any. A TCP segment that
    /// provoked nothing answers `None` rather than `Some(0)`, so a caller has one
    /// question per outcome: is there a frame to send.
    #[must_use]
    pub const fn reply(self) -> Option<usize> {
        match self {
            Self::ArpReply { len } | Self::EchoReply { len } => Some(len),
            Self::Tcp { len, .. } | Self::Onboarding { len, .. } if len > 0 => Some(len),
            Self::Tcp { .. }
            | Self::Onboarding { .. }
            | Self::Neighbour(_)
            | Self::Unclocked
            | Self::NotForUs
            | Self::Unhandled(_)
            | Self::Malformed(_)
            | Self::ReplyRefused(_) => None,
        }
    }

    /// What a transport made of the segment, where this was one — whichever of
    /// the two ports it arrived on.
    #[must_use]
    pub const fn tcp(self) -> Option<TcpOutcome> {
        match self {
            Self::Tcp { outcome, .. } | Self::Onboarding { outcome, .. } => Some(outcome),
            _ => None,
        }
    }
}

/// What an endpoint has seen, in the shape the metrics endpoint will
/// scrape. Monotonic and saturating on `pipeline::DropCounters`' terms: no reset,
/// because a scrape differences successive samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointCounters {
    /// ARP requests for our address, answered.
    pub arp_replies: u64,
    /// ARP replies handed to the neighbour cache, whatever it made of them.
    /// What each became is counted in [`Endpoint::neighbour_counters`], one
    /// field per decision, on `tcp_segments`' terms exactly.
    pub neighbour_replies: u64,
    /// Echo requests for our address, answered.
    pub echo_replies: u64,
    /// Frames addressed to somebody else.
    pub not_for_us: u64,
    /// Frames no parser would read. One counter for every [`Malformed`]: this
    /// endpoint exposes no surface that reports which, so a finer split
    /// would be numbers nobody reads.
    pub malformed: u64,
    /// Replies decided on and not written: a caller-side failure, and the one count
    /// here that is not about the wire.
    pub reply_refused: u64,
    /// TCP segments handed to the HTTP port's transport, whatever it made of
    /// them; what each became is counted in [`Endpoint::tcp_counters`], one
    /// field per cause.
    pub tcp_segments: u64,
    /// TCP segments handed to the onboarding port's transport, on
    /// `tcp_segments`' terms and counted apart from it: the two ports have two
    /// tables, and one total over both would say nothing about either.
    pub onboarding_segments: u64,
    /// TCP segments that arrived with no clock; see [`Outcome::Unclocked`].
    pub unclocked: u64,
    /// One slot per [`Unhandled`] reason, in [`Unhandled::ALL`] order.
    unhandled: [u64; Unhandled::ALL.len()],
}

impl EndpointCounters {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            arp_replies: 0,
            neighbour_replies: 0,
            echo_replies: 0,
            not_for_us: 0,
            malformed: 0,
            reply_refused: 0,
            tcp_segments: 0,
            onboarding_segments: 0,
            unclocked: 0,
            unhandled: [0; Unhandled::ALL.len()],
        }
    }

    /// Replies this endpoint composed, whichever kind. TCP segments are not among
    /// them: a connection sends without having been asked and answers a frame with
    /// nothing, so counting the two together would make neither mean anything.
    #[must_use]
    pub const fn replies(&self) -> u64 {
        self.arp_replies.saturating_add(self.echo_replies)
    }

    #[must_use]
    pub fn unhandled(&self, reason: Unhandled) -> u64 {
        // Every reason has a slot by construction — the array is sized by
        // `Unhandled::ALL` — so the zero is a value rather than an assertion,
        // a path a frame reaches admitting no panic.
        self.unhandled.get(reason.slot()).copied().unwrap_or(0)
    }

    #[must_use]
    pub fn unhandled_total(&self) -> u64 {
        self.unhandled
            .iter()
            .fold(0u64, |sum, count| sum.saturating_add(*count))
    }

    /// Every frame this endpoint was handed, which a caller compares against the
    /// frames it took off its pipeline.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.replies()
            .saturating_add(self.neighbour_replies)
            .saturating_add(self.not_for_us)
            .saturating_add(self.malformed)
            .saturating_add(self.reply_refused)
            .saturating_add(self.tcp_segments)
            .saturating_add(self.onboarding_segments)
            .saturating_add(self.unclocked)
            .saturating_add(self.unhandled_total())
    }

    /// One place deciding which count an outcome moves, so no path through
    /// [`Endpoint::handle`] returns an outcome it did not record.
    fn record(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::ArpReply { .. } => self.arp_replies = self.arp_replies.saturating_add(1),
            Outcome::Neighbour(_) => {
                self.neighbour_replies = self.neighbour_replies.saturating_add(1);
            }
            Outcome::EchoReply { .. } => self.echo_replies = self.echo_replies.saturating_add(1),
            Outcome::NotForUs => self.not_for_us = self.not_for_us.saturating_add(1),
            Outcome::Malformed(_) => self.malformed = self.malformed.saturating_add(1),
            Outcome::ReplyRefused(_) => self.reply_refused = self.reply_refused.saturating_add(1),
            Outcome::Tcp { .. } => self.tcp_segments = self.tcp_segments.saturating_add(1),
            Outcome::Onboarding { .. } => {
                self.onboarding_segments = self.onboarding_segments.saturating_add(1);
            }
            Outcome::Unclocked => self.unclocked = self.unclocked.saturating_add(1),
            Outcome::Unhandled(reason) => {
                if let Some(count) = self.unhandled.get_mut(reason.slot()) {
                    *count = count.saturating_add(1);
                }
            }
        }
    }
}

impl Default for EndpointCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// One addressed port, answering for itself. Not `Copy`, and not by omission: it
/// holds a connection table and the bytes those connections owe, so a copy would
/// answer on the same address with its own idea of every sequence space.
pub struct Endpoint {
    mac: MacAddress,
    address: Ipv4Address,
    prefix_length: u8,
    /// The station everything off this port's prefix is handed to, or `None`
    /// where the operator stated none — then this port reaches its own link and
    /// nothing else. Read by [`route::next_hop`] and by nothing that answers a
    /// frame: a reply is addressed to the station that sent it.
    gateway: Option<Ipv4Address>,
    counters: EndpointCounters,
    tcp: TcpStack<TCP_CONNECTIONS>,
    http: Server<TCP_CONNECTIONS>,
    /// The onboarding port's own transport, and the stream on it. Two fields
    /// rather than one because they are the same pairing as `tcp` and `http`
    /// beside them: a transport, and the thing that decides what its bytes mean.
    onboarding: TcpStack<ONBOARD_CONNECTIONS>,
    stream: Stream,
    paths: [Option<ReturnPath>; TCP_CONNECTIONS],
    neighbours: NeighbourCache,
    outbound: Option<Session>,
    outbound_counters: OutboundCounters,
}

/// Where one connection's frames arrive from, and so the only pair a segment this
/// endpoint originates unprompted can be addressed to. Not an ARP cache and
/// unable to become one: learned from the frame that opened the connection and
/// forgotten with it, so bounded by the connection table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReturnPath {
    connection: ConnectionId,
    mac: MacAddress,
    address: Ipv4Address,
}

/// Where the outbound session's next hop stands, as the step that asked about
/// it must act on.
///
/// Four answers rather than an `Option<MacAddress>`, because "not yet" and "not
/// ever" are different facts and the step in between — a request this end has to
/// put on the wire — is a frame rather than a state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NextHop {
    /// Resolved; a frame may be addressed to it.
    At(MacAddress),
    /// A request of `len` bytes is in the caller's storage. Send it.
    Asked(usize),
    /// A request is outstanding and its answer is not due. A segment composed
    /// now cannot be addressed and is dropped.
    Waiting,
    /// The session is over — nothing on this link answers for the next hop, or
    /// there was no room to ask — and what ending it produced, which the caller
    /// answers with. Ending a session gives its connection back to the
    /// transport, and giving one back can compose a segment.
    Over(Polled),
}

/// The connection a timeout concerns, whichever kind it is.
const fn timeout_connection(timeout: Timeout) -> ConnectionId {
    match timeout {
        Timeout::Resent { connection, .. }
        | Timeout::Retransmit { connection, .. }
        | Timeout::Abandoned { connection, .. }
        | Timeout::Reaped { connection } => connection,
    }
}

/// What one poll of a port's own work produced.
///
/// Three answers rather than an `Option<usize>`, because "produced no frame" and
/// "there was nothing to do" are different facts and a caller driving a pass to
/// exhaustion must tell them apart. A reaping produces no frame and leaves every
/// other connection's work undone; a loop that stopped there would send one
/// connection's segments and abandon the rest until the next wakeup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polled {
    /// A frame of `len` bytes is in the caller's storage. Send it and poll
    /// again.
    Frame { len: usize },
    /// Work was taken and produced no frame. Nothing to send, and the pass goes
    /// on.
    Handled,
    /// Nothing was due. The pass is over.
    Idle,
}

impl Polled {
    /// The frame to send, if any.
    #[must_use]
    pub const fn frame(self) -> Option<usize> {
        match self {
            Self::Frame { len } => Some(len),
            Self::Handled | Self::Idle => None,
        }
    }

    /// Whether the pass has more to do.
    #[must_use]
    pub const fn goes_on(self) -> bool {
        !matches!(self, Self::Idle)
    }
}

impl Endpoint {
    /// # Errors
    /// [`EndpointError`], for a pair no endpoint can answer under.
    pub fn new(
        mac: MacAddress,
        address: Ipv4Address,
        prefix_length: u8,
        gateway: Option<Ipv4Address>,
        secret: IsnSecret,
    ) -> Result<Self, EndpointError> {
        if !mac.is_unicast() {
            return Err(EndpointError::MacNotUnicast { mac });
        }
        if !address.is_unicast() {
            return Err(EndpointError::AddressNotUnicast { address });
        }
        if prefix_length > MAX_PREFIX_LENGTH {
            return Err(EndpointError::PrefixLengthOutOfRange { prefix_length });
        }
        Ok(Self {
            mac,
            address,
            prefix_length,
            // Not checked here, and deliberately: what a gateway has to be is a
            // statement about a *destination* as well as about the gateway, so
            // it is judged at the one place both are known — `route::next_hop`,
            // on every dial rather than once at construction.
            gateway,
            counters: EndpointCounters::new(),
            // The window starts at a request slot's whole capacity and is kept
            // equal to its free space from then on, which is what makes it mean
            // what a window means.
            tcp: TcpStack::new(
                address,
                MANAGEMENT_PORT,
                TCP_MSS,
                REQUEST_CAPACITY as u32,
                secret.clone(),
            ),
            // The same secret and so the same unpredictable initial sequence
            // numbers: the generator mixes the four-tuple in, and the two
            // stacks' tuples differ in the local port, so no number of one is
            // derivable from a number of the other.
            onboarding: TcpStack::new(
                address,
                ONBOARDING_PORT,
                TCP_MSS,
                INBOUND_CAPACITY as u32,
                secret,
            ),
            stream: Stream::new(),
            http: Server::new(),
            paths: [None; TCP_CONNECTIONS],
            neighbours: NeighbourCache::new(),
            outbound: None,
            outbound_counters: OutboundCounters::new(),
        })
    }

    #[must_use]
    pub const fn mac(&self) -> MacAddress {
        self.mac
    }

    #[must_use]
    pub const fn address(&self) -> Ipv4Address {
        self.address
    }

    #[must_use]
    pub const fn prefix_length(&self) -> u8 {
        self.prefix_length
    }

    /// The station everything off this port's prefix is handed to, where the
    /// operator stated one.
    #[must_use]
    pub const fn gateway(&self) -> Option<Ipv4Address> {
        self.gateway
    }

    #[must_use]
    pub const fn counters(&self) -> EndpointCounters {
        self.counters
    }

    /// What the neighbour cache has decided, one field per decision. It is where
    /// a station trying to place an entry is counted.
    #[must_use]
    pub const fn neighbour_counters(&self) -> NeighbourCounters {
        self.neighbours.counters()
    }

    /// What asking about a next hop has produced on this port, gathered from the
    /// two places that decide it: the cache, which asks and decides whether this
    /// end asked for a reply, and this endpoint, which decides whether the frame
    /// agreed with its own payload before the cache is consulted at all.
    #[must_use]
    pub fn resolutions(&self) -> Resolutions {
        let neighbours = self.neighbours.counters();
        Resolutions {
            requested: neighbours.requested,
            learned: neighbours.learned,
            unsolicited: neighbours.unsolicited,
            rebinding: neighbours.rebinding_refused,
            not_unicast: neighbours.not_unicast,
            contradicted: self.counters.unhandled(Unhandled::ArpSenderMacMismatch),
        }
    }

    /// What the outbound half has done, one field per decision.
    #[must_use]
    pub const fn outbound_counters(&self) -> OutboundCounters {
        self.outbound_counters
    }

    /// The session this port is running, if any.
    #[must_use]
    pub const fn outbound(&self) -> Option<&Session> {
        self.outbound.as_ref()
    }

    /// Open a connection to `destination` on `port`, carrying `request` and
    /// keeping what comes back.
    ///
    /// Nothing leaves here: the next hop is chosen and the session recorded, and
    /// [`poll_outbound`](Self::poll_outbound) is what puts a frame on the wire.
    /// That split is what lets an open be refused for a reason of this node's own
    /// — an unreachable destination, a request too long — before a peer has been
    /// given the chance to say anything.
    ///
    /// # Errors
    /// [`OpenError`], for a session already running, a destination this port
    /// cannot reach, or a request longer than the room for one.
    pub fn open_outbound(
        &mut self,
        destination: Ipv4Address,
        port: u16,
        request: &[u8],
    ) -> Result<(), OpenError> {
        if let Some(running) = self.outbound.as_ref() {
            OutboundCounters::bump(&mut self.outbound_counters.open_refused);
            return Err(OpenError::Busy {
                destination: running.destination(),
                port: running.port(),
            });
        }
        let next_hop = match route::next_hop(self.port_addressing(), destination) {
            Ok(next_hop) => next_hop,
            Err(refusal) => {
                OutboundCounters::bump(&mut self.outbound_counters.open_refused);
                return Err(OpenError::Unroutable(refusal));
            }
        };
        let session = match Session::new(destination, port, next_hop, request) {
            Ok(session) => session,
            Err(error) => {
                OutboundCounters::bump(&mut self.outbound_counters.open_refused);
                return Err(error);
            }
        };
        self.outbound = Some(session);
        OutboundCounters::bump(&mut self.outbound_counters.opened);
        Ok(())
    }

    /// Forget a finished session, so another may be opened.
    ///
    /// A session that has not finished is left alone and `false` answered: a
    /// caller that could drop a running one would leave the transport holding a
    /// connection nothing would ever read.
    pub fn close_outbound(&mut self) -> bool {
        let finished = self
            .outbound
            .as_ref()
            .is_some_and(|session| session.phase().ended().is_some());
        if finished {
            self.outbound = None;
        }
        finished
    }

    /// This port's addressing, as a route decision sees it.
    const fn port_addressing(&self) -> Port {
        Port {
            address: self.address,
            prefix_length: self.prefix_length,
            gateway: self.gateway,
        }
    }

    /// What the transport has seen, one field per cause.
    #[must_use]
    pub const fn tcp_counters(&self) -> TcpCounters {
        self.tcp.counters()
    }

    /// What the server above the transport has done, one field per cause.
    #[must_use]
    pub const fn http_counters(&self) -> HttpCounters {
        self.http.counters()
    }

    /// How many connections the port holds, in any state.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.tcp.connections()
    }

    /// How many connections this endpoint holds a return path for.
    ///
    /// Compared against [`connections`](Self::connections) by a caller checking
    /// what this crate is holding: the table has one entry per connection, so a
    /// path that outlived its connection is one a live connection can never
    /// have — and a connection with no path is one nothing this end composes can
    /// be addressed to.
    #[must_use]
    pub fn return_paths(&self) -> usize {
        self.paths.iter().flatten().count()
    }

    /// Decide what, if anything, to send in reply to one received frame,
    /// writing the reply into `out` and reporting its length in the outcome.
    ///
    /// `now` is `None` on a node with no time yet: ARP and ICMP are answered
    /// regardless, and a TCP segment is refused as [`Outcome::Unclocked`]. `out`
    /// may be shorter than the reply, and the outcome then says so.
    pub fn handle(&mut self, now: Option<Monotonic>, frame: &[u8], out: &mut [u8]) -> Outcome {
        // Before the frame is looked at, so a request for a shared-array surface
        // arriving in this very frame is answered rather than refused by a body
        // whose deadline had already passed.
        if let Some(now) = now {
            self.http.expire(now);
        }
        let outcome = self.decide(now, frame, out);
        self.counters.record(outcome);
        outcome
    }

    /// Take whatever the transport's timers now owe, writing one segment into `out`
    /// and answering what became of it.
    ///
    /// Called in a loop until it answers [`Polled::Idle`]: each answer either
    /// frees a connection or moves a deadline, so the loop terminates
    /// (`lfw_tcp::TcpStack::poll_timeouts`). A timer that produced no frame —
    /// a reaping, or a retransmission the server could not serve — is
    /// [`Polled::Handled`] and not the end of the pass, because the timer after
    /// it belongs to a different connection. A caller woken only by traffic reaps
    /// on the next frame rather than at the deadline.
    pub fn poll_timeouts(&mut self, now: Monotonic, out: &mut [u8]) -> Polled {
        let timeout = {
            let Some(segment) = out.get_mut(Ipv4Frame::PAYLOAD_AT..) else {
                return Polled::Idle;
            };
            match self.tcp.poll_timeouts(now, segment) {
                Some(timeout) => timeout,
                None => return Polled::Idle,
            }
        };
        let connection = timeout_connection(timeout);
        // Read before the answer, because a connection the transport abandoned or
        // reaped is already gone from its table by the time it says so.
        let path = self.path_of(connection);
        // A range of the outbound request is this end's to re-supply, and the
        // server above the transport holds no slot for a connection it did not
        // accept — so a timeout for the dial is answered here or it is answered
        // by nothing.
        let len = if self.is_outbound(connection) {
            self.answer_outbound(now, timeout, out)
        } else {
            out.get_mut(Ipv4Frame::PAYLOAD_AT..)
                .and_then(|segment| self.http.answer(&mut self.tcp, now, timeout, segment))
        };
        self.reconcile();
        match (path, len) {
            (Some(path), Some(len)) => Polled::Frame {
                len: self.frame_around(path, len, out),
            },
            _ => Polled::Handled,
        }
    }

    /// The target a completed request is waiting on a rendered body for.
    ///
    /// A caller answers it by publishing whatever the body is *about* and then
    /// calling [`supply_body`](Self::supply_body): the two steps exist so a
    /// scrape's own request has been counted before the numbers are read. See
    /// [`http`]'s header. The target is answered too, because the owner of one
    /// rendered target is not the owner of another.
    #[must_use]
    pub fn body_wanted(&self) -> Option<&'static str> {
        self.http.pending_render().map(|(_, target)| target)
    }

    /// Answer the request waiting on a whole body with `status` and whatever
    /// `render` writes. See [`http::Server::supply`].
    pub fn supply_body(
        &mut self,
        status: Status,
        content_type: Option<ContentType>,
        render: impl FnOnce(&mut [u8]) -> Option<usize>,
    ) {
        self.http.supply(status, content_type, render);
    }

    /// The target a submitted request body is waiting on a decision about. See
    /// [`http::Server::pending_submission`].
    #[must_use]
    pub fn submission_wanted(&self) -> Option<&'static str> {
        self.http.pending_submission().map(|(_, target)| target)
    }

    /// The submitted body itself. See [`http::Server::submission`].
    #[must_use]
    pub fn submission(&self) -> Option<&[u8]> {
        self.http.submission()
    }

    /// Register `target` as streamed, not `404`. See [`http::Server::serve_stream_at`].
    pub fn serve_stream_at(&mut self, target: &'static str) -> bool {
        self.http.serve_stream_at(target)
    }

    /// Register `target` as answered on `GET` with a rendered body. See
    /// [`http::Server::serve_rendered_at`].
    pub fn serve_rendered_at(&mut self, target: &'static str) -> bool {
        self.http.serve_rendered_at(target)
    }

    /// Register `target` as accepting a request body on `POST`. See
    /// [`http::Server::serve_body_at`].
    pub fn serve_body_at(&mut self, target: &'static str) -> bool {
        self.http.serve_body_at(target)
    }

    /// The target a request awaits a decision on. See [`http::Server::pending_stream`].
    #[must_use]
    pub fn pending_stream(&self) -> Option<(ConnectionId, &'static str)> {
        self.http.pending_stream()
    }

    /// Answer it with a body of `total` bytes. See [`http::Server::supply_stream`].
    pub fn begin_stream(&mut self, total: u64, content_type: ContentType) -> bool {
        self.http.supply_stream(total, content_type)
    }

    /// The window a streamed response needs. See [`http::Server::window_wanted`].
    #[must_use]
    pub fn window_wanted(&self) -> Option<(ConnectionId, u64, usize)> {
        self.http.window_wanted()
    }

    /// Hand over that window. See [`http::Server::supply_window`].
    pub fn supply_window(&mut self, start: u64, bytes: &[u8]) -> bool {
        self.http.supply_window(start, bytes)
    }

    /// Give up on the streamed response. See [`http::Server::abandon_stream`].
    pub fn abandon_stream(&mut self) {
        self.http.abandon_stream();
    }

    /// Compose the next segment any connection's response owes, writing it into
    /// `out` and answering what became of it.
    ///
    /// Driven in a loop until it answers [`Polled::Idle`], which happens as soon
    /// as every connection is done or blocked on its peer's window; a caller
    /// woken by one frame would otherwise send one segment per frame received.
    /// Each answer hands one range to the transport, so the loop is bounded by
    /// the response length and by `lfw_tcp::MAX_UNACKED`.
    ///
    /// A connection the server chose and could not drive ends the pass: the
    /// server takes the connections that *can* send first, so one that produced
    /// nothing is waiting on a window or on its peer, and neither arrives inside
    /// a pass. Cleanup runs either way, which is why the drive's answer is not
    /// short-circuited.
    pub fn poll_output(&mut self, now: Monotonic, out: &mut [u8]) -> Polled {
        // And here, so a wakeup that carried no frame at all — a neighbouring
        // domain's notification — still reclaims the array and puts the 408 that
        // says so on the wire.
        self.http.expire(now);
        self.http.sweep(&self.tcp);
        let Some(connection) = self.http.pending() else {
            return Polled::Idle;
        };
        let path = self.path_of(connection);
        let composed = out
            .get_mut(Ipv4Frame::PAYLOAD_AT..)
            .and_then(|segment| self.http.drive(&mut self.tcp, now, connection, segment));
        self.reconcile();
        match (path, composed) {
            (Some(path), Some(len)) => Polled::Frame {
                len: self.frame_around(path, len, out),
            },
            // A segment the transport took and this end has nowhere to send: the
            // transport holds the range and will ask for it again, and the pass
            // goes on rather than stopping on a connection with no return path.
            (None, Some(_)) => Polled::Handled,
            (_, None) => Polled::Idle,
        }
    }

    fn decide(&mut self, now: Option<Monotonic>, frame: &[u8], out: &mut [u8]) -> Outcome {
        let ethernet = match Ethernet::parse(frame) {
            Ok(ethernet) => ethernet,
            Err(error) => return Outcome::Malformed(Malformed::Frame(error)),
        };
        match ethernet.header.ether_type {
            EtherType::ARP => self.arp(now, &ethernet, out),
            EtherType::IPV4 => self.ipv4(now, &ethernet, out),
            EtherType::VLAN => Outcome::Unhandled(Unhandled::VlanTagged),
            other => Outcome::Unhandled(Unhandled::EtherType(Some(other))),
        }
    }

    /// An ARP request is broadcast, so this is the one path that accepts a frame
    /// not addressed to our own MAC.
    ///
    /// A reply is the other operation this port reads. It is judged by the same
    /// three rules a request is — addressed to us, its claimed sender agreeing
    /// with the frame that carried it, and that sender a unicast station on this
    /// link — and only then handed to the cache, which decides the one question
    /// those cannot: whether this end asked.
    fn arp(&mut self, now: Option<Monotonic>, ethernet: &Ethernet<'_>, out: &mut [u8]) -> Outcome {
        let destination = ethernet.header.destination;
        if destination != self.mac && !destination.is_broadcast() {
            return Outcome::NotForUs;
        }
        let packet = match ArpPacket::parse(ethernet.payload) {
            Ok(packet) => packet,
            Err(error) => return Outcome::Malformed(Malformed::Arp(error)),
        };
        if packet.operation == ArpOperation::Reply {
            return self.arp_reply(now, ethernet, &packet);
        }
        if packet.target_address != self.address {
            return Outcome::NotForUs;
        }
        if packet.sender_mac != ethernet.header.source {
            return Outcome::Unhandled(Unhandled::ArpSenderMacMismatch);
        }
        if let Some(refusal) = self.refuse_sender(packet.sender_mac, packet.sender_address) {
            return refusal;
        }
        let reply = ArpReply {
            mac: self.mac,
            address: self.address,
            target_mac: packet.sender_mac,
            target_address: packet.sender_address,
        };
        match reply.write(out) {
            Ok(len) => Outcome::ArpReply { len },
            Err(error) => Outcome::ReplyRefused(error),
        }
    }

    /// Take one ARP reply to the neighbour cache.
    ///
    /// A reply is unicast to the station that asked, so — unlike a request — one
    /// addressed to the broadcast address is **not** ours: it is a station
    /// announcing itself to the whole link, which is the gratuitous reply the
    /// cache would refuse in any case and which is refused here without being
    /// counted as a reply to anything.
    fn arp_reply(
        &mut self,
        now: Option<Monotonic>,
        ethernet: &Ethernet<'_>,
        packet: &ArpPacket,
    ) -> Outcome {
        if ethernet.header.destination != self.mac || packet.target_address != self.address {
            return Outcome::NotForUs;
        }
        if packet.sender_mac != ethernet.header.source {
            return Outcome::Unhandled(Unhandled::ArpSenderMacMismatch);
        }
        if let Some(refusal) = self.refuse_sender(packet.sender_mac, packet.sender_address) {
            return refusal;
        }
        let Some(now) = now else {
            return Outcome::Unclocked;
        };
        Outcome::Neighbour(
            self.neighbours
                .learn(now, packet.sender_address, packet.sender_mac),
        )
    }

    /// Drive the outbound session one step, writing whatever it owes into `out`.
    ///
    /// Called in a loop until it answers [`Polled::Idle`], as the two polls
    /// beside it are. Each answer either moves the session's phase, hands a range
    /// to the transport, or puts a resolution request on the wire, so the loop
    /// terminates; [`Polled::Handled`] is a step that produced no frame and is
    /// never the end of a pass, because the step after it may.
    pub fn poll_outbound(&mut self, now: Monotonic, out: &mut [u8]) -> Polled {
        // Before the phase is read: the transport frees a connection on its own
        // — an abandoned dial, a reset — and a session reading a handle the table
        // no longer holds would sit in `Dialling` for the life of the domain.
        self.reconcile();
        let Some(session) = self.outbound.as_ref() else {
            return Polled::Idle;
        };
        if session.phase().ended().is_some() {
            return Polled::Idle;
        }
        match session.phase() {
            Phase::Resolving => self.resolve_outbound(now, out),
            Phase::Dialling | Phase::Sending | Phase::Reading | Phase::Closing => {
                self.advance_outbound(now, out)
            }
            // Unreachable: an ended phase left above. A value rather than an
            // assertion, this being a path a peer's traffic paces.
            Phase::Ended(_) => Polled::Idle,
        }
    }

    /// Where this session's next hop stands, asking about it if it must.
    ///
    /// A hardware address already held is answered without the cache being
    /// consulted at all: an entry is immutable for its lifetime, and a session
    /// that re-read it would follow a rebinding the cache itself refuses.
    fn next_hop(&mut self, now: Monotonic, out: &mut [u8]) -> NextHop {
        let Some(session) = self.outbound.as_ref() else {
            return NextHop::Over(Polled::Handled);
        };
        if let Some(mac) = session.peer_mac() {
            return NextHop::At(mac);
        }
        let next_hop = session.next_hop().address;
        match self.neighbours.resolve(now, next_hop) {
            Resolution::Known(mac) => {
                if let Some(session) = self.outbound.as_mut() {
                    session.resolved_to(mac);
                }
                NextHop::At(mac)
            }
            Resolution::Ask => {
                let request = ArpRequest {
                    mac: self.mac,
                    address: self.address,
                    target_address: next_hop,
                };
                match request.write(out) {
                    Ok(len) => NextHop::Asked(len),
                    // The cache has already recorded that a request was handed
                    // over, so it answers `Ask` again once its own timeout has
                    // passed rather than waiting on a frame that never left.
                    Err(_) => NextHop::Waiting,
                }
            }
            Resolution::Waiting => NextHop::Waiting,
            Resolution::Unreachable => {
                NextHop::Over(self.end_outbound(Ended::NextHopUnreachable, out))
            }
            Resolution::NoRoom => NextHop::Over(self.end_outbound(Ended::NoRoomToResolve, out)),
        }
    }

    /// Ask about the next hop, and dial once there is a `SYN` to compose.
    ///
    /// The dial happens **whether or not the hardware address is known**, and
    /// that is the decision the neighbour cache is built around: the `SYN` is
    /// recorded by the transport and re-sent under RFC 6298's backoff, so a
    /// segment dropped for want of an address costs one retransmission timeout,
    /// while a queue would cost a buffer, a bound, and a second answer to what
    /// happens when that bound is reached.
    fn resolve_outbound(&mut self, now: Monotonic, out: &mut [u8]) -> Polled {
        match self.next_hop(now, out) {
            // A request is outstanding and its answer is not due. The dial goes
            // ahead regardless, so the transport's timer is armed while the
            // resolution runs and the retransmission finds the entry resolved.
            NextHop::At(_) | NextHop::Waiting => self.dial(now, out),
            NextHop::Asked(len) => Polled::Frame { len },
            NextHop::Over(polled) => polled,
        }
    }

    /// Compose the `SYN`, and address it if this end can.
    fn dial(&mut self, now: Monotonic, out: &mut [u8]) -> Polled {
        let Some((destination, port)) = self
            .outbound
            .as_ref()
            .map(|session| (session.destination(), session.port()))
        else {
            return Polled::Idle;
        };
        let dialled = {
            let Some(segment) = out.get_mut(Ipv4Frame::PAYLOAD_AT..) else {
                return Polled::Handled;
            };
            self.tcp.connect(now, destination, port, segment)
        };
        let dialled = match dialled {
            Ok(dialled) => dialled,
            Err(error) => return self.end_outbound(Ended::refused(error), out),
        };
        OutboundCounters::bump(&mut self.outbound_counters.dialled);
        let mac = self.outbound.as_ref().and_then(Session::peer_mac);
        if let Some(session) = self.outbound.as_mut() {
            session.dialled(dialled.connection);
            session.dialled_once();
        }
        let Some(mac) = mac else {
            // Dropped, not queued, and typed: the record the transport just made
            // is what re-sends it.
            OutboundCounters::bump(&mut self.outbound_counters.dropped_unresolved);
            return Polled::Handled;
        };
        // The return path is installed from the *resolution* rather than from a
        // frame, there being no frame yet — and it is never re-learned from one,
        // so whoever answers cannot redirect what this end sends next.
        self.remember(dialled.connection, mac, destination);
        Polled::Frame {
            len: self.frame_around((mac, destination), dialled.len, out),
        }
    }

    /// Carry a dialled session forward: send the request, read the answer, close.
    fn advance_outbound(&mut self, now: Monotonic, out: &mut [u8]) -> Polled {
        let Some(connection) = self.outbound.as_ref().and_then(Session::connection) else {
            return self.end_outbound(Ended::Lost, out);
        };
        let Some(state) = self.tcp.connection(connection).map(Connection::state) else {
            // The transport no longer holds it, and **which of the ways it can go
            // this was is the session's own to say**: it watched every segment
            // that arrived on this connection, so a reset, an acknowledgement of
            // what was never sent, and a budget that ran out in silence are three
            // endings here rather than one. Only a disappearance none of those
            // explains reaches the residual.
            let ended = self.outbound.as_ref().map_or(Ended::Lost, |session| {
                if session.peer_closed() {
                    Ended::Answered
                } else {
                    session.ending()
                }
            });
            return self.end_outbound(ended, out);
        };
        // The resolution may only have completed after the `SYN` was dropped, so
        // it is carried on here — and it is what ends a session whose next hop
        // never answers, the dial itself having nothing to time out against
        // beyond the transport's own silence.
        match self.next_hop(now, out) {
            NextHop::At(mac) => {
                let destination = self
                    .outbound
                    .as_ref()
                    .map_or(self.address, Session::destination);
                self.remember(connection, mac, destination);
            }
            NextHop::Asked(len) => return Polled::Frame { len },
            NextHop::Waiting => {}
            NextHop::Over(polled) => return polled,
        }
        let path = self.path_of(connection);
        match state {
            // The handshake is not done. Nothing is owed: the transport's own
            // retransmission is what re-sends the `SYN`, and a segment composed
            // here would be a second one.
            State::SynSent | State::SynReceived => Polled::Idle,
            State::Established | State::CloseWait => self.drive_outbound(now, path, out),
            // This end has closed and owes nothing but the last acknowledgement,
            // which the transport composes on the segment that arrives.
            State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::TimeWait
            | State::LastAck
            | State::Closed => {
                if let Some(session) = self.outbound.as_mut() {
                    session.enter(Phase::Closing);
                }
                Polled::Idle
            }
        }
    }

    /// Send whatever an established session owes: the rest of its request, then
    /// its own close once the peer has finished.
    fn drive_outbound(
        &mut self,
        now: Monotonic,
        path: Option<(MacAddress, Ipv4Address)>,
        out: &mut [u8],
    ) -> Polled {
        let Some(connection) = self.outbound.as_ref().and_then(Session::connection) else {
            return Polled::Idle;
        };
        let request_out = self.outbound.as_ref().is_some_and(Session::request_out);
        if !request_out {
            let sent = {
                let Self { outbound, tcp, .. } = self;
                let Some(session) = outbound.as_ref() else {
                    return Polled::Idle;
                };
                let Some(segment) = out.get_mut(Ipv4Frame::PAYLOAD_AT..) else {
                    return Polled::Idle;
                };
                tcp.send(now, connection, session.unsent(), segment)
            };
            let Ok(sent) = sent else {
                // The peer's window is closed or every record slot is taken.
                // Neither is a failure and neither is answered by composing
                // anything: an acknowledgement is what opens the window again.
                return Polled::Idle;
            };
            self.outbound_counters.request_bytes = self
                .outbound_counters
                .request_bytes
                .saturating_add(sent.bytes as u64);
            // The oldest range the transport still holds, read straight after
            // the first send: the handshake's `SYN` is acknowledged by the time
            // a connection can carry data, so that range is the request's own
            // beginning and nothing else.
            let oldest = self
                .tcp
                .connection(connection)
                .and_then(Connection::oldest_range);
            if let Some(session) = self.outbound.as_mut() {
                if let Some((sequence, _)) = oldest {
                    session.note_base(sequence);
                }
                session.took(sent.bytes);
                session.enter(if session.request_out() {
                    Phase::Reading
                } else {
                    Phase::Sending
                });
            }
            return match path {
                Some(path) => Polled::Frame {
                    len: self.frame_around(path, sent.len, out),
                },
                None => {
                    OutboundCounters::bump(&mut self.outbound_counters.dropped_unresolved);
                    Polled::Handled
                }
            };
        }
        // The request is out. This end closes once the peer has, which is what
        // makes the exchange one request and one answer rather than a stream
        // whose end nobody states.
        let peer_closed = self.outbound.as_ref().is_some_and(Session::peer_closed);
        if !peer_closed {
            if let Some(session) = self.outbound.as_mut() {
                session.enter(Phase::Reading);
            }
            return Polled::Idle;
        }
        let closed = {
            let Some(segment) = out.get_mut(Ipv4Frame::PAYLOAD_AT..) else {
                return Polled::Idle;
            };
            self.tcp.close(now, connection, segment)
        };
        let Ok(len) = closed else {
            return Polled::Idle;
        };
        if let Some(session) = self.outbound.as_mut() {
            session.enter(Phase::Closing);
        }
        match path {
            Some(path) => Polled::Frame {
                len: self.frame_around(path, len, out),
            },
            None => {
                OutboundCounters::bump(&mut self.outbound_counters.dropped_unresolved);
                Polled::Handled
            }
        }
    }

    /// End the session under `ended`, counting it and giving the transport back
    /// the connection it was composed on.
    ///
    /// The release is what makes the *next* dial to the same destination and
    /// port a new connection rather than one this node's own table refuses: a
    /// session that ends at the resolution leaves behind a `SYN` the transport
    /// still holds — that segment was dropped for want of a hardware address, so
    /// nothing at the far end will ever answer it and nothing but this ends it —
    /// and a session that ends any other way leaves either nothing or this end's
    /// own record of a finished close. What each of those owes the peer is the
    /// transport's decision and not this one's.
    fn end_outbound(&mut self, ended: Ended, out: &mut [u8]) -> Polled {
        let released = self.release_dialled(out);
        if let Some(session) = self.outbound.as_mut() {
            session.enter(Phase::Ended(ended));
        }
        let count = if ended.succeeded() {
            &mut self.outbound_counters.answered
        } else {
            &mut self.outbound_counters.failed
        };
        OutboundCounters::bump(count);
        released
    }

    /// Hand the transport back the connection this session dialled, writing
    /// whatever the release owes the peer into `out`.
    fn release_dialled(&mut self, out: &mut [u8]) -> Polled {
        let Some(connection) = self.outbound.as_ref().and_then(Session::connection) else {
            return Polled::Handled;
        };
        // Read before the release, which frees the path along with the slot the
        // reconciliation below matches it against.
        let path = self.path_of(connection);
        let composed = out
            .get_mut(Ipv4Frame::PAYLOAD_AT..)
            .map(|segment| self.tcp.release(connection, segment))
            .and_then(Released::composed);
        self.reconcile();
        match (path, composed) {
            (Some(path), Some(len)) => Polled::Frame {
                len: self.frame_around(path, len, out),
            },
            // A reset with nowhere to go, which is what a released connection
            // this end never resolved a hardware address for produces: it is
            // dropped exactly as the `SYN` before it was, the transport having
            // already forgotten the connection either way.
            _ => Polled::Handled,
        }
    }

    /// Unlike ARP, an IPv4 datagram is answered only when it was addressed to
    /// this port's own MAC: nothing here delivers a broadcast or multicast
    /// datagram locally.
    fn ipv4(&mut self, now: Option<Monotonic>, ethernet: &Ethernet<'_>, out: &mut [u8]) -> Outcome {
        if ethernet.header.destination != self.mac {
            return Outcome::NotForUs;
        }
        let packet = match Ipv4Packet::parse(ethernet.payload) {
            Ok(packet) => packet,
            Err(error) => return Outcome::Malformed(Malformed::Frame(error)),
        };
        let header = packet.header();
        if header.destination != self.address {
            return Outcome::NotForUs;
        }
        if let Some(refusal) = self.refuse_sender(ethernet.header.source, header.source) {
            return refusal;
        }
        if header.is_fragment() {
            return Outcome::Unhandled(Unhandled::Fragmented);
        }
        if header.protocol == Protocol::TCP {
            // The one thing read out of a segment before anything about it has
            // been verified, and it decides only which transport verifies it.
            // A segment too short to carry the field goes to the HTTP port's
            // stack, whose parse counts it as the malformed segment it is —
            // so no segment goes uncounted for being unreadable here.
            return match lfw_tcp::peeked_destination_port(packet.payload()) {
                Some(ONBOARDING_PORT) => self.onboarding(now, ethernet.header.source, &packet, out),
                _ => self.tcp(now, ethernet.header.source, &packet, out),
            };
        }
        if header.protocol != Protocol::ICMP {
            return Outcome::Unhandled(Unhandled::Protocol(Some(header.protocol)));
        }
        let echo = match IcmpEcho::parse_request(packet.payload()) {
            Ok(echo) => echo,
            Err(IcmpError::NotAnEchoRequest { .. }) => {
                return Outcome::Unhandled(Unhandled::NotAnEchoRequest);
            }
            Err(error) => return Outcome::Malformed(Malformed::Icmp(error)),
        };
        let reply = EchoReply {
            destination_mac: ethernet.header.source,
            source_mac: self.mac,
            source: self.address,
            destination: header.source,
            echo,
        };
        match reply.write(out) {
            Ok(len) => Outcome::EchoReply { len },
            Err(error) => Outcome::ReplyRefused(error),
        }
    }

    /// Hand one segment to the **onboarding** transport and keep whatever it
    /// delivered for the consumer above this crate.
    ///
    /// Nothing is composed in answer beyond what the transport itself owes —
    /// an acknowledgement, a handshake, a reset. What the consumer answers with
    /// goes out of [`poll_onboarding`](Self::poll_onboarding) instead, because
    /// the consumer is another protection domain and is not reachable inside
    /// the frame that provoked it.
    fn onboarding(
        &mut self,
        now: Option<Monotonic>,
        peer_mac: MacAddress,
        packet: &Ipv4Packet<'_>,
        out: &mut [u8],
    ) -> Outcome {
        let Some(now) = now else {
            return Outcome::Unclocked;
        };
        let source = packet.header().source;
        let received = {
            let Some(segment) = out.get_mut(Ipv4Frame::PAYLOAD_AT..) else {
                return Outcome::ReplyRefused(ReplyError::DoesNotFit {
                    needed: Ipv4Frame::PAYLOAD_AT,
                    capacity: out.len(),
                });
            };
            self.onboarding
                .receive(now, source, packet.payload(), segment)
        };
        let outcome = received.outcome;
        let len = received.emitted;
        let Some(connection) = received.connection else {
            if len == 0 {
                return Outcome::Onboarding { len: 0, outcome };
            }
            // A reset for a 4-tuple this port holds no connection for: the pair
            // the frame arrived from is the whole of the address, and the
            // segment still needs its two headers.
            return Outcome::Onboarding {
                len: self.frame_around((peer_mac, source), len, out),
                outcome,
            };
        };
        // A handle the transport no longer holds is not a session to take up:
        // a reset frees the slot inside the very call that reports the
        // connection it was on, and adopting it would hold this port's one slot
        // for a connection that is already gone. The reconciliation at the foot
        // of this method is what releases the session it *was* on.
        if self.onboarding.connection(connection).is_some() {
            self.stream.accepted(connection, peer_mac, source);
        }
        if !received.data.is_empty() {
            self.stream.take(received.data);
        }
        if received.peer_closed {
            self.stream.note_peer_closed();
        }
        // Lossless: bounded by the inbound array.
        let room = self.stream.room() as u32;
        self.onboarding.set_receive_window(connection, room);
        // Read before the reconciliation, which frees the session of a
        // connection this very segment ended — a reset, or the last
        // acknowledgement of a close.
        let path = self.stream.peer().unwrap_or((peer_mac, source));
        self.stream.reconcile(&self.onboarding);
        if len == 0 {
            return Outcome::Onboarding { len: 0, outcome };
        }
        Outcome::Onboarding {
            len: self.frame_around(path, len, out),
            outcome,
        }
    }

    /// Send whatever the onboarding session now owes: a timer of its own first,
    /// then the bytes its consumer answered with, then its close.
    ///
    /// Driven in a loop until it answers [`Polled::Idle`], as the three polls
    /// beside it are. Each answer either hands a range to the transport, frees
    /// the connection or moves a deadline, so the loop terminates.
    pub fn poll_onboarding(&mut self, now: Monotonic, out: &mut [u8]) -> Polled {
        self.stream.reconcile(&self.onboarding);
        let timeout = {
            let Some(segment) = out.get_mut(Ipv4Frame::PAYLOAD_AT..) else {
                return Polled::Idle;
            };
            self.onboarding.poll_timeouts(now, segment)
        };
        if let Some(timeout) = timeout {
            // Read before the answer: a connection the transport abandoned or
            // reaped is already gone from its table by the time it says so.
            let path = self.stream.peer();
            let composed = out.get_mut(Ipv4Frame::PAYLOAD_AT..).and_then(|segment| {
                self.stream
                    .answer(&mut self.onboarding, now, timeout, segment)
            });
            self.stream.reconcile(&self.onboarding);
            return match (path, composed) {
                (Some(path), Some(len)) => Polled::Frame {
                    len: self.frame_around(path, len, out),
                },
                _ => Polled::Handled,
            };
        }
        let path = self.stream.peer();
        let composed = out
            .get_mut(Ipv4Frame::PAYLOAD_AT..)
            .and_then(|segment| self.stream.drive(&mut self.onboarding, now, segment));
        match (path, composed) {
            (Some(path), Some(len)) => Polled::Frame {
                len: self.frame_around(path, len, out),
            },
            // A segment the transport took and this end has nowhere to send:
            // the transport holds the range and will ask for it again.
            (None, Some(_)) => Polled::Handled,
            (_, None) => Polled::Idle,
        }
    }

    /// The onboarding session, for a consumer reading what arrived.
    #[must_use]
    pub const fn stream(&self) -> &Stream {
        &self.stream
    }

    /// The onboarding session, for a consumer answering it.
    pub const fn stream_mut(&mut self) -> &mut Stream {
        &mut self.stream
    }

    /// What the onboarding port's own stream has done, one field per decision.
    #[must_use]
    pub const fn stream_counters(&self) -> StreamCounters {
        self.stream.counters()
    }

    /// What the onboarding port's transport has seen, one field per cause. Its
    /// own table and its own numbers: see [`tcp_counters`](Self::tcp_counters)
    /// for the HTTP port's.
    #[must_use]
    pub const fn onboarding_counters(&self) -> TcpCounters {
        self.onboarding.counters()
    }

    /// Hand one segment to the transport, drive the server over it, and compose
    /// whatever leaves.
    ///
    /// The segment is written where it will finally sit — at
    /// [`Ipv4Frame::PAYLOAD_AT`] — and the headers are stamped in front of it
    /// afterwards, so the payload is written exactly once.
    fn tcp(
        &mut self,
        now: Option<Monotonic>,
        peer_mac: MacAddress,
        packet: &Ipv4Packet<'_>,
        out: &mut [u8],
    ) -> Outcome {
        let Some(now) = now else {
            return Outcome::Unclocked;
        };
        let source = packet.header().source;
        // The delivered bytes are carried out of this block rather than
        // re-derived from the frame: they are a subslice of the *datagram's*
        // payload, whose borrow outlives the transport's borrow of `out`, and
        // only the transport knows which subslice — a segment trimmed at its
        // right edge to the receive window delivers its head, and taking the
        // last bytes instead would hand the server a slice it never accepted.
        let received = {
            let Some(segment) = out.get_mut(Ipv4Frame::PAYLOAD_AT..) else {
                return Outcome::ReplyRefused(ReplyError::DoesNotFit {
                    needed: Ipv4Frame::PAYLOAD_AT,
                    capacity: out.len(),
                });
            };
            self.tcp.receive(now, source, packet.payload(), segment)
        };
        let outcome = received.outcome;
        let mut len = received.emitted;

        // The transport frees connections on its own — an eviction under table
        // pressure being the one no timeout announces — so what this crate holds
        // per connection is reconciled against its table before a new one is
        // given room in either.
        self.reconcile();

        let Some(connection) = received.connection else {
            if len == 0 {
                return Outcome::Tcp { len: 0, outcome };
            }
            // A reset for a 4-tuple this endpoint holds no connection for. There
            // is no return path to look up and none to remember, so the pair the
            // frame arrived from is the whole of the address — and the segment
            // still needs its two headers, without which the length reported
            // here would name a segment with uninitialised bytes in front of it.
            return Outcome::Tcp {
                len: self.frame_around((peer_mac, source), len, out),
                outcome,
            };
        };
        // A connection this end dialled keeps the path the *resolution* chose:
        // its frames' Ethernet source is whatever answered, so learning from one
        // would let a station on the link take over a conversation this node
        // began by answering it once. A connection a peer opened has no other
        // source of a path, and this is it.
        if !self.is_outbound(connection) {
            self.remember(connection, peer_mac, source);
        }

        if self.is_outbound(connection) {
            // Before anything is made of the segment: that one arrived at all is
            // the fact separating a station that said nothing from one that
            // answered badly, and the two resets beside it are what name which
            // way it answered badly. Recorded here rather than derived from the
            // transport's own totals, because those span every connection on
            // this port and would attribute somebody else's reset to the dial.
            let misacknowledged = match outcome {
                TcpOutcome::Rejected(Rejection::Connection(Refusal::UnacceptableAck {
                    claimed,
                    expected,
                })) => Some((claimed.raw(), expected.raw())),
                _ => None,
            };
            if let Some(session) = self.outbound.as_mut() {
                session.segment_arrived(received.peer_reset, received.reset_sent);
                if let Some((claimed, expected)) = misacknowledged {
                    session.note_misacknowledged(claimed, expected);
                }
            }
            if !received.data.is_empty() {
                self.take_outbound(received.data);
            }
            if received.peer_closed
                && let Some(session) = self.outbound.as_mut()
            {
                session.note_peer_closed();
            }
        } else {
            if !received.data.is_empty() {
                self.http.take(now, connection, received.data);
            }
            if received.peer_closed {
                self.http.note_peer_closed(connection);
            }
        }
        if let Some(segment) = out.get_mut(Ipv4Frame::PAYLOAD_AT..)
            && let Some(composed) = self.http.drive(&mut self.tcp, now, connection, segment)
        {
            // A data segment or a `FIN` carries the acknowledgement a bare one
            // would have, so replacing the transport's answer loses nothing.
            len = composed;
        }
        // Read before the reconciliation, which frees the path of a connection
        // the exchange just ended.
        let path = self.path_of(connection).unwrap_or((peer_mac, source));
        self.reconcile();
        self.http.sweep(&self.tcp);
        if len == 0 {
            return Outcome::Tcp { len: 0, outcome };
        }
        Outcome::Tcp {
            len: self.frame_around(path, len, out),
            outcome,
        }
    }

    /// Answer one of the outbound connection's own timers.
    ///
    /// A re-composed control segment is already in `out` and needs nothing; a
    /// range of the request is re-supplied out of the session, which is why the
    /// session holds it. A dial the transport gave up on produces no segment
    /// here — an unanswered dial is abandoned in silence — and is reported to the
    /// caller by the next poll, which finds the connection gone.
    fn answer_outbound(
        &mut self,
        now: Monotonic,
        timeout: Timeout,
        out: &mut [u8],
    ) -> Option<usize> {
        match timeout {
            Timeout::Resent { len, .. } | Timeout::Abandoned { len, .. } => {
                // A control segment re-composed while the session is still
                // dialling is its `SYN` going out again, and nothing else: the
                // phase leaves `Dialling` the moment the handshake completes.
                // That count is what an operator reads against a station that
                // answered none of them.
                if let Some(session) = self.outbound.as_mut()
                    && matches!(timeout, Timeout::Resent { .. })
                    && session.phase() == Phase::Dialling
                {
                    session.dialled_once();
                }
                (len > 0).then_some(len)
            }
            Timeout::Reaped { .. } => None,
            Timeout::Retransmit {
                connection,
                sequence,
                len,
            } => {
                let at = self
                    .outbound
                    .as_ref()
                    .and_then(|session| session.offset_of(sequence))?;
                let Self { outbound, tcp, .. } = self;
                let payload = outbound.as_ref()?.range(at, usize::from(len))?;
                let segment = out.get_mut(Ipv4Frame::PAYLOAD_AT..)?;
                tcp.retransmit(now, connection, sequence, payload, segment)
                    .ok()
            }
        }
    }

    /// Whether `connection` is the one the outbound session dialled.
    fn is_outbound(&self, connection: ConnectionId) -> bool {
        self.outbound
            .as_ref()
            .and_then(Session::connection)
            .is_some_and(|dialled| dialled == connection)
    }

    /// Keep what the peer said, counting what there was no room for.
    fn take_outbound(&mut self, data: &[u8]) {
        let Some(session) = self.outbound.as_mut() else {
            return;
        };
        let (kept, dropped) = session.take(data);
        self.outbound_counters.answer_bytes = self
            .outbound_counters
            .answer_bytes
            .saturating_add(kept as u64);
        self.outbound_counters.answer_overflowed = self
            .outbound_counters
            .answer_overflowed
            .saturating_add(dropped as u64);
    }

    /// Stamp the Ethernet and IPv4 headers in front of a segment already written at
    /// [`Ipv4Frame::PAYLOAD_AT`], answering the frame's length.
    ///
    /// It cannot refuse, and the zero is a value rather than an assertion because
    /// no panic is admissible here: `len` bytes were written into `out[PAYLOAD_AT..]`,
    /// so `out` is at least as long as the frame needs. A zero would mean this
    /// crate wrote a segment somewhere other than where it said.
    fn frame_around(
        &self,
        (peer_mac, peer): (MacAddress, Ipv4Address),
        len: usize,
        out: &mut [u8],
    ) -> usize {
        Ipv4Frame {
            destination_mac: peer_mac,
            source_mac: self.mac,
            source: self.address,
            destination: peer,
            protocol: Protocol::TCP,
        }
        .write(out, len)
        .unwrap_or(0)
    }

    /// Remember where a connection's frames come from.
    fn remember(&mut self, connection: ConnectionId, mac: MacAddress, address: Ipv4Address) {
        let existing = self
            .paths
            .iter()
            .position(|path| path.is_some_and(|path| path.connection == connection));
        let Some(index) = existing.or_else(|| self.paths.iter().position(Option::is_none)) else {
            return;
        };
        if let Some(slot) = self.paths.get_mut(index) {
            *slot = Some(ReturnPath {
                connection,
                mac,
                address,
            });
        }
    }

    fn path_of(&self, connection: ConnectionId) -> Option<(MacAddress, Ipv4Address)> {
        self.paths
            .iter()
            .flatten()
            .find(|path| path.connection == connection)
            .map(|path| (path.mac, path.address))
    }

    /// Release everything this crate holds for connections the transport no
    /// longer does: the return paths here, and the request and response state in
    /// the server above.
    ///
    /// Reconciliation rather than a notification per release, because the
    /// transport takes a slot back for reasons that produce no event at all —
    /// an eviction under table pressure is a `SYN` answered, not a timeout — and
    /// a release nobody was told about is a return path and a request slot lost
    /// for the life of the domain. Bounded by the table, so it is a walk of
    /// [`TCP_CONNECTIONS`] entries wherever it is called.
    fn reconcile(&mut self) {
        for index in 0..TCP_CONNECTIONS {
            let held = self.paths.get(index).copied().flatten();
            let Some(path) = held else { continue };
            if self.tcp.connection(path.connection).is_none()
                && let Some(slot) = self.paths.get_mut(index)
            {
                *slot = None;
            }
        }
        self.http.reconcile(&self.tcp);
    }

    /// The two rules that decide whether a reply can be addressed at all, applied
    /// identically to every protocol: a station this endpoint may answer, on the
    /// link it is attached to.
    fn refuse_sender(&self, mac: MacAddress, address: Ipv4Address) -> Option<Outcome> {
        if !mac.is_unicast() || !address.is_unicast() {
            return Some(Outcome::Unhandled(Unhandled::SourceNotUnicast));
        }
        if !address.shares_prefix(self.address, self.prefix_length) {
            return Some(Outcome::Unhandled(Unhandled::SourceOffLink));
        }
        None
    }
}

#[cfg(test)]
mod tests;
