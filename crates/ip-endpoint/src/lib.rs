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
//! Two of CONCEPT §7.1's five at once.
//!
//! * **Untrusted network traffic.** Every byte handed to [`Endpoint::handle`] was
//!   put on a wire by whatever is attached to the port, so each is parsed through
//!   `net_headers` or `lfw_tcp` and refused by a typed error rather than believed.
//! * **The management-plane attacker.** The port this runs on is the management port
//!   (CONCEPT §9.1), so the station on it is the party that will one day open a TLS
//!   session to the management API, and everything it sends before then arrives
//!   here. A reply is a frame the appliance originates, and what decides whether one
//!   is composed is entirely below.
//!
//! # Every reply is a decision, so every decision is counted
//!
//! An [`Outcome`] is returned *and* recorded in [`EndpointCounters`], the only
//! evidence a port with an address is doing anything: a station probing an endpoint
//! that silently refuses everything looks exactly like an idle link. The counters
//! follow `routing::DropCounters` — saturating, never reset — because the rate is
//! the attacker's to choose.
//!
//! # The transport, and the one thing a connection does today
//!
//! `lfw_tcp` is the stack; on it sits [`echo::Echo`], which sends back what it was
//! sent — a complete byte-stream application rather than a stub, because the only
//! way to know a transport carries a stream is to carry one, and replaced wholesale
//! by the management HTTP server rather than extended (ENG-6). Two consequences: an
//! endpoint carries state between frames, so it is no longer `Copy`; and it needs a
//! clock, every transport deadline being stated against a `lfw_clock::Monotonic` the
//! caller reads — with none, a segment is [`Outcome::Unclocked`] and ARP and ICMP go
//! on as before.
//!
//! # Deliberate narrowness, and what each exclusion costs
//!
//! * **No ARP cache, and no ARP request is ever sent.** A reply goes to the MAC its
//!   request arrived from, which is on the frame, and a connection's return path is
//!   remembered with the connection ([`ReturnPath`]) rather than by address.
//! * **No address defence.** An RFC 5227 probe — sender address 0.0.0.0 — is
//!   refused rather than answered, so a second station claiming this address is not
//!   contradicted; answering one needs conflict state that does not exist.
//! * **A reply is only ever composed for a neighbour.** The sender must share our
//!   prefix: with no route table and no gateway, a reply to an off-link source would
//!   leave under a next hop this endpoint never chose — `routing`'s
//!   `DropReason::NoRoute`.
//! * **Unicast only, at both layers.** A group MAC or a non-unicast IPv4 source is
//!   refused rather than replied to: a reply addressed to a group is a reflector.
//! * **ICMP is echo and nothing else** — no unreachable, no redirect, no timestamp,
//!   and no fragment, an echo split across two datagrams being unreassemblable here.
//! * **One TCP port, and no UDP.** A segment for any other port is refused by
//!   `lfw_tcp` and counted there; a UDP datagram is [`Unhandled::Protocol`], as is
//!   every protocol but ICMP and TCP. One service, one port.
//!
//! # No allocator, and no buffer this crate owns
//!
//! [`Endpoint::handle`] writes its reply into storage the caller owns and returns
//! its length, so the caller decides where a reply is composed — in the protection
//! domain that runs this, a buffer it has just taken from a pool. Nothing here
//! allocates: the connection table and the echo's held bytes are fixed arrays sized
//! by the constants below.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

use lfw_clock::Monotonic;
use lfw_tcp::{ConnectionId, Outcome as TcpOutcome, TcpCounters, TcpStack, Timeout};

/// Re-exported rather than restated: the per-boot secret an initial sequence
/// number is derived from is obtained by the protection domain, and the segment
/// types are what a *test* composes one out of. Both reach this crate rather than
/// the transport under it, so neither caller needs a dependency on both.
pub use lfw_tcp::{Flags, IsnSecret, Outgoing, SeqNumber};
use net_headers::{
    ArpError, ArpOperation, ArpPacket, ArpReply, EchoReply, EtherType, Ethernet, IcmpEcho,
    IcmpError, Ipv4Address, Ipv4Frame, Ipv4Packet, MAX_PREFIX_LENGTH, MacAddress, ParseError,
    Protocol, ReplyError,
};

pub mod echo;

use echo::{ECHO_CAPACITY, Echo, EchoCounters};

/// Connections one management port holds at once, and so the bound a connection
/// flood is answered by (ENG-4).
///
/// Eight rather than one, because an operator's browser opens several at a time;
/// rather than many, because each carries a slot of [`ECHO_CAPACITY`] bytes in the
/// protection domain's own memory.
pub const TCP_CONNECTIONS: usize = 8;

/// The port this endpoint listens on: the management HTTP port. A constant rather
/// than a configured value because the service is the constant — CONCEPT §11 puts
/// `/metrics`, `/config` and `/logs` on the management interface, and a port a
/// document could move is one a scraper could not find.
pub const MANAGEMENT_PORT: u16 = 80;

/// The largest payload this endpoint composes in one segment. Equal to
/// [`ECHO_CAPACITY`], so a peer's whole window fits one segment: the two numbers are
/// one decision, asserted equal below rather than written twice.
pub const TCP_MSS: u16 = 1024;

const _: () = assert!(TCP_MSS as usize == ECHO_CAPACITY);

/// Why a configured pair cannot be an endpoint's.
///
/// The same three rules `config::validate` holds a `<management>` element to, so a
/// document that reached the appliance cannot produce one of these — and this type
/// is what makes that a check rather than an assumption, an image crossing a
/// protection-domain boundary between the two.
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
/// variant is one this endpoint *could* have been built to answer and deliberately
/// is not; one that is simply not ours is [`Outcome::NotForUs`], and one that is not
/// what it claims is [`Outcome::Malformed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unhandled {
    /// An 802.1Q tag, with no sub-interface to interpret it.
    VlanTagged,
    /// Neither ARP nor IPv4.
    EtherType(EtherType),
    /// An ARP reply, or an operation this endpoint does not answer.
    ArpNotARequest,
    /// IPv4, but not ICMP.
    Protocol(Protocol),
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
    /// Every variant, so a counter table is built by iteration rather than a list
    /// that drifts from the enum.
    pub const ALL: [Self; 9] = [
        Self::VlanTagged,
        Self::EtherType(EtherType(0)),
        Self::ArpNotARequest,
        Self::Protocol(Protocol(0)),
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
            Self::ArpNotARequest => "arp_not_a_request",
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
            Self::ArpNotARequest => 2,
            Self::Protocol(_) => 3,
            Self::NotAnEchoRequest => 4,
            Self::Fragmented => 5,
            Self::SourceNotUnicast => 6,
            Self::SourceOffLink => 7,
            Self::ArpSenderMacMismatch => 8,
        }
    }
}

impl fmt::Display for Unhandled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EtherType(ether_type) => write!(f, "{} {ether_type}", self.name()),
            Self::Protocol(protocol) => write!(f, "{} {protocol}", self.name()),
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
    /// A TCP segment was processed. `len` is what the transport composed in answer,
    /// zero where it composed nothing; what became of the segment is in
    /// [`Outcome::tcp`] and every cause is counted in [`Endpoint::tcp_counters`].
    Tcp { len: usize, outcome: TcpOutcome },
    /// A TCP segment arrived before this node had established a time. **Ours**, not
    /// the sender's: a node that has not finished booting is not a peer
    /// misbehaving. ARP and ICMP need no clock and are unaffected.
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
            Self::Tcp { len, .. } if len > 0 => Some(len),
            Self::Tcp { .. }
            | Self::Unclocked
            | Self::NotForUs
            | Self::Unhandled(_)
            | Self::Malformed(_)
            | Self::ReplyRefused(_) => None,
        }
    }

    /// What the transport made of the segment, where this was one.
    #[must_use]
    pub const fn tcp(self) -> Option<TcpOutcome> {
        match self {
            Self::Tcp { outcome, .. } => Some(outcome),
            _ => None,
        }
    }
}

/// What an endpoint has seen, in the shape the metrics endpoint (CONCEPT §11) will
/// scrape. Monotonic and saturating on `routing::DropCounters`' terms: no reset,
/// because a scrape differences successive samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointCounters {
    /// ARP requests for our address, answered.
    pub arp_replies: u64,
    /// Echo requests for our address, answered.
    pub echo_replies: u64,
    /// Frames addressed to somebody else.
    pub not_for_us: u64,
    /// Frames no parser would read. One counter for every [`Malformed`]: this
    /// endpoint has no surface to report which (MONITORING.md), so a finer split
    /// would be numbers nobody reads.
    pub malformed: u64,
    /// Replies decided on and not written: a caller-side failure, and the one count
    /// here that is not about the wire.
    pub reply_refused: u64,
    /// TCP segments handed to the transport, whatever it made of them; what each
    /// became is counted in [`Endpoint::tcp_counters`], one field per cause.
    pub tcp_segments: u64,
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
            echo_replies: 0,
            not_for_us: 0,
            malformed: 0,
            reply_refused: 0,
            tcp_segments: 0,
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
        // ENG-5 admitting none on a path a frame reaches.
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
            .saturating_add(self.not_for_us)
            .saturating_add(self.malformed)
            .saturating_add(self.reply_refused)
            .saturating_add(self.tcp_segments)
            .saturating_add(self.unclocked)
            .saturating_add(self.unhandled_total())
    }

    /// One place deciding which count an outcome moves, so no path through
    /// [`Endpoint::handle`] returns an outcome it did not record.
    fn record(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::ArpReply { .. } => self.arp_replies = self.arp_replies.saturating_add(1),
            Outcome::EchoReply { .. } => self.echo_replies = self.echo_replies.saturating_add(1),
            Outcome::NotForUs => self.not_for_us = self.not_for_us.saturating_add(1),
            Outcome::Malformed(_) => self.malformed = self.malformed.saturating_add(1),
            Outcome::ReplyRefused(_) => self.reply_refused = self.reply_refused.saturating_add(1),
            Outcome::Tcp { .. } => self.tcp_segments = self.tcp_segments.saturating_add(1),
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
#[derive(Clone, Debug)]
pub struct Endpoint {
    mac: MacAddress,
    address: Ipv4Address,
    prefix_length: u8,
    counters: EndpointCounters,
    tcp: TcpStack<TCP_CONNECTIONS>,
    echo: Echo<TCP_CONNECTIONS>,
    paths: [Option<ReturnPath>; TCP_CONNECTIONS],
}

/// Where one connection's frames arrive from, and so the only pair a segment this
/// endpoint originates unprompted can be addressed to.
///
/// Not an ARP cache and unable to become one: no lookup by address, no ageing, no
/// request ever sent. It is a connection's return path, learned from the frame that
/// opened it and forgotten with it, so bounded by the connection table (ENG-4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReturnPath {
    connection: ConnectionId,
    mac: MacAddress,
    address: Ipv4Address,
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

/// The last `len` bytes of a segment's payload: what the transport delivered in
/// order out of it. Taken from the frame again rather than carried across the
/// transport's borrow of the storage it wrote into, and bounded by the payload.
fn tcp_payload<'a>(packet: &Ipv4Packet<'a>, len: usize) -> &'a [u8] {
    let payload = packet.payload();
    let from = payload.len().saturating_sub(len);
    payload.get(from..).unwrap_or_default()
}

impl Endpoint {
    /// # Errors
    /// [`EndpointError`], for a pair no endpoint can answer under: a MAC that
    /// names no single station, an address no host may hold, or a prefix length
    /// no IPv4 prefix has.
    pub fn new(
        mac: MacAddress,
        address: Ipv4Address,
        prefix_length: u8,
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
            counters: EndpointCounters::new(),
            // The window starts at the echo's whole capacity and is kept equal to
            // its free space from then on, which is what makes it mean what a
            // window means.
            tcp: TcpStack::new(
                address,
                MANAGEMENT_PORT,
                TCP_MSS,
                ECHO_CAPACITY as u32,
                secret,
            ),
            echo: Echo::new(),
            paths: [None; TCP_CONNECTIONS],
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

    #[must_use]
    pub const fn counters(&self) -> EndpointCounters {
        self.counters
    }

    /// What the transport has seen, one field per cause.
    #[must_use]
    pub const fn tcp_counters(&self) -> TcpCounters {
        self.tcp.counters()
    }

    #[must_use]
    pub const fn echo_counters(&self) -> EchoCounters {
        self.echo.counters()
    }

    /// How many connections the port holds, in any state.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.tcp.connections()
    }

    /// Decide what, if anything, to send in reply to one received frame,
    /// writing the reply into `out` and reporting its length in the outcome.
    ///
    /// `now` is `None` on a node with no time yet: ARP and ICMP are answered
    /// regardless, and a TCP segment is refused as [`Outcome::Unclocked`] rather
    /// than processed against a fabricated instant. `out` may be shorter than the
    /// reply, in which case nothing is sent and the outcome says so.
    pub fn handle(&mut self, now: Option<Monotonic>, frame: &[u8], out: &mut [u8]) -> Outcome {
        let outcome = self.decide(now, frame, out);
        self.counters.record(outcome);
        outcome
    }

    /// Take whatever the transport's timers now owe, writing one segment into `out`
    /// and answering its length.
    ///
    /// Called in a loop until it answers `None`: each answer either frees a
    /// connection or moves a deadline, so the loop terminates
    /// (`lfw_tcp::TcpStack::poll_timeouts`). A caller woken only by traffic
    /// therefore reaps on the next frame rather than at the deadline, which is
    /// stated where the protection domain drives it.
    pub fn poll_timeouts(&mut self, now: Monotonic, out: &mut [u8]) -> Option<usize> {
        let timeout = {
            let segment = out.get_mut(Ipv4Frame::PAYLOAD_AT..)?;
            self.tcp.poll_timeouts(now, segment)?
        };
        let connection = timeout_connection(timeout);
        // Read before the answer, because a connection the transport abandoned or
        // reaped is already gone from its table by the time it says so.
        let path = self.path_of(connection);
        let len = {
            let segment = out.get_mut(Ipv4Frame::PAYLOAD_AT..)?;
            self.echo.answer(&mut self.tcp, now, timeout, segment)
        };
        if matches!(timeout, Timeout::Reaped { .. } | Timeout::Abandoned { .. }) {
            self.forget(connection);
        }
        Some(self.frame_around(path?, len?, out))
    }

    fn decide(&mut self, now: Option<Monotonic>, frame: &[u8], out: &mut [u8]) -> Outcome {
        let ethernet = match Ethernet::parse(frame) {
            Ok(ethernet) => ethernet,
            Err(error) => return Outcome::Malformed(Malformed::Frame(error)),
        };
        match ethernet.header.ether_type {
            EtherType::ARP => self.arp(&ethernet, out),
            EtherType::IPV4 => self.ipv4(now, &ethernet, out),
            EtherType::VLAN => Outcome::Unhandled(Unhandled::VlanTagged),
            other => Outcome::Unhandled(Unhandled::EtherType(other)),
        }
    }

    /// An ARP request is broadcast, so this is the one path that accepts a frame
    /// not addressed to our own MAC.
    fn arp(&self, ethernet: &Ethernet<'_>, out: &mut [u8]) -> Outcome {
        let destination = ethernet.header.destination;
        if destination != self.mac && !destination.is_broadcast() {
            return Outcome::NotForUs;
        }
        let request = match ArpPacket::parse(ethernet.payload) {
            Ok(packet) => packet,
            Err(error) => return Outcome::Malformed(Malformed::Arp(error)),
        };
        if request.operation != ArpOperation::Request {
            return Outcome::Unhandled(Unhandled::ArpNotARequest);
        }
        if request.target_address != self.address {
            return Outcome::NotForUs;
        }
        if request.sender_mac != ethernet.header.source {
            return Outcome::Unhandled(Unhandled::ArpSenderMacMismatch);
        }
        if let Some(refusal) = self.refuse_sender(request.sender_mac, request.sender_address) {
            return refusal;
        }
        let reply = ArpReply {
            mac: self.mac,
            address: self.address,
            target_mac: request.sender_mac,
            target_address: request.sender_address,
        };
        match reply.write(out) {
            Ok(len) => Outcome::ArpReply { len },
            Err(error) => Outcome::ReplyRefused(error),
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
            return self.tcp(now, ethernet.header.source, &packet, out);
        }
        if header.protocol != Protocol::ICMP {
            return Outcome::Unhandled(Unhandled::Protocol(header.protocol));
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

    /// Hand one segment to the transport, drive the echo over it, and compose
    /// whatever leaves.
    ///
    /// The segment is written where it will finally sit — at
    /// [`Ipv4Frame::PAYLOAD_AT`] — and the two headers are stamped in front of it
    /// afterwards, so the payload is written exactly once. That is what keeps a
    /// response zero-copy through this crate.
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
        let (outcome, connection, delivered, peer_closed, mut len) = {
            let Some(segment) = out.get_mut(Ipv4Frame::PAYLOAD_AT..) else {
                return Outcome::ReplyRefused(ReplyError::DoesNotFit {
                    needed: Ipv4Frame::PAYLOAD_AT,
                    capacity: out.len(),
                });
            };
            let received = self.tcp.receive(now, source, packet.payload(), segment);
            (
                received.outcome,
                received.connection,
                // Copied out rather than borrowed: the echo takes the bytes, and
                // the borrow of the segment they point into ends with this block.
                received.data.len(),
                received.peer_closed,
                received.emitted,
            )
        };

        let Some(connection) = connection else {
            return Outcome::Tcp { len, outcome };
        };
        // The return path, because there is no ARP cache: a segment sent unprompted
        // can only be addressed to the pair its frames arrive from.
        self.remember(connection, peer_mac, source);

        if delivered > 0 {
            let data = tcp_payload(packet, delivered);
            self.echo.take(connection, data);
        }
        if peer_closed {
            self.echo.note_peer_closed(connection);
        }
        if let Some(segment) = out.get_mut(Ipv4Frame::PAYLOAD_AT..)
            && let Some(composed) = self.echo.drive(&mut self.tcp, now, connection, segment)
        {
            // A data segment or a `FIN` carries the acknowledgement a bare one
            // would have, so replacing the transport's answer loses nothing.
            len = composed;
        }
        if self.tcp.connection(connection).is_none() {
            self.forget(connection);
        }
        if len == 0 {
            return Outcome::Tcp { len: 0, outcome };
        }
        Outcome::Tcp {
            len: self.frame_around((peer_mac, source), len, out),
            outcome,
        }
    }

    /// Stamp the Ethernet and IPv4 headers in front of a segment already written at
    /// [`Ipv4Frame::PAYLOAD_AT`], answering the frame's length.
    ///
    /// It cannot refuse, and the zero is a value rather than an assertion because
    /// ENG-5 admits none here. The proof: `len` bytes were written into
    /// `out[PAYLOAD_AT..]`, so `out` is at least `PAYLOAD_AT + len` long, which is
    /// what the frame needs. A zero would mean this crate wrote a segment somewhere
    /// other than where it said, and would surface as a lost reply.
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

    /// Release a connection's return path and its held bytes: the two are the whole
    /// of what this crate keeps per connection.
    fn forget(&mut self, connection: ConnectionId) {
        for slot in &mut self.paths {
            if slot.is_some_and(|path| path.connection == connection) {
                *slot = None;
            }
        }
        self.echo.release(connection);
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
