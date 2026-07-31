//! The terminal IPv4 endpoint: the appliance answering **for itself** on one
//! addressed port.
//!
//! `routing` decides what to do with a frame addressed to the appliance's MAC
//! and destined for somebody else. This crate is the other half of that
//! sentence — a frame destined for *us* — and today it answers exactly two
//! questions: "who holds this address" (ARP) and "are you there" (ICMP echo).
//! Nothing here forwards, and no frame that reaches it travels onward.
//!
//! # Adversary
//!
//! Two of CONCEPT §7.1's five at once, and this is the first crate in the
//! repository to face the second.
//!
//! * **Untrusted network traffic.** Every byte handed to [`Endpoint::handle`]
//!   was put on a wire by whatever is attached to the port, so each is parsed
//!   through `net_headers` and refused by a typed error rather than believed.
//! * **The management-plane attacker.** The port this runs on is the management
//!   port (CONCEPT §9.1), so the station on it is not a peer the appliance
//!   routes for — it is the party that will one day open a TLS session to the
//!   management API, and everything it sends before then arrives here. Answering
//!   it at all is the first authority the management plane has ever had over
//!   this node's behaviour: a reply is a frame the appliance originates, and
//!   what decides whether one is composed is entirely below.
//!
//! # Every reply is a decision, so every decision is counted
//!
//! An [`Outcome`] is returned *and* recorded in [`EndpointCounters`], which is
//! the only evidence that a port with an address is doing anything: a station
//! probing an endpoint that silently refuses everything looks exactly like an
//! idle link. The counters follow `routing::DropCounters` — saturating, never
//! reset — because the rate is the attacker's to choose and a scrape
//! differences successive samples.
//!
//! # Deliberate narrowness, and what each exclusion costs
//!
//! * **No ARP cache, and no ARP request is ever sent.** Nothing here originates
//!   traffic that needs one: a reply goes to the MAC its request arrived from,
//!   which is on the frame. A cache is state with no reader (ENG-7), and the
//!   day something on this port originates a connection is the day it arrives.
//! * **No address defence.** An RFC 5227 probe — sender address 0.0.0.0 — is
//!   refused rather than answered, so a second station claiming this address is
//!   not contradicted. Answering one is only useful with the cache and the
//!   conflict state above, and neither exists.
//! * **A reply is only ever composed for a neighbour.** The sender must share
//!   our prefix, because there is no route table here and no gateway: a reply to
//!   an off-link source would leave under the MAC that delivered the request,
//!   which is a next hop this endpoint never chose. The same restriction
//!   `routing` expresses as `DropReason::NoRoute`.
//! * **Unicast only, at both layers.** A group MAC or a non-unicast IPv4 source
//!   is refused rather than replied to: a reply addressed to a group is a
//!   reflector, and this endpoint answers into a broadcast domain it does not
//!   own.
//! * **ICMP is echo and nothing else**, so no unreachable, no redirect, no
//!   timestamp — and no fragment, an echo split across two datagrams being one
//!   this endpoint cannot reassemble.
//!
//! # No allocator, and no state between frames
//!
//! [`Endpoint::handle`] writes its reply into storage the caller owns and
//! returns its length, so the caller decides where a reply is composed — in the
//! protection domain that runs this, that is a buffer it has just taken
//! ownership of from a pool. The endpoint itself holds three configured values
//! and its counters, and carries nothing at all from one frame to the next.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

use net_headers::{
    ArpError, ArpOperation, ArpPacket, ArpReply, EchoReply, EtherType, Ethernet, IcmpEcho,
    IcmpError, Ipv4Address, Ipv4Packet, MAX_PREFIX_LENGTH, MacAddress, ParseError, Protocol,
    ReplyError,
};

/// Why a configured pair cannot be an endpoint's.
///
/// The same three rules `config::validate` holds a `<management>` element to, so
/// a document that reached the appliance cannot produce one of these — and this
/// type is what makes that a check rather than an assumption, the image crossing
/// a protection-domain boundary between the two.
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

/// Why a well-formed frame addressed to this endpoint went unanswered.
///
/// Every variant is a frame this endpoint *could* have been built to answer and
/// deliberately is not; a frame that is simply not ours is [`Outcome::NotForUs`]
/// and a frame that is not what it claims is [`Outcome::Malformed`].
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
    /// Every variant, so a counter table is built by iteration rather than by a
    /// list that drifts from the enum.
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
    /// [`ALL`](Self::ALL). The two payload-carrying variants collapse onto their
    /// own slot, the payload being the value refused rather than a second
    /// reason.
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

/// Which parser refused the frame, carrying its own error whole: a rejection is
/// attributable to the byte that caused it rather than to a category.
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

/// What one frame became. The vocabulary is closed and every variant is
/// counted, so there is no outcome a caller can meet and not know about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// An ARP reply of `len` bytes was written into the caller's storage.
    ArpReply { len: usize },
    /// An ICMP echo reply of `len` bytes was written into the caller's storage.
    EchoReply { len: usize },
    /// Addressed to somebody else, at L2 or at L3. The commonest outcome on a
    /// shared segment, and never a fault.
    NotForUs,
    /// Ours, well-formed, and not something this endpoint answers.
    Unhandled(Unhandled),
    /// Not the frame it claims to be.
    Malformed(Malformed),
    /// A reply this endpoint decided on could not be written. Not the sender's
    /// doing: the storage was the caller's, and it is the caller this names.
    ReplyRefused(ReplyError),
}

impl Outcome {
    /// The reply written into the caller's storage, if any.
    #[must_use]
    pub const fn reply(self) -> Option<usize> {
        match self {
            Self::ArpReply { len } | Self::EchoReply { len } => Some(len),
            Self::NotForUs | Self::Unhandled(_) | Self::Malformed(_) | Self::ReplyRefused(_) => {
                None
            }
        }
    }
}

/// What an endpoint has seen, in the shape the metrics endpoint (CONCEPT §11)
/// will scrape.
///
/// Monotonic for the endpoint's life and saturating, on `routing::DropCounters`'
/// terms: there is no reset, because a scrape differences successive samples and
/// a reset would forge a negative rate.
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
    /// would be numbers nobody reads — the choice `routing` made for
    /// `unparsable`.
    pub malformed: u64,
    /// Replies decided on and not written, which is a caller-side failure and
    /// the one count here that is not about the wire.
    pub reply_refused: u64,
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
            unhandled: [0; Unhandled::ALL.len()],
        }
    }

    /// Replies this endpoint composed, whichever kind.
    #[must_use]
    pub const fn replies(&self) -> u64 {
        self.arp_replies.saturating_add(self.echo_replies)
    }

    #[must_use]
    pub fn unhandled(&self, reason: Unhandled) -> u64 {
        match self.unhandled.get(reason.slot()) {
            Some(count) => *count,
            None => 0,
        }
    }

    #[must_use]
    pub fn unhandled_total(&self) -> u64 {
        self.unhandled
            .iter()
            .fold(0u64, |sum, count| sum.saturating_add(*count))
    }

    /// Every frame this endpoint was handed, which is what a caller compares
    /// against the frames it took off its pipeline.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.replies()
            .saturating_add(self.not_for_us)
            .saturating_add(self.malformed)
            .saturating_add(self.reply_refused)
            .saturating_add(self.unhandled_total())
    }

    /// One place deciding which count an outcome moves, so no path through
    /// [`Endpoint::handle`] can return an outcome it did not record.
    fn record(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::ArpReply { .. } => self.arp_replies = self.arp_replies.saturating_add(1),
            Outcome::EchoReply { .. } => self.echo_replies = self.echo_replies.saturating_add(1),
            Outcome::NotForUs => self.not_for_us = self.not_for_us.saturating_add(1),
            Outcome::Malformed(_) => self.malformed = self.malformed.saturating_add(1),
            Outcome::ReplyRefused(_) => self.reply_refused = self.reply_refused.saturating_add(1),
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

/// One addressed port, answering for itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    mac: MacAddress,
    address: Ipv4Address,
    prefix_length: u8,
    counters: EndpointCounters,
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

    /// Decide what, if anything, to send in reply to one received frame,
    /// writing the reply into `out` and reporting its length in the outcome.
    ///
    /// `out` may be shorter than the reply, in which case nothing is sent and
    /// the outcome says so; it is never read, so it may hold anything.
    pub fn handle(&mut self, frame: &[u8], out: &mut [u8]) -> Outcome {
        let outcome = self.decide(frame, out);
        self.counters.record(outcome);
        outcome
    }

    fn decide(&self, frame: &[u8], out: &mut [u8]) -> Outcome {
        let ethernet = match Ethernet::parse(frame) {
            Ok(ethernet) => ethernet,
            Err(error) => return Outcome::Malformed(Malformed::Frame(error)),
        };
        match ethernet.header.ether_type {
            EtherType::ARP => self.arp(&ethernet, out),
            EtherType::IPV4 => self.ipv4(&ethernet, out),
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
    fn ipv4(&self, ethernet: &Ethernet<'_>, out: &mut [u8]) -> Outcome {
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

    /// The two rules that decide whether a reply can be addressed at all,
    /// applied identically to both protocols: a station this endpoint may
    /// answer, on the link it is attached to.
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
