//! The outbound connection: this appliance reaching *out* of its addressed
//! port, rather than answering on it.
//!
//! # Adversary
//!
//! **The management-plane attacker**, and the whole of what is here is about the
//! two ways it can interfere with a connection this node originates. It can
//! decline to answer for the next hop, which the neighbour cache bounds and
//! reports; and it can answer *badly* once a connection exists, which the
//! transport bounds and reports. Neither is a state this session waits in
//! forever: every phase below leaves under a bound this end chose, and the one
//! that leaves under nothing a peer supplies is the one an operator reads.
//!
//! # One session, and why one is the right number
//!
//! A management channel is a channel: this node reaches one place, and reaching
//! it twice at once would be two channels with one of them redundant. So a
//! second open is refused with the session that already exists named, on the
//! transport's own terms for a second dial to a peer it already holds.
//!
//! # What this holds and what it does not
//!
//! It holds the request, because a request is bytes the transport records a
//! range of and asks for again — and it holds the answer, because bytes read off
//! a peer have to land somewhere before a caller can judge them. Both are fixed
//! arrays sized by a constant here, the shape every other buffer in this crate
//! has. Neither can grow: a request longer than [`REQUEST_CAPACITY`] is refused
//! at the open, and an answer past [`ANSWER_CAPACITY`] is counted and dropped
//! rather than being allowed to displace what came before it.
//!
//! What it does **not** hold is a segment, a retransmission copy, or a queue. A
//! segment is composed into the caller's storage exactly as every reply in this
//! crate is, and a segment that cannot be addressed is dropped rather than
//! queued — the transport's own retransmission is what sends it again, and the
//! neighbour resolution runs while that timer is armed.

use lfw_tcp::{ConnectionId, DialError, SeqNumber};
use net_headers::{Ipv4Address, MacAddress};

use crate::route::{Hop, RouteRefusal};

/// The longest request one session carries.
///
/// Sized for the fixed first-party probe this appliance sends and not for a
/// stream: a session that wanted more would be one holding a buffer somebody
/// else's bytes decide the size of, which is the thing this crate does not do.
pub const REQUEST_CAPACITY: usize = 64;

/// The most of a peer's answer one session keeps.
///
/// Everything past it is counted and dropped. The alternative — taking the tail
/// and dropping the head — would let a peer decide which of its own bytes this
/// end judged, which is a choice no peer gets to make.
pub const ANSWER_CAPACITY: usize = 256;

/// Why no session was opened.
///
/// Every variant is about *this* end — a session already running, a destination
/// this port cannot reach, a request longer than the room for one — because an
/// open is refused before a peer has been given the chance to say anything. What
/// a peer then does with the dial is an [`Ended`], never one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// A session is already running, and the destination it is running to is
    /// named so a caller that lost track of one does not open a second.
    Busy { destination: Ipv4Address, port: u16 },
    /// No next hop could be chosen for the destination. The route decision's own
    /// refusal, carried whole: it names this node's configuration or its choice
    /// of destination, and both are things an operator fixes.
    Unroutable(RouteRefusal),
    /// A request longer than [`REQUEST_CAPACITY`]. Refused rather than truncated:
    /// a request cut to fit is a different request, and the peer would answer the
    /// one that was sent rather than the one that was meant.
    RequestTooLong { len: usize },
}

/// How one session finished.
///
/// Every variant is terminal, every variant is *reported*, and — the whole point
/// of the list being this long — **every variant is a different thing to go and
/// look at**. A caller left with a session in no particular state would have
/// nothing to say on a console about a channel that did not come up; a caller
/// told only that the connection "was lost" would have something to say and no
/// way to act on it, which is worse, because a station that never answered, one
/// that refused the port, and one that is not speaking TCP correctly send an
/// operator to three different places.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The peer answered and both halves closed. The answer is in
    /// [`Session::answer`].
    Answered,
    /// Every request for the next hop's hardware address went unanswered, so no
    /// frame of this session could be addressed at all. Nothing on this link
    /// claims the next hop.
    NextHopUnreachable,
    /// The neighbour table held only live entries, so this next hop could not
    /// even be asked about.
    NoRoomToResolve,
    /// The retransmission budget ran out and **nothing arrived at all**: not a
    /// reset, not a bad handshake, nothing. Either no station holds the address
    /// the resolution answered with, or one does and nothing is listening on the
    /// port in a way that says so.
    Unanswered,
    /// The peer's reset ended the connection. Somebody is at that address and is
    /// refusing this port, which is the fastest and clearest refusal there is.
    ResetByPeer,
    /// The peer acknowledged a number this end never sent, which draws a reset
    /// and leaves the dial standing, so the session then runs its budget out.
    ///
    /// The two numbers travel because the gap between them is the diagnosis: a
    /// station replaying an old exchange, one composing a handshake it never
    /// received, or a middlebox rewriting the field. `claimed` is **the peer's
    /// number** — it is reported, and it is never one this end computes with.
    UnacceptableAcknowledgement {
        /// The acknowledgement number the peer's segment carried, raw.
        claimed: u32,
        /// The next sequence number this end had sent, raw.
        expected: u32,
    },
    /// The connection went away and none of the three above explains it:
    /// segments arrived that advanced nothing, or this node's own table took the
    /// slot back. The residual and not a class — carving those three out of it is
    /// exactly what stops this reading as "something went wrong somewhere".
    Lost,
    /// The transport's table was full and nothing in it could be taken back.
    /// This node's own state, and a table under pressure is a flood.
    NoRoomToDial,
    /// The transport already holds a connection on this very peer address and
    /// port. This node's own table, and the one case it cannot tell two
    /// connections apart in.
    ConnectionAlreadyOpen,
    /// The `SYN` did not fit the storage the caller offered, so nothing was
    /// opened. **This node's own defect**, expected never to appear.
    SynDidNotFit,
}

impl Ended {
    /// The transport's refusal of a dial, in this vocabulary. Its own function
    /// rather than a variant holding a [`DialError`], because a caller that had
    /// to reach inside one to know what to look at would be reading a fold this
    /// list exists to be rid of.
    #[must_use]
    pub const fn refused(error: DialError) -> Self {
        match error {
            DialError::TableFull => Self::NoRoomToDial,
            DialError::AlreadyOpen { .. } => Self::ConnectionAlreadyOpen,
            DialError::Write(_) => Self::SynDidNotFit,
        }
    }

    /// A stable short name, for a metric label or a report line. Underscored,
    /// as [`RouteRefusal::name`] is: these are label values rather than console
    /// tokens, and the two spellings are what tell the surfaces apart.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::NextHopUnreachable => "next_hop_unreachable",
            Self::NoRoomToResolve => "no_room_to_resolve",
            Self::Unanswered => "unanswered",
            Self::ResetByPeer => "reset_by_peer",
            Self::UnacceptableAcknowledgement { .. } => "unacceptable_acknowledgement",
            Self::Lost => "connection_lost",
            Self::NoRoomToDial => "no_room_to_dial",
            Self::ConnectionAlreadyOpen => "connection_already_open",
            Self::SynDidNotFit => "syn_did_not_fit",
        }
    }

    /// Whether the session reached the far end and read what it said.
    #[must_use]
    pub const fn succeeded(self) -> bool {
        matches!(self, Self::Answered)
    }
}

/// What one session's own frames did, as the counts an operator places a
/// failure with.
///
/// Every field is a fact this end observed about **this session's own
/// connection**, which is the one thing a session genuinely owns: the resolution
/// beside it is the port's and is counted as the port's ([`Resolutions`]). That
/// attribution is the whole value — a port-wide total of segments would fold in
/// whatever else the management port was carrying and send somebody to look at
/// the wrong connection.
///
/// Saturating and never reset, on [`OutboundCounters`]' terms.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DialFacts {
    /// `SYN`s the transport composed for this session, retransmissions
    /// included. Zero means no frame of the connection ever reached the wire,
    /// which is the resolution having ended the session first.
    pub syns: u64,
    /// Whether **any** segment at all arrived on this session's connection.
    /// The one fact that separates silence from a peer that answered badly, and
    /// so the one that makes [`Ended::Unanswered`] mean what it says.
    pub answered: bool,
    /// Resets from the peer that this connection acted on.
    pub resets_received: u64,
    /// Resets this end composed on it, each answering a segment RFC 793 says
    /// must be refused that way.
    pub resets_sent: u64,
}

impl DialFacts {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            syns: 0,
            answered: false,
            resets_received: 0,
            resets_sent: 0,
        }
    }

    /// This session's facts folded into a channel's running account of several.
    ///
    /// The channel spends more than one session, and what an operator reads is
    /// the channel: every handshake a station ignored, and not the last
    /// session's share of them. Reporting one session's would understate the
    /// evidence by as many times as the channel had attempts.
    #[must_use]
    pub const fn joined(self, later: Self) -> Self {
        Self {
            syns: self.syns.saturating_add(later.syns),
            answered: self.answered || later.answered,
            resets_received: self.resets_received.saturating_add(later.resets_received),
            resets_sent: self.resets_sent.saturating_add(later.resets_sent),
        }
    }
}

/// Where a session has got to.
///
/// The order below is the order a session passes through, and each phase leaves
/// under something this end can observe: an answer, a state the transport
/// reports, or a bound this end chose. None of them leaves on a wall-clock gap,
/// which is why a session that is slow is still a session rather than a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The next hop is being asked about. A `SYN` may already be on the
    /// transport's books — it is composed whether or not the hardware address is
    /// known, so its retransmission timer is armed while the resolution runs.
    Resolving,
    /// The `SYN` is out and the peer has not completed the handshake.
    Dialling,
    /// The handshake completed and the request has not gone out whole.
    Sending,
    /// The request is out and the answer is coming back.
    Reading,
    /// This end has closed and is waiting for the connection to finish.
    Closing,
    Ended(Ended),
}

impl Phase {
    /// A stable short name, for a metric label or a report line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Resolving => "resolving",
            Self::Dialling => "dialling",
            Self::Sending => "sending",
            Self::Reading => "reading",
            Self::Closing => "closing",
            Self::Ended(_) => "ended",
        }
    }

    /// How the session finished, where it has.
    #[must_use]
    pub const fn ended(self) -> Option<Ended> {
        match self {
            Self::Ended(ended) => Some(ended),
            _ => None,
        }
    }
}

/// What the outbound half of an endpoint has done, one field per decision.
///
/// Saturating and never reset, on `EndpointCounters`' terms: a peer chooses how
/// often a session fails, so a wrap would turn a channel that never comes up
/// back into a small number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutboundCounters {
    /// Sessions opened, whatever became of them.
    pub opened: u64,
    /// Opens refused before a frame was composed.
    pub open_refused: u64,
    /// `SYN`s the transport composed for a session.
    pub dialled: u64,
    /// Segments composed and then dropped for want of a hardware address for the
    /// next hop. Each is re-sent by the transport's own retransmission, so a
    /// small number here is a resolution that ran while a timer was armed and a
    /// large one is a next hop that answers slowly or not at all.
    pub dropped_unresolved: u64,
    /// Request bytes handed to the transport.
    pub request_bytes: u64,
    /// Answer bytes taken from a peer and kept.
    pub answer_bytes: u64,
    /// Answer bytes a peer sent past [`ANSWER_CAPACITY`], dropped.
    pub answer_overflowed: u64,
    /// Sessions that ended having read an answer.
    pub answered: u64,
    /// Sessions that ended without one, whatever ended them.
    pub failed: u64,
}

impl OutboundCounters {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            opened: 0,
            open_refused: 0,
            dialled: 0,
            dropped_unresolved: 0,
            request_bytes: 0,
            answer_bytes: 0,
            answer_overflowed: 0,
            answered: 0,
            failed: 0,
        }
    }

    pub(crate) fn bump(count: &mut u64) {
        *count = count.saturating_add(1);
    }
}

/// What asking about a next hop produced: the requests that went out, the
/// replies that became an entry, and the replies that became none.
///
/// **Port facts rather than session ones, and named as such.** A reply naming an
/// address nobody asked about belongs to no session by definition, and an entry
/// outlives the session that learned it — a later session finds the next hop
/// already resolved and asks nothing. Attributing either to one session would be
/// inventing the attribution, and it is what once made a channel report three
/// replies to one request. What makes these the channel's evidence anyway is a
/// subtraction: a caller reads them when the channel opens and again when it is
/// reported, and the difference is what the link did while it was running.
///
/// Saturating and never reset, on [`OutboundCounters`]' terms.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Resolutions {
    /// Requests for a next hop's hardware address, retries included.
    pub requested: u64,
    /// Replies that answered one and became an entry.
    pub learned: u64,
    /// Replies nothing was waiting on.
    pub unsolicited: u64,
    /// Replies for an address already resolved: an attempt to move a next hop
    /// this appliance is using.
    pub rebinding: u64,
    /// Replies whose sender hardware address no frame may be addressed to.
    pub not_unicast: u64,
    /// Replies whose own claim about their sender the frame carrying them
    /// disagreed with.
    pub contradicted: u64,
}

impl Resolutions {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            requested: 0,
            learned: 0,
            unsolicited: 0,
            rebinding: 0,
            not_unicast: 0,
            contradicted: 0,
        }
    }

    /// What happened since `earlier`, field by field.
    ///
    /// Saturating rather than wrapping, so a counter that saturated reads as no
    /// further movement instead of as an enormous one; and a later reading
    /// *behind* an earlier one is zero rather than a complement, because these
    /// counts only ever rise and a pair that says otherwise is a caller holding
    /// the two the wrong way round.
    #[must_use]
    pub const fn since(self, earlier: Self) -> Self {
        Self {
            requested: self.requested.saturating_sub(earlier.requested),
            learned: self.learned.saturating_sub(earlier.learned),
            unsolicited: self.unsolicited.saturating_sub(earlier.unsolicited),
            rebinding: self.rebinding.saturating_sub(earlier.rebinding),
            not_unicast: self.not_unicast.saturating_sub(earlier.not_unicast),
            contradicted: self.contradicted.saturating_sub(earlier.contradicted),
        }
    }
}

/// One outbound connection, from the address it is to and the bytes it carries
/// through to what it read back.
///
/// Not `Copy`, and not by omission: it holds the request the transport may ask
/// for again and the answer as it accumulates, so a copy would be a second,
/// diverging account of one conversation.
#[derive(Clone, Debug)]
pub struct Session {
    destination: Ipv4Address,
    port: u16,
    /// The station a frame of this session is handed to, chosen once by the
    /// route decision and never re-chosen: a next hop that moved mid-session
    /// would be a redirection this end took on a peer's word. It carries which
    /// of the port's two answers chose it, because the address alone cannot
    /// say and the two are different halves of a configuration to go and read.
    next_hop: Hop,
    /// The hardware address that next hop resolved to. Learned once and kept:
    /// re-reading it from the frames the answer arrives in would let whoever
    /// answers redirect everything after it.
    peer_mac: Option<MacAddress>,
    connection: Option<ConnectionId>,
    phase: Phase,
    request: [u8; REQUEST_CAPACITY],
    request_len: usize,
    /// How much of the request the transport has taken. A window smaller than
    /// the request is why this is a position rather than a flag.
    sent: usize,
    /// The sequence number the request's first byte occupies, learned from the
    /// transport once it has taken one. It is what turns a range the transport
    /// asks for again into an offset into the bytes held here — without it a
    /// retransmission would be a guess, and a guess would put the wrong bytes on
    /// the wire under a sequence number the peer would accept them at.
    base: Option<SeqNumber>,
    answer: [u8; ANSWER_CAPACITY],
    answered: usize,
    peer_closed: bool,
    /// What this session's own frames did, which is what an operator reads
    /// beside the token when the channel does not come up.
    facts: DialFacts,
    /// The first acknowledgement of something never sent, if one arrived. The
    /// first rather than the last: a station that keeps sending them sends the
    /// same one, and the first is the one that happened before this end had
    /// answered anything.
    misacknowledged: Option<(u32, u32)>,
}

impl Session {
    /// Begin a session to `destination` on `port`, through `next_hop`, carrying
    /// `request`.
    ///
    /// # Errors
    /// [`OpenError::RequestTooLong`], for a request longer than the room for one.
    pub(crate) fn new(
        destination: Ipv4Address,
        port: u16,
        next_hop: Hop,
        request: &[u8],
    ) -> Result<Self, OpenError> {
        let mut held = [0u8; REQUEST_CAPACITY];
        let Some(room) = held.get_mut(..request.len()) else {
            return Err(OpenError::RequestTooLong { len: request.len() });
        };
        room.copy_from_slice(request);
        Ok(Self {
            destination,
            port,
            next_hop,
            peer_mac: None,
            connection: None,
            phase: Phase::Resolving,
            request: held,
            request_len: request.len(),
            sent: 0,
            base: None,
            answer: [0; ANSWER_CAPACITY],
            answered: 0,
            peer_closed: false,
            facts: DialFacts::new(),
            misacknowledged: None,
        })
    }

    #[must_use]
    pub const fn destination(&self) -> Ipv4Address {
        self.destination
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The station this session's frames are handed to, and which of the port's
    /// two answers chose it.
    #[must_use]
    pub const fn next_hop(&self) -> Hop {
        self.next_hop
    }

    /// What this session's own frames did.
    #[must_use]
    pub const fn facts(&self) -> DialFacts {
        self.facts
    }

    /// How this session ended, given everything it observed, for the moment the
    /// transport stops holding its connection.
    ///
    /// The order is the attribution and not a preference: a reset the connection
    /// acted on is what ended it, whatever else arrived first; an acknowledgement
    /// of what was never sent does not end a dial but is what an operator must
    /// look at when the budget then runs out; silence is silence; and what is
    /// left is a disappearance this end cannot attribute, which is named as one
    /// rather than folded into the three above.
    pub(crate) fn ending(&self) -> Ended {
        if self.facts.resets_received > 0 {
            return Ended::ResetByPeer;
        }
        if let Some((claimed, expected)) = self.misacknowledged {
            return Ended::UnacceptableAcknowledgement { claimed, expected };
        }
        if !self.facts.answered {
            return Ended::Unanswered;
        }
        Ended::Lost
    }

    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    #[must_use]
    pub const fn connection(&self) -> Option<ConnectionId> {
        self.connection
    }

    /// What the peer said, as far as it was kept.
    #[must_use]
    pub fn answer(&self) -> &[u8] {
        self.answer.get(..self.answered).unwrap_or(&[])
    }

    /// The request bytes the transport has not taken yet.
    pub(crate) fn unsent(&self) -> &[u8] {
        self.request.get(self.sent..self.request_len).unwrap_or(&[])
    }

    /// The `len` request bytes at offset `at`, for a range the transport asks
    /// for again. `None` where this session never sent them.
    pub(crate) fn range(&self, at: usize, len: usize) -> Option<&[u8]> {
        let end = at.checked_add(len)?;
        if end > self.sent {
            return None;
        }
        self.request.get(at..end)
    }

    /// Where in the request `sequence` falls, or `None` for a number this
    /// session never sent — which is what a range asked for before the first
    /// byte went out, or one past everything that did, is.
    pub(crate) fn offset_of(&self, sequence: SeqNumber) -> Option<usize> {
        let base = self.base?;
        let ahead = sequence.distance_from(base) as usize;
        (ahead < self.sent).then_some(ahead)
    }

    /// Learn where the request's first byte sits in the connection's sequence
    /// space. Taken once: the transport reports the oldest range it still holds,
    /// and after the first send that range *is* the request's beginning.
    pub(crate) fn note_base(&mut self, sequence: SeqNumber) {
        if self.base.is_none() {
            self.base = Some(sequence);
        }
    }

    pub(crate) const fn peer_mac(&self) -> Option<MacAddress> {
        self.peer_mac
    }

    pub(crate) fn resolved_to(&mut self, mac: MacAddress) {
        if self.peer_mac.is_none() {
            self.peer_mac = Some(mac);
        }
    }

    /// One `SYN` was composed, whether it reached the wire or was dropped for
    /// want of an address. Composed and not sent, deliberately: the transport
    /// re-sends what it recorded, so the count an operator reads against a
    /// silent station is the count of handshake attempts this end made.
    pub(crate) fn dialled_once(&mut self) {
        OutboundCounters::bump(&mut self.facts.syns);
    }

    /// A segment arrived on this session's connection, whatever the transport
    /// made of it, and whichever resets it carried or drew.
    pub(crate) fn segment_arrived(&mut self, peer_reset: bool, reset_sent: bool) {
        self.facts.answered = true;
        if peer_reset {
            OutboundCounters::bump(&mut self.facts.resets_received);
        }
        if reset_sent {
            OutboundCounters::bump(&mut self.facts.resets_sent);
        }
    }

    /// The peer acknowledged a number this end never sent. Kept once: a station
    /// that repeats itself is one fault and not several.
    pub(crate) fn note_misacknowledged(&mut self, claimed: u32, expected: u32) {
        if self.misacknowledged.is_none() {
            self.misacknowledged = Some((claimed, expected));
        }
    }

    pub(crate) fn dialled(&mut self, connection: ConnectionId) {
        self.connection = Some(connection);
        self.phase = Phase::Dialling;
    }

    pub(crate) fn took(&mut self, bytes: usize) {
        self.sent = self.sent.saturating_add(bytes);
    }

    pub(crate) const fn request_out(&self) -> bool {
        self.sent >= self.request_len
    }

    pub(crate) fn enter(&mut self, phase: Phase) {
        self.phase = phase;
    }

    pub(crate) fn note_peer_closed(&mut self) {
        self.peer_closed = true;
    }

    pub(crate) const fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// Take `data` off the peer, keeping what there is room for and reporting
    /// what there was not.
    pub(crate) fn take(&mut self, data: &[u8]) -> (usize, usize) {
        let Some(room) = self.answer.get_mut(self.answered..) else {
            return (0, data.len());
        };
        let mut kept = 0usize;
        for (cell, byte) in room.iter_mut().zip(data) {
            *cell = *byte;
            kept = kept.saturating_add(1);
        }
        self.answered = self.answered.saturating_add(kept);
        (kept, data.len().saturating_sub(kept))
    }
}
