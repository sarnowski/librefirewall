//! The outbound connection: this appliance reaching *out* of its addressed
//! port, rather than answering on it.
//!
//! A **byte stream**, on the onboarding port's shape and for the same reason:
//! what runs over this connection is a session another domain terminates, and
//! the whole of what this may do with a byte is move it. It does not know what
//! the bytes are, it composes none of them, and it reads none.
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
//! Two fixed arrays and nothing else. [`SEND_CAPACITY`] bytes of what the
//! consumer above has answered with, because the transport owns no copy of a
//! range it may ask for again; and [`RECEIVE_CAPACITY`] bytes of what the peer
//! sent and the consumer has not taken, because a consumer is driven on a wakeup
//! and bytes arrive on a frame. Neither grows and neither is sized by anything a
//! peer sends: what does not fit is **counted and refused**, never dropped
//! silently and never allowed to displace what came before it. Both **slide**:
//! what the consumer has read and what the peer has acknowledged leave the front,
//! so a session of any length fits two arrays of a fixed size.
//!
//! The receive window is kept equal to the room actually left, so a peer that
//! keeps to the window cannot overflow the inbound array at all; the overflow
//! count is what a peer that does not keep to it produces.
//!
//! What this does **not** hold is a segment, a retransmission copy, or a queue. A
//! segment is composed into the caller's storage exactly as every reply in this
//! crate is, and a segment that cannot be addressed is dropped rather than
//! queued — the transport's own retransmission is what sends it again, and the
//! neighbour resolution runs while that timer is armed.

use lfw_tcp::{ConnectionId, DialError, SeqNumber};
use net_headers::{Ipv4Address, MacAddress};

use crate::route::{Hop, RouteRefusal};

/// Bytes the consumer has answered with that the peer has not acknowledged.
///
/// A **window**, not a budget for the session: an acknowledgement releases the
/// bytes it covers and the room is reused, so one array of this size carries a
/// session of any length, and what it bounds is only what may be outstanding at
/// once — the transport keeping no copy of a range it may ask for again.
///
/// **One whole run the consumer hands down has to fit**, one split across a
/// window that must drain first being a hole in the middle of a stream; that floor
/// is held to the consumer's own bound by an assertion sited where both numbers
/// are, and behind it is one more run's worth of queue. Deliberately not a TLS
/// record's size, the record layer handing its bytes down a run at a time.
pub const SEND_CAPACITY: usize = 8192;

/// Bytes read off the peer and held until the consumer takes them.
///
/// Sized so the room left is always a window worth advertising and never so
/// large that a peer can make this endpoint hold a page of its choosing: it is
/// the staging area between one frame and one wakeup, not a reassembly buffer.
/// The consumer reassembles, being the end that knows what the bytes are — and
/// the largest single flight the far end of such a session sends is a few
/// kilobytes, so a whole one lands before a wakeup has to have run.
pub const RECEIVE_CAPACITY: usize = 4096;

/// Why no session was opened.
///
/// Both variants are about *this* end — a session already running, a destination
/// this port cannot reach — because an open is refused before a peer has been
/// given the chance to say anything. What a peer then does with the dial is an
/// [`Ended`], never one of these.
///
/// Two rather than three: a session opens carrying nothing at all, so there is
/// no length for this end to refuse. What the consumer then answers with is
/// bounded by [`SEND_CAPACITY`] at the push and counted there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// A session is already running, and the destination it is running to is
    /// named so a caller that lost track of one does not open a second.
    Busy { destination: Ipv4Address, port: u16 },
    /// No next hop could be chosen for the destination. The route decision's own
    /// refusal, carried whole: it names this node's configuration or its choice
    /// of destination, and both are things an operator fixes.
    Unroutable(RouteRefusal),
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
///
/// None of them is a success. A session that came up is not an ending at all —
/// it is a connection this end is still holding, reported as
/// [`Phase::Established`] — and a stream the far end hung up on is
/// [`Self::ClosedByPeer`], which is a cause like any other rather than the
/// channel having worked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The peer closed its half and the connection finished. Whatever the
    /// session carried, the far end decided it was over — which for a channel
    /// meant to persist is a thing to go and look at rather than a healthy end.
    ClosedByPeer,
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
            Self::ClosedByPeer => "closed_by_peer",
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
    /// The handshake completed and the connection carries the stream. One phase
    /// and not a sending one beside a reading one: the two directions of a
    /// stream run at once, and a session that had to be in one of them could
    /// not read while it had something to say.
    Established,
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
            Self::Established => "established",
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
    /// Bytes the consumer answered with and the transport took.
    pub sent: u64,
    /// Bytes taken off a peer and held for the consumer.
    pub received: u64,
    /// Bytes a peer sent past the room left, refused. Unreachable while the
    /// window is honoured, which is why a number here is a peer that ignored it
    /// rather than an endpoint that ran out.
    pub overflowed: u64,
    /// Bytes the consumer answered with that there was no room for. **Ours**,
    /// not the peer's: the consumer is another domain, and this says its answer
    /// met a window still full of bytes the peer had not acknowledged.
    pub refused: u64,
    /// Sessions whose connection came up. Counted where the handshake completes
    /// and not where the session ends, a channel that is still running having no
    /// ending to be counted under.
    pub established: u64,
    /// Sessions that finished, whichever way they went.
    pub ended: u64,
}

impl OutboundCounters {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            opened: 0,
            open_refused: 0,
            dialled: 0,
            dropped_unresolved: 0,
            sent: 0,
            received: 0,
            overflowed: 0,
            refused: 0,
            established: 0,
            ended: 0,
        }
    }

    pub(crate) fn bump(count: &mut u64) {
        *count = count.saturating_add(1);
    }

    pub(crate) fn add(count: &mut u64, by: usize) {
        *count = count.saturating_add(by as u64);
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
/// subtraction: a caller reads them when an attempt opens and again when it is
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

/// One outbound connection, from the address it is to through to the bytes each
/// way and which end finished it.
///
/// Not `Copy`, and not by omission: it holds the bytes the transport may ask for
/// again and the bytes as they accumulate, so a copy would be a second,
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
    outbound: [u8; SEND_CAPACITY],
    outbound_len: usize,
    /// How much of `outbound` the transport has taken. A window smaller than
    /// what is held is why this is a position rather than a flag.
    sent: usize,
    /// The sequence number the **first byte still held** occupies, learned from
    /// the transport once it has taken one and moved forward by every release
    /// after that. It is what turns a range the transport asks for again into an
    /// offset into the bytes here — without it a retransmission would be a guess
    /// under a number the peer would accept the wrong bytes at. A moving origin
    /// is what makes the release representable: offset zero is wherever the
    /// window now starts.
    base: Option<SeqNumber>,
    inbound: [u8; RECEIVE_CAPACITY],
    inbound_len: usize,
    peer_closed: bool,
    /// The handshake completed at some point in this session's life. Recorded
    /// once and never cleared, which is what makes it the event rather than the
    /// state.
    handshaken: bool,
    /// The consumer has said the session is over. The close waits on the
    /// outbound bytes: a `FIN` composed in front of them would end the session
    /// before the last thing it had to say.
    consumer_closed: bool,
    /// A `FIN` has been composed, so nothing more is owed on this connection.
    closing: bool,
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
    /// Begin a session to `destination` on `port`, through `next_hop`.
    ///
    /// It carries nothing: a stream has no opening message, and what the
    /// consumer above has to say is pushed once the connection is up.
    pub(crate) const fn new(destination: Ipv4Address, port: u16, next_hop: Hop) -> Self {
        Self {
            destination,
            port,
            next_hop,
            peer_mac: None,
            connection: None,
            phase: Phase::Resolving,
            outbound: [0; SEND_CAPACITY],
            outbound_len: 0,
            sent: 0,
            base: None,
            inbound: [0; RECEIVE_CAPACITY],
            inbound_len: 0,
            peer_closed: false,
            handshaken: false,
            consumer_closed: false,
            closing: false,
            facts: DialFacts::new(),
            misacknowledged: None,
        }
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

    /// Whether the handshake has completed, so the stream may carry bytes.
    ///
    /// A fact this session recorded when it happened rather than one read back
    /// off the phase: a phase says where the session is *now*, so a session that
    /// came up and then closed would have to be inferred from the phases it is
    /// no longer in — and a caller reporting "the channel came up" must be
    /// reading the event and not a guess about it.
    #[must_use]
    pub const fn established(&self) -> bool {
        self.handshaken
    }

    #[must_use]
    pub const fn connection(&self) -> Option<ConnectionId> {
        self.connection
    }

    /// Bytes the peer sent that the consumer has not taken.
    #[must_use]
    pub fn received(&self) -> &[u8] {
        self.inbound.get(..self.inbound_len).unwrap_or(&[])
    }

    /// The room left for what the peer sends next, which is the window this end
    /// advertises.
    #[must_use]
    pub const fn room(&self) -> usize {
        RECEIVE_CAPACITY.saturating_sub(self.inbound_len)
    }

    /// The room left for what the consumer answers with next.
    #[must_use]
    pub const fn send_room(&self) -> usize {
        SEND_CAPACITY.saturating_sub(self.outbound_len)
    }

    /// Whether the peer has closed its half.
    #[must_use]
    pub const fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// Whether the consumer has ended the session.
    #[must_use]
    pub const fn consumer_closed(&self) -> bool {
        self.consumer_closed
    }

    /// Whether anything the consumer answered with is still waiting for the
    /// transport.
    #[must_use]
    pub const fn owes_bytes(&self) -> bool {
        self.sent < self.outbound_len
    }

    /// Drop the first `bytes` the consumer has taken, keeping the rest. A copy
    /// inside one fixed array and bounded by it, which is this half of the slide.
    pub fn consumed(&mut self, bytes: usize) {
        let taken = bytes.min(self.inbound_len);
        let left = self.inbound_len.saturating_sub(taken);
        self.inbound.copy_within(taken..self.inbound_len, 0);
        self.inbound_len = left;
    }

    /// The bytes the transport has not taken yet.
    pub(crate) fn unsent(&self) -> &[u8] {
        self.outbound
            .get(self.sent..self.outbound_len)
            .unwrap_or(&[])
    }

    /// The `len` bytes at offset `at` from the window's origin, for a range the
    /// transport asks for again. `None` past what was sent, or once acknowledged.
    pub(crate) fn range(&self, at: usize, len: usize) -> Option<&[u8]> {
        let end = at.checked_add(len)?;
        if end > self.sent {
            return None;
        }
        self.outbound.get(at..end)
    }

    /// Where in the bytes still held `sequence` falls, or `None` for one not held.
    /// Total over every number a peer can drive: one behind the origin measures as
    /// the enormous complement, outside what is held exactly as one ahead of it.
    pub(crate) fn offset_of(&self, sequence: SeqNumber) -> Option<usize> {
        let base = self.base?;
        let ahead = sequence.distance_from(base) as usize;
        (ahead < self.sent).then_some(ahead)
    }

    /// Learn where the first outbound byte sits in the connection's sequence
    /// space. Taken once: the transport reports the oldest range it still holds,
    /// and after the first send that range *is* that byte's place; every later
    /// move is a [`release`](Self::release).
    pub(crate) fn note_base(&mut self, sequence: SeqNumber) {
        if self.base.is_none() {
            self.base = Some(sequence);
        }
    }

    /// Give up every held byte before `unreleased`, answering how many left, and
    /// move the window's origin over them.
    ///
    /// The boundary is the transport's own — the oldest number it may still ask
    /// for a range at — and it is the only thing that may decide this: a byte
    /// released is one no retransmission can ask for again. Saturating at what was
    /// *sent* is what makes a close acknowledged along with the bytes in front of
    /// it release those and no more.
    pub(crate) fn release(&mut self, unreleased: SeqNumber) -> usize {
        let Some(base) = self.base else {
            return 0;
        };
        // Unconditional, a peer pacing this, and what stops a distance measured
        // backwards from reading as an enormous run of released bytes.
        if unreleased.precedes_or_equals(base) {
            return 0;
        }
        let held = self.outbound_len;
        let released = (unreleased.distance_from(base) as usize).min(self.sent);
        // And past what is held reaches outside the array rather than into it.
        if released == 0 || released > held {
            return 0;
        }
        self.outbound.copy_within(released..held, 0);
        self.outbound_len = held.saturating_sub(released);
        self.sent = self.sent.saturating_sub(released);
        // Lossless: bounded by `SEND_CAPACITY`.
        self.base = Some(base.add(released as u32));
        released
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

    pub(crate) fn enter(&mut self, phase: Phase) {
        self.phase = phase;
    }

    /// The handshake completed. Answers whether this is the first time, which is
    /// what makes the caller's count one per session rather than one per pass.
    pub(crate) fn note_handshaken(&mut self) -> bool {
        let first = !self.handshaken;
        self.handshaken = true;
        first
    }

    pub(crate) fn note_peer_closed(&mut self) {
        self.peer_closed = true;
    }

    pub(crate) const fn closing(&self) -> bool {
        self.closing
    }

    pub(crate) fn note_closing(&mut self) {
        self.closing = true;
    }

    /// Put `bytes` on the wire, answering how many there was room for and how
    /// many there was not.
    ///
    /// Fewer than offered is the **window full** rather than the end of anything,
    /// the room coming back as the peer acknowledges what is in it. Still this
    /// end's own refusal and counted as one: a caller that cannot re-offer has to
    /// end the session, a stream missing its middle being no stream.
    pub fn push(&mut self, bytes: &[u8]) -> (usize, usize) {
        let held = self.outbound_len;
        let Some(room) = self.outbound.get_mut(held..) else {
            return (0, bytes.len());
        };
        let mut kept = 0usize;
        for (cell, byte) in room.iter_mut().zip(bytes) {
            *cell = *byte;
            kept = kept.saturating_add(1);
        }
        self.outbound_len = held.saturating_add(kept);
        (kept, bytes.len().saturating_sub(kept))
    }

    /// The consumer has finished with the session. The close goes out once
    /// everything it answered with has.
    pub fn end_session(&mut self) {
        self.consumer_closed = true;
    }

    /// Take `data` off the peer, keeping what there is room for and reporting
    /// what there was not.
    ///
    /// Refused rather than truncated-and-forgotten: the count is what says a
    /// peer sent past the window it was given, and the bytes that did fit are
    /// the ones that arrived first, so the consumer reads a prefix of the stream
    /// rather than a hole in the middle of one.
    pub(crate) fn take(&mut self, data: &[u8]) -> (usize, usize) {
        let held = self.inbound_len;
        let Some(room) = self.inbound.get_mut(held..) else {
            return (0, data.len());
        };
        let mut kept = 0usize;
        for (cell, byte) in room.iter_mut().zip(data) {
            *cell = *byte;
            kept = kept.saturating_add(1);
        }
        self.inbound_len = held.saturating_add(kept);
        (kept, data.len().saturating_sub(kept))
    }
}
