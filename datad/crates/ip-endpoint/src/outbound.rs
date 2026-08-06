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

use crate::route::RouteRefusal;

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
/// Every variant is terminal and every variant is *reported*: a caller that was
/// left with a session in no particular state would have nothing to say on a
/// console about a channel that did not come up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The peer answered and both halves closed. The answer is in
    /// [`Session::answer`].
    Answered,
    /// Every request for the next hop's hardware address went unanswered, so no
    /// frame of this session could be addressed at all. Distinct from
    /// [`Lost`](Self::Lost) because the two are different things to go and look
    /// at: nothing on this link claims the next hop, as against a station that
    /// claimed it and then refused the connection.
    NextHopUnreachable,
    /// The neighbour table held only live entries, so this next hop could not
    /// even be asked about.
    NoRoomToResolve,
    /// The transport refused the dial: no room in its table, a connection on the
    /// 4-tuple already, or storage too small.
    Refused(DialError),
    /// The connection went away before the answer did — a reset, or the
    /// retransmission limit reached with nothing at the far end answering.
    Lost,
}

impl Ended {
    /// A stable short name, for a metric label or a report line. Underscored,
    /// as [`RouteRefusal::name`] is: these are label values rather than console
    /// tokens, and the two spellings are what tell the surfaces apart.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::NextHopUnreachable => "next_hop_unreachable",
            Self::NoRoomToResolve => "no_room_to_resolve",
            Self::Refused(_) => "dial_refused",
            Self::Lost => "connection_lost",
        }
    }

    /// Whether the session reached the far end and read what it said.
    #[must_use]
    pub const fn succeeded(self) -> bool {
        matches!(self, Self::Answered)
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
    /// would be a redirection this end took on a peer's word.
    next_hop: Ipv4Address,
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
        next_hop: Ipv4Address,
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

    /// The station this session's frames are handed to.
    #[must_use]
    pub const fn next_hop(&self) -> Ipv4Address {
        self.next_hop
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
