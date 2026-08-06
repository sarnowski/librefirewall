//! One connection: RFC 793 section 3.9's *SEGMENT ARRIVES*, with RFC 5961's
//! validation and RFC 6298's timer over it.
//!
//! # What a connection holds, and what it deliberately does not
//!
//! Two sequence spaces, the values negotiated at the handshake, a record per
//! unacknowledged segment, and three deadlines. **No byte of the stream.** The
//! record of an unacknowledged segment names a range — a sequence number and a
//! length — and the bytes for that range live wherever the caller put them; on
//! a retransmission the caller is asked for them again. That is the whole reason
//! this crate exists rather than a general-purpose one, and it is the crate
//! header's first constraint.
//!
//! # Why RFC 5961 is applied to `SYN_RECEIVED` too
//!
//! RFC 5961 section 3.2 speaks of synchronized states, and `SYN_RECEIVED` is not one.
//! Its rule — a `RST` is accepted only when its sequence number is exactly the
//! next byte expected, an in-window one that is not gets a challenge
//! acknowledgement — is applied here anyway, in every state. A peer that really
//! aborts sends its `RST` at exactly that number, so nothing legitimate is
//! refused; what the stricter test removes is the off-path attacker's ability to
//! tear down a half-open connection by guessing anywhere inside a window.
//!
//! # The one place RFC 793 is deliberately not followed
//!
//! A segment for a port nothing listens on is answered with a `RST` by RFC 793
//! section 3.4, and is dropped in silence here. This appliance's own port is not a
//! host's: an appliance that answers every closed port confirms its own presence
//! and its address to anyone who asks, which is authority handed to the
//! management-plane attacker for nothing in return. A peer that really did
//! reach the wrong port learns the same thing from its own timeout, one
//! round-trip later. It is counted as a refusal so the silence is not also
//! invisible.

use lfw_clock::{Duration, Monotonic};
use net_headers::Ipv4Address;

use crate::rto::RetransmissionTimer;
use crate::segment::{Flags, MAX_WINDOW_SCALE, Segment};
use crate::seq::SeqNumber;

/// How many unacknowledged segments one connection may have outstanding.
///
/// A bound rather than a window: each record obliges the *caller* to still hold
/// the bytes it named, so the number is a promise about the caller's memory as
/// much as about this table. Four is what lets a response span several segments
/// while keeping the record array small enough to sit in a protection domain's
/// own memory alongside the rest of the table.
pub const MAX_UNACKED: usize = 4;

/// How many times a segment is re-sent before the connection is abandoned.
///
/// RFC 1122 section 4.2.3.5 requires the give-up threshold to be an interval rather
/// than a count, and with RFC 6298's doubling this count *is* one: five retries
/// from a one-second floor is at least 31 seconds, and more on a slow path where
/// the estimate is larger. It is expressed as a count because that is the
/// quantity a table slot's occupancy is bounded by.
pub const MAX_RETRANSMITS: u32 = 5;

/// How long a connection may sit with nothing sent, received or outstanding
/// before its slot is taken back.
///
/// It exists so that *every* connection becomes reapable in finite time, which
/// is what bounds the table under a flood of connections that complete a
/// handshake and then go silent. Five minutes is long enough that no
/// management exchange reaches it and short enough that a slot is not held for
/// the life of the node.
pub const IDLE_TIMEOUT: Duration = Duration::from_millis(300_000);

/// How long `TIME_WAIT` is held: twice a 30-second maximum segment lifetime.
///
/// The state exists so that a delayed duplicate from the connection just closed
/// cannot be delivered into a new connection on the same 4-tuple, and the
/// interval is what makes that a guarantee rather than a hope. Under table
/// pressure a `TIME_WAIT` slot is taken back early — see
/// [`Connection::evictable`] — which trades that guarantee for the ability to
/// accept a new connection at all, in the one situation where holding it would
/// deny service.
pub const TIME_WAIT_DURATION: Duration = Duration::from_millis(60_000);

/// The states a connection can reach.
///
/// `LISTEN` is absent by construction: it is a property of the stack rather than
/// of a connection, so there is no way to hold a `Connection` in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// This end dialled and the peer has not answered. It knows the peer's
    /// address and port and nothing about its sequence space, so it can neither
    /// send nor receive a byte.
    SynSent,
    SynReceived,
    Established,
    /// The peer has closed; this end may still send.
    CloseWait,
    /// This end closed after the peer did, and owes nothing but the last
    /// acknowledgement.
    LastAck,
    /// This end closed first.
    FinWait1,
    /// This end's `FIN` is acknowledged; the peer has not closed.
    FinWait2,
    /// Both ends closed at once, and neither `FIN` is acknowledged yet.
    Closing,
    TimeWait,
    Closed,
}

impl State {
    /// A stable short name, for a metric label or a report line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SynSent => "syn-sent",
            Self::SynReceived => "syn-received",
            Self::Established => "established",
            Self::CloseWait => "close-wait",
            Self::LastAck => "last-ack",
            Self::FinWait1 => "fin-wait-1",
            Self::FinWait2 => "fin-wait-2",
            Self::Closing => "closing",
            Self::TimeWait => "time-wait",
            Self::Closed => "closed",
        }
    }
}

/// One segment sent and not yet acknowledged: the range it occupies, and what
/// the caller must be told to reproduce it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Unacked {
    pub sequence: SeqNumber,
    /// Payload bytes. The `SYN` and `FIN` phantom bytes are the flags below.
    pub len: u16,
    pub syn: bool,
    pub fin: bool,
    pub sent_at: Monotonic,
    /// Karn's algorithm: a range that has been re-sent yields no round-trip
    /// sample, because there is no telling which transmission was acknowledged.
    pub retransmitted: bool,
}

impl Unacked {
    /// The first sequence number past this record.
    fn end(&self) -> SeqNumber {
        self.sequence
            .add(u32::from(self.len))
            .add(u32::from(self.syn))
            .add(u32::from(self.fin))
    }
}

/// A segment the state machine decided to send that carries no payload.
///
/// Every data-carrying segment comes from `TcpStack::send` instead, because only
/// the caller holds the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reply {
    pub flags: Flags,
    pub sequence: SeqNumber,
    pub acknowledgement: SeqNumber,
    /// A `SYN-ACK`, which is the only segment RFC 793 and RFC 7323 section 2.2 permit
    /// the maximum-segment-size and window-scale options on.
    pub with_options: bool,
}

/// What processing one segment produced.
///
/// The facts a counter is moved for travel back rather than being counted here:
/// a connection holds no counters, so a stack's totals stay in one place and a
/// connection cannot record an outcome its caller then reports differently.
pub(crate) struct Processed<'a> {
    /// In-order payload this segment contributed, a subslice of its own.
    pub data: &'a [u8],
    pub reply: Option<Reply>,
    /// Why the segment was refused, where it was. `None` is acceptance.
    pub refusal: Option<Refusal>,
    /// The peer's `FIN` was accepted, so the caller may close in answer.
    pub peer_closed: bool,
    /// This connection is finished and its slot may be taken back.
    pub finished: bool,
    /// The handshake completed on this segment.
    pub established: bool,
    /// The segment carried `URG`, whose pointer was ignored.
    pub urgent: bool,
}

/// Why a segment did not advance the connection it named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    OutOfWindow,
    /// An in-window `RST` whose sequence number was not the next byte expected
    /// (RFC 5961 section 3.2), answered with a challenge acknowledgement.
    UnvalidatedReset,
    /// A `SYN` on a synchronized connection (RFC 5961 section 4), likewise challenged.
    UnexpectedSyn,
    /// An acknowledgement of something never sent.
    ///
    /// It carries both numbers because they are what an operator places the
    /// fault with: one is the peer's claim and the other is what this end had
    /// actually sent, and the gap between them says whether the peer is a
    /// station replaying an old exchange, one composing a handshake it never
    /// received, or a middlebox rewriting the field. `claimed` is **the peer's
    /// number**, reported and never arithmetic this end depends on.
    UnacceptableAck {
        /// The acknowledgement number the segment carried.
        claimed: SeqNumber,
        /// The next sequence number this end had sent, which is what an
        /// acceptable acknowledgement may not run past.
        expected: SeqNumber,
    },
    /// In-window payload that was not the next byte expected. See the crate
    /// header on why there is no reassembly queue to hold it.
    OutOfOrder,
    /// A segment with no `ACK` on a synchronized connection, which RFC 793 p.72
    /// drops without answering.
    NoAcknowledgement,
    /// A segment reaching a dial that carried neither `SYN` nor `RST`, which
    /// RFC 793 p.68 drops without answering. Its own cause rather than
    /// [`OutOfWindow`](Self::OutOfWindow): a connection this end has only
    /// dialled has no receive window for a segment to be outside of, so the
    /// refusal is that the segment says nothing about the handshake being
    /// waited for.
    NotAHandshake,
}

/// One connection's whole state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connection {
    peer_address: Ipv4Address,
    peer_port: u16,
    state: State,

    /// The oldest unacknowledged sequence number.
    snd_una: SeqNumber,
    /// The next sequence number to send.
    snd_nxt: SeqNumber,
    /// The peer's advertised window, already scaled.
    snd_wnd: u32,
    /// RFC 5961 section 5's `MAX.SND.WND`: the largest window this end has ever
    /// been offered, which is how far behind [`snd_una`](Self::snd_una) an
    /// acknowledgement may legitimately lag.
    snd_wnd_max: u32,
    /// RFC 793 p.72's `SND.WL1`/`SND.WL2`: which segment last moved the window,
    /// so an old segment arriving late cannot shrink it back.
    snd_wl1: SeqNumber,
    snd_wl2: SeqNumber,

    /// The peer's initial sequence number, which its own `SYN` occupies.
    irs: SeqNumber,
    /// The next byte expected.
    rcv_nxt: SeqNumber,
    /// This end's advertised window, unscaled bytes.
    rcv_wnd: u32,
    /// The shift this end advertised, zero unless the peer offered scaling.
    rcv_scale: u8,
    /// The shift to apply to the peer's advertised window.
    snd_scale: u8,
    /// The most this end will put in one segment.
    send_mss: u16,
    /// Read from the peer's `SYN` and acted on by nothing; see
    /// `crate::segment`'s header.
    sack_permitted: bool,

    unacked: [Option<Unacked>; MAX_UNACKED],
    timer: RetransmissionTimer,
    /// When the oldest unacknowledged segment must be re-sent.
    rto_deadline: Option<Monotonic>,
    /// When `TIME_WAIT` ends.
    time_wait_deadline: Option<Monotonic>,
    last_activity: Monotonic,
}

impl Connection {
    /// Accept a `SYN`, taking every value the handshake negotiates from it.
    ///
    /// `mss_limit` and `receive_window` are the *stack's* — a bound the peer does
    /// not choose — and `iss` comes from the generator, so nothing about
    /// a new connection is the peer's to decide except which values it offered.
    pub(crate) fn accept(
        now: Monotonic,
        segment: &Segment<'_>,
        source: Ipv4Address,
        iss: SeqNumber,
        mss_limit: u16,
        receive_window: u32,
    ) -> Self {
        let irs = segment.sequence;
        let rcv_nxt = irs.add(1);
        let scaling = segment.options.window_scale.is_some();
        let rcv_scale = if scaling {
            receive_scale(receive_window)
        } else {
            0
        };
        let mut connection = Self {
            peer_address: source,
            peer_port: segment.source_port,
            state: State::SynReceived,
            snd_una: iss,
            // The `SYN` this connection is about to send occupies one number.
            snd_nxt: iss.add(1),
            snd_wnd: scaled_window(segment.window, 0),
            snd_wnd_max: scaled_window(segment.window, 0),
            snd_wl1: segment.sequence,
            snd_wl2: iss,
            irs,
            rcv_nxt,
            rcv_wnd: advertisable(receive_window, rcv_scale),
            rcv_scale,
            snd_scale: segment.options.window_scale.unwrap_or(0),
            send_mss: negotiated_mss(segment.options.mss, mss_limit),
            sack_permitted: segment.options.sack_permitted,
            unacked: [None; MAX_UNACKED],
            timer: RetransmissionTimer::new(),
            rto_deadline: None,
            time_wait_deadline: None,
            last_activity: now,
        };
        // Recorded so the `SYN-ACK` is re-sent if it is lost, which is the one
        // retransmission a listener owes before a connection exists at all.
        connection.record(now, iss, 0, true, false);
        connection
    }

    /// Dial `peer`: compose the state a `SYN` about to go out leaves behind.
    ///
    /// The mirror of [`accept`](Self::accept) with one asymmetry that shapes
    /// everything below — **nothing about the peer's sequence space is known
    /// yet**. Its initial sequence number, the window it will offer, the segment
    /// size it will accept and whether it scales all arrive on the `SYN-ACK`, so
    /// until then this connection advertises a window it has committed to and
    /// sends nothing — `snd_wnd` is zero, so [`sendable`](Self::sendable) is
    /// zero on top of the state check its caller makes. `irs` and `rcv_nxt`
    /// stand at this end's own `iss` as placeholders and are replaced by
    /// [`receive`](Self::receive) out of the answer, which is the first thing
    /// that happens to a dialled connection and happens before it can deliver a
    /// byte or acknowledge one.
    ///
    /// `mss_limit` and `receive_window` are the stack's, as they are for a
    /// passive open, and `iss` comes from the same generator — an off-path
    /// attacker that could predict the number this end dials with could inject
    /// into a connection it cannot see, whichever end opened it.
    pub(crate) fn open(
        now: Monotonic,
        peer_address: Ipv4Address,
        peer_port: u16,
        iss: SeqNumber,
        mss_limit: u16,
        receive_window: u32,
    ) -> Self {
        // Offered unconditionally, which is the only way scaling is ever
        // enabled: RFC 7323 section 2.2 makes an answer that carries the option
        // conditional on a `SYN` that did, so a dial that withheld it could
        // never scale in either direction.
        let rcv_scale = receive_scale(receive_window);
        let mut connection = Self {
            peer_address,
            peer_port,
            state: State::SynSent,
            snd_una: iss,
            // The `SYN` about to go out occupies one number.
            snd_nxt: iss.add(1),
            snd_wnd: 0,
            snd_wnd_max: 0,
            snd_wl1: iss,
            snd_wl2: iss,
            irs: iss,
            rcv_nxt: iss,
            rcv_wnd: advertisable(receive_window, rcv_scale),
            rcv_scale,
            snd_scale: 0,
            // The limit until the answer narrows it, which is exactly what
            // `negotiated_mss` takes as its second argument.
            send_mss: mss_limit,
            sack_permitted: false,
            unacked: [None; MAX_UNACKED],
            timer: RetransmissionTimer::new(),
            rto_deadline: None,
            time_wait_deadline: None,
            last_activity: now,
        };
        // Recorded so the `SYN` is re-sent if it or the answer is lost, which is
        // the whole of what a dial owes before a connection exists at all — and
        // what bounds how long an unanswered one holds its slot, the record
        // being what `MAX_RETRANSMITS` is counted against.
        connection.record(now, iss, 0, true, false);
        connection
    }

    /// The `SYN` a dial owes, composed from its own state so a retransmission and
    /// the original are the same segment.
    ///
    /// It carries no acknowledgement: this end has no peer sequence number to
    /// acknowledge, and a `SYN` claiming to acknowledge zero is one a peer is
    /// entitled to answer with a reset.
    pub(crate) fn syn(&self) -> Reply {
        Reply {
            flags: Flags::SYN,
            sequence: self.snd_una,
            acknowledgement: SeqNumber::new(0),
            with_options: true,
        }
    }

    /// The `SYN-ACK` this connection owes, composed from its own state so a
    /// retransmission and the original are the same segment.
    pub(crate) fn syn_ack(&self) -> Reply {
        Reply {
            flags: Flags::SYN.with(Flags::ACK),
            sequence: self.snd_una,
            acknowledgement: self.rcv_nxt,
            with_options: true,
        }
    }

    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    #[must_use]
    pub const fn peer_address(&self) -> Ipv4Address {
        self.peer_address
    }

    #[must_use]
    pub const fn peer_port(&self) -> u16 {
        self.peer_port
    }

    /// The most this end will put in one segment, after clamping.
    #[must_use]
    pub const fn send_mss(&self) -> u16 {
        self.send_mss
    }

    /// Whether any round-trip time has been measured on this connection, for a
    /// caller reporting on what it holds.
    #[must_use]
    pub const fn measured(&self) -> bool {
        self.timer.measured()
    }

    /// The retransmission timeout in force.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timer.timeout()
    }

    /// The oldest unacknowledged range, for a caller that must still hold its
    /// bytes.
    #[must_use]
    pub fn oldest_range(&self) -> Option<(SeqNumber, u16)> {
        self.oldest_unacked()
            .map(|record| (record.sequence, record.len))
    }

    /// Whether the peer offered selective acknowledgement. Read by nothing that
    /// acts on it, and exposed so that adding SACK is a change to this crate's
    /// state machine rather than to its parser.
    #[must_use]
    pub const fn sack_permitted(&self) -> bool {
        self.sack_permitted
    }

    /// How many unacknowledged segments this connection has outstanding, and so
    /// how many ranges the caller must still hold the bytes of.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.unacked.iter().flatten().count()
    }

    /// Whether this connection may take a slot back for a new one under table
    /// pressure.
    ///
    /// An `ESTABLISHED` connection never may, which is the important half: a peer
    /// that can complete handshakes would otherwise be able to evict the
    /// connections of everybody else. What that costs is stated in the crate
    /// header — a table full of established connections refuses a new one until
    /// [`IDLE_TIMEOUT`] takes one back.
    ///
    /// `SYN_SENT` is the other one that never may, and for the same reason read
    /// from the other side: a half-open connection this end *dialled* is not
    /// state a peer made this node commit, and letting an inbound `SYN` evict one
    /// would hand the party on the port a way to cancel this node's own dial by
    /// flooding. It is still bounded in time — the retransmission limit ends an
    /// unanswered dial, and [`IDLE_TIMEOUT`] ends one whose answer never came.
    #[must_use]
    pub fn evictable(&self) -> bool {
        matches!(
            self.state,
            State::Closed | State::TimeWait | State::SynReceived
        )
    }

    /// When this connection's slot must be taken back regardless of pressure.
    fn expiry(&self) -> Monotonic {
        match self.time_wait_deadline {
            Some(deadline) => deadline,
            None => self.last_activity.saturating_add(IDLE_TIMEOUT),
        }
    }

    /// Whether a timer has taken this connection past its life.
    #[must_use]
    pub fn expired(&self, now: Monotonic) -> bool {
        matches!(self.state, State::Closed) || now >= self.expiry()
    }

    /// The range due to be re-sent, or `None` while no timer has expired.
    ///
    /// The deadline and the range are answered together because a deadline is
    /// only ever armed while something is outstanding ([`arm`](Self::arm)): a
    /// caller that asked for them separately would have a second, unreachable
    /// refusal to handle.
    pub(crate) fn due(&self, now: Monotonic) -> Option<Unacked> {
        self.rto_deadline
            .filter(|deadline| now >= *deadline)
            .and_then(|_| self.oldest_unacked())
    }

    /// The last activity on this connection, which is what orders eviction.
    pub(crate) fn last_activity(&self) -> Monotonic {
        self.last_activity
    }

    pub(crate) fn backoff(&self) -> u32 {
        self.timer.backoff()
    }

    /// Whether this segment names this connection.
    pub(crate) fn matches(&self, source: Ipv4Address, port: u16) -> bool {
        self.peer_address == source && self.peer_port == port
    }

    pub(crate) fn snd_nxt(&self) -> SeqNumber {
        self.snd_nxt
    }

    pub(crate) fn rcv_nxt(&self) -> SeqNumber {
        self.rcv_nxt
    }

    /// The acknowledgement this connection would send right now.
    pub(crate) fn acknowledgement(&self) -> Reply {
        Reply {
            flags: Flags::ACK,
            sequence: self.snd_nxt,
            acknowledgement: self.rcv_nxt,
            with_options: false,
        }
    }

    /// Replace the window this end advertises with the room its caller now has.
    ///
    /// This is what makes the advertised window mean what RFC 793 says it means —
    /// the receiver's free space — rather than a constant. A caller that keeps it
    /// equal to its own free space cannot be sent more than it can take, which
    /// removes the one lossy case a receiver with no reassembly queue would
    /// otherwise have: data acknowledged and then dropped for want of somewhere
    /// to put it.
    pub(crate) fn set_receive_window(&mut self, bytes: u32) {
        self.rcv_wnd = advertisable(bytes, self.rcv_scale);
    }

    /// The window this end is advertising, in unscaled bytes.
    #[must_use]
    pub const fn receive_window(&self) -> u32 {
        self.rcv_wnd
    }

    /// The window to advertise, scaled down by the shift this end negotiated.
    pub(crate) fn advertised_window(&self) -> u16 {
        // Lossless: `advertisable` bounded this to what the shift can express.
        (self.rcv_wnd >> self.rcv_scale) as u16
    }

    pub(crate) fn window_scale(&self) -> Option<u8> {
        // The option is sent exactly when the peer offered one, which is what
        // RFC 7323 section 2.2 makes the condition for scaling in either direction.
        if self.snd_scale > 0 || self.rcv_scale > 0 {
            Some(self.rcv_scale)
        } else {
            None
        }
    }

    /// The shift a handshake segment of this connection carries.
    ///
    /// A dial offers the option whatever shift it needs, because that is what
    /// makes scaling available at all; every other segment sends it exactly where
    /// the peer offered one first.
    pub(crate) fn handshake_scale(&self) -> Option<u8> {
        match self.state {
            State::SynSent => Some(self.rcv_scale),
            State::SynReceived
            | State::Established
            | State::CloseWait
            | State::LastAck
            | State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::TimeWait
            | State::Closed => self.window_scale(),
        }
    }

    /// How many payload bytes may be sent right now: the peer's window less
    /// what is already in flight, capped by the negotiated segment size.
    pub(crate) fn sendable(&self) -> usize {
        let in_flight = self.snd_nxt.distance_from(self.snd_una);
        let window = self.snd_wnd.saturating_sub(in_flight);
        usize::from(self.send_mss).min(window as usize)
    }

    /// Record a segment as sent and arm the timer for it, answering whether
    /// there was a record slot for it.
    ///
    /// A caller that is refused must not put the segment on the wire: an
    /// unrecorded segment is one no timer would ever re-send, which is the
    /// silent loss this boolean exists to prevent. Both callers
    /// (`TcpStack::send`, [`close`](Self::close)) record *before* composing
    /// anything, so a refusal costs a `WouldBlock` and no bytes.
    pub(crate) fn record(
        &mut self,
        now: Monotonic,
        sequence: SeqNumber,
        len: u16,
        syn: bool,
        fin: bool,
    ) -> bool {
        let Some(slot) = self.unacked.iter_mut().find(|slot| slot.is_none()) else {
            return false;
        };
        *slot = Some(Unacked {
            sequence,
            len,
            syn,
            fin,
            sent_at: now,
            retransmitted: false,
        });
        self.last_activity = now;
        self.arm(now);
        true
    }

    /// Note that this end has just put something on the wire for this
    /// connection, so an idle sweep does not take a slot back from under a
    /// retransmission in progress.
    pub(crate) fn note_activity(&mut self, now: Monotonic) {
        self.last_activity = now;
    }

    /// Advance the send sequence over a segment just recorded.
    pub(crate) fn advance_send(&mut self, count: u32) {
        self.snd_nxt = self.snd_nxt.add(count);
    }

    /// Arm the retransmission timer from `now`, if anything is outstanding.
    fn arm(&mut self, now: Monotonic) {
        self.rto_deadline = if self.unacked.iter().any(Option::is_some) {
            Some(now.saturating_add(self.timer.timeout()))
        } else {
            None
        };
    }

    /// The oldest unacknowledged segment, which is the one a timeout re-sends.
    pub(crate) fn oldest_unacked(&self) -> Option<Unacked> {
        self.unacked
            .iter()
            .flatten()
            .copied()
            .reduce(|oldest, candidate| {
                if candidate.sequence.precedes(oldest.sequence) {
                    candidate
                } else {
                    oldest
                }
            })
    }

    /// Note that the retransmission timer has expired: back it off once, re-arm
    /// it, and mark the oldest range so Karn's algorithm refuses a round-trip
    /// sample from it.
    ///
    /// Once per expiry, never once per segment written: RFC 6298 section 5.5 doubles the
    /// timeout when the timer fires, and a stack that doubled again when the
    /// caller supplied the bytes would back off twice for one loss.
    pub(crate) fn note_expiry(&mut self, now: Monotonic) {
        let oldest = self.oldest_unacked().map(|record| record.sequence);
        for slot in self.unacked.iter_mut().flatten() {
            if Some(slot.sequence) == oldest {
                slot.retransmitted = true;
                slot.sent_at = now;
            }
        }
        self.timer.back_off();
        self.arm(now);
    }

    /// The segment one payload-free record is re-sent as.
    ///
    /// Only a record with no payload reaches this: the bytes of one that has a
    /// payload are the caller's, so its timeout asks the caller for them instead
    /// — which is why there is no `PSH` case here.
    ///
    /// Which segment it is depends on the state the record was made in, and that
    /// is the whole reason this lives on the connection: a dial's `SYN` carries no
    /// acknowledgement and offers the window scale, and every other control
    /// segment acknowledges what has been received.
    pub(crate) fn control(&self, record: &Unacked) -> Reply {
        if record.syn && matches!(self.state, State::SynSent) {
            return self.syn();
        }
        let mut flags = Flags::ACK;
        if record.syn {
            flags = flags.with(Flags::SYN);
        }
        if record.fin {
            flags = flags.with(Flags::FIN);
        }
        Reply {
            flags,
            sequence: record.sequence,
            acknowledgement: self.rcv_nxt,
            with_options: record.syn,
        }
    }

    /// The `RST` this connection sends when it is torn down.
    ///
    /// A dial the peer has not answered carries no acknowledgement, there being
    /// no peer sequence number to acknowledge: RFC 793 section 3.4's reset from
    /// an unsynchronized state is a bare `RST` at this end's own next number, and
    /// one claiming to acknowledge zero is one the peer would refuse.
    pub(crate) fn reset(&self) -> Reply {
        match self.state {
            State::SynSent => Reply {
                flags: Flags::RST,
                sequence: self.snd_nxt,
                acknowledgement: SeqNumber::new(0),
                with_options: false,
            },
            State::SynReceived
            | State::Established
            | State::CloseWait
            | State::LastAck
            | State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::TimeWait
            | State::Closed => Reply {
                flags: Flags::RST.with(Flags::ACK),
                sequence: self.snd_nxt,
                acknowledgement: self.rcv_nxt,
                with_options: false,
            },
        }
    }

    /// The `RST` an exhausted connection owes, and `None` where it owes none.
    ///
    /// A dial whose retransmissions ran out owes none: nothing at the far end
    /// ever answered, so there is no connection for a reset to end, and a frame
    /// sent anyway would only confirm to an address that said nothing that this
    /// node is here. That is the same reason a segment for a port nothing listens
    /// on is dropped in silence rather than answered.
    pub(crate) fn abandonment(&self) -> Option<Reply> {
        match self.state {
            State::SynSent => None,
            State::SynReceived
            | State::Established
            | State::CloseWait
            | State::LastAck
            | State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::TimeWait
            | State::Closed => Some(self.reset()),
        }
    }

    /// The `RST` a connection given back by its caller owes, and `None` where it
    /// owes none: RFC 793 section 3.8's *ABORT* read state by state.
    ///
    /// A **synchronized** connection owes it, because the peer believes in an
    /// exchange this end has stopped carrying and goes on sending into it
    /// otherwise. A dial nothing answered owes none, for
    /// [`abandonment`](Self::abandonment)'s reason exactly. And a connection
    /// whose close is *over* owes none either: `CLOSING`, `LAST_ACK`,
    /// `TIME_WAIT` and `CLOSED` are this end's own record of an exchange both
    /// halves have ended, and resetting one would contradict a `FIN` the peer
    /// has already accepted.
    ///
    /// Giving a `TIME_WAIT` back early spends the guarantee that state exists
    /// for — a delayed duplicate of the connection just closed cannot be
    /// delivered into a new one on the same 4-tuple — and it is the trade
    /// [`evictable`](Self::evictable) already makes under table pressure. What
    /// buys it is the 4-tuple, which is otherwise held for a minute by nothing
    /// but this end's own bookkeeping.
    pub(crate) fn abort(&self) -> Option<Reply> {
        match self.state {
            State::SynSent | State::Closing | State::LastAck | State::TimeWait | State::Closed => {
                None
            }
            State::SynReceived
            | State::Established
            | State::CloseWait
            | State::FinWait1
            | State::FinWait2 => Some(self.reset()),
        }
    }

    /// Move to `CLOSED` without sending anything, which is what a `RST` and an
    /// abandonment both leave behind.
    pub(crate) fn close_hard(&mut self) {
        self.state = State::Closed;
        self.unacked = [None; MAX_UNACKED];
        self.rto_deadline = None;
    }

    /// The application has finished sending: send a `FIN` and move on.
    ///
    /// Returns `None` where this end has already closed or cannot, which is the
    /// case a caller that closes twice reaches.
    pub(crate) fn close(&mut self, now: Monotonic) -> Option<Reply> {
        let next = match self.state {
            State::Established => State::FinWait1,
            State::CloseWait => State::LastAck,
            // A dial has nothing to close gracefully: its `SYN` may not even have
            // arrived, so there is no stream for a `FIN` to end. A caller giving
            // up on one tears it down instead.
            State::SynSent
            | State::SynReceived
            | State::LastAck
            | State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::TimeWait
            | State::Closed => return None,
        };
        let sequence = self.snd_nxt;
        if !self.record(now, sequence, 0, false, true) {
            return None;
        }
        self.state = next;
        self.advance_send(1);
        Some(Reply {
            flags: Flags::FIN.with(Flags::ACK),
            sequence,
            acknowledgement: self.rcv_nxt,
            with_options: false,
        })
    }

    /// RFC 793 section 3.9's *SEGMENT ARRIVES* for one segment on an existing
    /// connection.
    pub(crate) fn receive<'a>(&mut self, now: Monotonic, segment: &Segment<'a>) -> Processed<'a> {
        // A dial has its own arrival processing and shares none of what follows:
        // it has no receive window for the acceptability test to be stated over,
        // and the answer it is waiting for is a segment that test would refuse.
        if self.state == State::SynSent {
            return self.receive_syn_sent(now, segment);
        }

        // A `SYN` at the initial receive sequence, while still in `SYN_RECEIVED`,
        // is the peer's own handshake arriving again. It is *outside* the receive
        // window — the window starts one past it — so the acceptability test
        // below would refuse it, and what it means depends on whether it carries
        // an acknowledgement.
        if self.state == State::SynReceived
            && segment.flags.contains(Flags::SYN)
            && !segment.flags.contains(Flags::RST)
            && segment.sequence == self.irs
        {
            self.last_activity = now;
            if !segment.flags.contains(Flags::ACK) {
                // This end's answer was lost, and re-sending it is what makes a
                // lost `SYN-ACK` recoverable from either side.
                return Processed {
                    data: &[],
                    reply: Some(self.syn_ack()),
                    refusal: None,
                    peer_closed: false,
                    finished: false,
                    established: false,
                    urgent: false,
                };
            }
            // The far half of a simultaneous open: both ends dialled, both
            // answered, and this is the answer. Its sequence number is a byte
            // already taken, so the only new thing in it is the acknowledgement —
            // which is what completes this end's handshake. The acknowledgement
            // sent back is what completes the peer's where its own answer to this
            // end's `SYN-ACK` was the segment that went missing.
            return match self.acknowledge(now, segment) {
                Ok(established) => Processed {
                    data: &[],
                    reply: Some(self.acknowledgement()),
                    refusal: None,
                    peer_closed: false,
                    finished: false,
                    established,
                    urgent: false,
                },
                Err(processed) => processed,
            };
        }

        if !self.acceptable(segment) {
            // RFC 793 p.69: an unacceptable segment is answered with an
            // acknowledgement so the peer learns what was expected — unless it
            // carried `RST`, which must never provoke one.
            let reply = (!segment.flags.contains(Flags::RST)).then(|| self.acknowledgement());
            return self.refuse(Refusal::OutOfWindow, reply);
        }

        if segment.flags.contains(Flags::RST) {
            return self.receive_reset(segment);
        }

        if segment.flags.contains(Flags::SYN) {
            // RFC 5961 section 4: a challenge rather than RFC 793's reset, so a blind
            // in-window `SYN` cannot tear a connection down.
            return self.refuse(Refusal::UnexpectedSyn, Some(self.acknowledgement()));
        }

        if !segment.flags.contains(Flags::ACK) {
            // RFC 793 p.72.
            return self.refuse(Refusal::NoAcknowledgement, None);
        }

        // Parsed and not acted on; see `TcpCounters::urgent_ignored`.
        let urgent = segment.flags.contains(Flags::URG);

        let established = match self.acknowledge(now, segment) {
            Ok(established) => established,
            Err(processed) => return processed,
        };
        self.last_activity = now;

        // TIME_WAIT holds no stream: a segment reaching it is a retransmission
        // to be acknowledged, and the wait restarts so the acknowledgement has
        // its own lifetime to be delivered in.
        //
        // RFC 793 section 3.9 restarts it on a retransmitted remote `FIN` and
        // on nothing else: any other acceptable segment is answered out of the
        // wait already running, so a peer cannot hold a slot indefinitely by
        // sending into a connection that is over.
        if self.state == State::TimeWait {
            if segment.flags.contains(Flags::FIN) {
                self.start_time_wait(now);
            }
            return Processed {
                data: &[],
                reply: Some(self.acknowledgement()),
                refusal: None,
                peer_closed: false,
                finished: false,
                established,
                urgent,
            };
        }

        let mut processed = self.receive_data(now, segment);
        processed.established = established;
        processed.urgent = urgent;
        processed
    }

    /// RFC 793 p.66's *SYN-SENT* arrival processing: the four things one segment
    /// can be to a dial the peer has not answered yet, in the order that section
    /// tests them.
    ///
    /// The order is the security property. An acknowledgement is checked before a
    /// reset is believed, so a reset a peer sends in the blind — one that names no
    /// number this end has ever sent — cannot cancel a dial; and a `SYN` is acted
    /// on only after both, so a segment that is neither this end's answer nor a
    /// refusal of it moves nothing.
    fn receive_syn_sent<'a>(&mut self, now: Monotonic, segment: &Segment<'a>) -> Processed<'a> {
        // First: an acknowledgement of anything other than the `SYN` this end
        // sent. RFC 793 answers it with a reset carrying the number the peer
        // claimed and **leaves the dial where it is** — a segment acknowledging
        // what was never sent is not evidence about the connection being opened,
        // so tearing one down for it would let a single forged segment cancel a
        // dial.
        let acknowledged = if segment.flags.contains(Flags::ACK) {
            let ack = segment.acknowledgement;
            if ack.precedes_or_equals(self.snd_una) || ack.follows(self.snd_nxt) {
                let reply = (!segment.flags.contains(Flags::RST)).then_some(Reply {
                    flags: Flags::RST,
                    sequence: ack,
                    acknowledgement: SeqNumber::new(0),
                    with_options: false,
                });
                return self.refuse(
                    Refusal::UnacceptableAck {
                        claimed: ack,
                        expected: self.snd_nxt,
                    },
                    reply,
                );
            }
            true
        } else {
            false
        };

        // Second: a reset, which ends the dial exactly where the acknowledgement
        // above was acceptable. One without an acknowledgement names nothing and
        // is dropped, which is RFC 5961 section 3.2's protection stated for the
        // one state that has no window to state it over.
        if segment.flags.contains(Flags::RST) {
            if !acknowledged {
                return self.refuse(Refusal::UnvalidatedReset, None);
            }
            self.close_hard();
            return Processed {
                data: &[],
                reply: None,
                refusal: None,
                peer_closed: false,
                finished: true,
                established: false,
                urgent: false,
            };
        }

        if !segment.flags.contains(Flags::SYN) {
            return self.refuse(Refusal::NotAHandshake, None);
        }

        // The answer, and the one point at which everything about the peer's
        // sequence space becomes known.
        self.irs = segment.sequence;
        self.rcv_nxt = segment.sequence.add(1);
        self.send_mss = negotiated_mss(segment.options.mss, self.send_mss);
        self.sack_permitted = segment.options.sack_permitted;
        match segment.options.window_scale {
            Some(scale) => self.snd_scale = scale,
            // RFC 7323 section 2.2: scaling holds only where both ends offered
            // the option, so a peer that answered without it leaves this end
            // unshifted — and the window it advertises has to be held back to
            // what an unshifted field can express, or the number on the wire
            // would mean something larger than this end can take.
            None => {
                self.rcv_scale = 0;
                self.rcv_wnd = advertisable(self.rcv_wnd, 0);
            }
        }
        self.snd_wnd = scaled_window(segment.window, self.snd_scale);
        self.snd_wnd_max = self.snd_wnd;
        self.snd_wl1 = segment.sequence;
        self.last_activity = now;

        if !acknowledged {
            // A `SYN` with no acknowledgement is the peer dialling this end at the
            // same time. Both ends are now answering a `SYN` they did not ask
            // for, which is the state a passive open is already in — and the
            // `SYN-ACK` re-uses the sequence number the outstanding `SYN` record
            // already covers, so the timer that was arming for the `SYN` arms for
            // the `SYN-ACK` and nothing else moves.
            self.snd_wl2 = self.snd_una;
            self.state = State::SynReceived;
            return Processed {
                data: &[],
                reply: Some(self.syn_ack()),
                refusal: None,
                peer_closed: false,
                finished: false,
                established: false,
                urgent: false,
            };
        }

        self.snd_wl2 = segment.acknowledgement;
        // The dial is answered. Retiring the `SYN` takes the one round-trip
        // sample a connection has before it carries anything, which is what its
        // first retransmission timeout rests on.
        self.retire(now, segment.acknowledgement);
        self.snd_una = segment.acknowledgement;
        self.state = State::Established;
        Processed {
            data: &[],
            reply: Some(self.acknowledgement()),
            refusal: None,
            peer_closed: false,
            finished: false,
            established: true,
            urgent: false,
        }
    }

    /// RFC 793 p.69's four-case acceptability test, over this end's window.
    fn acceptable(&self, segment: &Segment<'_>) -> bool {
        let length = segment.sequence_length();
        let window = self.rcv_wnd;
        match (length, window) {
            // A window of zero admits nothing but a segment that occupies no
            // sequence space at the exact next byte.
            (0, 0) => segment.sequence == self.rcv_nxt,
            (0, _) => segment.sequence.in_window(self.rcv_nxt, window),
            (_, 0) => false,
            (_, _) => {
                // Either end of the segment inside the window is enough: a
                // segment overlapping its left edge is trimmed rather than
                // refused, which is what makes a retransmission of partly
                // received data acceptable.
                let last = segment.sequence.add(length.saturating_sub(1));
                segment.sequence.in_window(self.rcv_nxt, window)
                    || last.in_window(self.rcv_nxt, window)
            }
        }
    }

    /// RFC 5961 section 3.2, applied in every state; see the module header.
    fn receive_reset<'a>(&mut self, segment: &Segment<'a>) -> Processed<'a> {
        if segment.sequence != self.rcv_nxt {
            return self.refuse(Refusal::UnvalidatedReset, Some(self.acknowledgement()));
        }
        self.close_hard();
        Processed {
            data: &[],
            reply: None,
            refusal: None,
            peer_closed: false,
            finished: true,
            established: false,
            urgent: false,
        }
    }

    /// The acknowledgement half of RFC 793 p.72, including the state
    /// transitions an acknowledged `FIN` causes.
    ///
    /// `Err` carries the refusal, so the caller stops processing the segment —
    /// which is what RFC 793's "drop the segment and return" means.
    fn acknowledge<'a>(
        &mut self,
        now: Monotonic,
        segment: &Segment<'a>,
    ) -> Result<bool, Processed<'a>> {
        let ack = segment.acknowledgement;
        let mut established = false;
        if self.state == State::SynReceived {
            // RFC 793 p.72: the acknowledgement must cover this end's own `SYN`
            // and nothing it has not sent. Anything else is answered with a
            // `RST` carrying the number the peer claimed.
            if !(ack.follows(self.snd_una) && ack.precedes_or_equals(self.snd_nxt)) {
                // Read before the teardown, so the number reported is the one
                // this end had sent rather than whatever the closed state holds.
                let expected = self.snd_nxt;
                self.close_hard();
                return Err(Processed {
                    data: &[],
                    reply: Some(Reply {
                        flags: Flags::RST,
                        sequence: ack,
                        acknowledgement: SeqNumber::new(0),
                        with_options: false,
                    }),
                    refusal: Some(Refusal::UnacceptableAck {
                        claimed: ack,
                        expected,
                    }),
                    peer_closed: false,
                    finished: true,
                    established: false,
                    urgent: false,
                });
            }
            self.state = State::Established;
            established = true;
        } else if ack.follows(self.snd_nxt) || ack.precedes(self.snd_una.sub(self.snd_wnd_max)) {
            // RFC 5961 section 5's acceptable range, both edges. Ahead of
            // `SND.NXT` is an acknowledgement of something never sent; further
            // than `MAX.SND.WND` behind `SND.UNA` is one no delayed duplicate
            // of a real segment can be, and taking it would let an off-path
            // attacker reach `update_window` with a window of its own choosing.
            // Both are answered with an acknowledgement of what really was,
            // which is RFC 793's answer and RFC 5961's challenge alike.
            return Err(self.refuse(
                Refusal::UnacceptableAck {
                    claimed: ack,
                    expected: self.snd_nxt,
                },
                Some(self.acknowledgement()),
            ));
        }

        if ack.follows(self.snd_una) {
            self.retire(now, ack);
            self.snd_una = ack;
        }
        self.update_window(segment);
        self.advance_after_ack(now);
        Ok(established)
    }

    /// Retire every range the acknowledgement covers, taking a round-trip
    /// sample from the newest that was not retransmitted (Karn's algorithm).
    fn retire(&mut self, now: Monotonic, ack: SeqNumber) {
        // The newest is the one furthest along the sequence space, not the one
        // in the last array slot: records are placed in whichever slot is free,
        // so slot order says nothing about send order.
        let mut newest: Option<(SeqNumber, Duration)> = None;
        for slot in &mut self.unacked {
            let Some(record) = slot else { continue };
            if record.end().follows(ack) {
                continue;
            }
            if !record.retransmitted
                && newest.is_none_or(|(sequence, _)| sequence.precedes(record.sequence))
            {
                newest = Some((record.sequence, now.since(record.sent_at)));
            }
            *slot = None;
        }
        if let Some((_, sample)) = newest {
            self.timer.measure(sample);
        }
        self.arm(now);
    }

    /// RFC 793 p.72's window update, with RFC 7323's shift applied.
    ///
    /// The `WL1`/`WL2` test is what keeps a segment that arrives out of order
    /// from replacing a newer window with its own older one.
    fn update_window(&mut self, segment: &Segment<'_>) {
        let newer = segment.sequence.follows(self.snd_wl1)
            || (segment.sequence == self.snd_wl1
                && segment.acknowledgement.follows_or_equals(self.snd_wl2));
        if newer {
            self.snd_wnd = scaled_window(segment.window, self.snd_scale);
            self.snd_wnd_max = self.snd_wnd_max.max(self.snd_wnd);
            self.snd_wl1 = segment.sequence;
            self.snd_wl2 = segment.acknowledgement;
        }
    }

    /// The state transitions an acknowledgement of this end's own `FIN` causes.
    fn advance_after_ack(&mut self, now: Monotonic) {
        let fin_acknowledged = !self
            .unacked
            .iter()
            .flatten()
            .any(|record| record.fin || record.syn);
        if !fin_acknowledged {
            return;
        }
        match self.state {
            State::FinWait1 => self.state = State::FinWait2,
            State::Closing => {
                self.state = State::TimeWait;
                self.start_time_wait(now);
            }
            State::LastAck => self.close_hard(),
            State::SynSent
            | State::SynReceived
            | State::Established
            | State::CloseWait
            | State::FinWait2
            | State::TimeWait
            | State::Closed => {}
        }
    }

    /// The data and `FIN` half of RFC 793 p.73.
    fn receive_data<'a>(&mut self, now: Monotonic, segment: &Segment<'a>) -> Processed<'a> {
        // Trim what has already been received: a retransmission overlapping the
        // left edge of the window carries bytes this end has, and the rest of it
        // is new.
        let already = self.rcv_nxt.distance_from(segment.sequence);
        let payload = if segment.sequence.precedes(self.rcv_nxt) {
            // The acceptability test already bounds `already` by the payload —
            // a segment whose *whole* payload predates the window is only
            // acceptable if its phantom byte reaches into it, which no `FIN`
            // alone can do — and the `min` is what makes the slice total
            // regardless.
            let skip = (already as usize).min(segment.payload.len());
            segment.payload.get(skip..).unwrap_or_default()
        } else if segment.sequence == self.rcv_nxt {
            segment.payload
        } else {
            // In window, ahead of the next byte, and there is nowhere to hold
            // it: the acknowledgement that follows re-requests it. Counted so a
            // reordering path is visible rather than merely slow.
            //
            // A `FIN` ahead of the next byte is refused on exactly these terms,
            // and that is the point of refusing before the payload is examined:
            // accepting one would close the connection over a hole, and the
            // bytes in it would never be delivered.
            return self.refuse(Refusal::OutOfOrder, Some(self.acknowledgement()));
        };

        // Trim the right edge to the window. Everything delivered starts at
        // `rcv_nxt` by the branches above, and the window is measured from
        // there, so the room is the whole of it: a peer overshooting the window
        // has the excess dropped rather than delivered, and the acknowledgement
        // that follows re-requests it.
        let room = (self.rcv_wnd as usize).min(payload.len());
        let deliver = payload.get(..room).unwrap_or_default();
        // Lossless: a payload is bounded by one IPv4 datagram.
        let accepted = deliver.len() as u32;
        self.rcv_nxt = self.rcv_nxt.add(accepted);

        // The `FIN` counts only where every byte before it has been taken,
        // which after the trim above means the whole payload was accepted.
        let fin = segment.flags.contains(Flags::FIN) && deliver.len() == payload.len();
        let mut peer_closed = false;
        if fin {
            self.rcv_nxt = self.rcv_nxt.add(1);
            peer_closed = true;
            match self.state {
                State::Established => self.state = State::CloseWait,
                State::FinWait1 => self.state = State::Closing,
                State::FinWait2 => {
                    self.state = State::TimeWait;
                    self.start_time_wait(now);
                }
                State::SynSent
                | State::SynReceived
                | State::CloseWait
                | State::LastAck
                | State::Closing
                | State::TimeWait
                | State::Closed => {}
            }
        }

        // Every accepted segment is acknowledged. There is no delayed
        // acknowledgement here (crate header), so the answer is immediate and
        // the caller may replace it with a data segment carrying the same
        // acknowledgement number.
        let reply =
            (accepted > 0 || fin || !segment.payload.is_empty()).then(|| self.acknowledgement());
        Processed {
            data: deliver,
            reply,
            refusal: None,
            peer_closed,
            finished: matches!(self.state, State::Closed),
            established: false,
            urgent: false,
        }
    }

    fn start_time_wait(&mut self, now: Monotonic) {
        self.time_wait_deadline = Some(now.saturating_add(TIME_WAIT_DURATION));
        self.unacked = [None; MAX_UNACKED];
        self.rto_deadline = None;
    }

    /// A refusal, with whatever answer it owes.
    fn refuse<'a>(&self, refusal: Refusal, reply: Option<Reply>) -> Processed<'a> {
        Processed {
            data: &[],
            reply,
            refusal: Some(refusal),
            peer_closed: false,
            finished: false,
            established: false,
            urgent: false,
        }
    }
}

/// The peer's advertised window with its shift applied.
///
/// `u32` because a scaled window can exceed 16 bits by definition, and the
/// product is bounded by `u16::MAX << 14`, which fits with room to spare.
fn scaled_window(window: u16, scale: u8) -> u32 {
    u32::from(window) << scale.min(MAX_WINDOW_SCALE)
}

/// The smallest shift that lets `window` be expressed in the 16 bits a header
/// carries.
///
/// Zero for any window that already fits, which is the only case an unscaled
/// connection may use.
fn receive_scale(window: u32) -> u8 {
    let mut scale = 0;
    while scale < MAX_WINDOW_SCALE && (window >> scale) > u32::from(u16::MAX) {
        scale += 1;
    }
    scale
}

/// The window a connection may hold, given the shift it will advertise it under:
/// no more than the shifted field can express.
fn advertisable(window: u32, scale: u8) -> u32 {
    let ceiling = u32::from(u16::MAX) << scale.min(MAX_WINDOW_SCALE);
    window.min(ceiling)
}

/// The segment size to send under, from the peer's offer and this end's own
/// limit.
///
/// A peer that offers none gets RFC 1122 section 4.2.2.6's default of 536; a peer that
/// offers more than this end can compose is clamped to it, and one that offers
/// an absurdly small size is lifted to the floor RFC 1122 section 4.2.2.6 makes a
/// receiver honour — a 1-byte segment size would otherwise turn one response
/// into hundreds of segments, which is an amplifier a peer chooses for free.
fn negotiated_mss(offered: Option<u16>, limit: u16) -> u16 {
    /// RFC 1122 section 4.2.2.6's default when no option is offered.
    const DEFAULT_MSS: u16 = 536;
    /// RFC 1122 section 3.3.3's smallest reassembly buffer, less the two headers: the
    /// least a peer may be held to.
    const FLOOR_MSS: u16 = 576 - 20 - 20;
    offered
        .unwrap_or(DEFAULT_MSS)
        .max(FLOOR_MSS)
        .min(limit.max(1))
}

#[cfg(test)]
mod tests;
