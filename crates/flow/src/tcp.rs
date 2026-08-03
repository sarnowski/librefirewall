//! TCP as an observer sees it: which segments a flow's state admits, and which
//! sequence numbers its two windows authorise.
//!
//! # Adversary
//!
//! Every field read here is **untrusted network traffic**: the flags, the
//! sequence number, the acknowledgement, the window, the data offset and the
//! option bytes are all a peer's choosing, and a segment claiming to be a `SYN`
//! and a `FIN` at once is exactly what a scanner sends. Nothing is believed and
//! nothing panics: every refusal is a typed value the table turns into a counter.
//!
//! # Why strictness is the point, and what it refuses
//!
//! A tracker that admitted any segment naming an existing flow would let an
//! attacker who can guess a five-tuple move the flow's state — and would let one
//! who cannot even do that open a flow with a bare `ACK`, because a firewall that
//! adopts mid-stream segments is a firewall whose default-deny can be walked
//! around with one packet. So two rules hold here and neither has an exception:
//!
//! * **A flow is opened by a `SYN` and by nothing else.** A segment for a
//!   five-tuple with no entry is refused, whatever it carries. That costs the
//!   ability to keep existing connections alive across a restart of this table,
//!   which is a deliberate trade: the alternative is an opening move the
//!   adversary also has.
//! * **A segment must be inside the window its peer authorised.** The four
//!   comparisons below are the whole of that, and the state machine only runs on a
//!   segment that passed them — so an out-of-window segment cannot move a state,
//!   cannot refresh a timeout, and cannot close a connection.
//!
//! # What an observer cannot do, and how that is answered
//!
//! RFC 5961 section 3.2 wants a `RST` accepted only when its sequence number is
//! exactly the next byte the receiver expects. An observer does not hold that
//! number: it sees what each side *sent*, not what either has consumed. The
//! window test is what is available at this fidelity, and it is applied to a
//! `RST` like anything else — with one addition, because the weakest moment is
//! the handshake: a `RST` that is the *first* thing seen in the replying
//! direction must acknowledge exactly the `SYN` it answers. That is the shape a
//! closed port's refusal has, and it is what a blind reset from off the path does
//! not.

use net_headers::{TCP_HEADER_LEN, TcpFlags, TcpHeader};

use crate::entry::{DirectionState, FlowState, MAX_ACK_SLACK, MAX_WINDOW_SCALE};
use crate::key::Direction;
use lfw_tcp::SeqNumber;

/// What a segment is, as this module reads it.
///
/// The window arrives unscaled, as it does on the wire, because the shift is a
/// property of the flow rather than of the segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Segment {
    pub flags: TcpFlags,
    pub sequence: SeqNumber,
    pub acknowledgement: SeqNumber,
    pub window: u16,
    /// The sequence space the segment occupies: its payload plus the phantom byte
    /// each of `SYN` and `FIN` takes (RFC 793 section 3.3).
    pub length: u32,
    /// The shift a `SYN`'s option area offered, absent where none did or where
    /// this is not a `SYN`.
    pub window_scale: Option<u8>,
}

/// Why a TCP segment is not one this tracker will read at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SegmentError {
    /// A data offset naming less header than a header is, or more than the
    /// datagram carries.
    HeaderLengthInvalid { data_offset: u8 },
    /// Fewer bytes behind the IPv4 header than a TCP header without options.
    Truncated { needed: usize, got: usize },
}

impl Segment {
    /// Read one segment out of the header the frame parser already decoded and
    /// the bytes behind the IPv4 header.
    ///
    /// The payload length is derived from the datagram rather than from the
    /// header's own claim about itself, which is what keeps a data offset the peer
    /// inflated from naming payload that is not there.
    ///
    /// # Errors
    /// [`SegmentError`], for a datagram no segment can be read out of.
    pub(crate) fn read(header: &TcpHeader, transport: &[u8]) -> Result<Self, SegmentError> {
        if transport.len() < TCP_HEADER_LEN {
            return Err(SegmentError::Truncated {
                needed: TCP_HEADER_LEN,
                got: transport.len(),
            });
        }
        // Five words is a header with no options; the offset is four bits, so the
        // product cannot overflow a `usize`.
        let header_len = usize::from(header.data_offset) * 4;
        if header.data_offset < 5 || header_len > transport.len() {
            return Err(SegmentError::HeaderLengthInvalid {
                data_offset: header.data_offset,
            });
        }
        let options = transport
            .get(TCP_HEADER_LEN..header_len)
            .unwrap_or_default();
        let payload_len = transport.len().saturating_sub(header_len);
        // Lossless: a payload is bounded by one IPv4 datagram, so far below 2^32.
        let length = (payload_len as u32)
            .saturating_add(u32::from(header.flags.syn()))
            .saturating_add(u32::from(header.flags.fin()));
        Ok(Self {
            flags: header.flags,
            sequence: SeqNumber::new(header.sequence),
            acknowledgement: SeqNumber::new(header.acknowledgement),
            window: header.window,
            length,
            window_scale: header.flags.syn().then(|| window_scale(options)).flatten(),
        })
    }

    /// One past everything this segment occupies.
    pub(crate) fn end(&self) -> SeqNumber {
        self.sequence.add(self.length)
    }

    /// The window this segment advertises, scaled.
    ///
    /// A `SYN`'s own window is never scaled: RFC 7323 section 2.2 makes the shift
    /// apply from the segment *after* the one that negotiated it, so scaling a
    /// `SYN`'s window would open the right edge by up to sixteen thousand times
    /// what the peer offered.
    pub(crate) fn scaled_window(&self, scale: u8) -> u32 {
        let shift = if self.flags.syn() {
            0
        } else {
            scale.min(MAX_WINDOW_SCALE)
        };
        u32::from(self.window) << shift
    }
}

/// The window-scale option's kind and length, per RFC 7323 section 2.2.
const OPTION_WINDOW_SCALE: u8 = 3;
const OPTION_END: u8 = 0;
const OPTION_NOP: u8 = 1;
const WINDOW_SCALE_LEN: u8 = 3;

/// The shift a `SYN`'s option area offers, or `None` where it offers none.
///
/// Every byte is the peer's, so the walk is bounded by the slice and every read
/// is a pattern match on what a `split_first` produced rather than an index. A
/// malformed option area yields `None` — the whole area is abandoned at the first
/// byte that does not describe an option, because reading past it would mean
/// guessing where the next one starts.
///
/// Only the shift is read. The other options a segment may carry change nothing a
/// tracker decides, and the appliance's own transport reads them for itself.
fn window_scale(options: &[u8]) -> Option<u8> {
    let mut rest = options;
    loop {
        let (kind, tail) = rest.split_first()?;
        match *kind {
            OPTION_END => return None,
            OPTION_NOP => rest = tail,
            _ => {
                let (len, payload) = tail.split_first()?;
                // A length below two cannot describe an option carrying one, and
                // a length past the area would make the next offset a guess.
                let body_len = usize::from(len.checked_sub(2)?);
                let body = payload.get(..body_len)?;
                if *kind == OPTION_WINDOW_SCALE {
                    if *len != WINDOW_SCALE_LEN {
                        return None;
                    }
                    let (shift, _) = body.split_first()?;
                    return Some((*shift).min(MAX_WINDOW_SCALE));
                }
                rest = payload.get(body_len..)?;
            }
        }
    }
}

/// What one segment is, as the state machine names it.
///
/// Every combination that is not one of these is refused before a flow is
/// touched, which is where a `SYN`+`FIN` scan and a segment with no flags at all
/// are turned away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    /// A `SYN` with no `ACK`: an opening move, or a retransmitted one.
    Syn,
    /// A `SYN` with an `ACK`.
    SynAck,
    /// An `ACK`, carrying data or not.
    Ack,
    /// A `FIN`, which must carry an `ACK` on a flow that has one to give.
    Fin,
    Reset,
}

/// Which event a flag combination is, or `None` for one no exchange produces.
///
/// The refusals here are the ones a scanner relies on being tolerated: a `SYN`
/// with a `FIN`, a segment with no flags, a `RST` carrying a `SYN`, and a `FIN`
/// with no `ACK` on a flow whose handshake is over.
#[must_use]
pub(crate) fn event(flags: TcpFlags) -> Option<Event> {
    if flags.rst() {
        // A reset ends a flow, so a segment that is also trying to open or close
        // one is a combination no stack composes.
        return (!flags.syn() && !flags.fin()).then_some(Event::Reset);
    }
    match (flags.syn(), flags.fin(), flags.ack()) {
        (true, false, false) => Some(Event::Syn),
        (true, false, true) => Some(Event::SynAck),
        (false, true, true) => Some(Event::Fin),
        (false, false, true) => Some(Event::Ack),
        // A `SYN` with a `FIN`, a `FIN` with no `ACK`, and a segment carrying
        // none of the four.
        _ => None,
    }
}

/// Whether a flow in `state` admits `event` arriving in `direction`.
///
/// This is the whole of the admissibility half of the state machine; where it
/// answers `true` the window check still has to pass, and where it answers
/// `false` nothing about the flow changes.
#[must_use]
pub(crate) fn admits(state: FlowState, event: Event, direction: Direction) -> bool {
    match (state, event) {
        // Nothing is admitted against a slot holding no flow, or one a reset has
        // already ended.
        (FlowState::Closed | FlowState::Vacant, _) => false,
        // Unreachable: the protocol is part of a flow's identity, so a TCP
        // segment never resolves to one of these. Answered as a value rather
        // than an assertion, no panic being admissible on a path a peer's traffic
        // reaches — and answered *before* the reset arm below, so a TCP reset
        // reaching a UDP flow would be refused rather than closing it.
        (
            FlowState::UdpUnreplied
            | FlowState::UdpAssured
            | FlowState::IcmpUnreplied
            | FlowState::IcmpReplied,
            _,
        ) => false,
        // A reset is admissible from any TCP state a flow can be in. What
        // constrains it is the window, not the state.
        (_, Event::Reset) => true,
        // A `SYN` while only the originator has spoken is either its own
        // retransmission or the reply half of a simultaneous open.
        (FlowState::SynSent, Event::Syn) => true,
        // A `SYN-ACK` from the originator would acknowledge something it has not
        // been sent.
        (FlowState::SynSent, Event::SynAck) => matches!(direction, Direction::Reply),
        // Nothing has been offered for either side to acknowledge or close.
        (FlowState::SynSent, Event::Ack | Event::Fin) => false,
        // Both ends have sent a `SYN` by now, so a retransmission of either, an
        // acknowledgement from either, and a close from either are all things a
        // real exchange produces — including the two `SYN-ACK`s a simultaneous
        // open crosses. No data has been accepted yet, so the window test is the
        // whole constraint.
        (FlowState::SynReceived, _) => true,
        // A `SYN` on a synchronized flow is RFC 5961 section 4's case: it is not
        // an opening move, and taking it as one would let a blind segment reset a
        // live connection's state.
        (
            FlowState::Established
            | FlowState::FinWait
            | FlowState::CloseWait
            | FlowState::Closing
            | FlowState::TimeWait,
            Event::Syn | Event::SynAck,
        ) => false,
        (
            FlowState::Established
            | FlowState::FinWait
            | FlowState::CloseWait
            | FlowState::Closing
            | FlowState::TimeWait,
            Event::Ack | Event::Fin,
        ) => true,
    }
}

/// Which edge of which window a segment fell outside.
///
/// Four edges rather than one refusal, because they accuse different things: a
/// sequence number ahead of the right edge is a sender exceeding what it was
/// offered, one behind the left edge is a stale duplicate or a forgery, and the
/// two acknowledgement edges are a peer confirming what was never sent or
/// re-confirming something a window ago.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowEdge {
    /// The sequence number is past the furthest point the peer authorised.
    SequenceAhead,
    /// The segment ends further behind than one of the peer's windows.
    SequenceBehind,
    /// The acknowledgement covers something the peer never sent.
    AckAhead,
    /// The acknowledgement is further behind the peer's newest data than any
    /// window offered.
    AckBehind,
    /// The first thing seen in the replying direction carried an acknowledgement
    /// that was not exactly the handshake it answers.
    AckNotHandshake,
}

/// Whether the windows the two directions have established authorise this
/// segment.
///
/// `sender` is what the direction this segment travelled in has sent; `peer` is
/// what the other one has. The first segment in a direction is *opened* rather
/// than checked — there is nothing yet to check it against — except for the one
/// value that can be checked, which is whether it acknowledges exactly the
/// handshake it claims to answer.
///
/// # Errors
/// [`WindowEdge`], naming the comparison that refused it.
pub(crate) fn in_window(
    sender: &DirectionState,
    peer: &DirectionState,
    segment: &Segment,
) -> Result<(), WindowEdge> {
    if !sender.spoken() {
        // Nothing has been seen from this side, so the sequence space it will use
        // is whatever this segment declares. An acknowledgement is the one field
        // with something to hold it to: the peer has sent exactly its own opening
        // segment, and a first reply that acknowledges anything else — a blind
        // reset above all — is answering a connection this pair does not have.
        if segment.flags.ack() && peer.spoken() && segment.acknowledgement != peer.end() {
            return Err(WindowEdge::AckNotHandshake);
        }
        return Ok(());
    }
    if segment.sequence.follows(sender.max_end()) {
        return Err(WindowEdge::SequenceAhead);
    }
    if segment.end().precedes(sender.end().sub(peer.max_window())) {
        return Err(WindowEdge::SequenceBehind);
    }
    if segment.flags.ack() {
        if segment.acknowledgement.follows(peer.end()) {
            return Err(WindowEdge::AckAhead);
        }
        // How far behind the peer's newest data this acknowledgement may lag: at
        // most what this side told the peer it could have in flight, and never
        // more than one unscaled window's worth.
        let slack = sender.max_window().min(MAX_ACK_SLACK);
        if segment.acknowledgement.precedes(peer.end().sub(slack)) {
            return Err(WindowEdge::AckBehind);
        }
    }
    Ok(())
}

/// Record an accepted segment against the two directions.
///
/// Called only after [`in_window`] has answered `Ok`, which is what makes every
/// value written here one the flow's own windows authorised.
pub(crate) fn record(sender: &mut DirectionState, peer: &mut DirectionState, segment: &Segment) {
    let window = segment.scaled_window(sender.scale());
    if sender.spoken() {
        sender.extend_end(segment.end());
        sender.widen_window(window);
    } else {
        sender.open(segment.end(), window);
    }
    if segment.flags.syn() {
        sender.note_syn(segment.window_scale);
    }
    if segment.flags.ack() {
        // This segment is what authorises the peer to send: it names what has
        // been received and how much more will be taken.
        peer.raise_max_end(segment.acknowledgement.add(window.max(1)));
        peer.note_acknowledged(segment.acknowledgement);
    }
    if segment.flags.fin() {
        sender.note_fin();
    }
}

/// The state a flow reaches after accepting `event` in `direction`.
///
/// The closing states are not tracked as transitions but computed from the two
/// directions' `FIN` facts, which is what makes a simultaneous close fall out
/// rather than needing an arm of its own: whether one side or both have closed,
/// and whether each close is acknowledged, is four booleans and there is exactly
/// one state for each combination of them.
#[must_use]
pub(crate) fn next_state(
    state: FlowState,
    event: Event,
    direction: Direction,
    closing: (bool, bool, bool, bool),
) -> FlowState {
    match (state, event) {
        (_, Event::Reset) => FlowState::Closed,
        (FlowState::SynSent, Event::Syn) => match direction {
            // The originator retransmitting its own opening move.
            Direction::Original => FlowState::SynSent,
            // A `SYN` from the other side while this one has not been answered:
            // a simultaneous open, and both ends have now spoken.
            Direction::Reply => FlowState::SynReceived,
        },
        (FlowState::SynSent, Event::SynAck) => FlowState::SynReceived,
        (FlowState::SynReceived, Event::Syn | Event::SynAck) => FlowState::SynReceived,
        // Everything else is a synchronized flow, and where it stands is what its
        // two `FIN`s say.
        _ => closed_state(closing),
    }
}

/// Which of the five synchronized states the two directions' `FIN` facts name.
const fn closed_state(closing: (bool, bool, bool, bool)) -> FlowState {
    let (lower_fin, lower_acked, upper_fin, upper_acked) = closing;
    match (lower_fin, upper_fin) {
        (false, false) => FlowState::Established,
        (true, true) => {
            if lower_acked && upper_acked {
                FlowState::TimeWait
            } else {
                FlowState::Closing
            }
        }
        (true, false) => {
            if lower_acked {
                FlowState::CloseWait
            } else {
                FlowState::FinWait
            }
        }
        (false, true) => {
            if upper_acked {
                FlowState::CloseWait
            } else {
                FlowState::FinWait
            }
        }
    }
}

#[cfg(test)]
mod tests;
