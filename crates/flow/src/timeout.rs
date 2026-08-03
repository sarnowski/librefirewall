//! How long a flow in each state may sit idle before its slot is taken back.
//!
//! # Why every one of these is a security number
//!
//! A timeout is the only thing that ever returns a slot a peer caused to be
//! filled, so each of these is the bound on how much state one class of traffic
//! can hold. Too long and a flood's state outlives the flood; too short and
//! legitimate traffic is refused mid-conversation, which for a firewall is the
//! worse failure of the two — a connection dropped by the middlebox looks to both
//! ends like a network fault and there is nothing on either of them to
//! diagnose it with.
//!
//! So each number below is anchored on something outside this file: the interval
//! the protocol itself retries over, or the interval a conforming endpoint is
//! required to keep a connection alive at. A number picked for feeling right is a
//! number nobody can defend when it drops a session.

use lfw_clock::Duration;

use crate::entry::FlowState;

/// A TCP flow with a `SYN` and nothing back.
///
/// RFC 6298's doubling puts a client's fourth `SYN` at about fifteen seconds from
/// its first, so thirty seconds is past the last attempt any conforming client
/// makes and a slot cannot be held longer than that by a `SYN` that will never be
/// answered. It is the shortest timeout here on purpose: this is the state a
/// `SYN` flood fills the table with.
pub const SYN_SENT_TIMEOUT: Duration = Duration::from_millis(30_000);

/// A TCP flow where both ends have sent a `SYN` and the handshake has not
/// completed.
///
/// The segment that would complete it is one round trip away, so the only reason
/// to wait at all is retransmission of a lost `SYN-ACK` — the same interval as
/// above, and for the same reason.
pub const SYN_RECEIVED_TIMEOUT: Duration = Duration::from_millis(30_000);

/// A TCP flow that completed its handshake and is idle.
///
/// Two hours, which is RFC 1122 section 4.2.3.6's keepalive interval: an endpoint
/// that keeps a connection alive at all does so at least this often, so a
/// conforming long-lived session is never dropped here. Anchoring on the
/// protocol's own number is what makes this defensible where a round hour would
/// not be — and it is the longest timeout in this file, so it is also the one
/// that decides how much of the table a quiet peer may hold.
pub const ESTABLISHED_TIMEOUT: Duration = Duration::from_millis(7_200_000);

/// One end has closed and its `FIN` is not yet acknowledged.
///
/// A minute: the acknowledgement is one round trip away and a lost `FIN` is
/// retransmitted a few times, so anything beyond this is a peer that has stopped
/// answering, which the shorter timeout should reclaim rather than the
/// established one.
pub const FIN_WAIT_TIMEOUT: Duration = Duration::from_millis(60_000);

/// One end has closed, its `FIN` is acknowledged, and the other end may still be
/// sending.
///
/// A half-closed connection is legitimate and can carry a whole response, so this
/// is not shortened to the round trip a `FIN` needs; a minute is long enough for
/// an application to finish writing and short enough that a peer that never
/// closes does not hold the slot for the established interval.
pub const CLOSE_WAIT_TIMEOUT: Duration = Duration::from_millis(60_000);

/// Both ends have closed and at least one `FIN` is unacknowledged.
///
/// The same round-trip reasoning as [`FIN_WAIT_TIMEOUT`]: what is outstanding is
/// an acknowledgement, not data.
pub const CLOSING_TIMEOUT: Duration = Duration::from_millis(60_000);

/// Both `FIN`s are acknowledged.
///
/// Twice the thirty-second maximum segment lifetime the appliance's own transport
/// is stated against, so the two agree about how long a delayed duplicate may
/// still arrive. The state costs nothing under pressure regardless: it is not
/// assured, so a new flow may take the slot.
pub const TIME_WAIT_TIMEOUT: Duration = Duration::from_millis(60_000);

/// A `RST` ended the flow.
///
/// Ten seconds rather than zero: a reset is retransmitted, and data already in
/// flight arrives after it. Holding the entry briefly means those segments are
/// classified against a flow that is known to be over instead of being read as a
/// mid-stream segment for no flow at all, which is a different refusal and a
/// misleading one.
pub const CLOSED_TIMEOUT: Duration = Duration::from_millis(10_000);

/// A UDP pseudo-flow with traffic in one direction only.
///
/// Thirty seconds, which is above the retry interval of the request/response
/// protocols this state is almost always a request of — a resolver gives up long
/// before it — and short enough that a one-way flood is reclaimed quickly.
pub const UDP_UNREPLIED_TIMEOUT: Duration = Duration::from_millis(30_000);

/// A UDP pseudo-flow the far end has answered.
///
/// Two minutes: above the thirty-to-sixty-second interval applications behind a
/// middlebox send keepalives at, so a conforming two-way UDP session survives,
/// and far below the established TCP interval, because UDP offers no close and
/// nothing but this timeout ever ends the flow.
pub const UDP_ASSURED_TIMEOUT: Duration = Duration::from_millis(120_000);

/// An ICMP echo exchange, answered or not.
///
/// One interval for both, because an echo is a single round trip either way:
/// there is no second segment to wait for once the reply has arrived, so a
/// separate answered interval would be a number with nothing to anchor it. Thirty
/// seconds is far above any round trip and above the one-second cadence a
/// conventional probe repeats at.
pub const ICMP_TIMEOUT: Duration = Duration::from_millis(30_000);

/// How long a flow in `state` may sit idle.
///
/// [`FlowState::Vacant`] answers zero, which is what makes the sweep total: a
/// vacant slot is trivially past its life and is skipped for holding nothing
/// rather than for having a special case here.
#[must_use]
pub const fn timeout(state: FlowState) -> Duration {
    match state {
        FlowState::Vacant => Duration::from_nanos(0),
        FlowState::SynSent => SYN_SENT_TIMEOUT,
        FlowState::SynReceived => SYN_RECEIVED_TIMEOUT,
        FlowState::Established => ESTABLISHED_TIMEOUT,
        FlowState::FinWait => FIN_WAIT_TIMEOUT,
        FlowState::CloseWait => CLOSE_WAIT_TIMEOUT,
        FlowState::Closing => CLOSING_TIMEOUT,
        FlowState::TimeWait => TIME_WAIT_TIMEOUT,
        FlowState::Closed => CLOSED_TIMEOUT,
        FlowState::UdpUnreplied => UDP_UNREPLIED_TIMEOUT,
        FlowState::UdpAssured => UDP_ASSURED_TIMEOUT,
        FlowState::IcmpUnreplied | FlowState::IcmpReplied => ICMP_TIMEOUT,
    }
}

#[cfg(test)]
mod tests;
