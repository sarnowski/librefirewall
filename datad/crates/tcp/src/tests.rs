//! The stack driven as a stack: whole handshakes, whole closes, and floods.
//!
//! # Why there is a harness rather than a list of transitions
//!
//! A state machine tested one transition at a time passes while being unable to
//! complete a handshake: every step is right and no sequence is. [`Peer`] is
//! therefore a scripted counterpart that keeps its own sequence space, composes
//! real segments with real checksums, and reads what the appliance answers back
//! into its own state — so a test says "open, send, close" and a divergence
//! anywhere in the exchange surfaces as the peer refusing what came back.
//!
//! It is deterministic and single-threaded. Time is a number the test advances,
//! which is the whole reason `lfw_clock::Monotonic` is a parameter rather than
//! something this crate reads: a retransmission that would take a second of real
//! time is one `advance` here.

use super::*;
use crate::segment::Outgoing;
use proptest::prelude::*;
use std::vec::Vec;

const APPLIANCE: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 15]);
const STATION: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 2]);
const PORT: u16 = 80;
const MSS_LIMIT: u16 = 1024;
const RECEIVE_WINDOW: u32 = 8192;

/// A stack of four connections, which is small enough that a flood reaches the
/// table's edge in a handful of segments.
type Bench = TcpStack<4>;

fn secret() -> IsnSecret {
    IsnSecret::from_bytes([
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1,
        0xf0,
    ])
}

fn stack() -> Bench {
    TcpStack::new(APPLIANCE, PORT, MSS_LIMIT, RECEIVE_WINDOW, secret())
}

/// An instant `nanos` after boot, built the way this crate's callers build one.
fn at(nanos: u64) -> Monotonic {
    use core::num::NonZeroU64;
    use lfw_clock::{Calibration, Ticks};
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(nanos))
}

fn after(span: lfw_clock::Duration) -> Monotonic {
    at(span.as_nanos())
}

/// One scripted peer on one 4-tuple.
struct Peer {
    address: Ipv4Address,
    port: u16,
    /// The next sequence number this peer will send.
    next: SeqNumber,
    /// What this peer expects to receive next, learned from what came back.
    expect: SeqNumber,
    window: u16,
    /// Offered on the `SYN`; `None` sends no option at all.
    mss: Option<u16>,
    window_scale: Option<u8>,
}

impl Peer {
    fn new(port: u16, iss: u32) -> Self {
        Self {
            address: STATION,
            port,
            next: SeqNumber::new(iss),
            expect: SeqNumber::new(0),
            window: 4096,
            mss: Some(1460),
            window_scale: None,
        }
    }

    fn at(address: Ipv4Address, port: u16, iss: u32) -> Self {
        Self {
            address,
            ..Self::new(port, iss)
        }
    }

    /// Compose a segment from this peer, advancing its sequence space over
    /// whatever the segment occupies.
    fn segment(&mut self, flags: Flags, payload: &[u8]) -> Vec<u8> {
        let mut out = std::vec![0u8; 2048];
        let syn = flags.contains(Flags::SYN);
        let len = Outgoing {
            source_port: self.port,
            destination_port: PORT,
            sequence: self.next,
            acknowledgement: self.expect,
            flags,
            window: self.window,
            mss: syn.then_some(self.mss).flatten(),
            window_scale: syn.then_some(self.window_scale).flatten(),
            payload,
        }
        .write(self.address, APPLIANCE, &mut out)
        .expect("room for a 2 KiB segment");
        out.truncate(len);
        // Lossless: a payload here is far below 2^32.
        let occupied =
            payload.len() as u32 + u32::from(syn) + u32::from(flags.contains(Flags::FIN));
        self.next = self.next.add(occupied);
        out
    }

    /// A segment that does *not* advance this peer's sequence space, for
    /// retransmissions and for deliberately out-of-window probes.
    fn segment_at(&self, sequence: SeqNumber, flags: Flags, payload: &[u8]) -> Vec<u8> {
        let mut out = std::vec![0u8; 2048];
        let len = Outgoing {
            source_port: self.port,
            destination_port: PORT,
            sequence,
            acknowledgement: self.expect,
            flags,
            window: self.window,
            mss: None,
            window_scale: None,
            payload,
        }
        .write(self.address, APPLIANCE, &mut out)
        .expect("room for a 2 KiB segment");
        out.truncate(len);
        out
    }

    fn syn(&mut self) -> Vec<u8> {
        self.segment(Flags::SYN, &[])
    }

    fn ack(&mut self) -> Vec<u8> {
        self.segment(Flags::ACK, &[])
    }

    fn data(&mut self, payload: &[u8]) -> Vec<u8> {
        self.segment(Flags::ACK.with(Flags::PSH), payload)
    }

    fn fin(&mut self) -> Vec<u8> {
        self.segment(Flags::FIN.with(Flags::ACK), &[])
    }

    /// The answer to a dial: this peer's own `SYN` acknowledging the appliance's.
    fn syn_ack(&mut self) -> Vec<u8> {
        self.segment(Flags::SYN.with(Flags::ACK), &[])
    }

    /// Read a segment the appliance sent, learning this peer's own expectation
    /// from it, and answer with its fields.
    fn read<'bytes>(&mut self, bytes: &'bytes [u8]) -> Segment<'bytes> {
        let segment =
            Segment::parse(APPLIANCE, self.address, bytes).expect("the appliance wrote a segment");
        assert_eq!(segment.source_port, PORT);
        assert_eq!(segment.destination_port, self.port);
        // Lossless: a segment this stack writes is far below 2^32 bytes.
        let occupied = segment.sequence_length();
        self.expect = segment.sequence.add(occupied);
        segment
    }
}

/// Complete a handshake and answer with the connection it opened.
fn handshake(stack: &mut Bench, now: Monotonic, peer: &mut Peer) -> ConnectionId {
    let mut out = [0u8; 2048];
    let syn = peer.syn();
    let received = stack.receive(now, peer.address, &syn, &mut out);
    assert_eq!(received.outcome, Outcome::Accepted);
    let id = received.connection.expect("a connection was opened");
    let syn_ack = peer.read(&out[..received.emitted]);
    assert!(syn_ack.flags.contains(Flags::SYN));
    assert!(syn_ack.flags.contains(Flags::ACK));

    let ack = peer.ack();
    let received = stack.receive(now, peer.address, &ack, &mut out);
    assert_eq!(received.outcome, Outcome::Advanced);
    assert_eq!(received.emitted, 0, "a bare acknowledgement was answered");
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::Established)
    );
    id
}

/// Dial a peer and let it answer, returning the connection the dial opened.
///
/// The mirror of [`handshake`]: there the peer opens and the appliance answers,
/// here the appliance opens and the peer answers, and everything after the two
/// is the same connection.
fn dial(stack: &mut Bench, now: Monotonic, peer: &mut Peer) -> ConnectionId {
    let mut out = [0u8; 2048];
    let dialled = stack
        .connect(now, peer.address, peer.port, &mut out)
        .expect("a slot and room for a SYN");
    let syn = peer.read(&out[..dialled.len]);
    assert!(syn.flags.contains(Flags::SYN));
    assert!(!syn.flags.contains(Flags::ACK));

    let syn_ack = peer.syn_ack();
    let received = stack.receive(now, peer.address, &syn_ack, &mut out);
    assert_eq!(received.outcome, Outcome::Advanced);
    let ack = peer.read(&out[..received.emitted]);
    assert!(ack.flags.contains(Flags::ACK));
    assert!(!ack.flags.contains(Flags::SYN));
    assert_eq!(
        stack.connection(dialled.connection).map(Connection::state),
        Some(State::Established)
    );
    dialled.connection
}

#[test]
fn a_handshake_opens_a_connection_and_negotiates_the_segment_size() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x1000);
    let mut out = [0u8; 2048];

    let syn = peer.syn();
    let received = stack.receive(at(0), STATION, &syn, &mut out);
    assert_eq!(received.outcome, Outcome::Accepted);
    let id = received.connection.expect("a connection");
    let syn_ack = peer.read(&out[..received.emitted]);

    // The `SYN-ACK` acknowledges the peer's own `SYN` and offers this end's
    // limit, which is below what the peer offered.
    assert_eq!(syn_ack.acknowledgement, SeqNumber::new(0x1001));
    assert_eq!(syn_ack.options.mss, Some(MSS_LIMIT));
    assert_eq!(syn_ack.window, 8192);
    // The peer offered no window scale, so none is sent back (RFC 7323 section 2.2).
    assert_eq!(syn_ack.options.window_scale, None);

    let connection = stack.connection(id).expect("the connection");
    assert_eq!(connection.state(), State::SynReceived);
    assert_eq!(connection.send_mss(), MSS_LIMIT);
    assert_eq!(connection.peer_port(), 40000);
    assert_eq!(connection.peer_address(), STATION);
    assert_eq!(stack.counters().connections_accepted, 1);
    assert_eq!(stack.counters().connections_established, 0);

    let ack = peer.ack();
    stack.receive(at(0), STATION, &ack, &mut out);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::Established)
    );
    assert_eq!(stack.counters().connections_established, 1);
    assert_eq!(stack.outstanding(id), 0, "the SYN-ACK is acknowledged");
}

/// RFC 7323 section 2.2: scaling applies only where both ends offered it, so a peer
/// that offers a shift gets one back and has its own window scaled.
#[test]
fn window_scaling_is_negotiated_at_the_handshake() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x2000);
    peer.window_scale = Some(7);
    peer.window = 1000;
    let mut out = [0u8; 2048];

    let syn = peer.syn();
    let received = stack.receive(at(0), STATION, &syn, &mut out);
    let id = received.connection.expect("a connection");
    let syn_ack = peer.read(&out[..received.emitted]);
    // This end's window fits sixteen bits, so its own shift is zero — and the
    // option is still sent, which is what enables scaling in the other
    // direction.
    assert_eq!(syn_ack.options.window_scale, Some(0));

    let ack = peer.ack();
    stack.receive(at(0), STATION, &ack, &mut out);
    // The peer's 1000-byte window read under its shift of seven is 128 000
    // bytes, so a send is bounded by the segment size rather than by the window.
    let sent = stack
        .send(at(0), id, &[0xab; 4096], &mut out)
        .expect("the window is wide open");
    assert_eq!(sent.bytes, usize::from(MSS_LIMIT));
}

#[test]
fn a_byte_stream_crosses_in_both_directions_and_the_close_is_clean() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x3000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    // The peer sends; the stack delivers the bytes and acknowledges them.
    let payload = b"GET /metrics HTTP/1.1\r\n\r\n";
    let data = peer.data(payload);
    let received = stack.receive(at(1_000), STATION, &data, &mut out);
    assert_eq!(received.outcome, Outcome::Advanced);
    assert_eq!(received.data, payload);
    let ack = peer.read(&out[..received.emitted]);
    assert!(ack.flags.contains(Flags::ACK));
    assert_eq!(
        ack.acknowledgement,
        SeqNumber::new(0x3001 + payload.len() as u32)
    );
    assert_eq!(stack.counters().bytes_received, payload.len() as u64);

    // The stack answers with the same bytes, which is what the management
    // endpoint does with them today.
    let sent = stack
        .send(at(2_000), id, payload, &mut out)
        .expect("a segment fits");
    assert_eq!(sent.bytes, payload.len());
    let echo = peer.read(&out[..sent.len]);
    assert_eq!(echo.payload, payload);
    assert!(echo.flags.contains(Flags::PSH));
    assert_eq!(stack.outstanding(id), 1, "the echo is unacknowledged");

    let ack = peer.ack();
    stack.receive(at(3_000), STATION, &ack, &mut out);
    assert_eq!(stack.outstanding(id), 0, "the echo was acknowledged");

    // The peer closes; the stack moves to CLOSE_WAIT and answers.
    let fin = peer.fin();
    let received = stack.receive(at(4_000), STATION, &fin, &mut out);
    assert!(received.peer_closed);
    peer.read(&out[..received.emitted]);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::CloseWait)
    );

    // This end closes in answer and waits for the last acknowledgement.
    let len = stack.close(at(5_000), id, &mut out).expect("a FIN fits");
    let their_fin = peer.read(&out[..len]);
    assert!(their_fin.flags.contains(Flags::FIN));
    assert!(their_fin.flags.contains(Flags::ACK));
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::LastAck)
    );

    let ack = peer.ack();
    let received = stack.receive(at(6_000), STATION, &ack, &mut out);
    assert_eq!(received.emitted, 0);
    assert_eq!(stack.connection(id), None, "the slot was taken back");
    assert_eq!(stack.connections(), 0);
    assert_eq!(stack.counters().connections_closed, 1);
}

/// The other close: this end goes first, so it passes through `FIN_WAIT_1`,
/// `FIN_WAIT_2` and `TIME_WAIT`.
#[test]
fn closing_first_passes_through_time_wait() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x4000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    let len = stack.close(at(1_000), id, &mut out).expect("a FIN fits");
    peer.read(&out[..len]);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::FinWait1)
    );

    // The peer acknowledges the FIN alone.
    let ack = peer.ack();
    stack.receive(at(2_000), STATION, &ack, &mut out);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::FinWait2)
    );

    // And then closes its own half.
    let fin = peer.fin();
    let received = stack.receive(at(3_000), STATION, &fin, &mut out);
    assert!(received.peer_closed);
    peer.read(&out[..received.emitted]);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::TimeWait)
    );

    // The wait is held, and then the slot comes back. The deadline runs from the
    // instant the state was entered, not from boot.
    assert_eq!(stack.poll_timeouts(at(4_000), &mut out), None);
    let expiry = at(3_000).saturating_add(TIME_WAIT_DURATION);
    assert_eq!(
        stack.poll_timeouts(expiry, &mut out),
        Some(Timeout::Reaped { connection: id })
    );
    assert_eq!(stack.connections(), 0);
    assert_eq!(stack.counters().connections_reaped, 1);
}

/// Simultaneous close: both ends send a `FIN` before either is acknowledged, so
/// the connection passes through `CLOSING`.
#[test]
fn a_simultaneous_close_passes_through_closing() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x5000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    let len = stack.close(at(1_000), id, &mut out).expect("a FIN fits");
    let ours = {
        let fin = Segment::parse(APPLIANCE, STATION, &out[..len]).expect("a FIN");
        assert!(fin.flags.contains(Flags::FIN));
        fin.sequence
    };
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::FinWait1)
    );

    // The peer's FIN acknowledges everything before this end's FIN but not the
    // FIN itself, which is what makes the close simultaneous. The peer is
    // deliberately not told about that FIN — `read` is what would advance its
    // expectation over it — so its own answer cannot acknowledge one it has not
    // seen.
    let fin = peer.segment_at(peer.next, Flags::FIN.with(Flags::ACK), &[]);
    let received = stack.receive(at(2_000), STATION, &fin, &mut out);
    assert!(received.peer_closed);
    peer.read(&out[..received.emitted]);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::Closing)
    );

    // Now the peer acknowledges this end's FIN too, which completes the close.
    peer.next = peer.next.add(1);
    peer.expect = ours.add(1);
    let ack = peer.ack();
    stack.receive(at(3_000), STATION, &ack, &mut out);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::TimeWait)
    );
}

/// RFC 793 p.69: an out-of-window segment is answered with an acknowledgement
/// naming what was expected, and never accepted.
#[test]
fn an_out_of_window_segment_is_answered_with_an_acknowledgement() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x6000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);
    let expected = peer.next;

    // Far to the right of the window.
    let ahead = peer.segment_at(expected.add(RECEIVE_WINDOW + 1), Flags::ACK, b"late");
    let received = stack.receive(at(1_000), STATION, &ahead, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::OutOfWindow))
    );
    assert!(received.data.is_empty());
    let answer = peer.read(&out[..received.emitted]);
    assert_eq!(answer.acknowledgement, expected);
    assert!(!answer.flags.contains(Flags::RST));

    // And far to the left of it.
    let behind = peer.segment_at(expected.add(u32::MAX - 4096), Flags::ACK, b"old");
    let received = stack.receive(at(2_000), STATION, &behind, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::OutOfWindow))
    );
    assert!(
        received.emitted > 0,
        "an out-of-window segment went unanswered"
    );
    assert_eq!(stack.counters().refused_out_of_window, 2);
    // Nothing about the connection moved.
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::Established)
    );
}

/// RFC 5961 section 3.2: a `RST` is accepted only at the exact next byte expected, and
/// an in-window one that is not gets a challenge acknowledgement.
#[test]
fn a_blind_in_window_reset_is_challenged_rather_than_obeyed() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x7000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);
    let expected = peer.next;

    let blind = peer.segment_at(expected.add(100), Flags::RST, &[]);
    let received = stack.receive(at(1_000), STATION, &blind, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::UnvalidatedReset))
    );
    let challenge = peer.read(&out[..received.emitted]);
    assert!(challenge.flags.contains(Flags::ACK));
    assert!(!challenge.flags.contains(Flags::RST));
    assert_eq!(challenge.acknowledgement, expected);
    assert_eq!(stack.counters().challenge_acks, 1);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::Established),
        "a blind reset tore the connection down"
    );

    // The exact one is obeyed.
    let exact = peer.segment_at(expected, Flags::RST, &[]);
    let received = stack.receive(at(2_000), STATION, &exact, &mut out);
    assert_eq!(received.outcome, Outcome::Advanced);
    assert_eq!(received.emitted, 0, "a reset was answered");
    assert_eq!(stack.connection(id), None);
    assert_eq!(stack.counters().resets_received, 1);
}

/// RFC 5961 section 4: a `SYN` on a synchronized connection is challenged rather than
/// answered with RFC 793's reset.
#[test]
fn a_syn_on_an_established_connection_is_challenged() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x8000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    let intruder = peer.segment_at(peer.next, Flags::SYN, &[]);
    let received = stack.receive(at(1_000), STATION, &intruder, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::UnexpectedSyn))
    );
    let challenge = peer.read(&out[..received.emitted]);
    assert!(!challenge.flags.contains(Flags::RST));
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::Established)
    );
}

/// The peer's `SYN` retransmitted while this end is still in `SYN_RECEIVED` is
/// answered with the `SYN-ACK` again, not with a bare acknowledgement the peer
/// could do nothing with.
#[test]
fn a_retransmitted_syn_is_answered_with_the_syn_ack_again() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x9000);
    let mut out = [0u8; 2048];

    let syn = peer.syn();
    let received = stack.receive(at(0), STATION, &syn, &mut out);
    let id = received.connection.expect("a connection");
    let first = peer.read(&out[..received.emitted]).sequence;

    let received = stack.receive(at(1_000), STATION, &syn, &mut out);
    assert_eq!(received.outcome, Outcome::Advanced);
    let again = peer.read(&out[..received.emitted]);
    assert!(again.flags.contains(Flags::SYN));
    assert!(again.flags.contains(Flags::ACK));
    assert_eq!(again.sequence, first, "a second sequence space was offered");
    assert_eq!(
        stack.counters().connections_accepted,
        1,
        "a second connection"
    );
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::SynReceived)
    );
}

/// An acknowledgement of something never sent is refused: with a `RST` out of
/// `SYN_RECEIVED`, per RFC 793 p.72, and with a challenge once synchronized.
#[test]
fn an_acknowledgement_of_something_never_sent_is_refused() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0xa000);
    let mut out = [0u8; 2048];

    let syn = peer.syn();
    let received = stack.receive(at(0), STATION, &syn, &mut out);
    let id = received.connection.expect("a connection");
    peer.read(&out[..received.emitted]);

    // An acknowledgement far beyond what this end sent. The number this end had
    // really reached is read before the peer's claim replaces it, because the
    // refusal reports both and an operator places the fault by the gap.
    let expected = peer.expect;
    peer.expect = peer.expect.add(1_000);
    let claimed = peer.expect;
    let wrong = peer.ack();
    let received = stack.receive(at(1_000), STATION, &wrong, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::UnacceptableAck {
            claimed,
            expected
        }))
    );
    let reset =
        Segment::parse(APPLIANCE, STATION, &out[..received.emitted]).expect("a reset came back");
    assert!(reset.flags.contains(Flags::RST));
    // RFC 793 p.72: the reset carries the number the peer claimed, so the peer
    // finds it acceptable.
    assert_eq!(reset.sequence, claimed);
    assert_eq!(
        stack.connection(id),
        None,
        "the half-open connection survived"
    );
    assert_eq!(stack.counters().resets_sent, 1);
    assert_eq!(stack.counters().refused_unacceptable_ack, 1);

    // And once established, a challenge rather than a reset.
    let mut peer = Peer::new(40001, 0xb000);
    let id = handshake(&mut stack, at(2_000), &mut peer);
    let expected = peer.expect;
    peer.expect = peer.expect.add(5_000);
    let claimed = peer.expect;
    let wrong = peer.ack();
    let received = stack.receive(at(3_000), STATION, &wrong, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::UnacceptableAck {
            claimed,
            expected
        }))
    );
    let challenge = Segment::parse(APPLIANCE, STATION, &out[..received.emitted])
        .expect("a challenge came back");
    assert!(!challenge.flags.contains(Flags::RST));
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::Established)
    );
}

/// A segment carrying no acknowledgement at all on a synchronized connection is
/// dropped without an answer (RFC 793 p.72).
#[test]
fn a_segment_with_no_acknowledgement_is_dropped_in_silence() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0xc000);
    let mut out = [0u8; 2048];
    handshake(&mut stack, at(0), &mut peer);

    let bare = peer.segment_at(peer.next, Flags::PSH, b"data");
    let received = stack.receive(at(1_000), STATION, &bare, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::NoAcknowledgement))
    );
    assert_eq!(received.emitted, 0);
    assert!(received.data.is_empty());
    assert_eq!(stack.counters().refused_no_acknowledgement, 1);
}

/// A retransmission overlapping the left edge of the window has its already
/// received prefix trimmed and the rest delivered, which is what makes a lost
/// acknowledgement recoverable.
#[test]
fn a_partly_received_retransmission_is_trimmed_rather_than_refused() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0xd000);
    let mut out = [0u8; 2048];
    handshake(&mut stack, at(0), &mut peer);
    let first = peer.next;

    let data = peer.data(b"abcd");
    let received = stack.receive(at(1_000), STATION, &data, &mut out);
    assert_eq!(received.data, b"abcd");
    peer.read(&out[..received.emitted]);

    // The peer re-sends from two bytes back, with two more bytes on the end.
    let overlap = peer.segment_at(first.add(2), Flags::ACK.with(Flags::PSH), b"cdef");
    let received = stack.receive(at(2_000), STATION, &overlap, &mut out);
    assert_eq!(received.data, b"ef", "the overlap was not trimmed");
    assert_eq!(stack.counters().bytes_received, 6);

    // A pure retransmission of bytes already taken delivers nothing and is still
    // acknowledged, so the peer stops re-sending.
    let stale = peer.segment_at(first, Flags::ACK.with(Flags::PSH), b"abcd");
    let received = stack.receive(at(3_000), STATION, &stale, &mut out);
    assert!(received.data.is_empty());
    assert!(
        received.emitted > 0,
        "a stale retransmission went unanswered"
    );
}

/// There is no reassembly queue, so in-window data ahead of the next byte is
/// dropped and re-requested. The acknowledgement that follows is what asks for
/// it again.
#[test]
fn in_window_data_ahead_of_the_next_byte_is_dropped_and_re_requested() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0xe000);
    let mut out = [0u8; 2048];
    handshake(&mut stack, at(0), &mut peer);
    let expected = peer.next;

    let ahead = peer.segment_at(expected.add(10), Flags::ACK.with(Flags::PSH), b"gap");
    let received = stack.receive(at(1_000), STATION, &ahead, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::OutOfOrder))
    );
    assert!(received.data.is_empty());
    let answer = peer.read(&out[..received.emitted]);
    assert_eq!(
        answer.acknowledgement, expected,
        "the hole was not re-requested"
    );
    assert_eq!(stack.counters().refused_out_of_order, 1);
}

/// A peer overshooting the advertised window has the excess dropped rather than
/// delivered: the window is a promise about how much this end will take.
#[test]
fn data_past_the_advertised_window_is_trimmed() {
    let mut stack = TcpStack::<2>::new(APPLIANCE, PORT, MSS_LIMIT, 16, secret());
    let mut peer = Peer::new(40000, 0xf000);
    let mut out = [0u8; 2048];

    let syn = peer.syn();
    let received = stack.receive(at(0), STATION, &syn, &mut out);
    let id = received.connection.expect("a connection");
    let syn_ack = peer.read(&out[..received.emitted]);
    assert_eq!(syn_ack.window, 16);
    let ack = peer.ack();
    stack.receive(at(0), STATION, &ack, &mut out);

    let flood = peer.segment_at(peer.next, Flags::ACK.with(Flags::PSH), &[0x5a; 64]);
    let received = stack.receive(at(1_000), STATION, &flood, &mut out);
    assert_eq!(
        received.data.len(),
        16,
        "more than the window was delivered"
    );
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::Established)
    );
}

#[test]
fn a_segment_for_a_port_nothing_listens_on_is_dropped_in_silence() {
    let mut stack = stack();
    let mut out = [0u8; 2048];
    let mut peer = Peer::new(40000, 0x1_0000);
    let mut segment = peer.syn();
    // Re-address it to a port this stack does not hold, checksum included.
    let elsewhere = Outgoing {
        source_port: 40000,
        destination_port: 8080,
        sequence: SeqNumber::new(1),
        acknowledgement: SeqNumber::new(0),
        flags: Flags::SYN,
        window: 4096,
        mss: None,
        window_scale: None,
        payload: &[],
    };
    let mut buffer = [0u8; 64];
    let len = elsewhere
        .write(STATION, APPLIANCE, &mut buffer)
        .expect("room");
    segment.clear();
    segment.extend_from_slice(&buffer[..len]);

    let received = stack.receive(at(0), STATION, &segment, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::NotListening { port: 8080 })
    );
    assert_eq!(received.emitted, 0, "a closed port answered");
    assert_eq!(stack.counters().refused_not_listening, 1);
    assert_eq!(stack.connections(), 0);
}

/// RFC 793 section 3.4: a segment naming a connection that does not exist is answered
/// with a `RST`, so a peer holding half a connection learns to let go — but a
/// `RST` itself never provokes one.
#[test]
fn a_segment_for_no_connection_is_reset_and_a_reset_is_not() {
    let mut stack = stack();
    let mut out = [0u8; 2048];
    let mut peer = Peer::new(40000, 0x2_0000);

    let stray = peer.ack();
    let received = stack.receive(at(0), STATION, &stray, &mut out);
    assert_eq!(received.outcome, Outcome::Rejected(Rejection::NoConnection));
    let reset =
        Segment::parse(APPLIANCE, STATION, &out[..received.emitted]).expect("a reset came back");
    assert!(reset.flags.contains(Flags::RST));
    assert_eq!(stack.counters().resets_sent, 1);

    // Data with no acknowledgement gets a `RST` acknowledging what arrived.
    let stray = peer.segment_at(SeqNumber::new(500), Flags::PSH, b"hello");
    let received = stack.receive(at(1_000), STATION, &stray, &mut out);
    let reset =
        Segment::parse(APPLIANCE, STATION, &out[..received.emitted]).expect("a reset came back");
    assert!(reset.flags.contains(Flags::RST));
    assert!(reset.flags.contains(Flags::ACK));
    assert_eq!(reset.acknowledgement, SeqNumber::new(505));

    // And a `RST` for nothing is dropped in silence.
    let stray = peer.segment_at(SeqNumber::new(700), Flags::RST, &[]);
    let received = stack.receive(at(2_000), STATION, &stray, &mut out);
    assert_eq!(received.outcome, Outcome::Rejected(Rejection::NoConnection));
    assert_eq!(received.emitted, 0);
    assert_eq!(stack.counters().resets_sent, 2, "a reset was answered");
    assert_eq!(stack.counters().refused_no_connection, 3);
}

/// A `SYN` flood: the table fills, the oldest half-open connection is taken back
/// for each new one, and the table never exceeds its capacity.
#[test]
fn a_flood_of_distinct_tuples_is_bounded_by_the_table() {
    let mut stack = stack();
    let mut out = [0u8; 2048];
    for index in 0..64u16 {
        let mut peer = Peer::new(40000 + index, u32::from(index) * 0x1000);
        let syn = peer.syn();
        // Each `SYN` is a full second apart, so eviction has an unambiguous
        // oldest to choose.
        stack.receive(
            at(u64::from(index) * 1_000_000_000),
            STATION,
            &syn,
            &mut out,
        );
        assert!(stack.connections() <= 4, "the table exceeded its capacity");
    }
    assert_eq!(stack.connections(), 4);
    assert_eq!(stack.counters().connections_accepted, 64);
    assert!(
        stack.counters().connections_evicted + stack.counters().connections_reaped >= 60,
        "nothing was taken back"
    );
    assert_eq!(stack.counters().refused_table_full, 0);
}

/// A table full of *established* connections refuses a new one rather than
/// evicting one: a peer that can complete handshakes must not be able to evict
/// everybody else.
#[test]
fn a_table_of_established_connections_refuses_rather_than_evicting() {
    let mut stack = stack();
    let mut out = [0u8; 2048];
    for index in 0..4u16 {
        let mut peer = Peer::new(40000 + index, u32::from(index) * 0x1000 + 1);
        handshake(&mut stack, at(1_000 + u64::from(index)), &mut peer);
    }
    assert_eq!(stack.connections(), 4);

    let mut newcomer = Peer::new(50000, 0x9_0000);
    let syn = newcomer.syn();
    let received = stack.receive(at(2_000), STATION, &syn, &mut out);
    assert_eq!(received.outcome, Outcome::Rejected(Rejection::TableFull));
    assert_eq!(received.emitted, 0, "a refusal was answered");
    assert_eq!(stack.counters().refused_table_full, 1);
    assert_eq!(stack.connections(), 4);

    // And once one has been idle long enough, the slot comes back.
    let late = after(IDLE_TIMEOUT).saturating_add(lfw_clock::Duration::from_millis(1));
    let syn = newcomer.syn();
    let received = stack.receive(late, STATION, &syn, &mut out);
    assert_eq!(received.outcome, Outcome::Accepted);
    assert_eq!(stack.connections(), 4);
}

/// The `SYN-ACK` is re-sent by the timer, composed from the connection's own
/// state so the peer sees one sequence space.
#[test]
fn a_lost_syn_ack_is_re_sent_by_the_timer() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x3_0000);
    let mut out = [0u8; 2048];

    let syn = peer.syn();
    let received = stack.receive(at(0), STATION, &syn, &mut out);
    let id = received.connection.expect("a connection");
    let first = Segment::parse(APPLIANCE, STATION, &out[..received.emitted])
        .expect("a SYN-ACK")
        .sequence;

    assert_eq!(stack.poll_timeouts(at(1_000), &mut out), None);
    let due = after(INITIAL_RTO);
    let timeout = stack.poll_timeouts(due, &mut out).expect("the timer fired");
    let Timeout::Resent { connection, len } = timeout else {
        panic!("expected a re-sent control segment, got {timeout:?}");
    };
    assert_eq!(connection, id);
    let again = Segment::parse(APPLIANCE, STATION, &out[..len]).expect("a SYN-ACK");
    assert!(again.flags.contains(Flags::SYN));
    assert_eq!(again.sequence, first);
    assert_eq!(again.options.mss, Some(MSS_LIMIT));
    assert_eq!(stack.counters().retransmits, 1);

    // The timer has backed off, so the same instant does not fire twice.
    assert_eq!(stack.poll_timeouts(due, &mut out), None);
}

/// A `SYN-ACK` re-sent to exhaustion abandons the connection with a `RST`.
#[test]
fn retransmissions_are_bounded_and_then_the_connection_is_abandoned() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x4_0000);
    let mut out = [0u8; 2048];

    let syn = peer.syn();
    let received = stack.receive(at(0), STATION, &syn, &mut out);
    let id = received.connection.expect("a connection");

    let mut now = at(0);
    let mut resent = 0;
    for _ in 0..MAX_RETRANSMITS + 4 {
        // Advanced by the timeout in force rather than by the ceiling: the
        // reaping sweep runs before the retransmission one, so a jump past the
        // idle limit would reap the connection instead of retransmitting on it.
        let timeout = stack
            .connection(id)
            .map(Connection::timeout)
            .expect("the connection is still held");
        now = now
            .saturating_add(timeout)
            .saturating_add(lfw_clock::Duration::from_nanos(1));
        match stack.poll_timeouts(now, &mut out) {
            Some(Timeout::Resent { .. }) => resent += 1,
            Some(Timeout::Abandoned { connection, len }) => {
                assert_eq!(connection, id);
                let reset =
                    Segment::parse(APPLIANCE, STATION, &out[..len]).expect("a reset came back");
                assert!(reset.flags.contains(Flags::RST));
                assert_eq!(resent, MAX_RETRANSMITS as usize);
                assert_eq!(stack.connections(), 0);
                assert_eq!(stack.counters().connections_abandoned, 1);
                return;
            }
            other => panic!("unexpected timeout {other:?}"),
        }
    }
    panic!("the connection was never abandoned");
}

/// Data must be re-sent by the caller, because this crate never kept it. That is
/// the crate's central trade, so it is asserted end to end.
#[test]
fn re_sending_data_asks_the_caller_for_the_bytes_again() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x5_0000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    let payload = b"the caller still holds these";
    let sent = stack
        .send(at(1_000), id, payload, &mut out)
        .expect("a segment");
    let first = Segment::parse(APPLIANCE, STATION, &out[..sent.len])
        .expect("a data segment")
        .sequence;

    let due = at(1_000).saturating_add(INITIAL_RTO);
    let timeout = stack.poll_timeouts(due, &mut out).expect("the timer fired");
    let Timeout::Retransmit {
        connection,
        sequence,
        len,
    } = timeout
    else {
        panic!("expected a request for the bytes, got {timeout:?}");
    };
    assert_eq!(connection, id);
    assert_eq!(sequence, first);
    assert_eq!(usize::from(len), payload.len());

    let written = stack
        .retransmit(due, id, sequence, payload, &mut out)
        .expect("the caller supplied the range");
    let again = Segment::parse(APPLIANCE, STATION, &out[..written]).expect("a data segment");
    assert_eq!(again.sequence, first);
    assert_eq!(again.payload, payload);
    assert_eq!(stack.counters().retransmits, 1);
    assert_eq!(stack.counters().bytes_retransmitted, payload.len() as u64);
}

/// The check that keeps a caller's bookkeeping mistake out of the stream, and
/// the enforcer `TcpStack::retransmit`'s documentation names.
#[test]
fn retransmitting_the_wrong_range_is_refused() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x6_0000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    assert_eq!(
        stack.retransmit(at(0), id, SeqNumber::new(0), b"", &mut out),
        Err(SendError::NothingOutstanding)
    );

    let payload = b"four";
    stack
        .send(at(1_000), id, payload, &mut out)
        .expect("a segment");
    let (oldest_sequence, oldest_len) = stack
        .connection(id)
        .and_then(Connection::oldest_range)
        .expect("one outstanding range");

    // The right sequence, the wrong length.
    assert_eq!(
        stack.retransmit(at(2_000), id, oldest_sequence, b"five!", &mut out),
        Err(SendError::WrongRange {
            expected: oldest_sequence,
            len: oldest_len
        })
    );
    // The right length, the wrong sequence.
    assert_eq!(
        stack.retransmit(at(2_000), id, oldest_sequence.add(1), payload, &mut out),
        Err(SendError::WrongRange {
            expected: oldest_sequence,
            len: oldest_len
        })
    );
}

/// Karn's algorithm: a range that has been re-sent yields no round-trip sample,
/// because there is no telling which transmission the acknowledgement covered.
#[test]
fn a_retransmitted_segment_yields_no_sample() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x7_0000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);
    // The handshake's own acknowledgement is a sample, so the timer has already
    // measured; a second connection with no measurement is what shows the rule.
    let mut fresh = Peer::new(40001, 0x7_1000);
    let other = handshake(&mut stack, at(0), &mut fresh);
    assert!(
        stack
            .connection(other)
            .is_some_and(|connection| connection.measured()),
        "the handshake yielded no sample"
    );

    let payload = b"abcd";
    stack
        .send(at(1_000), id, payload, &mut out)
        .expect("a segment");

    let due = at(1_000).saturating_add(INITIAL_RTO);
    let Some(Timeout::Retransmit { sequence, .. }) = stack.poll_timeouts(due, &mut out) else {
        panic!("the timer did not ask for the bytes");
    };
    stack
        .retransmit(due, id, sequence, payload, &mut out)
        .expect("the caller supplied the range");
    // The expiry doubled the timeout once, and that is the value a Karn-refused
    // sample must leave untouched.
    let after_backoff = stack
        .connection(id)
        .map(Connection::timeout)
        .expect("a timer");

    // The peer acknowledges long after the original was sent. A sample taken
    // from it would be the whole backoff interval and would inflate the estimate
    // for the rest of the connection's life.
    peer.expect = peer.expect.add(payload.len() as u32);
    let ack = peer.ack();
    let much_later = due.saturating_add(MAX_RTO);
    stack.receive(much_later, STATION, &ack, &mut out);
    assert_eq!(stack.outstanding(id), 0, "the range was not retired");
    assert_eq!(
        stack.connection(id).map(Connection::timeout),
        Some(after_backoff),
        "a retransmitted range moved the estimate"
    );

    // The control: the same late acknowledgement on a range that was *not*
    // retransmitted does move it, all the way to the ceiling. Without this the
    // assertion above would pass for a stack that never samples at all.
    stack
        .send(much_later, other, payload, &mut out)
        .expect("a segment");
    fresh.expect = fresh.expect.add(payload.len() as u32);
    let ack = fresh.ack();
    let far = much_later.saturating_add(MAX_RTO);
    stack.receive(far, STATION, &ack, &mut out);
    assert_eq!(
        stack.connection(other).map(Connection::timeout),
        Some(MAX_RTO),
        "a fresh range yielded no sample"
    );
}

/// The flow-control window: a send takes no more than the peer allowed, and a
/// closed window takes nothing at all.
#[test]
fn a_send_is_bounded_by_the_peers_window() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x8_0000);
    peer.window = 10;
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    let sent = stack
        .send(at(1_000), id, &[0xcc; 100], &mut out)
        .expect("ten bytes fit");
    assert_eq!(sent.bytes, 10);

    // Nothing more until the peer acknowledges.
    assert_eq!(
        stack.send(at(2_000), id, &[0xcc; 100], &mut out),
        Err(SendError::WouldBlock)
    );

    // A window of zero closes it entirely.
    peer.window = 0;
    peer.expect = peer.expect.add(10);
    let ack = peer.ack();
    stack.receive(at(3_000), STATION, &ack, &mut out);
    assert_eq!(
        stack.send(at(4_000), id, &[0xcc; 100], &mut out),
        Err(SendError::WouldBlock)
    );

    // And re-opening it lets the rest go.
    peer.window = 4096;
    let ack = peer.ack();
    stack.receive(at(5_000), STATION, &ack, &mut out);
    let sent = stack
        .send(at(6_000), id, &[0xcc; 100], &mut out)
        .expect("the window re-opened");
    assert_eq!(sent.bytes, 100);
}

/// RFC 793 p.72's `WL1`/`WL2` test: an old segment arriving late must not
/// replace a newer window with its own.
#[test]
fn an_old_segment_cannot_shrink_the_window_back() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x9_0000);
    peer.window = 100;
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);
    let stale_sequence = peer.next;

    // A newer segment widens the window.
    peer.window = 4096;
    let ack = peer.ack();
    stack.receive(at(1_000), STATION, &ack, &mut out);

    // The old one, re-delivered, names a smaller window at an older sequence.
    let stale = peer.segment_at(stale_sequence, Flags::ACK, &[]);
    stack.receive(at(2_000), STATION, &stale, &mut out);
    let sent = stack
        .send(at(3_000), id, &[0x11; 512], &mut out)
        .expect("the wider window is still in force");
    assert_eq!(sent.bytes, 512);
}

/// Only a connection in a state that can carry data accepts one, and a caller's
/// stale handle names nothing.
#[test]
fn a_send_is_refused_from_a_state_that_cannot_carry_it() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0xa_0000);
    let mut out = [0u8; 2048];

    let syn = peer.syn();
    let received = stack.receive(at(0), STATION, &syn, &mut out);
    let id = received.connection.expect("a connection");
    assert_eq!(
        stack.send(at(0), id, b"early", &mut out),
        Err(SendError::WrongState(State::SynReceived))
    );
    assert_eq!(
        stack.close(at(0), id, &mut out),
        Err(SendError::WrongState(State::SynReceived))
    );

    peer.read(&out[..received.emitted]);
    let ack = peer.ack();
    stack.receive(at(0), STATION, &ack, &mut out);
    stack.close(at(1_000), id, &mut out).expect("a FIN");
    assert_eq!(
        stack.close(at(2_000), id, &mut out),
        Err(SendError::WrongState(State::FinWait1))
    );
    assert_eq!(
        stack.send(at(2_000), id, b"late", &mut out),
        Err(SendError::WrongState(State::FinWait1))
    );
}

/// A handle to a slot that has been reused names nothing, which is what the
/// generation is for.
#[test]
fn a_stale_handle_never_addresses_the_connection_that_replaced_it() {
    let mut stack = TcpStack::<1>::new(APPLIANCE, PORT, MSS_LIMIT, RECEIVE_WINDOW, secret());
    let mut out = [0u8; 2048];

    let mut first = Peer::new(40000, 0xb_0000);
    let syn = first.syn();
    let received = stack.receive(at(0), STATION, &syn, &mut out);
    let stale = received.connection.expect("a connection");

    // The one slot is taken over by a second peer.
    let mut second = Peer::new(40001, 0xc_0000);
    let syn = second.syn();
    let received = stack.receive(at(1_000_000_000), STATION, &syn, &mut out);
    let fresh = received.connection.expect("a connection");
    assert_ne!(stale, fresh);
    assert_eq!(stack.connections(), 1);

    for outcome in [
        stack.send(at(2_000), stale, b"x", &mut out).map(|_| ()),
        stack.close(at(2_000), stale, &mut out).map(|_| ()),
        stack
            .retransmit(at(2_000), stale, SeqNumber::new(0), b"", &mut out)
            .map(|_| ()),
    ] {
        assert_eq!(outcome, Err(SendError::UnknownConnection));
    }
    assert_eq!(stack.connection(stale), None);
    assert_eq!(stack.outstanding(stale), 0);
    assert!(stack.connection(fresh).is_some());
}

/// Storage too small is **our** fault, not the peer's, and it is counted apart
/// from everything a peer can cause.
#[test]
fn a_reply_that_does_not_fit_is_counted_as_ours() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0xd_0000);
    let mut tiny = [0u8; 8];

    let syn = peer.syn();
    let received = stack.receive(at(0), STATION, &syn, &mut tiny);
    assert!(matches!(
        received.outcome,
        Outcome::Rejected(Rejection::WriteRefused(_))
    ));
    assert_eq!(received.emitted, 0);
    assert_eq!(stack.counters().write_refused, 1);
    // The connection survives: its own timer will try again with whatever
    // storage the next poll offers.
    assert_eq!(stack.connections(), 1);
    let id = received.connection.expect("a connection");

    let mut out = [0u8; 2048];
    let due = after(INITIAL_RTO);
    assert!(matches!(
        stack.poll_timeouts(due, &mut out),
        Some(Timeout::Resent { .. })
    ));
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::SynReceived)
    );

    // And a send into storage too small is refused the same way.
    let mut peer = Peer::new(40001, 0xd_1000);
    let id = handshake(&mut stack, at(0), &mut peer);
    // The range was recorded and the sequence advanced before the compose, so
    // the refusal names the bytes the caller must still hold for it.
    assert!(matches!(
        stack.send(at(1_000), id, b"payload", &mut tiny),
        Err(SendError::Write { committed: 7, .. })
    ));
    assert_eq!(stack.counters().write_refused, 2);
}

/// `URG` is parsed, the pointer ignored, the data delivered in band, and the
/// fact counted — which is what keeps "ignored" from also meaning "invisible".
#[test]
fn urgent_data_is_delivered_in_band_and_counted() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0xe_0000);
    let mut out = [0u8; 2048];
    handshake(&mut stack, at(0), &mut peer);

    let urgent = peer.segment_at(
        peer.next,
        Flags::ACK.with(Flags::URG).with(Flags::PSH),
        b"now",
    );
    let received = stack.receive(at(1_000), STATION, &urgent, &mut out);
    assert_eq!(received.data, b"now");
    assert_eq!(stack.counters().urgent_ignored, 1);
}

/// A malformed segment never reaches a connection, and the two refusals are
/// counted apart: a bad checksum accuses a corrupted or forged segment, a bad
/// data offset a sender that cannot compose one.
#[test]
fn malformed_segments_are_refused_before_any_connection_sees_them() {
    let mut stack = stack();
    let mut out = [0u8; 2048];

    let received = stack.receive(at(0), STATION, &[0u8; 4], &mut out);
    assert!(matches!(
        received.outcome,
        Outcome::Rejected(Rejection::Malformed(SegmentError::TooShort { got: 4 }))
    ));
    assert_eq!(stack.counters().refused_malformed, 1);

    let mut peer = Peer::new(40000, 0xf_0000);
    let mut syn = peer.syn();
    syn[16] ^= 0xff;
    let received = stack.receive(at(0), STATION, &syn, &mut out);
    assert!(matches!(
        received.outcome,
        Outcome::Rejected(Rejection::Malformed(SegmentError::ChecksumInvalid { .. }))
    ));
    assert_eq!(stack.counters().refused_bad_checksum, 1);
    assert_eq!(stack.counters().refused_malformed, 1);
    assert_eq!(stack.connections(), 0);
    assert_eq!(stack.counters().segments_received, 2);
}

/// Two peers on one port and two on another: nothing crosses between
/// connections, which is what the 4-tuple match is for.
#[test]
fn connections_are_kept_apart_by_their_whole_tuple() {
    let mut stack = stack();
    let mut out = [0u8; 2048];
    let mut first = Peer::new(40000, 0x10_0000);
    let mut second = Peer::at(Ipv4Address::from_octets([10, 0, 2, 3]), 40000, 0x20_0000);

    let one = handshake(&mut stack, at(0), &mut first);
    let two = handshake(&mut stack, at(0), &mut second);
    assert_ne!(one, two);
    assert_eq!(stack.connections(), 2);

    let data = first.data(b"first");
    let received = stack.receive(at(1_000), first.address, &data, &mut out);
    assert_eq!(received.connection, Some(one));
    assert_eq!(received.data, b"first");

    let data = second.data(b"second");
    let received = stack.receive(at(2_000), second.address, &data, &mut out);
    assert_eq!(received.connection, Some(two));
    assert_eq!(received.data, b"second");
}

/// The initial sequence number differs per 4-tuple, which is the RFC 6528
/// property an off-path attacker attacks.
#[test]
fn two_connections_are_offered_different_sequence_spaces() {
    let mut stack = stack();
    let mut out = [0u8; 2048];
    let mut sequences = Vec::new();
    for port in [40000u16, 40001, 40002] {
        let mut peer = Peer::new(port, 0x30_0000);
        let syn = peer.syn();
        let received = stack.receive(at(0), STATION, &syn, &mut out);
        sequences.push(
            Segment::parse(APPLIANCE, STATION, &out[..received.emitted])
                .expect("a SYN-ACK")
                .sequence,
        );
    }
    assert_ne!(sequences[0], sequences[1]);
    assert_ne!(sequences[1], sequences[2]);
    assert_ne!(sequences[0], sequences[2]);
}

/// `TIME_WAIT` answers a retransmitted `FIN` and restarts its wait, so the
/// acknowledgement has a lifetime of its own to be delivered in.
#[test]
fn a_retransmitted_fin_in_time_wait_is_answered_and_the_wait_restarts() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x40_0000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    let len = stack.close(at(1_000), id, &mut out).expect("a FIN");
    peer.read(&out[..len]);
    let ack = peer.ack();
    stack.receive(at(2_000), STATION, &ack, &mut out);
    let fin_sequence = peer.next;
    let fin = peer.fin();
    let received = stack.receive(at(3_000), STATION, &fin, &mut out);
    peer.read(&out[..received.emitted]);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::TimeWait)
    );

    // Re-deliver it one nanosecond before the wait would have ended.
    let late = after(TIME_WAIT_DURATION);
    let nearly = at(TIME_WAIT_DURATION.as_nanos() - 1);
    let again = peer.segment_at(fin_sequence, Flags::FIN.with(Flags::ACK), &[]);
    let received = stack.receive(nearly, STATION, &again, &mut out);
    assert!(received.emitted > 0, "a retransmitted FIN went unanswered");
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::TimeWait)
    );
    // The wait restarted, so the original deadline no longer reaps it.
    assert_eq!(stack.poll_timeouts(late, &mut out), None);
    let restarted = nearly.saturating_add(TIME_WAIT_DURATION);
    assert!(matches!(
        stack.poll_timeouts(restarted, &mut out),
        Some(Timeout::Reaped { .. })
    ));
}

/// A connection that never says anything again is taken back, which is what
/// makes every connection reapable in finite time.
#[test]
fn an_idle_connection_is_reaped() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x50_0000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);
    // Its own acknowledgement retired the SYN-ACK, so no retransmission timer
    // fires and the idle limit is what ends it.
    assert_eq!(stack.outstanding(id), 0);
    assert_eq!(stack.poll_timeouts(at(1_000), &mut out), None);
    assert_eq!(
        stack.poll_timeouts(after(IDLE_TIMEOUT), &mut out),
        Some(Timeout::Reaped { connection: id })
    );
    assert_eq!(stack.connections(), 0);
}

/// Every field of the stack a caller reads back is what it was built with.
#[test]
fn a_stack_reports_what_it_listens_on() {
    let stack = stack();
    assert_eq!(stack.address(), APPLIANCE);
    assert_eq!(stack.port(), PORT);
    assert_eq!(stack.connections(), 0);
    assert_eq!(stack.counters(), TcpCounters::new());
}

proptest! {
    /// The state machine never panics for an arbitrary sequence of arbitrary
    /// segments against an arbitrary state, and the table never exceeds its
    /// capacity. This is the no-panic-on-arbitrary-input invariant, over the whole surface at
    /// once: the bytes are arbitrary, so every parser, every window computation
    /// and every transition is reached by inputs nobody chose.
    #[test]
    fn arbitrary_segment_streams_never_panic_and_stay_bounded(
        segments in prop::collection::vec(
            (prop::collection::vec(any::<u8>(), 0..80), any::<u8>(), any::<u16>()),
            0..48,
        ),
    ) {
        let mut stack = stack();
        let mut out = [0u8; 2048];
        for (index, (bytes, source, span)) in segments.iter().enumerate() {
            // The source address varies, so a stream is spread over several
            // 4-tuples and the table is driven to its edge.
            let source = Ipv4Address::from_octets([10, 0, 2, *source]);
            let now = at(u64::from(*span) * 1_000_000);
            let received = stack.receive(now, source, bytes, &mut out);
            // Whatever was emitted fits the storage and is a segment or nothing.
            prop_assert!(received.emitted <= out.len());
            prop_assert!(received.data.len() <= bytes.len());
            prop_assert!(stack.connections() <= 4, "the table overflowed at {index}");
            // Draining the timers is bounded: each answer either frees a slot or
            // pushes a deadline out, so this cannot spin.
            let mut drained = 0;
            while stack.poll_timeouts(now, &mut out).is_some() {
                drained += 1;
                prop_assert!(drained <= 64, "the timers did not settle");
            }
            prop_assert_eq!(
                stack.counters().segments_received,
                index as u64 + 1,
                "a segment went uncounted"
            );
        }
    }

    /// A flood of distinct 4-tuples leaves state bounded by the table and by
    /// nothing the peer chooses. The counters are what make the
    /// boundedness observable rather than merely true.
    #[test]
    fn a_flood_of_distinct_tuples_leaves_bounded_state(
        count in 0usize..200,
        window in any::<u16>(),
    ) {
        let mut stack = stack();
        let mut out = [0u8; 2048];
        for index in 0..count {
            // Lossless: `count` is bounded above by the strategy.
            let mut peer = Peer::new(40000u16.wrapping_add(index as u16), index as u32 * 7);
            peer.window = window;
            let syn = peer.syn();
            stack.receive(at(index as u64 * 1_000_000_000), STATION, &syn, &mut out);
            prop_assert!(stack.connections() <= 4);
        }
        prop_assert_eq!(stack.counters().connections_accepted, count as u64);
        prop_assert!(stack.connections() <= count.min(4));
    }

    /// No segment is ever accepted outside the receive window: for any offset a
    /// peer chooses, data is delivered only where the segment began at the next
    /// byte expected or overlapped it.
    #[test]
    fn data_is_never_accepted_outside_the_window(offset in any::<u32>(), len in 0usize..40) {
        let mut stack = stack();
        let mut peer = Peer::new(40000, 0x1234);
        let mut out = [0u8; 2048];
        handshake(&mut stack, at(0), &mut peer);
        let expected = peer.next;

        let payload = std::vec![0x77u8; len];
        let probe = peer.segment_at(expected.add(offset), Flags::ACK.with(Flags::PSH), &payload);
        let received = stack.receive(at(1_000), STATION, &probe, &mut out);
        if received.data.is_empty() {
            return Ok(());
        }
        // Something was delivered, so the segment must have covered the next
        // byte expected — either starting at it, or starting before it and
        // reaching it.
        // Lossless: `len` is bounded by the strategy.
        let len = len as u32;
        let starts_at_next = offset == 0;
        // A segment starting *before* the next byte expected reaches it when its
        // own length covers the gap. The offset is that gap read backwards, so
        // the test is stated in the wrapped distance rather than in a sum that
        // would leave `u32`.
        let behind_by = 0u32.wrapping_sub(offset);
        let overlaps = behind_by > 0 && behind_by < len;
        prop_assert!(
            starts_at_next || overlaps,
            "offset {} delivered {} bytes",
            offset,
            received.data.len()
        );
        // And never more than the window.
        prop_assert!(received.data.len() as u32 <= RECEIVE_WINDOW);
    }

    /// Every connection becomes reapable in finite time, whatever state it is
    /// left in: the table cannot be filled with connections that never come
    /// back.
    #[test]
    fn every_connection_is_eventually_reapable(script in prop::collection::vec(0u8..6, 0..8)) {
        let mut stack = stack();
        let mut peer = Peer::new(40000, 0x99);
        let mut out = [0u8; 2048];
        let id = handshake(&mut stack, at(0), &mut peer);
        for step in &script {
            let segment = match step {
                0 => peer.data(b"data"),
                1 => peer.ack(),
                2 => peer.fin(),
                3 => peer.segment_at(peer.next, Flags::SYN, &[]),
                4 => peer.segment_at(peer.next.add(9_999), Flags::ACK, b"far"),
                _ => {
                    let _ = stack.close(at(1_000), id, &mut out);
                    continue;
                }
            };
            stack.receive(at(1_000), STATION, &segment, &mut out);
        }
        // Far beyond every deadline this crate holds.
        let far = at(IDLE_TIMEOUT.as_nanos() + TIME_WAIT_DURATION.as_nanos() + 1);
        let mut drained = 0;
        while stack.poll_timeouts(far, &mut out).is_some() {
            drained += 1;
            prop_assert!(drained <= 64, "the timers did not settle");
        }
        prop_assert_eq!(stack.connections(), 0, "a connection outlived every timer");
    }

    /// Whatever a caller offers, a send takes no more than the negotiated
    /// segment size and no more than the peer's window, and it reports exactly
    /// what it took.
    #[test]
    fn a_send_never_exceeds_the_segment_size_or_the_window(
        offered in 0usize..4096,
        window in any::<u16>(),
    ) {
        let mut stack = stack();
        let mut peer = Peer::new(40000, 0x4321);
        peer.window = window;
        let mut out = [0u8; 4096];
        let id = handshake(&mut stack, at(0), &mut peer);
        let payload = std::vec![0x5cu8; offered];
        match stack.send(at(1_000), id, &payload, &mut out) {
            Ok(sent) => {
                prop_assert!(sent.bytes <= offered);
                prop_assert!(sent.bytes <= usize::from(MSS_LIMIT));
                prop_assert!(sent.bytes <= usize::from(window));
                prop_assert!(sent.len >= sent.bytes);
                prop_assert_eq!(stack.outstanding(id), 1);
            }
            Err(SendError::WouldBlock) => {
                prop_assert!(offered == 0 || window == 0);
            }
            Err(other) => prop_assert!(false, "unexpected {:?}", other),
        }
    }
}

/// The record table is the bound on how much a caller may have in flight, and it
/// is what obliges the caller to hold those bytes. A send past it is refused
/// without a segment having been composed.
#[test]
fn a_send_is_refused_once_every_range_is_outstanding() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x11_0000);
    peer.window = 4096;
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    for index in 0..MAX_UNACKED {
        stack
            .send(at(1_000), id, b"chunk", &mut out)
            .unwrap_or_else(|error| panic!("range {index} was refused: {error:?}"));
    }
    assert_eq!(stack.outstanding(id), MAX_UNACKED);
    assert_eq!(
        stack.send(at(1_000), id, b"chunk", &mut out),
        Err(SendError::WouldBlock)
    );
    // And so is a close, which owes a record of its own for the `FIN`.
    assert_eq!(
        stack.close(at(1_000), id, &mut out),
        Err(SendError::WrongState(State::Established))
    );

    // The oldest range is the one a timeout asks for, whichever order they were
    // recorded in.
    let (oldest, _) = stack
        .connection(id)
        .and_then(Connection::oldest_range)
        .expect("four outstanding ranges");
    assert_eq!(oldest, peer.expect);
}

/// An acknowledgement covering some but not all of what is outstanding retires
/// exactly what it covers.
#[test]
fn a_partial_acknowledgement_retires_only_what_it_covers() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x12_0000);
    peer.window = 4096;
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    stack
        .send(at(1_000), id, b"first", &mut out)
        .expect("a segment");
    stack
        .send(at(1_000), id, b"second", &mut out)
        .expect("a segment");
    assert_eq!(stack.outstanding(id), 2);

    // Acknowledge the first five bytes only.
    peer.expect = peer.expect.add(5);
    let ack = peer.ack();
    stack.receive(at(2_000), STATION, &ack, &mut out);
    assert_eq!(stack.outstanding(id), 1);
    let (oldest, len) = stack
        .connection(id)
        .and_then(Connection::oldest_range)
        .expect("one range left");
    assert_eq!(oldest, peer.expect);
    assert_eq!(len, 6);

    // And then the rest.
    peer.expect = peer.expect.add(6);
    let ack = peer.ack();
    stack.receive(at(3_000), STATION, &ack, &mut out);
    assert_eq!(stack.outstanding(id), 0);
}

/// A `FIN` this end re-sends is composed from its record, so the peer sees the
/// same close twice rather than two different ones.
#[test]
fn a_lost_fin_is_re_sent_by_the_timer() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x13_0000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    let len = stack.close(at(1_000), id, &mut out).expect("a FIN");
    let first = Segment::parse(APPLIANCE, STATION, &out[..len])
        .expect("a FIN")
        .sequence;

    let due = at(1_000).saturating_add(INITIAL_RTO);
    let Some(Timeout::Resent { connection, len }) = stack.poll_timeouts(due, &mut out) else {
        panic!("the FIN was not re-sent");
    };
    assert_eq!(connection, id);
    let again = Segment::parse(APPLIANCE, STATION, &out[..len]).expect("a FIN");
    assert!(again.flags.contains(Flags::FIN));
    assert!(again.flags.contains(Flags::ACK));
    assert!(!again.flags.contains(Flags::SYN));
    assert_eq!(again.sequence, first);
    // A re-sent `FIN` carries no options: they belong on a `SYN` alone.
    assert_eq!(again.options, Options::default());
}

/// A window of zero on this end's side admits nothing but a segment occupying no
/// sequence space at the exact next byte — RFC 793 p.69's first case, which no
/// ordinary configuration reaches.
#[test]
fn a_zero_receive_window_admits_only_a_bare_acknowledgement() {
    let mut stack = TcpStack::<2>::new(APPLIANCE, PORT, MSS_LIMIT, 0, secret());
    let mut peer = Peer::new(40000, 0x14_0000);
    let mut out = [0u8; 2048];

    let syn = peer.syn();
    let received = stack.receive(at(0), STATION, &syn, &mut out);
    let id = received.connection.expect("a connection");
    let syn_ack = peer.read(&out[..received.emitted]);
    assert_eq!(syn_ack.window, 0);

    // A bare acknowledgement at the next byte is accepted, and completes the
    // handshake.
    let ack = peer.ack();
    let received = stack.receive(at(1_000), STATION, &ack, &mut out);
    assert_eq!(received.outcome, Outcome::Advanced);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::Established)
    );

    // Data is refused, the window promising room for none.
    let data = peer.segment_at(peer.next, Flags::ACK.with(Flags::PSH), b"x");
    let received = stack.receive(at(2_000), STATION, &data, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::OutOfWindow))
    );

    // And so is a bare acknowledgement anywhere but at that exact byte.
    let elsewhere = peer.segment_at(peer.next.add(1), Flags::ACK, &[]);
    let received = stack.receive(at(3_000), STATION, &elsewhere, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::OutOfWindow))
    );
}

/// A `FIN` ahead of the next byte expected is refused rather than closing the
/// connection over a hole: the bytes in that hole would never be delivered.
#[test]
fn a_fin_ahead_of_the_next_byte_does_not_close_the_connection() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x15_0000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    let early = peer.segment_at(peer.next.add(20), Flags::FIN.with(Flags::ACK), &[]);
    let received = stack.receive(at(1_000), STATION, &early, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::OutOfOrder))
    );
    assert!(!received.peer_closed);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::Established),
        "a FIN over a hole closed the connection"
    );
}

/// Storage too small on every path that composes something, so the one counter
/// that accuses this stack rather than a peer is reached from each of them.
#[test]
fn every_composing_path_counts_storage_too_small_as_ours() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x16_0000);
    let mut out = [0u8; 2048];
    let mut tiny = [0u8; 4];
    let id = handshake(&mut stack, at(0), &mut peer);

    // An acknowledgement provoked by data.
    let data = peer.data(b"provoke");
    let received = stack.receive(at(1_000), STATION, &data, &mut tiny);
    assert_eq!(received.emitted, 0);
    assert_eq!(
        received.data, b"provoke",
        "the data was refused with the reply"
    );
    assert_eq!(stack.counters().write_refused, 1);

    // A `RST` for a connection that does not exist.
    let mut stranger = Peer::new(40001, 0x16_1000);
    let stray = stranger.ack();
    let received = stack.receive(at(2_000), STATION, &stray, &mut tiny);
    assert_eq!(received.emitted, 0);
    assert_eq!(stack.counters().write_refused, 2);

    // A re-sent control segment.
    stack.close(at(3_000), id, &mut out).expect("a FIN");
    let due = at(3_000).saturating_add(INITIAL_RTO);
    assert_eq!(
        stack.poll_timeouts(due, &mut tiny),
        Some(Timeout::Resent {
            connection: id,
            len: 0
        })
    );
    assert_eq!(stack.counters().write_refused, 3);

    // A re-sent range of data, refused before the record is disturbed.
    let mut third = Peer::new(40002, 0x16_2000);
    let other = handshake(&mut stack, at(4_000), &mut third);
    stack
        .send(at(4_000), other, b"payload", &mut out)
        .expect("a segment");
    let (sequence, _) = stack
        .connection(other)
        .and_then(Connection::oldest_range)
        .expect("one range");
    // Nothing is committed by a retransmission: the range was already
    // outstanding before it was asked for.
    assert!(matches!(
        stack.retransmit(at(5_000), other, sequence, b"payload", &mut tiny),
        Err(SendError::Write { committed: 0, .. })
    ));
    assert_eq!(stack.counters().write_refused, 4);
}

/// A `RST` sent because a connection was abandoned cannot be written either, and
/// the connection still goes.
#[test]
fn an_abandoned_connection_goes_even_when_its_reset_does_not_fit() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x17_0000);
    let mut out = [0u8; 2048];
    let mut tiny = [0u8; 4];

    let syn = peer.syn();
    let received = stack.receive(at(0), STATION, &syn, &mut out);
    let id = received.connection.expect("a connection");

    let mut now = at(0);
    for _ in 0..MAX_RETRANSMITS {
        let timeout = stack
            .connection(id)
            .map(Connection::timeout)
            .expect("the connection is held");
        now = now
            .saturating_add(timeout)
            .saturating_add(lfw_clock::Duration::from_nanos(1));
        assert!(matches!(
            stack.poll_timeouts(now, &mut out),
            Some(Timeout::Resent { .. })
        ));
    }
    let timeout = stack
        .connection(id)
        .map(Connection::timeout)
        .expect("the connection is held");
    now = now
        .saturating_add(timeout)
        .saturating_add(lfw_clock::Duration::from_nanos(1));
    assert_eq!(
        stack.poll_timeouts(now, &mut tiny),
        Some(Timeout::Abandoned {
            connection: id,
            len: 0
        })
    );
    assert_eq!(stack.connections(), 0);
}

/// The peer's SACK-permitted option is read and recorded, and nothing acts on it.
#[test]
fn the_sack_permitted_option_is_recorded_and_acted_on_by_nothing() {
    let mut stack = stack();
    let mut out = [0u8; 2048];
    // A `SYN` carrying SACK-permitted, composed by hand: `Outgoing` writes only
    // the two options this stack negotiates.
    let mut syn = [0u8; 24];
    let header = Outgoing {
        source_port: 40000,
        destination_port: PORT,
        sequence: SeqNumber::new(0x18_0000),
        acknowledgement: SeqNumber::new(0),
        flags: Flags::SYN,
        window: 4096,
        mss: None,
        window_scale: None,
        payload: &[],
    };
    let len = header.write(STATION, APPLIANCE, &mut syn).expect("room");
    assert_eq!(len, 20);
    // Six words of header, the extra one holding SACK-permitted and two NOPs.
    let mut with_option = syn[..20].to_vec();
    with_option[12] = 6 << 4;
    with_option.extend_from_slice(&[4, 2, 1, 1]);
    // The checksum was computed over the shorter segment, so it is recomputed
    // here the way a peer would.
    with_option[16] = 0;
    with_option[17] = 0;
    let sum = net_headers::Checksum::new()
        .add_address(STATION)
        .add_address(APPLIANCE)
        .add_u16(u16::from(net_headers::Protocol::TCP.0))
        .add_u16(with_option.len() as u16)
        .add_bytes(&with_option);
    let checksum = sum.finish().to_be_bytes();
    with_option[16] = checksum[0];
    with_option[17] = checksum[1];

    let received = stack.receive(at(0), STATION, &with_option, &mut out);
    assert_eq!(received.outcome, Outcome::Accepted);
    let id = received.connection.expect("a connection");
    assert!(
        stack.connection(id).is_some_and(Connection::sack_permitted),
        "the option was not recorded"
    );
    // And nothing was sent back for it: this stack offers no SACK of its own.
    let syn_ack = Segment::parse(APPLIANCE, STATION, &out[..received.emitted]).expect("a SYN-ACK");
    assert!(!syn_ack.options.sack_permitted);
}

/// The oldest outstanding range is the one a timeout asks for, and record slots
/// are reused out of order: an acknowledgement frees the first slot, and the next
/// send takes it with a *higher* sequence than the record beside it.
#[test]
fn the_oldest_range_is_found_whatever_slot_holds_it() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x19_0000);
    peer.window = 4096;
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    stack
        .send(at(1_000), id, b"aaa", &mut out)
        .expect("a segment");
    stack
        .send(at(1_000), id, b"bbb", &mut out)
        .expect("a segment");
    let second = peer.expect.add(3);

    // Acknowledge the first range, freeing the slot it held.
    peer.expect = peer.expect.add(3);
    let ack = peer.ack();
    stack.receive(at(2_000), STATION, &ack, &mut out);

    // The next send takes that slot, and its sequence is the highest of the two.
    stack
        .send(at(3_000), id, b"ccc", &mut out)
        .expect("a segment");
    assert_eq!(stack.outstanding(id), 2);
    let (oldest, _) = stack
        .connection(id)
        .and_then(Connection::oldest_range)
        .expect("two ranges");
    assert_eq!(
        oldest, second,
        "the newer slot was taken for the oldest range"
    );
}

/// A slot that holds no connection cannot be advanced. Driven directly because
/// `receive` reaches `advance` only through a lookup that has already found one,
/// so the refusal is defensive rather than reachable from the wire — and a
/// defensive path nothing exercises is a path nobody knows the shape of.
#[test]
fn advancing_an_empty_slot_is_refused() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x1a_0000);
    let mut out = [0u8; 2048];
    let bytes = peer.syn();
    let parsed = Segment::parse(STATION, APPLIANCE, &bytes).expect("a SYN");

    let received = stack.advance(at(0), 3, STATION, &parsed, &mut out);
    assert_eq!(received.outcome, Outcome::Rejected(Rejection::NoConnection));
    assert_eq!(received.emitted, 0);
    assert_eq!(stack.connections(), 0);
}

/// The advertised window is the caller's free space, and a caller that keeps it
/// so cannot be sent more than it can take. That is what removes the one lossy
/// case a receiver with no reassembly queue would otherwise have.
#[test]
fn the_advertised_window_is_the_callers_to_set() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x1b_0000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);
    assert_eq!(
        stack.connection(id).map(Connection::receive_window),
        Some(RECEIVE_WINDOW)
    );

    // The caller has taken four bytes of its own room.
    assert!(stack.set_receive_window(id, 4));
    let data = peer.data(b"abcdefgh");
    let received = stack.receive(at(1_000), STATION, &data, &mut out);
    assert_eq!(received.data, b"abcd", "more than the window was delivered");
    let ack = peer.read(&out[..received.emitted]);
    assert_eq!(ack.window, 4);

    // And a closed window takes nothing at all, while a bare acknowledgement at
    // the next byte is still accepted (RFC 793 p.69).
    assert!(stack.set_receive_window(id, 0));
    let data = peer.segment_at(peer.next, Flags::ACK.with(Flags::PSH), b"x");
    let received = stack.receive(at(2_000), STATION, &data, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::OutOfWindow))
    );

    // A handle that names nothing is refused rather than silently ignored.
    let mut gone = Peer::new(40001, 0x1b_1000);
    let stale = handshake(&mut stack, at(3_000), &mut gone);
    let reset = gone.segment_at(gone.next, Flags::RST, &[]);
    stack.receive(at(4_000), STATION, &reset, &mut out);
    assert!(!stack.set_receive_window(stale, 100));
}

/// RFC 5961 section 5's left edge, which is the half RFC 793 does not state: an
/// acknowledgement further behind `SND.UNA` than any window the peer ever
/// offered is challenged rather than believed, so it never reaches the window
/// update.
#[test]
fn an_acknowledgement_far_behind_the_send_window_is_challenged() {
    let mut stack = stack();
    // A peer whose `SYN` offers 4096, which is `MAX.SND.WND` from then on.
    let mut peer = Peer::new(40000, 0x1c_0000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);
    let una = peer.expect;

    // Exactly at the left edge is inside the acceptable range, so the refusal
    // below is a boundary rather than a blanket one.
    peer.expect = una.sub(4_096);
    let edge = peer.segment_at(peer.next, Flags::ACK, &[]);
    let received = stack.receive(at(1_000), STATION, &edge, &mut out);
    assert_eq!(received.outcome, Outcome::Advanced);

    // One byte further back is not, and the answer is a challenge rather than a
    // reset: a blind acknowledgement must not tear a connection down.
    peer.expect = una.sub(4_097);
    // A window of one byte, which the challenge must keep this end from
    // believing — reaching `update_window` is what the test is really about.
    peer.window = 1;
    let stale = peer.segment_at(peer.next, Flags::ACK, &[]);
    let received = stack.receive(at(2_000), STATION, &stale, &mut out);
    // The refusal names the peer's claim and what this end had really sent,
    // which for a connection that has sent only its own `SYN` is `una`.
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::UnacceptableAck {
            claimed: una.sub(4_097),
            expected: una
        }))
    );
    let challenge = peer.read(&out[..received.emitted]);
    assert!(
        !challenge.flags.contains(Flags::RST),
        "a blind acknowledgement drew a reset"
    );
    assert_eq!(stack.counters().refused_unacceptable_ack, 1);

    // The window it carried never reached the connection: a send still takes
    // what the handshake's own window allows.
    let sent = stack
        .send(at(3_000), id, &[0u8; 64], &mut out)
        .expect("a segment");
    assert_eq!(
        sent.bytes, 64,
        "a window from a challenged acknowledgement was believed"
    );
}

/// RFC 793 section 3.9 restarts `TIME_WAIT` on a retransmitted remote `FIN` and
/// on nothing else: a peer that keeps acknowledging into a closed connection is
/// answered out of the wait already running rather than holding the slot for as
/// long as it cares to keep sending.
#[test]
fn a_bare_acknowledgement_in_time_wait_does_not_restart_the_wait() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x1c_1000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    let len = stack.close(at(0), id, &mut out).expect("a FIN");
    peer.read(&out[..len]);
    let ack = peer.ack();
    stack.receive(at(0), STATION, &ack, &mut out);
    let fin = peer.fin();
    let received = stack.receive(at(0), STATION, &fin, &mut out);
    peer.read(&out[..received.emitted]);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::TimeWait)
    );

    // A bare acknowledgement most of the way through the wait: answered, and
    // the deadline unmoved.
    let nearly = at(TIME_WAIT_DURATION.as_nanos() - 1);
    let probe = peer.segment_at(peer.next, Flags::ACK, &[]);
    let received = stack.receive(nearly, STATION, &probe, &mut out);
    assert!(
        received.emitted > 0,
        "a segment in TIME_WAIT went unanswered"
    );
    assert!(matches!(
        stack.poll_timeouts(after(TIME_WAIT_DURATION), &mut out),
        Some(Timeout::Reaped { .. })
    ));
}

/// RFC 5961 section 7: the replies a peer can provoke without holding a
/// connection are bounded per second across the whole table, and what the bound
/// withholds is counted rather than silent.
#[test]
fn unsolicited_replies_are_bounded_per_second_and_the_suppression_counted() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x1c_2000);
    let mut out = [0u8; 2048];
    // A bare acknowledgement for a 4-tuple nothing holds. RFC 793 answers every
    // one with a reset, which is the amplifier the limit exists to close.
    let stray = peer.ack();
    let over = 20usize;
    let mut answered = 0usize;
    for _ in 0..(CHALLENGE_LIMIT as usize + over) {
        if stack.receive(at(1_000), STATION, &stray, &mut out).emitted > 0 {
            answered += 1;
        }
    }
    assert_eq!(answered, CHALLENGE_LIMIT as usize);
    assert_eq!(stack.counters().resets_sent, u64::from(CHALLENGE_LIMIT));
    assert_eq!(stack.counters().challenges_suppressed, over as u64);
    // Every one of them was still refused and counted, so the silence is not
    // also invisible.
    assert_eq!(
        stack.counters().refused_no_connection,
        CHALLENGE_LIMIT as u64 + over as u64
    );

    // The next second's allowance is fresh.
    let later = at(1_000 + CHALLENGE_WINDOW.as_nanos());
    assert!(stack.receive(later, STATION, &stray, &mut out).emitted > 0);
}

/// The same allowance covers a synchronized connection's challenge
/// acknowledgements, and a reset is never withheld by it: a peer left believing
/// in a connection this end has torn down would go on sending into it.
#[test]
fn a_challenge_flood_is_bounded_and_a_reset_is_not() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x1c_3000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    // An in-window `SYN`, which RFC 5961 section 4 challenges. The same segment
    // over and over is what an off-path attacker sends.
    let intruder = peer.segment_at(peer.next, Flags::SYN, &[]);
    let mut answered = 0usize;
    for _ in 0..(CHALLENGE_LIMIT as usize + 5) {
        if stack
            .receive(at(1_000), STATION, &intruder, &mut out)
            .emitted
            > 0
        {
            answered += 1;
        }
    }
    assert_eq!(answered, CHALLENGE_LIMIT as usize);
    assert_eq!(stack.counters().challenges_suppressed, 5);
    assert_eq!(
        stack.counters().challenge_acks,
        CHALLENGE_LIMIT as u64 + 5,
        "a challenge decision went uncounted"
    );
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::Established),
        "a challenged SYN tore the connection down"
    );

    // The budget is spent, and a `RST` at exactly the next byte expected is
    // still accepted and still ends the connection.
    let reset = peer.segment_at(peer.next, Flags::RST, &[]);
    stack.receive(at(1_000), STATION, &reset, &mut out);
    assert_eq!(stack.connection(id), None);
    assert_eq!(stack.counters().resets_received, 1);
}

/// The round-trip sample comes from the newest range the acknowledgement
/// covered, and "newest" is by sequence: records take whichever array slot is
/// free, so a reused slot puts the newest range in front of an older one.
#[test]
fn the_round_trip_sample_comes_from_the_newest_range_by_sequence() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x1c_4000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);

    // Two ranges, filling the first two record slots. Neither answer is read:
    // what this peer acknowledges is set by hand below, one range at a time.
    stack.send(at(0), id, b"aaaa", &mut out).expect("a segment");
    stack.send(at(0), id, b"bbbb", &mut out).expect("a segment");

    // The oldest range expires, which marks it retransmitted so its
    // acknowledgement yields no sample at all (Karn's algorithm).
    assert!(matches!(
        stack.poll_timeouts(after(INITIAL_RTO), &mut out),
        Some(Timeout::Retransmit { .. })
    ));
    // Acknowledge only that first range, freeing the slot it held. It carries no
    // sample of its own, having been re-sent.
    peer.expect = peer.expect.add(4);
    let ack = peer.ack();
    stack.receive(after(INITIAL_RTO), STATION, &ack, &mut out);
    assert_eq!(stack.outstanding(id), 1);

    // The next range takes that freed slot, so the array now holds the newest
    // range in front of the older one — twenty seconds older.
    let late = at(20 * lfw_clock::NANOS_PER_SECOND);
    stack.send(late, id, b"cccc", &mut out).expect("a segment");

    // Acknowledge both a millisecond later. The sample is that millisecond, not
    // the twenty seconds the record in the later slot has been outstanding.
    peer.expect = peer.expect.add(8);
    let ack = peer.ack();
    let settled = at(20 * lfw_clock::NANOS_PER_SECOND + 1_000_000);
    stack.receive(settled, STATION, &ack, &mut out);
    assert_eq!(stack.outstanding(id), 0);
    assert!(stack.connection(id).is_some_and(Connection::measured));
    assert_eq!(
        stack.connection(id).map(Connection::timeout),
        Some(MIN_RTO),
        "the sample came from the older range in the later slot"
    );
}

/// Aborting says the message is incomplete, which a `FIN` cannot: it carries a
/// `RST`, and the slot goes with it rather than waiting on a timer.
#[test]
fn aborting_resets_the_peer_and_frees_the_slot() {
    let mut stack = stack();
    let mut peer = Peer::new(40000, 0x1c_5000);
    let mut out = [0u8; 2048];
    let id = handshake(&mut stack, at(0), &mut peer);
    stack
        .send(at(1_000), id, b"partial", &mut out)
        .expect("a segment");

    let len = stack.abort(id, &mut out).expect("a reset");
    let reset = Segment::parse(APPLIANCE, STATION, &out[..len]).expect("a segment");
    assert!(reset.flags.contains(Flags::RST));
    assert!(
        !reset.flags.contains(Flags::FIN),
        "a truncated message was ended as a complete one"
    );
    assert_eq!(stack.connection(id), None, "the slot outlived the reset");
    assert_eq!(stack.counters().resets_sent, 1);
    assert_eq!(stack.counters().connections_closed, 1);
    // A handle that names nothing any more is refused rather than resolved.
    assert_eq!(stack.abort(id, &mut out), Err(SendError::UnknownConnection));

    // Storage too small leaves the connection intact, so the next pass may try
    // again with whatever storage it offers.
    let mut other = Peer::new(40001, 0x1c_6000);
    let alive = handshake(&mut stack, at(2_000), &mut other);
    let mut tiny = [0u8; 8];
    assert!(matches!(
        stack.abort(alive, &mut tiny),
        Err(SendError::Write { committed: 0, .. })
    ));
    assert!(stack.connection(alive).is_some());
    assert_eq!(stack.abort(alive, &mut out).map(|len| len > 0), Ok(true));
}

/// Releasing gives the four-tuple back, and what it owes the peer follows from
/// the state rather than from the call.
///
/// The four situations a caller finished with a connection can be in, and each
/// has one right answer: a dial nothing answered is forgotten in silence, a
/// synchronized connection draws the reset that stops its peer sending into an
/// exchange this end no longer carries, a close that is over is forgotten too —
/// resetting one would contradict a `FIN` the peer already accepted — and a
/// handle the table has already ended names nothing to give back.
#[test]
fn releasing_a_connection_frees_the_tuple_and_tells_the_peer_only_where_it_must() {
    let mut out = [0u8; 2048];

    // A dial nothing answered: no connection exists at the far end for a reset
    // to end, so nothing is composed and the slot goes.
    let mut dialling = stack();
    let dialled = dialling
        .connect(at(0), STATION, 40000, &mut out)
        .expect("a slot and room for a SYN");
    assert_eq!(
        dialling.release(dialled.connection, &mut out),
        Released::Forgotten {
            state: State::SynSent
        }
    );
    assert_eq!(dialling.connection(dialled.connection), None);
    assert_eq!(dialling.counters().resets_sent, 0);
    // And the four-tuple is free, which is the whole point: the next dial to it
    // opens rather than naming the connection the last one left behind.
    assert!(
        dialling
            .connect(at(1_000), STATION, 40000, &mut out)
            .is_ok()
    );

    // A synchronized connection: the peer believes in it, so it is told.
    let mut live = stack();
    let mut peer = Peer::new(40001, 0x2a_0000);
    let established = handshake(&mut live, at(0), &mut peer);
    let Released::Reset { state, len } = live.release(established, &mut out) else {
        panic!("a synchronized connection owes its peer a reset");
    };
    assert_eq!(state, State::Established);
    let reset = peer.read(&out[..len]);
    assert!(reset.flags.contains(Flags::RST));
    assert!(reset.flags.contains(Flags::ACK));
    assert_eq!(live.connection(established), None);
    assert_eq!(live.counters().resets_sent, 1);

    // A close both halves finished, held in `TIME_WAIT` by this end alone. The
    // record is dropped and no segment leaves.
    let mut finished = stack();
    let mut peer = Peer::new(40002, 0x2b_0000);
    let closing = handshake(&mut finished, at(0), &mut peer);
    let len = finished.close(at(1_000), closing, &mut out).expect("a FIN");
    peer.read(&out[..len]);
    let fin = peer.fin();
    finished.receive(at(2_000), peer.address, &fin, &mut out);
    assert_eq!(
        finished.connection(closing).map(Connection::state),
        Some(State::TimeWait)
    );
    assert_eq!(
        finished.release(closing, &mut out),
        Released::Forgotten {
            state: State::TimeWait
        }
    );
    assert_eq!(finished.connection(closing), None);
    assert_eq!(finished.counters().resets_sent, 0);

    // And a handle the table already ended: nothing to give back, and no error
    // either — a caller releasing a connection a reset or a reaping took is the
    // ordinary case.
    assert_eq!(finished.release(closing, &mut out), Released::Absent);
    assert_eq!(finished.counters().resets_sent, 0);
}

/// Storage too small still frees the slot, which is the opposite of what an
/// abort does and the reason a release exists beside it: the caller has finished
/// with the connection and has nothing to try again with, so a slot kept back
/// would refuse its next dial for the four-tuple.
#[test]
fn a_release_whose_reset_does_not_fit_gives_the_slot_back_anyway() {
    let mut stack = stack();
    let mut out = [0u8; 2048];
    let mut peer = Peer::new(40003, 0x2c_0000);
    let established = handshake(&mut stack, at(0), &mut peer);

    let mut tiny = [0u8; 8];
    assert_eq!(
        stack.release(established, &mut tiny),
        Released::Reset {
            state: State::Established,
            len: 0
        }
    );
    assert_eq!(stack.connection(established), None);
    assert_eq!(stack.counters().write_refused, 1);
    assert_eq!(stack.counters().resets_sent, 0);
    assert!(stack.connect(at(1_000), STATION, 40003, &mut out).is_ok());
}

// ── The dial ────────────────────────────────────────────────────────────────

/// The whole of what an active open negotiates, read off the two segments it
/// takes: the `SYN` this end composes and the answer it accepts.
#[test]
fn a_dial_opens_a_connection_and_negotiates_the_segment_size() {
    let mut stack = stack();
    let mut peer = Peer::at(STATION, 8443, 0x5a_0000);
    peer.mss = Some(700);
    let mut out = [0u8; 2048];

    let dialled = stack
        .connect(at(0), STATION, 8443, &mut out)
        .expect("a slot and room for a SYN");
    let syn = peer.read(&out[..dialled.len]);
    // A dial carries `SYN` and nothing else: it has no peer sequence number to
    // acknowledge, so the acknowledgement field is zero and the flag is clear.
    assert_eq!(syn.flags, Flags::SYN);
    assert_eq!(syn.acknowledgement, SeqNumber::new(0));
    // The source port is this stack's own, which is the whole of the one-port
    // rule: a segment comes back to the port it left from or is refused.
    assert_eq!(syn.source_port, PORT);
    assert_eq!(syn.destination_port, 8443);
    assert_eq!(syn.options.mss, Some(MSS_LIMIT));
    // Offered unconditionally, which is what makes scaling available at all.
    assert_eq!(syn.options.window_scale, Some(0));
    assert_eq!(syn.window, RECEIVE_WINDOW as u16);

    let connection = stack
        .connection(dialled.connection)
        .expect("the connection the dial opened");
    assert_eq!(connection.state(), State::SynSent);
    assert_eq!(connection.peer_address(), STATION);
    assert_eq!(connection.peer_port(), 8443);
    assert_eq!(stack.counters().connections_dialled, 1);
    assert_eq!(stack.counters().connections_accepted, 0);
    assert_eq!(
        stack.outstanding(dialled.connection),
        1,
        "the SYN is unacknowledged"
    );

    let syn_ack = peer.syn_ack();
    let received = stack.receive(at(1_000), STATION, &syn_ack, &mut out);
    assert_eq!(received.outcome, Outcome::Advanced);
    let ack = peer.read(&out[..received.emitted]);
    assert_eq!(ack.flags, Flags::ACK);
    assert_eq!(ack.acknowledgement, SeqNumber::new(0x5a_0001));

    let connection = stack
        .connection(dialled.connection)
        .expect("the connection");
    assert_eq!(connection.state(), State::Established);
    // The peer's own offer, which is below this end's limit.
    assert_eq!(connection.send_mss(), 700);
    assert!(
        connection.measured(),
        "the answer to the SYN is the connection's first round-trip sample"
    );
    assert_eq!(stack.counters().connections_established, 1);
    assert_eq!(
        stack.outstanding(dialled.connection),
        0,
        "the SYN was acknowledged"
    );
}

/// A dialled connection is an ordinary one from the acknowledgement onwards:
/// bytes cross both ways and the close is the same close.
#[test]
fn a_dialled_connection_carries_a_stream_and_closes_cleanly() {
    let mut stack = stack();
    let mut peer = Peer::at(STATION, 8443, 0x5b_0000);
    let mut out = [0u8; 2048];
    let id = dial(&mut stack, at(0), &mut peer);

    let request = b"hello";
    let sent = stack
        .send(at(1_000), id, request, &mut out)
        .expect("the peer's window is open");
    assert_eq!(sent.bytes, request.len());
    let segment = peer.read(&out[..sent.len]);
    assert_eq!(segment.payload, request);

    let ack = peer.ack();
    stack.receive(at(2_000), STATION, &ack, &mut out);
    assert_eq!(stack.outstanding(id), 0);

    let answer = b"world";
    let data = peer.data(answer);
    let received = stack.receive(at(3_000), STATION, &data, &mut out);
    assert_eq!(received.data, answer);
    peer.read(&out[..received.emitted]);

    let len = stack.close(at(4_000), id, &mut out).expect("a FIN");
    let fin = peer.read(&out[..len]);
    assert!(fin.flags.contains(Flags::FIN));
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::FinWait1)
    );
    let ack = peer.ack();
    stack.receive(at(5_000), STATION, &ack, &mut out);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::FinWait2)
    );
    let fin = peer.fin();
    let received = stack.receive(at(6_000), STATION, &fin, &mut out);
    peer.read(&out[..received.emitted]);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(State::TimeWait)
    );
}

/// RFC 793 p.66: an answer acknowledging a number this end never sent draws a
/// reset carrying that number, and **the dial stands**. Tearing it down instead
/// would let one forged segment cancel this node's own dial.
#[test]
fn an_answer_acknowledging_the_wrong_sequence_is_reset_and_the_dial_stands() {
    let mut stack = stack();
    let mut peer = Peer::at(STATION, 8443, 0x5c_0000);
    let mut out = [0u8; 2048];
    let dialled = stack
        .connect(at(0), STATION, 8443, &mut out)
        .expect("a dial");
    let syn = peer.read(&out[..dialled.len]);
    let dialled_isn = syn.sequence;

    // Far ahead of anything sent, which is the direction RFC 793 tests first.
    peer.expect = dialled_isn.add(500);
    let bogus = peer.syn_ack();
    let received = stack.receive(at(1_000), STATION, &bogus, &mut out);
    // Both numbers travel with the refusal: what the station claimed, and the
    // one this end had actually reached — its `SYN` and nothing else.
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::UnacceptableAck {
            claimed: dialled_isn.add(500),
            expected: dialled_isn.add(1)
        }))
    );
    let reset = Segment::parse(APPLIANCE, STATION, &out[..received.emitted]).expect("a reset");
    assert!(reset.flags.contains(Flags::RST));
    assert_eq!(
        reset.sequence,
        dialled_isn.add(500),
        "the reset carries the number the peer claimed"
    );
    assert_eq!(
        stack.connection(dialled.connection).map(Connection::state),
        Some(State::SynSent),
        "a segment acknowledging what was never sent moved the dial"
    );

    // And the other edge: an acknowledgement at or below the initial sequence
    // number, which acknowledges nothing at all.
    peer.expect = dialled_isn;
    let bogus = peer.segment_at(peer.next, Flags::SYN.with(Flags::ACK), &[]);
    let received = stack.receive(at(2_000), STATION, &bogus, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::UnacceptableAck {
            claimed: dialled_isn,
            expected: dialled_isn.add(1)
        }))
    );
    assert_eq!(
        stack.connection(dialled.connection).map(Connection::state),
        Some(State::SynSent)
    );
    assert_eq!(stack.counters().refused_unacceptable_ack, 2);

    // The real answer still completes the dial that survived both.
    peer.expect = dialled_isn.add(1);
    let syn_ack = peer.syn_ack();
    stack.receive(at(3_000), STATION, &syn_ack, &mut out);
    assert_eq!(
        stack.connection(dialled.connection).map(Connection::state),
        Some(State::Established)
    );
}

/// A reset ends a dial exactly where it acknowledges the `SYN` that dial sent.
/// One that acknowledges nothing names nothing, and is the blind reset RFC 5961
/// exists to refuse — stated here for the one state that has no window to state
/// it over.
#[test]
fn a_reset_ends_a_dial_only_where_it_acknowledges_it() {
    let mut stack = stack();
    let mut peer = Peer::at(STATION, 8443, 0x5d_0000);
    let mut out = [0u8; 2048];
    let dialled = stack
        .connect(at(0), STATION, 8443, &mut out)
        .expect("a dial");
    let dialled_isn = peer.read(&out[..dialled.len]).sequence;

    let blind = peer.segment_at(peer.next, Flags::RST, &[]);
    let received = stack.receive(at(1_000), STATION, &blind, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::UnvalidatedReset))
    );
    assert_eq!(received.emitted, 0, "a reset was answered");
    assert_eq!(
        stack.connection(dialled.connection).map(Connection::state),
        Some(State::SynSent),
        "a reset naming nothing cancelled a dial"
    );

    peer.expect = dialled_isn.add(1);
    let refusal = peer.segment_at(peer.next, Flags::RST.with(Flags::ACK), &[]);
    let received = stack.receive(at(2_000), STATION, &refusal, &mut out);
    assert_eq!(received.outcome, Outcome::Advanced);
    assert_eq!(received.emitted, 0, "a reset was answered with a segment");
    assert_eq!(
        stack.connection(dialled.connection),
        None,
        "a refused connection outlived its reset"
    );
    assert_eq!(stack.counters().resets_received, 1);
    assert_eq!(stack.counters().connections_closed, 1);
}

/// The two reset facts a received segment reports, which are what lets a caller
/// tell a station that refused it from one that was never there.
///
/// A caller sees only that the table stopped holding a connection, and the table
/// stops holding one for a reset and for a retransmission budget alike. So the
/// segment says which: `peer_reset` for a reset this connection acted on, and
/// `reset_sent` for one this end composed in answer. Both are asserted against
/// the counters beside them, because a flag that disagreed with the count would
/// be a caller and a scrape reporting different things about one segment.
#[test]
fn a_received_segment_reports_the_reset_it_carried_and_the_one_it_drew() {
    let mut stack = stack();
    let mut peer = Peer::at(STATION, 8443, 0x5f_0000);
    let mut out = [0u8; 2048];
    let dialled = stack
        .connect(at(0), STATION, 8443, &mut out)
        .expect("a dial");
    let dialled_isn = peer.read(&out[..dialled.len]).sequence;

    // A blind reset is refused before it can end anything, so neither flag is
    // set: the connection stands and this end answers nothing.
    let blind = peer.segment_at(peer.next, Flags::RST, &[]);
    let received = stack.receive(at(1_000), STATION, &blind, &mut out);
    assert!(!received.peer_reset, "a refused reset ended the dial");
    assert!(!received.reset_sent);

    // An acknowledgement of what was never sent draws a reset from this end and
    // leaves the dial standing, so exactly one of the two flags is set.
    peer.expect = dialled_isn.add(500);
    let bogus = peer.syn_ack();
    let received = stack.receive(at(2_000), STATION, &bogus, &mut out);
    assert!(!received.peer_reset);
    assert!(
        received.reset_sent,
        "the reset this end sent was not reported"
    );
    assert_eq!(stack.counters().resets_sent, 1);
    assert_eq!(
        stack.connection(dialled.connection).map(Connection::state),
        Some(State::SynSent)
    );

    // And the reset that really ends it, which is the other flag alone.
    peer.expect = dialled_isn.add(1);
    let refusal = peer.segment_at(peer.next, Flags::RST.with(Flags::ACK), &[]);
    let received = stack.receive(at(3_000), STATION, &refusal, &mut out);
    assert!(
        received.peer_reset,
        "the reset that ended the dial was not reported"
    );
    assert!(!received.reset_sent, "a reset was answered with another");
    assert_eq!(stack.counters().resets_received, 1);
    assert_eq!(stack.counters().resets_sent, 1);
    assert_eq!(stack.connection(dialled.connection), None);
}

/// RFC 793 p.68: a segment reaching a dial that carries neither `SYN` nor `RST`
/// says nothing about the handshake being waited for, so it is dropped without
/// an answer and under its own cause.
#[test]
fn a_segment_that_is_neither_a_syn_nor_a_reset_leaves_a_dial_untouched() {
    let mut stack = stack();
    let mut peer = Peer::at(STATION, 8443, 0x5e_0000);
    let mut out = [0u8; 2048];
    let dialled = stack
        .connect(at(0), STATION, 8443, &mut out)
        .expect("a dial");
    let dialled_isn = peer.read(&out[..dialled.len]).sequence;
    peer.expect = dialled_isn.add(1);

    let bare = peer.segment_at(peer.next, Flags::ACK, b"payload");
    let received = stack.receive(at(1_000), STATION, &bare, &mut out);
    assert_eq!(
        received.outcome,
        Outcome::Rejected(Rejection::Connection(Refusal::NotAHandshake))
    );
    assert_eq!(received.emitted, 0);
    assert!(received.data.is_empty(), "a dial delivered a byte");
    assert_eq!(
        stack.connection(dialled.connection).map(Connection::state),
        Some(State::SynSent)
    );
    assert_eq!(stack.counters().refused_not_a_handshake, 1);
    assert_eq!(stack.counters().bytes_received, 0);
}

/// RFC 793's simultaneous open: both ends dial, so the answer to this end's
/// `SYN` is a `SYN` with no acknowledgement. It becomes the state a passive open
/// is already in, and the `SYN-ACK` re-uses the sequence number the outstanding
/// record already covers.
#[test]
fn a_simultaneous_open_turns_a_dial_into_an_answered_handshake() {
    let mut stack = stack();
    let mut peer = Peer::at(STATION, 8443, 0x5f_0000);
    let mut out = [0u8; 2048];
    let dialled = stack
        .connect(at(0), STATION, 8443, &mut out)
        .expect("a dial");
    let syn = peer.read(&out[..dialled.len]);
    let dialled_isn = syn.sequence;

    // The peer's own `SYN`, composed before it saw this end's: no acknowledgement.
    let their_syn = peer.segment(Flags::SYN, &[]);
    let received = stack.receive(at(1_000), STATION, &their_syn, &mut out);
    assert_eq!(received.outcome, Outcome::Advanced);
    let syn_ack = peer.read(&out[..received.emitted]);
    assert!(syn_ack.flags.contains(Flags::SYN));
    assert!(syn_ack.flags.contains(Flags::ACK));
    assert_eq!(
        syn_ack.sequence, dialled_isn,
        "the SYN-ACK left the sequence space the SYN already occupied"
    );
    assert_eq!(syn_ack.acknowledgement, SeqNumber::new(0x5f_0001));
    assert_eq!(
        stack.connection(dialled.connection).map(Connection::state),
        Some(State::SynReceived)
    );
    assert_eq!(
        stack.outstanding(dialled.connection),
        1,
        "one record covers the SYN and the SYN-ACK alike"
    );

    // And the peer's answer to this end's `SYN`, which arrives at the sequence
    // number its own `SYN` already occupied.
    let their_answer = peer.segment_at(SeqNumber::new(0x5f_0000), Flags::SYN.with(Flags::ACK), &[]);
    let received = stack.receive(at(2_000), STATION, &their_answer, &mut out);
    assert_eq!(received.outcome, Outcome::Advanced);
    let ack = peer.read(&out[..received.emitted]);
    assert_eq!(ack.flags, Flags::ACK);
    assert_eq!(
        stack.connection(dialled.connection).map(Connection::state),
        Some(State::Established)
    );
    assert_eq!(stack.counters().connections_established, 1);
    assert_eq!(stack.outstanding(dialled.connection), 0);
}

/// An unanswered dial re-sends its `SYN` under RFC 6298's backoff, and then ends
/// — in silence, because nothing at the far end ever answered for a reset to
/// tell.
#[test]
fn an_unanswered_dial_is_re_sent_and_then_abandoned_in_silence() {
    let mut stack = stack();
    let mut peer = Peer::at(STATION, 8443, 0x60_0000);
    let mut out = [0u8; 2048];
    let dialled = stack
        .connect(at(0), STATION, 8443, &mut out)
        .expect("a dial");
    let dialled_isn = peer.read(&out[..dialled.len]).sequence;

    // The deadlines are walked at exactly RFC 6298's schedule — one second, then
    // doubling — rather than by jumping past them, so the backoff is asserted and
    // not merely survived. Nothing here reaches `IDLE_TIMEOUT`, which is the
    // other way a dial ends and would mask this one.
    let mut elapsed = 0u64;
    let mut timeout = INITIAL_RTO.as_nanos();
    let mut resent = 0;
    for _ in 0..MAX_RETRANSMITS {
        elapsed = elapsed.saturating_add(timeout);
        assert_eq!(
            stack.poll_timeouts(at(elapsed - 1), &mut out),
            None,
            "the SYN was re-sent before its deadline"
        );
        let due = stack
            .poll_timeouts(at(elapsed), &mut out)
            .expect("the SYN is due");
        let Timeout::Resent { connection, len } = due else {
            panic!("a dial owes its own SYN, got {due:?}");
        };
        assert_eq!(connection, dialled.connection);
        let again = Segment::parse(APPLIANCE, STATION, &out[..len]).expect("a segment");
        // Every retransmission is the same segment the dial composed: a `SYN`
        // with no acknowledgement, at the same number, offering the same options.
        assert_eq!(again.flags, Flags::SYN);
        assert_eq!(again.sequence, dialled_isn);
        assert_eq!(again.acknowledgement, SeqNumber::new(0));
        assert_eq!(again.options.mss, Some(MSS_LIMIT));
        resent += 1;
        timeout = timeout.saturating_mul(2).min(MAX_RTO.as_nanos());
    }
    assert_eq!(resent, MAX_RETRANSMITS);
    assert!(
        elapsed >= 31 * lfw_clock::NANOS_PER_SECOND,
        "the give-up interval was shorter than RFC 1122 asks of one"
    );

    elapsed = elapsed.saturating_add(timeout);
    let timeout = stack
        .poll_timeouts(at(elapsed), &mut out)
        .expect("the retransmission budget is spent");
    assert_eq!(
        timeout,
        Timeout::Abandoned {
            connection: dialled.connection,
            len: 0,
        },
        "an unanswered dial announced itself to an address that never answered"
    );
    assert_eq!(stack.connection(dialled.connection), None);
    assert_eq!(stack.counters().connections_abandoned, 1);
    assert_eq!(
        stack.counters().resets_sent,
        0,
        "a reset went to a peer that had said nothing"
    );
    assert_eq!(stack.poll_timeouts(at(elapsed), &mut out), None);
}

/// A dial names a 4-tuple, and the table is keyed by one: a second dial to a
/// peer already connected is refused and hands back the connection that exists,
/// so a caller that lost track of one cannot open a connection the table could
/// not tell from the first.
#[test]
fn a_second_dial_to_the_same_peer_is_refused_and_names_the_connection() {
    let mut stack = stack();
    let mut peer = Peer::at(STATION, 8443, 0x61_0000);
    let mut out = [0u8; 2048];
    let id = dial(&mut stack, at(0), &mut peer);

    assert_eq!(
        stack.connect(at(1_000), STATION, 8443, &mut out),
        Err(DialError::AlreadyOpen { connection: id })
    );
    // A different port on the same address is a different connection.
    let other = stack
        .connect(at(1_000), STATION, 8444, &mut out)
        .expect("a second dial to a second port");
    assert_ne!(other.connection, id);
    assert_eq!(stack.connections(), 2);

    // And a peer that dialled *in* is likewise a connection a dial will not
    // duplicate: the table cannot tell two connections on one 4-tuple apart,
    // whichever end opened them.
    let mut inbound = Peer::new(40000, 0x61_9000);
    handshake(&mut stack, at(2_000), &mut inbound);
    assert!(matches!(
        stack.connect(at(3_000), STATION, 40000, &mut out),
        Err(DialError::AlreadyOpen { .. })
    ));
}

/// A dial never evicts. `free_slot` refuses to let a peer's `SYN` destroy an
/// established connection; this is the same rule read from the other side, and
/// it is what keeps this node's own dial from trading a session somebody holds
/// for one nobody has answered.
#[test]
fn a_dial_refuses_rather_than_evicting_and_takes_a_dead_slot_back() {
    let mut stack = stack();
    let mut out = [0u8; 2048];
    let mut peers: Vec<Peer> = (0..4)
        .map(|index| Peer::new(40000 + index, 0x62_0000 + u32::from(index) * 0x100))
        .collect();
    for peer in &mut peers {
        handshake(&mut stack, at(0), peer);
    }
    assert_eq!(stack.connections(), 4);

    assert_eq!(
        stack.connect(at(1_000), STATION, 8443, &mut out),
        Err(DialError::TableFull)
    );
    assert_eq!(stack.connections(), 4, "a dial evicted a live connection");
    assert_eq!(
        stack.counters().connections_evicted,
        0,
        "a dial was counted as an eviction"
    );

    // A slot whose connection is over is a reaping rather than an eviction, and a
    // dial may take one: every connection here has sat idle past its limit.
    let idle = after(IDLE_TIMEOUT);
    let dialled = stack
        .connect(idle, STATION, 8443, &mut out)
        .expect("a slot whose connection is over");
    assert_eq!(
        stack.connection(dialled.connection).map(Connection::state),
        Some(State::SynSent)
    );
    assert_eq!(stack.counters().connections_reaped, 1);
}

/// Storage too small refuses the dial and opens nothing: a connection whose
/// `SYN` never left would hold a slot and spend its whole retransmission budget
/// re-sending a segment its caller never learned had failed to go out.
#[test]
fn storage_too_small_refuses_a_dial_and_opens_nothing() {
    let mut stack = stack();
    let mut tiny = [0u8; 8];
    let mut out = [0u8; 2048];

    assert!(matches!(
        stack.connect(at(0), STATION, 8443, &mut tiny),
        Err(DialError::Write(WriteError::DoesNotFit { .. }))
    ));
    assert_eq!(stack.connections(), 0, "a refused dial took a slot");
    assert_eq!(stack.counters().write_refused, 1);
    assert_eq!(stack.counters().connections_dialled, 0);
    assert_eq!(stack.counters().segments_sent, 0);

    // And the same dial with room succeeds, so nothing was left behind.
    assert!(stack.connect(at(1_000), STATION, 8443, &mut out).is_ok());
    assert_eq!(stack.connections(), 1);
}

/// A dial has no stream for a `FIN` to end, so a caller closing one is refused
/// and told the state. Tearing it down is what is available, and the reset it
/// composes carries no acknowledgement — a dial has no peer sequence number to
/// acknowledge, and one claiming to acknowledge zero is one a peer refuses.
#[test]
fn a_dial_cannot_be_closed_gracefully_and_its_reset_acknowledges_nothing() {
    let mut stack = stack();
    let mut peer = Peer::at(STATION, 8443, 0x63_0000);
    let mut out = [0u8; 2048];
    let dialled = stack
        .connect(at(0), STATION, 8443, &mut out)
        .expect("a dial");
    let dialled_isn = peer.read(&out[..dialled.len]).sequence;

    assert_eq!(
        stack.close(at(1_000), dialled.connection, &mut out),
        Err(SendError::WrongState(State::SynSent))
    );
    assert_eq!(
        stack.send(at(1_000), dialled.connection, b"early", &mut out),
        Err(SendError::WrongState(State::SynSent)),
        "a dial carried a byte before it was answered"
    );

    let len = stack
        .abort(dialled.connection, &mut out)
        .expect("a dial may be torn down");
    let reset = Segment::parse(APPLIANCE, STATION, &out[..len]).expect("a reset");
    assert_eq!(reset.flags, Flags::RST);
    assert_eq!(reset.acknowledgement, SeqNumber::new(0));
    assert_eq!(reset.sequence, dialled_isn.add(1));
    assert_eq!(stack.connection(dialled.connection), None);
}

/// RFC 7323 section 2.2: a dial offers the option and a peer that answers
/// without it leaves **both** directions unshifted — which also holds the window
/// this end advertises back to what an unshifted field can express.
#[test]
fn a_peer_that_declines_the_window_scale_leaves_a_dial_unscaled() {
    let mut stack = TcpStack::<4>::new(APPLIANCE, PORT, MSS_LIMIT, 400_000, secret());
    let mut peer = Peer::at(STATION, 8443, 0x64_0000);
    peer.window_scale = None;
    peer.window = 1_000;
    let mut out = [0u8; 2048];

    let dialled = stack
        .connect(at(0), STATION, 8443, &mut out)
        .expect("a dial");
    let syn = peer.read(&out[..dialled.len]);
    // 400 000 bytes needs three bits of shift to be expressed in sixteen.
    assert_eq!(syn.options.window_scale, Some(3));
    assert_eq!(u32::from(syn.window) << 3, 400_000);

    let syn_ack = peer.syn_ack();
    let received = stack.receive(at(1_000), STATION, &syn_ack, &mut out);
    let ack = peer.read(&out[..received.emitted]);
    // Unshifted from here on, so the window on the wire is the whole of what this
    // end will take.
    assert_eq!(ack.window, u16::MAX);
    assert_eq!(
        stack
            .connection(dialled.connection)
            .map(Connection::receive_window),
        Some(u32::from(u16::MAX))
    );
    // And the peer's own window is read unshifted too, so a send is bounded by
    // the thousand bytes it actually offered.
    let sent = stack
        .send(at(2_000), dialled.connection, &[0xcd; 4096], &mut out)
        .expect("the window has room");
    assert_eq!(sent.bytes, 1_000);
}

/// A peer that answers with a scale gets one: the option this end offered is
/// what enables it, and the peer's window is then read under its own shift.
#[test]
fn a_peer_that_answers_with_a_scale_gets_a_scaled_connection() {
    let mut stack = stack();
    let mut peer = Peer::at(STATION, 8443, 0x65_0000);
    peer.window_scale = Some(7);
    peer.window = 1_000;
    let mut out = [0u8; 2048];
    let id = dial(&mut stack, at(0), &mut peer);

    // 1000 read under a shift of seven is 128 000 bytes, so the send is bounded
    // by the negotiated segment size rather than by the window.
    let sent = stack
        .send(at(1_000), id, &[0xab; 4096], &mut out)
        .expect("the window is wide open");
    assert_eq!(sent.bytes, usize::from(MSS_LIMIT));
}

/// Two dials to two peers are offered unrelated sequence spaces, for the reason
/// two accepted connections are: an off-path attacker that learned the offset for
/// one 4-tuple could otherwise inject into another.
#[test]
fn two_dials_are_offered_different_sequence_spaces() {
    let mut stack = stack();
    let mut out = [0u8; 2048];
    let first = stack
        .connect(at(0), STATION, 8443, &mut out)
        .expect("a dial");
    let one = Segment::parse(APPLIANCE, STATION, &out[..first.len])
        .expect("a SYN")
        .sequence;
    let elsewhere = Ipv4Address::from_octets([10, 0, 2, 99]);
    let second = stack
        .connect(at(0), elsewhere, 8443, &mut out)
        .expect("a second dial");
    let two = Segment::parse(APPLIANCE, elsewhere, &out[..second.len])
        .expect("a SYN")
        .sequence;
    assert_ne!(one, two);
}

proptest! {
    /// A dial never panics and never delivers a byte for an arbitrary stream of
    /// arbitrary segments, and it always ends: whatever a peer sends or withholds,
    /// the table is empty once every deadline has passed. This is the dial's
    /// half of the no-panic-on-arbitrary-input invariant, and its own
    /// termination property beside it — a dial that could be held open by a
    /// peer's silence would hold a slot for the life of the node.
    #[test]
    fn an_arbitrary_answer_never_panics_and_a_dial_always_ends(
        segments in prop::collection::vec(
            (prop::collection::vec(any::<u8>(), 0..80), any::<u16>()),
            0..24,
        ),
    ) {
        let mut stack = stack();
        let mut out = [0u8; 2048];
        let dialled = stack
            .connect(at(0), STATION, 8443, &mut out)
            .expect("a dial");
        for (bytes, span) in &segments {
            let now = at(u64::from(*span) * 1_000_000);
            let received = stack.receive(now, STATION, bytes, &mut out);
            prop_assert!(received.emitted <= out.len());
            // Nothing a dial has not been answered for can carry a byte to the
            // caller, and once it is answered a byte is only ever a subslice of
            // the segment it came in.
            prop_assert!(received.data.len() <= bytes.len());
            prop_assert!(stack.connections() <= 4);
            let mut drained = 0;
            while stack.poll_timeouts(now, &mut out).is_some() {
                drained += 1;
                prop_assert!(drained <= 64, "the timers did not settle");
            }
        }
        // Far beyond every deadline this crate holds, and beyond the whole
        // retransmission budget of a dial nothing answered.
        let far = at(
            IDLE_TIMEOUT.as_nanos()
                + TIME_WAIT_DURATION.as_nanos()
                + MAX_RTO.as_nanos() * u64::from(MAX_RETRANSMITS + 1)
                + 1,
        );
        let mut drained = 0;
        while stack.poll_timeouts(far, &mut out).is_some() {
            drained += 1;
            prop_assert!(drained <= 64, "the timers did not settle");
        }
        prop_assert_eq!(stack.connections(), 0, "a dial outlived every timer");
        prop_assert!(stack.connection(dialled.connection).is_none());
    }

    /// Whatever a peer answers with, a connection this end dialled is only ever
    /// in a state a dial can reach — and it reaches `ESTABLISHED` only through an
    /// answer that acknowledged the `SYN` it sent. An invalid transition is
    /// therefore not merely untested but unrepresentable in what the state can
    /// be observed to be.
    #[test]
    fn a_dial_only_ever_reaches_a_state_a_dial_can_reach(
        flags in any::<u8>(),
        acknowledgement in any::<u32>(),
        payload in prop::collection::vec(any::<u8>(), 0..24),
    ) {
        let mut stack = stack();
        let mut out = [0u8; 2048];
        let dialled = stack
            .connect(at(0), STATION, 8443, &mut out)
            .expect("a dial");
        let iss = Segment::parse(APPLIANCE, STATION, &out[..dialled.len])
            .expect("a SYN")
            .sequence;

        // Composed out of the six flags a header carries rather than from the
        // byte, so the strategy reaches every combination through the same
        // constants a peer's segment is read into.
        let mut carried = Flags::default();
        for (bit, flag) in [
            (0x01, Flags::FIN),
            (0x02, Flags::SYN),
            (0x04, Flags::RST),
            (0x08, Flags::PSH),
            (0x10, Flags::ACK),
            (0x20, Flags::URG),
        ] {
            if flags & bit != 0 {
                carried = carried.with(flag);
            }
        }
        let mut peer = Peer::at(STATION, 8443, 0x7000_0000);
        peer.expect = SeqNumber::new(acknowledgement);
        let answer = peer.segment_at(peer.next, carried, &payload);
        let received = stack.receive(at(1_000), STATION, &answer, &mut out);
        prop_assert!(received.data.is_empty(), "a dial delivered a byte to its caller");

        let state = stack.connection(dialled.connection).map(Connection::state);
        let carries = |flag: Flags| carried.contains(flag);
        let acknowledges_the_syn = carries(Flags::ACK)
            && SeqNumber::new(acknowledgement) == iss.add(1);
        match state {
            // Answered, so the handshake completed — which needs the `SYN` this
            // end sent to have been acknowledged.
            Some(State::Established) => {
                prop_assert!(acknowledges_the_syn && carries(Flags::SYN));
            }
            // A `SYN` with no acknowledgement of this end's: a simultaneous open.
            Some(State::SynReceived) => {
                prop_assert!(carries(Flags::SYN) && !carries(Flags::ACK));
            }
            // Nothing about the handshake, so the dial stands.
            Some(State::SynSent) => prop_assert!(!carries(Flags::SYN) || !acknowledges_the_syn),
            // Refused, which needs a reset that acknowledged the `SYN`.
            None => prop_assert!(carries(Flags::RST) && acknowledges_the_syn),
            other => prop_assert!(false, "a dial reached {other:?}"),
        }
    }
}
