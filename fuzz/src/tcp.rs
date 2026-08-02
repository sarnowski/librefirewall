//! `lfw_tcp` under the two adversaries that reach a listening port, driven as a
//! *stack* rather than as a parser.
//!
//! # The adversary and the surface
//!
//! Whatever is attached to the management port chooses every byte of every segment
//! and every instant at which one arrives (untrusted network traffic
//! **and** the management-plane attacker). What it does *not* choose is the
//! connection table's size or the clock's direction, and those are the two bounds
//! every assertion below is stated against.
//!
//! What makes this different from [`crate::ip_endpoint`]'s surface is state. A
//! parser answers one frame; a transport carries a *connection*, so a defect here
//! is reached by a sequence — a handshake half-completed, a window moved by a
//! stale segment, a range acknowledged twice, a timer fired between two arrivals.
//! The harness therefore drives an operation stream over two stacks at once: a
//! **listening** one that has never seen a valid segment, and an **established**
//! one whose handshake this harness completed itself, so the synchronized paths
//! are reached even by an input that could never compose a handshake.
//!
//! # Modelling authority, not politeness
//!
//! Modelling the adversary's full authority is what this is shaped by. Every value that crosses the boundary is
//! taken unreduced: the segment bytes, the source address, the instant, the window
//! a caller sets, the range it claims to be retransmitting. In particular the
//! *clock* is arbitrary and may move **backwards** — a peer cannot move a real
//! counter, but a stack that assumed monotonicity would be assuming something no
//! type here promises, and `lfw_clock::Monotonic::since` saturates precisely
//! because the hardware does not promise it either.
//!
//! Nothing filters a shape for being implausible. A segment claiming to be a
//! `SYN` and a `RST` and a `FIN` at once is exactly what a hostile peer sends.
//!
//! # What is asserted
//!
//! * **Totality.** Every byte string at every instant is answered — a segment
//!   processed, or a typed refusal — and nothing panics, indexes past a bound or
//!   overflows.
//! * **Boundedness of state.** The connection table never exceeds its capacity,
//!   whatever stream of distinct 4-tuples arrives. This is the
//!   connection-flood invariant, and it is asserted after every operation rather
//!   than at the end.
//! * **Boundedness of work.** Draining the timers terminates, and the harness
//!   asserts the loop exited by the timers *settling* rather than by its own cap —
//!   so a regression deleting the code's own bound fails here instead of being
//!   silently truncated.
//! * **Containment of the answer.** A segment written into the caller's storage
//!   never exceeds it, and the bytes past its length are never touched. This is
//!   what the protection domain rests on: it lends that many bytes onward.
//! * **Delivery is a subslice.** Data reported as delivered is inside the segment
//!   handed over and never longer than the window this end is advertising, so no
//!   byte a peer did not send can reach a caller.
//! * **Delivery is the stream, in order.** A peer that sends a known byte stream
//!   has exactly a prefix of it delivered, whatever the receive window was when
//!   each segment arrived. This is what a segment *trimmed* to the window has to
//!   satisfy: the transport keeps the head of the accepted region, so a caller
//!   reconstructing the delivered bytes from the wrong end would produce a
//!   stream that is no prefix of what was sent.
//! * **Every segment is counted, exactly once.** The counters are the only
//!   evidence a port is doing anything, so the total is asserted to move by one
//!   per segment.
//! * **Sequence numbers stay unpredictable.** Two stacks with different secrets
//!   answer the same `SYN` with different numbers, which is the RFC 6528 property
//!   an off-path attacker attacks.

use arbitrary::{Arbitrary, Unstructured};
use lfw_clock::{Calibration, Monotonic, Ticks};
use lfw_tcp::{Connection, ConnectionId, Flags, IsnSecret, Outgoing, SeqNumber, TcpStack, Timeout};
use net_headers::Ipv4Address;
use std::num::NonZeroU64;

use crate::{MAX_OPERATIONS, any_index, any_u16, any_u32, next_op};

/// The appliance's own addressing, so a verdict here is one it would reach.
const APPLIANCE: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 15]);
const PORT: u16 = 80;
const MSS_LIMIT: u16 = 1024;
const RECEIVE_WINDOW: u32 = 1024;

/// Connections one stack holds. Small on purpose: a flood reaches the table's
/// edge in a handful of segments, so the eviction and reaping paths are ordinary
/// inputs rather than rare ones.
const CONNECTIONS: usize = 4;

/// The initial sequence number the harness's own peer opens with, so a data
/// segment can be composed at the byte the receiver is next expecting.
const ESTABLISHED_IRS: u32 = 0x1000;

/// The address that peer sends from.
const ESTABLISHED_PEER: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 2]);

/// Storage the caller offers, and the byte it is filled with so a segment's own
/// bytes are distinguishable from untouched ones.
const OUT: usize = 2048;
const UNTOUCHED: u8 = 0xa5;

/// How many timeouts one drain may take before the harness calls the timers
/// unsettled.
///
/// Not a capability filter: it bounds nothing the adversary can express, and the
/// harness asserts the loop exited *below* it, so a stack whose timers did not
/// settle fails rather than being truncated into a pass.
const TIMER_DRAIN_LIMIT: usize = 4 * CONNECTIONS + 8;

/// Drive an operation stream over a listening stack and an established one.
pub fn tcp_segments_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    // The key is the adversary's to choose in the worst case — a node whose
    // entropy source is broken — so it comes out of the input rather than being
    // fixed here.
    let secret = IsnSecret::from_bytes(<[u8; 16]>::arbitrary(&mut unstructured).unwrap_or([0; 16]));
    let mut listening = stack(secret.clone());
    let (mut established, opened, acknowledgement) = established_stack(secret);

    // Segments handed to the *listening* stack, which is what its own received
    // counter is held to. Only the arm that delivers to it may move this;
    // `operations` is what bounds the loop, so the two cannot be conflated.
    let mut segments = 0u64;
    let mut operations = 0usize;
    // How much of the harness's own stream the established connection has taken,
    // and the concatenation of everything it reported delivering. The two must
    // agree byte for byte: the transport delivers the head of what it accepted,
    // so a caller reading the delivered bytes off the wrong end of a trimmed
    // segment would produce a run that is no prefix of what was sent.
    let mut delivered = 0u64;
    while let Some(op) = next_op(&mut unstructured) {
        operations += 1;
        let now = instant(any_u32(&mut unstructured));
        match op % 7 {
            6 => {
                // A well-formed data segment on the established connection,
                // longer than the receive window as often as not. Nothing else
                // in this harness reaches the synchronized data path: random
                // bytes never carry a checksum that verifies.
                let bytes =
                    stream_segment(&mut unstructured, delivered, acknowledgement, ESTABLISHED_PEER);
                let mut out = [UNTOUCHED; OUT];
                let received = established.receive(now, ESTABLISHED_PEER, &bytes, &mut out);
                for (index, byte) in received.data.iter().enumerate() {
                    assert_eq!(
                        *byte,
                        stream_byte(delivered.saturating_add(index as u64)),
                        "the delivered run is not the stream this peer sent"
                    );
                }
                delivered = delivered.saturating_add(received.data.len() as u64);
                assert!(received.emitted <= OUT);
                assert!(
                    out[received.emitted..].iter().all(|byte| *byte == UNTOUCHED),
                    "an answer wrote past the length it reported"
                );
            }
            0..=2 => {
                // A segment, from an arbitrary source, to both stacks: the same
                // bytes reach a table that has never seen a connection and one
                // that holds an established connection on this very tuple.
                let source = source_address(&mut unstructured);
                let bytes = segment_bytes(&mut unstructured);
                deliver(&mut listening, now, source, &bytes);
                deliver(&mut established, now, source, &bytes);
                segments += 1;
                assert_eq!(
                    listening.counters().segments_received,
                    segments,
                    "a segment went uncounted"
                );
            }
            3 => {
                // A caller's send, on a handle that may or may not name anything.
                let id = pick(&mut unstructured, opened);
                let payload = payload_bytes(&mut unstructured);
                let mut out = [UNTOUCHED; OUT];
                if let Ok(sent) = established.send(now, id, &payload, &mut out) {
                    assert!(sent.bytes <= payload.len());
                    assert!(sent.bytes <= usize::from(MSS_LIMIT));
                    assert!(sent.len <= OUT);
                    assert!(
                        out[sent.len..].iter().all(|byte| *byte == UNTOUCHED),
                        "a send wrote past the length it reported"
                    );
                }
            }
            4 => {
                let id = pick(&mut unstructured, opened);
                let mut out = [UNTOUCHED; OUT];
                if let Ok(len) = established.close(now, id, &mut out) {
                    assert!(len <= OUT);
                    assert!(out[len..].iter().all(|byte| *byte == UNTOUCHED));
                }
                // A window the caller chooses, unreduced: every `u32` is a legal
                // one and the stack holds it to what the shift can express.
                established.set_receive_window(id, any_u32(&mut unstructured));
            }
            _ => {
                // A retransmission with a range and bytes the caller may have
                // wrong, which is the disagreement `SendError::WrongRange` exists
                // to refuse.
                let id = pick(&mut unstructured, opened);
                let sequence = SeqNumber::new(any_u32(&mut unstructured));
                let payload = payload_bytes(&mut unstructured);
                let mut out = [UNTOUCHED; OUT];
                if let Ok(len) = established.retransmit(now, id, sequence, &payload, &mut out) {
                    assert!(len <= OUT);
                    assert!(out[len..].iter().all(|byte| *byte == UNTOUCHED));
                }
            }
        }

        for stack in [&mut listening, &mut established] {
            assert!(
                stack.connections() <= CONNECTIONS,
                "the connection table exceeded its capacity"
            );
            drain_timers(stack, now);
        }
        if operations >= MAX_OPERATIONS {
            break;
        }
    }

    // The RFC 6528 property, at the end so the whole input has had its chance to
    // move whatever state it can: two stacks that differ only in their secret
    // answer one `SYN` with different numbers.
    assert_sequence_numbers_differ();
}

/// Hand one segment over and hold the answer to everything the crate promises.
fn deliver<const N: usize>(
    stack: &mut TcpStack<N>,
    now: Monotonic,
    source: Ipv4Address,
    bytes: &[u8],
) {
    let before = stack.counters().segments_received;
    let mut out = [UNTOUCHED; OUT];
    let received = stack.receive(now, source, bytes, &mut out);
    assert_eq!(
        stack.counters().segments_received,
        before + 1,
        "a segment was processed without being counted"
    );
    assert!(received.emitted <= OUT, "an answer overran the storage");
    assert!(
        out[received.emitted..]
            .iter()
            .all(|byte| *byte == UNTOUCHED),
        "an answer wrote past the length it reported"
    );
    // Delivered data is a subslice of what arrived, and no longer than the window
    // this end is advertising: no byte a peer did not send can reach a caller,
    // and nothing past what this end said it could take is accepted. The window
    // is read off the connection rather than assumed, because the harness sets
    // it to arbitrary values of its own.
    assert!(received.data.len() <= bytes.len());
    let advertised = received
        .connection
        .and_then(|id| stack.connection(id))
        .map_or(RECEIVE_WINDOW, Connection::receive_window);
    assert!(
        received.data.len() as u32 <= advertised,
        "more was delivered than the window advertised"
    );
    if !received.data.is_empty() {
        assert!(
            received.connection.is_some(),
            "data was delivered without a connection to attribute it to"
        );
    }
    // An answer, where there is one, is a segment: it re-parses under the same
    // pseudo-header the peer would use, which is both checksums asserted the way
    // the station that receives one tests them.
    if received.emitted > 0 {
        let answer = lfw_tcp::Segment::parse(APPLIANCE, source, &out[..received.emitted])
            .expect("an answer this crate composed re-parses");
        assert_eq!(answer.source_port, PORT);
    }
}

/// Take every expired timer, asserting the loop settles rather than hitting the
/// harness's own cap.
fn drain_timers<const N: usize>(stack: &mut TcpStack<N>, now: Monotonic) {
    let mut taken = 0;
    let mut out = [UNTOUCHED; OUT];
    while let Some(timeout) = stack.poll_timeouts(now, &mut out) {
        match timeout {
            Timeout::Resent { len, .. } | Timeout::Abandoned { len, .. } => {
                assert!(len <= OUT);
                assert!(out[len..].iter().all(|byte| *byte == UNTOUCHED));
            }
            // The range asked for is one the caller must hold; the harness holds
            // nothing, so it answers with nothing and the timer backs off — which
            // is the path a caller that cannot supply the bytes takes.
            Timeout::Retransmit { len, .. } => assert!(len > 0),
            Timeout::Reaped { .. } => {}
        }
        taken += 1;
        assert!(
            taken < TIMER_DRAIN_LIMIT,
            "the timers did not settle: {taken} answers at one instant"
        );
        out = [UNTOUCHED; OUT];
    }
}

/// A stack listening on the appliance's own address and port.
fn stack(secret: IsnSecret) -> TcpStack<CONNECTIONS> {
    TcpStack::new(APPLIANCE, PORT, MSS_LIMIT, RECEIVE_WINDOW, secret)
}

/// A stack with one connection already established, so the synchronized paths are
/// reached by an input that could never compose a handshake itself.
fn established_stack(secret: IsnSecret) -> (TcpStack<CONNECTIONS>, Option<ConnectionId>, u32) {
    let mut stack = stack(secret);
    let mut out = [0u8; OUT];
    let now = instant(0);
    let peer = ESTABLISHED_PEER;
    let syn = compose(ESTABLISHED_IRS, 0, Flags::SYN, &[], peer);
    let received = stack.receive(now, peer, &syn, &mut out);
    let Some(id) = received.connection else {
        return (stack, None, 0);
    };
    // The `SYN-ACK`'s own sequence number is what the third segment must
    // acknowledge, and it is read back off the wire rather than predicted.
    let Ok(syn_ack) = lfw_tcp::Segment::parse(APPLIANCE, peer, &out[..received.emitted]) else {
        return (stack, Some(id), 0);
    };
    let acknowledgement = syn_ack.sequence.add(1).raw();
    let ack = compose(
        ESTABLISHED_IRS.wrapping_add(1),
        acknowledgement,
        Flags::ACK,
        &[],
        peer,
    );
    stack.receive(now, peer, &ack, &mut out);
    assert_eq!(
        stack.connection(id).map(Connection::state),
        Some(lfw_tcp::State::Established),
        "the harness could not establish a connection"
    );
    // What every later segment from this peer must acknowledge: an
    // acknowledgement of something never sent, or one further behind
    // `SND.UNA` than any window offered, is refused before a byte is delivered
    // (RFC 5961 section 5), so a stream driven with a stale one would never
    // reach the data path at all.
    (stack, Some(id), acknowledgement)
}

/// One well-formed segment, for the handshake the harness performs itself.
fn compose(
    sequence: u32,
    acknowledgement: u32,
    flags: Flags,
    payload: &[u8],
    peer: Ipv4Address,
) -> Vec<u8> {
    let mut out = vec![0u8; payload.len() + 256];
    let len = Outgoing {
        source_port: 40000,
        destination_port: PORT,
        sequence: SeqNumber::new(sequence),
        acknowledgement: SeqNumber::new(acknowledgement),
        flags,
        window: 4096,
        mss: flags.contains(Flags::SYN).then_some(1460),
        window_scale: None,
        payload,
    }
    .write(peer, APPLIANCE, &mut out)
    .expect("room for the payload and a header");
    out.truncate(len);
    out
}

/// An instant, which may be *anywhere* — including behind a previous one. See the
/// module header on why a backwards clock is the adversary's authority rather than
/// an implausible input.
fn instant(nanos: u32) -> Monotonic {
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(u64::from(nanos) * 4_096))
}

/// The source address a segment arrives from, spread over a small set so a stream
/// both revisits one connection and floods the table with new ones.
fn source_address(unstructured: &mut Unstructured<'_>) -> Ipv4Address {
    Ipv4Address::from_octets([10, 0, 2, any_u16(unstructured) as u8])
}

/// Bytes to be read as a segment. Taken whole and unreduced: no length prefix, no
/// structure this harness imposes, so a corpus entry is a segment off a wire.
///
/// The bound is above [`RECEIVE_WINDOW`] rather than a fraction of it, because a
/// cap below the window is a guard that deletes a path: a segment that cannot
/// outrun the window is one whose right edge is never trimmed.
fn segment_bytes(unstructured: &mut Unstructured<'_>) -> Vec<u8> {
    let len = usize::from(any_u16(unstructured) % (2 * RECEIVE_WINDOW as u16));
    let mut bytes = vec![0u8; len];
    for byte in &mut bytes {
        *byte = u8::arbitrary(unstructured).unwrap_or(0);
    }
    bytes
}

/// The byte at `offset` of the stream the harness's own peer sends: distinct per
/// position, so a delivered run says where it came from.
fn stream_byte(offset: u64) -> u8 {
    // 251 is prime and coprime with every window and segment length here, so a
    // run delivered from the wrong end of a segment is a different run rather
    // than the same one shifted.
    (offset % 251) as u8
}

/// One well-formed data segment on the established connection, carrying the
/// stream from the byte the receiver is next expecting.
///
/// Random bytes never compose a segment whose checksum verifies, so without this
/// the synchronized data path — and with it every trim — is unreachable however
/// long the harness runs. The length is the adversary's and deliberately reaches
/// past the receive window.
fn stream_segment(
    unstructured: &mut Unstructured<'_>,
    delivered: u64,
    acknowledgement: u32,
    peer: Ipv4Address,
) -> Vec<u8> {
    let len = usize::from(any_u16(unstructured) % (2 * RECEIVE_WINDOW as u16));
    let payload: Vec<u8> = (0..len as u64)
        .map(|index| stream_byte(delivered.saturating_add(index)))
        .collect();
    // Lossless: the harness's own stream stays far below 2^32 bytes.
    let sequence = ESTABLISHED_IRS.wrapping_add(1).wrapping_add(delivered as u32);
    compose(
        sequence,
        acknowledgement,
        Flags::ACK.with(Flags::PSH),
        &payload,
        peer,
    )
}

/// Bytes a caller offers to send. Bounded by what a slice can be *made* to be
/// here rather than by anything a peer may ask for.
fn payload_bytes(unstructured: &mut Unstructured<'_>) -> Vec<u8> {
    let len = usize::from(any_u16(unstructured) % 2_048);
    vec![u8::arbitrary(unstructured).unwrap_or(0); len]
}

/// A handle the caller uses: the one the harness opened, or one it invented. Both
/// are authority a caller has, and a handle that names nothing must be refused
/// rather than resolved.
fn pick(unstructured: &mut Unstructured<'_>, opened: Option<ConnectionId>) -> ConnectionId {
    match opened {
        Some(id) if any_index(unstructured, 2) == 0 => id,
        // A handle nothing issued. There is no constructor for one, so it is taken
        // from the stack's own view of a slot that may since have been reused —
        // which is exactly the stale handle the generation exists to refuse.
        _ => opened.unwrap_or_else(|| {
            let mut stack = self_referential_stack();
            let mut out = [0u8; OUT];
            let peer = Ipv4Address::from_octets([10, 0, 2, 9]);
            let syn = compose(1, 0, Flags::SYN, &[], peer);
            stack
                .receive(instant(0), peer, &syn, &mut out)
                .connection
                .expect("a fresh stack accepts a SYN")
        }),
    }
}

/// A throwaway stack, only to mint a handle that names nothing in the stack under
/// test.
fn self_referential_stack() -> TcpStack<1> {
    TcpStack::new(
        APPLIANCE,
        PORT,
        MSS_LIMIT,
        RECEIVE_WINDOW,
        IsnSecret::from_bytes([0x11; 16]),
    )
}

/// Two secrets, one `SYN`, two different answers.
fn assert_sequence_numbers_differ() {
    let peer = Ipv4Address::from_octets([10, 0, 2, 2]);
    let syn = compose(0x2000, 0, Flags::SYN, &[], peer);
    let mut sequences = Vec::new();
    for key in [[0x01u8; 16], [0x02u8; 16]] {
        let mut stack = stack(IsnSecret::from_bytes(key));
        let mut out = [0u8; OUT];
        let received = stack.receive(instant(7), peer, &syn, &mut out);
        let answer =
            lfw_tcp::Segment::parse(APPLIANCE, peer, &out[..received.emitted]).expect("a SYN-ACK");
        sequences.push(answer.sequence);
    }
    assert_ne!(
        sequences.first(),
        sequences.last(),
        "two secrets answered one SYN with one sequence number, which is the RFC 6528 property \
         an off-path attacker attacks"
    );
}
