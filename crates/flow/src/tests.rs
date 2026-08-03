//! The table driven as a table: whole handshakes, whole closes, floods, and the
//! two ICMP surfaces.
//!
//! # Why there is a harness rather than a list of transitions
//!
//! A state machine tested one transition at a time passes while being unable to
//! carry a connection: every step is right and no sequence is. [`Exchange`] is
//! therefore a scripted pair of endpoints that keeps both sequence spaces, so a
//! test says "open, send, close" and a divergence anywhere in it surfaces as the
//! table refusing something a real exchange produces.
//!
//! It is deterministic and single-threaded. Time is a number the test chooses,
//! which is the whole reason `lfw_clock::Monotonic` is a parameter rather than
//! something this crate reads: an idle timeout that would take two hours of real
//! time is one call here.

use super::*;
use net_headers::{IcmpHeader, TcpFlags, TcpHeader, UdpHeader};
use proptest::prelude::*;
use std::vec::Vec;

const CLIENT: Ipv4Address = Ipv4Address::from_octets([10, 0, 1, 10]);
const SERVER: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 20]);
const ROUTER: Ipv4Address = Ipv4Address::from_octets([10, 0, 3, 1]);

const FIN: TcpFlags = TcpFlags(0x01);
const SYN: TcpFlags = TcpFlags(0x02);
const RST: TcpFlags = TcpFlags(0x04);
const ACK: TcpFlags = TcpFlags(0x10);

/// Two flags at once, which the newtype offers no operator for.
const fn both(first: TcpFlags, second: TcpFlags) -> TcpFlags {
    TcpFlags(first.0 | second.0)
}

/// A table small enough that a flood reaches its edge in a handful of packets
/// and every slot is reachable by a bounded scan.
type Bench = FlowTable<16>;

fn table() -> Bench {
    FlowTable::new()
}

/// An instant `nanos` after boot, built the way this crate's callers build one.
fn at(nanos: u64) -> Monotonic {
    use core::num::NonZeroU64;
    use lfw_clock::{Calibration, Ticks};
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(nanos))
}

fn after(span: lfw_clock::Duration) -> Monotonic {
    at(span.as_nanos().saturating_add(1))
}

/// One packet, ready to be handed over.
struct Wire {
    source: Ipv4Address,
    destination: Ipv4Address,
    transport: Transport,
    bytes: Vec<u8>,
}

impl Wire {
    fn classify<const N: usize>(&self, table: &mut FlowTable<N>, now: Monotonic) -> Outcome {
        table.classify(
            now,
            &Packet {
                source: self.source,
                destination: self.destination,
                transport: self.transport,
                transport_bytes: &self.bytes,
            },
        )
    }
}

/// A scripted TCP exchange on one five-tuple, keeping both sequence spaces so a
/// test writes what happened rather than what the numbers were.
struct Exchange {
    client: Ipv4Address,
    server: Ipv4Address,
    client_port: u16,
    server_port: u16,
    /// The next sequence number each end will send.
    client_next: u32,
    server_next: u32,
    window: u16,
    /// The shift each end offers on its own `SYN`, absent for no option at all.
    client_scale: Option<u8>,
    server_scale: Option<u8>,
}

impl Exchange {
    fn new(client_port: u16) -> Self {
        Self {
            client: CLIENT,
            server: SERVER,
            client_port,
            server_port: 443,
            client_next: 0x1000_0000,
            server_next: 0x2000_0000,
            window: 4096,
            client_scale: None,
            server_scale: None,
        }
    }

    /// One segment, composed from whichever end sent it.
    fn segment(
        &self,
        from_client: bool,
        flags: TcpFlags,
        sequence: u32,
        acknowledgement: u32,
        options: &[u8],
        payload: &[u8],
    ) -> Wire {
        let mut bytes = std::vec![0u8; net_headers::TCP_HEADER_LEN];
        bytes.extend_from_slice(options);
        bytes.extend_from_slice(payload);
        // Lossless: the option area a test composes is a handful of bytes.
        let data_offset = ((net_headers::TCP_HEADER_LEN + options.len()) / 4) as u8;
        let (source, destination, source_port, destination_port) = if from_client {
            (self.client, self.server, self.client_port, self.server_port)
        } else {
            (self.server, self.client, self.server_port, self.client_port)
        };
        Wire {
            source,
            destination,
            transport: Transport::Tcp(TcpHeader {
                source_port,
                destination_port,
                sequence,
                acknowledgement,
                data_offset,
                flags,
                window: self.window,
                checksum: 0,
                urgent_pointer: 0,
            }),
            bytes,
        }
    }

    /// The window-scale option, padded to a word the way a real header pads it.
    fn scale_option(shift: u8) -> [u8; 4] {
        [1, 3, 3, shift]
    }

    fn syn(&mut self) -> Wire {
        let sequence = self.client_next;
        self.client_next = self.client_next.wrapping_add(1);
        let options = self.client_scale.map(Self::scale_option);
        self.segment(
            true,
            SYN,
            sequence,
            0,
            options.as_ref().map_or(&[][..], |option| &option[..]),
            &[],
        )
    }

    fn syn_ack(&mut self) -> Wire {
        let sequence = self.server_next;
        self.server_next = self.server_next.wrapping_add(1);
        let options = self.server_scale.map(Self::scale_option);
        self.segment(
            false,
            both(SYN, ACK),
            sequence,
            self.client_next,
            options.as_ref().map_or(&[][..], |option| &option[..]),
            &[],
        )
    }

    /// A bare acknowledgement from one end.
    fn ack(&self, from_client: bool) -> Wire {
        let (sequence, acknowledgement) = if from_client {
            (self.client_next, self.server_next)
        } else {
            (self.server_next, self.client_next)
        };
        self.segment(from_client, ACK, sequence, acknowledgement, &[], &[])
    }

    fn data(&mut self, from_client: bool, payload: &[u8]) -> Wire {
        let (sequence, acknowledgement) = if from_client {
            (self.client_next, self.server_next)
        } else {
            (self.server_next, self.client_next)
        };
        // Lossless: a test's payload is a handful of bytes.
        let length = payload.len() as u32;
        if from_client {
            self.client_next = self.client_next.wrapping_add(length);
        } else {
            self.server_next = self.server_next.wrapping_add(length);
        }
        self.segment(from_client, ACK, sequence, acknowledgement, &[], payload)
    }

    fn fin(&mut self, from_client: bool) -> Wire {
        let (sequence, acknowledgement) = if from_client {
            (self.client_next, self.server_next)
        } else {
            (self.server_next, self.client_next)
        };
        if from_client {
            self.client_next = self.client_next.wrapping_add(1);
        } else {
            self.server_next = self.server_next.wrapping_add(1);
        }
        self.segment(
            from_client,
            both(FIN, ACK),
            sequence,
            acknowledgement,
            &[],
            &[],
        )
    }

    fn reset(&self, from_client: bool) -> Wire {
        let (sequence, acknowledgement) = if from_client {
            (self.client_next, self.server_next)
        } else {
            (self.server_next, self.client_next)
        };
        self.segment(
            from_client,
            both(RST, ACK),
            sequence,
            acknowledgement,
            &[],
            &[],
        )
    }

    /// A segment at a sequence number of the test's choosing, for the refusals.
    fn at_sequence(
        &self,
        from_client: bool,
        flags: TcpFlags,
        sequence: u32,
        payload: &[u8],
    ) -> Wire {
        let acknowledgement = if from_client {
            self.server_next
        } else {
            self.client_next
        };
        self.segment(from_client, flags, sequence, acknowledgement, &[], payload)
    }

    /// A segment acknowledging a number of the test's choosing.
    fn at_ack(&self, from_client: bool, acknowledgement: u32) -> Wire {
        let sequence = if from_client {
            self.client_next
        } else {
            self.server_next
        };
        self.segment(from_client, ACK, sequence, acknowledgement, &[], &[])
    }
}

/// Open a flow and complete its handshake, answering the handle.
fn handshake<const N: usize>(
    table: &mut FlowTable<N>,
    now: Monotonic,
    exchange: &mut Exchange,
) -> FlowId {
    let syn = exchange.syn();
    let Outcome::New { flow, state } = syn.classify(table, now) else {
        panic!("a SYN did not open a flow");
    };
    assert_eq!(state, FlowState::SynSent);
    let syn_ack = exchange.syn_ack();
    assert!(matches!(
        syn_ack.classify(table, now),
        Outcome::Established {
            state: FlowState::SynReceived,
            ..
        }
    ));
    let ack = exchange.ack(true);
    assert!(matches!(
        ack.classify(table, now),
        Outcome::Established {
            state: FlowState::Established,
            ..
        }
    ));
    flow
}

/// A UDP datagram.
fn udp(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
) -> Wire {
    Wire {
        source,
        destination,
        transport: Transport::Udp(UdpHeader {
            source_port,
            destination_port,
            length: 8,
            checksum: 0,
        }),
        bytes: std::vec![0u8; net_headers::UDP_HEADER_LEN],
    }
}

/// An ICMP echo message.
fn echo(source: Ipv4Address, destination: Ipv4Address, message_type: u8, identifier: u16) -> Wire {
    let [high, low] = identifier.to_be_bytes();
    Wire {
        source,
        destination,
        transport: Transport::Icmp(IcmpHeader {
            message_type,
            code: 0,
            checksum: 0,
            rest_of_header: [high, low, 0, 1],
        }),
        bytes: std::vec![0u8; net_headers::ICMP_HEADER_LEN],
    }
}

/// An IPv4 header for a quoted datagram, with no options.
fn quoted_ipv4(source: Ipv4Address, destination: Ipv4Address, protocol: u8) -> Vec<u8> {
    let mut header = std::vec![0u8; net_headers::IPV4_HEADER_LEN];
    let mut write = |offset: usize, value: u8| {
        if let Some(cell) = header.get_mut(offset) {
            *cell = value;
        }
    };
    write(0, 0x45);
    write(9, protocol);
    for (index, octet) in source.octets().into_iter().enumerate() {
        write(12 + index, octet);
    }
    for (index, octet) in destination.octets().into_iter().enumerate() {
        write(16 + index, octet);
    }
    header
}

/// An ICMP error from `reporter` to `target`, quoting a TCP datagram.
fn icmp_error_quoting_tcp(
    reporter: Ipv4Address,
    target: Ipv4Address,
    quoted_source: Ipv4Address,
    quoted_destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
) -> Wire {
    let mut bytes = std::vec![0u8; net_headers::ICMP_HEADER_LEN];
    bytes.extend_from_slice(&quoted_ipv4(quoted_source, quoted_destination, 6));
    bytes.extend_from_slice(&source_port.to_be_bytes());
    bytes.extend_from_slice(&destination_port.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    Wire {
        source: reporter,
        destination: target,
        transport: Transport::Icmp(IcmpHeader {
            message_type: IcmpHeader::DESTINATION_UNREACHABLE,
            code: 3,
            checksum: 0,
            rest_of_header: [0; 4],
        }),
        bytes,
    }
}

// ---------------------------------------------------------------- handshakes

#[test]
fn a_syn_opens_a_flow_and_the_handshake_establishes_it() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let flow = handshake(&mut table, at(0), &mut exchange);
    assert_eq!(
        table.flow(flow).map(FlowEntry::state),
        Some(FlowState::Established)
    );
    assert_eq!(table.len(), 1);
    assert_eq!(table.counters().flows_created, 1);
    assert_eq!(table.counters().packets_established, 2);
}

/// The direction is the flow's own, not the packet's: the reply half of a
/// handshake is `Reply` however the canonical pair happens to sort.
#[test]
fn the_reply_direction_is_the_one_the_flow_was_not_opened_in() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let syn = exchange.syn();
    syn.classify(&mut table, at(0));
    let syn_ack = exchange.syn_ack();
    let Outcome::Established { direction, .. } = syn_ack.classify(&mut table, at(0)) else {
        panic!("the SYN-ACK was refused");
    };
    assert_eq!(direction, Direction::Reply);
    let ack = exchange.ack(true);
    let Outcome::Established { direction, .. } = ack.classify(&mut table, at(0)) else {
        panic!("the third segment was refused");
    };
    assert_eq!(direction, Direction::Original);
}

/// A flow and its reply are one entry, which is the whole reason the key is
/// orientation-free.
#[test]
fn a_flow_and_its_reply_resolve_to_one_entry() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let flow = handshake(&mut table, at(0), &mut exchange);
    let forward = exchange.data(true, b"request");
    let reverse = exchange.data(false, b"response");
    for wire in [&forward, &reverse] {
        let Outcome::Established { flow: seen, .. } = wire.classify(&mut table, at(1_000)) else {
            panic!("a segment on an established flow was refused");
        };
        assert_eq!(seen, flow);
    }
    assert_eq!(table.len(), 1);
}

/// A retransmitted `SYN` is the same flow, not a second one.
#[test]
fn a_retransmitted_syn_does_not_open_a_second_flow() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let syn = exchange.syn();
    let Outcome::New { flow, .. } = syn.classify(&mut table, at(0)) else {
        panic!("a SYN did not open a flow");
    };
    let again = exchange.segment(true, SYN, exchange.client_next.wrapping_sub(1), 0, &[], &[]);
    let Outcome::Established {
        flow: seen, state, ..
    } = again.classify(&mut table, at(1_000))
    else {
        panic!("a retransmitted SYN was refused");
    };
    assert_eq!(seen, flow);
    assert_eq!(state, FlowState::SynSent);
    assert_eq!(table.len(), 1);
}

/// A simultaneous open — both ends sending a bare `SYN` — reaches the same state
/// the ordinary handshake does, without an arm of its own in the machine.
#[test]
fn a_simultaneous_open_establishes() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let syn = exchange.syn();
    syn.classify(&mut table, at(0));
    // The server's own opening move, crossing the client's.
    let server_syn = exchange.segment(false, SYN, exchange.server_next, 0, &[], &[]);
    exchange.server_next = exchange.server_next.wrapping_add(1);
    assert!(matches!(
        server_syn.classify(&mut table, at(0)),
        Outcome::Established {
            state: FlowState::SynReceived,
            ..
        }
    ));
    // Each end then acknowledges the other's, in either order.
    let client_ack = exchange.ack(true);
    assert!(matches!(
        client_ack.classify(&mut table, at(0)),
        Outcome::Established {
            state: FlowState::Established,
            ..
        }
    ));
}

// ----------------------------------------------------------------- closing

#[test]
fn a_close_walks_fin_wait_close_wait_and_time_wait() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let flow = handshake(&mut table, at(0), &mut exchange);

    let fin = exchange.fin(true);
    assert!(matches!(
        fin.classify(&mut table, at(1_000)),
        Outcome::Established {
            state: FlowState::FinWait,
            ..
        }
    ));
    let ack = exchange.ack(false);
    assert!(matches!(
        ack.classify(&mut table, at(2_000)),
        Outcome::Established {
            state: FlowState::CloseWait,
            ..
        }
    ));
    // The half-closed direction may still send.
    let response = exchange.data(false, b"tail");
    assert!(matches!(
        response.classify(&mut table, at(3_000)),
        Outcome::Established {
            state: FlowState::CloseWait,
            ..
        }
    ));
    let server_fin = exchange.fin(false);
    assert!(matches!(
        server_fin.classify(&mut table, at(4_000)),
        Outcome::Established {
            state: FlowState::Closing,
            ..
        }
    ));
    let last = exchange.ack(true);
    assert!(matches!(
        last.classify(&mut table, at(5_000)),
        Outcome::Established {
            state: FlowState::TimeWait,
            ..
        }
    ));
    assert_eq!(
        table.flow(flow).map(FlowEntry::state),
        Some(FlowState::TimeWait)
    );
    assert_eq!(table.counters().flows_closed, 1);
}

/// Both ends closing at once reaches the same place, which is what computing the
/// closing state from the two `FIN`s rather than from a transition buys.
#[test]
fn a_simultaneous_close_reaches_time_wait() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    handshake(&mut table, at(0), &mut exchange);
    let client_fin = exchange.fin(true);
    let server_fin = exchange.fin(false);
    assert!(matches!(
        client_fin.classify(&mut table, at(1_000)),
        Outcome::Established {
            state: FlowState::FinWait,
            ..
        }
    ));
    assert!(matches!(
        server_fin.classify(&mut table, at(1_000)),
        Outcome::Established {
            state: FlowState::Closing,
            ..
        }
    ));
    // One acknowledgement each, and both `FIN`s are covered.
    let client_ack = exchange.ack(true);
    client_ack.classify(&mut table, at(2_000));
    let server_ack = exchange.ack(false);
    assert!(matches!(
        server_ack.classify(&mut table, at(2_000)),
        Outcome::Established {
            state: FlowState::TimeWait,
            ..
        }
    ));
}

#[test]
fn a_reset_closes_the_flow() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let flow = handshake(&mut table, at(0), &mut exchange);
    let reset = exchange.reset(false);
    assert!(matches!(
        reset.classify(&mut table, at(1_000)),
        Outcome::Established {
            state: FlowState::Closed,
            ..
        }
    ));
    assert_eq!(
        table.flow(flow).map(FlowEntry::state),
        Some(FlowState::Closed)
    );
    assert_eq!(table.counters().flows_closed, 1);
    // A closed flow admits nothing more, so a late segment is refused rather
    // than reviving it.
    let late = exchange.data(true, b"late");
    assert!(matches!(
        late.classify(&mut table, at(2_000)),
        Outcome::Refused(Refusal::InvalidState(FlowState::Closed))
    ));
}

/// The refusal that closed a handshake off from a blind reset: the first thing
/// the replying direction says must acknowledge exactly the `SYN` it answers.
#[test]
fn a_blind_reset_during_the_handshake_is_refused() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let syn = exchange.syn();
    syn.classify(&mut table, at(0));
    let blind = exchange.segment(false, both(RST, ACK), 0, 0x7777_7777, &[], &[]);
    assert!(matches!(
        blind.classify(&mut table, at(1_000)),
        Outcome::Refused(Refusal::OutOfWindow(WindowEdge::AckNotHandshake))
    ));
    assert_eq!(table.len(), 1);
    // The one a closed port really sends is admitted.
    let refused = exchange.segment(false, both(RST, ACK), 0, exchange.client_next, &[], &[]);
    assert!(matches!(
        refused.classify(&mut table, at(2_000)),
        Outcome::Established {
            state: FlowState::Closed,
            ..
        }
    ));
}

// ---------------------------------------------------------------- strictness

#[test]
fn a_mid_stream_segment_for_an_unknown_flow_is_refused() {
    let mut table = table();
    let exchange = Exchange::new(40_000);
    for flags in [ACK, both(FIN, ACK), both(RST, ACK), both(SYN, ACK)] {
        let wire = exchange.at_sequence(true, flags, 0x1234, b"payload");
        assert!(
            matches!(
                wire.classify(&mut table, at(0)),
                Outcome::Refused(Refusal::MidStream)
            ),
            "flags {flags:?} adopted a flow"
        );
    }
    assert!(table.is_empty());
    assert_eq!(table.counters().refused_mid_stream, 4);
}

#[test]
fn a_flag_combination_no_exchange_produces_is_refused() {
    let mut table = table();
    let exchange = Exchange::new(40_000);
    // A `SYN` with a `FIN`, a bare `FIN`, a `RST` with a `SYN`, and no flags.
    for flags in [both(SYN, FIN), FIN, both(RST, SYN), TcpFlags(0)] {
        let wire = exchange.at_sequence(true, flags, 0x1000_0000, &[]);
        assert!(
            matches!(
                wire.classify(&mut table, at(0)),
                Outcome::Refused(Refusal::InvalidFlags)
            ),
            "flags {flags:?} were admitted"
        );
    }
    assert_eq!(table.counters().refused_invalid_flags, 4);
}

#[test]
fn a_syn_on_a_synchronized_flow_is_refused() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    handshake(&mut table, at(0), &mut exchange);
    let wire = exchange.at_sequence(true, SYN, exchange.client_next, &[]);
    assert!(matches!(
        wire.classify(&mut table, at(1_000)),
        Outcome::Refused(Refusal::InvalidState(FlowState::Established))
    ));
}

/// Each of the four window edges, reached one at a time so a refusal names the
/// comparison that produced it rather than a category.
#[test]
fn every_window_edge_refuses_its_own_segment() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    handshake(&mut table, at(0), &mut exchange);

    let ahead = exchange.at_sequence(true, ACK, exchange.client_next.wrapping_add(100_000), b"x");
    assert!(matches!(
        ahead.classify(&mut table, at(1_000)),
        Outcome::Refused(Refusal::OutOfWindow(WindowEdge::SequenceAhead))
    ));

    let behind = exchange.at_sequence(true, ACK, exchange.client_next.wrapping_sub(100_000), b"x");
    assert!(matches!(
        behind.classify(&mut table, at(1_000)),
        Outcome::Refused(Refusal::OutOfWindow(WindowEdge::SequenceBehind))
    ));

    let ack_ahead = exchange.at_ack(true, exchange.server_next.wrapping_add(4_096));
    assert!(matches!(
        ack_ahead.classify(&mut table, at(1_000)),
        Outcome::Refused(Refusal::OutOfWindow(WindowEdge::AckAhead))
    ));

    let ack_behind = exchange.at_ack(true, exchange.server_next.wrapping_sub(100_000));
    assert!(matches!(
        ack_behind.classify(&mut table, at(1_000)),
        Outcome::Refused(Refusal::OutOfWindow(WindowEdge::AckBehind))
    ));

    assert_eq!(table.counters().refused_out_of_window, 4);
    // None of them moved the flow.
    assert_eq!(table.occupancy().get(FlowState::Established), 1);
}

/// A refused segment does not extend a flow's life, or anything able to guess a
/// five-tuple could hold a slot open with garbage.
#[test]
fn a_refused_segment_does_not_refresh_the_timeout() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let syn = exchange.syn();
    syn.classify(&mut table, at(0));
    let idle = timeout::SYN_SENT_TIMEOUT.as_nanos();
    // Well inside the interval, and refused.
    let garbage = exchange.at_sequence(true, ACK, 0xdead_beef, b"x");
    garbage.classify(&mut table, at(idle / 2));
    // The flow still expires on its original stamp.
    let sweep = table.poll(at(idle.saturating_add(1)));
    assert_eq!(sweep.expired, 1);
    assert!(table.is_empty());
}

/// Both ends must offer window scaling for either to use it, so a peer that
/// offers a shift to an end that did not is held to the unscaled window.
#[test]
fn scaling_applies_only_where_both_ends_offered_it() {
    let mut scaled = table();
    let mut exchange = Exchange::new(40_000);
    exchange.client_scale = Some(7);
    exchange.server_scale = Some(7);
    let flow = handshake(&mut scaled, at(0), &mut exchange);
    assert_eq!(
        scaled.flow(flow).map(|entry| entry.original().scale()),
        Some(7)
    );

    let mut unscaled = table();
    let mut lonely = Exchange::new(40_001);
    lonely.client_scale = Some(7);
    lonely.server_scale = None;
    let flow = handshake(&mut unscaled, at(0), &mut lonely);
    assert_eq!(
        unscaled.flow(flow).map(|entry| entry.original().scale()),
        Some(0)
    );
}

// ---------------------------------------------------------------------- UDP

#[test]
fn a_udp_datagram_opens_a_pseudo_flow_and_a_reply_assures_it() {
    let mut table = table();
    let request = udp(CLIENT, SERVER, 50_000, 53);
    let Outcome::New { flow, state } = request.classify(&mut table, at(0)) else {
        panic!("a UDP datagram did not open a flow");
    };
    assert_eq!(state, FlowState::UdpUnreplied);

    // A second datagram the same way leaves it one-way.
    let again = udp(CLIENT, SERVER, 50_000, 53);
    assert!(matches!(
        again.classify(&mut table, at(1_000)),
        Outcome::Established {
            state: FlowState::UdpUnreplied,
            ..
        }
    ));

    let reply = udp(SERVER, CLIENT, 53, 50_000);
    let Outcome::Established {
        flow: seen,
        state,
        direction,
    } = reply.classify(&mut table, at(2_000))
    else {
        panic!("a UDP reply was refused");
    };
    assert_eq!(seen, flow);
    assert_eq!(state, FlowState::UdpAssured);
    assert_eq!(direction, Direction::Reply);
    assert_eq!(table.len(), 1);
}

// --------------------------------------------------------------------- ICMP

#[test]
fn an_echo_request_opens_a_flow_and_its_reply_answers_it() {
    let mut table = table();
    let request = echo(CLIENT, SERVER, IcmpHeader::ECHO_REQUEST, 0x2a2a);
    let Outcome::New { flow, state } = request.classify(&mut table, at(0)) else {
        panic!("an echo request did not open a flow");
    };
    assert_eq!(state, FlowState::IcmpUnreplied);
    let reply = echo(SERVER, CLIENT, IcmpHeader::ECHO_REPLY, 0x2a2a);
    let Outcome::Established {
        flow: seen, state, ..
    } = reply.classify(&mut table, at(1_000))
    else {
        panic!("an echo reply was refused");
    };
    assert_eq!(seen, flow);
    assert_eq!(state, FlowState::IcmpReplied);
}

#[test]
fn an_echo_reply_never_opens_a_flow() {
    let mut table = table();
    let reply = echo(SERVER, CLIENT, IcmpHeader::ECHO_REPLY, 0x2a2a);
    assert!(matches!(
        reply.classify(&mut table, at(0)),
        Outcome::Refused(Refusal::NoSuchFlow)
    ));
    assert!(table.is_empty());
}

/// A reply travelling the way the request went is not an answer to it.
#[test]
fn an_echo_reply_from_the_requester_is_refused() {
    let mut table = table();
    let request = echo(CLIENT, SERVER, IcmpHeader::ECHO_REQUEST, 7);
    request.classify(&mut table, at(0));
    let wrong_way = echo(CLIENT, SERVER, IcmpHeader::ECHO_REPLY, 7);
    assert!(matches!(
        wrong_way.classify(&mut table, at(1_000)),
        Outcome::Refused(Refusal::InvalidState(FlowState::IcmpUnreplied))
    ));
}

/// A different identifier is a different flow, so an echo reply cannot answer
/// somebody else's probe.
#[test]
fn an_echo_identifier_separates_two_probes() {
    let mut table = table();
    let first = echo(CLIENT, SERVER, IcmpHeader::ECHO_REQUEST, 1);
    let second = echo(CLIENT, SERVER, IcmpHeader::ECHO_REQUEST, 2);
    first.classify(&mut table, at(0));
    second.classify(&mut table, at(0));
    assert_eq!(table.len(), 2);
}

#[test]
fn an_icmp_type_this_tracker_does_not_carry_is_refused() {
    let mut table = table();
    for message_type in [IcmpHeader::REDIRECT, 13, 17] {
        let wire = echo(ROUTER, CLIENT, message_type, 0);
        assert!(matches!(
            wire.classify(&mut table, at(0)),
            Outcome::Refused(Refusal::UnsupportedIcmp { .. })
        ));
    }
    assert_eq!(table.counters().refused_unsupported_icmp, 3);
}

#[test]
fn an_error_quoting_an_established_flow_is_related() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let flow = handshake(&mut table, at(0), &mut exchange);
    let data = exchange.data(true, b"request");
    data.classify(&mut table, at(1_000));

    let error = icmp_error_quoting_tcp(
        ROUTER,
        CLIENT,
        CLIENT,
        SERVER,
        40_000,
        443,
        exchange.client_next.wrapping_sub(7),
    );
    let Outcome::Related { flow: seen, quoted } = error.classify(&mut table, at(2_000)) else {
        panic!("an error quoting a live flow was not related");
    };
    assert_eq!(seen, flow);
    assert_eq!(quoted, Direction::Original);
    assert_eq!(table.counters().packets_related, 1);
}

/// The bind that stops an attacker attaching an error to a flow it merely knows
/// about: the quoted datagram must be one travelling away from the party the
/// error is addressed to.
#[test]
fn an_error_quoting_a_datagram_the_target_did_not_send_is_refused() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    handshake(&mut table, at(0), &mut exchange);
    // Addressed to the client, but quoting a datagram from the server.
    let error = icmp_error_quoting_tcp(
        ROUTER,
        CLIENT,
        SERVER,
        CLIENT,
        443,
        40_000,
        exchange.server_next,
    );
    assert!(matches!(
        error.classify(&mut table, at(1_000)),
        Outcome::Refused(Refusal::QuotedInvalid(
            QuotedError::NotFromTheReporter { .. }
        ))
    ));
    assert_eq!(table.counters().refused_quoted_invalid, 1);
}

/// The bind that costs an off-path attacker the sequence number as well as the
/// tuple.
#[test]
fn an_error_quoting_a_sequence_outside_the_window_is_refused() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    handshake(&mut table, at(0), &mut exchange);
    let error = icmp_error_quoting_tcp(
        ROUTER,
        CLIENT,
        CLIENT,
        SERVER,
        40_000,
        443,
        exchange.client_next.wrapping_add(500_000),
    );
    assert!(matches!(
        error.classify(&mut table, at(1_000)),
        Outcome::Refused(Refusal::OutOfWindow(WindowEdge::SequenceAhead))
    ));
}

#[test]
fn an_error_quoting_no_flow_at_all_is_refused() {
    let mut table = table();
    let error = icmp_error_quoting_tcp(ROUTER, CLIENT, CLIENT, SERVER, 1, 2, 3);
    assert!(matches!(
        error.classify(&mut table, at(0)),
        Outcome::Refused(Refusal::NoSuchFlow)
    ));
}

/// An error never opens, advances or refreshes anything.
#[test]
fn an_error_does_not_refresh_the_flow_it_reports_on() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    handshake(&mut table, at(0), &mut exchange);
    let idle = timeout::ESTABLISHED_TIMEOUT.as_nanos();
    let error = icmp_error_quoting_tcp(
        ROUTER,
        CLIENT,
        CLIENT,
        SERVER,
        40_000,
        443,
        exchange.client_next,
    );
    error.classify(&mut table, at(idle / 2));
    let sweep = table.poll(at(idle.saturating_add(1)));
    assert_eq!(sweep.expired, 1);
}

// ------------------------------------------------------- protocols and shapes

#[test]
fn a_protocol_this_tracker_holds_no_state_for_is_refused() {
    let mut table = table();
    let wire = Wire {
        source: CLIENT,
        destination: SERVER,
        transport: Transport::Unparsed(Protocol(47)),
        bytes: Vec::new(),
    };
    assert!(matches!(
        wire.classify(&mut table, at(0)),
        Outcome::Refused(Refusal::UnsupportedProtocol(Protocol(47)))
    ));
    assert_eq!(table.counters().refused_unsupported_protocol, 1);
}

#[test]
fn a_non_initial_fragment_is_refused() {
    let mut table = table();
    let wire = Wire {
        source: CLIENT,
        destination: SERVER,
        transport: Transport::NonInitialFragment,
        bytes: Vec::new(),
    };
    assert!(matches!(
        wire.classify(&mut table, at(0)),
        Outcome::Refused(Refusal::Fragment)
    ));
}

#[test]
fn a_truncated_transport_header_is_refused() {
    let mut table = table();
    for transport in [
        Transport::TruncatedTcp { available: 3 },
        Transport::TruncatedUdp { available: 2 },
        Transport::TruncatedIcmp { available: 1 },
    ] {
        let wire = Wire {
            source: CLIENT,
            destination: SERVER,
            transport,
            bytes: Vec::new(),
        };
        assert!(matches!(
            wire.classify(&mut table, at(0)),
            Outcome::Refused(Refusal::Malformed { .. })
        ));
    }
    assert_eq!(table.counters().refused_malformed, 3);
}

/// A data offset naming more header than the datagram carries is refused rather
/// than producing a payload length nobody sent.
#[test]
fn a_data_offset_past_the_datagram_is_refused() {
    let mut table = table();
    let exchange = Exchange::new(40_000);
    let mut wire = exchange.at_sequence(true, SYN, 0x1000, &[]);
    if let Transport::Tcp(ref mut header) = wire.transport {
        header.data_offset = 15;
    }
    assert!(matches!(
        wire.classify(&mut table, at(0)),
        Outcome::Refused(Refusal::Malformed { .. })
    ));
}

#[test]
fn a_tcp_datagram_shorter_than_its_header_is_refused() {
    let mut table = table();
    // A decoded header paired with a datagram too short to hold one, which is a
    // caller's own mistake and must be refused rather than read past.
    let wire = Wire {
        source: CLIENT,
        destination: SERVER,
        transport: Transport::Tcp(TcpHeader {
            source_port: 40_000,
            destination_port: 443,
            sequence: 1,
            acknowledgement: 0,
            data_offset: 5,
            flags: SYN,
            window: 4_096,
            checksum: 0,
            urgent_pointer: 0,
        }),
        bytes: std::vec![0u8; 4],
    };
    assert!(matches!(
        wire.classify(&mut table, at(0)),
        Outcome::Refused(Refusal::Malformed { needed: 20, got: 4 })
    ));
}

/// A probe sent more than once is the same flow, refreshed and left where it was:
/// a request is not an answer, in either direction.
#[test]
fn a_repeated_echo_request_refreshes_the_flow_it_already_opened() {
    let mut table = table();
    let first = echo(CLIENT, SERVER, IcmpHeader::ECHO_REQUEST, 5);
    let Outcome::New { flow, .. } = first.classify(&mut table, at(0)) else {
        panic!("an echo request did not open a flow");
    };
    let again = echo(CLIENT, SERVER, IcmpHeader::ECHO_REQUEST, 5);
    let Outcome::Established {
        flow: seen, state, ..
    } = again.classify(&mut table, at(1_000))
    else {
        panic!("a repeated echo request was refused");
    };
    assert_eq!(seen, flow);
    assert_eq!(state, FlowState::IcmpUnreplied);
    assert_eq!(table.len(), 1);
    // A request travelling the other way is also not an answer.
    let crossing = echo(SERVER, CLIENT, IcmpHeader::ECHO_REQUEST, 5);
    assert!(matches!(
        crossing.classify(&mut table, at(2_000)),
        Outcome::Established {
            state: FlowState::IcmpUnreplied,
            ..
        }
    ));
}

/// A quote naming a direction of a flow that has carried nothing is a claim about
/// a datagram that never travelled.
#[test]
fn an_error_quoting_a_direction_that_never_spoke_is_refused() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let syn = exchange.syn();
    syn.classify(&mut table, at(0));
    // The flow is half open: only the client has sent anything. An error to the
    // server, quoting a datagram the server supposedly sent, names a direction
    // this flow has never carried.
    let error = icmp_error_quoting_tcp(ROUTER, SERVER, SERVER, CLIENT, 443, 40_000, 1);
    assert!(matches!(
        error.classify(&mut table, at(1_000)),
        Outcome::Refused(Refusal::QuotedInvalid(
            QuotedError::NotFromTheReporter { .. }
        ))
    ));
}

/// A quoted sequence behind everything the direction was authorised to resend is
/// refused at the other edge.
#[test]
fn an_error_quoting_a_sequence_behind_the_window_is_refused() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    handshake(&mut table, at(0), &mut exchange);
    let data = exchange.data(true, b"request");
    data.classify(&mut table, at(1_000));
    let error = icmp_error_quoting_tcp(
        ROUTER,
        CLIENT,
        CLIENT,
        SERVER,
        40_000,
        443,
        exchange.client_next.wrapping_sub(500_000),
    );
    assert!(matches!(
        error.classify(&mut table, at(2_000)),
        Outcome::Refused(Refusal::OutOfWindow(WindowEdge::SequenceBehind))
    ));
}

/// A quote with no sequence space of its own — UDP — is corroborated by its tuple
/// alone, there being no number for a window to judge.
#[test]
fn an_error_quoting_a_udp_flow_is_related() {
    let mut table = table();
    let request = udp(CLIENT, SERVER, 50_000, 53);
    let Outcome::New { flow, .. } = request.classify(&mut table, at(0)) else {
        panic!("a UDP datagram did not open a flow");
    };
    let mut bytes = std::vec![0u8; net_headers::ICMP_HEADER_LEN];
    bytes.extend_from_slice(&quoted_ipv4(CLIENT, SERVER, 17));
    bytes.extend_from_slice(&50_000u16.to_be_bytes());
    bytes.extend_from_slice(&53u16.to_be_bytes());
    let error = Wire {
        source: ROUTER,
        destination: CLIENT,
        transport: Transport::Icmp(IcmpHeader {
            message_type: IcmpHeader::TIME_EXCEEDED,
            code: 0,
            checksum: 0,
            rest_of_header: [0; 4],
        }),
        bytes,
    };
    let Outcome::Related { flow: seen, quoted } = error.classify(&mut table, at(1_000)) else {
        panic!("an error quoting a live UDP flow was not related");
    };
    assert_eq!(seen, flow);
    assert_eq!(quoted, Direction::Original);
}

#[test]
fn every_refusal_has_a_distinct_name() {
    let refusals = [
        Refusal::UnsupportedProtocol(Protocol(47)),
        Refusal::Fragment,
        Refusal::Malformed { needed: 1, got: 0 },
        Refusal::InvalidFlags,
        Refusal::MidStream,
        Refusal::InvalidState(FlowState::Established),
        Refusal::OutOfWindow(WindowEdge::AckAhead),
        Refusal::NoSuchFlow,
        Refusal::QuotedInvalid(QuotedError::NotIpv4 { version: 6 }),
        Refusal::UnsupportedIcmp {
            message_type: 5,
            code: 0,
        },
        Refusal::TableFull,
        Refusal::BucketFull,
    ];
    for (position, refusal) in refusals.into_iter().enumerate() {
        for (other_position, other) in refusals.into_iter().enumerate() {
            assert_eq!(
                position == other_position,
                refusal == other,
                "{refusal:?} and {other:?} are not distinct"
            );
        }
    }
}

// -------------------------------------------------------- slots and pressure

/// The whole of the fail-closed eviction policy: a table full of established
/// flows refuses a new one rather than displacing any of them.
#[test]
fn a_full_table_of_established_flows_refuses_a_new_flow() {
    let mut table = table();
    let mut flows = Vec::new();
    for index in 0..16u16 {
        let mut exchange = Exchange::new(40_000 + index);
        flows.push(handshake(&mut table, at(0), &mut exchange));
    }
    assert_eq!(table.len(), 16);

    let mut newcomer = Exchange::new(60_000);
    let syn = newcomer.syn();
    assert!(matches!(
        syn.classify(&mut table, at(1_000)),
        Outcome::Refused(Refusal::TableFull)
    ));
    assert_eq!(table.counters().refused_table_full, 1);
    assert_eq!(table.counters().flows_evicted, 0);
    for flow in flows {
        assert_eq!(
            table.flow(flow).map(FlowEntry::state),
            Some(FlowState::Established),
            "an established flow was displaced"
        );
    }
}

/// A half-open flow is what pressure takes back, oldest first.
#[test]
fn pressure_takes_back_the_least_recently_seen_half_open_flow() {
    let mut table = table();
    let mut oldest = Exchange::new(40_000);
    let syn = oldest.syn();
    let Outcome::New { flow: victim, .. } = syn.classify(&mut table, at(0)) else {
        panic!("a SYN did not open a flow");
    };
    for index in 1..16u16 {
        let mut exchange = Exchange::new(40_000 + index);
        let syn = exchange.syn();
        syn.classify(&mut table, at(u64::from(index) * 1_000));
    }
    assert_eq!(table.len(), 16);

    let mut newcomer = Exchange::new(60_000);
    let syn = newcomer.syn();
    assert!(matches!(
        syn.classify(&mut table, at(20_000)),
        Outcome::New { .. }
    ));
    assert_eq!(table.counters().flows_evicted, 1);
    assert!(table.flow(victim).is_none(), "the newest was taken instead");
    assert_eq!(table.len(), 16);
}

/// A slot whose flow is over is a reaping rather than an eviction, and the two
/// are counted apart because they accuse different things.
#[test]
fn pressure_reaps_an_expired_flow_before_it_evicts_a_live_one() {
    let mut table = table();
    for index in 0..16u16 {
        let mut exchange = Exchange::new(40_000 + index);
        let syn = exchange.syn();
        syn.classify(&mut table, at(0));
    }
    let mut newcomer = Exchange::new(60_000);
    let syn = newcomer.syn();
    syn.classify(&mut table, after(timeout::SYN_SENT_TIMEOUT));
    assert_eq!(table.counters().flows_evicted, 0);
    assert!(table.counters().flows_expired >= 1);
}

/// A handle to a slot that has been reused names nothing, which is the whole
/// reason a handle carries a generation.
#[test]
fn a_handle_to_a_reused_slot_resolves_to_nothing() {
    let mut table = FlowTable::<1>::new();
    let mut first = Exchange::new(40_000);
    let syn = first.syn();
    let Outcome::New { flow: stale, .. } = syn.classify(&mut table, at(0)) else {
        panic!("a SYN did not open a flow");
    };
    assert!(table.flow(stale).is_some());
    // The one slot is taken back for a second flow.
    let mut second = Exchange::new(40_001);
    let syn = second.syn();
    let Outcome::New { flow: fresh, .. } = syn.classify(&mut table, at(1_000)) else {
        panic!("pressure did not take the half-open slot back");
    };
    assert_ne!(stale, fresh);
    assert!(table.flow(stale).is_none());
    assert!(table.flow(fresh).is_some());
}

// ------------------------------------------------------------- withdrawal

/// The slot a withdrawn flow held goes back, and the flow is gone from the
/// index rather than merely unreachable through its handle: the tuple that
/// opened it opens a *new* flow afterwards.
#[test]
fn withdrawing_a_flow_gives_its_slot_back() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let syn = exchange.syn();
    let Outcome::New { flow, .. } = syn.classify(&mut table, at(0)) else {
        panic!("a SYN did not open a flow");
    };
    assert_eq!(table.len(), 1);

    assert!(table.withdraw(flow));
    assert_eq!(table.len(), 0);
    assert!(table.flow(flow).is_none());
    assert_eq!(table.counters().flows_withdrawn, 1);
    assert_eq!(table.occupancy().get(FlowState::SynSent), 0);
    assert_eq!(table.occupancy().get(FlowState::Vacant), 16);

    // Off the chain, not merely emptied: the same key finds nothing and opens
    // again rather than resolving to the corpse.
    let mut again = Exchange::new(40_000);
    let syn = again.syn();
    assert!(matches!(
        syn.classify(&mut table, at(1_000)),
        Outcome::New { .. }
    ));
}

/// A handle whose slot was reused withdraws nothing. Otherwise a caller holding
/// a stale handle could destroy whichever flow inherited the slot — which on
/// this path would be a caller's refusal of one packet taking down somebody
/// else's live connection.
#[test]
fn withdrawing_a_stale_handle_destroys_nothing() {
    let mut table = FlowTable::<1>::new();
    let mut first = Exchange::new(40_000);
    let syn = first.syn();
    let Outcome::New { flow: stale, .. } = syn.classify(&mut table, at(0)) else {
        panic!("a SYN did not open a flow");
    };
    let mut second = Exchange::new(40_001);
    let syn = second.syn();
    let Outcome::New { flow: fresh, .. } = syn.classify(&mut table, at(1_000)) else {
        panic!("pressure did not take the half-open slot back");
    };
    assert_ne!(stale, fresh);

    assert!(!table.withdraw(stale), "a stale handle withdrew a flow");
    assert_eq!(table.counters().flows_withdrawn, 0);
    assert_eq!(
        table.flow(fresh).map(FlowEntry::state),
        Some(FlowState::SynSent),
        "a stale handle destroyed the flow that inherited its slot"
    );
}

/// Withdrawing a flow that is already gone is not an error and moves no
/// counter, so a caller need not know whether a sweep got there first.
#[test]
fn withdrawing_twice_takes_nothing_back_twice() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let syn = exchange.syn();
    let Outcome::New { flow, .. } = syn.classify(&mut table, at(0)) else {
        panic!("a SYN did not open a flow");
    };
    assert!(table.withdraw(flow));
    assert!(!table.withdraw(flow));
    assert_eq!(table.counters().flows_withdrawn, 1);
    assert_eq!(table.len(), 0);
}

/// Withdrawal reaches an established flow too, and that is deliberate: this is
/// the caller's statement that the packet it asked about is refused, and the
/// caller — not this table — decides which outcomes that applies to.
#[test]
fn withdrawing_an_established_flow_takes_it_back() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let flow = handshake(&mut table, at(0), &mut exchange);
    assert_eq!(table.occupancy().get(FlowState::Established), 1);
    assert!(table.withdraw(flow));
    assert_eq!(table.occupancy().get(FlowState::Established), 0);
    assert_eq!(table.len(), 0);
}

/// One bucket's chain is bounded, so a run of keys that hash into one bucket
/// costs that bucket and nothing else — the table keeps admitting flows whose
/// keys land elsewhere.
#[test]
fn a_chain_at_its_bound_refuses_the_next_key_for_that_bucket() {
    /// Wide enough that the chain bound is reached long before the slots run out.
    const SLOTS: usize = 128;
    let mut table = FlowTable::<SLOTS>::new();
    let bucket_of = |port: u16| {
        let (key, _) = FlowKey::of(
            Endpoint::new(CLIENT, port),
            Endpoint::new(SERVER, 443),
            Protocol::UDP,
        );
        (key.hash() as usize) & (SLOTS - 1)
    };
    // A run of keys that collide, found rather than assumed: the mixer decides
    // which ports share a bucket and no test may predict them.
    let target = bucket_of(40_000);
    let colliding: Vec<u16> = (40_000..u16::MAX)
        .filter(|port| bucket_of(*port) == target)
        .take(MAX_CHAIN + 1)
        .collect();
    assert_eq!(
        colliding.len(),
        MAX_CHAIN + 1,
        "not enough colliding ports to fill a chain"
    );
    for port in colliding.iter().take(MAX_CHAIN) {
        let wire = udp(CLIENT, SERVER, *port, 443);
        assert!(
            matches!(wire.classify(&mut table, at(0)), Outcome::New { .. }),
            "port {port} did not open a flow"
        );
    }
    let last = colliding.last().copied().expect("a last port");
    let wire = udp(CLIENT, SERVER, last, 443);
    assert!(matches!(
        wire.classify(&mut table, at(0)),
        Outcome::Refused(Refusal::BucketFull)
    ));
    assert_eq!(table.counters().refused_bucket_full, 1);
    // The slot the refused flow briefly held went back, and another bucket still
    // takes a flow.
    assert_eq!(table.len(), MAX_CHAIN);
    let elsewhere = udp(CLIENT, SERVER, 443, 40_000);
    assert!(matches!(
        elsewhere.classify(&mut table, at(0)),
        Outcome::New { .. }
    ));
}

// ------------------------------------------------------------------ sweeping

#[test]
fn the_sweep_takes_back_only_what_is_past_its_own_interval() {
    let mut table = table();
    let mut established = Exchange::new(40_000);
    let live = handshake(&mut table, at(0), &mut established);
    let mut half_open = Exchange::new(40_001);
    let syn = half_open.syn();
    syn.classify(&mut table, at(0));
    assert_eq!(table.len(), 2);

    let sweep = table.poll(after(timeout::SYN_SENT_TIMEOUT));
    assert_eq!(sweep.expired, 1);
    assert_eq!(sweep.examined, 16);
    assert_eq!(table.len(), 1);
    assert_eq!(
        table.flow(live).map(FlowEntry::state),
        Some(FlowState::Established)
    );

    table.poll(after(timeout::ESTABLISHED_TIMEOUT));
    assert!(table.is_empty());
    assert_eq!(table.counters().flows_expired, 2);
}

/// An expired flow is never used, whichever poll would eventually have collected
/// it: a lookup reclaims it and the packet opens a fresh flow instead.
#[test]
fn a_lookup_never_returns_an_expired_flow() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let stale = handshake(&mut table, at(0), &mut exchange);
    let late = exchange.data(true, b"x");
    // A segment on a flow whose interval has passed is mid-stream, not
    // established: the flow it names no longer exists.
    assert!(matches!(
        late.classify(&mut table, after(timeout::ESTABLISHED_TIMEOUT)),
        Outcome::Refused(Refusal::MidStream)
    ));
    assert!(table.flow(stale).is_none());
    assert_eq!(table.counters().flows_expired, 1);
}

/// A clock that runs backwards expires nothing, which is the safe direction: a
/// flow survives rather than being reaped out from under live traffic.
#[test]
fn a_clock_that_runs_backwards_expires_nothing() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let flow = handshake(&mut table, at(1_000_000_000), &mut exchange);
    let sweep = table.poll(at(0));
    assert_eq!(sweep.expired, 0);
    assert!(table.flow(flow).is_some());
}

/// A clock that does not advance expires nothing either, so the table fills and
/// then refuses — the fail-closed direction.
#[test]
fn a_clock_that_never_advances_fills_the_table_and_then_refuses() {
    let mut table = table();
    for index in 0..16u16 {
        let mut exchange = Exchange::new(40_000 + index);
        handshake(&mut table, at(7), &mut exchange);
    }
    let mut newcomer = Exchange::new(60_000);
    let syn = newcomer.syn();
    assert!(matches!(
        syn.classify(&mut table, at(7)),
        Outcome::Refused(Refusal::TableFull)
    ));
    assert_eq!(table.poll(at(7)).expired, 0);
}

// ------------------------------------------------------------------ the table

#[test]
fn a_fresh_table_is_empty_and_reports_every_slot_vacant() {
    let table = table();
    assert!(table.is_empty());
    assert_eq!(table.capacity(), 16);
    assert_eq!(table.occupancy().get(FlowState::Vacant), 16);
    assert_eq!(table.occupancy().occupied(), 0);
    assert_eq!(table.counters(), &FlowCounters::new());
    assert_eq!(FlowTable::<16>::default().len(), 0);
}

/// Re-initialising a table in place empties it, which is what a protection
/// domain does to a region it has just mapped.
#[test]
fn re_initialising_empties_the_table() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);
    let flow = handshake(&mut table, at(0), &mut exchange);
    table.initialise();
    assert!(table.is_empty());
    assert!(table.flow(flow).is_none());
    assert_eq!(table.counters(), &FlowCounters::new());
    // And it works again afterwards.
    let mut again = Exchange::new(40_000);
    handshake(&mut table, at(0), &mut again);
    assert_eq!(table.len(), 1);
}

/// The appliance's own table is the size its region has to be, and an entry is
/// the cache line the layout assertions fix it at.
#[test]
fn the_appliance_table_is_the_size_its_region_must_be() {
    use core::mem::size_of;
    assert_eq!(size_of::<FlowEntry>(), 64);
    assert_eq!(FLOW_CAPACITY, 1 << 20);
    // Four bytes of bucket head and sixty-four of entry per flow, plus one
    // aligned header.
    let index = 4 * FLOW_CAPACITY;
    let entries = 64 * FLOW_CAPACITY;
    assert!(FLOW_TABLE_BYTES > index + entries);
    assert!(FLOW_TABLE_BYTES < index + entries + 4096);
    assert_eq!(FLOW_TABLE_BYTES % 64, 0);
}

// --------------------------------------------------------------- properties

/// Every packet a stream can produce, driven at every instant it can be handed
/// over at.
fn arbitrary_wire(
    protocol: u8,
    source: u8,
    port: u16,
    flags: u8,
    sequence: u32,
    acknowledgement: u32,
    payload: usize,
) -> Wire {
    let source_address = Ipv4Address::from_octets([10, 0, 1, source]);
    match protocol % 3 {
        0 => Wire {
            source: source_address,
            destination: SERVER,
            transport: Transport::Tcp(TcpHeader {
                source_port: port,
                destination_port: 443,
                sequence,
                acknowledgement,
                data_offset: 5,
                flags: TcpFlags(flags),
                window: 4096,
                checksum: 0,
                urgent_pointer: 0,
            }),
            bytes: std::vec![0u8; net_headers::TCP_HEADER_LEN + payload],
        },
        1 => udp(source_address, SERVER, port, 53),
        _ => echo(
            source_address,
            SERVER,
            if flags & 1 == 0 {
                IcmpHeader::ECHO_REQUEST
            } else {
                IcmpHeader::ECHO_REPLY
            },
            port,
        ),
    }
}

/// Every slot's state, counted by walking the entries, so the running occupancy
/// can be held to what the table really holds rather than to itself.
fn counted_occupancy<const N: usize>(table: &FlowTable<N>) -> [u32; STATE_COUNT] {
    let mut counts = [0u32; STATE_COUNT];
    for entry in &table.entries {
        if let Some(count) = counts.get_mut(entry.state().index()) {
            *count = count.saturating_add(1);
        }
    }
    counts
}

proptest! {
    /// Arbitrary packets at arbitrary instants never panic and leave the table
    /// bounded. The bytes, the flags, the sequence numbers and the clock are all
    /// unreduced, so every parser, every window comparison and every transition
    /// is reached by inputs nobody chose — including a clock that goes backwards.
    #[test]
    fn arbitrary_packet_streams_never_panic_and_stay_bounded(
        packets in prop::collection::vec(
            (any::<u8>(), any::<u8>(), any::<u16>(), any::<u8>(), any::<u32>(), any::<u32>(), 0usize..64, any::<u32>()),
            0..64,
        ),
    ) {
        let mut table = table();
        for (index, (protocol, source, port, flags, sequence, acknowledgement, payload, when)) in
            packets.iter().enumerate()
        {
            let wire = arbitrary_wire(*protocol, *source, *port, *flags, *sequence, *acknowledgement, *payload);
            let outcome = wire.classify(&mut table, at(u64::from(*when)));
            prop_assert!(table.len() <= 16, "the table overflowed at {}", index);
            // Every packet is accounted for exactly once, and by exactly one
            // arm: a classification or a refusal, never both and never neither.
            let counters = table.counters();
            prop_assert_eq!(
                counters.classified_total() + counters.refused_total(),
                index as u64 + 1,
                "a packet went uncounted"
            );
            // A handle that came back names a flow, and one that did not is a
            // refusal.
            match outcome {
                Outcome::New { flow, .. } | Outcome::Established { flow, .. } | Outcome::Related { flow, .. } => {
                    prop_assert!(table.flow(flow).is_some(), "a handle named nothing");
                }
                Outcome::Refused(_) => {}
            }
            // The sweep is bounded and terminates whatever it finds.
            let sweep = table.poll(at(u64::from(*when)));
            prop_assert!(sweep.expired <= sweep.examined);
        }
    }

    /// A flood of distinct five-tuples leaves the state bounded by the table and
    /// by nothing the peer chooses, **and displaces no established flow**. This
    /// is the fail-closed eviction property, and it is the reason this crate
    /// exists in the shape it does.
    #[test]
    fn a_flood_of_distinct_tuples_evicts_no_established_flow(
        established in 1usize..8,
        flood in 0usize..200,
    ) {
        let mut table = table();
        let mut live = Vec::new();
        for index in 0..established {
            // Lossless: bounded by the strategy.
            let mut exchange = Exchange::new(40_000 + index as u16);
            live.push(handshake(&mut table, at(0), &mut exchange));
        }
        for index in 0..flood {
            // Lossless: bounded by the strategy.
            let mut attacker = Exchange::new(50_000 + index as u16);
            let syn = attacker.syn();
            syn.classify(&mut table, at(1_000 + index as u64));
            prop_assert!(table.len() <= 16);
        }
        for flow in &live {
            prop_assert_eq!(
                table.flow(*flow).map(FlowEntry::state),
                Some(FlowState::Established),
                "a flood displaced an established flow"
            );
        }
        prop_assert_eq!(
            table.occupancy().get(FlowState::Established),
            established as u32
        );
    }

    /// Every flow becomes reapable in finite time, whatever state a stream left
    /// it in: the table cannot be filled with flows that never come back.
    #[test]
    fn every_flow_is_eventually_reapable(script in prop::collection::vec(0u8..7, 0..12)) {
        let mut table = table();
        let mut exchange = Exchange::new(40_000);
        handshake(&mut table, at(0), &mut exchange);
        let mut udp_flow = udp(CLIENT, SERVER, 50_000, 53);
        udp_flow.classify(&mut table, at(0));
        let probe = echo(CLIENT, SERVER, IcmpHeader::ECHO_REQUEST, 9);
        probe.classify(&mut table, at(0));

        for step in &script {
            let wire = match step {
                0 => exchange.data(true, b"data"),
                1 => exchange.data(false, b"back"),
                2 => exchange.fin(true),
                3 => exchange.fin(false),
                4 => exchange.ack(true),
                5 => exchange.reset(true),
                _ => {
                    udp_flow = udp(SERVER, CLIENT, 53, 50_000);
                    udp_flow.classify(&mut table, at(1_000));
                    continue;
                }
            };
            wire.classify(&mut table, at(1_000));
        }
        // Far beyond every interval this crate holds.
        let far = at(timeout::ESTABLISHED_TIMEOUT
            .as_nanos()
            .saturating_add(timeout::TIME_WAIT_TIMEOUT.as_nanos())
            .saturating_add(1));
        // One pass over the table is enough: the stride covers a table this size.
        table.poll(far);
        prop_assert!(table.is_empty(), "a flow outlived every interval");
    }

    /// A flow and its reply always resolve to the same entry, whatever the
    /// addresses and ports are — which is what makes a reply `Established`
    /// rather than a second flow.
    #[test]
    fn a_packet_and_its_reply_always_resolve_to_one_entry(
        client_last in any::<u8>(),
        server_last in any::<u8>(),
        client_port in any::<u16>(),
        server_port in any::<u16>(),
    ) {
        let mut table = table();
        let client = Ipv4Address::from_octets([10, 0, 1, client_last]);
        let server = Ipv4Address::from_octets([10, 0, 2, server_last]);
        let request = udp(client, server, client_port, server_port);
        let Outcome::New { flow, .. } = request.classify(&mut table, at(0)) else {
            prop_assert!(false, "a first datagram did not open a flow");
            return Ok(());
        };
        let reply = udp(server, client, server_port, client_port);
        let Outcome::Established { flow: seen, direction, .. } = reply.classify(&mut table, at(1)) else {
            prop_assert!(false, "a reply did not resolve to the flow it answers");
            return Ok(());
        };
        prop_assert_eq!(seen, flow);
        // The direction is `Reply` unless the two endpoints are identical, in
        // which case there is only one orientation to be in.
        let same_endpoint = client == server && client_port == server_port;
        prop_assert_eq!(direction == Direction::Original, same_endpoint);
        prop_assert_eq!(table.len(), 1);
    }

    /// The table never reports an occupancy it does not hold: the running counts
    /// are exactly the states of its entries, and they sum to its capacity.
    #[test]
    fn the_reported_occupancy_is_the_occupancy_held(
        packets in prop::collection::vec(
            (any::<u8>(), any::<u8>(), any::<u16>(), any::<u8>(), any::<u32>(), any::<u32>()),
            0..48,
        ),
    ) {
        let mut table = table();
        for (protocol, source, port, flags, sequence, acknowledgement) in &packets {
            let wire = arbitrary_wire(*protocol, *source, *port, *flags, *sequence, *acknowledgement, 4);
            wire.classify(&mut table, at(1_000));
        }
        let occupancy = table.occupancy();
        let counted = counted_occupancy(&table);
        let mut total = 0u32;
        for state in FlowState::ALL {
            prop_assert_eq!(
                occupancy.get(state),
                counted.get(state.index()).copied().unwrap_or(0),
                "the reported count of {:?} is not the count held",
                state
            );
            total = total.saturating_add(occupancy.get(state));
        }
        prop_assert_eq!(total, 16, "the occupancy does not sum to the capacity");
        prop_assert_eq!(occupancy.occupied() as usize, table.len());
    }

    /// **A stream of denied opening packets costs no state at all.** This is
    /// the security property withdrawal exists for, stated the way the attack
    /// is: an adversary sends connection attempts a default-deny policy
    /// refuses, and every one of them is withdrawn, so occupancy returns to
    /// zero after each and the table never fills. Without it a refused
    /// connection still holds a slot and default deny becomes the amplifier —
    /// the attacker exhausts the table with connections the policy already
    /// said no to, and legitimate new flows are then refused with
    /// `TableFull`.
    ///
    /// The flood is far longer than the table is wide, so a version that
    /// withdrew nothing would reach `TableFull` inside the run rather than
    /// merely finish untidy.
    #[test]
    fn a_stream_of_denied_openings_leaves_no_state_behind(
        attempts in 1usize..200,
        datagrams in any::<bool>(),
    ) {
        let mut table = table();
        for index in 0..attempts {
            // Lossless: bounded by the strategy.
            let port = 40_000 + index as u16;
            let when = at(1_000 + index as u64);
            let outcome = if datagrams {
                udp(CLIENT, SERVER, port, 53).classify(&mut table, when)
            } else {
                Exchange::new(port).syn().classify(&mut table, when)
            };
            // Every attempt is a distinct tuple against an empty table, so
            // every one of them opens — which is what makes the withdrawal
            // below the only thing keeping the table empty.
            let Outcome::New { flow, .. } = outcome else {
                prop_assert!(false, "attempt {} did not open a flow: {:?}", index, outcome);
                unreachable!()
            };
            prop_assert_eq!(table.len(), 1);
            // What the caller does when the policy behind it says no.
            prop_assert!(table.withdraw(flow));
            prop_assert_eq!(table.len(), 0, "a denied opening kept its slot");
        }
        prop_assert_eq!(table.occupancy().occupied(), 0);
        prop_assert_eq!(table.occupancy().get(FlowState::Vacant), 16);
        prop_assert_eq!(table.counters().flows_withdrawn, attempts as u64);
        prop_assert_eq!(
            table.counters().refused_table_full,
            0,
            "the table filled with connections the policy had refused"
        );
    }
}

// ------------------------------------------------- the operator's vocabulary

/// A refusal reports the kind a counter and a metric label are stated in, and
/// the mapping is onto: every kind is produced by some refusal, so a label the
/// exposition can carry is one the table can actually reach.
#[test]
fn every_refusal_names_its_kind_and_every_kind_is_reachable() {
    let refusals = [
        (
            Refusal::UnsupportedProtocol(Protocol(47)),
            RefusalKind::UnsupportedProtocol,
        ),
        (Refusal::Fragment, RefusalKind::Fragment),
        (
            Refusal::Malformed { needed: 1, got: 0 },
            RefusalKind::Malformed,
        ),
        (Refusal::InvalidFlags, RefusalKind::InvalidFlags),
        (Refusal::MidStream, RefusalKind::MidStream),
        (
            Refusal::InvalidState(FlowState::Established),
            RefusalKind::InvalidState,
        ),
        (
            Refusal::OutOfWindow(WindowEdge::AckAhead),
            RefusalKind::OutOfWindow,
        ),
        (Refusal::NoSuchFlow, RefusalKind::NoSuchFlow),
        (
            Refusal::QuotedInvalid(QuotedError::NotIpv4 { version: 6 }),
            RefusalKind::QuotedInvalid,
        ),
        (
            Refusal::UnsupportedIcmp {
                message_type: 5,
                code: 0,
            },
            RefusalKind::UnsupportedIcmp,
        ),
        (Refusal::TableFull, RefusalKind::TableFull),
        (Refusal::BucketFull, RefusalKind::BucketFull),
    ];
    for (refusal, kind) in refusals {
        assert_eq!(refusal.kind(), kind, "{refusal:?} names the wrong kind");
    }
    for kind in RefusalKind::ALL {
        assert!(
            refusals.iter().any(|(_, named)| *named == kind),
            "{kind:?} is named by no refusal"
        );
    }
}

/// The two token sets this crate publishes are an operator surface, so each is
/// distinct within itself and spelled in the alphabet a metric label value
/// admits: lowercase, digits and underscore, never a hyphen.
#[test]
fn every_exposed_token_is_distinct_and_renderable() {
    let states: Vec<&str> = FlowState::ALL.into_iter().map(FlowState::name).collect();
    let kinds: Vec<&str> = RefusalKind::ALL
        .into_iter()
        .map(RefusalKind::name)
        .collect();
    for tokens in [&states, &kinds] {
        for (position, token) in tokens.iter().enumerate() {
            assert!(!token.is_empty());
            assert!(
                token
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
                "{token} is not spelled in the label alphabet"
            );
            assert!(
                tokens
                    .iter()
                    .enumerate()
                    .all(|(other, candidate)| other == position || candidate != token),
                "{token} is not distinct"
            );
        }
    }
}

/// The classification an outcome reports is the one whose counter moved.
///
/// This closes the loop the metric surface rests on: a caller labels a packet
/// from [`Outcome::classification`] and reads the number from
/// [`FlowCounters::classified`], and those are two matches in two crates. Driving
/// a real packet per classification and asserting the counter the outcome *names*
/// is the one that rose is what keeps them one mapping — a transposed pair would
/// report established traffic under `new` and nothing about either match would
/// notice.
#[test]
fn every_outcome_names_the_counter_that_moved() {
    let mut table = table();
    let mut exchange = Exchange::new(40_000);

    // One packet per classification, in the order a conversation produces them: a
    // `SYN` opens, its `SYN-ACK` advances, and an ICMP error quoting the data that
    // followed relates.
    let mut reached = Vec::new();
    let mut step = 0usize;
    let mut expect = |table: &mut Bench, reached: &mut Vec<Classification>, wire: &Wire, now| {
        let before = *table.counters();
        let outcome = wire.classify(table, now);
        let after = *table.counters();
        let classification = outcome
            .classification()
            .unwrap_or_else(|| panic!("step {step} was refused: {outcome:?}"));
        reached.push(classification);
        for candidate in Classification::ALL {
            let moved = after
                .classified(candidate)
                .saturating_sub(before.classified(candidate));
            assert_eq!(
                moved,
                u64::from(candidate == classification),
                "step {step} reported {classification:?} and {candidate:?}'s counter moved by \
                 {moved}"
            );
        }
        step += 1;
    };

    let syn = exchange.syn();
    expect(&mut table, &mut reached, &syn, at(0));
    let syn_ack = exchange.syn_ack();
    expect(&mut table, &mut reached, &syn_ack, at(1_000));
    let ack = exchange.ack(true);
    ack.classify(&mut table, at(2_000));
    let data = exchange.data(true, b"request");
    data.classify(&mut table, at(3_000));
    let error = icmp_error_quoting_tcp(
        ROUTER,
        CLIENT,
        CLIENT,
        SERVER,
        40_000,
        443,
        exchange.client_next.wrapping_sub(7),
    );
    expect(&mut table, &mut reached, &error, at(4_000));

    // The three steps reached the three classifications, so no arm of the
    // vocabulary went untested.
    for classification in Classification::ALL {
        assert!(
            reached.contains(&classification),
            "{classification:?} was not reached"
        );
    }

    // And a refusal reports no classification at all, which is what keeps the two
    // vocabularies disjoint rather than overlapping at one value.
    let mid_stream = Exchange::new(40_001).ack(true);
    assert_eq!(
        mid_stream.classify(&mut table, at(5_000)).classification(),
        None
    );
}
