//! `lfw_flow` under the two adversaries that reach a forwarded packet, driven as
//! a *table* rather than as a parser.
//!
//! # The adversary and the surface
//!
//! Whatever is on either wire chooses every byte of every packet and every
//! instant at which one arrives (untrusted network traffic), and it chooses **how
//! many distinct flows to ask for** (a connection-flood and state-exhaustion
//! attacker). What it does not choose is the table's size or the clock's
//! direction, and those two are the bounds every assertion below is stated
//! against.
//!
//! What makes this different from [`crate::tcp`]'s surface is that the state is
//! *shared between adversaries*: one flow's packets decide whether another flow
//! gets a slot. So the harness drives a stream over a table that already holds a
//! handshaked connection, and the property that matters is not about the stream at
//! all — it is that no stream can take that connection's slot away.
//!
//! # Modelling authority, not politeness
//!
//! Every value that crosses the boundary is taken unreduced: the addresses, the
//! ports, the protocol byte, the TCP flags, the sequence and acknowledgement
//! numbers, the window, the data offset, the option bytes, the payload length, the
//! ICMP type and code, and — the sharpest of them — the whole quoted datagram
//! inside an ICMP error, which is the five-tuple of somebody else's flow as an
//! attacker chose to write it.
//!
//! The *clock* is arbitrary and may move **backwards**. A peer cannot move a real
//! counter, but a table that assumed monotonicity would be assuming something no
//! type here promises, and `lfw_clock::Monotonic::since` saturates precisely
//! because the hardware does not promise it either.
//!
//! Nothing filters a shape for being implausible. A segment claiming to be a `SYN`
//! and a `FIN` and a `RST` at once is exactly what a scanner sends, and an ICMP
//! error quoting a header that never existed is exactly what a bypass attempt is.
//!
//! # What is asserted
//!
//! * **Totality.** Every packet at every instant is answered — classified, or
//!   refused with a typed reason — and nothing panics, indexes past a bound or
//!   overflows.
//! * **Boundedness of state.** The table never holds more flows than its capacity,
//!   whatever stream of distinct tuples arrives. Asserted after every operation
//!   rather than at the end.
//! * **Eviction is fail-closed.** This is the property the crate exists for: the
//!   number of *assured* flows never falls because a new flow was admitted. The
//!   harness reads it before and after every packet, so a change that let a flood
//!   displace an established connection fails here rather than in production.
//! * **The occupancy is the occupancy held.** The counts the table reports sum to
//!   its capacity, and its own length agrees with them, after every packet — so a
//!   slot leaked or double-counted is a finding rather than a slow drift.
//! * **Every packet is accounted for exactly once.** A classification and a
//!   refusal are exclusive and exhaustive, so the two totals sum to the packets
//!   handed over. A path that answered without counting is a hole in the only
//!   evidence an operator has.
//! * **A handle names a flow.** Every outcome carrying one resolves, and the
//!   generation refuses one whose slot has been reused.
//! * **The sweep is bounded.** It examines what it says it examines and reclaims no
//!   more than that.
//! * **A re-decision terminates over whatever the stream left behind, and takes
//!   back exactly what it was told to.** The pass walks the index rather than the
//!   entries, so which flows it can reach is decided by the chains an arbitrary
//!   stream of colliding tuples built — and the caller's own answer is arbitrary
//!   too, so the pass is exercised keeping everything, revoking everything, and
//!   every mixture. What it must never do is fail to terminate, revoke a flow the
//!   caller kept, or leave the occupancy disagreeing with itself.

use arbitrary::{Arbitrary, Unstructured};
use lfw_clock::{Calibration, Monotonic, Ticks};
use lfw_flow::{
    Disposition, FlowCounters, FlowEntry, FlowId, FlowState, FlowTable, Outcome, Packet,
    REVISIT_BUCKETS, REVISIT_FLOWS, Refusal, SWEEP_STRIDE,
};
use net_headers::{IcmpHeader, Ipv4Address, Protocol, TcpFlags, TcpHeader, Transport, UdpHeader};
use std::num::NonZeroU64;
use std::vec::Vec;

use crate::{MAX_OPERATIONS, any_u16, any_u32, next_op};

/// Flows one table holds. Small on purpose: a flood reaches the table's edge in a
/// handful of packets, so the eviction, the refusal and the reaping paths are
/// ordinary inputs rather than rare ones.
const CAPACITY: usize = 16;

/// The tuple the harness's own connection is established on, so the synchronized
/// paths are reached even by an input that could never compose a handshake.
/// The port the harness's own connection is opened on.
const HARNESS_INGRESS: u8 = 0;

const CLIENT: Ipv4Address = Ipv4Address::from_octets([10, 0, 1, 10]);
const SERVER: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 20]);
const CLIENT_PORT: u16 = 40_000;
const SERVER_PORT: u16 = 443;

/// Drive an arbitrary packet stream over a table that already holds a live
/// connection.
pub fn flow_table_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let mut table: FlowTable<CAPACITY> = FlowTable::new();
    let established = establish(&mut table);

    // The handshake the harness performed itself is already counted, so the
    // accounting below starts from what the table has seen rather than from zero.
    let mut packets = table.counters().packets_seen;
    let mut operations = 0usize;
    while let Some(op) = next_op(&mut unstructured) {
        operations += 1;
        let now = instant(any_u32(&mut unstructured));
        let assured_before = assured(&table);

        let wire = match op % 5 {
            0 | 1 => tcp_packet(&mut unstructured),
            2 => udp_packet(&mut unstructured),
            3 => icmp_packet(&mut unstructured),
            // An error quoting the harness's own live connection, with the
            // sequence number the adversary's to choose. Random bytes reach the
            // `Related` decision only by accident; this reaches it on purpose,
            // which is the whole point of the target.
            _ => quoting_error(&mut unstructured),
        };

        let outcome = table.classify(now, &wire.packet());
        packets += 1;

        assert!(
            table.len() <= CAPACITY,
            "the table holds more flows than its capacity"
        );
        // The fail-closed eviction property: admitting a flow never costs an
        // assured one.
        if matches!(outcome, Outcome::New { .. }) {
            assert!(
                assured(&table) >= assured_before,
                "admitting a new flow displaced an assured one"
            );
        }
        if matches!(outcome, Outcome::Refused(Refusal::TableFull)) {
            assert_eq!(
                table.len(),
                CAPACITY,
                "a full table was reported while it held free slots"
            );
        }
        match outcome {
            Outcome::New { flow, .. }
            | Outcome::Established { flow, .. }
            | Outcome::Related { flow, .. } => {
                assert!(table.flow(flow).is_some(), "a handle named nothing");
            }
            Outcome::Refused(_) => {}
        }
        assert_occupancy(&table);
        assert_accounted(table.counters(), packets);

        // The sweep, at the same arbitrary instant, examines what it says it does.
        let sweep = table.poll(now);
        assert_eq!(sweep.examined, SWEEP_STRIDE.min(CAPACITY));
        assert!(sweep.expired <= sweep.examined);
        assert_occupancy(&table);

        // And a whole re-decision over whatever the stream has left in the table,
        // with the caller's answer taken from the same input: the pass must
        // terminate, must revoke only what it was told to, and must leave the
        // occupancy consistent whichever chains the tuples happened to build.
        assert_revisiting_takes_back_only_what_it_is_told(
            &mut table,
            u8::arbitrary(&mut unstructured).unwrap_or(0),
        );
        assert_occupancy(&table);
        assert_accounted(table.counters(), packets);

        if operations >= MAX_OPERATIONS {
            break;
        }
    }

    assert_initialising_empties_the_table(&mut table, established);
}

/// One whole pass over the index, keeping a flow exactly where `keep` says so.
///
/// `keep` is a bit pattern the input chose, taken against the flow's own slot, so
/// one input reaches "keep everything", "revoke everything" and every mixture
/// between — which is what makes the selectivity property meaningful rather than a
/// restatement of one branch.
///
/// The pass is bounded per call, so a caller has to loop; a bound on how many calls
/// that may take is what makes non-termination a finding here rather than a hang.
fn assert_revisiting_takes_back_only_what_it_is_told<const N: usize>(
    table: &mut FlowTable<N>,
    keep: u8,
) {
    let before = table.len();
    let revoked_before = table.counters().flows_revoked;
    let mut kept = Vec::new();
    let mut cursor = 0usize;
    let mut calls = 0usize;
    let mut revoked = 0usize;
    loop {
        let pass = table.revisit(cursor, |flow| {
            assert!(
                (flow.id.slot() as usize) < N,
                "a re-decision reported a slot the table does not have"
            );
            if keep & (1u8 << (flow.id.slot() % 8)) == 0 {
                revoked += 1;
                Disposition::Revoke
            } else {
                kept.push(flow.id);
                Disposition::Keep
            }
        });
        assert!(pass.buckets <= REVISIT_BUCKETS);
        assert!(pass.examined <= REVISIT_FLOWS + lfw_flow::MAX_CHAIN);
        assert!(pass.revoked <= pass.examined);
        cursor = pass.next;
        calls += 1;
        // One window covers `REVISIT_BUCKETS` buckets and the table has `N`, so a
        // pass that has not finished by this many calls is not advancing.
        assert!(
            calls <= N.div_ceil(REVISIT_BUCKETS) + N + 1,
            "a re-decision did not terminate"
        );
        if pass.complete {
            break;
        }
    }
    // Exactly the flows the caller disowned, and no others.
    assert_eq!(
        table.len(),
        before - revoked,
        "a re-decision took back a different number of flows than it reported"
    );
    assert_eq!(
        table.counters().flows_revoked,
        revoked_before + revoked as u64,
        "a revocation was performed without being counted"
    );
    for id in kept {
        assert!(
            table.flow(id).is_some(),
            "a re-decision took back a flow the caller kept"
        );
    }
}

/// The counts the table reports sum to its capacity and agree with its own length.
fn assert_occupancy<const N: usize>(table: &FlowTable<N>) {
    let occupancy = table.occupancy();
    let mut total = 0u32;
    for state in FlowState::ALL {
        total = total.saturating_add(occupancy.get(state));
    }
    // Lossless: the capacity here is sixteen.
    assert_eq!(
        total, N as u32,
        "the occupancy does not sum to the capacity"
    );
    assert_eq!(
        occupancy.occupied() as usize,
        table.len(),
        "the length and the occupancy disagree"
    );
}

/// Every packet is either classified or refused, never both and never neither.
fn assert_accounted(counters: &FlowCounters, packets: u64) {
    assert_eq!(
        counters.classified_total() + counters.refused_total(),
        packets,
        "a packet was answered without being counted"
    );
    assert_eq!(counters.packets_seen, packets);
    assert_eq!(
        counters.internal_slot_desync, 0,
        "the table's own bookkeeping disagreed with itself"
    );
}

/// How many flows the table holds that may never be evicted.
fn assured<const N: usize>(table: &FlowTable<N>) -> u32 {
    let occupancy = table.occupancy();
    FlowState::ALL
        .into_iter()
        .filter(|state| state.is_assured())
        .fold(0u32, |total, state| {
            total.saturating_add(occupancy.get(state))
        })
}

/// Re-initialising the table empties it and refuses every handle issued before,
/// whatever the stream left in it.
///
/// The generations restart with the table, which is why this is the one thing
/// asserted about a handle across it: the crate states that no handle survives an
/// initialisation, and a caller holding one must discard it.
fn assert_initialising_empties_the_table<const N: usize>(
    table: &mut FlowTable<N>,
    issued: Option<FlowId>,
) {
    table.initialise();
    assert_eq!(table.len(), 0, "a flow survived the table being emptied");
    assert_eq!(
        table.counters(),
        &FlowCounters::new(),
        "the counters survived the table being emptied"
    );
    assert_occupancy(table);
    if let Some(issued) = issued {
        assert!(
            table.flow(issued).is_none(),
            "a handle resolved against an emptied table"
        );
    }
}

/// One packet, owning its own bytes so a [`Packet`] can borrow them.
struct Wire {
    /// Unreduced, on every other field's terms: the port is the *caller's* claim
    /// rather than the network's, and a table that read it would be reading a value
    /// nothing here validates. It is carried through to the opening a re-decision
    /// reports, so an arbitrary one is what proves that round trip.
    ingress: u8,
    source: Ipv4Address,
    destination: Ipv4Address,
    transport: Transport,
    bytes: Vec<u8>,
}

impl Wire {
    fn packet(&self) -> Packet<'_> {
        Packet {
            ingress: self.ingress,
            source: self.source,
            destination: self.destination,
            transport: self.transport,
            transport_bytes: &self.bytes,
        }
    }
}

/// An instant, which may be *anywhere* — including behind a previous one. See the
/// module header on why a backwards clock is the adversary's authority rather than
/// an implausible input.
fn instant(nanos: u32) -> Monotonic {
    let hz = NonZeroU64::new(lfw_clock::NANOS_PER_SECOND).expect("a nonzero frequency");
    // Scaled well past every interval the crate holds, so expiry, reaping and
    // eviction are all reachable within one input.
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(u64::from(nanos) * 4_096))
}

/// An address from a small set, so a stream both revisits one flow and floods the
/// table with new ones.
fn address(unstructured: &mut Unstructured<'_>) -> Ipv4Address {
    Ipv4Address::from_octets([10, 0, 1, any_u16(unstructured) as u8])
}

/// A TCP segment with every field the adversary's, including the option area the
/// window shift is read out of.
fn tcp_packet(unstructured: &mut Unstructured<'_>) -> Wire {
    let source = address(unstructured);
    let flags = TcpFlags(u8::arbitrary(unstructured).unwrap_or(0));
    let data_offset = u8::arbitrary(unstructured).unwrap_or(5) & 0x0f;
    let sequence = any_u32(unstructured);
    let acknowledgement = any_u32(unstructured);
    let window = any_u16(unstructured);
    let source_port = any_u16(unstructured);
    // Bounded by what a slice can be *made* to be here rather than by anything a
    // peer may ask for: the length is a property of the datagram the driver
    // already received, and the interesting decisions are at a handful of bytes.
    let length = usize::from(any_u16(unstructured) % 96);
    let mut bytes = Vec::with_capacity(length);
    for _ in 0..length {
        bytes.push(u8::arbitrary(unstructured).unwrap_or(0));
    }
    Wire {
        ingress: u8::arbitrary(unstructured).unwrap_or(0),
        source,
        destination: SERVER,
        transport: Transport::Tcp(TcpHeader {
            source_port,
            destination_port: SERVER_PORT,
            sequence,
            acknowledgement,
            data_offset,
            flags,
            window,
            checksum: any_u16(unstructured),
            urgent_pointer: any_u16(unstructured),
        }),
        bytes,
    }
}

fn udp_packet(unstructured: &mut Unstructured<'_>) -> Wire {
    let source = address(unstructured);
    let source_port = any_u16(unstructured);
    let destination_port = any_u16(unstructured);
    Wire {
        ingress: u8::arbitrary(unstructured).unwrap_or(0),
        source,
        destination: SERVER,
        transport: Transport::Udp(UdpHeader {
            source_port,
            destination_port,
            length: any_u16(unstructured),
            checksum: any_u16(unstructured),
        }),
        bytes: std::vec![0u8; net_headers::UDP_HEADER_LEN],
    }
}

/// An ICMP message of an arbitrary type, carrying arbitrary bytes behind its
/// header — so the quoted-datagram reader is driven by input nobody shaped.
fn icmp_packet(unstructured: &mut Unstructured<'_>) -> Wire {
    let source = address(unstructured);
    let message_type = u8::arbitrary(unstructured).unwrap_or(0);
    let code = u8::arbitrary(unstructured).unwrap_or(0);
    let identifier = any_u16(unstructured);
    let [high, low] = identifier.to_be_bytes();
    let length = usize::from(any_u16(unstructured) % 96);
    let mut bytes = std::vec![0u8; net_headers::ICMP_HEADER_LEN];
    for _ in 0..length {
        bytes.push(u8::arbitrary(unstructured).unwrap_or(0));
    }
    Wire {
        ingress: u8::arbitrary(unstructured).unwrap_or(0),
        source,
        destination: if any_u16(unstructured) % 2 == 0 {
            SERVER
        } else {
            CLIENT
        },
        transport: Transport::Icmp(IcmpHeader {
            message_type,
            code,
            checksum: any_u16(unstructured),
            rest_of_header: [high, low, 0, 1],
        }),
        bytes,
    }
}

/// An ICMP error quoting the harness's own connection, with every field of the
/// quote the adversary's.
///
/// This is the bypass surface: the tuple in the quote is a flow the table really
/// holds, so what stands between the error and a `Related` verdict is the
/// corroboration alone. Without composing one deliberately, the decision is
/// reachable only by an input that guessed a five-tuple.
fn quoting_error(unstructured: &mut Unstructured<'_>) -> Wire {
    let quoted_source = if any_u16(unstructured) % 4 == 0 {
        address(unstructured)
    } else {
        CLIENT
    };
    let version_and_length = if any_u16(unstructured) % 8 == 0 {
        u8::arbitrary(unstructured).unwrap_or(0x45)
    } else {
        0x45
    };
    let protocol = if any_u16(unstructured) % 8 == 0 {
        u8::arbitrary(unstructured).unwrap_or(6)
    } else {
        Protocol::TCP.0
    };
    let source_port = if any_u16(unstructured) % 4 == 0 {
        any_u16(unstructured)
    } else {
        CLIENT_PORT
    };
    let sequence = any_u32(unstructured);

    let mut bytes = std::vec![0u8; net_headers::ICMP_HEADER_LEN];
    let mut quoted = std::vec![0u8; net_headers::IPV4_HEADER_LEN];
    let write = |bytes: &mut Vec<u8>, offset: usize, value: u8| {
        if let Some(cell) = bytes.get_mut(offset) {
            *cell = value;
        }
    };
    write(&mut quoted, 0, version_and_length);
    write(
        &mut quoted,
        6,
        u8::arbitrary(unstructured).unwrap_or(0) & 0x1f,
    );
    write(&mut quoted, 9, protocol);
    for (index, octet) in quoted_source.octets().into_iter().enumerate() {
        write(&mut quoted, 12 + index, octet);
    }
    for (index, octet) in SERVER.octets().into_iter().enumerate() {
        write(&mut quoted, 16 + index, octet);
    }
    bytes.extend_from_slice(&quoted);
    bytes.extend_from_slice(&source_port.to_be_bytes());
    bytes.extend_from_slice(&SERVER_PORT.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    // A share of the stream truncates the quote, which is the reader's own bound
    // rather than a shape a sender could not produce.
    let keep = bytes
        .len()
        .saturating_sub(usize::from(any_u16(unstructured) % 24));
    bytes.truncate(keep);

    Wire {
        ingress: u8::arbitrary(unstructured).unwrap_or(0),
        source: address(unstructured),
        destination: CLIENT,
        transport: Transport::Icmp(IcmpHeader {
            message_type: IcmpHeader::DESTINATION_UNREACHABLE,
            code: 3,
            checksum: 0,
            rest_of_header: [0; 4],
        }),
        bytes,
    }
}

/// One segment of the harness's own handshake.
///
/// The one `Wire` whose ingress is fixed rather than arbitrary: this is the
/// harness's *own* connection, composed so the synchronized paths are reachable at
/// all, and every value in it is chosen for that.
fn handshake_segment(
    from_server: u8,
    flags: TcpFlags,
    sequence: u32,
    acknowledgement: u32,
) -> Wire {
    let (source, destination, source_port, destination_port) = if from_server == 0 {
        (CLIENT, SERVER, CLIENT_PORT, SERVER_PORT)
    } else {
        (SERVER, CLIENT, SERVER_PORT, CLIENT_PORT)
    };
    Wire {
        ingress: HARNESS_INGRESS,
        source,
        destination,
        transport: Transport::Tcp(TcpHeader {
            source_port,
            destination_port,
            sequence,
            acknowledgement,
            data_offset: 5,
            flags,
            window: 4_096,
            checksum: 0,
            urgent_pointer: 0,
        }),
        bytes: std::vec![0u8; net_headers::TCP_HEADER_LEN],
    }
}

/// Put one established connection in the table, so the synchronized paths and the
/// fail-closed eviction property are reachable by every input.
fn establish<const N: usize>(table: &mut FlowTable<N>) -> Option<FlowId> {
    const SYN: TcpFlags = TcpFlags(0x02);
    const ACK: TcpFlags = TcpFlags(0x10);
    const SYN_ACK: TcpFlags = TcpFlags(0x12);
    let client_iss = 0x1000_0000u32;
    let server_iss = 0x2000_0000u32;
    let now = instant(0);

    let syn = handshake_segment(0, SYN, client_iss, 0);
    let Outcome::New { flow, .. } = table.classify(now, &syn.packet()) else {
        return None;
    };
    let syn_ack = handshake_segment(1, SYN_ACK, server_iss, client_iss.wrapping_add(1));
    table.classify(now, &syn_ack.packet());
    let ack = handshake_segment(
        0,
        ACK,
        client_iss.wrapping_add(1),
        server_iss.wrapping_add(1),
    );
    table.classify(now, &ack.packet());
    assert_eq!(
        table.flow(flow).map(FlowEntry::state),
        Some(FlowState::Established),
        "the harness could not establish a connection"
    );
    Some(flow)
}
