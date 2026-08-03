use super::*;

use std::boxed::Box;
use std::vec::Vec;

use wire::{TAP_SNAP_LEN, TapFault};

/// The ring is far larger than a stack frame, so every test heaps it.
struct Ring {
    records: Box<TapRecords>,
    consume: Box<TapConsume>,
}

impl Ring {
    fn new() -> Self {
        Self {
            records: Box::new(TapRecords::zero()),
            consume: Box::new(TapConsume::zero()),
        }
    }

    fn drain(&self) -> Vec<(wire::CheckedTap, Vec<u8>)> {
        let mut reader = self.consume.reader(&self.records);
        let mut into = [0u8; TAP_SNAP_LEN];
        let mut read = Vec::new();
        reader.drain(usize::MAX, &mut into, |one| match one {
            Ok((checked, bytes)) => read.push((checked, bytes.to_vec())),
            Err(fault) => panic!("the producer wrote an annotation it cannot write: {fault:?}"),
        });
        read
    }
}

fn observation(frame: &[u8], outcome: TapOutcome) -> Observation<'_> {
    Observation {
        timestamp: 7,
        interface_id: 1,
        decision: TapDecision {
            outcome,
            direction: Some(TapDirection::Inbound),
            generation: 3,
            flow: None,
            rule: None,
            event: None,
        },
        frame,
    }
}

#[test]
fn every_drop_reason_maps_to_its_own_tap_reason() {
    let mapped: Vec<u32> = DropReason::ALL
        .iter()
        .map(|reason| tap_drop_reason(*reason).to_bits())
        .collect();
    let mut sorted = mapped.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        DropReason::ALL.len(),
        "two routing reasons share one tap encoding: {mapped:?}"
    );
    // The ABI states the two enums are declared in the same order, which is
    // what makes the mirrored `to_bits` a total conversion rather than a table
    // somebody has to keep aligned by hand.
    for (index, reason) in DropReason::ALL.iter().enumerate() {
        assert_eq!(
            tap_drop_reason(*reason).to_bits() as usize,
            index + 1,
            "{reason:?} does not mirror its declaration position"
        );
    }
}

#[test]
fn an_observation_reaches_the_reader_whole() {
    let ring = Ring::new();
    let mut tap = Tap::attach(&ring.records, &ring.consume);
    let frame = [0xAAu8; 64];

    tap.observe(observation(
        &frame,
        TapOutcome::Dropped(TapDropReason::NoRoute),
    ));

    let read = ring.drain();
    assert_eq!(read.len(), 1);
    let (checked, bytes) = &read[0];
    assert_eq!(checked.packet_id, 0);
    assert_eq!(checked.timestamp, 7);
    assert_eq!(checked.interface_id, 1);
    assert_eq!(checked.original_len, 64);
    assert_eq!(checked.generation, 3);
    assert_eq!(checked.outcome, TapOutcome::Dropped(TapDropReason::NoRoute));
    assert_eq!(checked.direction, Some(TapDirection::Inbound));
    assert_eq!(bytes.as_slice(), &frame[..]);
    assert_eq!(
        tap.counters(),
        TapCounters {
            observed: 1,
            dropped: 0,
            refused: 0
        }
    );
}

#[test]
fn packet_identities_are_monotone_across_observations() {
    let ring = Ring::new();
    let mut tap = Tap::attach(&ring.records, &ring.consume);
    let frame = [1u8; 16];
    for _ in 0..4 {
        tap.observe(observation(&frame, TapOutcome::Forwarded));
    }
    let ids: Vec<u64> = ring.drain().iter().map(|(tap, _)| tap.packet_id).collect();
    assert_eq!(ids, [0, 1, 2, 3]);
}

#[test]
fn a_full_ring_costs_the_newest_observation_and_nothing_else() {
    let ring = Ring::new();
    let mut tap = Tap::attach(&ring.records, &ring.consume);
    let frame = [2u8; 8];
    let capacity = ring.records.capacity();

    for _ in 0..capacity + 5 {
        tap.observe(observation(&frame, TapOutcome::Forwarded));
    }

    let counters = tap.counters();
    assert_eq!(counters.observed, capacity as u64);
    assert_eq!(counters.dropped, 5);
    assert_eq!(counters.refused, 0);
    // The producer kept its own position, so the oldest records survived and it
    // is the newest that were refused: identities 0..capacity, never a gap.
    let ids: Vec<u64> = ring.drain().iter().map(|(tap, _)| tap.packet_id).collect();
    assert_eq!(ids, (0..capacity as u64).collect::<Vec<_>>());
}

#[test]
fn a_frame_longer_than_a_slot_is_recorded_truncated_with_its_wire_length() {
    let ring = Ring::new();
    let mut tap = Tap::attach(&ring.records, &ring.consume);
    let frame = vec![3u8; TAP_SNAP_LEN + 64];

    tap.observe(observation(&frame, TapOutcome::Forwarded));

    let read = ring.drain();
    let (checked, bytes) = &read[0];
    assert_eq!(checked.original_len, frame.len() as u32);
    assert_eq!(bytes.len(), TAP_SNAP_LEN);
    assert_eq!(tap.counters().refused, 0);
}

#[test]
fn a_reader_that_never_drains_is_the_only_thing_a_full_ring_costs() {
    let ring = Ring::new();
    let mut tap = Tap::attach(&ring.records, &ring.consume);
    let frame = [4u8; 32];
    for _ in 0..1000 {
        tap.observe(observation(&frame, TapOutcome::Forwarded));
    }
    // Every offer was answered, none waited, and the ring still decodes.
    assert_eq!(tap.counters().observed + tap.counters().dropped, 1000);
    let mut reader = ring.consume.reader(&ring.records);
    let mut into = [0u8; TAP_SNAP_LEN];
    let mut faults = 0;
    reader.drain(usize::MAX, &mut into, |one| {
        if matches!(one, Err(TapFault::ReservedNonZero { .. })) {
            faults += 1;
        }
    });
    assert_eq!(faults, 0);
}

/// One live flow in `state`, as a re-decision hands it over.
///
/// The handle comes out of a real table rather than being built here: `FlowId` has
/// no public constructor, deliberately, so the only way to hold one is to have
/// opened the flow it names — which is also what makes the identity in the record
/// below one a reader could fold onto an opening.
fn live(state: FlowState) -> LiveFlow {
    let mut table = lfw_flow::FlowTable::<16>::new();
    let header = [0u8; net_headers::UDP_HEADER_LEN];
    let outcome = table.classify(
        lfw_clock::Monotonic::BOOT,
        &lfw_flow::Packet {
            ingress: 1,
            source: net_headers::Ipv4Address::from_octets([10, 0, 0, 2]),
            destination: net_headers::Ipv4Address::from_octets([10, 0, 1, 2]),
            transport: net_headers::Transport::Udp(net_headers::UdpHeader {
                source_port: 4444,
                destination_port: 5000,
                length: net_headers::UDP_HEADER_LEN as u16,
                checksum: 0,
            }),
            transport_bytes: &header,
        },
    );
    let lfw_flow::Outcome::New { flow, .. } = outcome else {
        panic!("a fresh tuple opens a flow: {outcome:?}");
    };
    let opening = table
        .flow(flow)
        .map(lfw_flow::FlowEntry::opening)
        .expect("the flow just opened");
    LiveFlow {
        id: flow,
        opening,
        state,
    }
}

/// **The record about no frame, composed by the producer and read back whole.**
///
/// It is the honesty of the thing that is under test: a revocation reaches the
/// recorder naming the conversation it ended and the state that conversation was
/// in, and claiming none of the four things a frame has — no wire length, no
/// captured bytes, no direction and no classification. The reader refuses each of
/// those by name, so a producer that supplied one would be refused here rather
/// than writing a fabricated cause into an artifact that is evidence.
#[test]
fn a_revoked_flow_is_published_naming_its_conversation_and_no_frame() {
    let ring = Ring::new();
    let mut tap = Tap::attach(&ring.records, &ring.consume);

    tap.observe_revocation(Revocation {
        timestamp: 11,
        flow: &live(FlowState::UdpAssured),
        generation: 9,
    });

    let read = ring.drain();
    assert_eq!(read.len(), 1);
    let (checked, bytes) = &read[0];
    assert!(bytes.is_empty(), "no bytes were on a wire");
    assert_eq!(checked.original_len, 0, "and none is claimed to have been");
    assert_eq!(checked.outcome, wire::TapOutcome::Revoked);
    assert_eq!(checked.direction, None);
    assert_eq!(checked.rule, None);
    assert_eq!(checked.event, Some(wire::TapEvent::FlowRevoked));
    assert_eq!(checked.generation, 9, "the commit that ended it");
    assert_eq!(checked.timestamp, 11);
    // The interface is the port the conversation was opened on, which is what a
    // record of its end is attributed to.
    assert_eq!(checked.interface_id, 1);
    assert_eq!(
        checked.flow,
        Some(wire::TapFlow {
            slot: live(FlowState::UdpAssured).id.slot(),
            generation: live(FlowState::UdpAssured).id.generation(),
            classification: None,
            state: wire::TapFlowState::UdpAssured,
        })
    );
    assert_eq!(tap.counters().observed, 1);
    assert_eq!(tap.counters().refused, 0);
}

/// A revocation is numbered out of the same sequence a frame observation is, so a
/// reader relating records across the two recordings never sees one identity twice.
#[test]
fn a_revocation_takes_the_next_packet_identity() {
    let ring = Ring::new();
    let mut tap = Tap::attach(&ring.records, &ring.consume);
    let frame = [7u8; 40];

    tap.observe(observation(&frame, TapOutcome::Forwarded));
    tap.observe_revocation(Revocation {
        timestamp: 0,
        flow: &live(FlowState::Established),
        generation: 2,
    });
    tap.observe(observation(&frame, TapOutcome::Forwarded));

    let ids: Vec<u64> = ring.drain().iter().map(|(tap, _)| tap.packet_id).collect();
    assert_eq!(ids, std::vec![0, 1, 2]);
}

/// Every state a live flow can be in reaches the ABI, so a revocation of a
/// conversation in any of them is recordable rather than silently dropped.
///
/// The vacant state is the one that cannot: a live flow is never in it, which is
/// what the conversion answers `None` for.
#[test]
fn every_state_a_live_flow_can_hold_is_recordable_and_the_vacant_one_is_not() {
    for state in FlowState::ALL {
        let flow = live(state);
        assert_eq!(
            tap_revoked_flow(&flow).is_some(),
            state != FlowState::Vacant,
            "{state:?}"
        );
    }
    // And a table that somehow offered a vacant flow publishes nothing rather
    // than a record naming a state the ABI has no encoding for.
    let ring = Ring::new();
    let mut tap = Tap::attach(&ring.records, &ring.consume);
    tap.observe_revocation(Revocation {
        timestamp: 0,
        flow: &live(FlowState::Vacant),
        generation: 1,
    });
    assert!(ring.drain().is_empty());
    assert_eq!(tap.counters().observed, 0);
}
