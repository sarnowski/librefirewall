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
        outcome,
        direction: TapDirection::Inbound,
        generation: 3,
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
    assert_eq!(checked.direction, TapDirection::Inbound);
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
