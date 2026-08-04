use super::*;
use core::mem::offset_of;
use proptest::prelude::*;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::vec::Vec;

/// The two regions one ring is, held together for a test that drives both ends.
struct Ring {
    records: TapRecords,
    consume: TapConsume,
}

impl Ring {
    fn zero() -> Self {
        Self {
            records: TapRecords::zero(),
            consume: TapConsume::zero(),
        }
    }

    fn writer(&self) -> TapWriter<'_> {
        self.records.writer(&self.consume)
    }

    fn reader(&self) -> TapReader<'_> {
        self.consume.reader(&self.records)
    }

    fn capacity(&self) -> usize {
        self.records.capacity()
    }
}

/// A snap-length buffer on the heap, so a test holding several does not put
/// tens of kilobytes on the stack.
fn buffer() -> Box<[u8; TAP_SNAP_LEN]> {
    Box::new([0; TAP_SNAP_LEN])
}

/// A forwarded inbound observation identifiable on the way out by `packet_id`.
fn tagged(packet_id: u64) -> TapAnnotation {
    TapAnnotation::new(packet_id, 0, 0, forwarded())
}

/// The decision a plainly forwarded frame carries: no flow, no rule, no event.
fn forwarded() -> TapDecision {
    TapDecision {
        outcome: TapOutcome::Forwarded,
        direction: Some(TapDirection::Inbound),
        generation: 0,
        flow: None,
        rule: None,
        event: None,
    }
}

/// A flow in `state`, classified as `classification`, at a fixed identity — so
/// a test asserting on the identity is asserting on what crossed rather than on
/// a number it also chose per case.
fn flow(classification: TapClassification, state: TapFlowState) -> TapFlow {
    TapFlow {
        slot: 4_321,
        generation: 17,
        classification: Some(classification),
        state,
    }
}

/// A frame whose every byte is derived from `tag`, so a payload delivered under
/// the wrong annotation is visible rather than plausible.
fn frame(tag: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| (tag as u8).wrapping_add(index as u8))
        .collect()
}

/// Store a raw annotation into a slot and publish it, which is what a peer that
/// does not keep to the protocol can do at any moment.
fn forge(ring: &Ring, at: u32, raw: &TapAnnotation) {
    let slot = ring.records.slot(at);
    slot.packet_id.store(raw.packet_id, Ordering::Relaxed);
    slot.timestamp.store(raw.timestamp, Ordering::Relaxed);
    slot.interface_id.store(raw.interface_id, Ordering::Relaxed);
    slot.original_len.store(raw.original_len, Ordering::Relaxed);
    slot.captured_len.store(raw.captured_len, Ordering::Relaxed);
    slot.verdict.store(raw.verdict, Ordering::Relaxed);
    slot.drop_reason.store(raw.drop_reason, Ordering::Relaxed);
    slot.flags.store(raw.flags, Ordering::Relaxed);
    slot.generation.store(raw.generation, Ordering::Relaxed);
    slot.flow_slot.store(raw.flow_slot, Ordering::Relaxed);
    slot.flow_generation
        .store(raw.flow_generation, Ordering::Relaxed);
    slot.classification
        .store(raw.classification, Ordering::Relaxed);
    slot.event.store(raw.event, Ordering::Relaxed);
    slot.flow_state.store(raw.flow_state, Ordering::Relaxed);
    slot.rule.store(raw.rule, Ordering::Relaxed);
    for (cell, word) in slot._reserved.iter().zip(raw._reserved) {
        cell.store(word, Ordering::Relaxed);
    }
}

/// A well-formed raw annotation, to be spoiled one field at a time.
fn sound_raw() -> TapAnnotation {
    TapAnnotation {
        packet_id: 7,
        timestamp: 9,
        interface_id: 1,
        original_len: 4,
        captured_len: 4,
        verdict: TapVerdict::Forwarded.to_bits(),
        drop_reason: 0,
        flags: TapDirection::Inbound.to_bits(),
        generation: 3,
        flow_slot: 0,
        flow_generation: 0,
        classification: 0,
        event: 0,
        flow_state: 0,
        rule: 0,
        _reserved: [0; TAP_RESERVED_WORDS],
    }
}

/// A forwarded inbound decision carrying whatever a case is about.
fn decision(flow: Option<TapFlow>, rule: Option<TapRule>, event: Option<TapEvent>) -> TapDecision {
    TapDecision {
        flow,
        rule,
        event,
        ..forwarded()
    }
}

/// One observation of a frame, with the lengths [`TapAnnotation::new`] leaves to
/// the writer already filled in.
///
/// A helper because a wire length of zero is no longer readable as an observation:
/// it is what says a record is about no frame, so a test that means to assert on
/// the decision words has to state a frame the record is about.
fn observed(decision: TapDecision) -> TapAnnotation {
    TapAnnotation {
        original_len: 4,
        captured_len: 4,
        ..TapAnnotation::new(0, 0, 1, decision)
    }
}

/// The one observation that is about no frame: a flow the appliance ended when a
/// policy commit stopped admitting it.
///
/// Composed here the way `pd_runtime::Tap::observe_revocation` composes it, so the
/// tests below assert on the shape a producer actually writes.
fn revocation(state: TapFlowState) -> TapAnnotation {
    TapAnnotation::new(
        0,
        0,
        1,
        TapDecision {
            outcome: TapOutcome::Revoked,
            direction: None,
            generation: 0,
            flow: Some(TapFlow {
                slot: 4_321,
                generation: 17,
                classification: None,
                state,
            }),
            rule: None,
            event: Some(TapEvent::FlowRevoked),
        },
    )
}

/// Publish one forged slot and read it back, which is the shape every hostile
/// annotation test takes.
fn read_forged(raw: &TapAnnotation) -> Result<CheckedTap, TapFault> {
    let ring = Ring::zero();
    let mut reader = ring.reader();
    let mut into = buffer();
    forge(&ring, 0, raw);
    ring.records.tail.store(1, Ordering::Release);
    reader
        .read(&mut into)
        .expect("one slot was published")
        .map(|(checked, _)| checked)
}

#[test]
fn the_regions_the_system_description_reserves_are_the_recorded_ones() {
    assert_eq!(TAP_SNAP_LEN, 2048);
    assert_eq!(TAP_SLOTS, 64);
    assert_eq!(size_of::<TapAnnotation>(), 80);
    assert_eq!(size_of::<TapSlot>(), 2128);
    assert_eq!(size_of::<TapRecords>(), 8 + 64 * 2128);
    assert_eq!(size_of::<TapRecords>(), 136_200);
    assert_eq!(TAP_RECORDS_REGION_SIZE, 139_264);
    assert!(TAP_RECORDS_REGION_SIZE >= size_of::<TapRecords>());
    assert!(TAP_RECORDS_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));

    assert_eq!(size_of::<TapConsume>(), 4);
    assert_eq!(TAP_CONSUME_REGION_SIZE, 0x1000);
    assert_eq!(offset_of!(TapConsume, head), 0);
    assert_eq!(offset_of!(TapRecords, tail), 0);
    assert_eq!(offset_of!(TapRecords, dropped), 4);
    assert_eq!(offset_of!(TapRecords, slots), 8);
}

/// The byte layout two protection domains agree on, written out rather than
/// derived, so a reorder fails here as well as in the assertion block.
#[test]
fn the_annotation_occupies_the_bytes_the_recorded_layout_names() {
    assert_eq!(offset_of!(TapAnnotation, packet_id), 0);
    assert_eq!(offset_of!(TapAnnotation, timestamp), 8);
    assert_eq!(offset_of!(TapAnnotation, interface_id), 16);
    assert_eq!(offset_of!(TapAnnotation, original_len), 20);
    assert_eq!(offset_of!(TapAnnotation, captured_len), 24);
    assert_eq!(offset_of!(TapAnnotation, verdict), 28);
    assert_eq!(offset_of!(TapAnnotation, drop_reason), 32);
    assert_eq!(offset_of!(TapAnnotation, flags), 36);
    assert_eq!(offset_of!(TapAnnotation, generation), 40);
    assert_eq!(offset_of!(TapAnnotation, flow_slot), 44);
    assert_eq!(offset_of!(TapAnnotation, flow_generation), 48);
    assert_eq!(offset_of!(TapAnnotation, classification), 52);
    assert_eq!(offset_of!(TapAnnotation, event), 56);
    assert_eq!(offset_of!(TapAnnotation, flow_state), 60);
    assert_eq!(offset_of!(TapAnnotation, rule), 64);
    assert_eq!(offset_of!(TapAnnotation, _reserved), 68);
    assert_eq!(TAP_RESERVED_WORDS, 3);
    assert_eq!(align_of::<TapAnnotation>(), 8);

    // The atomic image the producer writes is byte-identical to the plain one.
    assert_eq!(offset_of!(TapSlot, packet_id), 0);
    assert_eq!(offset_of!(TapSlot, timestamp), 8);
    assert_eq!(offset_of!(TapSlot, interface_id), 16);
    assert_eq!(offset_of!(TapSlot, original_len), 20);
    assert_eq!(offset_of!(TapSlot, captured_len), 24);
    assert_eq!(offset_of!(TapSlot, verdict), 28);
    assert_eq!(offset_of!(TapSlot, drop_reason), 32);
    assert_eq!(offset_of!(TapSlot, flags), 36);
    assert_eq!(offset_of!(TapSlot, generation), 40);
    assert_eq!(offset_of!(TapSlot, flow_slot), 44);
    assert_eq!(offset_of!(TapSlot, flow_generation), 48);
    assert_eq!(offset_of!(TapSlot, classification), 52);
    assert_eq!(offset_of!(TapSlot, event), 56);
    assert_eq!(offset_of!(TapSlot, flow_state), 60);
    assert_eq!(offset_of!(TapSlot, rule), 64);
    assert_eq!(offset_of!(TapSlot, _reserved), 68);
    assert_eq!(offset_of!(TapSlot, payload), 80);
}

#[test]
fn zeroed_regions_are_an_empty_ring() {
    let records = TapRecords::default();
    let consume = TapConsume::default();
    let reader = consume.reader(&records);
    let writer = records.writer(&consume);
    assert_eq!(records.capacity(), TAP_SLOTS - 1);
    assert_eq!(reader.capacity(), TAP_SLOTS - 1);
    assert_eq!(writer.capacity(), TAP_SLOTS - 1);
    assert!(reader.is_empty());
    assert!(writer.is_empty());
    assert_eq!(reader.len(), 0);
    assert_eq!(writer.len(), 0);
    assert_eq!(writer.dropped(), 0);
    assert_eq!(reader.refused(), 0);
    assert_eq!(reader.dropped_by_writer(), 0);
}

/// A zeroed slot is safe to read and is **refused**: it claims a forwarded frame
/// of no length, and no frame the pipeline reached a verdict on can have one — it
/// parsed as IPv4 over Ethernet, so it carried at least the two headers.
///
/// Refusing it is what keeps a record about no packet from being readable as a
/// record about one, which is the whole of how the revocation record stays honest.
/// The only way to reach a zeroed slot is a forged cursor: both cursors start at
/// zero, so a correct producer never publishes one.
#[test]
fn a_zeroed_slot_is_refused_as_an_observation_of_no_frame() {
    let ring = Ring::zero();
    let mut reader = ring.reader();
    let mut into = buffer();
    ring.records.tail.store(1, Ordering::Release);

    assert_eq!(
        reader.read(&mut into).expect("a slot is published"),
        Err(TapFault::WireLengthMissing {
            verdict: TapVerdict::Forwarded.to_bits(),
        })
    );
    assert_eq!(reader.refused(), 1);
}

/// The slot's own zero state, reached at run time rather than through the
/// `const` block a records region builds its array in.
#[test]
fn an_untouched_slot_holds_a_zeroed_annotation_and_a_zeroed_payload() {
    let slot = TapSlot::zero();
    assert_eq!(
        slot.load(),
        TapAnnotation {
            packet_id: 0,
            timestamp: 0,
            interface_id: 0,
            original_len: 0,
            captured_len: 0,
            verdict: 0,
            drop_reason: 0,
            flags: 0,
            generation: 0,
            flow_slot: 0,
            flow_generation: 0,
            classification: 0,
            event: 0,
            flow_state: 0,
            rule: 0,
            _reserved: [0; TAP_RESERVED_WORDS],
        }
    );
    assert!(
        slot.payload
            .iter()
            .all(|cell| cell.load(Ordering::Relaxed) == 0)
    );
}

#[test]
fn an_empty_ring_reads_nothing() {
    let ring = Ring::zero();
    let mut reader = ring.reader();
    let mut into = buffer();
    assert!(reader.read(&mut into).is_none());
    assert_eq!(reader.drain(TAP_SLOTS, &mut into, |_| ()), 0);
    assert!(reader.is_empty());
}

#[test]
fn every_field_and_every_payload_byte_survives_the_region() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    let bytes = frame(0x5a, 1500);
    let annotation = TapAnnotation::new(
        0xdead_beef_0000_0001,
        0x0123_4567_89ab_cdef,
        (MAX_INTERFACES - 1) as u8,
        TapDecision {
            outcome: TapOutcome::Dropped(TapDropReason::TtlExpired),
            direction: Some(TapDirection::Outbound),
            generation: 42,
            flow: Some(flow(TapClassification::New, TapFlowState::SynSent)),
            rule: TapRule::new(9),
            event: Some(TapEvent::PolicyDenied),
        },
    );
    assert_eq!(writer.write(&annotation, 1500, &bytes), Ok(1500));

    let (checked, payload) = reader
        .read(&mut into)
        .expect("one was written")
        .expect("it is well formed");
    assert_eq!(
        checked,
        CheckedTap {
            packet_id: 0xdead_beef_0000_0001,
            timestamp: 0x0123_4567_89ab_cdef,
            interface_id: (MAX_INTERFACES - 1) as u8,
            original_len: 1500,
            outcome: TapOutcome::Dropped(TapDropReason::TtlExpired),
            direction: Some(TapDirection::Outbound),
            generation: 42,
            flow: Some(flow(TapClassification::New, TapFlowState::SynSent)),
            rule: TapRule::new(9),
            event: Some(TapEvent::PolicyDenied),
        }
    );
    assert_eq!(payload, &bytes[..]);
}

#[test]
fn n_records_round_trip_with_every_payload_byte_preserved() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    let frames: Vec<Vec<u8>> = (0..8u64).map(|n| frame(n, 16 * (n as usize + 1))).collect();

    for (n, bytes) in frames.iter().enumerate() {
        let len = bytes.len() as u32;
        writer
            .write(&tagged(n as u64), len, bytes)
            .expect("the ring is empty");
    }
    for (n, bytes) in frames.iter().enumerate() {
        let (checked, payload) = reader
            .read(&mut into)
            .expect("eight were written")
            .expect("well formed");
        assert_eq!(checked.packet_id, n as u64);
        assert_eq!(checked.original_len, bytes.len() as u32);
        assert_eq!(payload, &bytes[..]);
    }
    assert!(reader.read(&mut into).is_none());
}

#[test]
fn a_frame_longer_than_the_snap_length_is_truncated_and_says_so() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    let jumbo = frame(0x11, 9000);
    assert_eq!(writer.write(&tagged(1), 9000, &jumbo), Ok(TAP_SNAP_LEN));

    let (checked, payload) = reader
        .read(&mut into)
        .expect("one was written")
        .expect("well formed");
    assert_eq!(checked.original_len, 9000, "the wire length is preserved");
    assert_eq!(payload.len(), TAP_SNAP_LEN);
    assert_eq!(payload, &jumbo[..TAP_SNAP_LEN]);
}

/// Exactly at the snap length, which is the boundary the truncation branch
/// turns on.
#[test]
fn a_frame_of_exactly_the_snap_length_crosses_whole() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    let exact = frame(0x22, TAP_SNAP_LEN);
    assert_eq!(
        writer.write(&tagged(1), TAP_SNAP_LEN as u32, &exact),
        Ok(TAP_SNAP_LEN)
    );
    let (_, payload) = reader.read(&mut into).expect("one").expect("well formed");
    assert_eq!(payload, &exact[..]);
}

/// A frame of one byte is the shortest an *observation* may carry, and it crosses
/// whole. Zero is not among them: a wire length of none is what says the record is
/// about no frame at all, which is the revocation's encoding and nothing else.
#[test]
fn the_shortest_frame_crosses_as_its_own_payload() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    assert_eq!(writer.write(&tagged(1), 1, &[0x5a]), Ok(1));
    let (checked, payload) = reader.read(&mut into).expect("one").expect("well formed");
    assert_eq!(checked.original_len, 1);
    assert_eq!(payload, &[0x5a]);
}

/// A first-party inconsistency, refused rather than clamped, and never counted
/// as a drop — nothing well-formed was offered.
#[test]
fn more_bytes_than_the_wire_length_is_refused_and_not_counted() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    assert_eq!(
        writer.write(&tagged(1), 4, &frame(0, 10)),
        Err(TapWriteError::FrameExceedsWireLength {
            frame_len: 10,
            original_len: 4,
        })
    );
    assert_eq!(writer.dropped(), 0, "a malformed call is not a drop");
    assert_eq!(ring.records.dropped.load(Ordering::Relaxed), 0);
    assert!(reader.read(&mut into).is_none(), "nothing was published");
}

/// The overflow policy, stated as behaviour: a full ring keeps what it holds
/// and refuses the newcomer, and never stalls the producer.
#[test]
fn a_full_ring_refuses_the_newest_and_leaves_the_rest_intact() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    let capacity = ring.capacity() as u64;
    for n in 0..capacity {
        writer
            .write(&tagged(n), 8, &frame(n, 8))
            .expect("below capacity");
    }
    assert_eq!(writer.len(), ring.capacity());

    for expected in 1..=3 {
        assert_eq!(
            writer.write(&tagged(999), 8, &frame(999, 8)),
            Err(TapWriteError::Full(TapRingFull { dropped: expected }))
        );
        assert_eq!(writer.dropped(), expected);
    }
    // The count reaches the recorder, which is what `epb_dropcount` carries.
    assert_eq!(reader.dropped_by_writer(), 3);

    // Every record already in the ring is still exactly what was written.
    for n in 0..capacity {
        let (checked, payload) = reader
            .read(&mut into)
            .expect("a full ring")
            .expect("well formed");
        assert_eq!(checked.packet_id, n);
        assert_eq!(payload, &frame(n, 8)[..]);
    }
    assert!(reader.read(&mut into).is_none());
}

#[test]
fn a_refusal_leaves_the_ring_untouched_and_the_producer_resumes() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    let capacity = ring.capacity() as u64;
    for n in 0..capacity {
        writer.write(&tagged(n), 4, &frame(n, 4)).expect("space");
    }
    assert!(writer.write(&tagged(100), 4, &frame(100, 4)).is_err());

    let (checked, _) = reader.read(&mut into).expect("full").expect("well formed");
    assert_eq!(checked.packet_id, 0);
    writer
        .write(&tagged(100), 4, &frame(100, 4))
        .expect("one slot was released");
    assert_eq!(writer.dropped(), 1, "the retry is not a second drop");

    let mut seen = Vec::new();
    reader.drain(TAP_SLOTS, &mut into, |read| {
        if let Ok((checked, _)) = read {
            seen.push(checked.packet_id);
        }
    });
    let mut expected: Vec<u64> = (1..capacity).collect();
    expected.push(100);
    assert_eq!(seen, expected);
}

#[test]
fn wraps_around_the_slot_array_repeatedly_with_the_consumer_keeping_up() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    for n in 0..1000u64 {
        writer
            .write(&tagged(n), 6, &frame(n, 6))
            .expect("one at a time");
        let (checked, payload) = reader
            .read(&mut into)
            .expect("just written")
            .expect("well formed");
        assert_eq!(checked.packet_id, n);
        assert_eq!(payload, &frame(n, 6)[..]);
        assert!(reader.is_empty());
    }
    assert_eq!(writer.dropped(), 0);
}

/// More records than slots with the consumer *lagging*: it takes a whole ring
/// at a time, so the producer wraps between drains.
#[test]
fn wraps_with_a_lagging_consumer_losing_only_what_was_counted() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    let mut offered = 0u64;
    let mut delivered = 0usize;

    for round in 0..5u64 {
        for n in 0..TAP_SLOTS as u64 * 2 {
            let tag = round * 1000 + n;
            offered += 1;
            let _ = writer.write(&tagged(tag), 4, &frame(tag, 4));
        }
        delivered += reader.drain(usize::MAX, &mut into, |read| {
            assert!(read.is_ok(), "the producer kept to the protocol");
        });
    }
    delivered += reader.drain(usize::MAX, &mut into, |_| ());

    assert_eq!(
        delivered as u64 + u64::from(writer.dropped()),
        offered,
        "every observation was either delivered or counted"
    );
}

#[test]
fn drain_stops_at_its_limit_and_at_the_capacity() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    for n in 0..7u64 {
        writer.write(&tagged(n), 2, &frame(n, 2)).expect("space");
    }
    assert_eq!(reader.drain(3, &mut into, |_| ()), 3);
    assert_eq!(reader.len(), 4, "the rest stayed queued");
    assert_eq!(reader.drain(0, &mut into, |_| ()), 0);
    assert_eq!(reader.drain(usize::MAX, &mut into, |_| ()), 4);
    assert_eq!(reader.drain(usize::MAX, &mut into, |_| ()), 0);
}

/// The bounded-work clamp: a caller that asks for everything gets at most the
/// ring, so one drain is finite for any caller and for any peer.
#[test]
fn a_drain_never_exceeds_the_capacity_however_large_the_limit() {
    for limit in [usize::MAX, TAP_SLOTS * 1000, TAP_SLOTS] {
        // A fresh ring each time, because a drain moves the reader's own
        // position: the claim is about one pass, not about a total.
        let ring = Ring::zero();
        let mut reader = ring.reader();
        let mut into = buffer();
        // A cursor that keeps the ring looking non-empty for as long as anyone
        // reads it.
        ring.records.tail.store(u32::MAX, Ordering::Release);
        assert_eq!(reader.drain(limit, &mut into, |_| ()), ring.capacity());
    }
    // And a limit below the capacity is the bound that applies.
    let ring = Ring::zero();
    let mut reader = ring.reader();
    let mut into = buffer();
    ring.records.tail.store(u32::MAX, Ordering::Release);
    assert_eq!(reader.drain(2, &mut into, |_| ()), 2);
}

/// A peer that keeps advancing its published cursor keeps the ring looking
/// non-empty. An unbounded loop over `read` would never return; a drain cannot.
#[test]
fn a_cursor_advancing_during_a_drain_cannot_extend_it() {
    let ring = Ring::zero();
    let mut reader = ring.reader();
    let mut into = buffer();
    for round in 0..20u32 {
        ring.records
            .tail
            .store(round.wrapping_mul(37).wrapping_add(11), Ordering::Release);
        let mut seen = 0usize;
        let taken = reader.drain(usize::MAX, &mut into, |_| {
            seen += 1;
            // The peer advances the cursor mid-drain, exactly as a live
            // forwarder does; the drain's own bound is what stops it.
            ring.records.tail.store(
                round.wrapping_mul(7).wrapping_add(seen as u32),
                Ordering::Release,
            );
        });
        assert!(taken <= ring.capacity(), "the drain did not terminate");
        assert_eq!(taken, seen);
    }
}

// --- hostile producer: one spoiled field at a time -------------------------

#[test]
fn a_captured_length_past_the_snap_length_is_refused() {
    for captured_len in [TAP_SNAP_LEN as u32 + 1, 0x0001_0000, u32::MAX] {
        let raw = TapAnnotation {
            captured_len,
            original_len: u32::MAX,
            ..sound_raw()
        };
        assert_eq!(
            read_forged(&raw),
            Err(TapFault::CapturedLenPastSnap { captured_len })
        );
    }
}

#[test]
fn a_captured_length_past_the_wire_length_is_refused() {
    let raw = TapAnnotation {
        captured_len: 40,
        original_len: 39,
        ..sound_raw()
    };
    assert_eq!(
        read_forged(&raw),
        Err(TapFault::CapturedLenPastOriginal {
            captured_len: 40,
            original_len: 39,
        })
    );
}

#[test]
fn an_interface_outside_the_table_is_refused_whether_or_not_it_is_a_byte() {
    // Not a `u8` at all.
    let raw = TapAnnotation {
        interface_id: 0x0001_0000,
        ..sound_raw()
    };
    assert_eq!(
        read_forged(&raw),
        Err(TapFault::InterfaceUnknown {
            interface_id: 0x0001_0000
        })
    );
    // A `u8` naming no row.
    let raw = TapAnnotation {
        interface_id: MAX_INTERFACES as u32,
        ..sound_raw()
    };
    assert_eq!(
        read_forged(&raw),
        Err(TapFault::InterfaceUnknown {
            interface_id: MAX_INTERFACES as u32
        })
    );
    // The last row that does exist is accepted.
    let raw = TapAnnotation {
        interface_id: MAX_INTERFACES as u32 - 1,
        ..sound_raw()
    };
    assert_eq!(
        read_forged(&raw).map(|checked| checked.interface_id),
        Ok((MAX_INTERFACES - 1) as u8)
    );
}

#[test]
fn a_reserved_word_left_non_zero_is_refused() {
    for index in 0..TAP_RESERVED_WORDS {
        let mut reserved = [0; TAP_RESERVED_WORDS];
        reserved[index] = 1;
        let raw = TapAnnotation {
            _reserved: reserved,
            ..sound_raw()
        };
        assert_eq!(
            read_forged(&raw),
            Err(TapFault::ReservedNonZero { reserved })
        );
    }
}

#[test]
fn a_flags_word_with_an_undefined_bit_is_refused() {
    for flags in [2, 0x8000_0000, u32::MAX] {
        let raw = TapAnnotation {
            flags,
            ..sound_raw()
        };
        assert_eq!(read_forged(&raw), Err(TapFault::FlagsUnknown { flags }));
    }
    // The one bit that is defined decodes.
    let raw = TapAnnotation {
        flags: TAP_FLAG_OUTBOUND,
        ..sound_raw()
    };
    assert_eq!(
        read_forged(&raw).map(|checked| checked.direction),
        Ok(Some(TapDirection::Outbound))
    );
}

#[test]
fn an_unknown_verdict_is_refused() {
    for verdict in [3, u32::MAX] {
        let raw = TapAnnotation {
            verdict,
            ..sound_raw()
        };
        assert_eq!(read_forged(&raw), Err(TapFault::VerdictUnknown { verdict }));
    }
}

#[test]
fn an_unknown_drop_reason_is_refused() {
    for drop_reason in [TAP_DROP_REASON_COUNT + 1, 0x1000, u32::MAX] {
        let raw = TapAnnotation {
            verdict: TapVerdict::Dropped.to_bits(),
            drop_reason,
            ..sound_raw()
        };
        assert_eq!(
            read_forged(&raw),
            Err(TapFault::DropReasonUnknown { drop_reason })
        );
    }
}

/// The two combinations the decoded [`TapOutcome`] makes unrepresentable, which
/// only a peer writing the two words directly can produce.
#[test]
fn a_verdict_and_a_reason_that_disagree_are_refused() {
    let raw = TapAnnotation {
        verdict: TapVerdict::Forwarded.to_bits(),
        drop_reason: TapDropReason::NoRoute.to_bits(),
        ..sound_raw()
    };
    assert_eq!(
        read_forged(&raw),
        Err(TapFault::DropReasonOnForwarded {
            drop_reason: TapDropReason::NoRoute.to_bits()
        })
    );

    let raw = TapAnnotation {
        verdict: TapVerdict::Dropped.to_bits(),
        drop_reason: 0,
        ..sound_raw()
    };
    assert_eq!(read_forged(&raw), Err(TapFault::DropReasonMissingOnDropped));
}

/// Every drop reason survives the region, which is what pins this ABI's
/// encoding to the enum it mirrors.
#[test]
fn every_drop_reason_round_trips_through_the_region() {
    let reasons = [
        TapDropReason::UnconfiguredIngressPort,
        TapDropReason::InterfaceDisabled,
        TapDropReason::NotAddressedToUs,
        TapDropReason::VlanTagged,
        TapDropReason::MartianSource,
        TapDropReason::UnroutableDestination,
        TapDropReason::AddressedToThisRouter,
        TapDropReason::TtlExpired,
        TapDropReason::NoRoute,
        TapDropReason::EgressIsIngress,
        TapDropReason::NoNeighbour,
        TapDropReason::FlowUnsupportedProtocol,
        TapDropReason::FlowFragment,
        TapDropReason::FlowMalformed,
        TapDropReason::FlowInvalidFlags,
        TapDropReason::FlowMidStream,
        TapDropReason::FlowInvalidState,
        TapDropReason::FlowOutOfWindow,
        TapDropReason::FlowNoSuchFlow,
        TapDropReason::FlowQuotedInvalid,
        TapDropReason::FlowUnsupportedIcmp,
        TapDropReason::FlowTableFull,
        TapDropReason::FlowBucketFull,
        TapDropReason::PolicyDenied,
        TapDropReason::NoPolicyMatch,
    ];
    assert_eq!(reasons.len() as u32, TAP_DROP_REASON_COUNT);
    for (index, reason) in reasons.iter().enumerate() {
        assert_eq!(reason.to_bits(), index as u32 + 1);
        assert_eq!(TapDropReason::from_bits(reason.to_bits()), Some(*reason));
        let raw = TapAnnotation {
            verdict: TapVerdict::Dropped.to_bits(),
            drop_reason: reason.to_bits(),
            ..sound_raw()
        };
        assert_eq!(
            read_forged(&raw).map(|checked| checked.outcome),
            Ok(TapOutcome::Dropped(*reason))
        );
    }
    assert_eq!(TapDropReason::from_bits(0), None);
}

/// Every classification, state, event and rule position survives the region,
/// which is what pins this ABI's four decision encodings to the enums they
/// mirror.
#[test]
fn every_decision_value_round_trips_through_the_region() {
    let classifications = [
        TapClassification::New,
        TapClassification::Established,
        TapClassification::Related,
    ];
    assert_eq!(classifications.len() as u32, TAP_CLASSIFICATION_COUNT);
    let states = [
        TapFlowState::SynSent,
        TapFlowState::SynReceived,
        TapFlowState::Established,
        TapFlowState::FinWait,
        TapFlowState::CloseWait,
        TapFlowState::Closing,
        TapFlowState::TimeWait,
        TapFlowState::Closed,
        TapFlowState::UdpUnreplied,
        TapFlowState::UdpAssured,
        TapFlowState::IcmpUnreplied,
        TapFlowState::IcmpReplied,
    ];
    assert_eq!(states.len() as u32, TAP_FLOW_STATE_COUNT);
    for (index, classification) in classifications.iter().enumerate() {
        assert_eq!(classification.to_bits(), index as u32 + 1);
        for (position, state) in states.iter().enumerate() {
            assert_eq!(state.to_bits(), position as u32 + 1);
            let expected = TapFlow {
                slot: 4_321,
                generation: 17,
                classification: Some(*classification),
                state: *state,
            };
            let raw = observed(decision(Some(expected), None, None));
            assert_eq!(
                read_forged(&raw).map(|checked| checked.flow),
                Ok(Some(expected))
            );
        }
    }
    for (index, event) in TapEvent::ALL.iter().enumerate() {
        assert_eq!(event.to_bits(), index as u32 + 1);
        let state = if *event == TapEvent::FlowClosed {
            TapFlowState::TimeWait
        } else {
            TapFlowState::Established
        };
        // The one event that is about no frame takes the revocation's own shape,
        // and it must: every per-frame word is refused on it.
        let raw = if *event == TapEvent::FlowRevoked {
            revocation(state)
        } else {
            observed(decision(
                Some(flow(TapClassification::Established, state)),
                event
                    .names_a_rule()
                    .then(|| TapRule::new(0).expect("a position")),
                Some(*event),
            ))
        };
        assert_eq!(
            read_forged(&raw).map(|checked| checked.event),
            Ok(Some(*event))
        );
    }
    for position in [0, 1, TAP_RULE_COUNT as usize - 1] {
        let rule = TapRule::new(position).expect("a declarable position");
        assert_eq!(usize::from(rule.position()), position);
        let raw = observed(decision(
            Some(flow(TapClassification::New, TapFlowState::SynSent)),
            Some(rule),
            Some(TapEvent::FlowOpened),
        ));
        assert_eq!(
            read_forged(&raw).map(|checked| checked.rule),
            Ok(Some(rule))
        );
    }
}

/// The one record that is about no frame, read back whole — and the four absences
/// that are what make it honest rather than a frame with the fields blanked.
#[test]
fn a_revocation_names_a_flow_and_no_frame() {
    let raw = revocation(TapFlowState::UdpAssured);
    let checked = read_forged(&raw).expect("a revocation is well formed");
    assert_eq!(checked.outcome, TapOutcome::Revoked);
    assert!(!checked.outcome.observes_a_frame());
    assert_eq!(checked.event, Some(TapEvent::FlowRevoked));
    // The conversation it ended, still identifiable: this is what a reader folds
    // the end of a connection onto the record that opened it by.
    assert_eq!(
        checked.flow,
        Some(TapFlow {
            slot: 4_321,
            generation: 17,
            classification: None,
            state: TapFlowState::UdpAssured,
        })
    );
    // And nothing that would claim a packet.
    assert_eq!(checked.original_len, 0);
    assert_eq!(checked.direction, None);
    assert_eq!(checked.rule, None);
}

/// Every per-frame fact a revocation may not carry, broken one at a time; and the
/// two an observation of a frame may not be without.
///
/// This is the pair of laws that keeps the encoding from having two ways to say
/// one thing: without the second half a peer could write a record about no packet
/// under an event that claims one, which is exactly the fabricated cause the
/// frameless record exists to avoid.
#[test]
fn a_record_that_confuses_a_flow_with_a_frame_is_refused() {
    let sound = revocation(TapFlowState::UdpAssured);
    let cases: [(TapAnnotation, TapFault); 6] = [
        (
            TapAnnotation {
                original_len: 60,
                ..sound
            },
            TapFault::WireLengthOnRevocation {
                original_len: 60,
                captured_len: 0,
            },
        ),
        (
            TapAnnotation {
                original_len: 60,
                captured_len: 60,
                ..sound
            },
            TapFault::WireLengthOnRevocation {
                original_len: 60,
                captured_len: 60,
            },
        ),
        (
            TapAnnotation {
                flags: TAP_FLAG_OUTBOUND,
                ..sound
            },
            TapFault::DirectionOnRevocation {
                flags: TAP_FLAG_OUTBOUND,
            },
        ),
        (
            TapAnnotation {
                classification: TapClassification::Established.to_bits(),
                ..sound
            },
            TapFault::ClassificationOnRevocation {
                classification: TapClassification::Established.to_bits(),
            },
        ),
        // The revocation verdict without its event, and the event without its
        // verdict: one fact written twice, so either half alone is refused.
        (
            TapAnnotation {
                event: TapEvent::FlowClosed.to_bits(),
                flow_state: TapFlowState::TimeWait.to_bits(),
                ..sound
            },
            TapFault::RevocationEventMismatch {
                verdict: TapVerdict::Revoked.to_bits(),
                event: TapEvent::FlowClosed.to_bits(),
            },
        ),
        (
            TapAnnotation {
                event: TapEvent::FlowRevoked.to_bits(),
                classification: TapClassification::Established.to_bits(),
                flow_state: TapFlowState::Established.to_bits(),
                ..sound_raw()
            },
            TapFault::RevocationEventMismatch {
                verdict: TapVerdict::Forwarded.to_bits(),
                event: TapEvent::FlowRevoked.to_bits(),
            },
        ),
    ];
    for (raw, expected) in cases {
        assert_eq!(read_forged(&raw), Err(expected), "{raw:?}");
    }
    // And the mirror: an observation of a frame with no wire length and one with
    // no direction, neither of which any frame can be.
    assert_eq!(
        read_forged(&TapAnnotation {
            original_len: 0,
            captured_len: 0,
            ..sound_raw()
        }),
        Err(TapFault::WireLengthMissing {
            verdict: TapVerdict::Forwarded.to_bits(),
        })
    );
    assert_eq!(
        read_forged(&TapAnnotation {
            flags: TAP_FLAGS_KNOWN + 1,
            ..sound_raw()
        }),
        Err(TapFault::FlagsUnknown {
            flags: TAP_FLAGS_KNOWN + 1,
        })
    );
}

/// The relations the six decision words must stand in, each broken on its own.
///
/// These are the refusals that make a log record's promises checkable rather
/// than conventional: a reader that folds events by flow identity, or reads a
/// close for how it closed, is relying on exactly these.
#[test]
fn a_decision_the_appliance_could_not_have_taken_is_refused() {
    let cases: [(TapAnnotation, TapFault); 10] = [
        (
            TapAnnotation {
                classification: TAP_CLASSIFICATION_COUNT + 1,
                flow_state: TapFlowState::SynSent.to_bits(),
                ..sound_raw()
            },
            TapFault::ClassificationUnknown {
                classification: TAP_CLASSIFICATION_COUNT + 1,
            },
        ),
        (
            TapAnnotation {
                classification: TapClassification::New.to_bits(),
                flow_state: TAP_FLOW_STATE_COUNT + 1,
                ..sound_raw()
            },
            TapFault::FlowStateUnknown {
                flow_state: TAP_FLOW_STATE_COUNT + 1,
            },
        ),
        (
            TapAnnotation {
                event: TAP_EVENT_COUNT + 1,
                ..sound_raw()
            },
            TapFault::EventUnknown {
                event: TAP_EVENT_COUNT + 1,
            },
        ),
        (
            TapAnnotation {
                rule: TAP_RULE_COUNT + 1,
                ..sound_raw()
            },
            TapFault::RuleUnknown {
                rule: TAP_RULE_COUNT + 1,
            },
        ),
        // A flow's identity with nothing to say what the frame was to it.
        (
            TapAnnotation {
                flow_slot: 12,
                flow_generation: 5,
                ..sound_raw()
            },
            TapFault::FlowWithoutClassification {
                flow_slot: 12,
                flow_generation: 5,
                flow_state: 0,
            },
        ),
        // A state with no classification, which is the same fault reported
        // against the word that was set.
        (
            TapAnnotation {
                flow_state: TapFlowState::Established.to_bits(),
                ..sound_raw()
            },
            TapFault::FlowWithoutClassification {
                flow_slot: 0,
                flow_generation: 0,
                flow_state: TapFlowState::Established.to_bits(),
            },
        ),
        (
            TapAnnotation {
                classification: TapClassification::Related.to_bits(),
                ..sound_raw()
            },
            TapFault::FlowStateMissingOnClassified {
                classification: TapClassification::Related.to_bits(),
            },
        ),
        (
            TapAnnotation {
                event: TapEvent::FlowAdvanced.to_bits(),
                ..sound_raw()
            },
            TapFault::FlowEventWithoutFlow {
                event: TapEvent::FlowAdvanced.to_bits(),
            },
        ),
        // A close whose state is one a flow leaves, so the record says a
        // conversation ended and does not say how.
        (
            TapAnnotation {
                classification: TapClassification::Established.to_bits(),
                flow_state: TapFlowState::Established.to_bits(),
                event: TapEvent::FlowClosed.to_bits(),
                ..sound_raw()
            },
            TapFault::CloseEventWithoutTerminalState {
                flow_state: TapFlowState::Established.to_bits(),
            },
        ),
        (
            TapAnnotation {
                event: TapEvent::PolicyDenied.to_bits(),
                rule: 0,
                ..sound_raw()
            },
            TapFault::RuleMissingOnFilterDecision {
                event: TapEvent::PolicyDenied.to_bits(),
            },
        ),
    ];
    for (raw, expected) in cases {
        assert_eq!(read_forged(&raw), Err(expected));
    }
}

/// A rule on any decision the filter took no part in, including on no decision
/// at all — the direction that would credit a hit to a rule that never ran.
#[test]
fn a_rule_on_a_decision_the_filter_did_not_take_is_refused() {
    let rule = TapRule::new(3).expect("a declarable position");
    for event in [
        None,
        Some(TapEvent::FlowAdvanced),
        Some(TapEvent::PolicyNoMatch),
    ] {
        let raw = TapAnnotation {
            classification: TapClassification::Established.to_bits(),
            flow_state: TapFlowState::Established.to_bits(),
            event: event.map_or(0, TapEvent::to_bits),
            rule: rule.to_bits(),
            ..sound_raw()
        };
        assert_eq!(
            read_forged(&raw),
            Err(TapFault::RuleOnEventWithoutFilterDecision {
                rule: rule.to_bits(),
                event: event.map_or(0, TapEvent::to_bits),
            })
        );
    }
}

#[test]
fn the_closed_sets_refuse_every_value_outside_them() {
    assert_eq!(TapVerdict::from_bits(0), Some(TapVerdict::Forwarded));
    assert_eq!(TapVerdict::from_bits(1), Some(TapVerdict::Dropped));
    assert_eq!(TapVerdict::from_bits(2), Some(TapVerdict::Revoked));
    assert_eq!(TapVerdict::from_bits(3), None);
    assert_eq!(TapDirection::from_bits(0), Some(TapDirection::Inbound));
    assert_eq!(
        TapDirection::from_bits(TAP_FLAG_OUTBOUND),
        Some(TapDirection::Outbound)
    );
    assert_eq!(TapDirection::from_bits(TAP_FLAGS_KNOWN + 1), None);
    assert_eq!(TapDirection::Outbound.to_bits(), TAP_FLAG_OUTBOUND);
    assert_eq!(TapVerdict::Dropped.to_bits(), 1);
}

/// A refused annotation is counted and the drain carries on, so one poisoned
/// slot does not stop the recorder draining the rest.
#[test]
fn a_refused_annotation_is_counted_and_the_drain_continues() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    writer.write(&tagged(1), 4, &frame(1, 4)).expect("space");
    writer.write(&tagged(2), 4, &frame(2, 4)).expect("space");
    writer.write(&tagged(3), 4, &frame(3, 4)).expect("space");
    // Spoil the middle slot behind the producer's back.
    forge(
        &ring,
        1,
        &TapAnnotation {
            verdict: 0xdead_beef,
            ..sound_raw()
        },
    );

    let mut outcomes = Vec::new();
    assert_eq!(
        reader.drain(TAP_SLOTS, &mut into, |read| {
            outcomes.push(read.map(|(checked, payload)| (checked.packet_id, payload.len())));
        }),
        3
    );
    assert_eq!(outcomes[0], Ok((1, 4)));
    assert_eq!(
        outcomes[1],
        Err(TapFault::VerdictUnknown {
            verdict: 0xdead_beef
        })
    );
    assert_eq!(outcomes[2], Ok((3, 4)));
    assert_eq!(reader.refused(), 1);
}

/// A refused annotation hands the visitor no bytes, so a recorder cannot write
/// a payload it has no valid length for.
#[test]
fn a_refused_annotation_carries_no_payload() {
    let ring = Ring::zero();
    let mut reader = ring.reader();
    let mut into = buffer();
    forge(
        &ring,
        0,
        &TapAnnotation {
            captured_len: u32::MAX,
            ..sound_raw()
        },
    );
    ring.records.tail.store(1, Ordering::Release);
    let mut visited = 0;
    reader.drain(1, &mut into, |read| {
        visited += 1;
        assert!(read.is_err());
    });
    assert_eq!(visited, 1);
}

// --- hostile cursors, both directions --------------------------------------

#[test]
fn a_hostile_cursor_never_indexes_out_of_bounds() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    for (head, tail) in [
        (u32::MAX, u32::MAX),
        (TAP_SLOTS as u32, 0),
        (0, TAP_SLOTS as u32),
        (1_000_000, 999_999),
        (7, 7),
    ] {
        ring.consume.head.store(head, Ordering::Relaxed);
        ring.records.tail.store(tail, Ordering::Relaxed);
        let _ = writer.write(&tagged(1), 4, &frame(1, 4));
        let _ = reader.read(&mut into);
        let (reader_len, writer_len) = (reader.len(), writer.len());
        assert!(reader_len <= reader.capacity());
        assert!(writer_len <= writer.capacity());
        assert_eq!(reader.is_empty(), reader_len == 0);
        assert_eq!(writer.is_empty(), writer_len == 0);
    }
}

/// A forged producer cursor far ahead presents slots that were never published.
/// They are stale or zeroed — in bounds, never out of it.
#[test]
fn a_producer_cursor_far_ahead_stays_within_the_slots() {
    let ring = Ring::zero();
    let mut reader = ring.reader();
    let mut into = buffer();
    ring.records.tail.store(u32::MAX, Ordering::Release);
    let taken = reader.drain(usize::MAX, &mut into, |read| {
        if let Ok((_, payload)) = read {
            assert!(payload.len() <= TAP_SNAP_LEN);
        }
    });
    assert_eq!(taken, ring.capacity());
    assert!(reader.len() <= reader.capacity());
}

/// The recorder's position is private, so a consume cursor rewound by anything
/// at all cannot make an already-recorded observation come back.
#[test]
fn a_rewound_consume_cursor_never_redelivers() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut into = buffer();
    for n in 0..4u64 {
        writer.write(&tagged(n), 4, &frame(n, 4)).expect("space");
    }
    for expected in 0..4u64 {
        ring.consume.head.store(0, Ordering::Relaxed);
        let (checked, _) = reader
            .read(&mut into)
            .expect("four were written")
            .expect("well formed");
        assert_eq!(checked.packet_id, expected);
    }
    assert!(reader.read(&mut into).is_none());
}

/// A forged consumer cursor ahead of the producer stalls the producer or lets
/// it reuse a slot. Either way it is the recorder harming its own records.
#[test]
fn a_consume_cursor_ahead_of_the_producer_only_costs_the_recorder() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let offered = 40u64;
    let mut written = 0u64;
    for n in 0..offered {
        ring.consume
            .head
            .store(n.wrapping_mul(13) as u32, Ordering::Relaxed);
        if writer.write(&tagged(n), 4, &frame(n, 4)).is_ok() {
            written += 1;
        }
        assert!(writer.len() <= writer.capacity());
    }
    assert_eq!(
        written + u64::from(writer.dropped()),
        offered,
        "every observation either landed or was counted"
    );
}

// --- neither side writes the other's region --------------------------------

/// Every word of a records region, for a comparison a store into any slot or
/// either header word would fail. Field by field rather than as bytes, so it
/// needs no `unsafe`.
fn records_image(records: &TapRecords) -> (u32, u32, Vec<(TapAnnotation, Vec<u8>)>) {
    (
        records.tail.load(Ordering::Relaxed),
        records.dropped.load(Ordering::Relaxed),
        (0..TAP_SLOTS as u32)
            .map(|index| {
                let slot = records.slot(index);
                (
                    slot.load(),
                    slot.payload
                        .iter()
                        .map(|cell| cell.load(Ordering::Relaxed))
                        .collect(),
                )
            })
            .collect(),
    )
}

#[test]
fn the_writer_never_writes_the_consume_region() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    // A value no correct recorder would publish, so a stray store of a
    // plausible cursor would still show up here.
    const FORGED: u32 = 0xa5a5_1234;
    ring.consume.head.store(FORGED, Ordering::Relaxed);

    for n in 0..(TAP_SLOTS as u64 * 4) {
        let _ = writer.write(&tagged(n), 4, &frame(n, 4));
        let _ = writer.len();
        let _ = writer.is_empty();
        let _ = writer.dropped();
        assert_eq!(
            ring.consume.head.load(Ordering::Relaxed),
            FORGED,
            "the producer stored into the recorder's region"
        );
    }
}

#[test]
fn the_reader_never_writes_the_records_region() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut into = buffer();
    for n in 0..12u64 {
        writer.write(&tagged(n), 9, &frame(n, 9)).expect("space");
    }
    // A drop count the recorder would have every incentive to erase.
    ring.records.dropped.store(77, Ordering::Relaxed);
    let before = records_image(&ring.records);

    let mut reader = ring.reader();
    for _ in 0..4 {
        assert!(reader.drain(usize::MAX, &mut into, |_| ()) <= ring.capacity());
        let _ = reader.len();
        let _ = reader.is_empty();
        let _ = reader.dropped_by_writer();
        let _ = reader.refused();
    }
    assert_eq!(
        records_image(&ring.records),
        before,
        "the recorder stored into the forwarder's region"
    );
    assert_eq!(ring.records.dropped.load(Ordering::Relaxed), 77);
}

// --- concurrency -----------------------------------------------------------

#[test]
fn a_producing_and_a_draining_thread_transfer_every_record_in_order() {
    const COUNT: u64 = 20_000;
    let ring = Ring::zero();

    thread::scope(|scope| {
        scope.spawn(|| {
            let mut writer = ring.writer();
            let mut n = 0;
            while n < COUNT {
                if writer.write(&tagged(n), 12, &frame(n, 12)).is_ok() {
                    n += 1;
                } else {
                    std::hint::spin_loop();
                }
            }
        });
        scope.spawn(|| {
            let mut reader = ring.reader();
            let mut into = buffer();
            let mut expected = 0;
            while expected < COUNT {
                match reader.read(&mut into) {
                    Some(read) => {
                        let (checked, payload) = read.expect("the producer is correct");
                        assert_eq!(checked.packet_id, expected);
                        assert_eq!(payload, &frame(expected, 12)[..]);
                        expected += 1;
                    }
                    None => std::hint::spin_loop(),
                }
            }
            assert_eq!(reader.refused(), 0);
        });
    });
}

#[test]
fn a_thread_scribbling_both_regions_cannot_break_either_side() {
    const ROUNDS: u64 = 5_000;
    let ring = Ring::zero();
    let stop = AtomicBool::new(false);

    thread::scope(|scope| {
        let producer = scope.spawn(|| {
            let mut writer = ring.writer();
            for n in 0..ROUNDS {
                let _ = writer.write(&tagged(n), 64, &frame(n, 64));
                assert!(writer.len() <= writer.capacity());
            }
        });
        let recorder = scope.spawn(|| {
            let mut reader = ring.reader();
            let mut into = buffer();
            let mut seen = 0usize;
            for _ in 0..ROUNDS {
                seen += reader.drain(4, &mut into, |read| {
                    if let Ok((checked, payload)) = read {
                        assert!(payload.len() <= usize::try_from(checked.original_len).unwrap());
                        assert!(usize::from(checked.interface_id) < MAX_INTERFACES);
                    }
                });
                assert!(reader.len() <= reader.capacity());
            }
            assert!(seen <= 4 * ROUNDS as usize);
        });
        let scribbler = scope.spawn(|| {
            let mut seed = 0x1234_5678u32;
            while !stop.load(Ordering::Relaxed) {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                // Both regions at once: on a booted node no single domain may
                // write both, so this is a strictly stronger adversary than
                // either mapping permits.
                ring.consume.head.store(seed, Ordering::Relaxed);
                ring.records
                    .tail
                    .store(seed.rotate_left(13), Ordering::Relaxed);
                ring.records
                    .dropped
                    .store(seed.rotate_left(7), Ordering::Relaxed);
                let slot = ring.records.slot(seed);
                slot.captured_len.store(seed, Ordering::Relaxed);
                slot.original_len
                    .store(seed.rotate_left(3), Ordering::Relaxed);
                slot.interface_id
                    .store(seed.rotate_left(5), Ordering::Relaxed);
                slot.verdict.store(seed.rotate_left(11), Ordering::Relaxed);
                slot.drop_reason
                    .store(seed.rotate_left(17), Ordering::Relaxed);
                slot.flags.store(seed.rotate_left(23), Ordering::Relaxed);
            }
        });

        producer.join().expect("the producer did not panic");
        recorder.join().expect("the recorder did not panic");
        stop.store(true, Ordering::Relaxed);
        scribbler.join().expect("the scribbler did not panic");
    });
}

// --- properties ------------------------------------------------------------

/// The `u32` words of [`TapAnnotation`] the byzantine-producer property drives,
/// which is every field but the two `u64`s and the reserved array.
const ANNOTATION_WORDS: usize = 13;

/// Everything a checked observation is allowed to be, restated here rather than
/// reached through the decode, so the property pins what is yielded and not
/// merely that something was.
fn assert_yield_is_recordable(checked: &CheckedTap, payload: &[u8]) -> Result<(), TestCaseError> {
    prop_assert!(usize::from(checked.interface_id) < MAX_INTERFACES);
    prop_assert!(payload.len() <= TAP_SNAP_LEN);
    prop_assert!(
        u64::try_from(payload.len()).expect("a length fits") <= u64::from(checked.original_len)
    );
    match checked.outcome {
        TapOutcome::Forwarded | TapOutcome::Revoked => {}
        TapOutcome::Dropped(reason) => {
            prop_assert!(reason.to_bits() >= 1);
            prop_assert!(reason.to_bits() <= TAP_DROP_REASON_COUNT);
        }
    }
    // Every relation the decision words must stand in, so the property pins the
    // coherence a reader of the recording relies on and not merely that four
    // more words decoded.
    if let Some(flow) = checked.flow {
        // A classification exactly where the record is about a frame: the one
        // that is not carries a flow and no packet.
        prop_assert_eq!(
            flow.classification.is_some(),
            checked.outcome.observes_a_frame()
        );
        if let Some(classification) = flow.classification {
            prop_assert!(classification.to_bits() >= 1);
            prop_assert!(classification.to_bits() <= TAP_CLASSIFICATION_COUNT);
        }
        prop_assert!(flow.state.to_bits() >= 1);
        prop_assert!(flow.state.to_bits() <= TAP_FLOW_STATE_COUNT);
    }
    // And the four facts a record about no frame may not carry, on the same terms.
    prop_assert_eq!(
        checked.direction.is_some(),
        checked.outcome.observes_a_frame()
    );
    if !checked.outcome.observes_a_frame() {
        prop_assert_eq!(checked.original_len, 0);
        prop_assert_eq!(checked.rule, None);
        prop_assert_eq!(checked.event, Some(TapEvent::FlowRevoked));
    }
    if let Some(rule) = checked.rule {
        prop_assert!(u32::from(rule.position()) < TAP_RULE_COUNT);
    }
    match checked.event {
        None => prop_assert!(checked.rule.is_none()),
        Some(event) => {
            prop_assert!(event.to_bits() >= 1);
            prop_assert!(event.to_bits() <= TAP_EVENT_COUNT);
            prop_assert_eq!(event.names_a_rule(), checked.rule.is_some());
            if event.names_a_flow() {
                prop_assert!(checked.flow.is_some());
            }
            if event == TapEvent::FlowClosed {
                prop_assert!(checked.flow.is_some_and(|flow| flow.state.is_terminal()));
            }
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The headline byzantine-producer property: every annotation word and the
    /// producer cursor is a value the forwarder chose, including values no
    /// correct forwarder produces. The recorder must return, must not be made
    /// to read more than the ring holds, and must yield no slice outside the
    /// buffer it was given.
    #[test]
    fn an_arbitrary_records_region_is_drained_safely(
        annotations in proptest::collection::vec(
            (any::<u64>(), any::<u64>(), any::<[u32; ANNOTATION_WORDS]>(),
             any::<[u32; TAP_RESERVED_WORDS]>()),
            1..=8,
        ),
        tails in proptest::collection::vec(any::<u32>(), 1..=8),
        limit in prop_oneof![Just(usize::MAX), 0usize..=200],
    ) {
        let ring = Ring::zero();
        let mut reader = ring.reader();
        let mut into = buffer();

        for (index, words) in annotations.iter().enumerate() {
            let (packet_id, timestamp, [interface_id, original_len, captured_len,
                 verdict, drop_reason, flags, generation, flow_slot, flow_generation,
                 classification, event, flow_state, rule], reserved) = *words;
            forge(&ring, index as u32, &TapAnnotation {
                packet_id, timestamp, interface_id, original_len, captured_len,
                verdict, drop_reason, flags, generation, flow_slot, flow_generation,
                classification, event, flow_state, rule, _reserved: reserved,
            });
        }

        let mut total = 0usize;
        for tail in tails {
            ring.records.tail.store(tail, Ordering::Release);

            let mut yielded = 0usize;
            let mut failed: Option<TestCaseError> = None;
            let taken = reader.drain(limit, &mut into, |read| {
                yielded += 1;
                if let Ok((checked, payload)) = read
                    && failed.is_none()
                    && let Err(error) = assert_yield_is_recordable(&checked, payload) {
                    failed = Some(error);
                }
            });
            if let Some(error) = failed {
                return Err(error);
            }
            // Terminates, and never more than the ring can hold in one pass.
            prop_assert_eq!(taken, yielded);
            prop_assert!(taken <= reader.capacity());
            prop_assert!(taken <= limit);
            total += taken;

            let reader_len = reader.len();
            prop_assert!(reader_len <= reader.capacity());
            prop_assert_eq!(reader.is_empty(), reader_len == 0);
            // The producer's claim about its own drops is exposed, never
            // trusted: whatever it says, it has bounded nothing above.
            let _ = reader.dropped_by_writer();
        }
        prop_assert!(reader.refused() as usize <= total);
    }

    /// The same, over the consume region and independently of the first: the
    /// recorder's cursor is arbitrary while the forwarder's own half is well
    /// formed. Nothing published there may lose an observation that was neither
    /// recorded nor counted.
    #[test]
    fn an_arbitrary_consume_region_leaves_the_producer_bounded(
        heads in proptest::collection::vec(any::<u32>(), 1..=32),
        payload_len in 0usize..=(TAP_SNAP_LEN + 64),
    ) {
        let ring = Ring::zero();
        let mut writer = ring.writer();
        let offered = heads.len();
        let bytes = frame(1, payload_len);
        let original_len = u32::try_from(payload_len).expect("a test length fits");
        let mut written = 0usize;
        let mut refused = 0u32;

        for (index, head) in heads.into_iter().enumerate() {
            ring.consume.head.store(head, Ordering::Relaxed);
            match writer.write(&tagged(index as u64), original_len, &bytes) {
                Ok(captured) => {
                    written += 1;
                    prop_assert!(captured <= TAP_SNAP_LEN);
                    prop_assert!(captured <= payload_len);
                }
                Err(TapWriteError::Full(full)) => {
                    refused += 1;
                    prop_assert_eq!(full.dropped, refused);
                }
                Err(other) => prop_assert!(false, "a well-formed call was refused: {:?}", other),
            }
            prop_assert_eq!(writer.dropped(), refused);
            let writer_len = writer.len();
            prop_assert!(writer_len <= writer.capacity());
            prop_assert_eq!(writer.is_empty(), writer_len == 0);
        }
        // Every observation offered either landed or was counted; a forged
        // cursor cannot make one disappear unaccounted for.
        prop_assert_eq!(written + usize::try_from(refused).expect("a count fits"), offered);
    }

    /// Interleaved writing and reading against a correct peer: the drop count
    /// plus the delivered count equals the offered count, and every payload
    /// delivered is exactly the one written under that `packet_id`.
    #[test]
    fn every_offered_observation_is_delivered_or_counted(
        // A frame of at least one byte, because zero is what says a record is
        // about no frame — action 1 offers those, so both record kinds cross.
        steps in proptest::collection::vec((0u8..=4, 1usize..=64), 1..=400),
    ) {
        let ring = Ring::zero();
        let mut writer = ring.writer();
        let mut reader = ring.reader();
        let mut into = buffer();
        let mut offered = 0u64;
        let mut delivered = 0u64;
        let mut next_tag = 0u64;

        for (action, size) in steps {
            if action == 0 {
                let bytes = frame(next_tag, size);
                let len = u32::try_from(size).expect("a test length fits");
                offered += 1;
                // A refused observation is never retried under the same tag
                // either way, so the sequence the reader sees stays a prefix.
                let _ = writer.write(&tagged(next_tag), len, &bytes);
                next_tag += 1;
            } else if action == 1 {
                offered += 1;
                let mut annotation = revocation(TapFlowState::UdpAssured);
                annotation.packet_id = next_tag;
                let _ = writer.write(&annotation, 0, &[]);
                next_tag += 1;
            } else {
                let mut error: Option<TestCaseError> = None;
                delivered += reader.drain(size, &mut into, |read| {
                    match read {
                        Ok((checked, payload)) => {
                            let expected = frame(checked.packet_id, payload.len());
                            if payload != &expected[..] && error.is_none() {
                                error = Some(TestCaseError::fail("a payload was not the one written"));
                            }
                        }
                        Err(fault) => if error.is_none() {
                            error = Some(TestCaseError::fail(format!("a correct producer was refused: {fault:?}")));
                        }
                    }
                }) as u64;
                if let Some(error) = error {
                    return Err(error);
                }
            }
        }
        delivered += reader.drain(usize::MAX, &mut into, |_| ()) as u64;

        prop_assert_eq!(delivered + u64::from(writer.dropped()), offered);
    }

    /// Both regions hostile at once, which is the only shape that covers a
    /// forwarder and a recorder compromised together. Bounded and panic-free is
    /// all either side may claim under it.
    #[test]
    fn both_regions_arbitrary_together_stay_bounded_and_panic_free(
        cursors in proptest::collection::vec((any::<u32>(), any::<u32>()), 1..=16),
        captured in any::<u32>(),
    ) {
        let ring = Ring::zero();
        let mut writer = ring.writer();
        let mut reader = ring.reader();
        let mut into = buffer();
        for index in 0..TAP_SLOTS as u32 {
            ring.records.slot(index).captured_len.store(captured, Ordering::Relaxed);
        }

        for (head, tail) in cursors {
            ring.consume.head.store(head, Ordering::Relaxed);
            ring.records.tail.store(tail, Ordering::Relaxed);
            let _ = writer.write(&tagged(1), 4, &frame(1, 4));
            let taken = reader.drain(usize::MAX, &mut into, |read| {
                if let Ok((_, payload)) = read {
                    assert!(payload.len() <= TAP_SNAP_LEN);
                }
            });
            prop_assert!(taken <= reader.capacity());
            prop_assert!(writer.len() <= writer.capacity());
            prop_assert!(reader.len() <= reader.capacity());
        }
    }
}
