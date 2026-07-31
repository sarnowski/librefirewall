use super::*;
use crate::log_record::{
    CheckedBody, CheckedDetail, CheckedStamp, CheckedValue, LOG_CHANGE_KIND_COUNT,
    LOG_DOMAIN_COUNT, LOG_DOMAIN_STATE_COUNT, LOG_FIELD_COUNT, LOG_GENERATION_OUTCOME_COUNT,
    LOG_OBJECT_KIND_COUNT, LOG_REJECT_REASON_COUNT, LogDetailKind, LogKind,
};
use core::mem::offset_of;
use proptest::prelude::*;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::vec::Vec;

/// The whole record as bytes; see the record module's tests for why every bit
/// pattern is one.
const RECORD_BYTES: usize = size_of::<LogRecord>();

fn record_from_bytes(bytes: [u8; RECORD_BYTES]) -> LogRecord {
    // SAFETY: `LogRecord` is `#[repr(C)]`, `Copy`, and asserted in
    // `log_record.rs` to be exactly the sum of its fields' sizes, so it has no
    // padding and every byte belongs to an integer field that admits any bit
    // pattern.
    unsafe { core::mem::transmute(bytes) }
}

/// The two regions one ring is, held together for a test that drives both ends.
struct Ring {
    records: LogRecords,
    consume: LogConsume,
}

impl Ring {
    fn zero() -> Self {
        Self {
            records: LogRecords::zero(),
            consume: LogConsume::zero(),
        }
    }

    fn writer(&self) -> LogWriter<'_> {
        self.records.writer(&self.consume)
    }

    fn reader(&self) -> LogReader<'_> {
        self.consume.reader(&self.records)
    }

    fn capacity(&self) -> usize {
        self.records.capacity()
    }
}

/// A record identifiable on the way out by the generation it names.
fn tagged(generation: u32) -> LogRecord {
    LogRecord {
        kind: LogKind::ConfigGeneration.to_bits(),
        generation,
        ..LogRecord::ZERO
    }
}

fn is_tagged(record: &Result<CheckedRecord, LogRecordError>, generation: u32) -> bool {
    matches!(
        record,
        Ok(CheckedRecord {
            body: CheckedBody::ConfigGeneration { generation: read, .. },
            ..
        }) if *read == generation
    )
}

fn generation_of(record: &Result<CheckedRecord, LogRecordError>) -> Option<u32> {
    match record {
        Ok(CheckedRecord {
            body: CheckedBody::ConfigGeneration { generation, .. },
            ..
        }) => Some(*generation),
        _ => None,
    }
}

#[test]
fn the_regions_the_system_description_reserves_are_the_recorded_ones() {
    assert_eq!(LOG_RING_SLOTS, 64);
    assert_eq!(size_of::<LogRecord>(), 232);
    assert_eq!(size_of::<LogRecords>(), 8 + 64 * 232);
    assert_eq!(size_of::<LogRecords>(), 14_856);
    assert_eq!(LOG_RECORDS_REGION_SIZE, 0x4000);
    assert!(LOG_RECORDS_REGION_SIZE >= size_of::<LogRecords>());
    assert!(LOG_RECORDS_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert_eq!(offset_of!(LogRecords, slots), 8);

    assert_eq!(size_of::<LogConsume>(), 4);
    assert_eq!(LOG_CONSUME_REGION_SIZE, 0x1000);
    assert!(LOG_CONSUME_REGION_SIZE >= size_of::<LogConsume>());
    assert!(LOG_CONSUME_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert_eq!(offset_of!(LogConsume, head), 0);
}

#[test]
fn zeroed_regions_are_an_empty_ring_holding_zeroed_records() {
    let records = LogRecords::default();
    let consume = LogConsume::default();
    let reader = consume.reader(&records);
    let writer = records.writer(&consume);
    assert_eq!(records.capacity(), LOG_RING_SLOTS - 1);
    assert_eq!(reader.capacity(), LOG_RING_SLOTS - 1);
    assert_eq!(writer.capacity(), LOG_RING_SLOTS - 1);
    assert!(reader.is_empty());
    assert!(writer.is_empty());
    assert_eq!(reader.len(), 0);
    assert_eq!(writer.dropped(), 0);
    assert_eq!(reader.undecodable(), 0);
    assert_eq!(reader.dropped_by_writer(), 0);
    assert_eq!(records.slot(0).load(), LogRecord::ZERO);
}

#[test]
fn empty_ring_reads_nothing() {
    let ring = Ring::zero();
    let mut reader = ring.reader();
    assert!(reader.read().is_none());
    assert_eq!(reader.drain(LOG_RING_SLOTS).count(), 0);
    assert!(reader.is_empty());
}

#[test]
fn records_come_back_in_the_order_they_were_written() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    for n in 0..5 {
        writer.write(&tagged(n)).expect("the ring is empty");
    }
    assert_eq!(writer.len(), 5);
    assert_eq!(reader.len(), 5);
    for n in 0..5 {
        assert!(is_tagged(&reader.read().expect("five were written"), n));
    }
    assert!(reader.is_empty());
    assert!(reader.read().is_none());
}

#[test]
fn a_record_survives_the_region_field_for_field() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let mut record = LogRecord {
        kind: LogKind::Domain.to_bits(),
        domain: 2,
        state: 3,
        detail: LogDetailKind::Refusal.to_bits(),
        operands: [0x1af4, 0x1000],
        operand_count: 2,
        signalled: 1,
        ..LogRecord::ZERO
    };
    record.cause.bytes[..14].copy_from_slice(b"not-virtio-net");
    record.cause.len = 14;
    writer.write(&record).expect("the ring is empty");

    let Some(Ok(CheckedRecord {
        body:
            CheckedBody::Domain {
                domain,
                state,
                detail: CheckedDetail::Refusal { cause, .. },
            },
        ..
    })) = reader.read()
    else {
        panic!("the record crossed intact");
    };
    assert_eq!((domain, state), (2, 3));
    assert_eq!(cause.as_str(), "not-virtio-net");
}

#[test]
fn fills_to_capacity_then_refuses_and_counts() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let reader = ring.reader();
    for n in 0..ring.capacity() as u32 {
        writer.write(&tagged(n)).expect("below capacity");
    }
    assert_eq!(writer.len(), ring.capacity());
    for expected in 1..=3 {
        assert_eq!(
            writer.write(&tagged(999)),
            Err(LogRingFull { dropped: expected })
        );
        assert_eq!(writer.dropped(), expected);
    }
    // The count reaches the console side, which is what makes a partial
    // transcript recognisable as one.
    assert_eq!(reader.dropped_by_writer(), 3);
}

/// The overflow policy, stated as behaviour: a full ring keeps the records that
/// were already in it and refuses the newcomer. On a boot transcript those are
/// the earliest records, which are the ones that say why a domain parked.
#[test]
fn a_full_ring_keeps_the_oldest_records_and_refuses_the_newest() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let capacity = ring.capacity() as u32;
    for n in 0..capacity {
        writer.write(&tagged(n)).expect("below capacity");
    }
    for n in capacity..capacity + 10 {
        assert!(writer.write(&tagged(n)).is_err());
    }
    assert_eq!(writer.dropped(), 10);

    let read: Vec<u32> = reader
        .drain(LOG_RING_SLOTS)
        .filter_map(|body| generation_of(&body))
        .collect();
    assert_eq!(read, (0..capacity).collect::<Vec<u32>>());
}

/// A refused record leaves the ring exactly as it was, so a writer that is
/// blocked and then unblocked resumes without a gap or a duplicate.
#[test]
fn a_refusal_leaves_the_ring_untouched_and_the_writer_resumes_after_a_drain() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let capacity = ring.capacity() as u32;
    for n in 0..capacity {
        writer.write(&tagged(n)).expect("below capacity");
    }
    assert!(writer.write(&tagged(100)).is_err());
    assert!(is_tagged(&reader.read().expect("the ring is full"), 0));
    writer.write(&tagged(100)).expect("one slot was released");
    assert_eq!(writer.dropped(), 1, "the retry is not a second drop");

    let read: Vec<u32> = reader
        .drain(LOG_RING_SLOTS)
        .filter_map(|body| generation_of(&body))
        .collect();
    let mut expected: Vec<u32> = (1..capacity).collect();
    expected.push(100);
    assert_eq!(read, expected);
}

#[test]
fn wraps_around_the_slot_array_repeatedly() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    for n in 0..1000 {
        writer.write(&tagged(n)).expect("one at a time");
        assert!(is_tagged(&reader.read().expect("just written"), n));
        assert!(reader.is_empty());
    }
    assert_eq!(writer.dropped(), 0);
}

#[test]
fn full_empty_transitions_hold_across_wrap() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    let capacity = ring.capacity() as u32;
    for round in 0..10 {
        for n in 0..capacity {
            writer.write(&tagged(round * capacity + n)).expect("space");
        }
        assert!(writer.write(&tagged(0)).is_err());
        assert_eq!(writer.len(), ring.capacity());
        assert_eq!(reader.len(), ring.capacity());
        for n in 0..capacity {
            assert!(is_tagged(
                &reader.read().expect("a full ring"),
                round * capacity + n
            ));
        }
        assert!(reader.read().is_none());
    }
}

#[test]
fn drain_stops_at_its_limit_and_reports_its_bound() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    for n in 0..7 {
        writer.write(&tagged(n)).expect("space");
    }
    let mut drain = reader.drain(3);
    assert_eq!(drain.size_hint(), (0, Some(3)));
    assert!(is_tagged(&drain.next().expect("three"), 0));
    assert_eq!(drain.size_hint(), (0, Some(2)));
    assert_eq!(drain.count(), 2);
    assert_eq!(reader.len(), 4, "the rest stayed queued");
    assert_eq!(reader.drain(0).count(), 0);
    assert_eq!(reader.drain(LOG_RING_SLOTS).count(), 4);
}

/// The ENG-4 clamp: a caller that asks for everything gets at most the ring,
/// so one drain is finite for any caller and for any peer.
#[test]
fn a_drain_never_exceeds_the_capacity_const_however_large_the_limit() {
    let ring = Ring::zero();
    let mut reader = ring.reader();
    for limit in [usize::MAX, LOG_RING_SLOTS * 1000, LOG_RING_SLOTS] {
        assert_eq!(reader.drain(limit).size_hint(), (0, Some(ring.capacity())));
    }
    assert_eq!(reader.drain(2).size_hint(), (0, Some(2)));
}

#[test]
fn an_undecodable_record_is_counted_and_the_drain_carries_on() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    writer.write(&tagged(1)).expect("space");
    writer
        .write(&LogRecord {
            kind: 0xdead_beef,
            ..LogRecord::ZERO
        })
        .expect("space");
    writer.write(&tagged(2)).expect("space");

    let read: Vec<Result<CheckedRecord, LogRecordError>> = reader.drain(LOG_RING_SLOTS).collect();
    assert_eq!(read.len(), 3);
    assert!(is_tagged(&read[0], 1));
    assert_eq!(
        read[1],
        Err(LogRecordError::KindUnknown { kind: 0xdead_beef })
    );
    assert!(is_tagged(&read[2], 2));
    assert_eq!(reader.undecodable(), 1);
}

#[test]
fn a_hostile_cursor_never_indexes_out_of_bounds() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    for (head, tail) in [
        (u32::MAX, u32::MAX),
        (LOG_RING_SLOTS as u32, 0),
        (0, LOG_RING_SLOTS as u32),
        (1_000_000, 999_999),
        (7, 7),
    ] {
        ring.consume.head.store(head, Ordering::Relaxed);
        ring.records.tail.store(tail, Ordering::Relaxed);
        let _ = writer.write(&tagged(1));
        let _ = reader.read();
        let (reader_len, writer_len) = (reader.len(), writer.len());
        assert!(reader_len <= reader.capacity());
        assert!(writer_len <= writer.capacity());
        assert_eq!(reader.is_empty(), reader_len == 0);
        assert_eq!(writer.is_empty(), writer_len == 0);
    }
}

/// The reader's position is private, so a console cursor rewound by anything at
/// all cannot make an already-rendered record come back and be printed twice.
#[test]
fn a_rewound_consume_cursor_never_redelivers() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    for n in 0..4 {
        writer.write(&tagged(n)).expect("space");
    }
    assert!(is_tagged(&reader.read().expect("four"), 0));
    ring.consume.head.store(0, Ordering::Relaxed);
    assert!(is_tagged(&reader.read().expect("four"), 1));
    ring.consume.head.store(0, Ordering::Relaxed);
    assert!(is_tagged(&reader.read().expect("four"), 2));
    assert!(is_tagged(&reader.read().expect("four"), 3));
    assert!(reader.read().is_none());
}

/// A tail behind the reader's own position: the emptiness test stays false
/// while the position walks round, so slots are presented a second time. The
/// walk stays in bounds and terminates, which is what this layer guarantees —
/// a duplicated console line is a rendering fault, not a memory-safety one.
#[test]
fn a_tail_behind_the_readers_position_redelivers_but_stays_bounded() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    for n in 0..3 {
        writer.write(&tagged(n)).expect("space");
    }
    assert_eq!(reader.drain(LOG_RING_SLOTS).count(), 3);
    assert!(reader.read().is_none(), "the ring is drained");

    ring.records.tail.store(2, Ordering::Relaxed);
    let read = reader.drain(LOG_RING_SLOTS).count();
    assert!(read <= ring.capacity());
    assert!(reader.read().is_none(), "the walk met the forged cursor");
}

/// A peer that keeps advancing its published cursor keeps the ring looking
/// non-empty. An unbounded loop over `read` would never return; a drain cannot.
#[test]
fn a_cursor_advancing_during_a_drain_cannot_extend_it() {
    let ring = Ring::zero();
    let mut reader = ring.reader();
    for round in 0..20u32 {
        ring.records
            .tail
            .store(round.wrapping_mul(37).wrapping_add(11), Ordering::Relaxed);
        let mut drain = reader.drain(LOG_RING_SLOTS);
        let mut seen = 0usize;
        while drain.next().is_some() {
            // The peer advances the cursor mid-drain, exactly as a live writing
            // domain does; the drain's own bound is what stops it.
            ring.records.tail.store(
                round.wrapping_mul(7).wrapping_add(seen as u32),
                Ordering::Relaxed,
            );
            seen += 1;
            assert!(seen <= LOG_RING_SLOTS, "the drain did not terminate");
        }
        assert!(seen <= ring.capacity());
    }
}

/// A writing domain that crashes and restarts re-zeroes its own region while
/// records are in flight. Both positions are private, so the console carries on
/// from where it was rather than replaying the transcript.
#[test]
fn a_writer_restart_mid_stream_does_not_replay_the_transcript() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    let mut reader = ring.reader();
    for n in 0..5 {
        writer.write(&tagged(n)).expect("space");
    }
    assert!(is_tagged(&reader.read().expect("five"), 0));
    assert!(is_tagged(&reader.read().expect("five"), 1));

    ring.records.tail.store(0, Ordering::Relaxed);
    ring.records.dropped.store(0, Ordering::Relaxed);

    let next = reader.drain(ring.capacity()).next().expect("more queued");
    assert!(is_tagged(&next, 2), "not a record already rendered");
    assert!(reader.len() <= reader.capacity());
    assert!(writer.write(&tagged(99)).is_ok());
}

/// The property the split exists to create, from the writer's side: a writing
/// domain drives its half through every state it has — filling, refusing,
/// wrapping, resuming — and the consume region is byte for byte what it was.
/// The type is what makes it so, and this is the check that the type was not
/// worked around: `LogWriter` holds the console's region only as a
/// `PeerConsume`, which carries no store.
#[test]
fn the_writer_never_writes_the_consume_region() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    // A value no correct console would publish, so a stray store of a plausible
    // cursor would still show up here.
    const FORGED: u32 = 0xa5a5_1234;
    ring.consume.head.store(FORGED, Ordering::Relaxed);

    for n in 0..(LOG_RING_SLOTS as u32 * 4) {
        let _ = writer.write(&tagged(n));
        let _ = writer.len();
        let _ = writer.is_empty();
        let _ = writer.dropped();
        assert_eq!(
            ring.consume.head.load(Ordering::Relaxed),
            FORGED,
            "the writer stored into the console's region"
        );
    }
}

/// The mirror property, from the console's side: a full drain over a populated
/// records region leaves every slot, the producer cursor and the drop count
/// exactly as the writer left them, so no console can mint or edit a record
/// attributed to a domain.
#[test]
fn the_reader_never_writes_the_records_region() {
    let ring = Ring::zero();
    let mut writer = ring.writer();
    for n in 0..12 {
        writer.write(&tagged(n)).expect("space");
    }
    // A drop count the console would have every incentive to erase.
    ring.records.dropped.store(77, Ordering::Relaxed);
    let before = records_image(&ring.records);

    let mut reader = ring.reader();
    for _ in 0..4 {
        assert!(reader.drain(usize::MAX).count() <= ring.capacity());
        let _ = reader.len();
        let _ = reader.is_empty();
        let _ = reader.dropped_by_writer();
        let _ = reader.undecodable();
    }
    assert_eq!(
        records_image(&ring.records),
        before,
        "the console stored into a writing domain's region"
    );
    assert_eq!(ring.records.dropped.load(Ordering::Relaxed), 77);
}

/// Every word of a records region, for a comparison that a store into any slot
/// or either header word would fail. Field by field rather than as bytes, so it
/// needs no `unsafe` to make the comparison.
fn records_image(records: &LogRecords) -> (u32, u32, Vec<LogRecord>) {
    (
        records.tail.load(Ordering::Relaxed),
        records.dropped.load(Ordering::Relaxed),
        (0..LOG_RING_SLOTS as u32)
            .map(|index| records.slot(index).load())
            .collect(),
    )
}

#[test]
fn a_writing_and_a_draining_thread_transfer_every_record_in_order() {
    const COUNT: u32 = 50_000;
    let ring = Ring::zero();

    thread::scope(|scope| {
        scope.spawn(|| {
            let mut writer = ring.writer();
            let mut n = 0;
            while n < COUNT {
                if writer.write(&tagged(n)).is_ok() {
                    n += 1;
                } else {
                    std::hint::spin_loop();
                }
            }
        });
        scope.spawn(|| {
            let mut reader = ring.reader();
            let mut expected = 0;
            while expected < COUNT {
                match reader.read() {
                    Some(body) => {
                        assert!(is_tagged(&body, expected));
                        expected += 1;
                    }
                    None => std::hint::spin_loop(),
                }
            }
            assert_eq!(reader.undecodable(), 0);
        });
    });
}

#[test]
fn a_thread_scribbling_both_regions_cannot_break_either_side() {
    const ROUNDS: u32 = 20_000;
    let ring = Ring::zero();
    let stop = AtomicBool::new(false);

    thread::scope(|scope| {
        let writer = scope.spawn(|| {
            let mut writer = ring.writer();
            for n in 0..ROUNDS {
                let _ = writer.write(&tagged(n));
                assert!(writer.len() <= writer.capacity());
            }
        });
        let reader = scope.spawn(|| {
            let mut reader = ring.reader();
            let mut seen = 0usize;
            for _ in 0..ROUNDS {
                seen += reader.drain(4).count();
                assert!(reader.len() <= reader.capacity());
            }
            assert!(seen <= 4 * ROUNDS as usize);
        });
        let scribbler = scope.spawn(|| {
            let mut seed = 0x1234_5678u32;
            let mut bytes = [0u8; RECORD_BYTES];
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
                for (index, slot) in bytes.iter_mut().enumerate() {
                    *slot = seed.rotate_left(index as u32 % 32) as u8;
                }
                ring.records.slot(seed).store(&record_from_bytes(bytes));
            }
        });

        writer.join().expect("the writer did not panic");
        reader.join().expect("the reader did not panic");
        stop.store(true, Ordering::Relaxed);
        scribbler.join().expect("the scribbler did not panic");
    });
}

/// Everything a record the console will render is allowed to be. Restated here
/// rather than reached through the decode, so the property pins what is yielded
/// and not merely that something was.
fn assert_yield_is_renderable(record: &CheckedRecord) -> Result<(), TestCaseError> {
    // The stamp is a decoded case rather than a raw discriminant, which is the
    // half of the record a peer can no longer make mean nothing.
    prop_assert!(matches!(
        record.at,
        CheckedStamp::Unsynchronized | CheckedStamp::Utc(_)
    ));
    match &record.body {
        CheckedBody::Domain { domain, state, .. } => {
            prop_assert!(*domain < LOG_DOMAIN_COUNT);
            prop_assert!(*state < LOG_DOMAIN_STATE_COUNT);
        }
        CheckedBody::ConfigChange {
            change,
            object,
            key,
            field,
            from,
            to,
            ..
        } => {
            prop_assert!(*change < LOG_CHANGE_KIND_COUNT);
            prop_assert!(*object < LOG_OBJECT_KIND_COUNT);
            prop_assert!(*field < LOG_FIELD_COUNT);
            prop_assert!(!key.as_bytes().is_empty());
            for value in [from, to].into_iter().flatten() {
                if let CheckedValue::Id(id) = value {
                    prop_assert!(!id.as_bytes().is_empty());
                }
            }
        }
        CheckedBody::ConfigGeneration { outcome, .. } => {
            prop_assert!(*outcome < LOG_GENERATION_OUTCOME_COUNT);
        }
        CheckedBody::ConfigRejected { reason, .. } => {
            prop_assert!(*reason < LOG_REJECT_REASON_COUNT);
        }
    }
    Ok(())
}

/// A record whose three most widely separated fields all carry the same tag:
/// `generation` at one word, `sequence` at the next, and `key` in the byte
/// array a hundred bytes further on. A reader that assembled one record out of
/// two slots would have to get all three from the same one to go unnoticed.
fn stamped(tag: u32) -> LogRecord {
    let mut record = LogRecord {
        kind: LogKind::ConfigChange.to_bits(),
        generation: tag,
        sequence: tag,
        ..LogRecord::ZERO
    };
    // Decimal digits, which are in the identifier alphabet `check_text` admits.
    let mut digits = [0u8; 10];
    let mut value = tag;
    let mut len = 0;
    for slot in digits.iter_mut() {
        *slot = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
        if value == 0 {
            break;
        }
    }
    for (slot, digit) in record.key.bytes.iter_mut().zip(digits[..len].iter().rev()) {
        *slot = *digit;
    }
    record.key.len = len as u8;
    record
}

/// The tag all three fields of a [`stamped`] record must agree on, or `None`
/// where the record is not one this test wrote.
fn stamp_of(record: &CheckedRecord) -> Option<(u32, u32, u32)> {
    let CheckedBody::ConfigChange {
        generation,
        sequence,
        key,
        ..
    } = &record.body
    else {
        return None;
    };
    let from_key = key.as_str().parse::<u32>().ok()?;
    Some((*generation, *sequence, from_key))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The headline byzantine-writer property, over the records region: every
    /// byte of every slot and the producer cursor is a value the writing domain
    /// chose, including values no correct writer produces — forged cursors,
    /// cursors outside the ring, a tail behind the head, and a cursor that keeps
    /// moving while the console drains. The console must return, must not be
    /// made to read more than the ring holds, and must render nothing it has not
    /// decoded.
    #[test]
    fn an_arbitrary_records_region_is_drained_safely(
        slots in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), RECORD_BYTES),
            1..=8,
        ),
        tails in proptest::collection::vec(any::<u32>(), 1..=8),
        limit in prop_oneof![Just(usize::MAX), 0usize..=200],
    ) {
        let ring = Ring::zero();
        let mut reader = ring.reader();

        for (index, bytes) in slots.iter().enumerate() {
            let mut image = [0u8; RECORD_BYTES];
            image.copy_from_slice(bytes);
            ring.records.slot(index as u32).store(&record_from_bytes(image));
        }

        let mut total = 0usize;
        for tail in tails {
            ring.records.tail.store(tail, Ordering::Relaxed);

            let read: Vec<Result<CheckedRecord, LogRecordError>> = reader.drain(limit).collect();
            // Terminates, and never more than the ring can hold in one pass.
            prop_assert!(read.len() <= LOG_RING_SLOTS);
            prop_assert!(read.len() <= reader.capacity());
            prop_assert!(read.len() <= limit);
            total += read.len();

            for decoded in read.iter().flatten() {
                assert_yield_is_renderable(decoded)?;
            }

            let reader_len = reader.len();
            prop_assert!(reader_len <= reader.capacity());
            prop_assert_eq!(reader.is_empty(), reader_len == 0);
            // The writer's claim about its own drops is exposed, never trusted:
            // whatever it says, it has bounded nothing above.
            let _ = reader.dropped_by_writer();
        }
        prop_assert_eq!(
            reader.undecodable() as usize <= total,
            true,
            "more records were refused than were read"
        );
    }

    /// The same, over the consume region and independently of the first: the
    /// console's cursor is arbitrary while the writing domain's own half is
    /// well-formed. Nothing published there may extend the writer's work, move
    /// its position out of the slot array, or lose a record that was neither
    /// written nor counted.
    #[test]
    fn an_arbitrary_consume_region_leaves_the_writer_bounded(
        heads in proptest::collection::vec(any::<u32>(), 1..=32),
    ) {
        let ring = Ring::zero();
        let mut writer = ring.writer();
        let offered = heads.len();
        let mut written = 0usize;
        let mut refused = 0u32;

        for (index, head) in heads.into_iter().enumerate() {
            ring.consume.head.store(head, Ordering::Relaxed);
            match writer.write(&tagged(index as u32)) {
                Ok(()) => written += 1,
                Err(full) => {
                    refused += 1;
                    prop_assert_eq!(full.dropped, refused);
                }
            }
            prop_assert_eq!(writer.dropped(), refused);
            let writer_len = writer.len();
            prop_assert!(writer_len <= writer.capacity());
            prop_assert_eq!(writer.is_empty(), writer_len == 0);
        }
        // Every record offered either landed or was counted; a forged cursor
        // cannot make one disappear unaccounted for (ENG-12).
        prop_assert_eq!(written + usize::try_from(refused).expect("a count fits"), offered);
        prop_assert_eq!(writer.dropped(), refused);
    }

    /// Both regions hostile at once, which is the only shape that covers a
    /// console and a writing domain compromised together. Bounded and
    /// panic-free is all either side may claim under it.
    #[test]
    fn both_regions_arbitrary_together_stay_bounded_and_panic_free(
        slots in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), RECORD_BYTES),
            1..=8,
        ),
        cursors in proptest::collection::vec((any::<u32>(), any::<u32>()), 1..=16),
    ) {
        let ring = Ring::zero();
        let mut writer = ring.writer();
        let mut reader = ring.reader();

        for (index, bytes) in slots.iter().enumerate() {
            let mut image = [0u8; RECORD_BYTES];
            image.copy_from_slice(bytes);
            ring.records.slot(index as u32).store(&record_from_bytes(image));
        }

        for (head, tail) in cursors {
            ring.consume.head.store(head, Ordering::Relaxed);
            ring.records.tail.store(tail, Ordering::Relaxed);
            let _ = writer.write(&tagged(1));
            let read = reader.drain(usize::MAX).count();
            prop_assert!(read <= reader.capacity());
            prop_assert!(writer.len() <= writer.capacity());
            prop_assert!(reader.len() <= reader.capacity());
        }
    }

    /// No record is ever assembled out of two different writes. Each slot is
    /// stamped with its own tag in three fields at three distant offsets, and
    /// every record the console decodes must have all three agreeing — under
    /// cursors that redeliver slots, skip them and run backwards.
    #[test]
    fn a_decoded_record_never_mixes_two_writes(
        tags in proptest::collection::vec(1u32..=99_999, 1..=LOG_RING_SLOTS),
        tails in proptest::collection::vec(any::<u32>(), 1..=8),
    ) {
        let ring = Ring::zero();
        let mut reader = ring.reader();
        for (index, tag) in tags.iter().enumerate() {
            ring.records.slot(index as u32).store(&stamped(*tag));
        }

        for tail in tails {
            ring.records.tail.store(tail, Ordering::Relaxed);
            for decoded in reader.drain(usize::MAX).flatten() {
                // A zeroed slot decodes to no `ConfigChange` at all, which is
                // absent rather than spliced.
                let Some((generation, sequence, from_key)) = stamp_of(&decoded) else {
                    continue;
                };
                prop_assert_eq!(generation, sequence, "two words of one record disagree");
                prop_assert_eq!(generation, from_key, "the text and the words disagree");
                prop_assert!(tags.contains(&generation), "a tag nothing wrote");
            }
        }
    }

    /// Whatever the region held, a drain is a *prefix* of the ring rather than
    /// an unbounded walk: reading the same region twice with the cursor stuck
    /// forward yields at most the capacity each time and never grows.
    #[test]
    fn repeated_drains_under_a_stuck_cursor_stay_bounded(
        tail in any::<u32>(),
        passes in 1usize..=6,
    ) {
        let ring = Ring::zero();
        let mut reader = ring.reader();
        ring.records.tail.store(tail, Ordering::Relaxed);
        for _ in 0..passes {
            let count = reader.drain(usize::MAX).count();
            prop_assert!(count <= reader.capacity());
        }
    }
}
