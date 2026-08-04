//! Geometry, appends, wraps and reader positions.
//!
//! The interesting states of a recording ring are the ones that take a running
//! appliance hours to reach — the second wrap, the reader overtaken mid-segment,
//! the record that will never fit — so they are reached here in a few calls and
//! asserted exactly. What the properties at the end add is the case nobody
//! writes by hand: that no sequence of appends and rolls, whatever the lengths,
//! ever names a byte outside the extent or inside the superblock's segment.

use super::*;
use proptest::prelude::*;
use std::vec::Vec;

const SEGMENT: usize = MIN_SEGMENT_BYTES;
const SEGMENT_SECTORS: u64 = (SEGMENT / SECTOR_SIZE) as u64;
/// Not zero and not a sector multiple, so a placement that confused the
/// prologue with a sector boundary is visible in the arithmetic.
const PROLOGUE: usize = 96;
const PAYLOAD: usize = SEGMENT - PROLOGUE;
/// Not zero, so an extent that was assumed to start at the device's front
/// fails rather than passes by coincidence.
const START: u64 = 64;

fn geometry(payload_segments: u64) -> Geometry {
    let sectors = (payload_segments + 1) * SEGMENT_SECTORS;
    Geometry::new(START, sectors, SEGMENT, START + sectors).expect("a legal extent")
}

fn ring(payload_segments: u64) -> Ring {
    Ring::new(geometry(payload_segments), PROLOGUE)
}

/// Append and publish, or say which refusal came back.
fn commit(ring: &mut Ring, len: usize) -> Option<Placement> {
    match ring.append(len) {
        Append::Placed(reservation) => {
            let placement = reservation.placement();
            reservation.commit();
            Some(placement)
        }
        Append::SegmentFull | Append::Oversized { .. } => None,
    }
}

/// Append `count` records of `len`, rolling whenever the open segment is full,
/// and report where each one landed and under which cursor.
fn append_all(ring: &mut Ring, len: usize, count: usize) -> Vec<(Cursor, Placement)> {
    let mut written = Vec::new();
    while written.len() < count {
        let cursor = ring.cursor();
        match commit(ring, len) {
            Some(placement) => written.push((cursor, placement)),
            None => {
                ring.roll();
            }
        }
    }
    written
}

#[test]
fn a_segment_that_is_not_a_sector_multiple_is_refused() {
    assert_eq!(
        Geometry::new(0, 64, SEGMENT + 1, 1024),
        Err(GeometryError::SegmentNotSectorMultiple { bytes: SEGMENT + 1 })
    );
}

#[test]
fn a_segment_below_the_minimum_is_refused() {
    // Zero passes the sector-multiple rule, so this is also what keeps the
    // divisions in `Geometry` from meeting a zero divisor.
    assert_eq!(
        Geometry::new(0, 64, 0, 1024),
        Err(GeometryError::SegmentTooSmall { bytes: 0 })
    );
    assert_eq!(
        Geometry::new(0, 64, MIN_SEGMENT_BYTES - SECTOR_SIZE, 1024),
        Err(GeometryError::SegmentTooSmall {
            bytes: MIN_SEGMENT_BYTES - SECTOR_SIZE
        })
    );
}

#[test]
fn an_extent_that_does_not_divide_into_segments_is_refused() {
    assert_eq!(
        Geometry::new(0, 33, SEGMENT, 1024),
        Err(GeometryError::ExtentNotSegmentMultiple {
            sectors: 33,
            segment_sectors: SEGMENT_SECTORS,
        })
    );
}

#[test]
fn an_extent_too_small_to_hold_history_is_refused() {
    // The superblock's segment plus one payload segment is a ring that evicts
    // everything on every roll, and an empty extent is not a ring at all.
    for total in 0..=MIN_PAYLOAD_SEGMENTS {
        let sectors = total * SEGMENT_SECTORS;
        assert_eq!(
            Geometry::new(0, sectors, SEGMENT, 1024),
            Err(GeometryError::TooFewSegments { segments: total })
        );
    }
}

#[test]
fn the_smallest_legal_ring_is_the_superblock_and_two_payload_segments() {
    let sectors = (MIN_PAYLOAD_SEGMENTS + 1) * SEGMENT_SECTORS;
    let geometry = Geometry::new(0, sectors, MIN_SEGMENT_BYTES, sectors).expect("a legal extent");
    assert_eq!(geometry.segments(), MIN_PAYLOAD_SEGMENTS);
    assert_eq!(
        geometry.payload_bytes(),
        MIN_PAYLOAD_SEGMENTS * SEGMENT as u64
    );
    // Two payload segments alternate, and neither is ever the superblock's.
    assert_eq!(geometry.superblock_sector(), 0);
    assert_eq!(geometry.segment_sector(0), SEGMENT_SECTORS);
    assert_eq!(geometry.segment_sector(1), 2 * SEGMENT_SECTORS);
    assert_eq!(geometry.segment_sector(2), geometry.segment_sector(0));
}

#[test]
fn an_extent_past_the_end_of_the_device_is_refused() {
    assert_eq!(
        Geometry::new(64, 32, SEGMENT, 95),
        Err(GeometryError::ExtentOutsideDevice {
            start: 64,
            sectors: 32,
            capacity: 95,
        })
    );
    // Exactly filling the device is not past its end.
    assert!(Geometry::new(64, 32, SEGMENT, 96).is_ok());
    // An extent whose end does not exist as a number is the same refusal: the
    // check is `start + sectors`, and it must not wrap into a small answer.
    assert_eq!(
        Geometry::new(
            u64::MAX - SEGMENT_SECTORS,
            8 * SEGMENT_SECTORS,
            SEGMENT,
            u64::MAX
        ),
        Err(GeometryError::ExtentOutsideDevice {
            start: u64::MAX - SEGMENT_SECTORS,
            sectors: 8 * SEGMENT_SECTORS,
            capacity: u64::MAX,
        })
    );
}

#[test]
fn an_extent_whose_bytes_do_not_fit_a_u64_is_refused() {
    // No device is this large; `capacity_sectors` is configuration rather than
    // a measurement, and refusing here is what leaves `payload_bytes` total.
    let sectors = (u64::MAX / SECTOR_SIZE as u64 + 1).next_multiple_of(SEGMENT_SECTORS);
    assert_eq!(
        Geometry::new(0, sectors, SEGMENT, u64::MAX),
        Err(GeometryError::ExtentExceedsByteAddressing { sectors })
    );
}

#[test]
fn a_geometry_is_determined_by_the_three_fields_a_superblock_stores() {
    // What lets `RingState::check` compare three numbers and call it the whole
    // geometry: the rest are functions of them, and the device capacity is a
    // rule applied at construction rather than a field.
    let from_exact = Geometry::new(START, 96, SEGMENT, START + 96).expect("a legal extent");
    let from_roomy = Geometry::new(START, 96, SEGMENT, u64::MAX / 1024).expect("a legal extent");
    assert_eq!(from_exact, from_roomy);
}

#[test]
fn the_segments_walk_the_extent_in_order_and_skip_the_superblocks() {
    let geometry = geometry(11);
    assert_eq!(geometry.start_sector(), START);
    assert_eq!(geometry.sectors(), 96);
    assert_eq!(geometry.segments(), 11);
    assert_eq!(geometry.segment_bytes(), SEGMENT);
    assert_eq!(geometry.segment_sectors(), SEGMENT_SECTORS);
    assert_eq!(geometry.payload_bytes(), 11 * SEGMENT as u64);
    assert_eq!(geometry.superblock_sector(), START);
    for index in 0..11 {
        assert_eq!(
            geometry.segment_sector(index),
            START + (index + 1) * SEGMENT_SECTORS
        );
    }
    // And a sequence far past a wrap addresses the segment now holding it,
    // rather than running off the end.
    assert_eq!(geometry.segment_sector(11), geometry.segment_sector(0));
    assert_eq!(
        geometry.segment_sector(u64::MAX),
        geometry.segment_sector(u64::MAX % 11)
    );
}

#[test]
fn a_fresh_ring_opens_its_first_segment_behind_the_prologue() {
    let ring = ring(3);
    assert_eq!(
        ring.cursor(),
        Cursor {
            sequence: 0,
            offset: PROLOGUE
        }
    );
    assert_eq!(ring.prologue_len(), PROLOGUE);
    assert_eq!(ring.segment_payload(), PAYLOAD);
    assert_eq!(ring.slack(), PAYLOAD);
    assert_eq!(ring.readable(), (0, 0));
    assert_eq!(ring.write_generation(), 0);
    assert_eq!(ring.counters(), RingCounters::default());
    assert_eq!(ring.geometry(), geometry(3));

    let prologue = ring.prologue();
    assert_eq!(prologue.sector(), START + SEGMENT_SECTORS);
    assert_eq!(prologue.byte_offset(), 0);
    assert_eq!(prologue.len(), PROLOGUE);
    assert!(!prologue.is_empty());
}

#[test]
fn a_record_that_fits_is_placed_at_the_cursor() {
    let mut ring = ring(3);
    let placement = commit(&mut ring, 1000).expect("a fresh segment holds it");
    assert_eq!(placement.sector(), START + SEGMENT_SECTORS);
    assert_eq!(placement.byte_offset(), PROLOGUE);
    assert_eq!(placement.len(), 1000);
    assert_eq!(
        ring.cursor(),
        Cursor {
            sequence: 0,
            offset: PROLOGUE + 1000
        }
    );
    assert_eq!(ring.slack(), PAYLOAD - 1000);
    assert_eq!(ring.counters().records_appended, 1);
    assert_eq!(ring.counters().bytes_appended, 1000);

    // The second lands immediately behind the first, in the same segment.
    let next = commit(&mut ring, 24).expect("room remains");
    assert_eq!(next.sector(), placement.sector());
    assert_eq!(next.byte_offset(), PROLOGUE + 1000);
    assert_eq!(ring.counters().bytes_appended, 1024);
}

#[test]
fn a_record_exactly_filling_the_remaining_space_fits_and_closes_the_segment() {
    let mut ring = ring(3);
    commit(&mut ring, 1000).expect("a fresh segment holds it");
    assert_eq!(ring.slack(), PAYLOAD - 1000);

    let placement = commit(&mut ring, PAYLOAD - 1000).expect("exactly the remainder");
    assert_eq!(placement.byte_offset(), PROLOGUE + 1000);
    assert_eq!(ring.cursor().offset, SEGMENT);
    assert_eq!(ring.slack(), 0);
    // Nothing but an empty record fits a full segment, and an empty one still
    // has a well-defined place.
    assert_eq!(ring.fit(1), Fit::SegmentFull);
    assert_eq!(
        ring.fit(0),
        Fit::Fits(Placement {
            sector: START + SEGMENT_SECTORS,
            byte_offset: SEGMENT,
            len: 0,
        })
    );
}

#[test]
fn a_record_exactly_filling_a_whole_segments_payload_fits_an_empty_one() {
    let mut ring = ring(3);
    let placement = commit(&mut ring, PAYLOAD).expect("the whole payload");
    assert_eq!(placement.byte_offset(), PROLOGUE);
    assert_eq!(placement.len(), PAYLOAD);
    assert_eq!(ring.cursor().offset, SEGMENT);
    // One byte more never fits any segment, so it is refused permanently
    // rather than deferred to a roll.
    assert_eq!(
        ring.fit(PAYLOAD + 1),
        Fit::Oversized {
            needed: PAYLOAD + 1,
            segment_payload: PAYLOAD,
        }
    );
}

#[test]
fn a_record_the_open_segment_cannot_hold_fits_the_next_one() {
    let mut ring = ring(3);
    commit(&mut ring, PAYLOAD - 500).expect("a fresh segment holds it");
    assert_eq!(ring.fit(1000), Fit::SegmentFull);
    assert!(matches!(ring.append(1000), Append::SegmentFull));
    // Refusing for want of room in *this* segment counts nothing: the record
    // is not lost, only deferred.
    assert_eq!(ring.counters().records_oversized, 0);

    let prologue = ring.roll();
    assert_eq!(prologue.sector(), START + 2 * SEGMENT_SECTORS);
    assert_eq!(prologue.byte_offset(), 0);
    assert_eq!(prologue.len(), PROLOGUE);
    assert_eq!(
        ring.cursor(),
        Cursor {
            sequence: 1,
            offset: PROLOGUE
        }
    );

    let placement = commit(&mut ring, 1000).expect("the new segment holds it");
    assert_eq!(placement.sector(), START + 2 * SEGMENT_SECTORS);
    assert_eq!(placement.byte_offset(), PROLOGUE);
    assert_eq!(ring.counters().segments_rolled, 1);
    assert_eq!(ring.counters().wraps, 0);
    // The tail of the closed segment is what a writer pads before rolling.
    assert_eq!(ring.counters().records_appended, 2);
}

#[test]
fn a_record_larger_than_a_segment_is_refused_permanently_and_counted() {
    let mut ring = ring(3);
    // Asking costs nothing and counts nothing.
    assert_eq!(
        ring.fit(SEGMENT * 2),
        Fit::Oversized {
            needed: SEGMENT * 2,
            segment_payload: PAYLOAD,
        }
    );
    assert_eq!(ring.counters().records_oversized, 0);

    // Attempting it is the loss, and that is what the metric counts.
    let refusal = ring.append(SEGMENT * 2);
    assert!(matches!(
        refusal,
        Append::Oversized {
            needed,
            segment_payload,
        } if needed == SEGMENT * 2 && segment_payload == PAYLOAD
    ));
    assert_eq!(refusal.placement(), None);
    assert_eq!(ring.counters().records_oversized, 1);
    // Rolling does not help, which is the difference from `SegmentFull`.
    ring.roll();
    assert!(matches!(ring.append(SEGMENT * 2), Append::Oversized { .. }));
    assert_eq!(ring.counters().records_oversized, 2);
    assert_eq!(
        ring.cursor(),
        Cursor {
            sequence: 1,
            offset: PROLOGUE
        }
    );
}

#[test]
fn a_prologue_that_fills_a_segment_leaves_a_payload_of_nothing() {
    // Not a fallible constructor: the misconfiguration names itself at the
    // point it bites, carrying the zero that explains it.
    let mut ring = Ring::new(geometry(3), SEGMENT * 4);
    assert_eq!(ring.segment_payload(), 0);
    assert_eq!(ring.slack(), 0);
    assert_eq!(ring.cursor().offset, SEGMENT);
    assert_eq!(ring.prologue().len(), SEGMENT);
    assert_eq!(
        ring.fit(1),
        Fit::Oversized {
            needed: 1,
            segment_payload: 0,
        }
    );
    assert!(matches!(ring.append(1), Append::Oversized { .. }));
    assert_eq!(ring.counters().records_oversized, 1);
    // Rolling keeps the ring total rather than walking the cursor out of its
    // segment.
    ring.roll();
    assert_eq!(
        ring.cursor(),
        Cursor {
            sequence: 1,
            offset: SEGMENT
        }
    );
}

#[test]
fn an_uncommitted_reservation_leaves_the_ring_exactly_where_it_was() {
    // The safe direction: a write that never reached the medium publishes
    // nothing, and the identical append can be made again.
    let mut ring = ring(3);
    let before = ring.cursor();
    let abandoned = match ring.append(700) {
        Append::Placed(reservation) => reservation.placement(),
        other => panic!("a fresh segment holds it, not {other:?}"),
    };
    assert_eq!(ring.cursor(), before);
    assert_eq!(ring.counters(), RingCounters::default());

    let retried = commit(&mut ring, 700).expect("the same room is still there");
    assert_eq!(retried, abandoned);
    assert_eq!(ring.counters().records_appended, 1);
}

#[test]
fn append_places_where_fit_said_it_would() {
    // One decision reached two ways, so a caller sizing a batch and a caller
    // reserving cannot be told different things.
    let mut ring = ring(3);
    for len in [0, 1, 999, PAYLOAD - 1, PAYLOAD, PAYLOAD + 1, usize::MAX] {
        let expected = ring.fit(len);
        let actual = ring.append(len);
        match (expected, &actual) {
            (Fit::Fits(placement), Append::Placed(reservation)) => {
                assert_eq!(reservation.placement(), placement);
                assert_eq!(actual.placement(), Some(placement));
            }
            (Fit::SegmentFull, Append::SegmentFull) => assert_eq!(actual.placement(), None),
            (
                Fit::Oversized {
                    needed,
                    segment_payload,
                },
                Append::Oversized {
                    needed: got_needed,
                    segment_payload: got_payload,
                },
            ) => {
                assert_eq!((needed, segment_payload), (*got_needed, *got_payload));
            }
            (expected, actual) => panic!("fit said {expected:?}, append did {actual:?}"),
        }
    }
}

#[test]
fn a_roll_counts_a_wrap_only_when_it_returns_to_the_first_segment() {
    let mut ring = ring(3);
    let first = ring.prologue().sector();
    for expected in 1..=3u64 {
        ring.roll();
        assert_eq!(ring.counters().segments_rolled, expected);
        assert_eq!(ring.counters().wraps, u64::from(expected == 3));
    }
    // The third roll came back to the segment the ring started in, whole.
    assert_eq!(ring.prologue().sector(), first);
    for _ in 0..3 {
        ring.roll();
    }
    assert_eq!(ring.counters().segments_rolled, 6);
    assert_eq!(ring.counters().wraps, 2);
    assert_eq!(ring.cursor().sequence, 6);
}

#[test]
fn a_wrap_replaces_one_whole_segment_and_no_part_of_another() {
    let geometry = geometry(3);
    for sequence in 0..3u64 {
        // Three payload segments, so sequences three apart share one and
        // nothing between them does.
        assert_eq!(
            geometry.segment_sector(sequence),
            geometry.segment_sector(sequence + 3)
        );
        for other in 0..3u64 {
            if other != sequence {
                assert_ne!(
                    geometry.segment_sector(sequence),
                    geometry.segment_sector(other)
                );
            }
        }
    }
    // The segments abut without overlapping, so replacing one covers every
    // sector of it and none of its neighbour's, and the last of them ends
    // exactly at the extent's end.
    for sequence in 0..2u64 {
        assert_eq!(
            geometry.segment_sector(sequence) + SEGMENT_SECTORS,
            geometry.segment_sector(sequence + 1)
        );
    }
    assert_eq!(
        geometry.segment_sector(2) + SEGMENT_SECTORS,
        geometry.start_sector() + geometry.sectors()
    );
}

#[test]
fn the_readable_window_advances_a_segment_at_a_time_once_the_ring_is_full() {
    let mut ring = ring(3);
    // Before the first wrap nothing has been evicted, so the window starts at
    // the beginning and only its newer end moves.
    assert_eq!(ring.readable(), (0, 0));
    ring.roll();
    assert_eq!(ring.readable(), (0, 1));
    ring.roll();
    assert_eq!(ring.readable(), (0, 2));
    // From here the ring is full and the older end starts to move with it.
    ring.roll();
    assert_eq!(ring.readable(), (1, 3));
    ring.roll();
    assert_eq!(ring.readable(), (2, 4));
}

#[test]
fn locate_reports_the_run_to_the_write_cursor_in_the_open_segment() {
    let mut ring = ring(3);
    commit(&mut ring, 1000).expect("a fresh segment holds it");

    let Located::Live(placement) = ring.locate(0, PROLOGUE) else {
        panic!("the byte was just written");
    };
    assert_eq!(placement.sector(), START + SEGMENT_SECTORS);
    assert_eq!(placement.byte_offset(), PROLOGUE);
    // As far as the cursor and no further: the bytes beyond it are the previous
    // wrap's, not this one's.
    assert_eq!(placement.len(), 1000);
    assert_eq!(run_len(ring.locate(0, PROLOGUE + 999)), Some(1));
    assert_eq!(ring.locate(0, PROLOGUE + 1000), Located::Unwritten);
    assert_eq!(ring.locate(0, SEGMENT), Located::Unwritten);
    // Ahead of the writer is not loss, and is not counted as any.
    assert_eq!(ring.locate(1, 0), Located::Unwritten);
    assert_eq!(ring.locate(u64::MAX, 0), Located::Unwritten);
    assert_eq!(ring.counters().reader_overruns, 0);
}

#[test]
fn locate_reports_a_closed_segment_readable_to_its_end() {
    let mut ring = ring(3);
    commit(&mut ring, 1000).expect("a fresh segment holds it");
    ring.roll();

    // The segment is closed, so its whole length is addressable — the tail a
    // writer was expected to pad included, which this crate addresses and does
    // not interpret.
    let Located::Live(placement) = ring.locate(0, PROLOGUE) else {
        panic!("one roll evicts nothing in a three-segment ring");
    };
    assert_eq!(placement.sector(), START + SEGMENT_SECTORS);
    assert_eq!(placement.len(), SEGMENT - PROLOGUE);
    assert_eq!(run_len(ring.locate(0, SEGMENT - 1)), Some(1));
    assert_eq!(ring.locate(0, SEGMENT), Located::Unwritten);
}

#[test]
fn an_overtaken_reader_is_told_the_gap_and_where_to_resynchronise() {
    let mut ring = ring(3);
    commit(&mut ring, 1000).expect("a fresh segment holds it");
    for _ in 0..3 {
        ring.roll();
    }
    assert_eq!(ring.readable(), (1, 3));

    // The gap is the measured loss, not a suspicion of one: one segment, and
    // sequence 1 is where to pick up again.
    assert_eq!(
        ring.locate(0, PROLOGUE),
        Located::Overrun { gap: 1, oldest: 1 }
    );
    assert_eq!(ring.counters().reader_overruns, 1);
    ring.roll();
    assert_eq!(
        ring.locate(0, PROLOGUE),
        Located::Overrun { gap: 2, oldest: 2 }
    );
    // One count per observation, so a reader that keeps asking keeps counting.
    assert_eq!(ring.counters().reader_overruns, 2);
    // And the sequence it was pointed at is live.
    assert!(matches!(ring.locate(2, 0), Located::Live(_)));
}

#[test]
fn a_ring_resumes_the_cursor_and_generation_the_medium_carried() {
    let geometry = geometry(3);
    let stored = RingState::new(
        geometry,
        9,
        Cursor {
            sequence: 7,
            offset: PROLOGUE + 40,
        },
        &[ReaderCursor {
            id: 2,
            cursor: Cursor {
                sequence: 6,
                offset: 0,
            },
        }],
    )
    .expect("a legal state");
    let checked = stored.check(&geometry).expect("the ring it describes");
    let mut ring = Ring::resume(checked, PROLOGUE);

    assert_eq!(ring.cursor(), stored.writer());
    assert_eq!(ring.write_generation(), 9);
    assert_eq!(ring.geometry(), geometry);
    // Counters are this run's, not the medium's: they are metrics rather than
    // delivery state, and a restart is where a counter is expected to reset.
    assert_eq!(ring.counters(), RingCounters::default());
    // The window resumes around the stored sequence, so the reader recorded
    // beside it is still live.
    assert_eq!(ring.readable(), (5, 7));
    assert!(matches!(ring.locate(6, 0), Located::Live(_)));
    assert_eq!(ring.locate(4, 0), Located::Overrun { gap: 1, oldest: 5 });
    // Appends carry on into the segment the cursor was left in.
    let placement = commit(&mut ring, 8).expect("room remains");
    assert_eq!(placement.sector(), geometry.segment_sector(7));
    assert_eq!(placement.byte_offset(), PROLOGUE + 40);
}

#[test]
fn a_cursor_resumed_below_the_prologue_still_refuses_what_a_segment_cannot_hold() {
    // A ring written under a shorter prologue leaves the open segment more room
    // than a fresh one has. `fit` stays stated against the segment, so a record
    // accepted now is one a roll could accept again.
    let geometry = geometry(3);
    let stored = RingState::new(
        geometry,
        1,
        Cursor {
            sequence: 0,
            offset: 10,
        },
        &[],
    )
    .expect("a legal state");
    let ring = Ring::resume(stored.check(&geometry).expect("the same ring"), PROLOGUE);

    assert_eq!(ring.slack(), SEGMENT - 10);
    assert_eq!(ring.segment_payload(), PAYLOAD);
    assert!(ring.slack() > ring.segment_payload());
    assert_eq!(
        ring.fit(PAYLOAD + 1),
        Fit::Oversized {
            needed: PAYLOAD + 1,
            segment_payload: PAYLOAD,
        }
    );
    assert!(matches!(ring.fit(PAYLOAD), Fit::Fits(_)));
}

#[test]
fn a_checkpoint_takes_the_next_generation_and_a_refusal_takes_none() {
    let mut ring = ring(3);
    commit(&mut ring, 64).expect("a fresh segment holds it");

    let first = ring
        .checkpoint(ring.cursor(), &[])
        .expect("no readers is a legal set");
    assert_eq!(first.write_generation(), 1);
    assert_eq!(first.writer(), ring.cursor());
    assert_eq!(first.geometry(), ring.geometry());
    assert_eq!(ring.write_generation(), 1);

    // The refusal leaves the ring untouched, generation included — so a
    // generation is never burned on a checkpoint that was never written.
    let duplicates = [
        ReaderCursor {
            id: 4,
            cursor: Cursor::default(),
        },
        ReaderCursor {
            id: 4,
            cursor: Cursor::default(),
        },
    ];
    assert_eq!(
        ring.checkpoint(ring.cursor(), &duplicates),
        Err(RingStateError::DuplicateReaderId { id: 4 })
    );
    assert_eq!(ring.write_generation(), 1);

    let second = ring
        .checkpoint(ring.cursor(), &duplicates[..1])
        .expect("one reader is legal");
    assert_eq!(second.write_generation(), 2);
    assert_eq!(ring.write_generation(), 2);
}

#[test]
fn a_checkpoint_round_trips_the_ring_through_the_medium() {
    // The loop the appliance actually runs: write records, checkpoint, lose
    // power, read the superblock back, resume, keep writing where it stopped.
    let mut ring = ring(3);
    append_all(&mut ring, 700, 12);
    let readers = [ReaderCursor {
        id: 1,
        cursor: Cursor {
            sequence: 1,
            offset: PROLOGUE,
        },
    }];
    let state = ring
        .checkpoint(ring.cursor(), &readers)
        .expect("a legal reader set");

    let mut region = [0u8; SUPERBLOCK_BYTES];
    encode_superblock(&mut region, &state, Copies::Parity);
    let recovered = decode_superblock(&region).expect("the copy just written");
    let resumed = Ring::resume(
        recovered.check(&ring.geometry()).expect("the same ring"),
        PROLOGUE,
    );

    assert_eq!(resumed.cursor(), ring.cursor());
    assert_eq!(resumed.readable(), ring.readable());
    assert_eq!(resumed.write_generation(), ring.write_generation());
    assert_eq!(
        recovered
            .readers()
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>(),
        readers
    );
}

#[test]
fn every_geometry_refusal_and_outcome_renders_distinctly() {
    // These are what an operator sees when a ring will not come up, so a
    // rendering that collapses two causes into one text is a defect.
    let rendered = [
        GeometryError::SegmentNotSectorMultiple { bytes: 1 },
        GeometryError::SegmentTooSmall { bytes: 1 },
        GeometryError::ExtentNotSegmentMultiple {
            sectors: 1,
            segment_sectors: 2,
        },
        GeometryError::TooFewSegments { segments: 1 },
        GeometryError::ExtentOutsideDevice {
            start: 1,
            sectors: 2,
            capacity: 3,
        },
        GeometryError::ExtentExceedsByteAddressing { sectors: 1 },
    ]
    .map(|error| std::format!("{error:?}"));
    let unique: std::collections::BTreeSet<&std::string::String> = rendered.iter().collect();
    assert_eq!(unique.len(), rendered.len());

    let mut ring = ring(3);
    assert!(!std::format!("{:?}", ring.fit(1)).is_empty());
    assert!(!std::format!("{:?}", ring.locate(0, 0)).is_empty());
    assert!(!std::format!("{:?}", ring.counters()).is_empty());
    assert!(!std::format!("{:?}", ring.append(1)).is_empty());
    assert!(!std::format!("{ring:?}").is_empty());
}

/// One step a writer may take.
#[derive(Clone, Copy, Debug)]
enum Step {
    Append(usize),
    Roll,
}

/// Lengths that straddle every boundary the ring has — empty, a sliver, the
/// exact payload, and more than a segment — rather than a uniform draw that
/// would spend the run in the middle.
fn steps() -> impl Strategy<Value = Vec<Step>> {
    let len = prop_oneof![
        Just(0usize),
        Just(1),
        Just(PAYLOAD - 1),
        Just(PAYLOAD),
        Just(PAYLOAD + 1),
        Just(usize::MAX),
        0usize..SEGMENT * 2,
    ];
    prop::collection::vec(
        prop_oneof![9 => len.prop_map(Step::Append), 1 => Just(Step::Roll)],
        0..400,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    /// The invariant the whole crate exists to hold: whatever a writer does,
    /// every byte it is told to write lies inside a payload segment of the
    /// extent — never past its end, never across a segment boundary, and never
    /// in the superblock's own segment, which a stray sequence of zero would
    /// otherwise reach.
    #[test]
    fn no_sequence_of_appends_places_a_byte_outside_a_payload_segment(
        segments in MIN_PAYLOAD_SEGMENTS..7u64,
        steps in steps(),
    ) {
        let geometry = geometry(segments);
        let mut ring = Ring::new(geometry, PROLOGUE);
        let first = geometry.start_sector() + SEGMENT_SECTORS;
        let end = geometry.start_sector() + geometry.sectors();

        let check = |placement: Placement| -> Result<(), TestCaseError> {
            prop_assert!(placement.sector() >= first, "the superblock's segment was addressed");
            prop_assert!(placement.sector() < end);
            // A placement always names a segment's first sector, so the offset
            // it carries is what has to stay inside that segment.
            prop_assert_eq!((placement.sector() - first) % SEGMENT_SECTORS, 0);
            prop_assert!(placement.byte_offset() <= SEGMENT);
            prop_assert!(placement.byte_offset() + placement.len() <= SEGMENT);
            Ok(())
        };

        check(ring.prologue())?;
        for step in steps {
            match step {
                Step::Append(len) => {
                    if let Append::Placed(reservation) = ring.append(len) {
                        let placement = reservation.placement();
                        reservation.commit();
                        check(placement)?;
                    }
                }
                Step::Roll => check(ring.roll())?,
            }
        }
    }

    /// The cursor never leaves the segment it is in — the standing proof behind
    /// `Reservation::commit`'s claim that `offset + len` cannot exceed the
    /// segment, and so behind the one piece of unchecked arithmetic here.
    #[test]
    fn the_cursor_never_leaves_its_segment(
        segments in MIN_PAYLOAD_SEGMENTS..7u64,
        prologue in prop_oneof![Just(0usize), Just(PROLOGUE), Just(SEGMENT), Just(SEGMENT * 3)],
        steps in steps(),
    ) {
        let mut ring = Ring::new(geometry(segments), prologue);
        prop_assert!(ring.cursor().offset <= SEGMENT);

        for step in steps {
            match step {
                Step::Append(len) => {
                    if let Append::Placed(reservation) = ring.append(len) {
                        reservation.commit();
                    }
                }
                Step::Roll => {
                    ring.roll();
                }
            }
            prop_assert!(ring.cursor().offset <= SEGMENT);
            prop_assert_eq!(ring.slack(), SEGMENT - ring.cursor().offset);
        }
    }

    /// A cursor only ever moves forward: the sequence never decreases, and
    /// within one sequence neither does the offset. A reader's `(sequence,
    /// offset)` is therefore comparable against it, which is what makes an
    /// overrun a subtraction rather than a guess.
    #[test]
    fn the_cursor_is_monotone(
        segments in MIN_PAYLOAD_SEGMENTS..7u64,
        steps in steps(),
    ) {
        let mut ring = Ring::new(geometry(segments), PROLOGUE);
        let mut previous = ring.cursor();
        let mut window = ring.readable();

        for step in steps {
            match step {
                Step::Append(len) => {
                    if let Append::Placed(reservation) = ring.append(len) {
                        reservation.commit();
                    }
                }
                Step::Roll => {
                    ring.roll();
                }
            }
            let cursor = ring.cursor();
            prop_assert!(cursor.sequence >= previous.sequence);
            if cursor.sequence == previous.sequence {
                prop_assert!(cursor.offset >= previous.offset);
            }
            let next = ring.readable();
            prop_assert!(next.0 >= window.0);
            prop_assert!(next.1 >= window.1);
            prop_assert_eq!(next.1, cursor.sequence);
            prop_assert!(next.1 - next.0 < ring.geometry().segments());
            previous = cursor;
            window = next;
        }
    }

    /// `locate` agrees with what was appended: a byte committed at a sequence
    /// and offset is found at the sector it was placed at, for as long as its
    /// segment is on the medium, and is reported overtaken from the moment it
    /// is not. Nothing in between, and nothing that outlives its segment.
    #[test]
    fn locate_finds_every_committed_byte_until_its_segment_is_replaced(
        segments in MIN_PAYLOAD_SEGMENTS..5u64,
        len in 1usize..PAYLOAD,
        count in 1usize..60,
    ) {
        let mut ring = Ring::new(geometry(segments), PROLOGUE);
        let written = append_all(&mut ring, len, count);
        let (oldest, newest) = ring.readable();
        let mut overtaken = 0u64;

        for (cursor, placement) in written {
            let located = ring.locate(cursor.sequence, cursor.offset);
            if cursor.sequence < oldest {
                prop_assert_eq!(
                    located,
                    Located::Overrun { gap: oldest - cursor.sequence, oldest }
                );
                overtaken += 1;
                continue;
            }
            let Located::Live(found) = located else {
                prop_assert!(false, "a live byte read as {:?}", located);
                unreachable!()
            };
            prop_assert_eq!(found.sector(), placement.sector());
            prop_assert_eq!(found.byte_offset(), placement.byte_offset());
            // The run reaches at least to the end of the record that was
            // written there, and never past the segment.
            prop_assert!(found.len() >= placement.len());
            prop_assert!(found.byte_offset() + found.len() <= SEGMENT);
            if cursor.sequence == newest {
                prop_assert_eq!(found.byte_offset() + found.len(), ring.cursor().offset);
            } else {
                prop_assert_eq!(found.byte_offset() + found.len(), SEGMENT);
            }
        }
        // Exactly the overtaken observations were counted, and none of the live
        // ones: a metric that over-reports loss is as useless as one that hides
        // it.
        prop_assert_eq!(ring.counters().reader_overruns, overtaken);
    }
}

/// The run length of a live position, for a case asserting only that.
fn run_len(located: Located) -> Option<usize> {
    match located {
        Located::Live(placement) => Some(placement.len()),
        Located::Overrun { .. } | Located::Unwritten => None,
    }
}
