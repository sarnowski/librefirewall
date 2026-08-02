//! The superblock as bytes and as a refusal.
//!
//! Two things are under test and they pull in opposite directions: that a
//! superblock this writer produced decodes back to exactly what went in, and
//! that nothing else does. The byte-exact cases pin the first so a field cannot
//! move unnoticed; the torn, forged and mismatched cases pin the second, which
//! is the one an offline attacker with the disk is working against.

use super::*;
use proptest::prelude::*;
use std::vec::Vec;

const SEGMENT: usize = crate::MIN_SEGMENT_BYTES;

/// A twelve-segment ring — the superblock's plus eleven payload — at `start`.
/// Wide enough that a coarser segment size still divides it, which is what the
/// geometry-mismatch cases need in order to differ in one field at a time.
fn geometry(start: u64) -> Geometry {
    let sectors = 12 * (SEGMENT / SECTOR_SIZE) as u64;
    Geometry::new(start, sectors, SEGMENT, start + sectors).expect("a legal extent")
}

fn state(generation: u64, writer: Cursor, readers: &[ReaderCursor]) -> RingState {
    RingState::new(geometry(64), generation, writer, readers).expect("a legal state")
}

fn reader(id: u32, sequence: u64, offset: usize) -> ReaderCursor {
    ReaderCursor {
        id,
        cursor: Cursor { sequence, offset },
    }
}

/// The half of `region` that copy `index` occupies.
fn copy_of(region: &[u8; SUPERBLOCK_BYTES], index: usize) -> &[u8] {
    let (first, second) = region.split_at(SUPERBLOCK_COPY_BYTES);
    if index == 0 { first } else { second }
}

/// Flip a bit inside copy `index`, at a byte the CRC covers.
fn tear(region: &mut [u8; SUPERBLOCK_BYTES], index: usize) {
    region[index * SUPERBLOCK_COPY_BYTES + GENERATION_AT] ^= 0x01;
}

#[test]
fn crc32_matches_the_published_check_values() {
    // The IEEE check value every implementation states, so a table built the
    // wrong way round or a missing final inversion fails here rather than in a
    // superblock nobody can read back.
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
    assert_eq!(crc32(b"a"), 0xE8B7_BE43);
    assert_eq!(crc32(&[0u8; 32]), 0x190A_55AD);
}

#[test]
fn the_magic_reads_as_ascii_on_the_medium() {
    // Little-endian, so the eight bytes at the front of the extent are the
    // eight characters in order — which is the whole point of choosing one.
    assert_eq!(&SUPERBLOCK_MAGIC.to_le_bytes(), b"LFWCAPRG");
}

#[test]
fn a_copy_is_written_field_by_field_where_the_layout_says() {
    let mut region = [0u8; SUPERBLOCK_BYTES];
    let written = encode_superblock(
        &mut region,
        &state(
            7,
            Cursor {
                sequence: 5,
                offset: 1234,
            },
            &[reader(9, 4, 7)],
        ),
    );

    // Generation 7 is odd, so the second copy is the one rewritten.
    assert_eq!(written, SUPERBLOCK_COPY_BYTES);
    assert!(copy_of(&region, 0).iter().all(|byte| *byte == 0));

    let copy = copy_of(&region, 1);
    assert_eq!(&copy[MAGIC_AT..MAGIC_AT + 8], b"LFWCAPRG");
    assert_eq!(read_u32(copy, VERSION_AT), SUPERBLOCK_VERSION);
    assert_eq!(read_u32(copy, READER_COUNT_AT), 1);
    assert_eq!(read_u64(copy, GENERATION_AT), 7);
    assert_eq!(read_u64(copy, START_SECTOR_AT), 64);
    assert_eq!(read_u64(copy, SECTORS_AT), 96);
    assert_eq!(read_u64(copy, SEGMENT_BYTES_AT), SEGMENT as u64);
    assert_eq!(read_u64(copy, WRITER_SEQUENCE_AT), 5);
    assert_eq!(read_u64(copy, WRITER_OFFSET_AT), 1234);
    assert_eq!(read_u32(copy, READERS_AT + READER_ID_AT), 9);
    assert_eq!(read_u32(copy, READERS_AT + READER_ID_AT + 4), 0);
    assert_eq!(read_u64(copy, READERS_AT + READER_SEQUENCE_AT), 4);
    assert_eq!(read_u64(copy, READERS_AT + READER_OFFSET_AT), 7);
    assert_eq!(read_u32(copy, CRC_AT), crc32(&copy[..CRC_AT]));
    // Everything the layout does not name is zero, so a forger has no byte to
    // put meaning in that a decode would carry.
    assert!(
        copy[READERS_AT + READER_BYTES..CRC_AT]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn an_encode_rewrites_one_copy_and_leaves_the_other_alone() {
    // The whole reason for two copies: the one the medium is relying on must
    // not be the one under the write head.
    let mut region = [0xAAu8; SUPERBLOCK_BYTES];
    assert_eq!(
        encode_superblock(&mut region, &state(2, Cursor::default(), &[])),
        0
    );
    assert!(copy_of(&region, 1).iter().all(|byte| *byte == 0xAA));

    let mut region = [0xAAu8; SUPERBLOCK_BYTES];
    assert_eq!(
        encode_superblock(&mut region, &state(3, Cursor::default(), &[])),
        SUPERBLOCK_COPY_BYTES
    );
    assert!(copy_of(&region, 0).iter().all(|byte| *byte == 0xAA));
}

#[test]
fn a_state_survives_the_medium_unchanged() {
    let original = state(
        4,
        Cursor {
            sequence: 11,
            offset: SEGMENT,
        },
        &[reader(1, 9, 0), reader(2, 11, 40), reader(300, 0, SEGMENT)],
    );
    let mut region = [0u8; SUPERBLOCK_BYTES];
    encode_superblock(&mut region, &original);
    assert_eq!(decode_superblock(&region), Some(original));
}

#[test]
fn an_unwritten_medium_is_a_fresh_ring_rather_than_a_fault() {
    assert_eq!(decode_superblock(&[0u8; SUPERBLOCK_BYTES]), None);
    assert_eq!(decode_superblock(&[0xFFu8; SUPERBLOCK_BYTES]), None);
}

#[test]
fn the_newer_generation_wins_whichever_copy_holds_it() {
    let mut region = [0u8; SUPERBLOCK_BYTES];
    let older = state(
        1,
        Cursor {
            sequence: 1,
            offset: 8,
        },
        &[],
    );
    let newer = state(
        2,
        Cursor {
            sequence: 2,
            offset: 16,
        },
        &[],
    );
    // Parity puts the odd generation in copy 1 and the even one in copy 0, so
    // this exercises the newer copy being the *first* one.
    encode_superblock(&mut region, &older);
    encode_superblock(&mut region, &newer);
    assert_eq!(decode_superblock(&region), Some(newer));

    // And the other way round, so neither ordering is being read as "later in
    // the region wins".
    let mut region = [0u8; SUPERBLOCK_BYTES];
    let older = state(
        2,
        Cursor {
            sequence: 2,
            offset: 16,
        },
        &[],
    );
    let newer = state(
        3,
        Cursor {
            sequence: 3,
            offset: 24,
        },
        &[],
    );
    encode_superblock(&mut region, &older);
    encode_superblock(&mut region, &newer);
    assert_eq!(decode_superblock(&region), Some(newer));
}

#[test]
fn a_torn_copy_costs_its_own_generation_and_no_more() {
    let older = state(
        1,
        Cursor {
            sequence: 1,
            offset: 8,
        },
        &[],
    );
    let newer = state(
        2,
        Cursor {
            sequence: 2,
            offset: 16,
        },
        &[],
    );
    let mut written = [0u8; SUPERBLOCK_BYTES];
    encode_superblock(&mut written, &older);
    encode_superblock(&mut written, &newer);

    // The newer copy is torn: the ring resumes one generation behind rather
    // than starting over, which is the whole return on writing two.
    let mut region = written;
    tear(&mut region, 0);
    assert_eq!(decode_superblock(&region), Some(older));

    // The older copy is torn: the newer one is untouched and still wins.
    let mut region = written;
    tear(&mut region, 1);
    assert_eq!(decode_superblock(&region), Some(newer));

    // Both torn: no copy, and a fresh ring rather than a guess.
    let mut region = written;
    tear(&mut region, 0);
    tear(&mut region, 1);
    assert_eq!(decode_superblock(&region), None);
}

#[test]
fn two_valid_copies_at_one_generation_resolve_to_the_first() {
    // Honest writers cannot produce this — one generation is written once — so
    // the case that reaches it is a forgery that arranged the tie, and the
    // answer must be fixed rather than incidental.
    let first = state(
        2,
        Cursor {
            sequence: 2,
            offset: 16,
        },
        &[],
    );
    let second = state(
        2,
        Cursor {
            sequence: 9,
            offset: 48,
        },
        &[],
    );
    let mut region = [0u8; SUPERBLOCK_BYTES];
    encode_superblock(&mut region, &first);

    let mut forged = [0u8; SUPERBLOCK_BYTES];
    encode_superblock(&mut forged, &second);
    let (_, target) = region.split_at_mut(SUPERBLOCK_COPY_BYTES);
    target.copy_from_slice(copy_of(&forged, 0));

    assert_eq!(decode_superblock(&region), Some(first));
}

#[test]
fn a_copy_that_is_not_this_writers_is_refused_however_it_differs() {
    let good = state(
        2,
        Cursor {
            sequence: 1,
            offset: 8,
        },
        &[reader(3, 1, 4)],
    );
    let mut written = [0u8; SUPERBLOCK_BYTES];
    encode_superblock(&mut written, &good);

    // Each mutation is repaired with a fresh CRC, so what is under test is the
    // field rule and not the checksum catching the edit.
    for (name, at, value) in [
        ("magic", MAGIC_AT, 0u64),
        ("version", VERSION_AT, u64::from(SUPERBLOCK_VERSION) + 1),
        ("reader count", READER_COUNT_AT, MAX_READERS as u64 + 1),
        ("segment size", SEGMENT_BYTES_AT, 100),
        ("extent", SECTORS_AT, 3),
        ("writer offset", WRITER_OFFSET_AT, SEGMENT as u64 + 1),
        ("reader padding", READERS_AT + READER_ID_AT + 4, 1),
        ("reader sequence", READERS_AT + READER_SEQUENCE_AT, 99),
    ] {
        let mut region = written;
        let copy = &mut region[..SUPERBLOCK_COPY_BYTES];
        copy[at..at + 8].copy_from_slice(&value.to_le_bytes());
        let crc = crc32(&copy[..CRC_AT]);
        copy[CRC_AT..CRC_AT + 4].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(decode_superblock(&region), None, "{name} was adopted");
    }
}

#[test]
fn a_byte_in_the_span_the_layout_does_not_name_refuses_the_copy() {
    // The reserved tail and the unused reader slots are written zero, so a
    // value there is another writer's meaning — refused now rather than
    // interpreted later.
    let good = state(2, Cursor::default(), &[reader(1, 0, 0)]);
    let mut written = [0u8; SUPERBLOCK_BYTES];
    encode_superblock(&mut written, &good);

    for at in [READERS_AT + READER_BYTES, CRC_AT - 1] {
        let mut region = written;
        let copy = &mut region[..SUPERBLOCK_COPY_BYTES];
        copy[at] = 1;
        let crc = crc32(&copy[..CRC_AT]);
        copy[CRC_AT..CRC_AT + 4].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(decode_superblock(&region), None, "byte {at} was ignored");
    }
}

#[test]
fn a_stored_extent_that_overflows_the_device_it_claims_is_refused() {
    // `stored_geometry` checks the extent against itself, so the only way past
    // that is an extent whose own end does not exist.
    let mut region = [0u8; SUPERBLOCK_BYTES];
    encode_superblock(&mut region, &state(2, Cursor::default(), &[]));
    let copy = &mut region[..SUPERBLOCK_COPY_BYTES];
    copy[START_SECTOR_AT..START_SECTOR_AT + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let crc = crc32(&copy[..CRC_AT]);
    copy[CRC_AT..CRC_AT + 4].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(decode_superblock(&region), None);
}

#[test]
fn a_writer_cursor_outside_its_segment_is_refused() {
    let error = RingState::new(
        geometry(0),
        1,
        Cursor {
            sequence: 0,
            offset: SEGMENT + 1,
        },
        &[],
    );
    assert_eq!(
        error,
        Err(RingStateError::WriterOffsetOutsideSegment {
            offset: SEGMENT + 1,
            segment_bytes: SEGMENT,
        })
    );
    // The segment's last boundary is a position, not an overrun: a writer that
    // exactly filled a segment sits there until it rolls.
    assert!(
        RingState::new(
            geometry(0),
            1,
            Cursor {
                sequence: 0,
                offset: SEGMENT,
            },
            &[],
        )
        .is_ok()
    );
}

#[test]
fn a_reader_set_this_ring_cannot_describe_is_refused_by_name() {
    let writer = Cursor {
        sequence: 4,
        offset: 16,
    };
    let five = [
        reader(1, 0, 0),
        reader(2, 0, 0),
        reader(3, 0, 0),
        reader(4, 0, 0),
        reader(5, 0, 0),
    ];
    assert_eq!(
        RingState::new(geometry(0), 1, writer, &five),
        Err(RingStateError::TooManyReaders { count: 5 })
    );
    assert_eq!(
        RingState::new(geometry(0), 1, writer, &[reader(7, 0, 0), reader(7, 1, 0)]),
        Err(RingStateError::DuplicateReaderId { id: 7 })
    );
    assert_eq!(
        RingState::new(geometry(0), 1, writer, &[reader(7, 0, SEGMENT + 1)]),
        Err(RingStateError::ReaderOffsetOutsideSegment {
            id: 7,
            offset: SEGMENT + 1,
            segment_bytes: SEGMENT,
        })
    );
    assert_eq!(
        RingState::new(geometry(0), 1, writer, &[reader(7, 5, 0)]),
        Err(RingStateError::ReaderAheadOfWriter {
            id: 7,
            sequence: 5,
            writer_sequence: 4,
        })
    );
    // A reader level with the writer's segment but past its offset is not
    // refused: it has been overtaken by nothing and `locate` already reports
    // that it has nothing to read.
    assert!(RingState::new(geometry(0), 1, writer, &[reader(7, 4, SEGMENT)]).is_ok());
    // Four is the capacity, so four distinct readers must be accepted.
    assert!(RingState::new(geometry(0), 1, writer, &five[..MAX_READERS]).is_ok());
}

#[test]
fn a_superblock_describing_another_ring_is_refused_rather_than_adopted() {
    let stored = state(3, Cursor::default(), &[]);
    let configured = geometry(64);
    assert_eq!(
        stored.check(&configured).map(|c| c.geometry()),
        Ok(configured)
    );

    // The extent was rebound, or this is not the device it was: each field is
    // named with both values so an operator can see which.
    assert_eq!(
        stored.check(&geometry(128)),
        Err(RingStateError::StartSectorMismatch {
            stored: 64,
            configured: 128,
        })
    );
    let longer = Geometry::new(64, 104, SEGMENT, 1024).expect("a legal extent");
    assert_eq!(
        stored.check(&longer),
        Err(RingStateError::SectorsMismatch {
            stored: 96,
            configured: 104,
        })
    );
    let coarser = Geometry::new(64, 96, 2 * SEGMENT, 1024).expect("a legal extent");
    assert_eq!(
        stored.check(&coarser),
        Err(RingStateError::SegmentBytesMismatch {
            stored: SEGMENT,
            configured: 2 * SEGMENT,
        })
    );
}

#[test]
fn a_checked_state_carries_forward_everything_the_medium_held() {
    let readers = [reader(1, 2, 3), reader(2, 3, 4)];
    let stored = state(
        6,
        Cursor {
            sequence: 3,
            offset: 9,
        },
        &readers,
    );
    let checked = stored.check(&geometry(64)).expect("the same ring");
    assert_eq!(checked.write_generation(), stored.write_generation());
    assert_eq!(checked.writer(), stored.writer());
    assert_eq!(checked.readers(), stored.readers());
    assert_eq!(
        checked
            .readers()
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>(),
        readers
    );
}

#[test]
fn every_refusal_renders_distinctly() {
    // `Debug` is the only rendering these errors have, and a refusal nobody can
    // read is a refusal nobody acts on.
    let rendered = [
        RingStateError::TooManyReaders { count: 5 },
        RingStateError::DuplicateReaderId { id: 1 },
        RingStateError::WriterOffsetOutsideSegment {
            offset: 1,
            segment_bytes: 2,
        },
        RingStateError::ReaderOffsetOutsideSegment {
            id: 1,
            offset: 2,
            segment_bytes: 3,
        },
        RingStateError::ReaderAheadOfWriter {
            id: 1,
            sequence: 2,
            writer_sequence: 3,
        },
        RingStateError::StartSectorMismatch {
            stored: 1,
            configured: 2,
        },
        RingStateError::SectorsMismatch {
            stored: 1,
            configured: 2,
        },
        RingStateError::SegmentBytesMismatch {
            stored: 1,
            configured: 2,
        },
    ]
    .map(|error| std::format!("{error:?}"));
    let unique: std::collections::BTreeSet<&std::string::String> = rendered.iter().collect();
    assert_eq!(unique.len(), rendered.len());

    let state = state(1, Cursor::default(), &[reader(1, 0, 0)]);
    assert!(!std::format!("{state:?}").is_empty());
    assert!(!std::format!("{:?}", state.check(&geometry(64))).is_empty());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Anything a writer here can state about a ring survives the medium
    /// exactly, readers and all.
    #[test]
    fn a_state_round_trips_through_the_medium(
        generation in any::<u64>(),
        sequence in any::<u64>(),
        offset in 0usize..=SEGMENT,
        readers in prop::collection::vec((any::<u32>(), any::<u64>(), 0usize..=SEGMENT), 0..=MAX_READERS),
    ) {
        let mut seen = std::collections::BTreeSet::new();
        let readers: Vec<ReaderCursor> = readers
            .into_iter()
            // Two rules the state refuses, applied to the generator rather
            // than filtered out of the run: an identifier is a reader's name,
            // and no reader has read a segment the writer never started.
            .filter(|(id, ..)| seen.insert(*id))
            .map(|(id, ahead, offset)| reader(id, sequence - (ahead % (sequence + 1)), offset))
            .collect();

        let original = RingState::new(geometry(64), generation, Cursor { sequence, offset }, &readers)
            .expect("every generated field is within its rule");
        let mut region = [0u8; SUPERBLOCK_BYTES];
        let written = encode_superblock(&mut region, &original);

        prop_assert_eq!(written, (generation % 2) as usize * SUPERBLOCK_COPY_BYTES);
        prop_assert_eq!(decode_superblock(&region), Some(original));
    }

    /// The property the offline-write adversary is up against: whatever bytes
    /// the medium hands back, a decode either refuses them or yields a state
    /// whose every cursor is inside the extent it describes. There is no third
    /// outcome, and in particular none that would place a write outside the
    /// ring.
    #[test]
    fn arbitrary_bytes_decode_to_nothing_or_to_a_state_that_holds(
        bytes in prop::collection::vec(any::<u8>(), SUPERBLOCK_BYTES),
        // A plausible copy far more often than random bytes would be: without
        // it the magic never matches and the run tests only the first branch.
        seed in prop::option::of((any::<u64>(), any::<u64>(), any::<u64>(), any::<u32>())),
        corrupt in prop::collection::vec((0usize..SUPERBLOCK_BYTES, any::<u8>()), 0..8),
    ) {
        let mut region = [0u8; SUPERBLOCK_BYTES];
        region.copy_from_slice(&bytes);
        if let Some((generation, sequence, offset, count)) = seed {
            let writer = Cursor { sequence, offset: (offset as usize) % (SEGMENT + 1) };
            let readers: Vec<ReaderCursor> = (0..u64::from(count) % (MAX_READERS as u64 + 1))
                .map(|id| reader(id as u32, sequence, 0))
                .collect();
            let state = RingState::new(geometry(64), generation, writer, &readers)
                .expect("every seeded field is within its rule");
            encode_superblock(&mut region, &state);
        }
        for (at, byte) in corrupt {
            region[at] = byte;
        }

        let Some(state) = decode_superblock(&region) else {
            return Ok(());
        };
        let geometry = state.geometry();
        let segment_bytes = geometry.segment_bytes();
        prop_assert!(state.writer().offset <= segment_bytes);
        prop_assert!(geometry.segments() >= crate::MIN_PAYLOAD_SEGMENTS);
        prop_assert!(geometry.segment_bytes() >= crate::MIN_SEGMENT_BYTES);
        prop_assert!(geometry.start_sector().checked_add(geometry.sectors()).is_some());
        // A sequence is unbounded by design — it counts segments ever started —
        // so what must hold is that every one of them addresses a sector inside
        // the extent and never the superblock's own segment.
        let sector = geometry.segment_sector(state.writer().sequence);
        prop_assert!(sector >= geometry.start_sector() + geometry.segment_sectors());
        prop_assert!(sector < geometry.start_sector() + geometry.sectors());
        for reader in state.readers().iter().flatten() {
            prop_assert!(reader.cursor.offset <= segment_bytes);
            prop_assert!(reader.cursor.sequence <= state.writer().sequence);
        }
    }
}
