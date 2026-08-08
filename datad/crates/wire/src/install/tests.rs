use std::{boxed::Box, vec, vec::Vec};

use proptest::prelude::*;

use super::*;

/// The region on the heap: it is 128 KiB and a test thread's stack is not sized
/// for several of them at once. The appliance never puts one there either — the
/// region is mapped memory.
fn region() -> Box<InstallStaging> {
    Box::new(InstallStaging::zero())
}

#[test]
fn a_zeroed_region_reads_back_as_zeroes_and_states_its_capacity() {
    let staging = region();
    let mut out = [0xff_u8; 64];
    staging.staged().copy(&mut out);
    assert_eq!(out, [0_u8; 64]);
    assert_eq!(staging.staged().capacity(), MAX_INSTALL_ARCHIVE);
}

#[test]
fn a_fresh_cursor_has_written_nothing_and_offers_the_whole_region() {
    let staging = region();
    let cursor = staging.upload().cursor();
    assert_eq!(cursor.written(), 0);
    assert_eq!(cursor.room(), MAX_INSTALL_ARCHIVE);
    assert!(cursor.finish().is_empty());
}

#[test]
fn what_one_write_places_is_what_comes_back_and_the_token_states_its_length() {
    let staging = region();
    let archive = [0xa5_u8; 4096];
    let mut cursor = staging.upload().cursor();
    assert_eq!(cursor.write(&archive), 4096);
    let staged = cursor.finish();
    assert_eq!(staged.len(), 4096);
    assert!(!staged.is_empty());

    let mut out = vec![0_u8; 8192];
    staging.staged().copy(&mut out);
    assert_eq!(out.get(..4096), Some(&archive[..]));
    // Nothing past the archive was written, so the rest is still the region's
    // zeroes rather than whatever a previous upload left.
    assert!(
        out.get(4096..)
            .is_some_and(|tail| tail.iter().all(|byte| *byte == 0))
    );
}

/// The whole reason the cursor exists: an archive arrives in whatever pieces the
/// network chose, and the pieces land end to end rather than each at the start.
#[test]
fn segments_land_after_one_another_and_the_region_holds_their_concatenation() {
    let staging = region();
    let mut cursor = staging.upload().cursor();
    assert_eq!(cursor.write(b"first"), 5);
    assert_eq!(cursor.written(), 5);
    assert_eq!(cursor.write(b"second"), 6);
    assert_eq!(cursor.written(), 11);
    assert_eq!(cursor.write(&[]), 0);
    assert_eq!(cursor.written(), 11);
    assert_eq!(cursor.finish().len(), 11);

    let mut out = [0_u8; 11];
    staging.staged().copy(&mut out);
    assert_eq!(&out, b"firstsecond");
}

/// The one bound the writing side has, and it is the region's rather than the
/// caller's claim: a write past the end places what fits and answers how much,
/// so the length a request states can never exceed the region.
#[test]
fn a_write_past_the_end_places_what_fits_and_says_how_much() {
    let staging = region();
    let mut cursor = staging.upload().cursor();
    let head = vec![7_u8; MAX_INSTALL_ARCHIVE - 8];
    assert_eq!(cursor.write(&head), MAX_INSTALL_ARCHIVE - 8);
    assert_eq!(cursor.room(), 8);
    // Sixteen offered into eight bytes of room.
    assert_eq!(cursor.write(&[9_u8; 16]), 8);
    assert_eq!(cursor.room(), 0);
    // And a cursor with no room takes nothing at all rather than wrapping to the
    // start, which would be an upload overwriting its own beginning.
    assert_eq!(cursor.write(&[1_u8; 32]), 0);
    assert_eq!(cursor.finish().len() as usize, MAX_INSTALL_ARCHIVE);

    let mut out = vec![0_u8; MAX_INSTALL_ARCHIVE];
    staging.staged().copy(&mut out);
    assert!(
        out.get(..MAX_INSTALL_ARCHIVE - 8)
            .unwrap()
            .iter()
            .all(|byte| *byte == 7)
    );
    assert!(
        out.get(MAX_INSTALL_ARCHIVE - 8..)
            .unwrap()
            .iter()
            .all(|byte| *byte == 9)
    );
}

/// A second cursor begins at the start again, which is what makes one upload
/// independent of the last: a peer must not inherit where the previous one got to.
#[test]
fn a_second_cursor_begins_at_the_start_of_the_region() {
    let staging = region();
    let mut first = staging.upload().cursor();
    first.write(b"aaaa");
    assert_eq!(first.finish().len(), 4);

    let mut second = staging.upload().cursor();
    assert_eq!(second.written(), 0);
    second.write(b"bb");
    assert_eq!(second.finish().len(), 2);

    let mut out = [0_u8; 4];
    staging.staged().copy(&mut out);
    // The tail of the first upload is still there — the region is not cleared
    // between uploads, and the length the request states is what bounds a reader.
    assert_eq!(&out, b"bbaa");
}

#[test]
fn clearing_leaves_the_region_holding_nothing() {
    let staging = region();
    let mut cursor = staging.upload().cursor();
    cursor.write(&[0xff; 1024]);
    let _placed = cursor.finish();
    staging.upload().clear();
    let mut out = vec![0xaa_u8; 2048];
    staging.staged().copy(&mut out);
    assert!(out.iter().all(|byte| *byte == 0));
}

/// A destination shorter than the region takes a prefix and no more, which is
/// what makes the copy bounded by the caller's storage rather than by the
/// region's size.
#[test]
fn a_short_destination_takes_a_prefix_and_nothing_past_it() {
    let staging = region();
    let mut cursor = staging.upload().cursor();
    cursor.write(&[9_u8; 128]);
    let _placed = cursor.finish();
    let mut out = [0_u8; 16];
    staging.staged().copy(&mut out);
    assert_eq!(out, [9_u8; 16]);
}

/// The writing domain's own read-back is the same view the installing domain
/// gets, which is what lets it validate the bytes that are really in the region
/// rather than an accumulation of its own.
#[test]
fn the_writing_side_reads_back_exactly_what_the_installing_side_would() {
    let staging = region();
    let mut cursor = staging.upload().cursor();
    cursor.write(b"ustar-shaped bytes");
    let _placed = cursor.finish();

    let mut written = [0_u8; 18];
    staging.written().copy(&mut written);
    let mut staged = [0_u8; 18];
    staging.staged().copy(&mut staged);
    assert_eq!(written, staged);
    assert_eq!(&written, b"ustar-shaped bytes");
}

proptest! {
    /// Round trip over arbitrary archives cut into arbitrary segments: what the
    /// region answers is exactly the concatenation, and the token's length is
    /// exactly how much of it fits.
    #[test]
    fn writing_in_segments_and_copying_round_trip(
        segments in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..512),
            0..8,
        ),
    ) {
        let staging = region();
        let mut cursor = staging.upload().cursor();
        let mut expected: Vec<u8> = Vec::new();
        for segment in &segments {
            prop_assert_eq!(cursor.write(segment), segment.len());
            expected.extend_from_slice(segment);
        }
        prop_assert_eq!(cursor.written() as usize, expected.len());
        let staged = cursor.finish();
        prop_assert_eq!(staged.len() as usize, expected.len());
        let mut out: Vec<u8> = vec![0; expected.len()];
        staging.staged().copy(&mut out);
        prop_assert_eq!(out, expected);
    }
}
