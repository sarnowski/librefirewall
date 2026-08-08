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
fn what_is_staged_is_what_comes_back_and_the_token_states_its_length() {
    let staging = region();
    let archive = [0xa5_u8; 4096];
    let staged = staging.upload().stage(&archive);
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

/// The one bound the writing side has, and it is the region's rather than the
/// caller's claim: a caller handing over more than fits gets a token naming what
/// was really stored, so the length a request states can never exceed the region.
#[test]
fn an_over_long_archive_is_truncated_and_the_token_says_so() {
    let staging = region();
    let too_much = vec![7_u8; MAX_INSTALL_ARCHIVE + 512];
    let staged = staging.upload().stage(&too_much);
    assert_eq!(staged.len() as usize, MAX_INSTALL_ARCHIVE);

    let mut out = vec![0_u8; MAX_INSTALL_ARCHIVE];
    staging.staged().copy(&mut out);
    assert!(out.iter().all(|byte| *byte == 7));
}

#[test]
fn staging_nothing_yields_an_empty_token_and_leaves_the_region_alone() {
    let staging = region();
    let _placed = staging.upload().stage(&[1, 2, 3]);
    let staged = staging.upload().stage(&[]);
    assert_eq!(staged.len(), 0);
    assert!(staged.is_empty());
    let mut out = [0_u8; 3];
    staging.staged().copy(&mut out);
    assert_eq!(out, [1, 2, 3]);
}

#[test]
fn clearing_leaves_the_region_holding_nothing() {
    let staging = region();
    let _placed = staging.upload().stage(&[0xff; 1024]);
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
    let _placed = staging.upload().stage(&[9_u8; 128]);
    let mut out = [0_u8; 16];
    staging.staged().copy(&mut out);
    assert_eq!(out, [9_u8; 16]);
}

proptest! {
    /// Round trip over arbitrary archives: what the region answers is exactly
    /// what was staged, and the token's length is exactly how much of it fits.
    #[test]
    fn staging_and_copying_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let staging = region();
        let staged = staging.upload().stage(&bytes);
        prop_assert_eq!(staged.len() as usize, bytes.len());
        let mut out: Vec<u8> = vec![0; bytes.len()];
        staging.staged().copy(&mut out);
        prop_assert_eq!(out, bytes);
    }
}
