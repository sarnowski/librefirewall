use super::*;
use proptest::prelude::*;

/// The state a domain finds when it maps a region nobody has published into,
/// and the one a firewall has to read as forwarding nothing.
#[test]
fn a_zeroed_region_reads_as_unowned() {
    assert!(!ApplianceOwnership::zero().owned());
}

#[test]
fn a_published_owner_is_read_back() {
    let region = ApplianceOwnership::zero();
    region.publish(true);
    assert!(region.owned());
}

/// The writer can also state the negative, and it reads back as the zeroed
/// region does — the two are one answer, which is what keeps the reader from
/// having a third case to decide about.
#[test]
fn a_published_absence_reads_as_unowned() {
    let region = ApplianceOwnership::zero();
    region.publish(true);
    region.publish(false);
    assert!(!region.owned());
}

/// The whole of what makes this region safe to map read-only into the domain
/// that decides frames: the writer is a peer, so every one of the four billion
/// words it can put here is input, and exactly one of them means owned.
#[test]
fn only_the_token_means_owned() {
    let region = ApplianceOwnership::zero();
    for word in [0, 1, 2, u32::MAX, OWNED_TOKEN ^ 1, OWNED_TOKEN.swap_bytes()] {
        region.word.store(word, Ordering::Relaxed);
        assert!(
            !region.owned(),
            "the word {word:#x} was read as an owner and only {OWNED_TOKEN:#x} may be"
        );
    }
    region.word.store(OWNED_TOKEN, Ordering::Relaxed);
    assert!(region.owned());
}

proptest! {
    /// The property stated over the whole input space rather than over the six
    /// words above: a compromised writer chooses this word, and its only reach
    /// is between the two answers.
    #[test]
    fn any_word_but_the_token_reads_as_unowned(word: u32) {
        let region = ApplianceOwnership::zero();
        region.word.store(word, Ordering::Relaxed);
        prop_assert_eq!(region.owned(), word == OWNED_TOKEN);
    }

    /// A writer publishing repeatedly leaves the region saying what it last
    /// said, with no accumulated state — there being none to accumulate.
    #[test]
    fn the_region_carries_the_last_publication(states: Vec<bool>) {
        let region = ApplianceOwnership::zero();
        let mut last = false;
        for state in states {
            region.publish(state);
            last = state;
        }
        prop_assert_eq!(region.owned(), last);
    }
}
