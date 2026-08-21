use super::*;
use proptest::prelude::*;

/// The state a domain finds when it maps a region nobody has published into, and
/// the one an appliance with no configuration history has to read.
#[test]
fn a_zeroed_region_records_no_version() {
    assert_eq!(DurableGeneration::zero().recorded(), 0);
}

#[test]
fn a_published_generation_is_read_back() {
    let region = DurableGeneration::zero();
    region.publish(7);
    assert_eq!(region.recorded(), 7);
}

/// The writer can also state the absence, and it reads back as the zeroed region
/// does — a medium whose array was emptied by a factory reset records no version,
/// and that is the same answer as one that never held any.
#[test]
fn a_published_absence_reads_as_no_version() {
    let region = DurableGeneration::zero();
    region.publish(4);
    region.publish(0);
    assert_eq!(region.recorded(), 0);
}

proptest! {
    /// The whole of what makes this region safe to map read-only into the domain
    /// that numbers configurations: a compromised writer chooses this word, and
    /// every value it can choose is read back as the number it is rather than
    /// decoded, so there is no pattern here to reject and none to fault on.
    #[test]
    fn any_word_reads_back_as_itself(word: u64) {
        let region = DurableGeneration::zero();
        region.publish(word);
        prop_assert_eq!(region.recorded(), word);
    }

    /// A writer publishing repeatedly leaves the region saying what it last said,
    /// with no accumulated state — there being none to accumulate. The writer is
    /// the only thing that decides whether the number rises, which is why nothing
    /// here enforces that it does.
    #[test]
    fn the_region_carries_the_last_publication(generations: Vec<u64>) {
        let region = DurableGeneration::zero();
        let mut last = 0;
        for generation in generations {
            region.publish(generation);
            last = generation;
        }
        prop_assert_eq!(region.recorded(), last);
    }
}
