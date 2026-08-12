use super::*;
use proptest::prelude::*;

extern crate alloc;
use alloc::vec::Vec;

/// A reading of `count` slots whose values are recognisable at a glance, so a
/// tail left behind by an earlier publish is visible in an assertion.
fn ramp(count: usize, base: u64) -> Vec<u64> {
    (0..count).map(|slot| base + slot as u64).collect()
}

#[test]
fn a_zeroed_region_carries_no_reading() {
    let region = StatsRelay::zero();
    assert_eq!(region.generation(), 0);
    assert_eq!(region.load(RELAY_SLOTS), None);
}

#[test]
fn a_published_reading_is_read_back_whole() {
    let region = StatsRelay::zero();
    let values = ramp(64, 1_000);
    region.publish(1_785_443_220_000_000_000, &values);
    assert_eq!(region.generation(), 2);

    let (generation, image) = region.load(64).expect("a settled reading");
    assert_eq!(generation, 2);
    assert_eq!(image.unix_nanos, 1_785_443_220_000_000_000);
    assert_eq!(image.filled, 64);
    assert_eq!(image.values(), values.as_slice());
}

/// The counter is what tells two readings apart and what paces the reader, so it
/// settles even on every publish.
#[test]
fn every_publish_advances_the_counter_by_two() {
    let region = StatsRelay::zero();
    for round in 1..=8u64 {
        region.publish(round, &ramp(4, round));
        let expected = u32::try_from(round).expect("small") * 2;
        assert_eq!(region.generation(), expected);
        assert!(region.generation().is_multiple_of(2));
        let (generation, image) = region.load(4).expect("a settled reading");
        assert_eq!(generation, expected);
        assert_eq!(image.unix_nanos, round);
        assert_eq!(image.values(), ramp(4, round).as_slice());
    }
}

/// A reading is meaningful only whole, so a reader must never assemble one from
/// two publishes. An odd counter is what a publish in progress looks like.
#[test]
fn a_publish_in_progress_is_not_read_under() {
    let region = StatsRelay::zero();
    region.publish(7, &ramp(8, 1));
    assert!(region.load(8).is_some());

    // A writer that went odd and stopped: what a domain faulting between its
    // first store and its last leaves behind. The region is peer-written, so a
    // reader may not assume it never happens.
    region.generation.store(3, Ordering::Relaxed);
    assert_eq!(region.generation(), 3);
    assert_eq!(region.load(8), None, "a torn reading was accepted");

    // And the next publish recovers it: `| 1` leaves the counter odd from an odd
    // value too, so one interrupted publish does not make the region
    // permanently unreadable.
    region.publish(9, &ramp(8, 100));
    assert_eq!(region.generation(), 4);
    assert_eq!(
        region.load(8).expect("recovered").1.values(),
        ramp(8, 100).as_slice()
    );
}

/// A counter that changes under every attempt is a writer a reader cannot win
/// against, and the retry limit is what keeps that a missed reading rather than a
/// hung domain.
#[test]
fn a_reader_gives_up_after_a_bounded_number_of_attempts() {
    let region = StatsRelay::zero();
    region.publish(1, &ramp(2, 5));

    region.generation.store(u32::MAX, Ordering::Relaxed);
    assert_eq!(region.load(2), None);
    // The counter is left exactly as it was: a reader changes nothing.
    assert_eq!(region.generation.load(Ordering::Relaxed), u32::MAX);
}

/// The counter wraps rather than saturating, and a wrapped one still settles
/// even — a node that published two billion times must not become unreadable.
#[test]
fn the_counter_wraps_to_an_even_value() {
    let region = StatsRelay::zero();
    region.generation.store(u32::MAX - 1, Ordering::Relaxed);
    region.publish(3, &ramp(2, 1));
    assert_eq!(region.generation(), 0);
    // Generation zero reads as "nothing published", which is the one cost of
    // spending a value on that meaning: one reading after two billion publishes.
    assert_eq!(region.load(2), None);
    region.publish(3, &ramp(2, 1));
    assert_eq!(region.generation(), 2);
    assert!(region.load(2).is_some());
}

/// A shorter publish must not leave a longer one's tail behind, or a reader
/// would attribute numbers from an older reading to slots this one never filled.
#[test]
fn a_shorter_publish_zeroes_what_the_longer_one_left() {
    let region = StatsRelay::zero();
    region.publish(1, &ramp(RELAY_SLOTS, 1));
    region.publish(2, &ramp(4, 900));

    let (_generation, image) = region.load(RELAY_SLOTS).expect("a settled reading");
    assert_eq!(image.values().get(..4), Some(ramp(4, 900).as_slice()));
    assert!(
        image.values().iter().skip(4).all(|value| *value == 0),
        "the previous reading's tail survived a shorter publish"
    );
}

/// The writer's slot count is bounded by the region, not by what a caller asked
/// for: the two sides are separate binaries and only this one knows the extent.
#[test]
fn a_publish_longer_than_the_region_is_written_as_far_as_it_reaches() {
    let region = StatsRelay::zero();
    let values = ramp(RELAY_SLOTS + 32, 1);
    region.publish(4, &values);

    let (_generation, image) = region.load(RELAY_SLOTS + 999).expect("a settled reading");
    assert_eq!(image.filled, RELAY_SLOTS, "a reader read past the region");
    assert_eq!(image.values(), &values[..RELAY_SLOTS]);
}

/// A reader asking for fewer slots than were published gets exactly those, and
/// the rest read as zero rather than as whatever the region holds — so a caller
/// cannot accidentally ship slots its own catalogue does not name.
#[test]
fn a_reader_takes_only_the_slots_it_asked_for() {
    let region = StatsRelay::zero();
    region.publish(5, &ramp(RELAY_SLOTS, 1));

    let (_generation, image) = region.load(3).expect("a settled reading");
    assert_eq!(image.filled, 3);
    assert_eq!(image.values(), ramp(3, 1).as_slice());
    assert!(image.slots.iter().skip(3).all(|value| *value == 0));
}

#[test]
fn the_region_is_one_page_and_holds_its_type() {
    assert_eq!(size_of::<StatsRelay>(), MAPPING_ALIGN);
    assert_eq!(align_of::<StatsRelay>(), 64);
    assert_eq!(STATS_RELAY_REGION_SIZE, MAPPING_ALIGN);
    assert_eq!(RELAY_SLOTS * 8 + RELAY_HEADER_BYTES, MAPPING_ALIGN);
}

/// The byte image two domains agree on, asserted rather than assumed. Read back
/// through the atomics rather than through a pointer cast, which is what a
/// `no_std` crate with no `unsafe` can do: the assertion is that each word
/// carries what was put in it at the offset the const block fixes.
#[test]
fn the_byte_image_is_the_layout_the_other_domain_maps() {
    let region = StatsRelay::zero();
    region.publish(0x0102_0304_0506_0708, &[0x1112_1314_1516_1718, 0x21]);
    assert_eq!(
        region.unix_nanos.load(Ordering::Relaxed),
        0x0102_0304_0506_0708
    );
    assert_eq!(
        region.slots[0].load(Ordering::Relaxed),
        0x1112_1314_1516_1718
    );
    assert_eq!(region.slots[1].load(Ordering::Relaxed), 0x21);
    assert_eq!(region._pad.load(Ordering::Relaxed), 0);
}

proptest! {
    /// Every bit pattern of every slot is a number a domain may have counted, so
    /// a publish of arbitrary values is read back exactly and never refused.
    #[test]
    fn an_arbitrary_reading_round_trips_through_the_region(
        unix_nanos in any::<u64>(),
        values in prop::collection::vec(any::<u64>(), 0..=64usize),
    ) {
        let region = StatsRelay::zero();
        region.publish(unix_nanos, &values);
        let (_generation, image) = region.load(values.len()).expect("a settled reading");
        prop_assert_eq!(image.unix_nanos, unix_nanos);
        prop_assert_eq!(image.values(), values.as_slice());
    }

    /// A wholly arbitrary region — every byte of it a peer's choice — is read
    /// totally: an answer or a refusal, never a fault, and never past the extent.
    #[test]
    fn an_arbitrary_region_is_read_totally_and_stays_within_it(
        generation in any::<u32>(),
        unix_nanos in any::<u64>(),
        slots in prop::collection::vec(any::<u64>(), 0..=32usize),
        asked in any::<usize>(),
    ) {
        let region = StatsRelay::zero();
        region.generation.store(generation, Ordering::Relaxed);
        region.unix_nanos.store(unix_nanos, Ordering::Relaxed);
        for (slot, value) in region.slots.iter().zip(&slots) {
            slot.store(*value, Ordering::Relaxed);
        }

        match region.load(asked) {
            Some((seen, image)) => {
                prop_assert_eq!(seen, generation);
                prop_assert!(seen.is_multiple_of(2) && seen != 0);
                prop_assert!(image.filled <= RELAY_SLOTS);
                prop_assert_eq!(image.values().len(), image.filled);
            }
            None => prop_assert!(!generation.is_multiple_of(2) || generation == 0),
        }
    }
}
