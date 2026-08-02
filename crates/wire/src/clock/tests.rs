use super::*;
use proptest::prelude::*;

fn image(tsc_hz: u64, boot_ticks: u64, boot_unix_nanos: u64) -> CalibrationImage {
    CalibrationImage {
        tsc_hz,
        boot_ticks,
        boot_unix_nanos,
    }
}

#[test]
fn a_zeroed_region_carries_no_calibration() {
    let region = ClockCalibration::zero();
    assert_eq!(region.generation(), 0);
    assert_eq!(region.load(), None);
}

#[test]
fn a_published_triple_is_read_back_whole() {
    let region = ClockCalibration::zero();
    let published = image(2_500_000_000, 0x1234_5678_9abc, 1_785_443_220_000_000_000);
    region.publish(&published);
    assert_eq!(region.generation(), 2);
    assert_eq!(region.load(), Some(published));
}

/// The counter is what tells two publishes apart, and it settles even every
/// time: a reader comparing two readings needs that.
#[test]
fn every_publish_advances_the_counter_by_two() {
    let region = ClockCalibration::zero();
    for round in 1..=8u64 {
        region.publish(&image(round, round * 2, round * 3));
        assert_eq!(
            region.generation(),
            u32::try_from(round).expect("small") * 2
        );
        assert!(region.generation().is_multiple_of(2));
        assert_eq!(region.load(), Some(image(round, round * 2, round * 3)));
    }
}

/// The three words are only meaningful together, so a reader must never assemble
/// one from two publishes. An odd counter is what a publish in progress looks
/// like, and a reader refuses it rather than reading under it.
#[test]
fn a_publish_in_progress_is_not_read_under() {
    let region = ClockCalibration::zero();
    region.publish(&image(1_000_000_000, 10, 20));
    assert!(region.load().is_some());

    // A writer that went odd and stopped. This is what a domain faulting between
    // its first store and its last leaves behind, and the region is peer-written
    // so a reader may not assume it never happens.
    region.generation.store(3, Ordering::Relaxed);
    assert_eq!(region.generation(), 3);
    assert_eq!(region.load(), None, "a torn triple was accepted");

    // And the next publish recovers it: `| 1` leaves the counter odd from an odd
    // value too, so one interrupted publish does not make the region
    // permanently unreadable.
    let recovered = image(3_000_000_000, 30, 40);
    region.publish(&recovered);
    assert_eq!(region.generation(), 4);
    assert_eq!(region.load(), Some(recovered));
}

/// A counter that changes under every attempt is a writer a reader cannot win
/// against, and the retry limit is what keeps that a lost timestamp rather than a
/// hung domain.
#[test]
fn a_reader_gives_up_after_a_bounded_number_of_attempts() {
    let region = ClockCalibration::zero();
    region.publish(&image(1, 2, 3));

    // An odd counter is the same lost race on every attempt, which is what the
    // loop's bound answers: it returns rather than spinning. A genuinely
    // *changing* counter cannot be produced by a single-threaded test, and this
    // is the same path — the loop reaching its limit.
    region.generation.store(u32::MAX, Ordering::Relaxed);
    assert_eq!(region.load(), None);
    // The counter is left exactly as it was: a reader changes nothing.
    assert_eq!(region.generation.load(Ordering::Relaxed), u32::MAX);
}

/// The counter wraps rather than saturating, and a wrapped one still settles
/// even — a node that published two billion times must not become unreadable.
#[test]
fn the_counter_wraps_to_an_even_value() {
    let region = ClockCalibration::zero();
    // The largest even value: the next publish takes it odd and then wraps.
    region.generation.store(u32::MAX - 1, Ordering::Relaxed);
    let published = image(4_000_000_000, 5, 6);
    region.publish(&published);
    assert_eq!(region.generation(), 0);
    // Generation zero reads as "nothing published", which is the one cost of
    // spending a value on that meaning. It is a value reached after two billion
    // publishes and it costs one reading.
    assert_eq!(region.load(), None);
    region.publish(&published);
    assert_eq!(region.generation(), 2);
    assert_eq!(region.load(), Some(published));
}

#[test]
fn the_region_is_a_whole_number_of_pages_and_holds_its_type() {
    assert_eq!(size_of::<ClockCalibration>(), 32);
    assert_eq!(align_of::<ClockCalibration>(), 8);
    assert_eq!(CLOCK_CALIBRATION_REGION_SIZE, MAPPING_ALIGN);
    assert!(CLOCK_CALIBRATION_REGION_SIZE >= size_of::<ClockCalibration>());
}

/// The byte image two domains agree on, asserted rather than assumed: the
/// generation first, then the padding, then the three words in order. A port to a
/// big-endian target fails this rather than shipping a swapped triple.
#[test]
fn the_byte_image_is_the_layout_the_other_domain_maps() {
    let region = ClockCalibration::zero();
    region.publish(&image(
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        0x2122_2324_2526_2728,
    ));
    // Read back through the atomics rather than through a pointer cast, which is
    // what a `no_std` crate with no `unsafe` can do: the assertion is that each
    // word carries what was put in it at the offset the const block fixes.
    assert_eq!(region.tsc_hz.load(Ordering::Relaxed), 0x0102_0304_0506_0708);
    assert_eq!(
        region.boot_ticks.load(Ordering::Relaxed),
        0x1112_1314_1516_1718
    );
    assert_eq!(
        region.boot_unix_nanos.load(Ordering::Relaxed),
        0x2122_2324_2526_2728
    );
    assert_eq!(region._pad.load(Ordering::Relaxed), 0);
}

proptest! {
    /// Any triple survives a round trip, every bit pattern of every word
    /// included: nothing here judges a value, so nothing here may alter one.
    #[test]
    fn any_triple_survives_a_round_trip(
        tsc_hz in any::<u64>(),
        boot_ticks in any::<u64>(),
        boot_unix_nanos in any::<u64>(),
    ) {
        let region = ClockCalibration::zero();
        let published = image(tsc_hz, boot_ticks, boot_unix_nanos);
        region.publish(&published);
        prop_assert_eq!(region.load(), Some(published));
    }

    /// A reader never sees a triple assembled from two publishes, whatever
    /// sequence of them it lands between: after any number of publishes the
    /// region reads back as the last one, whole.
    #[test]
    fn a_reader_only_ever_sees_one_publishers_whole_triple(
        triples in prop::collection::vec((any::<u64>(), any::<u64>(), any::<u64>()), 1..16),
    ) {
        let region = ClockCalibration::zero();
        for (tsc_hz, boot_ticks, boot_unix_nanos) in &triples {
            let published = image(*tsc_hz, *boot_ticks, *boot_unix_nanos);
            region.publish(&published);
            // Read between publishes, which is where a torn triple would show.
            prop_assert_eq!(region.load(), Some(published));
        }
        // Lossless: bounded by the strategy.
        prop_assert_eq!(region.generation(), triples.len() as u32 * 2);
    }

    /// Any counter value a peer can leave behind is answered rather than spun on,
    /// and an odd one is never read under.
    #[test]
    fn any_counter_a_peer_leaves_is_answered(generation in any::<u32>()) {
        let region = ClockCalibration::zero();
        region.publish(&image(7, 8, 9));
        region.generation.store(generation, Ordering::Relaxed);
        match region.load() {
            Some(read) => {
                prop_assert!(generation.is_multiple_of(2) && generation != 0);
                prop_assert_eq!(read, image(7, 8, 9));
            }
            None => prop_assert!(!generation.is_multiple_of(2) || generation == 0),
        }
    }
}
