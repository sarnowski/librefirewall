use super::*;

use lfw_clock::{
    MAX_PLAUSIBLE_TSC_HZ, MAX_PLAUSIBLE_UNIX_NANOS, MIN_PLAUSIBLE_TSC_HZ, MIN_PLAUSIBLE_UNIX_NANOS,
    NANOS_PER_SECOND, UtcNanos, epoch_is_plausible,
};
use lfw_log::Clock as _;
use proptest::prelude::*;
use wire::CalibrationImage;

const ONE_GHZ: u64 = 1_000_000_000;

/// An epoch inside the plausible band, so a test about the *frequency* is not
/// also a test about the epoch.
const EPOCH: u64 = 1_785_443_220 * NANOS_PER_SECOND;

fn published(image: CalibrationImage) -> ClockCalibration {
    let region = ClockCalibration::zero();
    region.publish(&image);
    region
}

fn plausible(boot_unix_nanos: u64) -> CalibrationImage {
    CalibrationImage {
        tsc_hz: ONE_GHZ,
        boot_ticks: 0,
        boot_unix_nanos,
    }
}

#[test]
fn an_unpublished_region_yields_no_instant_rather_than_the_epoch() {
    let region = ClockCalibration::zero();
    let clock = PdClock::new(&region);
    assert_eq!(clock.calibration(), None);
    assert_eq!(clock.now(), Stamp::Unsynchronized);
}

/// The refusal that matters most: a triple whose frequency is outside the band
/// would scale every reading, so it is answered exactly as no triple at all.
#[test]
fn a_frequency_outside_the_band_yields_no_instant() {
    for tsc_hz in [
        1,
        MIN_PLAUSIBLE_TSC_HZ - 1,
        MAX_PLAUSIBLE_TSC_HZ + 1,
        u64::MAX,
    ] {
        let region = published(CalibrationImage {
            tsc_hz,
            boot_ticks: 0,
            boot_unix_nanos: EPOCH,
        });
        let clock = PdClock::new(&region);
        assert_eq!(clock.calibration(), None, "{tsc_hz} Hz");
        assert_eq!(clock.now(), Stamp::Unsynchronized, "{tsc_hz} Hz");
    }
}

/// The other half of the same judgement, and the one a byzantine writing domain
/// reaches most cheaply: a frequency ranged while its epoch is believed lets a
/// peer date every record this domain emits anywhere `u64` nanoseconds reach. The
/// band is the one the clock domain refuses a register file's year against, so the
/// two ends of the region apply one judgement.
#[test]
fn an_epoch_outside_the_band_yields_no_instant() {
    for boot_unix_nanos in [
        0,
        1,
        MIN_PLAUSIBLE_UNIX_NANOS - 1,
        MAX_PLAUSIBLE_UNIX_NANOS + 1,
        u64::MAX,
    ] {
        let region = published(CalibrationImage {
            tsc_hz: ONE_GHZ,
            boot_ticks: 0,
            boot_unix_nanos,
        });
        let clock = PdClock::new(&region);
        assert_eq!(clock.calibration(), None, "{boot_unix_nanos} ns");
        assert_eq!(clock.now(), Stamp::Unsynchronized, "{boot_unix_nanos} ns");
    }
}

#[test]
fn both_ends_of_the_epoch_band_are_accepted() {
    for boot_unix_nanos in [MIN_PLAUSIBLE_UNIX_NANOS, MAX_PLAUSIBLE_UNIX_NANOS] {
        let region = published(CalibrationImage {
            tsc_hz: ONE_GHZ,
            boot_ticks: 0,
            boot_unix_nanos,
        });
        assert!(
            PdClock::new(&region).calibration().is_some(),
            "{boot_unix_nanos} ns"
        );
    }
}

#[test]
fn both_ends_of_the_band_are_accepted() {
    for tsc_hz in [MIN_PLAUSIBLE_TSC_HZ, MAX_PLAUSIBLE_TSC_HZ] {
        let region = published(CalibrationImage {
            tsc_hz,
            boot_ticks: 0,
            boot_unix_nanos: EPOCH,
        });
        assert!(PdClock::new(&region).calibration().is_some(), "{tsc_hz} Hz");
    }
}

/// The instant a stamp carries is the published epoch advanced by the counter,
/// which is what makes a record's time the node's own arithmetic rather than a
/// number the clock domain wrote once.
#[test]
fn a_published_calibration_yields_an_instant_at_or_after_its_epoch() {
    let epoch = EPOCH;
    let region = published(plausible(epoch));
    let clock = PdClock::new(&region);
    let Stamp::Utc(utc) = clock.now() else {
        panic!("a published calibration stamps a record");
    };
    assert!(utc >= UtcNanos::from_unix_nanos(epoch));
}

/// The counter runs, so two readings taken in order are in order. It is the one
/// property a stamped record's monotonicity rests on, and it is the reason the
/// calibration is read afresh rather than cached alongside a reading.
#[test]
fn successive_stamps_do_not_go_backwards() {
    let region = published(plausible(EPOCH));
    let clock = PdClock::new(&region);
    let mut previous = clock.now();
    for _ in 0..1_000 {
        let current = clock.now();
        assert!(current >= previous, "{current:?} preceded {previous:?}");
        previous = current;
    }
}

#[test]
fn the_counter_advances() {
    let first = read_timestamp_counter();
    let second = read_timestamp_counter();
    assert!(second.0 >= first.0);
}

/// A republished triple is picked up without the domain being told, which is
/// what "read afresh" buys and what a cache would cost.
#[test]
fn a_republished_calibration_is_read_on_the_next_question() {
    let region = ClockCalibration::zero();
    let clock = PdClock::new(&region);
    assert_eq!(clock.now(), Stamp::Unsynchronized);
    region.publish(&plausible(EPOCH));
    assert!(matches!(clock.now(), Stamp::Utc(_)));
    region.publish(&CalibrationImage {
        tsc_hz: 0,
        boot_ticks: 0,
        boot_unix_nanos: 0,
    });
    assert_eq!(clock.now(), Stamp::Unsynchronized);
}

proptest! {
    /// Total over the whole triple a peer can write: every one of them yields a
    /// stamp or the absence of one, and never a panic.
    #[test]
    fn any_published_triple_yields_a_stamp_or_none(
        tsc_hz in any::<u64>(),
        boot_ticks in any::<u64>(),
        boot_unix_nanos in any::<u64>(),
    ) {
        let region = published(CalibrationImage { tsc_hz, boot_ticks, boot_unix_nanos });
        let clock = PdClock::new(&region);
        let stamp = clock.now();
        let inside = (MIN_PLAUSIBLE_TSC_HZ..=MAX_PLAUSIBLE_TSC_HZ).contains(&tsc_hz)
            && epoch_is_plausible(boot_unix_nanos);
        prop_assert_eq!(matches!(stamp, Stamp::Utc(_)), inside);
        // An accepted triple never places the node before the epoch it named:
        // the conversion adds an elapsed count and saturates upward.
        if let Stamp::Utc(utc) = stamp {
            prop_assert!(utc >= UtcNanos::from_unix_nanos(boot_unix_nanos));
        }
    }
}
