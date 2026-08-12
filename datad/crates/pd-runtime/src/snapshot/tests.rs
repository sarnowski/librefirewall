use super::*;

use lfw_clock::{Calibration, Ticks};
use lfw_metrics::{SHARD_COUNT, SNAPSHOT_SLOTS, StatsShard};
use std::vec::Vec;

/// A calibration whose numbers make a tick a nanosecond, so a test names an
/// instant in the unit it reasons in.
fn calibration() -> Calibration {
    Calibration::new(
        core::num::NonZeroU64::new(1_000_000_000).expect("nonzero"),
        Ticks(0),
        1_700_000_000_000_000_000,
    )
}

fn at(nanos: u64) -> Monotonic {
    calibration().monotonic(Ticks(nanos))
}

/// Twelve shards a test owns, and the borrowed view over them the domain holds.
struct Shards(Vec<StatsShard>);

impl Shards {
    fn new() -> Self {
        Self((0..SHARD_COUNT).map(|_| StatsShard::zero()).collect())
    }

    fn regions(&self) -> StatsRegions<'_> {
        let mut shards = [&self.0[0]; SHARD_COUNT];
        for (slot, shard) in shards.iter_mut().zip(&self.0) {
            *slot = shard;
        }
        StatsRegions { shards }
    }
}

#[test]
fn the_first_pass_publishes_whatever_the_clock_says() {
    for now in [None, Some(at(0)), Some(at(5_000_000_000))] {
        let shards = Shards::new();
        let relay = StatsRelay::zero();
        let mut schedule = SnapshotSchedule::new();
        assert!(
            schedule.publish_due(now, None, &shards.regions(), &relay),
            "the first reading was withheld for {now:?}"
        );
        assert_eq!(relay.generation(), 2);
    }
}

/// The cadence is the whole of this type: a pass inside the period publishes
/// nothing, and the first one past it publishes.
#[test]
fn a_reading_goes_once_per_period_and_not_once_per_pass() {
    let shards = Shards::new();
    let relay = StatsRelay::zero();
    let mut schedule = SnapshotSchedule::new();

    assert!(schedule.publish_due(Some(at(0)), None, &shards.regions(), &relay));
    for inside in [1, 500_000_000, SNAPSHOT_PERIOD.as_nanos() - 1] {
        assert!(
            !schedule.publish_due(Some(at(inside)), None, &shards.regions(), &relay),
            "a reading went {inside} ns into the period"
        );
    }
    assert_eq!(
        relay.generation(),
        2,
        "only the first reading was published"
    );

    assert!(schedule.publish_due(
        Some(at(SNAPSHOT_PERIOD.as_nanos())),
        None,
        &shards.regions(),
        &relay
    ));
    assert_eq!(relay.generation(), 4);
}

/// A node whose clock domain has published nothing gets exactly one reading:
/// what the counters read before time was established is worth more than
/// nothing, and a second would need a period nothing can measure.
#[test]
fn an_unclocked_node_publishes_one_reading_and_no_more() {
    let shards = Shards::new();
    let relay = StatsRelay::zero();
    let mut schedule = SnapshotSchedule::new();

    assert!(schedule.publish_due(None, None, &shards.regions(), &relay));
    for _ in 0..8 {
        assert!(!schedule.publish_due(None, None, &shards.regions(), &relay));
    }
    assert_eq!(relay.generation(), 2);

    // And the first clocked pass publishes, the boot origin being a whole
    // period behind any instant a calibration names.
    assert!(schedule.publish_due(
        Some(at(SNAPSHOT_PERIOD.as_nanos())),
        None,
        &shards.regions(),
        &relay
    ));
}

/// A calibration replaced under a running node can name an instant behind the
/// last one. That is not a reason to publish twice in a period.
#[test]
fn an_instant_behind_the_last_one_does_not_publish_early() {
    let shards = Shards::new();
    let relay = StatsRelay::zero();
    let mut schedule = SnapshotSchedule::new();

    assert!(schedule.publish_due(Some(at(10_000_000_000)), None, &shards.regions(), &relay));
    assert!(!schedule.publish_due(Some(at(0)), None, &shards.regions(), &relay));
    assert_eq!(relay.generation(), 2);
}

/// The reading carries what the shards hold and the instant it was taken at, and
/// a reader takes both back whole.
#[test]
fn the_published_reading_is_the_shards_and_the_instant() {
    let shards = Shards::new();
    shards.0[0].publish(&[11, 22, 33]);
    let relay = StatsRelay::zero();
    let mut schedule = SnapshotSchedule::new();

    let utc = UtcNanos::from_unix_nanos(1_785_443_220_000_000_000);
    assert!(schedule.publish_due(Some(at(0)), Some(utc), &shards.regions(), &relay));

    let (_generation, image) = relay.load(SNAPSHOT_SLOTS).expect("a settled reading");
    assert_eq!(image.unix_nanos, utc.as_nanos());
    assert_eq!(image.values().get(..3), Some(&[11u64, 22, 33][..]));
    assert_eq!(image.filled, SNAPSHOT_SLOTS);
}

/// No calibration is a zero instant rather than a counter reading dressed as a
/// time: a reader states what it was given and repairs nothing.
#[test]
fn an_unclocked_reading_states_no_instant() {
    let shards = Shards::new();
    let relay = StatsRelay::zero();
    let mut schedule = SnapshotSchedule::new();
    assert!(schedule.publish_due(None, None, &shards.regions(), &relay));
    assert_eq!(
        relay.load(SNAPSHOT_SLOTS).expect("a reading").1.unix_nanos,
        0
    );
}
