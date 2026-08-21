use core::num::NonZeroU64;

use lfw_clock::{Calibration, Duration, Monotonic, NANOS_PER_SECOND, Ticks};
use proptest::prelude::*;

use super::{INITIAL_BACKOFF, MAX_BACKOFF, REDIAL_CEILING, Reconnect, Wait};

/// An instant, through the one path a `Monotonic` is reachable by — so a test
/// states one the way a caller of this crate would.
fn at(nanos: u64) -> Monotonic {
    let hz = NonZeroU64::new(NANOS_PER_SECOND).expect("a nonzero frequency");
    Calibration::new(hz, Ticks(0), 0).monotonic(Ticks(nanos))
}

/// A boot dials at once: the backoff spaces out *re*-dials, and an appliance
/// that waited before its first attempt would come up slower for nothing.
#[test]
fn a_fresh_schedule_is_due_immediately_and_at_its_floor() {
    let schedule = Reconnect::new(0x1234_5678_9abc_def0);
    assert!(schedule.due(at(0)));
    assert_eq!(schedule.bound(), INITIAL_BACKOFF);
    assert_eq!(schedule.remaining(at(0)), None);
}

/// The bound doubles per failure and stops at the cap, and every draw lands
/// inside the bound it was taken below.
#[test]
fn the_bound_doubles_per_failure_and_holds_at_the_cap() {
    let mut schedule = Reconnect::new(0xfeed_face_dead_beef);
    let mut now = at(0);
    let mut bounds = Vec::new();
    for _ in 0..24 {
        let wait = schedule.failed(now);
        assert!(
            wait.delay.as_nanos() <= wait.bound.as_nanos(),
            "a draw left the interval it was taken from: {wait:?}"
        );
        bounds.push(wait.bound);
        // The attempt is not due until the drawn delay has passed, and it is due
        // the instant it has.
        assert_eq!(schedule.due(now), wait.delay.as_nanos() == 0);
        now = now.saturating_add(wait.delay);
        assert!(schedule.due(now));
    }
    assert_eq!(bounds[0], INITIAL_BACKOFF);
    assert_eq!(bounds[1].as_nanos(), INITIAL_BACKOFF.as_nanos() * 2);
    assert_eq!(bounds[2].as_nanos(), INITIAL_BACKOFF.as_nanos() * 4);
    // And it never climbs past the cap however many attempts are spent.
    assert!(bounds.iter().all(|bound| *bound <= MAX_BACKOFF));
    assert_eq!(*bounds.last().expect("attempts were spent"), MAX_BACKOFF);
    assert_eq!(schedule.bound(), MAX_BACKOFF);
}

/// **A greeting is the only reset.** A schedule that had climbed to the cap
/// returns to its floor and is due at once — and nothing else does that, which
/// is what keeps a server that closes every connection from inviting a tight
/// redial loop.
#[test]
fn only_an_agreed_greeting_puts_the_schedule_back_on_its_floor() {
    let mut schedule = Reconnect::new(1);
    let mut now = at(0);
    for _ in 0..16 {
        let wait = schedule.failed(now);
        now = now.saturating_add(wait.delay);
    }
    assert_eq!(schedule.bound(), MAX_BACKOFF);
    // A further failure is still the cap: failing does not reset anything.
    let wait = schedule.failed(now);
    assert_eq!(wait.bound, MAX_BACKOFF);
    assert!(!schedule.due(now) || wait.delay.as_nanos() == 0);

    schedule.established();
    assert_eq!(schedule.bound(), INITIAL_BACKOFF);
    assert!(schedule.due(now), "a reset schedule waits for nothing");
    assert_eq!(schedule.failed(now).bound, INITIAL_BACKOFF);
}

/// The wait a console reports carries both numbers, in milliseconds, and they
/// are the two the schedule really used.
#[test]
fn a_wait_reports_the_delay_it_drew_and_the_bound_it_drew_below() {
    let wait = Wait {
        delay: Duration::from_millis(1_500),
        bound: Duration::from_millis(4_000),
    };
    assert_eq!(wait.delay_millis(), 1_500);
    assert_eq!(wait.bound_millis(), 4_000);
    // The cap, as an operator reads it: five minutes.
    assert_eq!(
        Wait {
            delay: MAX_BACKOFF,
            bound: MAX_BACKOFF
        }
        .bound_millis(),
        300_000
    );
}

/// What a re-dial costs is the transport's hold plus the first wait, and it is
/// read out of both rather than restated. A caller derives a promise from it —
/// the shortest confirmation window this appliance will accept — so a term
/// dropped from the sum, or a sum that stopped being their total, is what this
/// holds it to.
#[test]
fn a_redial_costs_the_transport_hold_and_one_wait_below_the_floor() {
    assert_eq!(
        REDIAL_CEILING.as_nanos(),
        lfw_tcp::TIME_WAIT_DURATION.as_nanos() + INITIAL_BACKOFF.as_nanos()
    );
    // And the schedule really does draw that first wait below the term the sum
    // used: the reset a greeting makes is what puts it back there, so a re-dial
    // after a working channel is bounded by the floor and not by whatever the
    // backoff had doubled to.
    let mut schedule = Reconnect::new(0x5eed_0000_0000_0001);
    let now = at(0);
    for _ in 0..8 {
        let _ = schedule.failed(now);
    }
    assert!(schedule.bound() > INITIAL_BACKOFF);
    schedule.established();
    assert_eq!(schedule.failed(now).bound, INITIAL_BACKOFF);
}

/// Two appliances seeded differently do not redial together, which is the whole
/// of what the jitter buys: a fleet disconnected at once must not come back at
/// once.
#[test]
fn two_schedules_seeded_differently_draw_different_delays() {
    let mut one = Reconnect::new(0x0123_4567_89ab_cdef);
    let mut other = Reconnect::new(0xfedc_ba98_7654_3210);
    let now = at(0);
    let differ = (0..8)
        .filter(|_| one.failed(now).delay != other.failed(now).delay)
        .count();
    assert!(
        differ >= 6,
        "two differently seeded schedules drew the same delay {} times of 8",
        8 - differ
    );
}

/// A part whose generator answered zero still spreads: the seed is displaced
/// rather than used raw, so a fleet of such parts does not redial in lockstep
/// with a fleet of any other.
#[test]
fn a_zero_seed_still_draws_a_spread_of_delays() {
    let mut schedule = Reconnect::new(0);
    let now = at(0);
    let mut drawn: Vec<u64> = (0..8)
        .map(|_| schedule.failed(now).delay.as_nanos())
        .collect();
    drawn.sort_unstable();
    let count = drawn.len();
    drawn.dedup();
    assert_eq!(drawn.len(), count, "a zero seed produced a repeated delay");
}

proptest! {
    /// Whatever the seed and however many attempts are spent, every draw is
    /// inside the interval the contract states, the bound never leaves its two
    /// ends, and nothing panics.
    #[test]
    fn every_draw_lands_inside_the_bound_it_was_taken_below(
        seed in any::<u64>(),
        attempts in 0usize..64,
    ) {
        let mut schedule = Reconnect::new(seed);
        let mut now = at(0);
        for _ in 0..attempts {
            let wait = schedule.failed(now);
            prop_assert!(wait.bound >= INITIAL_BACKOFF);
            prop_assert!(wait.bound <= MAX_BACKOFF);
            prop_assert!(wait.delay <= wait.bound);
            // The next attempt is due exactly when the delay has passed, and not
            // before it.
            prop_assert!(!schedule.due(now) || wait.delay.as_nanos() == 0);
            now = now.saturating_add(wait.delay);
            prop_assert!(schedule.due(now));
        }
    }
}
