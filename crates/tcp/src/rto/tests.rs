use super::*;
use proptest::prelude::*;

#[test]
fn a_fresh_timer_carries_the_initial_timeout_and_no_measurement() {
    let timer = RetransmissionTimer::new();
    assert_eq!(timer.timeout(), INITIAL_RTO);
    assert_eq!(timer.backoff(), 0);
    assert!(!timer.measured());
    assert_eq!(timer, RetransmissionTimer::default());
}

/// RFC 6298 section 2.2 worked through: a 400 ms sample gives SRTT 400 ms,
/// RTTVAR 200 ms, and RTO = 400 + 4*200 = 1200 ms — above the floor, so the
/// clamp does not hide the arithmetic.
#[test]
fn the_first_measurement_follows_the_initialisation_rule() {
    let mut timer = RetransmissionTimer::new();
    timer.measure(Duration::from_millis(400));
    assert!(timer.measured());
    assert_eq!(timer.timeout(), Duration::from_millis(1_200));
}

/// section 2.3 worked through from the state above: a second 400 ms sample leaves SRTT
/// at 400 ms and shrinks RTTVAR to 3/4 of 200 ms, so RTO = 400 + 4*150 = 1000 ms.
#[test]
fn a_repeated_sample_shrinks_the_variance() {
    let mut timer = RetransmissionTimer::new();
    timer.measure(Duration::from_millis(400));
    timer.measure(Duration::from_millis(400));
    assert_eq!(timer.timeout(), Duration::from_millis(1_000));
}

/// A sample far from the estimate widens the variance rather than moving the
/// estimate to it, which is the whole point of the smoothing: one slow
/// acknowledgement must not make the timeout track it.
#[test]
fn one_outlying_sample_widens_the_variance_rather_than_the_estimate() {
    let mut timer = RetransmissionTimer::new();
    timer.measure(Duration::from_millis(100));
    let after_first = timer.timeout();
    timer.measure(Duration::from_millis(2_000));
    assert!(
        timer.timeout() > after_first,
        "{:?} did not exceed {after_first:?}",
        timer.timeout()
    );
    // SRTT moved by only an eighth of the difference: 100 + 1900/8 = 337.5 ms,
    // so the timeout is nowhere near the 2 s sample plus four variances.
    assert!(timer.timeout() < Duration::from_millis(2_400));
}

/// section 2.4's floor, which a fast local peer reaches immediately: a zero sample
/// gives SRTT 0 and RTTVAR 0, so the formula yields the clock granularity and
/// the clamp lifts it to the minimum.
#[test]
fn a_zero_sample_is_lifted_to_the_floor() {
    let mut timer = RetransmissionTimer::new();
    timer.measure(Duration::from_nanos(0));
    assert_eq!(timer.timeout(), MIN_RTO);
}

/// section 5.5's backoff doubles and then holds at the ceiling, and the count is what a
/// caller's retry limit is compared against.
#[test]
fn the_backoff_doubles_and_saturates_at_the_ceiling() {
    let mut timer = RetransmissionTimer::new();
    let mut previous = timer.timeout();
    for expected in 1..=6 {
        timer.back_off();
        assert_eq!(timer.backoff(), expected);
        assert!(timer.timeout() >= previous);
        previous = timer.timeout();
    }
    for _ in 0..64 {
        timer.back_off();
    }
    assert_eq!(timer.timeout(), MAX_RTO);
}

/// section 5.3: a measurement after a backoff restarts from the measured path rather
/// than from the doubled guess, so one lost segment does not leave a connection
/// slow for the rest of its life.
#[test]
fn a_measurement_clears_the_backoff() {
    let mut timer = RetransmissionTimer::new();
    timer.back_off();
    timer.back_off();
    assert_eq!(timer.backoff(), 2);
    timer.measure(Duration::from_millis(400));
    assert_eq!(timer.backoff(), 0);
    assert_eq!(timer.timeout(), Duration::from_millis(1_200));
}

/// `recompute` cannot be reached without a measurement, and the guard that says
/// so must leave the timer alone rather than produce a timeout from nothing.
/// Driven directly because no public path reaches it.
#[test]
fn recomputing_without_a_measurement_changes_nothing() {
    let mut timer = RetransmissionTimer::new();
    timer.recompute();
    assert_eq!(timer, RetransmissionTimer::new());
}

proptest! {
    /// The timeout is inside RFC 6298's band after any sequence of arbitrary
    /// samples and backoffs. This is the property a retransmission storm would
    /// break: a wrapped computation lands below the floor.
    #[test]
    fn the_timeout_stays_inside_the_band(
        samples in prop::collection::vec(any::<u64>(), 0..32),
        backoffs in prop::collection::vec(any::<bool>(), 0..32),
    ) {
        let mut timer = RetransmissionTimer::new();
        for (sample, back_off) in samples.iter().zip(backoffs.iter().chain(core::iter::repeat(&false))) {
            timer.measure(Duration::from_nanos(*sample));
            if *back_off {
                timer.back_off();
            }
            prop_assert!(timer.timeout() >= MIN_RTO);
            prop_assert!(timer.timeout() <= MAX_RTO);
        }
        prop_assert!(timer.timeout() >= MIN_RTO);
        prop_assert!(timer.timeout() <= MAX_RTO);
    }

    /// Backing off never shortens the timeout, whatever it currently is: a
    /// backoff that reduced it would retransmit sooner after a loss than before
    /// one.
    #[test]
    fn backing_off_never_shortens_the_timeout(sample in any::<u64>(), rounds in 0u8..=16) {
        let mut timer = RetransmissionTimer::new();
        timer.measure(Duration::from_nanos(sample));
        let mut previous = timer.timeout();
        for _ in 0..rounds {
            timer.back_off();
            prop_assert!(timer.timeout() >= previous);
            previous = timer.timeout();
        }
    }

    /// A sample of the same value repeatedly converges rather than diverging:
    /// the variance falls towards zero and the timeout towards the floor or the
    /// sample itself, never away.
    #[test]
    fn a_constant_path_converges(sample in 0u64..=10_000_000_000) {
        let mut timer = RetransmissionTimer::new();
        timer.measure(Duration::from_nanos(sample));
        let first = timer.timeout();
        for _ in 0..64 {
            timer.measure(Duration::from_nanos(sample));
        }
        prop_assert!(timer.timeout() <= first);
        prop_assert!(timer.measured());
    }

    /// Every sample the whole `u64` range can express is answered, which is what
    /// makes an absurd acknowledgement delay a large timeout rather than an
    /// arithmetic fault.
    #[test]
    fn any_sample_is_answered(first in any::<u64>(), second in any::<u64>()) {
        let mut timer = RetransmissionTimer::new();
        timer.measure(Duration::from_nanos(first));
        timer.measure(Duration::from_nanos(second));
        prop_assert!(timer.timeout() >= MIN_RTO);
    }
}
