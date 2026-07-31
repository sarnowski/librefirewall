//! The retransmission timeout, computed per RFC 6298.
//!
//! # Why the estimator is here rather than one constant
//!
//! A fixed timeout is wrong in both directions and both are expensive. Too
//! short and every segment is sent twice on a path slower than the guess, which
//! on the dataplane this stack is meant to carry is a doubling of the load
//! precisely when the path is already the bottleneck. Too long and a lost
//! segment stalls a connection for that constant, which an attacker chooses by
//! dropping one packet. RFC 6298's smoothed estimate is what makes the timeout a
//! measurement of the path instead.
//!
//! # Every value is nanoseconds in a `u64`, and every operation saturates
//!
//! The round-trip time is derived from two readings of a clock a peer's traffic
//! drives, so the *input* is attacker-influenced even though the clock is not:
//! a peer that acknowledges a segment weeks later hands this code an enormous
//! sample. Saturating arithmetic is what makes that a large timeout rather than
//! a wrapped tiny one — and a wrapped tiny one is the dangerous direction, being
//! a retransmission storm. [`MAX_RTO`] then bounds it from above regardless.
//!
//! # The rounding, and where it differs from a fast LAN's habit
//!
//! RFC 6298 §2.4 rounds every computed timeout up to one second, and this
//! follows it rather than the sub-second minimum a local-network stack usually
//! picks. The reason is which error each choice makes: a floor that is too low
//! turns a momentarily slow peer into a duplicate-segment source, and this stack
//! answers a management port whose peer may be an operator across a WAN. A
//! management response that arrives a second late is not a fault; a stack that
//! doubles its own traffic under load is.

use lfw_clock::Duration;

/// RFC 6298 §2.1's initial value, in force until the first round-trip
/// measurement replaces it.
pub const INITIAL_RTO: Duration = Duration::from_millis(1_000);

/// RFC 6298 §2.4's floor. See the module header on why the RFC's own second is
/// kept rather than lowered.
pub const MIN_RTO: Duration = Duration::from_millis(1_000);

/// The ceiling RFC 6298 §2.5 permits, chosen at the low end of what it allows
/// (at least 60 seconds): a connection whose timeout has backed off this far is
/// one about to be abandoned, and a larger ceiling only lengthens how long its
/// table slot is held.
pub const MAX_RTO: Duration = Duration::from_millis(60_000);

/// The clock granularity `G` of RFC 6298 §2.4's `max(G, 4*RTTVAR)`.
///
/// One microsecond, because the reading behind a [`lfw_clock::Monotonic`] is a
/// timestamp counter converted to nanoseconds: the quantity is finer than this,
/// and claiming so would put a granularity in the formula that no measurement
/// backs.
const CLOCK_GRANULARITY: Duration = Duration::from_micros(1);

/// RFC 6298's `SRTT` and `RTTVAR`, and the timeout derived from them.
///
/// `srtt` is `None` until the first measurement, which is what distinguishes
/// §2.2's initialisation from §2.3's update — a distinction a zero would lose,
/// zero being also a perfectly possible sample from a fast local peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetransmissionTimer {
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    /// How many times the timeout has doubled without a measurement, which is
    /// what §5.5's exponential backoff counts and what the caller compares
    /// against its own retry limit.
    backoff: u32,
}

impl RetransmissionTimer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            srtt: None,
            rttvar: Duration::from_nanos(0),
            rto: INITIAL_RTO,
            backoff: 0,
        }
    }

    /// The timeout in force.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.rto
    }

    #[must_use]
    pub const fn backoff(&self) -> u32 {
        self.backoff
    }

    /// Whether any round-trip time has been measured yet.
    #[must_use]
    pub const fn measured(&self) -> bool {
        self.srtt.is_some()
    }

    /// Take one round-trip measurement, per RFC 6298 §2.2 and §2.3.
    ///
    /// The caller is responsible for Karn's algorithm — a sample must not come
    /// from a segment that was retransmitted — because only it knows which
    /// segment an acknowledgement covered. `crate::connection::Unacked` records
    /// that, and `Connection::acknowledge` is what refuses the sample; the
    /// property `a_retransmitted_segment_yields_no_sample` in `crate::tests`
    /// holds it to that (DOC-7).
    pub fn measure(&mut self, sample: Duration) {
        let sample_nanos = sample.as_nanos();
        match self.srtt {
            None => {
                // §2.2: SRTT <- R, RTTVAR <- R/2.
                self.srtt = Some(sample);
                self.rttvar = Duration::from_nanos(sample_nanos / 2);
            }
            Some(srtt) => {
                // §2.3, with alpha = 1/8 and beta = 1/4. The difference is
                // taken as an absolute value, so the order of the two readings
                // cannot make it negative.
                let srtt_nanos = srtt.as_nanos();
                let difference = srtt_nanos.abs_diff(sample_nanos);
                let rttvar = self.rttvar.as_nanos();
                self.rttvar =
                    Duration::from_nanos((rttvar - rttvar / 4).saturating_add(difference / 4));
                self.srtt = Some(Duration::from_nanos(
                    (srtt_nanos - srtt_nanos / 8).saturating_add(sample_nanos / 8),
                ));
            }
        }
        self.recompute();
        // §5.3: a new measurement resets the backoff, the timeout no longer
        // resting on a guess.
        self.backoff = 0;
    }

    /// §5.5: double the timeout on an expiry, up to [`MAX_RTO`].
    pub fn back_off(&mut self) {
        self.rto = clamp(self.rto.as_nanos().saturating_mul(2));
        self.backoff = self.backoff.saturating_add(1);
    }

    /// §2.4: `RTO <- SRTT + max(G, 4*RTTVAR)`, clamped to the band.
    fn recompute(&mut self) {
        let srtt = match self.srtt {
            Some(srtt) => srtt.as_nanos(),
            // Unreachable from `measure`, which sets `srtt` on both arms before
            // calling this; expressed as a value rather than an assertion
            // because an `assert!` on a path a peer's acknowledgement reaches is
            // what ENG-5 refuses.
            None => return,
        };
        let variance = self
            .rttvar
            .as_nanos()
            .saturating_mul(4)
            .max(CLOCK_GRANULARITY.as_nanos());
        self.rto = clamp(srtt.saturating_add(variance));
    }
}

impl Default for RetransmissionTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// Hold a computed timeout inside RFC 6298's band.
fn clamp(nanos: u64) -> Duration {
    Duration::from_nanos(nanos.clamp(MIN_RTO.as_nanos(), MAX_RTO.as_nanos()))
}

#[cfg(test)]
mod tests;
