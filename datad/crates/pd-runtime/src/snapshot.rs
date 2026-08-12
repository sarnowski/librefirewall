//! How often this node publishes a whole metric reading for the recorder to
//! frame into the connection history.
//!
//! Its own module because the decision it makes — publish now, or not yet — is
//! the whole of the cadence, and it is a decision worth driving from a host test
//! across a clock that arrives late, moves backwards, or never arrives at all.
//! The protection domain that owns the regions then holds one value and asks it
//! once per wakeup.
//!
//! # Adversary
//!
//! None of its own. It reads a clock this node established and writes a region
//! `wire::StatsRelay` owns the protocol of; what a peer can do to either is that
//! type's question and the clock domain's.

use lfw_clock::{Duration, Monotonic, UtcNanos};
use wire::StatsRelay;

use crate::StatsRegions;

/// How often a whole reading is published for the recorder to frame.
///
/// One second, which is the channel's own cadence rather than a number chosen
/// here: the appliance flushes accumulated ring bytes at least once per second,
/// so a reading published more often would land several to a flush and one
/// published less often would leave flushes with nothing new in them.
pub const SNAPSHOT_PERIOD: Duration = Duration::from_millis(1_000);

/// When the next whole reading is due.
///
/// A type rather than an instant in the domain's own state, because the decision
/// it makes is the whole of the cadence and belongs where a host test can drive
/// it across a clock that arrives late, goes backwards, or never arrives.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SnapshotSchedule {
    /// The instant the last reading went out at, or `None` before the first.
    published: Option<Monotonic>,
}

impl SnapshotSchedule {
    #[must_use]
    pub const fn new() -> Self {
        Self { published: None }
    }

    /// Publish a reading into `relay` if one is due, answering whether one went.
    ///
    /// `None` for `now` is a node whose clock domain has published nothing yet,
    /// and it publishes **once**: what the counters read before time was
    /// established is worth more than nothing at all, and the reading carries a
    /// zero instant rather than a counter reading dressed as a time. Afterwards
    /// the cadence needs a clock, so such a node publishes no more.
    ///
    /// An instant behind the last one — a calibration replaced under a running
    /// node — is not a reason to publish twice in a period: `since` saturates.
    pub fn publish_due(
        &mut self,
        now: Option<Monotonic>,
        utc: Option<UtcNanos>,
        stats: &StatsRegions<'_>,
        relay: &StatsRelay,
    ) -> bool {
        let due = match (self.published, now) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(last), Some(now)) => now.since(last) >= SNAPSHOT_PERIOD,
        };
        if !due {
            return false;
        }
        stats.publish_relay(relay, utc);
        // `Monotonic::BOOT` where there is no clock: the origin every reading is
        // measured from, so the first clocked pass is a period past it.
        self.published = Some(now.unwrap_or(Monotonic::BOOT));
        true
    }
}

#[cfg(test)]
mod tests;
