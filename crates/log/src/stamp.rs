//! When a record was emitted, and where a [`Sink`](crate::Sink) gets that.

use lfw_clock::UtcNanos;
use wire::CheckedStamp;

/// The instant a record was emitted, or the fact that the emitting domain had
/// none to give it.
///
/// A sum type rather than a `u64` with a reserved value: zero nanoseconds is
/// 1970-01-01, an instant a reader would take for a reading, and the records
/// emitted before this node establishes a time are most of a boot transcript,
/// too much to misdate silently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stamp {
    Unsynchronized,
    Utc(UtcNanos),
}

impl Stamp {
    /// What [`Self::Unsynchronized`] renders as. Inside the `[a-z0-9-]` console
    /// alphabet, so the field carries no character the rest of a line may not.
    pub const UNSYNCHRONIZED: &'static str = "unsynchronized";

    /// The stamp a record decoded out of a peer's region carries.
    pub(crate) const fn from_checked(stamp: CheckedStamp) -> Self {
        match stamp {
            CheckedStamp::Unsynchronized => Self::Unsynchronized,
            CheckedStamp::Utc(nanos) => Self::Utc(UtcNanos::from_unix_nanos(nanos)),
        }
    }
}

/// Where a [`RingSink`](crate::RingSink) gets the instant it stamps a record
/// with.
///
/// A trait rather than the calibration region itself, because reading the
/// counter is one instruction in a protection domain and none at all on a host,
/// and this crate forbids `unsafe`. `pd_runtime::PdClock` is what ships.
///
/// The sink asks rather than the call site telling it: *when* a record was
/// emitted is a fact about the emission and not about the event, so threading
/// an instant through every subsystem that has something to say would make the
/// field the caller's to get right in as many places as there are call sites.
pub trait Clock {
    fn now(&self) -> Stamp;
}

#[cfg(test)]
pub(crate) mod testing {
    use super::{Clock, Stamp};
    use lfw_clock::UtcNanos;

    /// A clock that answers the same thing every time, so a test asserting a
    /// rendered line need not know what the host's own counter said.
    pub(crate) struct FixedClock(pub(crate) Stamp);

    impl Clock for FixedClock {
        fn now(&self) -> Stamp {
            self.0
        }
    }

    pub(crate) const fn utc(nanos: u64) -> Stamp {
        Stamp::Utc(UtcNanos::from_unix_nanos(nanos))
    }
}
