//! The allowance an unauthenticated peer spends by asking, and the backoff it
//! earns by spending it.
//!
//! # Why a limiter that always forgives
//!
//! The port this bounds is the **only** way into an unprovisioned appliance.
//! There is no shell, no console input and no second interface, so a refusal
//! that never expired would be a way for anybody who can reach the port to make
//! the appliance unonboardable from across a network — the same effect as
//! destroying it, at no cost and from anywhere. That is why every quantity here
//! recovers: an allowance is refilled by the passage of time and by nothing
//! else, the interval between refills grows with consecutive refusals and stops
//! growing at [`MAX_BACKOFF_SHIFT`], and there is no state a peer can reach
//! from which an allowance never comes back.
//!
//! What it does buy is the other half: an administrator's own flow is two
//! requests and a peer's is unbounded, so a burst sized for the first turns the
//! second into something paced by a clock rather than by how fast an attacker
//! can open connections.
//!
//! # Adversary
//!
//! An **unauthenticated management-plane attacker**, who decides how often
//! [`Limiter::admit`] is called and nothing else. Every quantity here is a
//! first-party constant or an instant this appliance read; nothing a peer sent
//! reaches it, and the arithmetic saturates throughout, so no sequence of calls
//! and no clock reading produces a fault.
//!
//! # A node with no clock is not limited, and that is the safe direction
//!
//! The refill is measured in elapsed time, so a node whose clock domain never
//! published has no way to expire a refusal. Refusing anyway would be the
//! permanent lockout above; admitting is the other direction, and it is the one
//! the design chooses. The caller says which case it is by handing `None`.

use lfw_clock::{Duration, Monotonic};

/// Requests the surface answers back to back before any wait is imposed.
///
/// An administrator's own flow is two — the page and the request it links to —
/// and a browser fetching an icon beside them makes it three or four. Eight
/// leaves room for a reload and for a client that retries once, and is far
/// below what an attacker would want.
pub const BURST: u32 = 8;

/// How long one allowance takes to come back when nothing has been refused.
pub const BASE_INTERVAL: Duration = Duration::from_millis(1_000);

/// How far the interval may double. Five, so the longest a peer can make itself
/// wait is thirty-two seconds per request — long enough that hammering the
/// surface buys nothing, short enough that an administrator who tripped it by
/// accident waits less than a minute and never has to visit the appliance.
pub const MAX_BACKOFF_SHIFT: u32 = 5;

/// What the limiter is doing, written beside the refusal it caused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Throttle {
    /// Consecutive refusals, saturating at [`MAX_BACKOFF_SHIFT`] — past which
    /// more refusals lengthen nothing, the interval having stopped doubling.
    pub strikes: u32,
    /// Milliseconds until the next allowance. **Always finite**, which is the
    /// whole property this type exists to make visible on a console.
    pub wait_millis: u64,
}

/// The allowance, and how long the next one is away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limiter {
    /// Allowances in hand, never above [`BURST`].
    allowance: u32,
    /// When the allowance last moved. `None` until the first admitted call
    /// gives it an instant to measure from — an origin taken from a reading
    /// rather than assumed, because a limiter that assumed boot would hand a
    /// peer the whole span since boot as refill on its first request.
    since: Option<Monotonic>,
    strikes: u32,
}

impl Default for Limiter {
    fn default() -> Self {
        Self::new()
    }
}

impl Limiter {
    /// A full allowance and no strikes: an appliance that has just come up owes
    /// nobody a wait.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            allowance: BURST,
            since: None,
            strikes: 0,
        }
    }

    /// Allowances in hand.
    #[must_use]
    pub const fn allowance(&self) -> u32 {
        self.allowance
    }

    /// Consecutive refusals.
    #[must_use]
    pub const fn strikes(&self) -> u32 {
        self.strikes
    }

    /// Spend one allowance, or answer how long the wait is.
    ///
    /// `now` is `None` where the node has no clock — see the module header on
    /// why that admits rather than refuses.
    ///
    /// # Errors
    /// [`Throttle`], carrying how many consecutive refusals there have been and
    /// how long until the next allowance.
    pub fn admit(&mut self, now: Option<Monotonic>) -> Result<(), Throttle> {
        let Some(now) = now else {
            // Nothing is spent either: an allowance consumed against a clock
            // that cannot refill it would still reach zero, and the appliance
            // would be locked out by the very case this arm exists for.
            return Ok(());
        };
        let interval = self.interval();
        self.refill(now, interval);
        if let Some(left) = self.allowance.checked_sub(1) {
            self.allowance = left;
            // Cleared, not decremented: what the backoff is against is a run of
            // refusals, and a request that got through ends the run.
            self.strikes = 0;
            return Ok(());
        }
        // Counted before the wait is computed, so the wait reported is the one
        // this refusal earned rather than the one before it.
        self.strikes = self.strikes.saturating_add(1).min(MAX_BACKOFF_SHIFT);
        Err(Throttle {
            strikes: self.strikes,
            wait_millis: self.wait(now, self.interval()),
        })
    }

    /// How long one allowance takes to come back at the current strike count.
    ///
    /// Doubling, bounded: the shift is held to [`MAX_BACKOFF_SHIFT`] before it
    /// is applied, so the interval is at most [`BASE_INTERVAL`] times
    /// thirty-two and the shift itself can never reach a width the type does
    /// not have.
    fn interval(&self) -> Duration {
        let shift = self.strikes.min(MAX_BACKOFF_SHIFT);
        Duration::from_nanos(BASE_INTERVAL.as_nanos().saturating_mul(1_u64 << shift))
    }

    /// Give back whatever the elapsed time has earned, and move the origin by
    /// exactly what was given back.
    ///
    /// By what was given back and not to `now`, so the remainder of a partial
    /// interval is kept rather than discarded — a peer asking every half second
    /// against a one-second interval must still earn one allowance a second,
    /// and an origin reset on every call would earn it none.
    fn refill(&mut self, now: Monotonic, interval: Duration) {
        let Some(since) = self.since else {
            // The first call with a clock behind it: this instant is the origin
            // and nothing has elapsed against it.
            self.since = Some(now);
            return;
        };
        let nanos = interval.as_nanos();
        if nanos == 0 {
            // Unreachable while `BASE_INTERVAL` is positive, and answered
            // rather than asserted because a division is what follows: a
            // constant edited to zero must produce a limiter that refills at
            // once, never one that faults on a path a peer paces.
            self.allowance = BURST;
            self.since = Some(now);
            return;
        }
        let elapsed = now.since(since).as_nanos();
        let earned = elapsed / nanos;
        if earned == 0 {
            return;
        }
        let earned32 = u32::try_from(earned).unwrap_or(u32::MAX);
        self.allowance = self.allowance.saturating_add(earned32).min(BURST);
        if self.allowance == BURST {
            // Full: there is no remainder worth keeping, and an origin left
            // behind would hand the next refusal a span it did not wait.
            self.since = Some(now);
        } else {
            self.since =
                Some(since.saturating_add(Duration::from_nanos(earned.saturating_mul(nanos))));
        }
    }

    /// Milliseconds until the next allowance, rounded up so a reported wait is
    /// never shorter than the real one.
    fn wait(&self, now: Monotonic, interval: Duration) -> u64 {
        let Some(since) = self.since else {
            return interval.as_nanos() / NANOS_PER_MILLI;
        };
        let elapsed = now.since(since).as_nanos();
        let left = interval.as_nanos().saturating_sub(elapsed);
        left.div_ceil(NANOS_PER_MILLI)
    }
}

/// Nanoseconds in a millisecond, which the clock crate states as a conversion
/// and not as a constant this one can borrow.
const NANOS_PER_MILLI: u64 = 1_000_000;
