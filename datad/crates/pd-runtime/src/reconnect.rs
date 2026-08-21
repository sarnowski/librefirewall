//! The schedule an appliance re-dials its management channel on: bounded
//! exponential backoff with full jitter, and the one event that starts it
//! afresh.
//!
//! # Why a schedule at all, and why this one
//!
//! The channel is a persistent connection this appliance originates, so every
//! close is this end's problem to answer. Answering it immediately would turn a
//! management server that is down into a flood the moment it comes back — every
//! appliance it owns dialling at once, and each of them as fast as its own
//! transport allows. So the wait between attempts doubles, and it stops
//! doubling at a cap, because an appliance that has been disconnected for a day
//! must still reconnect within minutes of the server returning.
//!
//! **Full jitter, and not a fraction of one.** The delay is drawn uniformly
//! between zero and the current bound rather than being the bound itself or the
//! bound plus a wobble. A fleet is disconnected together — one server restart,
//! one link — so a fleet redialling in step is the ordinary case rather than the
//! unlucky one, and only a draw across the whole interval breaks the step.
//!
//! # What resets it, and what deliberately does not
//!
//! [`established`](Reconnect::established) is the only thing that puts the bound
//! back on its floor, and its caller is the one that has completed a **greeting
//! exchange** with the far end — an application-level agreement, not a
//! connection. A server that accepts a connection and closes it is exactly what
//! a schedule reset on a completed handshake would let invite a tight redial
//! loop, so a session that came up and went away without agreeing anything
//! leaves the schedule where it was and the bound goes on doubling.
//!
//! # The randomness, and what it must not be
//!
//! [`Reconnect::new`] takes a seed the caller draws once per boot from the
//! hardware generator. The generator below is a small deterministic mixer and is
//! **not a cryptographic one** — it does not need to be, a redial instant being
//! observable from the wire by anybody watching. What it must not be is *derived
//! from anything that has to stay secret*: an adversary reads redial instants
//! off the wire, so a schedule seeded from the transport's sequence-number
//! secret would leak that secret through its own timing, and a predictable
//! sequence number is an off-path injection primitive against the very peer this
//! channel faces. The seed is therefore a draw of its own.
//!
//! # Quantisation
//!
//! Deadlines here are judged on a pass, and passes arrive on
//! [`TICK_PERIOD`](crate::TICK_PERIOD). So a delay is reached at most one period
//! late and the drawn instants are quantised to it: ten distinct instants across
//! the first bound, three thousand at the cap. That is the resolution the whole
//! schedule is worth, and it is stated rather than assumed.

use lfw_clock::{Duration, Monotonic};

/// The first wait, and the one the schedule returns to.
pub const INITIAL_BACKOFF: Duration = Duration::from_millis(1_000);

/// The longest wait, whatever the attempt count reaches.
///
/// Five minutes: long enough that a management plane down for hours is not
/// dialled at a rate anybody notices, short enough that an appliance rejoins
/// within minutes of it returning.
pub const MAX_BACKOFF: Duration = Duration::from_millis(300_000);

// A floor of zero would make every draw zero and the doubling never leave it,
// which is a schedule with no wait in it at all; and a cap below the floor would
// clamp the first wait to less than the floor, so the two ends would name a
// range in the wrong order.
const _: () = assert!(INITIAL_BACKOFF.as_nanos() > 0);
const _: () = assert!(MAX_BACKOFF.as_nanos() >= INITIAL_BACKOFF.as_nanos());

/// What a re-dial costs: the longest between a session this appliance ended and
/// the next attempt opening.
///
/// A session this end closed is held by the endpoint above the transport until
/// the transport gives the connection's slot back, so no wait is drawn until that
/// `TIME_WAIT` is over; then one is, below [`INITIAL_BACKOFF`] rather than a
/// doubled bound — a re-dial being promised only of a channel that was working.
pub const REDIAL_CEILING: Duration = Duration::from_nanos(
    lfw_tcp::TIME_WAIT_DURATION
        .as_nanos()
        .saturating_add(INITIAL_BACKOFF.as_nanos()),
);

// A sum that had saturated would read as *shorter* than a term it is built from,
// which is the dangerous direction for a figure a floor is derived from.
const _: () = assert!(REDIAL_CEILING.as_nanos() > lfw_tcp::TIME_WAIT_DURATION.as_nanos());

/// The delay drawn for one wait, and the bound it was drawn below.
///
/// Both travel because neither alone says where the schedule stands: the delay
/// is one draw out of an interval, and the bound is how far the backoff has
/// climbed. A console reporting only the delay would show a small number for a
/// channel that had been failing for an hour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wait {
    /// How long until the next attempt, as drawn.
    pub delay: Duration,
    /// The bound it was drawn uniformly below.
    pub bound: Duration,
}

impl Wait {
    /// The delay in milliseconds, for a report line.
    #[must_use]
    pub const fn delay_millis(self) -> u64 {
        self.delay.as_nanos() / 1_000_000
    }

    /// The bound in milliseconds, for a report line.
    #[must_use]
    pub const fn bound_millis(self) -> u64 {
        self.bound.as_nanos() / 1_000_000
    }
}

/// Where the channel's re-dialling stands: how long the next wait may be, when
/// the current one is over, and the generator the draw comes from.
///
/// A value rather than a task, because nothing here may block: the domain
/// holding one is woken, asks whether an attempt is due, and returns.
#[derive(Clone, Copy, Debug)]
pub struct Reconnect {
    /// The current ceiling on a draw. It doubles per failed attempt and stops
    /// at [`MAX_BACKOFF`].
    bound: Duration,
    /// When the next attempt may open. `None` means now — which is what a boot
    /// starts at, an appliance having no reason to wait before its first dial.
    next: Option<Monotonic>,
    state: u64,
}

impl Reconnect {
    /// A schedule that is due at once, seeded from `seed`.
    ///
    /// Due at once, deliberately: the backoff exists to space out *re*-dials,
    /// and an appliance that waited a second before its first attempt would be
    /// a second slower to come up for no gain at all.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            bound: INITIAL_BACKOFF,
            next: None,
            // A zero seed would make the mixer below answer a fixed sequence, so
            // it is displaced onto a constant no draw can return to. The
            // generator is not a secret and this is not a defence — it is what
            // keeps a part whose generator answered zero from producing a fleet
            // that redials in lockstep.
            state: seed ^ 0x9e37_79b9_7f4a_7c15,
        }
    }

    /// Whether an attempt may open now.
    #[must_use]
    pub fn due(&self, now: Monotonic) -> bool {
        match self.next {
            None => true,
            Some(deadline) => now >= deadline,
        }
    }

    /// How long is left before the next attempt, or `None` where one is due.
    #[must_use]
    pub fn remaining(&self, now: Monotonic) -> Option<Duration> {
        let deadline = self.next?;
        (deadline > now).then(|| deadline.since(now))
    }

    /// The bound a draw would currently be taken below.
    #[must_use]
    pub const fn bound(&self) -> Duration {
        self.bound
    }

    /// An attempt has ended without the channel agreeing anything. Draw the next
    /// wait and double the bound.
    ///
    /// Drawn first and doubled after, so the first wait after a failure is taken
    /// below the floor rather than below twice it: a channel that fails once and
    /// recovers is delayed by up to a second, not up to two.
    pub fn failed(&mut self, now: Monotonic) -> Wait {
        let bound = self.bound;
        let delay = self.draw(bound);
        self.next = Some(now.saturating_add(delay));
        self.bound = double(bound);
        Wait { delay, bound }
    }

    /// The channel agreed a greeting with the far end, so the schedule starts
    /// afresh.
    ///
    /// The **only** reset, on the module header's terms: a connection that came
    /// up and said nothing is not one.
    pub const fn established(&mut self) {
        self.bound = INITIAL_BACKOFF;
        self.next = None;
    }

    /// A draw uniform over `[0, bound]`, in nanoseconds.
    ///
    /// SplitMix64's finaliser over a counter: three shifts and two
    /// multiplications, no allocation and no state beyond the word. The modulus
    /// is taken over `bound + 1` so the bound itself is reachable, which is what
    /// makes the interval closed as the contract states it.
    fn draw(&mut self, bound: Duration) -> Duration {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^= mixed >> 31;
        // Saturating rather than wrapping: `bound` is at most five minutes in
        // nanoseconds, so the add cannot reach `u64::MAX` — but a value that
        // saturated would give a modulus of zero, which no remainder is defined
        // against.
        let span = bound.as_nanos().saturating_add(1).max(1);
        Duration::from_nanos(mixed % span)
    }
}

/// Twice `bound`, held at [`MAX_BACKOFF`].
///
/// Saturating on the way up as well as capped: a doubling that wrapped would
/// turn the longest wait into a near-zero one, which is the dangerous direction
/// for anything bounding a redial rate.
const fn double(bound: Duration) -> Duration {
    let doubled = bound.as_nanos().saturating_mul(2);
    if doubled >= MAX_BACKOFF.as_nanos() {
        return MAX_BACKOFF;
    }
    Duration::from_nanos(doubled)
}

#[cfg(test)]
mod tests;
