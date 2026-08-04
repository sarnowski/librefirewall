//! What time it is, as a protection domain can answer it: one counter reading
//! converted by the calibration another domain published.
//!
//! # Adversary
//!
//! A byzantine neighbour protection domain. The calibration comes
//! out of a region the clock domain writes, so the frequency, the anchor
//! reading and the epoch are all a peer's numbers — and behind that peer sits
//! a hostile or malfunctioning device, whose timer and register file they
//! were measured from. Nothing here trusts them: an unpublished, torn or
//! implausible triple yields no instant rather than a wrong one, because a
//! record carrying a wrong time is worse than one carrying none — an operator
//! can see an absence.
//!
//! # Why the counter is read here and not once per domain
//!
//! `RDTSC` is the one instruction in this workspace every domain that stamps a
//! record has to execute, and each copy of it would be a separate `unsafe`
//! block obliging a separate safety claim that no compiler checks — a budget
//! kept minimal. This crate is where the claim is made once: every protection domain
//! already depends on it, and it is where `attach_region!` states the other
//! invariant they all share.
//!
//! # Why a region rather than an IPC
//!
//! There is no message to send. A channel to the clock domain would put a round
//! trip on the path of every record and hand a wakeup capability to seven
//! domains over a domain that runs once and parks; the system description says
//! what the read grant does and does not give instead.

use lfw_clock::{Calibration, Monotonic, Ticks};
use lfw_log::Stamp;
use wire::ClockCalibration;

use crate::endpoint::calibration_from;

/// One reading of the x86_64 timestamp counter.
///
/// The reading is deliberately not serialised with an `lfence`. Out-of-order
/// execution moves the instruction by tens of cycles; every consumer states its
/// result in milliseconds (a transport timeout) or renders it to the nanosecond
/// as a log stamp nothing is judged against, so the serialisation would tighten
/// an error orders of magnitude below anything measured with it.
#[must_use]
pub fn read_timestamp_counter() -> Ticks {
    // SAFETY: `_rdtsc` requires only that the instruction execute, which is two
    // facts neither this crate nor any first-party one provides. The target is
    // the guarantor of the first — `RDTSC` has been architectural on x86_64
    // since the ISA existed, and `support/targets/x86_64-sel4-minimal.json`
    // targets nothing else. The seL4 kernel is the guarantor of the
    // second: it leaves `CR4.TSD` clear, which is what makes the instruction
    // unprivileged in a protection domain. That is third-party runtime
    // behaviour, recorded rather than asserted — and it is the one step of this
    // argument no first-party component can make for itself. Being wrong about
    // it is a #GP the Microkit monitor reports as a fault in the calling
    // domain, not a silently wrong number.
    Ticks(unsafe { core::arch::x86_64::_rdtsc() })
}

/// A domain's view of what time it is: the calibration region, read afresh on
/// every question.
///
/// Afresh rather than cached, because the clock domain may republish and a cached
/// triple would go on converting readings with a calibration the writer has
/// withdrawn. [`EndpointStage`](crate::EndpointStage) holds one and re-reads on a
/// generation change for the same end and not a different one — neither may keep a
/// superseded triple; they differ only in how often the question is asked. The read
/// is three loads and a seqlock check, cheaper than the counter read beside it.
///
/// So a domain that has stamped a record is **not** thereby one that stamps every
/// later record. The clock domain publishes once and parks, which makes the
/// transition one-way in practice — but that is its behaviour, not this reader's
/// guarantee, and a latch asserting it would be the cache above under another name.
pub struct PdClock<'region> {
    published: &'region ClockCalibration,
}

impl<'region> PdClock<'region> {
    #[must_use]
    pub const fn new(published: &'region ClockCalibration) -> Self {
        Self { published }
    }

    /// The calibration now in force, or `None` where there is none this domain
    /// will convert a reading with.
    ///
    /// The cases collapse deliberately: nothing published, a triple torn under the
    /// read, and a triple whose frequency or epoch is outside the band all mean
    /// "no instant to give a record", and a caller telling them apart would still
    /// do the same thing.
    #[must_use]
    pub fn calibration(&self) -> Option<Calibration> {
        calibration_from(self.published.load()?).ok()
    }

    /// Nanoseconds since boot, for a consumer whose work cannot wait for a
    /// calibration.
    ///
    /// An unclocked domain reads [`Monotonic::BOOT`] rather than nothing, and
    /// what that buys is stated where it is spent: a connection table driven by
    /// an instant that never advances expires no flow, so it fills and then
    /// refuses new ones — which is the fail-closed direction, and strictly
    /// better than a dataplane that stops forwarding until the clock domain has
    /// published. A caller that must be able to *tell* asks
    /// [`calibration`](Self::calibration), which answers `None`.
    #[must_use]
    pub fn monotonic(&self) -> Monotonic {
        self.calibration().map_or(Monotonic::BOOT, |calibration| {
            calibration.monotonic(read_timestamp_counter())
        })
    }
}

impl lfw_log::Clock for PdClock<'_> {
    fn now(&self) -> Stamp {
        match self.calibration() {
            None => Stamp::Unsynchronized,
            Some(calibration) => Stamp::Utc(calibration.utc(read_timestamp_counter())),
        }
    }
}

#[cfg(test)]
mod tests;
