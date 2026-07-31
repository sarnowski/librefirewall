//! What time it is, as a protection domain can answer it: one counter reading
//! converted by the calibration another domain published.
//!
//! # Adversary
//!
//! The byzantine peer protection domain (CONCEPT §7.1). The calibration comes
//! out of a region the clock domain writes, so the frequency, the anchor
//! reading and the epoch are all a peer's numbers — and behind that peer sits
//! §7.1's hostile or malfunctioning device, whose timer and register file they
//! were measured from. Nothing here trusts them: an unpublished, torn or
//! implausible triple yields no instant rather than a wrong one, because a
//! record carrying a wrong time is worse than one carrying none — an operator
//! can see an absence.
//!
//! # Why the counter is read here and not once per domain
//!
//! `RDTSC` is the one instruction in this workspace every domain that stamps a
//! record has to execute, and each copy of it would be a separate `unsafe`
//! block obliging a separate DOC-6 claim that no compiler checks (ENG-11,
//! ENG-13). This crate is where the claim is made once: every protection domain
//! already depends on it, and it is where `attach_region!` states the other
//! invariant they all share.
//!
//! # Why a region rather than an IPC
//!
//! There is no message to send. A channel to the clock domain would put a round
//! trip on the path of every record and hand a wakeup capability to seven
//! domains over a domain that runs once and parks; the system description says
//! what the read grant does and does not give instead.

use lfw_clock::{Calibration, Ticks};
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
    // targets nothing else (CON-4). The seL4 kernel is the guarantor of the
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
/// Afresh rather than cached, because the clock domain may republish and a
/// cached triple would be a stopped clock that no longer says so. The read is
/// three loads and a seqlock check, which is cheaper than the counter read it
/// accompanies.
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
    /// The three cases collapse deliberately: nothing published yet, a triple
    /// torn under the read, and a frequency outside the band
    /// [`calibration_from`] accepts all mean "no instant to give a record", and
    /// a caller that told them apart would still do the same thing.
    #[must_use]
    pub fn calibration(&self) -> Option<Calibration> {
        calibration_from(self.published.load()?).ok()
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
