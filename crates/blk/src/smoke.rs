//! The block path's boot-time proof: read a sector of the real medium, write a
//! recognisable one back, and answer what happened.
//!
//! A protection domain that brought a device up has proved that the *device*
//! answered a handshake — configuration space, feature negotiation, a queue it
//! accepted. It has not proved that a byte ever crossed. The two failures look
//! identical from the console, and the second is the one a recording appliance
//! cannot survive, so this module makes the difference machine-observable: a
//! read whose bytes are the medium's, and a write whose bytes an outside
//! observer can find on the medium afterwards.
//!
//! # Why it is here and not in the protection domain
//!
//! Every decision the proof makes — which sectors, what the pattern is, how
//! long the device may take, what counts as a completion for the request that
//! was submitted, and what each failure is called — is first-party logic, and
//! logic welded to a Microkit entrypoint is logic no host test can reach
//! (LAY-2). The domain supplies the mapped regions and the doorbell; this
//! module supplies every judgement made through them.
//!
//! # The adversary
//!
//! CONCEPT §7.1's **hostile or malfunctioning device**. The proof believes
//! nothing it is told: the capacity is checked before a sector is named, a
//! completion is matched against the token the submit minted rather than taken
//! as an answer to the outstanding request, a short or failed transfer is a
//! typed error rather than a success, and the wait for each completion is
//! bounded by [`POLL_BUDGET`] — a driver constant, so a device that simply
//! never answers parks this proof instead of this domain (ENG-4). The bytes it
//! reads back are never interpreted: [`Report::probe_word`] is carried to the
//! console as a number and steers nothing.

use crate::bringup::{BlkDevice, Live};
use crate::io::{IoRegion, IoSector};
use crate::request::{Completed, Operation, Outcome, Requests, SubmitError, Token};
use crate::{Refusal, RefusalDetail, SECTOR_SIZE};

/// The sector the proof reads. Sector 0 because it is the one sector every
/// block device has, so the read needs no arithmetic against a capacity that
/// is the device's own claim.
pub const PROBE_SECTOR: u64 = 0;

/// The sector the proof writes its witness pattern to.
///
/// Not sector 0: the read must be able to fail independently of the write, and
/// a proof that wrote over the sector it had just read could not tell a medium
/// that answered reads from one that answered them out of the driver's own
/// staging window. Far enough in that no partitioning scheme's first structures
/// sit on it, and low enough that any medium worth calling one has it.
pub const WITNESS_SECTOR: u64 = 64;

/// The smallest medium the proof will run against, in sectors: enough to hold
/// [`WITNESS_SECTOR`] itself.
pub const MINIMUM_CAPACITY_SECTORS: u64 = WITNESS_SECTOR + 1;

/// The first eight bytes of the witness pattern — the token an outside observer
/// searches the medium for.
///
/// **Cross-artifact (DOC-7):** the enforcer is `xtask`'s QEMU harness, which
/// reads [`WITNESS_SECTOR`] out of the data disk after the run and compares it
/// against [`witness_pattern`] byte for byte. It calls these definitions rather
/// than restating them, so the two sides cannot drift.
pub const WITNESS_MAGIC: [u8; 8] = *b"LFW-BLK1";

/// Bytes of the witness pattern that are the magic and the sector it names.
const WITNESS_HEADER_LEN: usize = WITNESS_MAGIC.len() + size_of::<u64>();

/// How many completion polls one step may take before the device is declared
/// silent.
///
/// A driver constant rather than anything the device influences, which is what
/// makes the wait bounded (ENG-4). Large enough that a device merely slow under
/// an emulated CPU finishes inside it, and small enough that a device which
/// never answers gives the domain back to the scheduler in seconds rather than
/// holding a priority-1 timeslice for the life of the appliance.
pub const POLL_BUDGET: u32 = 20_000_000;

/// The 512 bytes the proof writes, and what an observer must find at
/// [`WITNESS_SECTOR`] afterwards.
///
/// Deliberately not a constant fill. A medium that answers every read with
/// zeroes, a staging window the write never left, and a disk image nobody
/// touched all produce a uniform sector; a pattern that varies byte to byte
/// and names its own target sector can only be there because these bytes were
/// written.
#[must_use]
pub fn witness_pattern() -> [u8; SECTOR_SIZE] {
    let mut out = [0u8; SECTOR_SIZE];
    let header = WITNESS_MAGIC
        .into_iter()
        .chain(WITNESS_SECTOR.to_le_bytes());
    for (byte, value) in out.iter_mut().zip(header) {
        *byte = value;
    }
    for (at, byte) in out.iter_mut().enumerate().skip(WITNESS_HEADER_LEN) {
        *byte = filler(at);
    }
    out
}

/// The pattern's body: a function of the offset alone, so every byte of the
/// sector carries a position and a sector shifted by even one byte fails the
/// comparison.
const fn filler(at: usize) -> u8 {
    (at as u8) ^ 0x5A
}

/// Telling the device to look at the request queue.
///
/// A seam over [`Live::ring`] rather than the [`Live`] itself, because a host
/// test's stand-in device has to *complete* the request the doorbell announces
/// — which is the whole of what a doorbell means to this module — and building
/// a [`Live`] would additionally require standing in for a PCI configuration
/// space that has nothing to do with the proof.
pub trait Ring {
    fn ring(&self);
}

impl<D: BlkDevice> Ring for Live<D> {
    fn ring(&self) {
        Live::ring(self);
    }
}

/// Which half of the proof a failure happened in. Carried on every error
/// because the two mean different things about the medium: a probe that failed
/// is a device that cannot be read, and a witness that failed is one that
/// answers reads and commits nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Probe,
    Witness,
}

impl Step {
    const fn operation(self) -> Operation {
        match self {
            Self::Probe => Operation::Read,
            Self::Witness => Operation::Write,
        }
    }

    const fn device_sector(self) -> u64 {
        match self {
            Self::Probe => PROBE_SECTOR,
            Self::Witness => WITNESS_SECTOR,
        }
    }

    /// The staging sector this step's data segment names. The two are disjoint,
    /// so the bytes the device wrote cannot be the bytes it is about to read.
    const fn staging(self) -> IoSector {
        match self {
            Self::Probe => IoSector::FIRST,
            Self::Witness => IoSector::SECOND,
        }
    }
}

/// Why the proof did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmokeError {
    /// The device claims fewer sectors than the proof addresses. Its own
    /// variant rather than a refused submit, because it is a fact about the
    /// medium rather than about one request, and it is decided before anything
    /// is published.
    TooSmall { capacity: u64, needed: u64 },
    /// The request layer refused to publish the step. Every [`SubmitError`]
    /// reachable here is a defect in this module or in the region wiring — the
    /// queue is otherwise empty and the range was checked — so the variant
    /// carries which, rather than being folded into a general failure.
    Refused { step: Step, error: SubmitError },
    /// [`POLL_BUDGET`] completions' worth of polling produced nothing this
    /// module could attribute to the request it submitted.
    Silent { step: Step },
    /// A completion arrived carrying a token the step did not mint. Expected to
    /// be unreachable — the queue holds one request at a time here — and its
    /// own variant precisely so that its arrival is legible rather than
    /// reported as a device error.
    Misattributed { step: Step },
    /// The device answered, and said no.
    Failed { step: Step, outcome: Outcome },
    /// The device answered `Ok` for fewer bytes than the sector it was asked
    /// for. A success by status and a failure in fact, which is exactly the
    /// case a proof exists to separate.
    Short { step: Step, bytes: u32 },
}

impl SmokeError {
    /// This failure as the console record of it, on the same terms
    /// `bringup::BringUpError::refusal` states its own: a token naming what
    /// broke and the numbers that token names.
    ///
    /// `signalled` is false throughout. The device is past `DRIVER_OK` by the
    /// time any of these is reachable and nothing here writes `STATUS_FAILED`
    /// to it: a medium that would not answer one request is left running, so a
    /// later milestone can retry it without a reset.
    #[must_use]
    pub fn refusal(&self) -> Refusal {
        let (cause, detail) = match self {
            Self::TooSmall { capacity, needed } => (
                "block-device-too-small",
                RefusalDetail::Two(*capacity, *needed),
            ),
            Self::Refused { step, error } => (
                match step {
                    Step::Probe => "block-probe-refused",
                    Step::Witness => "block-witness-refused",
                },
                RefusalDetail::One(submit_code(*error)),
            ),
            Self::Silent { step } => (
                match step {
                    Step::Probe => "block-probe-silent",
                    Step::Witness => "block-witness-silent",
                },
                RefusalDetail::One(u64::from(POLL_BUDGET)),
            ),
            Self::Misattributed { step } => (
                match step {
                    Step::Probe => "block-probe-misattributed",
                    Step::Witness => "block-witness-misattributed",
                },
                RefusalDetail::None,
            ),
            Self::Failed { step, outcome } => (
                match step {
                    Step::Probe => "block-probe-failed",
                    Step::Witness => "block-witness-failed",
                },
                RefusalDetail::One(outcome_code(*outcome)),
            ),
            Self::Short { step, bytes } => (
                match step {
                    Step::Probe => "block-probe-short",
                    Step::Witness => "block-witness-short",
                },
                RefusalDetail::Two(u64::from(*bytes), SECTOR_SIZE as u64),
            ),
        };
        Refusal {
            cause,
            detail,
            signalled: false,
        }
    }

    /// Which step failed, for a caller reporting on the proof as a whole.
    #[must_use]
    pub const fn step(&self) -> Option<Step> {
        match self {
            Self::TooSmall { .. } => None,
            Self::Refused { step, .. }
            | Self::Silent { step }
            | Self::Misattributed { step }
            | Self::Failed { step, .. }
            | Self::Short { step, .. } => Some(*step),
        }
    }
}

/// A [`SubmitError`] as one number, so a refusal reaches the console as which
/// refusal it was and not only as its class.
///
/// A small integer rather than the console's own vocabulary, because the
/// refusal tree belongs to `request` and a second copy of it here would drift
/// from it with nothing failing — the same reason [`Refusal::cause`] is a token
/// rather than an enum.
const fn submit_code(error: SubmitError) -> u64 {
    match error {
        SubmitError::NoFreeSlot => 0,
        SubmitError::QueueFull => 1,
        SubmitError::LengthNotSectorMultiple { .. } => 2,
        SubmitError::LengthZero => 3,
        SubmitError::OutsideCapacity { .. } => 4,
        SubmitError::DataAddressUnaligned { .. } => 5,
    }
}

/// An [`Outcome`] as one number, on [`submit_code`]'s terms. The device's own
/// status byte for the one case it is not one of the three defined values, so
/// nothing the device said is lost on the way to the console.
const fn outcome_code(outcome: Outcome) -> u64 {
    match outcome {
        Outcome::Ok => 0,
        Outcome::DeviceError => 1,
        Outcome::Unsupported => 2,
        Outcome::UnknownStatus { status } => 0x100 | status as u64,
    }
}

/// What the proof established about the medium.
///
/// Numbers only. [`probe_word`](Self::probe_word) is the first eight bytes of
/// what the device returned, which is device input and is carried as an
/// integer for an operator to look at — it steers nothing here and reaches no
/// surface but the console, so OBS-5 is satisfied by there being no payload in
/// it beyond eight bytes of a sector the appliance itself put nothing in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// The capacity the device claimed at bring-up, in [`SECTOR_SIZE`] sectors.
    pub capacity_sectors: u64,
    /// The first eight bytes of [`PROBE_SECTOR`], little-endian.
    pub probe_word: u64,
    /// Where the witness pattern was committed.
    pub witness_sector: u64,
}

/// Run the proof: read [`PROBE_SECTOR`], then write [`witness_pattern`] to
/// [`WITNESS_SECTOR`], waiting for each completion before starting the next.
///
/// One request in flight at a time, which is not an efficiency choice: the
/// second step's meaning depends on the first having finished, and a proof that
/// could not say which completion answered which request would prove nothing
/// about either.
///
/// # Errors
/// A [`SmokeError`]. The device is left live on every one of them.
pub fn prove(
    requests: &mut Requests<'_>,
    io: &mut IoRegion<'_>,
    ring: &dyn Ring,
) -> Result<Report, SmokeError> {
    let capacity = requests.capacity_sectors();
    if capacity < MINIMUM_CAPACITY_SECTORS {
        return Err(SmokeError::TooSmall {
            capacity,
            needed: MINIMUM_CAPACITY_SECTORS,
        });
    }

    run(requests, io, ring, Step::Probe)?;
    let mut probe = [0u8; SECTOR_SIZE];
    io.take(Step::Probe.staging(), &mut probe);

    io.put(Step::Witness.staging(), &witness_pattern());
    run(requests, io, ring, Step::Witness)?;

    Ok(Report {
        capacity_sectors: capacity,
        probe_word: leading_word(&probe),
        witness_sector: WITNESS_SECTOR,
    })
}

/// The first eight bytes of a sector as a little-endian integer.
///
/// Total over the array: a sector is longer than eight bytes by
/// `crate::SECTOR_SIZE`'s definition, and the copy is bounded by the
/// destination rather than by the source, so there is no length to get wrong
/// and no index to leave the buffer (ENG-5).
fn leading_word(sector: &[u8; SECTOR_SIZE]) -> u64 {
    let mut leading = [0u8; size_of::<u64>()];
    for (byte, value) in leading.iter_mut().zip(sector) {
        *byte = *value;
    }
    u64::from_le_bytes(leading)
}

/// Publish one step, ring, and wait for the completion that answers it.
fn run(
    requests: &mut Requests<'_>,
    io: &mut IoRegion<'_>,
    ring: &dyn Ring,
    step: Step,
) -> Result<(), SmokeError> {
    let token = requests
        .submit(
            step.operation(),
            step.device_sector(),
            io.sector_paddr(step.staging()),
            SECTOR_SIZE as u32,
        )
        .map_err(|error| SmokeError::Refused { step, error })?;
    ring.ring();
    let completed = await_completion(requests, step)?;
    judge(step, &token, &completed)
}

/// Poll until the device answers, or until the budget is spent.
fn await_completion(requests: &mut Requests<'_>, step: Step) -> Result<Completed, SmokeError> {
    for _ in 0..POLL_BUDGET {
        if let Some(completed) = requests.poll() {
            return Ok(completed);
        }
        core::hint::spin_loop();
    }
    Err(SmokeError::Silent { step })
}

/// What one completion says about the step that was submitted.
fn judge(step: Step, token: &Token, completed: &Completed) -> Result<(), SmokeError> {
    if completed.token != *token || completed.operation != step.operation() {
        return Err(SmokeError::Misattributed { step });
    }
    if completed.outcome != Outcome::Ok {
        return Err(SmokeError::Failed {
            step,
            outcome: completed.outcome,
        });
    }
    if completed.bytes != SECTOR_SIZE as u32 {
        return Err(SmokeError::Short {
            step,
            bytes: completed.bytes,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
