//! Reading each recording's superblock off the medium before the first record is
//! placed, so a boot continues the ring the last one left instead of writing a
//! fresh one over it.
//!
//! # Why it is here and not in the protection domain
//!
//! Every judgement it makes is first-party logic: which sector a recording's
//! superblock is at, how long the device may take to answer, what counts as a
//! completion for the read that was submitted, and whether what came back is a
//! superblock at all. Logic welded to a Microkit entrypoint is logic no host test
//! can reach, so the domain supplies the [`Medium`] and this module supplies every
//! decision made through it.
//!
//! # The adversary
//!
//! A **hostile or malfunctioning device**. The bytes read back are whatever holds
//! the extent — a medium an offline attacker composed, another deployment's ring,
//! a sector the device mis-addressed — and nothing here believes any of it: a
//! completion is matched against the job the submit was made under, a short or
//! failed transfer is a typed error rather than a success, the wait is bounded by
//! [`POLL_BUDGET`] so a device that never answers parks this read instead of this
//! domain, and what decodes is a [`RingState`] and not yet something a ring may
//! resume from — [`lfw_capture_ring::RingState::check`], against a geometry this
//! side built, is what settles that.
//!
//! # An unwritten medium is not a failure
//!
//! Both copies failing to decode is the ordinary first boot, so it is `None` and
//! never an error. A device refusing the read is: the boot proof has already moved
//! a sector each way by then, so a medium that will not answer here is one that
//! stopped answering, and a recording appliance that cannot read its own extent
//! has nothing to say about what it is about to overwrite.

use lfw_capture_ring::{
    GeometryError, RingState, SECTOR_SIZE, SUPERBLOCK_BYTES, decode_superblock,
};

use crate::deck::{Area, Completion, Ended, Job, Medium, Polled, Transfer, Which};

/// How many polls one read may take before the device is declared silent.
///
/// A first-party constant rather than anything the device influences, which is
/// what makes the wait bounded. The block path's boot proof spends the same budget
/// per step and for the same reasons: large enough that a device merely slow under
/// an emulated CPU finishes inside it, and small enough that one which never
/// answers gives the domain back to the scheduler in seconds.
pub const POLL_BUDGET: u32 = 20_000_000;

/// Why a recording's superblock could not be read. Each variant names the
/// recording it is about, the two extents failing independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreloadError {
    /// The extent is not a ring on this device, so there is no sector to read —
    /// the same fact [`crate::deck::DeckError::Extent`] reports, found earlier.
    Extent { which: Which, error: GeometryError },
    /// The medium would not take the read. Backpressure elsewhere in this crate
    /// and a failure here: nothing else is in flight at boot, so a device with no
    /// room for one descriptor has stopped working rather than being busy.
    Refused { which: Which },
    /// [`POLL_BUDGET`] polls produced no completion this module could attribute
    /// to the read it submitted.
    Silent { which: Which },
    /// A completion for a job this read did not submit. Expected to be unreachable
    /// — one request is outstanding at a time — and its own variant precisely so
    /// that its arrival is legible rather than reported as a device error.
    Misattributed { which: Which },
    /// The device answered, and said no.
    Failed { which: Which },
    /// The device answered `Ok` having moved fewer bytes than the region is. A
    /// success by status and a failure in fact: the shortfall still holds whatever
    /// was in the staging area, so decoding it would decode this side's leftovers.
    Short { which: Which, delivered: usize },
    /// The staging area is not the region's size, so there is nothing of the right
    /// shape to decode — a [`Medium`] breaking its own documented length rather
    /// than anything the device did, and its own variant for the reason above.
    Unstaged { which: Which, len: usize },
}

impl PreloadError {
    /// Which recording the read was for.
    #[must_use]
    pub const fn which(&self) -> Which {
        match self {
            Self::Extent { which, .. }
            | Self::Refused { which }
            | Self::Silent { which }
            | Self::Misattributed { which }
            | Self::Failed { which }
            | Self::Short { which, .. }
            | Self::Unstaged { which, .. } => *which,
        }
    }
}

/// Read both recordings' superblocks, in [`Which::ALL`] order. `None` for an
/// extent neither copy of which decodes, which is the ordinary first boot.
///
/// The reads are sequential rather than both in flight, and that is not an
/// efficiency choice: one request outstanding at a time is what lets a completion
/// be attributed, and both would share the one staging area besides.
///
/// # Errors
/// A [`PreloadError`] naming the recording whose read failed. The device is left
/// live on every one of them.
pub fn read_superblocks(
    capacity_sectors: u64,
    medium: &mut impl Medium,
) -> Result<[Option<RingState>; 2], PreloadError> {
    let mut stored = [None; 2];
    // Bounded by the array: the zip stops at whichever is shorter.
    for (slot, which) in stored.iter_mut().zip(Which::ALL) {
        *slot = read_one(which, capacity_sectors, medium)?;
    }
    Ok(stored)
}

/// One recording's superblock, or `None` for an extent nothing wrote.
fn read_one(
    which: Which,
    capacity_sectors: u64,
    medium: &mut impl Medium,
) -> Result<Option<RingState>, PreloadError> {
    let geometry = which
        .geometry(capacity_sectors)
        .map_err(|error| PreloadError::Extent { which, error })?;
    let job = Job::Preload(which);
    medium
        .submit(
            job,
            Transfer {
                area: Area::Superblock,
                at: 0,
                sector: geometry.superblock_sector(),
                len: SUPERBLOCK_BYTES,
                write: false,
            },
        )
        .map_err(|_| PreloadError::Refused { which })?;
    let completion = await_completion(medium, which)?;
    judge(which, job, &completion)?;

    let staging: &[u8] = medium.staging(Area::Superblock);
    let Ok(region) = <&[u8; SUPERBLOCK_BYTES]>::try_from(staging) else {
        return Err(PreloadError::Unstaged {
            which,
            len: staging.len(),
        });
    };
    Ok(decode_superblock(region))
}

/// Poll until the device answers the read, or until the budget is spent. A
/// completion the medium could attribute to no job is counted against the same
/// budget and the drain goes on: a device replaying its used ring must not be able
/// to end this wait, and must not be able to extend it either.
fn await_completion(medium: &mut impl Medium, which: Which) -> Result<Completion, PreloadError> {
    for _ in 0..POLL_BUDGET {
        match medium.poll() {
            Some(Polled::Settled(completion)) => return Ok(completion),
            Some(Polled::Unattributed) => {}
            None => core::hint::spin_loop(),
        }
    }
    Err(PreloadError::Silent { which })
}

/// What one completion says about the read that was submitted.
fn judge(which: Which, job: Job, completion: &Completion) -> Result<(), PreloadError> {
    if completion.job != job {
        return Err(PreloadError::Misattributed { which });
    }
    match completion.ended {
        Ended::Failed => Err(PreloadError::Failed { which }),
        Ended::Ok { delivered } if delivered != SUPERBLOCK_BYTES => {
            Err(PreloadError::Short { which, delivered })
        }
        Ended::Ok { .. } => Ok(()),
    }
}

// The region is a whole number of sectors, so the read asks the device for exactly
// what a transfer may be; a layout change that broke this would leave it asking
// for a partial sector, which a driver refuses at submit.
const _: () = assert!(SUPERBLOCK_BYTES.is_multiple_of(SECTOR_SIZE));

#[cfg(test)]
mod tests;
