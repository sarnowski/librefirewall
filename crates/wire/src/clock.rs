//! The calibration one domain measures and another reads: a counter frequency,
//! the reading it was anchored on, and the wall-clock instant that reading
//! corresponds to.
//!
//! Faces the byzantine neighbour protection domain. The domain that
//! writes this region measured its numbers against a device (`pds/clock`), so
//! what arrives here is a hostile or malfunctioning device's answer one
//! indirection away — and the writing domain itself is a peer whose behaviour a
//! reader may not assume. Nothing here judges the values: whether a frequency or
//! an epoch is plausible is `lfw_clock`'s question, and this crate cannot ask it
//! without depending on the crate that reads the region.
//!
//! # Why a seqlock rather than the handover's generation word
//!
//! [`ConfigHandover`](crate::ConfigHandover) publishes bytes and *then* releases
//! a generation, which is enough for it: an image is read whole, and a reader
//! that observed a torn one would refuse it on a field it could not decode.
//! A calibration has no such backstop. Its three words are only meaningful
//! *together* — a frequency from one measurement anchored to another
//! measurement's epoch names an instant that never existed — and every bit
//! pattern of each of them is individually plausible, so a torn triple is
//! undetectable by inspection.
//!
//! The generation counter here therefore carries the write in progress rather
//! than the identity of what was written: **even means settled, odd means being
//! written**. A reader takes the counter, the triple and the counter again, and
//! accepts only a pair of equal even readings — so it either sees one publisher's
//! whole triple or nothing at all. That is one word of state and no lock, which
//! matters because the reader is on the path of a management request and the
//! writer is a domain it cannot signal.
//!
//! # Bounded, because the writer is a peer
//!
//! A reader retries a torn read [`LOAD_ATTEMPTS`] times and then gives
//! up. A peer that holds the counter odd — by faulting mid-publish, or on
//! purpose — must not be able to spin a reader forever; a caller that is told
//! "nothing" once has lost a timestamp, which is a refusal it can report.

use core::{
    mem::{align_of, offset_of, size_of},
    sync::atomic::{AtomicU32, AtomicU64, Ordering, fence},
};

use crate::MAPPING_ALIGN;

/// How many times a reader retries a torn read before answering that there is
/// nothing to read.
///
/// Four rather than one, because a single retry would fail whenever a read
/// happened to land inside a publish — and rather than many, because a writer
/// that is still mid-publish after four attempts is not one more attempts will
/// help. A publish is five stores — the counter odd, the three words, the counter
/// even — so a reader losing four races to it has met something other than
/// ordinary interleaving.
pub const LOAD_ATTEMPTS: usize = 4;

/// A calibration as three raw words: what the writer measured, before anybody
/// has judged it.
///
/// Deliberately not `lfw_clock::Calibration`: that type's frequency is a
/// `NonZeroU64` and its constructor is a claim that the numbers are usable, and
/// nothing in a shared region may make that claim. The reading domain turns this
/// into one, or refuses it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CalibrationImage {
    pub tsc_hz: u64,
    pub boot_ticks: u64,
    pub boot_unix_nanos: u64,
}

/// The region: the three words and the counter that publishes them together.
///
/// Every field is private and the only ways in are [`publish`](Self::publish) and
/// [`load`](Self::load), so the protocol is a property of the type rather than a
/// convention its two domains are asked to keep.
#[repr(C)]
pub struct ClockCalibration {
    generation: AtomicU32,
    /// Padding to the alignment the three `u64`s need, named rather than implicit
    /// so the layout assertions below are about a declared field and a port to a
    /// target that padded differently fails them.
    _pad: AtomicU32,
    tsc_hz: AtomicU64,
    boot_ticks: AtomicU64,
    boot_unix_nanos: AtomicU64,
}

impl ClockCalibration {
    /// A zeroed region, which is what the kernel hands a domain that maps one:
    /// generation zero is even and settled, and a triple of zeroes is one no
    /// reader will accept as a calibration.
    ///
    /// A function rather than a `const` for [`ConfigHandover::zero`](crate::ConfigHandover::zero)'s
    /// reason: a `const` holding an atomic is copied at every mention.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            generation: AtomicU32::new(0),
            _pad: AtomicU32::new(0),
            tsc_hz: AtomicU64::new(0),
            boot_ticks: AtomicU64::new(0),
            boot_unix_nanos: AtomicU64::new(0),
        }
    }

    /// Publish one triple, leaving the counter even and higher than it was.
    ///
    /// Two higher from an even counter and one from an odd one, which is the point
    /// of the `| 1` below: the protocol needs the counter to end even and differ
    /// from what a reader could have taken, not to advance by a fixed step.
    ///
    /// The counter goes odd first, the words move under it, and it goes even
    /// last — so a reader that catches any part of this sees an odd counter or a
    /// changed one, and never a triple assembled from two publishes.
    pub fn publish(&self, image: &CalibrationImage) {
        // `| 1` rather than `+ 1`: it makes the counter odd from any starting
        // value, so a region left odd by a writer that faulted mid-publish is
        // still published into correctly rather than being left permanently
        // unreadable.
        let writing = self.generation.load(Ordering::Relaxed) | 1;
        self.generation.store(writing, Ordering::Relaxed);
        // The odd counter must be visible before the words move, which is what
        // this fence orders; the `Release` on the settling store below is what
        // orders the words before it.
        fence(Ordering::Release);
        self.tsc_hz.store(image.tsc_hz, Ordering::Relaxed);
        self.boot_ticks.store(image.boot_ticks, Ordering::Relaxed);
        self.boot_unix_nanos
            .store(image.boot_unix_nanos, Ordering::Relaxed);
        self.generation
            .store(writing.wrapping_add(1), Ordering::Release);
    }

    /// The generation now published, for a reader reporting on what it saw. Odd
    /// while a publish is in progress.
    #[must_use]
    pub fn generation(&self) -> u32 {
        self.generation.load(Ordering::Acquire)
    }

    /// One whole triple, or `None`.
    ///
    /// `None` means one of three things and the caller need not tell them apart:
    /// nothing has been published, a publish is in progress, or the writer
    /// changed it under this read [`LOAD_ATTEMPTS`] times over. All three are
    /// "no calibration right now", which is a state a caller reports rather than
    /// a failure it recovers from.
    #[must_use]
    pub fn load(&self) -> Option<CalibrationImage> {
        for _ in 0..LOAD_ATTEMPTS {
            let before = self.generation.load(Ordering::Acquire);
            if !before.is_multiple_of(2) {
                continue;
            }
            let image = CalibrationImage {
                tsc_hz: self.tsc_hz.load(Ordering::Relaxed),
                boot_ticks: self.boot_ticks.load(Ordering::Relaxed),
                boot_unix_nanos: self.boot_unix_nanos.load(Ordering::Relaxed),
            };
            // The words must be read before the counter is read again, which is
            // what this orders; without it the second load could be hoisted above
            // them and a torn triple would compare equal.
            fence(Ordering::Acquire);
            // Two conditions, answered the same way: a counter that changed under
            // the read is a publish this attempt lost, and generation zero is a
            // region nobody has published into. Both leave the loop to try again
            // and its bound to end it, so "no calibration" is one answer with one
            // meaning rather than two the caller must tell apart.
            //
            // A known bound: the counter is a `u32` that wraps, so a writer
            // publishing 2^31 times lands it on zero and this reader calls a
            // published triple unpublished. Fail-safe, and no denial a byzantine
            // writer lacks already by simply not publishing.
            if self.generation.load(Ordering::Relaxed) == before && before != 0 {
                return Some(image);
            }
        }
        None
    }
}

/// Bytes the system description reserves for the region, derived rather than
/// chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const CLOCK_CALIBRATION_REGION_SIZE: usize =
    size_of::<ClockCalibration>().next_multiple_of(MAPPING_ALIGN);

// The layout two protection domains agree on, fixed at build time. One
// maps this region read-write and the other read-only, and neither can see the
// other's view of it, so a reorder or a width change must be a compile error
// here rather than a silent break of the triple the reading domain assembles.
const _: () = {
    assert!(size_of::<ClockCalibration>() == 32);
    assert!(align_of::<ClockCalibration>() == 8);
    assert!(offset_of!(ClockCalibration, generation) == 0);
    assert!(offset_of!(ClockCalibration, _pad) == 4);
    assert!(offset_of!(ClockCalibration, tsc_hz) == 8);
    assert!(offset_of!(ClockCalibration, boot_ticks) == 16);
    assert!(offset_of!(ClockCalibration, boot_unix_nanos) == 24);

    // The three words are naturally aligned, which is what makes each store and
    // load a single access rather than two a reader could tear across.
    assert!(offset_of!(ClockCalibration, tsc_hz).is_multiple_of(align_of::<u64>()));
    assert!(offset_of!(ClockCalibration, boot_ticks).is_multiple_of(align_of::<u64>()));
    assert!(offset_of!(ClockCalibration, boot_unix_nanos).is_multiple_of(align_of::<u64>()));

    assert!(CLOCK_CALIBRATION_REGION_SIZE >= size_of::<ClockCalibration>());
    assert!(CLOCK_CALIBRATION_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
};

#[cfg(test)]
mod tests;
