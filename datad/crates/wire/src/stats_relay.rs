//! One whole metric reading, handed from the domain that can see every counter
//! shard to the domain that can write the medium.
//!
//! Faces the byzantine neighbour protection domain, on both sides. The
//! writer composed its numbers out of eleven regions other domains own, so what
//! arrives here is those domains' claims one indirection away; the reader is a
//! peer whose behaviour the writer may not assume either. Nothing here judges a
//! value: a counter is a `u64` and every bit pattern of one is a number.
//!
//! # Why this region exists at all
//!
//! The statistics shards are granted one writer and one reader each, and the
//! reader is the management domain. The recorder is the only domain that can
//! write the recording medium, and it maps no shard but its own — widening that
//! would delete the property the shard grants exist for. So the numbers travel
//! the other way: the domain that may read them all publishes one reading here,
//! and the domain that may write the medium copies it out. One page of authority
//! replaces eleven read grants on the domain holding the block device.
//!
//! # Why a seqlock, when a shard needs none
//!
//! A shard's slots are independently meaningful — a reader draws no conclusion
//! from two of them having moved together — so a shard is published with plain
//! relaxed stores. A *reading* is the opposite: its whole point is that every
//! number in it was taken at one instant, and a reader that assembled half of
//! one publish and half of the next would ship a moment that never existed to a
//! server that cannot tell. So this region carries
//! [`ClockCalibration`](crate::ClockCalibration)'s counter, for that type's
//! reason and with its protocol: **even means settled, odd means being
//! written**, and a reader accepts only a pair of equal even readings.
//!
//! The counter is also what paces the reader. It rises once per publish, so a
//! reader that remembers the last generation it took knows without a clock of
//! its own whether there is anything new to write — which is what lets the
//! recording's snapshot rate follow the publisher's rather than a second timer
//! that could drift away from it.
//!
//! # Bounded, because the writer is a peer
//!
//! A reader retries a torn read [`LOAD_ATTEMPTS`](crate::LOAD_ATTEMPTS) times
//! and then answers that there is nothing to read. A peer that holds the counter
//! odd — by faulting mid-publish, or on purpose — costs the reader a bounded run
//! of loads and a snapshot it reports having missed, never a spin.

use core::{
    mem::{align_of, offset_of, size_of},
    sync::atomic::{AtomicU32, AtomicU64, Ordering, fence},
};

use crate::{LOAD_ATTEMPTS, MAPPING_ALIGN};

/// Bytes of the region ahead of the first slot: the counter, its padding, and
/// the instant the reading was taken at.
const RELAY_HEADER_BYTES: usize = 16;

/// Counter slots the region carries.
///
/// Derived rather than chosen: the region is one page, and this is every slot
/// that fits behind [`RELAY_HEADER_BYTES`] in it. A page was already the
/// smallest grant a mapping can be, so slots below this number would buy no
/// memory and would only be a bound to raise later — and a reading that needed
/// more than a page would be a second page of authority on the domain holding
/// the block device.
///
/// The catalogue is what decides how many of these are *used*, and it is held
/// to this bound at build time by the crate that owns it (`lfw_metrics`), so a
/// catalogue that outgrew the page is a compile error rather than a reading
/// silently cut short.
pub const RELAY_SLOTS: usize = (MAPPING_ALIGN - RELAY_HEADER_BYTES) / 8;

/// The region: one reading, and the counter that publishes it whole.
///
/// Every field is private and the only ways in are [`publish`](Self::publish)
/// and [`load`](Self::load), so the protocol is a property of the type rather
/// than a convention its two domains are asked to keep.
#[repr(C, align(64))]
pub struct StatsRelay {
    generation: AtomicU32,
    /// Padding to the alignment the words below need, named rather than
    /// implicit so the layout assertions are about a declared field and a port
    /// to a target that padded differently fails them.
    _pad: AtomicU32,
    /// The instant the writer says the reading was taken at, in nanoseconds
    /// since the Unix epoch. Zero where the writer had no clock — a fact the
    /// reader carries onward rather than one it repairs, the writer being the
    /// only party that knows whether time was established.
    unix_nanos: AtomicU64,
    slots: [AtomicU64; RELAY_SLOTS],
}

/// One reading taken whole: what the writer said the instant was, how many
/// slots it filled, and the slots.
///
/// `filled` is the writer's own count and is bounded by [`RELAY_SLOTS`] on the
/// way in, so a reader indexes `slots` with it without a further check. Slots
/// past it are zero and mean nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayImage {
    pub unix_nanos: u64,
    pub filled: usize,
    pub slots: [u64; RELAY_SLOTS],
}

impl RelayImage {
    /// The slots the writer actually filled.
    #[must_use]
    pub fn values(&self) -> &[u64] {
        // `filled` is bounded by `RELAY_SLOTS` where it is set, so the fallback
        // is unreachable; it is a value rather than an assertion because
        // nothing about a metric reading may fault a domain.
        self.slots.get(..self.filled).unwrap_or(&self.slots)
    }
}

impl StatsRelay {
    /// A zeroed region, which is what the kernel hands a domain that maps one:
    /// generation zero is even and settled, and no reader accepts it as a
    /// reading.
    ///
    /// A function rather than a `const` for
    /// [`ClockCalibration::zero`](crate::ClockCalibration::zero)'s reason: a
    /// `const` holding an atomic is copied at every mention.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            generation: AtomicU32::new(0),
            _pad: AtomicU32::new(0),
            unix_nanos: AtomicU64::new(0),
            slots: [const { AtomicU64::new(0) }; RELAY_SLOTS],
        }
    }

    /// Publish one reading, leaving the counter even and higher than it was.
    ///
    /// `values` longer than the region is written as far as the region reaches;
    /// the crate that owns the catalogue asserts at build time that this cannot
    /// happen, and a bound that cannot be violated is better spent on the array
    /// than on an error nobody can produce. Slots the reading does not reach are
    /// zeroed, so a shorter publish never leaves a longer one's tail behind for
    /// a reader to attribute to it.
    pub fn publish(&self, unix_nanos: u64, values: &[u64]) {
        // `| 1` rather than `+ 1`: it makes the counter odd from any starting
        // value, so a region left odd by a writer that faulted mid-publish is
        // still published into correctly rather than being left permanently
        // unreadable.
        let writing = self.generation.load(Ordering::Relaxed) | 1;
        self.generation.store(writing, Ordering::Relaxed);
        // The odd counter must be visible before the words move, which is what
        // this fence orders; the `Release` on the settling store below is what
        // orders them before it.
        fence(Ordering::Release);
        self.unix_nanos.store(unix_nanos, Ordering::Relaxed);
        for (slot, value) in self.slots.iter().zip(values) {
            slot.store(*value, Ordering::Relaxed);
        }
        for slot in self.slots.iter().skip(values.len()) {
            slot.store(0, Ordering::Relaxed);
        }
        self.generation
            .store(writing.wrapping_add(1), Ordering::Release);
    }

    /// The generation now published, for a reader reporting on what it saw. Odd
    /// while a publish is in progress.
    #[must_use]
    pub fn generation(&self) -> u32 {
        self.generation.load(Ordering::Acquire)
    }

    /// One whole reading and the generation it was published under, or `None`.
    ///
    /// `None` means one of three things and the caller need not tell them apart:
    /// nothing has been published, a publish is in progress, or the writer
    /// changed it under this read [`LOAD_ATTEMPTS`](crate::LOAD_ATTEMPTS) times
    /// over. All three are "no reading right now", which is a state a caller
    /// reports rather than a failure it recovers from.
    ///
    /// `filled` is how many slots the caller asked to be read, bounded here
    /// rather than trusted: it comes from the catalogue on the reading side and
    /// the two sides are separate binaries.
    #[must_use]
    pub fn load(&self, filled: usize) -> Option<(u32, RelayImage)> {
        let filled = filled.min(RELAY_SLOTS);
        for _ in 0..LOAD_ATTEMPTS {
            let before = self.generation.load(Ordering::Acquire);
            if !before.is_multiple_of(2) {
                continue;
            }
            let mut image = RelayImage {
                unix_nanos: self.unix_nanos.load(Ordering::Relaxed),
                filled,
                slots: [0; RELAY_SLOTS],
            };
            for (value, slot) in image.slots.iter_mut().zip(&self.slots).take(filled) {
                *value = slot.load(Ordering::Relaxed);
            }
            // The words must be read before the counter is read again, which is
            // what this orders; without it the second load could be hoisted
            // above them and a torn reading would compare equal.
            fence(Ordering::Acquire);
            // Two conditions, answered the same way: a counter that changed
            // under the read is a publish this attempt lost, and generation zero
            // is a region nobody has published into. Both leave the loop to try
            // again and its bound to end it.
            //
            // A known bound, and `ClockCalibration`'s: the counter is a `u32`
            // that wraps, so a writer publishing 2^31 times lands it on zero and
            // this reader calls a published reading unpublished. Fail-safe, and
            // no denial a byzantine writer lacks already by simply not
            // publishing.
            if self.generation.load(Ordering::Relaxed) == before && before != 0 {
                return Some((before, image));
            }
        }
        None
    }
}

/// Bytes the system description reserves for the region, derived rather than
/// chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const STATS_RELAY_REGION_SIZE: usize = size_of::<StatsRelay>().next_multiple_of(MAPPING_ALIGN);

// The layout two protection domains agree on, fixed at build time. One maps this
// region read-write and the other read-only, and neither can see the other's
// view of it, so a reorder or a width change must be a compile error here rather
// than a reader attributing one series' number to another.
const _: () = {
    assert!(size_of::<StatsRelay>() == MAPPING_ALIGN);
    assert!(align_of::<StatsRelay>() == 64);
    assert!(offset_of!(StatsRelay, generation) == 0);
    assert!(offset_of!(StatsRelay, _pad) == 4);
    assert!(offset_of!(StatsRelay, unix_nanos) == 8);
    assert!(offset_of!(StatsRelay, slots) == RELAY_HEADER_BYTES);

    // Every slot naturally aligned, which is what makes each store and load a
    // single access rather than two a reader could tear across.
    assert!(RELAY_HEADER_BYTES.is_multiple_of(align_of::<u64>()));
    assert!(RELAY_SLOTS * 8 + RELAY_HEADER_BYTES == MAPPING_ALIGN);

    assert!(STATS_RELAY_REGION_SIZE >= size_of::<StatsRelay>());
    assert!(STATS_RELAY_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(STATS_RELAY_REGION_SIZE == MAPPING_ALIGN);
};

#[cfg(test)]
mod tests;
