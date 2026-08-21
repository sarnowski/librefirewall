//! The newest configuration version this appliance's medium records: one word,
//! written by the domain that holds the medium and read by the domain that numbers
//! configurations.
//!
//! Faces the byzantine neighbour protection domain. The reader maps this region
//! read-only and the writer is a peer whose behaviour it may not assume, so every
//! bit pattern reaching [`DurableGeneration::recorded`] is peer-written input.
//! What makes that safe is the total answer: every value the word can hold is a
//! version number, and the reader's only use for one is to number the next
//! configuration *above* it. A writer that puts a larger number here costs the
//! reader generations and never a fault — and it is the domain that decides
//! whether anything becomes durable at all, so it could refuse every version by
//! saying nothing.
//!
//! # Why the reader cannot take this for the running configuration
//!
//! Two notions of *current* meet here and conflating them is a defect this
//! appliance has already had. This word is the high-water mark of the **durable
//! history**; what the reader is running is whatever document is in force, which
//! after a boot is the one compiled into the image and is on no medium at all. So
//! it is a floor on the numbering and never the number of anything running.
//!
//! # One word, and why there is no seqlock over it
//!
//! [`ClockCalibration`](crate::ClockCalibration) brackets its three words with a
//! counter because they are meaningful only together and a torn triple is
//! undetectable by inspection. There is nothing here to tear: a naturally aligned
//! `u64` store is one access.
//!
//! # Zero is the absence
//!
//! A version is minted at one, and the slot table reserves zero for an empty slot.
//! A zeroed region is therefore a medium recording no version — every appliance no
//! management plane has pushed a configuration to — and it constrains nothing.
//! That is what the kernel hands a domain that maps this region, so a reader
//! running before the writer has published numbers versions as a fresh appliance
//! does.

use core::{
    mem::{align_of, offset_of, size_of},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::MAPPING_ALIGN;

/// The region: one word, and the two operations over it.
///
/// The field is private and the only ways in are [`publish`](Self::publish) and
/// [`recorded`](Self::recorded), so neither end can come to treat the word as
/// anything but the number it is.
#[repr(C)]
pub struct DurableGeneration {
    word: AtomicU64,
}

impl DurableGeneration {
    /// A zeroed region, which is what the kernel hands a domain that maps one.
    ///
    /// A function rather than a `const` for [`ConfigHandover::zero`](crate::ConfigHandover::zero)'s
    /// reason: a `const` holding an atomic is copied at every mention.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            word: AtomicU64::new(0),
        }
    }

    /// State the newest version the medium records.
    ///
    /// `Release`, so the slot table the writer made durable before calling this is
    /// ordered before the word a reader numbers against.
    pub fn publish(&self, generation: u64) {
        self.word.store(generation, Ordering::Release);
    }

    /// The newest version the region now says the medium records.
    ///
    /// A `u64` rather than an `Option`: zero is the absence and constrains
    /// nothing, which is what a reader would do with a `None`.
    #[must_use]
    pub fn recorded(&self) -> u64 {
        self.word.load(Ordering::Acquire)
    }
}

/// Bytes the system description reserves for the region, derived rather than
/// chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const DURABLE_GENERATION_REGION_SIZE: usize =
    size_of::<DurableGeneration>().next_multiple_of(MAPPING_ALIGN);

// The layout two protection domains agree on, fixed at build time. Neither can see
// the other's view of it, so a width change or a field appearing in front of the
// word must be a compile error here rather than a reader acting on eight wrong
// bytes. The alignment is what makes the store and the load single accesses, and
// so what makes the absent seqlock unnecessary.
const _: () = {
    assert!(size_of::<DurableGeneration>() == 8);
    assert!(align_of::<DurableGeneration>() == 8);
    assert!(offset_of!(DurableGeneration, word) == 0);
    assert!(offset_of!(DurableGeneration, word).is_multiple_of(align_of::<u64>()));

    assert!(DURABLE_GENERATION_REGION_SIZE >= size_of::<DurableGeneration>());
    assert!(DURABLE_GENERATION_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
};

#[cfg(test)]
mod tests;
