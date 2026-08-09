//! Whether this appliance has an owner: one word, written by the domain that
//! holds the identity and read by the domain that decides frames.
//!
//! Faces the byzantine neighbour protection domain. The reader maps this
//! region read-only and the writer is a peer whose behaviour it may not assume,
//! so every bit pattern reaching [`ApplianceOwnership::owned`] is peer-written
//! input. What makes that safe is that only one pattern means *owned*: the word
//! is compared against [`OWNED_TOKEN`] and anything else — a zeroed region, a
//! half-written word, a value a compromised writer chose — reads as unowned.
//! The undecodable answer is therefore the one that forwards nothing, which is
//! the direction a firewall's uncertainty has to fall.
//!
//! # One word, and why there is no seqlock over it
//!
//! [`ClockCalibration`](crate::ClockCalibration) brackets its three words with a
//! counter because they are meaningful only together and a torn triple is
//! undetectable by inspection. There is nothing here to tear: a naturally
//! aligned `u32` store is one access, so a reader observes the value before the
//! write or the value after it and never a blend of the two. A counter over one
//! word would be a protocol carrying no information, and a reader that could
//! observe an in-progress publication would have to decide what that meant.
//!
//! # The word only ever gains an owner
//!
//! An appliance takes an owner once. Losing one is a factory reset, which is
//! asked for by writing a sector of the store medium and takes effect on the
//! boot after it — so within one boot the only transition this region can
//! honestly carry is unowned to owned. Nothing here enforces that, because a
//! region cannot: what enforces it is the reader, which latches the first owned
//! reading it sees and so cannot be walked back to forwarding nothing by a
//! writer that changed its mind.

use core::{
    mem::{align_of, offset_of, size_of},
    sync::atomic::{AtomicU32, Ordering},
};

use crate::MAPPING_ALIGN;

/// The one word that means this appliance has an owner.
///
/// A recognisable constant rather than `1`, so that the region's zeroed state,
/// a partially written word and a value chosen by a compromised writer are all
/// the same answer — unowned — rather than each needing its own reading. It is
/// not a secret and authenticates nothing: it separates *published* from
/// *anything else*, and a domain that may write this region may write it.
pub const OWNED_TOKEN: u32 = 0x4f57_4e44;

/// The region: one word, and the two operations over it.
///
/// The field is private and the only ways in are [`publish`](Self::publish) and
/// [`owned`](Self::owned), so a reader cannot come to treat some other bit
/// pattern as ownership and a writer cannot publish a word that is neither.
#[repr(C)]
pub struct ApplianceOwnership {
    word: AtomicU32,
}

impl ApplianceOwnership {
    /// A zeroed region, which is what the kernel hands a domain that maps one —
    /// and which reads as unowned, so a forwarder that runs before the holder of
    /// the identity has published anything forwards nothing.
    ///
    /// A function rather than a `const` for [`ConfigHandover::zero`](crate::ConfigHandover::zero)'s
    /// reason: a `const` holding an atomic is copied at every mention.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            word: AtomicU32::new(0),
        }
    }

    /// State whether this appliance has an owner.
    ///
    /// `Release`, so everything the writer made durable before calling this —
    /// the state record carrying the owner — is ordered before the word a reader
    /// acts on.
    pub fn publish(&self, owned: bool) {
        let word = if owned { OWNED_TOKEN } else { 0 };
        self.word.store(word, Ordering::Release);
    }

    /// Whether the word now in the region is the one that means owned.
    ///
    /// The total answer to a two-valued question, so it is a `bool` rather than
    /// an `Option`: there is no third state for a caller to tell apart, every
    /// pattern that is not [`OWNED_TOKEN`] having one meaning and it being the
    /// safe one.
    #[must_use]
    pub fn owned(&self) -> bool {
        self.word.load(Ordering::Acquire) == OWNED_TOKEN
    }
}

/// Bytes the system description reserves for the region, derived rather than
/// chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const OWNERSHIP_REGION_SIZE: usize =
    size_of::<ApplianceOwnership>().next_multiple_of(MAPPING_ALIGN);

// The layout two protection domains agree on, fixed at build time. One maps this
// region read-write and the other read-only, and neither can see the other's
// view of it, so a width change or a field appearing in front of the word must
// be a compile error here rather than a reader acting on the wrong four bytes.
const _: () = {
    assert!(size_of::<ApplianceOwnership>() == 4);
    assert!(align_of::<ApplianceOwnership>() == 4);
    assert!(offset_of!(ApplianceOwnership, word) == 0);

    // Naturally aligned, which is what makes the store and the load single
    // accesses and so what makes the seqlock this region does not have
    // unnecessary.
    assert!(offset_of!(ApplianceOwnership, word).is_multiple_of(align_of::<u32>()));

    assert!(OWNERSHIP_REGION_SIZE >= size_of::<ApplianceOwnership>());
    assert!(OWNERSHIP_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
};

#[cfg(test)]
mod tests;
