//! The onboarding package's staging region: the one place an uploaded archive
//! sits while the domain that holds the device key decides whether to install
//! it.
//!
//! Faces the byzantine neighbour protection domain from the reading side, and
//! everything it holds is a **management-plane attacker's**: the bytes arrive as
//! the body of an upload the appliance authenticated nobody for, and the domain
//! that writes them here is the domain that terminated that upload's session. So
//! every byte of this region is twice untrusted — once for the party that
//! composed it and once for the neighbour that placed it — and nothing here reads
//! one.
//!
//! # Why a region of its own rather than the delegation's message field
//!
//! [`crate::SignRequest`] carries 256 bytes, and an archive is bounded at 128
//! KiB. Chunking one through the other would be five hundred and twelve
//! attacker-paced round trips and a reassembler holding partial state in the
//! domain that owns the medium — which is the one property the delegation has
//! that is worth keeping: **one demand produces one reply**, and a holder that
//! had to remember what a peer sent last time would have that property only as
//! long as the peer cooperated.
//!
//! A region costs 32 pages of address space and no state at all. The whole
//! archive is present or it is not, the length is one word of the request that
//! names it, and the holder's work per demand stays a constant of its own file.
//!
//! # Nothing here is a message, and that is the direction of the grant
//!
//! The domain that accumulates an upload maps this **read-write**; the domain
//! that installs one maps it **read-only**. The asymmetry is
//! [`crate::SignRequest`]'s and is load-bearing for the same reason with the
//! roles kept: a holder that could write the staging region could install an
//! archive nobody uploaded, and the party that uploads cannot be the party that
//! decides.
//!
//! # The reader takes a copy, and this ABI cannot make it
//!
//! There is no sequence number here and no publication protocol, because the
//! region carries no claim of its own: what says an archive is there, and how
//! much of it, is the delegation request that names it, whose `Release` store
//! orders every byte written here before it. What this ABI cannot do is stop the
//! writer rewriting the region *while* the holder reads it — the two domains run
//! concurrently and no fence makes a 128 KiB read atomic. So the holder copies
//! the whole region into storage of its own before it looks at a byte, and that
//! copy is the boundary the validation runs against. [`StagedArchive::copy`] is
//! shaped for exactly that: it takes the destination and answers nothing, so
//! there is no borrow of the region for a caller to validate through.

use core::{
    mem::size_of,
    sync::atomic::{AtomicU8, Ordering},
};

use crate::MAPPING_ALIGN;

/// Bytes of archive the staging region holds, and so the widest package this
/// appliance will look at.
///
/// One hundred and twenty-eight kibibytes, which is what the package contract
/// bounds an archive at: `lfw_package::ARCHIVE_BOUND` is the same number. This
/// crate declines to depend on the reader for one integer, on
/// [`crate::MAX_CERTIFICATE_LEN`]'s terms — the protection domain that sees both
/// is where they are held equal.
pub const MAX_INSTALL_ARCHIVE: usize = 128 * 1024;

/// Bytes the system description reserves for the staging region, derived rather
/// than chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const INSTALL_STAGING_REGION_SIZE: usize =
    size_of::<InstallStaging>().next_multiple_of(MAPPING_ALIGN);

/// The staging region: an archive and nothing else.
///
/// No length, no sequence and no status. Every one of those is a claim, and a
/// claim in this region would be a second place the request's own words are
/// stated — two numbers about one archive that a hostile writer could make
/// disagree.
#[repr(C)]
pub struct InstallStaging {
    /// One atomic per byte rather than packed into words, on
    /// [`crate::DownloadReply`]'s terms: these are an uploader's bytes, so
    /// packing them would make the byte order of the region a thing this crate
    /// chooses rather than a thing it mirrors.
    archive: [AtomicU8; MAX_INSTALL_ARCHIVE],
}

impl InstallStaging {
    /// A zeroed region, which is what the kernel hands a domain that maps one.
    /// A zeroed archive is not a package — it carries no ustar magic — so the
    /// idle state is one the holder refuses by an ordinary rule rather than by a
    /// sentinel.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            archive: [const { AtomicU8::new(0) }; MAX_INSTALL_ARCHIVE],
        }
    }

    /// Take the uploading side's handle: this region to write.
    #[must_use]
    pub const fn upload(&self) -> ArchiveUpload<'_> {
        ArchiveUpload(self)
    }

    /// Take the installing side's handle: this region to read, and no store on
    /// it.
    #[must_use]
    pub const fn staged(&self) -> StagedArchive<'_> {
        StagedArchive(self)
    }
}

impl Default for InstallStaging {
    fn default() -> Self {
        Self::zero()
    }
}

/// The region as the uploading domain holds it.
///
/// Its own type rather than methods on the region, so the direction a domain
/// speaks in is visible in what it holds: a domain with a [`StagedArchive`] has
/// no way to name a store.
pub struct ArchiveUpload<'region>(&'region InstallStaging);

impl ArchiveUpload<'_> {
    /// Place `archive` in the region, and take the token that names it.
    ///
    /// Truncated to what the region holds and the token carries **what was
    /// actually stored**, so a caller handing over more than fits asks about
    /// only the bytes that are there. Bytes past the archive are left as they
    /// were: an installer reads the length the request states and nothing
    /// beyond it, so clearing them would be work the protocol does not need —
    /// [`Self::clear`] is for a caller that wants the region to hold nothing.
    pub fn stage(&mut self, archive: &[u8]) -> StagedUpload {
        let mut stored = 0_u32;
        for (cell, byte) in self.0.archive.iter().zip(archive) {
            cell.store(*byte, Ordering::Relaxed);
            stored += 1;
        }
        StagedUpload { len: stored }
    }

    /// Zero the whole region.
    pub fn clear(&mut self) {
        for cell in &self.0.archive {
            cell.store(0, Ordering::Relaxed);
        }
    }
}

/// An archive placed in the staging region, and the length the delegation
/// request must state for it.
///
/// Neither `Copy` nor `Clone`, and minted only by [`ArchiveUpload::stage`]: the
/// number a request states about the region cannot be conjured beside a staging
/// that never happened. It is a convenience of the asking side and **not a
/// defence** — the holder is answering a byzantine neighbour and bounds the
/// stated length against its own region whatever produced it.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a staged archive nothing asks about is an upload that goes nowhere"]
pub struct StagedUpload {
    len: u32,
}

impl StagedUpload {
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Whether nothing was staged, which is an upload of no bytes rather than an
    /// absent one.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// The region as the installing domain holds it: loads only.
pub struct StagedArchive<'region>(&'region InstallStaging);

impl StagedArchive<'_> {
    /// Copy the region into `into`, bounded by `into` — `zip` walks the shorter
    /// of the two, so no index is taken.
    ///
    /// It answers nothing on purpose. A method handing back a borrow of the
    /// region would let a caller validate bytes the writing domain can still
    /// change under it, which is the one failure this region's reader has to
    /// avoid and the one a return type would invite.
    pub fn copy(&self, into: &mut [u8]) {
        for (byte, cell) in into.iter_mut().zip(&self.0.archive) {
            *byte = cell.load(Ordering::Relaxed);
        }
    }

    /// Bytes the region holds, which is the bound a stated length is judged
    /// against.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        MAX_INSTALL_ARCHIVE
    }
}

// A cross-PD shared-memory ABI: pin the layout so a size change is a compile
// error rather than a silently corrupted mapping, and pin the region to the
// pages the system description grants it. A type that outgrew them would widen a
// capability without anything saying so — the grant follows the constant, and the
// topology would change in a diff nobody was reading.
const _: () = {
    assert!(MAX_INSTALL_ARCHIVE > 0 && MAX_INSTALL_ARCHIVE <= u32::MAX as usize);
    assert!(size_of::<InstallStaging>() == MAX_INSTALL_ARCHIVE);
    assert!(INSTALL_STAGING_REGION_SIZE >= size_of::<InstallStaging>());
    assert!(INSTALL_STAGING_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    // Exactly the type, with no page of slack: the archive bound is a whole
    // number of pages already, so a region larger than the type would be address
    // space granted for nothing.
    assert!(INSTALL_STAGING_REGION_SIZE == MAX_INSTALL_ARCHIVE);
};

#[cfg(test)]
mod tests;
