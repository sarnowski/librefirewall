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

    /// Take the uploading side's read-back: this region as the domain that
    /// wrote it copies it out again.
    ///
    /// The same shape [`Self::staged`] hands the installing domain, and it is
    /// here for a reason of its own rather than as a convenience. An archive
    /// arrives a TLS delivery at a time and is written straight through
    /// [`UploadCursor`], so the writing domain never assembles a contiguous
    /// copy of its own — and it has to validate one before it asks anybody to
    /// install it. Copying the region back out is what gives it that copy, and
    /// it makes the bytes it validates the bytes that are **in the region**:
    /// were it to validate an accumulation of its own and write a second copy
    /// here, a mistake between the two would leave the two domains judging
    /// different archives.
    #[must_use]
    pub const fn written(&self) -> StagedArchive<'_> {
        StagedArchive(self)
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
/// speaks in is visible in what it holds: a domain that has only a
/// [`StagedArchive`] has no way to name a store.
pub struct ArchiveUpload<'region>(&'region InstallStaging);

impl<'region> ArchiveUpload<'region> {
    /// Begin an upload: a cursor at the start of the region.
    ///
    /// A cursor rather than a call that takes a whole archive, because an
    /// archive is never whole in the uploading domain: it arrives as the body
    /// of a request, a TLS delivery at a time, and a domain that had to hold
    /// one before it could place it would be carrying a second 128 KiB buffer
    /// for the sole purpose of assembling what this region already is.
    #[must_use]
    pub const fn cursor(self) -> UploadCursor<'region> {
        UploadCursor {
            region: self.0,
            written: 0,
        }
    }

    /// Zero the whole region.
    pub fn clear(&mut self) {
        for cell in &self.0.archive {
            cell.store(0, Ordering::Relaxed);
        }
    }
}

/// An upload in progress: the region, and how much of it has been written.
///
/// The offset lives here rather than in the caller, which is what makes "the
/// next segment goes after the last one" a property of the type instead of
/// arithmetic a domain facing a peer's pacing has to get right on every
/// delivery. The cursor is the only way to write the region, so an offset
/// nothing advanced cannot be used to place bytes.
pub struct UploadCursor<'region> {
    region: &'region InstallStaging,
    written: u32,
}

impl UploadCursor<'_> {
    /// Place `segment` after what is already there, answering how many of its
    /// bytes the region took.
    ///
    /// **Short rather than wrapping or refusing.** A caller handing over more
    /// than the region still holds gets the count that was really written, and
    /// a caller that cares — every caller does — compares it against what it
    /// offered. Truncation is what the region can do; deciding that a
    /// truncated upload is an upload to abandon is the caller's, because only
    /// the caller knows what it promised the party at the other end.
    pub fn write(&mut self, segment: &[u8]) -> usize {
        let from = self.written as usize;
        let mut stored = 0_usize;
        for (cell, byte) in self.region.archive.iter().skip(from).zip(segment) {
            cell.store(*byte, Ordering::Relaxed);
            stored += 1;
        }
        // Bounded by the region, whose length is a `u32` by the assertion at
        // the foot of this file, so the sum is one too and cannot wrap.
        self.written = self.written.saturating_add(clamp_u32(stored));
        stored
    }

    /// Bytes written so far.
    #[must_use]
    pub const fn written(&self) -> u32 {
        self.written
    }

    /// Bytes the region will still take.
    #[must_use]
    pub const fn room(&self) -> usize {
        MAX_INSTALL_ARCHIVE.saturating_sub(self.written as usize)
    }

    /// End the upload and take the token that names what is in the region.
    ///
    /// It consumes the cursor, so the length a request states is the length
    /// this upload finished at and not a number read off a cursor that is
    /// still moving.
    pub const fn finish(self) -> StagedUpload {
        StagedUpload { len: self.written }
    }
}

/// A count as a `u32`, saturating rather than truncating. Unreachable — the
/// region is smaller than [`u32::MAX`] by the assertion at the foot of this
/// file — and written this way rather than asserted because nothing on the
/// path an upload paces may fault.
const fn clamp_u32(len: usize) -> u32 {
    if len > u32::MAX as usize {
        u32::MAX
    } else {
        len as u32
    }
}

/// An archive placed in the staging region, and the length the delegation
/// request must state for it.
///
/// Neither `Copy` nor `Clone`, and minted only by [`UploadCursor::finish`]: the
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
