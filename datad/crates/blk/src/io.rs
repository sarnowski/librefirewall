//! The DMA-visible staging window: the bytes a block request's data segment
//! names, addressed by whole sectors and by nothing else.
//!
//! # Why a type and not a pointer and a length
//!
//! A data segment is an address handed to a device that will DMA to it, and
//! there is no IOMMU on this platform, so an offset computed
//! wrong is the device writing somewhere else. The authority to name a byte
//! therefore exists in one shape, [`IoSector`], `< IO_SECTORS` by
//! construction; every address here is that index times
//! [`SECTOR_SIZE`](crate::SECTOR_SIZE), so "inside the region" is arithmetic
//! rather than a check somebody remembered.
//!
//! A segment is a *span*, though, and its far end is the byte a device DMAs up
//! to, so [`IoSpan`] is the authority for a run of them: no layer below is in a
//! position to bound one, `Requests::submit` knowing the medium's capacity and
//! not this region's extent.
//!
//! # The adversary
//!
//! A **hostile or malfunctioning device**, on the read path: the
//! bytes copied out are whatever it DMA'd in, so they are payload and never a
//! value that steers a later access, and nothing here reads them. The base
//! address is the `io_paddr` setvar rather than the device's, and is checked
//! anyway: a missing setvar leaves the symbol at its default rather than
//! failing the build.

use core::marker::PhantomData;

use crate::{BLK_IO_REGION_SIZE, PAGE_SIZE, SECTOR_SIZE};

/// Sectors the staging window holds.
pub const IO_SECTORS: usize = BLK_IO_REGION_SIZE / SECTOR_SIZE;

const _: () = assert!(
    BLK_IO_REGION_SIZE.is_multiple_of(SECTOR_SIZE),
    "the staging region is not a whole number of sectors"
);
// A staging sector is held in a `u16`, so a window that could not be indexed in
// one would silently truncate every sector past the 65536th.
const _: () = assert!(
    IO_SECTORS <= u16::MAX as usize + 1,
    "a staging sector index must fit in a u16"
);
// [`IoSector::SECOND`] exists, so the window must have a second sector.
const _: () = assert!(
    IO_SECTORS >= 2,
    "the staging window holds fewer than two sectors"
);

/// One sector of the staging window: `< IO_SECTORS` by construction, so its
/// byte offset and physical address lie inside the region by arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IoSector(u16);

impl IoSector {
    /// The window's first sector.
    pub const FIRST: Self = Self(0);

    /// The window's second sector, a constant because a caller staging two
    /// transfers needs two disjoint sectors without a fallible conversion.
    pub const SECOND: Self = Self(1);

    /// The staging sector at `index`, or `None` where the window has no such
    /// sector.
    #[must_use]
    pub const fn new(index: usize) -> Option<Self> {
        if index < IO_SECTORS {
            // In range by the branch, and `IO_SECTORS` fits a `u16` by the
            // assertion above, so the cast is total.
            Some(Self(index as u16))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn get(self) -> usize {
        self.0 as usize
    }

    /// This sector's byte offset within the window, which is `< BLK_IO_REGION_SIZE`
    /// and whose end is `<= BLK_IO_REGION_SIZE`.
    const fn offset(self) -> usize {
        self.get() * SECTOR_SIZE
    }
}

/// A run of bytes of the staging window: wholly inside the region by
/// construction, because an [`IoSector`] bounds only its first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoSpan {
    sector: IoSector,
    len: u32,
}

impl IoSpan {
    /// The `len` bytes starting at `sector`, or `None` where they do not fit the
    /// window. Zero is refused: virtio-blk has no zero-length data segment.
    #[must_use]
    pub const fn new(sector: IoSector, len: u32) -> Option<Self> {
        if len == 0 {
            return None;
        }
        // `sector.offset() < BLK_IO_REGION_SIZE` by `IoSector`'s construction,
        // so the sum is the only part that can leave the window — and it is
        // computed in `usize`, which on this target holds every `u32`.
        match sector.offset().checked_add(len as usize) {
            Some(end) if end <= BLK_IO_REGION_SIZE => Some(Self { sector, len }),
            _ => None,
        }
    }

    /// The `len` bytes at byte offset `at` of the window, or `None` where `at` is
    /// not a sector boundary or the bytes do not fit. Refused rather than
    /// rounded down, which would hand the device a span starting before the
    /// bytes the caller meant.
    #[must_use]
    pub const fn at_offset(at: usize, len: u32) -> Option<Self> {
        if !at.is_multiple_of(SECTOR_SIZE) {
            return None;
        }
        match IoSector::new(at / SECTOR_SIZE) {
            Some(sector) => Self::new(sector, len),
            None => None,
        }
    }

    /// The window sector the span starts at.
    #[must_use]
    pub const fn sector(self) -> IoSector {
        self.sector
    }

    /// Bytes the span covers, never zero — which is why it is not a `len`: there
    /// is no empty form for an `is_empty` to answer.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.len
    }

    const fn offset(self) -> usize {
        self.sector.offset()
    }
}

/// Why a staging window could not be attached: its patched physical base is
/// zero, not page-aligned, or so high that the region's end is not
/// representable. `paddr` is the diagnosis, and the console is the only place
/// an operator sees it, there being no shell: zero means the `setvar` is missing or
/// misspelled, any other value means it is misplaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoRegionUnusable {
    pub paddr: u64,
}

/// A mapped, sector-addressed staging window and the physical base a device is
/// told about.
///
/// `'region` is the caller's assertion of how long the mapping lives, on
/// [`Requests`](crate::request::Requests)' terms: a raw pointer carries no
/// lifetime, so it exists for a caller to tie this value's life to a borrow.
pub struct IoRegion<'region> {
    base: *mut u8,
    paddr: u64,
    region: PhantomData<&'region mut [u8]>,
}

impl IoRegion<'_> {
    /// Attach to a mapped staging region.
    ///
    /// # Safety
    /// `base` must point to a live mapping of at least [`BLK_IO_REGION_SIZE`]
    /// bytes, shared only with the one block device this driver brought up, and
    /// staying mapped for at least `'region`. `paddr` must be that mapping's
    /// physical address; it is checked rather than trusted, so a caller owes
    /// only that the two describe the same region.
    ///
    /// # Errors
    /// [`IoRegionUnusable`], before any byte of the region is touched.
    pub unsafe fn attach(base: *mut u8, paddr: u64) -> Result<Self, IoRegionUnusable> {
        // Every address this type hands a device is `paddr` plus an offset the
        // `IoSector` bound keeps below `BLK_IO_REGION_SIZE`, so a base whose
        // region end is not representable would let one of those sums wrap.
        if paddr == 0
            || !paddr.is_multiple_of(PAGE_SIZE as u64)
            || paddr.checked_add(BLK_IO_REGION_SIZE as u64).is_none()
        {
            return Err(IoRegionUnusable { paddr });
        }
        Ok(Self {
            base,
            paddr,
            region: PhantomData,
        })
    }

    /// The physical address of `sector`, for a data segment of exactly one
    /// sector — the only length the sector bound is also the span bound for.
    /// Anything longer is an [`IoSpan`] and [`span_paddr`](Self::span_paddr).
    #[must_use]
    pub const fn sector_paddr(&self, sector: IoSector) -> u64 {
        // Cannot overflow: `attach` established that `paddr + BLK_IO_REGION_SIZE`
        // is representable, and `IoSector::offset` is below that size.
        self.paddr + sector.offset() as u64
    }

    /// The physical address a data segment covering `span` starts at — the span
    /// rather than its first sector, so the address and the length published
    /// beside it come from one bounded value.
    #[must_use]
    pub const fn span_paddr(&self, span: IoSpan) -> u64 {
        self.paddr + span.offset() as u64
    }

    /// Place one sector's worth of bytes into the window, for the device to
    /// read.
    pub fn put(&mut self, sector: IoSector, data: &[u8; SECTOR_SIZE]) {
        // SAFETY: `attach`'s contract makes `base` a live mapping of at least
        // `BLK_IO_REGION_SIZE` bytes held for `'region`, and `IoSector` — whose
        // only constructors are `new`, `FIRST` and `SECOND`, each bounded by
        // `IO_SECTORS` — puts `offset + SECTOR_SIZE` inside it. Source and
        // destination cannot overlap: `data` is the caller's, and this type is
        // the only thing that dereferences the region. `u8` needs no alignment.
        //
        // Ordering is the virtqueue's, not this copy's: the store is published
        // to the device by the release fence `SplitVirtqueue::add_chain`
        // executes before it advances the available ring, and the mapping is
        // cached, which is the premise `virtio::queue`'s fences are stated
        // against (systems/qemu-x86_64/librefirewall.system, beside `blk_io`).
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.base.add(sector.offset()),
                SECTOR_SIZE,
            );
        }
    }

    /// One span of the window, for a caller composing transfers in place — a
    /// recording, which is hundreds of kilobytes and has no other home: a
    /// protection domain's stack is tens and it has no allocator.
    ///
    /// A span rather than the whole window: a borrow covering bytes the device
    /// is filling right now is a race whatever the borrow says, and only the
    /// caller knows which spans have a transfer against them.
    pub fn staging(&mut self, span: IoSpan) -> &mut [u8] {
        // SAFETY: `attach`'s contract makes `base` a live `BLK_IO_REGION_SIZE`
        // mapping held for `'region`, and `IoSpan` puts `offset + len` inside
        // that size, so the slice is in bounds for the whole borrow; `u8` needs
        // no alignment and has no invalid bit pattern, so whatever the device
        // left there is initialized.
        //
        // Exclusivity has two halves. Against every other holder it is this
        // `&mut self` plus the grant: `blk_io` is mapped `rw` to the recorder
        // alone, which `xtask::sysdesc`'s `REGIONS` rule enforces. Against the
        // device it is the caller's: no transfer this driver published may still
        // be outstanding over `span`. The enforcer is `lfw_recorder::Deck`,
        // which partitions the window into areas no two transfers share and
        // holds at most one against each, proved by its
        // `only_one_flush_is_outstanding_at_a_time`. Bytes read back are the
        // device's and are payload, never a value that steers an access.
        unsafe { core::slice::from_raw_parts_mut(self.base.add(span.offset()), span.len as usize) }
    }

    /// Copy one sector's worth of bytes out of the window — whatever the device
    /// left there, which is payload and never a value that steers an access.
    pub fn take(&self, sector: IoSector, out: &mut [u8; SECTOR_SIZE]) {
        // SAFETY: as `put`, in the other direction, and the acquire fence in
        // `SplitVirtqueue::poll` is what makes the device's write visible before
        // the completion that reports it is believed.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.base.add(sector.offset()),
                out.as_mut_ptr(),
                SECTOR_SIZE,
            );
        }
    }
}

#[cfg(test)]
mod tests;
