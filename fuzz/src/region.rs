//! Zero-initialised, correctly aligned backing allocations standing in for the
//! memory regions a protection domain is handed at boot.
//!
//! Every region a harness drives is one seL4 maps and zeroes before a domain
//! attaches: `pd_runtime`'s three pipeline regions, a virtqueue's DMA region,
//! and a PCI function's ECAM page. A harness must reproduce both properties
//! exactly, because both are *preconditions* of the `unsafe` constructors under
//! test (`attach_region`, `SplitVirtqueue::new`,
//! `PciConfig::new`). A harness that violated one would be reporting undefined
//! behaviour of its own making as a finding in the crate — which is how a fuzz
//! target comes to be trusted while proving nothing.
//!
//! Heap rather than stack for two reasons. A `Pool` is 128 KiB, which a
//! libFuzzer worker's stack does not comfortably hold under AddressSanitizer;
//! and `alloc_zeroed` honours the `Layout`'s alignment for any type, whereas a
//! stack local of an over-aligned `#[repr(align(4096))]` type relies on the
//! compiler's stack realignment, which is exactly the guarantee a harness
//! should not be resting an `unsafe` precondition on.

use std::alloc::{Layout, alloc_zeroed, dealloc, handle_alloc_error};
use std::ptr::NonNull;

/// One zeroed, `T`-aligned allocation, freed on drop.
///
/// The value is never read as a `T` through a reference here: callers hand
/// [`as_ptr`](Self::as_ptr) to the `unsafe` constructor under test, which is
/// what a protection domain does with the virtual address Microkit patches in.
pub struct ZeroedRegion<T> {
    region: NonNull<T>,
}

impl<T> ZeroedRegion<T> {
    /// Allocate one zeroed, correctly aligned `T`.
    ///
    /// # Panics
    /// Aborts through [`handle_alloc_error`] if the allocation fails, which is
    /// the only sane response in a harness: continuing would drive the code
    /// under test over a null pointer and report the harness's own bug.
    #[must_use]
    pub fn new() -> Self {
        // A zero-sized `T` would make `alloc_zeroed` undefined; no region type
        // is zero-sized, and stating it here makes that a build error rather
        // than a latent one.
        const { assert!(size_of::<T>() > 0, "a region type must not be zero-sized") };
        let layout = Layout::new::<T>();
        // SAFETY: `layout` has a non-zero size, asserted immediately above, which
        // is `alloc_zeroed`'s only precondition.
        let raw = unsafe { alloc_zeroed(layout) }.cast::<T>();
        match NonNull::new(raw) {
            Some(region) => Self { region },
            None => handle_alloc_error(layout),
        }
    }

    /// The region's base address: zeroed, aligned to `align_of::<T>()`, and
    /// live for as long as this value is.
    #[must_use]
    pub fn as_ptr(&self) -> *mut T {
        self.region.as_ptr()
    }
}

impl<T> Default for ZeroedRegion<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for ZeroedRegion<T> {
    fn drop(&mut self) {
        // SAFETY: `region` came from `alloc_zeroed` with exactly this layout in
        // `new`, and is freed once because `ZeroedRegion` owns it and is not
        // `Copy` or `Clone`.
        unsafe { dealloc(self.region.as_ptr().cast::<u8>(), Layout::new::<T>()) }
    }
}

/// A byte region a device shares with the driver, over-aligned to 16 bytes.
///
/// 16 is `SplitVirtqueue::new`'s stated alignment requirement, and the region
/// is sized well above `QueueLayout::total_bytes` for every queue size the
/// harnesses drive (430 bytes at `SIZE = 16`).
#[repr(C, align(16))]
pub struct DmaRegion(pub [u8; DMA_REGION_BYTES]);

/// Size of a [`DmaRegion`]. A page, matching the smallest region Microkit maps.
pub const DMA_REGION_BYTES: usize = 4096;

impl DmaRegion {
    /// A zeroed, 16-byte-aligned DMA region on the heap.
    #[must_use]
    pub fn zeroed() -> ZeroedRegion<Self> {
        ZeroedRegion::new()
    }
}

/// One PCI function's 4 KiB configuration space, page-aligned.
///
/// The alignment is load-bearing rather than decorative: `virtio::pci`'s
/// `read16`/`read32` cast the base pointer to `u16`/`u32` and read volatile,
/// and their documented contract is that the offset is naturally aligned
/// *relative to a page base*. A `[u8; 4096]` local has `align_of == 1`, so
/// those casts would be misaligned for any base the allocator happened to hand
/// back — undefined behaviour introduced by the harness, in the harness. An
/// ECAM function base is page-aligned in hardware, so that is what this models.
#[repr(C, align(4096))]
pub struct EcamPage(pub [u8; ECAM_PAGE_BYTES]);

/// Size of an [`EcamPage`]: the 4 KiB `PciConfig::new` maps.
pub const ECAM_PAGE_BYTES: usize = 4096;

impl EcamPage {
    /// A zeroed, page-aligned configuration space on the heap.
    #[must_use]
    pub fn zeroed() -> ZeroedRegion<Self> {
        ZeroedRegion::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_region_is_zeroed_and_aligned_as_its_type_requires() {
        let dma = DmaRegion::zeroed();
        let page = EcamPage::zeroed();
        assert!(dma.as_ptr().is_aligned());
        assert!(page.as_ptr().is_aligned());
        assert_eq!(dma.as_ptr() as usize % 16, 0);
        assert_eq!(page.as_ptr() as usize % 4096, 0);
        // SAFETY: both pointers came from `alloc_zeroed` for exactly this type
        // and are live for the borrow below; no other reference exists.
        unsafe {
            assert!((*dma.as_ptr()).0.iter().all(|byte| *byte == 0));
            assert!((*page.as_ptr()).0.iter().all(|byte| *byte == 0));
        }
    }
}
