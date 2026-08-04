//! The appliance's one allocator: a bounded region, and the pointer
//! arithmetic that turns this domain's bookkeeping into addresses in it.
//!
//! Every decision about whether an allocation is served lives in
//! `lfw_tls::Bump`, which is portable, host-tested and holds no memory. What
//! is here is the part that cannot be either: a region this domain maps, and
//! the three pointer operations that reach into it. That split is the same one
//! the hardware instructions were put here under — the authority that cannot
//! be host-tested lives in the domain.
//!
//! # Why a failed allocation is not a returned error
//!
//! It cannot be. Rust's allocation failure path does not return: a `Vec` that
//! cannot grow calls the allocation error handler, which diverges. So the
//! property this appliance needs — a session that runs out of memory refuses
//! and closes rather than faulting — is arranged one step earlier, by the
//! session checking its headroom before a step whose allocations it could not
//! refuse part-way through. What [`GlobalAlloc::alloc`] does on exhaustion is
//! the backstop under that: it answers null, and the arena counts the refusal,
//! so a boot that ever reached it says so in its own report.
//!
//! # Adversary
//!
//! **Untrusted network traffic**, at one remove: a peer's handshake is what
//! this allocates for. The bound is a first-party constant it cannot move.

use core::{
    alloc::{GlobalAlloc, Layout},
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

use lfw_tls::Bump;

/// Bytes the cryptography domain's arena holds.
///
/// Two megabytes: far more than a session's measured high-water mark, which
/// the domain reports on every boot, and small enough to be an ordinary
/// mapping rather than a claim on the physical-address window — no device
/// reads it, so it needs no fixed address and is allocated from general
/// untyped memory like any other region this domain holds.
pub const ARENA_BYTES: usize = 0x20_0000;

/// The region, and the cursor over it.
///
/// `AtomicPtr` for the base rather than a raw pointer behind a hand-written
/// `Sync` claim: a global allocator must be `Sync`, and this way the compiler
/// checks it. The base is written once, before the first allocation, and read
/// on every one.
pub struct Arena {
    bump: Bump,
    base: AtomicPtr<u8>,
}

impl Arena {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bump: Bump::new(ARENA_BYTES),
            base: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// Point the arena at the region this domain mapped.
    ///
    /// Called once, before anything allocates. An allocation before it answers
    /// null, which is what a null base means: not yet usable.
    pub fn attach(&self, base: *mut u8) {
        self.base.store(base, Ordering::Release);
    }

    /// The bookkeeping, for the session that has to check its headroom and for
    /// the report that says what a boot used.
    #[must_use]
    pub fn bump(&self) -> &Bump {
        &self.bump
    }

    /// The offset of `ptr` within the region, or `None` where it is not in it.
    ///
    /// Address arithmetic and not pointer arithmetic, so no provenance
    /// question arises: this asks where a pointer is, never builds one.
    fn offset(&self, pointer: *mut u8) -> Option<usize> {
        let base = self.base.load(Ordering::Acquire);
        if base.is_null() {
            return None;
        }
        pointer.addr().checked_sub(base.addr())
    }
}

impl Default for Arena {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: `GlobalAlloc` requires that a returned pointer be valid for the
// requested layout and that distinct live allocations not overlap. Both are
// guaranteed by `lfw_tls::Bump`, which is the sole decider of every offset
// this returns: it hands out non-overlapping ranges inside `ARENA_BYTES`,
// aligns each to what was asked, and refuses anything it cannot fit. The
// region those offsets index is the one `Arena::attach` was given, whose
// extent is held to `ARENA_BYTES` by the `arena_crypto` element of the
// Microkit system description and by `xtask::sysdesc`, which compares the two.
unsafe impl GlobalAlloc for Arena {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = self.base.load(Ordering::Acquire);
        if base.is_null() {
            return ptr::null_mut();
        }
        let Ok(offset) = self.bump.allocate(layout.size(), layout.align()) else {
            return ptr::null_mut();
        };
        // SAFETY: `offset` came from `Bump::allocate`, which returns only
        // offsets whose whole block lies inside `ARENA_BYTES` — so the result
        // is inside the mapped region and the arithmetic stays within one
        // allocated object. `base` is that region's start, established by
        // `Arena::attach` from the mapping the system description grants.
        unsafe { base.add(offset) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if let Some(offset) = self.offset(pointer) {
            self.bump.release(offset, layout.size());
        }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if let Some(offset) = self.offset(pointer)
            && self.bump.grow_in_place(offset, layout.size(), new_size)
        {
            // The block was on top, so it grew where it lay and nothing moved.
            // This is the case that matters: a buffer being appended to is on
            // top for as long as nothing is allocated behind it, which is the
            // shape a TLS record layer produces.
            return pointer;
        }
        let Ok(wider) = Layout::from_size_align(new_size, layout.align()) else {
            return ptr::null_mut();
        };
        // SAFETY: `alloc`'s own contract, called here on the same terms.
        let moved = unsafe { self.alloc(wider) };
        if moved.is_null() {
            return moved;
        }
        // SAFETY: both pointers are live allocations from this arena and the
        // ranges do not overlap — `alloc` never returns a block that overlaps
        // a live one, which is `Bump`'s guarantee. The length is the smaller
        // of the two sizes, so it is inside both.
        unsafe {
            ptr::copy_nonoverlapping(pointer, moved, layout.size().min(new_size));
            self.dealloc(pointer, layout);
        }
        moved
    }
}

/// The mapped region itself, as the type the attach macro takes.
///
/// A byte array and nothing else: this is the one region in the system with no
/// structure, because what gives it structure is the allocator above rather
/// than an agreement with a peer. Page-aligned so every alignment up to
/// [`lfw_tls::MAX_ALIGN`] an offset satisfies is an address that satisfies it.
#[repr(C, align(4096))]
pub struct ArenaRegion {
    pub bytes: [u8; ARENA_BYTES],
}

/// The region and the bound the allocator was built with are the same number,
/// held here where both are visible rather than by the two agreeing by
/// accident.
const _: () = assert!(size_of::<ArenaRegion>() == ARENA_BYTES);
