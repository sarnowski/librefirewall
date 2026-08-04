use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

/// Why an allocation was refused.
///
/// Carries what was asked for and what was left, because those two numbers are
/// what an operator sizing a region needs and neither is derivable from the
/// other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaExhausted {
    pub requested: usize,
    pub remaining: usize,
}

/// The widest alignment this bookkeeper will serve.
///
/// A page, because the region it accounts for is a Microkit mapping and those
/// begin on one — so an offset aligned to any value up to this is an address
/// aligned to it. A request past this is refused as an exhaustion rather than
/// served wrongly; nothing in a TLS session asks for more than sixteen.
pub const MAX_ALIGN: usize = 4096;

/// The bookkeeping half of the arena: which bytes of a fixed region are in
/// use, and every rule about when a request is refused.
///
/// It holds no memory and no pointer — a caller pairs it with a region and
/// turns an offset into an address. That split is deliberate and is what makes
/// the fail-closed behaviour testable on a host: every decision this allocator
/// makes is here, in safe code, and the only thing that is not is the pointer
/// arithmetic, which belongs where the region does.
///
/// # A bump, and what recovers the space anyway
///
/// Allocation is a bump. Freeing recovers space only when the block being
/// freed is the one on top, and growing in place only when the same holds —
/// which sounds weak and is not, because the allocation a TLS session actually
/// churns is a buffer being appended to, and that buffer is on top for as long
/// as nothing is allocated behind it. What the pattern cannot recover is
/// reclaimed all at once by [`Bump::reset_to`] at the end of a session.
///
/// # Why exhaustion is refused before it happens
///
/// A failed allocation cannot be turned into a return value once it has
/// happened: the language's allocation error path does not return. So the
/// property this type is built to give is one step earlier —
/// [`Bump::remaining`] lets the caller refuse a step whose allocations have
/// not yet begun, which is a typed refusal on a live session rather than a
/// fault. [`Bump::allocate`] answers a refusal too, and that answer is the
/// backstop the guard exists to keep unreachable.
///
/// # Why atomics in a domain with one thread
///
/// A Microkit protection domain runs one thread, so nothing here is ever
/// contended. The atomics are not for that: they are what makes this type
/// `Sync` without an `unsafe impl`, and a global allocator has to be `Sync`.
/// The choice is between a claim the compiler checks and a paragraph of prose
/// asserting that no second thread exists, and the compiler is cheaper — an
/// uncontended compare-and-swap on this hardware is a handful of cycles, on a
/// path that is already allocating.
///
/// # Adversary
///
/// **Untrusted network traffic**, through the session that allocates: a peer
/// chooses how much of a handshake to send and therefore how much is
/// allocated. That is the whole reason this is bounded — the bound is a
/// first-party constant the peer cannot move, and every refusal is counted.
pub struct Bump {
    capacity: usize,
    used: AtomicUsize,
    high_water: AtomicUsize,
    refusals: AtomicU32,
}

impl Bump {
    /// A bookkeeper for a region of `capacity` bytes.
    #[must_use]
    pub const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            used: AtomicUsize::new(0),
            high_water: AtomicUsize::new(0),
            refusals: AtomicU32::new(0),
        }
    }

    /// The offset a block of `size` bytes at `align` may occupy.
    ///
    /// # Errors
    /// [`ArenaExhausted`] where the block does not fit, or where the alignment
    /// is past [`MAX_ALIGN`] — which no allocation a session makes asks for,
    /// and which is refused rather than served from an offset whose address
    /// alignment nothing establishes.
    pub fn allocate(&self, size: usize, align: usize) -> Result<usize, ArenaExhausted> {
        if align == 0 || align > MAX_ALIGN || !align.is_power_of_two() {
            return Err(self.refuse(size, self.used.load(Ordering::Relaxed)));
        }
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            // `align` is a power of two at most `MAX_ALIGN`, so the mask fits
            // and the round-up cannot wrap a `usize`.
            let padding = used.wrapping_neg() & (align - 1);
            let Some(start) = used.checked_add(padding) else {
                return Err(self.refuse(size, used));
            };
            let Some(end) = start.checked_add(size) else {
                return Err(self.refuse(size, used));
            };
            if end > self.capacity {
                return Err(self.refuse(size, used));
            }
            match self
                .used
                .compare_exchange_weak(used, end, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => {
                    self.high_water.fetch_max(end, Ordering::Relaxed);
                    return Ok(start);
                }
                Err(current) => used = current,
            }
        }
    }

    /// Give a block back. Space is recovered only where the block is the one
    /// on top; anything else is a no-op, and the space returns at the next
    /// reset.
    pub fn release(&self, offset: usize, size: usize) {
        if let Some(end) = offset.checked_add(size) {
            let _ = self
                .used
                .compare_exchange(end, offset, Ordering::AcqRel, Ordering::Relaxed);
        }
    }

    /// Widen the block at `offset` from `old` to `new` bytes without moving
    /// it, or answer that it cannot be done.
    ///
    /// This is what makes a growing buffer cheap: a `Vec` that doubles while
    /// it is the top block never copies and never strands its previous size.
    #[must_use]
    pub fn grow_in_place(&self, offset: usize, old: usize, new: usize) -> bool {
        let (Some(top), Some(end)) = (offset.checked_add(old), offset.checked_add(new)) else {
            return false;
        };
        if end > self.capacity {
            return false;
        }
        if self
            .used
            .compare_exchange(top, end, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        self.high_water.fetch_max(end, Ordering::Relaxed);
        true
    }

    /// A point to come back to. Everything allocated before it survives a
    /// reset; everything after it does not.
    #[must_use]
    pub fn mark(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    /// Return to a mark, releasing everything allocated since.
    ///
    /// A mark ahead of what is currently used is ignored rather than obeyed:
    /// moving the cursor forward here would hand out bytes twice.
    pub fn reset_to(&self, mark: usize) {
        let _ = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |used| {
                (mark <= used).then_some(mark)
            });
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    /// Bytes still available at the cursor. What a caller compares against a
    /// reserve before beginning a step whose allocations it cannot refuse
    /// part-way through.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.capacity
            .saturating_sub(self.used.load(Ordering::Acquire))
    }

    /// The most that was ever in use at once. The number that says how large
    /// the region has to be, and the one a boot reports.
    #[must_use]
    pub fn high_water(&self) -> usize {
        self.high_water.load(Ordering::Acquire)
    }

    /// How many allocations were refused. Non-zero means the guard did not
    /// hold — every refusal here is one the caller should have prevented.
    #[must_use]
    pub fn refusals(&self) -> u32 {
        self.refusals.load(Ordering::Acquire)
    }

    fn refuse(&self, requested: usize, used: usize) -> ArenaExhausted {
        self.refusals.fetch_add(1, Ordering::AcqRel);
        ArenaExhausted {
            requested,
            remaining: self.capacity.saturating_sub(used),
        }
    }
}

#[cfg(test)]
mod tests;
