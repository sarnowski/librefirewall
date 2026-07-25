//! Driver side of the virtio 1.0 split virtqueue.
//!
//! A split virtqueue is three sub-areas in one DMA region shared with the
//! device: the **descriptor table** (buffer address/length/flags), the
//! **driver (available) ring** the driver publishes buffers into, and the
//! **device (used) ring** the device publishes completions into. This type
//! owns the driver half — allocating descriptors, publishing them, and reaping
//! completions — and is transport-agnostic: a PCI or MMIO transport programs
//! the three area addresses ([`QueueLayout`]) into the device and rings the
//! doorbell.
//!
//! The region is DMA memory the device also touches, so field access is
//! volatile and ordered with explicit fences at the publish/reap boundaries,
//! exactly where a real device observes or produces the indices. The fences
//! order CPU-visible memory only; that suffices because x86 DMA is
//! cache-coherent and the region is mapped cached — a non-coherent platform
//! would additionally need cache maintenance here. Only single-descriptor
//! buffers are used (virtio-net needs no chaining per buffer), so the free list
//! is a simple index stack and no `NEXT` chain is walked.
//!
//! # The device is untrusted
//!
//! The device can write **every byte of the region** — not only the used ring
//! it owns by protocol, but the descriptor table and the driver ring as well
//! (CONCEPT §7.1). The governing rule here is therefore stronger than "validate
//! the used ring": *no value read back from the region is ever used to index
//! it*. Concretely:
//!
//! - **Descriptor identity is validated against driver-owned state, not
//!   against the shared region.** Every descriptor's lifecycle position
//!   (free → posted → reaped → free) lives in this struct's private
//!   `state` array, which the device cannot reach. A completion is accepted
//!   only when it names a descriptor this driver posted and the device has not
//!   already completed, so a forged id, an out-of-range id, and a replayed
//!   completion are all rejected before a [`Token`] exists for them.
//! - **The free list is private.** Its successor links live in the private
//!   `free_next` array rather than in each descriptor's shared `next` field.
//!   Reading that field back would hand the device the allocator: a scribbled
//!   `next` becomes `free_head`, and the very next `add` writes a descriptor at
//!   `free_head * 16` — anywhere in a `u16`, far outside the region. The `next`
//!   field is still *written* (zeroed) because it is part of the ABI the device
//!   reads, but it is never read.
//! - **Work is bounded by a driver-owned quantity.** A single [`poll`] examines
//!   at most `SIZE` used entries whatever index the device publishes. Across
//!   calls, it can hand out at most [`posted_count`] completions before the
//!   driver posts again, because each accepted completion moves its descriptor
//!   out of the posted state and nothing but [`add_writable`]/[`add_readable`]
//!   moves one back in. A `while let Some(..) = queue.poll()` drain therefore
//!   terminates against any device.
//! - **The reported length is clamped to the length this driver programmed**
//!   for that descriptor, held privately in `posted_len` for the same reason
//!   the state array is private: the copy in the shared descriptor table is
//!   within the device's reach.
//!
//! Taken together those four make every offset this type computes a function of
//! private state alone, so no device value can drive an out-of-bounds access,
//! unbounded work, or a panic.
//!
//! What is **not** checked, because it is not checkable from this side: the
//! device may complete a descriptor it never read, report fewer bytes than it
//! wrote, or never complete a descriptor at all. The first two are
//! indistinguishable from a short frame and are the parser's problem; the third
//! is a stall, which costs the driver the buffer and is visible as a
//! [`posted_count`] that stops falling. Whether a frame's *contents* make sense
//! is the business of whatever parses them.
//!
//! [`poll`]: SplitVirtqueue::poll
//! [`posted_count`]: SplitVirtqueue::posted_count
//! [`add_writable`]: SplitVirtqueue::add_writable
//! [`add_readable`]: SplitVirtqueue::add_readable

use core::sync::atomic::{Ordering, fence};

/// `VIRTQ_DESC_F_NEXT`: descriptor chains to `next`.
const VIRTQ_DESC_F_NEXT: u16 = 1;
/// `VIRTQ_DESC_F_WRITE`: buffer is device-writable (a receive buffer).
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Round `value` up to a multiple of `align` (a power of two).
const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// Increment a device-fault counter, saturating rather than wrapping; see
/// [`DeviceFaults`].
fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// Where one descriptor sits in its lifecycle. Kept in driver-private memory
/// rather than derived from the shared region, because the device can write
/// every byte of the region and would otherwise be answering the question
/// "may this completion be accepted?" itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DescriptorState {
    /// On the free list; may be allocated by `add`.
    Free,
    /// Published to the device, which owns the buffer until it completes.
    Posted,
    /// Completed by the device and handed to the driver as a [`Token`]; the
    /// descriptor stays allocated until the token is surrendered.
    Reaped,
}

/// Counts of the used-ring completions this queue refused, which are otherwise
/// invisible: a device replaying or forging completions at line rate looks
/// exactly like an idle link.
///
/// Every field is **monotonic** for the queue's life and **saturates** at
/// [`u64::MAX`] rather than wrapping, matching every other counter set in the
/// dataplane: a metrics endpoint (CONCEPT §11) derives a rate by differencing
/// successive scrapes, so a reset would forge a negative rate and a wrap would
/// turn a sustained flood back into a small number.
///
/// A non-zero value here is evidence about the *device*, never about this
/// driver: neither field is reachable by any code path that does not read the
/// shared used ring.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceFaults {
    /// Completions whose `id` was not a descriptor index of this queue.
    pub completion_out_of_range: u64,
    /// Completions naming a descriptor that was not posted to the device: a
    /// replay of one already reaped, or an echo of one never published.
    pub completion_not_posted: u64,
}

/// A buffer in flight: the head descriptor index the device echoes back in its
/// used-ring completion.
///
/// A `Token` is a claim on one descriptor, and only this queue can mint one.
/// [`add_writable`](SplitVirtqueue::add_writable) and
/// [`add_readable`](SplitVirtqueue::add_readable) mint one for the descriptor
/// they just published; [`poll`](SplitVirtqueue::poll) mints one only *after*
/// checking that the id the device echoed names a descriptor this driver
/// posted and has not already reaped. The device therefore cannot forge a
/// token, drive one out of range, or obtain two tokens for one descriptor —
/// and the wrapped index is private so safe code cannot forge one either. Read
/// it with [`index`](Token::index).
///
/// `Token` is deliberately neither `Copy` nor `Clone`, so surrendering one
/// consumes it and a token cannot be duplicated. That alone does not make
/// recycling safe, which is why it is not claimed: a token minted by `add_*`
/// names a descriptor the *device* still owns, and a token can outlive the
/// queue it came from. [`recycle`](SplitVirtqueue::recycle) therefore re-checks
/// the descriptor's own state and rejects anything that is not a reaped
/// descriptor of that queue.
#[derive(Debug, PartialEq, Eq)]
pub struct Token(u16);

impl Token {
    /// The head descriptor index this token names (always `< SIZE`). Borrows,
    /// so reading the index does not surrender the token.
    #[must_use]
    pub const fn index(&self) -> u16 {
        self.0
    }
}

/// Why [`SplitVirtqueue::recycle`] refused a token.
///
/// Both variants mean the queue's descriptor is not in the reaped state the
/// token claims, which no token obtained from [`poll`](SplitVirtqueue::poll)
/// and surrendered once to its own queue can produce. They are therefore a
/// driver-side bookkeeping error, not device input — the device's own
/// misbehaviour is already rejected inside `poll` and counted in
/// [`DeviceFaults`]. They are returned rather than asserted so a caller can
/// fail visibly on its own terms instead of inheriting a panic from a library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecycleError {
    /// The descriptor is already on the free list: the token was surrendered
    /// twice, or it belongs to a different queue.
    AlreadyFree(u16),
    /// The descriptor is still published to the device, which may write to its
    /// buffer at any moment. Reclaiming it would hand a live DMA target to the
    /// next allocation.
    StillPosted(u16),
}

/// The byte layout of a split virtqueue within its region: the offset of each
/// sub-area from the region base and the total size. A transport adds these to
/// the region's physical address to program the device's queue registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueLayout {
    /// Number of descriptors.
    pub size: usize,
    /// Offset of the descriptor table (always 0).
    pub descriptor_offset: usize,
    /// Offset of the driver (available) ring.
    pub driver_offset: usize,
    /// Offset of the device (used) ring.
    pub device_offset: usize,
    /// Total bytes the region must provide.
    pub total_bytes: usize,
}

/// The driver side of a split virtqueue of `SIZE` descriptors. `SIZE` must be a
/// power of two of at least 2 and at most 32768 (the ring index is a `u16`);
/// naming either [`LAYOUT`](Self::LAYOUT) or [`new`](Self::new) for a `SIZE`
/// outside that is a compile error.
pub struct SplitVirtqueue<const SIZE: usize> {
    region: *mut u8,
    /// Each descriptor's lifecycle position. Private, and never read back from
    /// the shared region — see the module header.
    state: [DescriptorState; SIZE],
    /// The buffer length this driver programmed into each descriptor, kept for
    /// clamping the device's reported completion length.
    posted_len: [u32; SIZE],
    /// The free list's successor links. Private rather than the descriptor's
    /// shared `next` field, which the device can rewrite — see the module
    /// header. Only entries of free descriptors are meaningful.
    free_next: [u16; SIZE],
    free_head: u16,
    num_free: u16,
    /// How many descriptors are published to the device right now. This is the
    /// driver-owned quantity that bounds how many completions `poll` can hand
    /// out before the driver posts again.
    num_posted: u16,
    avail_idx: u16,
    last_used: u16,
    faults: DeviceFaults,
}

impl<const SIZE: usize> SplitVirtqueue<SIZE> {
    const _CHECK: () = {
        assert!(SIZE.is_power_of_two(), "queue size must be a power of two");
        assert!(SIZE >= 2, "queue size must be at least 2");
        assert!(SIZE <= 32768, "queue size must fit a u16 ring index");
        // The associated offset constants and the free helper functions compute
        // the same virtqueue ABI two different ways; assert they agree so the
        // two computations can never silently drift apart.
        assert!(Self::AVAIL_OFF + 4 == avail_ring_off::<SIZE>(0));
        assert!(Self::USED_OFF == used_area_off::<SIZE>());
        assert!(Self::USED_IDX_OFF == used_area_off::<SIZE>() + 2);
    };
    const MASK: u16 = (SIZE as u16).wrapping_sub(1);

    const DESC_BYTES: usize = SIZE * 16;
    const AVAIL_OFF: usize = Self::DESC_BYTES;
    const AVAIL_BYTES: usize = 4 + 2 * SIZE + 2;
    const USED_OFF: usize = align_up(Self::AVAIL_OFF + Self::AVAIL_BYTES, 4);
    const USED_BYTES: usize = 4 + 8 * SIZE + 2;
    const TOTAL: usize = Self::USED_OFF + Self::USED_BYTES;

    const AVAIL_IDX_OFF: usize = Self::AVAIL_OFF + 2;
    const USED_IDX_OFF: usize = Self::USED_OFF + 2;

    /// The layout of this queue, for a transport to program into the device.
    ///
    /// Naming this constant forces the `SIZE` invariants below, so a layout for
    /// an impossible queue size cannot be computed and handed to a live device:
    /// the transport programs these offsets into the device's queue registers,
    /// where a garbage value would point the hardware's DMA at the wrong bytes.
    pub const LAYOUT: QueueLayout = {
        let () = Self::_CHECK;
        QueueLayout {
            size: SIZE,
            descriptor_offset: 0,
            driver_offset: Self::AVAIL_OFF,
            device_offset: Self::USED_OFF,
            total_bytes: Self::TOTAL,
        }
    };

    /// Initialise the driver's view over a region and seed the descriptor free
    /// list. The device (used) ring is left to the device.
    ///
    /// # Safety
    /// `region` must point to at least [`QueueLayout::total_bytes`] bytes,
    /// 16-byte aligned, zero-initialised, shared only with the one device that
    /// owns this queue, and must outlive the returned value.
    pub unsafe fn new(region: *mut u8) -> Self {
        let () = Self::_CHECK;
        // Chain every descriptor into the free list, in driver-private memory.
        // The last entry wraps to 0 and is never followed: taking it empties
        // the list, and `add` stops at `num_free == 0`.
        let mut free_next = [0u16; SIZE];
        for (index, next) in free_next.iter_mut().enumerate() {
            *next = (index as u16 + 1) % SIZE as u16;
        }
        let queue = Self {
            region,
            state: [DescriptorState::Free; SIZE],
            posted_len: [0; SIZE],
            free_next,
            free_head: 0,
            num_free: SIZE as u16,
            num_posted: 0,
            avail_idx: 0,
            last_used: 0,
            faults: DeviceFaults::default(),
        };
        // SAFETY: the available header lies within the region.
        unsafe {
            queue.write_u16(Self::AVAIL_OFF, 0);
            queue.write_u16(Self::AVAIL_IDX_OFF, 0);
        }
        queue
    }

    /// Buffers the driver can still publish before the ring is full.
    #[must_use]
    pub fn free_count(&self) -> usize {
        self.num_free as usize
    }

    /// Descriptors published to the device and not yet completed. This is the
    /// only quantity a completion can legitimately consume, so it is also the
    /// bound on how many completions [`poll`](Self::poll) can hand out before
    /// the driver posts again.
    #[must_use]
    pub fn posted_count(&self) -> usize {
        self.num_posted as usize
    }

    /// The used-ring completions this queue has refused; see [`DeviceFaults`].
    #[must_use]
    pub fn device_faults(&self) -> DeviceFaults {
        self.faults
    }

    /// Publish a device-writable (receive) buffer at physical address `paddr`.
    /// Returns its [`Token`], or `None` when no descriptor is free.
    pub fn add_writable(&mut self, paddr: u64, len: u32) -> Option<Token> {
        self.add(paddr, len, VIRTQ_DESC_F_WRITE)
    }

    /// Publish a device-readable (transmit) buffer at physical address `paddr`.
    pub fn add_readable(&mut self, paddr: u64, len: u32) -> Option<Token> {
        self.add(paddr, len, 0)
    }

    fn add(&mut self, paddr: u64, len: u32, flags: u16) -> Option<Token> {
        if self.num_free == 0 {
            return None;
        }
        let head = self.free_head;
        // The successor comes from the private free list. Taking it *before*
        // the writes below is deliberate: this is a bounds-checked index, so
        // even a broken free-list invariant faults here rather than after the
        // unchecked writes have already landed outside the region.
        self.free_head = self.free_next[head as usize];
        // SAFETY: `free_head` is only ever assigned a descriptor index — 0 in
        // `new`, a `free_next` entry (all `< SIZE`), or a `Token`'s index in
        // `recycle` — and never a value read back from the region, so
        // `head < SIZE` and every offset derived from it lies within it.
        unsafe {
            self.write_u64(desc_addr_off(head), paddr);
            self.write_u32(desc_len_off(head), len);
            // Single-descriptor buffers never chain, so strip any NEXT flag
            // defensively rather than trust the caller not to pass one, and
            // publish a `next` the device would find inert if it followed one
            // anyway. This field is write-only to us: the free list it used to
            // double as lives in `free_next` now, out of the device's reach.
            self.write_u16(desc_flags_off(head), flags & !VIRTQ_DESC_F_NEXT);
            self.write_u16(desc_next_off(head), 0);
        }
        self.state[head as usize] = DescriptorState::Posted;
        self.posted_len[head as usize] = len;
        self.num_free -= 1;
        self.num_posted += 1;

        let slot = self.avail_idx & Self::MASK;
        // SAFETY: `slot < SIZE`, so the ring entry lies within the region.
        unsafe { self.write_u16(avail_ring_off::<SIZE>(slot), head) };
        self.avail_idx = self.avail_idx.wrapping_add(1);
        // Publish the descriptor and ring entry before the index the device
        // reads to discover them.
        fence(Ordering::Release);
        // SAFETY: the available index lies within the region.
        unsafe { self.write_u16(Self::AVAIL_IDX_OFF, self.avail_idx) };
        Some(Token(head))
    }

    /// Reap the next completed buffer, returning its [`Token`] and how many
    /// bytes the device reported writing, **clamped** to the length this driver
    /// programmed for that descriptor. The descriptor stays allocated until
    /// [`recycle`](Self::recycle).
    ///
    /// `None` means no further completion is available to hand out from this
    /// call. That covers three cases, which a caller distinguishes — if it
    /// needs to — through [`device_faults`](Self::device_faults): the used ring
    /// is caught up; every entry examined was refused as malformed; or the
    /// per-call scan budget ran out. All three end a drain loop, which is the
    /// only decision the caller has to make.
    ///
    /// Untrusted-device handling is the module header's subject; in short, a
    /// completion is accepted only for a descriptor this driver posted and the
    /// device has not already completed, at most `SIZE` used entries are
    /// examined per call, and at most [`posted_count`](Self::posted_count)
    /// completions can be handed out before the driver posts again.
    pub fn poll(&mut self) -> Option<(Token, u32)> {
        for _ in 0..SIZE {
            // SAFETY: the used index lies within the region.
            let device_idx = unsafe { self.read_u16(Self::USED_IDX_OFF) };
            if device_idx == self.last_used {
                return None;
            }
            // Observe the completion the device published before the index bump.
            fence(Ordering::Acquire);
            let slot = self.last_used & Self::MASK;
            // SAFETY: `slot < SIZE`, so the used element lies within the region.
            let (id, len) = unsafe {
                (
                    self.read_u32(used_elem_id_off::<SIZE>(slot)),
                    self.read_u32(used_elem_len_off::<SIZE>(slot)),
                )
            };
            self.last_used = self.last_used.wrapping_add(1);
            if (id as usize) >= SIZE {
                bump(&mut self.faults.completion_out_of_range);
                continue;
            }
            let index = id as u16;
            if self.state[index as usize] != DescriptorState::Posted {
                // A replayed completion, or an echo of a descriptor never
                // published. Accepting it would mint a second live token for
                // one descriptor and let the free list take it twice.
                bump(&mut self.faults.completion_not_posted);
                continue;
            }
            self.state[index as usize] = DescriptorState::Reaped;
            self.num_posted -= 1;
            return Some((Token(index), len.min(self.posted_len[index as usize])));
        }
        None
    }

    /// Return a reaped descriptor to the free list, making it available again.
    ///
    /// # Errors
    /// [`RecycleError`] when the token does not name a reaped descriptor of
    /// this queue — a token still posted to the device, or one already
    /// surrendered. The free list is left untouched, so a caller that ignores
    /// the error loses the descriptor rather than corrupting the queue.
    pub fn recycle(&mut self, token: Token) -> Result<(), RecycleError> {
        // `head < SIZE` because `Token`'s field is private and every mint site
        // bounds it, so this indexes in range whatever the caller does.
        let head = token.0;
        match self.state[head as usize] {
            DescriptorState::Free => return Err(RecycleError::AlreadyFree(head)),
            DescriptorState::Posted => return Err(RecycleError::StillPosted(head)),
            DescriptorState::Reaped => {}
        }
        self.state[head as usize] = DescriptorState::Free;
        self.free_next[head as usize] = self.free_head;
        self.free_head = head;
        self.num_free += 1;
        Ok(())
    }

    // Volatile field accessors over the DMA region.

    unsafe fn read_u16(&self, off: usize) -> u16 {
        // SAFETY: `off` is derived from a validated index (this fn's contract), so the pointer is in-bounds and aligned for its width.
        unsafe { self.region.add(off).cast::<u16>().read_volatile() }
    }
    unsafe fn write_u16(&self, off: usize, value: u16) {
        // SAFETY: `off` is derived from a validated index (this fn's contract), so the pointer is in-bounds and aligned for its width.
        unsafe { self.region.add(off).cast::<u16>().write_volatile(value) }
    }
    unsafe fn read_u32(&self, off: usize) -> u32 {
        // SAFETY: `off` is derived from a validated index (this fn's contract), so the pointer is in-bounds and aligned for its width.
        unsafe { self.region.add(off).cast::<u32>().read_volatile() }
    }
    unsafe fn write_u32(&self, off: usize, value: u32) {
        // SAFETY: `off` is derived from a validated index (this fn's contract), so the pointer is in-bounds and aligned for its width.
        unsafe { self.region.add(off).cast::<u32>().write_volatile(value) }
    }
    unsafe fn write_u64(&self, off: usize, value: u64) {
        // SAFETY: `off` is derived from a validated index (this fn's contract), so the pointer is in-bounds and aligned for its width.
        unsafe { self.region.add(off).cast::<u64>().write_volatile(value) }
    }
}

const fn desc_addr_off(index: u16) -> usize {
    index as usize * 16
}
const fn desc_len_off(index: u16) -> usize {
    index as usize * 16 + 8
}
const fn desc_flags_off(index: u16) -> usize {
    index as usize * 16 + 12
}
const fn desc_next_off(index: u16) -> usize {
    index as usize * 16 + 14
}
const fn avail_ring_off<const SIZE: usize>(slot: u16) -> usize {
    SIZE * 16 + 4 + slot as usize * 2
}
const fn used_area_off<const SIZE: usize>() -> usize {
    align_up(SIZE * 16 + 4 + 2 * SIZE + 2, 4)
}
const fn used_elem_id_off<const SIZE: usize>(slot: u16) -> usize {
    used_area_off::<SIZE>() + 4 + slot as usize * 8
}
const fn used_elem_len_off<const SIZE: usize>(slot: u16) -> usize {
    used_elem_id_off::<SIZE>(slot) + 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::VecDeque;

    const SIZE: usize = 16;
    const BUF: usize = 2048;

    /// A 16-byte-aligned backing region.
    #[repr(C, align(16))]
    struct Region([u8; 4096]);

    /// A minimal device that plays the far side of the ring in the same thread:
    /// it reads the driver's available ring, writes a payload into the named
    /// buffer (addressed by the descriptor's `addr`, which the host test sets to
    /// a real pointer), and publishes a used-ring completion.
    struct TestDevice {
        region: *mut u8,
        last_avail: u16,
        used_idx: u16,
    }

    impl TestDevice {
        /// Publish a used-ring completion for `head` reporting `len` bytes,
        /// exactly as the device would — including for a head it was never
        /// given, which is how the hostile cases are driven.
        fn complete(&mut self, head: u32, len: u32) {
            let uslot = (self.used_idx as usize) & (SIZE - 1);
            // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
            unsafe {
                self.region
                    .add(used_elem_id_off::<SIZE>(uslot as u16))
                    .cast::<u32>()
                    .write_volatile(head);
                self.region
                    .add(used_elem_len_off::<SIZE>(uslot as u16))
                    .cast::<u32>()
                    .write_volatile(len);
            }
            fence(Ordering::Release);
            self.used_idx = self.used_idx.wrapping_add(1);
            // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
            unsafe {
                self.region
                    .add(used_area_off::<SIZE>() + 2)
                    .cast::<u16>()
                    .write_volatile(self.used_idx);
            }
        }

        /// The next head index the driver made available, or `None`.
        fn next_avail(&mut self) -> Option<u16> {
            // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
            let avail_idx = unsafe { self.region.add(SIZE * 16 + 2).cast::<u16>().read_volatile() };
            if avail_idx == self.last_avail {
                return None;
            }
            fence(Ordering::Acquire);
            let slot = (self.last_avail as usize) & (SIZE - 1);
            // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
            let head = unsafe {
                self.region
                    .add(avail_ring_off::<SIZE>(slot as u16))
                    .cast::<u16>()
                    .read_volatile()
            };
            self.last_avail = self.last_avail.wrapping_add(1);
            Some(head)
        }

        fn service_writable(&mut self, payload: &[u8]) -> bool {
            let Some(head) = self.next_avail() else {
                return false;
            };
            // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
            let addr = unsafe {
                self.region
                    .add(desc_addr_off(head))
                    .cast::<u64>()
                    .read_volatile()
            };
            // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
            let len = unsafe {
                self.region
                    .add(desc_len_off(head))
                    .cast::<u32>()
                    .read_volatile()
            } as usize;
            // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
            let flags = unsafe {
                self.region
                    .add(desc_flags_off(head))
                    .cast::<u16>()
                    .read_volatile()
            };
            assert_eq!(flags & VIRTQ_DESC_F_WRITE, VIRTQ_DESC_F_WRITE);

            let n = payload.len().min(len);
            let buffer = addr as *mut u8;
            // SAFETY: `buffer` is the real backing buffer the descriptor addresses and `n = min(payload, len)` stays within it.
            unsafe { core::ptr::copy_nonoverlapping(payload.as_ptr(), buffer, n) };

            self.complete(head as u32, n as u32);
            true
        }
    }

    /// A queue over a fresh region plus the device on its far side, which is
    /// what nearly every case below needs.
    struct Fixture {
        _region: Box<Region>,
        queue: SplitVirtqueue<SIZE>,
        device: TestDevice,
    }

    impl Fixture {
        fn new() -> Self {
            let mut region = Box::new(Region([0; 4096]));
            let ptr = region.0.as_mut_ptr();
            // SAFETY: the region is 16-byte-aligned, zeroed, larger than the queue layout, and owned solely by this test — `SplitVirtqueue::new`'s contract.
            let queue = unsafe { SplitVirtqueue::<SIZE>::new(ptr) };
            Self {
                _region: region,
                queue,
                device: TestDevice {
                    region: ptr,
                    last_avail: 0,
                    used_idx: 0,
                },
            }
        }
    }

    #[test]
    fn layout_offsets_and_size_are_correct() {
        let layout = SplitVirtqueue::<16>::LAYOUT;
        // desc: 16*16 = 256; avail at 256, bytes 4+32+2 = 38, ends 294;
        // used aligned up to 296, bytes 4+128+2 = 134, total 430.
        assert_eq!(layout.descriptor_offset, 0);
        assert_eq!(layout.driver_offset, 256);
        assert_eq!(layout.device_offset, 296);
        assert_eq!(layout.total_bytes, 430);
    }

    #[test]
    fn add_consumes_descriptors_and_recycle_restores_them_after_completion() {
        let mut fx = Fixture::new();
        assert_eq!(fx.queue.free_count(), SIZE);
        assert_eq!(fx.queue.posted_count(), 0);

        for i in 0..SIZE {
            fx.queue
                .add_writable(0x1000 + i as u64, BUF as u32)
                .expect("a descriptor is free");
        }
        assert_eq!(fx.queue.free_count(), 0);
        assert_eq!(fx.queue.posted_count(), SIZE);
        assert!(fx.queue.add_writable(0x9999, BUF as u32).is_none());

        // A descriptor is reclaimable only once the device has given it back.
        for head in 0..SIZE as u32 {
            fx.device.complete(head, 0);
        }
        for _ in 0..SIZE {
            let (token, _) = fx.queue.poll().expect("a completion is pending");
            assert_eq!(fx.queue.recycle(token), Ok(()));
        }
        assert_eq!(fx.queue.free_count(), SIZE);
        assert_eq!(fx.queue.posted_count(), 0);
        assert_eq!(fx.queue.device_faults(), DeviceFaults::default());
    }

    #[test]
    fn round_trip_delivers_payloads_and_wraps_the_rings() {
        // Cycle far more buffers than the ring holds so the available and used
        // ring positions wrap many times and every descriptor is reused,
        // mirroring a sustained receive path.
        const ROUNDS: u64 = 10_000;
        let mut fx = Fixture::new();

        // A pool of real buffers; their host addresses double as the "paddr"
        // the device writes into.
        let mut buffers: Vec<Box<[u8; BUF]>> = (0..SIZE).map(|_| Box::new([0u8; BUF])).collect();
        let addr_of = |b: &mut Box<[u8; BUF]>| b.as_mut_ptr() as u64;

        // Map a descriptor index back to the buffer it carries.
        let mut token_buffer = std::collections::HashMap::new();
        for (index, buffer) in buffers.iter_mut().enumerate() {
            let token = fx.queue.add_writable(addr_of(buffer), BUF as u32).unwrap();
            token_buffer.insert(token.index(), index);
        }

        for sequence in 0..ROUNDS {
            // Device fills exactly one posted buffer with the sequence number.
            assert!(fx.device.service_writable(&sequence.to_le_bytes()));

            let (token, len) = fx.queue.poll().expect("a completion is pending");
            assert_eq!(len, 8);
            let index = token_buffer[&token.index()];
            let value = u64::from_le_bytes(buffers[index][..8].try_into().unwrap());
            assert_eq!(value, sequence, "payload corrupted or out of order");

            // Return the descriptor and immediately repost the same buffer.
            assert_eq!(fx.queue.recycle(token), Ok(()));
            let token = fx
                .queue
                .add_writable(addr_of(&mut buffers[index]), BUF as u32)
                .unwrap();
            token_buffer.insert(token.index(), index);
        }

        assert!(fx.queue.poll().is_none());
        assert_eq!(fx.queue.device_faults(), DeviceFaults::default());
    }

    #[test]
    fn poll_drops_out_of_range_completions_from_a_bad_device() {
        let mut fx = Fixture::new();
        let mut buffer = Box::new([0u8; BUF]);
        let token = fx
            .queue
            .add_writable(buffer.as_mut_ptr() as u64, BUF as u32)
            .unwrap();

        // A buggy or hostile device posts a completion whose id is far outside
        // the descriptor table, followed by a valid completion for the real
        // descriptor. The bogus id must never reach recycle (which would write
        // out of bounds).
        fx.device.complete(9999, 0);
        fx.device.complete(u32::from(token.index()), BUF as u32);

        // The bogus entry is dropped safely and counted; the valid one is
        // returned.
        let (got, len) = fx
            .queue
            .poll()
            .expect("valid completion after the bogus one");
        assert_eq!(got, token);
        assert_eq!(len, BUF as u32);
        assert!(fx.queue.poll().is_none());
        assert_eq!(
            fx.queue.device_faults(),
            DeviceFaults {
                completion_out_of_range: 1,
                completion_not_posted: 0,
            }
        );
        assert_eq!(fx.queue.recycle(got), Ok(()));
        assert_eq!(fx.queue.free_count(), SIZE);
    }

    #[test]
    fn poll_refuses_a_replayed_completion() {
        // The free-list corruption this prevents: two tokens for one descriptor
        // let `recycle` link that descriptor's `next` to itself, after which
        // `add` re-issues the same descriptor forever and `free_count` climbs
        // past the queue size.
        let mut fx = Fixture::new();
        let token = fx.queue.add_writable(0x1000, BUF as u32).unwrap();
        let head = u32::from(token.index());

        fx.device.complete(head, 64);
        fx.device.complete(head, 64);

        let (got, _) = fx.queue.poll().expect("the first completion is valid");
        assert_eq!(got, token);
        assert!(
            fx.queue.poll().is_none(),
            "the replayed completion must not mint a second token"
        );
        assert_eq!(fx.queue.device_faults().completion_not_posted, 1);
        assert_eq!(fx.queue.recycle(got), Ok(()));
        assert_eq!(fx.queue.free_count(), SIZE);

        // And a third replay after the descriptor is free is refused too.
        fx.device.complete(head, 64);
        assert!(fx.queue.poll().is_none());
        assert_eq!(fx.queue.device_faults().completion_not_posted, 2);
        assert_eq!(fx.queue.free_count(), SIZE);
    }

    #[test]
    fn recycle_refuses_a_token_that_is_still_posted() {
        let mut fx = Fixture::new();
        let token = fx.queue.add_writable(0x1000, 64).unwrap();
        let index = token.index();
        assert_eq!(
            fx.queue.recycle(token),
            Err(RecycleError::StillPosted(index))
        );
        // The free list is untouched: the descriptor is still the device's.
        assert_eq!(fx.queue.free_count(), SIZE - 1);
        assert_eq!(fx.queue.posted_count(), 1);
    }

    #[test]
    fn recycle_refuses_a_token_from_another_queue() {
        // A token naming a descriptor that is free in *this* queue: the only
        // way to hold one is to have taken it from a different queue, which is
        // a driver bookkeeping error rather than device input.
        let mut fx = Fixture::new();
        let mut other = Fixture::new();
        let token = other.queue.add_writable(0x2000, 64).unwrap();
        other.device.complete(u32::from(token.index()), 64);
        let (reaped, _) = other.queue.poll().unwrap();
        let index = reaped.index();

        assert_eq!(
            fx.queue.recycle(reaped),
            Err(RecycleError::AlreadyFree(index))
        );
        assert_eq!(fx.queue.free_count(), SIZE);
    }

    #[test]
    fn poll_clamps_the_device_reported_length_to_the_posted_length() {
        let mut fx = Fixture::new();
        let token = fx.queue.add_writable(0x1000, 128).unwrap();
        // The device claims it wrote far more than the buffer it was given.
        fx.device.complete(u32::from(token.index()), u32::MAX);
        let (_, len) = fx.queue.poll().expect("a completion is pending");
        assert_eq!(
            len, 128,
            "an over-reported length must not escape the queue"
        );
    }

    #[test]
    fn add_readable_posts_a_non_writable_descriptor() {
        let mut fx = Fixture::new();
        let region_ptr = fx.device.region;
        let token = fx.queue.add_readable(0x4000, 64).unwrap();
        // A transmit (device-readable) descriptor must not carry the
        // device-writable flag.
        // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
        let flags = unsafe {
            region_ptr
                .add(desc_flags_off(token.index()))
                .cast::<u16>()
                .read_volatile()
        };
        assert_eq!(flags & VIRTQ_DESC_F_WRITE, 0);
        assert_eq!(fx.queue.free_count(), SIZE - 1);
    }

    #[test]
    fn ring_indices_wrap_through_the_u16_boundary() {
        let mut fx = Fixture::new();
        let mut buffers: Vec<Box<[u8; BUF]>> = (0..SIZE).map(|_| Box::new([0u8; BUF])).collect();
        let region_ptr = fx.device.region;

        // Force both ring positions to just below the u16 wrap so the cycles
        // below cross 0xFFFF -> 0x0000, where modular index bugs would live.
        fx.queue.avail_idx = u16::MAX - 1;
        fx.queue.last_used = u16::MAX - 1;
        // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
        unsafe {
            region_ptr
                .add(used_area_off::<SIZE>() + 2)
                .cast::<u16>()
                .write_volatile(u16::MAX - 1);
        }
        fx.device.last_avail = u16::MAX - 1;
        fx.device.used_idx = u16::MAX - 1;

        for sequence in 0..8u64 {
            let index = sequence as usize % SIZE;
            let token = fx
                .queue
                .add_writable(buffers[index].as_mut_ptr() as u64, BUF as u32)
                .unwrap();
            assert!(fx.device.service_writable(&sequence.to_le_bytes()));
            let (got, len) = fx.queue.poll().expect("a completion is pending");
            assert_eq!(got, token);
            assert_eq!(len, 8);
            let value = u64::from_le_bytes(buffers[index][..8].try_into().unwrap());
            assert_eq!(value, sequence, "payload corrupted across the u16 wrap");
            assert_eq!(fx.queue.recycle(got), Ok(()));
        }
    }

    #[test]
    fn poll_is_bounded_when_a_hostile_device_floods_invalid_ids() {
        let mut fx = Fixture::new();
        let region_ptr = fx.device.region;

        // The device claims a huge number of completions, every used entry
        // carrying an out-of-range id. `poll` must skip at most SIZE of them and
        // return None rather than spin proportionally to the device's claim.
        // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
        unsafe {
            for slot in 0..SIZE {
                region_ptr
                    .add(used_elem_id_off::<SIZE>(slot as u16))
                    .cast::<u32>()
                    .write_volatile(0xDEAD_BEEF);
                region_ptr
                    .add(used_elem_len_off::<SIZE>(slot as u16))
                    .cast::<u32>()
                    .write_volatile(0);
            }
            fence(Ordering::Release);
            region_ptr
                .add(used_area_off::<SIZE>() + 2)
                .cast::<u16>()
                .write_volatile(60_000);
        }
        assert_eq!(fx.queue.poll(), None);
        assert_eq!(
            fx.queue.device_faults().completion_out_of_range,
            SIZE as u64
        );
    }

    #[test]
    fn a_drain_loop_terminates_against_a_device_replaying_valid_completions() {
        // The livelock this closes: `poll` used to return `Some` for any
        // in-range id, so a device republishing one valid id while advancing
        // its used index made `while let Some(..) = poll()` run forever.
        let mut fx = Fixture::new();
        let head = u32::from(fx.queue.add_writable(0x1000, 64).unwrap().index());
        fx.device.complete(head, 64);

        let mut handed_out = 0usize;
        let mut guard = 0usize;
        // The reaped token is deliberately never recycled, so the descriptor
        // cannot return to the posted state and re-arm the loop from this side.
        while let Some((_reaped, _)) = fx.queue.poll() {
            handed_out += 1;
            guard += 1;
            assert!(guard < 1000, "the drain loop did not terminate");
            // The device keeps replaying the same completion mid-drain.
            fx.device.complete(head, 64);
        }
        // Exactly one descriptor was posted, so exactly one completion could
        // ever be handed out, however many the device published.
        assert_eq!(handed_out, 1);
        assert_eq!(fx.queue.posted_count(), 0);
    }

    #[test]
    fn a_scribbled_descriptor_table_cannot_steer_the_free_list() {
        // The out-of-bounds write this closes: the free list used to chain
        // through each descriptor's shared `next` field, so a device that
        // rewrote it owned `free_head` — and the next `add` wrote a descriptor
        // at `free_head * 16`, anywhere in a u16 and far outside the region.
        let mut fx = Fixture::new();
        let region_ptr = fx.device.region;

        // The device rewrites every byte of the descriptor table, which it can
        // reach at any time, with a value that would drive `free_head` out of
        // range if any of it were believed.
        // SAFETY: single-threaded test driving the ring's far side; the whole
        // descriptor table lies within the live, test-owned region.
        unsafe {
            for byte in 0..SIZE * 16 {
                region_ptr.add(byte).write_volatile(0xFF);
            }
        }
        fence(Ordering::Release);

        // Allocation still walks the driver's own free list: every descriptor
        // is handed out exactly once, in range.
        let mut seen = [false; SIZE];
        for _ in 0..SIZE {
            let token = fx
                .queue
                .add_writable(0x1000, BUF as u32)
                .expect("a descriptor is free");
            let index = token.index() as usize;
            assert!(index < SIZE, "the device steered an index out of range");
            assert!(!seen[index], "descriptor {index} was handed out twice");
            seen[index] = true;
        }
        assert!(fx.queue.add_writable(0x2000, BUF as u32).is_none());
        assert_eq!(fx.queue.free_count(), 0);
        assert_eq!(fx.queue.posted_count(), SIZE);
    }

    #[test]
    fn layout_is_correct_for_a_second_queue_size() {
        // A non-trivial second size guards the size-parametric ABI arithmetic
        // beyond the SIZE=16 case above.
        let layout = SplitVirtqueue::<64>::LAYOUT;
        // desc: 64*16 = 1024; avail at 1024, bytes 4+128+2 = 134, ends 1158;
        // used aligned up to 1160, bytes 4+512+2 = 518, total 1678.
        assert_eq!(layout.size, 64);
        assert_eq!(layout.descriptor_offset, 0);
        assert_eq!(layout.driver_offset, 1024);
        assert_eq!(layout.device_offset, 1160);
        assert_eq!(layout.total_bytes, 1678);
    }

    /// Publish a device used-ring completion for descriptor `head` at the next
    /// used slot, as the device would. Kept as a free helper so the property
    /// test can complete descriptors in an arbitrary (out-of-posting) order.
    fn device_complete(region: *mut u8, used_idx: &mut u16, head: u16) {
        const N: usize = 8;
        let slot = (*used_idx as usize) & (N - 1);
        // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
        unsafe {
            region
                .add(used_elem_id_off::<N>(slot as u16))
                .cast::<u32>()
                .write_volatile(head as u32);
            region
                .add(used_elem_len_off::<N>(slot as u16))
                .cast::<u32>()
                .write_volatile(0);
        }
        fence(Ordering::Release);
        *used_idx = used_idx.wrapping_add(1);
        // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
        unsafe {
            region
                .add(used_area_off::<N>() + 2)
                .cast::<u16>()
                .write_volatile(*used_idx);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// Random add/complete/poll/recycle sequences, with the device
        /// completing descriptors in and out of posting order, must never panic,
        /// never hand out a token index that is already in flight, and conserve
        /// the descriptor count: `free_count` equals the queue size minus every
        /// descriptor currently posted, completed-but-unpolled, or polled-but-
        /// unrecycled, and returns to full once all are recycled.
        #[test]
        fn split_virtqueue_accounting_holds_under_random_operations(
            ops in prop::collection::vec((0u8..4, any::<u16>()), 0..200),
        ) {
            const N: usize = 8;
            let mut region = Box::new(Region([0; 4096]));
            // SAFETY: the region is 16-byte-aligned, zeroed, larger than the queue layout, and owned solely by this test — `SplitVirtqueue::new`'s contract.
            let mut queue = unsafe { SplitVirtqueue::<N>::new(region.0.as_mut_ptr()) };
            let region_ptr = region.0.as_mut_ptr();

            let mut outstanding: Vec<Token> = Vec::new(); // posted, device not done
            let mut completed: VecDeque<Token> = VecDeque::new(); // device done, unpolled
            let mut inflight: Vec<Token> = Vec::new(); // polled, unrecycled
            let mut used_idx: u16 = 0;

            let check_invariants =
                |q: &SplitVirtqueue<N>,
                 outstanding: &[Token],
                 completed: &VecDeque<Token>,
                 inflight: &[Token]|
                 -> Result<(), TestCaseError> {
                    let allocated = outstanding.len() + completed.len() + inflight.len();
                    prop_assert_eq!(q.free_count(), N - allocated);
                    // Only descriptors the device has not completed are posted.
                    prop_assert_eq!(q.posted_count(), outstanding.len() + completed.len());
                    // A descriptor index is in exactly one state at a time.
                    let mut seen = [false; N];
                    for t in outstanding
                        .iter()
                        .chain(completed.iter())
                        .chain(inflight.iter())
                    {
                        let i = t.index() as usize;
                        prop_assert!(!seen[i], "descriptor {} held in two states", i);
                        seen[i] = true;
                    }
                    Ok(())
                };

            for (action, sel) in ops {
                match action {
                    0 => {
                        if queue.free_count() > 0 {
                            let token = queue.add_writable(0x1000, 64).unwrap();
                            outstanding.push(token);
                        }
                    }
                    1 => {
                        if !outstanding.is_empty() {
                            let i = (sel as usize) % outstanding.len();
                            let token = outstanding.remove(i);
                            device_complete(region_ptr, &mut used_idx, token.index());
                            completed.push_back(token);
                        }
                    }
                    2 => match queue.poll() {
                        Some((got, _)) => {
                            let expected = completed.pop_front();
                            // Compare by reference so the token is not consumed;
                            // `Token` is move-only, and it is stored below.
                            prop_assert_eq!(Some(&got), expected.as_ref());
                            inflight.push(got);
                        }
                        None => prop_assert!(completed.is_empty()),
                    },
                    _ => {
                        if !inflight.is_empty() {
                            let i = (sel as usize) % inflight.len();
                            prop_assert_eq!(queue.recycle(inflight.remove(i)), Ok(()));
                        }
                    }
                }
                check_invariants(&queue, &outstanding, &completed, &inflight)?;
            }

            // Drain everything and confirm the free list is whole again.
            for token in inflight.drain(..) {
                prop_assert_eq!(queue.recycle(token), Ok(()));
            }
            while let Some(token) = outstanding.pop() {
                device_complete(region_ptr, &mut used_idx, token.index());
                completed.push_back(token);
            }
            while let Some((got, _)) = queue.poll() {
                prop_assert_eq!(queue.recycle(got), Ok(()));
            }
            prop_assert_eq!(queue.free_count(), N);
            prop_assert_eq!(queue.posted_count(), 0);
            // Every completion in this run named a posted descriptor exactly
            // once, so a fault here would mean the queue refused a legitimate
            // completion.
            prop_assert_eq!(queue.device_faults(), DeviceFaults::default());
        }

        /// Arbitrary device bytes across the **whole** region — descriptor
        /// table, driver ring and device ring alike, all of which the device
        /// can write: `poll` must terminate, never mint a token outside the
        /// descriptor table, never hand out more completions than were posted,
        /// and never report more bytes than were programmed; and the free list
        /// must still be intact enough to re-post afterwards.
        #[test]
        fn poll_survives_an_arbitrary_used_ring(
            posts in 0usize..=8,
            bytes in prop::collection::vec(any::<u8>(), 0..256),
            used_idx in any::<u16>(),
        ) {
            const N: usize = 8;
            const POSTED_LEN: u32 = 512;
            let mut region = Box::new(Region([0; 4096]));
            let ptr = region.0.as_mut_ptr();
            // SAFETY: the region is 16-byte-aligned, zeroed, larger than the queue layout, and owned solely by this test — `SplitVirtqueue::new`'s contract.
            let mut queue = unsafe { SplitVirtqueue::<N>::new(ptr) };
            for _ in 0..posts {
                if queue.add_writable(0x1000, POSTED_LEN).is_none() {
                    break;
                }
            }
            let posted = queue.posted_count();

            // Overwrite every byte of the region with fuzzer-chosen bytes, then
            // claim an arbitrary used index. The device can write all of it,
            // not merely the used ring it owns by protocol, so a driver that
            // believed any of it — a descriptor's `next`, an available entry —
            // would be steered from here.
            let used_base = SplitVirtqueue::<N>::LAYOUT.device_offset;
            let total = SplitVirtqueue::<N>::LAYOUT.total_bytes;
            for offset in 0..total {
                let byte = bytes.get(offset % bytes.len().max(1)).copied().unwrap_or(0);
                // SAFETY: `offset < total_bytes`, which is inside the test-owned region.
                unsafe { ptr.add(offset).write_volatile(byte) };
            }
            fence(Ordering::Release);
            // SAFETY: the used index lies within the test-owned region.
            unsafe { ptr.add(used_base + 2).cast::<u16>().write_volatile(used_idx) };

            let mut handed_out = 0usize;
            let mut guard = 0usize;
            while let Some((token, len)) = queue.poll() {
                prop_assert!((token.index() as usize) < N);
                prop_assert!(len <= POSTED_LEN, "a device length escaped the clamp");
                handed_out += 1;
                guard += 1;
                prop_assert!(guard <= N, "the drain loop outran the posted descriptors");
                prop_assert_eq!(queue.recycle(token), Ok(()));
            }
            prop_assert!(handed_out <= posted);
            prop_assert!(queue.free_count() <= N);

            // The free list is driver-private, so the scribble cannot have
            // reached it: every descriptor it still holds allocates in range
            // and exactly once.
            let mut seen = [false; N];
            while let Some(token) = queue.add_writable(0x2000, POSTED_LEN) {
                let index = token.index() as usize;
                prop_assert!(index < N);
                prop_assert!(!seen[index], "descriptor {} handed out twice", index);
                seen[index] = true;
            }
            prop_assert_eq!(queue.free_count(), 0);
        }
    }
}
