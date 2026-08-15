//! Driver side of the virtio 1.0 split virtqueue: a descriptor table, the
//! driver (available) ring, and the device (used) ring, laid out in one DMA
//! region that a transport programs into the device ([`QueueLayout`]).
//!
//! Field access is volatile and fenced at the publish/reap boundaries, where a
//! real device observes or produces the indices. The fences order CPU-visible
//! memory only, which suffices because x86 DMA is cache-coherent and the region
//! is mapped cached; a non-coherent platform would need cache maintenance here
//! as well. A request may span several descriptors ([`add_chain`]): virtio-blk
//! needs a header, data and status at three different permissions.
//!
//! # The device is untrusted
//!
//! The adversary is a hostile or malfunctioning device, and it can
//! write **every byte of the region** — not only the used ring it owns by
//! protocol, but the descriptor table and the driver ring as well. The
//! governing rule is therefore stronger than "validate the used ring": *no
//! value read back from the region is ever used to index it*. Whether a
//! completion may be accepted, how much work one [`poll`] may do, and every
//! offset this type computes are all decided from the private fields below,
//! which live outside the region the device can reach.
//!
//! The free list is the sharpest case. Its successor links live in `free_next`
//! rather than in each descriptor's shared `next` field, because reading that
//! field back would hand the device the allocator: a scribbled `next` becomes
//! `free_head`, and the very next [`add_writable`] writes a descriptor at
//! `free_head * 16` — anywhere in a `u16`, far outside the region. A chain's
//! links are held apart for the same reason, in `chain_next`: they decide what
//! [`Completion::recycle`] frees, so believing the shared field would let a
//! device free a descriptor twice. That field is written for the ABI, and
//! never read.
//!
//! What is **not** checked, because it is not checkable from this side: the
//! device may complete a descriptor it never read, report fewer bytes than it
//! wrote, or never complete a descriptor at all. The first two are
//! indistinguishable from a short frame and are the parser's problem; the third
//! is a stall, which costs the driver the buffer and is visible as a
//! [`posted_count`] that stops falling.
//!
//! [`poll`]: SplitVirtqueue::poll
//! [`posted_count`]: SplitVirtqueue::posted_count
//! [`add_writable`]: SplitVirtqueue::add_writable
//! [`add_chain`]: SplitVirtqueue::add_chain

use core::sync::atomic::{Ordering, fence};

const DESC_STRIDE: usize = 16;
const USED_ELEM_STRIDE: usize = 8;

const VIRTQ_DESC_F_NEXT: u16 = 1;
/// Device-*writable*: a receive buffer, in virtio's device-centric sense.
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// virtio 1.0 starts the device (used) ring at a 4-byte boundary.
const USED_RING_ALIGN: usize = 4;

/// Terminates a `chain_next` list.
const NO_LINK: u16 = u16::MAX;

/// Round `value` up to the device ring's alignment.
const fn align_to_used_ring(value: usize) -> usize {
    (value + (USED_RING_ALIGN - 1)) & !(USED_RING_ALIGN - 1)
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DescriptorState {
    Free,
    /// Head of a posted chain, and the only descriptor of it the device may
    /// complete.
    Posted,
    /// A posted chain member that is not its head. Distinct from
    /// [`Posted`](Self::Posted) so completing one is refused rather than
    /// freeing the chain a second time, through the middle.
    PostedLink,
    /// Completed by the device and handed to the driver as a [`Completion`];
    /// the descriptor stays allocated until that completion is recycled.
    Reaped,
}

/// One buffer of a descriptor chain, in the order the device reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub paddr: u64,
    pub len: u32,
    /// True for a descriptor the *device* writes — virtio's own sense.
    pub device_writable: bool,
}

/// Counts of the used-ring completions this queue refused, which are otherwise
/// invisible: a device replaying or forging completions at line rate looks
/// exactly like an idle link.
///
/// Every field is monotonic for the queue's life and saturates at [`u64::MAX`]
/// rather than wrapping. A consumer of the appliance's metric readings derives a
/// rate by differencing successive ones, so a reset would forge a negative rate and
/// a wrap would turn a sustained flood back into a small number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceFaults {
    /// Completions whose `id` was not a descriptor index of this queue.
    pub completion_out_of_range: u64,
    /// Completions naming a descriptor that was not posted to the device: a
    /// replay of one already reaped, or an echo of one never published.
    pub completion_not_posted: u64,
    /// Completions claiming more bytes than the buffer that descriptor was
    /// posted with could hold. Counted before the length is clamped, so the
    /// attempt stays visible rather than being silently absorbed.
    pub completion_length_over_reported: u64,
}

/// One completed buffer, and the right to return its descriptor to the free
/// list — the device's half of the ownership transfer, made explicit.
///
/// Recycling into a queue other than the producing one does not compile:
///
/// ```compile_fail
/// #[repr(C, align(16))]
/// struct Region([u8; 4096]);
/// let mut first = Region([0; 4096]);
/// let mut second = Region([0; 4096]);
/// // SAFETY: two disjoint, zeroed, 16-byte-aligned regions, each larger than
/// // the layout and outliving its queue.
/// let mut a = unsafe { virtio::queue::SplitVirtqueue::<16>::new(first.0.as_mut_ptr()) };
/// // SAFETY: as above, over the second region.
/// let mut b = unsafe { virtio::queue::SplitVirtqueue::<16>::new(second.0.as_mut_ptr()) };
/// let (completion, _len) = a.poll().expect("a completion");
/// b.recycle(completion);
/// ```
///
/// Publishing a buffer yields only the descriptor index, never a value of this
/// type: a published descriptor belongs to the *device*, so there is no
/// reclaim right to hand out until it completes.
#[must_use = "dropping a completion strands its descriptor: the queue never reissues it"]
pub struct Completion<'queue, const SIZE: usize> {
    queue: &'queue mut SplitVirtqueue<SIZE>,
    head: u16,
}

impl<const SIZE: usize> Completion<'_, SIZE> {
    /// The descriptor index this completion names, always `< SIZE`.
    #[must_use]
    pub const fn index(&self) -> u16 {
        self.head
    }

    /// Return the descriptor to its queue's free list.
    pub fn recycle(self) {
        self.queue.release(self.head);
    }
}

/// Where each sub-area sits within the queue's region, and how much of it the
/// queue needs. A transport adds these to the region's physical address to
/// program the device's queue registers; `driver` and `device` are virtio's
/// available and used rings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueLayout {
    pub size: usize,
    pub descriptor_offset: usize,
    pub driver_offset: usize,
    pub device_offset: usize,
    pub total_bytes: usize,
}

/// The driver side of a split virtqueue of `SIZE` descriptors. `SIZE` must be a
/// power of two of at least 2 and at most 32768 (the ring index is a `u16`);
/// naming either [`LAYOUT`](Self::LAYOUT) or [`new`](Self::new) for a `SIZE`
/// outside that is a compile error.
pub struct SplitVirtqueue<const SIZE: usize> {
    region: *mut u8,
    state: [DescriptorState; SIZE],
    /// The buffer length this driver programmed into each descriptor, kept for
    /// clamping the device's reported completion length.
    posted_len: [u32; SIZE],
    /// The free list's successor links. Only entries of free descriptors are
    /// meaningful.
    free_next: [u16; SIZE],
    /// A posted chain's successor links, [`NO_LINK`]-terminated.
    chain_next: [u16; SIZE],
    free_head: u16,
    num_free: u16,
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
        assert!(SIZE <= NO_LINK as usize, "NO_LINK must name no descriptor");
    };

    const DESC_BYTES: usize = SIZE * DESC_STRIDE;
    const AVAIL_OFF: usize = Self::DESC_BYTES;
    const AVAIL_BYTES: usize = 4 + 2 * SIZE + 2;
    const USED_OFF: usize = align_to_used_ring(Self::AVAIL_OFF + Self::AVAIL_BYTES);
    const USED_BYTES: usize = 4 + USED_ELEM_STRIDE * SIZE + 2;
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
            chain_next: [NO_LINK; SIZE],
            free_head: 0,
            num_free: SIZE as u16,
            num_posted: 0,
            avail_idx: 0,
            last_used: 0,
            faults: DeviceFaults::default(),
        };
        queue.reset_avail_header();
        queue
    }

    /// Reduce any index into the descriptor table or either ring.
    ///
    /// Total in its argument, so every array access and region offset below is
    /// in range by arithmetic rather than by an argument about who validated
    /// what. `SIZE` is a power of two, so this is a mask once monomorphised.
    const fn wrap(index: u16) -> usize {
        index as usize % SIZE
    }

    #[must_use]
    pub fn free_count(&self) -> usize {
        self.num_free as usize
    }

    /// Requests published and not yet completed — one per chain, however long.
    /// The only quantity a completion can legitimately consume, and so the
    /// bound on how many [`poll`](Self::poll) hands out before posting again.
    #[must_use]
    pub fn posted_count(&self) -> usize {
        self.num_posted as usize
    }

    #[must_use]
    pub fn device_faults(&self) -> DeviceFaults {
        self.faults
    }

    /// Publish a receive buffer at physical address `paddr`, returning the
    /// descriptor index it went into or `None` when none is free.
    pub fn add_writable(&mut self, paddr: u64, len: u32) -> Option<u16> {
        self.add(paddr, len, true)
    }

    /// Publish a transmit buffer at physical address `paddr`.
    pub fn add_readable(&mut self, paddr: u64, len: u32) -> Option<u16> {
        self.add(paddr, len, false)
    }

    fn add(&mut self, paddr: u64, len: u32, device_writable: bool) -> Option<u16> {
        self.add_chain(&[Segment {
            paddr,
            len,
            device_writable,
        }])
    }

    /// Publish `segments` as one request the device consumes and completes as
    /// a unit, returning its head descriptor — the only one the device may
    /// name back, and the one [`Completion::recycle`] frees the chain through.
    ///
    /// `None`, with nothing allocated, when the chain is empty or wants more
    /// descriptors than are free: a part-allocated chain would strand every
    /// descriptor it had taken, since only a head can be completed.
    pub fn add_chain(&mut self, segments: &[Segment]) -> Option<u16> {
        // `num_free` never exceeds `SIZE`, so this refuses a chain longer than
        // the whole queue as well.
        if segments.is_empty() || segments.len() > self.num_free as usize {
            return None;
        }
        // Built tail first, because a descriptor's `next` is written with the
        // rest of it and the free list yields one index at a time: the
        // successor must exist already. Chain order is the links, not the
        // indices, so running backwards through the free list costs nothing.
        let mut successor = NO_LINK;
        let mut writable_len = 0u32;
        for segment in segments.iter().rev() {
            let index = Self::wrap(self.free_head);
            self.free_head = self.free_next[index];
            self.num_free -= 1;

            let mut flags = 0;
            if segment.device_writable {
                flags |= VIRTQ_DESC_F_WRITE;
                writable_len = writable_len.saturating_add(segment.len);
            }
            let next = if successor == NO_LINK {
                0
            } else {
                flags |= VIRTQ_DESC_F_NEXT;
                successor
            };
            self.publish_descriptor(index, segment.paddr, segment.len, flags, next);
            self.chain_next[index] = successor;
            self.state[index] = DescriptorState::PostedLink;
            successor = index as u16;
        }

        let head = Self::wrap(successor);
        self.state[head] = DescriptorState::Posted;
        // The clamp on what the device may report: virtio counts only the bytes
        // it wrote, so a chain it never writes into admits none.
        self.posted_len[head] = writable_len;
        self.num_posted += 1;

        let head = head as u16;
        self.publish_avail(self.avail_idx, head);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        // Publish the descriptors and ring entry before the index the device
        // reads to discover them.
        fence(Ordering::Release);
        self.set_avail_idx(self.avail_idx);
        Some(head)
    }

    /// Reap the next completed buffer and how many bytes the device reported
    /// writing, clamped to the length this driver programmed for that
    /// descriptor. The descriptor stays allocated until
    /// [`Completion::recycle`].
    ///
    /// `None` is one answer to three situations, which a caller separates — if
    /// it needs to — through [`device_faults`](Self::device_faults): the used
    /// ring is caught up, every entry examined was refused as malformed, or the
    /// per-call scan budget ran out. All three end a drain loop, which is the
    /// only decision the caller has to make.
    pub fn poll(&mut self) -> Option<(Completion<'_, SIZE>, u32)> {
        let (head, len) = self.reap_next()?;
        Some((Completion { queue: self, head }, len))
    }

    /// Kept out of [`poll`] so the borrow the completion carries is taken once,
    /// after the loop has finished with the queue, rather than conditionally
    /// from inside it.
    fn reap_next(&mut self) -> Option<(u16, u32)> {
        for _ in 0..SIZE {
            let device_idx = self.used_idx();
            if device_idx == self.last_used {
                return None;
            }
            // Observe the completion the device published before the index bump.
            fence(Ordering::Acquire);
            let (id, len) = self.used_elem(self.last_used);
            self.last_used = self.last_used.wrapping_add(1);
            if (id as usize) >= SIZE {
                bump(&mut self.faults.completion_out_of_range);
                continue;
            }
            let index = Self::wrap(id as u16);
            if self.state[index] != DescriptorState::Posted {
                // A replay, or an echo of a descriptor never published:
                // accepting it would mint a second live completion for one
                // descriptor and let the free list take it twice.
                bump(&mut self.faults.completion_not_posted);
                continue;
            }
            self.state[index] = DescriptorState::Reaped;
            self.num_posted -= 1;
            let posted_len = self.posted_len[index];
            if len > posted_len {
                bump(&mut self.faults.completion_length_over_reported);
            }
            return Some((index as u16, len.min(posted_len)));
        }
        None
    }

    /// Reachable only by consuming a [`Completion`], which exists only for a
    /// chain head this queue moved into the reaped state; its links come too.
    fn release(&mut self, head: u16) {
        let mut index = Self::wrap(head);
        // A chain holds each descriptor at most once, so the bound never ends
        // this walk — it makes termination the loop's property, not the list's.
        for _ in 0..SIZE {
            let successor = self.chain_next[index];
            self.state[index] = DescriptorState::Free;
            self.free_next[index] = self.free_head;
            self.free_head = index as u16;
            self.num_free += 1;
            if successor == NO_LINK {
                break;
            }
            index = Self::wrap(successor);
        }
    }

    // Each accessor below takes a descriptor index or a ring position rather
    // than a byte offset and reduces it with `wrap`, so no caller can name a
    // location: there is no precondition to delegate, and the only obligation
    // left is the one `new` took for the region itself.

    fn reset_avail_header(&self) {
        // SAFETY: `AVAIL_OFF`/`AVAIL_IDX_OFF` lie inside `TOTAL` and are
        // 2-aligned because `AVAIL_OFF` is a multiple of `DESC_STRIDE`, as the
        // layout assertions at the end of this file pin; `new`'s contract makes
        // `region` that many live 16-byte-aligned bytes for this value's life.
        unsafe {
            self.region
                .add(Self::AVAIL_OFF)
                .cast::<u16>()
                .write_volatile(0);
            self.region
                .add(Self::AVAIL_IDX_OFF)
                .cast::<u16>()
                .write_volatile(0);
        }
    }

    fn publish_descriptor(&self, index: usize, paddr: u64, len: u32, flags: u16, next: u16) {
        let base = desc_addr_off(index % SIZE);
        // SAFETY: reducing the index modulo `SIZE` puts
        // `base + DESC_STRIDE <= SIZE * DESC_STRIDE <= TOTAL`, and `region`
        // carries `new`'s contract. Each field's offset within the 16-byte
        // descriptor is a multiple of its own width, as the layout assertions
        // at the end of this file pin, over a 16-byte-aligned region.
        unsafe {
            self.region.add(base).cast::<u64>().write_volatile(paddr);
            self.region.add(base + 8).cast::<u32>().write_volatile(len);
            self.region
                .add(base + 12)
                .cast::<u16>()
                .write_volatile(flags);
            self.region
                .add(base + 14)
                .cast::<u16>()
                .write_volatile(next);
        }
    }

    fn publish_avail(&self, position: u16, head: u16) {
        let off = avail_ring_off::<SIZE>(Self::wrap(position));
        // SAFETY: the reduced position puts the entry inside the driver ring,
        // which ends before `USED_OFF <= TOTAL`; entries are 2-aligned for the
        // reason `reset_avail_header` gives, and `region` carries `new`'s
        // contract.
        unsafe { self.region.add(off).cast::<u16>().write_volatile(head) };
    }

    fn set_avail_idx(&self, value: u16) {
        // SAFETY: as `reset_avail_header`, for the same word.
        unsafe {
            self.region
                .add(Self::AVAIL_IDX_OFF)
                .cast::<u16>()
                .write_volatile(value)
        }
    }

    fn used_idx(&self) -> u16 {
        // SAFETY: `USED_IDX_OFF` lies inside `TOTAL` and is 2-aligned because
        // `align_to_used_ring` makes `USED_OFF` 4-aligned; `region` carries
        // `new`'s contract.
        unsafe {
            self.region
                .add(Self::USED_IDX_OFF)
                .cast::<u16>()
                .read_volatile()
        }
    }

    fn used_elem(&self, position: u16) -> (u32, u32) {
        let slot = Self::wrap(position);
        // SAFETY: the reduced position puts the 8-byte element inside the
        // device ring, which ends at `TOTAL`, and both words are 4-aligned
        // because `USED_OFF` is; `region` carries `new`'s contract.
        unsafe {
            (
                self.region
                    .add(used_elem_id_off::<SIZE>(slot))
                    .cast::<u32>()
                    .read_volatile(),
                self.region
                    .add(used_elem_len_off::<SIZE>(slot))
                    .cast::<u32>()
                    .read_volatile(),
            )
        }
    }
}

const fn desc_addr_off(slot: usize) -> usize {
    slot * DESC_STRIDE
}
const fn desc_len_off(slot: usize) -> usize {
    slot * DESC_STRIDE + 8
}
const fn desc_flags_off(slot: usize) -> usize {
    slot * DESC_STRIDE + 12
}
const fn desc_next_off(slot: usize) -> usize {
    slot * DESC_STRIDE + 14
}
const fn avail_ring_off<const SIZE: usize>(slot: usize) -> usize {
    SIZE * DESC_STRIDE + 4 + slot * 2
}
const fn used_area_off<const SIZE: usize>() -> usize {
    align_to_used_ring(SIZE * DESC_STRIDE + 4 + 2 * SIZE + 2)
}
const fn used_elem_id_off<const SIZE: usize>(slot: usize) -> usize {
    used_area_off::<SIZE>() + 4 + slot * USED_ELEM_STRIDE
}
const fn used_elem_len_off<const SIZE: usize>(slot: usize) -> usize {
    used_elem_id_off::<SIZE>(slot) + 4
}

// The virtio 1.0 wire layout, compared against literal byte positions rather
// than a second copy of the arithmetic. The device reaches these positions from
// the register values a transport programmed, so a change on this side it does
// not make is a silent disagreement about where every field lives. The literals
// are also what the region accessors' alignment claims rest on.
const _: () = assert!(desc_addr_off(0) == 0);
const _: () = assert!(desc_len_off(0) == 8);
const _: () = assert!(desc_flags_off(0) == 12);
const _: () = assert!(desc_next_off(0) == 14);
const _: () = assert!(desc_addr_off(1) == 16);
const _: () = assert!(desc_addr_off(7) == 112);

// SIZE = 16: 256 bytes of descriptor table, then the driver ring's flags at
// 256, its index at 258 and its first entry at 260; the device ring starts
// 4-aligned at 296 with its index at 298 and 8-byte elements from 300.
const _: () = assert!(SplitVirtqueue::<16>::AVAIL_OFF == 256);
const _: () = assert!(SplitVirtqueue::<16>::AVAIL_IDX_OFF == 258);
const _: () = assert!(avail_ring_off::<16>(0) == 260);
const _: () = assert!(avail_ring_off::<16>(1) == 262);
const _: () = assert!(used_area_off::<16>() == 296);
const _: () = assert!(SplitVirtqueue::<16>::USED_OFF == 296);
const _: () = assert!(SplitVirtqueue::<16>::USED_IDX_OFF == 298);
const _: () = assert!(used_elem_id_off::<16>(0) == 300);
const _: () = assert!(used_elem_len_off::<16>(0) == 304);
const _: () = assert!(used_elem_id_off::<16>(1) == 308);
const _: () = assert!(SplitVirtqueue::<16>::TOTAL == 430);

// SIZE = 64, where the driver ring ends at 1158 and the 4-byte alignment of
// the device ring is what moves it to 1160 — the one arithmetic step the
// SIZE = 16 case does not exercise differently.
const _: () = assert!(SplitVirtqueue::<64>::AVAIL_OFF == 1024);
const _: () = assert!(used_area_off::<64>() == 1160);
const _: () = assert!(used_elem_id_off::<64>(63) == 1668);
const _: () = assert!(SplitVirtqueue::<64>::TOTAL == 1678);

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::VecDeque;

    const SIZE: usize = 16;
    const BUF: usize = 2048;

    /// The heap allocation a fixture region owns, at the alignment
    /// `SplitVirtqueue::new` requires.
    #[repr(C, align(16))]
    struct Page([u8; 4096]);

    /// A fixture region, reachable only through the one raw pointer the queue
    /// and the device on its far side are both attached to.
    ///
    /// The bytes are `Box::into_raw`d and no `&`/`&mut` into them is ever
    /// formed, so both sides share a single tag for the region's whole life. A
    /// `Box` does not survive that: moving it into a fixture retags the
    /// allocation and invalidates every pointer already handed out, so the
    /// queue's next volatile write would itself be undefined behaviour while
    /// claiming to prove the queue's conduct against a hostile device.
    /// Exposing no reference makes that unrepresentable rather than a rule to
    /// remember.
    struct MappedRegion {
        page: *mut Page,
    }

    impl MappedRegion {
        fn zeroed() -> Self {
            Self {
                page: Box::into_raw(Box::new(Page([0; 4096]))),
            }
        }

        /// The pointer both sides are mapped over, and the only route to the
        /// bytes — `*mut` from `&self` deliberately, because handing either
        /// side a separately derived pointer is what a fixture must not do.
        fn base(&self) -> *mut u8 {
            self.page.cast::<u8>()
        }
    }

    impl Drop for MappedRegion {
        fn drop(&mut self) {
            // SAFETY: `page` came from `Box::into_raw` in `zeroed`, is never
            // replaced, and no other owner exists, so this reconstructs that
            // `Box` exactly once.
            drop(unsafe { Box::from_raw(self.page) });
        }
    }

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
                    .add(used_elem_id_off::<SIZE>(uslot))
                    .cast::<u32>()
                    .write_volatile(head);
                self.region
                    .add(used_elem_len_off::<SIZE>(uslot))
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
                    .add(avail_ring_off::<SIZE>(slot))
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
                    .add(desc_addr_off(head as usize))
                    .cast::<u64>()
                    .read_volatile()
            };
            // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
            let len = unsafe {
                self.region
                    .add(desc_len_off(head as usize))
                    .cast::<u32>()
                    .read_volatile()
            } as usize;
            // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
            let flags = unsafe {
                self.region
                    .add(desc_flags_off(head as usize))
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

    /// One descriptor as it stands in the shared table — `(paddr, len, flags,
    /// next)` — read from exactly where the device reads it.
    fn read_descriptor(region: *mut u8, index: u16) -> (u64, u32, u16, u16) {
        let slot = index as usize;
        // SAFETY: single-threaded test driving the ring's far side; a descriptor index lies within the live, test-owned region.
        unsafe {
            (
                region
                    .add(desc_addr_off(slot))
                    .cast::<u64>()
                    .read_volatile(),
                region.add(desc_len_off(slot)).cast::<u32>().read_volatile(),
                region
                    .add(desc_flags_off(slot))
                    .cast::<u16>()
                    .read_volatile(),
                region
                    .add(desc_next_off(slot))
                    .cast::<u16>()
                    .read_volatile(),
            )
        }
    }

    /// The descriptor indices of a posted chain, from the driver's own links
    /// rather than the shared `next` field the device can rewrite. Bounded by
    /// `SIZE`, so a corrupt list fails an assertion instead of hanging.
    fn chain_indices<const N: usize>(queue: &SplitVirtqueue<N>, head: u16) -> Vec<u16> {
        let mut indices = Vec::new();
        let mut index = head;
        for _ in 0..N {
            indices.push(index);
            let successor = queue.chain_next[index as usize];
            if successor == NO_LINK {
                break;
            }
            index = successor;
        }
        indices
    }

    /// A three-descriptor request shaped like virtio-blk's: a device-readable
    /// header, a device-writable data buffer, a device-writable status byte.
    fn block_request() -> [Segment; 3] {
        [
            Segment {
                paddr: 0x1000,
                len: 16,
                device_writable: false,
            },
            Segment {
                paddr: 0x2000,
                len: 512,
                device_writable: true,
            },
            Segment {
                paddr: 0x3000,
                len: 1,
                device_writable: true,
            },
        ]
    }

    /// A queue over a fresh region plus the device on its far side, which is
    /// what nearly every case below needs.
    struct Fixture {
        _region: MappedRegion,
        queue: SplitVirtqueue<SIZE>,
        device: TestDevice,
    }

    impl Fixture {
        fn new() -> Self {
            let region = MappedRegion::zeroed();
            let ptr = region.base();
            // SAFETY: `MappedRegion` is 16-byte-aligned, zeroed, larger than the queue layout, and live until this fixture's `Drop` — `SplitVirtqueue::new`'s contract.
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
            let (completion, _) = fx.queue.poll().expect("a completion is pending");
            completion.recycle();
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
        let mut descriptor_buffer = std::collections::HashMap::new();
        for (index, buffer) in buffers.iter_mut().enumerate() {
            let head = fx.queue.add_writable(addr_of(buffer), BUF as u32).unwrap();
            descriptor_buffer.insert(head, index);
        }

        for sequence in 0..ROUNDS {
            // Device fills exactly one posted buffer with the sequence number.
            assert!(fx.device.service_writable(&sequence.to_le_bytes()));

            let (completion, len) = fx.queue.poll().expect("a completion is pending");
            assert_eq!(len, 8);
            let index = descriptor_buffer[&completion.index()];
            let value = u64::from_le_bytes(buffers[index][..8].try_into().unwrap());
            assert_eq!(value, sequence, "payload corrupted or out of order");

            // Return the descriptor and immediately repost the same buffer.
            completion.recycle();
            let head = fx
                .queue
                .add_writable(addr_of(&mut buffers[index]), BUF as u32)
                .unwrap();
            descriptor_buffer.insert(head, index);
        }

        assert!(fx.queue.poll().is_none());
        assert_eq!(fx.queue.device_faults(), DeviceFaults::default());
    }

    #[test]
    fn poll_drops_out_of_range_completions_from_a_bad_device() {
        let mut fx = Fixture::new();
        let mut buffer = Box::new([0u8; BUF]);
        let head = fx
            .queue
            .add_writable(buffer.as_mut_ptr() as u64, BUF as u32)
            .unwrap();

        // A buggy or hostile device posts a completion whose id is far outside
        // the descriptor table, followed by a valid completion for the real
        // descriptor. The bogus id must never become a completion (whose
        // recycle would write out of bounds).
        fx.device.complete(9999, 0);
        fx.device.complete(u32::from(head), BUF as u32);

        // The bogus entry is dropped safely and counted; the valid one is
        // returned.
        let (completion, len) = fx
            .queue
            .poll()
            .expect("valid completion after the bogus one");
        assert_eq!(completion.index(), head);
        assert_eq!(len, BUF as u32);
        completion.recycle();
        assert!(fx.queue.poll().is_none());
        assert_eq!(
            fx.queue.device_faults(),
            DeviceFaults {
                completion_out_of_range: 1,
                completion_not_posted: 0,
                completion_length_over_reported: 0,
            }
        );
        assert_eq!(fx.queue.free_count(), SIZE);
    }

    #[test]
    fn poll_refuses_a_replayed_completion() {
        // The free-list corruption this prevents: two tokens for one descriptor
        // let `recycle` link that descriptor's `next` to itself, after which
        // `add` re-issues the same descriptor forever and `free_count` climbs
        // past the queue size.
        let mut fx = Fixture::new();
        let posted = fx.queue.add_writable(0x1000, BUF as u32).unwrap();
        let head = u32::from(posted);

        fx.device.complete(head, 64);
        fx.device.complete(head, 64);

        let (completion, _) = fx.queue.poll().expect("the first completion is valid");
        assert_eq!(completion.index(), posted);
        // Dropped rather than recycled, so the descriptor stays *reaped* —
        // the state the replay has to be refused in. Recycling first would put
        // it back on the free list and test the other state instead.
        drop(completion);
        assert!(
            fx.queue.poll().is_none(),
            "the replayed completion must not mint a second completion"
        );
        assert_eq!(fx.queue.device_faults().completion_not_posted, 1);
        assert_eq!(
            fx.queue.free_count(),
            SIZE - 1,
            "a dropped completion strands its descriptor rather than freeing it"
        );

        // A descriptor that has been all the way round and is back on the free
        // list refuses a replay too.
        let second = fx.queue.add_writable(0x2000, 64).unwrap();
        fx.device.complete(u32::from(second), 64);
        fx.queue
            .poll()
            .expect("the second completion is valid")
            .0
            .recycle();
        fx.device.complete(u32::from(second), 64);
        assert!(fx.queue.poll().is_none());
        assert_eq!(fx.queue.device_faults().completion_not_posted, 2);
        assert_eq!(fx.queue.free_count(), SIZE - 1);
    }

    #[test]
    fn poll_clamps_the_device_reported_length_and_counts_the_over_report() {
        let mut fx = Fixture::new();
        let head = fx.queue.add_writable(0x1000, 128).unwrap();
        // The device claims it wrote far more than the buffer it was given.
        fx.device.complete(u32::from(head), u32::MAX);
        let (completion, len) = fx.queue.poll().expect("a completion is pending");
        assert_eq!(
            len, 128,
            "an over-reported length must not escape the queue"
        );
        completion.recycle();
        // Clamping contains the damage; the counter is what makes the attempt
        // visible, so a device doing this at line rate is not silent.
        assert_eq!(
            fx.queue.device_faults(),
            DeviceFaults {
                completion_out_of_range: 0,
                completion_not_posted: 0,
                completion_length_over_reported: 1,
            }
        );
    }

    #[test]
    fn a_completion_reporting_at_most_the_posted_length_is_not_counted() {
        // The boundary the over-report counter must not fire on: a device that
        // fills the buffer exactly, and one that reports a short frame.
        let mut fx = Fixture::new();
        for len in [128u32, 64] {
            let head = fx.queue.add_writable(0x1000, 128).unwrap();
            fx.device.complete(u32::from(head), len);
            let (completion, reported) = fx.queue.poll().expect("a completion is pending");
            assert_eq!(reported, len);
            completion.recycle();
        }
        assert_eq!(fx.queue.device_faults(), DeviceFaults::default());
    }

    #[test]
    fn add_readable_posts_a_non_writable_descriptor() {
        let mut fx = Fixture::new();
        let region_ptr = fx.device.region;
        let head = fx.queue.add_readable(0x4000, 64).unwrap();
        // A transmit (device-readable) descriptor must not carry the
        // device-writable flag.
        // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
        let flags = unsafe {
            region_ptr
                .add(desc_flags_off(head as usize))
                .cast::<u16>()
                .read_volatile()
        };
        assert_eq!(flags & VIRTQ_DESC_F_WRITE, 0);
        assert_eq!(fx.queue.free_count(), SIZE - 1);
    }

    #[test]
    fn add_chain_publishes_one_request_spanning_three_descriptors() {
        let mut fx = Fixture::new();
        let region_ptr = fx.device.region;
        let segments = block_request();
        let head = fx
            .queue
            .add_chain(&segments)
            .expect("three descriptors are free");

        assert_eq!(fx.queue.free_count(), SIZE - 3);
        assert_eq!(
            fx.queue.posted_count(),
            1,
            "a chain is one request however many descriptors it spans"
        );

        // Walk the chain the device's way — from the head through the shared
        // `next` field — and check it names the segments in order, with the
        // permissions they asked for.
        let mut index = head;
        let mut walked = Vec::new();
        for (position, segment) in segments.iter().enumerate() {
            let (paddr, len, flags, next) = read_descriptor(region_ptr, index);
            assert_eq!(paddr, segment.paddr, "segment {position} address");
            assert_eq!(len, segment.len, "segment {position} length");
            assert_eq!(
                flags & VIRTQ_DESC_F_WRITE != 0,
                segment.device_writable,
                "segment {position} permission"
            );
            walked.push(index);
            if position + 1 == segments.len() {
                assert_eq!(flags & VIRTQ_DESC_F_NEXT, 0, "the tail must not chain on");
                assert_eq!(next, 0, "the tail's `next` names nothing");
            } else {
                assert_eq!(
                    flags & VIRTQ_DESC_F_NEXT,
                    VIRTQ_DESC_F_NEXT,
                    "segment {position} must chain on"
                );
                index = next;
            }
        }
        assert_eq!(
            chain_indices(&fx.queue, head),
            walked,
            "the driver's private links and the device's must describe one chain"
        );
        walked.sort_unstable();
        walked.dedup();
        assert_eq!(walked.len(), 3, "a chain must not reuse a descriptor");

        assert_eq!(fx.device.next_avail(), Some(head));
        assert_eq!(
            fx.device.next_avail(),
            None,
            "only the head enters the available ring"
        );
    }

    #[test]
    fn recycling_a_chain_head_returns_every_descriptor_in_the_chain() {
        let mut fx = Fixture::new();
        let head = fx
            .queue
            .add_chain(&block_request())
            .expect("three descriptors are free");
        assert_eq!(fx.queue.free_count(), SIZE - 3);

        fx.device.complete(u32::from(head), 513);
        let (completion, len) = fx.queue.poll().expect("the head completes");
        assert_eq!(completion.index(), head);
        assert_eq!(len, 513);
        completion.recycle();

        assert_eq!(fx.queue.free_count(), SIZE, "the whole chain came back");
        assert_eq!(fx.queue.posted_count(), 0);

        // And it came back usable: every descriptor allocates again, once.
        let mut seen = [false; SIZE];
        for _ in 0..SIZE {
            let index = fx
                .queue
                .add_writable(0x1000, 64)
                .expect("a descriptor is free") as usize;
            assert!(!seen[index], "descriptor {index} was handed out twice");
            seen[index] = true;
        }
        assert_eq!(fx.queue.device_faults(), DeviceFaults::default());
    }

    #[test]
    fn poll_refuses_a_completion_naming_a_chain_link() {
        // The double-free this closes: a link accepted on its own would go back
        // on the free list while the head still owns it, and recycling the head
        // would put the same descriptor there a second time.
        let mut fx = Fixture::new();
        let head = fx
            .queue
            .add_chain(&block_request())
            .expect("three descriptors are free");
        let links = &chain_indices(&fx.queue, head)[1..];
        assert_eq!(links.len(), 2);

        for &link in links {
            fx.device.complete(u32::from(link), 64);
        }
        assert!(
            fx.queue.poll().is_none(),
            "a chain is completable only through its head"
        );
        assert_eq!(fx.queue.device_faults().completion_not_posted, 2);
        assert_eq!(
            fx.queue.free_count(),
            SIZE - 3,
            "a refused completion frees nothing"
        );
        assert_eq!(fx.queue.posted_count(), 1);

        // The head still completes, and the chain still returns whole.
        fx.device.complete(u32::from(head), 0);
        fx.queue
            .poll()
            .expect("the head is still posted")
            .0
            .recycle();
        assert_eq!(fx.queue.free_count(), SIZE);
    }

    #[test]
    fn a_chain_clamps_to_the_sum_of_its_device_writable_segments() {
        let mut fx = Fixture::new();
        // 16 readable + 512 + 1 writable: 513 bytes the device may claim to
        // have written, and 16 it may not.
        let head = fx
            .queue
            .add_chain(&block_request())
            .expect("three descriptors are free");
        fx.device.complete(u32::from(head), u32::MAX);
        let (completion, len) = fx.queue.poll().expect("a completion is pending");
        assert_eq!(
            len, 513,
            "a segment the device only reads is not room it may claim to have filled"
        );
        completion.recycle();
        assert_eq!(fx.queue.device_faults().completion_length_over_reported, 1);

        // A chain the device only reads admits nothing at all.
        let readable = [
            Segment {
                paddr: 0x1000,
                len: 16,
                device_writable: false,
            },
            Segment {
                paddr: 0x2000,
                len: 64,
                device_writable: false,
            },
        ];
        let head = fx.queue.add_chain(&readable).expect("two are free");
        fx.device.complete(u32::from(head), 1);
        let (completion, len) = fx.queue.poll().expect("a completion is pending");
        assert_eq!(len, 0);
        completion.recycle();
        assert_eq!(fx.queue.device_faults().completion_length_over_reported, 2);
    }

    #[test]
    fn add_chain_refuses_a_chain_it_cannot_allocate_whole() {
        // A part-allocated chain would strand every descriptor it had taken:
        // only a head can be completed, and a chain that was never published
        // never gets one.
        let mut fx = Fixture::new();
        let filler = Segment {
            paddr: 0x1000,
            len: 64,
            device_writable: true,
        };

        assert!(
            fx.queue.add_chain(&[]).is_none(),
            "an empty chain has no head to return"
        );
        assert!(
            fx.queue.add_chain(&[filler; SIZE + 1]).is_none(),
            "a chain longer than the queue is refused, not truncated"
        );
        assert_eq!(fx.queue.free_count(), SIZE, "a refusal allocates nothing");

        for _ in 0..4 {
            fx.queue.add_writable(0x2000, 64).expect("a descriptor");
        }
        let remaining = fx.queue.free_count();
        assert!(fx.queue.add_chain(&vec![filler; remaining + 1]).is_none());
        assert_eq!(fx.queue.free_count(), remaining);
        assert_eq!(
            fx.queue.posted_count(),
            4,
            "the refused chain published nothing"
        );

        // Exactly what is free still succeeds, so the bound is the free count
        // and not something short of it.
        assert!(fx.queue.add_chain(&vec![filler; remaining]).is_some());
        assert_eq!(fx.queue.free_count(), 0);
        assert_eq!(fx.queue.posted_count(), 5);
    }

    #[test]
    fn add_chain_survives_a_reordered_free_list_and_a_ring_wrap() {
        let mut fx = Fixture::new();
        let region_ptr = fx.device.region;

        // Force both ring positions to just below the u16 wrap, so the chain
        // path publishes across 0xFFFF -> 0x0000.
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

        // Hand four descriptors back in an order that is not the order they
        // were taken, so `free_head` is no longer 0 and the free list no longer
        // runs in index order — the state a fresh queue never shows.
        let taken: Vec<u16> = (0..4)
            .map(|_| fx.queue.add_writable(0x1000, 64).expect("a descriptor"))
            .collect();
        for &head in &[taken[2], taken[0], taken[3], taken[1]] {
            fx.device.complete(u32::from(head), 0);
            fx.queue
                .poll()
                .expect("a completion is pending")
                .0
                .recycle();
        }
        assert_eq!(fx.queue.free_count(), SIZE);
        assert_ne!(
            fx.queue.free_head, 0,
            "the free list is no longer in index order"
        );

        // Chains and singles interleaved, each round taking four descriptors
        // and giving all four back.
        for round in 0..6u32 {
            let chain = fx.queue.add_chain(&block_request()).expect("three free");
            let single = fx.queue.add_writable(0x5000, 64).expect("a fourth");
            let members = chain_indices(&fx.queue, chain);
            assert_eq!(members.len(), 3, "round {round}");
            assert!(
                !members.contains(&single),
                "round {round}: the single took a descriptor the chain holds"
            );
            assert_eq!(fx.queue.free_count(), SIZE - 4, "round {round}");

            fx.device.complete(u32::from(chain), 513);
            fx.device.complete(u32::from(single), 64);
            for _ in 0..2 {
                fx.queue
                    .poll()
                    .expect("a completion is pending")
                    .0
                    .recycle();
            }
            assert_eq!(fx.queue.free_count(), SIZE, "round {round}");
            assert_eq!(fx.queue.posted_count(), 0, "round {round}");
        }
        assert_eq!(fx.queue.device_faults(), DeviceFaults::default());
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
            let head = fx
                .queue
                .add_writable(buffers[index].as_mut_ptr() as u64, BUF as u32)
                .unwrap();
            assert!(fx.device.service_writable(&sequence.to_le_bytes()));
            let (completion, len) = fx.queue.poll().expect("a completion is pending");
            assert_eq!(completion.index(), head);
            assert_eq!(len, 8);
            completion.recycle();
            let value = u64::from_le_bytes(buffers[index][..8].try_into().unwrap());
            assert_eq!(value, sequence, "payload corrupted across the u16 wrap");
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
                    .add(used_elem_id_off::<SIZE>(slot))
                    .cast::<u32>()
                    .write_volatile(0xDEAD_BEEF);
                region_ptr
                    .add(used_elem_len_off::<SIZE>(slot))
                    .cast::<u32>()
                    .write_volatile(0);
            }
            fence(Ordering::Release);
            region_ptr
                .add(used_area_off::<SIZE>() + 2)
                .cast::<u16>()
                .write_volatile(60_000);
        }
        assert!(fx.queue.poll().is_none());
        assert_eq!(
            fx.queue.device_faults().completion_out_of_range,
            SIZE as u64
        );
    }

    #[test]
    fn a_drain_loop_terminates_against_a_device_replaying_valid_completions() {
        // The livelock this closes: accepting any in-range id would let a
        // device republish one valid id while advancing its used index, and
        // `while let Some(..) = poll()` would never end.
        let mut fx = Fixture::new();
        let head = u32::from(fx.queue.add_writable(0x1000, 64).unwrap());
        fx.device.complete(head, 64);

        let mut handed_out = 0usize;
        let mut guard = 0usize;
        // The completion is deliberately dropped rather than recycled, so the
        // descriptor cannot return to the posted state and re-arm the loop
        // from this side.
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
        // The out-of-bounds write this closes: a free list chained through
        // each descriptor's shared `next` field would let a device that
        // rewrote it own `free_head`, and the next `add` would write a
        // descriptor at `free_head * 16` — anywhere in a u16, far outside
        // the region.
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
            let index = fx
                .queue
                .add_writable(0x1000, BUF as u32)
                .expect("a descriptor is free") as usize;
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
                .add(used_elem_id_off::<N>(slot))
                .cast::<u32>()
                .write_volatile(head as u32);
            region
                .add(used_elem_len_off::<N>(slot))
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

        /// Random add/chain/complete/poll/recycle sequences, with the device
        /// completing requests in and out of posting order, must never panic,
        /// never hand out a descriptor that is already in flight, and conserve
        /// the descriptor count: `free_count` equals the queue size minus every
        /// descriptor currently posted, completed-but-unpolled, or
        /// polled-but-stranded, and returns to full once all are recycled.
        /// Chains make that a sum over chain lengths rather than a count of
        /// heads, and add the invariant that a chain neither loses nor gains a
        /// link between its publication and its release.
        #[test]
        fn split_virtqueue_accounting_holds_under_random_operations(
            ops in prop::collection::vec((0u8..5, any::<u16>()), 0..200),
        ) {
            const N: usize = 8;
            let region = MappedRegion::zeroed();
            let region_ptr = region.base();
            // SAFETY: `MappedRegion` is 16-byte-aligned, zeroed, larger than the queue layout, and live until its `Drop` — `SplitVirtqueue::new`'s contract.
            let mut queue = unsafe { SplitVirtqueue::<N>::new(region_ptr) };

            // Each entry is a request: its head, and how many descriptors the
            // chain behind that head is supposed to hold.
            let mut outstanding: Vec<(u16, usize)> = Vec::new(); // posted, device not done
            let mut completed: VecDeque<(u16, usize)> = VecDeque::new(); // device done, unpolled
            let mut stranded: Vec<(u16, usize)> = Vec::new(); // polled, completion dropped
            let mut used_idx: u16 = 0;

            let check_invariants =
                |q: &SplitVirtqueue<N>,
                 outstanding: &[(u16, usize)],
                 completed: &VecDeque<(u16, usize)>,
                 stranded: &[(u16, usize)]|
                 -> Result<(), TestCaseError> {
                    // Only requests the device has not completed are posted.
                    prop_assert_eq!(q.posted_count(), outstanding.len() + completed.len());
                    // A descriptor is in exactly one state at a time, counting
                    // the links a head holds and not only the head itself.
                    let mut seen = [false; N];
                    let mut allocated = 0usize;
                    for (head, length) in outstanding
                        .iter()
                        .chain(completed.iter())
                        .chain(stranded.iter())
                    {
                        let chain = chain_indices(q, *head);
                        prop_assert_eq!(
                            chain.len(), *length,
                            "chain {} lost or gained a link", head
                        );
                        for index in chain {
                            let i = index as usize;
                            prop_assert!(!seen[i], "descriptor {} held in two states", i);
                            seen[i] = true;
                            allocated += 1;
                        }
                    }
                    prop_assert_eq!(q.free_count(), N - allocated);
                    Ok(())
                };

            for (action, sel) in ops {
                match action {
                    0 => {
                        if queue.free_count() > 0 {
                            let head = queue.add_writable(0x1000, 64).unwrap();
                            outstanding.push((head, 1));
                        }
                    }
                    // Two to four segments, so links exist and the
                    // all-or-nothing refusal is reached from both sides.
                    1 => {
                        let want = 2 + (sel as usize % 3);
                        let segments: Vec<Segment> = (0..want)
                            .map(|i| Segment {
                                paddr: 0x4000 + i as u64,
                                len: 64,
                                device_writable: i % 2 == 0,
                            })
                            .collect();
                        match queue.add_chain(&segments) {
                            Some(head) => outstanding.push((head, want)),
                            None => prop_assert!(
                                want > queue.free_count(),
                                "a chain that fits was refused"
                            ),
                        }
                    }
                    2 => {
                        if !outstanding.is_empty() {
                            let i = (sel as usize) % outstanding.len();
                            let request = outstanding.remove(i);
                            device_complete(region_ptr, &mut used_idx, request.0);
                            completed.push_back(request);
                        }
                    }
                    // Poll and recycle at once: a completion is the queue's
                    // exclusive borrow, so it cannot be parked and surrendered
                    // later — which is the property under test elsewhere.
                    3 => match queue.poll() {
                        Some((got, _)) => {
                            let expected = completed.pop_front();
                            prop_assert_eq!(Some(got.index()), expected.map(|(head, _)| head));
                            got.recycle();
                        }
                        None => prop_assert!(completed.is_empty()),
                    },
                    // Poll and drop: the chain stays reaped and out of the free
                    // list for good, which is the other terminal state a
                    // completion has.
                    _ => match queue.poll() {
                        Some((got, _)) => {
                            let head = got.index();
                            let expected = completed.pop_front();
                            prop_assert_eq!(Some(head), expected.map(|(head, _)| head));
                            drop(got);
                            stranded.push(expected.expect("a completion was pending"));
                        }
                        None => prop_assert!(completed.is_empty()),
                    },
                }
                check_invariants(&queue, &outstanding, &completed, &stranded)?;
            }

            // Drain everything and confirm the free list is whole but for the
            // descriptors deliberately stranded above.
            while let Some(request) = outstanding.pop() {
                device_complete(region_ptr, &mut used_idx, request.0);
                completed.push_back(request);
            }
            while let Some((got, _)) = queue.poll() {
                got.recycle();
            }
            let held: usize = stranded.iter().map(|(_, length)| length).sum();
            prop_assert_eq!(queue.free_count(), N - held);
            prop_assert_eq!(queue.posted_count(), 0);
            // Every completion in this run named a posted descriptor exactly
            // once, so a fault here would mean the queue refused a legitimate
            // completion.
            prop_assert_eq!(queue.device_faults(), DeviceFaults::default());
        }

        /// Arbitrary device bytes across the **whole** region — descriptor
        /// table, driver ring and device ring alike, all of which the device
        /// can write: `poll` must terminate, never name a descriptor outside
        /// the table, never hand out a descriptor that was not published as a
        /// chain head, never hand out one twice, never hand out more
        /// completions than were posted, never report more bytes than were
        /// programmed, and count every over-report it clamped; and the free
        /// list must still be intact enough to re-post afterwards.
        ///
        /// Chains are posted before the scribble because they are what a
        /// rewritten `next` field would steer: the links this driver frees a
        /// chain by are its own, so no arrangement of the region can make a
        /// completion release a descriptor the device chose.
        #[test]
        fn poll_survives_an_arbitrary_used_ring(
            chains in prop::collection::vec(1usize..=3, 0..4),
            posts in 0usize..=8,
            bytes in prop::collection::vec(any::<u8>(), 0..256),
            used_idx in any::<u16>(),
        ) {
            const N: usize = 8;
            const POSTED_LEN: u32 = 512;
            let region = MappedRegion::zeroed();
            let ptr = region.base();
            // SAFETY: `MappedRegion` is 16-byte-aligned, zeroed, larger than the queue layout, and live until its `Drop` — `SplitVirtqueue::new`'s contract.
            let mut queue = unsafe { SplitVirtqueue::<N>::new(ptr) };

            // What each published head is allowed to report back, which is the
            // clamp the drain below holds every completion to.
            let mut writable_of = std::collections::HashMap::new();
            for want in &chains {
                let segments: Vec<Segment> = (0..*want)
                    .map(|i| Segment {
                        paddr: 0x1000,
                        len: POSTED_LEN,
                        device_writable: i % 2 == 0,
                    })
                    .collect();
                if let Some(head) = queue.add_chain(&segments) {
                    let writable: u32 = segments
                        .iter()
                        .filter(|segment| segment.device_writable)
                        .map(|segment| segment.len)
                        .sum();
                    writable_of.insert(head, writable);
                }
            }
            for _ in 0..posts {
                let Some(head) = queue.add_writable(0x1000, POSTED_LEN) else {
                    break;
                };
                writable_of.insert(head, POSTED_LEN);
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
            let mut released = [false; N];
            while let Some((completion, len)) = queue.poll() {
                let head = completion.index();
                prop_assert!((head as usize) < N);
                let writable = *writable_of.get(&head).ok_or_else(|| TestCaseError::fail(
                    "a completion named a descriptor that was never published as a chain head"
                ))?;
                prop_assert!(len <= writable, "a device length escaped the clamp");
                prop_assert!(!released[head as usize], "head {} was freed twice", head);
                released[head as usize] = true;
                handed_out += 1;
                guard += 1;
                prop_assert!(guard <= N, "the drain loop outran the posted requests");
                completion.recycle();
            }
            prop_assert!(handed_out <= posted);
            prop_assert!(queue.free_count() <= N);
            // Every clamp is counted: an over-report cannot be absorbed
            // silently, so the tally bounds the completions handed out.
            prop_assert!(
                queue.device_faults().completion_length_over_reported <= handed_out as u64
            );

            // The free list is driver-private, so the scribble cannot have
            // reached it: every descriptor it still holds allocates in range
            // and exactly once.
            let mut seen = [false; N];
            while let Some(head) = queue.add_writable(0x2000, POSTED_LEN) {
                let index = head as usize;
                prop_assert!(index < N);
                prop_assert!(!seen[index], "descriptor {} handed out twice", index);
                seen[index] = true;
            }
            prop_assert_eq!(queue.free_count(), 0);
        }
    }
}
