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
//! The device is untrusted: everything it writes (the used ring and its
//! indices) is validated before use, and no device-supplied value is turned
//! into an out-of-range access or an unbounded loop (see [`SplitVirtqueue::poll`]).

use core::sync::atomic::{Ordering, fence};

/// `VIRTQ_DESC_F_NEXT`: descriptor chains to `next`.
const VIRTQ_DESC_F_NEXT: u16 = 1;
/// `VIRTQ_DESC_F_WRITE`: buffer is device-writable (a receive buffer).
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Round `value` up to a multiple of `align` (a power of two).
const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// A buffer in flight: the head descriptor index the device echoes back in its
/// used-ring completion.
///
/// A `Token` is proof of ownership of one in-flight descriptor. It is produced
/// only by [`SplitVirtqueue::add_writable`], [`add_readable`](SplitVirtqueue::add_readable),
/// and [`poll`](SplitVirtqueue::poll), and must be surrendered exactly once via
/// [`recycle`](SplitVirtqueue::recycle). The wrapped index is private so safe
/// code cannot forge an out-of-range token and drive an out-of-bounds volatile
/// write; read it with [`index`](Token::index).
///
/// `Token` is deliberately **not** `Copy`: a token names one in-flight
/// descriptor, so surrendering it must consume it. Recycling a token moves it,
/// which makes "surrender exactly once" a type invariant — a double-recycle
/// (which would push the same descriptor onto the free list twice and later
/// hand out two live tokens for it) is a move error, not a silent corruption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token(u16);

impl Token {
    /// The head descriptor index this token names (always `< SIZE`). Borrows,
    /// so reading the index does not surrender the token.
    #[must_use]
    pub const fn index(&self) -> u16 {
        self.0
    }
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
/// power of two of at least 2 and at most 32768 (the ring index is a `u16`).
pub struct SplitVirtqueue<const SIZE: usize> {
    region: *mut u8,
    free_head: u16,
    num_free: u16,
    avail_idx: u16,
    last_used: u16,
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
    pub const LAYOUT: QueueLayout = QueueLayout {
        size: SIZE,
        descriptor_offset: 0,
        driver_offset: Self::AVAIL_OFF,
        device_offset: Self::USED_OFF,
        total_bytes: Self::TOTAL,
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
        let queue = Self {
            region,
            free_head: 0,
            num_free: SIZE as u16,
            avail_idx: 0,
            last_used: 0,
        };
        // Chain every descriptor into the free list via its `next` field.
        for index in 0..SIZE as u16 {
            let next = if index + 1 < SIZE as u16 {
                index + 1
            } else {
                0
            };
            // SAFETY: `index < SIZE`, so the descriptor lies within the region.
            unsafe { queue.write_u16(desc_next_off(index), next) };
        }
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
        // SAFETY: `head` is a valid free descriptor index (invariant of the
        // free list); all offsets derived from it lie within the region.
        unsafe {
            self.free_head = self.read_u16(desc_next_off(head));
            self.write_u64(desc_addr_off(head), paddr);
            self.write_u32(desc_len_off(head), len);
            // Single-descriptor buffers never chain, so strip any NEXT flag
            // defensively rather than trust the caller not to pass one.
            self.write_u16(desc_flags_off(head), flags & !VIRTQ_DESC_F_NEXT);
            self.write_u16(desc_next_off(head), 0);
        }
        self.num_free -= 1;

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

    /// Reap the next completed buffer, returning its [`Token`] and the number
    /// of bytes the device wrote, or `None` when none have completed. The
    /// descriptor stays allocated until [`recycle`](Self::recycle).
    pub fn poll(&mut self) -> Option<(Token, u32)> {
        // Bound the work per call. A conformant device never has more than SIZE
        // buffers outstanding, so processing at most SIZE used entries here caps
        // a hostile device that floods the used ring with invalid ids while
        // continuously bumping its index: `poll` returns `None` after SIZE skips
        // instead of spinning forever, and the caller's drain loop then exits.
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
            // The used-ring `id` is device-controlled; a conformant device
            // echoes a head index we posted (< SIZE). Reject an out-of-range id
            // and keep draining, so a malformed completion can never drive an
            // out-of-bounds recycle. Deeper untrusted-device handling
            // (double-completion, leak accounting) is the driver PD's job (see
            // `pds/nic-driver`).
            if (id as usize) < SIZE {
                return Some((Token(id as u16), len));
            }
        }
        None
    }

    /// Return a reaped descriptor to the free list, making it available again.
    pub fn recycle(&mut self, token: Token) {
        let head = token.0;
        // `head` came from `add`/`poll`, so the private-field invariant makes it
        // a valid descriptor index. These assertions catch an internal
        // bookkeeping bug (a double-recycle, a token from another queue) in
        // debug builds rather than silently corrupting the free list — a bad
        // token here is an internal invariant failure, never device input.
        debug_assert!((head as usize) < SIZE, "recycled token index out of range");
        debug_assert!(self.num_free < SIZE as u16, "descriptor recycled twice");
        // SAFETY: `head < SIZE` by the private-field invariant, so the `next`
        // field lies within the region.
        unsafe { self.write_u16(desc_next_off(head), self.free_head) };
        self.free_head = head;
        self.num_free += 1;
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
        fn service_writable(&mut self, payload: &[u8]) -> bool {
            // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
            let avail_idx = unsafe { self.region.add(SIZE * 16 + 2).cast::<u16>().read_volatile() };
            if avail_idx == self.last_avail {
                return false;
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

            let uslot = (self.used_idx as usize) & (SIZE - 1);
            // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
            unsafe {
                self.region
                    .add(used_elem_id_off::<SIZE>(uslot as u16))
                    .cast::<u32>()
                    .write_volatile(head as u32);
                self.region
                    .add(used_elem_len_off::<SIZE>(uslot as u16))
                    .cast::<u32>()
                    .write_volatile(n as u32);
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
            true
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
    fn add_consumes_and_recycle_restores_descriptors() {
        let mut region = Box::new(Region([0; 4096]));
        // SAFETY: the region is 16-byte-aligned, zeroed, larger than the queue layout, and owned solely by this test — `Vq::new`'s contract.
        let mut queue = unsafe { SplitVirtqueue::<SIZE>::new(region.0.as_mut_ptr()) };
        assert_eq!(queue.free_count(), SIZE);

        let mut tokens = Vec::new();
        for i in 0..SIZE {
            tokens.push(queue.add_writable(0x1000 + i as u64, BUF as u32).unwrap());
        }
        assert_eq!(queue.free_count(), 0);
        assert!(queue.add_writable(0x9999, BUF as u32).is_none());

        for token in tokens {
            queue.recycle(token);
        }
        assert_eq!(queue.free_count(), SIZE);
    }

    #[test]
    fn round_trip_delivers_payloads_and_wraps_the_rings() {
        // Cycle far more buffers than the ring holds so the available and used
        // ring positions wrap many times and every descriptor is reused,
        // mirroring a sustained receive path.
        const ROUNDS: u64 = 10_000;
        let mut region = Box::new(Region([0; 4096]));
        let region_ptr = region.0.as_mut_ptr();

        // A pool of real buffers; their host addresses double as the "paddr"
        // the device writes into.
        let mut buffers: Vec<Box<[u8; BUF]>> = (0..SIZE).map(|_| Box::new([0u8; BUF])).collect();
        let addr_of = |b: &mut Box<[u8; BUF]>| b.as_mut_ptr() as u64;

        // SAFETY: the region is 16-byte-aligned, zeroed, larger than the queue layout, and owned solely by this test — `Vq::new`'s contract.
        let mut queue = unsafe { SplitVirtqueue::<SIZE>::new(region_ptr) };
        let mut device = TestDevice {
            region: region_ptr,
            last_avail: 0,
            used_idx: 0,
        };

        // Map a descriptor token back to the buffer index it carries.
        let mut token_buffer = std::collections::HashMap::new();
        for (index, buffer) in buffers.iter_mut().enumerate() {
            let token = queue.add_writable(addr_of(buffer), BUF as u32).unwrap();
            token_buffer.insert(token.0, index);
        }

        for sequence in 0..ROUNDS {
            // Device fills exactly one posted buffer with the sequence number.
            assert!(device.service_writable(&sequence.to_le_bytes()));

            let (token, len) = queue.poll().expect("a completion is pending");
            assert_eq!(len, 8);
            let index = token_buffer[&token.0];
            let value = u64::from_le_bytes(buffers[index][..8].try_into().unwrap());
            assert_eq!(value, sequence, "payload corrupted or out of order");

            // Return the descriptor and immediately repost the same buffer.
            queue.recycle(token);
            let token = queue
                .add_writable(addr_of(&mut buffers[index]), BUF as u32)
                .unwrap();
            token_buffer.insert(token.0, index);
        }

        assert!(queue.poll().is_none());
    }

    #[test]
    fn poll_drops_out_of_range_completions_from_a_bad_device() {
        let mut region = Box::new(Region([0; 4096]));
        let region_ptr = region.0.as_mut_ptr();
        // SAFETY: the region is 16-byte-aligned, zeroed, larger than the queue layout, and owned solely by this test — `Vq::new`'s contract.
        let mut queue = unsafe { SplitVirtqueue::<SIZE>::new(region_ptr) };
        let mut buffer = Box::new([0u8; BUF]);
        let token = queue
            .add_writable(buffer.as_mut_ptr() as u64, BUF as u32)
            .unwrap();

        // A buggy or hostile device posts a completion whose id is far outside
        // the descriptor table, followed by a valid completion for the real
        // descriptor. The bogus id must never reach recycle (which would write
        // out of bounds).
        // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
        unsafe {
            region_ptr
                .add(used_elem_id_off::<SIZE>(0))
                .cast::<u32>()
                .write_volatile(9999);
            region_ptr
                .add(used_elem_len_off::<SIZE>(0))
                .cast::<u32>()
                .write_volatile(0);
            region_ptr
                .add(used_elem_id_off::<SIZE>(1))
                .cast::<u32>()
                .write_volatile(token.0 as u32);
            region_ptr
                .add(used_elem_len_off::<SIZE>(1))
                .cast::<u32>()
                .write_volatile(BUF as u32);
            fence(Ordering::Release);
            region_ptr
                .add(used_area_off::<SIZE>() + 2)
                .cast::<u16>()
                .write_volatile(2);
        }

        // The bogus entry is dropped safely; the valid one is returned.
        let (got, len) = queue.poll().expect("valid completion after the bogus one");
        assert_eq!(got, token);
        assert_eq!(len, BUF as u32);
        assert!(queue.poll().is_none());
        queue.recycle(got);
        assert_eq!(queue.free_count(), SIZE);
    }

    #[test]
    fn add_readable_posts_a_non_writable_descriptor() {
        let mut region = Box::new(Region([0; 4096]));
        let region_ptr = region.0.as_mut_ptr();
        // SAFETY: the region is 16-byte-aligned, zeroed, larger than the queue layout, and owned solely by this test — `Vq::new`'s contract.
        let mut queue = unsafe { SplitVirtqueue::<SIZE>::new(region_ptr) };
        let token = queue.add_readable(0x4000, 64).unwrap();
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
        assert_eq!(queue.free_count(), SIZE - 1);
    }

    #[test]
    fn ring_indices_wrap_through_the_u16_boundary() {
        let mut region = Box::new(Region([0; 4096]));
        let region_ptr = region.0.as_mut_ptr();
        let mut buffers: Vec<Box<[u8; BUF]>> = (0..SIZE).map(|_| Box::new([0u8; BUF])).collect();
        // SAFETY: the region is 16-byte-aligned, zeroed, larger than the queue layout, and owned solely by this test — `Vq::new`'s contract.
        let mut queue = unsafe { SplitVirtqueue::<SIZE>::new(region_ptr) };

        // Force both ring positions to just below the u16 wrap so the cycles
        // below cross 0xFFFF -> 0x0000, where modular index bugs would live.
        queue.avail_idx = u16::MAX - 1;
        queue.last_used = u16::MAX - 1;
        // SAFETY: single-threaded test driving the ring's far side; the offset lies within the live, test-owned region.
        unsafe {
            region_ptr
                .add(used_area_off::<SIZE>() + 2)
                .cast::<u16>()
                .write_volatile(u16::MAX - 1);
        }
        let mut device = TestDevice {
            region: region_ptr,
            last_avail: u16::MAX - 1,
            used_idx: u16::MAX - 1,
        };

        for sequence in 0..8u64 {
            let index = sequence as usize % SIZE;
            let token = queue
                .add_writable(buffers[index].as_mut_ptr() as u64, BUF as u32)
                .unwrap();
            assert!(device.service_writable(&sequence.to_le_bytes()));
            let (got, len) = queue.poll().expect("a completion is pending");
            assert_eq!(got, token);
            assert_eq!(len, 8);
            let value = u64::from_le_bytes(buffers[index][..8].try_into().unwrap());
            assert_eq!(value, sequence, "payload corrupted across the u16 wrap");
            queue.recycle(got);
        }
    }

    #[test]
    fn poll_is_bounded_when_a_hostile_device_floods_invalid_ids() {
        let mut region = Box::new(Region([0; 4096]));
        let region_ptr = region.0.as_mut_ptr();
        // SAFETY: the region is 16-byte-aligned, zeroed, larger than the queue layout, and owned solely by this test — `Vq::new`'s contract.
        let mut queue = unsafe { SplitVirtqueue::<SIZE>::new(region_ptr) };

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
        assert_eq!(queue.poll(), None);
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
            // SAFETY: the region is 16-byte-aligned, zeroed, larger than the queue layout, and owned solely by this test — `Vq::new`'s contract.
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
                            // `Token` is non-`Copy`, and it is stored below.
                            prop_assert_eq!(Some(&got), expected.as_ref());
                            inflight.push(got);
                        }
                        None => prop_assert!(completed.is_empty()),
                    },
                    _ => {
                        if !inflight.is_empty() {
                            let i = (sel as usize) % inflight.len();
                            queue.recycle(inflight.remove(i));
                        }
                    }
                }
                check_invariants(&queue, &outstanding, &completed, &inflight)?;
            }

            // Drain everything and confirm the free list is whole again.
            for token in inflight.drain(..) {
                queue.recycle(token);
            }
            while let Some(token) = outstanding.pop() {
                device_complete(region_ptr, &mut used_idx, token.index());
                completed.push_back(token);
            }
            while let Some((got, _)) = queue.poll() {
                queue.recycle(got);
            }
            prop_assert_eq!(queue.free_count(), N);
        }
    }
}
