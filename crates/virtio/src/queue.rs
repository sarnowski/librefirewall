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
//! exactly where a real device observes or produces the indices. Only
//! single-descriptor buffers are used (virtio-net needs no chaining per
//! buffer), so the free list is a simple index stack and no `NEXT` chain is
//! walked.

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token(pub u16);

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
        loop {
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
            // (double-completion, leak accounting) is the driver PD's job — see
            // docs/virtio-net-driver.md.
            if (id as usize) < SIZE {
                return Some((Token(id as u16), len));
            }
        }
    }

    /// Return a reaped descriptor to the free list, making it available again.
    pub fn recycle(&mut self, token: Token) {
        let head = token.0;
        // SAFETY: `head` was a valid descriptor index handed out by `add`.
        unsafe { self.write_u16(desc_next_off(head), self.free_head) };
        self.free_head = head;
        self.num_free += 1;
    }

    // Volatile field accessors. Every offset is derived from a validated index,
    // so the effective pointer is in-bounds and aligned for its type.

    unsafe fn read_u16(&self, off: usize) -> u16 {
        unsafe { self.region.add(off).cast::<u16>().read_volatile() }
    }
    unsafe fn write_u16(&self, off: usize, value: u16) {
        unsafe { self.region.add(off).cast::<u16>().write_volatile(value) }
    }
    unsafe fn read_u32(&self, off: usize) -> u32 {
        unsafe { self.region.add(off).cast::<u32>().read_volatile() }
    }
    unsafe fn write_u32(&self, off: usize, value: u32) {
        unsafe { self.region.add(off).cast::<u32>().write_volatile(value) }
    }
    unsafe fn write_u64(&self, off: usize, value: u64) {
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
            let avail_idx = unsafe { self.region.add(SIZE * 16 + 2).cast::<u16>().read_volatile() };
            if avail_idx == self.last_avail {
                return false;
            }
            fence(Ordering::Acquire);
            let slot = (self.last_avail as usize) & (SIZE - 1);
            let head = unsafe {
                self.region
                    .add(avail_ring_off::<SIZE>(slot as u16))
                    .cast::<u16>()
                    .read_volatile()
            };
            self.last_avail = self.last_avail.wrapping_add(1);

            let addr = unsafe {
                self.region
                    .add(desc_addr_off(head))
                    .cast::<u64>()
                    .read_volatile()
            };
            let len = unsafe {
                self.region
                    .add(desc_len_off(head))
                    .cast::<u32>()
                    .read_volatile()
            } as usize;
            let flags = unsafe {
                self.region
                    .add(desc_flags_off(head))
                    .cast::<u16>()
                    .read_volatile()
            };
            assert_eq!(flags & VIRTQ_DESC_F_WRITE, VIRTQ_DESC_F_WRITE);

            let n = payload.len().min(len);
            let buffer = addr as *mut u8;
            unsafe { core::ptr::copy_nonoverlapping(payload.as_ptr(), buffer, n) };

            let uslot = (self.used_idx as usize) & (SIZE - 1);
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
        let mut queue = unsafe { SplitVirtqueue::<SIZE>::new(region_ptr) };
        let mut buffer = Box::new([0u8; BUF]);
        let token = queue
            .add_writable(buffer.as_mut_ptr() as u64, BUF as u32)
            .unwrap();

        // A buggy or hostile device posts a completion whose id is far outside
        // the descriptor table, followed by a valid completion for the real
        // descriptor. The bogus id must never reach recycle (which would write
        // out of bounds).
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
}
