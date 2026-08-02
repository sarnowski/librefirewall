use proptest::prelude::*;
use std::{vec, vec::Vec};

use super::*;

/// A host stand-in for the mapped staging region: a page-aligned allocation of
/// exactly the region's size, so a copy that ran off either end would be caught
/// by the allocator rather than by an assertion this file wrote.
struct Backing {
    bytes: Vec<u8>,
}

impl Backing {
    fn new() -> Self {
        Self {
            bytes: vec![0u8; BLK_IO_REGION_SIZE],
        }
    }

    /// Attach over this allocation at a plausible physical base.
    ///
    /// The base is a fixed page-aligned number rather than the allocation's own
    /// address: `sector_paddr` answers what a *device* would be told, and the
    /// two have nothing to do with each other on the host.
    fn attach(&mut self) -> IoRegion<'_> {
        // SAFETY: the allocation is `BLK_IO_REGION_SIZE` bytes, lives as long as
        // the borrow this returns, and nothing else touches it.
        unsafe { IoRegion::attach(self.bytes.as_mut_ptr(), BASE) }.expect("a usable base")
    }
}

const BASE: u64 = 0x3108_C000;

#[test]
fn the_window_is_a_whole_number_of_sectors_and_pages() {
    assert_eq!(IO_SECTORS, 512);
    assert_eq!(IO_SECTORS * SECTOR_SIZE, BLK_IO_REGION_SIZE);
}

#[test]
fn a_sector_past_the_window_cannot_be_named() {
    assert_eq!(IoSector::new(IO_SECTORS), None);
    assert_eq!(IoSector::new(usize::MAX), None);
    assert_eq!(
        IoSector::new(IO_SECTORS - 1).map(IoSector::get),
        Some(IO_SECTORS - 1)
    );
}

#[test]
fn the_two_named_sectors_are_the_first_two_and_are_distinct() {
    assert_eq!(IoSector::FIRST.get(), 0);
    assert_eq!(IoSector::SECOND.get(), 1);
    assert_ne!(IoSector::FIRST, IoSector::SECOND);
}

#[test]
fn an_unusable_base_is_refused_before_the_region_is_touched() {
    let mut backing = Backing::new();
    let base = backing.bytes.as_mut_ptr();
    for paddr in [0, 0x1_0000_0001, u64::MAX - 1] {
        // SAFETY: the allocation outlives the call and is `BLK_IO_REGION_SIZE`
        // bytes; the base under test is the *claimed physical* address, which
        // the constructor refuses without dereferencing anything.
        let refused = unsafe { IoRegion::attach(base, paddr) };
        assert_eq!(refused.err(), Some(IoRegionUnusable { paddr }));
    }
}

#[test]
fn a_base_whose_region_end_would_wrap_is_refused() {
    let mut backing = Backing::new();
    let paddr = u64::MAX - BLK_IO_REGION_SIZE as u64 + PAGE_SIZE as u64;
    // SAFETY: as above.
    let refused = unsafe { IoRegion::attach(backing.bytes.as_mut_ptr(), paddr) };
    assert_eq!(refused.err(), Some(IoRegionUnusable { paddr }));
}

#[test]
fn every_sector_address_lies_inside_the_region() {
    let mut backing = Backing::new();
    let io = backing.attach();
    for index in 0..IO_SECTORS {
        let sector = IoSector::new(index).expect("in range");
        let paddr = io.sector_paddr(sector);
        assert!(paddr >= BASE);
        assert!(paddr + SECTOR_SIZE as u64 <= BASE + BLK_IO_REGION_SIZE as u64);
        assert_eq!(paddr, BASE + (index * SECTOR_SIZE) as u64);
    }
}

#[test]
fn a_sector_round_trips_and_disturbs_no_other() {
    let mut backing = Backing::new();
    let mut io = backing.attach();
    let written = [0xA5u8; SECTOR_SIZE];
    io.put(IoSector::SECOND, &written);

    let mut read_back = [0u8; SECTOR_SIZE];
    io.take(IoSector::SECOND, &mut read_back);
    assert_eq!(read_back, written);

    let mut neighbour = [0xFFu8; SECTOR_SIZE];
    io.take(IoSector::FIRST, &mut neighbour);
    assert_eq!(neighbour, [0u8; SECTOR_SIZE]);
    let last = IoSector::new(IO_SECTORS - 1).expect("in range");
    io.take(last, &mut neighbour);
    assert_eq!(neighbour, [0u8; SECTOR_SIZE]);
}

proptest! {
    /// A put at any sector lands at exactly that sector's offset in the backing
    /// bytes, and nowhere else — the property the whole type exists for.
    #[test]
    fn a_put_lands_at_its_own_offset_and_only_there(
        index in 0usize..IO_SECTORS,
        fill in any::<u8>(),
    ) {
        prop_assume!(fill != 0);
        let mut backing = Backing::new();
        {
            let mut io = backing.attach();
            let sector = IoSector::new(index).expect("in range");
            io.put(sector, &[fill; SECTOR_SIZE]);
        }
        let start = index * SECTOR_SIZE;
        for (at, byte) in backing.bytes.iter().enumerate() {
            let expected = if (start..start + SECTOR_SIZE).contains(&at) { fill } else { 0 };
            prop_assert_eq!(*byte, expected, "byte {}", at);
        }
    }

    /// Whatever the device left in a sector comes back byte for byte, however
    /// hostile it is: this layer measures nothing and interprets nothing.
    #[test]
    fn a_take_answers_the_bytes_the_device_left(
        index in 0usize..IO_SECTORS,
        payload in proptest::collection::vec(any::<u8>(), SECTOR_SIZE),
    ) {
        let mut backing = Backing::new();
        let start = index * SECTOR_SIZE;
        backing.bytes[start..start + SECTOR_SIZE].copy_from_slice(&payload);
        let io = backing.attach();
        let mut out = [0u8; SECTOR_SIZE];
        io.take(IoSector::new(index).expect("in range"), &mut out);
        prop_assert_eq!(&out[..], &payload[..]);
    }
}

#[test]
fn the_staging_slice_is_the_whole_window_and_what_a_sector_addresses() {
    // The two views of the region must agree, or a recording composed through
    // the slice would be DMA'd from somewhere else.
    let mut backing = Backing::new();
    let mut region = backing.attach();
    assert_eq!(region.staging().len(), BLK_IO_REGION_SIZE);

    let at = IoSector::new(7).expect("the window has an eighth sector");
    let offset = at.get() * SECTOR_SIZE;
    if let Some(slot) = region.staging().get_mut(offset) {
        *slot = 0xA5;
    }
    let mut read = [0u8; SECTOR_SIZE];
    region.take(at, &mut read);
    assert_eq!(read[0], 0xA5);
    assert_eq!(region.sector_paddr(at), BASE + offset as u64);
}

#[test]
fn a_sector_placed_by_put_is_visible_through_the_staging_slice() {
    let mut backing = Backing::new();
    let mut region = backing.attach();
    let sector = [0x5Au8; SECTOR_SIZE];
    region.put(IoSector::SECOND, &sector);
    let offset = IoSector::SECOND.get() * SECTOR_SIZE;
    assert_eq!(
        region.staging().get(offset..offset + SECTOR_SIZE),
        Some(&sector[..])
    );
}
