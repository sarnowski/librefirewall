use core::cell::RefCell;
use proptest::prelude::*;
use std::{boxed::Box, vec::Vec};

use super::*;
use crate::io::IO_SECTORS;
use crate::request::VIRTIO_BLK_S_OK;
use crate::{BLK_IO_REGION_SIZE, BlkVirtqueue, DMA_REGION_SIZE};

/// Where the fixture's two regions pretend to sit. Far apart and far from
/// zero, so a data address computed against the wrong base is a wild number
/// rather than an offset that happens to land somewhere plausible.
const DMA_PADDR: u64 = 0x4000_0000;
const IO_PADDR: u64 = 0x6000_0000;
const CAPACITY: u64 = 4096;

const DESC_STRIDE: usize = 16;
const VIRTQ_DESC_F_NEXT: u16 = 1;

/// How the stand-in device behaves when the doorbell rings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Conduct {
    /// Answer the request exactly as a conforming device would: transfer the
    /// bytes, write `VIRTIO_BLK_S_OK`, report the right count.
    Conforming,
    /// Answer with a status byte of the device's choosing and no transfer.
    Status(u8),
    /// Answer `Ok` but report fewer bytes than the request asked for.
    Short(u32),
    /// Publish a completion for a descriptor head nobody posted.
    Forge { head: u32 },
    /// Say nothing at all.
    Silent,
    /// Answer the probe as a conforming device would and then fail the witness
    /// with `status`. A medium that reads and does not commit is the failure a
    /// bring-up handshake cannot distinguish, so it is the one the proof exists
    /// to separate — and it is the only way the witness step's own error arms
    /// are reachable at all.
    FailsTheWitness(u8),
}

#[repr(C, align(4096))]
struct DmaPage([u8; DMA_REGION_SIZE]);

#[repr(C, align(4096))]
struct IoPage([u8; BLK_IO_REGION_SIZE]);

/// One heap region reachable only through the raw pointer both sides share, on
/// exactly the terms `request`'s fixture states: forming a reference into it
/// while the driver writes through the pointer would invalidate the pointer's
/// tag, so no reference is ever formed.
struct Mapped<T> {
    page: *mut T,
}

impl<T> Mapped<T> {
    fn new(page: T) -> Self {
        Self {
            page: Box::into_raw(Box::new(page)),
        }
    }

    fn base(&self) -> *mut u8 {
        self.page.cast::<u8>()
    }
}

impl<T> Drop for Mapped<T> {
    fn drop(&mut self) {
        // SAFETY: `page` came from `Box::into_raw` in `new`, is never replaced,
        // and no other owner exists, so this reconstructs that `Box` once.
        drop(unsafe { Box::from_raw(self.page) });
    }
}

/// The far side of the virtqueue, plus a medium.
///
/// It reads the chain the driver published, moves bytes between the medium and
/// the physical address the data descriptor names — translating that address
/// back through the staging region's pretend base, which is what makes a driver
/// that computed it wrong fail here — and publishes the completion.
struct Device {
    dma: *mut u8,
    io: *mut u8,
    /// The medium: sector index to contents, sparse so a fixture can seed one
    /// sector without allocating a disk.
    medium: Vec<(u64, [u8; SECTOR_SIZE])>,
    conduct: Conduct,
    last_avail: u16,
    used_idx: u16,
    /// Every chain it saw, as (operation type, sector), for a test asserting on
    /// what the driver actually asked for.
    seen: Vec<(u32, u64)>,
}

/// One descriptor as it stands in the shared table.
#[derive(Clone, Copy)]
struct Descriptor {
    paddr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

impl Device {
    fn descriptor(&self, index: u16) -> Descriptor {
        let base = BlkVirtqueue::LAYOUT.descriptor_offset + index as usize * DESC_STRIDE;
        // SAFETY: single-threaded test driving the ring's far side; a descriptor
        // index below the queue size lies within the live, test-owned region.
        unsafe {
            Descriptor {
                paddr: self.dma.add(base).cast::<u64>().read_volatile(),
                len: self.dma.add(base + 8).cast::<u32>().read_volatile(),
                flags: self.dma.add(base + 12).cast::<u16>().read_volatile(),
                next: self.dma.add(base + 14).cast::<u16>().read_volatile(),
            }
        }
    }

    fn chain(&self, head: u16) -> Vec<Descriptor> {
        let mut chain = Vec::new();
        let mut index = head;
        for _ in 0..crate::QUEUE_SIZE {
            let descriptor = self.descriptor(index);
            chain.push(descriptor);
            if descriptor.flags & VIRTQ_DESC_F_NEXT == 0 {
                return chain;
            }
            index = descriptor.next;
        }
        panic!("the chain from {head} does not terminate");
    }

    fn next_avail(&mut self) -> Option<u16> {
        let driver = BlkVirtqueue::LAYOUT.driver_offset;
        // SAFETY: single-threaded test driving the ring's far side; the driver
        // ring lies within the live, test-owned region.
        let avail_idx = unsafe { self.dma.add(driver + 2).cast::<u16>().read_volatile() };
        if avail_idx == self.last_avail {
            return None;
        }
        let slot = self.last_avail as usize % crate::QUEUE_SIZE;
        // SAFETY: as above, for the entry at a slot reduced modulo the queue size.
        let head = unsafe {
            self.dma
                .add(driver + 4 + slot * 2)
                .cast::<u16>()
                .read_volatile()
        };
        self.last_avail = self.last_avail.wrapping_add(1);
        Some(head)
    }

    fn complete(&mut self, head: u32, len: u32) {
        let used = BlkVirtqueue::LAYOUT.device_offset;
        let slot = self.used_idx as usize % crate::QUEUE_SIZE;
        // SAFETY: single-threaded test driving the ring's far side; the device
        // ring lies within the live, test-owned region and the slot is reduced
        // modulo the queue size.
        unsafe {
            self.dma
                .add(used + 4 + slot * 8)
                .cast::<u32>()
                .write_volatile(head);
            self.dma
                .add(used + 8 + slot * 8)
                .cast::<u32>()
                .write_volatile(len);
            self.used_idx = self.used_idx.wrapping_add(1);
            self.dma
                .add(used + 2)
                .cast::<u16>()
                .write_volatile(self.used_idx);
        }
    }

    /// The staging-region offset a physical address names, asserting it is one
    /// this device was ever meant to reach.
    fn staging_offset(&self, paddr: u64) -> usize {
        assert!(
            (IO_PADDR..IO_PADDR + BLK_IO_REGION_SIZE as u64).contains(&paddr),
            "the driver named {paddr:#x}, which is outside the staging region"
        );
        usize::try_from(paddr - IO_PADDR).expect("inside the region")
    }

    fn read_staging(&self, paddr: u64) -> [u8; SECTOR_SIZE] {
        let offset = self.staging_offset(paddr);
        // SAFETY: `staging_offset` bounded the offset into the live, test-owned
        // staging allocation; `[u8; SECTOR_SIZE]` imposes no alignment.
        unsafe {
            self.io
                .add(offset)
                .cast::<[u8; SECTOR_SIZE]>()
                .read_volatile()
        }
    }

    fn write_staging(&self, paddr: u64, bytes: [u8; SECTOR_SIZE]) {
        let offset = self.staging_offset(paddr);
        // SAFETY: as `read_staging`, in the other direction.
        unsafe {
            self.io
                .add(offset)
                .cast::<[u8; SECTOR_SIZE]>()
                .write_volatile(bytes);
        }
    }

    fn write_status(&self, paddr: u64, value: u8) {
        let offset =
            usize::try_from(paddr - DMA_PADDR).expect("a status byte inside the DMA region");
        // SAFETY: the status byte the driver published lies in the live,
        // test-owned DMA allocation; one `u8` needs no alignment.
        unsafe { self.dma.add(offset).write_volatile(value) };
    }

    fn sector(&self, index: u64) -> [u8; SECTOR_SIZE] {
        self.medium
            .iter()
            .find(|(at, _)| *at == index)
            .map_or([0u8; SECTOR_SIZE], |(_, bytes)| *bytes)
    }

    fn store(&mut self, index: u64, bytes: [u8; SECTOR_SIZE]) {
        if let Some(slot) = self.medium.iter_mut().find(|(at, _)| *at == index) {
            slot.1 = bytes;
        } else {
            self.medium.push((index, bytes));
        }
    }

    /// Service everything the driver made available, per this device's conduct.
    fn service(&mut self) {
        while let Some(head) = self.next_avail() {
            let chain = self.chain(head);
            let header = chain.first().copied().expect("a chain is never empty");
            let status = chain.last().copied().expect("a chain is never empty");
            let (operation, sector) = self.decode_header(header.paddr);
            self.seen.push((operation, sector));

            let conduct = match self.conduct {
                Conduct::FailsTheWitness(status)
                    if operation == crate::request::VIRTIO_BLK_T_OUT =>
                {
                    Conduct::Status(status)
                }
                Conduct::FailsTheWitness(_) => Conduct::Conforming,
                other => other,
            };
            match conduct {
                Conduct::FailsTheWitness(_) => unreachable!("resolved above"),
                Conduct::Silent => return,
                Conduct::Forge { head: forged } => {
                    self.complete(forged, 1);
                    return;
                }
                Conduct::Status(byte) => {
                    self.write_status(status.paddr, byte);
                    self.complete(u32::from(head), 1);
                }
                Conduct::Short(reported) => {
                    self.write_status(status.paddr, VIRTIO_BLK_S_OK);
                    self.complete(u32::from(head), reported);
                }
                Conduct::Conforming => {
                    let data = chain.get(1).copied().expect("a data segment");
                    let moved = self.transfer(operation, sector, data);
                    self.write_status(status.paddr, VIRTIO_BLK_S_OK);
                    self.complete(u32::from(head), moved + 1);
                }
            }
        }
    }

    /// Move the bytes the request names, answering how many were transferred
    /// into device-writable memory.
    fn transfer(&mut self, operation: u32, sector: u64, data: Descriptor) -> u32 {
        assert_eq!(
            data.len, SECTOR_SIZE as u32,
            "the proof asks for one sector"
        );
        match operation {
            crate::request::VIRTIO_BLK_T_IN => {
                let bytes = self.sector(sector);
                self.write_staging(data.paddr, bytes);
                data.len
            }
            crate::request::VIRTIO_BLK_T_OUT => {
                let bytes = self.read_staging(data.paddr);
                self.store(sector, bytes);
                0
            }
            other => panic!("the proof issued an unexpected request type {other}"),
        }
    }

    /// The request type and sector out of the sixteen-byte header the driver
    /// wrote — the device's own view of what it was asked to do.
    fn decode_header(&self, paddr: u64) -> (u32, u64) {
        let offset = usize::try_from(paddr - DMA_PADDR).expect("a header inside the DMA region");
        // SAFETY: the header the driver published lies in the live, test-owned
        // DMA allocation; `[u8; 16]` imposes no alignment.
        let image = unsafe { self.dma.add(offset).cast::<[u8; 16]>().read_volatile() };
        let mut kind = [0u8; 4];
        kind.copy_from_slice(&image[..4]);
        let mut sector = [0u8; 8];
        sector.copy_from_slice(&image[8..16]);
        (u32::from_le_bytes(kind), u64::from_le_bytes(sector))
    }
}

/// The doorbell the proof rings, which is where this fixture's device runs.
///
/// Servicing on the ring is what makes the proof's own poll loop the thing
/// under test: it submits, rings, and must then find the completion by polling,
/// exactly as it does against QEMU.
struct Doorbell<'a> {
    device: &'a RefCell<Device>,
}

impl Ring for Doorbell<'_> {
    fn ring(&self) {
        self.device.borrow_mut().service();
    }
}

/// A driver, a staging window, and the device on the far side of both.
///
/// Field order is the drop order: the two `Mapped` allocations are declared
/// last, so they outlive the driver and the window attached over them.
struct Fixture {
    requests: Requests<'static>,
    device: RefCell<Device>,
    io: IoRegion<'static>,
    _dma: Mapped<DmaPage>,
    _staging: Mapped<IoPage>,
}

impl Fixture {
    fn new(conduct: Conduct, capacity: u64) -> Self {
        let dma = Mapped::new(DmaPage([0; DMA_REGION_SIZE]));
        let staging = Mapped::new(IoPage([0; BLK_IO_REGION_SIZE]));
        // SAFETY: the allocation is page-aligned, zeroed, larger than the queue
        // layout, and lives until this fixture drops — which its field order
        // puts after the driver.
        let queue = unsafe { BlkVirtqueue::new(dma.base()) };
        // SAFETY: the same region at the address the fixture claims for it; the
        // queue was built over this very pointer and the allocation outlives the
        // driver.
        let requests = unsafe { Requests::attach(dma.base(), DMA_PADDR, queue, capacity) };
        // SAFETY: `BLK_IO_REGION_SIZE` bytes, live for the fixture's life, and
        // reached through this one pointer alone.
        let io = unsafe { IoRegion::attach(staging.base(), IO_PADDR) }.expect("a usable base");
        Self {
            requests,
            device: RefCell::new(Device {
                dma: dma.base(),
                io: staging.base(),
                medium: Vec::new(),
                conduct,
                last_avail: 0,
                used_idx: 0,
                seen: Vec::new(),
            }),
            io,
            _dma: dma,
            _staging: staging,
        }
    }

    fn conforming() -> Self {
        Self::new(Conduct::Conforming, CAPACITY)
    }

    fn seed(&mut self, sector: u64, bytes: [u8; SECTOR_SIZE]) {
        self.device.borrow_mut().store(sector, bytes);
    }

    fn prove(&mut self) -> Result<Report, SmokeError> {
        let ring = Doorbell {
            device: &self.device,
        };
        prove(&mut self.requests, &mut self.io, &ring)
    }
}

#[test]
fn the_two_sectors_the_proof_names_are_distinct_and_within_the_minimum() {
    assert_ne!(PROBE_SECTOR, WITNESS_SECTOR);
    assert_eq!(MINIMUM_CAPACITY_SECTORS, WITNESS_SECTOR + 1);
    assert_ne!(Step::Probe.staging(), Step::Witness.staging());
    assert!(Step::Witness.staging().get() < IO_SECTORS);
}

#[test]
fn the_witness_pattern_is_not_a_uniform_fill_and_names_its_own_sector() {
    let pattern = witness_pattern();
    assert_eq!(&pattern[..8], &WITNESS_MAGIC);
    assert_eq!(
        u64::from_le_bytes(pattern[8..16].try_into().expect("eight bytes")),
        WITNESS_SECTOR
    );
    assert!(
        pattern.windows(2).any(|pair| pair[0] != pair[1]),
        "a uniform sector could be produced by a medium that wrote nothing"
    );
    assert_ne!(pattern, [0u8; SECTOR_SIZE]);
    assert_eq!(witness_pattern(), pattern, "the pattern is deterministic");
}

#[test]
fn a_conforming_device_answers_both_halves_and_commits_the_witness() {
    let mut seeded = [0u8; SECTOR_SIZE];
    for (at, byte) in seeded.iter_mut().enumerate() {
        *byte = at as u8;
    }
    let mut fixture = Fixture::conforming();
    fixture.seed(PROBE_SECTOR, seeded);

    let report = fixture.prove().expect("a conforming device");
    assert_eq!(report.capacity_sectors, CAPACITY);
    assert_eq!(report.witness_sector, WITNESS_SECTOR);
    assert_eq!(
        report.probe_word,
        u64::from_le_bytes(seeded[..8].try_into().expect("eight bytes")),
        "the probe word is the medium's first eight bytes"
    );

    let device = fixture.device.borrow();
    assert_eq!(
        device.sector(WITNESS_SECTOR),
        witness_pattern(),
        "the witness pattern must be on the medium afterwards"
    );
    assert_eq!(
        device.seen,
        std::vec![
            (crate::request::VIRTIO_BLK_T_IN, PROBE_SECTOR),
            (crate::request::VIRTIO_BLK_T_OUT, WITNESS_SECTOR),
        ],
        "the read must precede the write, and each must name its own sector"
    );
}

#[test]
fn the_probe_does_not_read_the_window_the_witness_is_staged_in() {
    // A medium answering every read with the witness pattern must still not be
    // able to make the proof pass by leaving the staging window alone: the two
    // steps use disjoint staging sectors, so the write's bytes are this
    // module's and never the device's.
    let mut fixture = Fixture::conforming();
    fixture.seed(PROBE_SECTOR, witness_pattern());
    fixture.prove().expect("a conforming device");
    assert_eq!(
        fixture.device.borrow().sector(WITNESS_SECTOR),
        witness_pattern()
    );
}

#[test]
fn a_medium_too_small_for_the_witness_is_refused_before_anything_is_published() {
    let mut fixture = Fixture::new(Conduct::Conforming, WITNESS_SECTOR);
    let error = fixture.prove().expect_err("too small");
    assert_eq!(
        error,
        SmokeError::TooSmall {
            capacity: WITNESS_SECTOR,
            needed: MINIMUM_CAPACITY_SECTORS,
        }
    );
    assert_eq!(error.step(), None);
    assert!(fixture.device.borrow().seen.is_empty());
    assert_eq!(fixture.requests.in_flight(), 0);
}

#[test]
fn a_device_that_never_answers_parks_the_proof_and_not_the_domain() {
    // The budget is what bounds this. A smaller one is used by driving the
    // silent conduct, which returns before completing anything at all: the loop
    // must end by itself.
    let mut fixture = Fixture::new(Conduct::Silent, CAPACITY);
    let error = fixture.prove().expect_err("a silent device");
    assert_eq!(error, SmokeError::Silent { step: Step::Probe });
    assert_eq!(error.refusal().cause, "block-probe-silent");
}

#[test]
fn a_device_error_on_the_probe_is_reported_as_one() {
    let mut fixture = Fixture::new(
        Conduct::Status(crate::request::VIRTIO_BLK_S_IOERR),
        CAPACITY,
    );
    let error = fixture.prove().expect_err("a device error");
    assert_eq!(
        error,
        SmokeError::Failed {
            step: Step::Probe,
            outcome: Outcome::DeviceError,
        }
    );
    let refusal = error.refusal();
    assert_eq!(refusal.cause, "block-probe-failed");
    assert_eq!(refusal.detail, RefusalDetail::One(1));
    assert!(!refusal.signalled);
}

#[test]
fn an_undecodable_status_reaches_the_console_carrying_the_byte() {
    let mut fixture = Fixture::new(Conduct::Status(0x7B), CAPACITY);
    let error = fixture.prove().expect_err("an undecodable status");
    assert_eq!(
        error,
        SmokeError::Failed {
            step: Step::Probe,
            outcome: Outcome::UnknownStatus { status: 0x7B },
        }
    );
    assert_eq!(error.refusal().detail, RefusalDetail::One(0x17B));
}

#[test]
fn a_short_read_is_a_failure_and_not_a_success() {
    let mut fixture = Fixture::new(Conduct::Short(1 + SECTOR_SIZE as u32 / 2), CAPACITY);
    let error = fixture.prove().expect_err("a short read");
    assert_eq!(
        error,
        SmokeError::Short {
            step: Step::Probe,
            bytes: SECTOR_SIZE as u32 / 2,
        }
    );
    assert_eq!(
        error.refusal().detail,
        RefusalDetail::Two(SECTOR_SIZE as u64 / 2, SECTOR_SIZE as u64)
    );
}

#[test]
fn a_forged_completion_is_not_taken_for_the_request_that_was_submitted() {
    // The proof's own chain starts at descriptor 0, so a completion naming any
    // other descriptor is one the queue never posted. The layer below refuses
    // it and answers `None`, so the proof sees a device that said nothing
    // rather than one that answered — which is the outcome worth having, since
    // believing it would report a medium that was never touched as proved.
    let mut fixture = Fixture::new(Conduct::Forge { head: 9 }, CAPACITY);
    let error = fixture.prove().expect_err("a forged completion");
    assert_eq!(error, SmokeError::Silent { step: Step::Probe });
    assert!(fixture.requests.faults().device.completion_not_posted > 0);
    assert_eq!(
        fixture.device.borrow().sector(WITNESS_SECTOR),
        [0u8; SECTOR_SIZE],
        "nothing may be committed after a completion the driver did not earn"
    );
}

/// A medium that answers reads and commits no write. The probe must pass, the
/// witness must fail, and the failure must name the witness — a proof that
/// reported the probe's step here would send an operator to the wrong half.
#[test]
fn a_medium_that_reads_and_does_not_commit_fails_at_the_witness() {
    let mut fixture = Fixture::new(
        Conduct::FailsTheWitness(crate::request::VIRTIO_BLK_S_IOERR),
        CAPACITY,
    );
    fixture.seed(PROBE_SECTOR, [0x11u8; SECTOR_SIZE]);
    let error = fixture.prove().expect_err("the witness failed");
    assert_eq!(
        error,
        SmokeError::Failed {
            step: Step::Witness,
            outcome: Outcome::DeviceError,
        }
    );
    assert_eq!(error.step(), Some(Step::Witness));
    assert_eq!(error.refusal().cause, "block-witness-failed");
    let device = fixture.device.borrow();
    assert_eq!(device.seen.len(), 2, "the probe ran before the witness");
    assert_eq!(
        device.sector(WITNESS_SECTOR),
        [0u8; SECTOR_SIZE],
        "nothing may be on the medium when the write was refused"
    );
}

/// A device that acknowledges a write it did not perform is believed, and that
/// is the protocol rather than a gap here: virtio-blk has no partial
/// acknowledgement for a write, so `Ok` is the only thing a driver has to go
/// on and `Completed::bytes` is derived from what was submitted. **This is
/// exactly why the proof is not the last word**: `xtask`'s QEMU harness reads
/// the witness sector back off the disk image afterwards, from outside the
/// guest, which is the only place a lying acknowledgement is caught.
#[test]
fn a_write_the_device_acknowledged_is_believed_here_and_checked_outside() {
    let mut fixture = Fixture::new(Conduct::FailsTheWitness(VIRTIO_BLK_S_OK), CAPACITY);
    let report = fixture.prove().expect("the device claimed success");
    assert_eq!(report.witness_sector, WITNESS_SECTOR);
    assert_eq!(
        fixture.device.borrow().sector(WITNESS_SECTOR),
        [0u8; SECTOR_SIZE],
        "and nothing reached the medium, which only an outside reader can see"
    );
}

#[test]
fn every_failure_names_a_distinct_console_token() {
    let errors = [
        SmokeError::TooSmall {
            capacity: 0,
            needed: 1,
        },
        SmokeError::Refused {
            step: Step::Probe,
            error: SubmitError::QueueFull,
        },
        SmokeError::Refused {
            step: Step::Witness,
            error: SubmitError::QueueFull,
        },
        SmokeError::Silent { step: Step::Probe },
        SmokeError::Silent {
            step: Step::Witness,
        },
        SmokeError::Misattributed { step: Step::Probe },
        SmokeError::Misattributed {
            step: Step::Witness,
        },
        SmokeError::Failed {
            step: Step::Probe,
            outcome: Outcome::DeviceError,
        },
        SmokeError::Failed {
            step: Step::Witness,
            outcome: Outcome::DeviceError,
        },
        SmokeError::Short {
            step: Step::Probe,
            bytes: 0,
        },
        SmokeError::Short {
            step: Step::Witness,
            bytes: 0,
        },
    ];
    let mut tokens: Vec<&str> = errors.iter().map(|error| error.refusal().cause).collect();
    let count = tokens.len();
    tokens.sort_unstable();
    tokens.dedup();
    assert_eq!(tokens.len(), count, "two failures share a console token");
    for error in &errors {
        assert!(!error.refusal().signalled, "the device is left live");
    }
}

#[test]
fn every_submit_refusal_has_its_own_code() {
    let codes = [
        SubmitError::NoFreeSlot,
        SubmitError::QueueFull,
        SubmitError::LengthNotSectorMultiple { len: 1 },
        SubmitError::LengthZero,
        SubmitError::OutsideCapacity {
            sector: 0,
            sectors: 0,
            capacity: 0,
        },
        SubmitError::DataAddressUnaligned { paddr: 1 },
    ]
    .map(submit_code);
    let mut sorted = codes.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), codes.len());
}

proptest! {
    /// Whatever the medium holds at the probe sector, the proof reports its
    /// first eight bytes and commits the same witness — the read's content
    /// never steers the write.
    #[test]
    fn the_probe_content_never_changes_what_is_written(
        seeded in proptest::collection::vec(any::<u8>(), SECTOR_SIZE),
    ) {
        let mut bytes = [0u8; SECTOR_SIZE];
        bytes.copy_from_slice(&seeded);
        let mut fixture = Fixture::conforming();
        fixture.seed(PROBE_SECTOR, bytes);
        let report = fixture.prove().expect("a conforming device");
        prop_assert_eq!(
            report.probe_word,
            u64::from_le_bytes(bytes[..8].try_into().expect("eight bytes"))
        );
        prop_assert_eq!(fixture.device.borrow().sector(WITNESS_SECTOR), witness_pattern());
    }

    /// No status byte the device can invent makes the proof pass, and none
    /// makes it panic: every one of the 256 is either `Ok` or a typed failure.
    #[test]
    fn no_status_byte_the_device_can_write_escapes_the_vocabulary(status in any::<u8>()) {
        let mut fixture = Fixture::new(Conduct::Status(status), CAPACITY);
        match fixture.prove() {
            // `Ok` with no transfer is still a short read: the device claimed
            // success and moved nothing.
            Ok(_) => prop_assert!(false, "a device that transferred nothing must not pass"),
            Err(SmokeError::Short { step: Step::Probe, .. }) => {
                prop_assert_eq!(status, VIRTIO_BLK_S_OK);
            }
            Err(SmokeError::Failed { step: Step::Probe, outcome }) => {
                prop_assert_ne!(outcome, Outcome::Ok);
            }
            Err(other) => prop_assert!(false, "unexpected {:?}", other),
        }
    }

    /// A capacity below the minimum is always refused and never publishes; one
    /// at or above it always runs both halves.
    #[test]
    fn the_capacity_bound_is_exact(capacity in 0u64..(WITNESS_SECTOR * 2)) {
        let mut fixture = Fixture::new(Conduct::Conforming, capacity);
        let outcome = fixture.prove();
        if capacity < MINIMUM_CAPACITY_SECTORS {
            prop_assert_eq!(
                outcome.expect_err("too small"),
                SmokeError::TooSmall { capacity, needed: MINIMUM_CAPACITY_SECTORS }
            );
            prop_assert!(fixture.device.borrow().seen.is_empty());
        } else {
            prop_assert_eq!(outcome.expect("large enough").capacity_sectors, capacity);
            prop_assert_eq!(fixture.device.borrow().seen.len(), 2);
        }
    }
}
