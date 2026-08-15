//! The virtio-blk request protocol: the header ABI the device reads, and the
//! state machine that turns a read, write or flush into a descriptor chain and
//! a completion back into an outcome.
//!
//! # The adversary
//!
//! A **hostile or malfunctioning device**, on three surfaces this
//! module is the last check before. The used-ring completion decides which
//! request is being answered; the status byte the device DMAs into this
//! driver's own region decides whether that request succeeded; and the byte
//! count it reports decides how much of a read buffer a caller will believe.
//! None is trusted: a completion is attributed through a map this module keeps
//! outside the region, an unrecognised status is its own outcome rather than a
//! success, and a count is derived from what was asked for rather than from
//! what was claimed.
//!
//! The *caller* is not an adversary — it is the protection domain this crate
//! is compiled into — but its sector range is checked all the same, because
//! the capacity it is checked against came from the device.
//!
//! # Why a slot table and not a descriptor table
//!
//! A request needs two pieces of memory the device reaches by physical address
//! and the driver by offset: sixteen bytes of header it reads, and one byte of
//! status it writes. Both must be private to one in-flight request, or a second
//! completion reads the first's status. Carving them per *slot* rather than per
//! descriptor is what makes that disjointness arithmetic — a [`SlotIndex`] is
//! `< SLOTS` by construction and its two offsets follow from the index — rather
//! than a property of whichever descriptors the queue's free list happened to
//! hand out.

use core::marker::PhantomData;

use virtio::queue::Segment;

/// [`RequestFaults::device`]'s type, nameable without depending on `virtio`.
pub use virtio::queue::DeviceFaults;

use crate::{BlkVirtqueue, HEADER_AREA_OFFSET, QUEUE_SIZE, SECTOR_SIZE, STATUS_AREA_OFFSET};

/// A read: the device writes the data buffer.
pub const VIRTIO_BLK_T_IN: u32 = 0;
/// A write: the device reads the data buffer.
pub const VIRTIO_BLK_T_OUT: u32 = 1;
/// A flush: the device commits everything already written to stable storage.
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;

/// The request completed.
pub const VIRTIO_BLK_S_OK: u8 = 0;
/// The device failed the request.
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
/// The device does not support the request.
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Bytes of status the device writes at the end of every request.
const STATUS_LEN: u32 = 1;

/// Requests this driver keeps in flight at once, and so the number of private
/// header and status areas the DMA region is carved into.
///
/// It is *not* the binding limit on concurrency. A read or a write is a
/// three-descriptor chain, so eight of them want 24 descriptors against a
/// [`QUEUE_SIZE`] of 16: the descriptor table runs out first, at five data
/// requests, and [`SubmitError::QueueFull`] is what says so. Both refusals
/// exist because both are reachable, and they name different exhaustions —
/// [`SubmitError::NoFreeSlot`] is this module's table, `QueueFull` the queue's.
pub const SLOTS: usize = 8;

/// The 16-byte header every virtio-blk request begins with, which the device
/// reads out of the DMA region.
///
/// `reserved` is not a field a caller can set: virtio 1.0 section 5.2.6 requires
/// it zero, and a constructor that cannot produce a non-zero one is the check.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestHeader {
    request_type: u32,
    reserved: u32,
    sector: u64,
}

impl RequestHeader {
    pub const LEN: usize = size_of::<Self>();

    #[must_use]
    pub const fn new(operation: Operation, sector: u64) -> Self {
        Self {
            request_type: operation.request_type(),
            reserved: 0,
            sector,
        }
    }

    /// Write this header's little-endian DMA image into `out`.
    ///
    /// The destination is a fixed-size array rather than a slice because a
    /// header that does not fit is then not a runtime error but a type error,
    /// and the image is written by destructuring rather than by indexing so no
    /// bound is checked at all.
    pub fn write_into(&self, out: &mut [u8; Self::LEN]) {
        let [t0, t1, t2, t3] = self.request_type.to_le_bytes();
        let [r0, r1, r2, r3] = self.reserved.to_le_bytes();
        let [s0, s1, s2, s3, s4, s5, s6, s7] = self.sector.to_le_bytes();
        *out = [
            t0, t1, t2, t3, r0, r1, r2, r3, s0, s1, s2, s3, s4, s5, s6, s7,
        ];
    }
}

// The header is DMA'd verbatim to the device, so its layout is a wire ABI and
// not a Rust struct's business: a reorder or a width change has to fail the
// build rather than silently shift every request by four bytes.
const _: () = {
    assert!(size_of::<RequestHeader>() == 16);
    assert!(align_of::<RequestHeader>() == 8);
    assert!(core::mem::offset_of!(RequestHeader, request_type) == 0);
    assert!(core::mem::offset_of!(RequestHeader, reserved) == 4);
    assert!(core::mem::offset_of!(RequestHeader, sector) == 8);
};

/// What a request asks the device to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Read `len` bytes into the caller's buffer, which the device writes.
    Read,
    /// Write `len` bytes from the caller's buffer, which the device reads.
    Write,
    /// Commit everything already written to stable storage. A flush addresses
    /// no range and carries no data segment, so [`Requests::submit`]'s
    /// `sector`, `data_paddr` and `len` are not part of one and are not read.
    Flush,
}

impl Operation {
    const fn request_type(self) -> u32 {
        match self {
            Self::Read => VIRTIO_BLK_T_IN,
            Self::Write => VIRTIO_BLK_T_OUT,
            Self::Flush => VIRTIO_BLK_T_FLUSH,
        }
    }

    /// Whether the chain carries a data segment between header and status.
    const fn has_data(self) -> bool {
        !matches!(self, Self::Flush)
    }

    /// Whether the *device* writes that data segment, in virtio's own sense.
    const fn data_device_writable(self) -> bool {
        matches!(self, Self::Read)
    }
}

/// Why [`Requests::submit`] refused a request. Every variant is a caller error
/// except [`NoFreeSlot`](Self::NoFreeSlot) and [`QueueFull`](Self::QueueFull),
/// which are backpressure and expected under load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitError {
    /// Every one of this driver's [`SLOTS`] header and status areas is held by
    /// an in-flight request.
    NoFreeSlot,
    /// The virtqueue has no room for the chain. Reachable with a free slot in
    /// hand, because a data request costs three descriptors and [`SLOTS`]
    /// exceeds a third of [`QUEUE_SIZE`].
    QueueFull,
    /// virtio-blk addresses whole sectors; a length that is not a multiple of
    /// [`SECTOR_SIZE`] names a transfer the device has no way to perform.
    LengthNotSectorMultiple { len: u32 },
    /// A zero-length read or write. Distinct from
    /// [`LengthNotSectorMultiple`](Self::LengthNotSectorMultiple) because zero
    /// *is* a multiple of the sector size and is still not a request: it would
    /// publish a zero-length descriptor and wait for a completion carrying
    /// nothing.
    LengthZero,
    /// The range runs past the end of the device, or its end is not
    /// representable. The capacity is the device's own claim and is the only
    /// thing standing between a caller and a write past the medium.
    OutsideCapacity {
        sector: u64,
        sectors: u64,
        capacity: u64,
    },
    /// Zero, not [`SECTOR_SIZE`]-aligned, or so high that the buffer's end is
    /// not representable. Not the specification's requirement but this
    /// driver's: the address is handed to a device that will DMA to it, and a
    /// block buffer that does not start on a sector boundary is a caller that
    /// has computed an address wrong.
    DataAddressUnaligned { paddr: u64 },
}

/// What the device said about a completed request, decoded from the single
/// status byte it wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    DeviceError,
    Unsupported,
    /// A status byte outside the three the specification defines. Its own
    /// outcome rather than an error or a success: a driver that folded it into
    /// either would be deciding, on the device's behalf, what a byte it has no
    /// meaning for meant.
    UnknownStatus {
        status: u8,
    },
}

/// A completed request: which one, what it was, how it ended, and how many
/// bytes of data that accounts for.
#[derive(Debug, PartialEq, Eq)]
pub struct Completed {
    pub token: Token,
    pub operation: Operation,
    pub outcome: Outcome,
    /// Data bytes transferred, and zero for anything but [`Outcome::Ok`].
    ///
    /// Derived rather than reported, because the device's own count answers a
    /// different question for each operation. On a read the device writes the
    /// data *and* the status, so its count includes the status byte and is
    /// reduced by it before being clamped to what was asked for — a short read
    /// is the one case where the count carries information. On a write only
    /// the status byte is device-writable, so the count is always one and says
    /// nothing; what a successful write moved is the length submitted, which
    /// virtio-blk has no way to partially acknowledge. A flush moves no data.
    pub bytes: u32,
}

/// A submitted request's identity.
///
/// Deliberately not [`Copy`]: it is the caller's handle on one in-flight
/// request, and duplicating it invites keeping a second one naming a slot that
/// has since been reissued. Equality against a [`Completed`]'s token is the
/// only operation, and the generation is what makes it an identity rather than
/// a position — a slot's generation advances on every completion, so a token
/// never matches a request other than the one it was minted for.
#[derive(Debug, PartialEq, Eq)]
pub struct Token {
    slot: SlotIndex,
    generation: u32,
}

/// Device misbehaviours this layer and the virtqueue below it refused, which
/// are otherwise invisible: a device replaying completions or writing garbage
/// statuses at line rate looks exactly like an idle disk.
///
/// Every count is monotonic for the driver's life and saturates at [`u64::MAX`]
/// rather than wrapping, on the same terms as [`DeviceFaults`]: a metrics
/// consumer differences successive readings, so a reset would
/// forge a negative rate and a wrap would turn a sustained flood into a small
/// number.
///
/// The split by answerability is structural. [`device`](Self::device) and
/// [`status_undecodable`](Self::status_undecodable) are expected to be non-zero
/// against a misbehaving device; [`completion_unmapped`](Self::completion_unmapped)
/// is expected to be zero forever, and an alert can be written against it
/// alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestFaults {
    /// The virtqueue's own refusals: a completion naming no descriptor of this
    /// queue, one naming a descriptor it never posted or already reaped, and
    /// one claiming more bytes than the chain could hold.
    pub device: DeviceFaults,
    /// Completions whose status byte was outside the three defined values.
    pub status_undecodable: u64,
    /// Completions this layer holds no request for, the descriptor having
    /// passed the queue's own check. Reachable only by attaching to a
    /// virtqueue that already carried traffic — a wiring defect in the
    /// protection domain, not a device behaviour.
    pub completion_unmapped: u64,
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// One of this driver's request slots: `< SLOTS` by construction, so the header
/// and status offsets derived from it lie inside the DMA region by arithmetic
/// and not by an argument about who checked. The `lib.rs` layout assertions are
/// the other half of that arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SlotIndex(u8);

// A slot is held in a `u8`, so a table that could not be named in one would
// silently truncate every index past the 255th.
const _: () = assert!(SLOTS <= u8::MAX as usize, "a slot index must fit in a u8");

impl SlotIndex {
    /// Every slot, in order. Total, so a scan of the table needs no fallible
    /// conversion and no branch that cannot be taken.
    fn all() -> impl Iterator<Item = Self> {
        (0..SLOTS as u8).map(Self)
    }

    const fn get(self) -> usize {
        self.0 as usize
    }

    const fn header_offset(self) -> usize {
        HEADER_AREA_OFFSET + self.get() * RequestHeader::LEN
    }

    const fn status_offset(self) -> usize {
        STATUS_AREA_OFFSET + self.get()
    }
}

/// What this layer remembers about a chain it published, kept outside the DMA
/// region so no part of it is a value the device can rewrite.
#[derive(Clone, Copy)]
struct Posted {
    slot: SlotIndex,
    operation: Operation,
    /// The data length submitted, which is the clamp on what a read may report.
    data_len: u32,
}

#[derive(Clone, Copy, Default)]
struct SlotRecord {
    live: bool,
    generation: u32,
}

/// The request state machine over one virtio-blk virtqueue and the DMA region
/// holding it.
///
/// `'dma` is the caller's own assertion, made at [`attach`](Self::attach), of
/// how long the region stays mapped. It is not derived from the pointer — a raw
/// pointer carries no lifetime — so it constrains nothing on its own; it exists
/// so a caller that *does* hold a borrow of the region can tie this value's
/// life to it, and it makes the type invariant in that lifetime rather than
/// silently outliving it in a struct.
pub struct Requests<'dma> {
    dma: *mut u8,
    dma_paddr: u64,
    queue: BlkVirtqueue,
    /// The device's own claim about how many sectors it has, taken at bring-up
    /// and never re-read: a device that changed its answer mid-flight would
    /// otherwise move the bound under requests already validated against it.
    capacity_sectors: u64,
    /// Which request occupies each descriptor head this layer published. The
    /// attribution the device does not get a say in.
    posted: [Option<Posted>; QUEUE_SIZE],
    slots: [SlotRecord; SLOTS],
    status_undecodable: u64,
    completion_unmapped: u64,
    region: PhantomData<&'dma mut [u8]>,
}

impl<'dma> Requests<'dma> {
    /// Attach to a mapped DMA region and the virtqueue placed at its base.
    ///
    /// # Safety
    /// `dma` must point to a live mapping of at least [`crate::DMA_REGION_SIZE`]
    /// bytes, 16-byte aligned, shared only with the one block device this
    /// driver brought up, and staying mapped for at least `'dma`.
    /// `dma_paddr` must be that mapping's physical address, and
    /// `dma_paddr + DMA_REGION_SIZE` must not overflow, because every
    /// descriptor address this type publishes is that base plus an offset the
    /// layout assertions bound by the region size. `queue` must be the
    /// [`BlkVirtqueue`] built over the same `dma` — the layout assertions place
    /// the header and status areas after it, and a queue over some other region
    /// would leave them overlapping whatever is at this one's base.
    ///
    /// **The enforcer of the address** is
    /// [`crate::bringup::Negotiated::configure_queue`], which refuses a zero,
    /// misaligned or wrapping `dma_paddr` before the device is ever programmed
    /// with it — proved by its `an_unusable_dma_region_address_is_refused`. The
    /// extent's enforcer is `xtask::sysdesc`, with the gap
    /// [`crate::DMA_REGION_SIZE`] records. The queue's provenance has no
    /// enforcer and is the caller's: it is a parameter rather than something
    /// built here so a host test can attach to a queue that already carried
    /// traffic, which is the only way this layer's
    /// [`RequestFaults::completion_unmapped`] is reachable.
    #[must_use]
    pub unsafe fn attach(
        dma: *mut u8,
        dma_paddr: u64,
        queue: BlkVirtqueue,
        capacity_sectors: u64,
    ) -> Self {
        Self {
            dma,
            dma_paddr,
            queue,
            capacity_sectors,
            posted: [None; QUEUE_SIZE],
            slots: [SlotRecord::default(); SLOTS],
            status_undecodable: 0,
            completion_unmapped: 0,
            region: PhantomData,
        }
    }

    /// The capacity this driver was brought up against, in [`SECTOR_SIZE`]
    /// sectors.
    #[must_use]
    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    /// Requests published to the device and not yet completed.
    ///
    /// Derived from the slot table rather than counted alongside it, so there
    /// is no second number to drift out of step with the first.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.slots.iter().filter(|slot| slot.live).count()
    }

    #[must_use]
    pub fn faults(&self) -> RequestFaults {
        RequestFaults {
            device: self.queue.device_faults(),
            status_undecodable: self.status_undecodable,
            completion_unmapped: self.completion_unmapped,
        }
    }

    /// Publish one request as a descriptor chain and return its identity.
    ///
    /// The chain is the shape virtio 1.0 section 5.2.6 fixes: a device-readable
    /// header, then for a read or a write the caller's data buffer at the
    /// permission that operation implies, then a device-writable status byte.
    /// A flush has no data segment and is two descriptors.
    ///
    /// Nothing is notified: ringing the doorbell is [`crate::bringup::Live`]'s,
    /// so a caller submitting a batch pays for one notification rather than
    /// one per request.
    ///
    /// # Errors
    /// A [`SubmitError`]. Nothing is published and no slot is consumed on any
    /// of them, so a refused submit leaves the device exactly as it found it.
    pub fn submit(
        &mut self,
        operation: Operation,
        sector: u64,
        data_paddr: u64,
        len: u32,
    ) -> Result<Token, SubmitError> {
        let data = self.validate(operation, sector, data_paddr, len)?;
        let slot = self.free_slot().ok_or(SubmitError::NoFreeSlot)?;
        self.write_header(slot, RequestHeader::new(operation, sector));

        // `dma_paddr + offset` cannot overflow: the offsets are bounded by
        // `DMA_REGION_SIZE` in the layout assertions, and `attach`'s contract
        // makes that sum representable.
        let header = Segment {
            paddr: self.dma_paddr + slot.header_offset() as u64,
            len: RequestHeader::LEN as u32,
            device_writable: false,
        };
        let status = Segment {
            paddr: self.dma_paddr + slot.status_offset() as u64,
            len: STATUS_LEN,
            device_writable: true,
        };
        let head = match data {
            Some(data) => self.queue.add_chain(&[header, data, status]),
            None => self.queue.add_chain(&[header, status]),
        }
        .ok_or(SubmitError::QueueFull)?;

        // `head < QUEUE_SIZE` and `slot.get() < SLOTS` are both the producing
        // types' guarantees — `Completion::index`'s and `SlotIndex`'s — so
        // neither store can be out of range.
        self.posted[head as usize] = Some(Posted {
            slot,
            operation,
            data_len: data.map_or(0, |segment| segment.len),
        });
        let record = &mut self.slots[slot.get()];
        record.live = true;
        Ok(Token {
            slot,
            generation: record.generation,
        })
    }

    /// Take one completion, or `None`.
    ///
    /// One per call by design, so a caller drains in a loop it bounds itself
    /// and a device flooding its used ring cannot park this domain inside a
    /// single call. `None` also ends the drain when a completion could
    /// not be attributed to a request, which is counted in
    /// [`RequestFaults::completion_unmapped`] rather than passed off as an
    /// idle queue.
    pub fn poll(&mut self) -> Option<Completed> {
        let (completion, reported) = self.queue.poll()?;
        let head = completion.index() as usize;
        // The descriptors belong to the queue whatever this layer makes of the
        // completion, so they go back before anything else can refuse it.
        completion.recycle();

        // Total in `head`: the queue guarantees it names one of its own
        // descriptors, and a value that somehow did not is the same
        // unattributable completion as a slot this layer never filled.
        let Some(posted) = self.posted.get_mut(head).and_then(Option::take) else {
            bump(&mut self.completion_unmapped);
            return None;
        };

        let status = self.read_status(posted.slot);
        let outcome = match status {
            VIRTIO_BLK_S_OK => Outcome::Ok,
            VIRTIO_BLK_S_IOERR => Outcome::DeviceError,
            VIRTIO_BLK_S_UNSUPP => Outcome::Unsupported,
            status => {
                bump(&mut self.status_undecodable);
                Outcome::UnknownStatus { status }
            }
        };

        // In range by `SlotIndex`, which is this crate's own value and never
        // the device's.
        let record = &mut self.slots[posted.slot.get()];
        record.live = false;
        let token = Token {
            slot: posted.slot,
            generation: record.generation,
        };
        record.generation = record.generation.wrapping_add(1);

        Some(Completed {
            token,
            operation: posted.operation,
            outcome,
            bytes: data_bytes(posted.operation, outcome, reported, posted.data_len),
        })
    }

    /// The data segment a request needs, or `None` for a flush, having refused
    /// everything about the request that can be refused before a slot or a
    /// descriptor is spent.
    fn validate(
        &self,
        operation: Operation,
        sector: u64,
        data_paddr: u64,
        len: u32,
    ) -> Result<Option<Segment>, SubmitError> {
        if !operation.has_data() {
            return Ok(None);
        }
        if len == 0 {
            return Err(SubmitError::LengthZero);
        }
        let Some(sectors) = sector_count(len) else {
            return Err(SubmitError::LengthNotSectorMultiple { len });
        };
        // Checked, because both operands are chosen by a caller and the
        // capacity they are judged against came from the device: a wrapped sum
        // is a range that passes the bound and lands anywhere on the medium.
        if sector
            .checked_add(sectors)
            .is_none_or(|end| end > self.capacity_sectors)
        {
            return Err(SubmitError::OutsideCapacity {
                sector,
                sectors,
                capacity: self.capacity_sectors,
            });
        }
        if data_paddr == 0
            || !data_paddr.is_multiple_of(SECTOR_SIZE as u64)
            || data_paddr.checked_add(u64::from(len)).is_none()
        {
            return Err(SubmitError::DataAddressUnaligned { paddr: data_paddr });
        }
        Ok(Some(Segment {
            paddr: data_paddr,
            len,
            device_writable: operation.data_device_writable(),
        }))
    }

    fn free_slot(&self) -> Option<SlotIndex> {
        self.slots
            .iter()
            .zip(SlotIndex::all())
            .find_map(|(record, index)| (!record.live).then_some(index))
    }

    fn write_header(&mut self, slot: SlotIndex, header: RequestHeader) {
        let mut image = [0u8; RequestHeader::LEN];
        header.write_into(&mut image);
        // SAFETY: `attach`'s contract makes `dma` a live mapping of at least
        // `DMA_REGION_SIZE` bytes. `slot` is `< SLOTS` by `SlotIndex`'s only
        // constructor, and `lib.rs`'s layout assertions put
        // `HEADER_AREA_OFFSET + SLOTS * RequestHeader::LEN` inside the region,
        // so this slot's sixteen bytes lie within it. `[u8; 16]` needs no
        // alignment. The area belongs to this slot alone, which no in-flight
        // request other than the one being built holds.
        unsafe {
            self.dma
                .add(slot.header_offset())
                .cast::<[u8; RequestHeader::LEN]>()
                .write_volatile(image);
        }
    }

    fn read_status(&self, slot: SlotIndex) -> u8 {
        // SAFETY: as `write_header`, for the one byte at
        // `STATUS_AREA_OFFSET + slot`, which the same assertions put inside the
        // region; a `u8` needs no alignment. The byte is the device's to write
        // and this driver's to interpret, which is `poll`'s business and not
        // this read's.
        unsafe { self.dma.add(slot.status_offset()).read_volatile() }
    }
}

/// Sectors in `len` bytes, or `None` when it is not a whole number of them.
fn sector_count(len: u32) -> Option<u64> {
    len.is_multiple_of(SECTOR_SIZE as u32)
        .then(|| u64::from(len) / SECTOR_SIZE as u64)
}

/// Data bytes a completion accounts for; see [`Completed::bytes`] for why each
/// operation answers differently.
fn data_bytes(operation: Operation, outcome: Outcome, reported: u32, submitted: u32) -> u32 {
    if outcome != Outcome::Ok {
        return 0;
    }
    match operation {
        Operation::Read => reported.saturating_sub(STATUS_LEN).min(submitted),
        Operation::Write => submitted,
        Operation::Flush => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DMA_REGION_SIZE;
    use proptest::prelude::*;
    use std::{boxed::Box, collections::BTreeSet, vec::Vec};

    /// The physical address the fixture region pretends to sit at: high enough
    /// that a wrong base shows up as a wild address rather than as a small
    /// offset that happens to work.
    const DMA_PADDR: u64 = 0x4000_0000;
    /// A caller's data buffer, sector-aligned and outside the DMA region.
    const DATA_PADDR: u64 = 0x5000_0000;
    const CAPACITY: u64 = 2048;

    const DESC_STRIDE: usize = 16;
    const VIRTQ_DESC_F_NEXT: u16 = 1;
    const VIRTQ_DESC_F_WRITE: u16 = 2;

    /// The heap allocation a fixture region owns, at the alignment the
    /// virtqueue at its base requires and the page alignment a Microkit
    /// mapping supplies.
    #[repr(C, align(4096))]
    struct Page([u8; DMA_REGION_SIZE]);

    /// A fixture region, reachable only through the one raw pointer the driver
    /// and the device on its far side are both attached to.
    ///
    /// The bytes are `Box::into_raw`d and no `&`/`&mut` into them is ever
    /// formed, so both sides share a single tag for the region's whole life. A
    /// reference would not survive: the driver writes its headers through the
    /// raw pointer, and such a write invalidates any reference derived from the
    /// same allocation, so a fixture that read a header back through one would
    /// itself be undefined behaviour while claiming to prove the driver's
    /// conduct against a hostile device. Exposing no reference makes
    /// that unrepresentable rather than a rule to remember.
    struct MappedRegion {
        page: *mut Page,
    }

    impl MappedRegion {
        fn zeroed() -> Self {
            Self {
                page: Box::into_raw(Box::new(Page([0; DMA_REGION_SIZE]))),
            }
        }

        /// The pointer both sides are mapped over, and the only route to the
        /// bytes — `*mut` from `&self` deliberately, because handing either
        /// side a separately derived pointer is what a fixture must not do.
        fn base(&self) -> *mut u8 {
            self.page.cast::<u8>()
        }

        fn read<const M: usize>(&self, off: usize) -> [u8; M] {
            assert!(
                off.saturating_add(M) <= DMA_REGION_SIZE,
                "read of {off:#x} escapes the region"
            );
            // SAFETY: the assertion above puts `off..off + M` inside the
            // allocation `zeroed` made, which `Drop` alone frees and which
            // therefore outlives `self`; `[u8; M]` imposes no alignment.
            unsafe { self.base().add(off).cast::<[u8; M]>().read_volatile() }
        }

        fn write<const M: usize>(&self, off: usize, bytes: [u8; M]) {
            assert!(
                off.saturating_add(M) <= DMA_REGION_SIZE,
                "write of {off:#x} escapes the region"
            );
            // SAFETY: bounded by the assertion above into the allocation
            // `zeroed` made and `Drop` alone frees, exactly as `read`.
            unsafe { self.base().add(off).cast::<[u8; M]>().write_volatile(bytes) };
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

    /// One descriptor as it stands in the shared table.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Descriptor {
        paddr: u64,
        len: u32,
        flags: u16,
        next: u16,
    }

    impl Descriptor {
        fn device_writable(self) -> bool {
            self.flags & VIRTQ_DESC_F_WRITE != 0
        }
    }

    /// The far side of the ring, driven by the test in the same thread: it
    /// reads what the driver made available, writes status bytes wherever it
    /// likes, and publishes completions — including ones it was never given,
    /// which is how the hostile cases are driven.
    struct RingDevice {
        region: *mut u8,
        last_avail: u16,
        used_idx: u16,
    }

    impl RingDevice {
        fn descriptor(&self, index: u16) -> Descriptor {
            let base = BlkVirtqueue::LAYOUT.descriptor_offset + index as usize * DESC_STRIDE;
            // SAFETY: single-threaded test driving the ring's far side; a
            // descriptor index below the queue size lies within the live,
            // test-owned region.
            unsafe {
                Descriptor {
                    paddr: self.region.add(base).cast::<u64>().read_volatile(),
                    len: self.region.add(base + 8).cast::<u32>().read_volatile(),
                    flags: self.region.add(base + 12).cast::<u16>().read_volatile(),
                    next: self.region.add(base + 14).cast::<u16>().read_volatile(),
                }
            }
        }

        /// The whole chain from `head`, following the driver's own `next`
        /// links. Bounded by the queue size, so a corrupt list fails an
        /// assertion instead of hanging.
        fn chain(&self, head: u16) -> Vec<Descriptor> {
            let mut chain = Vec::new();
            let mut index = head;
            for _ in 0..QUEUE_SIZE {
                let descriptor = self.descriptor(index);
                chain.push(descriptor);
                if descriptor.flags & VIRTQ_DESC_F_NEXT == 0 {
                    return chain;
                }
                index = descriptor.next;
            }
            panic!("the chain from {head} does not terminate");
        }

        /// The next head the driver made available, or `None`.
        fn next_avail(&mut self) -> Option<u16> {
            let driver = BlkVirtqueue::LAYOUT.driver_offset;
            // SAFETY: single-threaded test driving the ring's far side; the
            // driver ring lies within the live, test-owned region.
            let avail_idx = unsafe { self.region.add(driver + 2).cast::<u16>().read_volatile() };
            if avail_idx == self.last_avail {
                return None;
            }
            let slot = self.last_avail as usize % QUEUE_SIZE;
            // SAFETY: as above, for the entry at a slot reduced modulo the
            // queue size.
            let head = unsafe {
                self.region
                    .add(driver + 4 + slot * 2)
                    .cast::<u16>()
                    .read_volatile()
            };
            self.last_avail = self.last_avail.wrapping_add(1);
            Some(head)
        }

        /// Publish a used-ring completion for `head` reporting `len` bytes,
        /// exactly as the device would — including for a head it was never
        /// given.
        fn complete(&mut self, head: u32, len: u32) {
            let used = BlkVirtqueue::LAYOUT.device_offset;
            let slot = self.used_idx as usize % QUEUE_SIZE;
            // SAFETY: single-threaded test driving the ring's far side; the
            // device ring lies within the live, test-owned region and the slot
            // is reduced modulo the queue size.
            unsafe {
                self.region
                    .add(used + 4 + slot * 8)
                    .cast::<u32>()
                    .write_volatile(head);
                self.region
                    .add(used + 8 + slot * 8)
                    .cast::<u32>()
                    .write_volatile(len);
            }
            self.used_idx = self.used_idx.wrapping_add(1);
            // SAFETY: as above, for the used-ring index.
            unsafe {
                self.region
                    .add(used + 2)
                    .cast::<u16>()
                    .write_volatile(self.used_idx);
            }
        }
    }

    /// A driver over a fresh region plus the device on its far side.
    ///
    /// `Requests<'static>` because `'dma` is not derived from the raw pointer
    /// and so binds nothing: the region's life is this fixture's, and it is
    /// declared after the driver so it is dropped after it.
    struct Fixture {
        requests: Requests<'static>,
        device: RingDevice,
        region: MappedRegion,
    }

    impl Fixture {
        fn with_capacity(capacity: u64) -> Self {
            let region = MappedRegion::zeroed();
            let base = region.base();
            // SAFETY: `MappedRegion` is page-aligned, zeroed, larger than the
            // queue layout, and live until this fixture's `Drop`.
            let queue = unsafe { BlkVirtqueue::new(base) };
            // SAFETY: the same region, at the physical address the fixture
            // pretends it has; the queue was just built over this very pointer,
            // and the allocation outlives the driver, which this struct's field
            // order drops first.
            let requests = unsafe { Requests::attach(base, DMA_PADDR, queue, capacity) };
            Self {
                requests,
                device: RingDevice {
                    region: base,
                    last_avail: 0,
                    used_idx: 0,
                },
                region,
            }
        }

        fn new() -> Self {
            Self::with_capacity(CAPACITY)
        }

        /// The header image the driver wrote for `slot`.
        fn header(&self, slot: usize) -> [u8; RequestHeader::LEN] {
            self.region
                .read(HEADER_AREA_OFFSET + slot * RequestHeader::LEN)
        }

        /// Play the device: take the request the driver published and answer it
        /// with `status` and a reported byte count. Returns the head so a test
        /// can replay or forge against it.
        fn answer(&mut self, status: u8, reported: u32) -> u16 {
            let head = self.device.next_avail().expect("a request was published");
            let chain = self.device.chain(head);
            let last = *chain.last().expect("a chain is never empty");
            self.write_status(last.paddr, status);
            self.device.complete(u32::from(head), reported);
            head
        }

        /// Write a status byte at the physical address the driver published,
        /// translated back into the fixture region.
        fn write_status(&self, paddr: u64, value: u8) {
            let offset = usize::try_from(paddr - DMA_PADDR).expect("inside the region");
            self.region.write(offset, [value]);
        }

        /// Write `value` into every slot's status byte, which a device with no
        /// IOMMU in front of it is free to do whether or not it completed the
        /// requests holding them.
        fn scribble_statuses(&self, value: u8) {
            for slot in 0..SLOTS {
                self.region.write(STATUS_AREA_OFFSET + slot, [value]);
            }
        }
    }

    /// A read, a write and a flush, all valid against [`CAPACITY`].
    fn submit_read(fx: &mut Fixture) -> Result<Token, SubmitError> {
        fx.requests
            .submit(Operation::Read, 0, DATA_PADDR, SECTOR_SIZE as u32)
    }

    #[test]
    fn a_read_publishes_the_header_data_and_status_the_specification_names() {
        let mut fx = Fixture::new();
        let token = fx
            .requests
            .submit(Operation::Read, 9, DATA_PADDR, 2 * SECTOR_SIZE as u32)
            .expect("a valid read");
        assert_eq!(fx.requests.in_flight(), 1);

        // The header the device will read, byte for byte: type 0 little-endian,
        // four reserved zero bytes, then the sector.
        assert_eq!(
            fx.header(0),
            [0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0]
        );

        let head = fx.device.next_avail().expect("a request was published");
        let chain = fx.device.chain(head);
        assert_eq!(chain.len(), 3, "header, data, status");
        assert_eq!(chain[0].paddr, DMA_PADDR + HEADER_AREA_OFFSET as u64);
        assert_eq!(chain[0].len, RequestHeader::LEN as u32);
        assert!(!chain[0].device_writable(), "the device reads the header");
        assert_eq!(chain[1].paddr, DATA_PADDR);
        assert_eq!(chain[1].len, 2 * SECTOR_SIZE as u32);
        assert!(chain[1].device_writable(), "a read is filled by the device");
        assert_eq!(chain[2].paddr, DMA_PADDR + STATUS_AREA_OFFSET as u64);
        assert_eq!(chain[2].len, 1);
        assert!(chain[2].device_writable(), "the device writes the status");

        // The device answers with a full read: 1024 data bytes plus the status.
        fx.write_status(chain[2].paddr, VIRTIO_BLK_S_OK);
        fx.device
            .complete(u32::from(head), 2 * SECTOR_SIZE as u32 + 1);
        let completed = fx.requests.poll().expect("a completion");
        assert_eq!(
            completed,
            Completed {
                token,
                operation: Operation::Read,
                outcome: Outcome::Ok,
                bytes: 2 * SECTOR_SIZE as u32,
            }
        );
        assert_eq!(fx.requests.in_flight(), 0);
        assert_eq!(fx.requests.faults(), RequestFaults::default());
    }

    #[test]
    fn a_write_offers_its_data_to_the_device_rather_than_asking_for_it() {
        let mut fx = Fixture::new();
        let token = fx
            .requests
            .submit(Operation::Write, 1, DATA_PADDR, SECTOR_SIZE as u32)
            .expect("a valid write");
        assert_eq!(
            fx.header(0),
            [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            "type 1 and sector 1"
        );

        let head = fx.device.next_avail().expect("a request was published");
        let chain = fx.device.chain(head);
        assert_eq!(chain.len(), 3);
        assert!(
            !chain[1].device_writable(),
            "a write's data is the device's to read"
        );

        // Only the status byte is device-writable, so the device reports one.
        fx.write_status(chain[2].paddr, VIRTIO_BLK_S_OK);
        fx.device.complete(u32::from(head), 1);
        assert_eq!(
            fx.requests.poll().expect("a completion"),
            Completed {
                token,
                operation: Operation::Write,
                outcome: Outcome::Ok,
                bytes: SECTOR_SIZE as u32,
            },
            "a successful write moved what was submitted, not what was reported"
        );
    }

    #[test]
    fn a_flush_carries_no_data_segment_and_no_byte_count() {
        let mut fx = Fixture::new();
        // The data arguments are not part of a flush, so garbage in them must
        // not change the chain it publishes.
        let token = fx
            .requests
            .submit(Operation::Flush, u64::MAX, 7, u32::MAX)
            .expect("a flush addresses nothing");
        assert_eq!(
            fx.header(0),
            [
                4, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ],
            "type 4, and the sector field carries whatever was passed"
        );

        let head = fx.device.next_avail().expect("a request was published");
        let chain = fx.device.chain(head);
        assert_eq!(chain.len(), 2, "header and status only");
        assert!(!chain[0].device_writable());
        assert!(chain[1].device_writable());
        assert_eq!(chain[1].len, 1);

        // Even a device claiming bytes for a flush is not believed.
        fx.write_status(chain[1].paddr, VIRTIO_BLK_S_OK);
        fx.device.complete(u32::from(head), 4096);
        assert_eq!(
            fx.requests.poll().expect("a completion"),
            Completed {
                token,
                operation: Operation::Flush,
                outcome: Outcome::Ok,
                bytes: 0,
            }
        );
    }

    #[test]
    fn every_submit_refusal_names_its_own_cause() {
        let mut fx = Fixture::new();
        assert_eq!(
            fx.requests.submit(Operation::Read, 0, DATA_PADDR, 0),
            Err(SubmitError::LengthZero)
        );
        assert_eq!(
            fx.requests.submit(Operation::Write, 0, DATA_PADDR, 513),
            Err(SubmitError::LengthNotSectorMultiple { len: 513 })
        );
        assert_eq!(
            fx.requests
                .submit(Operation::Read, CAPACITY, DATA_PADDR, SECTOR_SIZE as u32),
            Err(SubmitError::OutsideCapacity {
                sector: CAPACITY,
                sectors: 1,
                capacity: CAPACITY,
            }),
            "the first sector past the medium is already outside it"
        );
        assert_eq!(
            fx.requests
                .submit(Operation::Read, u64::MAX, DATA_PADDR, SECTOR_SIZE as u32),
            Err(SubmitError::OutsideCapacity {
                sector: u64::MAX,
                sectors: 1,
                capacity: CAPACITY,
            }),
            "a range whose end is not representable is refused, not wrapped"
        );
        for paddr in [0, DATA_PADDR + 1, u64::MAX - 8] {
            assert_eq!(
                fx.requests
                    .submit(Operation::Read, 0, paddr, SECTOR_SIZE as u32),
                Err(SubmitError::DataAddressUnaligned { paddr }),
                "buffer at {paddr:#x} must be refused"
            );
        }
        assert_eq!(fx.requests.in_flight(), 0, "no refusal consumed a slot");
        assert!(
            fx.device.next_avail().is_none(),
            "no refusal published a descriptor"
        );
    }

    #[test]
    fn the_last_sector_of_the_medium_is_inside_it() {
        // The other side of the capacity boundary, so the check is pinned to it
        // rather than refusing every high sector.
        let mut fx = Fixture::new();
        fx.requests
            .submit(
                Operation::Write,
                CAPACITY - 1,
                DATA_PADDR,
                SECTOR_SIZE as u32,
            )
            .expect("the last sector is addressable");
    }

    #[test]
    fn the_descriptor_table_runs_out_before_the_slot_table_does() {
        // Five three-descriptor chains fill fifteen of sixteen descriptors, so
        // the sixth is refused by the queue while three slots are still free —
        // the two exhaustions are different and are reported differently.
        let mut fx = Fixture::new();
        for _ in 0..5 {
            submit_read(&mut fx).expect("a descriptor triple is free");
        }
        assert_eq!(fx.requests.in_flight(), 5);
        assert_eq!(submit_read(&mut fx), Err(SubmitError::QueueFull));
        assert_eq!(
            fx.requests.in_flight(),
            5,
            "a refused chain consumed no slot"
        );
        assert_eq!(
            fx.requests.submit(Operation::Flush, 0, 0, 0),
            Err(SubmitError::QueueFull),
            "one free descriptor is not the two a flush costs either"
        );

        // Completing one request returns its three descriptors, and a flush
        // then fits where a read still would not.
        fx.answer(VIRTIO_BLK_S_OK, SECTOR_SIZE as u32 + 1);
        fx.requests.poll().expect("a completion");
        fx.requests
            .submit(Operation::Flush, 0, 0, 0)
            .expect("four descriptors are free");
        fx.requests
            .submit(Operation::Flush, 0, 0, 0)
            .expect("two descriptors are free");
        assert_eq!(fx.requests.in_flight(), 6);
    }

    #[test]
    fn a_full_slot_table_refuses_the_next_request_and_one_completion_frees_one_slot() {
        let mut fx = Fixture::new();
        for _ in 0..SLOTS {
            fx.requests
                .submit(Operation::Flush, 0, 0, 0)
                .expect("a flush costs two descriptors");
        }
        assert_eq!(fx.requests.in_flight(), SLOTS);
        assert_eq!(
            fx.requests.submit(Operation::Flush, 0, 0, 0),
            Err(SubmitError::NoFreeSlot)
        );

        fx.answer(VIRTIO_BLK_S_OK, 0);
        fx.requests.poll().expect("a completion");
        assert_eq!(fx.requests.in_flight(), SLOTS - 1);
        fx.requests
            .submit(Operation::Flush, 0, 0, 0)
            .expect("exactly one slot came back");
        assert_eq!(fx.requests.in_flight(), SLOTS);
    }

    #[test]
    fn every_status_byte_the_device_can_write_decodes_to_its_own_outcome() {
        for (status, outcome) in [
            (VIRTIO_BLK_S_OK, Outcome::Ok),
            (VIRTIO_BLK_S_IOERR, Outcome::DeviceError),
            (VIRTIO_BLK_S_UNSUPP, Outcome::Unsupported),
            (0xff, Outcome::UnknownStatus { status: 0xff }),
            (3, Outcome::UnknownStatus { status: 3 }),
        ] {
            let mut fx = Fixture::new();
            submit_read(&mut fx).expect("a valid read");
            fx.answer(status, SECTOR_SIZE as u32 + 1);
            let completed = fx.requests.poll().expect("a completion");
            assert_eq!(completed.outcome, outcome, "status {status:#x}");
            assert_eq!(
                completed.bytes,
                if outcome == Outcome::Ok {
                    SECTOR_SIZE as u32
                } else {
                    0
                },
                "no bytes are credited to a request the device did not complete"
            );
            let undecodable = u64::from(matches!(outcome, Outcome::UnknownStatus { .. }));
            assert_eq!(fx.requests.faults().status_undecodable, undecodable);
            assert_eq!(fx.requests.in_flight(), 0, "the slot came back either way");
        }
    }

    #[test]
    fn a_short_read_is_reported_as_short_rather_than_as_what_was_asked_for() {
        let mut fx = Fixture::new();
        fx.requests
            .submit(Operation::Read, 0, DATA_PADDR, 4 * SECTOR_SIZE as u32)
            .expect("a valid read");
        // One sector of data plus the status byte.
        fx.answer(VIRTIO_BLK_S_OK, SECTOR_SIZE as u32 + 1);
        assert_eq!(
            fx.requests.poll().expect("a completion").bytes,
            SECTOR_SIZE as u32
        );
    }

    #[test]
    fn a_device_over_reporting_its_read_length_is_clamped_and_counted() {
        let mut fx = Fixture::new();
        fx.requests
            .submit(Operation::Read, 0, DATA_PADDR, SECTOR_SIZE as u32)
            .expect("a valid read");
        // Far more than the chain's device-writable bytes, which the virtqueue
        // clamps before this layer ever sees it.
        fx.answer(VIRTIO_BLK_S_OK, u32::MAX);
        assert_eq!(
            fx.requests.poll().expect("a completion").bytes,
            SECTOR_SIZE as u32,
            "a caller may never be told more bytes are valid than it asked for"
        );
        assert_eq!(
            fx.requests.faults().device.completion_length_over_reported,
            1
        );
    }

    #[test]
    fn a_completion_naming_a_descriptor_that_was_never_posted_is_refused() {
        let mut fx = Fixture::new();
        submit_read(&mut fx).expect("a valid read");
        // The head is 0; every other index names a descriptor this driver
        // published nothing on, and 99 names none at all.
        for forged in [5u32, 12, 99, u32::MAX] {
            fx.device.complete(forged, 512);
        }
        assert!(fx.requests.poll().is_none());
        assert_eq!(fx.requests.in_flight(), 1, "the real request is untouched");
        let faults = fx.requests.faults();
        assert_eq!(faults.device.completion_out_of_range, 2, "99 and u32::MAX");
        assert_eq!(faults.device.completion_not_posted, 2, "5 and 12");
        assert_eq!(faults.completion_unmapped, 0, "the queue refused them all");
    }

    #[test]
    fn a_replayed_completion_cannot_complete_one_request_twice() {
        let mut fx = Fixture::new();
        submit_read(&mut fx).expect("a valid read");
        let head = fx.answer(VIRTIO_BLK_S_OK, SECTOR_SIZE as u32 + 1);
        fx.requests.poll().expect("the first completion");

        fx.device.complete(u32::from(head), SECTOR_SIZE as u32 + 1);
        assert!(fx.requests.poll().is_none(), "the replay is refused");
        assert_eq!(fx.requests.faults().device.completion_not_posted, 1);
        assert_eq!(fx.requests.in_flight(), 0);
    }

    #[test]
    fn a_status_written_before_the_completion_changes_nothing_until_one_arrives() {
        let mut fx = Fixture::new();
        submit_read(&mut fx).expect("a valid read");
        // The device scribbles a success into the status area and stops there.
        fx.write_status(DMA_PADDR + STATUS_AREA_OFFSET as u64, VIRTIO_BLK_S_OK);
        assert!(fx.requests.poll().is_none(), "no completion was published");
        assert_eq!(fx.requests.in_flight(), 1);

        // And when it does complete, the byte it wrote earlier is the one read.
        fx.answer(VIRTIO_BLK_S_IOERR, SECTOR_SIZE as u32 + 1);
        assert_eq!(
            fx.requests.poll().expect("a completion").outcome,
            Outcome::DeviceError
        );
    }

    #[test]
    fn a_device_that_never_completes_costs_the_slot_and_nothing_else() {
        let mut fx = Fixture::new();
        for _ in 0..SLOTS {
            fx.requests
                .submit(Operation::Flush, 0, 0, 0)
                .expect("a flush costs two descriptors");
        }
        for _ in 0..64 {
            assert!(fx.requests.poll().is_none());
        }
        assert_eq!(fx.requests.in_flight(), SLOTS, "the accounting is unmoved");
        assert_eq!(fx.requests.faults(), RequestFaults::default());
    }

    #[test]
    fn a_completion_this_layer_holds_no_request_for_is_a_driver_fault() {
        // The queue cannot produce this: it refuses a completion for a
        // descriptor it did not post. Reaching an empty attribution map takes a
        // driver attaching to a virtqueue that already carried traffic — a
        // wiring defect, which is exactly what the counter names.
        let region = MappedRegion::zeroed();
        let base = region.base();
        // SAFETY: page-aligned, zeroed, larger than the layout, and live until
        // this function returns, which nothing derived here outlives.
        let mut queue = unsafe { BlkVirtqueue::new(base) };
        let head = queue
            .add_readable(DATA_PADDR, 16)
            .expect("a free descriptor");
        let mut device = RingDevice {
            region: base,
            last_avail: 0,
            used_idx: 0,
        };
        device.complete(u32::from(head), 0);

        // SAFETY: the same region and the queue built over it, at the physical
        // address the fixture pretends it has; the allocation outlives this
        // value.
        let mut requests = unsafe { Requests::attach(base, DMA_PADDR, queue, CAPACITY) };
        assert!(requests.poll().is_none());
        assert_eq!(requests.faults().completion_unmapped, 1);
        assert_eq!(requests.in_flight(), 0);
    }

    #[test]
    fn a_token_never_names_a_later_request_in_the_same_slot() {
        let mut fx = Fixture::new();
        let first = fx
            .requests
            .submit(Operation::Flush, 0, 0, 0)
            .expect("a flush");
        fx.answer(VIRTIO_BLK_S_OK, 0);
        let completed = fx.requests.poll().expect("a completion");
        assert_eq!(completed.token, first);

        let second = fx
            .requests
            .submit(Operation::Flush, 0, 0, 0)
            .expect("the slot came back");
        assert_ne!(
            second, completed.token,
            "the reissued slot is a different request"
        );
        fx.answer(VIRTIO_BLK_S_OK, 0);
        assert_eq!(fx.requests.poll().expect("a completion").token, second);
    }

    #[test]
    fn the_capacity_a_driver_was_brought_up_against_is_what_it_bounds_against() {
        let fx = Fixture::with_capacity(7);
        assert_eq!(fx.requests.capacity_sectors(), 7);
        // A device claiming nothing refuses every data request and still
        // accepts a flush, which addresses no range.
        let mut empty = Fixture::with_capacity(0);
        assert_eq!(
            submit_read(&mut empty),
            Err(SubmitError::OutsideCapacity {
                sector: 0,
                sectors: 1,
                capacity: 0,
            })
        );
        empty
            .requests
            .submit(Operation::Flush, 0, 0, 0)
            .expect("a flush needs no capacity");
    }

    #[test]
    fn the_header_image_is_the_wire_layout_and_not_a_rust_struct() {
        let mut image = [0xaau8; RequestHeader::LEN];
        RequestHeader::new(Operation::Write, 0x0102_0304_0506_0708).write_into(&mut image);
        assert_eq!(
            image,
            [1, 0, 0, 0, 0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1],
            "little-endian type, zero reserved, little-endian sector"
        );
        assert_eq!(
            RequestHeader::new(Operation::Read, 0),
            RequestHeader::new(Operation::Read, 0)
        );
    }

    /// One step a property test may take against the driver.
    #[derive(Clone, Copy, Debug)]
    enum Step {
        Submit(Operation, u64, u32),
        /// Answer the oldest outstanding request with this status.
        Answer(u8, u32),
        /// Publish a completion for an arbitrary descriptor index.
        Forge(u32, u32),
        Poll,
    }

    fn operation() -> impl Strategy<Value = Operation> {
        prop_oneof![
            Just(Operation::Read),
            Just(Operation::Write),
            Just(Operation::Flush),
        ]
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            4 => (operation(), 0u64..2100, prop_oneof![Just(512u32), Just(1024), Just(0), Just(513), any::<u32>()])
                .prop_map(|(op, sector, len)| Step::Submit(op, sector, len)),
            3 => (any::<u8>(), any::<u32>()).prop_map(|(status, len)| Step::Answer(status, len)),
            1 => (any::<u32>(), any::<u32>()).prop_map(|(head, len)| Step::Forge(head, len)),
            4 => Just(Step::Poll),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// Arbitrary submits, arbitrary device answers and forged completions
        /// in any order: the driver must never panic, and its slot accounting
        /// must stay exact — as many requests in flight as were accepted and
        /// not completed, and no slot held by two of them at once.
        #[test]
        fn slot_accounting_survives_arbitrary_submission_and_misbehaviour(
            steps in prop::collection::vec(step(), 1..48),
        ) {
            let mut fx = Fixture::new();
            let mut submitted = 0usize;
            let mut completed = 0usize;
            let mut live: BTreeSet<Token> = BTreeSet::new();
            for step in steps {
                match step {
                    Step::Submit(operation, sector, len) => {
                        if let Ok(token) = fx.requests.submit(operation, sector, DATA_PADDR, len) {
                            submitted += 1;
                            prop_assert!(live.insert(token), "a slot was handed out twice");
                        }
                    }
                    Step::Answer(status, len) => {
                        if let Some(head) = fx.device.next_avail() {
                            fx.scribble_statuses(status);
                            fx.device.complete(u32::from(head), len);
                        }
                    }
                    Step::Forge(head, len) => fx.device.complete(head, len),
                    Step::Poll => {
                        if let Some(done) = fx.requests.poll() {
                            completed += 1;
                            prop_assert!(live.remove(&done.token), "a completion named no live request");
                        }
                    }
                }
                prop_assert_eq!(fx.requests.in_flight(), submitted - completed);
                prop_assert_eq!(fx.requests.in_flight(), live.len());
                prop_assert!(fx.requests.in_flight() <= SLOTS);
            }
        }

        /// A sector range is either refused or lies wholly inside the device.
        /// Never accepted and out of range: the capacity is the device's own
        /// claim and this bound is the only thing between a caller and the
        /// medium's end.
        #[test]
        fn an_accepted_range_always_lies_inside_the_device(
            sector in any::<u64>(),
            len in any::<u32>(),
            capacity in any::<u64>(),
            write in any::<bool>(),
        ) {
            let mut fx = Fixture::with_capacity(capacity);
            let operation = if write { Operation::Write } else { Operation::Read };
            match fx.requests.submit(operation, sector, DATA_PADDR, len) {
                Ok(_) => {
                    prop_assert!(len > 0);
                    prop_assert!(len.is_multiple_of(SECTOR_SIZE as u32));
                    let sectors = u64::from(len) / SECTOR_SIZE as u64;
                    let end = sector.checked_add(sectors).expect("an accepted end is representable");
                    prop_assert!(end <= capacity);
                }
                Err(SubmitError::LengthZero) => prop_assert_eq!(len, 0),
                Err(SubmitError::LengthNotSectorMultiple { len: refused }) => {
                    prop_assert_eq!(refused, len);
                    prop_assert!(!len.is_multiple_of(SECTOR_SIZE as u32));
                }
                Err(SubmitError::OutsideCapacity { sector: s, sectors, capacity: c }) => {
                    prop_assert_eq!(s, sector);
                    prop_assert_eq!(c, capacity);
                    prop_assert!(sector.checked_add(sectors).is_none_or(|end| end > capacity));
                }
                Err(other) => prop_assert!(false, "an aligned buffer was refused as {:?}", other),
            }
        }

        /// Whatever byte the device leaves in the status area, the completion
        /// decodes to exactly one outcome, credits bytes only for a success,
        /// and never panics.
        #[test]
        fn any_status_byte_decodes_to_a_defined_outcome(
            status in any::<u8>(),
            reported in any::<u32>(),
            sectors in 1u32..4,
        ) {
            let mut fx = Fixture::new();
            let len = sectors * SECTOR_SIZE as u32;
            fx.requests.submit(Operation::Read, 0, DATA_PADDR, len).expect("a valid read");
            fx.answer(status, reported);
            let completed = fx.requests.poll().expect("a completion");
            let expected = match status {
                VIRTIO_BLK_S_OK => Outcome::Ok,
                VIRTIO_BLK_S_IOERR => Outcome::DeviceError,
                VIRTIO_BLK_S_UNSUPP => Outcome::Unsupported,
                status => Outcome::UnknownStatus { status },
            };
            prop_assert_eq!(completed.outcome, expected);
            prop_assert!(completed.bytes <= len);
            if expected != Outcome::Ok {
                prop_assert_eq!(completed.bytes, 0);
            }
            prop_assert_eq!(fx.requests.in_flight(), 0);
        }
    }

    // `Token` is ordered only so a property test can hold the live set in a
    // `BTreeSet`; the production API needs equality alone.
    impl PartialOrd for Token {
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for Token {
        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            (self.slot.0, self.generation).cmp(&(other.slot.0, other.generation))
        }
    }
}
