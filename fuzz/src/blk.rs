//! `lfw_blk::request` and `lfw_blk::io` under a hostile or malfunctioning block
//! device.
//!
//! # The adversary and the surface
//!
//! A **hostile or malfunctioning device**, and it owns more here
//! than on a NIC. The DMA region carries this driver's virtqueue *and* the
//! per-slot request headers *and* the per-slot status bytes, and the device can
//! write every byte of all three — the status byte legitimately, the rest by
//! misbehaving. Two of those bytes are the ones worth naming: the used-ring
//! index decides which slot's status byte is read, and the status byte decides
//! whether a caller believes its request succeeded.
//!
//! The staging window is the device's too, in the direction that matters: a
//! read is the device writing it. Nothing in this harness asserts anything
//! about its *contents*, because nothing in the driver reads them — that is the
//! property, and it is asserted by the region being scribbled freely below and
//! changing no outcome.
//!
//! # What the adversary may express
//!
//! * **Any byte of the DMA region, at any point in the stream** — the
//!   descriptor table, the available ring, the used ring, the headers this
//!   driver wrote, and the status bytes.
//! * **Any completion**: a full unreduced `u32` id and a full `u32` length, so
//!   forged ids, out-of-range ids, replays of a slot already reaped, echoes of
//!   one never posted, and byte counts far above what any chain could hold.
//! * **Any used index**, published as one 16-bit store, so the device chooses
//!   how many completions it claims rather than the fuzzer choosing which half
//!   of the index landed first.
//! * **Any status byte**, including the 253 the specification does not define.
//! * **Any capacity**, taken once at attach, including zero and `u64::MAX` —
//!   the number every sector range a caller names is judged against.
//!
//! The *caller* is not an adversary — it is the protection domain — but its
//! requests are generated just as freely, because the range it names is checked
//! against a capacity that came from the device, and a driver that trusted
//! either would let a sum wrap past the medium.
//!
//! # What is asserted
//!
//! Not merely the absence of a panic. Against an independent model:
//!
//! * **Slot conservation.** `in_flight()` equals the number of submits accepted
//!   minus the number of completions delivered, always, and never exceeds
//!   `SLOTS`. A driver that leaked a slot would stop accepting work after eight
//!   requests, and a driver that freed one twice would hand two live requests
//!   the same status byte.
//! * **Every accepted range lies inside the capacity**, with no wrap: the model
//!   recomputes the bound in `u128` and refuses to accept an acceptance the
//!   arithmetic does not support.
//! * **Every delivered completion is attributed to a request that was
//!   outstanding**, and to that request's operation — never to one already
//!   reaped, which is what a replay would produce.
//! * **The reported byte count is bounded by what was submitted**, and is
//!   exactly what the protocol allows for the operation: a write and a flush
//!   have nothing partial to report, so an over-reported length cannot become
//!   one.
//! * **Fault counters only rise**, so a device flooding the queue with rubbish
//!   remains visible to an operator differencing two scrapes rather than
//!   wrapping to a small number.

use arbitrary::Unstructured;
use lfw_blk::io::{IoRegion, IoSector};
use lfw_blk::request::SLOTS;
use lfw_blk::request::{Completed, Operation, Outcome, RequestFaults, Requests, SubmitError};
use lfw_blk::{BlkVirtqueue, DMA_REGION_SIZE, QUEUE_SIZE, SECTOR_SIZE, io::IO_SECTORS};

use crate::region::{BlkIoRegion, DmaRegion};

/// Operations one input may drive. Bounded so a single input cannot run for
/// unbounded time; the interesting interleavings are short.
const MAX_OPERATIONS: usize = 512;

/// The physical addresses the two regions claim. Page-aligned and far apart, so
/// an address computed against the wrong base is a wild number rather than an
/// offset that lands somewhere plausible.
const DMA_PADDR: u64 = 0x4000_0000;
const IO_PADDR: u64 = 0x6000_0000;

/// What this harness remembers about one outstanding request, kept outside the
/// region so no part of it is a value the device can rewrite — the same
/// discipline the driver itself keeps.
#[derive(Clone, Copy)]
struct Outstanding {
    operation: Operation,
    data_len: u32,
}

/// The far side of the ring: it writes wherever the fuzzer says, including into
/// the driver's own bookkeeping.
struct Device {
    base: *mut u8,
    used_idx: u16,
}

impl Device {
    /// # Safety
    /// `base` must be a live mapping of at least [`DMA_REGION_SIZE`] bytes that
    /// outlives this value and is shared with nothing but the queue over it.
    const unsafe fn new(base: *mut u8) -> Self {
        Self { base, used_idx: 0 }
    }

    /// Write one arbitrary byte anywhere in the region.
    fn scribble(&self, offset: usize, value: u8) {
        let at = offset % DMA_REGION_SIZE;
        // SAFETY: `at` is reduced modulo the region size, so it names a byte of
        // the live region `new`'s contract guarantees; a `u8` needs no
        // alignment.
        unsafe { self.base.add(at).write_volatile(value) };
    }

    /// Publish a used-ring entry naming any descriptor and any length.
    fn complete(&mut self, id: u32, len: u32) {
        let used = BlkVirtqueue::LAYOUT.device_offset;
        let slot = self.used_idx as usize % QUEUE_SIZE;
        // SAFETY: the device ring lies inside the live region and the slot is
        // reduced modulo the queue size, so both stores land within it; each is
        // naturally aligned, the ring being 4-byte aligned by the layout.
        unsafe {
            self.base
                .add(used + 4 + slot * 8)
                .cast::<u32>()
                .write_volatile(id);
            self.base
                .add(used + 8 + slot * 8)
                .cast::<u32>()
                .write_volatile(len);
        }
        self.used_idx = self.used_idx.wrapping_add(1);
        self.publish(self.used_idx);
    }

    /// Claim any number of completions, published as the device would.
    fn publish(&self, index: u16) {
        // SAFETY: the used-ring index lies inside the live region and is
        // 2-byte aligned by the layout.
        unsafe {
            self.base
                .add(BlkVirtqueue::LAYOUT.device_offset + 2)
                .cast::<u16>()
                .write_volatile(index);
        }
    }
}

fn any_u8(unstructured: &mut Unstructured<'_>) -> u8 {
    unstructured.arbitrary().unwrap_or(0)
}

fn any_u32(unstructured: &mut Unstructured<'_>) -> u32 {
    unstructured.arbitrary().unwrap_or(0)
}

fn any_u64(unstructured: &mut Unstructured<'_>) -> u64 {
    unstructured.arbitrary().unwrap_or(0)
}

/// Whether an operation carries a data segment. `Operation::has_data` is
/// `lfw_blk`'s own and private, so the model states it independently — which is
/// what a model is for: a harness that asked the code under test would be
/// asserting it agrees with itself.
const fn has_data(operation: Operation) -> bool {
    matches!(operation, Operation::Read | Operation::Write)
}

/// Whether the range `sector..sector + len/SECTOR_SIZE` is one the driver may
/// accept, computed independently and in a width that cannot wrap.
fn range_is_inside(sector: u64, len: u32, capacity: u64) -> bool {
    if len == 0 || !len.is_multiple_of(SECTOR_SIZE as u32) {
        return false;
    }
    let sectors = u128::from(len) / SECTOR_SIZE as u128;
    u128::from(sector) + sectors <= u128::from(capacity)
}

/// Every counter in `faults` is at least the corresponding one in `earlier`.
fn faults_only_rise(earlier: RequestFaults, now: RequestFaults) {
    assert!(now.status_undecodable >= earlier.status_undecodable);
    assert!(now.completion_unmapped >= earlier.completion_unmapped);
    assert!(now.device.completion_out_of_range >= earlier.device.completion_out_of_range);
    assert!(now.device.completion_not_posted >= earlier.device.completion_not_posted);
    assert!(
        now.device.completion_length_over_reported
            >= earlier.device.completion_length_over_reported
    );
}

/// What the protocol allows a completion of `operation` to report, given what
/// was submitted.
fn expected_bytes(completed: &Completed, submitted: u32) -> u32 {
    if completed.outcome != Outcome::Ok {
        return 0;
    }
    match completed.operation {
        // A read is the one case a short count carries information, so anything
        // from zero to what was asked for is admissible — and nothing above it.
        Operation::Read => completed.bytes,
        // Neither has a partial acknowledgement in the protocol, so the driver
        // must report exactly what was submitted and never the device's claim.
        Operation::Write => submitted,
        Operation::Flush => 0,
    }
}

/// Drive the block request state machine against a device that owns every byte
/// of the region it shares with it.
pub fn blk_requests_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let dma = DmaRegion::zeroed();
    let base = dma.as_ptr().cast::<u8>();
    const {
        assert!(
            BlkVirtqueue::LAYOUT.total_bytes <= DMA_REGION_SIZE,
            "the backing region is smaller than the queue layout requires"
        )
    };

    // The capacity is the device's own claim and is taken once, so every value
    // it could report — zero, one, `u64::MAX` — is an ordinary input here.
    let capacity = any_u64(&mut unstructured);

    // SAFETY: `base` is a live, zeroed, 16-byte-aligned region larger than
    // `LAYOUT.total_bytes` (asserted above), outliving both values below and
    // shared with nothing but the `Device` this queue belongs to — exactly
    // `SplitVirtqueue::new`'s contract.
    let queue = unsafe { BlkVirtqueue::new(base) };
    // SAFETY: the same region, at the address this harness claims for it; the
    // queue was built over this very pointer, and `DMA_PADDR + DMA_REGION_SIZE`
    // does not overflow.
    let mut requests = unsafe { Requests::attach(base, DMA_PADDR, queue, capacity) };
    // SAFETY: the same discipline for the staging window: a live, page-aligned
    // region of `BLK_IO_REGION_SIZE` bytes that outlives the value.
    let mut device = unsafe { Device::new(base) };

    let staging = BlkIoRegion::zeroed();
    // SAFETY: a live, page-aligned mapping of `BLK_IO_REGION_SIZE` bytes,
    // outliving this value and reached through this one pointer alone.
    let mut io = unsafe { IoRegion::attach(staging.as_ptr().cast::<u8>(), IO_PADDR) }
        .expect("a page-aligned, non-wrapping base");

    // The model: what this harness believes is outstanding, keyed by the token
    // the driver minted rather than by a slot the device could name.
    let mut outstanding: Vec<(lfw_blk::request::Token, Outstanding)> = Vec::new();
    let mut faults = requests.faults();

    for _ in 0..MAX_OPERATIONS {
        let Ok(op) = unstructured.arbitrary::<u8>() else {
            break;
        };
        assert!(
            requests.in_flight() == outstanding.len(),
            "the driver and the model disagree on how much is outstanding"
        );
        assert!(requests.in_flight() <= SLOTS, "more slots live than exist");

        match op % 6 {
            // Submit, with every parameter the caller controls taken freely.
            0 | 1 | 2 => {
                let operation = match op % 3 {
                    0 => Operation::Read,
                    1 => Operation::Write,
                    _ => Operation::Flush,
                };
                let sector = any_u64(&mut unstructured);
                let len = any_u32(&mut unstructured);
                // Half the time the data address is a real staging sector and
                // half the time it is whatever the fuzzer says, so both the
                // accepted and the refused shapes are reachable.
                let data_paddr = if any_u8(&mut unstructured) % 2 == 0 {
                    let sector = IoSector::new(any_u32(&mut unstructured) as usize % IO_SECTORS)
                        .expect("reduced into range");
                    io.sector_paddr(sector)
                } else {
                    any_u64(&mut unstructured)
                };
                let before = requests.in_flight();
                match requests.submit(operation, sector, data_paddr, len) {
                    Ok(token) => {
                        assert_eq!(
                            requests.in_flight(),
                            before + 1,
                            "an accepted submit did not take exactly one slot"
                        );
                        let data_len = if has_data(operation) { len } else { 0 };
                        if has_data(operation) {
                            assert!(
                                range_is_inside(sector, len, capacity),
                                "a range outside the medium was accepted: \
                                 sector {sector}, len {len}, capacity {capacity}"
                            );
                            assert!(
                                data_paddr != 0
                                    && data_paddr.is_multiple_of(SECTOR_SIZE as u64)
                                    && data_paddr.checked_add(u64::from(len)).is_some(),
                                "an unusable data address was accepted: {data_paddr:#x}"
                            );
                        }
                        outstanding.push((
                            token,
                            Outstanding {
                                operation,
                                data_len,
                            },
                        ));
                    }
                    Err(error) => {
                        assert_eq!(
                            requests.in_flight(),
                            before,
                            "a refused submit consumed a slot"
                        );
                        // Backpressure is the only refusal that says nothing
                        // about the request; every other one must be a request
                        // the model also refuses.
                        if !matches!(error, SubmitError::NoFreeSlot | SubmitError::QueueFull)
                            && has_data(operation)
                        {
                            assert!(
                                !range_is_inside(sector, len, capacity)
                                    || data_paddr == 0
                                    || !data_paddr.is_multiple_of(SECTOR_SIZE as u64)
                                    || data_paddr.checked_add(u64::from(len)).is_none(),
                                "a usable request was refused as {error:?}"
                            );
                        }
                    }
                }
            }
            // Reap one completion.
            3 => {
                let before = requests.in_flight();
                if let Some(completed) = requests.poll() {
                    assert_eq!(
                        requests.in_flight(),
                        before - 1,
                        "a completion freed something other than one slot"
                    );
                    let at = outstanding
                        .iter()
                        .position(|(token, _)| *token == completed.token)
                        .expect("a completion naming a request that is not outstanding");
                    let (_, posted) = outstanding.remove(at);
                    assert_eq!(
                        completed.operation, posted.operation,
                        "a completion changed the operation of the request it answered"
                    );
                    assert!(
                        completed.bytes <= posted.data_len,
                        "a completion reported {} bytes for a {}-byte request",
                        completed.bytes,
                        posted.data_len
                    );
                    assert_eq!(
                        completed.bytes,
                        expected_bytes(&completed, posted.data_len),
                        "a completion reported bytes the protocol does not allow"
                    );
                } else {
                    assert_eq!(
                        requests.in_flight(),
                        before,
                        "a poll that answered nothing freed a slot"
                    );
                }
            }
            // Scribble one byte of the shared region, anywhere.
            4 => {
                let offset = any_u32(&mut unstructured) as usize;
                device.scribble(offset, any_u8(&mut unstructured));
            }
            // Publish a completion, or forge the used index outright.
            _ => {
                if any_u8(&mut unstructured) % 4 == 0 {
                    device.publish(any_u32(&mut unstructured) as u16);
                } else {
                    device.complete(any_u32(&mut unstructured), any_u32(&mut unstructured));
                }
                // A staging write between completions, to show that what the
                // driver does with a completion does not depend on the payload.
                let sector = IoSector::new(any_u32(&mut unstructured) as usize % IO_SECTORS)
                    .expect("reduced into range");
                io.put(sector, &[any_u8(&mut unstructured); SECTOR_SIZE]);
            }
        }

        let now = requests.faults();
        faults_only_rise(faults, now);
        faults = now;
    }

    assert!(requests.in_flight() <= SLOTS);
    assert_eq!(requests.in_flight(), outstanding.len());
    assert_eq!(requests.capacity_sectors(), capacity);
}
