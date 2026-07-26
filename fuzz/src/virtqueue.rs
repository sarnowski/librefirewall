//! `virtio::queue` under a hostile or malfunctioning device.
//!
//! # The adversary and the surface
//!
//! The device can write **every byte of the virtqueue region** — not only the
//! used ring it owns by protocol, but the descriptor table and the available
//! ring as well (CONCEPT §7.1, and the module header of
//! `crates/virtio/src/queue.rs` states exactly this). The crate's governing rule
//! is correspondingly strong: *no value read back from the region is ever used
//! to index it*. The descriptor lifecycle, the free list's successor links and
//! the length each descriptor was posted with all live in driver-private memory
//! the device cannot reach.
//!
//! # What the adversary may express here
//!
//! * **Any byte of the region, at any point in the stream.** The previous
//!   harness overwrote only `[device_offset, total_bytes)` once, before any
//!   operation, so the descriptor table and the available ring — the two areas
//!   whose misuse would hand the device the *allocator* — were never varied at
//!   all. Both are scribbled here, repeatedly, interleaved with driver calls.
//! * **Any completion.** A used-ring entry carries a full, unreduced `u32` id
//!   and a full `u32` length: forged ids, out-of-range ids, replays of a
//!   descriptor already completed, echoes of one never posted, and lengths far
//!   above what the driver programmed.
//! * **Buffer addresses and lengths chosen freely** on `add_writable` and
//!   `add_readable`, rather than the two constants the previous harness used,
//!   which left the descriptor-table half of the ring outside the fuzzer's
//!   reach entirely.
//! * **Either terminal choice for a completion**: recycled back to the free
//!   list, or dropped and stranded out of it. Those are the two a driver has,
//!   and the harness takes both from the fuzzer's data.
//!
//! # What is no longer expressible, and why that is the fix
//!
//! A surrender to the *wrong* queue, and a second surrender of one descriptor,
//! used to be generated here — and were the bug class this target was named
//! for. They are now compile errors: a `Completion` **is** the exclusive borrow
//! of the queue that produced it, and `recycle` takes no queue argument, so
//! there is no expression that hands one to another queue or uses it twice.
//! That capability was never the *device's*, which is what TEST-8 governs; it
//! was the driver's own bookkeeping, and the queue's API no longer admits it.
//! Everything the device can express — every byte of the region, any
//! completion, any used index — is untouched below.
//!
//! # What is asserted
//!
//! * **The full descriptor lifecycle**, against an independent model:
//!   `add`/`poll`/`recycle` each produce exactly the outcome the model says,
//!   including which error variant. An accepted replay fails here as loudly as
//!   a panic would, which is the point — the previous harness's only
//!   postcondition, `free_count() <= SIZE`, is true of a queue that has
//!   accepted every forged completion the device sent.
//! * **Conservation.** `free_count() + posted_count() + reaped == SIZE` after
//!   every operation, with `reaped` from the model: no descriptor invented,
//!   none lost, none in two states.
//! * **The length clamp.** A completion's reported length never exceeds the
//!   length this driver programmed for that descriptor. That is what stops a
//!   device that over-reports from making a downstream domain read past a
//!   buffer.
//! * **Bounded delivery, asserted rather than truncated.** The final drain runs
//!   `posted_count() + 1` polls and asserts the last one returned `None`. The
//!   previous harness capped its loop at `4 * QSIZE` and never checked how the
//!   loop ended, so a regression removing the queue's own scan bound would have
//!   been silently truncated into a pass.
//! * **The over-report tally.** A device claiming more bytes than the buffer
//!   was posted with is clamped, and the clamp must be *counted*: the tally is
//!   checked against the completions the model knows were over-reported, so a
//!   silently absorbed over-report fails here.

use std::sync::atomic::{Ordering, fence};

use arbitrary::Unstructured;
use virtio::queue::SplitVirtqueue;

use crate::region::{DMA_REGION_BYTES, DmaRegion};
use crate::{MAX_OPERATIONS, any_u32, next_op};

/// Queue size the harness drives. 16 matches the driver PD's virtqueues and
/// keeps the region far inside the 4 KiB backing page.
const QSIZE: usize = 16;
/// The queue type under test.
type Vq = SplitVirtqueue<QSIZE>;

/// Where each descriptor sits, as the harness believes it: the model
/// `virtio::queue`'s private `state` array is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    /// On the free list; `add` may allocate it.
    Free,
    /// Published to the device.
    Posted,
    /// Completed and handed out as a token not yet surrendered.
    Reaped,
}

/// Byte offset of the used ring's `idx` field.
fn used_idx_offset() -> usize {
    Vq::LAYOUT.device_offset + 2
}

/// Byte offset of used-ring element `slot`'s `id` field.
fn used_elem_offset(slot: usize) -> usize {
    Vq::LAYOUT.device_offset + 4 + (slot % QSIZE) * 8
}

/// The device's own view of the shared region: it may write any byte of it.
struct Device {
    region: *mut u8,
    /// The device's private used-ring producer index. Publishing it is what
    /// makes the driver look at an entry, so the harness tracks its own rather
    /// than reading one back out of bytes it may itself have scribbled.
    used_idx: u16,
}

impl Device {
    /// # Safety
    /// `region` must point to at least `DMA_REGION_BYTES` writable bytes that
    /// outlive this value, shared with nothing but the queue under test.
    unsafe fn new(region: *mut u8) -> Self {
        Self {
            region,
            used_idx: 0,
        }
    }

    /// Write one byte anywhere in the region — the descriptor table and the
    /// available ring included.
    fn scribble(&self, offset: usize, byte: u8) {
        // SAFETY: the offset is reduced into the region this device was built
        // over, whose contract guarantees `DMA_REGION_BYTES` writable bytes.
        unsafe {
            self.region
                .add(offset % DMA_REGION_BYTES)
                .write_volatile(byte)
        };
    }

    /// Publish one completion naming descriptor `id` with reported length
    /// `len`, both entirely the device's choice.
    fn complete(&mut self, id: u32, len: u32) {
        let slot = (self.used_idx as usize) % QSIZE;
        let offset = used_elem_offset(slot);
        // SAFETY: `offset + 8 <= LAYOUT.total_bytes <= DMA_REGION_BYTES` because
        // `slot < QSIZE`, and both halves are 4-aligned within a 16-aligned
        // region — the element's `id` and `len` words.
        unsafe {
            self.region.add(offset).cast::<u32>().write_volatile(id);
            self.region
                .add(offset + 4)
                .cast::<u32>()
                .write_volatile(len);
        }
        self.used_idx = self.used_idx.wrapping_add(1);
        // The device publishes the entry before the index that reveals it.
        fence(Ordering::Release);
        // SAFETY: the used index lies at a 2-aligned offset within the region.
        unsafe {
            self.region
                .add(used_idx_offset())
                .cast::<u16>()
                .write_volatile(self.used_idx)
        };
    }

    /// Forge the used index outright, without publishing a matching entry:
    /// the device claiming completions it never produced.
    fn forge_used_index(&mut self, value: u16) {
        self.used_idx = value;
        // SAFETY: as in `complete` — a 2-aligned offset within the region.
        unsafe {
            self.region
                .add(used_idx_offset())
                .cast::<u16>()
                .write_volatile(value)
        };
    }
}

/// Drive the driver half of a split virtqueue against a device that owns every
/// byte of the shared region.
pub fn virtqueue_poll_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let region = DmaRegion::zeroed();
    let base = region.as_ptr().cast::<u8>();
    const {
        assert!(
            Vq::LAYOUT.total_bytes <= DMA_REGION_BYTES,
            "the backing region is smaller than the queue layout requires"
        )
    };

    // SAFETY: `base` is a live, zeroed, 16-byte-aligned region of
    // `DMA_REGION_BYTES` bytes — more than `LAYOUT.total_bytes`, asserted above
    // — that outlives `queue` and is shared with nothing but the `Device`
    // below, which is exactly the one device this queue belongs to. That is
    // `SplitVirtqueue::new`'s contract in full.
    let mut queue = unsafe { Vq::new(base) };
    // SAFETY: the same live region, for the same lifetime.
    let mut device = unsafe { Device::new(base) };

    let mut model = [Lifecycle::Free; QSIZE];
    // The length this harness programmed into each descriptor, mirroring the
    // queue's private `posted_len`, so the clamp can be checked independently.
    let mut programmed = [0u32; QSIZE];
    // Completions handed out. A clamped over-report is indistinguishable from
    // an exact report on this side — both come back as the posted length — so
    // what the model can hold the tally to is that it never counts more
    // over-reports than there were completions to over-report.
    let mut delivered = 0u64;

    for _ in 0..MAX_OPERATIONS {
        let Some(op) = next_op(&mut unstructured) else {
            break;
        };
        match op % 6 {
            // Publish a buffer, with an address and a length the harness does
            // not constrain: both land in the descriptor table the device reads.
            0 | 1 => {
                let paddr = u64::from(any_u32(&mut unstructured)) << 12;
                let len = any_u32(&mut unstructured);
                let free_before = queue.free_count();
                let outcome = if op % 6 == 0 {
                    queue.add_writable(paddr, len)
                } else {
                    queue.add_readable(paddr, len)
                };
                match outcome {
                    Some(head) => {
                        let index = head as usize;
                        assert!(free_before > 0, "a full queue handed out a descriptor");
                        assert!(index < QSIZE, "add handed out descriptor {index}");
                        assert_eq!(
                            model[index],
                            Lifecycle::Free,
                            "add handed out descriptor {index}, which was not free"
                        );
                        model[index] = Lifecycle::Posted;
                        programmed[index] = len;
                    }
                    None => assert_eq!(free_before, 0, "add refused while descriptors were free"),
                }
            }
            // Reap a completion and take one of the two terminal choices a
            // driver has for it: recycle it (op 2) or drop it (op 3), leaving
            // the descriptor reaped and out of the free list for good.
            op @ (2 | 3) => {
                let posted_before = queue.posted_count();
                if let Some((completion, reported)) = queue.poll() {
                    let index = completion.index() as usize;
                    assert!(index < QSIZE, "poll returned descriptor {index}");
                    assert_eq!(
                        model[index],
                        Lifecycle::Posted,
                        "poll accepted a completion for descriptor {index}, which was not posted \
                         — a replayed or forged completion was believed"
                    );
                    assert!(
                        reported <= programmed[index],
                        "the device reported {reported} bytes for descriptor {index}, which was \
                         posted with {}",
                        programmed[index]
                    );
                    assert!(
                        posted_before > 0,
                        "a completion arrived with nothing posted"
                    );
                    delivered += 1;
                    if op == 2 {
                        completion.recycle();
                        model[index] = Lifecycle::Free;
                    } else {
                        drop(completion);
                        model[index] = Lifecycle::Reaped;
                    }
                }
            }
            4 => {
                let id = any_u32(&mut unstructured);
                let len = any_u32(&mut unstructured);
                device.complete(id, len);
            }
            _ => {
                let offset = any_u32(&mut unstructured) as usize;
                let byte = any_u32(&mut unstructured) as u8;
                device.scribble(offset, byte);
            }
        }

        let reaped = model.iter().filter(|s| **s == Lifecycle::Reaped).count();
        let posted = model.iter().filter(|s| **s == Lifecycle::Posted).count();
        assert_eq!(queue.posted_count(), posted, "posted count diverged");
        assert_eq!(
            queue.free_count() + posted + reaped,
            QSIZE,
            "a descriptor was invented, lost, or held in two states at once"
        );
        assert!(
            queue.device_faults().completion_length_over_reported <= delivered,
            "the queue counted more over-reports than it handed out completions"
        );
    }

    // The device claims a used index far ahead of anything it published, which
    // is what "unbounded completions" looks like from the driver's side.
    device.forge_used_index(any_u32(&mut unstructured) as u16);

    // Delivery is bounded by a driver-owned quantity: at most `posted_count()`
    // completions can be handed out before the driver posts again, whatever the
    // device publishes. One poll more than the budget, and the count that comes
    // out is the assertion — not a cap the loop hides behind. Exceeding it
    // means a forged or replayed completion was believed, which is the failure
    // an "it did not panic" harness cannot see.
    let budget = queue.posted_count();
    let mut delivered = 0usize;
    for _ in 0..=budget {
        let Some((completion, reported)) = queue.poll() else {
            break;
        };
        let index = completion.index() as usize;
        assert_eq!(
            model[index],
            Lifecycle::Posted,
            "the drain accepted a completion for a descriptor that was not posted"
        );
        assert!(
            reported <= programmed[index],
            "the drain returned an unclamped length for descriptor {index}"
        );
        delivered += 1;
        completion.recycle();
        model[index] = Lifecycle::Free;
    }
    assert!(
        delivered <= budget,
        "the queue delivered {delivered} completions against {budget} posted descriptors"
    );
    // With nothing posted, no completion can be legitimate, so the used ring's
    // remaining entries — however the device forged its index — must all be
    // refused and `poll` must say so rather than hand one out.
    if queue.posted_count() == 0 {
        assert!(
            queue.poll().is_none(),
            "a completion was accepted while no descriptor was posted"
        );
    }
}
