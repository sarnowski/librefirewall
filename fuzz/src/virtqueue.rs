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
//! * **A duplicate surrender.** This is the shape the previous harness made
//!   unreachable by construction: it guarded `recycle` behind `if held[index]`,
//!   so a `recycle` of a descriptor that was not outstanding could never be
//!   generated, and the bug class the target was named for could not be found.
//!   Here every `Token` the queue mints is retained — from `add_*` (still
//!   posted to the device) as well as from `poll` (reaped) — and any of them
//!   may be surrendered at any time, so `StillPosted` and `AlreadyFree` are
//!   both reachable and both asserted.
//! * **Buffer addresses and lengths chosen freely** on `add_writable` and
//!   `add_readable`, rather than the two constants the previous harness used,
//!   which left the descriptor-table half of the ring outside the fuzzer's
//!   reach entirely.
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
//! * **`recycle`'s result is consumed.** It returns `#[must_use]`
//!   `Result<(), RecycleError>`; the previous harness dropped it, which the
//!   fuzz workspace's missing `[lints]` reduced to a warning nobody read. Here
//!   the exact variant is asserted, and `unused_must_use` is denied in
//!   `fuzz/Cargo.toml`.

use std::sync::atomic::{Ordering, fence};

use arbitrary::Unstructured;
use virtio::queue::{RecycleError, SplitVirtqueue, Token};

use crate::region::{DMA_REGION_BYTES, DmaRegion};
use crate::{MAX_OPERATIONS, any_index, any_u32, next_op};

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
    // Every token the queue has minted and this harness has not surrendered:
    // both the posted ones from `add_*` and the reaped ones from `poll`, so a
    // surrender of either is expressible.
    let mut tokens: Vec<Token> = Vec::new();

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
                    Some(token) => {
                        let index = token.index() as usize;
                        assert!(free_before > 0, "a full queue handed out a descriptor");
                        assert!(index < QSIZE, "add handed out descriptor {index}");
                        assert_eq!(
                            model[index],
                            Lifecycle::Free,
                            "add handed out descriptor {index}, which was not free"
                        );
                        model[index] = Lifecycle::Posted;
                        programmed[index] = len;
                        tokens.push(token);
                    }
                    None => assert_eq!(free_before, 0, "add refused while descriptors were free"),
                }
            }
            2 => {
                let posted_before = queue.posted_count();
                if let Some((token, reported)) = queue.poll() {
                    let index = token.index() as usize;
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
                    model[index] = Lifecycle::Reaped;
                    tokens.push(token);
                }
            }
            // Surrender an arbitrary held token: posted or reaped, this queue's
            // or a stale one. The outcome is fully determined by the model.
            3 => {
                if tokens.is_empty() {
                    continue;
                }
                let token = tokens.remove(any_index(&mut unstructured, tokens.len()));
                let index = token.index() as usize;
                let outcome = queue.recycle(token);
                match model[index] {
                    Lifecycle::Reaped => {
                        assert_eq!(outcome, Ok(()), "recycle refused a reaped descriptor");
                        model[index] = Lifecycle::Free;
                    }
                    Lifecycle::Posted => assert_eq!(
                        outcome,
                        Err(RecycleError::StillPosted(index as u16)),
                        "recycle reclaimed a descriptor the device still owns"
                    ),
                    Lifecycle::Free => assert_eq!(
                        outcome,
                        Err(RecycleError::AlreadyFree(index as u16)),
                        "recycle accepted a second surrender of one descriptor"
                    ),
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
        let Some((token, reported)) = queue.poll() else {
            break;
        };
        let index = token.index() as usize;
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
        assert_eq!(
            queue.recycle(token),
            Ok(()),
            "recycle refused a token this drain reaped an instant earlier"
        );
        model[index] = Lifecycle::Free;
    }
    assert!(
        delivered <= budget,
        "the queue delivered {delivered} completions against {budget} posted descriptors"
    );
    // With nothing posted, no completion can be legitimate, so the used ring's
    // remaining entries — however the device forged its index — must all be
    // refused and `poll` must say so rather than mint a token.
    if queue.posted_count() == 0 {
        assert_eq!(
            queue.poll(),
            None,
            "a completion was accepted while no descriptor was posted"
        );
    }
}
