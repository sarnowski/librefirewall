//! Host-testable driver logic for the virtio-net driver protection domain:
//! device bring-up ([`bringup`]), the steady-state dataplane in this root, and
//! the poll pass that runs it ([`port`]).
//!
//! The driver PD (`pds/nic-driver`) is a thin adapter: it maps the regions the
//! system description grants it, turns the three pointers into this crate's
//! types, and runs a loop. The logic lives here instead because welded to the
//! Microkit entrypoint none of it could be reached by a host test.
//!
//! # Untrusted inputs, and which layer answers for each
//!
//! Two of CONCEPT §7.1's distrust boundaries meet in this crate, and one is
//! answered a layer below:
//!
//! - The **hostile or malfunctioning device**. Everything it can *say* about a
//!   completion — a forged or out-of-range descriptor id, a replay of one
//!   already reaped, an echo of one never published, a flood of used entries —
//!   is refused inside [`virtio::queue`] before a `Completion` exists, and
//!   counted there in [`DeviceFaults`]. This crate keeps no second copy of that
//!   check: it would be a second answer to one question, and the queue is the
//!   layer holding the descriptor lifecycle the answer is derived from. What
//!   stays this crate's business is what the queue cannot know — the reported
//!   length must be clamped to the *pool buffer* behind the descriptor before a
//!   downstream domain reads it, and a completion with nothing past the
//!   virtio-net header carries no frame.
//! - The **byzantine neighbour PD** (the peer). Every transmit descriptor
//!   it queues is range-validated ([`pd_runtime::descriptor_in_bounds`], plus
//!   header room) before the span is touched, and checked against this driver's
//!   own in-flight set so the same buffer cannot be posted to the device twice.
//!   Its verdict word is decoded, not trusted. A frame it marked against the
//!   wire still arrives here to be returned, because a return is a produce on
//!   the free ring whose single producer is this driver; without that the pool
//!   would lose a buffer per routing drop, and routing drops are ordinary
//!   traffic. Nothing below the queue guards this boundary, so it is guarded
//!   here and nowhere else.
//!
//! # What this crate cannot enforce
//!
//! Writing the virtio-net header in front of a transmit frame needs the buffer
//! to be exclusively this driver's for the duration. That is a *protocol*
//! claim, not one this domain can verify: the buffer belongs to the transmit
//! pipeline's pool, whose ledger lives in the peer driver that owns it. A
//! byzantine peer can still name a buffer the pool owner has posted as its
//! own NIC's receive DMA target, in which case the 12-byte header write races
//! that DMA. Closing that needs either an IOMMU confining NIC DMA (CONCEPT
//! §7.2) or a cross-domain per-buffer ownership epoch; neither exists yet, and
//! no code in this domain can substitute for them. The damage is bounded to
//! corrupting a frame inside the shared pool, because the address handed to the
//! device is derived from an index that passed the pool bounds check.

#![cfg_attr(not(test), no_std)]

pub mod bringup;
pub mod port;

#[cfg(test)]
mod fake_device;

use lfw_metrics::{DriverSample, LogSample, PoolSample};
use pd_runtime::PoolCounters;
use pd_runtime::{
    BUFFER_SIZE, DRAIN_LIMIT, Descriptor, ForwardRings, OwnedBuffer, POOL_BUFFERS, Pool, PoolOwner,
    RING_SLOTS, ReturnRing, RingConsumer, RingProducer, Verdict, buffer_paddr,
    descriptor_in_bounds,
};
use virtio::net::VirtioNetHdr;
use virtio::queue::{DeviceFaults, SplitVirtqueue};

// The one place that depends on both: the pipeline fixes the room, this driver fills it.
const _: () = assert!(VirtioNetHdr::LEN == pd_runtime::DEVICE_HEADER_LEN as usize);

/// The tallies a driver protection domain keeps, split by who is answerable.
///
/// The split is structural on purpose. Both halves are recorded the same way —
/// a saturating counter — so a flat struct would leave the only thing that
/// distinguishes "the network is hostile" from "we have a bug" to prose. Here
/// the type carries it, and an alert can be written against
/// [`invariant`](Self::invariant) alone.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    /// What the port moved, which is the only thing here that is not a fault.
    pub traffic: Traffic,
    /// Expected to be non-zero on any network carrying traffic this node drops.
    pub input: InputDrops,
    /// Expected to be zero forever.
    pub invariant: InvariantFaults,
}

/// What crossed this port in each direction, on the same monotonic, saturating
/// terms as [`InputDrops`].
///
/// Frames *and* bytes in both directions, because neither alone is readable: a
/// frame count with no byte total cannot be told from one carrying nothing, and
/// a byte total with no frame count says nothing about the shape of the load.
/// Both are measured where this driver decides them — the receive length after
/// the device's own header is subtracted and clamped to the buffer, the transmit
/// length as the peer's descriptor named it — so neither is a number a device
/// reported and nobody checked.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Traffic {
    /// Frames taken off the device and handed to the peer.
    pub receive_frames: u64,
    /// Bytes those frames carried.
    pub receive_bytes: u64,
    /// Frames posted to the device for transmission.
    pub transmit_frames: u64,
    /// Bytes those frames carried.
    pub transmit_bytes: u64,
}

/// Counts of frames this driver did not put on the wire for a reason outside
/// itself — a neighbour misbehaving, or a neighbour deciding against the wire —
/// which are otherwise invisible: either at line rate looks like an idle link.
///
/// Every field is **monotonic** for the protection domain's life and
/// **saturates** at [`u64::MAX`] rather than wrapping. There is no reset: a
/// metrics endpoint derives a rate by differencing successive scrapes, so a
/// reset would forge a negative rate, and a wrap would turn a sustained flood
/// back into a small number — precisely when the number matters most.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InputDrops {
    /// Frames with nothing past the virtio-net header, dropped at the rx edge
    /// instead of forwarded as a header-only frame.
    pub rx_runt_dropped: u64,
    /// The buffer is returned to the pool, so nothing is lost but the frame —
    /// the peer is not keeping up, or is stalled deliberately.
    pub rx_peer_ring_full: u64,
    /// Transmit descriptors that failed span or header-room validation, or
    /// whose header the pool refused to place. All three name somewhere this
    /// driver may not write, which is one misbehaviour and so one counter.
    pub tx_malformed: u64,
    /// Transmit descriptors naming a buffer already in flight at the device.
    /// Dropped without a return, because the in-flight instance still owes that
    /// buffer's single return.
    pub tx_duplicate: u64,
    /// Transmit descriptors carrying [`Verdict::Discard`]: the device is not
    /// touched and no pool byte written. Non-zero is ordinary routing — ARP, a
    /// broadcast, an expired TTL — and nobody's fault, unlike its neighbours.
    pub tx_discarded: u64,
    /// Transmit descriptors whose verdict word decodes to neither variant. The
    /// buffer is returned as a discard's is, so nothing leaks, but the value is
    /// a defect in the producing domain and is never coerced to one (ENG-12).
    pub tx_verdict_undecodable: u64,
    /// Each one loses its buffer to the pool owner's ledger for good; the
    /// alternative — asserting — would let a peer that stalls the ring take
    /// this domain down.
    pub tx_free_ring_full: u64,
}

/// Counts of this driver's own broken bookkeeping. **A non-zero field here is a
/// defect in this crate or in how a protection domain wired it, never traffic.**
/// What is left that could trip one is driving a path against two different
/// virtqueues, which only this domain's own wiring can do.
///
/// They are counted rather than asserted, and the difference is deliberate:
/// these sit on the path a hostile device drives at line rate, so being *wrong*
/// about their unreachability would turn a reasoning error into a remotely
/// triggered outage of a dataplane port. A saturating counter under a name that
/// means "page someone" keeps the failure loud without handing the device a
/// kill switch. The same monotonic/saturating contract as [`InputDrops`]
/// applies.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InvariantFaults {
    /// A receive completion whose slot held no buffer: the virtqueue and this
    /// path's map disagree about what was posted. The frame is lost and the
    /// descriptor recycled.
    pub rx_completion_unmapped: u64,
    /// The transmit mirror of
    /// [`rx_completion_unmapped`](Self::rx_completion_unmapped). No buffer is
    /// returned, so the pool loses one.
    pub tx_completion_unmapped: u64,
    /// `refill` was handed a descriptor whose slot still held a buffer. That
    /// buffer is still a live DMA target somewhere, so it is leaked rather than
    /// released: putting it back in the pool would let it be issued a second
    /// time, which is the one outcome worse than losing it.
    pub rx_slot_occupied: u64,
    /// The transmit mirror of [`rx_slot_occupied`](Self::rx_slot_occupied). The
    /// displaced descriptor's buffer is leaked for the same reason and keeps
    /// its in-flight bit, so it is never reposted either.
    pub tx_slot_occupied: u64,
}

/// A snapshot of everything a driver protection domain can say about its two
/// neighbours and itself, in the shape the metrics endpoint (CONCEPT §11) will
/// scrape. Taken by value because a scrape wants one consistent picture, not
/// four live borrows.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DriverStats {
    pub counters: Counters,
    pub rx_device: DeviceFaults,
    pub tx_device: DeviceFaults,
}

impl DriverStats {
    /// This port in the shape `lfw_metrics` publishes, slot for slot.
    ///
    /// The conversion lives here rather than in that crate because this is where
    /// both halves are visible: `lfw_metrics` carries plain data and no
    /// dependency on this crate, and the test below is what holds its vocabulary
    /// tokens to the fields they name.
    #[must_use]
    pub fn to_sample(&self, receive_pool: PoolCounters, log: LogSample) -> DriverSample {
        let input = &self.counters.input;
        let invariant = &self.counters.invariant;
        let traffic = &self.counters.traffic;
        DriverSample {
            receive_frames: traffic.receive_frames,
            receive_bytes: traffic.receive_bytes,
            transmit_frames: traffic.transmit_frames,
            transmit_bytes: traffic.transmit_bytes,
            input_drops: [
                input.rx_runt_dropped,
                input.rx_peer_ring_full,
                input.tx_malformed,
                input.tx_duplicate,
                input.tx_discarded,
                input.tx_verdict_undecodable,
                input.tx_free_ring_full,
            ],
            invariant_faults: [
                invariant.rx_completion_unmapped,
                invariant.tx_completion_unmapped,
                invariant.rx_slot_occupied,
                invariant.tx_slot_occupied,
            ],
            receive_device_faults: device_faults(self.rx_device),
            transmit_device_faults: device_faults(self.tx_device),
            receive_pool: PoolSample {
                not_lent: receive_pool.reclaim_not_lent,
                ledger_refused: receive_pool.reclaim_refused,
            },
            log,
        }
    }

    #[must_use]
    pub fn sample<const Q: usize>(
        counters: &Counters,
        rx: &SplitVirtqueue<Q>,
        tx: &SplitVirtqueue<Q>,
    ) -> Self {
        Self {
            counters: *counters,
            rx_device: rx.device_faults(),
            tx_device: tx.device_faults(),
        }
    }
}

/// One queue's device-protocol faults, in the order `lfw_metrics` lists them.
const fn device_faults(faults: DeviceFaults) -> [u64; 3] {
    [
        faults.completion_out_of_range,
        faults.completion_not_posted,
        faults.completion_length_over_reported,
    ]
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// The receive path.
///
/// A posted buffer's ownership is a move-only [`OwnedBuffer`] in a per-slot
/// `Option`, so single ownership stays compiler-checkable while the buffer is
/// inside this domain: the `take()` on completion moves it out, and the frame
/// cannot be handed onward twice even by a coding error here.
pub struct RxPath<'ring, const Q: usize> {
    /// The buffer handed to the device in each descriptor slot.
    posted: [Option<OwnedBuffer<POOL_BUFFERS>>; Q],
    rx: RingProducer<'ring, RING_SLOTS>,
    /// Physical address of the pool region this NIC receives into, for deriving
    /// each posted buffer's DMA address. An address and no reference, because
    /// this path hands buffers to the device and never reads one: the domain is
    /// granted that pool's physical address with no mapping at all.
    pool_paddr: u64,
}

impl<'ring, const Q: usize> RxPath<'ring, Q> {
    /// Take the receive pipeline's `rx` producer handle. `pool_paddr` is the
    /// physical base of the pool this NIC receives into.
    ///
    /// **Unenforced precondition (DOC-7):** call once per protection domain.
    /// The handle is this domain's publish position, so a second path over the
    /// same pipeline overwrites slots the first has already handed to the
    /// peer. No type refuses the second call; `queue`'s crate header
    /// states that single-handle rule and why nothing enforces it. Treat it as
    /// unenforced rather than as checked elsewhere.
    #[must_use]
    pub fn attach(rings: &'ring ForwardRings, pool_paddr: u64) -> Self {
        Self {
            posted: [const { None }; Q],
            rx: rings.rx.producer(),
            pool_paddr,
        }
    }

    /// Post free pool buffers to the receive virtqueue until either runs dry,
    /// returning whether any was posted — which is how the caller knows whether
    /// to ring the receive doorbell.
    ///
    /// Bounded without an explicit cap: each iteration consumes one buffer from
    /// the pool ledger and one virtqueue descriptor, both driver-owned and
    /// finite, and the loop stops as soon as either is exhausted.
    pub fn refill(
        &mut self,
        rx: &mut SplitVirtqueue<Q>,
        pool: &mut PoolOwner<'_>,
        counters: &mut Counters,
    ) -> bool {
        let mut posted = false;
        while let Some(buffer) = pool.alloc() {
            // The index came from this pipeline's own ledger, so it is a real
            // pool index and the address it yields stays inside the region —
            // the property that keeps a DMA target where it belongs.
            let paddr = buffer_paddr(self.pool_paddr, buffer.index());
            match rx.add_writable(paddr, BUFFER_SIZE as u32) {
                Some(head) => {
                    let slot = head as usize;
                    if let Some(displaced) = self.posted[slot].replace(buffer) {
                        // This path and that queue disagree about what is
                        // posted; `displaced` is leaked rather than released,
                        // for the reason on `InvariantFaults::rx_slot_occupied`.
                        bump(&mut counters.invariant.rx_slot_occupied);
                        drop(displaced);
                    }
                    posted = true;
                }
                None => {
                    pool.release(buffer);
                    break;
                }
            }
        }
        posted
    }

    /// Drain completed receive descriptors, handing each valid frame to the
    /// peer with no copy. Returns whether any frame was submitted, which
    /// is how the caller knows whether to notify the peer.
    ///
    /// At most `Q` completions are processed per call: a conformant device never
    /// has more than `Q` buffers outstanding, so the cap costs nothing, while a
    /// device that floods its used ring cannot park this domain in the loop
    /// forever. That cap composes with the virtqueue's own — a single `poll`
    /// examines at most `Q` used entries — so one call is bounded whatever the
    /// device publishes, and no bound anywhere derives from a device value.
    pub fn drain(
        &mut self,
        rx: &mut SplitVirtqueue<Q>,
        pool: &mut PoolOwner<'_>,
        counters: &mut Counters,
    ) -> bool {
        let mut received = false;
        for _ in 0..Q {
            let Some((completion, used_len)) = rx.poll() else {
                break;
            };
            let slot = completion.index() as usize;
            let Some(buffer) = self.posted[slot].take() else {
                // Not device input — see `InvariantFaults`. No buffer is known
                // for the frame, but the descriptor is still this queue's.
                bump(&mut counters.invariant.rx_completion_unmapped);
                completion.recycle();
                continue;
            };
            // `used_len` is device-controlled; clamp to the buffer so a device
            // that over-reports cannot make a downstream PD read out of bounds.
            let frame_len = (used_len as usize)
                .min(BUFFER_SIZE)
                .saturating_sub(VirtioNetHdr::LEN);
            if frame_len == 0 {
                bump(&mut counters.input.rx_runt_dropped);
                pool.release(buffer);
                completion.recycle();
                continue;
            }
            // `lend` is where the ownership token dissolves into a bare index:
            // the buffer is owned downstream until it comes back on the free
            // ring, and that dissolution is also what permits the return.
            match pool.lend(
                &mut self.rx,
                buffer,
                VirtioNetHdr::LEN as u32,
                frame_len as u32,
                Verdict::Transmit,
            ) {
                Ok(()) => {
                    received = true;
                    bump(&mut counters.traffic.receive_frames);
                    // Saturating: the rate is the wire's to choose, and a
                    // wrapped total turns a sustained flood into a small number.
                    counters.traffic.receive_bytes = counters
                        .traffic
                        .receive_bytes
                        .saturating_add(frame_len as u64);
                }
                Err(buffer) => {
                    bump(&mut counters.input.rx_peer_ring_full);
                    pool.release(buffer);
                }
            }
            completion.recycle();
        }
        received
    }
}

/// The transmit path.
///
/// The two maps answer different questions and neither substitutes for the
/// other. The per-slot `Option` is the slot→descriptor map, the only record of
/// which peer descriptor to return once the device is done with it. The
/// in-flight set is indexed by *pool buffer* rather than by virtqueue slot, and
/// guards the peer boundary alone: whether this driver already holds the buffer
/// a new descriptor names.
pub struct TxPath<'ring, const Q: usize> {
    /// The peer descriptor handed to the device in each descriptor slot.
    posted: [Option<Descriptor>; Q],
    /// Which pool buffers this driver has at the device right now. A second
    /// descriptor naming one of them is a duplicate: posting it would put two
    /// virtqueue entries on one buffer and produce two returns for a buffer
    /// that was lent once.
    in_flight: [bool; POOL_BUFFERS],
    tx: RingConsumer<'ring, RING_SLOTS>,
    free: RingProducer<'ring, RING_SLOTS>,
    /// The pool the descriptors index, for writing the virtio-net header in
    /// place. This direction is the only one that dereferences a pool byte, and
    /// so the only one whose domain maps the region at all.
    pool: &'ring Pool,
    /// Physical address of that pool's region, for deriving each buffer's DMA
    /// address.
    pool_paddr: u64,
}

impl<'ring, const Q: usize> TxPath<'ring, Q> {
    /// Take the transmit pipeline's `tx` consumer and `free` producer handles.
    /// `pool` and `pool_paddr` are the mapped pool this NIC transmits out of
    /// and the physical base of that same region.
    ///
    /// **Unenforced precondition (DOC-7):** call once per protection domain. A
    /// second path over the same pipeline re-consumes frames the first has
    /// already handed to the device and returns their buffers twice. No type
    /// refuses the second call; `queue`'s crate header states that
    /// single-handle rule and why nothing enforces it. Treat it as unenforced
    /// rather than as checked elsewhere.
    #[must_use]
    pub fn attach(
        rings: &'ring ForwardRings,
        returns: &'ring ReturnRing,
        pool: &'ring Pool,
        pool_paddr: u64,
    ) -> Self {
        Self {
            posted: [None; Q],
            in_flight: [false; POOL_BUFFERS],
            tx: rings.tx.consumer(),
            free: returns.free.producer(),
            pool,
            pool_paddr,
        }
    }

    /// Reap transmit completions, returning each transmitted buffer to its
    /// pool-owning peer on the pipeline's free ring.
    ///
    /// At most `Q` completions per call, for the reason given on
    /// [`RxPath::drain`].
    pub fn reap(&mut self, tx: &mut SplitVirtqueue<Q>, counters: &mut Counters) {
        for _ in 0..Q {
            let Some((completion, _written)) = tx.poll() else {
                break;
            };
            let slot = completion.index() as usize;
            let Some(descriptor) = self.posted[slot].take() else {
                bump(&mut counters.invariant.tx_completion_unmapped);
                completion.recycle();
                continue;
            };
            // In range because `post` validated the descriptor before storing
            // it, so no peer value reaches this index.
            self.in_flight[descriptor.buffer as usize] = false;
            self.return_buffer(descriptor, counters);
            completion.recycle();
        }
    }

    /// Post frames the peer queued to the device while descriptors are
    /// free. Returns whether any frame was posted, which is how the caller
    /// knows whether to ring the transmit doorbell.
    ///
    /// Each descriptor crossed a protection-domain boundary and is untrusted.
    /// A malformed one is counted and dropped, and its buffer returned to the
    /// pool only when the index names a real pool buffer — a forged index has
    /// no owner — and is not the one an in-flight instance still owes a return
    /// for. A [`Verdict::Discard`] and an undecodable verdict are returned on
    /// those same terms, with neither the device nor the pool touched.
    ///
    /// The loop is capped at [`DRAIN_LIMIT`] iterations rather than at the
    /// virtqueue's free count, because a rejected descriptor consumes no
    /// virtqueue descriptor: a peer queueing nothing but malformed descriptors
    /// would otherwise leave the free count untouched and spin this domain
    /// forever. The cap drains a full ring of rejects in one round and stops.
    pub fn post(&mut self, tx: &mut SplitVirtqueue<Q>, counters: &mut Counters) -> bool {
        let mut sent = false;
        for _ in 0..DRAIN_LIMIT {
            if tx.free_count() == 0 {
                break;
            }
            let Some(descriptor) = self.tx.try_dequeue() else {
                break;
            };
            // Read first: it decides whether this is a frame at all, so a
            // buffer marked against the wire reaches neither device nor pool.
            let verdict = Verdict::from_bits(descriptor.verdict);
            let in_pool = (descriptor.buffer as usize) < POOL_BUFFERS;
            // The duplicate check comes first so a duplicate is never *also*
            // returned: exactly one return per lent buffer is what keeps the
            // owner's ledger from seeing a second, refused one — which is why
            // it sits ahead of the verdict branch and not beside it.
            if in_pool && self.in_flight[descriptor.buffer as usize] {
                bump(&mut counters.input.tx_duplicate);
                continue;
            }
            match verdict {
                Some(Verdict::Transmit) => {}
                // Device untouched, no pool byte written; the buffer goes back
                // the way `reap` sends a transmitted one.
                Some(Verdict::Discard) => {
                    bump(&mut counters.input.tx_discarded);
                    if in_pool {
                        self.return_buffer(descriptor, counters);
                    }
                    continue;
                }
                // Same handling of the buffer, separate tally: a word decoding
                // to nothing is a defect in the producing domain, and merging
                // the two would let it hide inside ordinary traffic (ENG-12).
                None => {
                    bump(&mut counters.input.tx_verdict_undecodable);
                    if in_pool {
                        self.return_buffer(descriptor, counters);
                    }
                    continue;
                }
            }
            // The 12 bytes in front of the frame are reserved header space in
            // the same buffer; on the receive side the device's own header
            // occupied them. `TX_NO_OFFLOAD` is a header requesting nothing,
            // which is all this driver may ask for while it negotiates no
            // offload feature.
            //
            // The pool's span check has the last word, so no frame is posted
            // whose header was never written; `InputDrops::tx_malformed` says
            // why a refusal is that counter and not a new one.
            let placed = match (
                descriptor_in_bounds(&descriptor),
                (descriptor.offset as usize).checked_sub(VirtioNetHdr::LEN),
            ) {
                (true, Some(header_offset)) => {
                    // SAFETY: the source is a local constant, so it cannot alias
                    // the pool, and the span is `write_at`'s own business — it
                    // bounds the write unconditionally and answers in its
                    // return value rather than faulting. Exclusive ownership has
                    // no guarantor inside this domain: `self.in_flight` rules
                    // out this driver holding the buffer twice, and the residual
                    // race against the pool owner's own rx DMA is stated in the
                    // crate header and is not closable here.
                    unsafe {
                        self.pool.write_at(
                            descriptor.buffer as usize,
                            header_offset,
                            &VirtioNetHdr::TX_NO_OFFLOAD,
                        )
                    }
                    .ok()
                    .map(|()| header_offset)
                }
                _ => None,
            };
            let Some(header_offset) = placed else {
                bump(&mut counters.input.tx_malformed);
                if in_pool {
                    self.return_buffer(descriptor, counters);
                }
                continue;
            };
            let paddr = buffer_paddr(self.pool_paddr, descriptor.buffer) + header_offset as u64;
            // A first-party invariant, not device or peer input, so it fails
            // visibly rather than being counted (ENG-5). The guarantor is
            // `virtio::queue::SplitVirtqueue::add` — the single body behind
            // both `add_*` methods — whose only early return is `if
            // self.num_free == 0`, and whose `free_count()` *is* `num_free`.
            // This iteration refused `free_count() == 0` at the top and has not
            // touched `tx` since: the dequeue, the validation and the header
            // write are all on the pipeline and the pool, so no descriptor was
            // consumed in between. `virtio`'s property
            // `split_virtqueue_accounting_holds_under_random_operations` proves
            // it, unwrapping an `add` after every observed `free_count() > 0`
            // across arbitrary add/complete/poll/recycle sequences.
            let head = tx
                .add_readable(paddr, descriptor.len + VirtioNetHdr::LEN as u32)
                .expect("free_count() > 0 was observed above and nothing since has touched tx");
            let slot = head as usize;
            if self.posted[slot].replace(descriptor).is_some() {
                // This path and that queue disagree about what is posted; see
                // `InvariantFaults::tx_slot_occupied` for why the displaced
                // descriptor is neither returned nor reposted. Unlike the
                // receive side there is no token to drop: a `Descriptor` is
                // plain `Copy` data, and discarding it *is* withholding the
                // return.
                bump(&mut counters.invariant.tx_slot_occupied);
            }
            self.in_flight[descriptor.buffer as usize] = true;
            bump(&mut counters.traffic.transmit_frames);
            counters.traffic.transmit_bytes = counters
                .traffic
                .transmit_bytes
                .saturating_add(u64::from(descriptor.len));
            sent = true;
        }
        sent
    }

    /// The free ring is sized above the pool, so a correctly accounted return
    /// cannot fail. A failure means accounting has already broken — a byzantine
    /// peer over-filling the ring — which is untrusted input, so it is counted
    /// and the buffer dropped rather than asserted: a peer must not be able to
    /// fault a well-behaved driver (CONCEPT §7.1).
    fn return_buffer(&mut self, descriptor: Descriptor, counters: &mut Counters) {
        if self.free.try_enqueue(descriptor).is_err() {
            bump(&mut counters.input.tx_free_ring_full);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{Ordering, fence};
    use pd_runtime::RING_SLOTS;
    use proptest::prelude::*;
    use std::boxed::Box;
    use std::vec::Vec;

    const Q: usize = 16;
    type Vq = SplitVirtqueue<Q>;

    /// Overwrite a ring's shared cursors the way a byzantine peer that maps the
    /// region read-write can at any moment. The cursors are private to `queue`,
    /// so reach them through the region's known ABI: `head` then `tail`, both
    /// `u32`, at the ring's front (pinned by that crate's own layout asserts).
    fn forge_cursors(ring: &pd_runtime::Ring, head: u32, tail: u32) {
        let base = core::ptr::from_ref(ring).cast::<core::sync::atomic::AtomicU32>();
        // SAFETY: `SpscRing` is `#[repr(C)]` with `head` at offset 0 and `tail`
        // at offset 4 as `AtomicU32`s (asserted in `queue`), so both pointers
        // are in bounds and correctly aligned for the live ring borrowed here.
        // Atomic stores are exactly what a peer domain performs on these words.
        unsafe {
            (*base).store(head, Ordering::Relaxed);
            (*base.add(1)).store(tail, Ordering::Relaxed);
        }
    }

    /// Overwrite the verdict word of ring slot `slot`, the way a byzantine
    /// peer that maps the region read-write does. It is the one descriptor
    /// field no first-party producer can put an undecodable value in —
    /// `PoolOwner::lend` takes a `Verdict` — so a test that wants one has to
    /// reach the shared image, exactly as the peer does. The route is the
    /// region's pinned ABI: a ring is `head`, `tail`, then `RING_SLOTS` slots of
    /// four `u32`s in `Descriptor` field order (asserted in `queue` and in
    /// `pd_runtime`), so slot `n`'s verdict is word `2 + 4 * n + 3`.
    fn forge_slot_verdict(ring: &pd_runtime::Ring, slot: usize, bits: u32) {
        let base = core::ptr::from_ref(ring).cast::<core::sync::atomic::AtomicU32>();
        // SAFETY: `slot % RING_SLOTS < RING_SLOTS`, so the computed word lies
        // inside the live ring borrowed here, and the layout above makes every
        // word of it a 4-aligned `AtomicU32`. An atomic store is precisely what
        // a peer domain performs on this word.
        unsafe {
            (*base.add(2 + 4 * (slot % RING_SLOTS) + 3)).store(bits, Ordering::Relaxed);
        }
    }

    /// A 16-byte-aligned virtqueue backing region (the alignment `Vq::new`
    /// requires), large enough for `Vq::LAYOUT.total_bytes`.
    #[repr(C, align(16))]
    struct VqRegion([u8; 4096]);

    impl VqRegion {
        fn boxed() -> Box<Self> {
            Box::new(Self([0; 4096]))
        }
    }

    /// The far side of one virtqueue, playing the device in the same thread: it
    /// reads the driver's available ring, addresses the real Box-backed buffer
    /// the descriptor names, and publishes a used-ring completion — the same
    /// shape as the fake in `crates/virtio/src/queue.rs`.
    struct FakeDevice {
        region: *mut u8,
        last_avail: u16,
        used_idx: u16,
    }

    impl FakeDevice {
        fn new(region: *mut u8) -> Self {
            Self {
                region,
                last_avail: 0,
                used_idx: 0,
            }
        }

        /// # Safety
        /// `off + 2` must lie within the virtqueue region this device was built
        /// over, and `off` must be 2-byte aligned.
        unsafe fn r16(&self, off: usize) -> u16 {
            // SAFETY: the caller guarantees the offset lies within the live,
            // test-owned region and is aligned for this width.
            unsafe { self.region.add(off).cast::<u16>().read_volatile() }
        }
        /// # Safety
        /// As [`r16`](Self::r16).
        unsafe fn w16(&self, off: usize, v: u16) {
            // SAFETY: the caller guarantees the offset lies within the live,
            // test-owned region and is aligned for this width.
            unsafe { self.region.add(off).cast::<u16>().write_volatile(v) }
        }
        /// # Safety
        /// `off + 4` must lie within the region and `off` must be 4-byte
        /// aligned.
        unsafe fn w32(&self, off: usize, v: u32) {
            // SAFETY: the caller guarantees the offset lies within the live,
            // test-owned region and is aligned for this width.
            unsafe { self.region.add(off).cast::<u32>().write_volatile(v) }
        }
        /// # Safety
        /// As [`w32`](Self::w32).
        unsafe fn r32(&self, off: usize) -> u32 {
            // SAFETY: the caller guarantees the offset lies within the live,
            // test-owned region and is aligned for this width.
            unsafe { self.region.add(off).cast::<u32>().read_volatile() }
        }
        /// # Safety
        /// `off + 8` must lie within the region and `off` must be 8-byte
        /// aligned.
        unsafe fn r64(&self, off: usize) -> u64 {
            // SAFETY: the caller guarantees the offset lies within the live,
            // test-owned region and is aligned for this width.
            unsafe { self.region.add(off).cast::<u64>().read_volatile() }
        }

        fn driver_off() -> usize {
            Vq::LAYOUT.driver_offset
        }
        fn device_off() -> usize {
            Vq::LAYOUT.device_offset
        }

        /// The next head index the driver made available, or `None`.
        fn next_avail(&mut self) -> Option<u16> {
            let d = Self::driver_off();
            // SAFETY: the available-ring header lies within the live,
            // test-owned virtqueue region and is 2-byte aligned.
            let avail_idx = unsafe { self.r16(d + 2) };
            if avail_idx == self.last_avail {
                return None;
            }
            fence(Ordering::Acquire);
            let slot = (self.last_avail as usize) & (Q - 1);
            // SAFETY: `slot < Q`, so the ring entry lies within the region, and
            // the entries are 2-byte aligned.
            let head = unsafe { self.r16(d + 4 + slot * 2) };
            self.last_avail = self.last_avail.wrapping_add(1);
            Some(head)
        }

        fn desc_addr(&self, head: u16) -> u64 {
            // SAFETY: `head < Q` (a posted descriptor), so the 16-byte
            // descriptor lies within the region and its address field is
            // 8-byte aligned.
            unsafe { self.r64(head as usize * 16) }
        }
        fn desc_len(&self, head: u16) -> u32 {
            // SAFETY: as `desc_addr`; the length field is 4-byte aligned.
            unsafe { self.r32(head as usize * 16 + 8) }
        }

        /// Publish a used-ring completion for `head`, reporting `used_len`.
        fn complete(&mut self, head: u16, used_len: u32) {
            let u = Self::device_off();
            let slot = (self.used_idx as usize) & (Q - 1);
            // SAFETY: `slot < Q`, so the used element lies within the live,
            // test-owned region, and both fields are 4-byte aligned.
            unsafe {
                self.w32(u + 4 + slot * 8, head as u32);
                self.w32(u + 4 + slot * 8 + 4, used_len);
            }
            fence(Ordering::Release);
            self.used_idx = self.used_idx.wrapping_add(1);
            // SAFETY: the used-ring index lies within the region, 2-byte
            // aligned.
            unsafe { self.w16(u + 2, self.used_idx) };
        }

        /// Receive side: fill the next posted buffer with `frame` and complete
        /// it reporting `used_len` (which the caller varies to exercise the
        /// clamp and runt paths). Returns the completed head index.
        fn deliver(&mut self, frame: &[u8], used_len: u32) -> u16 {
            let head = self.next_avail().expect("a buffer was posted");
            let addr = self.desc_addr(head) as *mut u8;
            let cap = self.desc_len(head) as usize;
            let n = frame.len().min(cap);
            // SAFETY: `addr` is the real backing buffer the descriptor names and
            // `n = min(frame, cap)` stays within it.
            unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), addr, n) };
            self.complete(head, used_len);
            head
        }

        /// Transmit side: read out the next posted frame's bytes and complete
        /// it. Returns the bytes the device would have put on the wire.
        fn transmit(&mut self) -> Vec<u8> {
            let head = self.next_avail().expect("a frame was posted");
            let addr = self.desc_addr(head) as *const u8;
            let len = self.desc_len(head) as usize;
            // SAFETY: `addr`/`len` come from the descriptor the driver posted,
            // naming a live buffer of that length.
            let bytes = unsafe { core::slice::from_raw_parts(addr, len) }.to_vec();
            self.complete(head, len as u32);
            bytes
        }
    }

    /// One receive virtqueue over a fresh region, plus the device on its far
    /// side and the pipeline regions it feeds. Each region is leaked so the
    /// ring handles the paths hold can borrow it for `'static`, exactly as a
    /// protection domain's mapped regions do.
    struct RxFixture {
        pool: &'static Pool,
        rings: &'static ForwardRings,
        returns: &'static ReturnRing,
        _region: Box<VqRegion>,
        vq: Vq,
        device: FakeDevice,
        owner: PoolOwner<'static>,
        rx: RxPath<'static, Q>,
        /// The peer's end of the `rx` ring, taken once for the fixture's
        /// life — a fresh handle per assertion would restart at slot zero and
        /// re-deliver descriptors already consumed.
        peer: RingConsumer<'static, RING_SLOTS>,
        /// The far transmitting driver's end of the `free` ring, taken once for
        /// the same reason as `peer`. It is how a peer's returns reach
        /// this domain, legitimate or forged.
        peer_returns: RingProducer<'static, RING_SLOTS>,
        counters: Counters,
    }

    impl RxFixture {
        fn new() -> Self {
            let pool: &'static Pool = Box::leak(Box::new(Pool::new()));
            let rings: &'static ForwardRings = Box::leak(Box::new(ForwardRings::new()));
            let returns: &'static ReturnRing = Box::leak(Box::new(ReturnRing::new()));
            let mut region = VqRegion::boxed();
            let ptr = region.0.as_mut_ptr();
            // SAFETY: `ptr` backs a 16-byte-aligned, zeroed VqRegion owned
            // solely by this test — `Vq::new`'s contract.
            let vq = unsafe { Vq::new(ptr) };
            let device = FakeDevice::new(ptr);
            // The device writes to the descriptor address as a real pointer, so
            // the "physical" pool base is that region's actual host address —
            // the pool being the whole of its region, with no offset to add.
            let pool_paddr = core::ptr::from_ref(pool) as u64;
            Self {
                pool,
                rings,
                returns,
                _region: region,
                vq,
                device,
                owner: PoolOwner::attach(returns),
                rx: RxPath::attach(rings, pool_paddr),
                peer: rings.rx.consumer(),
                peer_returns: returns.free.producer(),
                counters: Counters::default(),
            }
        }

        /// The pool indices this driver currently has posted to its own NIC as
        /// receive DMA targets. Read out of the path's own slot map, which is
        /// the only record of them.
        fn posted_buffers(&self) -> Vec<u32> {
            self.rx
                .posted
                .iter()
                .flatten()
                .map(OwnedBuffer::<POOL_BUFFERS>::index)
                .collect()
        }

        /// Queue a return on the `free` ring as the far driver would, naming
        /// whatever buffer the peer chooses.
        fn peer_returns_buffer(&mut self, buffer: u32) {
            self.peer_returns
                .try_enqueue(Descriptor::new(buffer, 0, 0, Verdict::Transmit))
                .expect("the free ring has room");
        }

        fn reclaim(&mut self) -> usize {
            self.owner.reclaim()
        }

        /// Drain the ledger, proving what it holds is a set of real, pairwise
        /// distinct pool indices — a repeat here is one buffer with two owners.
        fn drain_ledger_distinctly(&mut self) -> usize {
            let mut seen = [false; POOL_BUFFERS];
            let mut count = 0;
            while let Some(buffer) = self.owner.alloc() {
                let index = buffer.index() as usize;
                assert!(index < POOL_BUFFERS, "the ledger held index {index}");
                assert!(!seen[index], "index {index} was handed out twice");
                seen[index] = true;
                count += 1;
            }
            count
        }

        fn refill(&mut self) -> bool {
            self.rx
                .refill(&mut self.vq, &mut self.owner, &mut self.counters)
        }

        /// What the receive virtqueue refused from the device, which is where
        /// every forged, replayed, and out-of-range completion is now counted.
        fn device_faults(&self) -> DeviceFaults {
            self.vq.device_faults()
        }

        fn drain(&mut self) -> bool {
            self.rx
                .drain(&mut self.vq, &mut self.owner, &mut self.counters)
        }

        /// What the peer sees next on the `rx` ring.
        fn forwarded(&mut self) -> Option<Descriptor> {
            self.peer.try_dequeue()
        }

        /// The two halves of [`Counters`] a case is usually about, without the
        /// traffic tally beside them: a test asserting "nothing went wrong"
        /// would otherwise have to restate every frame it moved on the way.
        fn faults(&self) -> Faults {
            Faults {
                input: self.counters.input,
                invariant: self.counters.invariant,
            }
        }
    }

    /// The fault halves of [`Counters`], for the assertion above.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    struct Faults {
        input: InputDrops,
        invariant: InvariantFaults,
    }

    /// A frame handed to the peer is counted as received, and its byte total is
    /// the frame's own length rather than what the device reported: a device
    /// that over-reports has its length clamped first, so the total an operator
    /// reads is the driver's measurement and not the device's claim.
    #[test]
    fn a_received_frame_is_counted_with_the_length_the_driver_clamped_to() {
        let mut fx = RxFixture::new();
        fx.refill();
        let head = fx.device.next_avail().expect("a posted descriptor");
        // Far more than the buffer holds, so the clamp is what decides the count.
        fx.device.complete(head, u32::MAX);
        assert!(fx.drain());
        assert_eq!(fx.counters.traffic.receive_frames, 1);
        assert_eq!(
            fx.counters.traffic.receive_bytes,
            (BUFFER_SIZE - VirtioNetHdr::LEN) as u64,
            "the count is the clamped length"
        );
    }

    /// A frame posted to the device is counted as transmitted, with the length
    /// the peer's descriptor named — the header the driver adds is not traffic.
    #[test]
    fn a_transmitted_frame_is_counted_with_its_own_length() {
        let mut fx = TxFixture::new();
        fx.enqueue_frame(0, VirtioNetHdr::LEN, &[0x5Au8; 64]);
        assert!(fx.post());
        assert_eq!(fx.faults(), Faults::default());
        assert_eq!(fx.counters.traffic.transmit_frames, 1);
        assert_eq!(fx.counters.traffic.transmit_bytes, 64);
    }

    /// Every counter this driver keeps reaches a slot of the shard it publishes,
    /// and none reaches two. `lfw_metrics` names the vocabulary and depends on
    /// none of this, so this is the enforcer that separation obliges (DOC-7).
    #[test]
    fn every_driver_counter_reaches_its_own_slot() {
        let stats = DriverStats {
            counters: Counters {
                traffic: Traffic {
                    receive_frames: 1,
                    receive_bytes: 2,
                    transmit_frames: 3,
                    transmit_bytes: 4,
                },
                input: InputDrops {
                    rx_runt_dropped: 5,
                    rx_peer_ring_full: 6,
                    tx_malformed: 7,
                    tx_duplicate: 8,
                    tx_discarded: 9,
                    tx_verdict_undecodable: 10,
                    tx_free_ring_full: 11,
                },
                invariant: InvariantFaults {
                    rx_completion_unmapped: 12,
                    tx_completion_unmapped: 13,
                    rx_slot_occupied: 14,
                    tx_slot_occupied: 15,
                },
            },
            rx_device: DeviceFaults {
                completion_out_of_range: 16,
                completion_not_posted: 17,
                completion_length_over_reported: 18,
            },
            tx_device: DeviceFaults {
                completion_out_of_range: 19,
                completion_not_posted: 20,
                completion_length_over_reported: 21,
            },
        };
        let sample = stats.to_sample(
            PoolCounters {
                reclaim_not_lent: 22,
                reclaim_refused: 23,
            },
            LogSample {
                dropped: 24,
                refused: 25,
            },
        );
        let values = sample.values();
        assert_eq!(values.len(), lfw_metrics::DRIVER_SLOTS);
        let mut seen: Vec<u64> = values.to_vec();
        seen.sort_unstable();
        assert_eq!(seen, (1..=25).collect::<Vec<u64>>());
    }

    /// One transmit virtqueue over a fresh region, plus the device on its far
    /// side and the pipeline it drains.
    struct TxFixture {
        pool: &'static Pool,
        rings: &'static ForwardRings,
        free: &'static ReturnRing,
        _region: Box<VqRegion>,
        vq: Vq,
        device: FakeDevice,
        tx: TxPath<'static, Q>,
        /// The peer's end of the `tx` ring and the pool owner's end of the
        /// `free` ring, each taken once for the fixture's life; see
        /// [`RxFixture::peer`].
        peer: RingProducer<'static, RING_SLOTS>,
        returns: RingConsumer<'static, RING_SLOTS>,
        counters: Counters,
    }

    impl TxFixture {
        /// As `RxFixture::faults`.
        fn faults(&self) -> Faults {
            Faults {
                input: self.counters.input,
                invariant: self.counters.invariant,
            }
        }

        fn new() -> Self {
            let pool: &'static Pool = Box::leak(Box::new(Pool::new()));
            let rings: &'static ForwardRings = Box::leak(Box::new(ForwardRings::new()));
            let free: &'static ReturnRing = Box::leak(Box::new(ReturnRing::new()));
            let mut region = VqRegion::boxed();
            let ptr = region.0.as_mut_ptr();
            // SAFETY: `ptr` backs a 16-byte-aligned, zeroed VqRegion owned
            // solely by this test — `Vq::new`'s contract.
            let vq = unsafe { Vq::new(ptr) };
            let device = FakeDevice::new(ptr);
            // `post` derives buffer addresses from the pool region's base via
            // `buffer_paddr`, so the base is that region's real host address and
            // every buffer then resolves to its real bytes.
            let pool_paddr = core::ptr::from_ref(pool) as u64;
            Self {
                pool,
                rings,
                free,
                _region: region,
                vq,
                device,
                tx: TxPath::attach(rings, free, pool, pool_paddr),
                peer: rings.tx.producer(),
                returns: free.free.consumer(),
                counters: Counters::default(),
            }
        }

        fn post(&mut self) -> bool {
            self.tx.post(&mut self.vq, &mut self.counters)
        }

        fn reap(&mut self) {
            self.tx.reap(&mut self.vq, &mut self.counters);
        }

        /// What the transmit virtqueue refused from the device; see
        /// [`RxFixture::device_faults`].
        fn device_faults(&self) -> DeviceFaults {
            self.vq.device_faults()
        }

        /// Queue a raw descriptor as the peer would, valid or not.
        fn queue(&mut self, descriptor: Descriptor) {
            self.peer.try_enqueue(descriptor).expect("tx ring has room");
        }

        /// What the pool owner sees next on the `free` ring.
        fn returned(&mut self) -> Option<Descriptor> {
            self.returns.try_dequeue()
        }

        /// Place a frame the peer would have queued: write `payload` at
        /// `offset` (with a non-zero 12-byte header in front, so the header
        /// zeroing is observable) into pool buffer `buffer`, and enqueue the
        /// matching descriptor on the tx ring.
        fn enqueue_frame(&mut self, buffer: u32, offset: usize, payload: &[u8]) {
            // SAFETY: single-threaded test; the buffer is not otherwise in use,
            // and both spans lie within it.
            unsafe {
                self.pool
                    .write_at(
                        buffer as usize,
                        offset - VirtioNetHdr::LEN,
                        &[0xFFu8; VirtioNetHdr::LEN],
                    )
                    .expect("the header span lies within the buffer");
                self.pool
                    .write_at(buffer as usize, offset, payload)
                    .expect("the payload span lies within the buffer");
            }
            self.queue(Descriptor::new(
                buffer,
                offset as u32,
                payload.len() as u32,
                Verdict::Transmit,
            ));
        }
    }

    #[test]
    fn refill_posts_up_to_the_queue_when_the_pool_is_larger() {
        let mut fx = RxFixture::new();
        assert!(fx.refill());
        // The queue holds Q descriptors, the pool 64 buffers, so the queue is
        // the limit: Q posted, the rest still owned.
        assert_eq!(fx.vq.free_count(), 0);
        assert_eq!(fx.owner.owned(), POOL_BUFFERS - Q);
    }

    #[test]
    fn refill_stops_when_the_pool_is_exhausted() {
        let mut fx = RxFixture::new();
        // Leave the owner holding fewer buffers than the queue can hold.
        let mut held = Vec::new();
        while fx.owner.owned() > 4 {
            held.push(fx.owner.alloc().unwrap());
        }
        assert!(fx.refill());
        assert_eq!(fx.owner.owned(), 0);
        // Only four descriptors were consumed; the rest of the queue is free.
        assert_eq!(fx.vq.free_count(), Q - 4);
    }

    #[test]
    fn a_valid_frame_is_submitted_after_the_header() {
        let mut fx = RxFixture::new();
        fx.refill();
        let payload = [0xA1u8, 0xA2, 0xA3, 0xA4];
        let mut frame = std::vec![0u8; VirtioNetHdr::LEN];
        frame.extend_from_slice(&payload);
        fx.device.deliver(&frame, frame.len() as u32);

        assert!(fx.drain());
        assert_eq!(fx.faults(), Faults::default());
        let descriptor = fx.forwarded().expect("one frame forwarded");
        assert_eq!(descriptor.offset, VirtioNetHdr::LEN as u32);
        assert_eq!(descriptor.len, payload.len() as u32);
        let mut storage = [0u8; BUFFER_SIZE];
        // SAFETY: single-threaded test; we hold the dequeued descriptor and its
        // span was published by the code under test. The bytes are snapshotted
        // into this test's own `storage`, so nothing borrows the pool.
        let bytes = unsafe {
            fx.pool.copy_out(
                descriptor.buffer as usize,
                descriptor.offset as usize,
                descriptor.len,
                &mut storage,
            )
        }
        .expect("the driver published a span within one buffer");
        assert_eq!(bytes, &payload);
    }

    #[test]
    fn a_duplicate_receive_completion_is_refused_by_the_virtqueue() {
        // This crate used to detect the duplicate itself, through the `None` in
        // its per-slot map. It is now refused one layer down — `poll` mints no
        // token for a descriptor that is not posted — so the assertion moved to
        // where the check lives. What stays this crate's contract is the
        // consequence, and that is asserted here in full: no second frame, no
        // descriptor released twice, and nothing recorded against this driver.
        let mut fx = RxFixture::new();
        fx.refill();
        let frame = std::vec![0u8; VirtioNetHdr::LEN + 8];
        let head = fx.device.deliver(&frame, frame.len() as u32);
        assert!(fx.drain());
        let free_after_first = fx.vq.free_count();

        // The device echoes the same head a second time without a repost.
        fx.device.complete(head, frame.len() as u32);
        assert!(!fx.drain());
        assert_eq!(fx.device_faults().completion_not_posted, 1);
        assert_eq!(
            fx.faults(),
            Faults::default(),
            "a device duplicate is neither an input drop nor a driver fault here"
        );
        assert_eq!(fx.vq.free_count(), free_after_first);
        // The duplicate submitted no second frame.
        assert!(fx.forwarded().is_some());
        assert!(fx.forwarded().is_none());
    }

    #[test]
    fn drain_is_bounded_when_the_device_floods_duplicate_completions() {
        // A device that keeps publishing completions for a head it already had
        // reaped must not park the driver in the loop. The bound is now the
        // virtqueue's own per-`poll` scan budget of Q used entries — a
        // driver-owned quantity — so the flood is measured there: one `drain`
        // makes exactly Q entries' worth of progress and returns, however many
        // the device published.
        let mut fx = RxFixture::new();
        fx.refill();
        let frame = std::vec![0u8; VirtioNetHdr::LEN + 8];
        let head = fx.device.deliver(&frame, frame.len() as u32);
        assert!(fx.drain());

        for _ in 0..8 * Q {
            fx.device.complete(head, frame.len() as u32);
        }
        assert!(!fx.drain());
        assert_eq!(
            fx.device_faults().completion_not_posted,
            Q as u64,
            "at most Q completions are examined per call"
        );
        // A second call advances by exactly the same bound and never more, so
        // the cap is per call rather than a one-off.
        assert!(!fx.drain());
        assert_eq!(fx.device_faults().completion_not_posted, 2 * Q as u64);
        assert_eq!(fx.faults(), Faults::default());
        // Only the one real frame was ever forwarded.
        assert!(fx.forwarded().is_some());
        assert!(fx.forwarded().is_none());
    }

    #[test]
    fn an_over_reported_length_is_clamped_to_the_buffer() {
        let mut fx = RxFixture::new();
        fx.refill();
        // The device claims far more than the buffer holds.
        fx.device.deliver(&[0u8; 16], BUFFER_SIZE as u32 + 1000);

        assert!(fx.drain());
        assert_eq!(fx.faults(), Faults::default());
        let descriptor = fx.forwarded().expect("frame forwarded");
        // Clamped to the buffer, then the header removed.
        assert_eq!(descriptor.len, (BUFFER_SIZE - VirtioNetHdr::LEN) as u32);
    }

    #[test]
    fn a_runt_frame_is_dropped_and_counted() {
        let mut fx = RxFixture::new();
        fx.refill();
        let owned_before = fx.owner.owned();
        let free_before = fx.vq.free_count();
        // Nothing past the 12-byte header.
        fx.device
            .deliver(&[0u8; VirtioNetHdr::LEN], (VirtioNetHdr::LEN - 4) as u32);

        assert!(!fx.drain());
        assert_eq!(fx.counters.input.rx_runt_dropped, 1);
        assert!(fx.forwarded().is_none());
        // The buffer was released back and the descriptor recycled.
        assert_eq!(fx.owner.owned(), owned_before + 1);
        assert_eq!(fx.vq.free_count(), free_before + 1);
    }

    #[test]
    fn a_full_peer_ring_releases_the_buffer_and_counts_the_drop() {
        let mut fx = RxFixture::new();
        // A stalled or hostile peer: it publishes a `head` one slot ahead
        // of where the driver's own (private) publish position sits, so the
        // ring looks full to this side and every hand-off is refused. Filling
        // the ring with a second producer handle would prove nothing — that
        // handle would have its own position and never meet the path's.
        forge_cursors(&fx.rings.rx, 1, 0);

        fx.refill();
        let owned_before = fx.owner.owned();
        let free_before = fx.vq.free_count();
        let frame = std::vec![0u8; VirtioNetHdr::LEN + 8];
        fx.device.deliver(&frame, frame.len() as u32);

        assert!(!fx.drain());
        // The drop is counted: the old code released the buffer silently and a
        // stalled or hostile peer left no trace at all.
        assert_eq!(fx.counters.input.rx_peer_ring_full, 1);
        assert_eq!(
            fx.counters,
            Counters {
                // Nothing was handed to the peer, so nothing was received:
                // `traffic` moves only where a frame crossed.
                traffic: Traffic::default(),
                input: InputDrops {
                    rx_peer_ring_full: 1,
                    ..InputDrops::default()
                },
                invariant: InvariantFaults::default(),
            }
        );
        // The buffer came back to the owner and the descriptor was recycled.
        assert_eq!(fx.owner.owned(), owned_before + 1);
        assert_eq!(fx.vq.free_count(), free_before + 1);
    }

    #[test]
    fn a_peer_return_of_a_live_rx_dma_target_is_refused_and_the_buffer_stays_posted() {
        // The gap the *lent* set exists for, driven end to end rather than
        // asserted on a bare `PoolOwner`: `refill` hands these buffers to this
        // domain's own NIC as receive DMA targets, so the ledger sees them as
        // outstanding exactly as a lent one is. They never crossed `lend`, so a
        // peer naming one on the free ring is claiming to return something it
        // was never given. Accepting it would put a buffer the NIC is actively
        // writing back on the free stack for `alloc` to hand to a second owner.
        let mut fx = RxFixture::new();
        assert!(fx.refill());
        let posted = fx.posted_buffers();
        assert_eq!(posted.len(), Q, "refill fills the whole queue");
        let owned_before = fx.owner.owned();

        for buffer in &posted {
            fx.peer_returns_buffer(*buffer);
        }

        // Refused, every one, and counted as a peer that named a buffer it was
        // never lent — not as this driver's own bookkeeping fault.
        assert_eq!(fx.reclaim(), 0);
        assert_eq!(fx.owner.counters().reclaim_not_lent, posted.len() as u64);
        assert_eq!(fx.owner.counters().reclaim_refused, 0);
        assert_eq!(fx.counters.invariant, InvariantFaults::default());

        // The buffers stayed this driver's: the ledger did not grow, and the
        // slot map still holds exactly the same tokens.
        assert_eq!(fx.owner.owned(), owned_before);
        assert_eq!(fx.posted_buffers(), posted);

        // The decisive check: not one of them can be handed out again while it
        // is still a live DMA target. Draining the whole ledger must yield only
        // buffers that are not posted, and never a duplicate.
        let free = fx.drain_ledger_distinctly();
        assert_eq!(free, POOL_BUFFERS - Q);
        assert_eq!(fx.posted_buffers(), posted, "a posted buffer was re-issued");
    }

    #[test]
    fn a_peer_restart_with_buffers_in_flight_never_double_owns_one() {
        // The peer crashes and comes back with every shared cursor re-zeroed
        // while this driver has buffers posted at its NIC *and* frames lent to
        // the peer. Both of this domain's positions and both halves of its
        // ownership record are private, so the restart can replay and lose
        // descriptors but must never make one buffer answer to two owners.
        let mut fx = RxFixture::new();
        assert!(fx.refill());
        let frame = std::vec![0u8; VirtioNetHdr::LEN + 32];
        for _ in 0..4 {
            fx.device.deliver(&frame, frame.len() as u32);
        }
        assert!(fx.drain());
        let lent: Vec<Descriptor> = core::iter::from_fn(|| fx.forwarded()).collect();
        assert_eq!(lent.len(), 4, "four frames reached the peer");

        // The restart: every cursor of both rings back to zero, mid-stream.
        forge_cursors(&fx.rings.rx, 0, 0);
        forge_cursors(&fx.returns.free, 0, 0);

        // The far driver, also restarted, returns the frames it still had.
        for descriptor in &lent {
            fx.peer_returns_buffer(descriptor.buffer);
        }
        let reclaimed = fx.reclaim();
        assert!(
            reclaimed <= lent.len(),
            "more returns accepted than were lent"
        );

        // Keep driving both paths across the restart; nothing may fault, and
        // this driver may never look like it has a bug of its own.
        for _ in 0..4 {
            fx.refill();
            fx.device.deliver(&frame, frame.len() as u32);
            fx.drain();
            fx.reclaim();
            assert_eq!(fx.counters.invariant, InvariantFaults::default());
        }

        // Conservation, read out of the ledger and the slot map together: every
        // buffer this domain can still name is a real, distinct pool index, and
        // free plus posted never exceeds the pool.
        let posted = fx.posted_buffers();
        let free = fx.drain_ledger_distinctly();
        assert!(
            free + posted.len() <= POOL_BUFFERS,
            "free plus posted exceeds the pool, so a buffer was invented"
        );
        assert_eq!(fx.counters.invariant, InvariantFaults::default());
    }

    #[test]
    fn a_valid_frame_is_posted_with_a_zeroed_header_and_returned_on_completion() {
        let mut fx = TxFixture::new();
        let payload = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let descriptor = Descriptor::new(
            7,
            VirtioNetHdr::LEN as u32,
            payload.len() as u32,
            Verdict::Transmit,
        );
        fx.enqueue_frame(7, VirtioNetHdr::LEN, &payload);

        assert!(fx.post());
        assert_eq!(fx.faults(), Faults::default());

        // The device sees the frame with the 12 header bytes zeroed in front.
        let on_wire = fx.device.transmit();
        assert_eq!(on_wire.len(), VirtioNetHdr::LEN + payload.len());
        assert_eq!(&on_wire[..VirtioNetHdr::LEN], &[0u8; VirtioNetHdr::LEN]);
        assert_eq!(&on_wire[VirtioNetHdr::LEN..], &payload);

        // Reaping the completion returns the original descriptor to its owner.
        fx.reap();
        assert_eq!(fx.returned(), Some(descriptor));
        assert_eq!(fx.vq.free_count(), Q);
    }

    #[test]
    fn a_discarded_frame_returns_its_buffer_without_reaching_the_device() {
        // The routing drop, which is ordinary traffic rather than misbehaviour:
        // the producing domain decided against the wire, so nothing may be
        // posted and no pool byte written — and the buffer must still come
        // back, or the pool bleeds one per drop and the port dies in seconds.
        let mut fx = TxFixture::new();
        let untouched = [0xFFu8; VirtioNetHdr::LEN];
        // SAFETY: single-threaded test; buffer 6 is not otherwise in use and the
        // span lies within it.
        unsafe { fx.pool.write_at(6, 0, &untouched) }.expect("the header span lies within it");
        let discarded = Descriptor::new(6, VirtioNetHdr::LEN as u32, 8, Verdict::Discard);
        fx.queue(discarded);

        assert!(!fx.post(), "a discard must not ring the transmit doorbell");
        assert_eq!(
            fx.counters,
            Counters {
                traffic: Traffic::default(),
                input: InputDrops {
                    tx_discarded: 1,
                    ..InputDrops::default()
                },
                invariant: InvariantFaults::default(),
            }
        );
        assert_eq!(fx.vq.free_count(), Q, "no descriptor reached the device");
        assert!(
            fx.device.next_avail().is_none(),
            "a discarded frame was made available to the device"
        );

        // The reserved header space still holds what the test put there, so the
        // header write was never even attempted.
        let mut storage = [0u8; BUFFER_SIZE];
        // SAFETY: as above; the snapshot lands in this test's own storage, so
        // nothing borrows the pool.
        let bytes = unsafe {
            fx.pool
                .copy_out(6, 0, VirtioNetHdr::LEN as u32, &mut storage)
        }
        .expect("the header span lies within the buffer");
        assert_eq!(bytes, &untouched, "a discarded buffer was written to");

        // And it went back along the path a completed transmit uses.
        assert_eq!(fx.returned(), Some(discarded));
    }

    #[test]
    fn an_undecodable_verdict_returns_the_buffer_under_its_own_counter() {
        // A peer defect rather than a decision. The buffer is handled exactly as
        // a discard's — nothing may leak on a value nobody chose — while the
        // tally stays separate, or a peer writing garbage would hide
        // inside a routing-drop rate that is expected to be non-zero.
        let mut fx = TxFixture::new();
        let forged = Descriptor {
            buffer: 2,
            offset: VirtioNetHdr::LEN as u32,
            len: 8,
            verdict: 0xDEAD_BEEF,
        };
        fx.queue(forged);

        assert!(!fx.post());
        assert_eq!(
            fx.counters,
            Counters {
                traffic: Traffic::default(),
                input: InputDrops {
                    tx_verdict_undecodable: 1,
                    ..InputDrops::default()
                },
                invariant: InvariantFaults::default(),
            }
        );
        assert_eq!(fx.vq.free_count(), Q);
        assert!(fx.device.next_avail().is_none());
        assert_eq!(fx.returned(), Some(forged));
    }

    #[test]
    fn a_discard_naming_a_forged_index_is_counted_and_not_returned() {
        // A forged index has no owner, so returning it would put a buffer that
        // never existed onto someone's free stack — the reason the malformed
        // path withholds the return, and it holds however the frame is marked.
        let mut fx = TxFixture::new();
        for verdict in [Verdict::Discard, Verdict::Transmit] {
            fx.queue(Descriptor::new(
                POOL_BUFFERS as u32,
                VirtioNetHdr::LEN as u32,
                8,
                verdict,
            ));
            assert!(!fx.post());
            assert!(fx.returned().is_none());
        }
        assert_eq!(fx.counters.input.tx_discarded, 1);
        assert_eq!(fx.counters.input.tx_malformed, 1);
        assert_eq!(fx.counters.invariant, InvariantFaults::default());
    }

    #[test]
    fn a_duplicate_is_refused_before_a_discard_can_make_it_a_second_return() {
        // A buffer is in flight at the device and the peer queues it again,
        // this time marked against the wire. Acting on the mark would produce
        // the second return for a buffer that was lent once — which is why the
        // duplicate check sits ahead of the verdict branch and not beside it.
        let mut fx = TxFixture::new();
        fx.enqueue_frame(4, VirtioNetHdr::LEN, &[0xABu8; 6]);
        assert!(fx.post());

        fx.queue(Descriptor::new(
            4,
            VirtioNetHdr::LEN as u32,
            6,
            Verdict::Discard,
        ));
        assert!(!fx.post());
        assert_eq!(fx.counters.input.tx_duplicate, 1);
        assert_eq!(
            fx.counters.input.tx_discarded, 0,
            "the mark was not acted on"
        );
        assert!(fx.returned().is_none());

        // The in-flight instance still owes exactly one return, and delivers it.
        fx.device.transmit();
        fx.reap();
        assert!(fx.returned().is_some());
        assert!(fx.returned().is_none());
    }

    #[test]
    fn a_forged_buffer_index_is_dropped_without_a_return() {
        let mut fx = TxFixture::new();
        // Buffer index past the pool: it has no owner to return to.
        fx.queue(Descriptor::new(
            POOL_BUFFERS as u32,
            VirtioNetHdr::LEN as u32,
            8,
            Verdict::Transmit,
        ));

        assert!(!fx.post());
        assert_eq!(fx.counters.input.tx_malformed, 1);
        assert!(fx.returned().is_none());
        assert_eq!(fx.vq.free_count(), Q);
    }

    #[test]
    fn an_out_of_bounds_span_is_dropped_and_the_buffer_returned() {
        let mut fx = TxFixture::new();
        // Real buffer, but the span runs past the buffer end.
        let bad = Descriptor::new(
            3,
            VirtioNetHdr::LEN as u32,
            BUFFER_SIZE as u32,
            Verdict::Transmit,
        );
        fx.queue(bad);

        assert!(!fx.post());
        assert_eq!(fx.counters.input.tx_malformed, 1);
        // The index names a real buffer, so it is returned, not leaked.
        assert_eq!(fx.returned(), Some(bad));
        assert_eq!(fx.vq.free_count(), Q);
    }

    #[test]
    fn a_frame_without_header_room_is_dropped_and_the_buffer_returned() {
        let mut fx = TxFixture::new();
        // In bounds, but the offset leaves no room for the virtio-net header.
        let bad = Descriptor::new(5, (VirtioNetHdr::LEN - 1) as u32, 8, Verdict::Transmit);
        fx.queue(bad);

        assert!(!fx.post());
        assert_eq!(fx.counters.input.tx_malformed, 1);
        assert_eq!(fx.returned(), Some(bad));
        assert_eq!(fx.vq.free_count(), Q);
    }

    #[test]
    fn a_duplicate_transmit_descriptor_is_dropped_without_a_second_post_or_return() {
        // A byzantine peer hands the same buffer over twice. Posting both
        // would put two virtqueue entries on one buffer and produce two returns
        // for a buffer that was lent once — the second of which the pool owner
        // would refuse, losing it.
        let mut fx = TxFixture::new();
        let payload = [0xABu8; 6];
        fx.enqueue_frame(4, VirtioNetHdr::LEN, &payload);
        assert!(fx.post());
        let free_after_first = fx.vq.free_count();

        fx.queue(Descriptor::new(
            4,
            VirtioNetHdr::LEN as u32,
            payload.len() as u32,
            Verdict::Transmit,
        ));
        assert!(!fx.post());
        assert_eq!(fx.counters.input.tx_duplicate, 1);
        assert_eq!(fx.vq.free_count(), free_after_first, "nothing was posted");
        assert!(
            fx.returned().is_none(),
            "the duplicate must not produce a second return"
        );

        // The in-flight instance still owes exactly one return, and delivers it.
        fx.device.transmit();
        fx.reap();
        assert!(fx.returned().is_some());
        assert!(fx.returned().is_none());
    }

    #[test]
    fn a_duplicate_transmit_completion_is_refused_by_the_virtqueue() {
        // The transmit mirror of the receive case above: the duplicate is
        // refused by `poll`, so it is asserted there, while the consequence
        // this crate owes — exactly one return per lent buffer — is asserted
        // here.
        let mut fx = TxFixture::new();
        let payload = [1u8, 2, 3, 4];
        fx.enqueue_frame(9, VirtioNetHdr::LEN, &payload);
        assert!(fx.post());
        let head = fx.device.next_avail().expect("a frame was posted");
        fx.device
            .complete(head, (VirtioNetHdr::LEN + payload.len()) as u32);

        // First reap returns the buffer and recycles the descriptor.
        fx.reap();
        assert!(fx.returned().is_some());
        let free_after = fx.vq.free_count();

        fx.device.complete(head, 0);
        fx.reap();
        assert_eq!(fx.device_faults().completion_not_posted, 1);
        assert_eq!(fx.faults(), Faults::default());
        assert!(
            fx.returned().is_none(),
            "the duplicate must not produce a second return"
        );
        assert_eq!(fx.vq.free_count(), free_after);
    }

    #[test]
    fn reap_is_bounded_when_the_device_floods_completions() {
        // Nothing is posted, so every completion the device publishes names a
        // descriptor it was never given. As on the receive side the bound is
        // the virtqueue's per-`poll` budget of Q used entries, and `reap` makes
        // exactly that much progress per call.
        let mut fx = TxFixture::new();
        for _ in 0..8 * Q {
            fx.device.complete(0, 0);
        }
        fx.reap();
        assert_eq!(
            fx.device_faults().completion_not_posted,
            Q as u64,
            "at most Q completions are examined per call"
        );
        fx.reap();
        assert_eq!(fx.device_faults().completion_not_posted, 2 * Q as u64);
        assert_eq!(fx.faults(), Faults::default());
        assert!(fx.returned().is_none());
        assert_eq!(
            fx.vq.free_count(),
            Q,
            "nothing was posted, nothing recycled"
        );
    }

    #[test]
    fn a_full_free_ring_drops_and_counts_rather_than_faulting() {
        // The peer-reachable panic this replaces: a peer queues more
        // malformed-but-in-range descriptors than the free ring can hold, every
        // one takes the return path, and the ring fills.
        let mut fx = TxFixture::new();
        let capacity = fx.free.free.capacity();
        // In bounds, but no header room, so each is rejected *and* returned.
        let bad = Descriptor::new(1, 0, 8, Verdict::Transmit);

        for _ in 0..capacity {
            fx.queue(bad);
        }
        assert!(!fx.post());
        assert_eq!(fx.counters.input.tx_malformed, capacity as u64);
        assert_eq!(fx.counters.input.tx_free_ring_full, 0);

        // One more return than the free ring can hold.
        fx.queue(bad);
        assert!(!fx.post());
        assert_eq!(fx.counters.input.tx_free_ring_full, 1);
    }

    #[test]
    fn post_stops_at_a_full_virtqueue_and_leaves_the_rest_queued() {
        // More valid frames than the virtqueue holds. The surplus must stay on
        // the ring for the next round rather than be dequeued into nowhere,
        // which would lose a buffer per frame.
        let mut fx = TxFixture::new();
        for buffer in 0..(Q as u32 + 2) {
            fx.enqueue_frame(buffer, VirtioNetHdr::LEN, &[0xC3u8; 4]);
        }

        assert!(fx.post());
        assert_eq!(fx.vq.free_count(), 0, "the virtqueue is full");
        assert_eq!(fx.faults(), Faults::default());

        // Drain the device and reap, then the surplus goes out.
        for _ in 0..Q {
            fx.device.transmit();
        }
        fx.reap();
        assert!(fx.post());
        assert_eq!(fx.vq.free_count(), Q - 2);
        assert_eq!(fx.faults(), Faults::default());
    }

    #[test]
    fn post_is_bounded_when_a_peer_floods_malformed_descriptors() {
        // A malformed descriptor consumes no virtqueue descriptor, so the free
        // count never falls: only the iteration cap ends the loop. Forge the
        // shared cursor so the ring always looks non-empty, exactly as a peer
        // that keeps publishing does.
        let mut fx = TxFixture::new();
        for round in 0..6u32 {
            forge_cursors(&fx.rings.tx, 0, round.wrapping_mul(31).wrapping_add(7));
            assert!(!fx.post());
        }
        // Bounded per call: never more than DRAIN_LIMIT rejections in a round.
        assert!(fx.counters.input.tx_malformed <= 6 * DRAIN_LIMIT as u64);
        assert_eq!(
            fx.vq.free_count(),
            Q,
            "nothing malformed reached the device"
        );
    }

    /// A second virtqueue over its own region, plus the device on its far side.
    /// Driving a path against this one while it was filled from the fixture's
    /// own queue is the only way to reach an [`InvariantFaults`] field at all —
    /// which is the point: no device or peer input can.
    struct StrayQueue {
        _region: Box<VqRegion>,
        vq: Vq,
        device: FakeDevice,
    }

    impl StrayQueue {
        fn new() -> Self {
            let mut region = VqRegion::boxed();
            let ptr = region.0.as_mut_ptr();
            // SAFETY: `ptr` backs a 16-byte-aligned, zeroed VqRegion owned
            // solely by this test — `Vq::new`'s contract.
            let vq = unsafe { Vq::new(ptr) };
            Self {
                _region: region,
                vq,
                device: FakeDevice::new(ptr),
            }
        }

        /// Post one buffer at `paddr` and have the device complete it, so a
        /// `poll` on this queue yields a completion no other path ever mapped.
        fn post_and_complete(&mut self, paddr: u64, used_len: u32) {
            let head = self
                .vq
                .add_writable(paddr, BUFFER_SIZE as u32)
                .expect("a descriptor is free");
            self.device.complete(head, used_len);
        }
    }

    #[test]
    fn a_receive_completion_for_an_unmapped_slot_is_a_driver_fault_not_traffic() {
        // The device cannot produce this: `poll` refuses a completion for a
        // descriptor its own queue did not post. Reaching the empty slot takes
        // a driver that drives one path against two virtqueues — a wiring
        // defect, which is exactly what the counter names.
        let mut fx = RxFixture::new();
        let mut stray = StrayQueue::new();
        stray.post_and_complete(0x1000, (VirtioNetHdr::LEN + 8) as u32);

        // The path has posted nothing, so every slot of its map is empty.
        assert!(!fx.rx.drain(&mut stray.vq, &mut fx.owner, &mut fx.counters));
        assert_eq!(fx.counters.invariant.rx_completion_unmapped, 1);
        assert_eq!(fx.counters.input, InputDrops::default());
        assert!(fx.forwarded().is_none(), "no frame may be invented");
        // The descriptor still belongs to the queue that posted it, so it goes
        // back rather than leaking.
        assert_eq!(stray.vq.free_count(), Q);
        assert_eq!(stray.vq.device_faults(), DeviceFaults::default());
    }

    #[test]
    fn a_transmit_completion_for_an_unmapped_slot_is_a_driver_fault_not_traffic() {
        let mut fx = TxFixture::new();
        let mut stray = StrayQueue::new();
        stray.post_and_complete(0x1000, 64);

        fx.tx.reap(&mut stray.vq, &mut fx.counters);
        assert_eq!(fx.counters.invariant.tx_completion_unmapped, 1);
        assert_eq!(fx.counters.input, InputDrops::default());
        assert!(
            fx.returned().is_none(),
            "no buffer may be returned for a descriptor never lent"
        );
        assert_eq!(stray.vq.free_count(), Q);
    }

    #[test]
    fn refilling_an_already_mapped_slot_leaks_the_buffer_and_counts_the_fault() {
        // Same wiring defect from the other end: a fresh queue hands out slots
        // this path has already filled from another. The displaced buffer is
        // still a live DMA target of the first queue, so it must be leaked and
        // never returned to the pool, where it could be issued a second time.
        let mut fx = RxFixture::new();
        assert!(fx.refill());
        let owned_after_first = fx.owner.owned();
        let mut stray = StrayQueue::new();

        assert!(fx.rx.refill(&mut stray.vq, &mut fx.owner, &mut fx.counters));
        assert_eq!(fx.counters.invariant.rx_slot_occupied, Q as u64);
        assert_eq!(fx.counters.input, InputDrops::default());
        // Q buffers were taken from the pool and Q leaked, none released back.
        assert_eq!(fx.owner.owned(), owned_after_first - Q);
    }

    #[test]
    fn posting_into_an_already_mapped_slot_leaks_the_buffer_and_counts_the_fault() {
        // The transmit mirror of the test above, and the same wiring defect:
        // a second queue hands out slots this path has already filled from the
        // first. The displaced descriptor names a buffer the first queue may
        // still be reading, so the assertions are that it is *not* returned —
        // returning it would let the pool issue a live DMA target a second
        // time — and that it is not silently lost either.
        let mut fx = TxFixture::new();
        for buffer in 0..Q as u32 {
            fx.queue(Descriptor::new(
                buffer,
                VirtioNetHdr::LEN as u32,
                8,
                Verdict::Transmit,
            ));
        }
        assert!(fx.post());
        assert_eq!(fx.faults(), Faults::default());

        // A fresh queue restarts at slot zero, so every one of these collides.
        let mut stray = StrayQueue::new();
        for buffer in Q as u32..2 * Q as u32 {
            fx.queue(Descriptor::new(
                buffer,
                VirtioNetHdr::LEN as u32,
                8,
                Verdict::Transmit,
            ));
        }
        assert!(fx.tx.post(&mut stray.vq, &mut fx.counters));

        assert_eq!(fx.counters.invariant.tx_slot_occupied, Q as u64);
        assert_eq!(fx.counters.input, InputDrops::default());
        assert!(
            fx.returned().is_none(),
            "a displaced descriptor's buffer is leaked, never returned to the pool"
        );

        // The displaced buffer keeps its in-flight bit, which is what stops it
        // being posted a second time while the first queue may still hold it:
        // re-queueing buffer 0 is refused as a duplicate rather than reposted.
        let mut third = StrayQueue::new();
        fx.queue(Descriptor::new(
            0,
            VirtioNetHdr::LEN as u32,
            8,
            Verdict::Transmit,
        ));
        assert!(!fx.tx.post(&mut third.vq, &mut fx.counters));
        assert_eq!(fx.counters.input.tx_duplicate, 1);
        assert!(fx.returned().is_none());
    }

    #[test]
    fn driver_stats_sample_both_virtqueues_and_the_counters() {
        // The metrics endpoint (CONCEPT §11) needs one consistent picture, and
        // device misbehaviour must reach it rather than stay inside the queue.
        let mut rx = RxFixture::new();
        let mut tx = TxFixture::new();
        rx.refill();
        // A forged id on receive, a replay on transmit.
        rx.device.complete(9999, 0);
        rx.drain();
        tx.device.complete(0, 0);
        tx.reap();
        rx.counters.input.tx_duplicate = 7;

        let stats = DriverStats::sample(&rx.counters, &rx.vq, &tx.vq);
        assert_eq!(stats.rx_device.completion_out_of_range, 1);
        assert_eq!(stats.tx_device.completion_not_posted, 1);
        assert_eq!(stats.counters.input.tx_duplicate, 7);
        assert_eq!(stats.counters.invariant, InvariantFaults::default());
    }

    /// One whole transmit pipeline with the buffer cycle closed: the
    /// pool-owning peer at one end, this driver's transmit path at the other,
    /// and a byzantine peer between them choosing the verdict word.
    ///
    /// The publishing driver and the peer are collapsed into one
    /// [`publish`](Self::publish), since the descriptor a peer emits is
    /// what this fixture is about and the `rx` ring in between moves it
    /// unchanged. It is the only fixture here that closes the cycle, which is
    /// what makes "no buffer is leaked" observable at all: with the pool owner
    /// absent, a buffer that never comes back is indistinguishable from one
    /// nobody asked for.
    struct PipelineFixture {
        rings: &'static ForwardRings,
        _region: Box<VqRegion>,
        vq: Vq,
        device: FakeDevice,
        owner: PoolOwner<'static>,
        /// The peer's end of the `tx` ring, taken once for the fixture's
        /// life; see [`RxFixture::peer`].
        peer: RingProducer<'static, RING_SLOTS>,
        tx: TxPath<'static, Q>,
        /// How many descriptors that handle has published, and so which slot
        /// the next one lands in — the producer starts at zero and advances one
        /// slot per successful enqueue.
        published: usize,
        counters: Counters,
    }

    impl PipelineFixture {
        fn new() -> Self {
            let pool: &'static Pool = Box::leak(Box::new(Pool::new()));
            let rings: &'static ForwardRings = Box::leak(Box::new(ForwardRings::new()));
            let returns: &'static ReturnRing = Box::leak(Box::new(ReturnRing::new()));
            let mut region = VqRegion::boxed();
            let ptr = region.0.as_mut_ptr();
            // SAFETY: `ptr` backs a 16-byte-aligned, zeroed VqRegion owned
            // solely by this test — `Vq::new`'s contract.
            let vq = unsafe { Vq::new(ptr) };
            let device = FakeDevice::new(ptr);
            let pool_paddr = core::ptr::from_ref(pool) as u64;
            Self {
                rings,
                _region: region,
                vq,
                device,
                owner: PoolOwner::attach(returns),
                peer: rings.tx.producer(),
                tx: TxPath::attach(rings, returns, pool, pool_paddr),
                published: 0,
                counters: Counters::default(),
            }
        }

        /// Take a buffer from the pool and queue it for transmit under a verdict
        /// word wholly of the peer's choosing.
        ///
        /// `lend` cannot mint an undecodable word, so the peer writes it
        /// into the shared slot afterwards — which is what the peer really
        /// does, and the only way this case is expressible at all.
        fn publish(&mut self, len: u32, verdict_bits: u32) {
            let Some(buffer) = self.owner.alloc() else {
                return;
            };
            if let Err(returned) = self.owner.lend(
                &mut self.peer,
                buffer,
                VirtioNetHdr::LEN as u32,
                len,
                Verdict::Transmit,
            ) {
                self.owner.release(returned);
                return;
            }
            forge_slot_verdict(&self.rings.tx, self.published, verdict_bits);
            self.published += 1;
        }

        fn post(&mut self) -> bool {
            self.tx.post(&mut self.vq, &mut self.counters)
        }

        /// Let the device finish everything it was made available, then reap.
        fn complete_and_reap(&mut self) {
            while let Some(head) = self.device.next_avail() {
                let len = self.device.desc_len(head);
                self.device.complete(head, len);
            }
            self.tx.reap(&mut self.vq, &mut self.counters);
        }

        fn reclaim(&mut self) -> usize {
            self.owner.reclaim()
        }

        /// Buffers this driver has at the device right now — the only ones
        /// legitimately outside the owner's ledger once the pipeline is idle.
        fn in_flight(&self) -> usize {
            self.tx.in_flight.iter().filter(|held| **held).count()
        }
    }

    /// One move the byzantine peer makes against a closed pipeline.
    #[derive(Clone, Debug)]
    enum TxStep {
        /// Publish a buffer under a verdict word of the peer's choosing.
        Publish(u32, u32),
        /// Hand what is queued to the device.
        Post,
        /// Let the device finish, and reap the completions.
        Complete,
        /// Take the returns back into the pool.
        Reclaim,
    }

    /// A verdict word as a byzantine peer writes it: both values that
    /// decode, and the whole of the space that does not. The undecodable case
    /// is not a rare accident of `any::<u32>()` here — it is weighted in, so a
    /// strategy edit cannot quietly stop generating it (TEST-8).
    fn any_verdict_bits() -> impl Strategy<Value = u32> {
        prop_oneof![
            3 => Just(Verdict::Transmit.to_bits()),
            3 => Just(Verdict::Discard.to_bits()),
            2 => any::<u32>(),
        ]
    }

    fn any_tx_step() -> impl Strategy<Value = TxStep> {
        prop_oneof![
            5 => (1u32..64, any_verdict_bits()).prop_map(|(len, bits)| TxStep::Publish(len, bits)),
            4 => Just(TxStep::Post),
            3 => Just(TxStep::Complete),
            3 => Just(TxStep::Reclaim),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// The property this whole ABI exists to establish, over a long run of
        /// mixed transmit, discard and undecodable verdicts in arbitrary
        /// interleaving: every buffer comes home.
        ///
        /// A discard is normal traffic, so if the transmit path dropped a
        /// discarded descriptor without returning its buffer the pool would
        /// shrink by one per routing decision and a 64-buffer port would stop
        /// within seconds — a leak no panic and no counter would reveal. The
        /// mirror failure is as bad: returning a buffer that is still in flight
        /// would give it two owners. So the assertion is both halves at once —
        /// once the pipeline is drained the ledger holds the *whole* pool, and
        /// what it hands out is pairwise distinct.
        #[test]
        fn mixed_verdicts_never_leak_a_buffer_or_give_one_two_owners(
            steps in prop::collection::vec(any_tx_step(), 0..300),
        ) {
            let mut fx = PipelineFixture::new();

            for step in steps {
                match step {
                    TxStep::Publish(len, bits) => fx.publish(len, bits),
                    TxStep::Post => {
                        fx.post();
                    }
                    TxStep::Complete => fx.complete_and_reap(),
                    TxStep::Reclaim => {
                        prop_assert!(fx.reclaim() <= DRAIN_LIMIT);
                    }
                }
                // Conservation at every instant: nothing is invented, so what
                // the owner holds free plus what sits at the device can never
                // exceed the pool.
                prop_assert!(fx.owner.owned() + fx.in_flight() <= POOL_BUFFERS);
                // And no verdict the peer chose may be recorded as our defect.
                prop_assert_eq!(fx.counters.invariant, InvariantFaults::default());
            }

            // Drain: post what is queued, let the device finish it, reclaim the
            // returns. The pool holds 64 buffers and the queue takes 16 at a
            // time, so four rounds suffice for anything still in flight; eight
            // leaves margin without ever being what ends the loop, which the
            // assertion below is the check on.
            for _ in 0..8 {
                fx.post();
                fx.complete_and_reap();
                fx.reclaim();
            }
            prop_assert_eq!(
                fx.owner.owned(),
                POOL_BUFFERS,
                "the pool did not come whole again: a buffer was leaked"
            );

            let mut seen = [false; POOL_BUFFERS];
            let mut handed_out = 0usize;
            while let Some(buffer) = fx.owner.alloc() {
                let index = buffer.index() as usize;
                prop_assert!(index < POOL_BUFFERS, "the ledger held index {}", index);
                prop_assert!(!seen[index], "index {} was handed to two owners", index);
                seen[index] = true;
                handed_out += 1;
            }
            prop_assert_eq!(handed_out, POOL_BUFFERS);
        }

        /// Arbitrary device behaviour against the receive path: completions for
        /// arbitrary head indices with arbitrary reported lengths, in arbitrary
        /// order, interleaved with refills. Nothing may panic, work per call
        /// stays bounded, and no pool buffer may ever be owned twice — the
        /// buffers still posted plus those the owner holds free plus those
        /// handed to the peer must never exceed the pool.
        #[test]
        fn arbitrary_device_completions_never_panic_or_double_own_a_buffer(
            events in prop::collection::vec((any::<u16>(), any::<u32>(), any::<bool>()), 0..200),
        ) {
            let mut fx = RxFixture::new();
            let mut forwarded = 0usize;
            fx.refill();

            for (head, used_len, do_refill) in events {
                // A device may only ever name a slot of its queue; `poll`
                // already rejects a wider id, so drive the interesting range.
                fx.device.complete(head % (Q as u16), used_len);
                fx.drain();
                if do_refill {
                    fx.refill();
                }
                forwarded += fx.peer.drain(DRAIN_LIMIT).count();
                let posted = fx.rx.posted.iter().filter(|slot| slot.is_some()).count();
                prop_assert!(
                    posted + fx.owner.owned() <= POOL_BUFFERS,
                    "a buffer is both posted to the device and free in the pool"
                );
                prop_assert!(fx.vq.free_count() <= Q);
                // No device behaviour may look like a fault of ours: the
                // virtqueue answers for the device, so this stays zero however
                // the device misbehaves.
                prop_assert_eq!(fx.counters.invariant, InvariantFaults::default());
            }
            // Nothing returns a buffer to the pool in this scenario, so the
            // whole run can hand the peer at most one frame per buffer.
            prop_assert!(forwarded <= POOL_BUFFERS, "more frames than the pool has buffers");
        }

        /// Arbitrary peer descriptors against the transmit path: forged
        /// indices, out-of-range spans, missing header room, duplicates, and
        /// valid frames, with the device completing at arbitrary points.
        /// Nothing may panic, and the free ring must never carry more returns
        /// than descriptors were accepted — one return per lent buffer.
        #[test]
        fn arbitrary_peer_descriptors_never_panic_or_return_a_buffer_twice(
            descriptors in prop::collection::vec(
                (
                    any::<u32>(),
                    any::<u32>(),
                    any::<u32>(),
                    any_verdict_bits(),
                    any::<bool>(),
                ),
                0..120,
            ),
        ) {
            let mut fx = TxFixture::new();
            let mut returned = 0usize;
            let mut offered = 0usize;

            for (buffer, offset, len, verdict, complete) in descriptors {
                // Bias towards plausible values so the valid path is reached at
                // all, while arbitrary ones keep forged spans in the mix. The
                // verdict is not reduced at all: it is one word wholly the
                // peer's, and the values that decode to nothing are exactly the
                // ones a bias towards the two variants would delete (TEST-8).
                let descriptor = Descriptor {
                    buffer: buffer % (POOL_BUFFERS as u32 + 2),
                    offset: offset % (BUFFER_SIZE as u32 + 2),
                    len: len % (BUFFER_SIZE as u32 + 2),
                    verdict,
                };
                if fx.peer.try_enqueue(descriptor).is_ok() {
                    offered += 1;
                }
                fx.post();
                if complete {
                    while fx.device.next_avail().is_some() {}
                    // Complete every posted head; ids outside the queue are the
                    // virtqueue's own concern and are covered there.
                    for head in 0..Q as u16 {
                        fx.device.complete(head, 0);
                    }
                    fx.reap();
                }
                returned += fx.returns.drain(DRAIN_LIMIT).count();
                let in_flight = fx.tx.in_flight.iter().filter(|held| **held).count();
                prop_assert!(in_flight <= Q, "more buffers in flight than the queue holds");
                prop_assert!(fx.vq.free_count() <= Q);
                // Neither the peer's descriptors nor the device's completions
                // may be mistaken for a fault of ours.
                prop_assert_eq!(fx.counters.invariant, InvariantFaults::default());
            }
            // Every return corresponds to a descriptor the peer offered; the
            // path can never invent one, so returns can never outnumber the
            // descriptors actually accepted onto the ring.
            prop_assert!(returned <= offered, "a buffer was returned more often than it was lent");
        }
    }
}
