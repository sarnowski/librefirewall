//! Host-testable driver logic for the virtio-net driver protection domain:
//! device bring-up, the steady-state dataplane, and the poll pass that runs it.
//!
//! The driver PD (`pds/nic-driver`) is a thin adapter. It maps the regions the
//! system description grants it, turns the three pointers into this crate's
//! types, and runs a loop; **everything that can be wrong in a logic sense
//! lives here**, where a host test can reach it. Three modules divide the work:
//!
//! | module | what it owns |
//! |---|---|
//! | [`bringup`] | PCI identification, BAR placement, the virtio 1.0 handshake *ordering*, virtqueue configuration, and the `DRIVER_OK`-before-first-doorbell rule |
//! | this root | the two steady-state directions, [`RxPath`] and [`TxPath`], and the counters |
//! | [`port`] | one poll pass: which step runs when, and which step rings which doorbell |
//!
//! The security-critical dataplane logic in this root — clamping a
//! device-reported length to the buffer behind it, dropping a runt frame,
//! validating an untrusted peer's transmit descriptors — is portable `no_std`
//! code for the same reason: it runs under host unit tests, which it never
//! could while welded to the Microkit entrypoint. Refusing the device's forged,
//! replayed, and out-of-range completions is one layer further down, in
//! `virtio::queue`, and is host-tested there.
//!
//! # Handles are taken once, at attach
//!
//! Both paths are parameterised by the pipeline region's lifetime and take
//! their ring handles in `attach`, keeping them for the protection domain's
//! whole life. A handle holds this domain's own position in the ring, so taking
//! one per call would restart at slot zero and re-walk slots already used; see
//! the `pd_runtime` crate header. A driver calls each `attach` exactly once per
//! pipeline: [`RxPath`] takes the receive pipeline's `rx` producer, [`TxPath`]
//! the transmit pipeline's `tx` consumer and `free` producer, and
//! `pd_runtime::PoolOwner` the receive pipeline's `free` consumer.
//!
//! # Untrusted inputs, and which layer answers for each
//!
//! Two distrust boundaries meet in this crate (CONCEPT §7.1), and one of them
//! is answered a layer below:
//!
//! - **The device** is hostile, but everything it can *say* about a completion
//!   — a forged or out-of-range descriptor id, a replay of one already reaped,
//!   an echo of one never published, a flood of used entries — is refused
//!   inside [`virtio::queue`] before a `Token` exists, and counted there in
//!   [`DeviceFaults`]. This crate keeps no second copy of that check: it would
//!   be a second answer to one question, and the queue is the layer holding the
//!   descriptor lifecycle the answer is derived from. What stays this crate's
//!   business is what the queue cannot know — that the reported length must be
//!   clamped to the *pool buffer* behind the descriptor before a downstream
//!   domain reads it, and that a completion with nothing past the virtio-net
//!   header carries no frame and is dropped at the rx edge rather than
//!   forwarded as a header-only one.
//! - **The forwarder peer** is untrusted: every transmit descriptor it queues
//!   is range-validated ([`pd_runtime::descriptor_in_bounds`], plus header
//!   room) before the span is touched, and checked against this driver's own
//!   in-flight set so the same buffer cannot be posted to the device twice. A
//!   descriptor naming a real pool buffer is returned to its owner; a forged
//!   index has no owner and is dropped. Nothing below the queue guards this
//!   boundary, so it is guarded here and nowhere else.
//!
//! Neither can drive this crate to an out-of-bounds access, a panic, or
//! unbounded work: every loop over a device- or peer-fed queue is capped per
//! call by a driver-owned bound (the virtqueue's own `Q`, or
//! `pd_runtime::DRAIN_LIMIT`), and every rejection above is a counted drop.
//! Returning a buffer on the pipeline's free ring is likewise fallible — a full
//! ring is counted, not asserted.
//!
//! One `expect` survives that sweep, in [`TxPath::post`], and it is the only
//! panic-capable construct outside this crate's tests and its `const _` layout
//! assertions. It rests on a virtqueue invariant no device or peer can reach;
//! the proof, its guarantor and the property test that holds it are stated at
//! the call site.
//!
//! # The per-slot maps are a map, not a second check
//!
//! Each path holds a per-virtqueue-slot `Option`: which pool buffer went into
//! each receive descriptor, which peer descriptor into each transmit one. That
//! is the token→buffer mapping, which only this crate can hold — the virtqueue
//! carries no payload. It is *not* the duplicate-completion check it used to
//! double as; the queue makes a completion for a descriptor it did not post
//! unrepresentable, so an empty slot no longer means "the device lied". It now
//! means this driver's own two pieces of state disagree, which is a defect in
//! this crate or in how a protection domain wired it — see [`InvariantFaults`].
//!
//! # What this crate cannot enforce
//!
//! Writing the virtio-net header in front of a transmit frame needs the buffer
//! to be exclusively this driver's for the duration. That is a *protocol*
//! claim, not one this domain can verify: the buffer belongs to the transmit
//! pipeline's pool, whose ledger lives in the peer driver that owns it. What is
//! checked here is everything that is checkable locally — the span lies inside
//! one pool buffer, and this driver is not already holding that buffer in
//! flight. A byzantine forwarder can still name a buffer the pool owner has
//! posted as its own NIC's receive DMA target, in which case the 12-byte header
//! write races that DMA. Closing that needs either an IOMMU confining NIC DMA
//! (CONCEPT §7.2) or a cross-domain per-buffer ownership epoch; neither exists
//! yet, and no code in this domain can substitute for them. The damage is
//! bounded to corrupting a frame inside the shared pool: the address handed to
//! the device is always inside the region, because it is derived from an index
//! that passed the pool bounds check.
//!
//! # Observability groundwork
//!
//! Three counter sets meet here, and keeping them apart is the point: a number
//! is only actionable if it says *who* misbehaved.
//!
//! | set | who it indicts | where it lives |
//! |---|---|---|
//! | [`DeviceFaults`] | the device lied about a completion | `virtio::queue`, one per virtqueue |
//! | [`InputDrops`] | the device or the peer sent something this layer refused | [`Counters::input`] |
//! | [`InvariantFaults`] | *we* are broken | [`Counters::invariant`] |
//!
//! [`DriverStats`] samples all three into one snapshot, which is the shape the
//! future Prometheus metrics endpoint (CONCEPT §11) scrapes. The console
//! deliberately carries none of it, being reserved for system state rather than
//! traffic (MONITORING.md).

#![cfg_attr(not(test), no_std)]

pub mod bringup;
pub mod port;

#[cfg(test)]
mod fake_device;

use pd_runtime::{
    BUFFER_SIZE, DRAIN_LIMIT, Descriptor, OwnedBuffer, POOL_BUFFERS, Pipeline, Pool, PoolOwner,
    RING_SLOTS, RingConsumer, RingProducer, descriptor_in_bounds,
};
use virtio::net::VirtioNetHdr;
use virtio::queue::{DeviceFaults, SplitVirtqueue, Token};

/// The tallies a driver protection domain keeps, split by who is answerable for
/// them. Passed to every path method, so one domain accumulates both halves
/// across its two directions.
///
/// The split is structural on purpose. Both halves are recorded the same way —
/// a saturating counter — so a flat struct would leave the only thing that
/// distinguishes "the network is hostile" from "we have a bug" to prose. Here
/// the type carries it, and an alert can be written against
/// [`invariant`](Self::invariant) alone.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    /// Frames refused because a neighbour sent something invalid. Expected to
    /// be non-zero on a hostile network.
    pub input: InputDrops,
    /// Violations of this crate's own invariants. Expected to be zero forever.
    pub invariant: InvariantFaults,
}

/// Counts of frames dropped on the untrusted-input boundaries, which are
/// otherwise invisible: a device or neighbour misbehaving at line rate would
/// look exactly like an idle link.
///
/// Every field is **monotonic** for the protection domain's life and
/// **saturates** at [`u64::MAX`] rather than wrapping. There is no reset: a
/// metrics endpoint derives a rate by differencing successive scrapes, so a
/// reset would forge a negative rate, and a wrap would turn a sustained flood
/// back into a small number — precisely when the number matters most.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InputDrops {
    /// Received frames with nothing past the virtio-net header, dropped at the
    /// rx edge instead of forwarded as a header-only frame.
    pub rx_runt_dropped: u64,
    /// Received frames dropped because the forwarder's ring would not take
    /// them. The buffer is returned to the pool, so nothing is lost but the
    /// frame — the forwarder is not keeping up, or is stalled deliberately.
    pub rx_forwarder_ring_full: u64,
    /// Transmit descriptors from the peer that failed span or header-room
    /// validation.
    pub tx_malformed: u64,
    /// Transmit descriptors naming a buffer this driver already has in flight
    /// at the device. Dropped without a return, because the in-flight instance
    /// still owes that buffer's single return.
    pub tx_duplicate: u64,
    /// Buffer returns that could not be placed on the pipeline's free ring.
    /// Each one loses its buffer to the pool owner's ledger for good; the
    /// alternative — asserting — would let a peer that stalls the ring take
    /// this domain down.
    pub tx_free_ring_full: u64,
}

/// Counts of this driver's own broken bookkeeping. **A non-zero field here is a
/// defect in this crate or in how a protection domain wired it, never traffic.**
///
/// No device or peer input can reach any of these: `virtio::queue` refuses a
/// completion for a descriptor it did not post, so every `Token` this crate
/// sees names a descriptor its own `refill`/`post` published and its own
/// per-slot map recorded. What is left that could trip them is driving one path
/// against two different virtqueues, which only this domain's own wiring can
/// do.
///
/// They are counted rather than asserted, unlike the equivalent in
/// `pd_runtime::PoolOwner::release`, and the difference is deliberate: these
/// sit on the path a hostile device drives at line rate, so being *wrong* about
/// their unreachability would turn a reasoning error into a remotely triggered
/// outage of a dataplane port. A saturating counter under a name that means
/// "page someone" keeps the failure loud without handing the device a kill
/// switch. The same monotonic/saturating contract as [`InputDrops`] applies.
///
/// What makes each of them worth a counter rather than a panic is that each is
/// *reachable*: driving one path against two virtqueues trips it, which is what
/// each one's test does. An unreachability argument that no wiring defect can
/// falsify does not belong here — see the `expect` in [`TxPath::post`], whose
/// check and use sit on the same queue in the same iteration.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InvariantFaults {
    /// A receive completion whose slot held no buffer: the virtqueue and this
    /// path's map disagree about what was posted. The frame is lost and the
    /// descriptor recycled.
    pub rx_completion_unmapped: u64,
    /// A transmit completion whose slot held no descriptor — the transmit
    /// mirror of [`rx_completion_unmapped`](Self::rx_completion_unmapped). No
    /// buffer is returned, so the pool loses one.
    pub tx_completion_unmapped: u64,
    /// `refill` was handed a descriptor whose slot still held a buffer. That
    /// buffer is still a live DMA target somewhere, so it is leaked rather than
    /// released: putting it back in the pool would let it be issued a second
    /// time, which is the one outcome worse than losing it.
    pub rx_slot_occupied: u64,
    /// [`SplitVirtqueue::recycle`] refused a token this path had just reaped
    /// from that same queue, which no consistent pairing can produce. That
    /// descriptor never returns to the virtqueue's free list, so the queue
    /// permanently loses one of its `Q` slots.
    pub descriptor_recycle_refused: u64,
}

/// A snapshot of everything a driver protection domain can say about its two
/// neighbours and itself, in the shape the metrics endpoint (CONCEPT §11) will
/// scrape. Taken by value: the device faults live in the virtqueues and the
/// rest in [`Counters`], and a scrape wants one consistent picture, not four
/// live borrows.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DriverStats {
    /// What this crate refused or broke; see [`Counters`].
    pub counters: Counters,
    /// What the receive virtqueue refused from the device.
    pub rx_device: DeviceFaults,
    /// What the transmit virtqueue refused from the device.
    pub tx_device: DeviceFaults,
}

impl DriverStats {
    /// Sample the driver's two virtqueues and its counters together.
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

/// Increment a counter, saturating rather than wrapping; see [`InputDrops`].
fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// Return a just-reaped descriptor to its virtqueue's free list.
///
/// Shared by both paths so the refusal is handled in exactly one place. A
/// refusal is impossible for a token polled from this same queue an instant
/// earlier — `poll` leaves the descriptor in precisely the state `recycle`
/// requires — so it is recorded as an invariant fault, never as device
/// evidence; see [`InvariantFaults`] for why it is counted and not asserted.
fn recycle_descriptor<const Q: usize>(
    queue: &mut SplitVirtqueue<Q>,
    token: Token,
    faults: &mut InvariantFaults,
) {
    if queue.recycle(token).is_err() {
        bump(&mut faults.descriptor_recycle_refused);
    }
}

/// The receive path: which pool buffer is posted in each virtqueue slot, and
/// the handle onto which completed frames are published.
///
/// Ownership of a posted buffer is held as a move-only [`OwnedBuffer`] in a
/// per-slot `Option`, which is what makes the buffer's single ownership
/// checkable by the compiler for as long as it is inside this domain: the
/// `take()` on completion moves it out, so the frame cannot be handed onward
/// twice even by a coding error here.
pub struct RxPath<'pipe, const Q: usize> {
    /// The buffer handed to the device in each descriptor slot.
    posted: [Option<OwnedBuffer>; Q],
    /// Where completed frames are published to the forwarder. Taken once.
    rx: RingProducer<'pipe, RING_SLOTS>,
    /// Physical address of the receive pipeline region, for deriving each
    /// posted buffer's DMA address.
    pipe_paddr: u64,
}

impl<'pipe, const Q: usize> RxPath<'pipe, Q> {
    /// Take the receive pipeline's `rx` producer handle, with no buffers
    /// posted. `rx_pipe_paddr` is the physical address of the same region
    /// `rx_pipe` maps.
    ///
    /// Call once per protection domain: the handle is this domain's publish
    /// position, so a second path over the same pipeline would overwrite slots
    /// the first has already handed to the forwarder.
    #[must_use]
    pub fn attach(rx_pipe: &'pipe Pipeline, rx_pipe_paddr: u64) -> Self {
        Self {
            posted: [const { None }; Q],
            rx: rx_pipe.rx.producer(),
            pipe_paddr: rx_pipe_paddr,
        }
    }

    /// Post free pool buffers to the receive virtqueue until either the queue
    /// or the pool runs dry, recording which buffer went in each descriptor.
    /// Returns whether any buffer was posted, so the caller knows whether to
    /// ring the receive doorbell.
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
            let paddr = Pipeline::buffer_paddr(self.pipe_paddr, buffer.index());
            match rx.add_writable(paddr, BUFFER_SIZE as u32) {
                Some(token) => {
                    let slot = token.index() as usize;
                    if let Some(displaced) = self.posted[slot].replace(buffer) {
                        // The virtqueue handed out a descriptor whose slot is
                        // still mapped, so this path and that queue disagree.
                        // `displaced` is a live DMA target of whichever queue
                        // really holds it, so it is dropped — leaking one pool
                        // buffer — rather than released, which would let the
                        // pool issue it to a second owner.
                        bump(&mut counters.invariant.rx_slot_occupied);
                        drop(displaced);
                    }
                    posted = true;
                }
                None => {
                    // The receive queue is full; keep the buffer for next time.
                    pool.release(buffer);
                    break;
                }
            }
        }
        posted
    }

    /// Drain completed receive descriptors, handing each valid frame to the
    /// forwarder with no copy. Returns whether any frame was submitted, so the
    /// caller knows whether to notify the forwarder.
    ///
    /// At most `Q` completions are processed per call: a conformant device never
    /// has more than `Q` buffers outstanding, so the cap costs nothing, while a
    /// device that floods its used ring cannot park this domain in the loop
    /// forever. That cap composes with the virtqueue's own — a single `poll`
    /// examines at most `Q` used entries — so one call is bounded whatever the
    /// device publishes, and no bound anywhere derives from a device value.
    ///
    /// What a completion still gets checked for here, the queue having already
    /// refused every forged, replayed, or out-of-range one: the device-reported
    /// length is clamped to the pool buffer, a runt frame (nothing past the
    /// virtio-net header) is dropped and counted at the edge, and a buffer the
    /// forwarder's ring will not take is released rather than leaked. Every
    /// completion recycles its virtqueue descriptor, on every path.
    pub fn drain(
        &mut self,
        rx: &mut SplitVirtqueue<Q>,
        pool: &mut PoolOwner<'_>,
        counters: &mut Counters,
    ) -> bool {
        let mut received = false;
        for _ in 0..Q {
            let Some((token, used_len)) = rx.poll() else {
                break;
            };
            let slot = token.index() as usize;
            let Some(buffer) = self.posted[slot].take() else {
                // Not device input — see `InvariantFaults`. The frame is lost
                // because no buffer is known for it, but the descriptor is
                // still this queue's and goes back.
                bump(&mut counters.invariant.rx_completion_unmapped);
                recycle_descriptor(rx, token, &mut counters.invariant);
                continue;
            };
            // `used_len` is device-controlled; clamp to the buffer so a device
            // that over-reports cannot make a downstream PD read out of bounds.
            let frame_len = (used_len as usize)
                .min(BUFFER_SIZE)
                .saturating_sub(VirtioNetHdr::LEN);
            if frame_len == 0 {
                // A frame with nothing past the header carries no payload; drop
                // it at the rx edge rather than forward a header-only frame.
                bump(&mut counters.input.rx_runt_dropped);
                pool.release(buffer);
                recycle_descriptor(rx, token, &mut counters.invariant);
                continue;
            }
            // Hand the frame span (after the virtio header) to the forwarder
            // with no copy; the buffer is owned downstream until it comes back
            // on the free ring. `lend` is where the token dissolves into a bare
            // index, which is also what permits the return.
            match pool.lend(
                &mut self.rx,
                buffer,
                VirtioNetHdr::LEN as u32,
                frame_len as u32,
            ) {
                Ok(()) => received = true,
                Err(buffer) => {
                    bump(&mut counters.input.rx_forwarder_ring_full);
                    pool.release(buffer);
                }
            }
            recycle_descriptor(rx, token, &mut counters.invariant);
        }
        received
    }
}

/// The transmit path: which peer descriptor is posted in each virtqueue slot,
/// which pool buffers this driver currently has in flight, and the handles onto
/// the transmit pipeline.
///
/// The per-slot `Option` plays the same role as on the receive side: it is the
/// slot→descriptor map, the only record of which peer descriptor to return once
/// the device is done with it. The separate in-flight set is indexed by *pool
/// buffer* rather than by virtqueue slot, and guards the other adversary
/// entirely: whether the peer has already handed this driver the buffer a new
/// descriptor names. Neither substitutes for the other, and neither duplicates
/// the virtqueue's own device-facing checks.
pub struct TxPath<'pipe, const Q: usize> {
    /// The peer descriptor handed to the device in each descriptor slot.
    posted: [Option<Descriptor>; Q],
    /// Which pool buffers this driver has at the device right now. A second
    /// descriptor naming one of them is a duplicate: posting it would put two
    /// virtqueue entries on one buffer and produce two returns for a buffer
    /// that was lent once.
    in_flight: [bool; POOL_BUFFERS],
    /// Frames the forwarder has queued. Taken once.
    tx: RingConsumer<'pipe, RING_SLOTS>,
    /// Where transmitted buffers go back to their pool owner. Taken once.
    free: RingProducer<'pipe, RING_SLOTS>,
    /// The pool the descriptors index, for writing the virtio-net header in
    /// place. Borrowed from the same region as the handles above.
    pool: &'pipe Pool,
    /// Physical address of the transmit pipeline region, for deriving each
    /// buffer's DMA address.
    pipe_paddr: u64,
}

impl<'pipe, const Q: usize> TxPath<'pipe, Q> {
    /// Take the transmit pipeline's `tx` consumer and `free` producer handles,
    /// with no frames in flight. `tx_pipe_paddr` is the physical address of the
    /// same region `tx_pipe` maps.
    ///
    /// Call once per protection domain: a second path over the same pipeline
    /// would re-consume frames the first has already handed to the device, and
    /// return the buffers twice.
    #[must_use]
    pub fn attach(tx_pipe: &'pipe Pipeline, tx_pipe_paddr: u64) -> Self {
        Self {
            posted: [None; Q],
            in_flight: [false; POOL_BUFFERS],
            tx: tx_pipe.tx.consumer(),
            free: tx_pipe.free.producer(),
            pool: &tx_pipe.pool,
            pipe_paddr: tx_pipe_paddr,
        }
    }

    /// Reap transmit completions, returning each transmitted buffer to its
    /// pool-owning peer on the pipeline's free ring.
    ///
    /// At most `Q` completions per call, for the reason given on
    /// [`RxPath::drain`]. A completion the device forged, replayed, or aimed
    /// out of range never reaches here: the virtqueue refuses it and counts it
    /// in its own [`DeviceFaults`]. A slot holding no descriptor is therefore
    /// this driver's own bookkeeping fault, not traffic; see
    /// [`InvariantFaults`].
    pub fn reap(&mut self, tx: &mut SplitVirtqueue<Q>, counters: &mut Counters) {
        for _ in 0..Q {
            let Some((token, _written)) = tx.poll() else {
                break;
            };
            let slot = token.index() as usize;
            let Some(descriptor) = self.posted[slot].take() else {
                bump(&mut counters.invariant.tx_completion_unmapped);
                recycle_descriptor(tx, token, &mut counters.invariant);
                continue;
            };
            // In range because `post` validated the descriptor before storing
            // it, so no peer value reaches this index.
            self.in_flight[descriptor.buffer as usize] = false;
            self.return_buffer(descriptor, counters);
            recycle_descriptor(tx, token, &mut counters.invariant);
        }
    }

    /// Post frames the forwarder queued to the device while descriptors are
    /// free. Returns whether any frame was posted, so the caller knows whether
    /// to ring the transmit doorbell.
    ///
    /// Each descriptor crossed a protection-domain boundary and is untrusted.
    /// It is rejected unless this driver does not already hold the buffer in
    /// flight, its span lies within one pool buffer, and it leaves room for the
    /// virtio-net header in front of the frame. A malformed descriptor is
    /// counted and dropped, and its buffer returned to the pool only when the
    /// index names a real pool buffer (a forged index has no owner) and is not
    /// the one an in-flight instance still owes a return for. A valid frame has
    /// its 12-byte header zeroed in place — no offloads are negotiated — and is
    /// handed to the device zero-copy.
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
            let in_pool = (descriptor.buffer as usize) < POOL_BUFFERS;
            // The duplicate check comes first so a duplicate is never *also*
            // returned: exactly one return per lent buffer is what keeps the
            // owner's ledger from seeing a second, refused one.
            if in_pool && self.in_flight[descriptor.buffer as usize] {
                bump(&mut counters.input.tx_duplicate);
                continue;
            }
            if !descriptor_in_bounds(&descriptor)
                || (descriptor.offset as usize) < VirtioNetHdr::LEN
            {
                bump(&mut counters.input.tx_malformed);
                if in_pool {
                    self.return_buffer(descriptor, counters);
                }
                continue;
            }
            let header_offset = descriptor.offset as usize - VirtioNetHdr::LEN;
            // The 12 bytes in front of the frame are reserved header space in
            // the same buffer (on the receive side the device's own header
            // occupied them). `TX_NO_OFFLOAD` is the image of a header
            // requesting nothing, which is what this driver may ask for while
            // it negotiates no offload feature.
            // SAFETY: `descriptor_in_bounds` bounded `descriptor.buffer` to the
            // pool and `offset + len` to one buffer, and the header-room check
            // above bounds `header_offset = offset - 12`, so the 12 bytes at
            // `header_offset` lie inside buffer `descriptor.buffer` — the span
            // is checked here, not assumed. Exclusive ownership is a protocol
            // claim this domain cannot verify alone: the forwarder handing the
            // descriptor over is the claim, `self.in_flight` rules out this
            // driver holding the same buffer twice, and the pool owner's ledger
            // refuses a second return of it. The residue — a byzantine
            // forwarder naming a buffer its pool owner still has posted as an rx
            // DMA target — is stated in the crate header and is not closable
            // inside this domain. The source is a local constant, so it cannot
            // alias the pool.
            unsafe {
                self.pool.write_at(
                    descriptor.buffer as usize,
                    header_offset,
                    &VirtioNetHdr::TX_NO_OFFLOAD,
                );
            }
            let paddr =
                Pipeline::buffer_paddr(self.pipe_paddr, descriptor.buffer) + header_offset as u64;
            // A first-party invariant, not device or peer input, so it fails
            // visibly rather than being counted (AGENTS.md ENG-5). The
            // guarantor is `virtio::queue::SplitVirtqueue::add` — the single
            // body behind both `add_*` methods — whose only early return is
            // `if self.num_free == 0`, and whose `free_count()` *is*
            // `num_free`. This iteration refused `free_count() == 0` at the
            // top and has not touched `tx` since (the dequeue, the validation
            // and the header write are all on the pipeline and the pool), so
            // no descriptor was consumed in between. `virtio`'s property
            // `split_virtqueue_accounting_holds_under_random_operations` is
            // what proves it: it unwraps an `add` after every observed
            // `free_count() > 0` across arbitrary add/complete/poll/recycle
            // sequences.
            //
            // Counting it as an `InvariantFaults` field instead would be dead
            // state, and that is the distinction those counters draw: each of
            // them is reachable by driving one path against two virtqueues,
            // which is why each has a test that does exactly that. Here the
            // check and the call are on the same `tx` in the same iteration,
            // so no wiring defect reaches this at all — a counter that can
            // never move is noise in the operator contract.
            let token = tx
                .add_readable(paddr, descriptor.len + VirtioNetHdr::LEN as u32)
                .expect("free_count() > 0 was observed above and nothing since has touched tx");
            let slot = token.index() as usize;
            self.posted[slot] = Some(descriptor);
            self.in_flight[descriptor.buffer as usize] = true;
            sent = true;
        }
        sent
    }

    /// Return a transmitted (or rejected) buffer to the pipeline's pool owner.
    ///
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
    /// side and the pipeline it feeds. The pipeline is leaked so the ring
    /// handles the paths hold can borrow it for `'static`, exactly as a
    /// protection domain's mapped region does.
    struct RxFixture {
        pipeline: &'static Pipeline,
        _region: Box<VqRegion>,
        vq: Vq,
        device: FakeDevice,
        pool: PoolOwner<'static>,
        rx: RxPath<'static, Q>,
        /// The forwarder's end of the `rx` ring, taken once for the fixture's
        /// life — a fresh handle per assertion would restart at slot zero and
        /// re-deliver descriptors already consumed.
        forwarder: RingConsumer<'static, RING_SLOTS>,
        counters: Counters,
    }

    impl RxFixture {
        fn new() -> Self {
            let pipeline: &'static Pipeline = Box::leak(Box::new(Pipeline::new()));
            let mut region = VqRegion::boxed();
            let ptr = region.0.as_mut_ptr();
            // SAFETY: `ptr` backs a 16-byte-aligned, zeroed VqRegion owned
            // solely by this test — `Vq::new`'s contract.
            let vq = unsafe { Vq::new(ptr) };
            let device = FakeDevice::new(ptr);
            // The device writes to the descriptor address as a real pointer, so
            // the "physical" region base is the pipeline's actual host address.
            let region_paddr = core::ptr::from_ref(pipeline) as u64;
            Self {
                pipeline,
                _region: region,
                vq,
                device,
                pool: PoolOwner::attach(pipeline),
                rx: RxPath::attach(pipeline, region_paddr),
                forwarder: pipeline.rx.consumer(),
                counters: Counters::default(),
            }
        }

        fn refill(&mut self) -> bool {
            self.rx
                .refill(&mut self.vq, &mut self.pool, &mut self.counters)
        }

        /// What the receive virtqueue refused from the device, which is where
        /// every forged, replayed, and out-of-range completion is now counted.
        fn device_faults(&self) -> DeviceFaults {
            self.vq.device_faults()
        }

        fn drain(&mut self) -> bool {
            self.rx
                .drain(&mut self.vq, &mut self.pool, &mut self.counters)
        }

        /// What the forwarder sees next on the `rx` ring.
        fn forwarded(&mut self) -> Option<Descriptor> {
            self.forwarder.try_dequeue()
        }
    }

    /// One transmit virtqueue over a fresh region, plus the device on its far
    /// side and the pipeline it drains.
    struct TxFixture {
        pipeline: &'static Pipeline,
        _region: Box<VqRegion>,
        vq: Vq,
        device: FakeDevice,
        tx: TxPath<'static, Q>,
        /// The forwarder's end of the `tx` ring and the pool owner's end of the
        /// `free` ring, each taken once for the fixture's life; see
        /// [`RxFixture::forwarder`].
        forwarder: RingProducer<'static, RING_SLOTS>,
        returns: RingConsumer<'static, RING_SLOTS>,
        counters: Counters,
    }

    impl TxFixture {
        fn new() -> Self {
            let pipeline: &'static Pipeline = Box::leak(Box::new(Pipeline::new()));
            let mut region = VqRegion::boxed();
            let ptr = region.0.as_mut_ptr();
            // SAFETY: `ptr` backs a 16-byte-aligned, zeroed VqRegion owned
            // solely by this test — `Vq::new`'s contract.
            let vq = unsafe { Vq::new(ptr) };
            let device = FakeDevice::new(ptr);
            // `post` derives buffer addresses from the region base via
            // `Pipeline::buffer_paddr`, so the base is the pipeline's real host
            // address and the pool then resolves to its real bytes.
            let pipe_paddr = core::ptr::from_ref(pipeline) as u64;
            Self {
                pipeline,
                _region: region,
                vq,
                device,
                tx: TxPath::attach(pipeline, pipe_paddr),
                forwarder: pipeline.tx.producer(),
                returns: pipeline.free.consumer(),
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

        /// Queue a raw descriptor as the forwarder would, valid or not.
        fn queue(&mut self, descriptor: Descriptor) {
            self.forwarder
                .try_enqueue(descriptor)
                .expect("tx ring has room");
        }

        /// What the pool owner sees next on the `free` ring.
        fn returned(&mut self) -> Option<Descriptor> {
            self.returns.try_dequeue()
        }

        /// Place a frame the forwarder would have queued: write `payload` at
        /// `offset` (with a non-zero 12-byte header in front, so the header
        /// zeroing is observable) into pool buffer `buffer`, and enqueue the
        /// matching descriptor on the tx ring.
        fn enqueue_frame(&mut self, buffer: u32, offset: usize, payload: &[u8]) {
            // SAFETY: single-threaded test; the buffer is not otherwise in use,
            // and both spans lie within it.
            unsafe {
                self.pipeline.pool.write_at(
                    buffer as usize,
                    offset - VirtioNetHdr::LEN,
                    &[0xFFu8; VirtioNetHdr::LEN],
                );
                self.pipeline
                    .pool
                    .write_at(buffer as usize, offset, payload);
            }
            self.queue(Descriptor::new(buffer, offset as u32, payload.len() as u32));
        }
    }

    #[test]
    fn refill_posts_up_to_the_queue_when_the_pool_is_larger() {
        let mut fx = RxFixture::new();
        assert!(fx.refill());
        // The queue holds Q descriptors, the pool 64 buffers, so the queue is
        // the limit: Q posted, the rest still owned.
        assert_eq!(fx.vq.free_count(), 0);
        assert_eq!(fx.pool.owned(), POOL_BUFFERS - Q);
    }

    #[test]
    fn refill_stops_when_the_pool_is_exhausted() {
        let mut fx = RxFixture::new();
        // Leave the owner holding fewer buffers than the queue can hold.
        let mut held = Vec::new();
        while fx.pool.owned() > 4 {
            held.push(fx.pool.alloc().unwrap());
        }
        assert!(fx.refill());
        assert_eq!(fx.pool.owned(), 0);
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
        assert_eq!(fx.counters, Counters::default());
        let descriptor = fx.forwarded().expect("one frame forwarded");
        assert_eq!(descriptor.offset, VirtioNetHdr::LEN as u32);
        assert_eq!(descriptor.len, payload.len() as u32);
        // SAFETY: single-threaded test; we hold the dequeued descriptor and its
        // span was published by the code under test.
        let bytes = unsafe {
            fx.pipeline.pool.read(
                descriptor.buffer as usize,
                descriptor.offset as usize,
                descriptor.len,
            )
        };
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
            fx.counters,
            Counters::default(),
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
        assert_eq!(fx.counters, Counters::default());
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
        assert_eq!(fx.counters, Counters::default());
        let descriptor = fx.forwarded().expect("frame forwarded");
        // Clamped to the buffer, then the header removed.
        assert_eq!(descriptor.len, (BUFFER_SIZE - VirtioNetHdr::LEN) as u32);
    }

    #[test]
    fn a_runt_frame_is_dropped_and_counted() {
        let mut fx = RxFixture::new();
        fx.refill();
        let owned_before = fx.pool.owned();
        let free_before = fx.vq.free_count();
        // Nothing past the 12-byte header.
        fx.device
            .deliver(&[0u8; VirtioNetHdr::LEN], (VirtioNetHdr::LEN - 4) as u32);

        assert!(!fx.drain());
        assert_eq!(fx.counters.input.rx_runt_dropped, 1);
        assert!(fx.forwarded().is_none());
        // The buffer was released back and the descriptor recycled.
        assert_eq!(fx.pool.owned(), owned_before + 1);
        assert_eq!(fx.vq.free_count(), free_before + 1);
    }

    #[test]
    fn a_full_forwarder_ring_releases_the_buffer_and_counts_the_drop() {
        let mut fx = RxFixture::new();
        // A stalled or hostile forwarder: it publishes a `head` one slot ahead
        // of where the driver's own (private) publish position sits, so the
        // ring looks full to this side and every hand-off is refused. Filling
        // the ring with a second producer handle would prove nothing — that
        // handle would have its own position and never meet the path's.
        forge_cursors(&fx.pipeline.rx, 1, 0);

        fx.refill();
        let owned_before = fx.pool.owned();
        let free_before = fx.vq.free_count();
        let frame = std::vec![0u8; VirtioNetHdr::LEN + 8];
        fx.device.deliver(&frame, frame.len() as u32);

        assert!(!fx.drain());
        // The drop is counted: the old code released the buffer silently and a
        // stalled or hostile forwarder left no trace at all.
        assert_eq!(fx.counters.input.rx_forwarder_ring_full, 1);
        assert_eq!(
            fx.counters,
            Counters {
                input: InputDrops {
                    rx_forwarder_ring_full: 1,
                    ..InputDrops::default()
                },
                invariant: InvariantFaults::default(),
            }
        );
        // The buffer came back to the owner and the descriptor was recycled.
        assert_eq!(fx.pool.owned(), owned_before + 1);
        assert_eq!(fx.vq.free_count(), free_before + 1);
    }

    #[test]
    fn a_valid_frame_is_posted_with_a_zeroed_header_and_returned_on_completion() {
        let mut fx = TxFixture::new();
        let payload = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let descriptor = Descriptor::new(7, VirtioNetHdr::LEN as u32, payload.len() as u32);
        fx.enqueue_frame(7, VirtioNetHdr::LEN, &payload);

        assert!(fx.post());
        assert_eq!(fx.counters, Counters::default());

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
    fn a_forged_buffer_index_is_dropped_without_a_return() {
        let mut fx = TxFixture::new();
        // Buffer index past the pool: it has no owner to return to.
        fx.queue(Descriptor::new(
            POOL_BUFFERS as u32,
            VirtioNetHdr::LEN as u32,
            8,
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
        let bad = Descriptor::new(3, VirtioNetHdr::LEN as u32, BUFFER_SIZE as u32);
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
        let bad = Descriptor::new(5, (VirtioNetHdr::LEN - 1) as u32, 8);
        fx.queue(bad);

        assert!(!fx.post());
        assert_eq!(fx.counters.input.tx_malformed, 1);
        assert_eq!(fx.returned(), Some(bad));
        assert_eq!(fx.vq.free_count(), Q);
    }

    #[test]
    fn a_duplicate_transmit_descriptor_is_dropped_without_a_second_post_or_return() {
        // A byzantine forwarder hands the same buffer over twice. Posting both
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
        assert_eq!(fx.counters, Counters::default());
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
        assert_eq!(fx.counters, Counters::default());
        assert!(fx.returned().is_none());
        assert_eq!(
            fx.vq.free_count(),
            Q,
            "nothing was posted, nothing recycled"
        );
    }

    #[test]
    fn a_full_free_ring_drops_and_counts_rather_than_faulting() {
        // The peer-reachable panic this replaces: a forwarder queues more
        // malformed-but-in-range descriptors than the free ring can hold, every
        // one takes the return path, and the ring fills.
        let mut fx = TxFixture::new();
        let capacity = fx.pipeline.free.capacity();
        // In bounds, but no header room, so each is rejected *and* returned.
        let bad = Descriptor::new(1, 0, 8);

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
        assert_eq!(fx.counters, Counters::default());

        // Drain the device and reap, then the surplus goes out.
        for _ in 0..Q {
            fx.device.transmit();
        }
        fx.reap();
        assert!(fx.post());
        assert_eq!(fx.vq.free_count(), Q - 2);
        assert_eq!(fx.counters, Counters::default());
    }

    #[test]
    fn post_is_bounded_when_a_peer_floods_malformed_descriptors() {
        // A malformed descriptor consumes no virtqueue descriptor, so the free
        // count never falls: only the iteration cap ends the loop. Forge the
        // shared cursor so the ring always looks non-empty, exactly as a peer
        // that keeps publishing does.
        let mut fx = TxFixture::new();
        for round in 0..6u32 {
            forge_cursors(&fx.pipeline.tx, 0, round.wrapping_mul(31).wrapping_add(7));
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
        /// `poll` on this queue yields a token no other path ever mapped.
        fn post_and_complete(&mut self, paddr: u64, used_len: u32) {
            let head = self
                .vq
                .add_writable(paddr, BUFFER_SIZE as u32)
                .expect("a descriptor is free")
                .index();
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
        assert!(!fx.rx.drain(&mut stray.vq, &mut fx.pool, &mut fx.counters));
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
        let owned_after_first = fx.pool.owned();
        let mut stray = StrayQueue::new();

        assert!(fx.rx.refill(&mut stray.vq, &mut fx.pool, &mut fx.counters));
        assert_eq!(fx.counters.invariant.rx_slot_occupied, Q as u64);
        assert_eq!(fx.counters.input, InputDrops::default());
        // Q buffers were taken from the pool and Q leaked, none released back.
        assert_eq!(fx.pool.owned(), owned_after_first - Q);
    }

    #[test]
    fn refusing_to_recycle_a_descriptor_is_counted_as_a_driver_fault() {
        // `recycle` cannot refuse a token polled from the same queue an instant
        // earlier, so the refusal is unreachable through either path — but the
        // handling still has to be right, and it is the one place a `Result`
        // from the queue is answered. Exercise it directly with the token kind
        // the queue does refuse: one the device still owns.
        let mut region = VqRegion::boxed();
        // SAFETY: `ptr` backs a 16-byte-aligned, zeroed VqRegion owned solely
        // by this test — `Vq::new`'s contract.
        let mut vq = unsafe { Vq::new(region.0.as_mut_ptr()) };
        let token = vq.add_writable(0x1000, 64).expect("a descriptor is free");
        let mut faults = InvariantFaults::default();

        recycle_descriptor(&mut vq, token, &mut faults);
        assert_eq!(faults.descriptor_recycle_refused, 1);
        // Refused means refused: the descriptor stays the device's.
        assert_eq!(vq.free_count(), Q - 1);
        assert_eq!(vq.posted_count(), 1);
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Arbitrary device behaviour against the receive path: completions for
        /// arbitrary head indices with arbitrary reported lengths, in arbitrary
        /// order, interleaved with refills. Nothing may panic, work per call
        /// stays bounded, and no pool buffer may ever be owned twice — the
        /// buffers still posted plus those the owner holds free plus those
        /// handed to the forwarder must never exceed the pool.
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
                forwarded += fx.forwarder.drain(DRAIN_LIMIT).count();
                let posted = fx.rx.posted.iter().filter(|slot| slot.is_some()).count();
                prop_assert!(
                    posted + fx.pool.owned() <= POOL_BUFFERS,
                    "a buffer is both posted to the device and free in the pool"
                );
                prop_assert!(fx.vq.free_count() <= Q);
                // No device behaviour may look like a fault of ours: the
                // virtqueue answers for the device, so this stays zero however
                // the device misbehaves.
                prop_assert_eq!(fx.counters.invariant, InvariantFaults::default());
            }
            // Nothing returns a buffer to the pool in this scenario, so the
            // whole run can hand the forwarder at most one frame per buffer.
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
                (any::<u32>(), any::<u32>(), any::<u32>(), any::<bool>()),
                0..120,
            ),
        ) {
            let mut fx = TxFixture::new();
            let mut returned = 0usize;
            let mut offered = 0usize;

            for (buffer, offset, len, complete) in descriptors {
                // Bias towards plausible values so the valid path is reached at
                // all, while arbitrary ones keep forged spans in the mix.
                let descriptor = Descriptor::new(
                    buffer % (POOL_BUFFERS as u32 + 2),
                    offset % (BUFFER_SIZE as u32 + 2),
                    len % (BUFFER_SIZE as u32 + 2),
                );
                if fx.forwarder.try_enqueue(descriptor).is_ok() {
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
