//! `nic_driver_core`'s steady-state paths under **both** adversaries at once.
//!
//! # The adversaries and the surface
//!
//! Two distrust boundaries meet in the driver PD (CONCEPT §7.1), and this is
//! the only harness that drives them together, which is the point: the
//! interesting failures are the ones where a device completion and a peer
//! descriptor interact.
//!
//! * **The hostile or malfunctioning device** owns every byte of both virtqueue
//!   regions and publishes completions of its own choosing.
//! * **The byzantine forwarder** queues transmit descriptors naming any buffer,
//!   any span, and the same buffer repeatedly; it also maps both pipeline
//!   regions read-write and can forge the cursors of every ring this driver
//!   reads.
//!
//! # The invariant this target exists for
//!
//! `nic_driver_core` splits its tallies by *who is answerable*: `InputDrops`
//! counts what a neighbour did wrong, `InvariantFaults` counts what **this
//! crate** did wrong. That split is only worth having if it is true, so the
//! headline assertion here is that `Counters::invariant` stays at its default
//! for every input. Neither adversary may make this driver look like it has a
//! bug — the crate header's claim that no device or peer input can reach any
//! `InvariantFaults` field, checked rather than believed.
//!
//! # The notify signals, which no panic would reveal
//!
//! `refill`, `drain` and `post` each answer a `bool` that decides whether the
//! PD rings a doorbell — the device's, or the forwarder's notification. Both
//! ways of being wrong are silent. A `false` after work was really done strands
//! posted descriptors at a device that was never told and frames at a forwarder
//! that was never woken: a dataplane that stops rather than crashes. A `true`
//! after nothing was done is an MMIO write or a peer notification for no
//! reason, which on a shared bus is cost the adversary chose. Each call below
//! is therefore bracketed and its answer compared with what actually moved,
//! rather than discarded — discarding it is the "it did not panic" shape TEST-9
//! names.
//!
//! # What the adversary may express here
//!
//! Arbitrary used-ring completions (forged ids, out-of-range ids, replays,
//! lengths far above what was programmed) on either queue; arbitrary bytes
//! anywhere in either virtqueue region, descriptor table included; arbitrary
//! transmit descriptors from the forwarder, including duplicates of a buffer
//! already in flight; arbitrary returns on the receive pipeline's `free` ring;
//! and forged cursors on every ring.
//!
//! Two limits are deliberate, and neither removes an adversary capability:
//!
//! * **The `rx` ring's published `tail` is not forged.** Its producer is
//!   `RxPath` itself and its consumer is this harness's own forwarder stand-in,
//!   so forging it would corrupt the harness's bookkeeping about what the code
//!   published and could not affect the code under test at all. Its `head` —
//!   the word `RxPath`'s producer actually reads — *is* forged. The same
//!   reasoning applies to the `free` ring this driver produces on.
//! * **The DMA-address audit is suspended once the device scribbles a
//!   virtqueue region**, because that audit reads its evidence out of the very
//!   bytes the device just overwrote; its premise is gone, not its subject. The
//!   audit still runs over every input prefix before the first scribble, and
//!   every other assertion holds for the whole input.
//! * **The double-lend check is suspended for a buffer whose return the peer
//!   has put beyond this harness's knowledge**, for the same reason and with
//!   the same shape. The receive pipeline's `free` ring is the return path, so
//!   a return the peer queues on it is a *real* return and the pool owner is
//!   right to reclaim and re-issue the buffer — the peer is then harming
//!   itself, not being double-lent to. The peer reaches that ring two ways, and
//!   both disclaim: queueing a descriptor of its choosing (op 9) disclaims that
//!   index, and rewriting the ring's slots and cursors outright disclaims every
//!   index, because a forged `tail` republishes whatever bytes already sat in
//!   the slots and names nothing this harness can attribute.
//!
//!   This narrows an *assertion*, never the input: every adversary action stays
//!   expressible, and the check runs at full strength on every buffer whose
//!   ownership the peer has not deliberately confused. It is needed because
//!   this harness plays both the honest far driver and the byzantine peer on
//!   one ring while only the first updates its record of what is outstanding —
//!   holding the driver to that record made correct behaviour look like a
//!   duplicate, and a harness assertion that fires on correct behaviour is
//!   worse than none. Restoring full strength needs `PoolOwner::reclaim` to
//!   report *which* indices it accepted rather than how many, a change in
//!   `crates/pd-runtime` that this workspace does not own.
//!
//!   Both mechanisms are pinned as committed seeds —
//!   `peer_returns_a_lent_buffer_out_of_band` and
//!   `peer_forges_the_free_ring_image` — so the seed smoke tests replay them on
//!   every gate run and a model that starts firing falsely again fails in
//!   milliseconds rather than after a long fuzz run.

use arbitrary::Unstructured;
use nic_driver_core::bringup::QUEUE_SIZE;
use nic_driver_core::{Counters, InvariantFaults, RxPath, TxPath};
use pd_runtime::{
    BUFFER_SIZE, DRAIN_LIMIT, Descriptor, ForwardRings, POOL_BUFFERS, Pool, PoolOwner, RING_SLOTS,
    ReturnRing, Verdict, attach_region, descriptor_in_bounds,
};
use virtio::net::VirtioNetHdr;
use virtio::queue::SplitVirtqueue;

use crate::region::{DMA_REGION_BYTES, DmaRegion, ZeroedRegion};
use crate::ring_abi::PeerView;
use crate::{MAX_OPERATIONS, any_index, any_u32, next_op};

/// The driver's virtqueue size, taken from `bringup` so the harness cannot
/// drift from the queues the PD really builds.
const Q: usize = QUEUE_SIZE;
/// The queue type both directions use.
type Vq = SplitVirtqueue<Q>;

/// Physical address of the pool this driver receives into. The driver PD holds
/// this address and no mapping of that region at all, which is what this
/// harness reproduces: nothing below borrows `rx_pool`.
const RX_POOL_PADDR: u64 = 0x3100_0000;
/// Physical address of the pool this driver transmits out of, which it does
/// map — `TxPath::post` writes the virtio-net header into it.
const TX_POOL_PADDR: u64 = 0x3200_0000;

/// One descriptor as either adversary writes it into a shared slot.
///
/// A field-wise literal and not `Descriptor::new`, whose `Verdict` argument
/// would confine the verdict word to the two values that decode. That word is
/// plain shared memory to a peer, and the values that decode to *nothing* are
/// precisely the ones the transmit path has to account for separately — so the
/// draw weights the two decodable values against the rest of the space rather
/// than excluding either side of it (TEST-8).
fn any_descriptor(unstructured: &mut Unstructured<'_>) -> Descriptor {
    let buffer = any_u32(unstructured);
    let offset = any_u32(unstructured);
    let len = any_u32(unstructured);
    let verdict = match any_u32(unstructured) % 4 {
        0 => Verdict::Transmit.to_bits(),
        1 => Verdict::Discard.to_bits(),
        _ => any_u32(unstructured),
    };
    Descriptor {
        buffer,
        offset,
        len,
        verdict,
    }
}

/// The device's side of one virtqueue: it may write any byte of the region, and
/// publishes completions naming whatever descriptor it likes.
struct DeviceSide {
    region: *mut u8,
    /// The device's own used-ring producer index, kept privately so the harness
    /// does not read back bytes it may itself have scribbled.
    used_idx: u16,
    /// How many available-ring entries the DMA-address audit has checked.
    audited: u16,
    /// Set once the device has scribbled the region, after which the audit's
    /// evidence is no longer the driver's own writes; see the module header.
    scribbled: bool,
}

impl DeviceSide {
    /// # Safety
    /// `region` must point to at least `DMA_REGION_BYTES` writable bytes,
    /// 16-byte aligned, outliving this value, shared only with the one queue
    /// this device backs.
    unsafe fn new(region: *mut u8) -> Self {
        Self {
            region,
            used_idx: 0,
            audited: 0,
            scribbled: false,
        }
    }

    /// Read a `u16` at a 2-aligned in-region offset.
    ///
    /// # Safety
    /// `offset + 2 <= DMA_REGION_BYTES` and `offset` must be even.
    unsafe fn read_u16(&self, offset: usize) -> u16 {
        // SAFETY: the caller guarantees an even, in-region offset, and the
        // region is 16-byte aligned, so the `u16` pointer is aligned.
        unsafe { self.region.add(offset).cast::<u16>().read_volatile() }
    }

    /// Read a `u32` at a 4-aligned in-region offset.
    ///
    /// # Safety
    /// `offset + 4 <= DMA_REGION_BYTES` and `offset` must be a multiple of 4.
    unsafe fn read_u32(&self, offset: usize) -> u32 {
        // SAFETY: as `read_u16`, for four bytes at a 4-aligned offset.
        unsafe { self.region.add(offset).cast::<u32>().read_volatile() }
    }

    /// Read a `u64` at an 8-aligned in-region offset.
    ///
    /// # Safety
    /// `offset + 8 <= DMA_REGION_BYTES` and `offset` must be a multiple of 8.
    unsafe fn read_u64(&self, offset: usize) -> u64 {
        // SAFETY: as `read_u16`, for eight bytes at an 8-aligned offset; the
        // region's 16-byte alignment covers it.
        unsafe { self.region.add(offset).cast::<u64>().read_volatile() }
    }

    /// Overwrite one byte anywhere in the region — descriptor table, available
    /// ring, and used ring alike.
    fn scribble(&mut self, offset: usize, byte: u8) {
        self.scribbled = true;
        // SAFETY: the offset is reduced into the region this device was built
        // over, which its constructor's contract guarantees is writable.
        unsafe {
            self.region
                .add(offset % DMA_REGION_BYTES)
                .write_volatile(byte)
        };
    }

    /// Publish one completion naming descriptor `id` with reported length
    /// `len`, both entirely the device's choice.
    fn complete(&mut self, id: u32, len: u32) {
        let slot = (self.used_idx as usize) % Q;
        let element = Vq::LAYOUT.device_offset + 4 + slot * 8;
        // SAFETY: `slot < Q`, so `element + 8 <= LAYOUT.total_bytes`, which is
        // well inside `DMA_REGION_BYTES`; both words are 4-aligned.
        unsafe {
            self.region.add(element).cast::<u32>().write_volatile(id);
            self.region
                .add(element + 4)
                .cast::<u32>()
                .write_volatile(len);
        }
        self.used_idx = self.used_idx.wrapping_add(1);
        self.publish_used_index(self.used_idx);
    }

    /// Store the used index the driver reads, without necessarily having
    /// published a matching entry.
    fn publish_used_index(&self, value: u16) {
        // SAFETY: the used index sits at a 2-aligned offset inside the region.
        unsafe {
            self.region
                .add(Vq::LAYOUT.device_offset + 2)
                .cast::<u16>()
                .write_volatile(value)
        };
    }

    /// Check every descriptor the driver has published since the last audit:
    /// each must name a buffer wholly inside `[pool_base, pool_end)`.
    ///
    /// This is the arbitrary-physical-write invariant on the device-facing
    /// side. The address in a descriptor is what a real NIC DMAs to, so one
    /// outside the shared region is a write to memory this system never granted
    /// the device — the failure the pool's bounds checks exist to prevent, seen
    /// from the far end.
    fn audit_published_buffers(&mut self, pool_base: u64, pool_end: u64) {
        if self.scribbled {
            return;
        }
        // SAFETY: the available index sits at a 2-aligned in-region offset.
        let avail_idx = unsafe { self.read_u16(Vq::LAYOUT.driver_offset + 2) };
        // A single refill or post publishes at most `Q` descriptors, so the
        // loop is bounded by a driver-owned quantity even though `avail_idx`
        // is a value read back out of the shared region.
        let pending = avail_idx.wrapping_sub(self.audited).min(Q as u16);
        for step in 0..pending {
            let ring_slot = (self.audited.wrapping_add(step) as usize) % Q;
            let entry = Vq::LAYOUT.driver_offset + 4 + ring_slot * 2;
            // SAFETY: `ring_slot < Q`, so `entry + 2` is inside the available
            // ring and 2-aligned.
            let descriptor = usize::from(unsafe { self.read_u16(entry) });
            assert!(
                descriptor < Q,
                "the driver published descriptor index {descriptor}, outside its own queue"
            );
            // SAFETY: `descriptor < Q`, so the 16-byte descriptor lies inside
            // the table at the region's front; `addr` is 8-aligned and `len`
            // 4-aligned within it.
            let (addr, len) = unsafe {
                (
                    self.read_u64(descriptor * 16),
                    self.read_u32(descriptor * 16 + 8),
                )
            };
            assert!(
                addr >= pool_base && u64::from(len) <= pool_end.saturating_sub(addr),
                "the driver handed the device a DMA target [{addr:#x}, +{len}) outside the pool \
                 [{pool_base:#x}, {pool_end:#x}) — an arbitrary physical write"
            );
        }
        self.audited = avail_idx;
    }
}

/// Drive both dataplane directions against a hostile device and a byzantine
/// forwarder at the same time.
pub fn driver_paths_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);

    // Six regions, one pipeline's worth each side, allocated separately exactly
    // as Microkit maps them. The pool this driver receives into is allocated but
    // never attached: the PD is granted its physical address alone, so a harness
    // holding a reference to it would model a wider grant than the system gives.
    let rx_rings_region = ZeroedRegion::<ForwardRings>::new();
    let rx_free_region = ZeroedRegion::<ReturnRing>::new();
    let tx_rings_region = ZeroedRegion::<ForwardRings>::new();
    let tx_free_region = ZeroedRegion::<ReturnRing>::new();
    let tx_pool_region = ZeroedRegion::<Pool>::new();
    // SAFETY: each is a live, zeroed allocation of exactly its region type,
    // aligned by `Layout::new`, outliving every handle taken from it, and `Sync`
    // with no safe path to its bytes; no `&mut` is ever created to any of them
    // — `attach_region`'s contract in full.
    let rx_rings: &ForwardRings = unsafe { attach_region(rx_rings_region.as_ptr()) };
    // SAFETY: as above, for the receive pipeline's return region.
    let rx_free: &ReturnRing = unsafe { attach_region(rx_free_region.as_ptr()) };
    // SAFETY: as above, for the transmit pipeline's forwarder region.
    let tx_rings: &ForwardRings = unsafe { attach_region(tx_rings_region.as_ptr()) };
    // SAFETY: as above, for the transmit pipeline's return region.
    let tx_free: &ReturnRing = unsafe { attach_region(tx_free_region.as_ptr()) };
    // SAFETY: as above, for the one pool a driver PD maps.
    let tx_pool: &Pool = unsafe { attach_region(tx_pool_region.as_ptr()) };

    let rx_vq_region = DmaRegion::zeroed();
    let tx_vq_region = DmaRegion::zeroed();
    const { assert!(Vq::LAYOUT.total_bytes <= DMA_REGION_BYTES) };
    // What makes the `drain` notify assertion exact rather than approximately
    // true: `drain` lends at most `Q` frames per call, so the `rx` tail advances
    // by at most `Q` and can never complete a whole lap of the ring and land
    // back where it started, which would read as "nothing was published". Stated
    // as a build failure because it is a relationship between two constants
    // this harness does not own, and a future change to either would otherwise
    // turn the assertion silently wrong instead of loudly so.
    const {
        assert!(
            Q < RING_SLOTS,
            "a drain could advance the rx tail by a full ring and look like no progress"
        )
    };
    // SAFETY: each backing region is live, zeroed, 16-byte aligned and larger
    // than `LAYOUT.total_bytes` (asserted above), and each is shared with
    // exactly one `DeviceSide` — `SplitVirtqueue::new`'s contract.
    let mut rx_vq = unsafe { Vq::new(rx_vq_region.as_ptr().cast::<u8>()) };
    // SAFETY: as above, for the transmit queue's own region.
    let mut tx_vq = unsafe { Vq::new(tx_vq_region.as_ptr().cast::<u8>()) };
    // SAFETY: the same two live regions, for the same lifetimes.
    let mut rx_device = unsafe { DeviceSide::new(rx_vq_region.as_ptr().cast::<u8>()) };
    // SAFETY: as above.
    let mut tx_device = unsafe { DeviceSide::new(tx_vq_region.as_ptr().cast::<u8>()) };

    let mut pool = PoolOwner::attach(rx_free);
    let mut receive = RxPath::<Q>::attach(rx_rings, RX_POOL_PADDR);
    let mut transmit = TxPath::<Q>::attach(tx_rings, tx_free, tx_pool, TX_POOL_PADDR);
    let mut counters = Counters::default();

    // The neighbouring domains, each taking exactly one handle.
    let mut forwarder_takes_rx = rx_rings.rx.consumer();
    let mut far_driver_returns = rx_free.free.producer();
    let mut forwarder_queues_tx = tx_rings.tx.producer();
    let mut far_owner_takes_free = tx_free.free.consumer();

    let rx_ring_view = PeerView::<RING_SLOTS>::new(&rx_rings.rx);
    let rx_free_view = PeerView::<RING_SLOTS>::new(&rx_free.free);
    let tx_ring_view = PeerView::<RING_SLOTS>::new(&tx_rings.tx);
    let tx_free_view = PeerView::<RING_SLOTS>::new(&tx_free.free);

    let rx_pool_base = RX_POOL_PADDR;
    let rx_pool_end = rx_pool_base + (POOL_BUFFERS * BUFFER_SIZE) as u64;
    let tx_pool_base = TX_POOL_PADDR;
    let tx_pool_end = tx_pool_base + (POOL_BUFFERS * BUFFER_SIZE) as u64;

    // Which receive-pool buffers this driver has handed to the forwarder and
    // not yet had returned. A second appearance of one is a buffer with two
    // owners, which is the failure the whole ownership chain exists to prevent.
    let mut lent_to_forwarder = [false; POOL_BUFFERS];
    // Buffers whose ownership the peer has deliberately confused by queueing a
    // return for them out of band (op 9). See `lent_to_forwarder`'s check in
    // op 8 for why the claim above cannot survive that.
    let mut disclaimed = [false; POOL_BUFFERS];
    // Frames the forwarder has taken and the far tx driver has not returned.
    let mut parked: Vec<Descriptor> = Vec::new();
    let mut previous_input = counters.input;

    for _ in 0..MAX_OPERATIONS {
        let Some(op) = next_op(&mut unstructured) else {
            break;
        };
        match op % 13 {
            0 => {
                // `refill` only ever adds, so the posted count rising is
                // exactly "a descriptor was published" — the condition its
                // answer claims. See the module header on notify signals.
                let posted_before = rx_vq.posted_count();
                let refilled = receive.refill(&mut rx_vq, &mut pool, &mut counters);
                assert_eq!(
                    refilled,
                    rx_vq.posted_count() > posted_before,
                    "refill's receive-doorbell signal disagrees with what it posted"
                );
                rx_device.audit_published_buffers(rx_pool_base, rx_pool_end);
            }
            1 => {
                // A frame reaching the forwarder is a descriptor published on
                // the `rx` ring, and this driver is that ring's producer: the
                // peer forges its `head`, never its `tail`, so the tail moving
                // is the code's own record of the work its answer claims.
                let tail_before = rx_ring_view.tail();
                let received = receive.drain(&mut rx_vq, &mut pool, &mut counters);
                assert_eq!(
                    received,
                    rx_ring_view.tail() != tail_before,
                    "drain's forwarder-notify signal disagrees with what it published"
                );
            }
            2 => transmit.reap(&mut tx_vq, &mut counters),
            3 => {
                // As op 0: `post` never polls, so a rising posted count is
                // exactly the "a frame went to the device" its answer claims.
                let posted_before = tx_vq.posted_count();
                let sent = transmit.post(&mut tx_vq, &mut counters);
                assert_eq!(
                    sent,
                    tx_vq.posted_count() > posted_before,
                    "post's transmit-doorbell signal disagrees with what it posted"
                );
                tx_device.audit_published_buffers(tx_pool_base, tx_pool_end);
            }
            4 => {
                let reclaimed = pool.reclaim();
                assert!(
                    reclaimed <= DRAIN_LIMIT,
                    "reclaim processed {reclaimed} returns, past the {DRAIN_LIMIT} bound"
                );
            }
            5 => {
                let id = any_u32(&mut unstructured);
                let len = any_u32(&mut unstructured);
                if any_u32(&mut unstructured) & 1 == 0 {
                    rx_device.complete(id, len);
                } else {
                    tx_device.complete(id, len);
                }
            }
            6 => {
                let offset = any_u32(&mut unstructured) as usize;
                let byte = any_u32(&mut unstructured) as u8;
                if any_u32(&mut unstructured) & 1 == 0 {
                    rx_device.scribble(offset, byte);
                } else {
                    tx_device.scribble(offset, byte);
                }
            }
            7 => {
                // The forwarder queueing a transmit descriptor: any buffer, any
                // span, and freely repeated. Half the stream is biased into the
                // pool's index range so the duplicate and header-room
                // rejections come up often rather than by chance.
                let mut descriptor = any_descriptor(&mut unstructured);
                if any_u32(&mut unstructured) & 1 == 0 {
                    descriptor.buffer %= POOL_BUFFERS as u32 + 1;
                    descriptor.offset %= (BUFFER_SIZE + 1) as u32;
                    descriptor.len %= (BUFFER_SIZE + 1) as u32;
                    // The span is biased so the valid path is reached; the
                    // verdict is not, because the two values that decode are
                    // two of four billion and a bias towards them is exactly
                    // what would delete the undecodable case (TEST-8). It is
                    // instead drawn from a distribution that weights all three
                    // outcomes, in `any_descriptor`.
                }
                let _full = forwarder_queues_tx.try_enqueue(descriptor);
            }
            8 => {
                // The forwarder taking what this driver published. The buffers
                // are *not* returned here: they are parked, and a separate
                // operation returns them. Returning inline would clear the
                // in-flight flag in the same breath as setting it, and the
                // duplicate this check exists for would only ever be caught in
                // the narrow window where the free ring happened to be full.
                let limit = any_u32(&mut unstructured) as usize % (2 * DRAIN_LIMIT + 2);
                let taken: Vec<Descriptor> = forwarder_takes_rx.drain(limit).collect();
                assert!(taken.len() <= limit, "drain exceeded its limit");
                for descriptor in taken {
                    assert!(
                        descriptor_in_bounds(&descriptor),
                        "the driver published {descriptor:?}, whose span leaves the pool — a \
                         device that over-reported its completion length reached a peer"
                    );
                    assert_eq!(
                        descriptor.offset,
                        VirtioNetHdr::LEN as u32,
                        "the driver published a frame that does not start after the header"
                    );
                    assert!(descriptor.len > 0, "a runt frame reached the forwarder");
                    assert_eq!(
                        Verdict::from_bits(descriptor.verdict),
                        Some(Verdict::Transmit),
                        "the driver published {descriptor:?} under a verdict that is not \
                         Transmit — a received frame is a real frame, and anything else here \
                         is traffic dropped on a decision no domain made"
                    );
                    let buffer = descriptor.buffer as usize;
                    // Only for a buffer whose ownership the peer has not
                    // deliberately confused. Once op 9 has queued a return
                    // naming this buffer, the pool owner is *right* to reclaim
                    // and re-issue it — the free ring is the return path, and a
                    // peer that gives a buffer back while still using its own
                    // copy is harming itself, not being double-lent to. This
                    // harness plays both the honest far driver and the
                    // byzantine peer on that one ring, so without this it
                    // asserts a duplicate against its own incomplete record of
                    // what was returned, and fires on correct driver behaviour.
                    assert!(
                        !lent_to_forwarder[buffer] || disclaimed[buffer],
                        "buffer {buffer} was handed to the forwarder twice without a return — \
                         one pool buffer with two owners"
                    );
                    lent_to_forwarder[buffer] = true;
                    parked.push(descriptor);
                }
            }
            9 => {
                // A return of the far driver's choosing on the receive
                // pipeline's free ring: forged indices, duplicates, and returns
                // of buffers this driver still has posted to its own NIC.
                let mut descriptor = any_descriptor(&mut unstructured);
                if any_u32(&mut unstructured) & 1 == 0 {
                    descriptor.buffer %= POOL_BUFFERS as u32 + 1;
                }
                if far_driver_returns.try_enqueue(descriptor).is_ok() {
                    // A queued return IS a return, whoever queued it and
                    // whatever they keep doing with their copy. Give up this
                    // harness's claim on the buffer rather than let op 8 hold
                    // the driver to a record that no longer describes who owns
                    // it. The adversary loses nothing — the descriptor above is
                    // still wholly its choice, forged indices included.
                    let buffer = descriptor.buffer as usize;
                    if buffer < POOL_BUFFERS {
                        lent_to_forwarder[buffer] = false;
                        disclaimed[buffer] = true;
                        parked.retain(|parked| parked.buffer != descriptor.buffer);
                    }
                }
            }
            10 => {
                // The transmit pipeline's pool owner collecting its returns.
                let limit = any_u32(&mut unstructured) as usize % (2 * DRAIN_LIMIT + 2);
                let returned = far_owner_takes_free.drain(limit).count();
                assert!(returned <= limit, "drain exceeded its limit");
            }
            12 => {
                // The far tx driver returning parked buffers, as many as the
                // peer feels like. A buffer stays in flight until its return is
                // actually queued, because only then can the reclaim/alloc/refill
                // cycle legitimately publish it again.
                let count = any_u32(&mut unstructured) as usize % (parked.len() + 1);
                for _ in 0..count {
                    let descriptor = parked.remove(any_index(&mut unstructured, parked.len()));
                    if far_driver_returns.try_enqueue(descriptor).is_ok() {
                        lent_to_forwarder[descriptor.buffer as usize] = false;
                    } else {
                        parked.push(descriptor);
                        break;
                    }
                }
            }
            _ => {
                let head = any_u32(&mut unstructured);
                let tail = any_u32(&mut unstructured);
                let slot = any_u32(&mut unstructured) as usize;
                let descriptor = any_descriptor(&mut unstructured);
                match any_u32(&mut unstructured) % 4 {
                    // This driver produces on `rx`; only the cursor it *reads*
                    // is the peer's to forge. See the module header.
                    0 => rx_ring_view.set_head(head),
                    // This driver produces on the transmit pipeline's `free`.
                    1 => tx_free_view.set_head(head),
                    // Both rings this driver consumes are the peer's entirely.
                    2 => {
                        rx_free_view.set_head(head);
                        rx_free_view.set_tail(tail);
                        rx_free_view.store_slot(slot, descriptor);
                        // Rewriting the return ring's contents and cursors
                        // injects returns naming buffers of the peer's
                        // choosing, and unlike op 9 it leaves no trace this
                        // harness can attribute to an index: a forged `tail`
                        // alone republishes whatever bytes already sat in the
                        // slots. After this the harness knows nothing about
                        // which buffers are still outstanding, so it keeps no
                        // claim about any of them.
                        disclaimed = [true; POOL_BUFFERS];
                    }
                    _ => {
                        tx_ring_view.set_head(head);
                        tx_ring_view.set_tail(tail);
                        tx_ring_view.store_slot(slot, descriptor);
                    }
                }
            }
        }

        // The headline: neither adversary may make this driver look like it has
        // a bug. Every `InvariantFaults` field is documented as unreachable
        // from device or peer input; this is that claim under test.
        assert_eq!(
            counters.invariant,
            InvariantFaults::default(),
            "device or peer input drove this driver into its own invariant faults"
        );
        // Input drops are expected to rise — that is the adversary being
        // rejected — but never to fall, which would hide a flood.
        let input = counters.input;
        assert!(input.rx_runt_dropped >= previous_input.rx_runt_dropped);
        assert!(input.rx_forwarder_ring_full >= previous_input.rx_forwarder_ring_full);
        assert!(input.tx_malformed >= previous_input.tx_malformed);
        assert!(input.tx_duplicate >= previous_input.tx_duplicate);
        assert!(input.tx_free_ring_full >= previous_input.tx_free_ring_full);
        previous_input = input;

        // The queues account for exactly `Q` descriptors at every instant, so a
        // completion the device forged can neither invent nor destroy one.
        assert!(rx_vq.free_count() + rx_vq.posted_count() <= Q);
        assert!(tx_vq.free_count() + tx_vq.posted_count() <= Q);
        assert!(pool.owned() <= POOL_BUFFERS);
    }

    // Whatever the device and the peer did, the driver's own bookkeeping must
    // still be clean and its pool must still hand out only real, distinct
    // buffers.
    assert_eq!(counters.invariant, InvariantFaults::default());
    let mut seen = [false; POOL_BUFFERS];
    // One more than the pool holds, so the loop ends on exhaustion rather than
    // on this bound; asserted immediately afterwards.
    for _ in 0..=POOL_BUFFERS {
        let Some(buffer) = pool.alloc() else {
            break;
        };
        let index = buffer.index() as usize;
        assert!(index < POOL_BUFFERS, "the ledger held index {index}");
        assert!(!seen[index], "index {index} was free twice");
        seen[index] = true;
        drop(buffer);
    }
    assert_eq!(
        pool.owned(),
        0,
        "the final drain ended on its own bound rather than on an empty ledger"
    );
}
