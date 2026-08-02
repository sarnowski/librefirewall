//! The steady-state poll pass of a dataplane port, and the order its steps run
//! in.
//!
//! [`RxPath`] and [`TxPath`] (the crate root) each answer for one direction's
//! distrust boundaries. What is left is the *sequence* a driver runs them in,
//! which used to live inside the protection domain's `loop` where no host test
//! could reach it. [`NicPort`] owns it, so it is asserted here rather
//! than believed.
//!
//! # Why the order is the order
//!
//! One pass is `reclaim → refill → drain → notify`, then `reap → post →
//! notify`. Each adjacency is chosen against a named failure of its reverse:
//!
//! - `reclaim` before `refill`, or the refill draws on a pool a whole pass out
//!   of date and a busy link posts fewer buffers than it holds.
//! - `refill` before `drain`, so descriptors freed by the *previous* pass's
//!   completions are back at the device before this pass takes more frames out.
//! - `reap` before `post`, because reaping frees the virtqueue descriptors
//!   `post` then fills; the reverse stalls the transmit direction one pass in
//!   every burst.
//!
//! Each signal is raised once per batch, not once per frame: a notification is
//! an seL4 system call and the peer rereads the ring until it is empty, so
//! a second one for the same batch buys nothing and costs a context switch. A
//! doorbell is rung only when its step produced work, so an idle port performs
//! no MMIO write at all.
//!
//! # Adversaries
//!
//! This module adds no distrust boundary of its own; it composes two that
//! already exist. The **hostile or malfunctioning device** is
//! answered by `virtio::queue` and [`RxPath`], the **byzantine neighbour PD**
//! (the peer) by [`TxPath`] and `pd_runtime::PoolOwner`. What this module
//! must not do is reintroduce an unbounded loop between them.

use pd_runtime::{ForwardRings, Pool, PoolCounters, PoolOwner, ReturnRing};

use crate::bringup::{DriverVirtqueue, Live, QUEUE_SIZE, VirtioDevice};
use crate::{Counters, DriverStats, RxPath, TxPath};

/// How a poll pass tells the peer that frames are waiting.
///
/// A trait so the poll sequence is host-testable: `sel4_microkit::Channel`
/// cannot be constructed off seL4, and a notification is invisible from inside
/// the domain that sends it, so a test asserting "notified exactly once, after
/// `drain` and before the receive doorbell" has nothing else to observe.
pub trait PeerSignal {
    /// Signal the peer. Called at most once per poll pass.
    fn notify(&self);
}

/// Which signals one poll pass raised.
///
/// Exists so a test can assert which steps produced work without reading the
/// device's MMIO, and so a caller can tell a pass that moved traffic from an
/// idle one. It is not a tally: the counts an operator wants are the
/// [`Counters`] and `DeviceFaults` that [`stats`](NicPort::stats) samples.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PollOutcome {
    pub notified_peer: bool,
    pub rang_receive_doorbell: bool,
    pub rang_transmit_doorbell: bool,
}

impl PollOutcome {
    #[must_use]
    pub fn is_idle(&self) -> bool {
        *self == Self::default()
    }
}

/// The regions of the pipeline a port receives *into*, whose pool it owns.
///
/// There is no `&Pool` field, and its absence *is* the grant: this direction
/// hands buffer addresses to its NIC and never dereferences one, so the domain
/// maps no part of that pool and holds only its physical base.
///
/// A struct rather than loose arguments because [`TransmitSide`] carries the
/// same shapes in the same order; being a distinct type is what makes passing
/// the two the wrong way round a compile error.
pub struct ReceiveSide<'ring> {
    /// Shared with the peer; this port produces on `rx`.
    pub rings: &'ring ForwardRings,
    /// Where the transmitting driver hands buffers back; consumed here.
    pub returns: &'ring ReturnRing,
    pub pool_paddr: u64,
}

/// The regions of the pipeline a port transmits *out of*, whose pool belongs to
/// the peer driver and is mapped here: writing the virtio-net header in front
/// of a frame is the only production dereference of pool bytes in the system.
pub struct TransmitSide<'ring> {
    /// Shared with the peer; this port consumes `tx`.
    pub rings: &'ring ForwardRings,
    /// Where this port hands buffers back to their owner.
    pub returns: &'ring ReturnRing,
    pub pool: &'ring Pool,
    pub pool_paddr: u64,
}

/// One dataplane port's steady state.
///
/// The port owns its virtqueues rather than borrowing them per call: a
/// virtqueue carries the driver-private descriptor lifecycle — which
/// descriptors are free, which are published, and what length each was posted
/// with — so a second view of the same ring would hand out descriptors the
/// first still considers the device's.
pub struct NicPort<'ring> {
    receive_queue: DriverVirtqueue,
    transmit_queue: DriverVirtqueue,
    pool: PoolOwner<'ring>,
    receive: RxPath<'ring, QUEUE_SIZE>,
    transmit: TxPath<'ring, QUEUE_SIZE>,
    counters: Counters,
}

impl<'ring> NicPort<'ring> {
    /// Take every handle this port needs and move both virtqueues in.
    ///
    /// **Unenforced precondition:** call once per protection domain.
    /// Every handle taken here is this domain's own position in a ring, so a
    /// second port over the same pipelines restarts at slot zero and re-walks
    /// slots already used. No type refuses the second call; `queue`'s crate
    /// header states that single-handle rule and why nothing enforces it. Treat
    /// it as unenforced rather than as checked elsewhere.
    #[must_use]
    pub fn attach(
        receive: ReceiveSide<'ring>,
        transmit: TransmitSide<'ring>,
        receive_queue: DriverVirtqueue,
        transmit_queue: DriverVirtqueue,
    ) -> Self {
        Self {
            receive_queue,
            transmit_queue,
            pool: PoolOwner::attach(receive.returns),
            receive: RxPath::attach(receive.rings, receive.pool_paddr),
            transmit: TxPath::attach(
                transmit.rings,
                transmit.returns,
                transmit.pool,
                transmit.pool_paddr,
            ),
            counters: Counters::default(),
        }
    }

    /// Fill the receive virtqueue with buffers before the device is live,
    /// returning whether any was posted.
    ///
    /// Separate from [`poll_once`](Self::poll_once) because it must run while
    /// the device is still [`Configured`](crate::bringup::Configured): the
    /// descriptors are published to the available ring, and the device is told
    /// about them by the receive doorbell that
    /// [`go_live`](crate::bringup::Configured::go_live) rings *after*
    /// `DRIVER_OK`. Priming from inside the poll loop instead would leave the
    /// device live with an empty receive queue for one pass, dropping whatever
    /// arrived in it.
    pub fn prime(&mut self) -> bool {
        self.receive
            .refill(&mut self.receive_queue, &mut self.pool, &mut self.counters)
    }

    /// Run one poll pass in both directions; see the module header for the
    /// order and why it is that order.
    ///
    /// Each step is bounded per call by a driver-owned quantity, so neither the
    /// device nor the peer can extend a pass.
    pub fn poll_once<D: VirtioDevice>(
        &mut self,
        device: &Live<D>,
        peer: &impl PeerSignal,
    ) -> PollOutcome {
        self.pool.reclaim();
        let reposted =
            self.receive
                .refill(&mut self.receive_queue, &mut self.pool, &mut self.counters);
        let forwarded =
            self.receive
                .drain(&mut self.receive_queue, &mut self.pool, &mut self.counters);
        if forwarded {
            peer.notify();
        }
        if reposted {
            device.ring_receive();
        }

        self.transmit
            .reap(&mut self.transmit_queue, &mut self.counters);
        let transmitted = self
            .transmit
            .post(&mut self.transmit_queue, &mut self.counters);
        if transmitted {
            device.ring_transmit();
        }

        PollOutcome {
            notified_peer: forwarded,
            rang_receive_doorbell: reposted,
            rang_transmit_doorbell: transmitted,
        }
    }

    /// Sample this port in the shape the appliance's metrics endpoint
    /// scrapes.
    #[must_use]
    pub fn stats(&self) -> DriverStats {
        DriverStats::sample(&self.counters, &self.receive_queue, &self.transmit_queue)
    }

    /// What this port's receive pool owner has seen, which is where a forged
    /// return from the peer is refused and counted.
    #[must_use]
    pub fn pool_counters(&self) -> PoolCounters {
        self.pool.counters()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InvariantFaults;
    use crate::bringup::{Offered, RX_QUEUE, TX_QUEUE};
    use crate::fake_device::{Event, FakeDevice, Log};
    use core::sync::atomic::{Ordering, fence};
    use pd_runtime::{
        BUFFER_SIZE, Descriptor, POOL_BUFFERS, RING_SLOTS, RingConsumer, RingProducer, Verdict,
    };
    use proptest::prelude::*;
    use std::boxed::Box;
    use std::vec;
    use std::vec::Vec;
    use virtio::net::VirtioNetHdr;

    /// A peer that records its notification into the shared log, so a
    /// notification and a doorbell ring land in one ordered sequence.
    struct RecordingPeer {
        log: Log,
    }

    impl PeerSignal for RecordingPeer {
        fn notify(&self) {
            self.log.record(Event::PeerNotified);
        }
    }

    /// The heap allocation a fixture region owns, carrying the 16-byte
    /// alignment `SplitVirtqueue::new` requires.
    #[repr(C, align(16))]
    struct VqPage([u8; 4096]);

    /// A fixture virtqueue region, reachable only through the one raw pointer
    /// the queue under test is built over.
    ///
    /// The bytes are `Box::into_raw`d and no `&`/`&mut` into them is ever
    /// formed, so fixture and driver share a single tag for the whole region's
    /// life. A `Box` field would not survive: moving the fixture into place
    /// emits a `Unique` retag over the allocation, which pops the tag the
    /// virtqueue was built from and makes every later driver access undefined
    /// behaviour — while the fixture goes on claiming to prove the driver's
    /// conduct against a hostile device. Owning the allocation as a
    /// raw pointer leaves no `Box` to move and so no ordering to get wrong,
    /// which is what makes that unrepresentable rather than a rule to
    /// remember.
    struct VqRegion {
        page: *mut VqPage,
    }

    impl VqRegion {
        fn zeroed() -> Self {
            Self {
                page: Box::into_raw(Box::new(VqPage([0; 4096]))),
            }
        }

        /// The pointer the virtqueue is built over, and the only route to the
        /// bytes — `*mut` from `&self` deliberately, because handing out a
        /// second, separately derived pointer is what a fixture must not do.
        fn base(&self) -> *mut u8 {
            self.page.cast::<u8>()
        }
    }

    impl Drop for VqRegion {
        fn drop(&mut self) {
            // SAFETY: `page` came from `Box::into_raw` in `zeroed`, is never
            // replaced, and no other owner exists, so this reconstructs that
            // `Box` exactly once.
            drop(unsafe { Box::from_raw(self.page) });
        }
    }

    /// A frame length the device can report that is neither runt nor clamped.
    const FRAME_LEN: u32 = (VirtioNetHdr::LEN + 64) as u32;

    /// One dataplane port with both virtqueues over real regions, a live fake
    /// device, the peer handles on both pipelines, and the shared log.
    ///
    /// Every pipeline region is leaked so the port's handles borrow it for
    /// `'static`, exactly as a protection domain's mapped regions do. Every
    /// peer handle is taken once here for the fixture's life: a fresh handle
    /// per assertion would restart at slot zero and re-walk slots already used.
    struct PortFixture {
        receive_region: VqRegion,
        transmit_region: VqRegion,
        port: NicPort<'static>,
        device: Live<FakeDevice>,
        peer: RecordingPeer,
        log: Log,
        /// The peer's end of the receive pipeline's `rx` ring: what this
        /// port publishes completed frames onto.
        forwarded: RingConsumer<'static, RING_SLOTS>,
        /// The peer's end of the receive pipeline's `free` ring: how a
        /// buffer comes back to this port, which owns that pool.
        returns: RingProducer<'static, RING_SLOTS>,
        /// The peer's end of the transmit pipeline's `tx` ring: how frames
        /// are queued for this port to send.
        to_transmit: RingProducer<'static, RING_SLOTS>,
        /// The device's used-ring index for the receive virtqueue.
        receive_used_idx: u16,
    }

    impl PortFixture {
        /// Bring a device fully up and attach a port to it, leaving the receive
        /// virtqueue primed exactly as a driver protection domain does.
        fn new() -> Self {
            let log = Log::new();
            let device = FakeDevice::conforming(&log);
            let bus = device.bus();
            let configured = Offered::new(device)
                .acknowledge(&bus)
                .expect("a conforming device acknowledges")
                .negotiate_features()
                .expect("a conforming device offers virtio 1.0")
                .configure_queues(0x3000_0000)
                .expect("a conforming device takes both queues");

            // The receive pipeline: this port owns its pool, and — as under
            // seL4 — takes only that pool's address, never a reference to it.
            let receive_pool: &'static Pool = Box::leak(Box::new(Pool::new()));
            let receive_rings: &'static ForwardRings = Box::leak(Box::new(ForwardRings::new()));
            let receive_returns: &'static ReturnRing = Box::leak(Box::new(ReturnRing::new()));
            // The transmit pipeline, whose pool belongs to the peer driver and
            // is mapped here for the header write alone.
            let transmit_pool: &'static Pool = Box::leak(Box::new(Pool::new()));
            let transmit_rings: &'static ForwardRings = Box::leak(Box::new(ForwardRings::new()));
            let transmit_returns: &'static ReturnRing = Box::leak(Box::new(ReturnRing::new()));
            let receive_region = VqRegion::zeroed();
            let transmit_region = VqRegion::zeroed();
            // SAFETY: `VqRegion::zeroed` allocates a 16-byte-aligned, zeroed
            // 4096-byte region freed by its own `Drop` alone, so it outlives
            // the queue, and `base` is the only pointer into it, so no second
            // queue is built over it — `SplitVirtqueue::new`'s contract.
            let receive_queue = unsafe { DriverVirtqueue::new(receive_region.base()) };
            // SAFETY: as above, over the second, disjoint region.
            let transmit_queue = unsafe { DriverVirtqueue::new(transmit_region.base()) };

            // Each pool region's real host address stands in for its physical
            // one, so a buffer address the port derives resolves to real bytes.
            let mut port = NicPort::attach(
                ReceiveSide {
                    rings: receive_rings,
                    returns: receive_returns,
                    pool_paddr: core::ptr::from_ref(receive_pool) as u64,
                },
                TransmitSide {
                    rings: transmit_rings,
                    returns: transmit_returns,
                    pool: transmit_pool,
                    pool_paddr: core::ptr::from_ref(transmit_pool) as u64,
                },
                receive_queue,
                transmit_queue,
            );
            assert!(port.prime(), "the pool starts full");

            Self {
                receive_region,
                transmit_region,
                port,
                device: configured.go_live(),
                peer: RecordingPeer { log: log.clone() },
                log,
                forwarded: receive_rings.rx.consumer(),
                returns: receive_returns.free.producer(),
                to_transmit: transmit_rings.tx.producer(),
                receive_used_idx: 0,
            }
        }

        fn poll(&mut self) -> PollOutcome {
            self.port.poll_once(&self.device, &self.peer)
        }

        /// Publish a receive completion for descriptor `head` reporting
        /// `used_len`, the way the device does: write the used element, fence,
        /// then advance the used index.
        fn complete_receive(&mut self, head: u16, used_len: u32) {
            let used = DriverVirtqueue::LAYOUT.device_offset;
            let slot = (self.receive_used_idx as usize) & (QUEUE_SIZE - 1);
            let base = self.receive_region.base();
            self.receive_used_idx = self.receive_used_idx.wrapping_add(1);
            // SAFETY: `slot < QUEUE_SIZE`, so the used element and the used
            // index both lie inside the 4096-byte region this test owns, and
            // the virtqueue layout makes each field naturally aligned.
            unsafe {
                base.add(used + 4 + slot * 8)
                    .cast::<u32>()
                    .write_volatile(u32::from(head));
                base.add(used + 4 + slot * 8 + 4)
                    .cast::<u32>()
                    .write_volatile(used_len);
                fence(Ordering::Release);
                base.add(used + 2)
                    .cast::<u16>()
                    .write_volatile(self.receive_used_idx);
            }
        }

        /// Play the device on the transmit side: consume every frame the driver
        /// made available and complete each one.
        fn transmit_everything(&mut self) {
            let driver = DriverVirtqueue::LAYOUT.driver_offset;
            let used = DriverVirtqueue::LAYOUT.device_offset;
            let base = self.transmit_region.base();
            // SAFETY: every offset below lies inside the 4096-byte region this
            // test owns — the available-ring header and its `QUEUE_SIZE`
            // entries, and the used ring's header and its `QUEUE_SIZE`
            // elements — each naturally aligned by the virtqueue layout.
            unsafe {
                let available = base.add(driver + 2).cast::<u16>().read_volatile();
                fence(Ordering::Acquire);
                for index in 0..available {
                    let slot = (index as usize) & (QUEUE_SIZE - 1);
                    let head = base
                        .add(driver + 4 + slot * 2)
                        .cast::<u16>()
                        .read_volatile();
                    base.add(used + 4 + slot * 8)
                        .cast::<u32>()
                        .write_volatile(u32::from(head));
                    base.add(used + 4 + slot * 8 + 4)
                        .cast::<u32>()
                        .write_volatile(0);
                }
                fence(Ordering::Release);
                base.add(used + 2).cast::<u16>().write_volatile(available);
            }
        }

        /// Queue a frame on the transmit pipeline as the peer would.
        fn queue_transmit(&mut self, buffer: u32) {
            self.to_transmit
                .try_enqueue(Descriptor::new(
                    buffer,
                    VirtioNetHdr::LEN as u32,
                    8,
                    Verdict::Transmit,
                ))
                .expect("the tx ring has room");
        }
    }

    #[test]
    fn an_idle_port_raises_no_signal_and_performs_no_mmio() {
        let mut fx = PortFixture::new();
        fx.log.take();
        let outcome = fx.poll();
        assert!(outcome.is_idle());
        assert_eq!(outcome, PollOutcome::default());
        assert!(
            fx.log.take().is_empty(),
            "an idle pass must not ring a doorbell or notify"
        );
    }

    #[test]
    fn a_received_frame_notifies_the_peer_and_the_freed_descriptor_rings_next_pass() {
        // The consequence of refilling *before* draining: the descriptor a
        // completion frees goes back to the device on the following pass, and
        // the pass that forwarded the frame raises the notification alone.
        // A test asserting both signals in one pass would be asserting an
        // ordering the dataplane does not have.
        let mut fx = PortFixture::new();
        fx.complete_receive(0, FRAME_LEN);
        fx.log.take();

        let first = fx.poll();
        assert_eq!(
            first,
            PollOutcome {
                notified_peer: true,
                rang_receive_doorbell: false,
                rang_transmit_doorbell: false,
            }
        );
        assert_eq!(fx.log.take(), vec![Event::PeerNotified]);

        let second = fx.poll();
        assert!(second.rang_receive_doorbell);
        assert!(!second.notified_peer);
        assert_eq!(fx.log.take(), vec![Event::Rang(RX_QUEUE)]);
    }

    #[test]
    fn the_peer_is_notified_once_per_pass_however_many_frames_arrive() {
        // A notification is a system call and the peer drains the ring, so
        // a second one for the same batch costs a context switch and buys
        // nothing. A device completing every posted descriptor at once must
        // still produce exactly one.
        let mut fx = PortFixture::new();
        for head in 0..QUEUE_SIZE as u16 {
            fx.complete_receive(head, FRAME_LEN);
        }
        fx.log.take();

        fx.poll();
        let notifications = fx
            .log
            .take()
            .iter()
            .filter(|event| **event == Event::PeerNotified)
            .count();
        assert_eq!(notifications, 1);
    }

    #[test]
    fn a_queued_frame_rings_only_the_transmit_doorbell() {
        let mut fx = PortFixture::new();
        fx.queue_transmit(3);
        fx.log.take();

        let outcome = fx.poll();
        assert_eq!(
            outcome,
            PollOutcome {
                notified_peer: false,
                rang_receive_doorbell: false,
                rang_transmit_doorbell: true,
            }
        );
        assert_eq!(fx.log.take(), vec![Event::Rang(TX_QUEUE)]);
    }

    #[test]
    fn a_pass_that_does_everything_runs_receive_before_transmit() {
        // Receive before transmit is the pass's shape, and a test exercising
        // one direction at a time would not notice the two being swapped. The
        // first pass frees a receive descriptor so the second can raise all
        // three signals at once.
        let mut fx = PortFixture::new();
        fx.complete_receive(0, FRAME_LEN);
        fx.poll();

        fx.complete_receive(1, FRAME_LEN);
        fx.queue_transmit(5);
        fx.log.take();

        let outcome = fx.poll();
        assert_eq!(
            outcome,
            PollOutcome {
                notified_peer: true,
                rang_receive_doorbell: true,
                rang_transmit_doorbell: true,
            }
        );
        assert_eq!(
            fx.log.take(),
            vec![
                Event::PeerNotified,
                Event::Rang(RX_QUEUE),
                Event::Rang(TX_QUEUE),
            ],
        );
    }

    #[test]
    fn reclaim_precedes_refill_so_a_returned_buffer_is_reposted_in_the_same_pass() {
        // Why `reclaim` is first. With the pool empty, only a buffer the
        // peer returns can refill the receive queue — and it can only do
        // so in the same pass if the return is reclaimed before the refill
        // runs. Reversing the two would leave the queue a descriptor short for
        // a whole pass on every return.
        let mut fx = PortFixture::new();
        let mut held = Vec::new();
        while let Some(buffer) = fx.port.pool.alloc() {
            held.push(buffer);
        }

        fx.complete_receive(0, FRAME_LEN);
        let first = fx.poll();
        assert!(first.notified_peer);
        assert!(
            !first.rang_receive_doorbell,
            "the pool is empty, so nothing can be reposted yet"
        );

        // The peer finishes with the frame and hands the buffer back.
        let descriptor = fx.forwarded.try_dequeue().expect("a frame was forwarded");
        fx.returns
            .try_enqueue(descriptor)
            .expect("the free ring has room");

        let second = fx.poll();
        assert!(
            second.rang_receive_doorbell,
            "the reclaimed buffer reached the device in the same pass"
        );
    }

    #[test]
    fn reap_precedes_post_so_a_full_transmit_queue_drains_and_refills_in_one_pass() {
        // Why `reap` is first. With every transmit descriptor completed but not
        // yet reaped, a queued frame can only go out in this pass if reaping
        // frees a descriptor before posting looks for one. Reversing the two
        // would stall the transmit direction one pass in every burst.
        let mut fx = PortFixture::new();
        for buffer in 0..QUEUE_SIZE as u32 {
            fx.queue_transmit(buffer);
        }
        fx.poll();
        assert_eq!(fx.port.transmit_queue.free_count(), 0, "the queue is full");

        fx.transmit_everything();
        fx.queue_transmit(QUEUE_SIZE as u32 + 1);
        fx.log.take();

        let outcome = fx.poll();
        assert!(
            outcome.rang_transmit_doorbell,
            "reaping freed a descriptor for the queued frame in the same pass"
        );
        assert_eq!(fx.log.take(), vec![Event::Rang(TX_QUEUE)]);
    }

    #[test]
    fn stats_carry_the_counters_and_both_virtqueues_device_faults() {
        // What the metrics endpoint scrapes must reach it from all three
        // places, or a device misbehaving at line rate looks like an idle link.
        let mut fx = PortFixture::new();
        // A frame with nothing past the header, and a completion for a
        // descriptor this queue never posted.
        fx.complete_receive(0, VirtioNetHdr::LEN as u32);
        fx.complete_receive(QUEUE_SIZE as u16 + 9, 64);
        fx.poll();

        let stats = fx.port.stats();
        assert_eq!(stats.counters.input.rx_runt_dropped, 1);
        assert_eq!(stats.rx_device.completion_out_of_range, 1);
        assert_eq!(stats.counters.invariant, InvariantFaults::default());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// A hostile device and a byzantine peer driving the pass
        /// together: arbitrary completions with arbitrary reported lengths, and
        /// arbitrary descriptors — forged indices included — queued for
        /// transmit. No pass may panic, each pass raises each signal at most
        /// once, and the outcome must report exactly the signals raised: a
        /// doorbell rung without the outcome saying so would make the outcome,
        /// which is what a caller acts on, a lie.
        #[test]
        fn every_pass_is_bounded_and_reports_exactly_the_signals_it_raised(
            events in prop::collection::vec(
                (any::<u16>(), any::<u32>(), any::<u32>(), any::<bool>()),
                0..80,
            ),
        ) {
            let mut fx = PortFixture::new();
            for (head, used_len, buffer, queue) in events {
                fx.complete_receive(head % (QUEUE_SIZE as u16 + 4), used_len);
                if queue {
                    // The verdict is the peer's word to choose, undecodable
                    // values included, so it comes from the same arbitrary
                    // input as the span rather than from a valid variant.
                    let descriptor = Descriptor {
                        buffer: buffer % (POOL_BUFFERS as u32 + 2),
                        offset: VirtioNetHdr::LEN as u32,
                        len: (used_len % (BUFFER_SIZE as u32)).max(1),
                        verdict: used_len,
                    };
                    // A full ring is one of the states under test, so a refused
                    // enqueue is part of the scenario rather than a failure.
                    let _ring_may_be_full = fx.to_transmit.try_enqueue(descriptor);
                }
                fx.log.take();
                let outcome = fx.poll();
                let raised = fx.log.take();

                prop_assert_eq!(
                    raised.contains(&Event::PeerNotified),
                    outcome.notified_peer
                );
                prop_assert_eq!(
                    raised.contains(&Event::Rang(RX_QUEUE)),
                    outcome.rang_receive_doorbell
                );
                prop_assert_eq!(
                    raised.contains(&Event::Rang(TX_QUEUE)),
                    outcome.rang_transmit_doorbell
                );
                // One pass raises each signal at most once, whatever either
                // neighbour published, so a pass performs bounded work.
                prop_assert!(raised.len() <= 3);
                // Nothing either neighbour does may be recorded as our fault.
                prop_assert_eq!(fx.port.stats().counters.invariant, InvariantFaults::default());
            }
        }
    }
}
