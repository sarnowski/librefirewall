//! The steady-state poll pass of a dataplane port, and the order its steps run
//! in.
//!
//! [`RxPath`] and [`TxPath`] (the crate root) each answer for one direction's
//! distrust boundaries. What is left is the *sequence* in which a driver runs
//! them and which step raises which signal — six ordered calls that used to
//! live inside the protection domain's `loop`, where no host test could reach
//! them. [`DataplanePort`] owns them, so the sequence is asserted here rather
//! than believed.
//!
//! # Why the order is the order
//!
//! One pass is `reclaim → refill → drain → notify`, then `reap → post → notify`:
//!
//! 1. **`reclaim`** first, because it is what returns buffers the forwarder has
//!    finished with to the pool ledger. Running it after `refill` would refill
//!    from a pool that is a whole pass out of date, and a busy link would post
//!    fewer buffers than it has.
//! 2. **`refill`** before `drain`, so descriptors freed by the *previous*
//!    pass's completions are back at the device before this pass takes more
//!    frames out. The receive doorbell is rung once for the whole batch, after
//!    `drain`, rather than per buffer.
//! 3. **`drain`** publishes completed frames to the forwarder, and the
//!    forwarder is notified once per pass rather than once per frame: a
//!    notification is an seL4 system call, and the forwarder rereads the ring
//!    until it is empty, so a second notification for the same batch buys
//!    nothing and costs a context switch.
//! 4. **`reap` before `post`**, because reaping frees the virtqueue descriptors
//!    that `post` then fills. The reverse order would post against a queue
//!    still holding last pass's completed descriptors and stall the transmit
//!    direction one pass in every burst.
//!
//! Each doorbell is rung only when its step actually produced work, so an idle
//! port performs no MMIO writes at all.
//!
//! # Adversaries
//!
//! This module adds no distrust boundary of its own; it composes two that
//! already exist. The **hostile or malfunctioning device** (CONCEPT §7.1) is
//! answered by `virtio::queue` and [`RxPath`], the **byzantine neighbour PD**
//! (the forwarder) by [`TxPath`] and `pd_runtime::PoolOwner`. What this module
//! must not do is reintroduce an unbounded loop between them, and it does not:
//! [`poll_once`](DataplanePort::poll_once) runs each step exactly once, and
//! every step is itself bounded per call by a driver-owned quantity, so one
//! pass performs a bounded amount of work whatever the device and the peer
//! publish. There is no `while` anywhere in this module.

use pd_runtime::{Pipeline, PoolOwner};

use crate::bringup::{DriverVirtqueue, Live, QUEUE_SIZE, VirtioDevice};
use crate::{Counters, DriverStats, RxPath, TxPath};

/// How a poll pass tells the forwarder that frames are waiting.
///
/// A protection domain implements this over its Microkit channel. It is a trait
/// so the poll sequence is host-testable: `sel4_microkit::Channel` cannot be
/// constructed off seL4, and a notification is invisible from inside the domain
/// that sends it, so a test asserting "the forwarder was notified exactly once,
/// after `drain` and before the receive doorbell" has nothing else to observe.
pub trait ForwarderSignal {
    /// Signal the forwarder. Called at most once per poll pass.
    fn notify(&self);
}

/// What one poll pass did.
///
/// Every field is "at least one", not a count: the pass raises each signal once
/// for the whole batch (see the module header), so the counts a caller might
/// want are the [`Counters`] and `DeviceFaults` that
/// [`stats`](DataplanePort::stats) samples, not this. It exists so a test can
/// assert which steps produced work without reading the device's MMIO, and so a
/// caller can tell a pass that moved traffic from an idle one.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PollOutcome {
    /// Frames were published to the forwarder and it was notified.
    pub notified_forwarder: bool,
    /// Buffers were reposted to the receive virtqueue and its doorbell rung.
    pub rang_receive_doorbell: bool,
    /// Frames were posted to the transmit virtqueue and its doorbell rung.
    pub rang_transmit_doorbell: bool,
}

impl PollOutcome {
    /// Whether the pass did nothing at all: no frame in either direction, no
    /// buffer reposted, and so no MMIO write and no notification.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        *self == Self::default()
    }
}

/// One dataplane port's steady state: both virtqueues, both pipeline
/// directions, and the tallies.
///
/// The port owns its virtqueues rather than borrowing them per call, for the
/// same reason [`RxPath`] owns its ring handle: a virtqueue carries the
/// driver-private descriptor lifecycle — which descriptors are free, which are
/// published, and what length each was posted with — so a second view of the
/// same ring would hand out descriptors the first still considers the device's.
pub struct DataplanePort<'pipe> {
    receive_queue: DriverVirtqueue,
    transmit_queue: DriverVirtqueue,
    pool: PoolOwner<'pipe>,
    receive: RxPath<'pipe, QUEUE_SIZE>,
    transmit: TxPath<'pipe, QUEUE_SIZE>,
    counters: Counters,
}

impl<'pipe> DataplanePort<'pipe> {
    /// Take every handle this port needs, once, and move both virtqueues in.
    ///
    /// `receive_pipeline` is the pipeline this port receives *into* — its pool
    /// is this NIC's receive DMA target and this port owns that pool — and
    /// `transmit_pipeline` the one it transmits *out of*, whose pool belongs to
    /// the peer driver. Each `_paddr` is the physical address of the region the
    /// matching reference maps, which is what turns a pool index into a DMA
    /// address.
    ///
    /// Call once per protection domain. Every handle taken here is this
    /// domain's own position in a ring; taking a second set would restart at
    /// slot zero and re-walk slots already used (see the `pd_runtime` crate
    /// header).
    #[must_use]
    pub fn attach(
        receive_pipeline: &'pipe Pipeline,
        receive_pipeline_paddr: u64,
        transmit_pipeline: &'pipe Pipeline,
        transmit_pipeline_paddr: u64,
        receive_queue: DriverVirtqueue,
        transmit_queue: DriverVirtqueue,
    ) -> Self {
        Self {
            receive_queue,
            transmit_queue,
            pool: PoolOwner::attach(receive_pipeline),
            receive: RxPath::attach(receive_pipeline, receive_pipeline_paddr),
            transmit: TxPath::attach(transmit_pipeline, transmit_pipeline_paddr),
            counters: Counters::default(),
        }
    }

    /// Fill the receive virtqueue with buffers before the device is live.
    ///
    /// Separate from [`poll_once`](Self::poll_once) because it must run while
    /// the device is still [`Configured`](crate::bringup::Configured): the
    /// descriptors are published to the available ring, and the device is told
    /// about them by the receive doorbell that
    /// [`go_live`](crate::bringup::Configured::go_live) rings *after*
    /// `DRIVER_OK`. Priming from inside the poll loop instead would leave the
    /// device live with an empty receive queue for one pass, dropping whatever
    /// arrived in it.
    ///
    /// Returns whether any buffer was posted — false only if the pool is empty,
    /// which at attach time it never is.
    pub fn prime(&mut self) -> bool {
        self.receive
            .refill(&mut self.receive_queue, &mut self.pool, &mut self.counters)
    }

    /// Run one poll pass in both directions; see the module header for the
    /// order and why it is that order.
    ///
    /// Bounded: six calls, each itself bounded per call by a driver-owned
    /// quantity, and no loop of its own. Neither the device nor the forwarder
    /// can extend a pass.
    pub fn poll_once<D: VirtioDevice>(
        &mut self,
        device: &Live<D>,
        forwarder: &impl ForwarderSignal,
    ) -> PollOutcome {
        self.pool.reclaim();
        let reposted =
            self.receive
                .refill(&mut self.receive_queue, &mut self.pool, &mut self.counters);
        let forwarded =
            self.receive
                .drain(&mut self.receive_queue, &mut self.pool, &mut self.counters);
        if forwarded {
            forwarder.notify();
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
            notified_forwarder: forwarded,
            rang_receive_doorbell: reposted,
            rang_transmit_doorbell: transmitted,
        }
    }

    /// Sample everything this port can say about its device, its peer, and
    /// itself, in the shape the metrics endpoint (CONCEPT §11) will scrape.
    #[must_use]
    pub fn stats(&self) -> DriverStats {
        DriverStats::sample(&self.counters, &self.receive_queue, &self.transmit_queue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InvariantFaults;
    use crate::bringup::{RX_QUEUE, TX_QUEUE, offered};
    use crate::fake_device::{Event, FakeDevice, Log};
    use core::sync::atomic::{Ordering, fence};
    use pd_runtime::{
        BUFFER_SIZE, Descriptor, POOL_BUFFERS, RING_SLOTS, RingConsumer, RingProducer,
    };
    use proptest::prelude::*;
    use std::boxed::Box;
    use std::vec;
    use std::vec::Vec;
    use virtio::net::VirtioNetHdr;

    /// A forwarder that records its notification into the shared log, so a
    /// notification and a doorbell ring land in one ordered sequence.
    struct RecordingForwarder {
        log: Log,
    }

    impl ForwarderSignal for RecordingForwarder {
        fn notify(&self) {
            self.log.record(Event::ForwarderNotified);
        }
    }

    /// A 16-byte-aligned virtqueue backing region, the alignment
    /// `SplitVirtqueue::new` requires.
    #[repr(C, align(16))]
    struct VqRegion([u8; 4096]);

    /// A frame length the device can report that is neither runt nor clamped.
    const FRAME_LEN: u32 = (VirtioNetHdr::LEN + 64) as u32;

    /// One dataplane port with both virtqueues over real regions, a live fake
    /// device, the peer handles on both pipelines, and the shared log.
    ///
    /// The pipelines are leaked so the port's handles borrow them for
    /// `'static`, exactly as a protection domain's mapped region does. Every
    /// peer handle is taken once here for the fixture's life: a fresh handle
    /// per assertion would restart at slot zero and re-walk slots already used.
    struct PortFixture {
        receive_region: Box<VqRegion>,
        transmit_region: Box<VqRegion>,
        port: DataplanePort<'static>,
        device: Live<FakeDevice>,
        forwarder: RecordingForwarder,
        log: Log,
        /// The forwarder's end of the receive pipeline's `rx` ring: what this
        /// port publishes completed frames onto.
        forwarded: RingConsumer<'static, RING_SLOTS>,
        /// The forwarder's end of the receive pipeline's `free` ring: how a
        /// buffer comes back to this port, which owns that pool.
        returns: RingProducer<'static, RING_SLOTS>,
        /// The forwarder's end of the transmit pipeline's `tx` ring: how frames
        /// are queued for this port to send.
        peer: RingProducer<'static, RING_SLOTS>,
        /// The device's used-ring index for the receive virtqueue.
        receive_used_idx: u16,
    }

    impl PortFixture {
        /// Bring a device fully up and attach a port to it, leaving the receive
        /// virtqueue primed exactly as a driver protection domain does.
        fn new() -> Self {
            let log = Log::new();
            let configured = offered(FakeDevice::conforming(&log))
                .acknowledge()
                .expect("a conforming device acknowledges")
                .negotiate_features()
                .expect("a conforming device offers virtio 1.0")
                .configure_queues(0x3000_0000)
                .expect("a conforming device takes both queues");

            let receive_pipeline: &'static Pipeline = Box::leak(Box::new(Pipeline::new()));
            let transmit_pipeline: &'static Pipeline = Box::leak(Box::new(Pipeline::new()));
            let mut receive_region = Box::new(VqRegion([0; 4096]));
            let mut transmit_region = Box::new(VqRegion([0; 4096]));
            // SAFETY: the pointer backs a 16-byte-aligned, zeroed region owned
            // solely by this test and outliving the queue, and no second queue
            // is built over it — `SplitVirtqueue::new`'s contract.
            let receive_queue = unsafe { DriverVirtqueue::new(receive_region.0.as_mut_ptr()) };
            // SAFETY: as above, over the second, disjoint region.
            let transmit_queue = unsafe { DriverVirtqueue::new(transmit_region.0.as_mut_ptr()) };

            // The pipelines' real host addresses stand in for their physical
            // ones, so a buffer address the port derives resolves to real bytes.
            let mut port = DataplanePort::attach(
                receive_pipeline,
                core::ptr::from_ref(receive_pipeline) as u64,
                transmit_pipeline,
                core::ptr::from_ref(transmit_pipeline) as u64,
                receive_queue,
                transmit_queue,
            );
            assert!(port.prime(), "the pool starts full");

            Self {
                receive_region,
                transmit_region,
                port,
                device: configured.go_live(),
                forwarder: RecordingForwarder { log: log.clone() },
                log,
                forwarded: receive_pipeline.rx.consumer(),
                returns: receive_pipeline.free.producer(),
                peer: transmit_pipeline.tx.producer(),
                receive_used_idx: 0,
            }
        }

        fn poll(&mut self) -> PollOutcome {
            self.port.poll_once(&self.device, &self.forwarder)
        }

        /// Publish a receive completion for descriptor `head` reporting
        /// `used_len`, the way the device does: write the used element, fence,
        /// then advance the used index.
        fn complete_receive(&mut self, head: u16, used_len: u32) {
            let used = DriverVirtqueue::LAYOUT.device_offset;
            let slot = (self.receive_used_idx as usize) & (QUEUE_SIZE - 1);
            let base = self.receive_region.0.as_mut_ptr();
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
            let base = self.transmit_region.0.as_mut_ptr();
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

        /// Queue a frame on the transmit pipeline as the forwarder would.
        fn queue_transmit(&mut self, buffer: u32) {
            self.peer
                .try_enqueue(Descriptor::new(buffer, VirtioNetHdr::LEN as u32, 8))
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
    fn a_received_frame_notifies_the_forwarder_and_the_freed_descriptor_rings_next_pass() {
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
                notified_forwarder: true,
                rang_receive_doorbell: false,
                rang_transmit_doorbell: false,
            }
        );
        assert_eq!(fx.log.take(), vec![Event::ForwarderNotified]);

        let second = fx.poll();
        assert!(second.rang_receive_doorbell);
        assert!(!second.notified_forwarder);
        assert_eq!(fx.log.take(), vec![Event::Rang(RX_QUEUE)]);
    }

    #[test]
    fn the_forwarder_is_notified_once_per_pass_however_many_frames_arrive() {
        // A notification is a system call and the forwarder drains the ring, so
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
            .filter(|event| **event == Event::ForwarderNotified)
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
                notified_forwarder: false,
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
                notified_forwarder: true,
                rang_receive_doorbell: true,
                rang_transmit_doorbell: true,
            }
        );
        assert_eq!(
            fx.log.take(),
            vec![
                Event::ForwarderNotified,
                Event::Rang(RX_QUEUE),
                Event::Rang(TX_QUEUE),
            ],
        );
    }

    #[test]
    fn reclaim_precedes_refill_so_a_returned_buffer_is_reposted_in_the_same_pass() {
        // Why `reclaim` is first. With the pool empty, only a buffer the
        // forwarder returns can refill the receive queue — and it can only do
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
        assert!(first.notified_forwarder);
        assert!(
            !first.rang_receive_doorbell,
            "the pool is empty, so nothing can be reposted yet"
        );

        // The forwarder finishes with the frame and hands the buffer back.
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

        /// A hostile device and a byzantine forwarder driving the pass
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
                    let descriptor = Descriptor::new(
                        buffer % (POOL_BUFFERS as u32 + 2),
                        VirtioNetHdr::LEN as u32,
                        (used_len % (BUFFER_SIZE as u32)).max(1),
                    );
                    // A full ring is one of the states under test, so a refused
                    // enqueue is part of the scenario rather than a failure.
                    let _ring_may_be_full = fx.peer.try_enqueue(descriptor);
                }
                fx.log.take();
                let outcome = fx.poll();
                let raised = fx.log.take();

                prop_assert_eq!(
                    raised.contains(&Event::ForwarderNotified),
                    outcome.notified_forwarder
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
