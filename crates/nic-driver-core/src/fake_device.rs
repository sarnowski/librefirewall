//! A recording stand-in for a virtio device, for host tests only.
//!
//! The bring-up sequence's whole job is *ordering* (`bringup`'s module header),
//! and ordering is not observable through MMIO: a `CommonCfg` mapped over plain
//! host memory reads back exactly what was written, so a device that refuses a
//! reset, clears `FEATURES_OK`, offers one virtqueue, or names an unusable
//! doorbell slot cannot be expressed at all — and neither can "was the doorbell
//! rung before or after `DRIVER_OK`". This type implements
//! [`VirtioDevice`](crate::bringup::VirtioDevice) as a device *chooses* to
//! answer, and appends every driver action to a shared [`Log`], so a test
//! asserts the sequence rather than the end state.
//!
//! It models the *authority a device has* — any feature bitmap, any queue
//! count, any `queue_notify_off`, a reset it may simply not acknowledge — and
//! constrains none of it to what a conforming device would do.
//! [`FakeDevice::conforming`] is the well-behaved baseline; every builder
//! method takes one capability away from it.

use core::cell::{Cell, RefCell};
use std::rc::Rc;
use std::vec::Vec;

use virtio::pci::{NotifyError, QueueSetupError, ResetError, STATUS_FEATURES_OK};
use virtio::queue::QueueLayout;

use crate::bringup::{BusMaster, QueueDoorbell, VirtioDevice};

/// One thing a driver did to the device, in the order it did it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    /// The device was reset.
    Reset,
    /// The device was granted bus-master DMA.
    DmaEnabled,
    /// The `device_status` byte was overwritten with this value.
    Status(u8),
    /// This feature bitmap was written as the driver's accepted set.
    DriverFeatures(u64),
    /// This virtqueue's ring addresses were programmed and it was enabled.
    QueueConfigured(u16),
    /// This virtqueue's doorbell was successfully placed.
    DoorbellPlaced(u16),
    /// This virtqueue's doorbell was rung.
    Rang(u16),
    /// The peer was notified that frames are waiting.
    PeerNotified,
}

/// The shared, ordered record every fake in a test appends to. Cloning shares
/// the same log, which is what lets a device, its two doorbells, and the
/// peer signal all land in one sequence.
#[derive(Clone, Default)]
pub(crate) struct Log(Rc<RefCell<Vec<Event>>>);

impl Log {
    /// An empty log.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Everything recorded so far, oldest first.
    pub(crate) fn events(&self) -> Vec<Event> {
        self.0.borrow().clone()
    }

    /// Everything recorded since the last call, clearing the log, so a test
    /// asserts one poll pass's sequence rather than the whole run's.
    pub(crate) fn take(&self) -> Vec<Event> {
        core::mem::take(&mut self.0.borrow_mut())
    }

    /// Append one event.
    pub(crate) fn record(&self, event: Event) {
        self.0.borrow_mut().push(event);
    }
}

/// The `queue_notify_off` the fake reports for virtqueue 0; queue `i` gets
/// `NOTIFY_BASE + i`, so the two directions are distinguishable in the log and
/// a doorbell refusal can be aimed at one of them.
const NOTIFY_BASE: u16 = 0x10;

/// The DMA gate as a recorder: it appends to the same [`Log`] the device does,
/// so *when* the driver opened it sits in one sequence with the reset it must
/// follow. Nothing about it can refuse — a PCI command-register write cannot
/// fail — so the only thing worth observing is the order.
pub(crate) struct FakeBusMaster {
    log: Log,
}

impl FakeBusMaster {
    pub(crate) fn new(log: &Log) -> Self {
        Self { log: log.clone() }
    }
}

impl BusMaster for FakeBusMaster {
    fn enable_dma(&self) {
        self.log.record(Event::DmaEnabled);
    }
}

/// A doorbell that records its ring instead of writing MMIO.
pub(crate) struct FakeDoorbell {
    log: Log,
}

impl QueueDoorbell for FakeDoorbell {
    fn ring(&self, queue: u16) {
        self.log.record(Event::Rang(queue));
    }
}

/// A virtio device that answers however a test tells it to.
pub(crate) struct FakeDevice {
    log: Log,
    offered: u64,
    queues: u16,
    notify_base: u16,
    /// `Some(status)` for a device that never acknowledges its reset, carrying
    /// the status byte it holds instead.
    reset_refused: Option<u8>,
    /// A device that clears `FEATURES_OK` on readback, refusing the set.
    clears_features_ok: bool,
    /// The virtqueue index whose setup is refused, and why.
    refused_queue: Option<(u16, QueueSetupError)>,
    /// The virtqueue index whose doorbell cannot be placed, and why.
    refused_doorbell: Option<(u16, NotifyError)>,
    status: Cell<u8>,
}

impl FakeDevice {
    /// A device that does everything the virtio 1.0 specification requires of
    /// it: acknowledges the reset, offers virtio 1.0, keeps `FEATURES_OK`,
    /// exposes both virtqueues, and places both doorbells.
    pub(crate) fn conforming(log: &Log) -> Self {
        Self {
            log: log.clone(),
            offered: crate::bringup::ACCEPTED_FEATURES,
            queues: 2,
            notify_base: NOTIFY_BASE,
            reset_refused: None,
            clears_features_ok: false,
            refused_queue: None,
            refused_doorbell: None,
            status: Cell::new(0),
        }
    }

    /// The DMA gate over this device's own log, so a test can drive the
    /// handshake and read the reset and the grant out of one sequence. Taken
    /// before the device is moved into [`Offered`](crate::bringup::Offered).
    pub(crate) fn bus(&self) -> FakeBusMaster {
        FakeBusMaster::new(&self.log)
    }

    /// Offer this feature bitmap instead of exactly virtio 1.0.
    pub(crate) fn offering(mut self, features: u64) -> Self {
        self.offered = features;
        self
    }

    /// Report this many virtqueues.
    pub(crate) fn with_queues(mut self, queues: u16) -> Self {
        self.queues = queues;
        self
    }

    /// Report `queue_notify_off` values based at `base` rather than
    /// [`NOTIFY_BASE`].
    pub(crate) fn with_notify_off(mut self, base: u16) -> Self {
        self.notify_base = base;
        self
    }

    /// Never acknowledge the reset, holding `status` throughout.
    pub(crate) fn refusing_reset(mut self, status: u8) -> Self {
        self.reset_refused = Some(status);
        self
    }

    /// Clear `FEATURES_OK` on readback, refusing the negotiated set.
    pub(crate) fn clearing_features_ok(mut self) -> Self {
        self.clears_features_ok = true;
        self
    }

    /// Refuse to have virtqueue `index` programmed, for the stated reason.
    pub(crate) fn refusing_queue(mut self, index: u16, error: QueueSetupError) -> Self {
        self.refused_queue = Some((index, error));
        self
    }

    /// Name an unusable doorbell slot for virtqueue `index`.
    pub(crate) fn refusing_doorbell(mut self, index: u16, error: NotifyError) -> Self {
        self.refused_doorbell = Some((index, error));
        self
    }

    /// Which virtqueue a `queue_notify_off` this device reported belongs to.
    /// The inverse of what [`setup_queue`](VirtioDevice::setup_queue) returns,
    /// so a doorbell refusal can be aimed at one direction without the trait
    /// carrying an index it has no other use for.
    fn queue_of(&self, notify_off: u16) -> u16 {
        notify_off.wrapping_sub(self.notify_base)
    }
}

impl VirtioDevice for FakeDevice {
    type Doorbell = FakeDoorbell;

    fn reset(&self) -> Result<(), ResetError> {
        self.log.record(Event::Reset);
        match self.reset_refused {
            Some(status) => Err(ResetError::NotAcknowledged { status }),
            None => {
                self.status.set(0);
                Ok(())
            }
        }
    }

    fn status(&self) -> u8 {
        let held = self.status.get();
        if self.clears_features_ok {
            held & !STATUS_FEATURES_OK
        } else {
            held
        }
    }

    fn set_status(&self, value: u8) {
        self.log.record(Event::Status(value));
        self.status.set(value);
    }

    fn device_features(&self) -> u64 {
        self.offered
    }

    fn set_driver_features(&self, features: u64) {
        self.log.record(Event::DriverFeatures(features));
    }

    fn num_queues(&self) -> u16 {
        self.queues
    }

    fn setup_queue(
        &self,
        index: u16,
        _layout: &QueueLayout,
        _ring_paddr: u64,
    ) -> Result<u16, QueueSetupError> {
        if let Some((refused, error)) = self.refused_queue
            && refused == index
        {
            return Err(error);
        }
        self.log.record(Event::QueueConfigured(index));
        Ok(self.notify_base.wrapping_add(index))
    }

    fn place_doorbell(&self, notify_off: u16) -> Result<FakeDoorbell, NotifyError> {
        let index = self.queue_of(notify_off);
        if let Some((refused, error)) = self.refused_doorbell
            && refused == index
        {
            return Err(error);
        }
        self.log.record(Event::DoorbellPlaced(index));
        Ok(FakeDoorbell {
            log: self.log.clone(),
        })
    }
}
