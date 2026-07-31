//! The consuming end of a pipeline that has no onward pipeline: a port whose
//! frames stop where they arrive, and which answers for itself.
//!
//! # Adversary
//!
//! Two of CONCEPT §7.1's, and they arrive by different routes. Every descriptor
//! read here was written by the driver that owns the receive pool, so its buffer
//! index, its span and its verdict word are a **byzantine peer protection
//! domain**'s choice and none of them is trusted. Every *frame byte* behind such
//! a descriptor was chosen by whatever is attached to the port — untrusted
//! network traffic, and on the management port the **management-plane
//! attacker**. What is done with those bytes is `lfw_ip_endpoint`'s business;
//! what this module owns is the ownership protocol around them.
//!
//! # Why a role of its own rather than a [`RouteStage`](crate::RouteStage)
//!
//! In the routed dataplane a frame's descriptor travels *onward*: the stage
//! hands it to the egress driver, and that driver is what puts the buffer back
//! on the ingress driver's `free` ring. The buffer is therefore returned by a
//! domain the stage never has to be granted the ring of, which is the whole
//! reason the forwarder can be denied both `free` rings.
//!
//! A terminal port has no egress driver to inherit that obligation, so the
//! descriptor's journey ends in this domain and there is exactly one way the
//! buffer can go back: this domain produces the return itself. That is the same
//! producer/consumer split the dataplane already has between its two drivers —
//! the pool's owner consumes returns (`PoolOwner::reclaim`), a domain that has
//! finished with a buffer produces one — with this domain standing where the
//! egress driver stands. It needs the `free` ring read-write and it does *not*
//! become the receive pool's owner: the owner is the driver, which alone decides
//! whether a returned index is one it lent.
//!
//! # A reply travels the other way round
//!
//! Answering needs the mirror image of all that. A reply is a frame this domain
//! *originates*, so it holds the transmit pool as its [`PoolOwner`]: it takes a
//! buffer, writes the reply into it, and lends it on the transmit pipeline for
//! the driver to put on the wire — which returns it on the transmit `free` ring
//! this domain then reclaims. The two pools are owned by different domains in
//! opposite directions, and that asymmetry is what keeps a single forged return
//! from ever reaching a ledger that would believe it.
//!
//! The receive pool is mapped **read-only** here, because a received frame is
//! only ever copied out of it: nothing this domain does alters a frame it was
//! sent. The transmit pool is mapped read-write, for the one write there is.
//!
//! # Two buffers of scratch, and why neither is a `poll` local
//!
//! A frame is snapshotted into this stage's own memory before it is parsed, for
//! [`RouteStage`](crate::RouteStage)'s reason: bytes left in the pool are free
//! to change under the decision that inspected them. The reply is composed into
//! a second buffer rather than into the pool directly, because the pool exposes
//! no safe path to its bytes at all — a written reply is *copied* in, once, in
//! one call. Both are fields because the protection domain's stack is finite and
//! this is 2 KiB apiece.
//!
//! # An unaddressed port still drains
//!
//! Until a generation is committed there is no endpoint, and a frame that
//! arrives then is counted, returned and answered by nothing. That is not a
//! failure mode to guard against but the ordinary state of a node between boot
//! and its first commit, and the alternative — holding descriptors until an
//! address arrives — would strand the pool for as long as it took.

use core::num::NonZeroU64;

use lfw_clock::{Calibration, MAX_PLAUSIBLE_TSC_HZ, MIN_PLAUSIBLE_TSC_HZ, Monotonic, Ticks};
use lfw_ip_endpoint::{Endpoint, IsnSecret};
use lfw_log::RejectReason;
use wire::{CalibrationImage, ClockCalibration, ConfigHandover};

use crate::{
    BUFFER_SIZE, Committed, CommittedReader, DEVICE_HEADER_LEN, DRAIN_LIMIT, Descriptor,
    ForwardRings, Pool, PoolCounters, PoolOwner, RING_SLOTS, ReturnRing, RingConsumer,
    RingProducer, Verdict, bump, descriptor_in_bounds, place, snapshot,
};

/// How many segments one pass may send out of the transport's own timers.
///
/// A bound the peer does not choose (ENG-4): every answer from
/// `Endpoint::poll_timeouts` either frees a connection or moves a deadline, so
/// the loop terminates on its own — this is what keeps a pass short even so, and
/// it is derived from the connection table rather than chosen, one connection
/// being able to owe at most a retransmission and a reaping in one instant.
pub const TIMER_LIMIT: usize = 2 * lfw_ip_endpoint::TCP_CONNECTIONS;

/// Why a published calibration is not one this domain will convert a counter
/// reading with.
///
/// The region is peer-written (`wire::ClockCalibration`), so a frequency in it is
/// a hostile or malfunctioning device's answer one indirection away and is judged
/// here rather than believed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalibrationRefused {
    /// The region's counter moved but no whole triple could be read out from
    /// under it: a publish in progress, or one the writer left unfinished
    /// (`wire::ClockCalibration`). Not a refusal of anything the writer said —
    /// there was nothing to refuse — and answered by looking again on the next
    /// pass rather than by remembering it.
    ///
    /// A region nobody has published into is *not* this: its counter has not
    /// moved, so there is nothing new to report and `take_clock` answers `None`.
    NotPublished,
    /// A frequency no x86_64 timestamp counter has. The band is `lfw_clock`'s, so
    /// this domain applies that crate's judgement rather than a second copy of it.
    FrequencyImplausible { tsc_hz: u64 },
}

/// Turn a published triple into a calibration, or refuse it.
///
/// # Errors
/// [`CalibrationRefused`], naming the value that refused it.
pub fn calibration_from(image: CalibrationImage) -> Result<Calibration, CalibrationRefused> {
    let Some(tsc_hz) = NonZeroU64::new(image.tsc_hz) else {
        return Err(CalibrationRefused::FrequencyImplausible { tsc_hz: 0 });
    };
    if tsc_hz.get() < MIN_PLAUSIBLE_TSC_HZ || tsc_hz.get() > MAX_PLAUSIBLE_TSC_HZ {
        return Err(CalibrationRefused::FrequencyImplausible {
            tsc_hz: tsc_hz.get(),
        });
    }
    Ok(Calibration::new(
        tsc_hz,
        Ticks(image.boot_ticks),
        image.boot_unix_nanos,
    ))
}

/// The longest reply this stage can send, and so the whole of the storage the
/// endpoint composes into: one pool buffer, less the room the device's header
/// takes in front of the frame.
///
/// Sizing the endpoint's output by it rather than by the buffer is what makes a
/// reply that would not fit a *refusal the endpoint counts* instead of a frame
/// composed here and then dropped.
pub const MAX_REPLY_LEN: usize = BUFFER_SIZE - DEVICE_HEADER_LEN as usize;

/// What a terminal endpoint has seen, in the shape the metrics endpoint
/// (CONCEPT §11) will scrape.
///
/// Monotonic for the domain's life and saturating, on
/// [`PoolCounters`](crate::PoolCounters)'s terms: there is no reset, because a
/// scrape differences successive samples and a reset would forge a negative
/// rate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EndpointStageCounters {
    /// Frames taken off the pipeline whose descriptor named a span inside one
    /// pool buffer.
    pub frames: u64,
    /// Bytes those frames carried, as the descriptors named them. It is the
    /// *ingress driver's* measurement — that domain clamped the length its
    /// device reported to the buffer behind it — and never a length this domain
    /// derived, which is why `malformed_descriptor` is counted separately
    /// rather than folded in.
    pub bytes: u64,
    /// Descriptors naming a span outside the pool. Their bytes are counted
    /// nowhere: a span this domain cannot believe is not a frame length it may
    /// add to a total an operator reads.
    pub malformed_descriptor: u64,
    /// Spans the pool refused to snapshot, leaving nothing to answer.
    pub snapshot_failed: u64,
    /// Returns the receive pool owner's ring would not take. Each loses its
    /// buffer to that owner's ledger for good, so a rising count is a shrinking
    /// pool.
    pub return_ring_full: u64,
    /// Frames that arrived before any generation was committed, so there was no
    /// address to answer at. Counted apart from every refusal the endpoint
    /// makes: an unaddressed port is a node that has not been configured yet,
    /// not a frame anybody rejected.
    pub unaddressed: u64,
    /// Replies the endpoint composed and this stage handed to the driver.
    pub replies_sent: u64,
    /// Replies composed and then lost, one counter per place they can be: a
    /// transmit pool with every buffer still in flight, and a transmit ring the
    /// driver has stopped draining. Both leave the *received* frame counted and
    /// its buffer returned; what is lost is the answer.
    pub reply_pool_exhausted: u64,
    pub reply_ring_full: u64,
    /// A reply the pool would not take the bytes of. Unreachable while
    /// [`MAX_REPLY_LEN`] and [`DEVICE_HEADER_LEN`] agree with `BUFFER_SIZE`,
    /// which the assertion at the end of this module holds them to; counted
    /// rather than asserted so a divergence surfaces as a lost reply with a
    /// number attached.
    pub reply_write_failed: u64,
    /// The generation the endpoint's addressing came from, and 0 while it has
    /// none. The counts above span the domain's life and no commit resets them,
    /// so this is what tells two scrapes apart.
    pub generation: u32,
    /// Committed images this domain would not read. It uses none of them, so a
    /// refusal changes nothing it is doing; it is counted because a publisher
    /// offering images this domain cannot read looks otherwise like one that has
    /// stopped publishing.
    pub configs_refused: u64,
    /// The calibration generation this domain is converting counter readings
    /// with, and 0 while it has none. As `generation`, it is what tells two
    /// scrapes apart.
    pub clock_generation: u32,
    /// Published calibrations this domain would not use, one per pass over a
    /// region it refuses. A rising count is a clock domain publishing numbers no
    /// counter has; a count that stays zero beside `unclocked` above zero is a
    /// clock domain that has published nothing at all, and the two are different
    /// things to go and look at.
    pub clocks_refused: u64,
    /// Segments this stage's transport composed out of its own timers — a
    /// retransmission, a reset, a close — as against a reply to a frame.
    pub timer_segments: u64,
}

/// A pipeline's consuming end where the descriptor goes no further: it counts
/// each frame, answers the ones addressed to this port, and hands the buffer
/// straight back to the receive pool's owner.
pub struct EndpointStage<'ring> {
    from: RingConsumer<'ring, RING_SLOTS>,
    free: RingProducer<'ring, RING_SLOTS>,
    rx_pool: &'ring Pool,
    to: RingProducer<'ring, RING_SLOTS>,
    tx: PoolOwner<'ring>,
    tx_pool: &'ring Pool,
    /// The addressing in force, or `None` until a generation is committed.
    endpoint: Option<Endpoint>,
    /// The per-boot secret the transport's initial sequence numbers are derived
    /// from, held because the endpoint is built later — when a generation is
    /// committed — and the secret is obtained once, at start-up, by the domain
    /// that can reach the instruction for it.
    secret: IsnSecret,
    /// What a counter reading means, or `None` until the clock domain has
    /// published a triple this stage will use.
    calibration: Option<Calibration>,
    /// The calibration generation `calibration` came from, so a republished one is
    /// picked up and an unchanged one is not re-read.
    clock_generation: u32,
    config: CommittedReader,
    received: [u8; BUFFER_SIZE],
    reply: [u8; MAX_REPLY_LEN],
    counters: EndpointStageCounters,
}

/// The four regions one terminal port's two pipelines are granted as, in the
/// direction each is used.
///
/// A struct rather than six arguments because they are three shapes twice over,
/// and being named is what makes handing the receive side where the transmit
/// side belongs a compile error rather than a port that answers into itself.
pub struct EndpointRegions<'ring> {
    /// Received frames arrive on `rx`; consumed here.
    pub receive: &'ring ForwardRings,
    /// Where the receive pool's owner takes its buffers back; produced here.
    pub receive_returns: &'ring ReturnRing,
    /// The pool the receiving NIC DMAs into, mapped read-only: a frame is copied
    /// out of it and nothing here writes one.
    pub receive_pool: &'ring Pool,
    /// Replies are queued on `tx`; produced here.
    pub transmit: &'ring ForwardRings,
    /// Where the transmitting driver hands reply buffers back; consumed here, as
    /// this domain owns that pool.
    pub transmit_returns: &'ring ReturnRing,
    pub transmit_pool: &'ring Pool,
}

impl<'ring> EndpointStage<'ring> {
    /// Take every handle a terminal port needs.
    ///
    /// **Unenforced precondition (DOC-7):** call once per protection domain per
    /// pipeline. Each handle is this domain's own position in a ring, so a
    /// second stage over the same pipelines re-consumes descriptors the first
    /// already returned and produces a second return for each — which is
    /// refused by [`PoolOwner::reclaim`](crate::PoolOwner::reclaim)'s lent set
    /// and counted there, so the damage is a lost buffer rather than a
    /// double-owned one. No type refuses the second call; `queue`'s crate
    /// header states that single-handle rule and why nothing enforces it.
    #[must_use]
    pub fn attach(regions: EndpointRegions<'ring>, secret: IsnSecret) -> Self {
        Self {
            from: regions.receive.rx.consumer(),
            free: regions.receive_returns.free.producer(),
            rx_pool: regions.receive_pool,
            to: regions.transmit.tx.producer(),
            tx: PoolOwner::attach(regions.transmit_returns),
            tx_pool: regions.transmit_pool,
            endpoint: None,
            secret,
            calibration: None,
            clock_generation: 0,
            config: CommittedReader::new(),
            received: [0; BUFFER_SIZE],
            reply: [0; MAX_REPLY_LEN],
            counters: EndpointStageCounters::default(),
        }
    }

    /// Take whatever generation the publisher has committed, and answer with the
    /// record of a refusal where there is one.
    ///
    /// Read before every drain rather than on a signal, because this domain
    /// holds no channel to the publisher: what wakes it is a frame, so the
    /// addressing is picked up on the way to answering one.
    pub fn take_configuration(
        &mut self,
        handover: &ConfigHandover,
        ports: u8,
    ) -> Option<ConfigRefused> {
        match self.config.take(handover, ports)? {
            Committed::Image {
                generation,
                checked,
            } => {
                match crate::endpoint_from(&checked, self.secret.clone()) {
                    Ok(endpoint) => {
                        self.endpoint = endpoint;
                        self.counters.generation = generation;
                        None
                    }
                    // The image's own reader accepted the entry and this
                    // domain's endpoint would not, which is a disagreement
                    // between two checks rather than a malformed field: it is
                    // reported under the reason the stricter one names.
                    Err(_) => {
                        bump(&mut self.counters.configs_refused);
                        Some(ConfigRefused {
                            generation,
                            reason: RejectReason::AddressNotUnicast,
                            detail: generation,
                        })
                    }
                }
            }
            Committed::Refused {
                generation,
                reason,
                detail,
            } => {
                bump(&mut self.counters.configs_refused);
                Some(ConfigRefused {
                    generation,
                    reason,
                    detail,
                })
            }
        }
    }

    /// Take whatever calibration the clock domain has published, and answer with
    /// the refusal where there is one.
    ///
    /// Read before every drain, for the reason the configuration is: this domain
    /// holds no channel to the clock domain either, so what wakes it is a frame
    /// and the time is picked up on the way to answering one. A generation it has
    /// already converted is not re-read — the region is peer-written, and
    /// re-deriving a calibration from it per pass would let that peer move this
    /// node's clock under a connection's timers.
    pub fn take_clock(&mut self, region: &ClockCalibration) -> Option<CalibrationRefused> {
        let generation = region.generation();
        if generation == self.clock_generation {
            return None;
        }
        let Some(image) = region.load() else {
            // The counter moved and no whole triple could be read from under it:
            // a publish in progress, one the writer left unfinished, or a counter
            // that has wrapped back to zero. None of them is a refusal of
            // anything the writer said, and none is remembered — the next pass
            // looks again.
            return Some(CalibrationRefused::NotPublished);
        };
        match calibration_from(image) {
            Ok(calibration) => {
                self.calibration = Some(calibration);
                self.clock_generation = generation;
                self.counters.clock_generation = generation;
                None
            }
            Err(refusal) => {
                // Remembered, so a clock domain publishing an implausible triple
                // is refused once rather than on every frame that arrives.
                self.clock_generation = generation;
                bump(&mut self.counters.clocks_refused);
                Some(refusal)
            }
        }
    }

    /// The instant `now` names, or `None` while no calibration has been taken.
    #[must_use]
    pub fn monotonic(&self, now: Ticks) -> Option<Monotonic> {
        self.calibration
            .as_ref()
            .map(|calibration| calibration.monotonic(now))
    }

    /// Take frames off the pipeline until it is observed empty, the return ring
    /// refuses one, or [`DRAIN_LIMIT`] descriptors have been handled. Returns
    /// how many **frames** were counted, which is the quantity a caller acts
    /// on: a pass that moved only malformed descriptors has nothing new to say
    /// about the port.
    ///
    /// Every descriptor is returned, malformed ones included. The index is
    /// peer-supplied and this domain has no ledger to judge it against, so
    /// judging it is the owner's job and not a second, weaker copy of it here;
    /// withholding a return instead would lose the buffer behind every
    /// descriptor whose *span* was wrong while its index was perfectly good.
    ///
    /// Draining stops on the first refused return for
    /// [`RouteStage::poll`](crate::RouteStage::poll)'s reason: the ring is
    /// sized above the pool, so a refusal means accounting has already broken,
    /// and every further dequeue would strand another buffer.
    ///
    /// Reply buffers are reclaimed first, so a burst is answered out of the
    /// buffers the previous pass's replies have already freed.
    pub fn poll(&mut self, now: Ticks) -> usize {
        self.tx.reclaim();
        let now = self.monotonic(now);
        let mut frames = 0;
        for _ in 0..DRAIN_LIMIT {
            let Some(descriptor) = self.from.try_dequeue() else {
                break;
            };
            if descriptor_in_bounds(&descriptor) {
                bump(&mut self.counters.frames);
                // Saturating: the rate is attacker-controlled, and a wrapped
                // total turns a sustained flood back into a small number.
                self.counters.bytes = self
                    .counters
                    .bytes
                    .saturating_add(u64::from(descriptor.len));
                frames += 1;
                self.answer(now, &descriptor);
            } else {
                bump(&mut self.counters.malformed_descriptor);
            }
            if self.free.try_enqueue(descriptor).is_err() {
                bump(&mut self.counters.return_ring_full);
                break;
            }
        }
        if let Some(now) = now {
            self.drive_timers(now);
        }
        frames
    }

    /// Send whatever the transport's own timers now owe.
    ///
    /// Bounded by [`TIMER_LIMIT`] as well as by the loop's own termination, so a
    /// pass is short whatever the table holds.
    fn drive_timers(&mut self, now: Monotonic) {
        for _ in 0..TIMER_LIMIT {
            let Self {
                endpoint, reply, ..
            } = self;
            let Some(endpoint) = endpoint.as_mut() else {
                return;
            };
            let Some(len) = endpoint.poll_timeouts(now, reply) else {
                return;
            };
            bump(&mut self.counters.timer_segments);
            self.send(len);
        }
    }

    /// The addressing in force, for a caller that reports what the port answers
    /// at. `None` until a generation is committed.
    #[must_use]
    pub const fn endpoint(&self) -> Option<&Endpoint> {
        self.endpoint.as_ref()
    }

    #[must_use]
    pub const fn counters(&self) -> EndpointStageCounters {
        self.counters
    }

    /// What the transmit pool owner has seen, which is where a forged return on
    /// the reply pipeline is refused and counted.
    #[must_use]
    pub fn transmit_pool_counters(&self) -> PoolCounters {
        self.tx.counters()
    }

    /// Snapshot the frame this descriptor names, decide on it, and send whatever
    /// the endpoint composed.
    ///
    /// The descriptor has already been bounded by
    /// [`descriptor_in_bounds`](crate::descriptor_in_bounds); every failure past
    /// that point is counted and the frame left unanswered, because a reply this
    /// domain could not send is not a reason to withhold the buffer the frame
    /// arrived in.
    fn answer(&mut self, now: Option<Monotonic>, descriptor: &Descriptor) {
        if let Some(len) = self.compose(now, descriptor) {
            self.send(len);
        }
    }

    /// Snapshot the frame and hand it to the endpoint, answering with the length
    /// of whatever it composed. Every outcome is recorded in the endpoint's own
    /// counters, so what is decided here is only whether a frame leaves.
    fn compose(&mut self, now: Option<Monotonic>, descriptor: &Descriptor) -> Option<usize> {
        let Self {
            rx_pool,
            endpoint,
            received,
            reply,
            counters,
            ..
        } = self;
        let Some(endpoint) = endpoint.as_mut() else {
            bump(&mut counters.unaddressed);
            return None;
        };
        let Ok(frame) = snapshot(rx_pool, descriptor, received) else {
            bump(&mut counters.snapshot_failed);
            return None;
        };
        endpoint.handle(now, frame, reply).reply()
    }

    /// Put `len` bytes of the composed reply into a transmit buffer and lend it
    /// to the driver.
    ///
    /// The frame is written at [`DEVICE_HEADER_LEN`], leaving the driver room to
    /// place the virtio-net header in front of it — the offset a receiving
    /// driver's own descriptors carry, and the one
    /// `nic_driver_core::TxPath::post` subtracts that header from.
    fn send(&mut self, len: usize) {
        let Some(buffer) = self.tx.alloc() else {
            bump(&mut self.counters.reply_pool_exhausted);
            return;
        };
        let Some(bytes) = self.reply.get(..len) else {
            bump(&mut self.counters.reply_write_failed);
            self.tx.release(buffer);
            return;
        };
        if place(self.tx_pool, buffer.index(), DEVICE_HEADER_LEN, bytes).is_err() {
            bump(&mut self.counters.reply_write_failed);
            self.tx.release(buffer);
            return;
        }
        // Lossless: `len` indexes `self.reply`, which is `BUFFER_SIZE` bytes.
        let len = len as u32;
        match self.tx.lend(
            &mut self.to,
            buffer,
            DEVICE_HEADER_LEN,
            len,
            Verdict::Transmit,
        ) {
            Ok(()) => bump(&mut self.counters.replies_sent),
            Err(buffer) => {
                bump(&mut self.counters.reply_ring_full);
                self.tx.release(buffer);
            }
        }
    }
}

/// A committed image this domain would not read, in the vocabulary a console
/// line speaks.
///
/// It is not an [`Offer`](crate::Offer): there is nothing to stage and nothing
/// to acknowledge, so the only thing a refusal here produces is a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigRefused {
    pub generation: u32,
    pub reason: RejectReason,
    /// The number `reason` names.
    pub detail: u32,
}

// What makes `reply_write_failed` unreachable while these two agree: a reply is
// at most `MAX_REPLY_LEN` bytes and lands at `DEVICE_HEADER_LEN`, so the span is
// exactly one buffer. It is counted rather than asserted for
// `PoolCounters::reclaim_refused`'s reason — a divergence should surface as a
// lost reply with a number attached, not as a faulted domain.
const _: () = assert!(MAX_REPLY_LEN + DEVICE_HEADER_LEN as usize == BUFFER_SIZE);

#[cfg(test)]
mod tests;
