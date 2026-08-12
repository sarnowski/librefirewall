//! The consuming end of a pipeline that has no onward pipeline: a port whose
//! frames stop where they arrive, and which answers for itself.
//!
//! # Adversary
//!
//! Two adversaries, and they arrive by different routes. Every descriptor
//! read here was written by the driver that owns the receive pool, so its buffer
//! index, its span and its verdict word are a **byzantine neighbour protection
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

use lfw_clock::{
    Calibration, MAX_PLAUSIBLE_TSC_HZ, MIN_PLAUSIBLE_TSC_HZ, Monotonic, Ticks, UtcNanos,
};
use lfw_ip_endpoint::{
    ConnectionId, ContentType, Endpoint, IsnSecret, Status,
    http::{MAX_BODY_TARGETS, MAX_RENDERED_TARGETS, MAX_STREAM_TARGETS, METRICS_TARGET},
    onboard::{Ended as OnboardEnded, StreamCounters},
    outbound::{DialFacts, Ended, OpenError, Resolutions, Session},
    route::Hop,
};
use lfw_log::RejectReason;
use lfw_metrics::{InterfaceInventory, LogSample, RuleInventory};
use net_headers::Ipv4Address;
use wire::{CalibrationImage, ClockCalibration, ConfigHandover};

use crate::{
    BUFFER_SIZE, Committed, CommittedReader, DEVICE_HEADER_LEN, DRAIN_LIMIT, Descriptor,
    ForwardRings, Pool, PoolCounters, PoolOwner, RING_SLOTS, ReturnRing, RingConsumer,
    RingProducer, StatsRegions, Verdict, bump, descriptor_in_bounds, place, snapshot,
};

/// How many segments one pass may send out of the transport's own timers.
///
/// A bound the peer does not choose: every answer from
/// `Endpoint::poll_timeouts` either frees a connection or moves a deadline, so
/// the loop terminates on its own — this is what keeps a pass short even so, and
/// it is derived from the connection table rather than chosen, one connection
/// being able to owe at most a retransmission and a reaping in one instant.
pub const TIMER_LIMIT: usize = 2 * lfw_ip_endpoint::TCP_CONNECTIONS;

/// How many segments one pass may send out of the server above the transport.
///
/// A bound the peer does not choose, derived rather than picked: a
/// connection may have at most `lfw_tcp::MAX_UNACKED` ranges outstanding before
/// its window refuses another, so this is every connection saturated at once and
/// the loop stops long before it on any real pass.
pub const OUTPUT_LIMIT: usize = lfw_tcp_max_unacked() * lfw_ip_endpoint::TCP_CONNECTIONS;

/// How many steps one pass may spend on the outbound session.
///
/// A bound the peer does not choose, on [`OUTPUT_LIMIT`]'s terms: every answer
/// from `Endpoint::poll_outbound` either moves the session's phase, hands a
/// range to the transport, or puts a resolution request on the wire, so the loop
/// terminates on its own. One session owes at most a resolution, a dial, its
/// request in `MAX_UNACKED` ranges and a close, and this is that with room to
/// spare.
pub const DIAL_LIMIT: usize = lfw_tcp_max_unacked() + 4;

/// How many steps one pass may spend on the onboarding port.
///
/// A bound the peer does not choose, on [`OUTPUT_LIMIT`]'s terms: every answer
/// from `Endpoint::poll_onboarding` either hands a range to the transport, frees
/// the connection or moves a deadline, so the loop terminates on its own. One
/// session owes at most its answer in `MAX_UNACKED` ranges, a close, and the
/// timers of the one connection the port holds, and this is that with room to
/// spare.
pub const ONBOARD_LIMIT: usize = lfw_tcp_max_unacked() + 4;

/// `lfw_tcp::MAX_UNACKED`, reached through the endpoint that re-exports the
/// transport rather than through a second dependency on it.
const fn lfw_tcp_max_unacked() -> usize {
    lfw_ip_endpoint::MAX_UNACKED
}

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
    /// An epoch outside the band `lfw_clock::epoch_is_plausible` admits. The
    /// publishing domain refuses the same band at the register file, so this is
    /// that judgement applied at the reading end of the region rather than a
    /// second one: a peer that reached past its own check is not believed here.
    EpochImplausible { unix_nanos: u64 },
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
    if !lfw_clock::epoch_is_plausible(image.boot_unix_nanos) {
        return Err(CalibrationRefused::EpochImplausible {
            unix_nanos: image.boot_unix_nanos,
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

/// What a terminal endpoint has seen, in the shape the appliance's own
/// metrics endpoint will scrape.
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
    /// What the recording downloads served through this endpoint have done.
    /// Carried here rather than passed to `publish` so the protection domain
    /// routes one value into its shard and not two (`crate::download`).
    pub downloads: crate::download::DownloadCounters,
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
    /// The interface identities the committed generation names, which the metric
    /// surface reports and nothing else here reads. Held beside `endpoint` rather
    /// than derived from it: the endpoint is the *management* port's addressing
    /// alone, and the info series cover every port the document configured.
    interfaces: InterfaceInventory,
    /// The rule identities the committed generation declares, on `interfaces`'
    /// terms and for the same reader. Identity alone: every hit count is in the
    /// forwarding domain's shard, which this domain maps read-only, and the two
    /// are joined on a rule's position.
    rules: RuleInventory,
    /// The targets this domain answers by streaming. Held here as well as in the
    /// endpoint because a committed generation builds a **new** endpoint: a
    /// registration made at start-up would otherwise be lost the first time an
    /// operator published a document, and the target would start answering 404.
    targets: [Option<&'static str>; MAX_STREAM_TARGETS],
    /// The targets this domain answers with a body it renders whole, and the ones
    /// it accepts a request body on. Held here for `targets`' reason exactly: a
    /// commit builds a new endpoint, and a registration this domain did not keep
    /// would be lost with the old one — which for the configuration target would
    /// mean an operator's first successful submission made the next one a `404`.
    rendered: [Option<&'static str>; MAX_RENDERED_TARGETS],
    bodies: [Option<&'static str>; MAX_BODY_TARGETS],
    /// Every stats region this domain is granted: its own, written at the end of
    /// each pass, and the seven it reads to answer a scrape.
    stats: StatsRegions<'ring>,
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
    /// **Unenforced precondition:** call once per protection domain per
    /// pipeline. Each handle is this domain's own position in a ring, so a
    /// second stage over the same pipelines re-consumes descriptors the first
    /// already returned and produces a second return for each — which is
    /// refused by [`PoolOwner::reclaim`](crate::PoolOwner::reclaim)'s lent set
    /// and counted there, so the damage is a lost buffer rather than a
    /// double-owned one. No type refuses the second call; `queue`'s crate
    /// header states that single-handle rule and why nothing enforces it.
    #[must_use]
    pub fn attach(
        regions: EndpointRegions<'ring>,
        secret: IsnSecret,
        stats: StatsRegions<'ring>,
    ) -> Self {
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
            interfaces: InterfaceInventory::EMPTY,
            rules: RuleInventory::EMPTY,
            targets: [None; MAX_STREAM_TARGETS],
            rendered: [None; MAX_RENDERED_TARGETS],
            bodies: [None; MAX_BODY_TARGETS],
            stats,
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
        // The borrow of the reader's own image ends with this block, so what
        // leaves it is owned: the endpoint and the inventory the commit
        // produced, or the refusal it produced instead. Assigning them is the
        // caller's next step and needs the whole of `self`.
        let taken = {
            let Self { config, secret, .. } = self;
            match config.take(handover, ports)? {
                Committed::Image {
                    generation,
                    checked,
                } => match crate::endpoint_from(&checked, secret.clone()) {
                    Ok(endpoint) => Ok((
                        generation,
                        endpoint,
                        crate::interfaces_from(&checked),
                        crate::rules_from(&checked),
                    )),
                    // The image's own reader accepted the entry and this
                    // domain's endpoint would not, which is a disagreement
                    // between two checks rather than a malformed field: it is
                    // reported under the reason the stricter one names.
                    Err(_) => Err(ConfigRefused {
                        generation,
                        reason: RejectReason::AddressNotUnicast,
                        detail: generation,
                    }),
                },
                Committed::Refused {
                    generation,
                    reason,
                    detail,
                } => Err(ConfigRefused {
                    generation,
                    reason,
                    detail,
                }),
            }
        };
        match taken {
            Ok((generation, endpoint, interfaces, rules)) => {
                self.adopt(endpoint);
                self.apply_targets();
                // Replaced wholesale rather than merged: what the metric
                // surface reports is the generation in force, and an interface
                // or a rule the new document dropped must stop being reported
                // rather than linger as a stale series.
                self.interfaces = interfaces;
                self.rules = rules;
                self.counters.generation = generation;
                None
            }
            Err(refused) => {
                bump(&mut self.counters.configs_refused);
                Some(refused)
            }
        }
    }

    /// Take the endpoint a commit produced, **keeping the one in force where the
    /// addressing has not moved**.
    ///
    /// An [`Endpoint`] is not only an address: it holds the connection table, every
    /// connection's return path and the server's request slots. Replacing it
    /// therefore drops every connection open on the port — which is correct when
    /// the address changed, those connections having been to an address this port
    /// no longer answers at, and is a defect when it did not: a generation
    /// submitted over one of those connections would kill the connection that
    /// submitted it, and the client would wait out its timeout on a change that had
    /// in fact been committed.
    ///
    /// So the identity compared is the whole of what makes an endpoint one — its
    /// MAC, its address and its prefix — and a generation that moves none of them
    /// leaves the port exactly as it is.
    fn adopt(&mut self, offered: Option<Endpoint>) {
        let unchanged = match (self.endpoint.as_ref(), offered.as_ref()) {
            (Some(running), Some(offered)) => {
                running.mac() == offered.mac()
                    && running.address() == offered.address()
                    && running.prefix_length() == offered.prefix_length()
            }
            // A port that had no addressing and now has one, or had one and now has
            // none, has moved by definition.
            _ => false,
        };
        if !unchanged {
            self.endpoint = offered;
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
                // And the one it replaces is dropped with it. A superseded
                // calibration dates every later segment by a measurement the
                // publisher has itself withdrawn, which is the plausible-looking
                // wrong time this module refuses to produce; answering
                // `unsynchronized` instead costs a peer no denial it lacks,
                // since it could withhold the region's first publish anyway.
                self.calibration = None;
                bump(&mut self.counters.clocks_refused);
                Some(refusal)
            }
        }
    }

    /// Register `target` as one this domain answers by streaming a body it
    /// produces window by window, rather than with `404`.
    ///
    /// Called once at start-up: the registration outlives every committed
    /// generation, because a new document replaces the endpoint and this is what
    /// puts the target back on it. Answers `false` where the target is already
    /// registered, where it is the exposition's own, or where the table is full
    /// — none of which a fixed set of start-up registrations can reach, and all
    /// of which are answered rather than asserted so a caller learns of its own
    /// mistake instead of having it swallowed.
    pub fn serve_stream_at(&mut self, target: &'static str) -> bool {
        if target == METRICS_TARGET
            || self.targets.iter().flatten().any(|it| *it == target)
            || self.rendered.iter().flatten().any(|it| *it == target)
        {
            return false;
        }
        let Some(slot) = self.targets.iter_mut().find(|slot| slot.is_none()) else {
            return false;
        };
        *slot = Some(target);
        self.apply_targets();
        true
    }

    /// Register `target` as one this domain answers on `GET` with a body it renders
    /// whole, on [`serve_stream_at`](Self::serve_stream_at)'s terms.
    pub fn serve_rendered_at(&mut self, target: &'static str) -> bool {
        if target == METRICS_TARGET
            || self.rendered.iter().flatten().any(|it| *it == target)
            || self.targets.iter().flatten().any(|it| *it == target)
        {
            return false;
        }
        let Some(slot) = self.rendered.iter_mut().find(|slot| slot.is_none()) else {
            return false;
        };
        *slot = Some(target);
        self.apply_targets();
        true
    }

    /// Register `target` as one this domain accepts a request body on, on the same
    /// terms — except that a target already answered on `GET` is *not* refused:
    /// one path that states a resource and replaces it is what the configuration
    /// surface is.
    pub fn serve_body_at(&mut self, target: &'static str) -> bool {
        if self.bodies.iter().flatten().any(|it| *it == target) {
            return false;
        }
        let Some(slot) = self.bodies.iter_mut().find(|slot| slot.is_none()) else {
            return false;
        };
        *slot = Some(target);
        self.apply_targets();
        true
    }

    /// Put every registered target on the endpoint in force.
    ///
    /// Each registration takes: the endpoint's own table is [`MAX_STREAM_TARGETS`]
    /// entries and this one is bounded by the same constant, holds no duplicate
    /// and holds no [`METRICS_TARGET`], which is the whole of what that table
    /// refuses. Re-registering one it already holds is refused there and changes
    /// nothing here.
    fn apply_targets(&mut self) {
        let (targets, rendered, bodies) = (self.targets, self.rendered, self.bodies);
        let Some(endpoint) = self.endpoint.as_mut() else {
            return;
        };
        for target in targets.iter().flatten() {
            endpoint.serve_stream_at(target);
        }
        for target in rendered.iter().flatten() {
            endpoint.serve_rendered_at(target);
        }
        for target in bodies.iter().flatten() {
            endpoint.serve_body_at(target);
        }
    }

    /// The target a request is waiting on a rendered body for, or `None`.
    #[must_use]
    pub fn body_wanted(&self) -> Option<&'static str> {
        self.endpoint.as_ref()?.body_wanted()
    }

    /// The document a `POST` submitted, waiting on a decision.
    #[must_use]
    pub fn submission(&self) -> Option<&[u8]> {
        self.endpoint.as_ref()?.submission()
    }

    /// Answer the request waiting on a whole body by copying `bytes` into the
    /// endpoint's staging array.
    ///
    /// Copied rather than borrowed into the array, because the two live in
    /// different places: the bytes come out of a shared region this domain reads and
    /// the array is the endpoint's own. The copy is bounded by the array, which the
    /// server's own reservation is what sizes.
    pub fn supply_rendered(
        &mut self,
        status: Status,
        content_type: Option<ContentType>,
        bytes: &[u8],
    ) {
        let Some(endpoint) = self.endpoint.as_mut() else {
            return;
        };
        endpoint.supply_body(status, content_type, |out| {
            let mut written = 0usize;
            for (cell, byte) in out.iter_mut().zip(bytes) {
                *cell = *byte;
                written = written.saturating_add(1);
            }
            // A body that does not fit is refused rather than truncated: the server
            // counts it and answers `503`, which is the same answer a renderer that
            // could not compose one gets.
            (written == bytes.len()).then_some(written)
        });
    }

    /// The registered target a request is waiting on a decision about, and the
    /// connection that asked.
    ///
    /// Answered with [`begin_stream`](Self::begin_stream) where this domain can
    /// produce the body and [`abandon_stream`](Self::abandon_stream) where it
    /// cannot; leaving it unanswered holds the endpoint's one staging buffer and
    /// refuses every scrape made in the meantime.
    #[must_use]
    pub fn pending_stream(&self) -> Option<(ConnectionId, &'static str)> {
        self.endpoint.as_ref()?.pending_stream()
    }

    /// Answer that target with a body of `total` bytes, delivered window by
    /// window. `false` leaves the request unanswered, and this domain then owes
    /// it an [`abandon_stream`](Self::abandon_stream).
    pub fn begin_stream(&mut self, total: u64, content_type: ContentType) -> bool {
        self.endpoint
            .as_mut()
            .is_some_and(|endpoint| endpoint.begin_stream(total, content_type))
    }

    /// The body byte a window must begin at before the streamed response can go
    /// on, the most the endpoint will take there, and the connection waiting on
    /// it.
    ///
    /// It is a window **start** and not the next byte to send: it lies a
    /// retransmit span behind, because the transport owns no copy of a range it
    /// may re-ask for. The length is a bound rather than a demand — fewer bytes
    /// advance the response and the remainder is asked for again — which is what
    /// lets a supplier reading a segmented medium answer at all.
    #[must_use]
    pub fn stream_wanted(&self) -> Option<(ConnectionId, u64, usize)> {
        self.endpoint.as_ref()?.window_wanted()
    }

    /// Hand the endpoint the window beginning at body byte `start`. `false`
    /// where it is not the window that was asked for, which is counted there and
    /// leaves the response where it was.
    pub fn supply_window(&mut self, start: u64, bytes: &[u8]) -> bool {
        self.endpoint
            .as_mut()
            .is_some_and(|endpoint| endpoint.supply_window(start, bytes))
    }

    /// Give up on the streamed response: the connection closes short of the
    /// length its head announced rather than being padded to it.
    /// Take the download half's counters, so this domain's shard carries them.
    pub fn note_downloads(&mut self, counters: crate::download::DownloadCounters) {
        self.counters.downloads = counters;
    }

    pub fn abandon_stream(&mut self) {
        if let Some(endpoint) = self.endpoint.as_mut() {
            endpoint.abandon_stream();
        }
    }

    /// The instant `now` names, or `None` while no calibration has been taken.
    #[must_use]
    pub fn monotonic(&self, now: Ticks) -> Option<Monotonic> {
        self.calibration
            .as_ref()
            .map(|calibration| calibration.monotonic(now))
    }

    /// The wall-clock instant `now` names, or `None` while no calibration has
    /// been taken — which is the instant a published reading is stamped with.
    #[must_use]
    pub fn utc(&self, now: Ticks) -> Option<UtcNanos> {
        self.calibration
            .as_ref()
            .map(|calibration| calibration.utc(now))
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
    pub fn poll(&mut self, now: Ticks, log: LogSample) -> usize {
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
        // Before the body, and this is the whole reason the body is *asked for*
        // rather than rendered inside the parse: the exposition carries this
        // domain's own counters, and the request it answers has just been
        // counted. Publishing here is what makes a scrape report the scrape.
        self.publish(log);
        self.supply_body();
        if let Some(now) = now {
            self.drive_timers(now);
            self.drive_output(now);
        }
        self.publish(log);
        frames
    }

    /// Render the exposition for a request that is waiting on one.
    ///
    /// The whole metric surface, read out of the eight shards this domain is
    /// granted, into the server's own staging buffer — which is sized by the
    /// renderer's worst case, so the `None` path is unreachable and counted
    /// rather than asserted (`lfw_ip_endpoint::http`).
    fn supply_body(&mut self) {
        let stats = self.stats;
        let interfaces = self.interfaces;
        let rules = self.rules;
        let Some(endpoint) = self.endpoint.as_mut() else {
            return;
        };
        // The exposition's own target and no other: a rendered body this domain
        // does not own the source of belongs to whichever half registered it, and
        // rendering metrics into it would answer one target with another's body.
        if endpoint.body_wanted() != Some(METRICS_TARGET) {
            return;
        }
        endpoint.supply_body(Status::Ok, Some(ContentType::Metrics), |out| {
            stats
                .snapshot()
                .with_interfaces(interfaces)
                .with_rules(rules)
                .render(out)
                .ok()
        });
    }

    /// Send whatever the server above the transport now owes.
    ///
    /// A response spans many segments and a pass is woken by one frame, so
    /// without this a scrape would advance one segment per acknowledgement
    /// round trip. Bounded by [`OUTPUT_LIMIT`] as well as by the loop's own
    /// termination — every answer hands a range to the transport, and a
    /// connection blocks once `lfw_tcp::MAX_UNACKED` of them are outstanding.
    fn drive_output(&mut self, now: Monotonic) {
        for _ in 0..OUTPUT_LIMIT {
            let Self {
                endpoint, reply, ..
            } = self;
            let Some(endpoint) = endpoint.as_mut() else {
                return;
            };
            // A pass that produced no frame is not a pass with nothing left to
            // do: cleanup after a connection the transport freed produces
            // nothing, and stopping there would leave every other connection's
            // segments until the next wakeup.
            let polled = endpoint.poll_output(now, reply);
            if !polled.goes_on() {
                return;
            }
            if let Some(len) = polled.frame() {
                self.send(len);
            }
        }
    }

    /// Write this domain's own counters into the shard it owns.
    ///
    /// Once per pass rather than once per frame, which is what keeps the whole
    /// metric surface at no measurable dataplane cost: the cost of a drain of up to
    /// `DRAIN_LIMIT` descriptors is one bounded run of relaxed stores.
    ///
    /// A scrape answered *during* a pass therefore reads this domain's own
    /// series as of the end of the previous one; every other domain's is as
    /// fresh as that domain last published. A self-reporting metric cannot do
    /// better — a scrape can never include the bytes of its own answer — and
    /// the operator contract records it.
    pub fn publish(&self, log: LogSample) {
        let sample = crate::stats::management_sample(
            &self.counters,
            self.tx.counters(),
            self.endpoint.as_ref(),
            log,
        );
        self.stats.own().publish(&sample.values());
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
            // A reaping produces no frame and the timer after it belongs to a
            // different connection, so the pass goes on: `Polled::Idle` is the
            // only end of it.
            let polled = endpoint.poll_timeouts(now, reply);
            if !polled.goes_on() {
                return;
            }
            if let Some(len) = polled.frame() {
                bump(&mut self.counters.timer_segments);
                self.send(len);
            }
        }
    }

    /// Open the one connection this port reaches out with.
    ///
    /// Nothing leaves here and nothing is carried, on `Endpoint::open_outbound`'s
    /// terms: it is [`drive_dial`](Self::drive_dial) that puts a frame on the
    /// wire, and what the session carries is pushed once it is up. `None` where
    /// the port has no address yet, which is a state to wait out rather than a
    /// refusal — a session cannot be opened out of a port that has no source
    /// address to open it from.
    ///
    /// # Errors
    /// `OpenError`, for a session already running or a destination this port
    /// cannot reach.
    pub fn open_dial(
        &mut self,
        destination: Ipv4Address,
        port: u16,
    ) -> Option<Result<(), OpenError>> {
        let endpoint = self.endpoint.as_mut()?;
        Some(endpoint.open_outbound(destination, port))
    }

    /// Whether the channel's connection has come up, so the stream over it may
    /// carry bytes.
    #[must_use]
    pub fn dial_established(&self) -> bool {
        self.endpoint
            .as_ref()
            .and_then(Endpoint::outbound)
            .is_some_and(Session::established)
    }

    /// Bytes the channel's peer sent that have not been taken.
    #[must_use]
    pub fn dial_received(&self) -> &[u8] {
        self.endpoint
            .as_ref()
            .and_then(Endpoint::outbound)
            .map_or(&[], Session::received)
    }

    /// Drop the first `bytes` of them, which the consumer above has taken.
    pub fn dial_consumed(&mut self, bytes: usize) {
        if let Some(endpoint) = self.endpoint.as_mut() {
            endpoint.consume_outbound(bytes);
        }
    }

    /// Put `bytes` on the channel's connection, answering how many there was
    /// room for. Zero where the port has no addressing or no session, which is
    /// bytes with nowhere to go rather than an answer that was refused.
    pub fn dial_push(&mut self, bytes: &[u8]) -> usize {
        self.endpoint
            .as_mut()
            .map_or(0, |endpoint| endpoint.push_outbound(bytes))
    }

    /// The room the channel's session has for what is pushed onto it next. Zero
    /// where the port has no addressing or no session, on [`Self::dial_push`]'s
    /// terms: bytes with nowhere to go have no room waiting for them either.
    #[must_use]
    pub fn dial_send_room(&self) -> usize {
        self.endpoint
            .as_ref()
            .map_or(0, Endpoint::outbound_send_room)
    }

    /// End the channel's session from this end. The close goes out once
    /// everything pushed onto it has.
    pub fn end_dial_session(&mut self) {
        if let Some(endpoint) = self.endpoint.as_mut() {
            endpoint.end_outbound_session();
        }
    }

    /// End the channel's session **on `connection`**, answering whether that was
    /// still the session this stage held.
    ///
    /// The connection is named rather than implied, on
    /// [`Self::onboard_end_session`]'s terms: the terminating domain decides on
    /// one wakeup and the schedule above may have opened a different attempt by
    /// the next, and ending the wrong one would hand a peer the new session as
    /// the price of the old.
    pub fn end_dial_session_on(&mut self, connection: ConnectionId) -> bool {
        if self.dial_connection() != Some(connection) {
            return false;
        }
        self.end_dial_session();
        true
    }

    /// Send whatever the outbound session now owes.
    ///
    /// [`drive_output`](Self::drive_output)'s shape on the half that dials
    /// rather than answers, and bounded the same way: by [`DIAL_LIMIT`] as well
    /// as by the loop's own termination. A step that produces no frame is not
    /// the end of a pass — a resolution that is still outstanding produces
    /// nothing and the step after it may.
    pub fn drive_dial(&mut self, now: Monotonic) {
        for _ in 0..DIAL_LIMIT {
            let Self {
                endpoint, reply, ..
            } = self;
            let Some(endpoint) = endpoint.as_mut() else {
                return;
            };
            let polled = endpoint.poll_outbound(now, reply);
            if !polled.goes_on() {
                return;
            }
            if let Some(len) = polled.frame() {
                self.send(len);
            }
        }
    }

    /// The onboarding connection a session is running on, or `None` where the
    /// port has no addressing yet or nothing has connected.
    #[must_use]
    pub fn onboard_session(&self) -> Option<ConnectionId> {
        self.endpoint.as_ref()?.stream().connection()
    }

    /// Bytes the onboarding peer sent that have not been handed over.
    #[must_use]
    pub fn onboard_received(&self) -> &[u8] {
        self.endpoint
            .as_ref()
            .map_or(&[], |endpoint| endpoint.stream().received())
    }

    /// Drop the first `bytes` of them, which have been handed over.
    pub fn onboard_consumed(&mut self, bytes: usize) {
        if let Some(endpoint) = self.endpoint.as_mut() {
            endpoint.stream_mut().consumed(bytes);
        }
    }

    /// Whether the onboarding peer has closed its half.
    #[must_use]
    pub fn onboard_peer_closed(&self) -> bool {
        self.endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.stream().peer_closed())
    }

    /// Put `bytes` on the onboarding connection, answering how many there was
    /// room for. Zero where the port has no addressing, which is a session that
    /// cannot exist rather than an answer that was refused.
    pub fn onboard_push(&mut self, bytes: &[u8]) -> usize {
        self.endpoint
            .as_mut()
            .map_or(0, |endpoint| endpoint.stream_mut().push(bytes))
    }

    /// End the onboarding session **on `connection`**: the terminating domain has
    /// finished with it.
    ///
    /// Answers whether that session was still the one running. The connection is
    /// named rather than implied, because the terminating domain decides on one
    /// wakeup and the transport may hold a different connection by the next —
    /// `lfw_ip_endpoint::onboard::Stream::end_session` is where the identity is
    /// checked, and an unaddressed port holds no session for any name.
    pub fn onboard_end_session(&mut self, connection: ConnectionId) -> bool {
        self.endpoint
            .as_mut()
            .is_some_and(|endpoint| endpoint.stream_mut().end_session(connection))
    }

    /// How the last onboarding session ended, taken once so the domain that
    /// reports it reports each session exactly once.
    pub fn take_onboard_ending(&mut self) -> Option<OnboardEnded> {
        self.endpoint.as_mut()?.stream_mut().take_ending()
    }

    /// How the onboarding session running now would end if it ended at this
    /// instant.
    ///
    /// Read live rather than taken, and it is what a close composed while the
    /// connection is still up carries: the taken ending exists only once the
    /// transport has let the connection go, and a close goes out before that
    /// wherever the peer is the end that hung up.
    #[must_use]
    pub fn onboard_ending(&self) -> OnboardEnded {
        self.endpoint
            .as_ref()
            .map_or(OnboardEnded::Forgotten, |endpoint| {
                endpoint.stream().ending()
            })
    }

    /// What the onboarding port's own stream has done, one field per decision.
    #[must_use]
    pub fn onboard_counters(&self) -> StreamCounters {
        self.endpoint
            .as_ref()
            .map_or_else(StreamCounters::default, Endpoint::stream_counters)
    }

    /// Send whatever the onboarding port now owes.
    ///
    /// [`drive_output`](Self::drive_output)'s shape on the port that carries a
    /// byte stream, and bounded the same way: by [`ONBOARD_LIMIT`] as well as by
    /// the loop's own termination. A step that produces no frame is not the end
    /// of a pass — a reaping produces none and the step after it may.
    pub fn drive_onboarding(&mut self, now: Monotonic) {
        for _ in 0..ONBOARD_LIMIT {
            let Self {
                endpoint, reply, ..
            } = self;
            let Some(endpoint) = endpoint.as_mut() else {
                return;
            };
            let polled = endpoint.poll_onboarding(now, reply);
            if !polled.goes_on() {
                return;
            }
            if let Some(len) = polled.frame() {
                self.send(len);
            }
        }
    }

    /// How the outbound session finished, where it has. `None` while one is
    /// still running, and `None` where there is no session at all.
    #[must_use]
    pub fn dial_ended(&self) -> Option<Ended> {
        self.endpoint
            .as_ref()
            .and_then(Endpoint::outbound)
            .and_then(|session| session.phase().ended())
    }

    /// What the outbound session's own frames did, and the station they were
    /// handed to.
    ///
    /// Read **before** [`close_dial`](Self::close_dial), which drops the session
    /// and everything it observed with it: a caller that reported the token and
    /// then asked for the counts would report a channel with no evidence beside
    /// it. `None` where there is no session.
    #[must_use]
    pub fn dial_facts(&self) -> Option<(Hop, DialFacts)> {
        self.endpoint
            .as_ref()
            .and_then(Endpoint::outbound)
            .map(|session| (session.next_hop(), session.facts()))
    }

    /// The connection the channel's session is running on, or `None` where the
    /// port has no addressing, no session, a session whose handshake has not
    /// finished, or one that has ended.
    ///
    /// **Held to the handshake at one end deliberately.** What reads this is the
    /// relay above, and a relay that opened a session at the far end while the
    /// transport was still resolving or retransmitting would have the domain
    /// that holds the device key composing a client hello into a connection that
    /// may never come up — and paying for it out of a bounded arena on every
    /// attempt of a schedule that never gives up.
    ///
    /// **And to the ending at the other**, which is what lets the relay above
    /// finish: a session it can no longer carry stops being one it holds, so the
    /// relay closes the far end and closes its account, and the schedule that
    /// owns the transport session lets it go only once that has happened.
    #[must_use]
    pub fn dial_connection(&self) -> Option<ConnectionId> {
        let session = self.endpoint.as_ref().and_then(Endpoint::outbound)?;
        if !session.established() || session.phase().ended().is_some() {
            return None;
        }
        session.connection()
    }

    /// Whether the channel's peer has closed its half.
    #[must_use]
    pub fn dial_peer_closed(&self) -> bool {
        self.endpoint
            .as_ref()
            .and_then(Endpoint::outbound)
            .is_some_and(Session::peer_closed)
    }

    /// How the channel's session would end if it ended at this instant, in the
    /// vocabulary both domains report a relayed session in.
    ///
    /// The three-value vocabulary and not the transport's ten: what an operator
    /// reads about *why* a dial failed is the `dial-outcome=` record, which
    /// carries all ten. What this answers is the narrower question the relay asks
    /// — which end finished it — so a fold here loses nothing that is reported
    /// anywhere else.
    #[must_use]
    pub fn dial_stream_ending(&self) -> OnboardEnded {
        self.endpoint.as_ref().and_then(Endpoint::outbound).map_or(
            OnboardEnded::Forgotten,
            |session| {
                if session.peer_closed() {
                    OnboardEnded::ByPeer
                } else if session.consumer_closed() {
                    OnboardEnded::ByConsumer
                } else {
                    OnboardEnded::Forgotten
                }
            },
        )
    }

    /// Forget a finished session, so another may be opened. `false` where the
    /// session is still running or there is none.
    ///
    /// The caller holds it until the relay above has finished with it, which is
    /// what keeps [`Self::dial_stream_ending`] answerable for as long as anybody
    /// asks: everything the ending is read off is inside the session, and
    /// closing it drops all of it.
    pub fn close_dial(&mut self) -> bool {
        self.endpoint.as_mut().is_some_and(Endpoint::close_outbound)
    }

    /// What asking about a next hop has produced on this port: requests, what
    /// they learned, and the replies that became no entry, by reason.
    ///
    /// The port's own running totals, so a caller reporting a channel reads them
    /// when it opens and again when it reports, and states the difference. Zero
    /// where the port has no addressing yet, which is a port that has asked
    /// about nothing.
    #[must_use]
    pub fn resolutions(&self) -> Resolutions {
        self.endpoint
            .as_ref()
            .map_or_else(Resolutions::new, Endpoint::resolutions)
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
