#![no_main]
#![no_std]

//! Management protection domain: the addressed endpoint of the dedicated
//! management port. It takes every frame that port receives off the pipeline,
//! answers the ones addressed to it — ARP requests for its own address, ICMP echo
//! requests to it, and TCP connections to its one listening port — and reports
//! what the port has received.
//!
//! # Adversary
//!
//! The **management-plane attacker**, reached through a **byzantine
//! neighbour PD**. Whatever is attached to the management port is the first, and
//! this is now the domain that *answers* it: a reply is a frame the appliance
//! originates because of something that party sent. Nothing it sends arrives
//! here directly — the driver instance that owns the port publishes a
//! descriptor, so every buffer index, span and verdict word read here is that
//! domain's choice. Both are answered in `pd_runtime::endpoint` and
//! `lfw_ip_endpoint`, where host tests drive them; this file maps seven
//! regions and calls two functions.
//!
//! # The port carries no forwarded traffic, and that is a grant
//!
//! The design isolates the management port from the dataplane. This domain
//! holds no dataplane region, no device capability and no I/O port, and the
//! forwarder holds no management region — the mutual exclusion is stated in
//! `systems/qemu-x86_64/librefirewall.system` and checked in both directions by
//! `xtask::sysdesc`'s per-mapper grant set. What it does hold is both of the
//! management port's own pipelines, because answering needs a frame to leave as
//! well as arrive.
//!
//! # Why this domain returns buffers and owns the reply pool
//!
//! A terminal port has no egress driver to return a buffer, so this domain
//! produces the returns itself on the receive pipeline and is granted
//! `mgmt_rx_free` read-write; and a reply is a frame it originates, so it owns
//! the transmit pool and reclaims what the driver hands back. It is not the owner
//! of the receive pool: the driver is, and it alone decides whether a returned
//! index is one it lent.
//!
//! # It reads the configuration and acknowledges nothing
//!
//! The addressing comes from the configuration document, so this
//! domain maps `cfg` READ-ONLY and `cfgack` **not at all**. That asymmetry with
//! the forwarder is the point: the forwarder is the *consumer* of the two-phase
//! commit — it reads the offered generation, stages a table and acknowledges,
//! which is what a commit waits for — while this domain reads the **committed**
//! generation only. It cannot delay a commit, cannot refuse one on anybody's
//! behalf, and cannot forge the acknowledgement that releases one.
//! `pd_runtime::CommittedReader` is that weaker role, and it holds the whole of
//! it.
//!
//! What it costs: this domain holds no channel to the configuration domain, so
//! it learns of a commit only when the next frame wakes it.
//!
//! # Two instructions, and why they are here rather than in a crate
//!
//! Reading a counter and drawing a random number are capabilities, not logic:
//! neither can be exercised by a host test. So both live here, each in one
//! `unsafe` block naming what guarantees it, and everything done *with* the
//! numbers is in a crate.
//!
//! * **`RDTSC`**, once per wakeup. It is what makes a `Monotonic` out of the
//!   calibration this domain reads, and every transport timer is stated against
//!   one. There is no IPC for a timestamp and there is no timer interrupt: a
//!   reading costs one instruction, and asking another domain for one would cost a
//!   round trip on the path of every frame.
//! * **`RDRAND`**, once at start-up, for the secret the transport's initial
//!   sequence numbers are derived from (`entropy`). A predictable sequence number
//!   is an off-path injection primitive against the very attacker this port
//!   faces, so a part with no `RDRAND` — or one whose generator will not answer —
//!   refuses this domain rather than being answered with a weak secret.
//!
//! # It reads the clock and cannot set it
//!
//! The calibration region is mapped READ-ONLY, on the same footing as `cfg`. One
//! that could write it would be able to move this node's own idea of time —
//! every retransmission and reaping deadline, and one day every certificate's
//! validity window — from the domain that answers the
//! management-plane attacker. Every number in it is judged rather than believed
//! (`pd_runtime::calibration_from`), the clock domain having measured them
//! against a device; a triple this domain refuses leaves the port answering ARP
//! and ICMP and refusing TCP.
//!
//! # It answers `GET /metrics`, and it reads seven other domains to do it
//!
//! It maps **eight** stats shards: its own read-write, and one per other
//! protection domain READ-ONLY. That asymmetry is the whole argument — every
//! number it renders is a claim only the domain that made it could have written,
//! so a compromise of the domain that faces the management-plane attacker cannot
//! forge a clean line for a port that is dropping every frame. What stays
//! withheld is in `systems/qemu-x86_64/librefirewall.system` beside those rows.
//! Its own shard is the one region in this system with exactly one mapper, so
//! the renderer walks one uniform array rather than seven regions plus a live
//! read of its own counters.
//!
//! # Deviation from the design: the endpoint is plain HTTP
//!
//! The design requires the management API to carry encryption, authentication
//! and read/write authorization through an mTLS certificate pair. **None of it
//! exists.** There is no TLS in this appliance, this domain authenticates
//! nobody, and anything that can reach the management port can read every metric
//! this node exposes. `GET /config` and `GET /logs` are absent too and answer 404
//! rather than being stubbed. Until the required TLS termination
//! exists the port belongs on an isolated network; the status table records it.
//!
//! # What a console record says, and why not one per frame
//!
//! The console carries system state and never traffic, so nothing here
//! reports a frame. What it reports is the port's running total, on any pass
//! that moved at least one: "this port is receiving", which is a fact about the
//! node. Every count now also reaches `/metrics`, where the rest of what this
//! domain knows about itself lives.

mod entropy;

use entropy::EntropyError;
use lfw_log::{Domain, DomainDetail, DomainState, Event, Refusal, RefusalDetail, RingSink, Sink};
use lfw_metrics::StatsShard;
use pd_runtime::{
    CalibrationRefused, ClockCalibration, ConfigHandover, Downloads, EndpointRegions,
    EndpointStage, ForwardRings, IsnSecret, PdClock, Pool, ReturnRing, StatsRegions, attach_region,
    log_sample, read_timestamp_counter,
};
use sel4_microkit::{ChannelSet, Handler, Infallible, protection_domain};
use wire::{DownloadReply, DownloadRequest, LogConsume, LogRecords};

/// How many dataplane ports the build has, and so the bound a committed image's
/// interface entries are checked against — the same build fact `pds/forwarder`
/// states. The management port is not among them, which is why this is 2 and not
/// 3: a document cannot put this port in the router's set.
///
/// A literal rather than `config::PORT_COUNT`, deliberately: linking that crate
/// would put an XML parser inside the domain that faces the management-plane
/// attacker, and this domain has no document to read.
const PORTS: u8 = 2;

/// This domain's lifecycle record.
fn announce(sink: &dyn Sink, state: DomainState, detail: DomainDetail) {
    sink.emit(&Event::Domain {
        domain: Domain::Management,
        state,
        detail,
    });
}

/// Why this domain could not start.
///
/// One variant, because there is one thing it needs and cannot do without: a
/// per-boot secret for the transport's initial sequence numbers. Everything else
/// it needs is a mapping, and a wrong mapping is a fault rather than a refusal.
fn entropy_refusal(error: EntropyError) -> Refusal {
    // `signalled` is false because there is no device to be told to stop: the
    // instruction either answered or did not, and nothing was left mid-sequence.
    match error {
        EntropyError::NotSupported { feature_word } => Refusal {
            cause: "rdrand-not-supported",
            detail: RefusalDetail::One(u64::from(feature_word)),
            signalled: false,
        },
        EntropyError::Exhausted { word } => Refusal {
            cause: "rdrand-exhausted",
            detail: RefusalDetail::One(word as u64),
            signalled: false,
        },
    }
}

/// The clock domain's refusals, in the vocabulary a console line speaks.
fn clock_refusal(refusal: CalibrationRefused) -> Refusal {
    match refusal {
        CalibrationRefused::NotPublished => Refusal {
            cause: "clock-not-published",
            detail: RefusalDetail::None,
            signalled: false,
        },
        CalibrationRefused::FrequencyImplausible { tsc_hz } => Refusal {
            cause: "clock-implausible-frequency",
            detail: RefusalDetail::One(tsc_hz),
            signalled: false,
        },
    }
}

#[protection_domain]
fn init() -> Management {
    // Before anything that could have something to say. The region is zeroed by
    // the kernel, so it is a valid empty ring the moment it is mapped, and the
    // console domain drains it whenever it comes up.
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let clock: &'static ClockCalibration = attach_region!(clock_vaddr: ClockCalibration);
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(clock));
    announce(&sink, DomainState::Starting, DomainDetail::None);

    // First, because it is the one thing that can refuse: a port that came up and
    // then turned out to have no secret would have answered a `SYN` in the
    // meantime with a predictable sequence number.
    let secret = match entropy::secret_bytes() {
        Ok(bytes) => IsnSecret::from_bytes(bytes),
        Err(error) => {
            announce(
                &sink,
                DomainState::Refused,
                DomainDetail::Refusal(entropy_refusal(error)),
            );
            return Management::Refused;
        }
    };

    // In `lfw_metrics::SHARDS` order, which is the ABI: a snapshot reads slot 3
    // as `nic_driver2`'s, so a pair handed over out of order would attribute one
    // port's traffic to another.
    let stats = StatsRegions {
        shards: [
            attach_region!(stats_forwarder_vaddr: StatsShard),
            attach_region!(stats_nic_driver0_vaddr: StatsShard),
            attach_region!(stats_nic_driver1_vaddr: StatsShard),
            attach_region!(stats_nic_driver2_vaddr: StatsShard),
            attach_region!(stats_management_vaddr: StatsShard),
            attach_region!(stats_console_vaddr: StatsShard),
            attach_region!(stats_config_vaddr: StatsShard),
            attach_region!(stats_clock_vaddr: StatsShard),
            attach_region!(stats_recorder_vaddr: StatsShard),
        ],
    };
    let stage = EndpointStage::attach(
        EndpointRegions {
            receive: attach_region!(mgmt_rx_fwd_vaddr: ForwardRings),
            receive_returns: attach_region!(mgmt_rx_free_vaddr: ReturnRing),
            receive_pool: attach_region!(mgmt_rx_pool_vaddr: Pool),
            transmit: attach_region!(mgmt_tx_fwd_vaddr: ForwardRings),
            transmit_returns: attach_region!(mgmt_tx_free_vaddr: ReturnRing),
            transmit_pool: attach_region!(mgmt_tx_pool_vaddr: Pool),
        },
        secret,
        stats,
    );
    let handover: &'static ConfigHandover = attach_region!(cfg_vaddr: ConfigHandover);
    let request: &'static DownloadRequest = attach_region!(dl_request_vaddr: DownloadRequest);
    let reply: &'static DownloadReply = attach_region!(dl_reply_vaddr: DownloadReply);
    let downloads = Downloads::attach(request, reply);
    let mut stage = stage;
    // Both recordings, before the first frame: a target registered late would
    // answer `404` to a client that asked at exactly the wrong moment.
    let registered = downloads.register(&mut stage);
    // The port is unaddressed until a generation is committed and unclocked until
    // the clock domain has published, and neither is a failure: both are states a
    // node passes through between boot and its first frame.
    announce(&sink, DomainState::Ready, DomainDetail::None);
    if !registered {
        // A build fact rather than a run-time condition — the endpoint's target
        // table is one size — so it is recorded and the port carries on serving
        // everything else.
        announce(
            &sink,
            DomainState::Ready,
            DomainDetail::Refusal(Refusal {
                cause: "recording-targets-unregistered",
                detail: RefusalDetail::None,
                signalled: false,
            }),
        );
    }

    Management::Running(Running {
        stage,
        downloads,
        handover,
        clock,
        sink,
    })
}

/// A domain that started, or one that refused and holds only the channel it said
/// so on.
///
/// Two states rather than an `Option`, because the difference is what the event
/// loop does: a refused domain has no stage to drive and must not be woken into
/// pretending it has one. It still parks in the Microkit event loop, as
/// `pds/clock` does after a refusal — a domain that returned would take the
/// monitor's fault path, which is not what a *decided* refusal is.
#[expect(
    clippy::large_enum_variant,
    reason = "boxing needs an allocator; the running variant holds the two frame \
              buffers a reply is composed through, and one domain holds one value \
              of this for its whole life"
)]
enum Management {
    Running(Running),
    /// A domain that refused. It carries nothing: whatever it had to say is
    /// already in its ring, and there is no stage for a wakeup to drive.
    Refused,
}

struct Running {
    /// Kept for the domain's life, as the handles inside it are this domain's
    /// positions in four rings; a second stage would restart at slot zero.
    stage: EndpointStage<'static>,
    /// The recording downloads this port serves. Kept for the same reason: it
    /// holds this domain's position in the request channel's sequence.
    downloads: Downloads<'static>,
    handover: &'static ConfigHandover,
    clock: &'static ClockCalibration,
    sink: RingSink<'static, PdClock<'static>>,
}

impl Handler for Management {
    type Error = Infallible;

    /// A wakeup names no reason, so every question is asked of the regions: what
    /// the clock domain has published, what the configuration domain has
    /// committed, and what the driver has published. The two shared regions
    /// first, because a frame answered under the generation and the calibration
    /// that arrived with it is a frame answered correctly.
    ///
    /// A refused domain does nothing at all here. It holds no stage, and nothing
    /// in this system can wake it in any case — the driver's notification is the
    /// only capability held on this domain, and a domain that refused is one that
    /// will never answer a frame.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        let Self::Running(running) = self else {
            return Ok(());
        };
        if let Some(refusal) = running.stage.take_clock(running.clock) {
            announce(
                &running.sink,
                DomainState::Ready,
                DomainDetail::Refusal(clock_refusal(refusal)),
            );
        }
        if let Some(refused) = running.stage.take_configuration(running.handover, PORTS) {
            running.sink.emit(&Event::ConfigRejected {
                generation: refused.generation,
                reason: refused.reason,
                offset: refused.detail,
            });
        }
        // Read once per wakeup and used for the whole pass: every frame in one
        // drain is answered at one instant, which is what makes a retransmission
        // deadline a property of the pass rather than of a frame's position in it.
        //
        // The log ring's own counts travel in with it, because the shard the
        // pass publishes carries them and this domain is the only thing that can
        // read them.
        // Before the frames, so a window the recorder answered between wakeups
        // is in the transport's hands by the time this pass composes a segment.
        // It never blocks: a pass with no reply yet does nothing.
        running.downloads.poll(&mut running.stage);
        let log = log_sample(running.sink.dropped(), running.sink.refused());
        let moved = running.stage.poll(read_timestamp_counter(), log);
        // And after them, because a request parsed in this very pass is what
        // puts a stream in `pending_stream`.
        running.downloads.poll(&mut running.stage);
        if moved > 0 {
            let counters = running.stage.counters();
            announce(
                &running.sink,
                DomainState::Ready,
                DomainDetail::Received {
                    frames: counters.frames,
                    bytes: counters.bytes,
                },
            );
        }
        Ok(())
    }
}
