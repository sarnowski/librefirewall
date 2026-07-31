use super::*;
use crate::{ConfigImage, ConfigPublisher, POOL_BUFFERS, Ring};
use lfw_metrics::{LogSample, SHARD_COUNT, StatsShard};
use net_headers::{
    ARP_FRAME_LEN, EtherType, Ethernet, IPV4_HEADER_LEN, Ipv4Address, Ipv4Packet, MacAddress,
};
use proptest::prelude::*;
use std::boxed::Box;
use std::vec;
use std::vec::Vec;
use wire::ManagementImage;

/// A frame length that fits behind the device header.
const FRAME_LEN: u32 = 64;

/// How many dataplane ports the image this fixture publishes is checked
/// against; the appliance's own count, so a fixture image is one the forwarder
/// would accept too.
const PORTS: u8 = 2;

/// The per-boot secret the transport's initial sequence numbers are derived
/// from. Fixed here so a fixture is deterministic; the protection domain obtains
/// one from `RDRAND`.
const SECRET: [u8; 16] = [
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

/// A counter reading every pass is made at. The fixture's frames are ARP and
/// ICMP, which need no time at all, so one reading is enough for every test that
/// does not set out to exercise the clock.
const NOW: Ticks = Ticks(1_000_000);

/// A plausible counter frequency, and the triple a clock domain publishes.
const TSC_HZ: u64 = 2_500_000_000;

/// The management port's own addressing, as the fixture's documents give it.
const OUR_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x52]);
const OUR_ADDRESS: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 15]);
const STATION_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0c]);
const STATION_ADDRESS: Ipv4Address = Ipv4Address::from_octets([10, 0, 2, 2]);

/// Both pipelines' regions and every role that faces the stage across them,
/// allocated the way protection domains are handed them: separate mappings that
/// share nothing, leaked so each borrows them for `'static`. Every handle is
/// taken once for the fixture's life, because a second restarts at slot zero.
struct Fixture {
    /// The driver that owns the receive pool: it lends buffers onto `rx` and
    /// consumes the returns this stage produces.
    owner: PoolOwner<'static>,
    /// The driver's `rx` producer handle.
    publish: RingProducer<'static, RING_SLOTS>,
    /// The receive pool, which the driver fills by DMA and the stage reads.
    rx_pool: &'static Pool,
    /// The transmit side of the driver: it consumes what the stage lends and
    /// produces the returns the stage reclaims.
    transmit: RingConsumer<'static, RING_SLOTS>,
    transmit_returns: RingProducer<'static, RING_SLOTS>,
    tx_pool: &'static Pool,
    /// The configuration region, written by the publishing domain.
    handover: &'static ConfigHandover,
    /// Kept so a test can forge the shared cursors a driver owns.
    receive: &'static ForwardRings,
    /// The calibration region, written by the clock domain.
    clock: &'static ClockCalibration,
    stage: EndpointStage<'static>,
}

impl EndpointStage<'_> {
    /// [`EndpointStage::poll`] with no log counts, which is every test here: a
    /// log ring belongs to the protection domain and not to the stage, so the
    /// counts it publishes are the domain's to supply.
    fn poll_stage(&mut self, now: Ticks) -> usize {
        self.poll(now, LogSample::default())
    }
}

/// Eight leaked stats shards, standing in for the regions the system description
/// grants this domain. Leaked rather than owned by the fixture because the stage
/// borrows them for its whole life, exactly as the protection domain's mappings
/// are `'static`.
fn stats_regions() -> StatsRegions<'static> {
    let shards: &'static [StatsShard; SHARD_COUNT] =
        Box::leak(Box::new([const { StatsShard::zero() }; SHARD_COUNT]));
    StatsRegions {
        shards: core::array::from_fn(|index| &shards[index]),
    }
}

impl Fixture {
    /// A stage with no addressing yet: what a node is between boot and its first
    /// commit.
    fn unaddressed() -> Self {
        let receive: &'static ForwardRings = Box::leak(Box::new(ForwardRings::new()));
        let receive_returns: &'static ReturnRing = Box::leak(Box::new(ReturnRing::new()));
        let receive_pool: &'static Pool = Box::leak(Box::new(Pool::new()));
        let transmit: &'static ForwardRings = Box::leak(Box::new(ForwardRings::new()));
        let transmit_returns: &'static ReturnRing = Box::leak(Box::new(ReturnRing::new()));
        let transmit_pool: &'static Pool = Box::leak(Box::new(Pool::new()));
        let handover: &'static ConfigHandover = Box::leak(Box::new(ConfigHandover::zero()));
        Self {
            owner: PoolOwner::attach(receive_returns),
            publish: receive.rx.producer(),
            rx_pool: receive_pool,
            transmit: transmit.tx.consumer(),
            transmit_returns: transmit_returns.free.producer(),
            tx_pool: transmit_pool,
            handover,
            receive,
            stage: EndpointStage::attach(
                EndpointRegions {
                    receive,
                    receive_returns,
                    receive_pool,
                    transmit,
                    transmit_returns,
                    transmit_pool,
                },
                IsnSecret::from_bytes(SECRET),
                stats_regions(),
            ),
            clock: Box::leak(Box::new(ClockCalibration::zero())),
        }
    }

    /// A stage addressed the way the appliance's own document addresses it.
    fn new() -> Self {
        let mut fixture = Self::unaddressed();
        fixture.commit(management_image(1, OUR_MAC, OUR_ADDRESS, 24));
        fixture
    }

    /// Publish and release one generation, as the configuration domain does once
    /// the forwarder has acknowledged it, and let the stage take it.
    fn commit(&mut self, image: ConfigImage) -> Option<ConfigRefused> {
        let mut publisher = ConfigPublisher::new();
        let generation = publisher.offer(self.handover, &image);
        self.handover.publish_committed(generation);
        self.stage.take_configuration(self.handover, PORTS)
    }

    /// Stand in for the receiving driver: take a buffer, DMA `frame` into it
    /// behind the device header, and publish the span on the `rx` ring. Answers
    /// the index published, or `None` when the pool is momentarily empty.
    fn receive(&mut self, frame: &[u8]) -> Option<u32> {
        let buffer = self.owner.alloc()?;
        let index = buffer.index();
        crate::place(self.rx_pool, index, DEVICE_HEADER_LEN, frame).expect("a frame fits");
        // Lossless: a frame the fixture builds is far below `BUFFER_SIZE`.
        let len = frame.len() as u32;
        self.owner
            .lend(
                &mut self.publish,
                buffer,
                DEVICE_HEADER_LEN,
                len,
                Verdict::Transmit,
            )
            .ok()?;
        Some(index)
    }

    /// As [`Fixture::receive`], for a frame whose bytes nothing reads: the
    /// length is all the counting tests need.
    fn receive_opaque(&mut self, len: u32) -> Option<u32> {
        let buffer = self.owner.alloc()?;
        let index = buffer.index();
        self.owner
            .lend(
                &mut self.publish,
                buffer,
                DEVICE_HEADER_LEN,
                len,
                Verdict::Transmit,
            )
            .ok()?;
        Some(index)
    }

    /// Publish a descriptor no correct driver would produce, as a byzantine one
    /// can at any moment: the ring is shared read-write.
    fn publish_raw(&mut self, descriptor: Descriptor) -> bool {
        self.publish.try_enqueue(descriptor).is_ok()
    }

    /// Forge the receive ring's cursors, which a driver that maps the region
    /// read-write can do at any moment.
    fn forge_receive_cursors(&mut self, head: u32, tail: u32) {
        forge_cursors(&self.receive.rx, head, tail);
    }

    /// Take what the stage lent on the transmit pipeline, as the driver's
    /// transmit path does: the frame bytes out of the pool, and the descriptor
    /// handed back on the free ring afterwards.
    fn transmitted(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        for (descriptor, frame) in self.drain_transmit() {
            self.transmit_returns
                .try_enqueue(descriptor)
                .expect("the return ring is sized above the pool");
            frames.push(frame);
        }
        frames
    }

    /// As [`Fixture::transmitted`], leaving every buffer outstanding: what a
    /// driver that transmits and then never returns anything does.
    fn drain_transmit(&mut self) -> Vec<(Descriptor, Vec<u8>)> {
        let mut frames = Vec::new();
        while let Some(descriptor) = self.transmit.try_dequeue() {
            assert!(descriptor_in_bounds(&descriptor));
            assert_eq!(descriptor.verdict, Verdict::Transmit.to_bits());
            assert_eq!(
                descriptor.offset, DEVICE_HEADER_LEN,
                "a reply leaves room for the device header"
            );
            let mut frame = vec![0u8; descriptor.len as usize];
            // SAFETY: the descriptor came off the stage's own transmit ring and
            // `descriptor_in_bounds` was just asserted of it; `frame` is this
            // fixture's own storage and borrows nothing of the pool.
            unsafe {
                self.tx_pool.copy_out(
                    descriptor.buffer as usize,
                    descriptor.offset as usize,
                    descriptor.len,
                    &mut frame,
                )
            }
            .expect("the span the stage published");
            frames.push((descriptor, frame));
        }
        frames
    }
}

/// A committed image addressing the management port, and nothing else: the
/// dataplane half is empty, which is what makes these tests about the management
/// entry alone.
fn management_image(
    generation: u32,
    mac: MacAddress,
    address: Ipv4Address,
    prefix_length: u8,
) -> ConfigImage {
    ConfigImage {
        generation,
        management: ManagementImage {
            enabled: 1,
            prefix_length,
            mac: mac.0,
            address: address.octets(),
            ..ManagementImage::ZERO
        },
        ..ConfigImage::ZERO
    }
}

/// An ARP request for `target`, as the station on the wire puts one there.
fn arp_request(target: Ipv4Address) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&MacAddress::BROADCAST.0);
    frame.extend_from_slice(&STATION_MAC.0);
    frame.extend_from_slice(&EtherType::ARP.0.to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&EtherType::IPV4.0.to_be_bytes());
    frame.push(6);
    frame.push(4);
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&STATION_MAC.0);
    frame.extend_from_slice(&STATION_ADDRESS.octets());
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&target.octets());
    frame
}

/// An ICMP echo request to `target` carrying `payload`.
fn echo_request(target: Ipv4Address, payload: &[u8]) -> Vec<u8> {
    let mut icmp = vec![8u8, 0, 0, 0, 0x12, 0x34, 0, 7];
    icmp.extend_from_slice(payload);
    let sum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());

    let mut frame = Vec::new();
    frame.extend_from_slice(&OUR_MAC.0);
    frame.extend_from_slice(&STATION_MAC.0);
    frame.extend_from_slice(&EtherType::IPV4.0.to_be_bytes());
    let mut ip = [0u8; IPV4_HEADER_LEN];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((IPV4_HEADER_LEN + icmp.len()) as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 1;
    ip[12..16].copy_from_slice(&STATION_ADDRESS.octets());
    ip[16..20].copy_from_slice(&target.octets());
    let sum = checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&icmp);
    frame
}

/// The RFC 1071 sum, written independently of the crates under test.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for index in 0..bytes.len().div_ceil(2) {
        let high = bytes[index * 2];
        let low = bytes.get(index * 2 + 1).copied().unwrap_or(0);
        sum += u32::from(u16::from_be_bytes([high, low]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// What an addressed stage has seen before any frame reaches it: nothing but
/// the generation its addressing came from.
fn addressed() -> EndpointStageCounters {
    EndpointStageCounters {
        generation: 1,
        ..EndpointStageCounters::default()
    }
}

#[test]
fn a_fresh_stage_has_seen_nothing_and_an_empty_pipeline_leaves_it_that_way() {
    let mut unaddressed = Fixture::unaddressed();
    assert_eq!(
        unaddressed.stage.counters(),
        EndpointStageCounters::default()
    );
    assert!(unaddressed.stage.endpoint().is_none());
    assert_eq!(unaddressed.stage.poll_stage(NOW), 0);
    assert_eq!(
        unaddressed.stage.counters(),
        EndpointStageCounters::default()
    );

    let mut fixture = Fixture::new();
    assert_eq!(fixture.stage.counters(), addressed());
    assert_eq!(fixture.stage.poll_stage(NOW), 0);
    assert_eq!(fixture.stage.counters(), addressed());
    assert_eq!(
        fixture.stage.endpoint().expect("addressed").address(),
        OUR_ADDRESS
    );
}

/// The whole cycle, which is the property a terminal port rests on: a frame the
/// driver lends is counted here and its buffer reaches that driver's own ledger
/// again, so the pool neither shrinks nor ends up double-owned.
#[test]
fn a_received_frame_is_counted_and_its_buffer_returned_to_the_owner() {
    let mut fixture = Fixture::new();
    let full = fixture.owner.owned();
    fixture
        .receive_opaque(FRAME_LEN)
        .expect("the pool starts full");
    assert_eq!(fixture.owner.owned(), full - 1, "the buffer is lent");

    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    assert_eq!(
        fixture.stage.counters(),
        EndpointStageCounters {
            frames: 1,
            bytes: u64::from(FRAME_LEN),
            ..addressed()
        }
    );

    assert_eq!(fixture.owner.reclaim(), 1);
    assert_eq!(fixture.owner.owned(), full, "the buffer is back");
    assert_eq!(fixture.owner.counters(), crate::PoolCounters::default());
}

/// The headline property of an addressed terminal port: a frame it answers
/// leaves on the *transmit* pipeline while the frame it arrived in goes back to
/// the driver that lent it, so one received frame moves one buffer each way and
/// neither pool shrinks.
#[test]
fn an_arp_request_for_this_port_is_answered_on_the_transmit_pipeline() {
    let mut fixture = Fixture::new();
    let received_full = fixture.owner.owned();
    fixture
        .receive(&arp_request(OUR_ADDRESS))
        .expect("the pool starts full");

    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    let counters = fixture.stage.counters();
    assert_eq!(counters.frames, 1);
    assert_eq!(counters.replies_sent, 1);
    assert_eq!(counters.reply_pool_exhausted, 0);
    assert_eq!(counters.reply_ring_full, 0);
    assert_eq!(counters.reply_write_failed, 0);
    assert_eq!(
        fixture
            .stage
            .endpoint()
            .expect("addressed")
            .counters()
            .arp_replies,
        1
    );

    // The frame that arrived is on its way back to the driver that lent it.
    assert_eq!(fixture.owner.reclaim(), 1);
    assert_eq!(fixture.owner.owned(), received_full);

    // And a reply is on the wire, decoded field by field rather than compared
    // against bytes this test built.
    let frames = fixture.transmitted();
    assert_eq!(frames.len(), 1);
    let reply = &frames[0];
    assert_eq!(reply.len(), ARP_FRAME_LEN);
    let ethernet = Ethernet::parse(reply).expect("a reply is a frame");
    assert_eq!(ethernet.header.destination, STATION_MAC);
    assert_eq!(ethernet.header.source, OUR_MAC);
    assert_eq!(ethernet.header.ether_type, EtherType::ARP);
}

/// The same, for the other protocol the endpoint speaks — and here the reply's
/// own IPv4 header is what proves the whole chain: the stage copied a frame out
/// of one pool, the endpoint composed an answer, and the stage copied it into a
/// second pool at the offset the driver expects.
#[test]
fn an_echo_request_for_this_port_is_answered_with_a_well_formed_datagram() {
    let mut fixture = Fixture::new();
    fixture
        .receive(&echo_request(OUR_ADDRESS, b"payload-0123456789"))
        .expect("the pool starts full");
    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    assert_eq!(fixture.stage.counters().replies_sent, 1);

    let frames = fixture.transmitted();
    assert_eq!(frames.len(), 1);
    let ethernet = Ethernet::parse(&frames[0]).expect("a reply is a frame");
    assert_eq!(ethernet.header.destination, STATION_MAC);
    assert_eq!(ethernet.header.source, OUR_MAC);
    let packet = Ipv4Packet::parse(ethernet.payload).expect("a valid datagram");
    assert_eq!(packet.header().source, OUR_ADDRESS);
    assert_eq!(packet.header().destination, STATION_ADDRESS);
    let message = packet.payload();
    assert_eq!(message[0], 0, "an echo reply is type 0");
    assert_eq!(checksum(message), 0, "its own sum validates");
    assert_eq!(&message[8..], b"payload-0123456789");
}

/// A frame the endpoint refuses moves the received counters and nothing on the
/// transmit side: no buffer is taken, and the port stays silent.
#[test]
fn a_frame_this_port_does_not_answer_leaves_the_transmit_pipeline_untouched() {
    let mut fixture = Fixture::new();
    let elsewhere = Ipv4Address::from_octets([10, 0, 2, 99]);
    for frame in [arp_request(elsewhere), echo_request(elsewhere, b"x")] {
        fixture.receive(&frame).expect("a buffer is free");
    }
    assert_eq!(fixture.stage.poll_stage(NOW), 2);

    let counters = fixture.stage.counters();
    assert_eq!(counters.frames, 2);
    assert_eq!(counters.replies_sent, 0);
    assert!(fixture.transmitted().is_empty());
    assert_eq!(
        fixture
            .stage
            .endpoint()
            .expect("addressed")
            .counters()
            .not_for_us,
        2
    );
    assert_eq!(fixture.owner.reclaim(), 2, "both buffers still come back");
}

/// Before the first commit there is no address, so nothing is answered — and
/// the frames are still counted and their buffers still returned, because an
/// unconfigured node is not a reason to strand a pool.
#[test]
fn an_unaddressed_port_counts_and_returns_without_answering() {
    let mut fixture = Fixture::unaddressed();
    let full = fixture.owner.owned();
    fixture
        .receive(&arp_request(OUR_ADDRESS))
        .expect("the pool starts full");
    assert_eq!(fixture.stage.poll_stage(NOW), 1);

    let counters = fixture.stage.counters();
    assert_eq!(counters.frames, 1);
    assert_eq!(counters.unaddressed, 1);
    assert_eq!(counters.replies_sent, 0);
    assert_eq!(counters.generation, 0);
    assert!(fixture.transmitted().is_empty());
    assert_eq!(fixture.owner.reclaim(), 1);
    assert_eq!(fixture.owner.owned(), full);

    // And once a generation is committed, the very next frame is answered.
    assert_eq!(
        fixture.commit(management_image(1, OUR_MAC, OUR_ADDRESS, 24)),
        None
    );
    assert_eq!(fixture.stage.counters().generation, 1);
    fixture
        .receive(&arp_request(OUR_ADDRESS))
        .expect("a buffer is free");
    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    assert_eq!(fixture.stage.counters().replies_sent, 1);
}

/// The port answers under the addressing it was *last* given: a second
/// generation replaces the first, and a frame for the old address stops being
/// ours.
#[test]
fn a_second_generation_moves_the_address_the_port_answers_at() {
    let mut fixture = Fixture::new();
    let moved = Ipv4Address::from_octets([10, 0, 2, 200]);
    let other_mac = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x53]);
    assert_eq!(
        fixture.commit(management_image(2, other_mac, moved, 24)),
        None
    );
    assert_eq!(fixture.stage.counters().generation, 2);

    fixture
        .receive(&arp_request(OUR_ADDRESS))
        .expect("a buffer is free");
    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    assert!(
        fixture.transmitted().is_empty(),
        "the old address is somebody else's now"
    );

    fixture.receive(&arp_request(moved)).expect("a buffer");
    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    let frames = fixture.transmitted();
    assert_eq!(frames.len(), 1);
    let ethernet = Ethernet::parse(&frames[0]).expect("a frame");
    assert_eq!(ethernet.header.source, other_mac);
}

/// A committed image this domain will not read leaves the addressing exactly as
/// it was: refusing one is not a reason to forget the one in force.
#[test]
fn a_refused_generation_leaves_the_port_answering_as_before() {
    let mut fixture = Fixture::new();
    let mut broken = management_image(2, OUR_MAC, OUR_ADDRESS, 24);
    broken.management.prefix_length = 33;
    let refused = fixture.commit(broken).expect("an unreadable image");
    assert_eq!(refused.generation, 2);
    assert_eq!(refused.reason, RejectReason::PrefixLengthOutOfRange);
    assert_eq!(fixture.stage.counters().configs_refused, 1);
    assert_eq!(
        fixture.stage.counters().generation,
        1,
        "the generation in force is the one that was read"
    );

    fixture
        .receive(&arp_request(OUR_ADDRESS))
        .expect("a buffer");
    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    assert_eq!(fixture.stage.counters().replies_sent, 1);

    // One commit, one outcome, however often it is asked for.
    assert_eq!(
        fixture.stage.take_configuration(fixture.handover, PORTS),
        None
    );
    assert_eq!(fixture.stage.counters().configs_refused, 1);
}

/// A generation that disables the management interface takes the address away,
/// which is how an operator turns the port off.
#[test]
fn a_disabled_management_interface_stops_the_port_answering() {
    let mut fixture = Fixture::new();
    let mut disabled = management_image(2, OUR_MAC, OUR_ADDRESS, 24);
    disabled.management.enabled = 0;
    assert_eq!(fixture.commit(disabled), None);
    assert!(fixture.stage.endpoint().is_none());

    fixture
        .receive(&arp_request(OUR_ADDRESS))
        .expect("a buffer");
    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    assert_eq!(fixture.stage.counters().unaddressed, 1);
    assert!(fixture.transmitted().is_empty());
}

/// The transmit pool is finite, and a driver that stops transmitting is what
/// exhausts it. Every reply after that is lost and counted, and the *received*
/// side keeps working throughout — which is what keeps a stalled reply path from
/// stranding the receive pool as well.
#[test]
fn a_transmit_pool_with_nothing_coming_back_loses_replies_and_says_so() {
    let mut fixture = Fixture::new();
    for _ in 0..POOL_BUFFERS {
        fixture
            .receive(&arp_request(OUR_ADDRESS))
            .expect("a buffer");
        assert_eq!(fixture.stage.poll_stage(NOW), 1);
        assert_eq!(fixture.owner.reclaim(), 1);
    }
    let counters = fixture.stage.counters();
    assert_eq!(counters.replies_sent, POOL_BUFFERS as u64);
    assert_eq!(counters.reply_pool_exhausted, 0);

    // Nothing has been transmitted, so every reply buffer is still in flight.
    fixture
        .receive(&arp_request(OUR_ADDRESS))
        .expect("a buffer");
    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    let counters = fixture.stage.counters();
    assert_eq!(counters.reply_pool_exhausted, 1);
    assert_eq!(counters.replies_sent, POOL_BUFFERS as u64);
    assert_eq!(
        fixture.owner.reclaim(),
        1,
        "the received buffer still comes back"
    );

    // The driver transmits, and the pool refills: the next frame is answered.
    assert_eq!(fixture.transmitted().len(), POOL_BUFFERS);
    fixture
        .receive(&arp_request(OUR_ADDRESS))
        .expect("a buffer");
    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    assert_eq!(
        fixture.stage.counters().replies_sent,
        POOL_BUFFERS as u64 + 1
    );
}

/// The pool the *replies* come out of is this domain's, so a forged return on
/// that pipeline is refused by this domain's own ledger — the mirror of the
/// receive side, where the driver is the judge.
#[test]
fn a_forged_return_on_the_reply_pipeline_is_refused_by_this_domains_ledger() {
    let mut fixture = Fixture::new();
    fixture
        .receive(&arp_request(OUR_ADDRESS))
        .expect("a buffer");
    assert_eq!(fixture.stage.poll_stage(NOW), 1);

    // The reply's own descriptor, returned twice: the first is the return the
    // driver owes, the second is the forgery. Only one buffer was lent, so the
    // ledger must accept exactly one of them.
    let lent = fixture.drain_transmit();
    assert_eq!(lent.len(), 1);
    let (descriptor, _frame) = lent[0].clone();
    for _ in 0..2 {
        fixture
            .transmit_returns
            .try_enqueue(descriptor)
            .expect("the ring is sized above the pool");
    }
    fixture.stage.poll_stage(NOW);
    assert_eq!(fixture.stage.transmit_pool_counters().reclaim_not_lent, 1);

    // And an index this domain has never lent at all, which is what a forged
    // one looks like when the ledger has nothing outstanding.
    fixture
        .transmit_returns
        .try_enqueue(Descriptor::new(
            POOL_BUFFERS as u32,
            DEVICE_HEADER_LEN,
            FRAME_LEN,
            Verdict::Transmit,
        ))
        .expect("the ring is sized above the pool");
    fixture.stage.poll_stage(NOW);
    assert_eq!(fixture.stage.transmit_pool_counters().reclaim_not_lent, 2);
}

/// The port runs indefinitely on a pool of [`POOL_BUFFERS`], which it can only
/// do if every buffer really does come back: more frames than the pool holds,
/// through one stage, with the owner reclaiming as a driver does.
#[test]
fn a_pool_sized_run_never_runs_the_owner_out_of_buffers() {
    let mut fixture = Fixture::new();
    let full = fixture.owner.owned();
    for _ in 0..POOL_BUFFERS * 4 {
        fixture
            .receive_opaque(FRAME_LEN)
            .expect("a buffer is always free");
        assert_eq!(fixture.stage.poll_stage(NOW), 1);
        assert_eq!(fixture.owner.reclaim(), 1);
    }
    assert_eq!(fixture.owner.owned(), full);
    assert_eq!(fixture.stage.counters().frames, (POOL_BUFFERS * 4) as u64);
    assert_eq!(fixture.owner.counters(), crate::PoolCounters::default());
}

/// `bytes` is a sum and not a multiple of one length, which a fixed-size probe
/// could never tell apart.
#[test]
fn the_byte_total_is_the_sum_of_the_lengths_the_driver_published() {
    let mut fixture = Fixture::new();
    let lengths = [
        1u32,
        60,
        64,
        100,
        128,
        (BUFFER_SIZE as u32) - DEVICE_HEADER_LEN,
    ];
    for len in lengths {
        fixture.receive_opaque(len).expect("the pool holds six");
    }
    assert_eq!(fixture.stage.poll_stage(NOW), lengths.len());
    let counters = fixture.stage.counters();
    assert_eq!(counters.frames, lengths.len() as u64);
    assert_eq!(
        counters.bytes,
        lengths.iter().copied().map(u64::from).sum::<u64>()
    );
    assert_eq!(counters.malformed_descriptor, 0);
}

/// A drain answers with frames rather than descriptors, so a pass that moved
/// nothing but rubbish reports nothing new — which is what keeps a caller from
/// announcing a count that did not change.
#[test]
fn a_pass_that_moved_only_malformed_descriptors_counts_no_frame_and_no_byte() {
    let mut fixture = Fixture::new();
    let malformed = malformed_descriptors();
    for descriptor in &malformed {
        assert!(fixture.publish_raw(*descriptor));
    }
    assert_eq!(fixture.stage.poll_stage(NOW), 0);
    let counters = fixture.stage.counters();
    assert_eq!(counters.frames, 0);
    assert_eq!(counters.bytes, 0, "no unbelievable span reaches the total");
    assert_eq!(counters.malformed_descriptor, malformed.len() as u64);
}

/// Every one of them is nevertheless handed back, and the owner is what judges
/// the index: a forged one is refused there and counted as the forgery it is,
/// rather than being silently believed here or silently withheld.
#[test]
fn a_malformed_descriptor_is_still_returned_and_the_owner_judges_its_index() {
    let mut fixture = Fixture::new();
    let full = fixture.owner.owned();
    assert!(fixture.publish_raw(Descriptor::new(
        POOL_BUFFERS as u32,
        0,
        1,
        Verdict::Transmit,
    )));
    assert_eq!(fixture.stage.poll_stage(NOW), 0);
    assert_eq!(fixture.stage.counters().malformed_descriptor, 1);

    assert_eq!(fixture.owner.reclaim(), 0);
    assert_eq!(fixture.owner.counters().reclaim_not_lent, 1);
    assert_eq!(fixture.owner.owned(), full);
}

/// A real, lent buffer whose *span* the peer got wrong is recovered rather than
/// stranded: the index is good, so the return is legitimate and the owner takes
/// it, while the length is not counted.
#[test]
fn a_lent_buffer_with_an_unbelievable_span_is_recovered_and_its_length_ignored() {
    let mut fixture = Fixture::new();
    let full = fixture.owner.owned();
    let lent = fixture
        .receive_opaque(FRAME_LEN)
        .expect("the pool starts full");
    // The driver's own descriptor is dropped unread, and a second one naming
    // the same lent index with a span off the end of the buffer takes its place
    // — which is exactly the edit a byzantine driver makes in the shared ring.
    let _ = fixture.stage.poll_stage(NOW);
    assert_eq!(fixture.owner.reclaim(), 1);
    assert_eq!(fixture.owner.owned(), full);

    let index = fixture.receive_opaque(FRAME_LEN).expect("a buffer is free");
    assert!(fixture.publish_raw(Descriptor::new(
        index,
        DEVICE_HEADER_LEN,
        BUFFER_SIZE as u32,
        Verdict::Transmit,
    )));
    // Two descriptors now name the one lent buffer: the driver's and the forged
    // one. The stage counts one frame and one malformed span, and produces two
    // returns — of which the owner accepts exactly one, the second naming a
    // buffer it no longer has lent.
    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    assert_eq!(fixture.stage.counters().malformed_descriptor, 1);
    assert_eq!(fixture.owner.reclaim(), 1);
    assert_eq!(fixture.owner.counters().reclaim_not_lent, 1);
    assert_eq!(fixture.owner.owned(), full);
    assert_ne!(lent, u32::MAX);
}

/// The residue this role shares with every other: a peer that stops reclaiming
/// fills the return ring, and the response is a count and a stop rather than a
/// fault or an unbounded loop.
#[test]
fn a_full_return_ring_stops_the_drain_and_is_counted() {
    let mut fixture = Fixture::unaddressed();
    let frame = |index: u32| {
        Descriptor::new(
            index % POOL_BUFFERS as u32,
            DEVICE_HEADER_LEN,
            FRAME_LEN,
            Verdict::Transmit,
        )
    };

    // Fill the ingress ring to capacity and drain it with nobody reclaiming, so
    // the return ring ends the pass exactly full — the state a driver that has
    // stopped taking its buffers back leaves it in. Both rings hold one below
    // their slot count, so this fills the second precisely.
    let mut published = 0u32;
    while fixture.publish_raw(frame(published)) {
        published += 1;
    }
    assert_eq!(fixture.stage.poll_stage(NOW), published as usize);
    assert_eq!(fixture.stage.counters().return_ring_full, 0);

    // Two more frames arrive and neither buffer has anywhere to go. The first
    // is still counted — it did arrive — and its refused return ends the pass,
    // so the second is not dequeued into a ring that cannot take it either.
    for index in 0..2 {
        assert!(
            fixture.publish_raw(frame(index)),
            "the ingress ring was just drained"
        );
    }
    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    let counters = fixture.stage.counters();
    assert_eq!(counters.return_ring_full, 1);
    assert_eq!(counters.frames, u64::from(published) + 1);
    assert_eq!(counters.malformed_descriptor, 0);

    // What stopping bought: at most one buffer is stranded per pass, so the
    // second frame is still on the ingress ring when the next one runs. It is
    // counted then and stranded in its turn, one at a time, for as long as the
    // owner stays stalled — never a whole ring's worth at once.
    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    let counters = fixture.stage.counters();
    assert_eq!(counters.return_ring_full, 2);
    assert_eq!(counters.frames, u64::from(published) + 2);
    assert_eq!(
        fixture.stage.poll_stage(NOW),
        0,
        "and now the ingress ring is empty"
    );
}

/// Descriptors a byzantine driver can publish that name no span inside a pool
/// buffer: a forged index, a span that runs off the end, and one whose offset
/// and length sum past what a `u32` holds.
fn malformed_descriptors() -> Vec<Descriptor> {
    vec![
        Descriptor::new(POOL_BUFFERS as u32, 0, 1, Verdict::Transmit),
        Descriptor::new(u32::MAX, 0, 1, Verdict::Transmit),
        Descriptor::new(0, 0, (BUFFER_SIZE as u32) + 1, Verdict::Transmit),
        Descriptor::new(0, BUFFER_SIZE as u32, 1, Verdict::Transmit),
        Descriptor::new(0, u32::MAX, u32::MAX, Verdict::Transmit),
    ]
}

/// Overwrite a ring's shared cursors the way a byzantine peer that maps the
/// region read-write can at any moment. The cursors are private to `queue`, so
/// reach them through the region's known ABI: `head` then `tail`, both `u32`, at
/// the ring's front (pinned by that crate's own layout asserts).
fn forge_cursors(ring: &Ring, head: u32, tail: u32) {
    use core::sync::atomic::{AtomicU32, Ordering};
    let base = core::ptr::from_ref(ring).cast::<AtomicU32>();
    // SAFETY: `SpscRing` is `#[repr(C)]` with `head` at offset 0 and `tail` at
    // offset 4 as `AtomicU32`s (asserted in `queue`), so both pointers are in
    // bounds and correctly aligned for the live ring borrowed here. Atomic
    // stores are exactly what a peer domain performs on these words.
    unsafe {
        (*base).store(head, Ordering::Relaxed);
        (*base.add(1)).store(tail, Ordering::Relaxed);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// A byzantine driver driving the stage: arbitrary descriptors and, between
    /// passes, arbitrary cursors. No pass may panic, each is bounded by this
    /// crate's own [`DRAIN_LIMIT`] rather than by anything the peer published,
    /// every counter is monotonic, and a counted frame may add at most one
    /// buffer's worth of bytes to the total — so a forged span cannot inflate a
    /// number an operator reads.
    #[test]
    fn every_pass_is_bounded_and_counts_only_believable_lengths(
        descriptors in prop::collection::vec(
            (any::<u32>(), any::<u32>(), any::<u32>(), any::<u32>()),
            0..200,
        ),
        forged in prop::collection::vec((any::<u32>(), any::<u32>()), 0..8),
    ) {
        // Addressed, so the frame bytes behind an arbitrary descriptor reach a
        // real endpoint and a reply can be composed as well as refused.
        let mut fixture = Fixture::new();
        let mut previous = fixture.stage.counters();
        for (buffer, offset, len, verdict) in descriptors {
            // A full ring is one of the states under test, so a refused enqueue
            // is part of the scenario rather than a failure.
            let _ring_may_be_full = fixture.publish_raw(Descriptor {
                buffer,
                offset,
                len,
                verdict,
            });
            let frames = fixture.stage.poll_stage(NOW);
            let counters = fixture.stage.counters();

            prop_assert!(frames <= DRAIN_LIMIT);
            prop_assert!(counters.frames >= previous.frames);
            prop_assert!(counters.bytes >= previous.bytes);
            prop_assert!(counters.malformed_descriptor >= previous.malformed_descriptor);
            prop_assert!(counters.return_ring_full >= previous.return_ring_full);

            let counted = counters.frames - previous.frames;
            prop_assert_eq!(counted, frames as u64);
            prop_assert!(counters.bytes - previous.bytes <= counted * BUFFER_SIZE as u64);
            previous = counters;

            // The owner's end, drained every pass so the stage meets a peer
            // that keeps up as well as one that does not, and the transmit
            // side's, so a reply never stalls for want of a reclaimed buffer.
            prop_assert!(fixture.owner.reclaim() <= DRAIN_LIMIT);
            prop_assert!(fixture.transmitted().len() <= DRAIN_LIMIT);

            // Every reply that left is a frame the endpoint composed, and every
            // frame the endpoint answered left or was counted as lost.
            let endpoint = fixture.stage.endpoint().expect("addressed").counters();
            prop_assert_eq!(
                endpoint.replies(),
                counters.replies_sent
                    + counters.reply_pool_exhausted
                    + counters.reply_ring_full
                    + counters.reply_write_failed
            );
            prop_assert_eq!(
                endpoint.total(),
                counters.frames - counters.snapshot_failed - counters.unaddressed
            );
        }

        for (head, tail) in forged {
            fixture.forge_receive_cursors(head, tail);
            prop_assert!(fixture.stage.poll_stage(NOW) <= DRAIN_LIMIT);
        }
    }
}

/// The calibration a clock domain publishes, and what this stage does with it.
///
/// The region is peer-written, so the frequency in it is judged rather than
/// believed: a triple naming no counter any x86_64 part has is refused, and the
/// refusal is a console record rather than a converted reading.
#[test]
fn a_published_calibration_is_taken_and_an_implausible_one_refused() {
    let mut fixture = Fixture::new();
    // A region nobody has published into: nothing new to report, and no
    // calibration either.
    assert_eq!(fixture.stage.take_clock(fixture.clock), None);
    assert_eq!(fixture.stage.monotonic(NOW), None);
    assert_eq!(fixture.stage.counters().clocks_refused, 0);

    fixture.clock.publish(&CalibrationImage {
        tsc_hz: TSC_HZ,
        boot_ticks: 0,
        boot_unix_nanos: 1_785_443_220_000_000_000,
    });
    assert_eq!(fixture.stage.take_clock(fixture.clock), None);
    assert_eq!(fixture.stage.counters().clock_generation, 2);
    // A reading converts: 1 000 000 ticks of a 2.5 GHz counter is 400 000 ns.
    assert_eq!(
        fixture
            .stage
            .monotonic(NOW)
            .map(lfw_clock::Monotonic::as_nanos),
        Some(400_000)
    );

    // The same generation is not re-read, which is what keeps a peer from moving
    // this node's clock under a connection's timers on every frame.
    assert_eq!(fixture.stage.take_clock(fixture.clock), None);
    assert_eq!(fixture.stage.counters().clocks_refused, 0);

    // A counter that moved to a value with no whole triple behind it — a publish
    // in progress, or one that wrapped back to zero after two billion of them.
    // Reported and not remembered, so the next pass looks again; the region this
    // stage already took stays in force.
    let unpublished = ClockCalibration::zero();
    assert_eq!(
        fixture.stage.take_clock(&unpublished),
        Some(CalibrationRefused::NotPublished)
    );
    assert_eq!(fixture.stage.counters().clocks_refused, 0);
    assert_eq!(
        fixture
            .stage
            .monotonic(NOW)
            .map(lfw_clock::Monotonic::as_nanos),
        Some(400_000)
    );

    // A republished triple no counter has is refused, once, and the calibration
    // in force is left exactly as it was.
    fixture.clock.publish(&CalibrationImage {
        tsc_hz: 1,
        boot_ticks: 0,
        boot_unix_nanos: 0,
    });
    assert_eq!(
        fixture.stage.take_clock(fixture.clock),
        Some(CalibrationRefused::FrequencyImplausible { tsc_hz: 1 })
    );
    assert_eq!(fixture.stage.counters().clocks_refused, 1);
    assert_eq!(fixture.stage.take_clock(fixture.clock), None);
    assert_eq!(fixture.stage.counters().clocks_refused, 1);
    assert_eq!(
        fixture
            .stage
            .monotonic(NOW)
            .map(lfw_clock::Monotonic::as_nanos),
        Some(400_000)
    );
}

/// Every frequency the band refuses, and the two edges it admits.
#[test]
fn the_frequency_band_is_the_clock_crates_own() {
    for tsc_hz in [0, 1, MIN_PLAUSIBLE_TSC_HZ - 1, MAX_PLAUSIBLE_TSC_HZ + 1] {
        assert_eq!(
            calibration_from(CalibrationImage {
                tsc_hz,
                boot_ticks: 0,
                boot_unix_nanos: 0
            }),
            Err(CalibrationRefused::FrequencyImplausible { tsc_hz })
        );
    }
    for tsc_hz in [MIN_PLAUSIBLE_TSC_HZ, TSC_HZ, MAX_PLAUSIBLE_TSC_HZ] {
        let calibration = calibration_from(CalibrationImage {
            tsc_hz,
            boot_ticks: 7,
            boot_unix_nanos: 9,
        })
        .expect("a plausible frequency");
        assert_eq!(calibration.tsc_hz().get(), tsc_hz);
        assert_eq!(calibration.boot_ticks(), Ticks(7));
        assert_eq!(calibration.boot_unix_nanos(), 9);
    }
}

/// A TCP segment on a port with no clock is counted and answered by nothing,
/// while ARP on the same port is answered as it always was: the transport needs
/// time and the other two protocols do not.
#[test]
fn a_segment_before_the_clock_is_counted_and_arp_still_answered() {
    let mut fixture = Fixture::new();
    let segment = tcp_syn(40000);
    fixture.receive(&segment).expect("a buffer");
    fixture
        .receive(&arp_request(OUR_ADDRESS))
        .expect("a buffer");
    assert_eq!(fixture.stage.poll_stage(NOW), 2);

    let endpoint = fixture.stage.endpoint().expect("an addressed port");
    assert_eq!(endpoint.counters().unclocked, 1);
    assert_eq!(endpoint.counters().arp_replies, 1);
    assert_eq!(endpoint.counters().tcp_segments, 0);
    // One frame left: the ARP reply.
    assert_eq!(fixture.transmitted().len(), 1);
}

/// A handshake across the pipeline, and the transport's own timer re-sending the
/// `SYN-ACK` on a later pass. That second frame is the one no received frame
/// asked for, and it is what proves the timers are driven at all.
#[test]
fn a_handshake_crosses_the_pipeline_and_its_timer_re_sends() {
    let mut fixture = Fixture::new();
    fixture.clock.publish(&CalibrationImage {
        tsc_hz: TSC_HZ,
        boot_ticks: 0,
        boot_unix_nanos: 0,
    });
    assert_eq!(fixture.stage.take_clock(fixture.clock), None);

    fixture.receive(&tcp_syn(40000)).expect("a buffer");
    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    let frames = fixture.transmitted();
    assert_eq!(frames.len(), 1, "a SYN-ACK did not leave");
    let first = tcp_flags(&frames[0]);
    assert_eq!(first & 0x12, 0x12, "the answer was not a SYN-ACK");

    let endpoint = fixture.stage.endpoint().expect("an addressed port");
    assert_eq!(endpoint.counters().tcp_segments, 1);
    assert_eq!(endpoint.tcp_counters().connections_accepted, 1);
    assert_eq!(fixture.stage.counters().timer_segments, 0);

    // A pass a whole retransmission timeout later, with no frame at all: the
    // timer is what produces the segment.
    let later = Ticks(NOW.0 + TSC_HZ * 2);
    assert_eq!(fixture.stage.poll_stage(later), 0);
    assert!(fixture.stage.counters().timer_segments >= 1);
    let frames = fixture.transmitted();
    assert!(!frames.is_empty(), "the timer sent nothing");
    assert_eq!(tcp_flags(&frames[0]) & 0x12, 0x12);
}

/// A `SYN` for the management port, framed the way a station puts one on the wire.
fn tcp_syn(port: u16) -> Vec<u8> {
    let mut out = vec![0u8; 128];
    let len = lfw_ip_endpoint::Outgoing {
        source_port: port,
        destination_port: lfw_ip_endpoint::MANAGEMENT_PORT,
        sequence: lfw_ip_endpoint::SeqNumber::new(0x1234),
        acknowledgement: lfw_ip_endpoint::SeqNumber::new(0),
        flags: lfw_ip_endpoint::Flags::SYN,
        window: 4096,
        mss: Some(1024),
        window_scale: None,
        payload: &[],
    }
    .write(
        STATION_ADDRESS,
        OUR_ADDRESS,
        out.get_mut(net_headers::Ipv4Frame::PAYLOAD_AT..)
            .expect("room"),
    )
    .expect("room for a segment");
    let total = net_headers::Ipv4Frame {
        destination_mac: OUR_MAC,
        source_mac: STATION_MAC,
        source: STATION_ADDRESS,
        destination: OUR_ADDRESS,
        protocol: net_headers::Protocol::TCP,
    }
    .write(&mut out, len)
    .expect("room for a frame");
    out.truncate(total);
    out
}

/// The control bits of the segment inside a frame the stage sent.
fn tcp_flags(frame: &[u8]) -> u8 {
    let ethernet = Ethernet::parse(frame).expect("a frame");
    let packet = Ipv4Packet::parse(ethernet.payload).expect("a datagram");
    assert_eq!(packet.header().protocol, net_headers::Protocol::TCP);
    packet.payload().get(13).copied().expect("a TCP header")
}

/// A clock and no address: the timers are driven and there is no transport to
/// drive, which is the ordinary state of a node between the clock domain's publish
/// and the configuration domain's first commit.
#[test]
fn a_clocked_but_unaddressed_port_drives_no_timers() {
    let mut fixture = Fixture::unaddressed();
    fixture.clock.publish(&CalibrationImage {
        tsc_hz: TSC_HZ,
        boot_ticks: 0,
        boot_unix_nanos: 0,
    });
    assert_eq!(fixture.stage.take_clock(fixture.clock), None);
    assert!(fixture.stage.monotonic(NOW).is_some());

    fixture.receive(&tcp_syn(40000)).expect("a buffer");
    assert_eq!(fixture.stage.poll_stage(NOW), 1);
    assert_eq!(fixture.stage.counters().unaddressed, 1);
    assert_eq!(fixture.stage.counters().timer_segments, 0);
    assert!(fixture.transmitted().is_empty());
}
