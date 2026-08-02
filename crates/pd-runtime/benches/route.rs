//! Microbenchmarks for the routed dataplane's per-packet cost.
//!
//! `RouteStage::poll` is where a frame stops being an opaque span: every packet
//! pays a full-frame snapshot out of the pool, a parse, a routing decision,
//! and — when it is forwarded — a header rewrite and a 34-byte write back. That
//! is the whole of what the 10 Gbit/s budget has to fit into per packet, and
//! none of it existed while the stage only moved descriptors.
//!
//! Three shapes are measured because they are the three costs, not three
//! variations of one: a forwarded packet pays everything; a packet the router
//! refuses pays the snapshot, the parse and the decision and stops; and a frame
//! that is not IPv4 at all stops at the parse. Reading them together is what
//! separates "parsing is expensive" from "the rewrite is expensive", and the
//! forwarded case is swept across frame sizes because the snapshot is the one
//! part that scales with the frame.
//!
//! Each measurement covers the routing pass and nothing around it. Getting a
//! frame into the pool takes a full-frame copy the dataplane never makes — the
//! receiving NIC DMAs it there — and at 1500 bytes that copy is about the size of
//! the snapshot being measured, so it is performed outside the timed region.
//! What is timed is one `poll` over a batch of already-placed frames, which is
//! also the shape the stage runs in: a wakeup drains what has arrived.
//!
//! Single-core measurements. Cross-core throughput against the 10 Gbit/s target
//! belongs to QEMU/KVM and physical hardware, not here.

use std::hint::black_box;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use net_headers::{
    ETHERNET_HEADER_LEN, EtherType, IPV4_HEADER_LEN, Ipv4Address, MacAddress, Protocol,
    UDP_HEADER_LEN,
};
use pd_runtime::{
    Configuration, Descriptor, ForwardRings, Pool, PoolOwner, RING_SLOTS, ReturnRing, RingProducer,
    RouteStage, Verdict,
};
use pipeline::Pipeline;
use routing::{Interface, Neighbour, PortId, Router};

/// Representative Ethernet payload sizes: a minimum frame, a mid-size frame,
/// and a near-MTU frame, matching `packet-buffer`'s pool benchmarks so the
/// snapshot's share of this cost is comparable against them.
const SIZES: [usize; 3] = [64, 512, 1500];

const PORT0: PortId = PortId(0);
const PORT1: PortId = PortId(1);
const GATEWAY0_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]);
const GATEWAY1_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x51]);
const HOST_A_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0a]);
const HOST_B_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0b]);
const HOST_A: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 2]);
const HOST_B: Ipv4Address = Ipv4Address::from_octets([10, 0, 1, 2]);

/// The offset a real frame sits at: behind the device's own 12-byte header.
const DEVICE_HEADER_LEN: u32 = 12;

/// The generation the table below is attributed to. Which number it is does not
/// reach any measured path — a poll must simply be given one.
const GENERATION: u32 = 1;

/// A two-port topology of the shape the appliance is configured into at run
/// time, so the table walk being measured is the one it performs.
static ROUTER: LazyLock<Router<2, 2>> = LazyLock::new(|| {
    Router::from_slices(
        &[
            Interface {
                port: PORT0,
                mac: GATEWAY0_MAC,
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
                prefix_length: 24,
                enabled: true,
            },
            Interface {
                port: PORT1,
                mac: GATEWAY1_MAC,
                address: Ipv4Address::from_octets([10, 0, 1, 1]),
                prefix_length: 24,
                enabled: true,
            },
        ],
        &[
            Neighbour {
                port: PORT0,
                address: HOST_A,
                mac: HOST_A_MAC,
            },
            Neighbour {
                port: PORT1,
                address: HOST_B,
                mac: HOST_B_MAC,
            },
        ],
    )
    .expect("two of each fit in two")
});

/// A well-formed UDP-over-IPv4 frame from host A to host B.
fn udp_frame(destination: Ipv4Address, payload_len: usize) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&GATEWAY0_MAC.0);
    frame.extend_from_slice(&HOST_A_MAC.0);
    frame.extend_from_slice(&EtherType::IPV4.0.to_be_bytes());

    let total_length = (IPV4_HEADER_LEN + UDP_HEADER_LEN + payload_len) as u16;
    let mut ip = [0u8; IPV4_HEADER_LEN];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total_length.to_be_bytes());
    ip[8] = 64;
    ip[9] = Protocol::UDP.0;
    ip[12..16].copy_from_slice(&HOST_A.octets());
    ip[16..20].copy_from_slice(&destination.octets());
    let header_checksum = checksum(&ip);
    ip[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    frame.extend_from_slice(&ip);

    frame.extend_from_slice(&4444u16.to_be_bytes());
    frame.extend_from_slice(&5000u16.to_be_bytes());
    frame.extend_from_slice(&((UDP_HEADER_LEN + payload_len) as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend(std::iter::repeat_n(0x5Au8, payload_len));
    frame
}

fn checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
    let mut sum = 0u32;
    for (index, pair) in header.chunks(2).enumerate() {
        if index != 5 {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One pipeline's three regions, boxed as three separate mappings.
struct Regions {
    pool: Box<Pool>,
    rings: Box<ForwardRings>,
    returns: Box<ReturnRing>,
}

impl Regions {
    fn new() -> Self {
        Self {
            pool: Box::new(Pool::new()),
            rings: Box::new(ForwardRings::new()),
            returns: Box::new(ReturnRing::new()),
        }
    }
}

/// Publish one frame on the `rx` ring the way the receiving driver does.
fn publish(
    pool: &Pool,
    owner: &mut PoolOwner<'_>,
    rx: &mut RingProducer<'_, RING_SLOTS>,
    frame: &[u8],
) {
    let buffer = owner.alloc().expect("the pool is drained every iteration");
    let index = buffer.index();
    // SAFETY: `buffer` came from the ledger, so this benchmark owns the index
    // until `lend` transfers it, and `frame` is a local that cannot alias the
    // pool.
    unsafe { pool.write_at(index as usize, DEVICE_HEADER_LEN as usize, frame) }
        .expect("a frame is far smaller than a buffer");
    owner
        .lend(
            rx,
            buffer,
            DEVICE_HEADER_LEN,
            frame.len() as u32,
            Verdict::Transmit,
        )
        .expect("the ring is drained every iteration");
}

/// Frames put through one timed pass.
///
/// A batch, not a single frame, for two reasons. The frames have to be placed
/// into the pool before the pass and taken back out after it — neither of which
/// a production path performs, the receiving NIC having DMA'd the frame — so the
/// timed region is opened and closed by hand around `poll` alone, and a batch
/// amortises the two clock reads that costs over 32 frames instead of paying
/// them per frame. It is also the shape the stage really runs in: a wakeup
/// drains what has arrived, rather than one frame per call.
///
/// Under the pool's 64 buffers and the ring's capacity with room to spare, so a
/// batch never runs into either limit; `DRAIN_LIMIT` is above both, so one pass
/// takes the whole batch.
const BATCH: usize = 32;

/// Measure the routing pass over [`BATCH`] published frames, asserting the
/// verdict each produced: a benchmark that accepted either would silently report
/// the cost of the cheap path under the name of the expensive one.
///
/// Only `poll` is inside the measurement. Placing the frames into the pool is a
/// full-frame copy the dataplane never makes — at 1500 bytes it is about the size
/// of the snapshot this exists to isolate, so timing it here would roughly halve
/// the reported throughput and contaminate the difference between the forwarded
/// and dropped cases, which is the number the two are read for.
fn measure(c: &mut Criterion, name: &str, frame: &[u8], expected: Verdict, bytes: Option<u64>) {
    let regions = Regions::new();
    let mut owner = PoolOwner::attach(&regions.returns);
    let mut rx_in = regions.rings.rx.producer();
    let mut stage = RouteStage::attach(&regions.rings, &regions.pool, PORT0, PORT1);
    let mut pipeline = Pipeline::new();
    let configuration = Configuration::new(GENERATION, &ROUTER);
    let mut tx_out = regions.rings.tx.consumer();
    let mut free_in = regions.returns.free.producer();

    let mut group = c.benchmark_group(name);
    match bytes {
        Some(bytes) => group.throughput(Throughput::Bytes(bytes * BATCH as u64)),
        // Per frame either way, so the two cases stay comparable: with a byte
        // rate where the frame size is being swept, and with a frame rate where
        // it is fixed and the difference between shapes is the point.
        None => group.throughput(Throughput::Elements(BATCH as u64)),
    };
    group.bench_with_input(
        BenchmarkId::from_parameter(frame.len()),
        frame,
        |b, frame| {
            b.iter_custom(|iterations| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    // Untimed: the placement, which no production path performs.
                    for _ in 0..BATCH {
                        publish(&regions.pool, &mut owner, &mut rx_in, frame);
                    }

                    let started = Instant::now();
                    let handed_on = black_box(stage.poll(&mut pipeline, configuration, None));
                    elapsed += started.elapsed();

                    assert_eq!(handed_on, BATCH, "every frame must be handed on");
                    // Untimed: draining the far side back to the owner, so every
                    // iteration starts from the same empty rings and full pool.
                    for _ in 0..BATCH {
                        let descriptor: Descriptor =
                            tx_out.try_dequeue().expect("the batch was handed on");
                        assert_eq!(Verdict::from_bits(descriptor.verdict), Some(expected));
                        free_in
                            .try_enqueue(descriptor)
                            .expect("the free ring is drained every iteration");
                    }
                    assert_eq!(owner.reclaim(), BATCH);
                }
                elapsed
            });
        },
    );
    group.finish();
}

/// The full per-packet cost: snapshot, parse, decide, rewrite, write back.
fn route_forwarded(c: &mut Criterion) {
    for size in SIZES {
        let frame = udp_frame(HOST_B, size);
        let bytes = frame.len() as u64;
        measure(c, "route_forwarded", &frame, Verdict::Transmit, Some(bytes));
    }
}

/// A well-formed packet the router refuses: everything above except the rewrite
/// and the write back, so the difference against `route_forwarded` at the same
/// size is what forwarding itself costs.
fn route_dropped_by_policy(c: &mut Criterion) {
    let frame = udp_frame(Ipv4Address::from_octets([203, 0, 113, 4]), SIZES[0]);
    measure(c, "route_dropped_by_policy", &frame, Verdict::Discard, None);
}

/// Bytes that are not an IPv4 frame: the parse rejects them and nothing else
/// runs, which is the floor the other two are measured against.
fn route_unparsable(c: &mut Criterion) {
    let frame = vec![0xAA; ETHERNET_HEADER_LEN + SIZES[0]];
    measure(c, "route_unparsable", &frame, Verdict::Discard, None);
}

criterion_group!(
    benches,
    route_forwarded,
    route_dropped_by_policy,
    route_unparsable
);
criterion_main!(benches);
