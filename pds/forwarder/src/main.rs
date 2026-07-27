#![no_main]
#![no_std]

//! Forwarder protection domain — the routing stage between the two NIC ports.
//! Pipeline 0 carries frames received on port 0 to port 1's transmitter and
//! pipeline 1 the reverse: each frame is snapshotted out of the pool, parsed,
//! decided on, and — if it is to be forwarded — rewritten for its next hop in
//! place, so ownership and 34 bytes of header move and the payload never does.
//!
//! # Adversary
//!
//! Untrusted network traffic **and** a byzantine neighbour PD (CONCEPT §7.1).
//! Every descriptor this domain reads was written into shared memory by a NIC
//! driver domain, and every byte it now parses was put on the wire by whatever
//! is attached to a dataplane port. Both are untrusted, and both are rejected
//! by a counted drop rather than a fault; the logic that does the rejecting is
//! `net_headers`, `routing` and `pd_runtime`, on the host, where it is tested.
//!
//! # Constraints
//!
//! Two [`ForwardRings`] regions and the two [`Pool`]s they index are the entire
//! grant — no device capability, and of each pipeline not the `free` ring, on
//! which a forged return would put a live DMA target back onto an owner's free
//! stack. The pool is mapped because a routed frame's L2/L3 headers are
//! rewritten in place, so a compromised forwarder can corrupt a frame in
//! flight; it still cannot forge a return, which is the isolation the region
//! split exists for.
//!
//! Ring handles are taken once and kept for the domain's life, a handle being
//! this domain's position: one per notification would restart at slot zero and
//! re-deliver. Microkit coalesces notifications and a wakeup names no port, so
//! both pipelines drain unconditionally; the drivers poll, so nothing is
//! notified onward.
//!
//! # The configuration, and the fact nothing checks
//!
//! [`ROUTER`] is data, not logic: every decision made from it lives in
//! `crates/routing`, and a table here is what a configuration protection domain
//! will one day hand over (CONCEPT §6.3).
//!
//! Its two interface MACs must equal the MACs QEMU gives the guest NICs —
//! `mac=52:54:00:12:34:5{port}` in `tools/xtask/src/qemu.rs`'s `nic_device`.
//! Nothing in the build compares the two. If they diverge, every frame is
//! addressed to a MAC no interface claims, `Router::decide` answers
//! `DropReason::NotAddressedToUs`, and the appliance forwards nothing at all
//! while both ports stay up.

use net_headers::{Ipv4Address, MacAddress};
use pd_runtime::{ForwardRings, Pool, RouteStage, attach_region};
use routing::{Interface, Neighbour, PortId, Router};
use sel4_microkit::{ChannelSet, Handler, Infallible, debug_println, protection_domain};

const PORT0: PortId = PortId(0);
const PORT1: PortId = PortId(1);

/// The appliance's own presence on the two directly attached subnets, and the
/// hosts it can resolve on them. Static because neither ARP nor a management
/// plane exists to change it; see `crates/routing` on why that is a table.
static ROUTER: Router<2, 2> = Router::new(
    [
        Interface {
            port: PORT0,
            mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]),
            address: Ipv4Address::from_octets([10, 0, 0, 1]),
            prefix_length: 24,
        },
        Interface {
            port: PORT1,
            mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x51]),
            address: Ipv4Address::from_octets([10, 0, 1, 1]),
            prefix_length: 24,
        },
    ],
    [
        Neighbour {
            port: PORT0,
            address: Ipv4Address::from_octets([10, 0, 0, 2]),
            mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0a]),
        },
        Neighbour {
            port: PORT1,
            address: Ipv4Address::from_octets([10, 0, 1, 2]),
            mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0b]),
        },
    ],
);

#[protection_domain]
fn init() -> Forwarder {
    let fwd0: &'static ForwardRings = attach_region!(fwd0_vaddr: ForwardRings);
    let fwd1: &'static ForwardRings = attach_region!(fwd1_vaddr: ForwardRings);
    let pool0: &'static Pool = attach_region!(pool0_vaddr: Pool);
    let pool1: &'static Pool = attach_region!(pool1_vaddr: Pool);
    debug_println!("LIBREFIREWALL_FWD:start");
    Forwarder {
        stages: [
            RouteStage::attach(fwd0, pool0, &ROUTER, PORT0, PORT1),
            RouteStage::attach(fwd1, pool1, &ROUTER, PORT1, PORT0),
        ],
    }
}

struct Forwarder {
    stages: [RouteStage<'static, 2, 2>; 2],
}

impl Handler for Forwarder {
    type Error = Infallible;

    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        for stage in &mut self.stages {
            stage.poll();
        }
        Ok(())
    }
}
