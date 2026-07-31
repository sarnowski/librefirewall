#![no_main]
#![no_std]

//! Management protection domain: the endpoint of the dedicated management port.
//! It takes every frame that port receives off the pipeline, counts it, and
//! reports the running total.
//!
//! # Adversary
//!
//! CONCEPT §7.1's **management-plane attacker**, reached through a **byzantine
//! neighbour PD**. Whatever is attached to the management port is the first, and
//! nothing it sends arrives here directly: the driver instance that owns that
//! port publishes a descriptor, so every buffer index, span and verdict word
//! read here is that domain's choice. Both are answered in
//! `pd_runtime::TerminalStage`, where a host test drives them (LAY-2); this file
//! maps four regions and calls one function.
//!
//! # The port carries no forwarded traffic, and that is a grant
//!
//! CONCEPT §9.1 isolates the management port from the dataplane. This domain
//! holds no dataplane region, no buffer pool, no configuration region, no device
//! capability and no I/O port, and the forwarder holds no management region —
//! the mutual exclusion is stated in
//! `systems/qemu-x86_64/librefirewall.system` and checked in both directions by
//! `xtask::sysdesc`'s per-mapper grant set.
//!
//! # Why this domain returns buffers and the forwarder does not
//!
//! In the routed dataplane a descriptor travels onward and the *egress* driver
//! returns the buffer, which is what lets the forwarder be denied both `free`
//! rings. A terminal port has no egress driver, so this domain produces the
//! returns itself and is granted `mgmt_rx_free` read-write. It is not the pool's
//! owner: the driver is, and it alone decides whether a returned index is one it
//! lent. The argument is `pd_runtime::terminal`'s and the grant is the system
//! description's.
//!
//! # No pool, so no frame is ever read
//!
//! Frames and bytes come off the descriptors, so this domain maps no pool and
//! dereferences no frame byte — the mirror of the receiving driver, which takes
//! its pool's physical address with no mapping. The RX pool is therefore mapped by
//! no protection domain at all, a cross-artifact fact `xtask::sysdesc`'s
//! `mgmt_rx_pool` rule holds by granting the region to nobody. Reading a frame is
//! what ARP and IP will need, and the grant arrives with the first of them.
//!
//! # What a record says, and why not one per frame
//!
//! The console carries system state and never traffic (OBS-1), so nothing here
//! reports a frame. What it reports is the port's running total, on any pass
//! that moved at least one frame: a cumulative pair an operator reads as "this
//! port is receiving", which is a fact about the node. The counts move to the
//! metrics endpoint (CONCEPT §11) when one exists, and MONITORING.md records
//! that this record is where they live until then.

use lfw_log::{Domain, DomainDetail, DomainState, Event, RingSink, Sink};
use pd_runtime::{ForwardRings, ReturnRing, TerminalStage, attach_region};
use sel4_microkit::{ChannelSet, Handler, Infallible, protection_domain};
use wire::{LogConsume, LogRecords};

/// This domain's lifecycle record.
fn announce(sink: &dyn Sink, state: DomainState, detail: DomainDetail) {
    sink.emit(&Event::Domain {
        domain: Domain::Management,
        state,
        detail,
    });
}

#[protection_domain]
fn init() -> Management {
    // Before anything that could have something to say. The region is zeroed by
    // the kernel, so it is a valid empty ring the moment it is mapped, and the
    // console domain drains it whenever it comes up.
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let sink = RingSink::new(log.writer(log_consume));
    announce(&sink, DomainState::Starting, DomainDetail::None);

    let rings: &'static ForwardRings = attach_region!(mgmt_rx_fwd_vaddr: ForwardRings);
    let returns: &'static ReturnRing = attach_region!(mgmt_rx_free_vaddr: ReturnRing);
    let stage = TerminalStage::attach(rings, returns);
    // Nothing here can refuse: there is no device to answer and no build datum
    // to judge, so this domain reaches its event loop or faults, and there is no
    // third outcome for a `refused` record to name.
    announce(&sink, DomainState::Ready, DomainDetail::None);

    Management { stage, sink }
}

struct Management {
    /// Kept for the domain's life, as the handles inside it are this domain's
    /// positions in two rings; a second stage would restart at slot zero.
    stage: TerminalStage<'static>,
    sink: RingSink<'static>,
}

impl Handler for Management {
    type Error = Infallible;

    /// A wakeup names no reason, so the question is asked of the region: drain
    /// what the driver published, and say what the port has now received if any
    /// of it was a frame.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        if self.stage.poll() > 0 {
            let counters = self.stage.counters();
            announce(
                &self.sink,
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
