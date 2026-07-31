#![no_main]
#![no_std]

//! Management protection domain: the addressed endpoint of the dedicated
//! management port. It takes every frame that port receives off the pipeline,
//! answers the ones addressed to it — ARP requests for its own address, ICMP
//! echo requests to it — and reports what the port has received.
//!
//! # Adversary
//!
//! CONCEPT §7.1's **management-plane attacker**, reached through a **byzantine
//! neighbour PD**. Whatever is attached to the management port is the first, and
//! this is now the domain that *answers* it: a reply is a frame the appliance
//! originates because of something that party sent. Nothing it sends arrives
//! here directly — the driver instance that owns the port publishes a
//! descriptor, so every buffer index, span and verdict word read here is that
//! domain's choice. Both are answered in `pd_runtime::endpoint` and
//! `lfw_ip_endpoint`, where host tests drive them (LAY-2); this file maps seven
//! regions and calls two functions.
//!
//! # The port carries no forwarded traffic, and that is a grant
//!
//! CONCEPT §9.1 isolates the management port from the dataplane. This domain
//! holds no dataplane region, no device capability and no I/O port, and the
//! forwarder holds no management region — the mutual exclusion is stated in
//! `systems/qemu-x86_64/librefirewall.system` and checked in both directions by
//! `xtask::sysdesc`'s per-mapper grant set. What it does hold is both of the
//! management port's own pipelines, because answering needs a frame to leave as
//! well as arrive.
//!
//! # Why this domain returns buffers and owns the reply pool
//!
//! In the routed dataplane a descriptor travels onward and the *egress* driver
//! returns the buffer, which is what lets the forwarder be denied both `free`
//! rings. A terminal port has no egress driver, so this domain produces the
//! returns itself on the receive pipeline and is granted `mgmt_rx_free`
//! read-write; and a reply is a frame it originates, so it is the *owner* of the
//! transmit pool and reclaims what the driver hands back. It is not the owner of
//! the receive pool: the driver is, and it alone decides whether a returned index
//! is one it lent. The argument is `pd_runtime::endpoint`'s and the grant is the
//! system description's.
//!
//! # It reads the configuration and acknowledges nothing
//!
//! The addressing comes from the configuration document (CONCEPT §12.3), so this
//! domain maps `cfg` READ-ONLY and `cfgack` **not at all**. That asymmetry with
//! the forwarder is the point: the forwarder is the *consumer* of the two-phase
//! commit — it reads the offered generation, stages a table and acknowledges,
//! which is what a commit waits for — while this domain reads the **committed**
//! generation only. It cannot delay a commit, cannot refuse one on anybody's
//! behalf, and cannot forge the acknowledgement that releases one.
//! `pd_runtime::CommittedReader` is that weaker role, and it holds the whole of
//! it.
//!
//! What it costs, stated because nothing here would otherwise reveal it: this
//! domain holds no channel to the configuration domain, so it learns of a commit
//! only when something else wakes it — the next frame to arrive. A port that is
//! never spoken to never picks up its address, and nothing needs it to.
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
use pd_runtime::{
    ConfigHandover, EndpointRegions, EndpointStage, ForwardRings, Pool, ReturnRing, attach_region,
};
use sel4_microkit::{ChannelSet, Handler, Infallible, protection_domain};
use wire::{LogConsume, LogRecords};

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

#[protection_domain]
fn init() -> Management {
    // Before anything that could have something to say. The region is zeroed by
    // the kernel, so it is a valid empty ring the moment it is mapped, and the
    // console domain drains it whenever it comes up.
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let sink = RingSink::new(log.writer(log_consume));
    announce(&sink, DomainState::Starting, DomainDetail::None);

    let stage = EndpointStage::attach(EndpointRegions {
        receive: attach_region!(mgmt_rx_fwd_vaddr: ForwardRings),
        receive_returns: attach_region!(mgmt_rx_free_vaddr: ReturnRing),
        receive_pool: attach_region!(mgmt_rx_pool_vaddr: Pool),
        transmit: attach_region!(mgmt_tx_fwd_vaddr: ForwardRings),
        transmit_returns: attach_region!(mgmt_tx_free_vaddr: ReturnRing),
        transmit_pool: attach_region!(mgmt_tx_pool_vaddr: Pool),
    });
    let handover: &'static ConfigHandover = attach_region!(cfg_vaddr: ConfigHandover);
    // Nothing here can refuse: there is no device to answer and no build datum
    // to judge, so this domain reaches its event loop or faults, and there is no
    // third outcome for a `refused` record to name. The port is unaddressed
    // until a generation is committed, which is a state rather than a failure.
    announce(&sink, DomainState::Ready, DomainDetail::None);

    Management {
        stage,
        handover,
        sink,
    }
}

struct Management {
    /// Kept for the domain's life, as the handles inside it are this domain's
    /// positions in four rings; a second stage would restart at slot zero.
    stage: EndpointStage<'static>,
    handover: &'static ConfigHandover,
    sink: RingSink<'static>,
}

impl Handler for Management {
    type Error = Infallible;

    /// A wakeup names no reason, so both questions are asked of the regions:
    /// what the configuration domain has committed, and what the driver has
    /// published. The configuration first, because a frame answered under the
    /// generation that arrived with it is a frame answered correctly.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        if let Some(refused) = self.stage.take_configuration(self.handover, PORTS) {
            self.sink.emit(&Event::ConfigRejected {
                generation: refused.generation,
                reason: refused.reason,
                offset: refused.detail,
            });
        }
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
