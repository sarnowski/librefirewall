#![no_main]
#![no_std]

//! virtio-net driver protection domain: it drives one dataplane port (QEMU
//! q35, virtio 1.0 PCI), one instance per port.
//!
//! # Adversary
//!
//! A hostile or malfunctioning NIC device (CONCEPT §7.1). This domain maps the
//! device's configuration space, the MMIO window its BAR is relocated to, and
//! the DMA regions it writes, so everything the device produces is untrusted
//! input. DMA is unconfined — no IOMMU on this platform (CONCEPT §7.2) — so an
//! address handed to the device is an address it may write.
//!
//! # What is decided elsewhere, and the one thing that is not
//!
//! Which devices are acceptable, what order the handshake runs in, and what a
//! poll pass does all live in `nic_driver_core`, where a host test can drive
//! them against a stand-in device (LAY-2). [`PoolDmaBase`] deviates from that
//! and is recorded here as the deviation it is: the value it guards enters
//! `nic_driver_core` through
//! [`DataplanePort::attach`](nic_driver_core::port::DataplanePort::attach) as a
//! plain `u64`, so no type can refuse an unchecked address there — only this
//! call site can, and a check in this file cannot be host-tested. Moving the
//! newtype into `pd_runtime`, beside the [`MAPPING_ALIGN`] and
//! [`POOL_REGION_SIZE`] it checks against, closes the gap.
//!
//! # Everything this domain touches is patched in at build time
//!
//! Hardware topology is static (CONCEPT §12.3), so this driver performs no PCI
//! enumeration: it never scans a bus and holds capabilities for exactly one
//! function's ECAM page, and two instances of one binary drive two devices with
//! no code difference. Each port joins two pipelines of three regions each —
//! pool, forwarder rings, return ring — and maps five of the six. The sixth,
//! **the pool this port receives into**, is an address and nothing more: it
//! goes to the NIC as a DMA target and no byte of it is dereferenced here, so a
//! mapping would be authority with no use. Microkit patches a `setvar
//! region_paddr` whether or not the same domain maps the region, which is what
//! makes that grant expressible. Each instance is patched from
//! `systems/qemu-x86_64/librefirewall.system`:
//!
//! | symbol | what it names |
//! |---|---|
//! | `ecam_vaddr` | the 4 KiB ECAM page of this instance's pinned PCI function |
//! | `bar_vaddr` | the `BAR_WINDOW_SIZE` MMIO window the device's BAR is relocated to |
//! | `vq_vaddr` | the zeroed `VQ_REGION_SIZE` virtqueue DMA region |
//! | `rx_fwd_vaddr` / `tx_fwd_vaddr` | the `ForwardRings` region of each pipeline |
//! | `rx_free_vaddr` / `tx_free_vaddr` | the `ReturnRing` region of each |
//! | `tx_pool_vaddr` | the pool this port transmits out of — the only pool it maps |
//! | `bar_paddr`, `vq_paddr` | the physical addresses of those two device regions |
//! | `rx_pool_paddr`, `tx_pool_paddr` | the physical bases of both pools, for the device |
//!
//! # Scheduling: two drivers busy-loop at equal priority
//!
//! Microkit has no periodic wakeup and this driver takes no interrupt (no
//! MSI-X, no INTx) by design, so it polls by never returning from `init`. The
//! system description fixes what follows, and it is not visible from this file:
//! the two driver instances share **priority 1** and both loop forever, so
//! their mutual progress rests entirely on seL4's round-robin scheduling of
//! equal-priority threads. On the single-core bring-up this is why a driver
//! must never spin on a device-controlled condition — a device that withholds
//! an answer would deny the timeslice to the other port, not merely to itself.
//! The forwarder runs at **priority 2** and preempts on notification, so the
//! busy loop cannot starve it.
//!
//! # Channel 0 sends and never receives
//!
//! [`NicDriver`]'s `notified` entrypoint is unreachable by *capability* rather
//! than by control flow — a property of the system, not of this file. Microkit's
//! optional `notify` attribute on a `<channel>`'s `<end>` "indicates that the
//! protection domain for this end can send a notification to the other end;
//! defaults to **true**" (Microkit 2.3.0 user manual §7.6). The forwarder's end
//! of each of the two driver channels is marked `notify="false"` in the system
//! description, so each driver keeps its send capability on the forwarder while
//! the forwarder holds none on either driver. The entrypoint satisfies
//! `sel4_microkit::Handler`.

use lfw_log::{
    Domain, DomainDetail, DomainState, Event, MAX_LINE_LEN, Refusal, RefusalDetail, Sink, render,
};
use nic_driver_core::bringup::{
    self, BringUpError, DriverVirtqueue, Live, MappedDevice, QUEUE_SIZE, TX_VQ_OFFSET,
};
use nic_driver_core::port::{DataplanePort, ForwarderSignal, ReceiveSide, TransmitSide};
use pd_runtime::{ForwardRings, MAPPING_ALIGN, POOL_REGION_SIZE, Pool, ReturnRing, attach_region};
use sel4_microkit::{Channel, debug_println, memory_region_symbol, protection_domain, var};
use virtio::pci::PciConfig;

/// The forwarder. Send-only; see the crate header on channel 0.
const FORWARDER: Channel = Channel::new(0);

struct ForwarderChannel;

impl ForwarderSignal for ForwarderChannel {
    fn notify(&self) {
        FORWARDER.notify();
    }
}

/// Which pipeline's pool a rejected DMA base named.
#[derive(Clone, Copy)]
enum PoolRegion {
    /// `rx_pool_paddr`.
    Receive,
    /// `tx_pool_paddr`.
    Transmit,
}

impl PoolRegion {
    /// The console token for a base this region could not supply.
    const fn cause(self) -> &'static str {
        match self {
            Self::Receive => "receive-pool-dma-base",
            Self::Transmit => "transmit-pool-dma-base",
        }
    }
}

/// Why this domain could not start.
enum StartupError {
    /// A pool region's patched physical address cannot be a DMA base: it is
    /// zero, not [`MAPPING_ALIGN`]-aligned, or its region would run off the end
    /// of the address space.
    ///
    /// `paddr` is the diagnosis, and the console is the only place an operator
    /// sees it (CONCEPT §11): zero means the `setvar` is missing or misspelled
    /// in the system description, any other value means it is misaligned.
    PoolDmaBaseUnusable { region: PoolRegion, paddr: usize },
    /// The device refused bring-up, or build data it is programmed with was
    /// rejected; see [`BringUpError`].
    Device(BringUpError),
}

impl From<BringUpError> for StartupError {
    fn from(error: BringUpError) -> Self {
        Self::Device(error)
    }
}

impl StartupError {
    /// This refusal as the console record of it. The device half is
    /// `nic_driver_core`'s to name, that being where the tree it walks lives.
    fn refusal(&self) -> Refusal {
        match self {
            Self::PoolDmaBaseUnusable { region, paddr } => Refusal {
                cause: region.cause(),
                detail: RefusalDetail::One(*paddr as u64),
                // Rejected before `PciConfig::new`, so no configuration-space
                // access has happened: the BAR is unplaced and bus mastering is
                // still off, and there is nothing to have signalled through.
                signalled: false,
            },
            Self::Device(error) => error.refusal(),
        }
    }
}

/// The console as a [`Sink`].
///
/// It is the last-resort channel and the only one this build has (CONCEPT §11),
/// so a line that cannot be rendered is reported as the event it came from
/// rather than dropped (ENG-12).
struct Console;

impl Sink for Console {
    fn emit(&self, event: &Event) {
        let mut line = [0u8; MAX_LINE_LEN];
        let rendered = render(event, &mut line)
            .ok()
            .and_then(|written| line.get(..written))
            .and_then(|bytes| core::str::from_utf8(bytes).ok());
        match rendered {
            Some(text) => debug_println!("{text}"),
            None => debug_println!("LFW-PD unrendered={event:?}"),
        }
    }
}

const CONSOLE: Console = Console;

fn announce(state: DomainState, detail: DomainDetail) {
    CONSOLE.emit(&Event::Domain {
        domain: Domain::NicDriver,
        state,
        detail,
    });
}

/// The physical base of a pool region, checked usable as a device DMA base.
///
/// The value is not device input: it is the `rx_pool_paddr` / `tx_pool_paddr`
/// setvar the Microkit tool patches from the system description, and an absent
/// or misspelled `setvar` leaves the symbol at its `var!` default instead of
/// failing the build — so zero is what a *missing* patch produces, and is
/// refused first. What makes the check worth a type is that DMA is unconfined
/// (see the crate header): [`DataplanePort::attach`] turns this into the
/// address of every buffer the device is programmed with. `rx_pool_paddr` has
/// nothing else checking it at all, that region never being mapped here, so a
/// wrong value cannot surface as a fault on a load.
#[derive(Clone, Copy)]
struct PoolDmaBase(u64);

impl PoolDmaBase {
    /// Check a patched physical address on the same footing as `bar_paddr`
    /// (`nic_driver_core::bringup::Identified::place_bar`) and `vq_paddr`
    /// (`Negotiated::configure_queues`): non-zero, aligned, wholly addressable.
    fn new(region: PoolRegion, paddr: usize) -> Result<Self, StartupError> {
        let unusable = StartupError::PoolDmaBaseUnusable { region, paddr };
        if paddr == 0 || !paddr.is_multiple_of(MAPPING_ALIGN) {
            return Err(unusable);
        }
        // `DataplanePort` derives every buffer's DMA address by adding an
        // offset within `POOL_REGION_SIZE`; a sum that wraps leaves the region.
        let base = paddr as u64;
        if base.checked_add(POOL_REGION_SIZE as u64).is_none() {
            return Err(unusable);
        }
        Ok(Self(base))
    }

    const fn get(self) -> u64 {
        self.0
    }
}

#[protection_domain]
fn init() -> NicDriver {
    announce(DomainState::Starting, DomainDetail::None);
    match bring_up() {
        Ok((device, mut port)) => {
            announce(
                DomainState::Ready,
                DomainDetail::ReceivePosted(QUEUE_SIZE as u32),
            );
            loop {
                port.poll_once(&device, &ForwarderChannel);
                core::hint::spin_loop();
            }
        }
        Err(error) => {
            // The whole reason, not a summary: with no shell and no CLI
            // (CONCEPT §11) this line is all an operator gets.
            announce(DomainState::Refused, DomainDetail::Refusal(error.refusal()));
            NicDriver
        }
    }
}

/// Map this domain's regions and bring its device up, receive queue primed.
fn bring_up() -> Result<(Live<MappedDevice>, DataplanePort<'static>), StartupError> {
    let ecam = memory_region_symbol!(ecam_vaddr: *mut u8).as_ptr();
    let bar = memory_region_symbol!(bar_vaddr: *mut u8).as_ptr();
    let vq = memory_region_symbol!(vq_vaddr: *mut u8).as_ptr();
    let rx_fwd: &'static ForwardRings = attach_region!(rx_fwd_vaddr: ForwardRings);
    let rx_free: &'static ReturnRing = attach_region!(rx_free_vaddr: ReturnRing);
    let tx_fwd: &'static ForwardRings = attach_region!(tx_fwd_vaddr: ForwardRings);
    let tx_free: &'static ReturnRing = attach_region!(tx_free_vaddr: ReturnRing);
    // The one pool this domain maps; see the crate header on the other.
    let tx_pool: &'static Pool = attach_region!(tx_pool_vaddr: Pool);
    let bar_paddr = *var!(bar_paddr: usize = 0);
    let vq_paddr = *var!(vq_paddr: usize = 0) as u64;
    // Checked before the first configuration-space access, so a rejection parks
    // the domain with the device untouched rather than with a bus-mastering
    // device pointed at whatever these addresses name.
    let rx_pool_paddr = PoolDmaBase::new(PoolRegion::Receive, *var!(rx_pool_paddr: usize = 0))?;
    let tx_pool_paddr = PoolDmaBase::new(PoolRegion::Transmit, *var!(tx_pool_paddr: usize = 0))?;

    // SAFETY: `ecam` is the mapped 4 KiB ECAM page of the pinned PCI function,
    // guaranteed by `systems/qemu-x86_64/librefirewall.system`, which maps
    // `ecam0`/`ecam1` at `ecam_vaddr` into this PD alone and holds the mapping
    // for the PD's whole life — exactly `PciConfig::new`'s contract.
    let config = unsafe { PciConfig::new(ecam) };

    let placed = bringup::identify(&config)?.place_bar(&config, bar_paddr)?;
    // SAFETY: `bar` is the `bar0`/`bar1` region of
    // `systems/qemu-x86_64/librefirewall.system`, guaranteeing
    // `BAR_WINDOW_SIZE` bytes, page-aligned (so far more than the
    // `virtio::pci::COMMON_CFG_ALIGN` the window must carry) and mapped for the
    // PD's whole life, at the physical address `place_bar` just programmed —
    // `PlacedBar::map`'s contract. Nothing is required of the device's own
    // offsets: `identify` bounded them against the same constant.
    let negotiated = unsafe { placed.map(bar) }
        .acknowledge()?
        .negotiate_features()?;
    announce(
        DomainState::Negotiated,
        DomainDetail::Features(negotiated.features()),
    );
    let configured = negotiated.configure_queues(vq_paddr)?;

    // SAFETY: `vq` is the `vq0`/`vq1` region of
    // `systems/qemu-x86_64/librefirewall.system`, guaranteeing a zeroed,
    // page-aligned (so 16-byte-aligned) mapping shared with this device alone;
    // `bringup`'s `total_bytes <= TX_VQ_OFFSET` const-assertion proves the
    // receive queue fits before the transmit queue's offset —
    // `SplitVirtqueue::new`'s contract.
    let receive_queue = unsafe { DriverVirtqueue::new(vq) };
    // SAFETY: the same region; `bringup`'s `TX_VQ_OFFSET.is_multiple_of(16)`
    // and `TX_VQ_OFFSET + total_bytes <= VQ_REGION_SIZE` const-assertions keep
    // the transmit queue a disjoint, 16-byte-aligned, sole-owned window inside
    // it, and `configure_queues` programmed the device from the same constants.
    let transmit_queue = unsafe { DriverVirtqueue::new(vq.add(TX_VQ_OFFSET)) };

    let mut port = DataplanePort::attach(
        ReceiveSide {
            rings: rx_fwd,
            returns: rx_free,
            pool_paddr: rx_pool_paddr.get(),
        },
        TransmitSide {
            rings: tx_fwd,
            returns: tx_free,
            pool: tx_pool,
            pool_paddr: tx_pool_paddr.get(),
        },
        receive_queue,
        transmit_queue,
    );
    port.prime();
    Ok((configured.go_live(), port))
}

/// Returned only to give `init` a return type — and by a rejected bring-up,
/// where returning parks the domain in the Microkit event loop with the poll
/// loop never entered and, past the point the device is reachable,
/// `STATUS_FAILED` written to it: idle and harmless rather than faulted.
struct NicDriver;

impl sel4_microkit::Handler for NicDriver {
    type Error = sel4_microkit::Infallible;

    /// Unreachable; see the crate header on channel 0.
    fn notified(&mut self, _channels: sel4_microkit::ChannelSet) -> Result<(), Self::Error> {
        Ok(())
    }
}
