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
//! input. DMA is unconfined here — there is no IOMMU on this platform (CONCEPT
//! §7.2) — so an address handed to the device is an address it may write.
//!
//! # What is decided elsewhere, and the one thing that is not
//!
//! Which devices are acceptable, what order the handshake runs in, and what a
//! poll pass does all live in `nic_driver_core`, where a host test can drive
//! them against a stand-in device (LAY-2). [`PipelineDmaBase`] deviates from
//! that and is recorded here as the deviation it is: the value it guards enters
//! `nic_driver_core` through
//! [`DataplanePort::attach`](nic_driver_core::port::DataplanePort::attach),
//! which takes a plain `u64`, so no type can refuse an unchecked address at
//! that boundary — only this call site can, and a check in this file cannot be
//! host-tested. Moving the newtype into `pd_runtime`, beside the
//! [`MAPPING_ALIGN`] and [`REGION_SIZE`] it checks against, and having `attach`
//! take it, is what would close the gap.
//!
//! # Everything this domain touches is patched in at build time
//!
//! Hardware topology is static (CONCEPT §12.3), so this driver performs no PCI
//! enumeration: it never scans a bus and holds capabilities for exactly one
//! function's ECAM page. Two instances of one binary therefore drive two
//! devices with no code difference between them. The Microkit tool patches each
//! instance from `systems/qemu-x86_64/librefirewall.system`:
//!
//! | symbol | what it names |
//! |---|---|
//! | `ecam_vaddr` | the 4 KiB ECAM page of this instance's pinned PCI function |
//! | `bar_vaddr` | the `BAR_WINDOW_SIZE` MMIO window the device's BAR is relocated to |
//! | `vq_vaddr` | the zeroed `VQ_REGION_SIZE` virtqueue DMA region |
//! | `rx_pipe_vaddr` / `tx_pipe_vaddr` | the two pipeline regions this port joins |
//! | `bar_paddr`, `vq_paddr`, `rx_pipe_paddr`, `tx_pipe_paddr` | the physical addresses of those regions, for programming the device |
//!
//! # Scheduling: two drivers busy-loop at equal priority
//!
//! Microkit has no periodic wakeup and this driver takes no interrupt (no
//! MSI-X, no INTx) by design, so it polls by never returning from `init`. The
//! system description fixes what follows, and it is not visible from this file:
//! the two driver instances share **priority 1** and both loop forever, so
//! neither yields and neither blocks, and their mutual progress rests entirely
//! on seL4's round-robin scheduling of equal-priority threads. On the
//! single-core bring-up this is why a driver must never spin on a
//! device-controlled condition — a device that withholds an answer would deny
//! the timeslice to the other port, not merely to itself. The forwarder runs at
//! **priority 2** and preempts on notification, so the busy loop cannot starve
//! it.
//!
//! # Channel 0 sends and never receives
//!
//! [`NicDriver`]'s `notified` entrypoint is unreachable by *capability* rather
//! than by control flow, which is the difference between a property of this
//! file and a property of the system. Microkit's optional `notify` attribute on a
//! `<channel>`'s `<end>` "indicates that the protection domain for this end can
//! send a notification to the other end; defaults to **true**" (Microkit 2.3.0
//! user manual §7.6). Both `<end pd="forwarder" …>` elements in
//! `systems/qemu-x86_64/librefirewall.system` are marked `notify="false"`, so
//! each driver keeps its send capability on the forwarder while the forwarder
//! holds none on either driver. The entrypoint exists to satisfy
//! `sel4_microkit::Handler`.

use nic_driver_core::bringup::{
    self, BringUpError, DriverVirtqueue, Live, MappedDevice, QUEUE_SIZE, TX_VQ_OFFSET,
};
use nic_driver_core::port::{DataplanePort, ForwarderSignal};
use pd_runtime::{MAPPING_ALIGN, Pipeline, REGION_SIZE, attach_pipeline};
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

/// Which pipeline region a rejected DMA base named.
#[derive(Clone, Copy, Debug)]
enum PipelineRegion {
    /// `rx_pipe_paddr`.
    Receive,
    /// `tx_pipe_paddr`.
    Transmit,
}

/// Why this domain could not start.
#[derive(Debug)]
enum StartupError {
    /// A pipeline region's patched physical address cannot be a DMA base: it is
    /// zero, not [`MAPPING_ALIGN`]-aligned, or its region would run off the end
    /// of the address space.
    ///
    /// `paddr` is the diagnosis, and the console is the only place an operator
    /// sees it (CONCEPT §11): zero means the `setvar` is missing or misspelled
    /// in the system description, any other value means it is misaligned.
    #[expect(dead_code, reason = "read by the derived Debug on the console line")]
    PipelineDmaBaseUnusable {
        region: PipelineRegion,
        paddr: usize,
    },
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
    /// Whether the device was told to stop, or was left decoding nothing.
    fn signalled_to_device(&self) -> bool {
        match self {
            // Rejected before `PciConfig::new`, so no configuration-space
            // access has happened: the BAR is unplaced and bus mastering is
            // still off.
            Self::PipelineDmaBaseUnusable { .. } => false,
            Self::Device(error) => error.signalled_to_device(),
        }
    }
}

/// The physical base of a mapped pipeline region, checked to be usable as a
/// device DMA base.
///
/// The value is not device input: it is the `rx_pipe_paddr` / `tx_pipe_paddr`
/// setvar the Microkit tool patches from the system description, and an absent
/// or misspelled `setvar` leaves the symbol at its `var!` default instead of
/// failing the build. Zero is therefore the value a *missing* patch produces,
/// which is why it is refused first. What makes the check worth a type is that
/// DMA is unconfined (see the crate header): [`DataplanePort::attach`] turns
/// this into the address of every buffer the device is programmed with, and the
/// address the device is given is the address it writes.
#[derive(Clone, Copy)]
struct PipelineDmaBase(u64);

impl PipelineDmaBase {
    /// Check a patched physical address, on the same footing as `bar_paddr`
    /// (`nic_driver_core::bringup::Identified::place_bar`) and `vq_paddr`
    /// (`Negotiated::configure_queues`): non-zero, [`MAPPING_ALIGN`]-aligned,
    /// and wholly addressable.
    fn new(region: PipelineRegion, paddr: usize) -> Result<Self, StartupError> {
        let unusable = StartupError::PipelineDmaBaseUnusable { region, paddr };
        if paddr == 0 || !paddr.is_multiple_of(MAPPING_ALIGN) {
            return Err(unusable);
        }
        // `DataplanePort` derives every buffer's DMA address by adding an
        // offset within `REGION_SIZE` to this base, and a sum that wraps would
        // name a buffer outside the mapping.
        let base = paddr as u64;
        if base.checked_add(REGION_SIZE as u64).is_none() {
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
    debug_println!("LIBREFIREWALL_NIC:driver:start");
    match bring_up() {
        Ok((device, mut port)) => {
            debug_println!("LIBREFIREWALL_NIC:driver-ok rx-posted={QUEUE_SIZE}");
            loop {
                port.poll_once(&device, &ForwarderChannel);
                core::hint::spin_loop();
            }
        }
        Err(error) => {
            // The whole reason, not a summary: with no shell and no CLI
            // (CONCEPT §11) this line is all an operator gets.
            debug_println!(
                "LIBREFIREWALL_NIC:fail error={error:?} signalled={}",
                error.signalled_to_device()
            );
            NicDriver
        }
    }
}

/// Map this domain's regions and bring its device up, leaving it live with its
/// receive queue primed.
fn bring_up() -> Result<(Live<MappedDevice>, DataplanePort<'static>), StartupError> {
    let ecam = memory_region_symbol!(ecam_vaddr: *mut u8).as_ptr();
    let bar = memory_region_symbol!(bar_vaddr: *mut u8).as_ptr();
    let vq = memory_region_symbol!(vq_vaddr: *mut u8).as_ptr();
    let rx_pipe: &'static Pipeline = attach_pipeline!(rx_pipe_vaddr);
    let tx_pipe: &'static Pipeline = attach_pipeline!(tx_pipe_vaddr);
    let bar_paddr = *var!(bar_paddr: usize = 0);
    let vq_paddr = *var!(vq_paddr: usize = 0) as u64;
    // Checked before the first configuration-space access, so a rejection parks
    // the domain with the device untouched rather than with a bus-mastering
    // device pointed at whatever these addresses name.
    let rx_pipe_paddr =
        PipelineDmaBase::new(PipelineRegion::Receive, *var!(rx_pipe_paddr: usize = 0))?;
    let tx_pipe_paddr =
        PipelineDmaBase::new(PipelineRegion::Transmit, *var!(tx_pipe_paddr: usize = 0))?;

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
    debug_println!(
        "LIBREFIREWALL_NIC:features negotiated={:#x}",
        negotiated.features()
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
        rx_pipe,
        rx_pipe_paddr.get(),
        tx_pipe,
        tx_pipe_paddr.get(),
        receive_queue,
        transmit_queue,
    );
    port.prime();
    Ok((configured.go_live(), port))
}

/// Returned only to give `init` a return type — and by a rejected bring-up,
/// where returning parks the protection domain in the Microkit event loop with
/// the poll loop never entered and, past the point the device is reachable,
/// `STATUS_FAILED` written to it: idle and harmless rather than faulted.
struct NicDriver;

impl sel4_microkit::Handler for NicDriver {
    type Error = sel4_microkit::Infallible;

    /// Unreachable; see the crate header on channel 0.
    fn notified(&mut self, _channels: sel4_microkit::ChannelSet) -> Result<(), Self::Error> {
        Ok(())
    }
}
