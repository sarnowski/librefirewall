#![no_main]
#![no_std]

//! virtio-net driver protection domain: it drives one dataplane port (QEMU
//! q35, virtio 1.0 PCI). One instance runs per dataplane port of the current
//! two-port forwarding bring-up; the management, session-replication, and
//! mirror roles of the full port model (CONCEPT §9) are future ports, not part
//! of this slice.
//!
//! # This binary is an adapter and nothing else
//!
//! It does exactly three things: it turns the addresses the Microkit tool
//! patched into it into `nic_driver_core` types, it runs the poll loop, and it
//! reports a rejected bring-up on the console. Every decision — what makes a
//! device acceptable, what order the handshake runs in, what a poll pass does
//! and which step rings which doorbell — lives in `nic_driver_core`
//! ([`bringup`](nic_driver_core::bringup), [`port`](nic_driver_core::port)),
//! where a host test can drive it against a stand-in device. Nothing that can
//! be wrong in a logic sense is decided in this file, because nothing in this
//! file can be tested off seL4.
//!
//! Both directions are **zero-copy** over one buffer pool per pipeline: the
//! receive buffers are the rx pipeline's pool itself (the NIC DMAs each frame
//! into a buffer the forwarder and peer driver read in place), and transmit
//! frames are DMA'd straight out of the tx pipeline's pool after the driver
//! zeroes the 12-byte virtio-net header in front of the frame.
//!
//! # Everything this domain touches is patched in at build time
//!
//! Hardware topology is static (CONCEPT §12.3): this driver performs **no PCI
//! enumeration**. It never scans a bus, never reads a device it was not given,
//! and holds capabilities for exactly one function's ECAM page. The Microkit
//! tool patches each instance from `systems/qemu-x86_64/librefirewall.system`:
//!
//! | symbol | what it names |
//! |---|---|
//! | `ecam_vaddr` | the 4 KiB ECAM page of this instance's pinned PCI function |
//! | `bar_vaddr` | the `BAR_WINDOW_SIZE` MMIO window the device's BAR is relocated to |
//! | `vq_vaddr` | the zeroed `VQ_REGION_SIZE` virtqueue DMA region |
//! | `rx_pipe_vaddr` / `tx_pipe_vaddr` | the two pipeline regions this port joins |
//! | `bar_paddr`, `vq_paddr`, `rx_pipe_paddr`, `tx_pipe_paddr` | the physical addresses of those regions, for programming the device |
//!
//! Two instances of this one binary therefore drive two different devices with
//! no code difference between them. The consequence worth stating plainly:
//! **this driver cannot bind a device it was not built for.** The ids at the
//! pinned function are checked and a mismatch is a rejection
//! ([`BringUpError::NotVirtioNet`]) — there is no fallback scan, so a machine
//! whose PCI topology differs from the one the image was built for produces a
//! parked driver, never a driver bound to the wrong device.
//!
//! The window *sizes* are `nic_driver_core`'s constants rather than this
//! file's, so the bound a device offset is checked against and the window
//! actually mapped cannot be edited apart. That they in turn match the `size=`
//! attributes in the system description has no enforcer; see
//! [`BAR_WINDOW_SIZE`](nic_driver_core::bringup::BAR_WINDOW_SIZE).
//!
//! # Scheduling: two drivers busy-loop at equal priority
//!
//! Microkit has no periodic wakeup and this driver takes no interrupt (no
//! MSI-X, no INTx) by design, so it polls by never returning from `init`. Two
//! consequences follow from the system description, and neither is obvious from
//! this file alone:
//!
//! - The forwarder runs at **priority 2** against this domain's **1**, so it
//!   preempts on notification and the busy loop cannot starve it.
//! - The **two driver instances run at the same priority 1 and both loop
//!   forever**, so neither ever yields and neither ever blocks. Their mutual
//!   progress rests entirely on seL4's round-robin scheduling of equal-priority
//!   threads within a timeslice, and each instance occupies a core for as long
//!   as the system runs. On the single-core bring-up this is why a driver must
//!   not spin on a device-controlled condition — a device that withholds an
//!   answer would deny the timeslice to the other port, not merely to itself —
//!   and it is why every wait in `nic_driver_core` and `virtio::pci` is bounded
//!   by a driver-owned count. Interrupt-driven operation and the multicore
//!   dataplane both change this picture and are open (README status).
//!
//! # Channel 0 is used in one direction only, and the capability says so
//!
//! This domain holds one channel to the forwarder and only ever sends on it.
//! [`NicDriver::notified`] is unreachable, and unreachable by *capability*
//! rather than merely by control flow — which is the difference between a
//! property of this file and a property of the system.
//!
//! Microkit expresses the narrow grant on the `<channel>`'s `<end>`: the
//! optional `notify` attribute "indicates that the protection domain for this
//! end can send a notification to the other end; defaults to **true**"
//! (Microkit 2.3.0 user manual §7.6). Both `<end pd="forwarder" …>` elements
//! in `systems/qemu-x86_64/librefirewall.system` are marked `notify="false"`,
//! so each driver keeps its send capability on the forwarder while the
//! forwarder holds none on either driver. Nothing can arrive at this
//! entrypoint even if `pds/forwarder` grew code that tried; today it has none
//! (it implements `notified` and constructs no `Channel` to send on).
//!
//! Control flow agrees, which is why the narrowing costs this domain nothing:
//! on a healthy bring-up `init` never returns, and on a rejected one the
//! domain parks with the poll loop never entered, so it never reaches the
//! Microkit event loop at all. The entrypoint exists solely to satisfy
//! `sel4_microkit::Handler`.

use nic_driver_core::bringup::{
    self, BringUpError, DriverVirtqueue, Live, MappedDevice, QUEUE_SIZE, TX_VQ_OFFSET,
};
use nic_driver_core::port::{DataplanePort, ForwarderSignal};
use pd_runtime::{Pipeline, attach_pipeline};
use sel4_microkit::{Channel, debug_println, memory_region_symbol, protection_domain, var};
use virtio::pci::PciConfig;

/// The forwarder, which this domain notifies when frames are waiting on the
/// receive pipeline. See the crate header on why nothing arrives back.
const FORWARDER: Channel = Channel::new(0);

/// The poll pass's outward signal, bound to the channel above.
struct ForwarderChannel;

impl ForwarderSignal for ForwarderChannel {
    fn notify(&self) {
        FORWARDER.notify();
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
            // (CONCEPT §11) this line is all an operator gets, and every
            // `BringUpError` variant carries the value that caused it.
            // `signalled` says whether the device was told to stop or was left
            // decoding nothing, which depends on whether its BAR had been
            // placed when the rejection happened.
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
///
/// Every step is `nic_driver_core`'s; what happens here is the mapping and the
/// order, and the order is not this function's to choose — each state is
/// produced only by the transition before it (see
/// [`bringup`](nic_driver_core::bringup)), so this reads as a sequence because
/// it is the only sequence expressible.
fn bring_up() -> Result<(Live<MappedDevice>, DataplanePort<'static>), BringUpError> {
    // Mapped windows and DMA physical addresses, all patched by the Microkit
    // tool from librefirewall.system; see the crate header's table. Each
    // `unsafe` use below states the precondition it upholds.
    let ecam = memory_region_symbol!(ecam_vaddr: *mut u8).as_ptr();
    let bar = memory_region_symbol!(bar_vaddr: *mut u8).as_ptr();
    let vq = memory_region_symbol!(vq_vaddr: *mut u8).as_ptr();
    // The pipeline this NIC receives into (its pool is this NIC's receive DMA
    // target) and the one it transmits out of. The aliasing invariant both
    // share is stated once, in `attach_pipeline!`.
    let rx_pipe: &'static Pipeline = attach_pipeline!(rx_pipe_vaddr);
    let tx_pipe: &'static Pipeline = attach_pipeline!(tx_pipe_vaddr);
    let bar_paddr = *var!(bar_paddr: usize = 0);
    let vq_paddr = *var!(vq_paddr: usize = 0) as u64;
    let rx_pipe_paddr = *var!(rx_pipe_paddr: usize = 0) as u64;
    let tx_pipe_paddr = *var!(tx_pipe_paddr: usize = 0) as u64;

    // SAFETY: `ecam` is the mapped 4 KiB ECAM page of the pinned device
    // function (patched from librefirewall.system, which maps `ecam0`/`ecam1`
    // at `ecam_vaddr` into this PD) and stays mapped for the PD's whole life —
    // exactly `PciConfig::new`'s contract.
    let config = unsafe { PciConfig::new(ecam) };

    let placed = bringup::identify(&config)?.place_bar(&config, bar_paddr)?;
    // SAFETY: `bar` is the mapped BAR window patched from librefirewall.system,
    // whose `bar0`/`bar1` region is `BAR_WINDOW_SIZE` bytes at the physical
    // address `place_bar` just programmed, page-aligned (so far more than the
    // `virtio::pci::COMMON_CFG_ALIGN` the window must carry) and mapped for the
    // PD's whole life — `PlacedBar::map`'s contract. Nothing is required of the
    // device's own offsets here: `identify` bounded them against the same
    // constant and refused any common-configuration offset the registers behind
    // it could not be addressed at.
    let negotiated = unsafe { placed.map(bar) }
        .acknowledge()?
        .negotiate_features()?;
    debug_println!(
        "LIBREFIREWALL_NIC:features negotiated={:#x}",
        negotiated.features()
    );
    let configured = negotiated.configure_queues(vq_paddr)?;

    // Both virtqueues live in the one DMA region: receive at offset 0, transmit
    // at TX_VQ_OFFSET, the same placement `configure_queues` programmed into
    // the device from the same constants.
    // SAFETY: `vq` is the mapped, zeroed, page-aligned (so 16-byte-aligned)
    // virtqueue DMA region, shared only with this device; `bringup`'s
    // `total_bytes <= TX_VQ_OFFSET` const-assertion proves the receive queue
    // fits before the transmit queue's offset — `SplitVirtqueue::new`'s
    // contract.
    let receive_queue = unsafe { DriverVirtqueue::new(vq) };
    // SAFETY: the same region; `bringup`'s `TX_VQ_OFFSET.is_multiple_of(16)`
    // and `TX_VQ_OFFSET + total_bytes <= VQ_REGION_SIZE` const-assertions keep
    // the transmit queue a disjoint, 16-byte-aligned, sole-owned window inside
    // it.
    let transmit_queue = unsafe { DriverVirtqueue::new(vq.add(TX_VQ_OFFSET)) };

    let mut port = DataplanePort::attach(
        rx_pipe,
        rx_pipe_paddr,
        tx_pipe,
        tx_pipe_paddr,
        receive_queue,
        transmit_queue,
    );
    // Buffers are posted while the device is still `Configured`, and
    // `go_live` is what sets DRIVER_OK and only then rings the receive
    // doorbell — the ordering is the type's, not this call site's.
    port.prime();
    Ok((configured.go_live(), port))
}

/// Carries no state: on a healthy bring-up the driver never returns from
/// `init`, so this exists only to satisfy the Microkit entrypoint's return
/// type.
///
/// It is also what a rejected bring-up returns. Returning parks the protection
/// domain in the Microkit event loop with the poll loop never entered and, past
/// the point the device is reachable, `STATUS_FAILED` written to it — an idle,
/// harmless domain rather than a faulted one. Restarting it is the PD
/// fault-handling milestone (README status), not this domain's job.
struct NicDriver;

impl sel4_microkit::Handler for NicDriver {
    type Error = sel4_microkit::Infallible;

    /// Unreachable; see the crate header's note on channel 0.
    fn notified(&mut self, _channels: sel4_microkit::ChannelSet) -> Result<(), Self::Error> {
        Ok(())
    }
}
