#![no_main]
#![no_std]

//! Console protection domain: the one holder of the serial controller. It
//! drains every other domain's log ring, renders each record, and puts the line
//! on COM1.
//!
//! # Adversary
//!
//! Both of the ones this domain can meet (CONCEPT §7.1). The **byzantine peer
//! protection domain** owns the five records regions mapped here read-only:
//! every slot, the producer cursor and the drop count are peer-chosen, and
//! nothing this domain does can correct one. The **hostile or malfunctioning
//! device** is the controller, which may never report its transmitter empty.
//! Neither is judged in this file: `wire` and `lfw_log` refuse a record and
//! `uart_16550` bounds every wait.
//!
//! # Ten regions, not five
//!
//! Each writing domain's ring is two regions carrying opposite grants. This
//! domain maps the records read-only, so it cannot forge a line attributed to a
//! domain that never emitted one, and maps that domain's consume cursor
//! read-write, because how far the console has read is this domain's own
//! statement and the writer must not be able to forge it.
//!
//! # Why it never leaves `init`
//!
//! Exactly as `pds/nic-driver`, and for a reason of its own. Microkit has no
//! periodic wakeup, so a console driven from `notified` must return to the
//! event loop after each activation — and a boot transcript longer than the
//! UART's 16-byte FIFO would then stall until some unrelated domain logged
//! again. The transcript is the whole purpose of a console, so it busy-polls at
//! priority 1 alongside the drivers, where round-robin gives it a slice rather
//! than letting it stall the dataplane.
//!
//! **The rejected alternative is an interrupt-driven transmitter**, which would
//! remove the polling entirely. It needs the system's first `<irq>` element — a
//! second new capability class — so it is recorded here rather than built.
//!
//! # One mechanism, and the window where there is none
//!
//! This domain's own `LFW-PD domain=console state=…` records go through
//! [`ConsolePrinter::print`], the call a peer's decoded record takes (ENG-7);
//! there is no second path for its own output.
//!
//! Its first write is nevertheless the only event in this system with no
//! observability behind it, and the window is stated rather than hidden: from
//! entry into `init` to the moment [`Uart::initialise`] returns, nothing this
//! domain does can be reported *on the console*, because the reporting
//! mechanism is what is being started. That window is two statements — claim
//! the port window, run the register sequence — and the `state=starting`
//! record on the next line closes it.
//!
//! Two different failures fall inside it, and they are no longer equally dark.
//! A refused **capability** — the slot or the grant no longer being what
//! [`com1`] expects — is now caught by [`Com1::claim`] and named on the debug
//! kernel's channel, the same one the Microkit monitor reports this domain's
//! faults on. That channel does not exist in the release image, so in release
//! this failure rejoins the second.
//!
//! A refused **controller** is the second, and the accepted residue is that
//! `uart_16550` distinguishes six ways for that to happen and this domain can
//! carry none of them out. There is no second channel — no `GET /logs` ring yet
//! (MONITORING.md), no metrics endpoint — and the peers' log regions are
//! read-only here, so the refusal cannot be written into one even in principle.
//! The consequence is a node that prints nothing, which is the diagnosis at one
//! bit rather than six. What closes it is a reporting channel independent of
//! the console.
//!
//! Drain order, the per-ring burst, what becomes of an undecodable record and
//! which counter accuses whom are all in [`ConsolePrinter`], where a host test
//! drives them (LAY-2); the register protocol and every bounded wait are in
//! `uart_16550`. This file maps ten regions, claims one port window, and
//! calls one function in a loop.
//!
//! # Why the port access is here and not in `uart_16550`
//!
//! Reaching an x86 port under seL4 is an invocation of *this domain's* I/O-port
//! capability, at a CNode slot Microkit assigns to the domain — so the code
//! that performs it is authority-bound to the protection domain and cannot be
//! written, or host-tested, in a portable crate. It lives in [`com1`], which is
//! the adapter LAY-2 asks a PD to be: no decision, no bound, no protocol. What
//! `uart_16550` keeps is everything a host test can judge, including the
//! address arithmetic that keeps every invocation inside the granted window.
//!
//! # No channel in either direction
//!
//! This domain holds no notification capability and no writing domain holds one
//! on it. A channel would be authority for nothing: the loop below never
//! returns, so this domain never reaches the Microkit event loop and could not
//! observe a wakeup, and it discovers work by reading the cursor each writer
//! publishes — which it does on every pass anyway. [`Console::notified`] exists
//! only because [`Handler`] requires it, and it is reachable only on the path
//! where the controller was refused and this domain parked.

mod com1;

use com1::Com1;
use lfw_log::{ConsolePrinter, Domain, DomainDetail, DomainState, Event};
use pd_runtime::attach_region;
use sel4_microkit::{ChannelSet, Handler, Infallible, debug_println, protection_domain};
use uart_16550::{Transmitter, Uart, WriteError};
use wire::{LogConsume, LogReader, LogRecords};

/// The log rings this domain drains, and so the length of the round-robin: one
/// per writing domain, matching the five pairs of `<map>` rows on the console
/// domain in `systems/qemu-x86_64/librefirewall.system`. Which domains exist is
/// fixed by the system description (CONCEPT §12.3), so this is a build fact.
const RINGS: usize = 5;

/// The programmed controller as somewhere to put bytes. A newtype because both
/// the trait and the transmitter are foreign here, and that is all it adds.
struct SerialLine<'uart>(Transmitter<'uart, Com1>);

impl lfw_log::ByteSink for SerialLine<'_> {
    type Error = WriteError;

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.write_bytes(bytes)
    }
}

/// This domain's own lifecycle record.
const fn announce(state: DomainState) -> Event {
    Event::Domain {
        domain: Domain::Console,
        state,
        detail: DomainDetail::None,
    }
}

#[protection_domain]
fn init() -> Console {
    let forwarder: &'static LogRecords = attach_region!(log_forwarder_vaddr: LogRecords);
    let nic_driver0: &'static LogRecords = attach_region!(log_nic_driver0_vaddr: LogRecords);
    let nic_driver1: &'static LogRecords = attach_region!(log_nic_driver1_vaddr: LogRecords);
    let config: &'static LogRecords = attach_region!(log_config_vaddr: LogRecords);
    let clock: &'static LogRecords = attach_region!(log_clock_vaddr: LogRecords);
    let forwarder_consume: &'static LogConsume =
        attach_region!(log_forwarder_consume_vaddr: LogConsume);
    let nic_driver0_consume: &'static LogConsume =
        attach_region!(log_nic_driver0_consume_vaddr: LogConsume);
    let nic_driver1_consume: &'static LogConsume =
        attach_region!(log_nic_driver1_consume_vaddr: LogConsume);
    let config_consume: &'static LogConsume = attach_region!(log_config_consume_vaddr: LogConsume);
    let clock_consume: &'static LogConsume = attach_region!(log_clock_consume_vaddr: LogConsume);

    let port = match Com1::claim() {
        Ok(port) => port,
        Err(fault) => {
            // The capability itself is wrong — the slot no longer holds one,
            // or its range no longer covers what the driver addresses. That is
            // a build fact, not a device, so it is worth telling apart from a
            // controller that merely refused; the debug kernel's channel is
            // where the monitor already reports this domain's faults, and it
            // compiles out of the release image entirely.
            debug_println!(
                "console: I/O-port capability refused at port {:#06x}: seL4_Error {}",
                fault.port,
                fault.error
            );
            return Console;
        }
    };

    let mut uart = Uart::new(port);
    let Ok(transmitter) = uart.initialise() else {
        // Unreportable by construction; see the crate header on the window with
        // no observability behind it. Parking leaves the domain idle rather
        // than retrying a controller that has already refused a sequence every
        // step of which was confirmed by readback.
        return Console;
    };

    let mut printer = ConsolePrinter::new(SerialLine(transmitter));
    printer.print(&announce(DomainState::Starting));

    // Taken once and kept, which is what `LogConsume::reader` asks of a caller:
    // a second handle restarts at slot zero and re-renders every record the
    // first consumed. They live as long as the loop below, which never ends.
    // Each pairs this domain's own consume region with the records region of
    // the domain that fills it.
    let mut readers: [LogReader<'static>; RINGS] = [
        forwarder_consume.reader(forwarder),
        nic_driver0_consume.reader(nic_driver0),
        nic_driver1_consume.reader(nic_driver1),
        config_consume.reader(config),
        clock_consume.reader(clock),
    ];
    printer.print(&announce(DomainState::Ready));

    loop {
        printer.drain(&mut readers);
        core::hint::spin_loop();
    }
}

/// Returned only by a refused controller, where returning parks the domain in
/// the Microkit event loop with the drain loop never entered: idle and harmless
/// rather than spinning on a device that will not answer.
struct Console;

impl Handler for Console {
    type Error = Infallible;

    /// No domain can reach it: nothing in this system holds a notification
    /// capability on this one, so the event loop this parks in has no sender.
    /// It exists because [`Handler`] requires it; see the crate header.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        Ok(())
    }
}
