#![no_main]
#![no_std]

//! Console protection domain: the one holder of the serial controller. It
//! drains every other domain's log ring, renders each record, and puts the line
//! on COM1.
//!
//! # Adversary
//!
//! Both of the adversaries this domain can meet. The **byzantine peer
//! protection domain** owns the nine records regions mapped here read-only:
//! every slot, the producer cursor and the drop count are peer-chosen, and
//! nothing this domain does can correct one. The **hostile or malfunctioning
//! device** is the controller, which may never report its transmitter empty.
//! Neither is judged in this file: `wire` and `lfw_log` refuse a record and
//! `uart_16550` bounds every wait.
//!
//! # Eighteen regions, not nine
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
//! [`ConsolePrinter::print`], the call a peer's decoded record takes;
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
//! Two different failures fall inside it, and they are not equally dark.
//!
//! A refused **controller** this domain can still report. It cannot print, but
//! its stats shard is its own to write, so `init` publishes it before parking and
//! `librefirewall_uart_init_failures_total` moves — which is what lets a scrape
//! tell a refused controller from a console that came up and printed nothing. The
//! residue is granularity: `uart_16550` distinguishes six ways for the register
//! sequence to fail and one counter carries none of them apart.
//!
//! A refused **capability** — the slot or the grant no longer being what [`com1`]
//! expects — is the darker one. No controller was addressed, so no initialisation
//! failed and there is nothing truthful to put in the shard; a zeroed shard is
//! also what an unstarted domain leaves. The fault is named on the debug kernel's
//! channel instead, which the release image does not have. What closes it is a
//! reporting channel independent of the console.
//!
//! Drain order, the per-ring burst, what becomes of an undecodable record and
//! which counter accuses whom are all in [`ConsolePrinter`], where a host test
//! drives them; the register protocol and every bounded wait are in
//! `uart_16550`. This file maps eighteen log regions, claims one port window, and
//! calls one function in a loop.
//!
//! # Why the port access is here and not in `uart_16550`
//!
//! Reaching an x86 port under seL4 is an invocation of *this domain's* I/O-port
//! capability, at a CNode slot Microkit assigns to the domain — so the code
//! that performs it is authority-bound to the protection domain and cannot be
//! written, or host-tested, in a portable crate. It lives in [`com1`], which is
//! the thin adapter a PD should be: no decision, no bound, no protocol. What
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
use lfw_log::{
    Clock as _, ConsoleCounters, ConsolePrinter, Domain, DomainDetail, DomainState, Event,
};
use lfw_metrics::{ConsoleSample, StatsShard};
use pd_runtime::{PdClock, attach_region};
use sel4_microkit::{ChannelSet, Handler, Infallible, debug_println, protection_domain};
use uart_16550::{Transmitter, Uart, WriteError};
use wire::{ClockCalibration, LogConsume, LogReader, LogRecords};

/// The log rings this domain drains, and so the length of the round-robin: one
/// per writing domain, matching the ten pairs of `<map>` rows on the console
/// domain in `systems/qemu-x86_64/librefirewall.system`. Which domains exist is
/// fixed by the system description, so this is a build fact.
const RINGS: usize = 10;

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
    let nic_driver2: &'static LogRecords = attach_region!(log_nic_driver2_vaddr: LogRecords);
    let management: &'static LogRecords = attach_region!(log_management_vaddr: LogRecords);
    let recorder: &'static LogRecords = attach_region!(log_recorder_vaddr: LogRecords);
    let hardware_probe: &'static LogRecords = attach_region!(log_hardware_probe_vaddr: LogRecords);
    let crypto: &'static LogRecords = attach_region!(log_crypto_vaddr: LogRecords);
    let forwarder_consume: &'static LogConsume =
        attach_region!(log_forwarder_consume_vaddr: LogConsume);
    let nic_driver0_consume: &'static LogConsume =
        attach_region!(log_nic_driver0_consume_vaddr: LogConsume);
    let nic_driver1_consume: &'static LogConsume =
        attach_region!(log_nic_driver1_consume_vaddr: LogConsume);
    let config_consume: &'static LogConsume = attach_region!(log_config_consume_vaddr: LogConsume);
    let clock_consume: &'static LogConsume = attach_region!(log_clock_consume_vaddr: LogConsume);
    let nic_driver2_consume: &'static LogConsume =
        attach_region!(log_nic_driver2_consume_vaddr: LogConsume);
    let management_consume: &'static LogConsume =
        attach_region!(log_management_consume_vaddr: LogConsume);
    let recorder_consume: &'static LogConsume =
        attach_region!(log_recorder_consume_vaddr: LogConsume);
    let hardware_probe_consume: &'static LogConsume =
        attach_region!(log_hardware_probe_consume_vaddr: LogConsume);
    let crypto_consume: &'static LogConsume = attach_region!(log_crypto_consume_vaddr: LogConsume);
    let stats: &'static StatsShard = attach_region!(stats_vaddr: StatsShard);
    // For its own two records alone: a peer's instant is rendered, never minted.
    let stamps = PdClock::new(attach_region!(clock_vaddr: ClockCalibration));

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
        // No line can be printed, so the shard is the only statement left — and it
        // is writable, the refusal being the device's and not the mapping's.
        // Publishing here is what moves `init_failures`, so an operator who can
        // scrape reads a refused controller rather than a shard of zeroes. Nothing
        // was printed, so the record counters are zero and the device's three
        // carry the whole of it. Parking leaves the domain idle rather than
        // retrying a controller that refused a sequence confirmed at every step.
        stats.publish(
            &ConsoleCounters::default()
                .to_sample(uart.stats().to_sample())
                .values(),
        );
        return Console;
    };

    let mut printer = ConsolePrinter::new(SerialLine(transmitter));
    printer.print(stamps.now(), &announce(DomainState::Starting));

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
        nic_driver2_consume.reader(nic_driver2),
        management_consume.reader(management),
        recorder_consume.reader(recorder),
        hardware_probe_consume.reader(hardware_probe),
        crypto_consume.reader(crypto),
    ];
    printer.print(stamps.now(), &announce(DomainState::Ready));

    // Written once so a scrape taken before the first record reads a console
    // that is up, and thereafter only when something moved. Compared rather than
    // stored unconditionally for `pds/nic-driver`'s reason: this is a busy loop,
    // and an unconditional publish would dirty the shard's cache line millions
    // of times a second for nothing.
    let mut published = sample(&printer);
    stats.publish(&published.values());
    loop {
        printer.drain(&mut readers);
        let current = sample(&printer);
        if current != published {
            stats.publish(&current.values());
            published = current;
        }
        core::hint::spin_loop();
    }
}

/// This domain's counters and its device's, in the shape their shared shard
/// lays them out.
///
/// Assembled in `lfw_log`, where a test holds the metric surface's vocabulary to
/// the fields it names; this file supplies the one thing only it has,
/// which is both halves at once.
fn sample(printer: &ConsolePrinter<SerialLine<'_>>) -> ConsoleSample {
    printer
        .counters()
        .to_sample(printer.writer().0.stats().to_sample())
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
