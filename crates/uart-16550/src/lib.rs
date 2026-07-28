//! The 16550-compatible UART at x86 I/O port `0x3F8` (COM1): the register
//! protocol that programs it, and the write path that puts a byte on it.
//!
//! It carries the console, which on a node with no shell and no CLI (CONCEPT
//! §11) is a last-resort channel. The register sequencing lives here rather
//! than in the protection domain so that it can be driven by a host test;
//! [`PortIo`] is the seam the caller supplies the port behind.
//!
//! # Why no port access lives here
//!
//! Reaching a port under seL4 means invoking an I/O-port capability at a CNode
//! slot Microkit assigns the domain — never `in`/`out`, which the kernel's TSS
//! bitmap faults regardless of the grant. No portable crate can hold that
//! authority, so the only real [`PortIo`] is `pds/console/src/com1.rs`, which
//! argues it in full; here there is no `unsafe` and no seL4 dependency.
//!
//! # The adversary
//!
//! CONCEPT §7.1's **hostile or malfunctioning device**. Every byte read back
//! here — the interrupt-enable readback, the line-control readback, the divisor
//! latches, the interrupt-identification bits, the line status — is chosen by
//! the device, and a device that simply never answers is indistinguishable from
//! one that answers wrongly. Both are met the same way: every wait is bounded
//! by a named constant of this crate's own, and every refusal is a typed
//! [`InitError`] or [`WriteError`] plus a counter. A UART that never reports its
//! transmitter empty must not wedge the only diagnostic channel the product
//! has, which is why no loop below is permitted to spin on a device value.
//!
//! # One device, one driver
//!
//! Azure Serial Console attaches to "ttyS0 or COM1" and QEMU's q35 machine
//! exposes COM1 as a 16550A: the same 16550-compatible UART at the same port.
//! There is therefore no second, Azure-specific driver to write, and writing one
//! would be this driver duplicated (ENG-6). Where the two differ is
//! *availability*, not registers, and neither difference is expressible in code:
//! Azure reaches the console only when boot diagnostics are enabled on the VM,
//! and Microsoft documents the serial console as possibly unavailable after a
//! live migration of a Generation 2 VM using Trusted Launch with Secure Boot.
//! An operator acts on both; this crate cannot.
//!
//! # Why there is nothing to configure
//!
//! [`COM1_BASE`] and [`DIVISOR`] are constants rather than parameters because
//! they are hardware topology, and CONCEPT §12.3 fixes hardware in the system
//! description: the port window this driver may touch is granted by an
//! `<ioport>` element, so a runtime base would be a value the capability could
//! not follow. The build-time constant and the grant are one fact stated twice,
//! and the second statement is checked by the assertions beside
//! [`Register::port`].
//!
//! # Rejected alternatives
//!
//! * **An interrupt-driven transmitter.** It is the right end state and would
//!   remove the polling entirely, but it would introduce the system's first IRQ
//!   and a new capability class. That is a change to the capability topology,
//!   not to a driver.
//! * **A typestate for DLAB**, so that the divisor latches were unreachable
//!   while the word-format registers were addressable. DLAB is a bit inside the
//!   *device*, and this driver learns its value only by reading a register the
//!   device is free to lie about, so a type asserting "DLAB is set" would assert
//!   something no first-party value can guarantee. It stays a documented
//!   aliasing of two offsets, checked by readback like every other step.
//! * **A hardware-flow-control handshake** (DTR/RTS through the modem-control
//!   register). Nothing on either end of this link asserts flow control, and a
//!   console that blocked on a peer's readiness would be a console that stops
//!   reporting exactly when the node is in trouble.

#![cfg_attr(not(test), no_std)]

#[cfg(test)]
mod fake_port;

/// The x86 I/O port the first serial controller decodes at on a PC-compatible
/// machine, QEMU's q35 and an Azure Generation 2 VM alike.
pub const COM1_BASE: u16 = 0x3F8;

/// Consecutive I/O ports the controller occupies, and the width of the
/// `<ioport>` grant that admits them.
///
/// **Cross-artifact (DOC-7):** equal to the `size` attribute of the
/// `<ioport id="0" addr="0x3f8" size="8" />` element granted to the console
/// domain in `systems/qemu-x86_64/librefirewall.system`; [`Register::port`] and
/// its assertions keep every address formed here inside it.
pub const PORT_COUNT: u16 = 8;

/// The controller's reference clock, in hertz — the 1.8432 MHz crystal a
/// PC-compatible 16550 is driven from.
pub const REFERENCE_CLOCK_HZ: u32 = 1_843_200;

/// Bits of the reference clock consumed per transmitted bit: the 16550 samples
/// each bit sixteen times, so the fastest rate it can produce is
/// `REFERENCE_CLOCK_HZ / 16`.
pub const CLOCK_TICKS_PER_BIT: u32 = 16;

/// The line rate this console runs at.
pub const BAUD_RATE: u32 = 115_200;

/// The value programmed into the divisor latches.
///
/// `1_843_200 / 16 = 115_200`, which is exactly [`BAUD_RATE`], so the divisor is
/// 1 — the fastest the part can go, and the reason 115200 is the conventional
/// ceiling for this controller.
pub const DIVISOR: u16 = (REFERENCE_CLOCK_HZ / (CLOCK_TICKS_PER_BIT * BAUD_RATE)) as u16;

// The division above discards a remainder, which would silently produce a baud
// rate the far end does not use, so the identity is restated as a product.
const _: () = assert!(DIVISOR == 1);
const _: () = assert!(REFERENCE_CLOCK_HZ == CLOCK_TICKS_PER_BIT * BAUD_RATE * DIVISOR as u32);

/// Bytes the transmit FIFO holds once [`Uart::initialise`] has enabled it, so a
/// caller can size a burst it knows will not wait.
pub const FIFO_DEPTH: usize = 16;

/// Reads of the line-status register one [`Transmitter::write_byte`] may make
/// while waiting for the transmitter-holding register to report itself empty.
///
/// A byte at [`BAUD_RATE`] occupies the line for about 87 µs, and a port read is
/// at least a microsecond — an `in` to a legacy port is slow on real hardware
/// and traps to the hypervisor under virtualization — so this is upwards of a
/// hundred times the longest wait a working controller can impose. It is a
/// constant of this crate rather than anything derived from the device, which is
/// what makes the loop bounded by a value the adversary does not choose (ENG-4).
pub const THRE_POLL_LIMIT: u32 = 10_000;

/// Reads of the interrupt-identification register one [`Uart::initialise`] may
/// make while waiting for the controller to report its FIFOs enabled.
///
/// A controller reflects a FIFO-control write in the very next bus cycle, so
/// unlike [`THRE_POLL_LIMIT`] this bounds no real wait at all — it bounds a
/// device that answers forever without ever agreeing, which is the same fault
/// as one that never answers.
pub const FIFO_POLL_LIMIT: u32 = 1_000;

const _: () = assert!(THRE_POLL_LIMIT > 0);
const _: () = assert!(FIFO_POLL_LIMIT > 0);

/// Port operations [`Uart::initialise`] performs outside the FIFO-confirmation
/// poll: two per verified register write (six of them), plus the second divisor
/// write and its readback, plus the FIFO-control write itself.
pub const INIT_FIXED_PORT_OPS: u32 = 13;

/// The most port operations one [`Uart::initialise`] can perform, whatever the
/// device answers. Asserting a run against this is how a test proves the
/// sequence terminates rather than merely that it terminated this time.
pub const INIT_PORT_OPS_MAX: u32 = INIT_FIXED_PORT_OPS + FIFO_POLL_LIMIT;

/// The most port operations one [`Transmitter::write_byte`] can perform: the
/// bounded line-status poll, and the one write it guards.
pub const WRITE_PORT_OPS_MAX: u32 = THRE_POLL_LIMIT + 1;

/// Every interrupt source off. This driver polls, and an unmasked source with no
/// IRQ routed to it would leave the controller asserting a line nothing services.
const IER_ALL_DISABLED: u8 = 0x00;

/// Line-control bit 7, the divisor-latch access bit: while set, offsets 0 and 1
/// address the divisor latches instead of the data and interrupt-enable
/// registers.
const LCR_DLAB: u8 = 0x80;

/// Line-control word format: eight data bits, no parity, one stop bit.
const LCR_8N1: u8 = 0x03;

/// FIFO control: enable the FIFOs, discard whatever the firmware left in each of
/// them, and set the receive trigger to 14 bytes. The trigger governs an
/// interrupt this driver has disabled, and is written because the field has no
/// "unused" encoding.
const FCR_PROGRAMMED: u8 = 0xC7;

/// Interrupt-identification bits 7:6, which a 16550A sets while its FIFOs are
/// enabled. This is the only readback the controller offers for the FIFO-control
/// register, which is itself write-only.
const IIR_FIFOS_ENABLED: u8 = 0xC0;

/// Line-status bit 5: the transmitter-holding register is empty and will accept
/// a byte.
const LSR_THRE: u8 = 0x20;

/// One addressable register of the controller, named by the offset it sits at
/// within the granted [`PORT_COUNT`]-port window.
///
/// The enum is the whole of what [`PortIo`] can be asked for, so an offset
/// outside the window is unrepresentable rather than rejected (DOC-9). Only the
/// five offsets this driver uses are declared: the modem-control, modem-status
/// and scratch registers are granted by the same `<ioport>` element and touched
/// by nothing here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Register {
    /// Offset 0. Written, it is the transmitter-holding register; read, the
    /// receive buffer. While [`LCR_DLAB`] is set it is the divisor latch's low
    /// byte in both directions.
    Data = 0,
    /// Offset 1. The interrupt-enable register, and the divisor latch's high
    /// byte while [`LCR_DLAB`] is set.
    InterruptEnable = 1,
    /// Offset 2. Written, it is the FIFO-control register; **read, it is the
    /// interrupt-identification register**, which is the only way to observe
    /// whether a FIFO-control write took.
    FifoControl = 2,
    /// Offset 3. The line-control register: word format, and the divisor-latch
    /// access bit.
    LineControl = 3,
    /// Offset 5. The line-status register, read-only.
    LineStatus = 5,
}

impl Register {
    /// Every register this driver can address, so a [`PortIo`] proving its
    /// authority spans the whole demand enumerates it rather than restating it.
    pub const ALL: [Self; 5] = [
        Self::Data,
        Self::InterruptEnable,
        Self::FifoControl,
        Self::LineControl,
        Self::LineStatus,
    ];

    /// This register's offset from the base of the port window.
    #[must_use]
    pub const fn offset(self) -> u8 {
        self as u8
    }

    /// The x86 I/O port this register is addressed at.
    ///
    /// An OR, not an addition: the assertions below zero [`COM1_BASE`]'s low
    /// three bits, so the offset cannot leave the granted window and nothing can
    /// overflow (ENG-5). `pub` so the out-of-crate [`PortIo`] need not restate
    /// it unchecked.
    #[must_use]
    pub const fn port(self) -> u16 {
        COM1_BASE | self.offset() as u16
    }
}

const _: () = assert!(PORT_COUNT.is_power_of_two());
const _: () = assert!(COM1_BASE.is_multiple_of(PORT_COUNT));

// The 16550 register map is fixed by the part, and every address this crate
// forms is `COM1_BASE | offset` (see `port`), so a wrong discriminant would
// address a different register rather than fail.
const _: () = assert!(Register::Data.offset() == 0);
const _: () = assert!(Register::InterruptEnable.offset() == 1);
const _: () = assert!(Register::FifoControl.offset() == 2);
const _: () = assert!(Register::LineControl.offset() == 3);
const _: () = assert!(Register::LineStatus.offset() == 5);
const _: () = assert!((Register::LineStatus.offset() as u16) < PORT_COUNT);

/// Byte-wide access to the controller's registers.
///
/// A seam, and for the reason `nic_driver_core::bringup`'s device seam exists:
/// the interesting behaviours are *disagreements* between what the driver wrote
/// and what it reads back, and the instructions that produce them cannot run in
/// a host test at all. Both methods take `&mut self` because both are
/// side-effecting on the real part — a read of the receive buffer pops the FIFO
/// and a read of the line status clears its error bits — so neither is a
/// question that can be asked twice for the same answer.
pub trait PortIo {
    fn read(&mut self, register: Register) -> u8;

    fn write(&mut self, register: Register, value: u8);
}

/// Why the controller was not accepted as a usable console.
///
/// Every variant carries what the device answered, because an operator with no
/// shell (CONCEPT §11) distinguishes an absent controller — which answers `0xFF`
/// to everything — from one that took the divisor and then refused the word
/// format only if the two produce different console lines (ENG-12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    /// The interrupt-enable register did not read back as cleared. This is the
    /// first register touched, so it is also where an absent controller and a
    /// port window granted to nothing surface.
    InterruptsNotDisabled { read_back: u8 },
    /// The line-control register did not report the divisor-latch access bit,
    /// so the divisor latches are not addressable and the baud rate cannot be
    /// programmed at all.
    DlabNotLatched { read_back: u8 },
    /// The divisor latches did not read back what was written to them.
    DivisorNotAccepted { wrote: u16, read_back: u16 },
    /// The line-control register did not report the word format written to it.
    WordFormatNotAccepted { wrote: u8, read_back: u8 },
    /// The interrupt-identification register never reported the FIFOs enabled
    /// within [`FIFO_POLL_LIMIT`] reads, carrying the last value it answered.
    FifosNotEnabled { polls: u32, iir: u8 },
    /// The line-control register still reported the divisor-latch access bit
    /// after it was written clear, so offsets 0 and 1 would still address the
    /// divisor latches and no byte written would ever leave the part.
    DlabNotCleared { read_back: u8 },
}

/// Why a byte was not handed to the controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The line status never reported the transmitter-holding register empty
    /// within [`THRE_POLL_LIMIT`] reads. The byte is dropped: a console that
    /// blocked here would be one that stops the domain rather than one that
    /// loses a line.
    TransmitterNeverReady { polls: u32 },
}

/// What this driver can say about itself, in the shape the metrics endpoint
/// (CONCEPT §11) scrapes.
///
/// Every field is **monotonic** for the protection domain's life and
/// **saturates** at [`u64::MAX`] rather than wrapping, and there is no reset: a
/// scrape derives a rate by differencing successive samples, so a reset would
/// forge a negative rate and a wrap would turn a sustained fault back into a
/// small number exactly when it matters. Taken by value, because a scrape wants
/// one consistent picture rather than a live borrow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UartStats {
    /// Bytes handed to the transmitter-holding register. Not bytes that reached
    /// the far end: nothing on this link reports that.
    pub bytes_written: u64,
    /// Bytes dropped because the transmitter never reported itself empty.
    /// Non-zero means console output has been lost.
    pub thre_timeouts: u64,
    /// Refused initialisations. Expected to be zero; one means the console was
    /// never usable, and more than one means a caller retried.
    pub init_failures: u64,
}

/// The controller, before it has been programmed.
///
/// The write path is not on this type. It is on [`Transmitter`], which only
/// [`initialise`](Self::initialise) produces, so writing to an unprogrammed
/// controller — at whatever baud rate the firmware happened to leave — cannot
/// be written rather than being a rule to remember (DOC-9).
pub struct Uart<P> {
    port: P,
    stats: UartStats,
}

impl<P: PortIo> Uart<P> {
    /// Take the port. Nothing is written to the device here.
    #[must_use]
    pub const fn new(port: P) -> Self {
        Self {
            port,
            stats: UartStats {
                bytes_written: 0,
                thre_timeouts: 0,
                init_failures: 0,
            },
        }
    }

    /// Program the controller — interrupts off, 115200 8N1, FIFOs enabled and
    /// emptied — and yield the write path.
    ///
    /// Bounded by [`INIT_PORT_OPS_MAX`] port operations whatever the device
    /// answers, so a controller that never agrees is refused rather than waited
    /// on. A refusal leaves the device wherever the failing step left it: there
    /// is no state to unwind to, because the state before the call is whatever
    /// the firmware left and is no better.
    pub fn initialise(&mut self) -> Result<Transmitter<'_, P>, InitError> {
        match self.program() {
            Ok(()) => Ok(Transmitter { uart: self }),
            Err(error) => {
                self.stats.init_failures = self.stats.init_failures.saturating_add(1);
                Err(error)
            }
        }
    }

    /// A snapshot of the counters, including those of a refused initialisation.
    #[must_use]
    pub const fn stats(&self) -> UartStats {
        self.stats
    }

    /// The register sequence, each step confirmed by a readback before the next
    /// is attempted.
    ///
    /// Confirming every step is what turns "the controller is absent" — which
    /// reads `0xFF` everywhere — and "the controller took the divisor and
    /// refused the word format" into two different errors instead of a console
    /// that emits nothing and says why nowhere.
    fn program(&mut self) -> Result<(), InitError> {
        self.port.write(Register::InterruptEnable, IER_ALL_DISABLED);
        let read_back = self.port.read(Register::InterruptEnable);
        if read_back != IER_ALL_DISABLED {
            return Err(InitError::InterruptsNotDisabled { read_back });
        }

        self.port.write(Register::LineControl, LCR_DLAB);
        let read_back = self.port.read(Register::LineControl);
        if read_back != LCR_DLAB {
            return Err(InitError::DlabNotLatched { read_back });
        }

        // Offsets 0 and 1 address the divisor latches for as long as the bit
        // confirmed above stays set, which is why the word format below is
        // written with it still set and cleared only afterwards.
        let [low, high] = DIVISOR.to_le_bytes();
        self.port.write(Register::Data, low);
        self.port.write(Register::InterruptEnable, high);
        let read_back = u16::from_le_bytes([
            self.port.read(Register::Data),
            self.port.read(Register::InterruptEnable),
        ]);
        if read_back != DIVISOR {
            return Err(InitError::DivisorNotAccepted {
                wrote: DIVISOR,
                read_back,
            });
        }

        let wrote = LCR_8N1 | LCR_DLAB;
        self.port.write(Register::LineControl, wrote);
        let read_back = self.port.read(Register::LineControl);
        if read_back != wrote {
            return Err(InitError::WordFormatNotAccepted { wrote, read_back });
        }

        self.confirm_fifos()?;

        self.port.write(Register::LineControl, LCR_8N1);
        let read_back = self.port.read(Register::LineControl);
        if read_back != LCR_8N1 {
            return Err(InitError::DlabNotCleared { read_back });
        }
        Ok(())
    }

    /// Enable and empty the FIFOs, then wait — bounded by [`FIFO_POLL_LIMIT`] —
    /// for the controller to report them enabled.
    ///
    /// The FIFO-control register is write-only, so this step is confirmed
    /// through a different register than it wrote — and one that answers
    /// without ever agreeing needs a bound, where a readback that merely
    /// disagrees is judged on the first read.
    fn confirm_fifos(&mut self) -> Result<(), InitError> {
        self.port.write(Register::FifoControl, FCR_PROGRAMMED);
        let mut iir = 0;
        for _ in 0..FIFO_POLL_LIMIT {
            iir = self.port.read(Register::FifoControl);
            if iir & IIR_FIFOS_ENABLED == IIR_FIFOS_ENABLED {
                return Ok(());
            }
        }
        Err(InitError::FifosNotEnabled {
            polls: FIFO_POLL_LIMIT,
            iir,
        })
    }
}

/// A programmed controller, borrowed from the [`Uart`] that owns the counters.
///
/// The borrow is what keeps the counters reachable across a refused
/// initialisation: a caller that is told its console is unusable still holds the
/// [`Uart`], and [`Uart::stats`] still answers.
pub struct Transmitter<'uart, P> {
    uart: &'uart mut Uart<P>,
}

impl<P: PortIo> Transmitter<'_, P> {
    /// Hand one byte to the transmitter, waiting — bounded by
    /// [`THRE_POLL_LIMIT`] — for it to report itself empty first.
    ///
    /// Bounded by [`WRITE_PORT_OPS_MAX`] port operations whatever the device
    /// answers. Exhaustion drops the byte and counts it: this is the last-resort
    /// diagnostic channel, and a controller that stops accepting bytes must cost
    /// the domain its output rather than its liveness.
    pub fn write_byte(&mut self, byte: u8) -> Result<(), WriteError> {
        for _ in 0..THRE_POLL_LIMIT {
            if self.uart.port.read(Register::LineStatus) & LSR_THRE != 0 {
                self.uart.port.write(Register::Data, byte);
                self.uart.stats.bytes_written = self.uart.stats.bytes_written.saturating_add(1);
                return Ok(());
            }
        }
        self.uart.stats.thre_timeouts = self.uart.stats.thre_timeouts.saturating_add(1);
        Err(WriteError::TransmitterNeverReady {
            polls: THRE_POLL_LIMIT,
        })
    }

    /// Hand every byte over in order, stopping at the first refusal.
    ///
    /// The bound is `bytes.len()` times [`WRITE_PORT_OPS_MAX`], and `bytes` is a
    /// first-party slice — a rendered console record — not anything the device
    /// chose, so the loop is bounded by the caller and each iteration by
    /// [`write_byte`](Self::write_byte). How much of the slice reached the
    /// device before a refusal is the difference in
    /// [`bytes_written`](UartStats::bytes_written) across the call.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), WriteError> {
        for byte in bytes {
            self.write_byte(*byte)?;
        }
        Ok(())
    }

    /// A snapshot of the counters; see [`Uart::stats`], which this borrow
    /// forbids reaching directly while the transmitter is alive.
    #[must_use]
    pub const fn stats(&self) -> UartStats {
        self.uart.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_port::{FakePort, Log, Op};
    use proptest::prelude::*;
    use std::vec;
    use std::vec::Vec;

    /// The write of a register, and the read that confirms it — the pair every
    /// verified step of the sequence is made of.
    fn verified(register: Register, wrote: u8, read: u8) -> Vec<Op> {
        vec![
            Op::Write {
                register,
                value: wrote,
            },
            Op::Read {
                register,
                value: read,
            },
        ]
    }

    /// Every port operation a conforming controller sees during
    /// initialisation, in order. Each step is one entry of this list, so a test
    /// asserting a prefix of it asserts that step and everything before it.
    fn conforming_sequence() -> Vec<Op> {
        let mut expected = Vec::new();
        // 1. Interrupts off.
        expected.extend(verified(Register::InterruptEnable, IER_ALL_DISABLED, 0x00));
        // 2. Divisor latches addressable.
        expected.extend(verified(Register::LineControl, LCR_DLAB, LCR_DLAB));
        // 3. The divisor itself, low byte then high, then both read back.
        expected.push(Op::Write {
            register: Register::Data,
            value: 0x01,
        });
        expected.push(Op::Write {
            register: Register::InterruptEnable,
            value: 0x00,
        });
        expected.push(Op::Read {
            register: Register::Data,
            value: 0x01,
        });
        expected.push(Op::Read {
            register: Register::InterruptEnable,
            value: 0x00,
        });
        // 4. 8N1, with the latch bit still set.
        expected.extend(verified(
            Register::LineControl,
            LCR_8N1 | LCR_DLAB,
            LCR_8N1 | LCR_DLAB,
        ));
        // 5. FIFOs enabled and emptied, confirmed through the IIR.
        expected.push(Op::Write {
            register: Register::FifoControl,
            value: FCR_PROGRAMMED,
        });
        expected.push(Op::Read {
            register: Register::FifoControl,
            value: IIR_FIFOS_ENABLED,
        });
        // 6. The latch bit cleared, so offset 0 is the transmitter again.
        expected.extend(verified(Register::LineControl, LCR_8N1, LCR_8N1));
        expected
    }

    /// Initialise against a fake, returning the log and the outcome. The
    /// transmitter is dropped: tests that write take [`ready`] instead.
    fn initialise(port: FakePort) -> (Log, Result<(), InitError>, UartStats) {
        let log = port.log();
        let mut uart = Uart::new(port);
        let outcome = uart.initialise().map(|_| ());
        (log, outcome, uart.stats())
    }

    #[test]
    fn every_register_addresses_the_port_the_datasheet_puts_it_at() {
        // The claim `pds/console`'s capability probe rests on: the OR that
        // forms an address is an addition onto the base, and every address it
        // can form lies inside the granted window. Asserted rather than
        // argued, because an OR that is not an addition addresses a register
        // the driver did not ask for — silently, and identically on a
        // conforming part.
        for register in Register::ALL {
            let port = register.port();
            assert_eq!(port, COM1_BASE + u16::from(register.offset()));
            assert!((COM1_BASE..COM1_BASE + PORT_COUNT).contains(&port));
        }
    }

    #[test]
    fn every_register_is_in_all() {
        // `Register::ALL` is what a `PortIo` implementation probes its
        // authority against, so a variant missing from it is a port the
        // console would reach having proven nothing about it. The match is
        // exhaustive, so a new variant fails to compile until it is listed;
        // this then fails until it is listed *here*.
        for register in [
            Register::Data,
            Register::InterruptEnable,
            Register::FifoControl,
            Register::LineControl,
            Register::LineStatus,
        ] {
            let listed = match register {
                Register::Data
                | Register::InterruptEnable
                | Register::FifoControl
                | Register::LineControl
                | Register::LineStatus => Register::ALL.contains(&register),
            };
            assert!(listed, "{register:?} is missing from Register::ALL");
        }
        assert_eq!(Register::ALL.len(), 5);
    }

    #[test]
    fn a_conforming_controller_is_programmed_in_the_order_the_part_requires() {
        let (log, outcome, stats) = initialise(FakePort::conforming());
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            log.ops(),
            conforming_sequence(),
            "interrupts off, latch, divisor, word format, FIFOs, latch cleared"
        );
        assert_eq!(stats, UartStats::default());
    }

    #[test]
    fn the_recorded_fixed_operation_count_is_what_the_sequence_actually_costs() {
        // INIT_PORT_OPS_MAX is what every termination proof below rests on, and
        // its fixed part is a number nothing else would falsify. A conforming
        // controller answers the FIFO poll on the first read, so the whole run
        // is the fixed part plus exactly one poll.
        let (log, outcome, _) = initialise(FakePort::conforming());
        assert_eq!(outcome, Ok(()));
        assert_eq!(log.len() as u32, INIT_FIXED_PORT_OPS + 1);
        assert!(log.len() as u32 <= INIT_PORT_OPS_MAX);
    }

    #[test]
    fn the_divisor_is_the_one_that_yields_115200_baud_from_the_reference_clock() {
        assert_eq!(DIVISOR, 1);
        assert_eq!(
            REFERENCE_CLOCK_HZ / (CLOCK_TICKS_PER_BIT * u32::from(DIVISOR)),
            BAUD_RATE
        );
        // And it is what the sequence actually programs, low byte first.
        let (log, _, _) = initialise(FakePort::conforming());
        let written: Vec<u8> = log
            .ops()
            .iter()
            .skip_while(|op| {
                *op != &Op::Write {
                    register: Register::LineControl,
                    value: LCR_DLAB,
                }
            })
            .filter_map(|op| match op {
                Op::Write {
                    register: Register::Data | Register::InterruptEnable,
                    value,
                } => Some(*value),
                _ => None,
            })
            .collect();
        assert_eq!(written, DIVISOR.to_le_bytes());
    }

    #[test]
    fn a_controller_that_will_not_clear_its_interrupt_enable_is_refused_first() {
        // The first step, and so where an absent controller — every port
        // reading 0xFF — surfaces before anything else has been written.
        let (log, outcome, stats) =
            initialise(FakePort::conforming().misreporting(Register::InterruptEnable, 0xFF));
        assert_eq!(
            outcome,
            Err(InitError::InterruptsNotDisabled { read_back: 0xFF })
        );
        assert_eq!(
            log.ops(),
            verified(Register::InterruptEnable, IER_ALL_DISABLED, 0xFF),
            "nothing may be written after the step that failed"
        );
        assert_eq!(stats.init_failures, 1);
    }

    #[test]
    fn a_controller_that_will_not_latch_the_divisor_access_bit_is_refused() {
        let (log, outcome, stats) =
            initialise(FakePort::conforming().misreporting(Register::LineControl, 0x00));
        assert_eq!(outcome, Err(InitError::DlabNotLatched { read_back: 0x00 }));
        let mut expected = verified(Register::InterruptEnable, IER_ALL_DISABLED, 0x00);
        expected.extend(verified(Register::LineControl, LCR_DLAB, 0x00));
        assert_eq!(log.ops(), expected, "the divisor is never written");
        assert_eq!(stats.init_failures, 1);
    }

    #[test]
    fn a_controller_that_will_not_hold_the_divisor_is_refused_with_what_it_answered() {
        let (log, outcome, stats) =
            initialise(FakePort::conforming().misreporting(Register::Data, 0xAA));
        assert_eq!(
            outcome,
            Err(InitError::DivisorNotAccepted {
                wrote: DIVISOR,
                read_back: 0x00AA,
            })
        );
        // Both latch bytes are written and both are read back before the
        // verdict: a controller that holds one and drops the other is a
        // controller at the wrong baud rate, not half-programmed.
        assert_eq!(log.len(), 4 + 4);
        assert_eq!(stats.init_failures, 1);
    }

    #[test]
    fn a_controller_that_will_not_take_the_word_format_is_refused() {
        // It reports the latch bit — so the divisor was programmable — and
        // then reports it alone, refusing the eight-bit word.
        let (log, outcome, stats) =
            initialise(FakePort::conforming().misreporting(Register::LineControl, LCR_DLAB));
        assert_eq!(
            outcome,
            Err(InitError::WordFormatNotAccepted {
                wrote: LCR_8N1 | LCR_DLAB,
                read_back: LCR_DLAB,
            })
        );
        assert!(
            !log.ops().iter().any(|op| matches!(
                op,
                Op::Write {
                    register: Register::FifoControl,
                    ..
                }
            )),
            "the FIFOs are not touched on a controller whose word format is unknown"
        );
        assert_eq!(stats.init_failures, 1);
    }

    #[test]
    fn a_controller_whose_fifos_never_come_up_is_refused_after_a_bounded_wait() {
        // The "reset never completes" device: it answers every read, forever,
        // and never agrees. It must cost a bounded number of reads, not the
        // domain.
        let (log, outcome, stats) = initialise(FakePort::conforming().never_enabling_fifos());
        assert_eq!(
            outcome,
            Err(InitError::FifosNotEnabled {
                polls: FIFO_POLL_LIMIT,
                iir: 0x00,
            })
        );
        let polls = log
            .ops()
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    Op::Read {
                        register: Register::FifoControl,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(polls as u32, FIFO_POLL_LIMIT);
        assert!(log.len() as u32 <= INIT_PORT_OPS_MAX);
        assert_eq!(stats.init_failures, 1);
    }

    #[test]
    fn a_controller_that_will_not_release_the_divisor_access_bit_is_refused_last() {
        // Every earlier step agrees; only the final clear does not. Unrefused,
        // offset 0 would still address the divisor latch and no byte written
        // would ever leave the part.
        let (log, outcome, stats) = initialise(FakePort::conforming().never_clearing_dlab());
        assert_eq!(
            outcome,
            Err(InitError::DlabNotCleared {
                read_back: LCR_8N1 | LCR_DLAB,
            })
        );
        assert_eq!(log.len() as u32, INIT_FIXED_PORT_OPS + 1);
        assert_eq!(stats.init_failures, 1);
    }

    #[test]
    fn each_refused_step_reaches_the_operator_as_its_own_error() {
        // ENG-12: six ways for a controller to be unusable must not collapse
        // into one console line. Each is driven to its own variant, and no two
        // are equal.
        let refusals = [
            initialise(FakePort::conforming().misreporting(Register::InterruptEnable, 0xFF)).1,
            initialise(FakePort::conforming().misreporting(Register::LineControl, 0x00)).1,
            initialise(FakePort::conforming().misreporting(Register::Data, 0xAA)).1,
            initialise(FakePort::conforming().misreporting(Register::LineControl, LCR_DLAB)).1,
            initialise(FakePort::conforming().never_enabling_fifos()).1,
            initialise(FakePort::conforming().never_clearing_dlab()).1,
        ];
        for (index, outcome) in refusals.iter().enumerate() {
            assert!(outcome.is_err(), "refusal {index} must be an error");
            for other in refusals.iter().skip(index + 1) {
                assert_ne!(outcome, other);
            }
        }
    }

    #[test]
    fn a_slow_controller_is_accepted_at_the_last_poll_the_bound_permits() {
        // The boundary itself: the FIFOs come up on the final read the loop is
        // allowed to make.
        let (log, outcome, stats) =
            initialise(FakePort::conforming().enabling_fifos_after(FIFO_POLL_LIMIT - 1));
        assert_eq!(outcome, Ok(()));
        assert_eq!(log.len() as u32, INIT_PORT_OPS_MAX);
        assert_eq!(stats.init_failures, 0);
    }

    #[test]
    fn a_controller_one_poll_slower_than_the_bound_is_refused() {
        // One past the boundary. The two tests together pin the bound to
        // FIFO_POLL_LIMIT rather than to "eventually".
        let (log, outcome, _) =
            initialise(FakePort::conforming().enabling_fifos_after(FIFO_POLL_LIMIT));
        assert_eq!(
            outcome,
            Err(InitError::FifosNotEnabled {
                polls: FIFO_POLL_LIMIT,
                iir: 0x00,
            })
        );
        // The whole poll budget was spent and then the sequence stopped: two
        // operations short of the ceiling, which are step 6's, never made.
        assert_eq!(log.len() as u32, INIT_PORT_OPS_MAX - 2);
    }

    /// Initialise a conforming-until-programmed fake and run `body` against the
    /// transmitter, returning the log and the final counters.
    fn ready(
        port: FakePort,
        body: impl FnOnce(&mut Transmitter<'_, FakePort>),
    ) -> (Log, UartStats) {
        let log = port.log();
        let mut uart = Uart::new(port);
        {
            let mut transmitter = uart.initialise().expect("the fake accepts the sequence");
            log.take();
            body(&mut transmitter);
        }
        (log, uart.stats())
    }

    #[test]
    fn a_byte_is_written_only_after_the_transmitter_reports_itself_empty() {
        let (log, stats) = ready(FakePort::conforming(), |transmitter| {
            assert_eq!(transmitter.write_byte(b'A'), Ok(()));
        });
        assert_eq!(
            log.ops(),
            vec![
                Op::Read {
                    register: Register::LineStatus,
                    value: LSR_THRE,
                },
                Op::Write {
                    register: Register::Data,
                    value: b'A',
                },
            ]
        );
        assert_eq!(stats.bytes_written, 1);
        assert_eq!(stats.thre_timeouts, 0);
    }

    #[test]
    fn a_transmitter_that_never_empties_costs_a_bounded_number_of_reads_and_the_byte() {
        // The hostile device this crate exists to survive: it never asserts
        // THRE. The write must return, drop the byte, count it, and never
        // reach the data register.
        let (log, stats) = ready(
            FakePort::conforming().never_asserting_thre(),
            |transmitter| {
                assert_eq!(
                    transmitter.write_byte(b'A'),
                    Err(WriteError::TransmitterNeverReady {
                        polls: THRE_POLL_LIMIT,
                    })
                );
            },
        );
        assert_eq!(log.len() as u32, THRE_POLL_LIMIT);
        assert!(log.len() as u32 <= WRITE_PORT_OPS_MAX);
        assert!(
            !log.ops().iter().any(|op| matches!(
                op,
                Op::Write {
                    register: Register::Data,
                    ..
                }
            )),
            "no byte may be handed to a transmitter that never reported itself empty"
        );
        assert_eq!(stats.bytes_written, 0);
        assert_eq!(stats.thre_timeouts, 1);
    }

    #[test]
    fn a_transmitter_that_empties_on_the_last_permitted_read_still_takes_the_byte() {
        let (log, stats) = ready(
            FakePort::conforming().asserting_thre_after(THRE_POLL_LIMIT - 1),
            |transmitter| assert_eq!(transmitter.write_byte(b'Z'), Ok(())),
        );
        assert_eq!(log.len() as u32, WRITE_PORT_OPS_MAX);
        assert_eq!(stats.bytes_written, 1);
        assert_eq!(stats.thre_timeouts, 0);
    }

    #[test]
    fn a_transmitter_one_read_slower_than_the_bound_loses_the_byte() {
        let (log, stats) = ready(
            FakePort::conforming().asserting_thre_after(THRE_POLL_LIMIT),
            |transmitter| {
                assert_eq!(
                    transmitter.write_byte(b'Z'),
                    Err(WriteError::TransmitterNeverReady {
                        polls: THRE_POLL_LIMIT,
                    })
                );
            },
        );
        assert_eq!(log.len() as u32, THRE_POLL_LIMIT);
        assert_eq!(stats.bytes_written, 0);
        assert_eq!(stats.thre_timeouts, 1);
    }

    #[test]
    fn arbitrary_line_status_bytes_gate_the_write_on_one_bit_and_nothing_else() {
        // A controller answering whatever it likes on every line-status read.
        // Only bit 5 may decide, so a byte with it set is taken however many
        // other bits — framing, parity, overrun, break — are set with it.
        let (log, stats) = ready(
            FakePort::conforming().with_line_status(vec![0x00, 0xDF, 0x01, 0xFF]),
            |transmitter| assert_eq!(transmitter.write_byte(b'x'), Ok(())),
        );
        // 0x00, 0xDF and 0x01 all have bit 5 clear; 0xFF is the first with it
        // set, so four reads and then the write.
        assert_eq!(log.len(), 5);
        assert_eq!(stats.bytes_written, 1);
    }

    #[test]
    fn a_register_answering_differently_on_every_read_never_forges_a_ready_transmitter() {
        // A device whose line status alternates: the write happens on a read
        // that actually carried the bit, and the count of writes is the count
        // of bytes, never more.
        let (log, stats) = ready(
            FakePort::conforming().with_line_status(vec![0x00, LSR_THRE]),
            |transmitter| {
                assert_eq!(transmitter.write_bytes(b"ab"), Ok(()));
            },
        );
        let writes = log
            .ops()
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    Op::Write {
                        register: Register::Data,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(writes, 2);
        assert_eq!(stats.bytes_written, 2);
        // Two reads per byte: the alternation makes every other one refuse.
        assert_eq!(log.len(), 6);
    }

    #[test]
    fn a_burst_stops_at_the_first_refusal_and_says_how_much_got_out() {
        // The FIFO takes the first byte and the controller then wedges. The
        // slice is not retried and the difference in bytes_written is what
        // reached the device.
        let (_, stats) = ready(
            FakePort::conforming()
                .asserting_thre_after(0)
                .wedging_after(1),
            |transmitter| {
                assert_eq!(
                    transmitter.write_bytes(b"abc"),
                    Err(WriteError::TransmitterNeverReady {
                        polls: THRE_POLL_LIMIT,
                    })
                );
            },
        );
        assert_eq!(stats.bytes_written, 1);
        assert_eq!(stats.thre_timeouts, 1);
    }

    #[test]
    fn an_empty_burst_does_not_touch_the_device_at_all() {
        let (log, stats) = ready(FakePort::conforming(), |transmitter| {
            assert_eq!(transmitter.write_bytes(&[]), Ok(()));
        });
        assert_eq!(log.len(), 0);
        assert_eq!(stats.bytes_written, 0);
    }

    #[test]
    fn the_counters_saturate_rather_than_wrap_at_the_top() {
        // A wrap would turn a sustained fault back into a small number
        // exactly when the number matters, so the top is a fixed point.
        let mut uart = Uart::new(FakePort::conforming().never_asserting_thre());
        uart.stats = UartStats {
            bytes_written: u64::MAX,
            thre_timeouts: u64::MAX,
            init_failures: u64::MAX,
        };
        {
            let mut transmitter = uart.initialise().expect("the fake accepts the sequence");
            assert!(transmitter.write_byte(b'!').is_err());
            assert_eq!(transmitter.stats().thre_timeouts, u64::MAX);
        }
        let mut refusing = Uart::new(FakePort::conforming().never_enabling_fifos());
        refusing.stats.init_failures = u64::MAX;
        assert!(refusing.initialise().is_err());
        assert_eq!(refusing.stats().init_failures, u64::MAX);
    }

    #[test]
    fn a_write_counts_toward_the_bytes_written_only_when_it_reached_the_device() {
        let mut uart = Uart::new(
            FakePort::conforming()
                .asserting_thre_after(0)
                .wedging_after(2),
        );
        let mut transmitter = uart.initialise().expect("the fake accepts the sequence");
        assert_eq!(transmitter.write_byte(1), Ok(()));
        assert_eq!(transmitter.write_byte(2), Ok(()));
        assert!(transmitter.write_byte(3).is_err());
        assert_eq!(
            transmitter.stats(),
            UartStats {
                bytes_written: 2,
                thre_timeouts: 1,
                init_failures: 0,
            }
        );
    }

    #[test]
    fn the_fifo_depth_a_caller_bounds_a_burst_by_is_the_one_the_sequence_enables() {
        // FCR bit 0 is what turns the FIFOs on, and FIFO_DEPTH is the 16550A's
        // depth. A caller sizing a burst by the const is sizing it by what the
        // sequence actually programmed.
        assert_eq!(FIFO_DEPTH, 16);
        assert_eq!(FCR_PROGRAMMED & 0x01, 0x01);
        let (log, outcome, _) = initialise(FakePort::conforming());
        assert_eq!(outcome, Ok(()));
        assert!(log.ops().contains(&Op::Write {
            register: Register::FifoControl,
            value: FCR_PROGRAMMED,
        }));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// The termination property, and the one that matters most: whatever a
        /// controller answers — to every register, differently on every read —
        /// initialisation returns, and returns having made no more port
        /// operations than the named bound admits. A device that could make it
        /// spin would hang this test rather than fail it, which is precisely
        /// the failure mode being excluded.
        #[test]
        fn initialisation_terminates_within_its_bound_for_any_device_answers(
            answers in prop::collection::vec(any::<u8>(), 1..48),
        ) {
            let port = FakePort::conforming().answering(answers);
            let log = port.log();
            let mut uart = Uart::new(port);
            let outcome = uart.initialise().map(|_| ());
            prop_assert!(log.len() as u32 <= INIT_PORT_OPS_MAX);
            // A refusal is counted exactly once, and a success not at all.
            prop_assert_eq!(uart.stats().init_failures, u64::from(outcome.is_err()));
        }

        /// The same property for the write path, over a controller whose line
        /// status is arbitrary and changes on every read.
        #[test]
        fn a_write_terminates_within_its_bound_for_any_line_status(
            status in prop::collection::vec(any::<u8>(), 1..48),
            byte in any::<u8>(),
        ) {
            let port = FakePort::conforming().with_line_status(status.clone());
            let log = port.log();
            let mut uart = Uart::new(port);
            {
                let mut transmitter = uart.initialise().expect("the fake accepts the sequence");
                log.take();
                let outcome = transmitter.write_byte(byte);
                // The bit is the whole decision: the byte is taken exactly when
                // some answer in the cycle carries it.
                prop_assert_eq!(
                    outcome.is_ok(),
                    status.iter().any(|value| value & LSR_THRE != 0)
                );
            }
            prop_assert!(log.len() as u32 <= WRITE_PORT_OPS_MAX);
            let stats = uart.stats();
            prop_assert_eq!(stats.bytes_written + stats.thre_timeouts, 1);
        }

        /// A burst over an arbitrary controller is bounded by the caller's own
        /// slice length times the per-byte bound, and never writes more bytes
        /// than it was given.
        #[test]
        fn a_burst_is_bounded_by_the_slice_and_the_per_byte_bound(
            status in prop::collection::vec(any::<u8>(), 1..8),
            bytes in prop::collection::vec(any::<u8>(), 0..FIFO_DEPTH),
        ) {
            let port = FakePort::conforming().with_line_status(status);
            let log = port.log();
            let mut uart = Uart::new(port);
            {
                let mut transmitter = uart.initialise().expect("the fake accepts the sequence");
                log.take();
                let _ = transmitter.write_bytes(&bytes);
            }
            let ceiling = bytes.len() as u64 * u64::from(WRITE_PORT_OPS_MAX);
            prop_assert!(log.len() as u64 <= ceiling);
            prop_assert!(uart.stats().bytes_written <= bytes.len() as u64);
        }

        /// Every port operation the driver makes, on any path, names a register
        /// inside the granted window — the property the `<ioport>` grant is
        /// sized against.
        #[test]
        fn every_port_operation_stays_inside_the_granted_window(
            answers in prop::collection::vec(any::<u8>(), 1..48),
            byte in any::<u8>(),
        ) {
            let port = FakePort::conforming().answering(answers);
            let log = port.log();
            let mut uart = Uart::new(port);
            if let Ok(mut transmitter) = uart.initialise() {
                let _ = transmitter.write_byte(byte);
            }
            for op in log.ops() {
                let offset = match op {
                    Op::Read { register, .. } | Op::Write { register, .. } => register.offset(),
                };
                prop_assert!(u16::from(offset) < PORT_COUNT);
            }
        }
    }
}
