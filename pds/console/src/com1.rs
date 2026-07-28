//! The COM1 controller as a protection domain reaches it: an seL4 I/O-port
//! capability invocation, behind `uart_16550`'s [`PortIo`] seam.
//!
//! # Adversary
//!
//! CONCEPT §7.1's **hostile or malfunctioning device** — the controller, which
//! may answer anything or never answer. Nothing here judges it: every byte goes
//! straight to `uart_16550`, which bounds each wait and confirms each step by
//! readback. No peer domain and no network byte reaches this path.
//!
//! # Why an invocation, and not `in`/`out`
//!
//! seL4 leaves the TSS I/O permission bitmap denying every port and never edits
//! it, so `in`/`out` in a protection domain raises #GP however the capability
//! space is arranged: the `<ioport>` grant makes the *invocation* legal, not
//! the *instruction*. This domain's first boot faulted at exactly that — `out
//! %al,(%dx)` against 0x3F9, the first write of the UART init sequence — with
//! the grant present and correct. `seL4_X86_IOPort_In8`/`Out8` are the only way
//! through, and rust-sel4 exposes both as safe Rust, so this file has no
//! `unsafe`.
//!
//! # Why the slot number is written out here
//!
//! `sel4-microkit` publishes a `Channel` for every capability class a domain
//! can be granted except this one: `channel.rs` declares
//! `BASE_OUTPUT_NOTIFICATION_SLOT`, `BASE_ENDPOINT_SLOT`, `BASE_IRQ_SLOT` and
//! `BASE_TCB_SLOT` but no ioport base, and the one ioport symbol it reads —
//! `pd_ioports` in `sel4-microkit/base/src/symbols.rs:175` — is `pub(crate)`
//! and `dead_code`. ENG-8 says prefer the framework; there is nothing to
//! prefer, so the slot is stated below and [`Com1::claim`] proves it.
//!
//! **Rejected: re-declaring `microkit_ioports`** to read the grant bitmask the
//! Microkit tool patches into the image. It is a `pub(crate)` framework
//! internal, reaching it needs `unsafe` (ENG-13), and the only case it uniquely
//! catches — an *empty* slot, which cap-faults rather than returning an error —
//! already reaches an operator as the monitor's `faulting PD: console`. Copying
//! an internal to make a loud failure quieter is a poor trade.

use sel4::sys::{seL4_CPtr, seL4_Error};
use uart_16550::{PortIo, Register};

/// Microkit's CNode slot for a domain's first I/O-port capability.
///
/// **Cross-artifact (DOC-7).** Nothing here can check this at build time: the
/// Microkit tool chooses it and emits no header for it. Two things enforce it.
///
/// *Detection* is the pinned SDK. `MICROKIT_VERSION=2.3.0` in
/// `third-party/sources.lock` is checksum-verified on every build (DEP-1) and
/// moves only through a change that runs the whole gate (DEP-3); `xtask image`
/// then writes the slot that SDK actually assigned into
/// `build/image/<config>/report.txt`, where `ioports_0x3f8_console` stands at
/// slot 394 — which is where this number came from and what a reviewer rereads
/// it against. That report is generated, so it moves when the tool does.
///
/// *Enforcement* is [`Com1::claim`], which invokes the capability before this
/// domain relies on it, so a slot that moved is refused by name rather than
/// met as a fault in the middle of a console line.
const BASE_IOPORT_SLOT: seL4_CPtr = 394;

/// The `id` of the `<ioport id="0" addr="0x3f8" size="8" />` element on the
/// console domain in `systems/qemu-x86_64/librefirewall.system:436` — this
/// grant's index within the ioport bank.
const COM1_IOPORT_ID: seL4_CPtr = 0;

/// The capability this domain invokes to reach COM1.
const COM1_IOPORT: seL4_CPtr = BASE_IOPORT_SLOT + COM1_IOPORT_ID;

/// Why the I/O-port capability was not accepted.
///
/// It carries the refused port and the kernel's own verdict because the fixes
/// differ: a wrong capability type means [`BASE_IOPORT_SLOT`] no longer matches
/// the SDK, a range refusal means the `<ioport>` element no longer covers what
/// `uart_16550` addresses, and neither is diagnosable from "the node printed
/// nothing".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortFault {
    /// The port the probe was refused on.
    pub port: u16,
    /// What the kernel answered.
    pub error: seL4_Error::Type,
}

/// The COM1 controller, reached by invoking this domain's I/O-port capability.
///
/// It carries neither base address nor capability pointer: both are fixed by
/// the system description (CONCEPT §12.3), so a field would be a second,
/// unchecked statement of [`COM1_IOPORT`] and of `uart_16550`'s `COM1_BASE`.
/// The private unit field makes [`claim`](Self::claim) — and so the probe —
/// the only way to obtain one.
pub struct Com1(());

impl Com1 {
    /// Prove the capability answers for every port the driver can address, and
    /// take it.
    ///
    /// This is the check that replaces a #GP with a verdict (ENG-12). It reads
    /// each register in [`Register::ALL`], which is the driver's entire demand
    /// — `uart_16550` can ask [`PortIo`] for nothing else, and
    /// `every_register_is_in_all` holds that list exhaustive — so success means
    /// every later invocation is one the kernel has already accepted at that
    /// port.
    ///
    /// Reads, not writes: a write probe must invent a value, and at offset 0
    /// that value is transmitted. One range check covers both directions (seL4
    /// 16.0.0 `decodeX86PortInvocation`) — third-party runtime behaviour, so it
    /// is recorded rather than asserted, being the one step of the argument
    /// this domain cannot make for itself.
    ///
    /// The reads are harmless before programming: offset 0 pops a receive FIFO
    /// nothing has filled, offset 5 clears line-status bits the driver has not
    /// consulted, and the rest are read-only.
    ///
    /// # Errors
    /// [`PortFault`] naming the first refused port and the kernel's verdict.
    pub fn claim() -> Result<Self, PortFault> {
        for register in Register::ALL {
            let port = register.port();
            if let Err(error) = in8(port) {
                return Err(PortFault { port, error });
            }
        }
        Ok(Self(()))
    }
}

impl PortIo for Com1 {
    /// A refused invocation answers `0xFF` — deliberate, not a fallback: it is
    /// what an absent controller answers, and the one value that makes
    /// `Uart::initialise` refuse at its first readback,
    /// `InterruptsNotDisabled { read_back: 0xFF }`, before anything is written.
    /// [`Com1::claim`] makes the path unreachable; it is written fail-closed
    /// rather than as a panic because a panicking domain is the opaque fault
    /// this file exists to remove.
    fn read(&mut self, register: Register) -> u8 {
        in8(register.port()).unwrap_or(0xFF)
    }

    /// A refused invocation drops the byte, for [`read`](Self::read)'s reason:
    /// the driver reads back every register it writes, so a dropped write
    /// surfaces as a readback disagreeing rather than as silence.
    fn write(&mut self, register: Register, value: u8) {
        let _ = out8(register.port(), value);
    }
}

/// Invoke `seL4_X86_IOPort_In8` and turn the kernel's verdict into a `Result`.
///
/// The verdict stays a raw code rather than becoming `sel4::Error`, which would
/// otherwise be the framework's type to prefer (ENG-8): `sel4::Error::from_sys`
/// panics on a code outside the ten it knows, and a diagnosis that faults on an
/// unfamiliar answer is the failure mode this file replaces.
fn in8(port: u16) -> Result<u8, seL4_Error::Type> {
    let answer = sel4::with_ipc_buffer_mut(|buffer| {
        buffer.inner_mut().seL4_X86_IOPort_In8(COM1_IOPORT, port)
    });
    if answer.error == seL4_Error::seL4_NoError {
        Ok(answer.result)
    } else {
        Err(answer.error)
    }
}

/// Invoke `seL4_X86_IOPort_Out8`; see [`in8`] on the verdict's type.
fn out8(port: u16, value: u8) -> Result<(), seL4_Error::Type> {
    let error = sel4::with_ipc_buffer_mut(|buffer| {
        buffer
            .inner_mut()
            .seL4_X86_IOPort_Out8(COM1_IOPORT, port.into(), value.into())
    });
    if error == seL4_Error::seL4_NoError {
        Ok(())
    } else {
        Err(error)
    }
}
