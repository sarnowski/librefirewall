//! The CMOS real-time clock as a protection domain reaches it: an seL4
//! I/O-port capability invocation, behind `lfw_rtc`'s [`CmosPortIo`] seam.
//!
//! # Adversary
//!
//! CONCEPT §7.1's **hostile or malfunctioning device** — the part, which may
//! answer anything or never settle. Nothing here judges it: every byte goes
//! straight to `lfw_rtc`, which bounds each wait, ranges each field, and takes
//! two agreeing snapshots before decoding anything. No peer domain and no
//! network byte reaches this path.
//!
//! # Why an invocation, and not `in`/`out`
//!
//! This file exists in the shape it does because `pds/console/src/com1.rs`
//! learned it the expensive way, and the lesson is exactly as true at 0x70 as
//! at 0x3F8: seL4 leaves the TSS I/O permission bitmap denying every port and
//! never edits it, so `in`/`out` in a protection domain raises #GP however the
//! capability space is arranged. **The `<ioport>` grant makes the *invocation*
//! legal, never the *instruction*.** The console's first boot faulted on
//! `out %al,(%dx)` with a grant that was present and correct.
//! `seL4_X86_IOPort_In8`/`Out8` are the only way through, and rust-sel4 exposes
//! both as safe Rust, so this file has no `unsafe`.
//!
//! # Why the slot number is written out here
//!
//! `sel4-microkit` publishes a `Channel` for every capability class a domain
//! can be granted except this one — `channel.rs` declares
//! `BASE_OUTPUT_NOTIFICATION_SLOT`, `BASE_ENDPOINT_SLOT`, `BASE_IRQ_SLOT` and
//! `BASE_TCB_SLOT` and no ioport base, and the one ioport symbol it reads is
//! `pub(crate)` and `dead_code`. ENG-8 says prefer the framework; there is
//! nothing to prefer, so the slot is stated below and [`Cmos::claim`] proves it.
//!
//! **The number is this domain's own, and it must be read as this domain's even
//! though it currently equals the console's.** Microkit 2.3.0 places a
//! protection domain's first ioport capability at a fixed slot in that domain's
//! own CNode, so both domains hold theirs at 394 and a reader is invited to
//! conclude the constant is a property of the tool rather than of the grant.
//! It is not one this file may rest on: what the tool guarantees is a slot in
//! *this* CNode, and the generated report is where it is read per domain. A
//! copy taken from `com1.rs` would be right today for a reason nobody checked.

use lfw_rtc::{CmosPortIo, DATA_PORT, INDEX_PORT, Register};
use sel4::sys::{seL4_CPtr, seL4_Error};

/// Microkit's CNode slot for this domain's first I/O-port capability.
///
/// **Cross-artifact (DOC-7).** Nothing here can check this at build time: the
/// Microkit tool chooses it and emits no header for it. Two things enforce it,
/// exactly as they do for the console's own slot.
///
/// *Detection* is the pinned SDK. `MICROKIT_VERSION=2.3.0` in
/// `third-party/sources.lock` is checksum-verified on every build (DEP-1) and
/// moves only through a change that runs the whole gate (DEP-3); `xtask image`
/// then writes the slot that SDK actually assigned into
/// `build/image/<config>/report.txt`, under `cnode_clock`, where
/// `ioports_0x70_clock` stands at slot 394 — which is where this number came
/// from and what a reviewer rereads it against, in that CNode and not in the
/// console's. That report is generated, so it moves when the tool does.
///
/// *Enforcement* is [`Cmos::claim`], which invokes the capability before this
/// domain relies on it, so a slot that moved is refused by name rather than met
/// as a fault in the middle of a calibration.
const BASE_IOPORT_SLOT: seL4_CPtr = 394;

/// The `id` of the `<ioport id="0" addr="0x70" size="2" />` element on the
/// clock domain in `systems/qemu-x86_64/librefirewall.system` — this grant's
/// index within the ioport bank.
const CMOS_IOPORT_ID: seL4_CPtr = 0;

/// The capability this domain invokes to reach the CMOS register file.
const CMOS_IOPORT: seL4_CPtr = BASE_IOPORT_SLOT + CMOS_IOPORT_ID;

/// Why the I/O-port capability was not accepted.
///
/// It carries the refused port and the kernel's own verdict because the fixes
/// differ: a wrong capability type means [`BASE_IOPORT_SLOT`] no longer matches
/// what the tool assigned this domain, a range refusal means the `<ioport>`
/// element no longer covers both ports `lfw_rtc` addresses, and neither is
/// diagnosable from "the node reported no time".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortFault {
    /// The port the probe was refused on.
    pub port: u16,
    /// What the kernel answered.
    pub error: seL4_Error::Type,
}

/// The CMOS register file, reached by invoking this domain's I/O-port
/// capability.
///
/// It carries neither port number nor capability pointer: both are fixed by the
/// system description (CONCEPT §12.3), so a field would be a second, unchecked
/// statement of [`CMOS_IOPORT`] and of `lfw_rtc`'s own port constants. The
/// private unit field makes [`claim`](Self::claim) — and so the probe — the
/// only way to obtain one.
pub struct Cmos(());

impl Cmos {
    /// Prove the capability answers for both ports the driver can address, and
    /// take it.
    ///
    /// This is the check that replaces a #GP with a verdict (ENG-12), and the
    /// window is the whole of `lfw_rtc`'s demand: [`INDEX_PORT`] and
    /// [`DATA_PORT`] are the only two addresses that crate forms, and its
    /// `PORT_COUNT` const-assertion holds them adjacent and the pair aligned.
    ///
    /// Reads, not writes, on `Com1::claim`'s reasoning: a write probe must
    /// invent a value, and at [`INDEX_PORT`] the value it invents selects a
    /// register — including, with bit 7 set, one that leaves the non-maskable
    /// interrupt disabled. One range check covers both directions (seL4 16.0.0
    /// `decodeX86PortInvocation`) — third-party runtime behaviour, so it is
    /// recorded rather than asserted, being the one step of the argument this
    /// domain cannot make for itself.
    ///
    /// The reads are harmless: the CMOS data register answers whichever
    /// register the firmware last selected and pops nothing, and the index
    /// register is an address latch rather than a value.
    ///
    /// # Errors
    /// [`PortFault`] naming the first refused port and the kernel's verdict.
    pub fn claim() -> Result<Self, PortFault> {
        for port in [INDEX_PORT, DATA_PORT] {
            if let Err(error) = in8(port) {
                return Err(PortFault { port, error });
            }
        }
        Ok(Self(()))
    }
}

impl CmosPortIo for Cmos {
    /// A refused invocation drops the index, which leaves the *previous*
    /// selection latched and so makes the following data read answer a register
    /// nobody asked for. That is not a silent fallback: `lfw_rtc` takes two
    /// snapshots and decodes only when they agree byte for byte, and a register
    /// file read through a stuck latch either disagrees or answers a status
    /// byte no time field can be, so the refusal surfaces as one of that
    /// crate's typed errors rather than as a plausible instant.
    /// [`Cmos::claim`] makes the path unreachable; it is written this way
    /// rather than as a panic because a panicking domain is the opaque fault
    /// this file exists to remove.
    fn write_index(&mut self, index: u8) {
        let _ = out8(INDEX_PORT, index);
    }

    /// A refused invocation answers `0xFF` — deliberate, not a fallback: it is
    /// what an unclaimed port answers, and `lfw_rtc` is written against exactly
    /// that reading. `0xFF` in status A holds the update-in-progress bit set
    /// forever, so the read is refused as `UpdateNeverCompleted` before any
    /// time field is looked at.
    fn read_data(&mut self) -> u8 {
        in8(DATA_PORT).unwrap_or(0xFF)
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
        buffer.inner_mut().seL4_X86_IOPort_In8(CMOS_IOPORT, port)
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
            .seL4_X86_IOPort_Out8(CMOS_IOPORT, port.into(), value.into())
    });
    if error == seL4_Error::seL4_NoError {
        Ok(())
    } else {
        Err(error)
    }
}

// The probe above is the whole of `lfw_rtc`'s demand only while that crate can
// address nothing outside the two ports it names, which is what these hold: the
// window is exactly the grant, and every register the crate can select is
// reached through the same two addresses.
const _: () = assert!(DATA_PORT == INDEX_PORT + 1);
const _: () = assert!(lfw_rtc::PORT_COUNT == 2);
// And the nine registers are addressed by index rather than by port, so the
// grant's width does not grow with the register map.
const _: () = assert!(Register::ALL.len() == 9);
