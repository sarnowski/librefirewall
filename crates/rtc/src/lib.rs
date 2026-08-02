//! The PC CMOS real-time clock at x86 I/O ports `0x70`/`0x71`: the index/data
//! protocol that reads it, and the decoding that turns its register file into
//! one Unix instant.
//!
//! It is read **once, at boot**, to establish the epoch a node's time is
//! anchored to; from there `lfw_clock::Calibration` advances time from the
//! timestamp counter, so no drift correction, no periodic re-read and no
//! comparison of two readings belongs here. The appliance's
//! trusted-time mechanism is a deliberately open question, and TLS certificate
//! validation depends on accurate time; this crate is the anchoring half of
//! what would settle that, and it exposes no signal of its own.
//!
//! # The adversary
//!
//! A **hostile or malfunctioning device**. Every byte here is one
//! the part chose: each time and date register, the century, and the two status
//! registers that say how the rest are encoded. A part that answers nothing —
//! an unclaimed port reads `0xFF` — is indistinguishable from one that answers
//! wrongly, and a part whose update cycle never completes is indistinguishable
//! from one whose update-in-progress bit is stuck high. All of it is met the
//! same way: the wait is bounded by a named constant of this crate's own
//! ([`UIP_POLL_LIMIT`], [`SNAPSHOT_ATTEMPTS`]) rather than by anything the
//! device reports, nothing is believed without being ranged, and every
//! refusal is its own [`RtcError`]. A clock that cannot be read must cost a
//! node its epoch and say so, not its liveness.
//!
//! # Why no port access lives here
//!
//! Reaching a port under seL4 means invoking an I/O-port capability at a CNode
//! slot Microkit assigns the domain — never `in`/`out`, which the kernel's TSS
//! bitmap faults regardless of the grant. No portable crate can hold that
//! authority, so [`CmosPortIo`] is the seam it is supplied behind, exactly as
//! `pds/console/src/com1.rs` supplies `uart_16550::PortIo`; that invocation is
//! safe Rust in `rust-sel4`, so neither side of the seam needs `unsafe` and
//! this one has none at all. The seam is also what makes the interesting
//! behaviours reachable from a host test: they are all *what the part answers*,
//! and no host can make a real one answer wrongly.
//!
//! # Why the index is written with the NMI bit clear
//!
//! Bit 7 of port `0x70` is not part of the CMOS address — it gates the
//! non-maskable interrupt, and a write leaves NMI *disabled* while it is set.
//! Every index this crate writes has it clear, so NMI is never disabled and
//! there is no window to re-enable it in; the alternative — mask, read, restore
//! — would need a saved bit that a fault between the two writes would lose,
//! leaving the machine unable to report a hardware error for the rest of its
//! uptime. The assertions beside [`Register::index`] are what hold the choice.
//!
//! # Why the register file is read as UTC
//!
//! **Decision.** The part is treated as holding UTC. It carries no field that
//! says whether it does: nothing in CMOS distinguishes a clock set to UTC from
//! one set to local time, so this cannot be discovered and must be assumed.
//! QEMU's default is `base=utc` and a UTC hardware clock is the server
//! convention. **Consequence:** on a machine whose firmware set the part to
//! local time the epoch established here is wrong by that zone's offset, in a
//! way no check in this crate can detect and no later reading would reveal —
//! and since certificate validity is judged against it, the failure surfaces as
//! a wrongly accepted or wrongly rejected certificate rather than as an error.
//!
//! # Why the century is validated rather than assumed
//!
//! The year register counts 0..=99, so a century has to come from somewhere.
//! CMOS register `0x32` is not in the MC146818 datasheet — ACPI's FADT names
//! the offset and every chipset that implements it stores the value in the
//! format status B selects, which is what QEMU's `mc146818rtc` does. Because it
//! is a convention rather than a specified register, the assembled year is
//! ranged against [`MIN_PLAUSIBLE_YEAR`] and [`MAX_PLAUSIBLE_YEAR`] and refused
//! outside it. Defaulting to `20xx` when the register looks wrong was rejected:
//! it would turn a part that answers `0x00` or `0xFF` into a confident,
//! plausible-looking epoch, the silent fallback that papers over a failure —
//! and an appliance with no epoch can be told so, while one with a wrong epoch
//! cannot tell anyone anything.
//!
//! # Rejected alternatives
//!
//! * **Restating the calendar ranges here.** Whether a day exists depends on
//!   the month and on the leap rule, so a check written beside this decoder
//!   would be a second statement of `lfw_clock`'s calendar and a second place
//!   for the four-century rule to be wrong. Every range a civil date has is
//!   decided by [`CivilTime::to_unix_seconds`] instead and reaches a caller as
//!   [`RtcError::NotACivilInstant`], which carries that verdict verbatim; what
//!   is decided here is only what `lfw_clock` cannot see — whether a byte is
//!   well-formed BCD, whether a 12-hour hour is in 1..=12, and whether the
//!   century yields a plausible year.
//! * **Consuming `self` on the read**, so that a second one could not be
//!   written. A refusal here is worth retrying — a boot that hit a part
//!   mid-update should ask again rather than give up its epoch — and "read
//!   once" is a property of the boot sequence, not of this type: nothing in the
//!   part changes because it was read.
//! * **Interrupt-driven waiting** on the update-ended interrupt in status C,
//!   instead of the bounded poll below. It would remove the polling, and it
//!   would introduce the system's first IRQ and a new capability class — a
//!   change to the capability topology, not to a driver.
//! * **Setting the part's mode** — writing status B to force binary, 24-hour
//!   values before reading. It would delete two decode paths, and it would make
//!   a boot-time read a boot-time *write* to the one device that carries state
//!   across a power cycle, on a part whose write behaviour mid-update is
//!   undefined. Honouring what the firmware chose costs two branches and no
//!   authority.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use lfw_clock::{CivilTime, CivilTimeError, UNIX_EPOCH_YEAR};

#[cfg(test)]
mod fake_port;

/// The x86 I/O port the CMOS address register decodes at: the register to be
/// read next is selected by writing its index here.
pub const INDEX_PORT: u16 = 0x70;

/// The x86 I/O port the CMOS data register decodes at, answering whichever
/// register [`INDEX_PORT`] last selected.
pub const DATA_PORT: u16 = 0x71;

/// Consecutive I/O ports the part occupies, and so the width an `<ioport>`
/// grant admitting a [`CmosPortIo`] implementation has to have.
///
/// **Cross-artifact fact:** the grant is the `clock` domain's `<ioport
/// id="0" addr="0x70" size="2" />` in `systems/qemu-x86_64/librefirewall.system`,
/// held to this constant by `xtask::sysdesc`'s `IO_PORTS` rule. The domain
/// enforces the match the way `pds/console/src/com1.rs` does, and `pds/clock`'s
/// `Cmos::claim` is where it does it: by invoking the capability for both ports
/// before relying on it.
pub const PORT_COUNT: u16 = 2;

const _: () = assert!(DATA_PORT - INDEX_PORT + 1 == PORT_COUNT);
const _: () = assert!(INDEX_PORT.is_multiple_of(PORT_COUNT));

/// Bit 7 of the byte written to [`INDEX_PORT`]: while set, the non-maskable
/// interrupt stays disabled.
const NMI_DISABLE: u8 = 0x80;

/// Status A bit 7, `UIP`: the part has begun or is about to begin an update, so
/// the time and date registers are in flux.
const STATUS_A_UIP: u8 = 0x80;

/// Status B bit 2, `DM`: set, the time and date registers hold plain binary;
/// clear, they hold packed decimal.
const STATUS_B_BINARY: u8 = 0x04;

/// Status B bit 1: set, the hours register counts 0..=23; clear, it counts
/// 1..=12 with [`HOURS_PM`] carrying the half of the day.
const STATUS_B_24_HOUR: u8 = 0x02;

/// Hours register bit 7, meaningful only while status B selects 12-hour
/// counting: set, the hour is in the afternoon.
const HOURS_PM: u8 = 0x80;

/// The earliest year the assembled century and year are accepted as naming.
///
/// The century register is an ACPI-era convention (see the crate header), so
/// there is no machine implementing it that predates 2000 — and the two values
/// an absent or dead register answers, `0x00` and `0xFF`, both land outside the
/// band, which is what makes the floor a check rather than a formality.
pub const MIN_PLAUSIBLE_YEAR: u16 = 2000;

/// The latest year the assembled century and year are accepted as naming.
///
/// Beyond any service life an appliance built now will have, and still two
/// orders of magnitude short of what a byte pair can express, so a garbled
/// century is refused rather than believed. It is a ceiling on plausibility and
/// not on the arithmetic: `lfw_clock` counts seconds well past it.
pub const MAX_PLAUSIBLE_YEAR: u16 = 2200;

// The floor is what keeps the epoch conversion from ever being asked for a
// pre-epoch year, and an empty band would refuse every reading.
const _: () = assert!(MIN_PLAUSIBLE_YEAR >= UNIX_EPOCH_YEAR);
const _: () = assert!(MIN_PLAUSIBLE_YEAR < MAX_PLAUSIBLE_YEAR);

/// Reads of status A one snapshot may make while waiting for the update in
/// progress bit to clear.
///
/// An MC146818-compatible part asserts the bit at most 244 µs before an update
/// begins and completes the update within 1984 µs, so 2.3 ms bounds the longest
/// wait a working part can impose. A read here is two port operations and a
/// legacy port access is at least a microsecond — slow on real hardware, and a
/// trap to the hypervisor under virtualization — so this is upwards of four
/// times that. It is a constant of this crate rather than anything derived from
/// the device, which is what makes the loop bounded by a value the adversary
/// does not choose.
pub const UIP_POLL_LIMIT: u32 = 10_000;

/// Snapshots of the register file one [`Rtc::read_unix_seconds`] may take while
/// waiting for two consecutive ones to agree.
///
/// A part ticks once a second and a snapshot costs microseconds, so a
/// conforming part disagrees with its predecessor at most once in a row and two
/// snapshots almost always suffice; three chances at agreement is ample. Beyond
/// that the part is not ticking under the reader but changing under it, which no
/// number of retries fixes.
///
/// A constant rather than an argument, for [`UIP_POLL_LIMIT`]'s reason: a bound
/// a caller passes is a bound something outside this crate chooses, and a caller
/// passing zero would need a refusal of its own for a wait that never happened.
pub const SNAPSHOT_ATTEMPTS: u32 = 4;

const _: () = assert!(UIP_POLL_LIMIT > 0);
const _: () = assert!(SNAPSHOT_ATTEMPTS > 1);

/// Port operations one register read costs: the index write that selects it,
/// and the data read that answers.
const PORT_OPS_PER_REGISTER: u32 = 2;

/// The most port operations one snapshot can cost, whatever the device answers:
/// the bounded status-A poll, and the register file it guards.
pub const SNAPSHOT_PORT_OPS_MAX: u32 =
    (UIP_POLL_LIMIT + SNAPSHOT_REGISTERS.len() as u32) * PORT_OPS_PER_REGISTER;

/// The most port operations one [`Rtc::read_unix_seconds`] can cost, whatever
/// the device answers. Asserting a run against this is how a test proves the
/// read terminates rather than merely that it terminated this time.
pub const READ_PORT_OPS_MAX: u32 = SNAPSHOT_ATTEMPTS * SNAPSHOT_PORT_OPS_MAX;

/// One addressable register of the part, named by the CMOS index it is selected
/// by.
///
/// The enum is the whole of what this crate will ask [`CmosPortIo`] for, so an
/// index outside the vocabulary — including one with [`NMI_DISABLE`] set — is
/// unrepresentable rather than rejected. Only the nine registers this
/// crate reads are declared: the alarm registers, status C and D, and the
/// hundred-odd bytes of general-purpose CMOS lie in the same index space and are
/// touched by nothing here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Register {
    /// Index `0x00`. Seconds of the minute.
    Seconds = 0x00,
    /// Index `0x02`. Minutes of the hour.
    Minutes = 0x02,
    /// Index `0x04`. Hours, counted as status B says — and in 12-hour counting
    /// its bit 7 is [`HOURS_PM`] rather than part of the value.
    Hours = 0x04,
    /// Index `0x07`. Day of the month, from one.
    DayOfMonth = 0x07,
    /// Index `0x08`. Month of the year, from one.
    Month = 0x08,
    /// Index `0x09`. Year within the century, 0..=99.
    Year = 0x09,
    /// Index `0x32`. The century — an ACPI convention rather than a register
    /// the MC146818 datasheet defines, which is why the year it completes is
    /// ranged (see the crate header).
    Century = 0x32,
    /// Index `0x0A`. Status A, whose bit 7 is [`STATUS_A_UIP`]; the rest select
    /// the divider and the periodic-interrupt rate and are read by nothing here.
    StatusA = 0x0A,
    /// Index `0x0B`. Status B, whose bits 2 and 1 are [`STATUS_B_BINARY`] and
    /// [`STATUS_B_24_HOUR`] — the encoding every other register is read
    /// through.
    StatusB = 0x0B,
}

impl Register {
    /// Every register this crate can address, so a [`CmosPortIo`] proving its
    /// authority spans the whole demand enumerates it rather than restating it.
    pub const ALL: [Self; 9] = [
        Self::Seconds,
        Self::Minutes,
        Self::Hours,
        Self::DayOfMonth,
        Self::Month,
        Self::Year,
        Self::Century,
        Self::StatusA,
        Self::StatusB,
    ];

    /// The byte written to [`INDEX_PORT`] to select this register.
    ///
    /// The CMOS index and the byte written are the same value because
    /// [`NMI_DISABLE`] is clear in every one of them, which the assertions below
    /// hold rather than argue: a discriminant with bit 7 set would address a
    /// different register *and* disable the non-maskable interrupt, and neither
    /// would fail anywhere else.
    #[must_use]
    pub const fn index(self) -> u8 {
        self as u8
    }
}

// The MC146818 index map is fixed by the part, and a wrong discriminant would
// read a different register rather than fail: index 0x01 answers the seconds
// *alarm*, which on a part whose alarm was never programmed is a plausible
// number that never changes.
const _: () = assert!(Register::Seconds.index() == 0x00);
const _: () = assert!(Register::Minutes.index() == 0x02);
const _: () = assert!(Register::Hours.index() == 0x04);
const _: () = assert!(Register::DayOfMonth.index() == 0x07);
const _: () = assert!(Register::Month.index() == 0x08);
const _: () = assert!(Register::Year.index() == 0x09);
const _: () = assert!(Register::Century.index() == 0x32);
const _: () = assert!(Register::StatusA.index() == 0x0A);
const _: () = assert!(Register::StatusB.index() == 0x0B);

// NMI stays enabled: the crate header's choice, stated as the nine facts that
// make it true.
const _: () = assert!(Register::Seconds.index() & NMI_DISABLE == 0);
const _: () = assert!(Register::Minutes.index() & NMI_DISABLE == 0);
const _: () = assert!(Register::Hours.index() & NMI_DISABLE == 0);
const _: () = assert!(Register::DayOfMonth.index() & NMI_DISABLE == 0);
const _: () = assert!(Register::Month.index() & NMI_DISABLE == 0);
const _: () = assert!(Register::Year.index() & NMI_DISABLE == 0);
const _: () = assert!(Register::Century.index() & NMI_DISABLE == 0);
const _: () = assert!(Register::StatusA.index() & NMI_DISABLE == 0);
const _: () = assert!(Register::StatusB.index() & NMI_DISABLE == 0);

/// The registers one snapshot reads, in the order it reads them.
///
/// Status B travels with the values it decodes rather than being read once,
/// which is what puts the encoding bits inside the agreement test below: a part
/// that flips `DM` between two snapshots is a part whose snapshots disagree.
/// Status A is absent because it is the poll that precedes a snapshot, not part
/// of one.
const SNAPSHOT_REGISTERS: [Register; 8] = [
    Register::Seconds,
    Register::Minutes,
    Register::Hours,
    Register::DayOfMonth,
    Register::Month,
    Register::Year,
    Register::Century,
    Register::StatusB,
];

/// Byte-wide access to the part's register file.
///
/// **Precondition, delegated to the caller:** `index` names a member of
/// [`Register::ALL`], so it carries no [`NMI_DISABLE`] bit and selects a
/// register within the CMOS index space an implementation's `<ioport>` grant
/// covers. Enforced by [`Rtc`], which is this crate's only caller of the trait
/// and forms every index through [`Register::index`]; proven by the property
/// `every_index_written_names_a_register_and_leaves_nmi_enabled`, which reads
/// back every index reached on any path, and by the assertions above, which
/// range the nine the vocabulary contains.
///
/// Both methods take `&mut self` because both are side-effecting on the real
/// part: the index write latches a selection that outlives the call, and a data
/// read answers whatever the last one selected. Neither is a question that can
/// be asked twice for the same answer.
pub trait CmosPortIo {
    fn write_index(&mut self, index: u8);

    fn read_data(&mut self) -> u8;
}

/// Why the part named no Unix instant.
///
/// Every variant carries what the device answered, because an operator — who
/// has no shell on this appliance — separates an absent part, every read
/// answering `0xFF`, from one whose battery died and answers zeroes, and a
/// clock stuck mid-update from one ticking too fast to catch, only if the
/// cases produce different console lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtcError {
    /// Status A reported an update in progress for [`UIP_POLL_LIMIT`] reads,
    /// carrying the last byte it answered. A part whose bit is stuck and one
    /// whose update never ends are the same observation; both mean the register
    /// file was never quiescent enough to read.
    UpdateNeverCompleted { polls: u32, status_a: u8 },
    /// [`SNAPSHOT_ATTEMPTS`] snapshots were taken and no two consecutive ones
    /// were equal, so no reading was ever confirmed. Nothing of the register
    /// file travels: every snapshot differed from its neighbour by construction,
    /// and which byte differed is not something an operator can act on — that
    /// the file will not hold still is.
    SnapshotsNeverAgreed { attempts: u32 },
    /// Status B selected packed decimal and this register's value is not: one of
    /// its nibbles is above nine. Refused rather than decoded, because `0x1A`
    /// read as decimal is a number the part never meant.
    ///
    /// For [`Register::Hours`] in 12-hour counting, `value` is what remains
    /// after [`HOURS_PM`] is masked off, that bit not being part of the value —
    /// so a part answering `0x8A` is reported as having answered `0x0A`.
    NotBinaryCodedDecimal { register: Register, value: u8 },
    /// Status B selected 12-hour counting and the hours register, with
    /// [`HOURS_PM`] masked off, is not in 1..=12. Distinct from a range refusal
    /// of the converted hour: what is wrong is the 12-hour encoding itself, and
    /// which half of the day the part claimed is part of saying so.
    HourOutsideTwelveHourRange { hour: u8, pm: bool },
    /// The century and year registers assemble to a year outside
    /// [`MIN_PLAUSIBLE_YEAR`]..=[`MAX_PLAUSIBLE_YEAR`]. The century travels
    /// beside the year because it is the register to suspect: the year alone
    /// cannot be wrong by a hundred.
    ImplausibleYear { year: u16, century: u8 },
    /// The registers assembled into a civil date and time that names no Unix
    /// instant — a day the month does not have, 29 February in a common year, an
    /// hour past 23. `cause` is `lfw_clock`'s own verdict, carried verbatim
    /// rather than re-derived, and `civil` is what the part claimed.
    NotACivilInstant {
        civil: CivilTime,
        cause: CivilTimeError,
    },
}

/// Whether the time and date registers hold packed decimal or plain binary —
/// status B's `DM` bit as a type, so the two encodings cannot be swapped at a
/// call site the way a `bool` argument can be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DataMode {
    Bcd,
    Binary,
}

impl DataMode {
    const fn from_status_b(status_b: u8) -> Self {
        if status_b & STATUS_B_BINARY == 0 {
            Self::Bcd
        } else {
            Self::Binary
        }
    }
}

/// Whether the hours register counts 0..=23 or 1..=12 with a half-of-day flag —
/// status B's 24/12 bit, as a type for [`DataMode`]'s reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HourFormat {
    TwentyFour,
    Twelve,
}

impl HourFormat {
    const fn from_status_b(status_b: u8) -> Self {
        if status_b & STATUS_B_24_HOUR == 0 {
            Self::Twelve
        } else {
            Self::TwentyFour
        }
    }
}

/// One pass over the register file: the bytes as the part answered them,
/// undecoded.
///
/// Equality over the raw bytes is the whole of the agreement test, and it is
/// taken before any decoding so that two snapshots a part disagreed on are never
/// interpreted — including when both would have decoded to something plausible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snapshot {
    seconds: u8,
    minutes: u8,
    hours: u8,
    day_of_month: u8,
    month: u8,
    year_of_century: u8,
    century: u8,
    status_b: u8,
}

/// The part, behind the port authority a caller supplies.
pub struct Rtc<P: CmosPortIo> {
    port: P,
}

impl<P: CmosPortIo> Rtc<P> {
    /// Take the port. Nothing is read from the device here.
    #[must_use]
    pub const fn new(port: P) -> Self {
        Self { port }
    }

    /// Read the wall time and return it as whole seconds since the Unix epoch.
    ///
    /// Each snapshot waits out the update-in-progress bit — bounded by
    /// [`UIP_POLL_LIMIT`] — and then reads the whole of
    /// [`SNAPSHOT_REGISTERS`]; snapshots are taken until two consecutive ones
    /// are byte-for-byte equal, bounded by [`SNAPSHOT_ATTEMPTS`]. Only then is
    /// anything decoded: the encoding status B selected, the 12-hour hour if
    /// that is what the part counts, the century, and the civil date, whose
    /// ranges [`CivilTime::to_unix_seconds`] decides.
    ///
    /// Bounded by [`READ_PORT_OPS_MAX`] port operations whatever the device
    /// answers, so a part that never settles costs a bounded number of reads
    /// rather than the domain that asked.
    pub fn read_unix_seconds(&mut self) -> Result<u64, RtcError> {
        let mut previous: Option<Snapshot> = None;
        for _ in 0..SNAPSHOT_ATTEMPTS {
            self.wait_for_update_to_complete()?;
            let snapshot = self.snapshot();
            if previous == Some(snapshot) {
                return decode(snapshot);
            }
            previous = Some(snapshot);
        }
        Err(RtcError::SnapshotsNeverAgreed {
            attempts: SNAPSHOT_ATTEMPTS,
        })
    }

    /// Poll status A — bounded by [`UIP_POLL_LIMIT`] — until it reports no
    /// update in progress.
    fn wait_for_update_to_complete(&mut self) -> Result<(), RtcError> {
        let mut status_a = 0;
        for _ in 0..UIP_POLL_LIMIT {
            status_a = self.read_register(Register::StatusA);
            if status_a & STATUS_A_UIP == 0 {
                return Ok(());
            }
        }
        Err(RtcError::UpdateNeverCompleted {
            polls: UIP_POLL_LIMIT,
            status_a,
        })
    }

    /// One pass over [`SNAPSHOT_REGISTERS`], in order.
    ///
    /// The destructuring pattern and that array are positionally coupled, which
    /// the compiler checks for arity and `a_read_places_every_register_in_the_field_it_belongs_to`
    /// checks for order.
    fn snapshot(&mut self) -> Snapshot {
        let [
            seconds,
            minutes,
            hours,
            day_of_month,
            month,
            year_of_century,
            century,
            status_b,
        ] = SNAPSHOT_REGISTERS.map(|register| self.read_register(register));
        Snapshot {
            seconds,
            minutes,
            hours,
            day_of_month,
            month,
            year_of_century,
            century,
            status_b,
        }
    }

    /// Select a register and read it: the two port operations every read here
    /// is made of.
    fn read_register(&mut self, register: Register) -> u8 {
        self.port.write_index(register.index());
        self.port.read_data()
    }
}

/// Turn an agreed snapshot into seconds since the epoch, or name the first
/// register that made it impossible.
///
/// Fields are decoded most-significant first, so a part answering nonsense
/// everywhere is reported by its year rather than by whichever check ran last.
fn decode(snapshot: Snapshot) -> Result<u64, RtcError> {
    let mode = DataMode::from_status_b(snapshot.status_b);
    let format = HourFormat::from_status_b(snapshot.status_b);

    let century = field(mode, Register::Century, snapshot.century)?;
    let year_of_century = field(mode, Register::Year, snapshot.year_of_century)?;
    // Widened before the multiplication: in binary mode both bytes are whatever
    // the part chose, and the assertion below ranges the largest year the pair
    // can form rather than assuming a well-behaved one.
    let year = u16::from(century) * 100 + u16::from(year_of_century);
    if !(MIN_PLAUSIBLE_YEAR..=MAX_PLAUSIBLE_YEAR).contains(&year) {
        return Err(RtcError::ImplausibleYear { year, century });
    }

    let month = field(mode, Register::Month, snapshot.month)?;
    let day = field(mode, Register::DayOfMonth, snapshot.day_of_month)?;
    let hour = hour(mode, format, snapshot.hours)?;
    let minute = field(mode, Register::Minutes, snapshot.minutes)?;
    let second = field(mode, Register::Seconds, snapshot.seconds)?;

    let civil = CivilTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        // The part counts whole seconds; it has no finer field to read.
        nanosecond: 0,
    };
    civil
        .to_unix_seconds()
        .map_err(|cause| RtcError::NotACivilInstant { civil, cause })
}

// The year assembly cannot leave `u16` for any pair of bytes a part can answer.
const _: () = assert!(u8::MAX as u32 * 100 + u8::MAX as u32 <= u16::MAX as u32);

/// One time or date register's value, in whichever encoding status B selected.
fn field(mode: DataMode, register: Register, value: u8) -> Result<u8, RtcError> {
    match mode {
        DataMode::Binary => Ok(value),
        DataMode::Bcd => match from_bcd(value) {
            Some(decoded) => Ok(decoded),
            None => Err(RtcError::NotBinaryCodedDecimal { register, value }),
        },
    }
}

/// The hours register as an hour of the day, 0..=23 — or a refusal, if the part
/// counts twelve to a half-day and named an hour outside one.
///
/// An hour above 23 in 24-hour counting is not refused here: it is a range on a
/// civil time, and [`decode`] delegates every one of those to
/// [`CivilTime::to_unix_seconds`].
fn hour(mode: DataMode, format: HourFormat, raw: u8) -> Result<u8, RtcError> {
    match format {
        HourFormat::TwentyFour => field(mode, Register::Hours, raw),
        HourFormat::Twelve => {
            let pm = raw & HOURS_PM != 0;
            let hour = field(mode, Register::Hours, raw & !HOURS_PM)?;
            if hour == 0 || hour > 12 {
                return Err(RtcError::HourOutsideTwelveHourRange { hour, pm });
            }
            // `% 12` folds twelve onto zero, which is what midnight and noon
            // need, and bounds the remainder at eleven — so the sum is at most
            // twenty-three for any byte, not only for one the check above
            // admitted.
            Ok(hour % 12 + if pm { 12 } else { 0 })
        }
    }
}

/// The number a packed-decimal byte names, or `None` for a byte that names
/// none.
const fn from_bcd(value: u8) -> Option<u8> {
    let tens = value >> 4;
    let units = value & 0x0F;
    if tens > 9 || units > 9 {
        return None;
    }
    // Both nibbles are at most nine, so the product is at most ninety and the
    // sum at most ninety-nine: neither can leave `u8`.
    Some(tens * 10 + units)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_port::{
        CONFORMING_DIVIDER_BITS, CONFORMING_INSTANT, FakeCmos, Log, Op, UNDECODED,
    };
    use proptest::prelude::*;
    use std::vec;
    use std::vec::Vec;

    /// The epoch second [`CONFORMING_INSTANT`] names, written out rather than
    /// computed, so the two statements of it have to agree.
    const CONFORMING_UNIX_SECONDS: u64 = 1_785_443_225;

    /// The epoch second an instant this module composed names. Test-side only:
    /// nothing in the crate under test may assume a civil time is valid.
    fn epoch_of(instant: CivilTime) -> u64 {
        instant
            .to_unix_seconds()
            .expect("this module composes a civil time inside the plausible band")
    }

    /// Read against a fake, returning the shared log and the outcome.
    fn read(port: FakeCmos) -> (Log, Result<u64, RtcError>) {
        let log = port.log();
        let mut rtc = Rtc::new(port);
        let outcome = rtc.read_unix_seconds();
        (log, outcome)
    }

    /// The registers a run selected, in order — what a sequence assertion is
    /// made against, since a data read carries no index of its own.
    fn indices(log: &Log) -> Vec<u8> {
        log.ops()
            .iter()
            .filter_map(|op| match op {
                Op::WriteIndex { index } => Some(*index),
                Op::ReadData { .. } => None,
            })
            .collect()
    }

    /// How many times a run selected `register`.
    fn selections(log: &Log, register: Register) -> u32 {
        indices(log)
            .into_iter()
            .filter(|index| *index == register.index())
            .count() as u32
    }

    /// The first and last epoch second the plausible year band admits, taken
    /// from the band's own endpoints rather than written out.
    fn band() -> core::ops::RangeInclusive<u64> {
        let start = CivilTime {
            year: MIN_PLAUSIBLE_YEAR,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            nanosecond: 0,
        };
        let end = CivilTime {
            year: MAX_PLAUSIBLE_YEAR,
            month: 12,
            day: 31,
            hour: 23,
            minute: 59,
            second: 59,
            nanosecond: 0,
        };
        epoch_of(start)..=epoch_of(end)
    }

    /// Every claim a read's outcome has to satisfy, whatever the part answered:
    /// an accepted instant lies inside the plausible band, and a refusal carries
    /// a value consistent with the cause it names.
    ///
    /// Shared between the arbitrary-bytes property and
    /// `an_arbitrary_byte_cycle_can_still_name_a_plausible_instant`, which is
    /// what drives the accepting side of it from a stream a test chose.
    fn outcome_is_consistent(outcome: &Result<u64, RtcError>) -> bool {
        match outcome {
            Ok(seconds) => band().contains(seconds),
            Err(RtcError::UpdateNeverCompleted { polls, .. }) => *polls == UIP_POLL_LIMIT,
            Err(RtcError::SnapshotsNeverAgreed { attempts }) => *attempts == SNAPSHOT_ATTEMPTS,
            Err(RtcError::NotBinaryCodedDecimal { value, .. }) => from_bcd(*value).is_none(),
            Err(RtcError::HourOutsideTwelveHourRange { hour, .. }) => *hour == 0 || *hour > 12,
            Err(RtcError::ImplausibleYear { year, .. }) => {
                !(MIN_PLAUSIBLE_YEAR..=MAX_PLAUSIBLE_YEAR).contains(year)
            }
            Err(RtcError::NotACivilInstant { civil, cause }) => {
                civil.to_unix_seconds() == Err(*cause)
            }
        }
    }

    #[test]
    fn every_register_is_selected_by_the_index_the_datasheet_gives_it() {
        // The map the whole decoder rests on, and the NMI choice the crate
        // header makes: asserted rather than argued, because a wrong index reads
        // a neighbouring register that answers a plausible number, and a bit 7
        // that crept in would leave the machine unable to report a hardware
        // fault.
        for (register, index) in [
            (Register::Seconds, 0x00),
            (Register::Minutes, 0x02),
            (Register::Hours, 0x04),
            (Register::DayOfMonth, 0x07),
            (Register::Month, 0x08),
            (Register::Year, 0x09),
            (Register::Century, 0x32),
            (Register::StatusA, 0x0A),
            (Register::StatusB, 0x0B),
        ] {
            assert_eq!(register.index(), index, "{register:?}");
            assert_eq!(register.index() & NMI_DISABLE, 0, "{register:?}");
        }
        assert_eq!(DATA_PORT, INDEX_PORT + 1);
        assert_eq!(PORT_COUNT, 2);
    }

    #[test]
    fn every_register_is_in_all() {
        // `Register::ALL` is what a `CmosPortIo` implementation probes its
        // authority against, so a variant missing from it is a register this
        // crate would select having proven nothing about it. The match is
        // exhaustive, so a new variant fails to compile until it is listed; this
        // then fails until it is listed *here*.
        for register in [
            Register::Seconds,
            Register::Minutes,
            Register::Hours,
            Register::DayOfMonth,
            Register::Month,
            Register::Year,
            Register::Century,
            Register::StatusA,
            Register::StatusB,
        ] {
            let listed = match register {
                Register::Seconds
                | Register::Minutes
                | Register::Hours
                | Register::DayOfMonth
                | Register::Month
                | Register::Year
                | Register::Century
                | Register::StatusA
                | Register::StatusB => Register::ALL.contains(&register),
            };
            assert!(listed, "{register:?} is missing from Register::ALL");
        }
        assert_eq!(Register::ALL.len(), 9);
    }

    #[test]
    fn a_snapshot_reads_every_register_but_the_one_that_gates_it() {
        // The two vocabularies are one fact apart: a snapshot is the whole file
        // except status A, which is the poll that precedes a snapshot rather
        // than part of one.
        for register in SNAPSHOT_REGISTERS {
            assert!(Register::ALL.contains(&register), "{register:?}");
            assert_ne!(register, Register::StatusA);
        }
        assert_eq!(SNAPSHOT_REGISTERS.len(), Register::ALL.len() - 1);
    }

    #[test]
    fn a_healthy_packed_decimal_part_reads_the_instant_it_holds() {
        let (log, outcome) = read(FakeCmos::conforming());
        assert_eq!(outcome, Ok(CONFORMING_UNIX_SECONDS));
        assert_eq!(
            epoch_of(CONFORMING_INSTANT),
            CONFORMING_UNIX_SECONDS,
            "the fake's instant and the expected second must be one fact"
        );
        // Status A, then the file, twice — because agreement needs a predecessor
        // to agree with.
        let mut one_pass = vec![Register::StatusA.index()];
        one_pass.extend(SNAPSHOT_REGISTERS.iter().map(|register| register.index()));
        let mut expected = one_pass.clone();
        expected.extend(one_pass);
        assert_eq!(indices(&log), expected);
    }

    #[test]
    fn a_read_places_every_register_in_the_field_it_belongs_to() {
        // The positional coupling between `SNAPSHOT_REGISTERS` and the pattern
        // that destructures it. Every field is given a distinct value, so a
        // transposed pair produces a different instant rather than the same one.
        let instant = CivilTime {
            year: 2134,
            month: 5,
            day: 6,
            hour: 7,
            minute: 8,
            second: 9,
            nanosecond: 0,
        };
        let (_, outcome) = read(FakeCmos::conforming().holding(instant));
        assert_eq!(outcome, Ok(epoch_of(instant)));
    }

    #[test]
    fn a_binary_mode_part_reads_the_same_instant_as_a_packed_decimal_one() {
        // The `DM` bit honoured: the same instant, encoded the other way.
        let (_, outcome) = read(FakeCmos::conforming().in_binary_mode());
        assert_eq!(outcome, Ok(CONFORMING_UNIX_SECONDS));
    }

    #[test]
    fn a_twelve_hour_part_reads_the_hour_its_half_of_day_bit_names() {
        // Every boundary of the fold: both twelves, which map to midnight and to
        // noon, and the hours either side of them, in both encodings.
        for hour in [0u8, 1, 11, 12, 13, 23] {
            let instant = CivilTime {
                hour,
                ..CONFORMING_INSTANT
            };
            for part in [
                FakeCmos::conforming()
                    .holding(instant)
                    .in_twelve_hour_mode(),
                FakeCmos::conforming()
                    .holding(instant)
                    .in_twelve_hour_mode()
                    .in_binary_mode(),
            ] {
                let (_, outcome) = read(part);
                assert_eq!(outcome, Ok(epoch_of(instant)), "{hour}");
            }
        }
    }

    #[test]
    fn a_twelve_hour_part_naming_an_hour_outside_one_to_twelve_is_refused() {
        // Zero and thirteen, in both halves of the day: a 12-hour part has no
        // encoding for either, so converting one would invent an hour. The last
        // case is why the half-of-day bit is masked before the value is decoded
        // rather than after: `0x99` is nineteen in the afternoon, not
        // ninety-nine.
        for (raw, hour, pm) in [
            (0x00, 0, false),
            (0x80, 0, true),
            (0x13, 13, false),
            (0x93, 13, true),
            (0x99, 19, true),
        ] {
            let (_, outcome) = read(
                FakeCmos::conforming()
                    .in_twelve_hour_mode()
                    .misreporting(Register::Hours, raw),
            );
            assert_eq!(
                outcome,
                Err(RtcError::HourOutsideTwelveHourRange { hour, pm }),
                "{raw:#04x}"
            );
            assert!(outcome_is_consistent(&outcome), "{raw:#04x}");
        }

        // And the half-of-day bit is masked off *before* the value is decoded,
        // so a 12-hour part answering a byte no decimal names is refused for its
        // encoding rather than for a range — reporting the masked value, which
        // is the value.
        let (_, outcome) = read(
            FakeCmos::conforming()
                .in_twelve_hour_mode()
                .misreporting(Register::Hours, 0x8A),
        );
        assert_eq!(
            outcome,
            Err(RtcError::NotBinaryCodedDecimal {
                register: Register::Hours,
                value: 0x0A,
            })
        );
    }

    #[test]
    fn an_hour_past_twenty_three_is_refused_by_the_calendar_it_is_delegated_to() {
        // 24-hour counting has no separate encoding to be wrong, so the only
        // thing wrong with 24 is that no civil time has it — which is
        // `lfw_clock`'s verdict, not this crate's.
        let (_, outcome) = read(FakeCmos::conforming().misreporting(Register::Hours, 0x24));
        assert_eq!(
            outcome,
            Err(RtcError::NotACivilInstant {
                civil: CivilTime {
                    hour: 24,
                    ..CONFORMING_INSTANT
                },
                cause: CivilTimeError::HourOutOfRange { hour: 24 },
            })
        );
    }

    #[test]
    fn only_two_bits_of_status_b_decide_how_the_file_is_read() {
        // Every other bit of status B selects an interrupt or daylight-saving
        // behaviour this crate never programs, and a part is free to have them
        // set; the instant must not move when it does.
        let noise = !(STATUS_B_BINARY | STATUS_B_24_HOUR);
        let (_, outcome) = read(FakeCmos::conforming().with_status_b_noise(noise));
        assert_eq!(outcome, Ok(CONFORMING_UNIX_SECONDS));
        // And the same for status A, whose low bits are the divider and the
        // periodic-interrupt rate.
        let (_, outcome) = read(FakeCmos::conforming().with_status_a_noise(!STATUS_A_UIP));
        assert_eq!(outcome, Ok(CONFORMING_UNIX_SECONDS));
    }

    #[test]
    fn a_part_whose_update_never_completes_is_refused_after_a_bounded_wait() {
        // The device this crate exists to survive: it answers every read,
        // forever, and never reports its file quiescent. It must cost a bounded
        // number of reads, not the domain.
        let (log, outcome) = read(FakeCmos::conforming().never_completing_update());
        assert_eq!(
            outcome,
            Err(RtcError::UpdateNeverCompleted {
                polls: UIP_POLL_LIMIT,
                status_a: CONFORMING_DIVIDER_BITS | STATUS_A_UIP,
            })
        );
        assert_eq!(selections(&log, Register::StatusA), UIP_POLL_LIMIT);
        // The whole budget of one snapshot's wait, and then nothing: no register
        // of a file that was never quiescent is read.
        assert_eq!(log.len() as u32, UIP_POLL_LIMIT * PORT_OPS_PER_REGISTER);
        assert!(log.len() as u32 <= READ_PORT_OPS_MAX);
        assert_eq!(selections(&log, Register::Seconds), 0);
    }

    #[test]
    fn a_part_that_completes_its_update_on_the_last_permitted_poll_is_still_read() {
        // The boundary itself: the bit clears on the final read the loop is
        // allowed to make.
        let (log, outcome) =
            read(FakeCmos::conforming().completing_update_after(UIP_POLL_LIMIT - 1));
        assert_eq!(outcome, Ok(CONFORMING_UNIX_SECONDS));
        // One exhausted wait and its snapshot, then a second wait that clears at
        // once and a second snapshot.
        let file = SNAPSHOT_REGISTERS.len() as u32;
        assert_eq!(
            log.len() as u32,
            (UIP_POLL_LIMIT + file + 1 + file) * PORT_OPS_PER_REGISTER
        );
        assert!(log.len() as u32 <= READ_PORT_OPS_MAX);
    }

    #[test]
    fn a_part_one_poll_slower_than_the_bound_is_refused() {
        // One past the boundary. The two tests together pin the bound to
        // `UIP_POLL_LIMIT` rather than to "eventually".
        let (log, outcome) = read(FakeCmos::conforming().completing_update_after(UIP_POLL_LIMIT));
        assert_eq!(
            outcome,
            Err(RtcError::UpdateNeverCompleted {
                polls: UIP_POLL_LIMIT,
                status_a: CONFORMING_DIVIDER_BITS | STATUS_A_UIP,
            })
        );
        assert_eq!(log.len() as u32, UIP_POLL_LIMIT * PORT_OPS_PER_REGISTER);
    }

    #[test]
    fn a_part_that_never_holds_still_is_refused_after_a_bounded_number_of_snapshots() {
        // A file that ticks on every read: no two consecutive snapshots can
        // agree, and none of them may be decoded on that account.
        let (log, outcome) = read(FakeCmos::conforming().never_settling());
        assert_eq!(
            outcome,
            Err(RtcError::SnapshotsNeverAgreed {
                attempts: SNAPSHOT_ATTEMPTS,
            })
        );
        assert_eq!(selections(&log, Register::Seconds), SNAPSHOT_ATTEMPTS);
        assert!(log.len() as u32 <= READ_PORT_OPS_MAX);
    }

    #[test]
    fn a_part_that_settles_after_one_disagreement_is_read() {
        // The retry doing its job: the first two snapshots straddle a tick, the
        // second and third agree, and the instant reported is the later one —
        // never the value only one snapshot ever showed.
        let (log, outcome) = read(FakeCmos::conforming().settling_after(1));
        assert_eq!(outcome, Ok(CONFORMING_UNIX_SECONDS + 1));
        assert_eq!(selections(&log, Register::Seconds), 3);
    }

    #[test]
    fn the_recorded_operation_count_is_what_a_read_actually_costs() {
        // `READ_PORT_OPS_MAX` is what every termination proof here rests on. A
        // stable part answers on the second snapshot, so a whole read is two
        // waits of one poll each and two passes over the file.
        let (log, outcome) = read(FakeCmos::conforming());
        assert_eq!(outcome, Ok(CONFORMING_UNIX_SECONDS));
        assert_eq!(
            log.len() as u32,
            2 * (1 + SNAPSHOT_REGISTERS.len() as u32) * PORT_OPS_PER_REGISTER
        );
        assert_eq!(log.len(), 36);
        assert_eq!(
            SNAPSHOT_PORT_OPS_MAX,
            (UIP_POLL_LIMIT + 8) * PORT_OPS_PER_REGISTER
        );
        assert_eq!(READ_PORT_OPS_MAX, SNAPSHOT_ATTEMPTS * SNAPSHOT_PORT_OPS_MAX);
        assert!(log.len() as u32 <= READ_PORT_OPS_MAX);
    }

    #[test]
    fn every_register_that_is_not_packed_decimal_is_refused_by_its_own_name() {
        // Each of the seven registers the decoder reads through the `DM` bit,
        // driven to the same fault, so no two of them collapse into one line.
        for register in [
            Register::Century,
            Register::Year,
            Register::Month,
            Register::DayOfMonth,
            Register::Hours,
            Register::Minutes,
            Register::Seconds,
        ] {
            for value in [0x0A, 0xA0, 0xFF, 0x1F] {
                let (_, outcome) = read(FakeCmos::conforming().misreporting(register, value));
                assert_eq!(
                    outcome,
                    Err(RtcError::NotBinaryCodedDecimal { register, value }),
                    "{register:?} answering {value:#04x}"
                );
            }
        }
    }

    #[test]
    fn a_byte_that_is_not_packed_decimal_is_a_plain_number_in_binary_mode() {
        // The `DM` bit honoured on the refusal path too: `0xA0` is not decimal
        // and is 160, so a binary-mode part is refused for the range it named
        // rather than for an encoding it never claimed.
        let (_, outcome) = read(
            FakeCmos::conforming()
                .in_binary_mode()
                .misreporting(Register::Seconds, 0xA0),
        );
        assert_eq!(
            outcome,
            Err(RtcError::NotACivilInstant {
                civil: CivilTime {
                    second: 160,
                    ..CONFORMING_INSTANT
                },
                cause: CivilTimeError::SecondOutOfRange { second: 160 },
            })
        );
    }

    #[test]
    fn every_byte_is_decoded_as_packed_decimal_exactly_when_it_is_one() {
        // Exhaustive over the whole byte, because this is the one place a wrong
        // number would be produced rather than refused: `0x1A` read as decimal
        // is a value the part never meant.
        for value in 0..=u8::MAX {
            let tens = value >> 4;
            let units = value & 0x0F;
            let well_formed = tens <= 9 && units <= 9;
            assert_eq!(from_bcd(value).is_some(), well_formed, "{value:#04x}");
            if let Some(decoded) = from_bcd(value) {
                assert_eq!(decoded, tens * 10 + units, "{value:#04x}");
                assert!(decoded <= 99);
            }
        }
        assert_eq!(from_bcd(0x00), Some(0));
        assert_eq!(from_bcd(0x99), Some(99));
        assert_eq!(from_bcd(0x9A), None);
        assert_eq!(from_bcd(0xA9), None);
    }

    #[test]
    fn an_implausible_century_is_refused_rather_than_assumed_to_be_twenty() {
        // The bytes an absent part and a dead battery answer, and a century that
        // is merely wrong: none of them may become a confident epoch.
        for (raw, century, year) in [(0x00, 0, 26), (0x19, 19, 1926), (0x99, 99, 9926)] {
            let (_, outcome) = read(FakeCmos::conforming().misreporting(Register::Century, raw));
            assert_eq!(
                outcome,
                Err(RtcError::ImplausibleYear { year, century }),
                "{raw:#04x}"
            );
        }
        // All-ones is not decimal, so its encoding is refused before a century
        // is ever assembled — the more specific of the two faults.
        let (_, outcome) = read(FakeCmos::conforming().misreporting(Register::Century, UNDECODED));
        assert_eq!(
            outcome,
            Err(RtcError::NotBinaryCodedDecimal {
                register: Register::Century,
                value: UNDECODED,
            })
        );
    }

    #[test]
    fn the_plausible_year_band_is_inclusive_at_both_ends() {
        for year in [MIN_PLAUSIBLE_YEAR, MAX_PLAUSIBLE_YEAR] {
            let instant = CivilTime {
                year,
                month: 1,
                day: 1,
                ..CONFORMING_INSTANT
            };
            let (_, outcome) = read(FakeCmos::conforming().holding(instant));
            assert_eq!(outcome, Ok(epoch_of(instant)), "{year}");
        }
        for year in [MIN_PLAUSIBLE_YEAR - 1, MAX_PLAUSIBLE_YEAR + 1] {
            let instant = CivilTime {
                year,
                month: 1,
                day: 1,
                ..CONFORMING_INSTANT
            };
            let (_, outcome) = read(FakeCmos::conforming().holding(instant));
            assert_eq!(
                outcome,
                Err(RtcError::ImplausibleYear {
                    year,
                    century: (year / 100) as u8,
                }),
                "{year}"
            );
        }
    }

    #[test]
    fn a_date_no_calendar_has_is_refused_by_the_conversion_it_is_delegated_to() {
        // The delegation the crate header names. Whether a day exists
        // depends on the month and on the leap rule, and `lfw_clock` owns both;
        // the refusal reaching a caller is its verdict, carried whole.
        let base = CONFORMING_INSTANT;
        for (register, raw, civil, cause) in [
            (
                Register::Month,
                0x00,
                CivilTime { month: 0, ..base },
                CivilTimeError::MonthOutOfRange { month: 0 },
            ),
            (
                Register::Month,
                0x13,
                CivilTime { month: 13, ..base },
                CivilTimeError::MonthOutOfRange { month: 13 },
            ),
            (
                Register::DayOfMonth,
                0x00,
                CivilTime { day: 0, ..base },
                CivilTimeError::DayOutOfRange {
                    year: base.year,
                    month: base.month,
                    day: 0,
                },
            ),
            (
                Register::DayOfMonth,
                0x32,
                CivilTime { day: 32, ..base },
                CivilTimeError::DayOutOfRange {
                    year: base.year,
                    month: base.month,
                    day: 32,
                },
            ),
            (
                Register::Minutes,
                0x60,
                CivilTime { minute: 60, ..base },
                CivilTimeError::MinuteOutOfRange { minute: 60 },
            ),
            (
                // Second 60 is what a leap second would need, and Unix time has
                // no instant for one.
                Register::Seconds,
                0x60,
                CivilTime { second: 60, ..base },
                CivilTimeError::SecondOutOfRange { second: 60 },
            ),
        ] {
            let (_, outcome) = read(FakeCmos::conforming().misreporting(register, raw));
            assert_eq!(
                outcome,
                Err(RtcError::NotACivilInstant { civil, cause }),
                "{register:?} answering {raw:#04x}"
            );
        }
    }

    #[test]
    fn the_leap_rule_is_the_calendars_and_not_a_second_copy_of_it() {
        // 29 February exists in 2024 and not in 2100, and the register file is
        // byte-for-byte identical in both cases. A month-length table beside
        // this decoder would be a second place for the four-century rule to be
        // wrong.
        let leap_day = CivilTime {
            month: 2,
            day: 29,
            ..CONFORMING_INSTANT
        };
        for year in [2024u16, 2000, 2400] {
            let instant = CivilTime { year, ..leap_day };
            let (_, outcome) = read(FakeCmos::conforming().holding(instant));
            let expected = if year <= MAX_PLAUSIBLE_YEAR {
                Ok(epoch_of(instant))
            } else {
                Err(RtcError::ImplausibleYear {
                    year,
                    century: (year / 100) as u8,
                })
            };
            assert_eq!(outcome, expected, "{year}");
        }
        for year in [2025u16, 2100, 2200] {
            let instant = CivilTime { year, ..leap_day };
            let (_, outcome) = read(FakeCmos::conforming().holding(instant));
            assert_eq!(
                outcome,
                Err(RtcError::NotACivilInstant {
                    civil: instant,
                    cause: CivilTimeError::DayOutOfRange {
                        year,
                        month: 2,
                        day: 29,
                    },
                }),
                "{year}"
            );
        }
    }

    #[test]
    fn each_way_a_read_can_fail_reaches_an_operator_as_its_own_error() {
        // Six ways for a part to be unreadable must not collapse into
        // one console line. Each is driven to its own variant, and no two are
        // equal.
        let refusals = [
            read(FakeCmos::conforming().never_completing_update()).1,
            read(FakeCmos::conforming().never_settling()).1,
            read(FakeCmos::conforming().misreporting(Register::Seconds, 0x0A)).1,
            read(
                FakeCmos::conforming()
                    .in_twelve_hour_mode()
                    .misreporting(Register::Hours, 0x00),
            )
            .1,
            read(FakeCmos::conforming().misreporting(Register::Century, 0x19)).1,
            read(FakeCmos::conforming().misreporting(Register::Month, 0x00)).1,
        ];
        for (index, outcome) in refusals.iter().enumerate() {
            assert!(outcome.is_err(), "refusal {index} must be an error");
            assert!(outcome_is_consistent(outcome), "refusal {index}");
            for other in refusals.iter().skip(index + 1) {
                assert_ne!(outcome, other);
            }
        }
    }

    #[test]
    fn a_part_answering_nothing_at_all_is_refused_rather_than_read() {
        // An unclaimed port window: every read answers all-ones, so status A
        // reports an update that never ends.
        let (log, outcome) = read(FakeCmos::conforming().answering(vec![UNDECODED]));
        assert_eq!(
            outcome,
            Err(RtcError::UpdateNeverCompleted {
                polls: UIP_POLL_LIMIT,
                status_a: UNDECODED,
            })
        );
        assert!(log.len() as u32 <= READ_PORT_OPS_MAX);

        // A part with nothing to answer at all — a shape the double must keep
        // generable rather than refuse — reads the same way.
        let (_, outcome) = read(FakeCmos::conforming().answering(vec![]));
        assert_eq!(
            outcome,
            Err(RtcError::UpdateNeverCompleted {
                polls: UIP_POLL_LIMIT,
                status_a: UNDECODED,
            })
        );

        // And a window backed by memory that was never a register file: status A
        // reports quiescence, and the zeroed century names year zero.
        let (_, outcome) = read(FakeCmos::conforming().answering(vec![0x00]));
        assert_eq!(
            outcome,
            Err(RtcError::ImplausibleYear {
                year: 0,
                century: 0,
            })
        );
    }

    #[test]
    fn an_arbitrary_byte_cycle_can_still_name_a_plausible_instant() {
        // The honest limit of what this crate decides. A part answering a
        // three-byte cycle is not telling the truth about anything, and the
        // cycle below lands on a plausible date in every field — so it is
        // accepted. Nothing here can distinguish a lying part from a truthful
        // one; what it distinguishes is an implausible reading from a plausible
        // one, and the accepting side of `outcome_is_consistent` is what that
        // claim is made against.
        let instant = CivilTime {
            year: 2010,
            month: 6,
            day: 20,
            hour: 10,
            minute: 6,
            second: 20,
            nanosecond: 0,
        };
        let (log, outcome) = read(FakeCmos::conforming().answering(vec![10, 20, 6]));
        assert_eq!(outcome, Ok(epoch_of(instant)));
        assert!(outcome_is_consistent(&outcome));
        assert!(band().contains(&epoch_of(instant)));
        assert!(log.len() as u32 <= READ_PORT_OPS_MAX);
    }

    #[test]
    fn the_double_answers_a_data_read_with_no_register_selected() {
        // The fake constrains nothing about the order a part may be
        // driven in, so a data read before any index write, and one after an
        // index outside the vocabulary, are answered and logged like any other.
        // A guard here would delete the region
        // `every_index_written_names_a_register_and_leaves_nmi_enabled`
        // searches.
        let mut port = FakeCmos::conforming();
        let log = port.log();
        assert_eq!(port.read_data(), UNDECODED);
        port.write_index(0xFF);
        assert_eq!(port.read_data(), UNDECODED);
        assert_eq!(
            log.ops(),
            vec![
                Op::ReadData { value: UNDECODED },
                Op::WriteIndex { index: 0xFF },
                Op::ReadData { value: UNDECODED },
            ]
        );
    }

    #[test]
    fn a_register_answering_differently_on_every_read_is_never_read_as_stable() {
        // A part whose status B alternates between the two encodings. The two
        // snapshots differ in that byte alone, which is why status B travels
        // inside the agreement test rather than being read once: read once, this
        // part would have decoded a packed-decimal file as binary.
        let bcd = STATUS_B_24_HOUR;
        let binary = STATUS_B_24_HOUR | STATUS_B_BINARY;
        let (log, outcome) =
            read(FakeCmos::conforming().answering_register(Register::StatusB, vec![bcd, binary]));
        assert_eq!(
            outcome,
            Err(RtcError::SnapshotsNeverAgreed {
                attempts: SNAPSHOT_ATTEMPTS,
            })
        );
        assert_eq!(selections(&log, Register::StatusB), SNAPSHOT_ATTEMPTS);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// The property that matters most: whatever the part answers — any byte,
        /// for any index, a different one on every read — the read returns,
        /// returns within the bound it names, and returns a value consistent
        /// with the cause it names. A device that could make it spin would hang
        /// this test rather than fail it, which is precisely the failure being
        /// excluded.
        #[test]
        fn a_read_terminates_within_its_bound_for_any_device_bytes(
            answers in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            let port = FakeCmos::conforming().answering(answers);
            let log = port.log();
            let mut rtc = Rtc::new(port);
            let outcome = rtc.read_unix_seconds();
            prop_assert!(log.len() as u32 <= READ_PORT_OPS_MAX);
            prop_assert!(outcome_is_consistent(&outcome), "{:?}", outcome);
        }

        /// The same over a part whose *status A alone* is arbitrary, so the
        /// bounded wait is entered and left at every point in its budget rather
        /// than only at the two ends the unit tests pin.
        #[test]
        fn a_read_terminates_within_its_bound_for_any_status_a(
            status_a in prop::collection::vec(any::<u8>(), 1..16),
        ) {
            let quiescent = status_a.iter().any(|byte| byte & STATUS_A_UIP == 0);
            // The byte the last permitted poll would read, so the refusal is
            // checked to carry what the part actually answered rather than
            // whatever the cycle happens to start with.
            let last = status_a[(UIP_POLL_LIMIT as usize - 1) % status_a.len()];
            let port = FakeCmos::conforming()
                .answering_register(Register::StatusA, status_a);
            let log = port.log();
            let mut rtc = Rtc::new(port);
            let outcome = rtc.read_unix_seconds();
            prop_assert!(log.len() as u32 <= READ_PORT_OPS_MAX);
            prop_assert!(outcome_is_consistent(&outcome), "{:?}", outcome);
            // The bit is the whole decision: the file is read exactly when some
            // answer in the cycle reports it quiescent.
            prop_assert_eq!(outcome, if quiescent {
                Ok(CONFORMING_UNIX_SECONDS)
            } else {
                Err(RtcError::UpdateNeverCompleted {
                    polls: UIP_POLL_LIMIT,
                    status_a: last,
                })
            });
        }

        /// Every index this crate writes, on any path, names a register of the
        /// closed vocabulary and leaves the non-maskable interrupt enabled — the
        /// precondition `CmosPortIo` delegates and this property enforces.
        #[test]
        fn every_index_written_names_a_register_and_leaves_nmi_enabled(
            answers in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            let port = FakeCmos::conforming().answering(answers);
            let log = port.log();
            let mut rtc = Rtc::new(port);
            let _ = rtc.read_unix_seconds();
            let vocabulary: Vec<u8> = Register::ALL.iter().map(|register| register.index()).collect();
            for index in indices(&log) {
                prop_assert!(vocabulary.contains(&index), "{:#04x} is not a register", index);
                prop_assert_eq!(index & NMI_DISABLE, 0);
            }
        }

        /// A healthy part round-trips: any civil time a plausible year admits,
        /// held in any of the four encodings the two status-B bits select and
        /// behind arbitrary noise in both status registers, reads back as exactly
        /// the second `lfw_clock` gives it — or, where the date does not exist,
        /// as `lfw_clock`'s own refusal carried whole.
        #[test]
        fn a_healthy_part_round_trips_every_instant_a_plausible_year_admits(
            year in MIN_PLAUSIBLE_YEAR..=MAX_PLAUSIBLE_YEAR,
            month in 1u8..=12,
            day in 1u8..=31,
            hour in 0u8..=23,
            minute in 0u8..=59,
            second in 0u8..=59,
            binary in any::<bool>(),
            twelve_hour in any::<bool>(),
            status_a_noise in any::<u8>(),
            status_b_noise in any::<u8>(),
        ) {
            let instant = CivilTime { year, month, day, hour, minute, second, nanosecond: 0 };
            let mut port = FakeCmos::conforming()
                .holding(instant)
                .with_status_a_noise(status_a_noise)
                .with_status_b_noise(status_b_noise);
            if binary {
                port = port.in_binary_mode();
            }
            if twelve_hour {
                port = port.in_twelve_hour_mode();
            }
            let log = port.log();
            let mut rtc = Rtc::new(port);
            let outcome = rtc.read_unix_seconds();
            prop_assert_eq!(
                outcome,
                instant
                    .to_unix_seconds()
                    .map_err(|cause| RtcError::NotACivilInstant { civil: instant, cause }),
            );
            prop_assert!(log.len() as u32 <= READ_PORT_OPS_MAX);
        }

        /// A part that ticks under the reader is read at the value two snapshots
        /// agreed on, or refused — never at a value only one snapshot showed.
        #[test]
        fn a_ticking_part_is_read_only_at_a_value_two_snapshots_agreed_on(
            settle in 0..8u32,
        ) {
            let port = FakeCmos::conforming().settling_after(settle);
            let log = port.log();
            let mut rtc = Rtc::new(port);
            let outcome = rtc.read_unix_seconds();
            prop_assert!(log.len() as u32 <= READ_PORT_OPS_MAX);
            // The file advances a second per read of the seconds register until
            // it settles, and agreement then needs one further snapshot:
            // `settle + 2` snapshots in all, which the attempt bound admits only
            // while it does.
            prop_assert_eq!(outcome, if settle + 2 <= SNAPSHOT_ATTEMPTS {
                Ok(CONFORMING_UNIX_SECONDS + u64::from(settle))
            } else {
                Err(RtcError::SnapshotsNeverAgreed { attempts: SNAPSHOT_ATTEMPTS })
            });
        }
    }
}
