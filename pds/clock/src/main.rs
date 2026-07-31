#![no_main]
#![no_std]

//! Clock protection domain: it establishes what time it is, once, and says so.
//!
//! Four steps, in one `init` that never runs again: probe the HPET and start
//! its counter, measure the timestamp counter against it, read the CMOS
//! real-time clock for an epoch to anchor that counter to, and publish one
//! record stating the frequency it measured and the instant it established.
//! Then it parks.
//!
//! # Adversary
//!
//! CONCEPT §7.1's **hostile or malfunctioning device**, twice over: the timer
//! block whose page this domain maps, and the battery-backed register file
//! behind its two I/O ports. Every number either produces is that device's
//! choice — a period, a counter reading, a packed-decimal byte, a century — and
//! none of them is judged here. `lfw_hpet`, `lfw_clock` and `lfw_rtc` range
//! what they are told and bound every wait by a constant of their own; this
//! file maps a page, claims a port window, and turns whichever of them refused
//! into a console record.
//!
//! # What this domain does NOT do, and why that is the whole design
//!
//! It publishes no calibration to anybody. There is no shared region carrying
//! the frequency and the epoch, because nothing in this system reads time yet:
//! a region nobody maps is a grant nobody uses and an ABI nobody checks
//! (ENG-7). The region lands with its first consumer, and what this domain
//! proves in the meantime is the entire chain that would fill it — HPET,
//! calibration, RTC, UTC, and a rendered line an operator reads.
//!
//! It also does not correct, re-read or discipline anything. The RTC is read
//! exactly once; from there a `Calibration` advances time from the counter. A
//! second reading would be a second epoch to reconcile with the first, which is
//! a clock discipline algorithm and not a boot step.
//!
//! # Why the time this establishes is not trusted time
//!
//! CONCEPT §13.1 leaves the trusted-time mechanism open, and this is not it.
//! The CMOS answer is unauthenticated and unattested; a hypervisor, a dead
//! battery or firmware that set the part to local time all produce a plausible
//! instant this domain cannot tell from a correct one (`lfw_rtc`'s header
//! records the UTC assumption and what it costs). What is established here is a
//! *measured* counter rate and a *stated* epoch — enough to timestamp, and not
//! enough to judge a certificate by. README's status table says so in the row
//! this domain fills in.
//!
//! # Records go to a ring, not to `debug_println!`
//!
//! That macro compiles to `seL4_DebugPutChar`, absent from the release kernel,
//! so a domain that refused to start would reach nobody in the profile that
//! ships. A typed [`Event`] in this domain's own ring, rendered by the console
//! domain, works in both — and the ring is a zeroed region the moment it is
//! mapped, so a record written here survives until the console comes up.
//!
//! # Priority 3, and one millisecond of it
//!
//! The system description sets it and explains it. What matters here is the
//! consequence: this domain preempts the dataplane for the length of one
//! calibration window, once, at boot. [`CALIBRATION_WINDOW`] is what that costs.
//!
//! # No channel, in either direction
//!
//! This domain holds no notification capability and none is held on it. It runs
//! to completion in `init` and then blocks in the Microkit event loop, where
//! nothing can reach it. [`Clock::notified`] exists only because [`Handler`]
//! requires it.

mod cmos;
mod hpet_mmio;

use cmos::{Cmos, PortFault};
use hpet_mmio::HpetPage;
use lfw_clock::{
    Calibration, CalibrationError, CivilTimeError, Duration, NANOS_PER_SECOND, Ticks, calibrate,
};
use lfw_hpet::{Hpet, HpetError, WORST_CASE_SERVICEABLE_WAIT};
use lfw_log::{Domain, DomainDetail, DomainState, Event, Refusal, RefusalDetail, RingSink, Sink};
use lfw_rtc::{Rtc, RtcError};
use pd_runtime::attach_region;
use sel4_microkit::{ChannelSet, Handler, Infallible, protection_domain};
use wire::{LogConsume, LogRecords};

/// How long the timestamp counter is measured against the reference timer.
///
/// A millisecond is the interval `lfw_hpet`'s header derives: it resolves a
/// gigahertz-class counter to better than a part in ten thousand, which is the
/// accuracy a rate measured against a self-describing oscillator is worth
/// asking for. Longer buys precision this domain has no consumer for and costs
/// the dataplane its start-up; shorter runs into the measurement's own overhead,
/// below.
const CALIBRATION_WINDOW: Duration = Duration::from_millis(1);

// The window has to be one the reference timer can actually serve on the least
// favourable block its specification admits, and that bound is `lfw_hpet`'s to
// state rather than this domain's to assume (DOC-7). An order of magnitude of
// headroom, asserted rather than argued.
const _: () = assert!(CALIBRATION_WINDOW.as_nanos() <= WORST_CASE_SERVICEABLE_WAIT.as_nanos());
const _: () = assert!(CALIBRATION_WINDOW.as_nanos() > 0);

/// This domain's lifecycle record.
fn announce(sink: &dyn Sink, state: DomainState, detail: DomainDetail) {
    sink.emit(&Event::Domain {
        domain: Domain::Clock,
        state,
        detail,
    });
}

/// A refusal this domain raises, which never leaves a device mid-sequence.
///
/// `signalled` says whether the device was told to stop, and it is `false` on
/// every refusal here because neither device has a "stop" to be told: the HPET
/// is a free-running counter whose enable bit this domain sets and never
/// clears, and the CMOS is a register file that is only ever read. A domain
/// that refused leaves both exactly as the firmware did.
const fn refusal(cause: &'static str, detail: RefusalDetail) -> Refusal {
    Refusal {
        cause,
        detail,
        signalled: false,
    }
}

/// Why this domain could not establish a time.
///
/// One variant per stage rather than one per cause: the causes belong to the
/// three crates that raise them, and duplicating their trees here would be a
/// second copy to keep in step (`lfw_log::Refusal`'s `cause` is a `&'static str`
/// for that reason). What this enum adds is which stage the refusal came out
/// of, which the tokens then carry into the console line as their prefix.
enum StartupError {
    /// The I/O-port capability did not answer for the CMOS window.
    Port(PortFault),
    /// The timer block was not one this node can measure against, or its
    /// counter would not advance far enough to measure across.
    Reference(HpetError),
    /// The interval was measured and the frequency derived from it is not one
    /// any x86_64 timestamp counter has.
    Calibration(CalibrationError),
    /// The real-time clock named no instant.
    Epoch(RtcError),
    /// The instant the part named cannot be expressed as nanoseconds since the
    /// epoch.
    ///
    /// Unreachable while `lfw_rtc` refuses a year outside
    /// `MIN_PLAUSIBLE_YEAR..=MAX_PLAUSIBLE_YEAR`, whose ceiling is three orders
    /// of magnitude short of what `u64` nanoseconds hold — but that bound is
    /// that crate's and this domain does not restate it, so the multiplication
    /// is checked here rather than assumed (ENG-5). The seconds it refused are
    /// the whole of the diagnosis.
    EpochOutOfRange { unix_seconds: u64 },
}

impl From<HpetError> for StartupError {
    fn from(error: HpetError) -> Self {
        Self::Reference(error)
    }
}

impl From<CalibrationError> for StartupError {
    fn from(error: CalibrationError) -> Self {
        Self::Calibration(error)
    }
}

impl From<RtcError> for StartupError {
    fn from(error: RtcError) -> Self {
        Self::Epoch(error)
    }
}

impl StartupError {
    /// This refusal as the console record of it.
    ///
    /// The mapping is exhaustive over every variant of all four trees, so a
    /// cause added upstream fails this match rather than reaching an operator
    /// as a token that names something else.
    fn refusal(&self) -> Refusal {
        match self {
            Self::Port(fault) => refusal(
                "cmos-ioport-refused",
                RefusalDetail::Two(u64::from(fault.port), u64::from(fault.error)),
            ),
            Self::Reference(error) => reference_refusal(*error),
            Self::Calibration(error) => calibration_refusal(*error),
            Self::Epoch(error) => epoch_refusal(*error),
            Self::EpochOutOfRange { unix_seconds } => {
                refusal("epoch-out-of-range", RefusalDetail::One(*unix_seconds))
            }
        }
    }
}

/// The timer block's refusals. `polls` is `lfw_hpet::COUNTER_POLL_LIMIT` in
/// every variant that carries one — a constant of that crate, known without
/// being transmitted — so the two operands are spent on what varies.
fn reference_refusal(error: HpetError) -> Refusal {
    match error {
        HpetError::NotPresent { capabilities } => {
            refusal("hpet-not-present", RefusalDetail::One(capabilities))
        }
        HpetError::ImplausibleClockPeriod { femtoseconds } => refusal(
            "hpet-implausible-clock-period",
            RefusalDetail::One(u64::from(femtoseconds)),
        ),
        HpetError::CounterTooNarrow { capabilities } => {
            refusal("hpet-counter-too-narrow", RefusalDetail::One(capabilities))
        }
        HpetError::NotEnabled { read_back } => {
            refusal("hpet-not-enabled", RefusalDetail::One(read_back))
        }
        HpetError::CounterStalled { counter, .. } => {
            refusal("hpet-counter-stalled", RefusalDetail::One(counter))
        }
        HpetError::CounterTooSlow {
            observed, wanted, ..
        } => refusal(
            "hpet-counter-too-slow",
            RefusalDetail::Two(observed, wanted),
        ),
        HpetError::DurationTooLong { nanoseconds } => {
            refusal("hpet-duration-too-long", RefusalDetail::One(nanoseconds))
        }
    }
}

/// The measurement's own refusals.
fn calibration_refusal(error: CalibrationError) -> Refusal {
    match error {
        CalibrationError::NoTicksElapsed => refusal("tsc-no-ticks-elapsed", RefusalDetail::None),
        CalibrationError::NoReferenceInterval => {
            refusal("hpet-no-reference-interval", RefusalDetail::None)
        }
        CalibrationError::ImplausiblySlow { hz } => {
            refusal("tsc-implausibly-slow", RefusalDetail::One(hz))
        }
        // Saturating, and the one operand on this path that is not the exact
        // value: the quotient reaching this variant may itself exceed `u64` —
        // a tick delta near `u64::MAX` over a reference interval of one — and
        // the record carries 64-bit operands. `u64::MAX` is not a frequency any
        // part has either, so the saturated number says the same thing the
        // exact one would: far outside the band. The token is what an operator
        // acts on.
        CalibrationError::ImplausiblyFast { hz } => refusal(
            "tsc-implausibly-fast",
            RefusalDetail::One(u64::try_from(hz).unwrap_or(u64::MAX)),
        ),
    }
}

/// The real-time clock's refusals. `polls` and `attempts` are
/// `lfw_rtc::UIP_POLL_LIMIT` and `SNAPSHOT_ATTEMPTS`, constants of that crate,
/// so neither is transmitted.
fn epoch_refusal(error: RtcError) -> Refusal {
    match error {
        RtcError::UpdateNeverCompleted { status_a, .. } => refusal(
            "rtc-update-never-completed",
            RefusalDetail::One(u64::from(status_a)),
        ),
        RtcError::SnapshotsNeverAgreed { .. } => {
            refusal("rtc-snapshots-never-agreed", RefusalDetail::None)
        }
        RtcError::NotBinaryCodedDecimal { register, value } => refusal(
            "rtc-not-binary-coded-decimal",
            RefusalDetail::Two(u64::from(register.index()), u64::from(value)),
        ),
        RtcError::HourOutsideTwelveHourRange { hour, pm } => refusal(
            "rtc-hour-outside-twelve-hour-range",
            RefusalDetail::Two(u64::from(hour), u64::from(pm)),
        ),
        RtcError::ImplausibleYear { year, century } => refusal(
            "rtc-implausible-year",
            RefusalDetail::Two(u64::from(year), u64::from(century)),
        ),
        RtcError::NotACivilInstant { cause, .. } => civil_refusal(cause),
    }
}

/// A civil date the part named that no Unix instant answers to.
///
/// One token per field rather than one for the group, because each names a
/// different thing to go and look at: a month of 13 is a decode that went
/// wrong, and 29 February in a common year is a part whose date survived every
/// range check and is still not a day. The `civil` the error carries is
/// dropped: the field that is wrong travels with the token, and the rest of the
/// date is six more numbers the line has no budget for.
fn civil_refusal(cause: CivilTimeError) -> Refusal {
    match cause {
        CivilTimeError::BeforeEpoch { year } => refusal(
            "rtc-civil-before-epoch",
            RefusalDetail::One(u64::from(year)),
        ),
        CivilTimeError::MonthOutOfRange { month } => refusal(
            "rtc-civil-month-out-of-range",
            RefusalDetail::One(u64::from(month)),
        ),
        // The month beside the day, and the year dropped: a day is out of range
        // *for a month*, and the only case where the year decides is 29
        // February, which the pair already names.
        CivilTimeError::DayOutOfRange { month, day, .. } => refusal(
            "rtc-civil-day-out-of-range",
            RefusalDetail::Two(u64::from(month), u64::from(day)),
        ),
        CivilTimeError::HourOutOfRange { hour } => refusal(
            "rtc-civil-hour-out-of-range",
            RefusalDetail::One(u64::from(hour)),
        ),
        CivilTimeError::MinuteOutOfRange { minute } => refusal(
            "rtc-civil-minute-out-of-range",
            RefusalDetail::One(u64::from(minute)),
        ),
        CivilTimeError::SecondOutOfRange { second } => refusal(
            "rtc-civil-second-out-of-range",
            RefusalDetail::One(u64::from(second)),
        ),
        CivilTimeError::NanosecondOutOfRange { nanosecond } => refusal(
            "rtc-civil-nanosecond-out-of-range",
            RefusalDetail::One(u64::from(nanosecond)),
        ),
    }
}

#[protection_domain]
fn init() -> Clock {
    // Before anything that could have something to say. The region is zeroed by
    // the kernel, so it is a valid empty ring the moment it is mapped, and the
    // console domain drains it whenever it comes up.
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let sink = RingSink::new(log.writer(log_consume));

    announce(&sink, DomainState::Starting, DomainDetail::None);
    match establish() {
        Ok(calibration) => {
            // The instant as of now rather than the anchor itself, which is
            // what makes this line evidence of the whole chain: it is the RTC's
            // epoch advanced by the counter, under the frequency just measured,
            // so a broken conversion shows up here and not only in a host test.
            let now = read_timestamp_counter();
            announce(
                &sink,
                DomainState::Ready,
                DomainDetail::Established {
                    tsc_hz: calibration.tsc_hz(),
                    utc: calibration.utc(now),
                },
            );
        }
        Err(error) => {
            // The whole reason, not a summary: with no shell and no CLI
            // (CONCEPT §11) this record is all an operator gets.
            announce(
                &sink,
                DomainState::Refused,
                DomainDetail::Refusal(error.refusal()),
            );
        }
    }
    Clock
}

/// Measure the counter, read the epoch, and anchor one to the other.
fn establish() -> Result<Calibration, StartupError> {
    // Claimed before the timer is touched, so a domain whose port grant is
    // wrong refuses without having started a counter it cannot report on.
    let port = Cmos::claim().map_err(StartupError::Port)?;

    let hpet = Hpet::probe(HpetPage::map())?;
    let window = hpet.ticks_for(CALIBRATION_WINDOW)?;

    // The two counters are read around the same wait, so both deltas cover one
    // span of real time and their ratio is the frequency. The span the counter
    // delta covers is the *longer* of the two by one reference read at each end
    // — `wait_ticks` reads the timer after the first reading here and before
    // the second — so the derived frequency is an overestimate bounded by that
    // overhead over the window: two uncached reads against a millisecond, which
    // is parts in a thousand at worst. It is stated rather than corrected
    // because subtracting an estimate of the overhead would replace a bounded,
    // one-signed error with an unbounded one, and because nothing consumes this
    // frequency yet.
    let before = read_timestamp_counter();
    let (start, end) = hpet.wait_ticks(window)?;
    let after = read_timestamp_counter();

    // Wrapping, on `wait_ticks`'s own terms: the difference of two readings of
    // a free-running counter is the elapsed count whether or not it crossed the
    // top of `u64` between them. A delta this produces that is *implausible*
    // rather than merely large is what `calibrate` refuses.
    let elapsed = after.0.wrapping_sub(before.0);
    let tsc_hz = calibrate(elapsed, end.wrapping_sub(start), hpet.frequency_hz())?;

    let unix_seconds = Rtc::new(port).read_unix_seconds()?;
    let boot_unix_nanos = unix_seconds
        .checked_mul(NANOS_PER_SECOND)
        .ok_or(StartupError::EpochOutOfRange { unix_seconds })?;
    Ok(Calibration::new(tsc_hz, after, boot_unix_nanos))
}

/// One reading of the x86_64 timestamp counter.
///
/// The reading is deliberately not serialised with an `lfence`. Out-of-order
/// execution moves the instruction by tens of cycles and the window it is
/// measuring is millions, so the serialisation would tighten an error already
/// an order of magnitude below the reference-read overhead named at the call
/// site — and it would do it on the one path where a wrong barrier is
/// indistinguishable from a right one.
fn read_timestamp_counter() -> Ticks {
    // SAFETY: `_rdtsc` requires only that the instruction execute, which is two
    // facts neither this domain nor any first-party crate provides. The target
    // is the guarantor of the first — `RDTSC` has been architectural on x86_64
    // since the ISA existed, and `support/targets/x86_64-sel4-minimal.json` targets
    // nothing else (CON-4). The seL4 kernel is the guarantor of the second: it
    // leaves `CR4.TSD` clear, which is what makes the instruction unprivileged
    // in a protection domain. That is third-party runtime behaviour, recorded
    // rather than asserted — and it is the one step of this argument this
    // domain cannot make for itself. Being wrong about it is a #GP the Microkit
    // monitor reports as a fault in this domain, not a silently wrong number.
    Ticks(unsafe { core::arch::x86_64::_rdtsc() })
}

/// Returned by `init` in every case: this domain runs once and then parks in
/// the Microkit event loop, whether it established a time or refused to.
struct Clock;

impl Handler for Clock {
    type Error = Infallible;

    /// Unreachable by capability: nothing in this system holds a notification
    /// capability on this domain, so the event loop it parks in has no sender.
    /// It exists because [`Handler`] requires it; see the crate header.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        Ok(())
    }
}
