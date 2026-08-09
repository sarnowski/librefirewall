#![no_main]
#![no_std]

//! Clock protection domain: it establishes what time it is, says so, and from
//! then on announces that time has passed.
//!
//! Five steps, in one `init` that never runs again: probe the HPET and start
//! its counter, measure the timestamp counter against it, read the CMOS
//! real-time clock for an epoch to anchor that counter to, publish one record
//! stating the frequency it measured and the instant it established, and arm
//! one of the block's comparators to raise an interrupt on a period. After that
//! it does one thing, for ever: on each of those interrupts it acknowledges the
//! kernel and signals the management domain.
//!
//! # Adversary
//!
//! The **hostile or malfunctioning device**, twice over: the timer
//! block whose page this domain maps, and the battery-backed register file
//! behind its two I/O ports. Every number either produces is that device's
//! choice — a period, a counter reading, a packed-decimal byte, a century — and
//! none of them is judged here. `lfw_hpet`, `lfw_clock` and `lfw_rtc` range
//! what they are told and bound every wait by a constant of their own; this
//! file maps a page, claims a port window, and turns whichever of them refused
//! into a console record.
//!
//! # It publishes what it measured, once, and to one reader
//!
//! The calibration goes into a shared region (`wire::ClockCalibration`) the
//! management domain maps read-only; it arrived with its first consumer, the
//! condition the note it replaces set.
//! **Publishing is the last thing this domain does**, after the record saying what
//! it measured, so an operator reading a frequency off the line and a domain
//! converting readings with one never see different numbers. A refusal publishes
//! nothing: a zeroed region is one no reader takes, so a domain that could not
//! establish a time leaves the port unclocked rather than clocked wrongly.
//!
//! It does not correct, re-read or discipline anything. The RTC is read
//! exactly once; from there a `Calibration` advances time from the counter. A
//! second reading would be a second epoch to reconcile with the first, which is
//! a clock discipline algorithm and not a boot step.
//!
//! # Why the time this establishes is not trusted time
//!
//! The design leaves the trusted-time mechanism open, and this is not it.
//! The CMOS answer is unauthenticated and unattested; a hypervisor, a dead
//! battery or firmware that set the part to local time all produce a plausible
//! instant this domain cannot tell from a correct one (`lfw_rtc`'s header
//! records the UTC assumption and what it costs). What is established here is a
//! *measured* counter rate and a *stated* epoch — enough to timestamp, and not
//! enough to judge a certificate by.
//!
//! # Records go to a ring, not to `debug_println!`
//!
//! That macro compiles to `seL4_DebugPutChar`, absent from the release kernel,
//! so a domain that refused to start would reach nobody in the profile that
//! ships. A typed [`Event`] in this domain's own ring, rendered by the console
//! domain, works in both — and the ring is a zeroed region the moment it is
//! mapped, so a record written here survives until the console comes up.
//!
//! # It is the only domain that can know time has passed, so it is the one that
//! # says so
//!
//! Nothing in this appliance is woken by the passage of time. A protection
//! domain is entered when a frame arrives or when a peer signals it, so a domain
//! holding a deadline and no traffic sits at that deadline for ever — and the
//! management channel's every schedule is exactly that shape: a reconnection
//! backoff, an acknowledgement cadence, a flush that owes a send once a second.
//! A silent link produces no frame, which is precisely the condition those
//! schedules exist for.
//!
//! This domain maps the timer block, so it is the only one that can be told by
//! hardware that an interval has elapsed. [`TICK_PERIOD`] is the interval it
//! asks for, and what it does with the answer is signal the domain that has an
//! obligation time creates. **The signal carries nothing.** The receiver maps
//! the calibration this domain published and reads the timestamp counter itself,
//! so an instant sent alongside would be a second statement of one fact, and the
//! two would differ by however long the signal took.
//!
//! # A tick costs a constant, and one that arrives early costs nothing
//!
//! [`Clock::notified`] acknowledges, counts, signals and publishes: no loop, no
//! device access, and nothing whose length depends on anything. It cannot fall
//! behind either, and that is the kernel's doing rather than this file's — an
//! interrupt stays masked until it is acknowledged, and a notification is a flag
//! rather than a queue, so a period that elapsed while the previous one was
//! being served is one wakeup and not two waiting.
//!
//! # A node that cannot be woken still forwards, and still says so
//!
//! Arming can fail — a comparator that cannot re-arm itself, one that cannot
//! drive the interrupt this build holds, one that drops what is written to it.
//! It is reported as a refusal on a `ready` record and nothing else happens: the
//! calibration stands, the dataplane forwards, and the management domain is
//! woken by frames exactly as it was before this domain gained a timer. Failing
//! closed would be an appliance that stops forwarding because a timer chip is
//! absent, which is a worse node than one whose schedules are coarse.
//!
//! # Priority 3, and what it now costs
//!
//! The system description sets it and explains it. The consequence used to be
//! one calibration window at boot; it is now that plus one preemption of the
//! dataplane every [`TICK_PERIOD`], each of them the constant above.
//! [`CALIBRATION_WINDOW`] is what the first costs.
//!
//! # Two channels, and neither is a way in
//!
//! [`TICK`] is an interrupt, not a peer: no domain in this system can raise it,
//! and the only thing that arrives on it is the block this domain programmed.
//! [`MANAGEMENT`] is a send capability and nothing holds one on this domain, so
//! the event loop below has no sender but the timer.

mod cmos;
mod hpet_mmio;

use cmos::{Cmos, PortFault};
use hpet_mmio::HpetPage;
use lfw_clock::{
    Calibration, CalibrationError, CivilTimeError, Duration, NANOS_PER_SECOND, calibrate,
};
use lfw_hpet::{Hpet, HpetError, MAX_PERIODIC_TICKS, TimerError, WORST_CASE_SERVICEABLE_WAIT};
use lfw_log::{Domain, DomainDetail, DomainState, Event, Refusal, RefusalDetail, RingSink, Sink};
use lfw_metrics::{ClockSample, StatsShard};
use lfw_rtc::{Rtc, RtcError};
use pd_runtime::{PdClock, TICK_PERIOD, attach_region, log_sample, read_timestamp_counter};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, protection_domain};
use wire::{CalibrationImage, ClockCalibration, LogConsume, LogRecords};

/// The interrupt the timer block raises, and the only thing that can enter this
/// domain after `init`. It is an `<irq>` rather than a peer's channel: no
/// protection domain in this system can raise it.
const TICK: Channel = Channel::new(0);

/// The management domain, and the one send capability this domain holds. It
/// blocks in the Microkit event loop and reads no clock of its own, so an
/// interval that elapsed is invisible to it until it is woken.
const MANAGEMENT: Channel = Channel::new(1);

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
// state rather than this domain's to assume. Two orders of magnitude of
// headroom — a millisecond against a hundred — asserted rather than argued.
const _: () = assert!(CALIBRATION_WINDOW.as_nanos() <= WORST_CASE_SERVICEABLE_WAIT.as_nanos());
const _: () = assert!(CALIBRATION_WINDOW.as_nanos() > 0);

// The interval `pd_runtime` chose has to be one a periodic comparator can
// actually be armed with on the slowest counter the block's specification
// admits, and that bound is `lfw_hpet`'s to state rather than this domain's to
// assume: a hundred milliseconds of a 10 MHz counter is a million ticks against
// a bound of two thousand million. Asserted here because this is the domain
// that arms it.
const _: () = assert!(
    TICK_PERIOD.as_nanos() / (NANOS_PER_SECOND / lfw_hpet::MIN_FREQUENCY_HZ) <= MAX_PERIODIC_TICKS
);

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
    /// is checked here rather than assumed. The seconds it refused are
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

/// The periodic wakeup's refusals, in the vocabulary a console line speaks.
///
/// Its own function beside the three above because what it reports is a
/// different outcome: those three end with no time established, and every one of
/// these leaves the node clocked, forwarding and answering its port — and only
/// its schedules coarse. Which is why they ride on a `ready` record.
fn timer_refusal(error: TimerError) -> Refusal {
    match error {
        TimerError::NotPeriodicCapable { configuration } => {
            refusal("hpet-timer-not-periodic", RefusalDetail::One(configuration))
        }
        // The pin beside the bitmap: the bitmap alone says which inputs the
        // block offers and not which one this build asked it for.
        TimerError::RouteUnavailable { route_cap } => refusal(
            "hpet-timer-route-unavailable",
            RefusalDetail::Two(u64::from(route_cap), u64::from(lfw_hpet::INTERRUPT_PIN)),
        ),
        TimerError::PeriodTooShort { nanoseconds } => refusal(
            "hpet-timer-period-too-short",
            RefusalDetail::One(nanoseconds),
        ),
        // Saturating, on `tsc-implausibly-fast`'s terms: the count reaching this
        // variant may itself exceed `u64`, and a saturated number says what the
        // exact one would — far past the bound. The bound travels beside it,
        // because a count with nothing to compare it against is unreadable.
        TimerError::PeriodTooLong { ticks } => refusal(
            "hpet-timer-period-too-long",
            RefusalDetail::Two(u64::try_from(ticks).unwrap_or(u64::MAX), MAX_PERIODIC_TICKS),
        ),
        TimerError::NotArmed { read_back } => {
            refusal("hpet-timer-not-armed", RefusalDetail::One(read_back))
        }
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
    let published: &'static ClockCalibration = attach_region!(clock_vaddr: ClockCalibration);
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(published));
    let stats: &'static StatsShard = attach_region!(stats_vaddr: StatsShard);

    announce(&sink, DomainState::Starting, DomainDetail::None);
    let mut frequency_hertz = 0;
    let mut ticking = false;
    match establish() {
        Ok(Started { calibration, tick }) => {
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
            // After the record, and only on the path that established a time; see
            // the crate header on why the order and the silence both matter.
            published.publish(&CalibrationImage {
                tsc_hz: calibration.tsc_hz().get(),
                boot_ticks: calibration.boot_ticks().0,
                boot_unix_nanos: calibration.boot_unix_nanos(),
            });
            frequency_hertz = calibration.tsc_hz().get();
            // After the calibration and its record, so a node that established
            // a time says so before it says anything about its wakeups — and
            // so an operator reading a refusal here knows the two are separate
            // facts about one boot.
            match tick {
                Ok(_) => ticking = true,
                Err(error) => announce(
                    &sink,
                    DomainState::Ready,
                    DomainDetail::Refusal(timer_refusal(error)),
                ),
            }
        }
        Err(error) => {
            // The whole reason, not a summary: with no shell and no CLI
            // on the appliance, this record is all an operator gets.
            announce(
                &sink,
                DomainState::Refused,
                DomainDetail::Refusal(error.refusal()),
            );
        }
    }
    // The last record this domain will ever emit, and so the last change its log
    // counts will ever take: everything after this point is a tick, and a tick
    // says nothing. A refusal leaves the frequency at zero, which is what "this
    // node measured nothing" reads as.
    let sample = ClockSample {
        frequency_hertz,
        ticks: 0,
        log: log_sample(sink.dropped(), sink.refused()),
    };
    stats.publish(&sample.values());
    if ticking {
        Clock::Ticking(Ticking { stats, sample })
    } else {
        Clock::Parked
    }
}

/// What one boot of this domain established: a time, and either a periodic
/// wakeup or the reason there is none.
///
/// The two travel together because they are made together and reported
/// together, and separating them would let a caller publish one without ever
/// looking at the other.
struct Started {
    calibration: Calibration,
    /// The accumulator the comparator was armed with, or why it was not.
    tick: Result<u64, TimerError>,
}

/// Measure the counter, read the epoch, anchor one to the other, and arm the
/// wakeup.
fn establish() -> Result<Started, StartupError> {
    // Claimed before the timer is touched, so a domain whose port grant is
    // wrong refuses without having started a counter it cannot report on.
    let port = Cmos::claim().map_err(StartupError::Port)?;

    let mut hpet = Hpet::probe(HpetPage::map())?;
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
    // Against the block's truncated frequency rather than its period, which is
    // consistent with `ticks_for` dividing by the period and not at odds with it:
    // the truncation is a part in 10^8, three orders below the two-read overhead
    // above, and a rate is the form `calibrate` takes.
    let tsc_hz = calibrate(elapsed, end.wrapping_sub(start), hpet.frequency_hz())?;

    let unix_seconds = Rtc::new(port).read_unix_seconds()?;
    // After the register file and not before it: a `Calibration`'s reading and its
    // instant claim to name the *same* moment, and the read above spends port
    // operations of its own — bounded by `lfw_rtc::READ_PORT_OPS_MAX`, ordinarily
    // a handful plus a wait on the update in progress bit. Anchoring on the
    // calibration window's last reading would date the node that span early and
    // run every timestamp it later emits fast by it.
    let anchor = read_timestamp_counter();
    let boot_unix_nanos = unix_seconds
        .checked_mul(NANOS_PER_SECOND)
        .ok_or(StartupError::EpochOutOfRange { unix_seconds })?;

    // Last, and after the anchor: arming spends device accesses of its own, and
    // a reading taken before them and paired with an instant read after them
    // would date this node by however long the block took to answer. It is also
    // the one step whose failure is not this function's to refuse — a node with
    // a time and no wakeup is a node, and a node with no time is not.
    let tick = hpet.arm_periodic(TICK_PERIOD);

    Ok(Started {
        calibration: Calibration::new(tsc_hz, anchor, boot_unix_nanos),
        tick,
    })
}

/// What this domain does for the rest of the boot.
///
/// Two states rather than a flag, because the difference is what the event loop
/// does: a parked domain has no shard to move and must not be woken into
/// pretending it has one. Nothing can wake it either — a domain that could not
/// arm its comparator holds an interrupt the block will never raise.
enum Clock {
    Ticking(Ticking),
    /// A domain with no wakeup: it established a time and could not arm one, or
    /// it refused and has no time to keep. Its shard was published in `init` and
    /// nothing will move it.
    Parked,
}

/// The whole of what a tick touches.
struct Ticking {
    stats: &'static StatsShard,
    /// Republished on every tick. Every field but the count was fixed in `init`
    /// — this domain emits no record after it — so the shard is carried whole
    /// rather than recomposed from parts that cannot change.
    sample: ClockSample,
}

impl Handler for Clock {
    type Error = Infallible;

    /// One period has elapsed: tell the kernel, count it, wake the domain that
    /// has a deadline, and publish.
    ///
    /// The channel is not inspected. This domain has exactly one thing that can
    /// enter it and the kernel names it in `channels`, so comparing the two
    /// would be this domain checking the kernel's arithmetic against a constant
    /// of its own — and a wakeup on any other channel is one no capability in
    /// this system can produce.
    ///
    /// The acknowledgement comes first so the next period is not spent masked,
    /// and the signal before the shard so a scrape never overtakes the wakeup it
    /// is evidence of.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        let Self::Ticking(ticking) = self else {
            return Ok(());
        };
        // Infallible in practice and not by type: the only error this can carry
        // is a capability this domain was not granted, which is a build fact
        // rather than a run-time condition, and a domain that stopped
        // acknowledging would stop being woken — which the count says.
        let _ = TICK.irq_ack();
        ticking.sample.ticks = ticking.sample.ticks.saturating_add(1);
        MANAGEMENT.notify();
        ticking.stats.publish(&ticking.sample.values());
        Ok(())
    }
}
