//! Time arithmetic: a raw timestamp-counter reading turned into nanoseconds
//! since boot, nanoseconds since the Unix epoch, a civil (Gregorian) date, and
//! an RFC 3339 line.
//!
//! Nothing here reads a counter, and no function takes a reference to one: a
//! caller supplies every reading as a value. That split is the point. Reading
//! the TSC is one instruction whose result is a hardware fact, and calibrating
//! it against a reference timer is a capability a protection domain must be
//! granted; the conversion arithmetic is neither, and it is the part that can be
//! driven exhaustively by a host test. The system this lands in is one where
//! no record is timestamped and no time source is trusted, a record being
//! ordered by `(generation, seq)` within a boot — this crate is the arithmetic
//! half of the source that would change that, and it changes no exposed signal
//! on its own.
//!
//! # The adversary
//!
//! No adversary reaches this crate directly: there is no device
//! register, no shared region and no network byte in it, and every argument is
//! an integer a first-party caller computed. Being out of an adversary's reach
//! is not a licence — only seL4, Microkit and `rust-sel4` are trusted, and
//! nothing first-party inherits that status — so the obligation carried here is
//! the one an input path would carry: every function is total over the whole of
//! its argument domain, every product that could leave `u64` is widened rather
//! than wrapped, and a value that cannot be interpreted comes back as a typed
//! error rather than a panic.
//!
//! That is not defensive habit. The numbers a caller will supply are
//! first-party only in the last step: a calibration interval is measured
//! against a hardware timer, so a **hostile or malfunctioning device**
//! stands one indirection behind [`calibrate`]'s arguments, and a crate that
//! assumed its caller had already judged them would put that judgement nowhere.
//! [`calibrate`] therefore decides plausibility itself, against
//! [`MIN_PLAUSIBLE_TSC_HZ`] and [`MAX_PLAUSIBLE_TSC_HZ`].
//!
//! # Why the conversion is widened
//!
//! `ticks * 1_000_000_000 / tsc_hz` is the whole of the tick-to-nanosecond
//! conversion, and its numerator leaves `u64` at 18.4 billion ticks — about
//! eighteen seconds of a 1 GHz counter. Computing it in `u64` would therefore
//! wrap on a node that had been up for half a minute. It is computed in `u128`
//! and narrowed once, at the end.
//!
//! Two cheaper shapes were rejected. Dividing first (`ticks / tsc_hz *
//! 1_000_000_000`) stays in `u64` and discards every sub-second digit, the only
//! part of a timestamp a reader compares. A precomputed fixed-point reciprocal
//! would remove the division and add an error budget to prove — worth it on a
//! dataplane path, and this is not one.
//!
//! Floating point is not used at all. A protection domain would have to
//! establish FPU state to reach it, and a rounded conversion has no exact
//! inverse, which would cost the round-trip property the calendar code is
//! checked by.
//!
//! # Why the calendar is Hinnant's algorithm and not a table
//!
//! `civil_from_days` and `days_from_civil` are Howard Hinnant's era
//! decomposition: shift the epoch to 0000-03-01 so that a leap day falls at the
//! end of a year, then divide the day count into 400-year eras. The
//! four-century rule lives in the era arithmetic rather than in a
//! `year % 400` branch, and the pair are exact inverses over the whole range —
//! which is what makes the exhaustive round-trip below a proof rather than a
//! sample. A month-length table walked in a loop would need its own bound and
//! would put the leap rule in the one place a reader cannot check by
//! inspection.
//!
//! Unix time excludes leap seconds, so a day here is exactly 86 400 seconds.
//! That is what makes the inverse exact, and it is also the reason a second of
//! 60 is refused by [`CivilTime::to_unix_seconds`]: the value a leap second
//! would need has no Unix instant to map to.
//!
//! # Rejected: a calendar dependency
//!
//! `chrono` and `time` are pure Rust, as first-party userspace must stay, but
//! neither is a pinned input, both carry a `std`-leaning surface far
//! larger than the two dozen lines of integer arithmetic actually wanted, and
//! neither could be held to the coverage floor as first-party code is. The
//! algorithm is public and short enough to test exhaustively, which is the
//! stronger position.
//!
//! # Where a wall-clock reading can come from
//!
//! [`Ticks`] is transparent: a caller reads the counter and hands the number
//! over. [`Monotonic`] is not constructible from an integer at all and only a
//! [`Calibration`] produces one, so an uptime cannot be composed by a caller
//! that never established its counter's frequency. [`UtcNanos`] carries that
//! rule and one exception, [`UtcNanos::from_unix_nanos`]: an instant already
//! established elsewhere and published as a count is one to reconstruct rather
//! than compose, and re-deriving a calendar from it would put a second copy of
//! this arithmetic wherever one is read. [`Duration`] is opaque for neither
//! reason: a caller authors a duration rather than observing one.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::num::NonZeroU64;

/// Nanoseconds in a second — the scale [`Monotonic`] and [`UtcNanos`] count in.
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

const NANOS_PER_MICROSECOND: u64 = 1_000;
const NANOS_PER_MILLISECOND: u64 = 1_000_000;

const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 60 * SECONDS_PER_MINUTE;
const SECONDS_PER_DAY: u64 = 24 * SECONDS_PER_HOUR;
const NANOS_PER_DAY: u64 = SECONDS_PER_DAY * NANOS_PER_SECOND;

/// The first year a [`CivilTime`] can be converted back to a Unix instant:
/// before it, a count of seconds since the epoch would be negative and `u64`
/// has no room for one.
pub const UNIX_EPOCH_YEAR: u16 = 1970;

/// Days per 400-year era, and years per era: the period over which the
/// Gregorian leap rule repeats exactly.
const DAYS_PER_ERA: u64 = 146_097;
const YEARS_PER_ERA: u64 = 400;

/// Days from 0000-03-01 — the shifted epoch Hinnant's decomposition counts
/// from, chosen so a leap day is the last day of a year — to 1970-01-01.
const DAYS_FROM_SHIFTED_EPOCH_TO_UNIX: u64 = 719_468;

/// Days per four years, per century and per era in the shifted calendar, as the
/// year-of-era recovery needs them.
const DAYS_PER_4_YEARS: u64 = 1_460;
const DAYS_PER_CENTURY: u64 = 36_524;
const DAYS_PER_ERA_LESS_ONE: u64 = 146_096;
const DAYS_PER_COMMON_YEAR: u64 = 365;

/// The lowest derived frequency [`calibrate`] will accept, in hertz.
///
/// The invariant TSC of an x86_64 part is driven from the core crystal at the
/// part's nominal frequency; the slowest x86_64 CPUs ever shipped are in the
/// hundreds of megahertz, so 10 MHz is more than an order of magnitude below
/// anything real. A derived frequency under it is therefore a statement about
/// the *measurement* — too few ticks observed for the reference interval, which
/// is what a reference timer that reports an interval it did not measure looks
/// like — and not about the part.
pub const MIN_PLAUSIBLE_TSC_HZ: u64 = 10_000_000;

/// The highest derived frequency [`calibrate`] will accept, in hertz.
///
/// No x86_64 part's invariant TSC runs above roughly 6 GHz, so 100 GHz leaves
/// more than an order of magnitude of headroom over anything that could ship
/// while still catching the failure that matters: a reference interval reported
/// far shorter than it was, which inflates the quotient without bound.
pub const MAX_PLAUSIBLE_TSC_HZ: u64 = 100_000_000_000;

// A band with an empty interior would reject every measurement, and one whose
// floor were zero would admit a stopped counter as a calibrated one.
const _: () = assert!(MIN_PLAUSIBLE_TSC_HZ > 0);
const _: () = assert!(MIN_PLAUSIBLE_TSC_HZ < MAX_PLAUSIBLE_TSC_HZ);

/// The years a boot instant may fall in, from which the band below is derived.
///
/// Private, because the band a caller applies is the nanosecond one: a year is
/// what a register file reports and nanoseconds are what a [`Calibration`] holds.
/// `lfw_rtc` states the same two years at its own granularity, and a test there
/// holds the two statements together.
const MIN_PLAUSIBLE_EPOCH_YEAR: u16 = 2000;
const MAX_PLAUSIBLE_EPOCH_YEAR: u16 = 2200;

/// Midnight UTC opening the first year a boot instant may fall in.
pub const MIN_PLAUSIBLE_UNIX_NANOS: u64 = year_start_unix_nanos(MIN_PLAUSIBLE_EPOCH_YEAR);

/// The last nanosecond of the final year a boot instant may fall in — the end of
/// that year and not its start, a band closing at its midnight having refused
/// every instant inside the year it names.
pub const MAX_PLAUSIBLE_UNIX_NANOS: u64 = year_start_unix_nanos(MAX_PLAUSIBLE_EPOCH_YEAR + 1) - 1;

/// Whether an instant is one this node will date a record with.
///
/// Beside [`MIN_PLAUSIBLE_TSC_HZ`]'s judgement and for its reason: both halves of
/// a [`Calibration`] arrive from a device one indirection away, and a frequency
/// ranged while its epoch is not leaves a reader converting readings into a year
/// no appliance runs in. An instant outside the band states something about the
/// *source* — a dead battery, packed decimal read as binary, a peer publishing
/// whatever it likes — and nothing about the node's uptime.
#[must_use]
pub const fn epoch_is_plausible(unix_nanos: u64) -> bool {
    unix_nanos >= MIN_PLAUSIBLE_UNIX_NANOS && unix_nanos <= MAX_PLAUSIBLE_UNIX_NANOS
}

/// Nanoseconds since the Unix epoch at midnight UTC opening `year`.
///
/// A refusal is a build error rather than a value, which is why the band is
/// computed at compile time: every year passed here is a literal above the epoch,
/// and a change that made one refusable fails the build instead of shipping zero.
const fn year_start_unix_nanos(year: u16) -> u64 {
    let midnight = CivilTime {
        year,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
        nanosecond: 0,
    };
    match midnight.to_unix_seconds() {
        Ok(seconds) => seconds * NANOS_PER_SECOND,
        Err(_) => panic!("the first of January names a Unix instant in every year after 1970"),
    }
}

// An empty interior would refuse every instant, and a floor of zero would admit
// the epoch itself — exactly what an unset register file reports.
const _: () = assert!(MIN_PLAUSIBLE_UNIX_NANOS > 0);
const _: () = assert!(MIN_PLAUSIBLE_UNIX_NANOS < MAX_PLAUSIBLE_UNIX_NANOS);

/// A raw reading of the x86_64 timestamp counter.
///
/// Transparent, because it is one hardware number and this crate can say
/// nothing more about it than the caller who read it already knows: not which
/// core produced it, not whether that core's counter is invariant, and not
/// whether it is the same counter a [`Calibration`] was built against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ticks(pub u64);

/// Nanoseconds since the boot reading a [`Calibration`] was anchored on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Monotonic(u64);

impl Monotonic {
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// Truncating, as every coarser view below is: a reader that wants the
    /// nanoseconds asks for them, and a rounded microsecond would make two
    /// views of one reading disagree about which second it fell in.
    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0 / NANOS_PER_MICROSECOND
    }

    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0 / NANOS_PER_MILLISECOND
    }

    /// The instant `span` after this one, saturating in [`Duration::from_millis`]'s
    /// direction: a wrap would turn the furthest future instant into one already
    /// past, which for a deadline is the difference between waiting and firing at
    /// once. It exists so a deadline needs no way to build a [`Monotonic`] from an
    /// integer, which would give up the guarantee the crate header states.
    #[must_use]
    pub const fn saturating_add(self, span: Duration) -> Self {
        Self(self.0.saturating_add(span.as_nanos()))
    }

    /// How long after `earlier` this instant is, saturating at zero for
    /// [`Calibration::monotonic`]'s reason: a reading behind an earlier one is a
    /// counter that moved backwards, and no elapsed time answers it.
    #[must_use]
    pub const fn since(self, earlier: Self) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }
}

/// Nanoseconds since 1970-01-01T00:00:00Z, excluding leap seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcNanos(u64);

impl UtcNanos {
    /// An instant another component established; see the crate header.
    #[must_use]
    pub const fn from_unix_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn unix_seconds(self) -> u64 {
        self.0 / NANOS_PER_SECOND
    }
}

/// A span of time, in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(u64);

impl Duration {
    /// Saturating, and deliberately in that direction: the value that saturates
    /// is 585 years, so the only spans affected are ones no wait or interval
    /// describes, and a wrap would turn the longest expressible span into a
    /// near-zero one — the dangerous way round for anything a caller uses to
    /// bound a wait.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis.saturating_mul(NANOS_PER_MILLISECOND))
    }

    #[must_use]
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros.saturating_mul(NANOS_PER_MICROSECOND))
    }

    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }
}

/// Why a measured interval did not yield a usable counter frequency.
///
/// One variant per cause, and each carries what was derived, because an
/// operator with no shell separates a reference timer that
/// reported nothing from one that reported an interval it did not measure only
/// if the two produce different lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalibrationError {
    /// The counter did not advance across the interval. Nothing can be derived
    /// from it: a stopped counter and an interval measured across no time at
    /// all are the same observation.
    NoTicksElapsed,
    /// The reference timer reported an interval of zero, which no division can
    /// be taken against.
    NoReferenceInterval,
    /// The derived frequency is below [`MIN_PLAUSIBLE_TSC_HZ`]. Zero appears
    /// here rather than in a variant of its own: it is the extreme of the same
    /// cause, reached when the tick delta is small relative to the reference
    /// interval.
    ImplausiblySlow { hz: u64 },
    /// The derived frequency is above [`MAX_PLAUSIBLE_TSC_HZ`], carrying the
    /// exact quotient.
    ///
    /// `u128` rather than `u64` because the quotient reaching this variant may
    /// itself exceed `u64` — a tick delta near `u64::MAX` over a reference
    /// interval of one — and narrowing it for the report would print a
    /// plausible-looking frequency for the very measurement the band exists to
    /// refuse.
    ImplausiblyFast { hz: u128 },
}

/// Derive a counter frequency from a tick delta measured across a reference
/// interval of a known-rate timer.
///
/// `reference_elapsed` is counted in `reference_hz` units, so
/// `ticks_elapsed / (reference_elapsed / reference_hz)` is the frequency, and
/// the multiplication is done first and in `u128` to keep the whole
/// significance of a short interval.
pub fn calibrate(
    ticks_elapsed: u64,
    reference_elapsed: u64,
    reference_hz: NonZeroU64,
) -> Result<NonZeroU64, CalibrationError> {
    if ticks_elapsed == 0 {
        return Err(CalibrationError::NoTicksElapsed);
    }
    if reference_elapsed == 0 {
        return Err(CalibrationError::NoReferenceInterval);
    }

    // Both factors are `u64`, so the product is at most `(2^64 - 1)^2`, which
    // is below `u128::MAX`: the widening is not a margin, it is exact.
    let derived = (ticks_elapsed as u128 * reference_hz.get() as u128) / reference_elapsed as u128;
    if derived > MAX_PLAUSIBLE_TSC_HZ as u128 {
        return Err(CalibrationError::ImplausiblyFast { hz: derived });
    }

    // Below the ceiling, so within `u64` and exact. The two refusals below are
    // ordered so that neither arm is unreachable: the quotient can genuinely be
    // zero, and zero is reported as the slow case it is rather than as a
    // separate cause.
    let derived = derived as u64;
    let Some(hz) = NonZeroU64::new(derived) else {
        return Err(CalibrationError::ImplausiblySlow { hz: derived });
    };
    if hz.get() < MIN_PLAUSIBLE_TSC_HZ {
        return Err(CalibrationError::ImplausiblySlow { hz: hz.get() });
    }
    Ok(hz)
}

/// What a node needs to turn a counter reading into a time: the counter's
/// frequency, the reading taken at boot, and the wall-clock instant that
/// reading corresponds to.
///
/// The frequency is a [`NonZeroU64`] rather than a checked `u64`, so the
/// division below has no zero case to reject and no caller has one to remember.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Calibration {
    tsc_hz: NonZeroU64,
    boot_ticks: Ticks,
    boot_unix_nanos: u64,
}

impl Calibration {
    #[must_use]
    pub const fn new(tsc_hz: NonZeroU64, boot_ticks: Ticks, boot_unix_nanos: u64) -> Self {
        Self {
            tsc_hz,
            boot_ticks,
            boot_unix_nanos,
        }
    }

    #[must_use]
    pub const fn tsc_hz(&self) -> NonZeroU64 {
        self.tsc_hz
    }

    #[must_use]
    pub const fn boot_ticks(&self) -> Ticks {
        self.boot_ticks
    }

    #[must_use]
    pub const fn boot_unix_nanos(&self) -> u64 {
        self.boot_unix_nanos
    }

    /// Nanoseconds since boot for `now`.
    ///
    /// A reading below the boot reading yields zero rather than an error. This
    /// is hardware semantics, not a convenience: the TSC is per-core, the
    /// architecture does not guarantee that two cores' counters agree, and a
    /// migrated or restored virtual machine can observe one that moved
    /// backwards. There is no elapsed time to report in any of those cases, and
    /// a signed or wrapping answer would report a 584-year uptime instead.
    #[must_use]
    pub const fn monotonic(&self, now: Ticks) -> Monotonic {
        let elapsed = now.0.saturating_sub(self.boot_ticks.0);
        // The numerator leaves `u64` at eighteen seconds of a 1 GHz counter,
        // which is why it is formed in `u128` and narrowed after the division.
        let nanos = (elapsed as u128 * NANOS_PER_SECOND as u128) / self.tsc_hz.get() as u128;
        if nanos > u64::MAX as u128 {
            Monotonic(u64::MAX)
        } else {
            Monotonic(nanos as u64)
        }
    }

    /// The wall-clock instant of `now`, as nanoseconds since the Unix epoch.
    ///
    /// Saturating at the top for the reason [`Monotonic`] saturates: an uptime
    /// that has run the counter past what `u64` nanoseconds can express is a
    /// counter this crate cannot describe, and a wrap would place the node in
    /// 1970.
    #[must_use]
    pub const fn utc(&self, now: Ticks) -> UtcNanos {
        UtcNanos(
            self.boot_unix_nanos
                .saturating_add(self.monotonic(now).as_nanos()),
        )
    }
}

/// A civil (proleptic Gregorian) date and time in UTC.
///
/// The fields are public and unvalidated because both directions need that: one
/// is produced by [`from_utc`](Self::from_utc) from an instant that cannot be
/// invalid, and the other is composed field by field from an operator's input,
/// where every field is a separate thing to reject. A validated constructor
/// would therefore need a second, unvalidated type beside it to parse into.
/// Validity is decided in exactly one place instead — by
/// [`to_unix_seconds`](Self::to_unix_seconds), which is the only operation that
/// needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CivilTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanosecond: u32,
}

/// Why a civil time named no Unix instant.
///
/// One variant per field, each carrying the value that was refused, so a
/// rejected configuration line says which field to fix rather than that
/// something in it was wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CivilTimeError {
    /// Before [`UNIX_EPOCH_YEAR`], so the instant precedes the epoch and no
    /// count of seconds since it exists.
    BeforeEpoch {
        year: u16,
    },
    MonthOutOfRange {
        month: u8,
    },
    /// Zero, or past the end of that month in that year — which is where the
    /// leap rule is enforced, 29 February being valid in one year and not the
    /// next.
    DayOutOfRange {
        year: u16,
        month: u8,
        day: u8,
    },
    HourOutOfRange {
        hour: u8,
    },
    MinuteOutOfRange {
        minute: u8,
    },
    /// Past 59. A leap second would be second 60, and Unix time has no instant
    /// for one.
    SecondOutOfRange {
        second: u8,
    },
    /// A whole second or more of sub-second remainder.
    NanosecondOutOfRange {
        nanosecond: u32,
    },
}

impl CivilTime {
    /// The civil time of an instant.
    ///
    /// Total: every [`UtcNanos`] names a civil time, and every field of the
    /// result is in range because the instant it came from was.
    #[must_use]
    pub const fn from_utc(time: UtcNanos) -> Self {
        let nanos = time.as_nanos();
        let nanos_of_day = nanos % NANOS_PER_DAY;
        let seconds_of_day = nanos_of_day / NANOS_PER_SECOND;
        let (year, month, day) = civil_from_days(nanos / NANOS_PER_DAY);

        // Every narrowing here is lossless, and each is bounded by something
        // stated rather than assumed: `MAX_CIVIL_YEAR` is asserted below to fit
        // four digits, the calendar decomposition confines the month to 1..=12
        // and the day to 1..=31, and `nanos_of_day` is a remainder modulo one
        // day, so the clock fields cannot reach 24, 60 and 60 respectively.
        Self {
            year: year as u16,
            month: month as u8,
            day: day as u8,
            hour: (seconds_of_day / SECONDS_PER_HOUR) as u8,
            minute: (seconds_of_day / SECONDS_PER_MINUTE % SECONDS_PER_MINUTE) as u8,
            second: (seconds_of_day % SECONDS_PER_MINUTE) as u8,
            nanosecond: (nanos_of_day % NANOS_PER_SECOND) as u32,
        }
    }

    /// Whole seconds since the Unix epoch, or the first field that named no
    /// instant.
    ///
    /// The exact inverse of [`from_utc`](Self::from_utc) at second resolution.
    /// The `nanosecond` field is validated and then does not contribute, which
    /// is deliberate: silently accepting an out-of-range remainder while
    /// dropping it would tell a caller its value was understood when it was not.
    ///
    /// Fields are checked most-significant first, so the error names the first
    /// thing actually wrong rather than whichever check ran last.
    pub const fn to_unix_seconds(&self) -> Result<u64, CivilTimeError> {
        if self.year < UNIX_EPOCH_YEAR {
            return Err(CivilTimeError::BeforeEpoch { year: self.year });
        }
        if self.month == 0 || self.month > 12 {
            return Err(CivilTimeError::MonthOutOfRange { month: self.month });
        }
        let year = self.year as u64;
        let month = self.month as u64;
        if self.day == 0 || self.day as u64 > days_in_month(year, month) {
            return Err(CivilTimeError::DayOutOfRange {
                year: self.year,
                month: self.month,
                day: self.day,
            });
        }
        if self.hour > 23 {
            return Err(CivilTimeError::HourOutOfRange { hour: self.hour });
        }
        if self.minute > 59 {
            return Err(CivilTimeError::MinuteOutOfRange {
                minute: self.minute,
            });
        }
        if self.second > 59 {
            return Err(CivilTimeError::SecondOutOfRange {
                second: self.second,
            });
        }
        if self.nanosecond as u64 >= NANOS_PER_SECOND {
            return Err(CivilTimeError::NanosecondOutOfRange {
                nanosecond: self.nanosecond,
            });
        }

        // No step below can overflow, and the bound is asserted rather than
        // argued: `MAX_CIVIL_SECONDS` is the largest value this expression can
        // take over every `CivilTime` the checks above admit.
        let days = days_from_civil(year, month, self.day as u64);
        Ok(days * SECONDS_PER_DAY
            + self.hour as u64 * SECONDS_PER_HOUR
            + self.minute as u64 * SECONDS_PER_MINUTE
            + self.second as u64)
    }
}

/// The civil year, month and day of a day count since the Unix epoch.
///
/// Total and exact over every `u64` day count. Only the epoch shift can leave
/// `u64`, so only it is widened; after the era division every intermediate is
/// bounded by the era itself.
const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days as u128 + DAYS_FROM_SHIFTED_EPOCH_TO_UNIX as u128;
    let era = shifted / DAYS_PER_ERA as u128;
    let day_of_era = (shifted - era * DAYS_PER_ERA as u128) as u64;
    let era = era as u64;

    let year_of_era = (day_of_era - day_of_era / DAYS_PER_4_YEARS + day_of_era / DAYS_PER_CENTURY
        - day_of_era / DAYS_PER_ERA_LESS_ONE)
        / DAYS_PER_COMMON_YEAR;
    let shifted_year = year_of_era + era * YEARS_PER_ERA;
    let day_of_year =
        day_of_era - (DAYS_PER_COMMON_YEAR * year_of_era + year_of_era / 4 - year_of_era / 100);

    // The shifted year starts in March, so a month index runs 0 for March to 11
    // for February and the 153-day quotient recovers it from the day of year:
    // five months of the March-to-February order span 153 days exactly.
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = if month <= 2 {
        shifted_year + 1
    } else {
        shifted_year
    };
    (year, month, day)
}

/// The day count since the Unix epoch of a civil date — the exact inverse of
/// [`civil_from_days`].
///
/// **Precondition, delegated to the caller:** `year >= UNIX_EPOCH_YEAR` and `month`
/// in `1..=12`, without which the two subtractions below underflow. Enforced by
/// [`CivilTime::to_unix_seconds`], which is the only caller and refuses both
/// before reaching here; proven by the property
/// `to_unix_seconds_rejects_exactly_the_invalid_civil_times` and, at the
/// epoch boundary where the underflow would first occur, by the unit test
/// `the_epoch_is_the_first_instant_a_civil_time_can_name`.
const fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    // March-first, so February's leap day is the last day of the shifted year
    // and no month before it shifts when one is inserted.
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year / YEARS_PER_ERA;
    let year_of_era = shifted_year - era * YEARS_PER_ERA;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era =
        year_of_era * DAYS_PER_COMMON_YEAR + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * DAYS_PER_ERA + day_of_era - DAYS_FROM_SHIFTED_EPOCH_TO_UNIX
}

/// Days in a month of a year, and zero for a month that does not exist — which
/// makes the function total and rejects every day of a nonexistent month
/// without a second check.
const fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(YEARS_PER_ERA))
}

/// The largest day count a [`UtcNanos`] can reach, and the civil year at it.
const MAX_EPOCH_DAYS: u64 = u64::MAX / NANOS_PER_DAY;
const MAX_CIVIL_YEAR: u64 = civil_from_days(MAX_EPOCH_DAYS).0;

// `u64` nanoseconds run out in the twenty-sixth century, and this is what makes
// two narrowings lossless rather than merely unlikely: `CivilTime::from_utc`'s
// cast of the year to `u16`, and `render_rfc3339`'s fixed four-digit year
// field, which is why that function needs no error path at all.
const _: () = assert!(MAX_CIVIL_YEAR <= 9999);

/// The largest second count [`CivilTime::to_unix_seconds`] can return, over
/// every civil time its own checks admit: the last second of the last day a
/// `u16` year can name.
const MAX_CIVIL_SECONDS: u64 = days_from_civil(u16::MAX as u64, 12, 31) * SECONDS_PER_DAY
    + 23 * SECONDS_PER_HOUR
    + 59 * SECONDS_PER_MINUTE
    + 59;

// So the sum in `to_unix_seconds` cannot overflow for any accepted input — a
// `u16` year reaches only into the sixty-sixth millennium, three orders of
// magnitude short of what `u64` seconds hold.
const _: () = assert!(MAX_CIVIL_SECONDS < u64::MAX);

// The epoch anchor both directions are defined against, checked at compile time
// because an off-by-one here would shift every timestamp the node ever emits by
// a day and break no other assertion.
const _: () = assert!(days_from_civil(UNIX_EPOCH_YEAR as u64, 1, 1) == 0);

/// Bytes of `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ` — an RFC 3339 instant in UTC with
/// nanosecond precision.
pub const RFC3339_LEN: usize = 30;

/// Render `time` as RFC 3339, in UTC, with all nine fractional digits.
///
/// Infallible by type: the output is a fixed-size array, so its length is
/// checked by the compiler at the one place it is written, and the only value
/// that could not fit a field — a year past 9999 — is excluded by the assertion
/// on `MAX_CIVIL_YEAR` above.
pub fn render_rfc3339(time: UtcNanos, out: &mut [u8; RFC3339_LEN]) {
    let civil = CivilTime::from_utc(time);
    let [y3, y2, y1, y0] = four_digits(u64::from(civil.year));
    let [mo1, mo0] = two_digits(u64::from(civil.month));
    let [d1, d0] = two_digits(u64::from(civil.day));
    let [h1, h0] = two_digits(u64::from(civil.hour));
    let [mi1, mi0] = two_digits(u64::from(civil.minute));
    let [s1, s0] = two_digits(u64::from(civil.second));
    let [n8, n7, n6, n5, n4, n3, n2, n1, n0] = nine_digits(u64::from(civil.nanosecond));

    *out = [
        y3, y2, y1, y0, b'-', mo1, mo0, b'-', d1, d0, b'T', h1, h0, b':', mi1, mi0, b':', s1, s0,
        b'.', n8, n7, n6, n5, n4, n3, n2, n1, n0, b'Z',
    ];
}

/// One decimal digit of `value` at `place`, as ASCII.
///
/// The `% 10` is what bounds the result to `0..=9` and so keeps the addition
/// from overflowing for any `u64` — including one wider than the field it is
/// being rendered into, which renders its low digits instead. Every caller
/// below is a field whose width is bounded by a compile-time assertion or by
/// the calendar decomposition, so that case is not reachable here.
const fn digit(value: u64, place: u64) -> u8 {
    b'0' + (value / place % 10) as u8
}

const fn two_digits(value: u64) -> [u8; 2] {
    [digit(value, 10), digit(value, 1)]
}

const fn four_digits(value: u64) -> [u8; 4] {
    [
        digit(value, 1_000),
        digit(value, 100),
        digit(value, 10),
        digit(value, 1),
    ]
}

const fn nine_digits(value: u64) -> [u8; 9] {
    [
        digit(value, 100_000_000),
        digit(value, 10_000_000),
        digit(value, 1_000_000),
        digit(value, 100_000),
        digit(value, 10_000),
        digit(value, 1_000),
        digit(value, 100),
        digit(value, 10),
        digit(value, 1),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::{string::String, vec::Vec};

    /// A gigahertz counter, so a tick is a nanosecond and an expected value can
    /// be read off the input.
    const ONE_GHZ: NonZeroU64 = NonZeroU64::new(1_000_000_000).expect("a literal above zero");
    /// The slowest counter the band admits, where the conversion's numerator is
    /// largest and the `u128` widening is load-bearing.
    const SLOWEST: NonZeroU64 =
        NonZeroU64::new(MIN_PLAUSIBLE_TSC_HZ).expect("MIN_PLAUSIBLE_TSC_HZ is above zero");

    /// 2026-07-30T20:27:00.123456789Z, as nanoseconds since the epoch: the
    /// instant `RFC3339_LEN`'s documentation is sized against.
    const SAMPLE_UNIX_NANOS: u64 = 1_785_443_220 * NANOS_PER_SECOND + 123_456_789;

    fn calibration(tsc_hz: NonZeroU64, boot_ticks: u64, boot_unix_nanos: u64) -> Calibration {
        Calibration::new(tsc_hz, Ticks(boot_ticks), boot_unix_nanos)
    }

    fn rendered(nanos: u64) -> String {
        let mut out = [0u8; RFC3339_LEN];
        render_rfc3339(UtcNanos(nanos), &mut out);
        String::from_utf8(out.to_vec()).expect("the renderer writes ASCII digits and separators")
    }

    /// The band's ends are the years it names, computed from the calendar here
    /// rather than read back out of the constants under test.
    #[test]
    fn the_plausible_epoch_band_opens_and_closes_where_its_years_do() {
        assert_eq!(
            CivilTime::from_utc(UtcNanos(MIN_PLAUSIBLE_UNIX_NANOS)),
            CivilTime {
                year: 2000,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
                nanosecond: 0,
            }
        );
        assert_eq!(
            CivilTime::from_utc(UtcNanos(MAX_PLAUSIBLE_UNIX_NANOS)),
            CivilTime {
                year: 2200,
                month: 12,
                day: 31,
                hour: 23,
                minute: 59,
                second: 59,
                nanosecond: 999_999_999,
            }
        );
    }

    /// The band is inclusive at both ends, and the instants just outside each are
    /// refused: a boundary an operator's node could sit on must not be the one
    /// value that reads as implausible.
    #[test]
    fn both_ends_of_the_plausible_epoch_band_are_accepted_and_neither_neighbour_is() {
        assert!(epoch_is_plausible(MIN_PLAUSIBLE_UNIX_NANOS));
        assert!(epoch_is_plausible(MAX_PLAUSIBLE_UNIX_NANOS));
        assert!(!epoch_is_plausible(MIN_PLAUSIBLE_UNIX_NANOS - 1));
        assert!(!epoch_is_plausible(MAX_PLAUSIBLE_UNIX_NANOS + 1));
        // The two instants a register file reports when it reports nothing.
        assert!(!epoch_is_plausible(0));
        assert!(!epoch_is_plausible(u64::MAX));
        // And the instant every expectation in this module is written against.
        assert!(epoch_is_plausible(SAMPLE_UNIX_NANOS));
    }

    /// Why a calibration's anchor reading and its epoch are taken together: the
    /// pair *is* the claim that one names the other, so a reading taken a span
    /// before the instant it is paired with makes every later conversion read that
    /// span late — one-signed, on every timestamp the node emits.
    #[test]
    fn an_anchor_taken_before_its_instant_runs_the_clock_fast_by_that_span() {
        // A gigahertz counter, so a tick is a nanosecond and the span is readable.
        let span_nanos = 2_300_000;
        let together = calibration(ONE_GHZ, span_nanos, SAMPLE_UNIX_NANOS);
        let anchored_early = calibration(ONE_GHZ, 0, SAMPLE_UNIX_NANOS);

        let now = Ticks(span_nanos + NANOS_PER_SECOND);
        assert_eq!(
            together.utc(now).as_nanos(),
            SAMPLE_UNIX_NANOS + NANOS_PER_SECOND
        );
        assert_eq!(
            anchored_early.utc(now).as_nanos() - together.utc(now).as_nanos(),
            span_nanos,
            "the error is the span between the two readings, and always forward"
        );
    }

    /// An independent validator, written from the calendar rules rather than
    /// from the code under test, so agreement between the two is evidence.
    fn is_valid(civil: &CivilTime) -> bool {
        let days = match civil.month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                let year = civil.year;
                if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
                {
                    29
                } else {
                    28
                }
            }
            _ => 0,
        };
        civil.year >= UNIX_EPOCH_YEAR
            && (1..=12).contains(&civil.month)
            && civil.day >= 1
            && civil.day <= days
            && civil.hour <= 23
            && civil.minute <= 59
            && civil.second <= 59
            && u64::from(civil.nanosecond) < NANOS_PER_SECOND
    }

    #[test]
    fn a_duration_is_the_nanoseconds_its_unit_names() {
        assert_eq!(Duration::from_nanos(1).as_nanos(), 1);
        assert_eq!(Duration::from_micros(1).as_nanos(), 1_000);
        assert_eq!(Duration::from_millis(1).as_nanos(), 1_000_000);
        assert_eq!(Duration::from_millis(1_500).as_nanos(), 1_500_000_000);
        assert_eq!(Duration::from_nanos(0).as_nanos(), 0);
    }

    #[test]
    fn a_duration_beyond_what_nanoseconds_hold_saturates_upward() {
        // Upward, because these are used to bound waits: a wrapped span would
        // make the longest expressible wait the shortest one.
        assert_eq!(Duration::from_millis(u64::MAX).as_nanos(), u64::MAX);
        assert_eq!(Duration::from_micros(u64::MAX).as_nanos(), u64::MAX);
        // The last value that does not saturate, and the first that does.
        let exact = u64::MAX / NANOS_PER_MILLISECOND;
        assert_eq!(
            Duration::from_millis(exact).as_nanos(),
            exact * NANOS_PER_MILLISECOND
        );
        assert_eq!(Duration::from_millis(exact + 1).as_nanos(), u64::MAX);
    }

    #[test]
    fn a_monotonic_reading_renders_at_three_scales_by_truncation() {
        let clock = calibration(ONE_GHZ, 0, 0);
        let reading = clock.monotonic(Ticks(1_999_999_999));
        assert_eq!(reading.as_nanos(), 1_999_999_999);
        assert_eq!(reading.as_micros(), 1_999_999);
        assert_eq!(reading.as_millis(), 1_999);
    }

    #[test]
    fn elapsed_nanoseconds_are_the_tick_delta_scaled_by_the_frequency() {
        let clock = calibration(ONE_GHZ, 1_000, 0);
        assert_eq!(clock.monotonic(Ticks(1_000)).as_nanos(), 0);
        assert_eq!(clock.monotonic(Ticks(1_001)).as_nanos(), 1);
        assert_eq!(
            clock.monotonic(Ticks(1_000 + 3 * ONE_GHZ.get())).as_nanos(),
            3 * NANOS_PER_SECOND
        );

        // A counter whose frequency does not divide a nanosecond: the quotient
        // truncates and nothing else changes.
        let odd = NonZeroU64::new(3_000_000_000).expect("a literal above zero");
        let clock = calibration(odd, 0, 0);
        assert_eq!(clock.monotonic(Ticks(3)).as_nanos(), 1);
        assert_eq!(clock.monotonic(Ticks(2)).as_nanos(), 0);
    }

    #[test]
    fn a_tick_count_near_the_top_of_u64_converts_without_wrapping() {
        // The whole reason the conversion is widened. In `u64` the numerator
        // `ticks * 1_000_000_000` wraps above eighteen billion ticks, so this
        // is checked against the exact `u128` value rather than against a
        // number this crate produced.
        for ticks in [
            u64::MAX,
            u64::MAX - 1,
            u64::MAX / 2,
            u64::MAX / NANOS_PER_SECOND + 1,
            NANOS_PER_SECOND * 19,
        ] {
            let clock = calibration(SLOWEST, 0, 0);
            let expected = (u128::from(ticks) * u128::from(NANOS_PER_SECOND))
                / u128::from(MIN_PLAUSIBLE_TSC_HZ);
            let observed = u128::from(clock.monotonic(Ticks(ticks)).as_nanos());
            if expected > u128::from(u64::MAX) {
                assert_eq!(observed, u128::from(u64::MAX), "{ticks} must saturate");
            } else {
                assert_eq!(observed, expected, "{ticks} must convert exactly");
            }
        }
    }

    #[test]
    fn an_elapsed_span_past_what_nanoseconds_hold_saturates() {
        // 10 MHz for 58 000 years: representable in ticks, not in nanoseconds.
        let clock = calibration(SLOWEST, 0, 0);
        assert_eq!(clock.monotonic(Ticks(u64::MAX)).as_nanos(), u64::MAX);
        // The boundary: the largest tick count that still converts exactly.
        let last_exact = u64::MAX / (NANOS_PER_SECOND / MIN_PLAUSIBLE_TSC_HZ);
        assert!(clock.monotonic(Ticks(last_exact)).as_nanos() < u64::MAX);
        assert_eq!(clock.monotonic(Ticks(last_exact + 1)).as_nanos(), u64::MAX);
    }

    #[test]
    fn a_reading_below_the_boot_reading_reports_no_elapsed_time() {
        // A different core's counter, or a restored virtual machine's: there is
        // no elapsed time to report, and a wrap would report 584 years of it.
        let clock = calibration(ONE_GHZ, 5_000, 1_700_000_000 * NANOS_PER_SECOND);
        assert_eq!(clock.monotonic(Ticks(0)).as_nanos(), 0);
        assert_eq!(clock.monotonic(Ticks(4_999)).as_nanos(), 0);
        assert_eq!(clock.utc(Ticks(0)).as_nanos(), clock.boot_unix_nanos());
    }

    /// The two operations a deadline is computed with. They exist so that a
    /// caller holding timeouts never needs a way to build a `Monotonic` from an
    /// integer, which is what keeps the type's guarantee intact.
    #[test]
    fn an_instant_advances_by_a_span_and_measures_back_to_it() {
        let clock = calibration(ONE_GHZ, 0, 0);
        let start = clock.monotonic(Ticks(1_000));
        let later = start.saturating_add(Duration::from_micros(3));
        assert_eq!(later.as_nanos(), 4_000);
        assert_eq!(later.since(start), Duration::from_micros(3));
        // Backwards is no elapsed time rather than an enormous span.
        assert_eq!(start.since(later), Duration::from_nanos(0));
        assert_eq!(start.since(start), Duration::from_nanos(0));
    }

    #[test]
    fn advancing_an_instant_saturates_rather_than_wrapping() {
        let clock = calibration(ONE_GHZ, 0, 0);
        let far = clock.monotonic(Ticks(u64::MAX));
        assert_eq!(far.as_nanos(), u64::MAX);
        assert_eq!(
            far.saturating_add(Duration::from_millis(1)).as_nanos(),
            u64::MAX
        );
        assert_eq!(far.since(clock.monotonic(Ticks(0))).as_nanos(), u64::MAX);
    }

    #[test]
    fn a_utc_reading_is_the_boot_instant_plus_the_elapsed_span() {
        let boot = 1_785_443_220 * NANOS_PER_SECOND;
        let clock = calibration(ONE_GHZ, 100, boot);
        assert_eq!(clock.utc(Ticks(100)).as_nanos(), boot);
        assert_eq!(
            clock.utc(Ticks(100 + 2 * ONE_GHZ.get())).as_nanos(),
            boot + 2 * NANOS_PER_SECOND
        );
        assert_eq!(clock.utc(Ticks(100)).unix_seconds(), 1_785_443_220);
    }

    /// A published instant reconstructed by a reader is the instant that was
    /// published, and it reads as one however it was obtained: the two routes
    /// into the type must not produce values a renderer tells apart.
    #[test]
    fn an_instant_reconstructed_from_a_published_count_is_the_instant_that_was_published() {
        let boot = 1_785_443_220 * NANOS_PER_SECOND;
        let established = calibration(ONE_GHZ, 100, boot).utc(Ticks(100));
        let reconstructed = UtcNanos::from_unix_nanos(established.as_nanos());
        assert_eq!(reconstructed, established);
        assert_eq!(reconstructed.as_nanos(), boot);
        assert_eq!(
            CivilTime::from_utc(reconstructed),
            CivilTime::from_utc(established)
        );
        for nanos in [0, 1, u64::MAX] {
            assert_eq!(UtcNanos::from_unix_nanos(nanos).as_nanos(), nanos);
        }
    }

    #[test]
    fn a_utc_reading_past_what_nanoseconds_hold_saturates_rather_than_returning_to_1970() {
        let clock = calibration(ONE_GHZ, 0, u64::MAX - 5);
        assert_eq!(clock.utc(Ticks(4)).as_nanos(), u64::MAX - 1);
        assert_eq!(clock.utc(Ticks(5)).as_nanos(), u64::MAX);
        assert_eq!(clock.utc(Ticks(u64::MAX)).as_nanos(), u64::MAX);
    }

    #[test]
    fn a_calibration_reports_back_what_it_was_built_from() {
        let clock = calibration(SLOWEST, 42, 7);
        assert_eq!(clock.tsc_hz(), SLOWEST);
        assert_eq!(clock.boot_ticks(), Ticks(42));
        assert_eq!(clock.boot_unix_nanos(), 7);
    }

    #[test]
    fn a_frequency_is_derived_from_the_reference_interval_it_was_measured_over() {
        let reference = NonZeroU64::new(1_000_000).expect("a literal above zero");
        // 2 500 000 000 ticks across 1 000 000 reference units of a 1 MHz
        // timer — one second — is 2.5 GHz.
        assert_eq!(
            calibrate(2_500_000_000, 1_000_000, reference),
            Ok(NonZeroU64::new(2_500_000_000).expect("a literal above zero"))
        );
        // A tenth of a second yields the same frequency: the multiplication
        // runs before the division, so a short interval keeps its significance.
        assert_eq!(
            calibrate(250_000_000, 100_000, reference),
            Ok(NonZeroU64::new(2_500_000_000).expect("a literal above zero"))
        );
    }

    #[test]
    fn a_counter_that_did_not_advance_calibrates_nothing() {
        let reference = NonZeroU64::new(1_000_000).expect("a literal above zero");
        assert_eq!(
            calibrate(0, 1_000_000, reference),
            Err(CalibrationError::NoTicksElapsed)
        );
        // Checked before the reference interval, so a stopped counter is not
        // reported as a broken reference timer.
        assert_eq!(
            calibrate(0, 0, reference),
            Err(CalibrationError::NoTicksElapsed)
        );
    }

    #[test]
    fn a_reference_timer_reporting_no_interval_calibrates_nothing() {
        let reference = NonZeroU64::new(1_000_000).expect("a literal above zero");
        assert_eq!(
            calibrate(1_000, 0, reference),
            Err(CalibrationError::NoReferenceInterval)
        );
    }

    #[test]
    fn a_frequency_outside_the_plausible_band_is_refused_with_the_value_derived() {
        let hz = NonZeroU64::new(1).expect("a literal above zero");
        // One tick per second: a hundredth of the floor.
        assert_eq!(
            calibrate(100_000, 1, hz),
            Err(CalibrationError::ImplausiblySlow { hz: 100_000 })
        );
        // A tick delta far smaller than the interval derives zero, which is the
        // extreme of the same cause rather than a separate one.
        assert_eq!(
            calibrate(1, u64::MAX, hz),
            Err(CalibrationError::ImplausiblySlow { hz: 0 })
        );
        // And the other end, where the exact quotient exceeds `u64` and is
        // reported as such rather than narrowed into plausibility.
        assert_eq!(
            calibrate(
                u64::MAX,
                1,
                NonZeroU64::new(u64::MAX).expect("a literal above zero")
            ),
            Err(CalibrationError::ImplausiblyFast {
                hz: u128::from(u64::MAX) * u128::from(u64::MAX)
            })
        );
    }

    #[test]
    fn the_plausible_band_is_inclusive_at_both_ends() {
        let hz = NonZeroU64::new(1).expect("a literal above zero");
        assert_eq!(
            calibrate(MIN_PLAUSIBLE_TSC_HZ, 1, hz),
            Ok(NonZeroU64::new(MIN_PLAUSIBLE_TSC_HZ).expect("the floor is above zero"))
        );
        assert_eq!(
            calibrate(MIN_PLAUSIBLE_TSC_HZ - 1, 1, hz),
            Err(CalibrationError::ImplausiblySlow {
                hz: MIN_PLAUSIBLE_TSC_HZ - 1
            })
        );
        assert_eq!(
            calibrate(MAX_PLAUSIBLE_TSC_HZ, 1, hz),
            Ok(NonZeroU64::new(MAX_PLAUSIBLE_TSC_HZ).expect("the ceiling is above zero"))
        );
        assert_eq!(
            calibrate(MAX_PLAUSIBLE_TSC_HZ + 1, 1, hz),
            Err(CalibrationError::ImplausiblyFast {
                hz: u128::from(MAX_PLAUSIBLE_TSC_HZ) + 1
            })
        );
    }

    #[test]
    fn each_way_a_calibration_can_fail_reaches_an_operator_as_its_own_error() {
        // Four distinct causes must not collapse into one line.
        let hz = NonZeroU64::new(1).expect("a literal above zero");
        let refusals = [
            calibrate(0, 1, hz),
            calibrate(1, 0, hz),
            calibrate(1, 2, hz),
            calibrate(u64::MAX, 1, hz),
        ];
        for (index, outcome) in refusals.iter().enumerate() {
            assert!(outcome.is_err(), "refusal {index} must be an error");
            for other in refusals.iter().skip(index + 1) {
                assert_ne!(outcome, other);
            }
        }
    }

    #[test]
    fn the_epoch_is_the_first_instant_a_civil_time_can_name() {
        // The boundary `days_from_civil`'s delegated precondition rests on: one
        // year lower and its subtractions would underflow, which is why
        // `to_unix_seconds` refuses before reaching it.
        let epoch = CivilTime::from_utc(UtcNanos(0));
        assert_eq!(
            epoch,
            CivilTime {
                year: 1970,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
                nanosecond: 0,
            }
        );
        assert_eq!(epoch.to_unix_seconds(), Ok(0));

        let before = CivilTime {
            year: 1969,
            month: 12,
            day: 31,
            ..epoch
        };
        assert_eq!(
            before.to_unix_seconds(),
            Err(CivilTimeError::BeforeEpoch { year: 1969 })
        );
        assert_eq!(
            CivilTime { year: 0, ..epoch }.to_unix_seconds(),
            Err(CivilTimeError::BeforeEpoch { year: 0 })
        );
    }

    #[test]
    fn known_instants_decompose_to_the_dates_they_are() {
        let cases = [
            // The era boundary Hinnant's shift is built around.
            (951_868_800u64, (2000u16, 3u8, 1u8, 0u8, 0u8, 0u8)),
            // The leap day before it, in a century year that is a leap year.
            (951_782_400, (2000, 2, 29, 0, 0, 0)),
            // 2100 is not a leap year: 28 February is followed by 1 March.
            (4_107_456_000, (2100, 2, 28, 0, 0, 0)),
            (4_107_542_400, (2100, 3, 1, 0, 0, 0)),
            // 2024 is, by the four-year rule.
            (1_709_164_800, (2024, 2, 29, 0, 0, 0)),
            // The last second of a year, and the first of the next.
            (1_767_225_599, (2025, 12, 31, 23, 59, 59)),
            (1_767_225_600, (2026, 1, 1, 0, 0, 0)),
            // A time of day with every field distinct.
            (1_785_443_220, (2026, 7, 30, 20, 27, 0)),
        ];
        for (seconds, (year, month, day, hour, minute, second)) in cases {
            let civil = CivilTime::from_utc(UtcNanos(seconds * NANOS_PER_SECOND));
            assert_eq!(
                (
                    civil.year,
                    civil.month,
                    civil.day,
                    civil.hour,
                    civil.minute,
                    civil.second
                ),
                (year, month, day, hour, minute, second),
                "second {seconds}"
            );
            assert_eq!(civil.nanosecond, 0);
            assert_eq!(civil.to_unix_seconds(), Ok(seconds));
        }
    }

    #[test]
    fn the_sub_second_remainder_is_carried_and_does_not_disturb_the_date() {
        let civil = CivilTime::from_utc(UtcNanos(SAMPLE_UNIX_NANOS));
        assert_eq!(civil.nanosecond, 123_456_789);
        assert_eq!(civil.second, 0);
        assert_eq!(civil.to_unix_seconds(), Ok(1_785_443_220));

        // The last nanosecond of a second stays inside it.
        let civil = CivilTime::from_utc(UtcNanos(NANOS_PER_SECOND - 1));
        assert_eq!((civil.second, civil.nanosecond), (0, 999_999_999));
    }

    #[test]
    fn the_largest_instant_nanoseconds_can_express_is_a_date_and_not_an_error() {
        let civil = CivilTime::from_utc(UtcNanos(u64::MAX));
        assert_eq!(u64::from(civil.year), MAX_CIVIL_YEAR);
        assert_eq!(civil.to_unix_seconds(), Ok(u64::MAX / NANOS_PER_SECOND));
        // The four-digit year field and the `u16` narrowing both rest on the
        // compile-time bound on `MAX_CIVIL_YEAR`; this is that bound observed
        // through the renderer, where a year past 9999 would lose its leading
        // digit rather than fail.
        let line = rendered(u64::MAX);
        assert_eq!(line.len(), RFC3339_LEN);
        assert_eq!(
            line.get(0..4).and_then(|year| year.parse::<u64>().ok()),
            Some(MAX_CIVIL_YEAR)
        );
    }

    #[test]
    fn every_out_of_range_field_is_refused_by_its_own_name() {
        let valid = CivilTime::from_utc(UtcNanos(SAMPLE_UNIX_NANOS));
        assert!(valid.to_unix_seconds().is_ok());

        let cases = [
            (
                CivilTime { month: 0, ..valid },
                CivilTimeError::MonthOutOfRange { month: 0 },
            ),
            (
                CivilTime { month: 13, ..valid },
                CivilTimeError::MonthOutOfRange { month: 13 },
            ),
            (
                CivilTime { day: 0, ..valid },
                CivilTimeError::DayOutOfRange {
                    year: valid.year,
                    month: 7,
                    day: 0,
                },
            ),
            (
                CivilTime { day: 32, ..valid },
                CivilTimeError::DayOutOfRange {
                    year: valid.year,
                    month: 7,
                    day: 32,
                },
            ),
            (
                CivilTime { hour: 24, ..valid },
                CivilTimeError::HourOutOfRange { hour: 24 },
            ),
            (
                CivilTime {
                    minute: 60,
                    ..valid
                },
                CivilTimeError::MinuteOutOfRange { minute: 60 },
            ),
            (
                CivilTime {
                    second: 60,
                    ..valid
                },
                CivilTimeError::SecondOutOfRange { second: 60 },
            ),
            (
                CivilTime {
                    nanosecond: 1_000_000_000,
                    ..valid
                },
                CivilTimeError::NanosecondOutOfRange {
                    nanosecond: 1_000_000_000,
                },
            ),
            (
                CivilTime {
                    nanosecond: u32::MAX,
                    ..valid
                },
                CivilTimeError::NanosecondOutOfRange {
                    nanosecond: u32::MAX,
                },
            ),
        ];
        for (civil, expected) in cases {
            assert_eq!(civil.to_unix_seconds(), Err(expected), "{civil:?}");
        }
    }

    #[test]
    fn a_month_that_does_not_exist_has_no_valid_day_at_all() {
        // The arm `to_unix_seconds`'s own month check keeps out of reach, tested
        // here because it is what makes `days_in_month` total: a length of zero
        // rejects every day rather than admitting one by default.
        for month in [0u64, 13, 99, u64::MAX] {
            assert_eq!(days_in_month(2026, month), 0, "month {month}");
        }
        // And the months that do exist, against the lengths a calendar gives
        // them, February in a leap year and a common year both.
        let lengths = [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        for (index, expected) in lengths.into_iter().enumerate() {
            let month = index as u64 + 1;
            assert_eq!(days_in_month(2025, month), expected, "month {month}");
        }
        assert_eq!(days_in_month(2024, 2), 29);
    }

    #[test]
    fn a_month_length_is_that_month_of_that_year_and_not_a_maximum() {
        let base = CivilTime::from_utc(UtcNanos(0));
        // 30-day months reject the 31st; 31-day months accept it.
        for month in [4u8, 6, 9, 11] {
            let civil = CivilTime {
                month,
                day: 31,
                ..base
            };
            assert_eq!(
                civil.to_unix_seconds(),
                Err(CivilTimeError::DayOutOfRange {
                    year: base.year,
                    month,
                    day: 31,
                })
            );
            assert!(
                CivilTime {
                    month,
                    day: 30,
                    ..base
                }
                .to_unix_seconds()
                .is_ok()
            );
        }
        for month in [1u8, 3, 5, 7, 8, 10, 12] {
            assert!(
                CivilTime {
                    month,
                    day: 31,
                    ..base
                }
                .to_unix_seconds()
                .is_ok()
            );
        }
        // And February, where the answer depends on the year: 2024 is a leap
        // year, 2100 is not despite being a multiple of four, 2400 is.
        for (year, february) in [(2024u16, 29u8), (2025, 28), (2100, 28), (2400, 29)] {
            let civil = CivilTime {
                year,
                month: 2,
                day: february,
                ..base
            };
            assert!(civil.to_unix_seconds().is_ok(), "{year}-02-{february}");
            let past = CivilTime {
                day: february + 1,
                ..civil
            };
            assert_eq!(
                past.to_unix_seconds(),
                Err(CivilTimeError::DayOutOfRange {
                    year,
                    month: 2,
                    day: february + 1,
                })
            );
        }
    }

    #[test]
    fn the_first_wrong_field_is_the_one_reported() {
        // Every field wrong at once: the order is most-significant first, so
        // the answer is about the year and not about the nanosecond.
        let all_wrong = CivilTime {
            year: 1900,
            month: 0,
            day: 0,
            hour: 99,
            minute: 99,
            second: 99,
            nanosecond: u32::MAX,
        };
        assert_eq!(
            all_wrong.to_unix_seconds(),
            Err(CivilTimeError::BeforeEpoch { year: 1900 })
        );
        assert_eq!(
            CivilTime {
                year: 2026,
                ..all_wrong
            }
            .to_unix_seconds(),
            Err(CivilTimeError::MonthOutOfRange { month: 0 })
        );
        assert_eq!(
            CivilTime {
                year: 2026,
                month: 1,
                ..all_wrong
            }
            .to_unix_seconds(),
            Err(CivilTimeError::DayOutOfRange {
                year: 2026,
                month: 1,
                day: 0
            })
        );
        assert_eq!(
            CivilTime {
                year: 2026,
                month: 1,
                day: 1,
                ..all_wrong
            }
            .to_unix_seconds(),
            Err(CivilTimeError::HourOutOfRange { hour: 99 })
        );
        assert_eq!(
            CivilTime {
                year: 2026,
                month: 1,
                day: 1,
                hour: 0,
                ..all_wrong
            }
            .to_unix_seconds(),
            Err(CivilTimeError::MinuteOutOfRange { minute: 99 })
        );
        assert_eq!(
            CivilTime {
                year: 2026,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                ..all_wrong
            }
            .to_unix_seconds(),
            Err(CivilTimeError::SecondOutOfRange { second: 99 })
        );
    }

    #[test]
    fn every_representable_day_round_trips_through_the_calendar() {
        // Exhaustive over the whole domain a `UtcNanos` can reach — 213 503
        // days — so the inverse and the four-digit year bound are verified
        // rather than argued from monotonicity.
        let mut previous = (0u16, 0u8, 0u8);
        for days in 0..=MAX_EPOCH_DAYS {
            let civil = CivilTime::from_utc(UtcNanos(days * NANOS_PER_DAY));
            assert_eq!(
                civil.to_unix_seconds(),
                Ok(days * SECONDS_PER_DAY),
                "day {days}"
            );
            assert!(is_valid(&civil), "day {days} yielded {civil:?}");
            assert!(u64::from(civil.year) <= MAX_CIVIL_YEAR, "day {days}");
            let current = (civil.year, civil.month, civil.day);
            assert!(current > previous, "day {days} did not advance the date");
            previous = current;
        }
        assert_eq!(previous.0 as u64, MAX_CIVIL_YEAR);
    }

    #[test]
    fn a_rendered_instant_is_the_rfc3339_line_for_it() {
        assert_eq!(
            rendered(SAMPLE_UNIX_NANOS),
            "2026-07-30T20:27:00.123456789Z"
        );
        assert_eq!(rendered(0), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(
            rendered(951_782_400 * NANOS_PER_SECOND + 1),
            "2000-02-29T00:00:00.000000001Z"
        );
        assert_eq!(
            rendered(1_767_225_599 * NANOS_PER_SECOND + 999_999_999),
            "2025-12-31T23:59:59.999999999Z"
        );
    }

    #[test]
    fn a_rendered_instant_overwrites_the_whole_buffer() {
        // The buffer is a caller's, and may hold an earlier line: every byte of
        // it is written, so no digit of a previous instant can survive into a
        // shorter field of this one.
        let mut out = [b'X'; RFC3339_LEN];
        render_rfc3339(UtcNanos(SAMPLE_UNIX_NANOS), &mut out);
        assert!(!out.contains(&b'X'));
        render_rfc3339(UtcNanos(0), &mut out);
        assert_eq!(&out, b"1970-01-01T00:00:00.000000000Z");
    }

    /// The shape of an RFC 3339 line at nanosecond precision: which positions
    /// are digits and which are separators. Written as data rather than as a
    /// parser, so the assertion is about position and not about a regex.
    const RFC3339_SEPARATORS: [(usize, u8); 6] = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
    ];

    #[test]
    fn the_rendered_length_is_the_constant_callers_size_a_buffer_by() {
        assert_eq!("2026-07-30T20:27:00.123456789Z".len(), RFC3339_LEN);
        assert_eq!(RFC3339_SEPARATORS.len() + 1, 7);
    }

    proptest! {
        /// Elapsed time never runs backwards as the counter advances, for any
        /// frequency in the band and any pair of readings.
        #[test]
        fn elapsed_time_never_decreases_as_the_counter_advances(
            hz in MIN_PLAUSIBLE_TSC_HZ..=MAX_PLAUSIBLE_TSC_HZ,
            boot_ticks in any::<u64>(),
            earlier in any::<u64>(),
            later in any::<u64>(),
        ) {
            let hz = NonZeroU64::new(hz).expect("the band's floor is above zero");
            let clock = calibration(hz, boot_ticks, 0);
            let (earlier, later) = if earlier <= later { (earlier, later) } else { (later, earlier) };
            prop_assert!(
                clock.monotonic(Ticks(earlier)) <= clock.monotonic(Ticks(later)),
                "{} then {} at {} Hz from {}", earlier, later, hz, boot_ticks,
            );
            // And a reading at or before the anchor is zero, never a wrap.
            prop_assert_eq!(clock.monotonic(Ticks(boot_ticks)).as_nanos(), 0);
        }

        /// A wall-clock reading is exactly the boot instant plus the elapsed
        /// span, saturating rather than wrapping at the top.
        #[test]
        fn a_utc_reading_is_the_boot_instant_plus_elapsed_nanoseconds(
            hz in MIN_PLAUSIBLE_TSC_HZ..=MAX_PLAUSIBLE_TSC_HZ,
            boot_ticks in any::<u64>(),
            boot_unix_nanos in any::<u64>(),
            now in any::<u64>(),
        ) {
            let hz = NonZeroU64::new(hz).expect("the band's floor is above zero");
            let clock = calibration(hz, boot_ticks, boot_unix_nanos);
            let now = Ticks(now);
            prop_assert_eq!(
                clock.utc(now).as_nanos(),
                boot_unix_nanos.saturating_add(clock.monotonic(now).as_nanos()),
            );
            prop_assert!(clock.utc(now).as_nanos() >= boot_unix_nanos);
            prop_assert_eq!(
                clock.utc(now).unix_seconds(),
                clock.utc(now).as_nanos() / NANOS_PER_SECOND,
            );
        }

        /// The conversion agrees with the exact `u128` arithmetic for any
        /// frequency and any reading — the property a `u64` numerator fails.
        #[test]
        fn the_conversion_agrees_with_exact_arithmetic(
            hz in 1u64..=u64::MAX,
            ticks in any::<u64>(),
        ) {
            let clock = calibration(
                NonZeroU64::new(hz).expect("the range starts at one"),
                0,
                0,
            );
            let exact = (u128::from(ticks) * u128::from(NANOS_PER_SECOND)) / u128::from(hz);
            let expected = if exact > u128::from(u64::MAX) { u64::MAX } else { exact as u64 };
            prop_assert_eq!(clock.monotonic(Ticks(ticks)).as_nanos(), expected);
        }

        /// Calibration is total over arbitrary readings, and an accepted
        /// frequency is always in the band it claims to enforce.
        #[test]
        fn calibration_is_total_and_accepts_only_the_plausible_band(
            ticks_elapsed in any::<u64>(),
            reference_elapsed in any::<u64>(),
            reference_hz in 1u64..=u64::MAX,
        ) {
            let reference_hz = NonZeroU64::new(reference_hz).expect("the range starts at one");
            match calibrate(ticks_elapsed, reference_elapsed, reference_hz) {
                Ok(hz) => {
                    prop_assert!((MIN_PLAUSIBLE_TSC_HZ..=MAX_PLAUSIBLE_TSC_HZ).contains(&hz.get()));
                    // And it is the exact quotient, not a clamped one.
                    let exact = (u128::from(ticks_elapsed) * u128::from(reference_hz.get()))
                        / u128::from(reference_elapsed);
                    prop_assert_eq!(u128::from(hz.get()), exact);
                }
                Err(CalibrationError::NoTicksElapsed) => prop_assert_eq!(ticks_elapsed, 0),
                Err(CalibrationError::NoReferenceInterval) => {
                    prop_assert_ne!(ticks_elapsed, 0);
                    prop_assert_eq!(reference_elapsed, 0);
                }
                Err(CalibrationError::ImplausiblySlow { hz }) => {
                    prop_assert!(hz < MIN_PLAUSIBLE_TSC_HZ);
                }
                Err(CalibrationError::ImplausiblyFast { hz }) => {
                    prop_assert!(hz > u128::from(MAX_PLAUSIBLE_TSC_HZ));
                }
            }
        }

        /// A frequency that is derived and then used describes the same
        /// counter: one reference interval of ticks reads back as one second,
        /// to within the truncation of a single division.
        #[test]
        fn a_derived_frequency_measures_the_counter_it_was_derived_from(
            hz in MIN_PLAUSIBLE_TSC_HZ..=MAX_PLAUSIBLE_TSC_HZ,
            reference_hz in 1_000u64..=1_000_000_000,
        ) {
            let reference = NonZeroU64::new(reference_hz).expect("the range starts above zero");
            // Exactly one second of the counter, measured over one second of
            // the reference timer.
            let derived = calibrate(hz, reference_hz, reference)
                .expect("a whole second of an in-band counter is in band");
            prop_assert_eq!(derived.get(), hz);
            let clock = calibration(derived, 0, 0);
            prop_assert_eq!(clock.monotonic(Ticks(hz)).as_nanos(), NANOS_PER_SECOND);
        }

        /// The calendar round-trips over a wide range of instants: an arbitrary
        /// second from 1970 to 2200 decomposes and recomposes to itself.
        #[test]
        fn a_civil_time_recomposes_to_the_second_it_came_from(
            seconds in 0u64..=7_258_118_400,
            nanosecond in 0u64..NANOS_PER_SECOND,
        ) {
            let civil = CivilTime::from_utc(UtcNanos(seconds * NANOS_PER_SECOND + nanosecond));
            prop_assert!(is_valid(&civil), "{:?}", civil);
            prop_assert_eq!(u64::from(civil.nanosecond), nanosecond);
            prop_assert_eq!(civil.to_unix_seconds(), Ok(seconds));
            prop_assert!((UNIX_EPOCH_YEAR..=2200).contains(&civil.year));
        }

        /// And over the whole `UtcNanos` domain, where the range above cannot
        /// reach: any instant at all decomposes to a valid civil time whose
        /// second count is the instant's own.
        #[test]
        fn every_instant_decomposes_to_a_valid_civil_time(nanos in any::<u64>()) {
            let civil = CivilTime::from_utc(UtcNanos(nanos));
            prop_assert!(is_valid(&civil), "{} yielded {:?}", nanos, civil);
            prop_assert_eq!(civil.to_unix_seconds(), Ok(nanos / NANOS_PER_SECOND));
            prop_assert_eq!(u64::from(civil.nanosecond), nanos % NANOS_PER_SECOND);
        }

        /// A civil time is accepted exactly when an independently written
        /// validator says it is valid — so neither over-accepts nor
        /// over-rejects, whatever a caller composes field by field.
        #[test]
        fn to_unix_seconds_rejects_exactly_the_invalid_civil_times(
            year in 0u16..=2600,
            month in any::<u8>(),
            day in any::<u8>(),
            hour in any::<u8>(),
            minute in any::<u8>(),
            second in any::<u8>(),
            nanosecond in any::<u32>(),
        ) {
            let civil = CivilTime { year, month, day, hour, minute, second, nanosecond };
            let outcome = civil.to_unix_seconds();
            prop_assert_eq!(outcome.is_ok(), is_valid(&civil), "{:?}", civil);
            if let Ok(seconds) = outcome {
                // An accepted value is the instant it names: decomposing it
                // returns every field but the sub-second remainder.
                let round_tripped = CivilTime::from_utc(UtcNanos(
                    seconds * NANOS_PER_SECOND + u64::from(nanosecond),
                ));
                prop_assert_eq!(round_tripped, civil);
            }
        }

        /// Rendering is total: every instant produces exactly `RFC3339_LEN`
        /// bytes, every one of them ASCII, digits and separators in the fixed
        /// positions RFC 3339 puts them.
        #[test]
        fn every_instant_renders_as_a_fixed_width_ascii_line(nanos in any::<u64>()) {
            let mut out = [0u8; RFC3339_LEN];
            render_rfc3339(UtcNanos(nanos), &mut out);
            prop_assert_eq!(out.len(), RFC3339_LEN);
            prop_assert!(out.iter().all(u8::is_ascii));

            let separators: Vec<usize> = RFC3339_SEPARATORS.iter().map(|(at, _)| *at).collect();
            for (index, byte) in out.iter().enumerate() {
                match RFC3339_SEPARATORS.iter().find(|(at, _)| *at == index) {
                    Some((_, expected)) => prop_assert_eq!(byte, expected),
                    None if index == RFC3339_LEN - 1 => prop_assert_eq!(*byte, b'Z'),
                    None => prop_assert!(byte.is_ascii_digit(), "position {} is not a digit", index),
                }
            }
            prop_assert_eq!(separators.len(), 6);
        }

        /// A rendered line names the instant it was rendered from: the digits
        /// parse back to the same civil fields.
        #[test]
        fn a_rendered_line_parses_back_to_the_instant_it_named(nanos in any::<u64>()) {
            let line = rendered(nanos);
            let civil = CivilTime::from_utc(UtcNanos(nanos));
            let field = |from: usize, to: usize| -> u64 {
                line.get(from..to)
                    .expect("the line is RFC3339_LEN bytes of known layout")
                    .parse()
                    .expect("every field position holds digits")
            };
            prop_assert_eq!(field(0, 4), u64::from(civil.year));
            prop_assert_eq!(field(5, 7), u64::from(civil.month));
            prop_assert_eq!(field(8, 10), u64::from(civil.day));
            prop_assert_eq!(field(11, 13), u64::from(civil.hour));
            prop_assert_eq!(field(14, 16), u64::from(civil.minute));
            prop_assert_eq!(field(17, 19), u64::from(civil.second));
            prop_assert_eq!(field(20, 29), u64::from(civil.nanosecond));
        }

        /// A duration is the nanoseconds its unit names, saturating and never
        /// wrapping, for every input.
        ///
        /// The strategy is weighted rather than uniform: a uniform `u64` is
        /// almost always large enough to saturate every scale, so the exact and
        /// the saturating regions would each be reached by one arm of the
        /// generator and never deliberately.
        #[test]
        fn a_duration_never_wraps_whatever_unit_it_is_given(
            value in prop_oneof![
                any::<u64>(),
                0u64..=1_000_000,
                (u64::MAX / NANOS_PER_MILLISECOND - 8)..=(u64::MAX / NANOS_PER_MILLISECOND + 8),
                (u64::MAX - 8)..=u64::MAX,
            ],
        ) {
            let exact = |scale: u64| -> u64 {
                let product = u128::from(value) * u128::from(scale);
                if product > u128::from(u64::MAX) { u64::MAX } else { product as u64 }
            };
            prop_assert_eq!(Duration::from_nanos(value).as_nanos(), value);
            prop_assert_eq!(Duration::from_micros(value).as_nanos(), exact(NANOS_PER_MICROSECOND));
            prop_assert_eq!(Duration::from_millis(value).as_nanos(), exact(NANOS_PER_MILLISECOND));
            // Saturation is upward, so a span is never shortened by it.
            prop_assert!(Duration::from_millis(value).as_nanos() >= value);
            prop_assert!(Duration::from_micros(value).as_nanos() >= value);
        }

        /// The coarser views of an elapsed span are the finer one divided, for
        /// every reading.
        #[test]
        fn the_coarser_views_of_a_reading_are_the_finer_one_divided(
            hz in MIN_PLAUSIBLE_TSC_HZ..=MAX_PLAUSIBLE_TSC_HZ,
            ticks in any::<u64>(),
        ) {
            let clock = calibration(
                NonZeroU64::new(hz).expect("the band's floor is above zero"),
                0,
                0,
            );
            let reading = clock.monotonic(Ticks(ticks));
            prop_assert_eq!(reading.as_micros(), reading.as_nanos() / NANOS_PER_MICROSECOND);
            prop_assert_eq!(reading.as_millis(), reading.as_nanos() / NANOS_PER_MILLISECOND);
            prop_assert!(reading.as_millis() <= reading.as_micros());
        }
    }
}
