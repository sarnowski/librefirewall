/// A civil date and time in UTC, which is the only form a certificate's
/// validity is written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Utc {
    pub year: i64,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

/// Seconds in a day, and the two multiples of it the conversion below needs.
const SECONDS_PER_DAY: i64 = 86_400;

impl Utc {
    /// The civil time a Unix second stands for.
    ///
    /// The day arithmetic is Howard Hinnant's `civil_from_days`, which is
    /// exact over the whole range of a 64-bit day count and has no table, no
    /// leap-second list and no branch on the year — this crate needs a
    /// certificate's two timestamps and nothing else, so a date library would
    /// be a dependency for one function.
    #[must_use]
    pub fn from_unix_seconds(seconds: i64) -> Self {
        let days = seconds.div_euclid(SECONDS_PER_DAY);
        let rest = seconds.rem_euclid(SECONDS_PER_DAY);
        // Shift the epoch to 0000-03-01 so leap days land at the end of the
        // era, which is what removes every special case from the month
        // arithmetic below.
        let shifted = days + 719_468;
        let era = shifted.div_euclid(146_097);
        let day_of_era = shifted.rem_euclid(146_097);
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_prime = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
        let month = if month_prime < 10 {
            month_prime + 3
        } else {
            month_prime - 9
        };
        let year = year_of_era + era * 400 + i64::from(month <= 2);
        Self {
            year,
            month: month as u8,
            day: day as u8,
            hour: (rest / 3600) as u8,
            minute: (rest % 3600 / 60) as u8,
            second: (rest % 60) as u8,
        }
    }

    /// The thirteen characters a `UTCTime` carries: `YYMMDDHHMMSSZ`.
    ///
    /// # Errors
    /// The year, where it is outside the range two digits can name without
    /// ambiguity. Certificates past 2049 are written as `GeneralizedTime`
    /// instead, and this crate emits no such certificate — a ten-year validity
    /// from any plausible clock stays well inside the window, and a clock that
    /// says otherwise is a fault to surface rather than a format to guess at.
    pub fn to_utc_time(self) -> Result<[u8; 13], i64> {
        if !(1950..2050).contains(&self.year) {
            return Err(self.year);
        }
        let two = |value: u8| [b'0' + value / 10, b'0' + value % 10];
        let year = two((self.year % 100) as u8);
        let month = two(self.month);
        let day = two(self.day);
        let hour = two(self.hour);
        let minute = two(self.minute);
        let second = two(self.second);
        Ok([
            year[0], year[1], month[0], month[1], day[0], day[1], hour[0], hour[1], minute[0],
            minute[1], second[0], second[1], b'Z',
        ])
    }
}

#[cfg(test)]
mod tests;
