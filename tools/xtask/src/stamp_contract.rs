//! The instant every console record must carry, judged over one boot's whole
//! serial capture.
//!
//! This is the only contract that reads both in-kernel channels at once: the
//! stamp is the one field of the grammar that does not belong to a shape, so a
//! contract per channel would judge it twice and still miss the records the
//! other one names.
//!
//! `LFW-BOOT` is deliberately outside it. Those records are written by the boot
//! manager **before seL4 starts** (MONITORING.md, *Boot-manager records*), so
//! there is no protection domain, no calibration region and no counter reading
//! behind them; a stamp on one would be a different mechanism wearing the same
//! field name.
//!
//! # What can be asserted about a clock, and what cannot
//!
//! Nothing here knows what time it is. The appliance's epoch is whatever the
//! emulated CMOS answered, so no instant can be compared against the harness's
//! own clock and no run could produce the same one twice. What is available is
//! the shape of the transition and the band `lfw_rtc` accepts, and both are the
//! appliance's own statements about itself:
//!
//! * **Every record carries the field**, in one of exactly two forms. A record
//!   without one is a build whose renderer and whose grammar have parted.
//! * **The transition happens once, in one direction, per domain.** A domain
//!   emits before the clock domain publishes and stamps nothing; from the
//!   publish on it stamps everything. An unsynchronized record *after* a
//!   stamped one from the same domain would mean a calibration was withdrawn,
//!   which nothing in this system can do.
//! * **A domain's own stamps do not go backwards.** Within one ring the console
//!   renders in emission order (MONITORING.md), and one domain reads one
//!   counter, so its instants are non-decreasing.
//!
//! # Why the ordering is per domain and never across the capture
//!
//! The console serves the rings round-robin (MONITORING.md, *Ordering and
//! time*), so which domain's record reaches the line first is decided by where
//! that rotation stood — not by which event happened first. A monotonicity
//! assertion over the capture as a whole would therefore fail on a healthy
//! node, and passing would prove only that the rotation happened to agree.
//!
//! `nic-driver` is excluded from the ordering half for the same reason one step
//! further in: **three** protection domains publish under that one token, into
//! three separate rings, so their records interleave by rotation exactly as two
//! different domains' do. The `domain=` field cannot tell them apart — it names
//! the program, not the instance — and inventing an instance field to make this
//! assertion possible would change the operator's grammar to suit a test. They
//! are held to everything that is not an ordering.
//!
//! # No adversary
//!
//! On [`crate::console_records`]'s terms: the capture is the appliance's own
//! output on a wire only the harness is attached to.

use std::collections::BTreeMap;
use std::path::Path;

use lfw_clock::{CivilTime, NANOS_PER_SECOND, UtcNanos};
use lfw_log::{Domain, Stamp};
use lfw_rtc::{MAX_PLAUSIBLE_YEAR, MIN_PLAUSIBLE_YEAR};

use crate::console_records::{
    CONFIG_PREFIX, LIFECYCLE_PREFIX, TIME_KEY, records_on, value as field_value,
};

/// The token an unsynchronized record carries, taken from the crate that
/// renders it rather than restated: a copy here would go on agreeing with
/// itself after the appliance changed the word.
const UNSYNCHRONIZED: &str = Stamp::UNSYNCHRONIZED;

/// Bytes of `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`, which is the only other form the
/// field takes.
const INSTANT_LEN: usize = lfw_clock::RFC3339_LEN;

/// What one record's `time=` field says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Instant {
    /// The emitting domain had established no time.
    Unsynchronized,
    /// Nanoseconds since the Unix epoch, as the field named them.
    Utc(u64),
}

/// Judge every record's instant in one boot's serial capture.
///
/// # Errors
/// The verdict, naming the record that broke the contract and where the whole
/// run log is.
pub(crate) fn judge(serial: &[u8], log: &Path) -> Result<String, String> {
    let text = String::from_utf8_lossy(serial);
    let mut records = records_on(&text, LIFECYCLE_PREFIX);
    records.extend(records_on(&text, CONFIG_PREFIX));
    if records.is_empty() {
        return Err(verdict(
            "the capture carries no in-kernel record at all, so nothing was stamped",
            log,
        ));
    }

    let mut unsynchronized = 0usize;
    let mut stamped = 0usize;
    // Per emitting domain, because the console's rotation decides the order of
    // the capture and only a ring's own order is emission order.
    let mut last: BTreeMap<&str, Instant> = BTreeMap::new();

    for record in &records {
        let instant = parse(record, log)?;
        match instant {
            Instant::Unsynchronized => unsynchronized += 1,
            Instant::Utc(nanos) => {
                stamped += 1;
                in_band(record, nanos, log)?;
            }
        }
        let Some(domain) = ordered_domain(record) else {
            continue;
        };
        if let Some(previous) = last.insert(domain, instant) {
            follows(record, previous, instant, log)?;
        }
    }

    if unsynchronized == 0 {
        return Err(verdict(
            "every record carried an instant, and a boot cannot: the domains that emit during \
             their own `init` run before the clock domain publishes, so a transcript with no \
             `time=unsynchronized` record means the field is not being read from the calibration \
             region at all",
            log,
        ));
    }
    if stamped == 0 {
        return Err(verdict(
            "no record carried an instant, so the calibration reached no writing domain: the \
             clock domain publishes after its own `ready` record, and every record emitted after \
             that must be stamped",
            log,
        ));
    }
    Ok(format!(
        "{stamped} of {} records carry a UTC instant and {unsynchronized} predate the calibration",
        records.len()
    ))
}

/// The `domain=` token a record's ordering is grouped under, or `None` where it
/// has no ordering to judge: `LFW-CFG` carries no domain field, `LFW-BOOT` is
/// written before the kernel starts, and `nic-driver` names three domains.
fn ordered_domain(record: &str) -> Option<&str> {
    let domain = field_value(record, "domain")?;
    (domain != Domain::NicDriver.name()).then_some(domain)
}

fn parse(record: &str, log: &Path) -> Result<Instant, String> {
    let Some(field) = field_value(record, TIME_KEY) else {
        return Err(verdict(
            &format!(
                "{record:?} carries no `{TIME_KEY}=` field, and every record of every channel is \
                 specified with one (MONITORING.md)"
            ),
            log,
        ));
    };
    if field == UNSYNCHRONIZED {
        return Ok(Instant::Unsynchronized);
    }
    let nanos = unix_nanos(field).ok_or_else(|| {
        verdict(
            &format!(
                "{record:?} carries `{TIME_KEY}={field}`, which is neither the \
                 `{UNSYNCHRONIZED}` token nor an RFC 3339 instant of the fixed \
                 {INSTANT_LEN}-byte form the renderer produces"
            ),
            log,
        )
    })?;
    Ok(Instant::Utc(nanos))
}

/// The instant `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ` names, or `None` where the
/// field is not one.
///
/// Parsed into the appliance's own calendar arithmetic rather than compared as
/// text: a lexicographic order would agree with a chronological one for this
/// fixed form and would go on agreeing if the form changed, which is exactly
/// the drift a harness must not have.
fn unix_nanos(field: &str) -> Option<u64> {
    if field.len() != INSTANT_LEN {
        return None;
    }
    let at = |range: core::ops::Range<usize>| field.get(range);
    if at(4..5)? != "-" || at(7..8)? != "-" || at(10..11)? != "T" {
        return None;
    }
    if at(13..14)? != ":" || at(16..17)? != ":" || at(19..20)? != "." || at(29..30)? != "Z" {
        return None;
    }
    let civil = CivilTime {
        year: at(0..4)?.parse().ok()?,
        month: at(5..7)?.parse().ok()?,
        day: at(8..10)?.parse().ok()?,
        hour: at(11..13)?.parse().ok()?,
        minute: at(14..16)?.parse().ok()?,
        second: at(17..19)?.parse().ok()?,
        nanosecond: at(20..29)?.parse().ok()?,
    };
    let seconds = civil.to_unix_seconds().ok()?;
    seconds
        .checked_mul(NANOS_PER_SECOND)?
        .checked_add(u64::from(civil.nanosecond))
}

/// The band the appliance's own real-time-clock reader accepts, which is the
/// only external judgement available: an instant outside it is not the instant
/// that crate decoded.
fn in_band(record: &str, nanos: u64, log: &Path) -> Result<(), String> {
    let year = CivilTime::from_utc(UtcNanos::from_unix_nanos(nanos)).year;
    if (MIN_PLAUSIBLE_YEAR..=MAX_PLAUSIBLE_YEAR).contains(&year) {
        return Ok(());
    }
    Err(verdict(
        &format!(
            "{record:?} is dated in the year {year}, outside the \
             {MIN_PLAUSIBLE_YEAR}..={MAX_PLAUSIBLE_YEAR} band `lfw_rtc` accepts — so the instant \
             on the line is not one derived from the epoch that crate decoded"
        ),
        log,
    ))
}

/// What one domain's next record may say, given what its last one said.
fn follows(record: &str, previous: Instant, current: Instant, log: &Path) -> Result<(), String> {
    match (previous, current) {
        (Instant::Utc(_), Instant::Unsynchronized) => Err(verdict(
            &format!(
                "{record:?} carries no instant after an earlier record from the same domain \
                 carried one. A calibration is published once and never withdrawn, so a domain \
                 that has stamped a record stamps every later one"
            ),
            log,
        )),
        (Instant::Utc(earlier), Instant::Utc(later)) if later < earlier => Err(verdict(
            &format!(
                "{record:?} is dated before an earlier record from the same domain: {later} \
                 nanoseconds against {earlier}. One domain reads one counter and the console \
                 renders its ring in emission order, so its instants cannot go backwards"
            ),
            log,
        )),
        _ => Ok(()),
    }
}

fn verdict(finding: &str, log: &Path) -> String {
    format!("{finding}\n  full run log: {}", log.display())
}

#[cfg(test)]
mod tests;
