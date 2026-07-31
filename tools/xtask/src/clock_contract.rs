//! The clock record one boot must produce on the `LFW-PD` console channel.
//!
//! This is [`crate::config_transcript`]'s pattern applied to the other console
//! channel, and to the one record in the system whose *content* is a
//! measurement rather than a restatement of something the build already knows.
//! Nothing here reads prose and nothing here waits on a clock — the appliance's
//! own is the thing under test.
//!
//! # What can be asserted about a measurement, and what cannot
//!
//! The frequency the clock domain reports is whatever the host's timestamp
//! counter runs at, scaled by whatever QEMU's HPET emulation delivers, so no
//! exact value is available to compare against and no run of this gate could
//! produce one twice. What *is* available is the two bands the appliance's own
//! crates enforce, and asserting against them is what makes this a contract
//! rather than a smoke test: `lfw_clock::calibrate` refuses a frequency outside
//! [`MIN_PLAUSIBLE_TSC_HZ`]..=[`MAX_PLAUSIBLE_TSC_HZ`], and `lfw_rtc` refuses a
//! year outside [`MIN_PLAUSIBLE_YEAR`]..=[`MAX_PLAUSIBLE_YEAR`]. A record
//! carrying a number outside either would mean the value on the line is not the
//! value those crates produced — a rendering fault, a torn record, or a field
//! read out of the wrong offset — which is precisely what a black-box assertion
//! can see and a host test cannot.
//!
//! The bands are imported rather than restated for the reason every constant in
//! [`crate::sysdesc`] is: a copy here would drift from the appliance's, and the
//! drift would show up as a gate that passes on a value the appliance would
//! have refused.
//!
//! # Why `state=ready` is half the assertion
//!
//! The clock domain reports `refused` with a cause token on every path that
//! does not end in a measurement, and a refusal is a well-formed record on the
//! same channel. A reader that looked only for `tsc-hz=` would find nothing in
//! either case and report the same verdict for "the record is missing" and "the
//! HPET answered all-ones" — so the refusal is recognised, quoted, and reported
//! as itself.

use std::path::Path;

use lfw_clock::{MAX_PLAUSIBLE_TSC_HZ, MIN_PLAUSIBLE_TSC_HZ};
use lfw_log::{Domain, DomainState};
use lfw_rtc::{MAX_PLAUSIBLE_YEAR, MIN_PLAUSIBLE_YEAR};

/// What opens a record on any channel, and therefore what closes the one before
/// it — [`crate::config_transcript`]'s marker, for the reason stated there:
/// MONITORING.md makes this a reader's only handle, and a record is never
/// recognised by a line boundary.
const RECORD_MARKER: &str = "LFW-";

/// The prefix marking a run of serial bytes as a protection-domain lifecycle
/// record. The grammar is fixed in `crates/log/src/render.rs`.
const LIFECYCLE_PREFIX: &str = "LFW-PD ";

/// Judge the clock domain's record in one boot's serial capture.
///
/// # Errors
/// The verdict, naming what the channel carried against what the appliance owes
/// it, and where the whole run log is.
pub(crate) fn judge(serial: &[u8], log: &Path) -> Result<String, String> {
    let text = String::from_utf8_lossy(serial);
    let ours: Vec<&str> = lifecycle_records(&text)
        .into_iter()
        .filter(|record| record.contains(&field("domain", Domain::Clock.name())))
        .collect();

    let refused = field("state", DomainState::Refused.name());
    if let Some(record) = ours.iter().find(|record| record.contains(&refused)) {
        return Err(format!(
            "the clock domain refused to establish a time: {record:?}. The cause token names \
             which of the three stages refused — `hpet-` the timer block, `tsc-` the \
             measurement, `rtc-` the real-time clock, `cmos-ioport-` the port capability \
             itself — and MONITORING.md lists what each one's operands are.\n  full run log: {}",
            log.display()
        ));
    }

    let ready = field("state", DomainState::Ready.name());
    let established: Vec<&&str> = ours
        .iter()
        .filter(|record| record.contains(&ready))
        .collect();
    let [record] = established[..] else {
        return Err(format!(
            "the console carried {} `{}` record(s) for the clock domain in the `ready` state, \
             and a boot produces exactly one: this domain runs once in `init` and then parks, so \
             none means it never published and several mean something else is writing its \
             ring\n  clock records observed: {ours:#?}\n  full run log: {}",
            established.len(),
            LIFECYCLE_PREFIX.trim_end(),
            log.display()
        ));
    };

    let tsc_hz: u64 = value(record, "tsc-hz", log)?
        .parse()
        .map_err(|error| format!("{record:?}: tsc-hz is no number: {error}"))?;
    if !(MIN_PLAUSIBLE_TSC_HZ..=MAX_PLAUSIBLE_TSC_HZ).contains(&tsc_hz) {
        return Err(format!(
            "{record:?} reports a counter frequency of {tsc_hz} Hz, outside the \
             {MIN_PLAUSIBLE_TSC_HZ}..={MAX_PLAUSIBLE_TSC_HZ} band `lfw_clock::calibrate` \
             accepts — so the number on the line is not the number that function \
             returned\n  full run log: {}",
            log.display()
        ));
    }

    let utc = value(record, "utc", log)?;
    let year: u16 = utc
        .get(..4)
        .ok_or_else(|| format!("{record:?}: utc is shorter than a year"))?
        .parse()
        .map_err(|error| format!("{record:?}: the utc year is no number: {error}"))?;
    if !(MIN_PLAUSIBLE_YEAR..=MAX_PLAUSIBLE_YEAR).contains(&year) {
        return Err(format!(
            "{record:?} establishes the year {year}, outside the \
             {MIN_PLAUSIBLE_YEAR}..={MAX_PLAUSIBLE_YEAR} band `lfw_rtc` accepts — so the instant \
             on the line is not the instant that crate decoded\n  full run log: {}",
            log.display()
        ));
    }

    Ok(format!("the clock established {utc} at {tsc_hz} Hz"))
}

/// One `key=value` field as the console grammar writes it, so a search for one
/// cannot match a different key ending in the same letters.
fn field(key: &str, value: &str) -> String {
    format!(" {key}={value}")
}

/// The value of `key` in `record`, up to the next space or the end of it.
fn value<'a>(record: &'a str, key: &str, log: &Path) -> Result<&'a str, String> {
    let needle = format!(" {key}=");
    let at = record.find(&needle).ok_or_else(|| {
        format!(
            "{record:?} carries no `{key}=` field, and the clock domain's ready record is \
             specified with one (MONITORING.md)\n  full run log: {}",
            log.display()
        )
    })? + needle.len();
    let rest = record.get(at..).unwrap_or_default();
    Ok(rest.split(' ').next().unwrap_or(rest))
}

/// The lifecycle records a capture carries, in emission order.
///
/// The scan is [`crate::config_transcript`]'s, and is duplicated in neither
/// substance nor accident: a record is opened by [`RECORD_MARKER`] anywhere in
/// a line and runs to the next marker, so a record that did not begin its line
/// is still recovered and prose that quotes one is read as one — the marker's
/// price, which fails closed here exactly as it does there.
fn lifecycle_records(text: &str) -> Vec<&str> {
    text.lines().flat_map(records_in_line).collect()
}

fn records_in_line(line: &str) -> Vec<&str> {
    let markers: Vec<usize> = line
        .match_indices(RECORD_MARKER)
        .map(|(at, _)| at)
        .collect();
    markers
        .iter()
        .enumerate()
        .filter_map(|(position, start)| {
            let end = markers.get(position + 1).copied().unwrap_or(line.len());
            line.get(*start..end).map(str::trim)
        })
        .filter(|record| record.starts_with(LIFECYCLE_PREFIX))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> &'static Path {
        Path::new("/nonexistent/qemu.log")
    }

    /// A capture of the shape a passing boot leaves: the other domains'
    /// lifecycle records, the configuration channel, and the clock's own.
    fn capture(clock: &str) -> String {
        format!(
            "Bootstrapping kernel\r\n\
             LFW-BOOT slot=A state=confirmed\r\n\
             LFW-PD domain=config state=starting\r\n\
             LFW-PD domain=clock state=starting\r\n\
             LFW-CFG generation=0 outcome=applied changes=0\r\n\
             {clock}\r\n\
             LFW-PD domain=nic-driver state=ready rx-posted=64\r\n"
        )
    }

    const READY: &str = "LFW-PD domain=clock state=ready tsc-hz=2999998000 \
                         utc=2026-07-30T20:27:00.123456789Z";

    #[test]
    fn a_boot_that_established_a_plausible_time_is_accepted() {
        let proved = judge(capture(READY).as_bytes(), log()).expect("a plausible clock record");
        assert!(
            proved.contains("2026-07-30T20:27:00.123456789Z"),
            "{proved}"
        );
        assert!(proved.contains("2999998000"), "{proved}");
    }

    #[test]
    fn a_record_that_did_not_begin_its_line_is_still_recovered() {
        // MONITORING.md's obligation, which the debug kernel's own output makes
        // real: a record preceded on its line by kernel prose is still a record.
        let torn = capture(&format!("Bootstrapping node #0{READY}"));
        judge(torn.as_bytes(), log()).expect("a record that shares its line with prose");
    }

    #[test]
    fn a_boot_whose_clock_refused_is_reported_as_the_refusal_it_is() {
        let verdict = judge(
            capture(
                "LFW-PD domain=clock state=refused cause=hpet-not-present signalled=false \
                 detail=0xffffffffffffffff",
            )
            .as_bytes(),
            log(),
        )
        .expect_err("a refused clock");
        assert!(verdict.contains("refused to establish a time"), "{verdict}");
        assert!(verdict.contains("hpet-not-present"), "{verdict}");
    }

    #[test]
    fn a_boot_that_never_reached_the_clock_domain_is_refused() {
        // The silence a domain that faulted or was never scheduled leaves, and
        // the one an empty release capture leaves: the same verdict, because
        // neither carried the record.
        for silent in [
            String::new(),
            "Bootstrapping kernel\r\n".to_owned(),
            capture("LFW-PD domain=clock state=starting"),
        ] {
            let verdict = judge(silent.as_bytes(), log()).expect_err("no ready record");
            assert!(verdict.contains("carried 0"), "{verdict}");
        }
    }

    #[test]
    fn two_ready_records_are_refused_rather_than_read_as_one() {
        let text = format!("{}{READY}\r\n", capture(READY));
        let verdict = judge(text.as_bytes(), log()).expect_err("a doubled record");
        assert!(verdict.contains("carried 2"), "{verdict}");
    }

    #[test]
    fn a_frequency_outside_the_band_the_appliance_accepts_is_refused() {
        for hz in [
            0,
            MIN_PLAUSIBLE_TSC_HZ - 1,
            MAX_PLAUSIBLE_TSC_HZ + 1,
            u64::MAX,
        ] {
            let record = READY.replace("2999998000", &hz.to_string());
            let verdict = judge(capture(&record).as_bytes(), log()).expect_err("{hz} Hz");
            assert!(verdict.contains("counter frequency"), "{verdict}");
            assert!(verdict.contains(&hz.to_string()), "{verdict}");
        }
        // And both ends of the band itself are accepted, so the check is a band
        // and not an interior.
        for hz in [MIN_PLAUSIBLE_TSC_HZ, MAX_PLAUSIBLE_TSC_HZ] {
            let record = READY.replace("2999998000", &hz.to_string());
            judge(capture(&record).as_bytes(), log()).expect("a frequency on the boundary");
        }
    }

    #[test]
    fn a_year_outside_the_band_the_appliance_accepts_is_refused() {
        for year in ["1970", "1999", "2201", "9999"] {
            let record = READY.replace("2026-07-30", &format!("{year}-07-30"));
            let verdict = judge(capture(&record).as_bytes(), log()).expect_err("{year}");
            assert!(verdict.contains("establishes the year"), "{verdict}");
            assert!(verdict.contains(year), "{verdict}");
        }
        for year in [MIN_PLAUSIBLE_YEAR, MAX_PLAUSIBLE_YEAR] {
            let record = READY.replace("2026-07-30", &format!("{year}-07-30"));
            judge(capture(&record).as_bytes(), log()).expect("a year on the boundary");
        }
    }

    #[test]
    fn a_ready_record_missing_a_field_is_refused_by_the_field_it_is_missing() {
        for (record, missing) in [
            ("LFW-PD domain=clock state=ready", "tsc-hz"),
            ("LFW-PD domain=clock state=ready tsc-hz=2999998000", "utc"),
        ] {
            let verdict = judge(capture(record).as_bytes(), log()).expect_err("a partial record");
            assert!(verdict.contains(&format!("`{missing}=`")), "{verdict}");
        }
    }

    #[test]
    fn a_field_that_is_not_a_number_is_reported_rather_than_read_as_zero() {
        for (from, to) in [("2999998000", "fast"), ("2026-07-30", "soon-07-30")] {
            let record = READY.replace(from, to);
            let verdict = judge(capture(&record).as_bytes(), log()).expect_err("a bad field");
            assert!(verdict.contains("no number"), "{verdict}");
        }
    }

    #[test]
    fn another_domains_record_is_never_read_as_the_clocks() {
        // The channel carries every domain's lifecycle, and `domain=` is the
        // only thing separating them. A search for `state=ready` alone would
        // find the driver's.
        let text = capture("LFW-PD domain=console state=ready");
        let verdict = judge(text.as_bytes(), log()).expect_err("no clock record at all");
        assert!(verdict.contains("carried 0"), "{verdict}");
    }
}
