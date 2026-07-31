//! Recovering the appliance's structured records out of one boot's serial
//! capture, for the three contracts that judge them.
//!
//! MONITORING.md makes the `LFW-` prefix a reader's only handle: a record is not
//! a line, and nothing promises one line is one record. Two things in the
//! capture make that concrete — the debug kernel writes the same port for its
//! own prose, and GRUB writes it before anything else does — so a record may
//! begin in the middle of a line and a line may carry several.
//!
//! # Why one scanner rather than one per contract
//!
//! [`crate::config_transcript`], [`crate::clock_contract`] and
//! [`crate::management_contract`] each judge a different channel and each need
//! exactly this scan. It lived in all three, differing only in the prefix they
//! filtered on, with a comment in each saying the duplication was deliberate.
//! One copy taking the prefix as a parameter is the same three behaviours with
//! one place for the marker rule to be right (ENG-6).
//!
//! # What it deliberately does not do, and what that costs
//!
//! It does not reassemble a record torn through its own middle: the head
//! fragment is kept, the tail carries no marker and is discarded, and the
//! contract that reads them reports a mismatch rather than quietly accepting
//! one. Two concurrent writers leave nothing to decide by which fragment
//! continues which, so a harness that guessed would be inventing records.
//!
//! The price, which is the right way to be wrong: prose that *quotes* a record
//! reads as one. A quoted record carries its prose with it, so it lands as a
//! mismatch or a refused field and stops the gate, where a torn record went
//! unseen.
//!
//! # No adversary
//!
//! Nothing here reads hostile input. The capture is the appliance's own output
//! on a wire only the harness is attached to, so CON-2 names no CONCEPT §7.1
//! adversary for this path; what it defends against is a contract reading a
//! record that was never written.

/// What opens a record on any channel, and therefore what closes the one before
/// it.
pub(crate) const RECORD_MARKER: &str = "LFW-";

/// The prefix marking a record as a protection-domain lifecycle one. The
/// grammar is fixed in `crates/log/src/render.rs`.
pub(crate) const LIFECYCLE_PREFIX: &str = "LFW-PD ";

/// As [`LIFECYCLE_PREFIX`], for the configuration channel.
pub(crate) const CONFIG_PREFIX: &str = "LFW-CFG ";

/// The protection-domain lifecycle records a capture carries, in emission order.
pub(crate) fn lifecycle_records(text: &str) -> Vec<&str> {
    records_on(text, LIFECYCLE_PREFIX)
}

/// Every record in `text` on the channel `prefix` names, in emission order.
pub(crate) fn records_on<'a>(text: &'a str, prefix: &str) -> Vec<&'a str> {
    text.lines()
        .flat_map(|line| records_in_line(line, prefix))
        .collect()
}

/// The records one captured line carries, in the order they were written: each
/// [`RECORD_MARKER`] opens a candidate that runs to the next marker or to the
/// end of the line, and only the candidates on `prefix`'s channel are kept. So
/// GRUB's prose, seL4's boot chatter and every other channel cannot be mistaken
/// for one of these wherever in a line they sit.
fn records_in_line<'a>(line: &'a str, prefix: &str) -> Vec<&'a str> {
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
        .filter(|record| record.starts_with(prefix))
        .collect()
}

/// The key of the instant every record carries, first among its fields.
pub(crate) const TIME_KEY: &str = "time";

/// One `key=value` field as the console grammar writes it, so a search for one
/// cannot match a different key ending in the same letters.
pub(crate) fn field(key: &str, value: &str) -> String {
    format!(" {key}={value}")
}

/// `record` without its instant.
///
/// The instant is the one field whose value two runs of one build disagree
/// about, so a contract comparing a record against a line the build rendered
/// compares this. What the instant itself owes is judged on its own
/// ([`crate::stamp_contract`]), over every record rather than the few a
/// transcript names.
pub(crate) fn without_time(record: &str) -> String {
    let needle = field(TIME_KEY, "");
    let Some(at) = record.find(&needle) else {
        return record.to_owned();
    };
    let rest = record.get(at + needle.len()..).unwrap_or_default();
    let tail = rest.find(' ').map_or("", |end| &rest[end..]);
    format!("{}{tail}", &record[..at])
}

/// The value of `key` in `record`, up to the next space or the end of it.
/// `None` where the record carries no such field.
pub(crate) fn value<'a>(record: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!(" {key}=");
    let at = record.find(&needle)? + needle.len();
    let rest = record.get(at..)?;
    Some(rest.split(' ').next().unwrap_or(rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    const READY: &str = "LFW-PD domain=clock state=ready tsc-hz=42";

    #[test]
    fn a_record_that_owns_its_line_is_recovered() {
        assert_eq!(records_on(READY, LIFECYCLE_PREFIX), [READY]);
    }

    /// The obligation the debug kernel's own output makes real: a record
    /// preceded on its line by prose is still a record.
    #[test]
    fn a_record_that_did_not_begin_its_line_is_still_recovered() {
        let torn = format!("Bootstrapping node #0{READY}");
        assert_eq!(records_on(&torn, LIFECYCLE_PREFIX), [READY]);
    }

    /// Several records on one line, which is what a kernel writing the same
    /// port between two of them produces.
    #[test]
    fn every_record_on_one_line_is_recovered_in_order() {
        let line = "LFW-PD domain=config state=starting LFW-PD domain=clock state=starting";
        assert_eq!(
            records_on(line, LIFECYCLE_PREFIX),
            [
                "LFW-PD domain=config state=starting",
                "LFW-PD domain=clock state=starting"
            ]
        );
    }

    /// The prefix is what separates the channels, and it separates them within a
    /// line as well as between lines.
    #[test]
    fn another_channels_record_is_never_returned() {
        let mixed = "LFW-BOOT slot=A state=confirmed LFW-CFG generation=0 outcome=applied \
                     changes=0\r\nLFW-PD domain=console state=ready\r\n";
        assert_eq!(
            records_on(mixed, LIFECYCLE_PREFIX),
            ["LFW-PD domain=console state=ready"]
        );
        assert_eq!(
            records_on(mixed, "LFW-CFG "),
            ["LFW-CFG generation=0 outcome=applied changes=0"]
        );
        assert!(records_on(mixed, "LFW-NOPE ").is_empty());
    }

    #[test]
    fn a_capture_with_no_records_yields_none() {
        for text in ["", "Bootstrapping kernel\r\n", "LFW-\r\n"] {
            assert!(records_on(text, LIFECYCLE_PREFIX).is_empty(), "{text:?}");
        }
    }

    #[test]
    fn a_field_is_read_up_to_the_next_space_and_a_missing_one_is_none() {
        assert_eq!(value(READY, "domain"), Some("clock"));
        assert_eq!(value(READY, "state"), Some("ready"));
        assert_eq!(value(READY, "tsc-hz"), Some("42"));
        assert_eq!(value(READY, "utc"), None);
    }

    /// A key that is the tail of another must not match it, which is the whole
    /// reason a field is searched for with its leading space.
    #[test]
    fn a_record_without_its_instant_keeps_every_other_field_in_place() {
        assert_eq!(
            without_time("LFW-PD time=unsynchronized domain=clock state=starting"),
            "LFW-PD domain=clock state=starting"
        );
        assert_eq!(
            without_time(
                "LFW-PD time=2026-07-30T20:27:00.123456789Z domain=management state=ready \
                 frames=4 bytes=352"
            ),
            "LFW-PD domain=management state=ready frames=4 bytes=352"
        );
        // The last field, which is where an off-by-one would take the tail with
        // it, and a record carrying no instant at all.
        assert_eq!(without_time("LFW-PD time=unsynchronized"), "LFW-PD");
        assert_eq!(without_time("LFW-PD domain=clock"), "LFW-PD domain=clock");
    }

    #[test]
    fn a_key_ending_in_another_keys_letters_does_not_match_it() {
        let record = "LFW-PD domain=management state=ready frames=4 bytes=352";
        assert_eq!(value(record, "bytes"), Some("352"));
        assert_eq!(value(record, "frames"), Some("4"));
        assert_eq!(value(record, "ames"), None);
        assert_eq!(field("state", "ready"), " state=ready");
    }
}
