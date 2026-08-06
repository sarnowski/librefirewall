//! The one record the appliance owes about the channel it dials out of its
//! management port.
//!
//! [`crate::management_contract`]'s pattern on the other half of that port. There
//! the harness knows the numbers in advance because it put them on the wire;
//! here it knows them because it decided how the station on the far end would
//! behave — a station that answers, one that never does, one that refuses, one
//! that acknowledges what was never sent, and one that answers for somebody
//! else. Each of those has exactly one right outcome, and this is where the
//! appliance's own account of the channel is held to it.
//!
//! # The record is one, and that is half the contract
//!
//! A channel is reported when it is decided and a decided channel is never
//! re-opened, so the console carries exactly one `dial-outcome=` record per
//! boot. Two would be a domain that reopened a channel it had already given a
//! verdict on, and an operator reading the first would have been told something
//! that later stopped being true. So the count is asserted, not just the content.
//!
//! # What an attempt count catches that a token cannot
//!
//! The token says how the last session ended; the attempt count says how many
//! the appliance spent getting there. A channel that came up on the first dial
//! and one that came up after two failures are the same token and a different
//! node, and a channel that failed *without* spending its attempts is a bound
//! that did not hold. Both are stated.
//!
//! # No adversary
//!
//! As [`crate::console_records`]: this reads the appliance's own output on a
//! channel only the harness is attached to.

use std::path::Path;

use lfw_log::{DialOutcome, Domain};

use crate::console_records::{LIFECYCLE_PREFIX, field, lifecycle_records, value};

/// The field that identifies the record, and the three beside it.
const DESTINATION: &str = "dial-destination";
const PORT: &str = "dial-port";
const ATTEMPTS: &str = "dial-attempts";
const OUTCOME: &str = "dial-outcome";

/// What the appliance must say about the channel, given how the station on the
/// far end of it behaved.
///
/// The destination and the port are not here: they are first-party constants of
/// the code under test, restated in the harness beside the station's own copy,
/// and a contract that took them from a field of itself could not catch the
/// appliance dialling somewhere else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DialVerdict {
    /// The token the record must carry.
    pub outcome: DialOutcome,
    /// How many sessions the appliance must have spent on the channel.
    pub attempts: u64,
}

/// Whether the appliance has decided the channel and said so.
///
/// The observable a boot with a misbehaving station waits on. Such a boot never
/// sees a channel close — that is what makes it the boot it is — so what says
/// the appliance has finished is its own record, which is an event rather than a
/// duration.
pub(crate) fn reported(serial: &[u8]) -> bool {
    let text = String::from_utf8_lossy(serial);
    !records(&text).is_empty()
}

/// Judge the appliance's record of its dialled channel against what the station
/// on the far end of it did.
///
/// # Errors
/// The verdict, naming the field and the two values, and where the whole run log
/// is.
pub(crate) fn judge(
    serial: &[u8],
    log: &Path,
    owed: DialVerdict,
    destination: ([u8; 4], u16),
) -> Result<String, String> {
    let text = String::from_utf8_lossy(serial);
    let ours = records(&text);
    let [record] = ours[..] else {
        return Err(format!(
            "the console carried {} `{}` record(s) for the management domain naming a dialled \
             channel, and a boot produces exactly one: the channel is reported when it is decided \
             and a decided channel is never re-opened. None means the domain never decided it — \
             it was left with a session running, or it never reached a committed generation to \
             open one from\n  full run log: {}",
            ours.len(),
            LIFECYCLE_PREFIX.trim_end(),
            log.display()
        ));
    };

    let (address, port) = destination;
    let stated = read(record, DESTINATION, log)?;
    let expected = address.map(|octet| octet.to_string()).join(".");
    if stated != expected {
        return Err(format!(
            "the appliance dialled {stated} and this station stands at {expected}. The \
             destination is a first-party constant of the appliance, so a record naming another \
             address is a channel taken somewhere nobody asked for\n  the record: \
             {record:?}\n  full run log: {}",
            log.display()
        ));
    }
    let stated = read(record, PORT, log)?;
    if stated != port.to_string() {
        return Err(format!(
            "the appliance dialled port {stated} and this station listens on {port}\n  the \
             record: {record:?}\n  full run log: {}",
            log.display()
        ));
    }

    let attempts = number(record, ATTEMPTS, log)?;
    if attempts != owed.attempts {
        return Err(format!(
            "the appliance spent {attempts} session(s) on the channel and this station's \
             behaviour obliges {}. The count is what separates a channel that came up at once \
             from one that came up after failures, and a channel that failed short of its bound \
             is that bound not holding\n  the record: {record:?}\n  full run log: {}",
            owed.attempts,
            log.display()
        ));
    }

    let stated = read(record, OUTCOME, log)?;
    if stated != owed.outcome.name() {
        return Err(format!(
            "the appliance reported the channel as `{stated}` and this station's behaviour \
             obliges `{}`. The token is a closed vocabulary and each of its values names a \
             different thing to go and look at, so the wrong one is an operator sent to the \
             wrong place\n  the record: {record:?}\n  full run log: {}",
            owed.outcome.name(),
            log.display()
        ));
    }

    Ok(format!(
        "the appliance reported its channel to {expected}:{port} as `{stated}` after {attempts} \
         attempt(s)"
    ))
}

/// Every lifecycle record of the management domain that names a dialled channel.
fn records(text: &str) -> Vec<&str> {
    lifecycle_records(text)
        .into_iter()
        .filter(|record| record.contains(&field("domain", Domain::Management.name())))
        .filter(|record| value(record, OUTCOME).is_some())
        .collect()
}

fn read(record: &str, key: &str, log: &Path) -> Result<String, String> {
    value(record, key).map(str::to_owned).ok_or_else(|| {
        format!(
            "{record:?} names a dialled channel and carries no `{key}=`, and the four fields are \
             specified to travel together\n  full run log: {}",
            log.display()
        )
    })
}

fn number(record: &str, key: &str, log: &Path) -> Result<u64, String> {
    read(record, key, log)?.parse().map_err(|error| {
        format!(
            "{record:?}: {key} is no number: {error}\n  full run log: {}",
            log.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> &'static Path {
        Path::new("/nonexistent/qemu.log")
    }

    const STATION: ([u8; 4], u16) = ([10, 0, 2, 2], 4433);

    const ANSWERED: DialVerdict = DialVerdict {
        outcome: DialOutcome::Answered,
        attempts: 1,
    };

    fn dialled(destination: &str, port: u16, attempts: u64, outcome: &str) -> String {
        format!(
            "LFW-PD domain=management state=ready dial-destination={destination} \
             dial-port={port} dial-attempts={attempts} dial-outcome={outcome}\r\n"
        )
    }

    /// The records a boot leaves around the one this contract reads, so a
    /// fixture is a capture rather than a single line.
    fn booted() -> String {
        String::from(
            "LFW-PD domain=management state=starting\r\n\
             LFW-PD domain=management state=ready\r\n\
             LFW-PD domain=management state=ready frames=4 bytes=352\r\n",
        )
    }

    #[test]
    fn a_channel_reported_as_this_station_behaved_is_accepted() {
        let capture = booted() + &dialled("10.0.2.2", 4433, 1, "answered");
        let proved = judge(capture.as_bytes(), log(), ANSWERED, STATION).expect("the right record");
        assert!(proved.contains("10.0.2.2:4433"), "{proved}");
        assert!(proved.contains("`answered`"), "{proved}");
        assert!(proved.contains("1 attempt"), "{proved}");
    }

    /// Every token of the vocabulary is readable back as itself, so a contract
    /// stated for one outcome cannot pass on another.
    #[test]
    fn each_outcome_is_held_to_its_own_token() {
        for owed in DialOutcome::ALL {
            let capture = booted() + &dialled("10.0.2.2", 4433, 3, owed.name());
            let verdict = DialVerdict {
                outcome: owed,
                attempts: 3,
            };
            judge(capture.as_bytes(), log(), verdict, STATION).expect("its own token");
            for other in DialOutcome::ALL.into_iter().filter(|other| *other != owed) {
                let wrong = DialVerdict {
                    outcome: other,
                    attempts: 3,
                };
                let refused =
                    judge(capture.as_bytes(), log(), wrong, STATION).expect_err("another token");
                assert!(refused.contains(owed.name()), "{refused}");
                assert!(refused.contains(other.name()), "{refused}");
            }
        }
    }

    #[test]
    fn a_channel_that_spent_the_wrong_number_of_attempts_names_both_counts() {
        let capture = booted() + &dialled("10.0.2.2", 4433, 2, "connection-lost");
        let owed = DialVerdict {
            outcome: DialOutcome::ConnectionLost,
            attempts: 3,
        };
        let verdict = judge(capture.as_bytes(), log(), owed, STATION).expect_err("two of three");
        assert!(verdict.contains("spent 2 session(s)"), "{verdict}");
        assert!(verdict.contains("obliges 3"), "{verdict}");
    }

    #[test]
    fn a_channel_taken_to_another_address_or_port_is_refused_by_the_field_that_moved() {
        let elsewhere = booted() + &dialled("10.0.2.3", 4433, 1, "answered");
        let verdict =
            judge(elsewhere.as_bytes(), log(), ANSWERED, STATION).expect_err("another address");
        assert!(verdict.contains("dialled 10.0.2.3"), "{verdict}");

        let other_port = booted() + &dialled("10.0.2.2", 443, 1, "answered");
        let verdict =
            judge(other_port.as_bytes(), log(), ANSWERED, STATION).expect_err("another port");
        assert!(verdict.contains("dialled port 443"), "{verdict}");
    }

    /// A channel is decided once. Two records mean a domain that gave a verdict
    /// and then gave another, which makes the first a thing an operator was told
    /// and that stopped being true.
    #[test]
    fn a_channel_reported_twice_is_refused_as_readily_as_one_never_reported() {
        let twice = booted()
            + &dialled("10.0.2.2", 4433, 1, "answered")
            + &dialled("10.0.2.2", 4433, 2, "connection-lost");
        let verdict = judge(twice.as_bytes(), log(), ANSWERED, STATION).expect_err("two records");
        assert!(verdict.contains("carried 2"), "{verdict}");

        let never = booted();
        let verdict = judge(never.as_bytes(), log(), ANSWERED, STATION).expect_err("no record");
        assert!(verdict.contains("carried 0"), "{verdict}");
    }

    /// Another domain's record is never read as this one's, on
    /// [`crate::management_contract`]'s terms: `domain=` is the only thing
    /// separating the channels.
    #[test]
    fn another_domains_record_is_never_read_as_the_management_ports() {
        let capture = booted()
            + "LFW-PD domain=forwarder state=ready dial-destination=10.0.2.2 dial-port=4433 \
               dial-attempts=1 dial-outcome=answered\r\n";
        let verdict = judge(capture.as_bytes(), log(), ANSWERED, STATION).expect_err("not ours");
        assert!(verdict.contains("carried 0"), "{verdict}");
        assert!(!reported(capture.as_bytes()));
    }

    #[test]
    fn a_record_is_reported_only_once_the_appliance_has_decided_the_channel() {
        assert!(!reported(booted().as_bytes()));
        assert!(reported(
            (booted() + &dialled("10.0.2.2", 4433, 3, "next-hop-unreachable")).as_bytes()
        ));
    }

    #[test]
    fn an_attempt_count_that_is_no_number_is_reported_rather_than_read_as_zero() {
        let capture = booted() + &dialled("10.0.2.2", 4433, 0, "answered").replace("=0 ", "=many ");
        let verdict = judge(capture.as_bytes(), log(), ANSWERED, STATION).expect_err("a bad field");
        assert!(verdict.contains("is no number"), "{verdict}");
    }
}
