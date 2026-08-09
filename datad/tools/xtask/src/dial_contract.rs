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
//! # And what the counts catch that a token cannot
//!
//! A deployed node has no shell, so a failed channel is diagnosable from the
//! console or not at all — and three of the four stations below once produced
//! **one** token between them. So a failing boot is held to the counts as well:
//! the handshakes the appliance composed, whether anything came back at all, the
//! resets in each direction, the requests the resolution spent and what it
//! learned, and the replies the port turned away. Each of the four scenarios
//! asserts the subset that tells it apart from the other three, which is what
//! keeps the un-folding from quietly folding back.
//!
//! An expectation is stated **exactly** where the appliance's own constants fix
//! the number and as a **floor** where a retransmission backoff or a cache
//! lifetime decides it: a count asserted exactly against something a timer
//! chooses is a flake, and one asserted as a floor of zero is no assertion. Which
//! of the two each is, is stated where the scenario states it.
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

/// The fields of the three records a failed channel adds, and of the fourth an
/// unacceptable acknowledgement adds after them.
const NEXT_HOP: &str = "dial-next-hop";
const NEXT_HOP_VIA: &str = "dial-next-hop-via";
const REQUESTS: &str = "dial-requests";
const LEARNED: &str = "dial-learned";
const UNSOLICITED: &str = "dial-reply-unsolicited";
const REBINDING: &str = "dial-reply-rebinding";
const NOT_UNICAST: &str = "dial-reply-not-unicast";
const CONTRADICTED: &str = "dial-reply-contradicted";
const SYNS: &str = "dial-syns";
const RESETS_RECEIVED: &str = "dial-resets-received";
const RESETS_SENT: &str = "dial-resets-sent";
const ANSWERED: &str = "dial-answered";
const ACKNOWLEDGED: &str = "dial-acknowledged";
const EXPECTED: &str = "dial-expected";

/// What a count on one of those records must be.
///
/// Two shapes rather than one, because the appliance's counts come from two
/// different kinds of thing: a bound it chose, which fixes a number exactly, and
/// a timer or a cache lifetime, which fixes only a floor. Stating a
/// timer-decided count exactly would be a flake, and stating a bound-decided one
/// as a floor would let a regression through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Count {
    Exactly(u64),
    AtLeast(u64),
}

impl Count {
    /// Whether `observed` satisfies this expectation.
    pub(crate) fn holds(self, observed: u64) -> bool {
        match self {
            Self::Exactly(expected) => observed == expected,
            Self::AtLeast(floor) => observed >= floor,
        }
    }

    /// This expectation as a clause for a verdict.
    pub(crate) fn stated(self) -> String {
        match self {
            Self::Exactly(expected) => format!("exactly {expected}"),
            Self::AtLeast(floor) => format!("at least {floor}"),
        }
    }
}

/// The counts a failed channel's own records must carry.
///
/// Every field is here because it distinguishes one of the four misbehaviours
/// from another; nothing is asserted for the sake of asserting it. The route's
/// own two are the exception and earn their place differently: they say the
/// frames went where this port's addressing sends them, which is what makes
/// every other count a statement about the station rather than about a
/// misrouted channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DialAccount {
    /// The station the frames were handed to, and whether the port's prefix or
    /// its gateway chose it.
    pub next_hop: ([u8; 4], &'static str),
    pub requests: Count,
    pub learned: Count,
    /// Replies the port turned away, in `UNSOLICITED`, `REBINDING`,
    /// `NOT_UNICAST`, `CONTRADICTED` order.
    pub unlearned: [Count; 4],
    pub syns: Count,
    pub resets_received: Count,
    pub resets_sent: Count,
    /// Whether anything at all arrived on the channel's connections. **The one
    /// field that separates silence from a station that answered badly**, and so
    /// the one the un-folding rests on.
    pub answered: bool,
    /// Whether the appliance owes the sequence pair at all. `false` obliges the
    /// record to be **absent**: a channel that carried no such claim and
    /// reported numbers anyway would be reporting numbers it invented. `true`
    /// obliges it to be present and to carry exactly what the station on the far
    /// end read off the wire, which the run supplies.
    pub acknowledged: bool,
}

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
    /// The counts the records after it must carry, where the channel failed.
    /// `None` for a channel that came up, which owes none of them.
    pub account: Option<DialAccount>,
}

/// Whether the appliance has decided the channel and said **all** of what that
/// decision owes.
///
/// The observable a boot with a misbehaving station waits on. Such a boot never
/// sees a channel close — that is what makes it the boot it is — so what says
/// the appliance has finished is its own records, which are events rather than a
/// duration.
///
/// **The whole set and not the first of it.** A failed channel reports the
/// outcome and then the three records that place it, and the domain emits them
/// in one pass — but a console renders a ring at 115200 baud, so a run that
/// stopped at the outcome could kill the emulator with the evidence still in the
/// UART and then fail for want of the very records the appliance had already
/// written. Waiting on the last of them is waiting on the observable this
/// contract is about to judge.
pub(crate) fn reported(serial: &[u8]) -> bool {
    let text = String::from_utf8_lossy(serial);
    let [record] = records(&text)[..] else {
        return false;
    };
    // Which record the appliance emits last is decided by the outcome, and the
    // three cases are the three shapes of the report: a channel that came up
    // places no fault and owes nothing further, one that failed places it in
    // three more records, and one a station misacknowledged adds the pair it
    // claimed after those.
    let last = match value(record, OUTCOME) {
        Some(token) if token == DialOutcome::Answered.name() => return true,
        Some(token) if token == DialOutcome::UnacceptableAcknowledgement.name() => ACKNOWLEDGED,
        _ => SYNS,
    };
    !ours_carrying(&text, last).is_empty()
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
    claimed: Option<(u32, u32)>,
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

    let Some(account) = owed.account else {
        // A channel that came up owes no counts, and must carry none: the extra
        // records exist to place a failure, and a healthy boot emitting them
        // would be a console saying something happened that did not.
        for key in [NEXT_HOP, UNSOLICITED, SYNS, ACKNOWLEDGED] {
            if let Some(found) = ours_carrying(&text, key).first() {
                return Err(format!(
                    "the channel came up and the console carries a `{key}=` record anyway: a \
                     healthy boot places no fault, so these records are emitted only where there \
                     is one\n  the record: {found:?}\n  full run log: {}",
                    log.display()
                ));
            }
        }
        return Ok(format!(
            "the appliance reported its channel to {expected}:{port} as `{stated}` after \
             {attempts} attempt(s)"
        ));
    };
    let placed = judge_account(&text, log, account, claimed)?;
    Ok(format!(
        "the appliance reported its channel to {expected}:{port} as `{stated}` after {attempts} \
         attempt(s), and placed it: {placed}"
    ))
}

/// Hold the three records a failed channel adds — and the fourth an unacceptable
/// acknowledgement adds — to what this station's behaviour obliges.
///
/// Each record is read on its own, by a key only it carries, so a missing one is
/// reported as the record it is rather than as a field of another.
fn judge_account(
    text: &str,
    log: &Path,
    owed: DialAccount,
    claimed: Option<(u32, u32)>,
) -> Result<String, String> {
    let route = only(text, log, NEXT_HOP)?;
    let (address, via) = owed.next_hop;
    let expected = address.map(|octet| octet.to_string()).join(".");
    let stated = read(&route, NEXT_HOP, log)?;
    if stated != expected {
        return Err(format!(
            "the appliance handed this channel's frames to {stated} and its own addressing sends \
             them to {expected}. Every count beside it is a statement about the station, and a \
             misrouted channel would make all of them statements about somebody else\n  the \
             record: {route:?}\n  full run log: {}",
            log.display()
        ));
    }
    let stated = read(&route, NEXT_HOP_VIA, log)?;
    if stated != via {
        return Err(format!(
            "the appliance says it chose that next hop by the `{stated}` and this port's \
             addressing chooses it by the `{via}`. The two send an operator to different halves \
             of the configuration document\n  the record: {route:?}\n  full run log: {}",
            log.display()
        ));
    }
    counted(&route, REQUESTS, owed.requests, log)?;
    counted(&route, LEARNED, owed.learned, log)?;

    let unlearned = only(text, log, UNSOLICITED)?;
    for (key, owed) in [UNSOLICITED, REBINDING, NOT_UNICAST, CONTRADICTED]
        .into_iter()
        .zip(owed.unlearned)
    {
        counted(&unlearned, key, owed, log)?;
    }

    let segments = only(text, log, SYNS)?;
    counted(&segments, SYNS, owed.syns, log)?;
    counted(&segments, RESETS_RECEIVED, owed.resets_received, log)?;
    counted(&segments, RESETS_SENT, owed.resets_sent, log)?;
    let stated = read(&segments, ANSWERED, log)?;
    if stated != owed.answered.to_string() {
        return Err(format!(
            "the appliance reports `{ANSWERED}={stated}` and this station's behaviour obliges \
             `{}`. It is the fact that separates a station saying nothing from one answering \
             badly, so the wrong value is the whole diagnosis inverted\n  the record: \
             {segments:?}\n  full run log: {}",
            owed.answered,
            log.display()
        ));
    }

    let claimed = if owed.acknowledged {
        // The station's own reading of both numbers, not the appliance's: a
        // console held to a pair the appliance also supplied would be the
        // appliance agreeing with itself.
        let Some((claimed, expected)) = claimed else {
            return Err(format!(
                "this station's behaviour obliges the appliance to report the sequence number it \
                 claimed, and the station never read one off the wire — so there is nothing \
                 independent to hold the console to and the run proves less than it says\n  full \
                 run log: {}",
                log.display()
            ));
        };
        let record = only(text, log, ACKNOWLEDGED)?;
        counted(
            &record,
            ACKNOWLEDGED,
            Count::Exactly(u64::from(claimed)),
            log,
        )?;
        counted(&record, EXPECTED, Count::Exactly(u64::from(expected)), log)?;
        format!(", and the station claimed {claimed} against {expected} really sent")
    } else {
        if let Some(found) = ours_carrying(text, ACKNOWLEDGED).first() {
            return Err(format!(
                "no station claimed a sequence number on this channel and the console reports a \
                 pair anyway\n  the record: {found:?}\n  full run log: {}",
                log.display()
            ));
        }
        String::new()
    };
    Ok(format!(
        "{} request(s) and {} learned, {} handshake(s), {} reset(s) in and {} out, answered={}{claimed}",
        read(&route, REQUESTS, log)?,
        read(&route, LEARNED, log)?,
        read(&segments, SYNS, log)?,
        read(&segments, RESETS_RECEIVED, log)?,
        read(&segments, RESETS_SENT, log)?,
        read(&segments, ANSWERED, log)?,
    ))
}

/// The one management record carrying `key`, refusing none and refusing two.
///
/// A record per key rather than a search of everything: each of the four carries
/// a key no other does, and a boot emitting one of them twice would be a domain
/// that decided a channel twice — the same defect the outcome record's own count
/// exists to catch.
fn only(text: &str, log: &Path, key: &str) -> Result<String, String> {
    let found = ours_carrying(text, key);
    let [record] = &found[..] else {
        return Err(format!(
            "the console carried {} management record(s) with a `{key}=` field, and a channel \
             that failed produces exactly one: none means the appliance reported a token with no \
             evidence beside it, which is a failure an operator cannot act on without the \
             wire\n  full run log: {}",
            found.len(),
            log.display()
        ));
    };
    Ok(record.clone())
}

fn counted(record: &str, key: &str, owed: Count, log: &Path) -> Result<(), String> {
    let observed = number(record, key, log)?;
    if owed.holds(observed) {
        return Ok(());
    }
    Err(format!(
        "the appliance reports `{key}={observed}` and this station's behaviour obliges {}. This \
         count is one of the facts that tells this misbehaviour from the others, so the wrong \
         value is an operator sent to the wrong place\n  the record: {record:?}\n  full run \
         log: {}",
        owed.stated(),
        log.display()
    ))
}

/// Every lifecycle record of the management domain that names a dialled channel.
fn records(text: &str) -> Vec<&str> {
    ours(text)
        .into_iter()
        .filter(|record| value(record, OUTCOME).is_some())
        .collect()
}

/// Every management record carrying `key`.
fn ours_carrying(text: &str, key: &str) -> Vec<String> {
    ours(text)
        .into_iter()
        .filter(|record| value(record, key).is_some())
        .map(str::to_owned)
        .collect()
}

/// Every lifecycle record this domain emitted.
fn ours(text: &str) -> Vec<&str> {
    lifecycle_records(text)
        .into_iter()
        .filter(|record| record.contains(&field("domain", Domain::Management.name())))
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

    const CAME_UP: DialVerdict = DialVerdict {
        outcome: DialOutcome::Answered,
        attempts: 1,
        account: None,
    };

    /// The counts the fixtures below place, and the shape a scenario states.
    const PLACED: DialAccount = DialAccount {
        next_hop: ([10, 0, 2, 2], "prefix"),
        requests: Count::AtLeast(1),
        learned: Count::Exactly(1),
        unlearned: [Count::Exactly(0); 4],
        syns: Count::AtLeast(3),
        resets_received: Count::Exactly(0),
        resets_sent: Count::Exactly(0),
        answered: false,
        acknowledged: false,
    };

    /// The three records a failed channel adds, in the order it emits them.
    fn placed() -> String {
        String::from(
            "LFW-PD domain=management state=ready dial-next-hop=10.0.2.2 \
             dial-next-hop-via=prefix dial-requests=1 dial-learned=1\r\n\
             LFW-PD domain=management state=ready dial-reply-unsolicited=0 \
             dial-reply-rebinding=0 dial-reply-not-unicast=0 dial-reply-contradicted=0\r\n\
             LFW-PD domain=management state=ready dial-syns=18 dial-resets-received=0 \
             dial-resets-sent=0 dial-answered=false\r\n",
        )
    }

    /// The fifth record, which only a misacknowledged channel adds.
    fn acknowledged(claimed: u32, expected: u32) -> String {
        format!(
            "LFW-PD domain=management state=ready dial-acknowledged={claimed} \
             dial-expected={expected}\r\n"
        )
    }

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
        let proved =
            judge(capture.as_bytes(), log(), CAME_UP, STATION, None).expect("the right record");
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
                account: None,
            };
            judge(capture.as_bytes(), log(), verdict, STATION, None).expect("its own token");
            for other in DialOutcome::ALL.into_iter().filter(|other| *other != owed) {
                let wrong = DialVerdict {
                    outcome: other,
                    attempts: 3,
                    account: None,
                };
                let refused = judge(capture.as_bytes(), log(), wrong, STATION, None)
                    .expect_err("another token");
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
            account: None,
        };
        let verdict =
            judge(capture.as_bytes(), log(), owed, STATION, None).expect_err("two of three");
        assert!(verdict.contains("spent 2 session(s)"), "{verdict}");
        assert!(verdict.contains("obliges 3"), "{verdict}");
    }

    #[test]
    fn a_channel_taken_to_another_address_or_port_is_refused_by_the_field_that_moved() {
        let elsewhere = booted() + &dialled("10.0.2.3", 4433, 1, "answered");
        let verdict = judge(elsewhere.as_bytes(), log(), CAME_UP, STATION, None)
            .expect_err("another address");
        assert!(verdict.contains("dialled 10.0.2.3"), "{verdict}");

        let other_port = booted() + &dialled("10.0.2.2", 443, 1, "answered");
        let verdict =
            judge(other_port.as_bytes(), log(), CAME_UP, STATION, None).expect_err("another port");
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
        let verdict =
            judge(twice.as_bytes(), log(), CAME_UP, STATION, None).expect_err("two records");
        assert!(verdict.contains("carried 2"), "{verdict}");

        let never = booted();
        let verdict =
            judge(never.as_bytes(), log(), CAME_UP, STATION, None).expect_err("no record");
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
        let verdict =
            judge(capture.as_bytes(), log(), CAME_UP, STATION, None).expect_err("not ours");
        assert!(verdict.contains("carried 0"), "{verdict}");
        assert!(!reported(capture.as_bytes()));
    }

    /// A failed channel is not reported until the records that place it have
    /// arrived too — the property that keeps a run from killing the emulator
    /// with its own evidence still in the UART.
    #[test]
    fn a_failed_channel_is_reported_only_once_its_evidence_has_arrived_as_well() {
        assert!(!reported(booted().as_bytes()));
        let outcome_alone = booted() + &dialled("10.0.2.2", 4433, 3, "next-hop-unreachable");
        assert!(!reported(outcome_alone.as_bytes()));
        assert!(reported((outcome_alone + &placed()).as_bytes()));
    }

    /// A channel that came up owes none of them, so its outcome record is the
    /// whole of what there is to wait for.
    #[test]
    fn a_channel_that_came_up_is_reported_by_its_outcome_alone() {
        assert!(reported(
            (booted() + &dialled("10.0.2.2", 4433, 1, "answered")).as_bytes()
        ));
    }

    /// A misacknowledged channel adds a fifth record after the three, so the
    /// three are not the whole of what to wait for on that one outcome.
    #[test]
    fn a_misacknowledged_channel_is_reported_only_once_its_pair_has_arrived() {
        let placed =
            booted() + &dialled("10.0.2.2", 4433, 3, "unacceptable-acknowledgement") + &placed();
        assert!(!reported(placed.as_bytes()));
        assert!(reported(
            (placed + &acknowledged(0x1234_5678, 99)).as_bytes()
        ));
    }

    /// The counts a failed channel places, read record by record and each held
    /// to what the station's behaviour obliges.
    #[test]
    fn a_channel_that_placed_its_fault_is_accepted_and_its_counts_are_reported() {
        let capture = booted() + &dialled("10.0.2.2", 4433, 3, "unanswered") + &placed();
        let owed = DialVerdict {
            outcome: DialOutcome::Unanswered,
            attempts: 3,
            account: Some(PLACED),
        };
        let proved =
            judge(capture.as_bytes(), log(), owed, STATION, None).expect("the right records");
        assert!(proved.contains("18 handshake(s)"), "{proved}");
        assert!(proved.contains("answered=false"), "{proved}");
    }

    /// Every count is checked, and each names itself when it is wrong: a
    /// contract that reported "the counts disagree" would leave an author
    /// diffing four records by eye.
    #[test]
    fn each_count_that_disagrees_names_its_own_field() {
        let capture = booted() + &dialled("10.0.2.2", 4433, 3, "unanswered") + &placed();
        let cases: [(DialAccount, &str); 5] = [
            (
                DialAccount {
                    syns: Count::Exactly(4),
                    ..PLACED
                },
                "dial-syns=18",
            ),
            (
                DialAccount {
                    learned: Count::Exactly(0),
                    ..PLACED
                },
                "dial-learned=1",
            ),
            (
                DialAccount {
                    resets_received: Count::AtLeast(1),
                    ..PLACED
                },
                "dial-resets-received=0",
            ),
            (
                DialAccount {
                    unlearned: [
                        Count::AtLeast(1),
                        Count::Exactly(0),
                        Count::Exactly(0),
                        Count::Exactly(0),
                    ],
                    ..PLACED
                },
                "dial-reply-unsolicited=0",
            ),
            (
                DialAccount {
                    answered: true,
                    ..PLACED
                },
                "dial-answered=false",
            ),
        ];
        for (account, named) in cases {
            let owed = DialVerdict {
                outcome: DialOutcome::Unanswered,
                attempts: 3,
                account: Some(account),
            };
            let refused = judge(capture.as_bytes(), log(), owed, STATION, None)
                .expect_err("a count that moved");
            assert!(refused.contains(named), "{refused}");
        }
    }

    /// A channel taken somewhere this port's addressing does not send it makes
    /// every other count a fact about the wrong station, so it is refused by the
    /// address and by the way it was chosen.
    #[test]
    fn a_channel_routed_elsewhere_is_refused_by_the_field_that_moved() {
        let owed = DialVerdict {
            outcome: DialOutcome::Unanswered,
            attempts: 3,
            account: Some(PLACED),
        };
        let elsewhere = booted()
            + &dialled("10.0.2.2", 4433, 3, "unanswered")
            + &placed().replace("dial-next-hop=10.0.2.2", "dial-next-hop=10.0.2.99");
        let refused =
            judge(elsewhere.as_bytes(), log(), owed, STATION, None).expect_err("another next hop");
        assert!(
            refused.contains("handed this channel's frames to 10.0.2.99"),
            "{refused}"
        );

        let by_gateway = booted()
            + &dialled("10.0.2.2", 4433, 3, "unanswered")
            + &placed().replace("dial-next-hop-via=prefix", "dial-next-hop-via=gateway");
        let refused =
            judge(by_gateway.as_bytes(), log(), owed, STATION, None).expect_err("the other answer");
        assert!(refused.contains("`gateway`"), "{refused}");
    }

    /// A channel that failed and placed nothing is the defect this whole
    /// contract exists for: a token with no evidence beside it is a failure an
    /// operator cannot act on. Each missing record is named as the record it is.
    #[test]
    fn a_failed_channel_that_placed_nothing_is_refused_record_by_record() {
        let owed = DialVerdict {
            outcome: DialOutcome::Unanswered,
            attempts: 3,
            account: Some(PLACED),
        };
        let bare = booted() + &dialled("10.0.2.2", 4433, 3, "unanswered");
        let refused = judge(bare.as_bytes(), log(), owed, STATION, None).expect_err("no evidence");
        assert!(refused.contains("`dial-next-hop=`"), "{refused}");

        // And each of the others in turn, with the ones before it present.
        for key in ["dial-reply-unsolicited", "dial-syns"] {
            let mut capture = booted() + &dialled("10.0.2.2", 4433, 3, "unanswered");
            for line in placed().lines() {
                if !line.contains(key) {
                    capture.push_str(line);
                    capture.push_str("\r\n");
                }
            }
            let refused = judge(capture.as_bytes(), log(), owed, STATION, None)
                .expect_err("a record missing");
            assert!(refused.contains(&format!("`{key}=`")), "{refused}");
        }
    }

    /// A channel that came up owes no counts and must carry none: the records
    /// place a fault, and a healthy boot emitting them would say something
    /// happened that did not.
    #[test]
    fn a_channel_that_came_up_and_placed_a_fault_anyway_is_refused() {
        let capture = booted() + &dialled("10.0.2.2", 4433, 1, "answered") + &placed();
        let refused = judge(capture.as_bytes(), log(), CAME_UP, STATION, None)
            .expect_err("evidence with no fault");
        assert!(
            refused.contains("carries a `dial-next-hop=` record anyway"),
            "{refused}"
        );
    }

    /// The sequence pair is reported only where a station claimed one, and is
    /// held to both numbers where it is.
    #[test]
    fn the_claimed_sequence_pair_is_required_where_one_was_claimed_and_refused_where_none_was() {
        let pair = "LFW-PD domain=management state=ready dial-acknowledged=3735928559 \
                    dial-expected=1\r\n";
        let capture = booted()
            + &dialled("10.0.2.2", 4433, 3, "unacceptable-acknowledgement")
            + &placed()
            + pair;
        let owed = |acknowledged| DialVerdict {
            outcome: DialOutcome::UnacceptableAcknowledgement,
            attempts: 3,
            account: Some(DialAccount {
                acknowledged,
                ..PLACED
            }),
        };
        let station_read = Some((3_735_928_559, 1));
        judge(capture.as_bytes(), log(), owed(true), STATION, station_read)
            .expect("the pair the station claimed");

        // The console is held to what the *station* read, so a console naming
        // some other number is refused however self-consistent it is.
        let refused = judge(capture.as_bytes(), log(), owed(true), STATION, Some((7, 1)))
            .expect_err("another number");
        assert!(
            refused.contains("dial-acknowledged=3735928559"),
            "{refused}"
        );

        // A pair reported where none was claimed is numbers the appliance
        // invented, and is refused as readily as a missing one.
        let refused = judge(capture.as_bytes(), log(), owed(false), STATION, None)
            .expect_err("an unclaimed pair");
        assert!(refused.contains("reports a pair anyway"), "{refused}");

        let without =
            booted() + &dialled("10.0.2.2", 4433, 3, "unacceptable-acknowledgement") + &placed();
        let refused = judge(without.as_bytes(), log(), owed(true), STATION, station_read)
            .expect_err("a pair that was claimed and not reported");
        assert!(refused.contains("`dial-acknowledged=`"), "{refused}");

        // And a station that read nothing off the wire leaves the console with
        // nothing independent to be held to, which is a run proving less than
        // it says rather than a run that passed.
        let refused = judge(capture.as_bytes(), log(), owed(true), STATION, None)
            .expect_err("no independent reading");
        assert!(refused.contains("never read one off the wire"), "{refused}");
    }

    #[test]
    fn an_attempt_count_that_is_no_number_is_reported_rather_than_read_as_zero() {
        let capture = booted() + &dialled("10.0.2.2", 4433, 0, "answered").replace("=0 ", "=many ");
        let verdict =
            judge(capture.as_bytes(), log(), CAME_UP, STATION, None).expect_err("a bad field");
        assert!(verdict.contains("is no number"), "{verdict}");
    }
}
