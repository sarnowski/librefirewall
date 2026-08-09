//! The records the appliance owes about one session on its onboarding port.
//!
//! [`crate::dial_contract`]'s pattern on the other of the two ports the
//! management endpoint listens on, and on the other direction of the same wire.
//! There the appliance connects and the harness answers; here the harness
//! connects and the appliance answers. What is judged is the same shape of
//! thing: the harness decided what the station on its end would do, exactly one
//! set of records follows from that, and this is where the appliance's own
//! account is held to it.
//!
//! # Three records, from two domains, and the count is half the contract
//!
//! A session that ends is reported by both domains that carried it — the one
//! that owns the network and the one that terminates the session — and the
//! network end adds the port's own running totals beside its account. So a boot
//! that opened one session carries exactly three records: two accounts of one
//! session and one account of the port.
//!
//! The count is asserted rather than assumed. Two accounts from one domain would
//! be a session reported twice or a second session nobody opened; one would be a
//! domain that carried a session and never said so, which is exactly the state a
//! reader of a deployed node cannot distinguish from a port nothing ever reached.
//!
//! # The two accounts are compared to each other, not only to the expectation
//!
//! The two domains count the same items independently, over an ABI in which
//! neither can see what the other saw: the network end counts an item when its
//! answer arrives, the terminating end when it answers one. Holding the two to
//! **each other** is what catches a relay that lost something — a handover one
//! end made and the other never saw would be invisible in either account read
//! alone, and reads as a relay that carried nothing rather than one that dropped
//! an item.
//!
//! # What is exact and what is a floor
//!
//! A count is asserted **exactly** where a first-party constant or this harness's
//! own wire decides it, and as a **floor** where the machine does.
//!
//! The bytes are exact: this end put a known number of them on the wire in one
//! segment, and what the appliance answers with is nothing at all. The port's
//! totals are exact: one connection accepted, and whether it was forgotten
//! follows from how this station ended it.
//!
//! **The items are a floor, and deliberately.** A session's handover is a run of
//! items over the relay, and the run's length depends on how many passes found
//! nothing waiting: each of those spends a `Poll`, and how many there are is
//! decided by the accelerator, the scheduler and the moment a frame arrived
//! rather than by anything either end chose. The floor is the run every session
//! must contain whatever the machine does — the open, the delivery of the one
//! payload, and the close — and asserting the exact number instead would be a
//! gate that passes on one machine and fails on the next.
//!
//! # No adversary
//!
//! As [`crate::console_records`]: this reads the appliance's own output on a
//! channel only the harness is attached to.

use std::path::Path;

use lfw_log::{Domain, DomainState, OnboardEnd, OnboardOutcome};

use crate::console_records::{LIFECYCLE_PREFIX, field, lifecycle_records, value};
use crate::dial_contract::Count;
use crate::forward_harness::OnboardAccount;

/// The fields of a session's own account, on both domains' records.
const RELAYED: &str = "onboard-relayed";
const RECEIVED: &str = "onboard-received";
const SENT: &str = "onboard-sent";
const ENDED: &str = "onboard-ended";

/// The field the terminating domain leads its account of the handshake with.
const HANDSHAKE: &str = "onboard-tls";

/// What that field must say on every one of these boots.
///
/// The station delivers the opening of a TLS record and never the rest of it,
/// so the server holds those bytes and decides nothing about them — and what
/// ends the session is the transport going away under it, however this
/// station chose to take it away. A close, a reset and a session ended beside a
/// crowded port all reach the peer having gone, which is what this token names.
///
/// Asserted here rather than left to the handshake boot, and this is the point
/// of asserting it at all: these three boots decide how a session *ends*, and a
/// server that reported an ending of its own — a record it refused, an arena it
/// ran out of — would still satisfy every count below.
const OWED_OUTCOME: OnboardOutcome = OnboardOutcome::PeerClosed;

/// The fields of the port's own totals, which the network end alone reports.
const ACCEPTED: &str = "onboard-accepted";
const FORGOTTEN: &str = "onboard-forgotten";
const OVERFLOWED: &str = "onboard-overflowed";
const REFUSED: &str = "onboard-refused";

/// The fewest items one session of this shape can carry.
///
/// The run every session contains whatever the machine does: the open that
/// begins it, the delivery of the one payload it carries, and the close that
/// ends it. Everything above this number is a pass that found nothing waiting
/// and spent a `Poll` on saying so, which is the machine's decision rather than
/// either end's — see the header on why that makes this a floor.
const ITEMS_PER_SESSION: u64 = 3;

/// What the appliance must say about the session, given what the station on the
/// other end of it did.
///
/// The bytes are not here: they are what this harness put on the wire, supplied
/// by the run itself, and a contract that took them from a field of its own
/// could not catch a port reporting a length nothing sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OnboardVerdict {
    /// Which end both domains must name as having finished the session.
    pub ended: OnboardEnd,
    /// Connections the transport stopped holding mid-session. Exact: it follows
    /// from how this station ended its one connection and from nothing else.
    pub forgotten: Count,
}

/// Whether the appliance has reported the session and said what the port has
/// done.
///
/// The observable a boot that opens a session waits on. Such a boot's own
/// connection is finished before the appliance's account of it exists — the pass
/// that closes the account runs after the connection is gone — so what says the
/// port has finished is the port's own records, which are an event rather than a
/// duration.
///
/// All three, because all three are judged: a run that stopped on the first
/// would kill QEMU with the rest still in the log ring, and report a domain that
/// was about to speak as one that never did.
pub(crate) fn reported(serial: &[u8]) -> bool {
    let text = String::from_utf8_lossy(serial);
    !sessions(&text, Domain::Management).is_empty()
        && !sessions(&text, Domain::Crypto).is_empty()
        && !port_records(&text).is_empty()
}

/// Judge the records one boot's session left on the console against what the
/// station that drove it did.
///
/// # Errors
/// The verdict, naming the field and the two values, and where the whole run log
/// is.
pub(crate) fn judge(
    serial: &[u8],
    log: &Path,
    owed: OnboardVerdict,
    observed: OnboardAccount,
) -> Result<String, String> {
    let text = String::from_utf8_lossy(serial);
    let network = one_session(&text, Domain::Management, log)?;
    let terminating = one_session(&text, Domain::Crypto, log)?;

    let bytes = observed.delivered;
    for (domain, record) in [(Domain::Management, network), (Domain::Crypto, terminating)] {
        let ended = read(record, ENDED, log)?;
        if ended != owed.ended.name() {
            return Err(format!(
                "the {} domain reports the onboarding session ended by `{ended}` and this \
                 station ended it as `{}`: {record:?}. The two are different things for an \
                 operator to go and look at — a peer that hung up, this appliance's own decision, \
                 and a connection that stopped existing while neither end said anything\n  full \
                 run log: {}",
                domain.name(),
                owed.ended.name(),
                log.display()
            ));
        }
        // Exact, and this is what makes the record an account rather than a
        // flag: the station put these bytes on the wire itself, in one segment,
        // so a number short of them is bytes that reached the port and never
        // crossed the relay.
        let received = number(record, RECEIVED, log)?;
        if received != bytes {
            return Err(format!(
                "the {} domain reports {received} byte(s) received for the session and this \
                 station delivered {bytes} in one segment: {record:?}\n  full run log: {}",
                domain.name(),
                log.display()
            ));
        }
        // Exact for the other reason: what this station delivers is the opening
        // of a TLS record and never the whole of one, so the server behind the
        // relay holds it and answers nothing at all — and both ends report that
        // as a fact rather than as a placeholder. The station holds the same
        // claim on the wire, refusing a single byte back on the connection.
        let sent = number(record, SENT, log)?;
        if sent != 0 {
            return Err(format!(
                "the {} domain reports {sent} byte(s) sent back on the session and the domain \
                 that terminates one answers with nothing: {record:?}\n  full run log: {}",
                domain.name(),
                log.display()
            ));
        }
        let relayed = number(record, RELAYED, log)?;
        let floor = Count::AtLeast(ITEMS_PER_SESSION);
        if !floor.holds(relayed) {
            return Err(format!(
                "the {} domain reports {relayed} item(s) relayed for the session and one of this \
                 shape carries {} — the open that begins it, the delivery of its one payload, and \
                 the close that ends it. It is a floor and not an equality because every pass \
                 that finds nothing waiting spends an item saying so, and how many of those there \
                 are is the machine's decision: {record:?}\n  full run log: {}",
                domain.name(),
                floor.stated(),
                log.display()
            ));
        }
    }

    // And the two accounts against each other, which no expectation could state:
    // the two domains count the same items over an ABI neither can see the other
    // through, so a handover one made and the other never saw is invisible in
    // either account read alone.
    let near = number(network, RELAYED, log)?;
    let far = number(terminating, RELAYED, log)?;
    if near != far {
        return Err(format!(
            "the two domains report {near} and {far} item(s) for one session. Each counts an item \
             the other answered, so a difference is a handover one end made and the other never \
             saw — a relay that lost something, which reads in either account alone as a session \
             that simply carried less\n  network end: {network:?}\n  terminating end: \
             {terminating:?}\n  full run log: {}",
            log.display()
        ));
    }

    // What the server behind the relay made of the session, which no count
    // above can state: every one of these boots hands it half a record and
    // takes the transport away, so the one outcome it may report is the peer
    // having gone.
    let handshake = one_handshake(&text, log)?;
    let outcome = read(handshake, HANDSHAKE, log)?;
    if outcome != OWED_OUTCOME.name() {
        return Err(format!(
            "the cryptography domain reports the handshake ended `{outcome}` and this station \
             took the transport away under one that had decided nothing, which is `{}`: \
             {handshake:?}. Each of the ten is a different thing for an administrator to go and \
             change\n  full run log: {}",
            OWED_OUTCOME.name(),
            log.display()
        ));
    }

    let port = one_port_record(&text, log)?;
    // One connection accepted, and exactly one. A number above it is a
    // connection that reached the port and produced no session record — which is
    // the whole of what the crowding station must NOT provoke — and one below is
    // a session reported for a connection the port never took.
    let accepted = number(port, ACCEPTED, log)?;
    if accepted != 1 {
        return Err(format!(
            "the port reports {accepted} connection(s) accepted and this station opened one \
             session on it: {port:?}. More than one is a connection that became no session — the \
             second this port holds no slot for — and fewer is a session reported for a \
             connection nothing took\n  full run log: {}",
            log.display()
        ));
    }
    let forgotten = number(port, FORGOTTEN, log)?;
    if !owed.forgotten.holds(forgotten) {
        return Err(format!(
            "the port reports {forgotten} connection(s) forgotten and this station's own ending \
             obliges {}: {port:?}. A connection the transport stopped holding while a session ran \
             on it is neither end having said the session was over\n  full run log: {}",
            owed.forgotten.stated(),
            log.display()
        ));
    }
    // Both zero, and both for reasons this station holds on the wire: it keeps
    // inside the window it was given, and the appliance answers with nothing at
    // all — so a number in either is the port refusing bytes nobody's behaviour
    // here can explain.
    for (key, why) in [
        (
            OVERFLOWED,
            "bytes a peer sent past the room the port had left, which is unreachable while the \
             advertised window is honoured — and this station sent one segment far inside it",
        ),
        (
            REFUSED,
            "bytes the terminating domain answered with that there was no room for, and that \
             domain answers with nothing",
        ),
    ] {
        let count = number(port, key, log)?;
        if count != 0 {
            return Err(format!(
                "the port reports {count} for `{key}=`, and it counts {why}: {port:?}\n  full run \
                 log: {}",
                log.display()
            ));
        }
    }

    // The wire's own half, which no console record can state: what the appliance
    // did *not* answer.
    //
    // The absence is only evidence if the thing it is an absence of was
    // attempted, so the station that crowds is required to have crowded. A boot
    // whose second `SYN` never went out would satisfy every check below
    // vacuously and read as a port that refused a connection nobody opened.
    if observed.behaviour.crowds() && !observed.crowded {
        return Err(format!(
            "this station's whole subject is a second connection opened while the first is \
             established, and it never put that SYN on the wire — so the absence of an answer to \
             it is an absence of nothing\n  full run log: {}",
            log.display()
        ));
    }
    if observed.crowd_answers != 0 {
        return Err(format!(
            "the appliance answered the second connection {} time(s). This port holds one \
             connection and an established one is not evictable, so a second SYN finds no slot \
             and nothing to take one from — the transport drops it in silence\n  full run log: {}",
            observed.crowd_answers,
            log.display()
        ));
    }

    Ok(format!(
        "one onboarding session of {bytes} byte(s) ended `{}`, reported by both domains with \
         {near} item(s) each, beside a port that accepted {accepted} connection(s) and forgot \
         {forgotten}{}",
        owed.ended.name(),
        if observed.crowded {
            ", the second connection drawing no answer at all"
        } else {
            ""
        }
    ))
}

/// The session accounts one domain wrote: its `ready` records carrying
/// `onboard-ended=`.
fn sessions(text: &str, domain: Domain) -> Vec<&str> {
    ours(text, domain)
        .into_iter()
        .filter(|record| value(record, ENDED).is_some())
        .collect()
}

/// The terminating domain's account of the handshake: its `ready` record
/// carrying `onboard-tls=`.
fn handshakes(text: &str) -> Vec<&str> {
    ours(text, Domain::Crypto)
        .into_iter()
        .filter(|record| value(record, HANDSHAKE).is_some())
        .collect()
}

/// The port's own totals: the network end's `ready` records carrying
/// `onboard-accepted=`.
fn port_records(text: &str) -> Vec<&str> {
    ours(text, Domain::Management)
        .into_iter()
        .filter(|record| value(record, ACCEPTED).is_some())
        .collect()
}

/// One domain's `ready` lifecycle records.
fn ours(text: &str, domain: Domain) -> Vec<&str> {
    let ready = field("state", DomainState::Ready.name());
    lifecycle_records(text)
        .into_iter()
        .filter(|record| {
            record.contains(&field("domain", domain.name())) && record.contains(&ready)
        })
        .collect()
}

fn one_session<'a>(text: &'a str, domain: Domain, log: &Path) -> Result<&'a str, String> {
    let found = sessions(text, domain);
    let [record] = found[..] else {
        return Err(format!(
            "the console carried {} `{}` record(s) for the {} domain accounting for an onboarding \
             session, and a boot that opens one produces exactly one. None means the domain \
             carried a session and never said so — which a reader of a deployed node cannot tell \
             from a port nothing ever reached — and several mean a session reported twice or a \
             second nobody opened\n  records observed: {found:#?}\n  full run log: {}",
            found.len(),
            LIFECYCLE_PREFIX.trim_end(),
            domain.name(),
            log.display()
        ));
    };
    Ok(record)
}

fn one_handshake<'a>(text: &'a str, log: &Path) -> Result<&'a str, String> {
    let found = handshakes(text);
    let [record] = found[..] else {
        return Err(format!(
            "the console carried {} `{}` record(s) for the cryptography domain accounting for the \
             handshake, and a boot that opens one session produces exactly one. None means a \
             session was carried and how it ended reached no surface, which is the one thing an \
             administrator whose client will not connect has to read\n  records observed: \
             {found:#?}\n  full run log: {}",
            found.len(),
            LIFECYCLE_PREFIX.trim_end(),
            log.display()
        ));
    };
    Ok(record)
}

fn one_port_record<'a>(text: &'a str, log: &Path) -> Result<&'a str, String> {
    let found = port_records(text);
    let [record] = found[..] else {
        return Err(format!(
            "the console carried {} `{}` record(s) for the management domain stating the \
             onboarding port's own totals, and one goes out beside every session account. The \
             account states what a session carried and cannot explain it, so a boot with the one \
             and not the other leaves a fault placeable in neither\n  records observed: \
             {found:#?}\n  full run log: {}",
            found.len(),
            LIFECYCLE_PREFIX.trim_end(),
            log.display()
        ));
    };
    Ok(record)
}

/// The value of `key` in `record`, or a verdict naming the field the record is
/// specified to carry and does not.
fn read<'a>(record: &'a str, key: &str, log: &Path) -> Result<&'a str, String> {
    value(record, key).ok_or_else(|| {
        format!(
            "{record:?} carries no `{key}=` field, and this record is specified with one\n  full \
             run log: {}",
            log.display()
        )
    })
}

fn number(record: &str, key: &str, log: &Path) -> Result<u64, String> {
    read(record, key, log)?
        .parse()
        .map_err(|error| format!("{record:?}: {key} is no number: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward_harness::OnboardBehaviour;

    fn log() -> &'static Path {
        Path::new("/nonexistent/qemu.log")
    }

    const NETWORK: &str = "LFW-PD time=2026-08-07T00:00:00Z domain=management state=ready \
                           onboard-relayed=4 onboard-received=19 onboard-sent=0 \
                           onboard-ended=peer";
    const PORT: &str = "LFW-PD time=2026-08-07T00:00:00Z domain=management state=ready \
                        onboard-accepted=1 onboard-forgotten=0 onboard-overflowed=0 \
                        onboard-refused=0";
    const TERMINATING: &str = "LFW-PD time=2026-08-07T00:00:00Z domain=crypto state=ready \
                               onboard-relayed=4 onboard-received=19 onboard-sent=0 \
                               onboard-ended=peer";
    const HANDSHAKE_RECORD: &str =
        "LFW-PD time=2026-08-07T00:00:00Z domain=crypto state=ready onboard-tls=peer-closed";

    /// A capture of the shape a passing boot leaves: the three records, among
    /// the other domains' lifecycle lines.
    fn capture(records: &[&str]) -> String {
        let mut text = String::from(
            "LFW-PD domain=management state=ready\r\nLFW-PD domain=clock state=ready tsc-hz=1\r\n",
        );
        for record in records {
            text.push_str(record);
            text.push_str("\r\n");
        }
        text
    }

    fn completed() -> OnboardVerdict {
        OnboardVerdict {
            ended: OnboardEnd::Peer,
            forgotten: Count::Exactly(0),
        }
    }

    fn account(behaviour: OnboardBehaviour) -> OnboardAccount {
        OnboardAccount {
            behaviour,
            delivered: 19,
            crowded: matches!(behaviour, OnboardBehaviour::Crowds),
            crowd_answers: 0,
            segments: 3,
        }
    }

    #[test]
    fn a_session_both_domains_agree_on_is_accepted() {
        let proved = judge(
            capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD]).as_bytes(),
            log(),
            completed(),
            account(OnboardBehaviour::Completes),
        )
        .expect("a well-formed session");
        assert!(proved.contains("19 byte(s)"), "{proved}");
        assert!(proved.contains("`peer`"), "{proved}");
    }

    #[test]
    fn the_records_are_what_the_run_waits_on() {
        assert!(reported(
            capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD]).as_bytes()
        ));
        // Each of the three on its own is a boot that has not finished
        // reporting, and a capture cut before any of them is not one to judge.
        for partial in [
            capture(&[]),
            capture(&[NETWORK]),
            capture(&[NETWORK, PORT]),
            capture(&[NETWORK, TERMINATING, HANDSHAKE_RECORD]),
        ] {
            assert!(!reported(partial.as_bytes()), "{partial}");
        }
    }

    #[test]
    fn a_session_one_domain_never_reported_is_refused_by_the_domain_that_is_silent() {
        for (records, domain) in [
            (vec![PORT, TERMINATING, HANDSHAKE_RECORD], "management"),
            (vec![NETWORK, PORT, HANDSHAKE_RECORD], "crypto"),
        ] {
            let verdict = judge(
                capture(&records).as_bytes(),
                log(),
                completed(),
                account(OnboardBehaviour::Completes),
            )
            .expect_err("a domain that said nothing");
            assert!(verdict.contains("carried 0"), "{verdict}");
            assert!(verdict.contains(domain), "{verdict}");
        }
    }

    #[test]
    fn a_session_reported_twice_by_one_domain_is_refused() {
        let verdict = judge(
            capture(&[NETWORK, NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD]).as_bytes(),
            log(),
            completed(),
            account(OnboardBehaviour::Completes),
        )
        .expect_err("a doubled account");
        assert!(verdict.contains("carried 2"), "{verdict}");
    }

    #[test]
    fn a_port_record_missing_beside_an_account_is_refused() {
        let verdict = judge(
            capture(&[NETWORK, TERMINATING, HANDSHAKE_RECORD]).as_bytes(),
            log(),
            completed(),
            account(OnboardBehaviour::Completes),
        )
        .expect_err("no port totals");
        assert!(verdict.contains("own totals"), "{verdict}");
    }

    #[test]
    fn an_ending_neither_this_station_produced_is_refused_by_both_tokens() {
        for record in [NETWORK, TERMINATING] {
            let text = capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD]).replace(
                record,
                &record.replace("onboard-ended=peer", "onboard-ended=forgotten"),
            );
            let verdict = judge(
                text.as_bytes(),
                log(),
                completed(),
                account(OnboardBehaviour::Completes),
            )
            .expect_err("the wrong ending");
            assert!(verdict.contains("`forgotten`"), "{verdict}");
            assert!(verdict.contains("`peer`"), "{verdict}");
        }
    }

    /// The station that resets rather than closing: both ends must say the
    /// transport forgot the connection, and the port must have counted one.
    #[test]
    fn an_abandoned_session_is_judged_by_the_ending_and_the_port_that_lost_the_connection() {
        let abandoned = OnboardVerdict {
            ended: OnboardEnd::Forgotten,
            forgotten: Count::Exactly(1),
        };
        let text = capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD])
            .replace("onboard-ended=peer", "onboard-ended=forgotten")
            .replace("onboard-forgotten=0", "onboard-forgotten=1");
        judge(
            text.as_bytes(),
            log(),
            abandoned,
            account(OnboardBehaviour::Abandons),
        )
        .expect("a session the transport forgot");

        // And a port that lost nothing under a station that reset is the
        // connection having been given up some other way.
        let kept = capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD])
            .replace("onboard-ended=peer", "onboard-ended=forgotten");
        let verdict = judge(
            kept.as_bytes(),
            log(),
            abandoned,
            account(OnboardBehaviour::Abandons),
        )
        .expect_err("a connection nothing forgot");
        assert!(verdict.contains("forgotten"), "{verdict}");
    }

    #[test]
    fn a_byte_count_short_of_what_the_station_delivered_is_refused() {
        let text = capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD])
            .replace("onboard-received=19", "onboard-received=11");
        let verdict = judge(
            text.as_bytes(),
            log(),
            completed(),
            account(OnboardBehaviour::Completes),
        )
        .expect_err("a short account");
        assert!(verdict.contains("11 byte(s) received"), "{verdict}");
        assert!(verdict.contains("delivered 19"), "{verdict}");
    }

    #[test]
    fn a_byte_answered_back_is_refused_though_nothing_answers_yet() {
        let text = capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD])
            .replace("onboard-sent=0", "onboard-sent=5");
        let verdict = judge(
            text.as_bytes(),
            log(),
            completed(),
            account(OnboardBehaviour::Completes),
        )
        .expect_err("bytes nothing composed");
        assert!(verdict.contains("5 byte(s) sent"), "{verdict}");
    }

    /// The floor holds at its own value and refuses below it, and every number
    /// above it is a pass that found nothing waiting.
    #[test]
    fn the_item_count_is_a_floor_rather_than_an_equality() {
        for relayed in ["3", "4", "97"] {
            let text = capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD])
                .replace("onboard-relayed=4", &format!("onboard-relayed={relayed}"));
            judge(
                text.as_bytes(),
                log(),
                completed(),
                account(OnboardBehaviour::Completes),
            )
            .unwrap_or_else(|verdict| panic!("{relayed} items: {verdict}"));
        }
        for relayed in ["0", "2"] {
            let text = capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD])
                .replace("onboard-relayed=4", &format!("onboard-relayed={relayed}"));
            let verdict = judge(
                text.as_bytes(),
                log(),
                completed(),
                account(OnboardBehaviour::Completes),
            )
            .expect_err("a session shorter than its own open, delivery and close");
            assert!(verdict.contains("at least 3"), "{verdict}");
        }
    }

    /// The comparison no expectation makes: two ends of one relay that disagree
    /// about how many items crossed.
    #[test]
    fn two_domains_that_counted_different_item_runs_are_refused() {
        let text = capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD]).replace(
            "domain=crypto state=ready onboard-relayed=4",
            "domain=crypto state=ready onboard-relayed=5",
        );
        let verdict = judge(
            text.as_bytes(),
            log(),
            completed(),
            account(OnboardBehaviour::Completes),
        )
        .expect_err("two accounts of one session");
        assert!(verdict.contains("lost something"), "{verdict}");
    }

    #[test]
    fn a_second_accepted_connection_is_refused_as_one_that_became_no_session() {
        let text = capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD])
            .replace("onboard-accepted=1", "onboard-accepted=2");
        let verdict = judge(
            text.as_bytes(),
            log(),
            completed(),
            account(OnboardBehaviour::Crowds),
        )
        .expect_err("a connection that became no session");
        assert!(verdict.contains("2 connection(s) accepted"), "{verdict}");
    }

    #[test]
    fn a_port_that_overflowed_or_refused_a_byte_is_refused_by_the_field_it_counted() {
        for (from, to, named) in [
            ("onboard-overflowed=0", "onboard-overflowed=7", "overflowed"),
            ("onboard-refused=0", "onboard-refused=7", "refused"),
        ] {
            let text = capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD]).replace(from, to);
            let verdict = judge(
                text.as_bytes(),
                log(),
                completed(),
                account(OnboardBehaviour::Completes),
            )
            .expect_err("a port that refused bytes");
            assert!(verdict.contains(named), "{verdict}");
        }
    }

    /// The wire's own half: a console that reads perfectly beside a port that
    /// answered a `SYN` it holds no slot for is still a failure, and the console
    /// could never say so.
    #[test]
    fn an_answer_to_the_second_connection_is_refused_though_the_console_reads_clean() {
        let mut observed = account(OnboardBehaviour::Crowds);
        observed.crowd_answers = 1;
        let verdict = judge(
            capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD]).as_bytes(),
            log(),
            completed(),
            observed,
        )
        .expect_err("an answer to the crowding SYN");
        assert!(verdict.contains("second connection 1 time(s)"), "{verdict}");
    }

    /// And the absence is only evidence of something if it was attempted: a
    /// crowding boot whose second `SYN` never went out would satisfy every other
    /// check vacuously.
    #[test]
    fn a_crowding_station_that_never_opened_its_second_connection_proves_nothing() {
        let mut observed = account(OnboardBehaviour::Crowds);
        observed.crowded = false;
        let verdict = judge(
            capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD]).as_bytes(),
            log(),
            completed(),
            observed,
        )
        .expect_err("a second connection nothing opened");
        assert!(verdict.contains("absence of nothing"), "{verdict}");
    }

    #[test]
    fn a_record_missing_a_field_is_refused_by_the_field_it_is_missing() {
        for (from, missing) in [
            (" onboard-received=19", "onboard-received"),
            (" onboard-sent=0", "onboard-sent"),
            (" onboard-relayed=4", "onboard-relayed"),
        ] {
            let text = capture(&[NETWORK, PORT, TERMINATING, HANDSHAKE_RECORD]).replace(from, "");
            let verdict = judge(
                text.as_bytes(),
                log(),
                completed(),
                account(OnboardBehaviour::Completes),
            )
            .expect_err("a partial record");
            assert!(verdict.contains(&format!("`{missing}=`")), "{verdict}");
        }
    }

    #[test]
    fn another_domains_record_is_never_read_as_a_session_account() {
        // The channel carries every domain's lifecycle, and `domain=` is the
        // only thing separating them.
        let text = capture(&[
            &NETWORK.replace("domain=management", "domain=recorder"),
            PORT,
            TERMINATING,
            HANDSHAKE_RECORD,
        ]);
        let verdict = judge(
            text.as_bytes(),
            log(),
            completed(),
            account(OnboardBehaviour::Completes),
        )
        .expect_err("no account from the domain that owns the port");
        assert!(verdict.contains("carried 0"), "{verdict}");
    }
}
