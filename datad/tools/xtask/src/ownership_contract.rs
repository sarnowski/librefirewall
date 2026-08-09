//! Hold every boot to the ownership it was provisioned with.
//!
//! An appliance no management plane has taken forwards nothing, so whether a
//! boot's medium carries an owner decides what every other contract in the gate
//! may ask of it. That makes the ownership a *precondition* of the run rather
//! than an observation of it — and a precondition nothing checks is a scenario
//! that can quietly come to prove the opposite of what its table says: a boot
//! provisioned owned that came up unowned forwards nothing, and the verdict a
//! reader gets is "the routed contract timed out", which names the symptom and
//! not the cause.
//!
//! So the harness states what it attached and the appliance states what it read,
//! and the two are compared. The appliance's statement is the forwarding domain's
//! own console record — the one an operator reads for exactly this question —
//! rendered here through `lfw_log` rather than written out, so the expectation
//! and the appliance cannot come to spell one fact two ways.
//!
//! # What this is not
//!
//! It is not a reading of the medium. Nothing here opens the store image: the
//! bytes carry the appliance's private scalar, and a harness that decoded them
//! to answer a yes/no question would be a second place that had to be trusted
//! not to print one. The question is answered where an administrator would
//! answer it.

use std::path::Path;

use lfw_log::{Domain, DomainDetail, DomainState, Event, MAX_LINE_LEN, Ownership, Stamp, render};

use crate::console_records::{lifecycle_records, value, without_time};

/// The console line the forwarding domain writes about ownership, less its
/// instant.
///
/// Rendered through the appliance's own renderer for [`crate::config_transcript`]'s
/// reason: a literal written out here would be this harness agreeing with itself
/// about a grammar the appliance owns.
fn line(ownership: Ownership) -> Result<String, String> {
    let event = Event::Domain {
        domain: Domain::Forwarder,
        state: DomainState::Ready,
        detail: DomainDetail::<&'static str>::Ownership(ownership),
    };
    let mut buffer = [0u8; MAX_LINE_LEN];
    let written = render(Stamp::Unsynchronized, &event, &mut buffer)
        .map_err(|_| String::from("the ownership record does not fit one console line"))?;
    let bytes = buffer
        .get(..written)
        .ok_or_else(|| String::from("the ownership record rendered past its own length"))?;
    let rendered = String::from_utf8(bytes.to_vec())
        .map_err(|_| String::from("the ownership record rendered bytes that are not UTF-8"))?;
    Ok(without_time(&rendered))
}

/// Hold one boot's serial capture to the ownership its medium carried.
///
/// The record must be there and must say what the harness provisioned. Both
/// halves matter and they fail differently: an absent record is a forwarding
/// domain that never said whether it may forward at all — which is the one
/// question an operator holding a silent appliance has — and a record saying the
/// other word is a boot whose every other verdict was reached under a premise
/// the table does not hold.
///
/// A boot may say the word twice, and only in one direction: a node adopted
/// while it runs states `unowned` at bring-up and `owned` when it is taken. So
/// what is required is that the **last** record agrees, and that no record
/// walks ownership backwards — an appliance cannot lose an owner except by a
/// factory reset, which takes effect on the boot after the one that asks.
///
/// # Errors
/// The verdict, naming what was provisioned against what the domain said, and
/// where the whole run log is.
pub(crate) fn judge(serial: &[u8], expected: Ownership, log: &Path) -> Result<String, String> {
    let text = String::from_utf8_lossy(serial);
    let said: Vec<Ownership> = lifecycle_records(&text)
        .into_iter()
        .filter(|record| value(record, "domain") == Some(Domain::Forwarder.name()))
        .filter_map(|record| value(record, "ownership").map(String::from))
        .map(|token| {
            Ownership::ALL
                .into_iter()
                .find(|known| known.name() == token)
                .ok_or(token)
        })
        .collect::<Result<Vec<Ownership>, String>>()
        .map_err(|token| {
            format!(
                "the forwarding domain reported ownership as {token:?}, which is outside the \
                 vocabulary this build declares ({:?}). A token the appliance can print and the \
                 gate cannot read is a console an operator cannot read either\n  full run log: {}",
                Ownership::ALL.map(Ownership::name),
                log.display()
            )
        })?;

    let Some(last) = said.last().copied() else {
        return Err(format!(
            "the forwarding domain never said whether this appliance has an owner, and it comes \
             up saying so. A node that forwards nothing because nobody has onboarded it is \
             indistinguishable, from every other surface, from one whose traffic is being lost — \
             the console record is what tells those apart\n  full run log: {}",
            log.display()
        ));
    };
    if last != expected {
        return Err(format!(
            "the harness attached a store medium carrying an appliance that is {}, and the \
             forwarding domain reports {}. Every other verdict this boot reached was reached \
             under the wrong premise: an {} appliance forwards nothing at all, whatever its \
             policy says\n  full run log: {}",
            expected.name(),
            last.name(),
            Ownership::Unowned.name(),
            log.display()
        ));
    }
    if said
        .windows(2)
        .any(|pair| pair == [Ownership::Owned, Ownership::Unowned])
    {
        return Err(format!(
            "the forwarding domain reported {:?} in this boot, so it gave up an owner while \
             running. An appliance loses one only by a factory reset, which is asked for on the \
             medium and takes effect on the next boot — so a domain that walks this backwards is \
             one a peer can switch the whole dataplane off with\n  full run log: {}",
            said.iter().map(|one| one.name()).collect::<Vec<&str>>(),
            log.display()
        ));
    }

    let expectation = line(expected)?;
    Ok(match said.len() {
        1 => format!("the forwarding domain reported `{expectation}`"),
        // The one transition a boot can carry, and worth naming as a transition:
        // it is what the adopting scenario exists to produce.
        _ => format!(
            "the forwarding domain reported `{expectation}` after coming up {}, so the appliance \
             was taken while it ran",
            Ownership::Unowned.name()
        ),
    })
}
