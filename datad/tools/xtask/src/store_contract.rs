//! The identity records one boot must produce on the `LFW-PD` console channel,
//! and the one claim only two boots can make: that the same appliance came back.
//!
//! This is [`crate::clock_contract`]'s pattern applied to the store domain, with
//! one difference that changes what a contract can be. A clock's record is a
//! measurement, so the most that can be asserted about it is a band. An
//! identity's record is a *value that must not change*, and the value is not
//! known to the build — it is 128 bits the appliance drew for itself. So the
//! assertion is not against a constant but against **another boot of the same
//! medium**, which is the only place the claim exists at all.
//!
//! # What one boot proves, and what it cannot
//!
//! One boot proves shape: exactly one identity record, exactly one fingerprint
//! record, a device identifier that is 32 lowercase hexadecimal characters and a
//! fingerprint that is 64 — the certificate profile's renderings, byte for byte,
//! because the management server validates against the same page and an
//! administrator compares two renderings character for character. A second
//! rendering is a defect there, so it is a failure here.
//!
//! What one boot cannot prove is persistence. A domain that minted a fresh
//! identity on every boot would satisfy every assertion above, and it is exactly
//! the defect this whole domain exists to prevent. So the pair
//! ([`hold_to_source`]) is where the contract lives: the second boot of one
//! medium must report the *same* identifier and the *same* fingerprint, under a
//! generation that did not go backwards.
//!
//! A **factory reset** is the same claim inverted ([`hold_reset_to_source`]): the
//! boot that honoured one must report a *different* identifier and a *different*
//! fingerprint, unowned and at the generation a mint starts from, and must say on
//! the console what it destroyed. Reversed rather than relaxed, because "the
//! identity changed" is exactly what a reset owes and exactly what a reload must
//! never do, and one function accepting both would accept a domain that confused
//! them.
//!
//! # No adversary
//!
//! The capture is the appliance's own output on a wire only the harness is
//! attached to, so no threat-model adversary is named for this path; what it
//! defends against is an appliance that forgot who it was. **Nothing here reads
//! the medium**, deliberately: it carries the private scalar in plaintext, and a
//! harness that parsed it would be a second place that had to be trusted never
//! to print one. The one thing about a reset that no console record can settle —
//! whether the key is really gone from the bytes — is proved where the medium is
//! already open, by `crate::data_disk::StoreDisk::judge_secret_erased`.

use std::path::Path;

use lfw_log::{Domain, DomainState};
use lfw_x509::{DEVICE_ID_LEN, FINGERPRINT_LEN};

use crate::console_records::{LIFECYCLE_PREFIX, field, lifecycle_records, value as field_value};

/// The identity one boot reported, as the console rendered it.
///
/// The strings are the rendered forms rather than parsed numbers, and that is the
/// point: what an administrator compares is the rendering, so what the gate
/// compares is the rendering. A parse-then-compare would pass on two boots that
/// printed one value two ways.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    /// 32 lowercase hexadecimal characters.
    pub device: String,
    /// 64 lowercase hexadecimal characters.
    pub fingerprint: String,
    pub generation: u64,
    pub onboarded: bool,
    /// What this boot reported destroying, where it honoured a factory-reset
    /// request. `None` on every ordinary boot, which is what makes an unasked-for
    /// reset a finding rather than a variation.
    pub reset: Option<Reset>,
}

/// What one boot said a factory reset destroyed.
///
/// Numbers about the appliance that is gone, and nothing about the one that
/// replaced it: the identity records beside this one are where that is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reset {
    pub generation: u64,
    pub documents: u64,
    pub was_owned: bool,
}

impl Identity {
    /// This identity as one line of a run summary.
    pub(crate) fn summary(&self) -> String {
        let reset = match self.reset {
            Some(reset) => format!(
                ", after a factory reset that cleared generation {} with {} document(s) from an {} \
                 appliance",
                reset.generation,
                reset.documents,
                if reset.was_owned { "owned" } else { "unowned" }
            ),
            None => String::new(),
        };
        format!(
            "device {} at generation {} ({}), key fingerprint {}{reset}",
            self.device,
            self.generation,
            if self.onboarded { "owned" } else { "unowned" },
            self.fingerprint
        )
    }
}

/// Whether the store domain has said everything it is going to say.
///
/// The fingerprint record is the LAST one the domain emits on a boot that
/// established an identity, and a ring is drained in the order it was written, so
/// its presence means the identity record ahead of it is already in the capture.
/// A refusal ends the boot too — a domain that refused is a refusal to report
/// rather than a boot that failed to complete, exactly as the cryptography
/// domain's contract has it.
///
/// **A partially transmitted fingerprint is not the record**, and that is not a
/// nicety: this answer is what ends the boot, so a `true` on the first hexadecimal
/// character the console put on the wire would kill the guest mid-line and leave
/// the capture holding a truncated field the judge then reports as a rendering
/// defect. The value is fixed-width by the certificate profile, so its full width
/// is exactly the "this record is whole" test — and the width comes from
/// `lfw_x509` rather than from a number here, so the two cannot part.
pub(crate) fn finished(capture: &[u8]) -> bool {
    let text = String::from_utf8_lossy(capture);
    let ours = field("domain", Domain::Store.name());
    let refused = field("state", DomainState::Refused.name());
    lifecycle_records(&text).into_iter().any(|record| {
        record.contains(&ours)
            && (record.contains(&refused)
                || field_value(record, "fingerprint")
                    .is_some_and(|text| text.len() >= FINGERPRINT_LEN))
    })
}

/// Judge the store domain's records in one boot's serial capture.
///
/// # Errors
/// The verdict, naming what the channel carried against what the appliance owes
/// it, and where the whole run log is.
pub(crate) fn judge(serial: &[u8], log: &Path) -> Result<Identity, String> {
    let text = String::from_utf8_lossy(serial);
    let ours: Vec<&str> = lifecycle_records(&text)
        .into_iter()
        .filter(|record| record.contains(&field("domain", Domain::Store.name())))
        .collect();

    let refused = field("state", DomainState::Refused.name());
    if let Some(record) = ours.iter().find(|record| record.contains(&refused)) {
        return Err(format!(
            "the store domain refused to establish an identity: {record:?}. The cause token names \
             which step refused — `staging-` or `store-medium-` the device and its grant, \
             `state-` a transfer of the record, `stored-` a record the medium carried that this \
             build will not act on, `rdrand-` or `generator-` the randomness a key would descend \
             from, and the rest the identity holding to itself.\n  full run log: {}",
            log.display()
        ));
    }

    let identities: Vec<&&str> = ours
        .iter()
        .filter(|record| field_value(record, "device").is_some())
        .collect();
    let [identity] = identities[..] else {
        return Err(format!(
            "the console carried {} `{}` record(s) naming a device for the store domain, and a \
             boot produces exactly one: this domain establishes an identity once in `init` and \
             then parks, so none means it never published and several mean it established more \
             than one identity in a boot\n  store records observed: {ours:#?}\n  \
             full run log: {}",
            identities.len(),
            LIFECYCLE_PREFIX.trim_end(),
            log.display()
        ));
    };

    let fingerprints: Vec<&&str> = ours
        .iter()
        .filter(|record| field_value(record, "fingerprint").is_some())
        .collect();
    let [fingerprint_record] = fingerprints[..] else {
        return Err(format!(
            "the console carried {} record(s) naming a fingerprint for the store domain, and a \
             boot produces exactly one. It is the only place an administrator learns the key this \
             appliance authenticates with — the node has no shell and no CLI — so none is an \
             appliance nobody can onboard\n  store records observed: {ours:#?}\n  \
             full run log: {}",
            fingerprints.len(),
            log.display()
        ));
    };

    let device = rendering(identity, "device", DEVICE_ID_LEN, log)?;
    let fingerprint = rendering(fingerprint_record, "fingerprint", FINGERPRINT_LEN, log)?;
    let generation: u64 = value(identity, "generation", log)?
        .parse()
        .map_err(|error| format!("{identity:?}: generation is no number: {error}"))?;
    if generation == 0 {
        return Err(format!(
            "{identity:?} reports generation 0, and a minted state starts at 1 — zero is what a \
             zeroed medium reads as, so the number on the line is not a generation this appliance \
             committed\n  full run log: {}",
            log.display()
        ));
    }
    let onboarded = match value(identity, "onboarded", log)? {
        "true" => true,
        "false" => false,
        other => {
            return Err(format!(
                "{identity:?} reports onboarded={other:?}, and the field is a boolean\n  \
                 full run log: {}",
                log.display()
            ));
        }
    };

    Ok(Identity {
        device,
        fingerprint,
        generation,
        onboarded,
        reset: reset(&ours, log)?,
    })
}

/// The one record a boot that honoured a factory reset emits, or `None` on a boot
/// that honoured none.
///
/// Several is a finding rather than a first-wins: a reset happens once, because
/// the request is cleared before anything is destroyed, so two records mean the
/// domain honoured a request it had already answered.
fn reset(ours: &[&str], log: &Path) -> Result<Option<Reset>, String> {
    let records: Vec<&&str> = ours
        .iter()
        .filter(|record| field_value(record, "cleared-generation").is_some())
        .collect();
    let record = match records[..] {
        [] => return Ok(None),
        [record] => record,
        _ => {
            return Err(format!(
                "the console carried {} record(s) naming a factory reset for the store domain, and \
                 a boot honours at most one: the request is cleared before anything is destroyed, \
                 so a second record is a request answered twice\n  store records observed: \
                 {ours:#?}\n  full run log: {}",
                records.len(),
                log.display()
            ));
        }
    };
    let number = |key: &str| -> Result<u64, String> {
        value(record, key, log)?
            .parse()
            .map_err(|error| format!("{record:?}: {key} is no number: {error}"))
    };
    let was_owned = match value(record, "was-owned", log)? {
        "true" => true,
        "false" => false,
        other => {
            return Err(format!(
                "{record:?} reports was-owned={other:?}, and the field is a boolean\n  \
                 full run log: {}",
                log.display()
            ));
        }
    };
    Ok(Some(Reset {
        generation: number("cleared-generation")?,
        documents: number("cleared-documents")?,
        was_owned,
    }))
}

/// The value of `key` in `record`, or a verdict naming the field the record is
/// specified to carry and does not.
fn value<'a>(record: &'a str, key: &str, log: &Path) -> Result<&'a str, String> {
    field_value(record, key).ok_or_else(|| {
        format!(
            "{record:?} carries no `{key}=` field, and the store domain's identity record is \
             specified with one\n  full run log: {}",
            log.display()
        )
    })
}

/// One rendered field, held to the certificate profile's own width and alphabet.
///
/// The width comes from `lfw_x509` rather than from a number here, so the profile
/// and this check are one fact: a rendering that changed width there fails here
/// rather than being compared against a stale constant.
fn rendering(record: &str, key: &str, width: usize, log: &Path) -> Result<String, String> {
    let text = value(record, key, log)?;
    if text.len() != width {
        return Err(format!(
            "{record:?} renders `{key}=` as {} character(s) and the certificate profile defines \
             {width}. An administrator compares two renderings of this value character for \
             character, so a second width is a defect rather than a formatting choice\n  \
             full run log: {}",
            text.len(),
            log.display()
        ));
    }
    if !text
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!(
            "{record:?} renders `{key}=` outside lowercase hexadecimal, and the profile defines \
             one rendering: lowercase, no separators\n  full run log: {}",
            log.display()
        ));
    }
    Ok(text.to_owned())
}

/// Hold the identity a carried medium's second boot reported to the one its first
/// boot minted.
///
/// This is the whole contract, and neither boot can make it alone: the first
/// proves an identity was minted and the second proves it is the *same* one. A
/// domain that minted afresh on every boot passes every single-boot assertion in
/// this module and fails here.
///
/// # Errors
/// A different identifier, a different fingerprint, or a generation that went
/// backwards — each naming both boots and both values.
pub(crate) fn hold_to_source(
    source: (&str, &Identity),
    reloaded: (&str, &Identity),
) -> Result<String, String> {
    let (minted_name, minted) = source;
    let (reloaded_name, returned) = reloaded;
    if minted.device != returned.device {
        return Err(format!(
            "the {reloaded_name} boot reloaded the medium the {minted_name} boot minted and \
             reported device {} where the first reported {}. Two boots of one medium are one \
             appliance, so a different name means the identity did not survive the reboot — the \
             domain minted afresh over it, which is the whole defect a persistent identity exists \
             to prevent",
            returned.device, minted.device
        ));
    }
    if minted.fingerprint != returned.fingerprint {
        return Err(format!(
            "the {reloaded_name} boot reported key fingerprint {} where the {minted_name} boot \
             reported {}, under the same device identifier. That is worse than a changed name: an \
             administrator who verified the first fingerprint would be trusting a key the \
             appliance no longer holds",
            returned.fingerprint, minted.fingerprint
        ));
    }
    if returned.generation < minted.generation {
        return Err(format!(
            "the {reloaded_name} boot reports generation {} and the {minted_name} boot reported \
             {}. A generation only ever advances — it is what selects the copy a commit writes — so \
             a lower one on a later boot means the older copy of the record was adopted over the \
             newer",
            returned.generation, minted.generation
        ));
    }
    if returned.reset.is_some() {
        return Err(format!(
            "the {reloaded_name} boot reported a factory reset, and its whole subject is reloading \
             the identity the {minted_name} boot minted. A reset destroys that identity, so this \
             boot cannot be evidence of its survival — the medium carried a request no scenario \
             wrote, or the domain honoured one that was not there"
        ));
    }
    Ok(format!(
        "the {reloaded_name} boot reloaded the identity the {minted_name} boot minted on the same \
         medium: {}",
        returned.summary()
    ))
}

/// Hold the identity a **factory-reset** boot reported to the one the medium
/// carried before it.
///
/// The inverse of [`hold_to_source`] and deliberately not a relaxation of it. A
/// reset owes four things at once, and each is a different way of failing: it must
/// say on the console what it destroyed, it must come back under a *different*
/// name and a *different* key, it must come back **unowned**, and it must come
/// back at the generation a mint starts from. A domain that cleared the request
/// and left the identity in place passes none of them; one that cleared the
/// identity and kept the owner flag passes two.
///
/// What this cannot see is whether the old key is really gone from the bytes,
/// because a re-mint changes the record whatever happened to the sectors around
/// it. That half is `crate::data_disk::StoreDisk::judge_secret_erased`'s, and
/// neither half stands in for the other.
///
/// # Errors
/// Any of the four, each naming both boots and what it expected of the second.
pub(crate) fn hold_reset_to_source(
    source: (&str, &Identity),
    reset: (&str, &Identity),
) -> Result<String, String> {
    let (previous_name, previous) = source;
    let (reset_name, returned) = reset;
    let Some(cleared) = returned.reset else {
        return Err(format!(
            "the {reset_name} boot was given a medium carrying a factory-reset request and its \
             console names no reset at all. Either the domain read the request and did not act on \
             it, or it acted and said nothing — and an appliance that gives up its owner silently \
             leaves an operator with no way to know it happened, there being no shell and no CLI"
        ));
    };
    if previous.device == returned.device {
        return Err(format!(
            "the {reset_name} boot honoured a factory reset and came back as device {}, which is \
             the device the {previous_name} boot reported. A reset destroys the identity and mints \
             a fresh one, so the same name means the key and the certificate the request was meant \
             to revoke are still what this appliance authenticates with",
            returned.device
        ));
    }
    if previous.fingerprint == returned.fingerprint {
        return Err(format!(
            "the {reset_name} boot honoured a factory reset and came back under the key \
             fingerprint the {previous_name} boot reported. That is the substance of a reset rather \
             than a detail of it: an administrator who was told this appliance had been reset would \
             be re-onboarding it onto the key its previous owner already holds"
        ));
    }
    if returned.onboarded {
        return Err(format!(
            "the {reset_name} boot honoured a factory reset and reports itself owned. Unowned is \
             what a reset returns an appliance to, and it is the whole of what makes it \
             onboardable again"
        ));
    }
    if returned.generation != 1 {
        return Err(format!(
            "the {reset_name} boot honoured a factory reset and reports generation {}, and a \
             minted state starts at 1. A higher one means the record it is running on descends \
             from the one that was destroyed rather than replacing it",
            returned.generation
        ));
    }
    if cleared.generation != previous.generation {
        return Err(format!(
            "the {reset_name} boot reports clearing generation {} and the {previous_name} boot ran \
             on generation {}. The record a reset destroyed is the record the previous boot was \
             running on, so a different number means the domain read one copy and overwrote \
             another",
            cleared.generation, previous.generation
        ));
    }
    Ok(format!(
        "the {reset_name} boot honoured a factory-reset request on the medium the {previous_name} \
         boot ran on and came back a different, unowned appliance: {}",
        returned.summary()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> &'static Path {
        Path::new("/nonexistent/qemu.log")
    }

    const DEVICE: &str = "0123456789abcdef0123456789abcdef";
    const FINGERPRINT: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn identity_record(device: &str, generation: u64, onboarded: bool) -> String {
        format!(
            "LFW-PD time=unsynchronized domain=store state=ready device={device} \
             generation={generation} onboarded={onboarded}"
        )
    }

    fn fingerprint_record(fingerprint: &str) -> String {
        format!("LFW-PD time=unsynchronized domain=store state=ready fingerprint={fingerprint}")
    }

    fn reset_record(generation: u64, documents: u64, was_owned: bool) -> String {
        format!(
            "LFW-PD time=unsynchronized domain=store state=negotiated \
             cleared-generation={generation} cleared-documents={documents} was-owned={was_owned}"
        )
    }

    /// A capture of the shape a passing boot leaves.
    fn capture(records: &[String]) -> String {
        let mut text = String::from(
            "Bootstrapping kernel\r\n\
             LFW-BOOT slot=A state=confirmed\r\n\
             LFW-PD domain=store state=starting\r\n\
             LFW-PD domain=clock state=ready tsc-hz=2999998000 \
             utc=2026-07-30T20:27:00.123456789Z\r\n",
        );
        for record in records {
            text.push_str(record);
            text.push_str("\r\n");
        }
        text
    }

    fn passing() -> String {
        capture(&[
            identity_record(DEVICE, 1, false),
            fingerprint_record(FINGERPRINT),
        ])
    }

    #[test]
    fn a_boot_that_established_an_identity_is_accepted_and_reports_it() {
        let identity = judge(passing().as_bytes(), log()).expect("a well-formed pair of records");
        assert!(identity.reset.is_none());
        assert_eq!(identity.device, DEVICE);
        assert_eq!(identity.fingerprint, FINGERPRINT);
        assert_eq!(identity.generation, 1);
        assert!(!identity.onboarded);
        assert!(identity.summary().contains(DEVICE));
        assert!(identity.summary().contains("unowned"));
    }

    /// The obligation the debug kernel's own output makes real: a record preceded
    /// on its line by prose is still a record.
    #[test]
    fn a_record_that_did_not_begin_its_line_is_still_recovered() {
        let torn = capture(&[
            format!("Bootstrapping node #0{}", identity_record(DEVICE, 1, false)),
            fingerprint_record(FINGERPRINT),
        ]);
        judge(torn.as_bytes(), log()).expect("a record that shares its line with prose");
    }

    #[test]
    fn a_boot_whose_store_refused_is_reported_as_the_refusal_it_is() {
        let verdict = judge(
            capture(&[
                "LFW-PD domain=store state=refused cause=stored-public-key-mismatch \
                 signalled=true"
                    .to_owned(),
            ])
            .as_bytes(),
            log(),
        )
        .expect_err("a refused store");
        assert!(
            verdict.contains("refused to establish an identity"),
            "{verdict}"
        );
        assert!(verdict.contains("stored-public-key-mismatch"), "{verdict}");
    }

    #[test]
    fn a_boot_that_never_reached_the_store_domain_is_refused() {
        for silent in [
            String::new(),
            "Bootstrapping kernel\r\n".to_owned(),
            capture(&[]),
        ] {
            let verdict = judge(silent.as_bytes(), log()).expect_err("no identity record");
            assert!(verdict.contains("carried 0"), "{verdict}");
        }
    }

    #[test]
    fn two_identity_records_are_refused_rather_than_read_as_one() {
        let text = capture(&[
            identity_record(DEVICE, 1, false),
            identity_record(DEVICE, 2, false),
            fingerprint_record(FINGERPRINT),
        ]);
        let verdict = judge(text.as_bytes(), log()).expect_err("a doubled identity");
        assert!(verdict.contains("carried 2"), "{verdict}");
    }

    #[test]
    fn a_boot_that_named_no_fingerprint_is_refused() {
        let text = capture(&[identity_record(DEVICE, 1, false)]);
        let verdict = judge(text.as_bytes(), log()).expect_err("no fingerprint");
        assert!(verdict.contains("naming a fingerprint"), "{verdict}");
        assert!(verdict.contains("nobody can onboard"), "{verdict}");
    }

    /// The profile's two widths, held from both sides: one character short and
    /// one long are both refused, and the exact width is accepted.
    #[test]
    fn a_rendering_of_the_wrong_width_is_refused_by_the_profiles_own_number() {
        for wrong in [&DEVICE[..31], &format!("{DEVICE}0")[..]] {
            let text = capture(&[
                identity_record(wrong, 1, false),
                fingerprint_record(FINGERPRINT),
            ]);
            let verdict = judge(text.as_bytes(), log()).expect_err("{wrong}");
            assert!(verdict.contains("character for character"), "{verdict}");
        }
        for wrong in [&FINGERPRINT[..63], &format!("{FINGERPRINT}0")[..]] {
            let text = capture(&[identity_record(DEVICE, 1, false), fingerprint_record(wrong)]);
            judge(text.as_bytes(), log()).expect_err("{wrong}");
        }
    }

    /// Upper case is the second rendering the profile calls a defect, so it is
    /// one here.
    #[test]
    fn an_upper_case_rendering_is_refused_as_the_second_rendering_it_is() {
        let text = capture(&[
            identity_record(&DEVICE.to_uppercase(), 1, false),
            fingerprint_record(FINGERPRINT),
        ]);
        let verdict = judge(text.as_bytes(), log()).expect_err("upper case");
        assert!(verdict.contains("lowercase hexadecimal"), "{verdict}");
    }

    #[test]
    fn a_generation_of_zero_is_refused_as_the_zeroed_medium_it_reads_as() {
        let text = capture(&[
            identity_record(DEVICE, 0, false),
            fingerprint_record(FINGERPRINT),
        ]);
        let verdict = judge(text.as_bytes(), log()).expect_err("generation zero");
        assert!(verdict.contains("generation 0"), "{verdict}");
    }

    #[test]
    fn an_onboarded_field_that_is_no_boolean_is_refused() {
        let text = capture(&[
            "LFW-PD domain=store state=ready device=0123456789abcdef0123456789abcdef \
             generation=1 onboarded=maybe"
                .to_owned(),
            fingerprint_record(FINGERPRINT),
        ]);
        let verdict = judge(text.as_bytes(), log()).expect_err("no boolean");
        assert!(verdict.contains("is a boolean"), "{verdict}");
    }

    #[test]
    fn another_domains_record_is_never_read_as_the_stores() {
        let text = capture(&["LFW-PD domain=crypto state=ready".to_owned()]);
        let verdict = judge(text.as_bytes(), log()).expect_err("no store record at all");
        assert!(verdict.contains("carried 0"), "{verdict}");
    }

    /// The boot ends on the fingerprint record or on a refusal, and on nothing
    /// else — a `starting` record must not end it, or the capture would be judged
    /// before the identity was in it.
    #[test]
    fn the_boot_ends_on_the_last_record_the_domain_writes() {
        assert!(finished(passing().as_bytes()));
        assert!(finished(
            capture(&[
                "LFW-PD domain=store state=refused cause=state-read-failed signalled=true"
                    .to_owned()
            ])
            .as_bytes()
        ));
        assert!(!finished(capture(&[]).as_bytes()));
        assert!(!finished(
            capture(&[identity_record(DEVICE, 1, false)]).as_bytes()
        ));
        // The case that cost a whole gate run: the console had put part of the
        // fingerprint on the wire and this must not yet be the end of the boot,
        // because ending it there kills the guest mid-line and the judge then
        // reports the truncation as a rendering defect.
        for partial in [&FINGERPRINT[..1], &FINGERPRINT[..27], &FINGERPRINT[..63]] {
            assert!(
                !finished(
                    capture(&[
                        identity_record(DEVICE, 1, false),
                        fingerprint_record(partial),
                    ])
                    .as_bytes()
                ),
                "a fingerprint of {} character(s) ended the boot",
                partial.len()
            );
        }
        // And another domain finishing does not end this boot.
        assert!(!finished(
            capture(&["LFW-PD domain=crypto state=ready".to_owned()]).as_bytes()
        ));
    }

    fn identity(device: &str, fingerprint: &str, generation: u64) -> Identity {
        Identity {
            device: device.to_owned(),
            fingerprint: fingerprint.to_owned(),
            generation,
            onboarded: false,
            reset: None,
        }
    }

    #[test]
    fn the_same_identity_at_the_same_generation_is_accepted() {
        let minted = identity(DEVICE, FINGERPRINT, 1);
        let reloaded = identity(DEVICE, FINGERPRINT, 1);
        let proved = hold_to_source(("minted", &minted), ("reloaded", &reloaded))
            .expect("one appliance, twice");
        assert!(proved.contains(DEVICE), "{proved}");
        // And at a higher generation, which a commit between the two boots would
        // produce.
        hold_to_source(
            ("minted", &minted),
            ("reloaded", &identity(DEVICE, FINGERPRINT, 4)),
        )
        .expect("a generation that advanced");
    }

    /// The three ways the pair fails, each named for what it means rather than
    /// for which field moved.
    #[test]
    fn a_second_boot_that_is_a_different_appliance_is_refused() {
        let minted = identity(DEVICE, FINGERPRINT, 2);
        let other_device = identity(&DEVICE.replace('0', "1"), FINGERPRINT, 2);
        let verdict = hold_to_source(("minted", &minted), ("reloaded", &other_device))
            .expect_err("a different name");
        assert!(verdict.contains("minted afresh over it"), "{verdict}");

        let other_key = identity(DEVICE, &FINGERPRINT.replace('0', "1"), 2);
        let verdict =
            hold_to_source(("minted", &minted), ("reloaded", &other_key)).expect_err("a new key");
        assert!(verdict.contains("no longer holds"), "{verdict}");

        let older = identity(DEVICE, FINGERPRINT, 1);
        let verdict = hold_to_source(("minted", &minted), ("reloaded", &older))
            .expect_err("a generation that went backwards");
        assert!(verdict.contains("only ever advances"), "{verdict}");
    }
    /// The reset record: parsed as its own shape, and never confused with the
    /// identity beside it.
    #[test]
    fn a_boot_that_honoured_a_reset_reports_what_it_destroyed() {
        let text = capture(&[
            reset_record(4, 2, true),
            identity_record(DEVICE, 1, false),
            fingerprint_record(FINGERPRINT),
        ]);
        let identity = judge(text.as_bytes(), log()).expect("a reset boot's three records");
        assert_eq!(
            identity.reset,
            Some(Reset {
                generation: 4,
                documents: 2,
                was_owned: true,
            })
        );
        assert!(identity.summary().contains("factory reset"), "{identity:?}");
        // And a reset of an appliance whose record this build could not read,
        // which reports zeroes rather than refusing.
        let text = capture(&[
            reset_record(0, 0, false),
            identity_record(DEVICE, 1, false),
            fingerprint_record(FINGERPRINT),
        ]);
        let identity = judge(text.as_bytes(), log()).expect("a reset over an unreadable record");
        assert_eq!(
            identity.reset,
            Some(Reset {
                generation: 0,
                documents: 0,
                was_owned: false,
            })
        );
    }

    #[test]
    fn two_reset_records_are_refused_rather_than_read_as_one() {
        let text = capture(&[
            reset_record(4, 2, true),
            reset_record(5, 0, false),
            identity_record(DEVICE, 1, false),
            fingerprint_record(FINGERPRINT),
        ]);
        let verdict = judge(text.as_bytes(), log()).expect_err("a doubled reset");
        assert!(verdict.contains("answered twice"), "{verdict}");
    }

    #[test]
    fn a_reset_record_whose_owner_field_is_no_boolean_is_refused() {
        let text = capture(&[
            "LFW-PD domain=store state=negotiated cleared-generation=4 cleared-documents=2 \
             was-owned=perhaps"
                .to_owned(),
            identity_record(DEVICE, 1, false),
            fingerprint_record(FINGERPRINT),
        ]);
        let verdict = judge(text.as_bytes(), log()).expect_err("no boolean");
        assert!(verdict.contains("is a boolean"), "{verdict}");
    }

    fn after_reset(device: &str, fingerprint: &str, cleared: u64) -> Identity {
        Identity {
            reset: Some(Reset {
                generation: cleared,
                documents: 0,
                was_owned: false,
            }),
            ..identity(device, fingerprint, 1)
        }
    }

    #[test]
    fn a_reset_that_came_back_a_different_unowned_appliance_is_accepted() {
        let previous = identity(DEVICE, FINGERPRINT, 4);
        let fresh = after_reset(&DEVICE.replace('0', "1"), &FINGERPRINT.replace('0', "1"), 4);
        let proved = hold_reset_to_source(("reloaded", &previous), ("reset", &fresh))
            .expect("a reset appliance");
        assert!(proved.contains("different, unowned appliance"), "{proved}");
    }

    /// Every way a reset fails, and each one is a different defect rather than a
    /// different field: the identity surviving, the key surviving, an owner
    /// surviving, a record that descends from the destroyed one, and a reset that
    /// happened without saying so.
    #[test]
    fn a_reset_that_did_not_give_the_appliance_up_is_refused() {
        let previous = identity(DEVICE, FINGERPRINT, 4);
        let other = DEVICE.replace('0', "1");
        let other_key = FINGERPRINT.replace('0', "1");

        let verdict = hold_reset_to_source(
            ("reloaded", &previous),
            ("reset", &identity(DEVICE, FINGERPRINT, 1)),
        )
        .expect_err("no reset record");
        assert!(verdict.contains("names no reset at all"), "{verdict}");

        let verdict = hold_reset_to_source(
            ("reloaded", &previous),
            ("reset", &after_reset(DEVICE, &other_key, 4)),
        )
        .expect_err("the same name");
        assert!(verdict.contains("still what this appliance"), "{verdict}");

        let verdict = hold_reset_to_source(
            ("reloaded", &previous),
            ("reset", &after_reset(&other, FINGERPRINT, 4)),
        )
        .expect_err("the same key");
        assert!(
            verdict.contains("previous owner already holds"),
            "{verdict}"
        );

        let owned = Identity {
            onboarded: true,
            ..after_reset(&other, &other_key, 4)
        };
        let verdict =
            hold_reset_to_source(("reloaded", &previous), ("reset", &owned)).expect_err("owned");
        assert!(verdict.contains("Unowned is what a reset"), "{verdict}");

        let advanced = Identity {
            generation: 5,
            ..after_reset(&other, &other_key, 4)
        };
        let verdict = hold_reset_to_source(("reloaded", &previous), ("reset", &advanced))
            .expect_err("a generation past a mint's");
        assert!(verdict.contains("starts at 1"), "{verdict}");

        let verdict = hold_reset_to_source(
            ("reloaded", &previous),
            ("reset", &after_reset(&other, &other_key, 3)),
        )
        .expect_err("cleared a generation the previous boot did not run on");
        assert!(verdict.contains("read one copy"), "{verdict}");
    }

    /// And the other direction: a boot whose subject is a *reload* must not have
    /// reset anything.
    #[test]
    fn a_reload_that_reported_a_reset_is_refused() {
        let minted = identity(DEVICE, FINGERPRINT, 1);
        let reset = Identity {
            reset: Some(Reset {
                generation: 1,
                documents: 0,
                was_owned: false,
            }),
            ..identity(DEVICE, FINGERPRINT, 1)
        };
        let verdict = hold_to_source(("minted", &minted), ("reloaded", &reset))
            .expect_err("a reload that reset");
        assert!(verdict.contains("cannot be evidence"), "{verdict}");
    }
}
