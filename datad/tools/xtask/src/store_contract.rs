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
//! # No adversary
//!
//! The capture is the appliance's own output on a wire only the harness is
//! attached to, so no threat-model adversary is named for this path; what it
//! defends against is an appliance that forgot who it was. **Nothing here reads
//! the medium**, deliberately: it carries the private scalar in plaintext, and a
//! harness that parsed it would be a second place that had to be trusted never
//! to print one.

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
}

impl Identity {
    /// This identity as one line of a run summary.
    pub(crate) fn summary(&self) -> String {
        format!(
            "device {} at generation {} ({}), key fingerprint {}",
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
    })
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
    Ok(format!(
        "the {reloaded_name} boot reloaded the identity the {minted_name} boot minted on the same \
         medium: {}",
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
}
