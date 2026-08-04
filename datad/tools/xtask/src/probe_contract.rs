//! The hardware-probe record one boot must produce on the `LFW-PD` console
//! channel.
//!
//! This is [`crate::clock_contract`]'s pattern applied to the record that
//! answers the management-plane plan's central hardware hypothesis: that a
//! hardfloat, SSE-enabled protection domain boots on this kernel at all, that
//! AES-NI and PCLMULQDQ execute and answer their known answers, and that XMM
//! state survives the kernel's context switches. The probe domain makes those
//! claims in one `state=ready` record; this module is what turns the claim
//! into a gate verdict.
//!
//! # What is asserted, and why the preemption floor is part of it
//!
//! Exactly one ready record, carrying `aes=proven` and `pclmul=proven` — the
//! constant fields the record's variant mints, so their absence means the line
//! is not the record it claims to be — and a `preemptions=` count of at least
//! one. The floor is the XMM half of the experiment: a run that was never
//! preempted checked its live value against nothing the kernel had to save
//! and restore, so it would prove the instructions and not the state. The
//! probe runs at the busy-loop domains' own priority precisely so round-robin
//! preempts it, and a boot where that never happened is a finding, not a pass.
//!
//! # A refusal is reported as itself
//!
//! The probe refuses with a cause token on every path that does not end in a
//! proof — a missing CPUID feature, a wrong known answer, a corrupted pattern
//! — and that record is the experiment's other possible answer. It is quoted
//! whole, because on the plan's own terms a probe that cannot run is a result
//! to report, never one to force past.

use std::path::Path;

use lfw_log::{Domain, DomainState};

use crate::console_records::{LIFECYCLE_PREFIX, field, lifecycle_records, value as field_value};

/// Judge the hardware probe's record in one boot's serial capture.
///
/// # Errors
/// The verdict, naming what the channel carried against what the appliance owes
/// it, and where the whole run log is.
pub(crate) fn judge(serial: &[u8], log: &Path) -> Result<String, String> {
    let text = String::from_utf8_lossy(serial);
    let ours: Vec<&str> = lifecycle_records(&text)
        .into_iter()
        .filter(|record| record.contains(&field("domain", Domain::HardwareProbe.name())))
        .collect();

    let refused = field("state", DomainState::Refused.name());
    if let Some(record) = ours.iter().find(|record| record.contains(&refused)) {
        return Err(format!(
            "the hardware probe refused: {record:?}. The cause token names what failed — a \
             `*-not-supported` token is a CPUID feature below the compile-time baseline (the \
             guest CPU model, on this bench), a `*-known-answer-mismatch` token is an \
             instruction that executed and answered wrongly, and `xmm-pattern-corrupted` is \
             XMM state that did not survive a context switch. This is the experiment's answer, \
             to be reported rather than worked around.\n  full run log: {}",
            log.display()
        ));
    }

    let ready = field("state", DomainState::Ready.name());
    let proven: Vec<&&str> = ours
        .iter()
        .filter(|record| record.contains(&ready))
        .collect();
    let [record] = proven[..] else {
        return Err(format!(
            "the console carried {} `{}` record(s) for the hardware probe in the `ready` state, \
             and a boot produces exactly one: this domain runs once in `init` and then parks, so \
             none means it never published — or faulted before it could, which the debug re-run \
             diagnoses — and several mean something else is writing its ring\n  probe records \
             observed: {ours:#?}\n  full run log: {}",
            proven.len(),
            LIFECYCLE_PREFIX.trim_end(),
            log.display()
        ));
    };

    for (key, expected) in [("aes", "proven"), ("pclmul", "proven")] {
        let got = value(record, key, log)?;
        if got != expected {
            return Err(format!(
                "{record:?} carries {key}={got} and the probe's ready record is specified with \
                 {key}={expected} — the line is not the record its domain and state claim\n  \
                 full run log: {}",
                log.display()
            ));
        }
    }

    let preemptions: u64 = value(record, "preemptions", log)?
        .parse()
        .map_err(|error| format!("{record:?}: preemptions is no number: {error}"))?;
    let iterations: u64 = value(record, "iterations", log)?
        .parse()
        .map_err(|error| format!("{record:?}: iterations is no number: {error}"))?;
    if preemptions == 0 {
        return Err(format!(
            "{record:?} observed no preemption, so the XMM half of the claim is untested: the \
             live value was never checked across a context switch. The probe shares the \
             busy-loop domains' priority exactly so round-robin preempts it, so a boot where \
             that never happened inside the probe's budget is a scheduling finding\n  full run \
             log: {}",
            log.display()
        ));
    }

    Ok(format!(
        "the hardware probe proved AES-NI, PCLMULQDQ and XMM survival across {preemptions} \
         preemption(s) in {iterations} passes"
    ))
}

/// The value of `key` in `record`, or a verdict naming the field the record is
/// specified to carry and does not.
fn value<'a>(record: &'a str, key: &str, log: &Path) -> Result<&'a str, String> {
    field_value(record, key).ok_or_else(|| {
        format!(
            "{record:?} carries no `{key}=` field, and the hardware probe's ready record is \
             specified with one\n  full run log: {}",
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

    /// A capture of the shape a passing boot leaves: the other domains'
    /// lifecycle records, the configuration channel, and the probe's own.
    fn capture(probe: &str) -> String {
        format!(
            "Bootstrapping kernel\r\n\
             LFW-BOOT slot=A state=confirmed\r\n\
             LFW-PD domain=hardware-probe state=starting\r\n\
             LFW-PD domain=clock state=ready tsc-hz=2999998000 utc=2026-07-30T20:27:00.123456789Z\r\n\
             {probe}\r\n\
             LFW-PD domain=nic-driver state=ready rx-posted=64\r\n"
        )
    }

    const READY: &str = "LFW-PD domain=hardware-probe state=ready aes=proven pclmul=proven \
                         preemptions=4 iterations=90000";

    #[test]
    fn a_boot_that_proved_the_profile_across_a_preemption_is_accepted() {
        let proved = judge(capture(READY).as_bytes(), log()).expect("a proven probe record");
        assert!(proved.contains("4 preemption(s)"), "{proved}");
        assert!(proved.contains("90000 passes"), "{proved}");
    }

    #[test]
    fn a_boot_whose_probe_refused_is_reported_as_the_refusal_it_is() {
        let verdict = judge(
            capture(
                "LFW-PD domain=hardware-probe state=refused cause=aes-known-answer-mismatch \
                 signalled=false detail=0x0,0x0",
            )
            .as_bytes(),
            log(),
        )
        .expect_err("a refused probe");
        assert!(verdict.contains("the hardware probe refused"), "{verdict}");
        assert!(verdict.contains("aes-known-answer-mismatch"), "{verdict}");
    }

    #[test]
    fn a_boot_that_never_reached_the_probe_is_refused() {
        for silent in [
            String::new(),
            "Bootstrapping kernel\r\n".to_owned(),
            capture("LFW-PD domain=hardware-probe state=starting"),
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
    fn an_unpreempted_run_is_a_finding_rather_than_a_pass() {
        let record = READY.replace("preemptions=4", "preemptions=0");
        let verdict = judge(capture(&record).as_bytes(), log()).expect_err("no preemption");
        assert!(verdict.contains("observed no preemption"), "{verdict}");
    }

    #[test]
    fn a_record_missing_a_field_is_refused_by_the_field_it_is_missing() {
        for (record, missing) in [
            (
                "LFW-PD domain=hardware-probe state=ready pclmul=proven preemptions=1 \
                 iterations=1",
                "aes",
            ),
            (
                "LFW-PD domain=hardware-probe state=ready aes=proven preemptions=1 iterations=1",
                "pclmul",
            ),
            (
                "LFW-PD domain=hardware-probe state=ready aes=proven pclmul=proven iterations=1",
                "preemptions",
            ),
            (
                "LFW-PD domain=hardware-probe state=ready aes=proven pclmul=proven preemptions=1",
                "iterations",
            ),
        ] {
            let verdict = judge(capture(record).as_bytes(), log()).expect_err("a partial record");
            assert!(verdict.contains(&format!("`{missing}=`")), "{verdict}");
        }
    }

    #[test]
    fn a_count_that_is_not_a_number_is_reported_rather_than_read_as_zero() {
        let record = READY.replace("preemptions=4", "preemptions=often");
        let verdict = judge(capture(&record).as_bytes(), log()).expect_err("a bad field");
        assert!(verdict.contains("no number"), "{verdict}");
    }

    #[test]
    fn another_domains_ready_record_is_never_read_as_the_probes() {
        let text = capture("LFW-PD domain=console state=ready");
        let verdict = judge(text.as_bytes(), log()).expect_err("no probe record at all");
        assert!(verdict.contains("carried 0"), "{verdict}");
    }
}
