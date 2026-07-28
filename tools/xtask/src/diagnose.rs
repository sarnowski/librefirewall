//! Fail on the shipped kernel configuration, diagnose on the debug one.
//!
//! Every end-to-end scenario boots the release configuration, because that is
//! the image a release publishes (BLD-3). That closes the hole two consecutive
//! changes fell into — a console that reached nothing because `debug_println!`
//! compiles to a kernel debug syscall the release kernel is not built with, and
//! a Multiboot2 module GRUB placed below 1 MiB that the debug image survived
//! only by being too large to fit down there — and it costs the one thing the
//! debug kernel was ever worth: its serial diagnostics.
//!
//! [`after_shipping_failure`] buys that back at the only moment it is needed.
//! When a scenario fails on the release image, that ONE scenario is re-run
//! against the debug kernel and the result is reported beside the failure. The
//! green path pays nothing; a red path pays one extra boot, when there is
//! already a problem to spend it on.
//!
//! # The divergence is the diagnosis
//!
//! Establish first what cannot differ: `image.rs` passes `--release` to the
//! protection-domain build in *both* kernel configurations, so there is no
//! debug binary — our Rust is the same compilation either way. What differs is
//! the seL4 kernel build (`PRINTING`, `DEBUG_BUILD`, `HARDWARE_DEBUG_API`,
//! `IRQ_REPORTING`, `COLOUR_PRINTING`, `USER_STACK_TRACE_LENGTH`,
//! `VERIFICATION_BUILD`) and, downstream of it, the size and layout of the
//! image GRUB has to place. So the two outcomes mean different things and the
//! verdict says which:
//!
//! * **Fails on release, passes on debug.** The defect is a function of the
//!   kernel configuration or of the image it produces, and nothing else. That
//!   is the exact signature of both defects above, and it points at a region of
//!   the system a Rust-level reading of the diff will not reach.
//! * **Fails on both.** The defect is configuration-independent, and the debug
//!   kernel's serial output — fault reports, register dumps, its own boot
//!   chatter — is the diagnosis. It is surfaced verbatim.
//!
//! # It is evidence, never a second chance
//!
//! The debug re-run cannot change the verdict (ENG-12): `after_shipping_failure`
//! returns a failure string on every path, including the one where the debug
//! boot passed. A scenario that fails on the image that ships has failed.
//!
//! And the surfaced serial text is *diagnostic output shown to a human*, never
//! an assertion input (TEST-13). Nothing in this module parses it, matches it,
//! or lets it decide anything; the only thing read out of a log is whether it
//! carried any guest bytes at all, which is a size and not a contract.

use std::{fmt, fs, path::Path};

use crate::image;

/// How many trailing lines of the debug run's serial capture are quoted into
/// the verdict. Enough for an seL4 fault report and its register dump, which is
/// what sits at the end of a capture whose boot died; the whole log is named
/// beside it for everything earlier.
const DIAGNOSTIC_TAIL_LINES: usize = 80;

/// Which seL4 kernel configuration an end-to-end scenario boots, and therefore
/// what its result means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Run {
    /// The configuration a release ships. This run IS the verdict.
    Shipping,
    /// The debug kernel, booted only after a [`Run::Shipping`] run of the same
    /// scenario has already failed. Its result is evidence and never a verdict.
    Diagnostic,
}

impl Run {
    /// The Microkit/seL4 kernel configuration this run assembles its image in.
    pub(crate) fn config(self) -> &'static str {
        match self {
            Self::Shipping => image::RELEASE_CONFIG,
            Self::Diagnostic => image::DEBUG_CONFIG,
        }
    }

    /// What this run appends to the names it derives — run logs, scenario
    /// build workspaces, working disks — so a diagnostic re-run can never
    /// overwrite the artifacts of the shipping run it is diagnosing. Those are
    /// the evidence of the failure under investigation.
    pub(crate) fn name_suffix(self) -> &'static str {
        match self {
            Self::Shipping => "",
            Self::Diagnostic => "-debug",
        }
    }
}

/// The line the QEMU harness writes into a run log immediately before the
/// guest's own bytes. Everything above it is the harness describing how it
/// configured QEMU; everything below is the guest.
pub(crate) const GUEST_OUTPUT_MARKER: &str = "# --- captured guest serial output follows ---\n";

/// Re-run one failed scenario against the debug kernel and compose the verdict
/// the operator sees, which is a failure on every path.
///
/// `rerun` must boot the SAME scenario in [`Run::Diagnostic`], writing its
/// capture to `diagnostic_log`; `shipping_log` is the capture the failing
/// release boot already wrote.
pub(crate) fn after_shipping_failure(
    label: &str,
    verdict: impl fmt::Display,
    shipping_log: &Path,
    diagnostic_log: &Path,
    rerun: impl FnOnce() -> Result<(), String>,
) -> String {
    println!(
        "\n  {label} FAILED on the release image. Re-running this one scenario on the debug \
         kernel to diagnose it — the result below is evidence, and does not change the verdict."
    );
    let diagnosis = diagnose(diagnostic_log, rerun());
    println!("  debug re-run finished: {}\n", diagnosis.headline());

    format!(
        "{label} failed on the RELEASE image, which is the image that ships.\n\
         \n  release verdict: {verdict}\
         \n  release serial:  {}{}\
         \n\n{}",
        shipping_log.display(),
        silent_release_note(shipping_log),
        diagnosis.render(diagnostic_log),
    )
}

/// What the debug re-run established.
enum Diagnosis {
    /// The scenario passed on the debug kernel, so the defect is a function of
    /// the kernel configuration or of the image it produces.
    PassesOnDebug,
    /// It failed on the debug kernel too, with this verdict, and the debug
    /// kernel's capture is the diagnosis.
    FailsOnDebug(String),
    /// No debug boot happened at all — the debug image could not be assembled,
    /// or the harness failed before QEMU wrote a capture. Reported as its own
    /// outcome rather than as "fails on both", which it is not evidence of.
    NotReached(String),
}

/// Classify the re-run's outcome. A failure that left no capture behind never
/// reached a boot: the harness writes the run log on every path out of a boot,
/// so its absence is the mechanical difference between a scenario that failed
/// on the debug kernel and one the debug kernel never ran.
fn diagnose(diagnostic_log: &Path, outcome: Result<(), String>) -> Diagnosis {
    match outcome {
        Ok(()) => Diagnosis::PassesOnDebug,
        Err(verdict) if diagnostic_log.is_file() => Diagnosis::FailsOnDebug(verdict),
        Err(verdict) => Diagnosis::NotReached(verdict),
    }
}

impl Diagnosis {
    /// One clause for the progress line printed as the re-run finishes.
    fn headline(&self) -> &'static str {
        match self {
            Self::PassesOnDebug => "it PASSES on the debug kernel — the failure diverges",
            Self::FailsOnDebug(_) => "it fails on the debug kernel too",
            Self::NotReached(_) => "the debug kernel was never booted",
        }
    }

    fn render(&self, diagnostic_log: &Path) -> String {
        match self {
            Self::PassesOnDebug => format!(
                "  *** DIVERGENCE: this scenario PASSES on the debug kernel and FAILS on the \
                 release kernel. ***\n\
                 \n  \
                 The protection domains are not the difference: `image.rs` builds them with the \
                 `--release`\n  \
                 Cargo profile in both configurations, so there is no debug binary and our Rust \
                 is one\n  \
                 compilation. What differs is the seL4 KERNEL build — PRINTING, DEBUG_BUILD, \
                 HARDWARE_DEBUG_API,\n  \
                 IRQ_REPORTING, COLOUR_PRINTING, USER_STACK_TRACE_LENGTH, VERIFICATION_BUILD — \
                 and the size\n  \
                 and layout of the image GRUB then has to place. Look there, not at the diff.\n\
                 \n  \
                 Both have shipped a defect with exactly this signature: a console that emitted \
                 nothing,\n  \
                 because `debug_println!` compiles to `seL4_DebugPutChar` and the release kernel \
                 carries no\n  \
                 such syscall; and a Multiboot2 module GRUB placed below 1 MiB, where seL4 loaded \
                 userland\n  \
                 over its own page tables — which the debug image survived only by being too \
                 large to fit\n  \
                 down there.\n\
                 \n  \
                 The debug boot's serial capture is the healthy run, so it is a baseline rather \
                 than a\n  diagnosis: {}",
                diagnostic_log.display()
            ),
            Self::FailsOnDebug(verdict) => format!(
                "  This scenario fails on the debug kernel as well, so the defect does not \
                 depend on the\n  \
                 kernel configuration. The debug kernel's serial output is the diagnosis, and \
                 the release\n  \
                 kernel could not have produced it.\n\
                 \n  \
                 debug verdict: {verdict}\n\
                 {}",
                quote_capture(diagnostic_log)
            ),
            Self::NotReached(verdict) => format!(
                "  The debug re-run never reached a boot, so it says nothing about the release \
                 failure\n  \
                 above — which stands on its own and is what must be fixed. The re-run failed \
                 with:\n\
                 \n  {verdict}"
            ),
        }
    }
}

/// The tail of a run log's guest output, framed for a human to read.
///
/// This is text printed for a person, never anything a contract is judged
/// against (TEST-13). It is quoted verbatim and interpreted by nobody.
fn quote_capture(log: &Path) -> String {
    let path = log.display();
    let Some(output) = guest_output(log) else {
        return format!(
            "\n  The debug run left no readable capture at {path}, so there is no serial output \
             to show."
        );
    };
    let lines: Vec<&str> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.is_empty() {
        return format!(
            "\n  The debug run's capture at {path} carries no guest output at all — which on the \
             DEBUG\n  \
             kernel is itself the finding, that kernel printing its own boot chatter \
             unconditionally.\n  \
             Suspect something ahead of the kernel: firmware, the boot manager, or where GRUB \
             placed\n  the Multiboot2 module."
        );
    }
    let shown = lines.len().min(DIAGNOSTIC_TAIL_LINES);
    let tail = &lines[lines.len() - shown..];
    format!(
        "\n  --- last {shown} of {} guest serial lines, from {path} ---\n  {}\n  \
         --- end of debug serial output ---",
        lines.len(),
        tail.join("\n  ")
    )
}

/// The note a release failure carries when its capture is empty.
///
/// A release boot that dies produces an empty serial log, and a bare timeout
/// over one reads as a second, mysterious fault rather than as the expected
/// silence of a kernel built without `CONFIG_PRINTING`. Saying which it is, and
/// pointing at where the diagnosis actually comes from, is the difference
/// between an actionable failure and the one that cost real time (ENG-12).
fn silent_release_note(shipping_log: &Path) -> String {
    match guest_output(shipping_log) {
        Some(output) if output.trim().is_empty() => String::from(
            " (EMPTY)\n  \
             The release capture carries no guest bytes. That is expected rather than a second \
             fault:\n  \
             the release kernel is built without CONFIG_PRINTING and prints nothing of its own, \
             so a boot\n  \
             that dies before the console domain claims the UART leaves no trace at all. A \
             timeout here\n  \
             therefore carries no diagnosis — which is what the debug re-run below is for.",
        ),
        Some(output) => format!(" ({} bytes of guest output)", output.len()),
        None => String::from(
            " (MISSING)\n  \
             No capture was written, so the failure happened before QEMU was booted at all — an \
             image\n  \
             assembly or harness failure rather than something the guest did.",
        ),
    }
}

/// The guest's own bytes in a run log, or `None` when the log is absent or
/// carries no capture section. Its length is the only thing read out of it.
fn guest_output(log: &Path) -> Option<String> {
    let text = fs::read_to_string(log).ok()?;
    text.split_once(GUEST_OUTPUT_MARKER)
        .map(|(_harness_header, guest)| guest.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A unique, non-existent path under the temp dir. `xtask` carries no
    /// dependencies, so uniqueness is built from the pid and a counter.
    fn scratch(name: &str) -> std::path::PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "librefirewall-diagnose-{name}-{}-{unique}.log",
            std::process::id()
        ))
    }

    /// A run log as the harness writes one: the header it generates, the
    /// marker, then the guest's bytes.
    fn write_log(path: &Path, guest: &str) {
        fs::write(
            path,
            format!("# librefirewall QEMU run: test\n# accel=tcg\n{GUEST_OUTPUT_MARKER}{guest}"),
        )
        .unwrap();
    }

    #[test]
    fn the_two_runs_never_share_a_name_or_a_kernel_configuration() {
        // The property the whole arrangement rests on: a diagnostic re-run must
        // not overwrite the shipping run's log, scenario build tree, or working
        // disk, because those are the evidence of the failure it is diagnosing.
        assert_eq!(Run::Shipping.config(), image::RELEASE_CONFIG);
        assert_eq!(Run::Diagnostic.config(), image::DEBUG_CONFIG);
        assert_ne!(Run::Shipping.config(), Run::Diagnostic.config());
        assert_ne!(Run::Shipping.name_suffix(), Run::Diagnostic.name_suffix());
        assert!(Run::Shipping.name_suffix().is_empty());
    }

    #[test]
    fn a_scenario_that_passes_on_debug_is_reported_as_a_divergence_and_still_fails() {
        let shipping = scratch("diverge-release");
        let diagnostic = scratch("diverge-debug");
        write_log(&shipping, "");
        write_log(&diagnostic, "Bootstrapping kernel\nLFW-CFG generation=0\n");

        let verdict = after_shipping_failure(
            "system scenario generation-swap",
            "the fail-closed record appears 0 times",
            &shipping,
            &diagnostic,
            || Ok(()),
        );

        // The divergence must be the loudest thing in the message: it is the
        // GRUB defect's signature and the console defect's alike.
        assert!(verdict.contains("*** DIVERGENCE"), "{verdict}");
        assert!(
            verdict.contains("PASSES on the debug kernel")
                && verdict.contains("FAILS on the release kernel"),
            "{verdict}"
        );
        // The two precedents, named so the reader knows where to look.
        assert!(verdict.contains("seL4_DebugPutChar"), "{verdict}");
        assert!(verdict.contains("below 1 MiB"), "{verdict}");
        // And the thing that is NOT the difference, so nobody re-reads the diff.
        assert!(
            verdict.contains("there is no debug binary"),
            "the identical PD compilation must be stated: {verdict}"
        );
        // ENG-12: passing on debug is evidence, not a second chance.
        assert!(
            verdict.contains("failed on the RELEASE image"),
            "the verdict must remain a failure: {verdict}"
        );
        assert!(
            verdict.contains("the fail-closed record appears 0 times"),
            "the release verdict must survive the framing: {verdict}"
        );

        fs::remove_file(&shipping).unwrap();
        fs::remove_file(&diagnostic).unwrap();
    }

    #[test]
    fn an_empty_release_capture_is_explained_rather_than_left_as_a_bare_timeout() {
        // The failure shape that cost real time: the release kernel prints
        // nothing, so a boot that dies leaves an empty log and a timeout with
        // no diagnosis in it.
        let shipping = scratch("silent-release");
        let diagnostic = scratch("silent-debug");
        write_log(&shipping, "");
        write_log(&diagnostic, "Bootstrapping kernel\nseL4 fault: cap fault\n");

        let verdict = after_shipping_failure(
            "system scenario routed-forwarding",
            "timed out after 180s waiting for the routed contract",
            &shipping,
            &diagnostic,
            || Err("timed out after 180s waiting for the routed contract".to_owned()),
        );

        assert!(verdict.contains("(EMPTY)"), "{verdict}");
        assert!(verdict.contains("CONFIG_PRINTING"), "{verdict}");
        assert!(
            verdict.contains("carries no diagnosis"),
            "the empty log must be named as carrying nothing: {verdict}"
        );
        // Fails on both: the debug capture is the diagnosis and is surfaced.
        assert!(
            verdict.contains("does not depend on the") && verdict.contains("kernel configuration"),
            "{verdict}"
        );
        assert!(verdict.contains("seL4 fault: cap fault"), "{verdict}");
        assert!(verdict.contains("end of debug serial output"), "{verdict}");

        fs::remove_file(&shipping).unwrap();
        fs::remove_file(&diagnostic).unwrap();
    }

    #[test]
    fn a_long_debug_capture_is_quoted_by_its_tail_and_says_how_much_it_dropped() {
        // A tool's actionable output is at the END, and a whole boot log pasted
        // into a verdict buries it.
        let log = scratch("long-debug");
        let guest: String = (0..500).map(|line| format!("line-{line}\n")).collect();
        write_log(&log, &guest);

        let quoted = quote_capture(&log);
        assert!(quoted.contains("line-499"), "the last line must be kept");
        assert!(!quoted.contains("line-0\n"), "the head must be dropped");
        assert!(
            quoted.contains(&format!("last {DIAGNOSTIC_TAIL_LINES} of 500")),
            "the reader must be told how much was dropped: {quoted}"
        );

        fs::remove_file(&log).unwrap();
    }

    #[test]
    fn a_debug_run_that_never_booted_is_not_reported_as_failing_on_debug() {
        // The distinction that keeps the divergence verdict honest: an image
        // that would not assemble is not evidence that the scenario fails on
        // the debug kernel, and claiming it were would point at the wrong half
        // of the system.
        let shipping = scratch("unreached-release");
        write_log(&shipping, "Bootstrapping kernel\n");
        let diagnostic = scratch("unreached-debug");
        assert!(!diagnostic.is_file());

        let verdict = after_shipping_failure(
            "A/B scenario confirmed-A",
            "the boot manager did not make the expected sequence of decisions",
            &shipping,
            &diagnostic,
            || Err("build protection domains: cargo exited 101".to_owned()),
        );

        assert!(verdict.contains("never reached a boot"), "{verdict}");
        assert!(
            !verdict.contains("fails on the debug kernel as well"),
            "an unbuilt image must not be read as a debug failure: {verdict}"
        );
        assert!(verdict.contains("cargo exited 101"), "{verdict}");
        assert!(
            verdict.contains("the boot manager did not make the expected sequence"),
            "the release verdict must still be the thing to fix: {verdict}"
        );

        fs::remove_file(&shipping).unwrap();
    }

    #[test]
    fn a_release_capture_that_carried_output_is_measured_rather_than_called_empty() {
        let shipping = scratch("noisy-release");
        write_log(
            &shipping,
            "LFW-CFG generation=0 outcome=applied changes=0\n",
        );
        let note = silent_release_note(&shipping);
        assert!(!note.contains("EMPTY"), "{note}");
        assert!(note.contains("bytes of guest output"), "{note}");
        fs::remove_file(&shipping).unwrap();
    }

    #[test]
    fn a_missing_release_capture_is_named_as_a_failure_before_the_boot() {
        let note = silent_release_note(&scratch("absent-release"));
        assert!(note.contains("(MISSING)"), "{note}");
        assert!(note.contains("before QEMU was booted"), "{note}");
    }

    #[test]
    fn an_empty_debug_capture_is_itself_reported_as_the_finding() {
        // The debug kernel prints unconditionally, so a debug capture with
        // nothing in it means the failure is ahead of the kernel entirely.
        let log = scratch("empty-debug");
        write_log(&log, "\n   \n");
        let quoted = quote_capture(&log);
        assert!(quoted.contains("no guest output at all"), "{quoted}");
        assert!(quoted.contains("Multiboot2 module"), "{quoted}");
        fs::remove_file(&log).unwrap();
    }
}
