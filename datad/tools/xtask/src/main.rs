//! librefirewall build & release orchestrator.
//!
//! `xtask` is the single Rust entry point behind the `Makefile`: it builds the
//! protection-domain binaries for the seL4 target, assembles them into the
//! Microkit kernel/system pair, packages a signed A/B GPT disk, and boots that
//! disk in QEMU to assert the system's observable contracts. It is a `std`
//! binary with no third-party dependency — so the bootstrap tooling stays
//! auditable and builds offline inside the pinned container — and two
//! first-party ones, the crates whose constants [`sysdesc`] holds the system
//! description to.
//!
//! # The adversary
//!
//! No threat-model adversary reaches this crate: it runs on a developer's
//! machine, on the host side of an emulator, and nothing it parses
//! arrives from a network, a device, or a peer protection domain. Being out of
//! an adversary's reach is not a licence — only seL4, Microkit and `rust-sel4`
//! are trusted, and nothing first-party inherits that status — and here the
//! obligation it leaves is sharper than the exemption it does not grant.
//!
//! Everything this crate reads back was composed by the appliance it is
//! judging: a serial capture, a GPT disk image and the recording extents on the
//! data disk beside it, and pcapng bodies pulled through a real HTTP client.
//! Those bytes are the *subject* of the assertion, so the case where they are
//! malformed is not an unlikely one — it is the case a failing gate exists to
//! report. A harness that indexed or unwrapped its way through them would abort
//! on exactly the input it was built to describe, replacing a named verdict with
//! a backtrace and losing the diagnosis with it. So every walk over guest-
//! composed bytes follows the lengths the bytes themselves state, is bounded by
//! a number the guest did not choose, and answers a verdict rather than
//! panicking — the same discipline a protection domain owes untrusted input,
//! adopted here because the alternative is a harness that cannot report the
//! defect it found.
//!
//! The orchestration is split by concern, each stage in its own module:
//!
//! - [`sysdesc`] — the system description held to the constants the PDs map it
//!   with.
//! - [`reference_contract`] — the operator reference chapters held to the
//!   catalogues they describe.
//! - [`target_spec`] — artifacts held to the target specification they were
//!   compiled against.
//! - [`image`] — build the PDs and assemble the Microkit image.
//! - [`disk`] — the signed A/B GPT disk: partition geometry and assembly.
//! - [`signing`] — the development payload-signing trust anchor.
//! - [`grub`] — the signed GRUB boot base (core image + seed grubenv).
//! - [`qemu`] — booting the disk through OVMF/GRUB, and the system forwarding
//!   gate.
//! - [`ab_test`] — the A/B boot state-machine scenarios.
//! - [`evidence`] — the manifest, SPDX SBOM, and checksums.
//! - [`host`] — the host-side commands (fast gate, coverage, bench, fuzz, clean).
//! - [`forward_harness`] — the two-port socket-backed forwarding harness.
//! - [`topology`] — the bench read out of the configuration document under test.
//! - [`config_transcript`] — the `LFW-CFG` console channel one boot must carry.
//! - [`clock_contract`] — the clock domain's own record on the `LFW-PD` channel.
//! - [`management_contract`] — the management port's count on the same channel.
//! - [`stamp_contract`] — the instant every record of every channel carries.
//! - [`console_records`] — recovering structured records out of a serial capture.
//! - [`diagnose`] — re-run a failed release scenario on the debug kernel.
//!
//! `main` is only CLI dispatch: it maps a subcommand to the owning stage, and
//! composes the two gates. [`ci`] is the complete pre-push gate, and every
//! end-to-end scenario in it boots the RELEASE configuration — the image a
//! release publishes. [`release`] is that gate plus the guarantee
//! `dist/` never survives a run that failed to prove what it holds; it boots
//! nothing of its own, because there is nothing left for it to prove.

use std::{env, error::Error, fmt, fs, io, path::Path, process::ExitCode};

mod ab_test;
mod artifacts;
mod budgets;
mod channel_contract;
mod clock_contract;
mod config_submission_contract;
mod config_transcript;
mod console_records;
mod crypto_contract;
mod crypto_profile;
mod data_disk;
mod diagnose;
mod dial_contract;
mod disk;
mod evidence;
mod forward_harness;
mod grub;
mod host;
mod image;
mod management_contract;
mod metrics_contract;
mod onboard_contract;
mod onboard_install_contract;
mod onboard_request_contract;
mod onboard_tls_contract;
mod ownership_contract;
mod pins;
mod probe_contract;
mod qemu;
mod recording_contract;
mod reference_contract;
mod reproducible;
mod signing;
mod stamp_contract;
mod store_contract;
mod surface_contract;
mod sysdesc;
mod target_spec;
mod topology;
mod util;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let command = env::args().nth(1).ok_or_else(usage)?;
    if env::args().nth(2).is_some() {
        return Err(usage().into());
    }

    let root = util::workspace_root()?;
    match command.as_str() {
        // The shipping artifact. `image` is what an operator runs to get
        // something deployable, and what a deployment gets is the release
        // configuration — so that is what it builds, with no flag to remember.
        "image" => image::image(&root, image::RELEASE_CONFIG)?,
        // The debug kernel as an explicit opt-in, for hand inspection of a
        // build nothing ships. Nothing in any gate reaches it: `ci` boots
        // release, and the only other thing that compiles this configuration
        // is `host`'s two-configuration PD lint.
        "image-debug" => image::image(&root, image::DEBUG_CONFIG)?,
        "run" => {
            // The DEBUG kernel, deliberately, and the one place that choice is
            // still right: an interactive run is the command whose serial
            // output a human is sitting and reading, so the kernel's own
            // diagnostics (PRINTING, IRQ_REPORTING, the user stack traces) are
            // worth their cost here exactly as they are not in a gate that
            // asserts on machine-observable contracts. Nothing is proved here,
            // so the shipped-profile guarantee is not at stake.
            image::image(&root, image::DEBUG_CONFIG)?;
            qemu::run_system(&root)?;
        }
        "test" => host::test_host(&root)?,
        "coverage" => host::coverage(&root)?,
        "bench" => host::bench(&root)?,
        "fuzz" => host::fuzz(&root)?,
        "verify-reproducible" => reproducible::verify_reproducible(&root)?,
        "test-system" => {
            image::image(&root, image::RELEASE_CONFIG)?;
            println!("system tests passed: {}", qemu::test_system(&root)?);
        }
        "test-ab" => {
            image::image(&root, image::RELEASE_CONFIG)?;
            println!("A/B fallback tests passed: {}", ab_test::test_ab(&root)?);
        }
        "ci" => {
            println!("ci passed: {}", ci(&root)?);
        }
        "release" => release(&root)?,
        "clean" => host::clean(&root)?,
        _ => return Err(usage().into()),
    }
    Ok(())
}

/// The complete pull-request gate: the fast host gate, the fuzz targets, and
/// the assembled RELEASE image proved against the QEMU system and A/B
/// contracts. Returns what those boots proved.
///
/// # Why every end-to-end scenario boots the release configuration
///
/// Because it is the image a release publishes, and the shipped
/// profile must be the tested profile. The arrangement this replaced booted the
/// debug image here and left the release image to `release`, which nothing runs
/// on push — and two consecutive changes shipped defects reachable only in the
/// configuration no gate touched: a console that emitted nothing, because
/// `debug_println!` compiles to a kernel debug syscall the release kernel is
/// not built with; and a Multiboot2 module GRUB placed below 1 MiB, which the
/// debug image survived only by being too large to fit down there.
///
/// It costs nothing in coverage of our own code. `image` passes `--release` to
/// the protection-domain build in both configurations, so there is no debug
/// binary and the Rust compiled here is the Rust that ships; the difference is
/// the seL4 kernel build alone. What it does cost is the debug kernel's serial
/// diagnostics on a failure, and [`diagnose`] buys those back for the one
/// scenario that failed rather than for every scenario that did not.
///
/// # Why the debug image is assembled here and never booted here
///
/// Because [`diagnose`] cannot buy back diagnostics from an image that no
/// longer assembles, and nothing else here would notice that it stopped. It
/// once did stop — a target specification changed, the debug configuration's
/// artifacts were not the ones anybody rebuilt, and every gate stayed green
/// while every failing scenario reported that its re-run never reached a boot.
/// Compiling the domains for the debug kernel, which the two-configuration
/// lint pass already does, is not the same act as assembling and signing a
/// disk from them. So the assembly runs, its output is proved by nothing, and
/// that is the whole point: the diagnostic path is verified to exist before a
/// failure needs it. It is assembled as a scenario disk under the build tree
/// and never published: `dist/` holds the release disk the boots above just
/// judged, and a debug disk written over it would destroy the artifact under
/// judgement.
fn ci(root: &Path) -> Result<String, Box<dyn Error>> {
    host::test_host(root)?;
    host::fuzz(root)?;
    image::image(root, image::RELEASE_CONFIG)?;
    let system = qemu::test_system(root)?;
    let ab = ab_test::test_ab(root)?;
    let diagnostic = image::scenario_image(
        root,
        image::DEBUG_CONFIG,
        Path::new(image::CONFIGURATION_DOCUMENT),
        "diagnostic-path",
    )?;
    Ok(format!(
        "{system}; and {ab}; the diagnostic image a failure would be re-run on assembles, at {}",
        diagnostic.display()
    ))
}

/// Run the full acceptance gate and publish what it proved.
///
/// [`ci`] already assembles the release configuration into `dist/` — manifest,
/// SBOM, checksums and the signed A/B disk — and already boots that disk
/// through every system and A/B scenario. So `release` adds no boot of its
/// own; what it adds is the rule's other half: when the gate did not prove the
/// artifact, `dist/` is emptied rather than left holding an unproven image that
/// looks finished.
///
/// # Why there is nothing left here to prove
///
/// There used to be. `ci` booted the debug image, so the release disk was
/// booted exactly once — here — and the contracts asserted against it were this
/// function's alone. Both of those contracts are now asserted inside `ci`,
/// against the same release disk: the routed contract by every system scenario
/// that boots an owned appliance, the same six frames accounted for as refusals
/// by every A/B scenario that boots a factory-fresh one, and the `LFW-CFG`
/// console transcript by two of the system scenarios (`generation-swap` on the
/// published disk and `alternate-configuration` on a second document's).
/// Re-booting the release disk once more here, to re-assert a subset of what the
/// system and A/B scenarios just asserted, would cost an image build and a QEMU
/// run and establish nothing.
///
/// The emptying covers the whole of [`ci`], not a boot alone: assembly
/// populates `dist/` partway through, so a failure after that point leaves an
/// incomplete release behind exactly as a failed boot leaves an unproven one,
/// and the guarantee does not distinguish the two. A failure *before* assembly is
/// covered for the same reason — `dist/` may still hold a previous build, and
/// a release run that did not prove an artifact must not leave one publishable.
fn release(root: &Path) -> Result<(), Box<dyn Error>> {
    let dist = root.join("dist");
    match ci(root) {
        Ok(proof) => {
            println!(
                "release image proved against the forwarding and console contracts: {proof}; \
                 published in {}",
                dist.display()
            );
            Ok(())
        }
        Err(failure) => Err(discard_dist(&dist, &failure).into()),
    }
}

/// Empty `dist/` after a release attempt that did not prove its artifact, and
/// describe what actually happened to it.
///
/// The returned sentence is the only thing an operator sees, so it may not
/// claim a removal that did not occur. The guarantee is that a
/// failed release leaves no unproven image behind; reporting "discarded" over a
/// directory that is still there states the opposite of the truth and hides the
/// one condition that needs acting on. Each of the three outcomes therefore
/// gets its own wording, and the failed removal names the path and the io error
/// so the operator can clear it by hand.
fn discard_dist(dist: &Path, failure: &dyn fmt::Display) -> String {
    let path = dist.display();
    match fs::remove_dir_all(dist) {
        Ok(()) => {
            format!("the release configuration was not proved, and {path} was discarded: {failure}")
        }
        Err(removal) if removal.kind() == io::ErrorKind::NotFound => format!(
            "the release configuration was not proved; {path} does not exist, so nothing was \
             left to publish: {failure}"
        ),
        Err(removal) => format!(
            "the release configuration was not proved, AND {path} could not be emptied \
             ({removal}); it may still hold the unproven image — remove it by hand before \
             anything publishes it: {failure}"
        ),
    }
}

fn usage() -> String {
    "usage: cargo xtask <image|image-debug|run|test|coverage|bench|fuzz|verify-reproducible\
     |test-system|test-ab|ci|release|clean>"
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A unique, non-existent path under the temp dir. `xtask` carries no
    /// dependencies, so the uniqueness is built from the pid and a counter
    /// rather than from a temp-dir crate.
    fn scratch_path(name: &str) -> std::path::PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "librefirewall-xtask-{name}-{}-{unique}",
            std::process::id()
        ))
    }

    #[test]
    fn a_removed_dist_is_reported_as_discarded() {
        let dist = scratch_path("discard");
        fs::create_dir_all(&dist).unwrap();
        fs::write(dist.join("librefirewall-qemu-x86_64.img"), b"unproven").unwrap();

        let message = discard_dist(&dist, &"the boot never forwarded a frame");

        assert!(!dist.exists(), "the unproven image must not survive");
        assert!(message.contains("was discarded"), "got: {message}");
        assert!(
            message.contains("the boot never forwarded a frame"),
            "the underlying failure is what the operator must fix: {message}"
        );
    }

    #[test]
    fn a_dist_that_cannot_be_emptied_is_never_claimed_to_have_been() {
        // The defect this closes: the removal used to be discarded with `.ok()`
        // while the message asserted the image "was discarded", so a failed
        // removal published an unproven artifact behind a sentence saying it
        // had been deleted. A path that is a file, not a directory, makes
        // `remove_dir_all` fail without needing privileges to arrange.
        let dist = scratch_path("unremovable");
        fs::write(&dist, b"not a directory").unwrap();

        let message = discard_dist(&dist, &"the boot never forwarded a frame");

        assert!(
            dist.exists(),
            "the arrangement under test is a failed removal"
        );
        assert!(
            !message.contains("was discarded"),
            "a removal that did not happen must not be claimed: {message}"
        );
        assert!(
            message.contains("could not be emptied")
                && message.contains("may still hold the unproven image"),
            "the operator must be told what is still there: {message}"
        );
        assert!(
            message.contains(&dist.display().to_string()),
            "the path to clear by hand must be named: {message}"
        );
        assert!(
            message.contains("the boot never forwarded a frame"),
            "the original failure must survive the removal failure: {message}"
        );

        fs::remove_file(&dist).unwrap();
    }

    #[test]
    fn an_absent_dist_is_reported_as_nothing_to_publish() {
        let dist = scratch_path("absent");
        assert!(!dist.exists());

        let message = discard_dist(&dist, &"assembly failed before dist/ was created");

        assert!(
            !message.contains("was discarded") && !message.contains("could not be emptied"),
            "an absent directory was neither removed nor left behind: {message}"
        );
        assert!(
            message.contains("nothing was left to publish"),
            "got: {message}"
        );
    }
}
