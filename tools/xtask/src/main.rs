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
//! The orchestration is split by concern, each stage in its own module:
//!
//! - [`sysdesc`] — the system description held to the constants the PDs map it
//!   with.
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
//!
//! `main` is only CLI dispatch: it maps a subcommand to the owning stage, and
//! composes the two gates — [`ci`] is the complete pull-request gate, and
//! `release` is that gate plus an acceptance run of the release configuration
//! itself.

use std::{env, error::Error, fmt, fs, io, path::Path, process::ExitCode};

mod ab_test;
mod artifacts;
mod budgets;
mod disk;
mod evidence;
mod forward_harness;
mod grub;
mod host;
mod image;
mod pins;
mod qemu;
mod reproducible;
mod signing;
mod sysdesc;
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
        "image" => image::image(&root, image::DEBUG_CONFIG)?,
        "run" => {
            image::image(&root, image::DEBUG_CONFIG)?;
            qemu::run_system(&root)?;
        }
        "test" => host::test_host(&root)?,
        "coverage" => host::coverage(&root)?,
        "bench" => host::bench(&root)?,
        "fuzz" => host::fuzz(&root)?,
        "verify-reproducible" => reproducible::verify_reproducible(&root)?,
        "test-system" => {
            image::image(&root, image::DEBUG_CONFIG)?;
            qemu::test_system(&root)?;
        }
        "test-ab" => {
            image::image(&root, image::DEBUG_CONFIG)?;
            ab_test::test_ab(&root)?;
        }
        "ci" => ci(&root)?,
        "release" => release(&root)?,
        "clean" => host::clean(&root)?,
        _ => return Err(usage().into()),
    }
    Ok(())
}

/// The complete pull-request gate: the fast host gate, the fuzz targets, and
/// the assembled debug image proved against the QEMU system and A/B contracts.
fn ci(root: &Path) -> Result<(), Box<dyn Error>> {
    host::test_host(root)?;
    host::fuzz(root)?;
    image::image(root, image::DEBUG_CONFIG)?;
    qemu::test_system(root)?;
    ab_test::test_ab(root)?;
    Ok(())
}

/// Run the full acceptance gate and then assemble *and prove* the release
/// configuration.
///
/// The release configuration is a different kernel build from the one [`ci`]
/// exercises, so passing the gate on the debug image says nothing about it.
/// Publishing an artifact no test has booted is how a broken release ships, so
/// the release disk must satisfy the same forwarding contract before it counts
/// as a release; when it does not, `dist/` is emptied rather than left holding
/// an unproven image that looks finished.
///
/// The emptying covers the *whole* of [`prove_release_configuration`], not the
/// boot alone: assembly populates `dist/` partway through, so a failure after
/// that point leaves an incomplete release behind exactly as a failed boot
/// leaves an unproven one, and BLD-3 does not distinguish the two.
fn release(root: &Path) -> Result<(), Box<dyn Error>> {
    ci(root)?;
    let dist = root.join("dist");
    match prove_release_configuration(root, &dist) {
        Ok(traffic) => {
            println!("release image proved against the forwarding contract: {traffic} as required");
            Ok(())
        }
        Err(failure) => Err(discard_dist(&dist, &failure).into()),
    }
}

/// Assemble the release configuration into `dist/` and hold the disk it
/// produced to the forwarding contract, returning what that boot moved. A
/// release that says only "proved" cannot be told from one whose contract had
/// grown empty; the counts say how much traffic the claim rests on.
fn prove_release_configuration(root: &Path, dist: &Path) -> Result<String, Box<dyn Error>> {
    image::image(root, image::RELEASE_CONFIG)?;
    let booted =
        qemu::boot_and_forward(root, &dist.join(artifacts::DIST_DISK), "qemu-release.log")?;
    Ok(booted.traffic.summary())
}

/// Empty `dist/` after a release attempt that did not prove its artifact, and
/// describe what actually happened to it.
///
/// The returned sentence is the only thing an operator sees, so it may not
/// claim a removal that did not occur (ENG-12). BLD-3's guarantee is that a
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
    "usage: cargo xtask \
     <image|run|test|coverage|bench|fuzz|verify-reproducible|test-system|test-ab|ci|release|clean>"
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
