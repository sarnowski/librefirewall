//! librefirewall build & release orchestrator.
//!
//! `xtask` is the single Rust entry point behind the `Makefile`: it builds the
//! protection-domain binaries for the seL4 target, assembles them into the
//! Microkit kernel/system pair, packages a signed A/B GPT disk, and boots that
//! disk in QEMU to assert the system's observable contracts. It is a
//! zero-dependency `std` binary so the bootstrap tooling stays auditable and
//! builds offline inside the pinned container.
//!
//! The orchestration is split by concern, each stage in its own module:
//!
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

use std::{env, error::Error, fs, path::Path, process::ExitCode};

mod ab_test;
mod artifacts;
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
fn release(root: &Path) -> Result<(), Box<dyn Error>> {
    ci(root)?;
    image::image(root, image::RELEASE_CONFIG)?;

    let dist = root.join("dist");
    let disk = dist.join(artifacts::DIST_DISK);
    if let Err(error) = qemu::boot_and_forward(root, &disk, "qemu-release.log") {
        fs::remove_dir_all(&dist).ok();
        return Err(format!(
            "the release-configuration image failed the forwarding contract and was \
             discarded: {error}"
        )
        .into());
    }
    println!("release image proved against the forwarding contract");
    Ok(())
}

fn usage() -> String {
    "usage: cargo xtask \
     <image|run|test|coverage|bench|fuzz|verify-reproducible|test-system|test-ab|ci|release|clean>"
        .to_owned()
}
