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
//! `main` is only CLI dispatch: it maps a subcommand to the owning stage.

// Binary crate: no library API to document.
#![allow(missing_docs)]

use std::{env, process::ExitCode};

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

fn run() -> Result<(), String> {
    let command = env::args().nth(1).ok_or_else(usage)?;
    if env::args().nth(2).is_some() {
        return Err(usage());
    }

    let root = util::workspace_root()?;
    match command.as_str() {
        "image" => image::image(&root, image::DEBUG_CONFIG),
        "run" => {
            image::image(&root, image::DEBUG_CONFIG)?;
            qemu::run_system(&root)
        }
        // `test` and `test-host` are the same fast host gate.
        "test" | "test-host" => host::test_host(&root),
        "coverage" => host::coverage(&root),
        "bench" => host::bench(&root),
        "fuzz" => host::fuzz(&root),
        "verify-reproducible" => reproducible::verify_reproducible(&root),
        "test-system" => {
            image::image(&root, image::DEBUG_CONFIG)?;
            qemu::test_system(&root)
        }
        "test-ab" => {
            image::image(&root, image::DEBUG_CONFIG)?;
            ab_test::test_ab(&root)
        }
        "ci" => {
            host::test_host(&root)?;
            image::image(&root, image::DEBUG_CONFIG)?;
            qemu::test_system(&root)?;
            ab_test::test_ab(&root)
        }
        "release" => {
            host::test_host(&root)?;
            image::image(&root, image::DEBUG_CONFIG)?;
            qemu::test_system(&root)?;
            ab_test::test_ab(&root)?;
            image::image(&root, image::RELEASE_CONFIG)
        }
        "clean" => host::clean(&root),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    // `test` and `test-host` are aliases for the same fast host gate.
    "usage: cargo xtask <image|run|test|test-host|coverage|bench|fuzz|verify-reproducible|test-system|test-ab|ci|release|clean>"
        .to_owned()
}
