//! seL4/Microkit image assembly — the `image` command.
//!
//! Builds the two protection-domain ELFs for the seL4 target, assembles them
//! with the Microkit tool into the kernel/system pair, copies that pair into
//! `dist/` as the update input, then hands off to [`crate::disk`] to produce the
//! signed A/B GPT disk and to [`crate::evidence`] for the manifest, SBOM, and
//! checksums.
//!
//! [`verify_inputs`] gates the build on the pinned toolchain *before* anything
//! is compiled, so a mismatched builder fails early and by name rather than deep
//! inside the toolchain — and so the versions the manifest records as provenance
//! are the versions that actually produced the image. Every pinned input the
//! manifest names is checked: an unverified provenance field is a claim, not
//! evidence.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    artifacts::{
        BUILD_KERNEL_IMAGE, BUILD_MICROKIT_REPORT, BUILD_SYSTEM_IMAGE, DIST_KERNEL, DIST_SYSTEM,
    },
    disk, evidence, grub,
    pins::{self, Pins},
    util::{Error, copy_file, recreate_dir, run_command},
};

pub(crate) const TARGET: &str = "x86_64-sel4-minimal";
pub(crate) const BOARD: &str = "x86_64_generic";
pub(crate) const DEBUG_CONFIG: &str = "debug";
pub(crate) const RELEASE_CONFIG: &str = "release";
const MICROKIT_SDK: &str = "/opt/microkit";
const RUST_SEL4: &str = "/opt/rust-sel4";

const SYSTEM_DESCRIPTION: &str = "systems/qemu-x86_64/librefirewall.system";
/// Protection-domain binaries the system image is assembled from.
///
/// The single owner of that list: [`crate::host::test_host`] lints exactly these
/// packages for the seL4 target, so a PD added here is linted by the same edit
/// that makes it shippable and cannot slip through unlinted.
pub(crate) const SYSTEM_PDS: &[&str] = &["nic-driver", "forwarder"];

/// The pinned SDK's include directory for one seL4 kernel configuration.
///
/// These headers are what `sel4-sys` generates its bindings from and what
/// `sel4-config` derives every `sel4_cfg` flag from, so they — not the Cargo
/// profile — are what makes a protection-domain compilation
/// configuration-specific. Exposed so the PD lint compiles the PDs against the
/// same headers the image build does, rather than restating the SDK's layout.
pub(crate) fn board_include_dir(config: &str) -> PathBuf {
    Path::new(MICROKIT_SDK)
        .join("board")
        .join(BOARD)
        .join(config)
        .join("include")
}

/// Build the protection domains, assemble the Microkit image, and package the
/// signed A/B disk and its release evidence into `dist/`.
///
/// `config` selects the *Microkit/seL4 kernel* configuration (`debug` or
/// `release`), not a Cargo profile — see the note on the PD build below.
pub(crate) fn image(root: &Path, config: &str) -> Result<(), Error> {
    let pins = pins::read(root)?;
    verify_inputs(config, &pins)?;

    let build = root.join("build/image").join(config);
    let dist = root.join("dist");
    recreate_dir(&build)?;
    recreate_dir(&dist)?;

    let target_root = root.join("target").join(config);
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .env("SEL4_INCLUDE_DIRS", board_include_dir(config))
            .env("CARGO_TARGET_DIR", &target_root)
            .args([
                "build",
                "--locked",
                // Always the optimized Cargo profile, in every `config`. The
                // `debug`/`release` distinction here is the seL4 KERNEL
                // configuration (debug serial output and kernel assertions),
                // which is orthogonal to how the PDs are compiled. The PDs are
                // the dataplane and must be optimized in any configuration a
                // forwarding test is meaningful in; they are also `no_std`
                // binaries that depend on this profile's `panic = "abort"`,
                // there being no unwinder under seL4.
                "--release",
                "-Z",
                "build-std=core",
                // The dataplane copies bytes into pool buffers, which lowers to
                // the mem* intrinsics; have compiler-builtins provide them since
                // there is no libc under seL4.
                "-Z",
                "build-std-features=compiler-builtins-mem",
                "--target",
                TARGET,
            ])
            .args(SYSTEM_PDS.iter().flat_map(|pd| ["-p", pd])),
        "build protection domains",
    )?;

    let target_dir = target_root.join(TARGET).join("release");
    for pd in SYSTEM_PDS {
        let elf = format!("{pd}.elf");
        copy_file(&target_dir.join(&elf), &build.join(&elf))?;
    }

    run_command(
        Command::new(Path::new(MICROKIT_SDK).join("bin/microkit"))
            .current_dir(root)
            .arg(root.join(SYSTEM_DESCRIPTION))
            .arg("--search-path")
            .arg(&build)
            .args(["--board", BOARD, "--config", config, "-o"])
            .arg(build.join(BUILD_SYSTEM_IMAGE))
            .arg("-r")
            // The capability/memory report is build-internal debugging
            // evidence and a full disclosure of the system's authority
            // topology; it stays out of the published artifact set.
            .arg(build.join(BUILD_MICROKIT_REPORT)),
        "assemble Microkit image",
    )?;

    // The loose kernel/system pair is published as the update input; the disk
    // below is the deployable artifact. The 32-bit kernel ELF is the Multiboot2
    // image GRUB boots (its entry is a 32-bit trampoline; the 64-bit sel4.elf
    // shares the same entry but the 32-bit image is what both QEMU and GRUB
    // load).
    copy_file(&build.join(BUILD_KERNEL_IMAGE), &dist.join(DIST_KERNEL))?;
    copy_file(&build.join(BUILD_SYSTEM_IMAGE), &dist.join(DIST_SYSTEM))?;

    let fingerprint = disk::assemble_disk(root, &build, &dist)?;

    evidence::write_manifest(&dist, config, &fingerprint, &pins)?;
    evidence::write_sbom(root, &dist)?;
    evidence::write_checksums(&dist)?;
    println!("packaged boot artifacts in {}", dist.display());
    Ok(())
}

/// Verify, before anything is compiled, that the builder holds the pinned
/// toolchain this build claims to use, and that the SDK pieces the assembly
/// consumes are present.
///
/// This establishes *identity by version*: every pin the manifest goes on to
/// record as provenance is checked against the installed input, so no field in
/// that manifest is an unchecked claim. It does not establish *integrity of
/// content* — the sha256 pins in `sources.lock` are verified when the builder
/// image fetches each archive, and the archives do not survive into the running
/// container for xtask to re-check.
fn verify_inputs(config: &str, pins: &Pins) -> Result<(), Error> {
    verify_version(
        &Path::new(RUST_SEL4).join("VERSION"),
        &pins.rust_sel4_version,
        "rust-sel4",
    )?;
    verify_version(
        &Path::new(MICROKIT_SDK).join("VERSION"),
        &pins.microkit_version,
        "Microkit SDK",
    )?;
    // GRUB is built from source into the builder rather than unpacked, so it
    // carries no VERSION file; ask the tool that will build the boot base. The
    // manifest records this version as provenance, and provenance nothing
    // checks is just a claim.
    grub::installed_version(&pins.grub_version)?;
    crate::util::require_file(&Path::new(MICROKIT_SDK).join("bin/microkit"))?;
    crate::util::require_file(
        &Path::new(MICROKIT_SDK)
            .join("board")
            .join(BOARD)
            .join(config)
            .join("elf")
            .join(BUILD_KERNEL_IMAGE),
    )
}

fn verify_version(path: &Path, expected: &str, name: &str) -> Result<(), Error> {
    let actual = std::fs::read_to_string(path)
        .map_err(|error| Error::io(&format!("read the pinned {name}"), path, error))?;
    if actual.trim() != expected {
        return Err(Error::invalid(format!(
            "{name} at {} has version {:?}, expected {expected:?}",
            path.display(),
            actual.trim()
        )));
    }
    Ok(())
}
