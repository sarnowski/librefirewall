//! seL4/Microkit image assembly — the `image` command.
//!
//! Builds the two protection-domain ELFs for the seL4 target, assembles them
//! with the Microkit tool into the kernel/system pair, copies that pair into
//! `dist/` as the update input and debugging evidence, then hands off to
//! [`crate::disk`] to produce the signed A/B GPT disk and to [`crate::evidence`]
//! for the manifest, SBOM, and checksums. [`verify_inputs`] gates the build on
//! the pinned SDK/rust-sel4 versions so a mismatched builder fails early and
//! by name rather than deep inside the toolchain.

use std::{path::Path, process::Command};

use crate::{
    artifacts::{DIST_KERNEL, DIST_REPORT, DIST_SYSTEM},
    disk, evidence,
    util::{copy_file, recreate_dir, run_command},
};

pub(crate) const TARGET: &str = "x86_64-sel4-minimal";
pub(crate) const BOARD: &str = "x86_64_generic";
pub(crate) const DEBUG_CONFIG: &str = "debug";
pub(crate) const RELEASE_CONFIG: &str = "release";
const MICROKIT_SDK: &str = "/opt/microkit";
const RUST_SEL4: &str = "/opt/rust-sel4";
pub(crate) const RUST_SEL4_VERSION: &str = "5.0.0";
pub(crate) const MICROKIT_VERSION: &str = "2.3.0";

const SYSTEM_DESCRIPTION: &str = "systems/qemu-x86_64/librefirewall.system";
/// Protection-domain binaries the system image is assembled from.
const SYSTEM_PDS: &[&str] = &["nic-driver", "forwarder"];

pub(crate) fn image(root: &Path, config: &str) -> Result<(), String> {
    verify_inputs(config)?;

    let build = root.join("build/image").join(config);
    let dist = root.join("dist");
    recreate_dir(&build)?;
    recreate_dir(&dist)?;

    let board_dir = Path::new(MICROKIT_SDK)
        .join("board")
        .join(BOARD)
        .join(config);
    let target_root = root.join("target").join(config);
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .env("SEL4_INCLUDE_DIRS", board_dir.join("include"))
            .env("CARGO_TARGET_DIR", &target_root)
            .args([
                "build",
                "--locked",
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
            .arg(build.join("loader.img"))
            .arg("-r")
            .arg(build.join("report.txt")),
        "assemble Microkit image",
    )?;

    // The loose kernel/system pair stays in dist as the update input and as
    // debugging evidence; the disk below is the deployable artifact. The 32-bit
    // kernel ELF is the Multiboot2 image GRUB boots (its entry is a 32-bit
    // trampoline; the 64-bit sel4.elf shares the same entry but the 32-bit image
    // is what both QEMU and GRUB load).
    copy_file(&build.join("sel4_32.elf"), &dist.join(DIST_KERNEL))?;
    copy_file(&build.join("loader.img"), &dist.join(DIST_SYSTEM))?;
    copy_file(&build.join("report.txt"), &dist.join(DIST_REPORT))?;

    let fingerprint = disk::assemble_disk(root, &build, &dist)?;

    evidence::write_manifest(&dist, config, &fingerprint)?;
    evidence::write_sbom(root, &dist)?;
    evidence::write_checksums(&dist)?;
    println!("packaged boot artifacts in {}", dist.display());
    Ok(())
}

fn verify_inputs(config: &str) -> Result<(), String> {
    verify_version(
        &Path::new(RUST_SEL4).join("VERSION"),
        RUST_SEL4_VERSION,
        "rust-sel4",
    )?;
    verify_version(
        &Path::new(MICROKIT_SDK).join("VERSION"),
        MICROKIT_VERSION,
        "Microkit SDK",
    )?;
    crate::util::require_file(&Path::new(MICROKIT_SDK).join("bin/microkit"))?;
    crate::util::require_file(
        &Path::new(MICROKIT_SDK)
            .join("board")
            .join(BOARD)
            .join(config)
            .join("elf/sel4_32.elf"),
    )
}

fn verify_version(path: &Path, expected: &str, name: &str) -> Result<(), String> {
    let actual = std::fs::read_to_string(path)
        .map_err(|error| format!("required {name} input {}: {error}", path.display()))?;
    if actual.trim() != expected {
        return Err(format!(
            "{name} at {} has version {:?}, expected {expected:?}",
            path.display(),
            actual.trim()
        ));
    }
    Ok(())
}
