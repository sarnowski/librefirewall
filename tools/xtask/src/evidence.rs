//! Release evidence: the manifest, the SPDX SBOM, and the checksums.
//!
//! Every image build emits, alongside the deployable artifacts, the provenance
//! a consumer needs to trust them: a manifest describing the target, boot
//! scheme, and signing trust profile (recording `development` and the dev-key
//! fingerprint so a dev-signed image is never mistaken for production), an SPDX
//! 2.3 SBOM produced by syft, and sha256 checksums over the artifact set.

use std::{path::Path, process::Command};

use crate::{
    artifacts::{
        DIST_CHECKSUMS, DIST_DISK, DIST_KERNEL, DIST_MANIFEST, DIST_REPORT, DIST_SBOM, DIST_SYSTEM,
    },
    image::{BOARD, TARGET},
    pins::Pins,
    util::run_command,
};

pub(crate) fn write_manifest(
    dist: &Path,
    config: &str,
    key_fingerprint: &str,
    pins: &Pins,
) -> Result<(), String> {
    let manifest = format!(
        concat!(
            "{{\n",
            "  \"format\": 2,\n",
            "  \"target\": \"{}\",\n",
            "  \"microkit\": {{\"version\": \"{}\", \"board\": \"{}\", \"config\": \"{}\"}},\n",
            "  \"rust_sel4\": {{\"version\": \"{}\"}},\n",
            "  \"boot\": {{\"manager\": \"grub\", \"grub_version\": \"{}\", \"scheme\": \"ab\", \"secure_boot\": false}},\n",
            "  \"signing\": {{\"trust_profile\": \"development\", \"key_fingerprint\": \"{}\"}},\n",
            "  \"disk\": {{\"image\": \"{}\", \"table\": \"gpt\", \"slots\": [\"SLOTA\", \"SLOTB\"]}},\n",
            "  \"artifacts\": [\"{}\", \"{}\", \"{}\", \"{}\", \"{}\"]\n",
            "}}\n"
        ),
        TARGET,
        pins.microkit_version,
        BOARD,
        config,
        pins.rust_sel4_version,
        pins.grub_version,
        key_fingerprint,
        DIST_DISK,
        DIST_DISK,
        DIST_KERNEL,
        DIST_SYSTEM,
        DIST_REPORT,
        DIST_SBOM
    );
    std::fs::write(dist.join(DIST_MANIFEST), manifest)
        .map_err(|error| format!("write manifest: {error}"))
}

pub(crate) fn write_sbom(root: &Path, dist: &Path) -> Result<(), String> {
    let sbom = dist.join(DIST_SBOM);
    run_command(
        Command::new("syft")
            .current_dir(root)
            .args([
                "scan",
                "dir:.",
                "--exclude",
                "./build",
                "--exclude",
                "./dist",
                "--exclude",
                "./target",
                "--source-name",
                "librefirewall",
                "--source-version",
                env!("CARGO_PKG_VERSION"),
                "--output",
            ])
            .arg(format!("spdx-json={}", sbom.display())),
        "generate SPDX SBOM",
    )?;

    run_command(
        Command::new("python3")
            .arg("-c")
            .arg(concat!(
                "import json,sys; ",
                "document=json.load(open(sys.argv[1], encoding='utf-8')); ",
                "assert document['spdxVersion']=='SPDX-2.3'; ",
                "assert document['packages']"
            ))
            .arg(&sbom),
        "validate SPDX 2.3 SBOM",
    )
}

pub(crate) fn write_checksums(dist: &Path) -> Result<(), String> {
    let artifacts = [
        DIST_DISK,
        DIST_KERNEL,
        DIST_SYSTEM,
        DIST_MANIFEST,
        DIST_REPORT,
        DIST_SBOM,
    ];
    let output = Command::new("sha256sum")
        .current_dir(dist)
        .args(artifacts)
        .output()
        .map_err(|error| format!("run sha256sum: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "sha256sum failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    std::fs::write(dist.join(DIST_CHECKSUMS), output.stdout)
        .map_err(|error| format!("write {DIST_CHECKSUMS}: {error}"))
}
