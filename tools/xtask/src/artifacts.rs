//! Names of the deployable artifacts written to `dist/`.
//!
//! Centralised so image assembly, disk writing, and the manifest/checksum
//! evidence all name the same files: the manifest and the checksums must list
//! exactly the artifacts the build produces, so a single owner of these names
//! keeps the three stages from drifting apart.

pub(crate) const DIST_KERNEL: &str = "librefirewall-kernel.elf";
pub(crate) const DIST_SYSTEM: &str = "librefirewall-system.img";
pub(crate) const DIST_REPORT: &str = "librefirewall-microkit-report.txt";
pub(crate) const DIST_MANIFEST: &str = "librefirewall-manifest.json";
pub(crate) const DIST_SBOM: &str = "librefirewall-sbom.spdx.json";
pub(crate) const DIST_CHECKSUMS: &str = "librefirewall-checksums.sha256";
pub(crate) const DIST_DISK: &str = "librefirewall-qemu-x86_64.img";
