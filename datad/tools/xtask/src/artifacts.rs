//! The single owner of build- and release-artifact names.
//!
//! Image assembly, disk writing, signing, and the manifest/checksum evidence
//! must all name the same files. [`DIST_ARTIFACTS`] is the authoritative set of
//! what a build publishes: the manifest's artifact list and the checksum file
//! are both derived from it, so the two can never drift from each other or from
//! what is actually written.
//!
//! `dist/` holds only deployable outputs and the evidence that describes
//! them. Build-internal products — the Microkit
//! capability/memory report, the intermediate partition images, the development
//! keyring — stay under `build/`: the report in particular is a full disclosure
//! of the capability and memory topology and is debugging evidence, not
//! something a release ships.

/// The seL4 kernel ELF: the 32-bit Multiboot2 image GRUB loads.
pub(crate) const DIST_KERNEL: &str = "librefirewall-kernel.elf";
/// The Microkit system image: the `module2` payload loaded beside the kernel.
pub(crate) const DIST_SYSTEM: &str = "librefirewall-system.img";
/// Provenance for the artifacts: target, pinned inputs, boot scheme, trust.
pub(crate) const DIST_MANIFEST: &str = "librefirewall-manifest.json";
/// SPDX 2.3 software bill of materials.
pub(crate) const DIST_SBOM: &str = "librefirewall-sbom.spdx.json";
/// SHA-256 over every other published artifact.
pub(crate) const DIST_CHECKSUMS: &str = "librefirewall-checksums.sha256";
/// The deployable artifact: the signed GPT A/B disk.
pub(crate) const DIST_DISK: &str = "librefirewall-qemu-x86_64.img";

/// Everything a build publishes into `dist/`, in the order the manifest lists
/// it. [`crate::evidence`] derives both the manifest's artifact array and the
/// checksum file from this one slice; nothing else may enumerate `dist/`.
pub(crate) const DIST_ARTIFACTS: &[&str] = &[
    DIST_DISK,
    DIST_KERNEL,
    DIST_SYSTEM,
    DIST_MANIFEST,
    DIST_SBOM,
    DIST_CHECKSUMS,
];

/// The Microkit system image inside the build tree. On x86_64 the kernel and
/// the system image are two separate ELFs loaded by a Multiboot2 bootloader,
/// so this is the `module2` payload — not an Arm-style self-contained loader.
pub(crate) const BUILD_SYSTEM_IMAGE: &str = "system.img";
/// The 32-bit seL4 kernel image the Microkit tool emits beside the system
/// image; its entry point is the Multiboot2 trampoline GRUB and QEMU load.
pub(crate) const BUILD_KERNEL_IMAGE: &str = "sel4_32.elf";
/// The Microkit capability/memory report: build-internal debugging evidence,
/// deliberately not published (see the module header).
pub(crate) const BUILD_MICROKIT_REPORT: &str = "report.txt";

/// The throwaway development signing keyring, relative to the workspace root.
/// Generated once per checkout, never committed, removed by `clean`.
pub(crate) const BUILD_DEV_KEY_DIR: &str = "build/dev-keys";
/// The exported development public key: signed payloads are verified against
/// it and it is embedded into the GRUB core image, so the same file is the
/// single trust anchor on both sides.
pub(crate) const DEV_PUBLIC_KEY: &str = "librefirewall-dev-pub.gpg";
