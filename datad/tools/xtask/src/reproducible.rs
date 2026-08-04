//! `verify-reproducible`: build the image twice from scratch and prove the
//! deployable boot payload is byte-identical.
//!
//! It builds the RELEASE configuration, because the claim worth making is about
//! the artifact that ships: a payload nothing deploys reproducing bit for bit
//! is evidence about a build nobody runs.
//!
//! Only the loose boot payload — the seL4 kernel and the Microkit system image
//! — is compared. It carries no signature, key, or SBOM timestamp, so it must
//! reproduce exactly from the same pinned inputs (and empirically does, even
//! across a wiped build tree). The signed disk, manifest, SBOM, and checksums
//! are deliberately excluded: the development signatures embed a per-build GPG
//! creation time and syft stamps each SBOM with a fresh document id, so those
//! artifacts differ between builds by design of the dev trust anchor and the
//! SBOM tool, not because the build is non-deterministic. Once deterministic
//! release signing exists, the signed disk can join the compared set.

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    artifacts::{DIST_KERNEL, DIST_SYSTEM},
    image::{self, RELEASE_CONFIG},
    util::{Error, copy_file, recreate_dir},
};

/// The artifacts compared for byte-identity: the loose boot payload only.
const REPRODUCIBLE_ARTIFACTS: &[&str] = &[DIST_KERNEL, DIST_SYSTEM];

/// Build the image twice from scratch and prove the boot payload is
/// byte-identical across the two builds.
pub(crate) fn verify_reproducible(root: &Path) -> Result<(), Error> {
    let scratch = root.join("build/image/reproducible");
    recreate_dir(&scratch)?;

    let first = build_and_capture(root, &scratch, "a")?;
    let second = build_and_capture(root, &scratch, "b")?;

    let mut diffs = Vec::new();
    for name in REPRODUCIBLE_ARTIFACTS {
        let a = fs::read(first.join(name))
            .map_err(|error| Error::io("read build a's", &first.join(name), error))?;
        let b = fs::read(second.join(name))
            .map_err(|error| Error::io("read build b's", &second.join(name), error))?;
        if a == b {
            println!(
                "verify-reproducible: {name} reproduced byte-for-byte ({} bytes)",
                a.len()
            );
        } else {
            diffs.push(format!(
                "  {name}: build a is {} bytes, build b is {} bytes",
                a.len(),
                b.len()
            ));
        }
    }

    if diffs.is_empty() {
        println!(
            "verify-reproducible: all {} deployable payload artifact(s) are byte-identical \
             across two isolated builds",
            REPRODUCIBLE_ARTIFACTS.len()
        );
        Ok(())
    } else {
        Err(Error::invalid(format!(
            "verify-reproducible: {} artifact(s) did not reproduce:\n{}",
            diffs.len(),
            diffs.join("\n")
        )))
    }
}

/// Build the image from a wiped per-config target tree (forcing a genuine
/// recompile and repackage rather than reusing cached outputs) and copy the
/// compared artifacts out of `dist/` into `scratch/<tag>`.
fn build_and_capture(root: &Path, scratch: &Path, tag: &str) -> Result<PathBuf, Error> {
    recreate_dir(&root.join("target").join(RELEASE_CONFIG))?;
    image::image(root, RELEASE_CONFIG)?;

    let out = scratch.join(tag);
    recreate_dir(&out)?;
    for name in REPRODUCIBLE_ARTIFACTS {
        copy_file(&root.join("dist").join(name), &out.join(name))?;
    }
    Ok(out)
}
