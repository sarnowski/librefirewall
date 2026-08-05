//! Artifacts are reused only while the target specification they were compiled
//! against is still the one on disk.
//!
//! Cargo fingerprints the compiler, the profile, the enabled features and every
//! source file it reads. It does not fingerprint a JSON target specification, so
//! a `--target x86_64-sel4-simd` build whose specification was edited since the
//! last one is reported up to date and links object code compiled under the old
//! one. That is not a theoretical cost: withdrawing a target feature once left an
//! artifact directory holding third-party objects that still used it, and the
//! image built from that directory was refused by the disassembly check — a build
//! that had to be explained instead of one that explained itself.
//!
//! Keying the invalidation on the specification rather than on either symptom is
//! what covers both directions. A specification that *withdraws* a feature leaves
//! instructions in the binary, and [`crate::crypto_profile::check_image`] reads
//! them back out of it — the direction the cost above was paid in. A
//! specification that *gains* one leaves a binary quietly missing the
//! acceleration it was edited to obtain, and nothing looks for an absence nobody
//! named.
//!
//! [`reconcile`] therefore records the specification text beside the artifacts it
//! produced and compares the two before every build that could reuse them. A
//! mismatch — or an artifact directory recording nothing at all — discards that
//! directory and says so; an agreement is silent, so the mechanism costs a warm
//! build nothing. The record is the specification itself rather than a digest of
//! it: it is a couple of dozen lines, an exact comparison needs no collision
//! argument, and it lets the discard name the lines that moved.
//!
//! The unit is one target's own directory, because that is exactly what a target
//! specification decides. A build directory holding both seL4 targets loses only
//! the half whose specification moved; the host-side build scripts and procedural
//! macros beside them are compiled against neither and are never touched. That
//! matters for more than speed in the debug configuration, where the image
//! build's directory is also where the host dev profile writes.
//!
//! A cache may accelerate a build; it may never decide one.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::util::{Error, recreate_dir};

/// Where the JSON target specifications live, relative to the workspace root:
/// the directory `RUST_TARGET_PATH` points cargo at, because a specification
/// this module compares and one the compiler loads have to be the same file.
const DIRECTORY: &str = "support/targets";

/// The file recording, inside a target's own artifact directory, the
/// specification text those artifacts were compiled against.
///
/// It sits inside the directory it describes, so discarding those artifacts
/// discards the record with them and no record can outlive what it was written
/// about.
const RECORD: &str = ".target-specification";

/// The workspace-relative path of one target's JSON specification. The single
/// owner of where a specification lives.
pub(crate) fn specification(target: &str) -> PathBuf {
    Path::new(DIRECTORY).join(format!("{target}.json"))
}

/// Discard `target_dir`'s artifacts for `target` unless they were compiled
/// against the specification now on disk, then record that specification for the
/// build about to run.
///
/// Call it before every cargo invocation naming a JSON target, with the
/// `CARGO_TARGET_DIR` that invocation will use.
///
/// # Errors
/// The specification cannot be read — every caller names a target this workspace
/// carries a JSON file for, and a build that cannot read one is a build about to
/// reuse artifacts against nothing — or the artifact directory cannot be
/// replaced.
pub(crate) fn reconcile(root: &Path, target_dir: &Path, target: &str) -> Result<(), Error> {
    let path = root.join(specification(target));
    let current = fs::read_to_string(&path)
        .map_err(|error| Error::io("read the target specification", &path, error))?;
    let artifacts = target_dir.join(target);

    match recorded(&artifacts)? {
        Some(recorded) if recorded == current => return Ok(()),
        Some(recorded) => {
            println!(
                "{target}: the specification changed since {} was built, and cargo does not \
                 fingerprint it — discarding those artifacts rather than linking object code \
                 compiled against the old one{}",
                artifacts.display(),
                changed_lines(&recorded, &current)
            );
            recreate_dir(&artifacts)?;
        }
        None if artifacts.exists() => {
            println!(
                "{target}: {} records no specification, so nothing says which one its artifacts \
                 were compiled against — discarding them, because a cache may accelerate a build \
                 and never decide one",
                artifacts.display()
            );
            recreate_dir(&artifacts)?;
        }
        None => {
            fs::create_dir_all(&artifacts)
                .map_err(|error| Error::io("create", &artifacts, error))?;
        }
    }

    let record = artifacts.join(RECORD);
    fs::write(&record, &current).map_err(|error| Error::io("write", &record, error))
}

/// The specification `artifacts` records having been compiled against, or `None`
/// where it records none — a directory nothing has built yet, or one built before
/// any record was kept, which is the same unanswerable question either way.
fn recorded(artifacts: &Path) -> Result<Option<String>, Error> {
    let record = artifacts.join(RECORD);
    match fs::read_to_string(&record) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::io(
            "read the recorded target specification",
            &record,
            error,
        )),
    }
}

/// The lines that differ, rendered to follow the discard message.
///
/// Empty when the two texts differ without any line differing — a reordering, or
/// a change in trailing whitespace — so the message is never followed by a claim
/// with nothing under it.
fn changed_lines(recorded: &str, current: &str) -> String {
    let before: Vec<&str> = recorded.lines().collect();
    let after: Vec<&str> = current.lines().collect();
    let mut rendered = String::new();
    for line in before.iter().filter(|line| !after.contains(line)) {
        rendered.push_str("\n  - was: ");
        rendered.push_str(line.trim());
    }
    for line in after.iter().filter(|line| !before.contains(line)) {
        rendered.push_str("\n  + now: ");
        rendered.push_str(line.trim());
    }
    rendered
}

#[cfg(test)]
mod tests;
