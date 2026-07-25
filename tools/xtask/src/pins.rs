//! The pinned upstream versions, read from `third-party/sources.lock`.
//!
//! `sources.lock` is the single source of truth for every pinned input: the
//! `Makefile` includes it as make variables and the builder `Containerfile`
//! sources it as shell variables. xtask parses the same file at build time
//! rather than restating the versions as consts, so a bumped pin cannot drift
//! from the value the container was built against.
//!
//! The file is a flat `KEY=value` list (valid as both make and shell), with
//! `#` comments and blank lines.
//!
//! Because three different readers interpret this file, a key that appears
//! twice would not mean the same thing to all of them — make and shell both
//! take the *last* assignment, and any parser that took the first would
//! silently build against a different pin than the container was built with.
//! A duplicate is therefore rejected rather than resolved.

use std::{collections::BTreeMap, fs, path::Path};

use crate::util::Error;

/// The pinned versions xtask needs: to gate the builder in
/// [`crate::image`]'s `verify_inputs` and to record provenance in the manifest.
#[derive(Debug)]
pub(crate) struct Pins {
    /// rust-sel4 version, with the source tag's leading `v` stripped: the tag
    /// is `v5.0.0` but the SDK's on-disk `VERSION` file and the manifest carry
    /// the bare `5.0.0`, so this is the form both compare against.
    pub(crate) rust_sel4_version: String,
    /// Microkit SDK version, compared against the SDK's on-disk `VERSION`.
    pub(crate) microkit_version: String,
    /// GRUB version, compared against the version the installed
    /// `grub-mkstandalone` reports for itself.
    pub(crate) grub_version: String,
}

/// Read and validate the pinned upstream versions from
/// `third-party/sources.lock`.
///
/// Errors if the file cannot be read, a required key is missing, or any key is
/// assigned more than once.
pub(crate) fn read(root: &Path) -> Result<Pins, Error> {
    let path = root.join("third-party/sources.lock");
    let text = fs::read_to_string(&path).map_err(|error| Error::io("read", &path, error))?;
    parse(&text)
}

fn parse(text: &str) -> Result<Pins, Error> {
    let mut pins: BTreeMap<&str, &str> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if pins.insert(key, value.trim()).is_some() {
            return Err(Error::invalid(format!(
                "sources.lock assigns {key} more than once; make, the builder shell, \
                 and xtask would not all resolve it to the same value"
            )));
        }
    }

    let value = |key: &str| -> Result<String, Error> {
        pins.get(key)
            .map(|value| (*value).to_owned())
            .ok_or_else(|| Error::invalid(format!("sources.lock is missing {key}")))
    };
    let rust_sel4 = value("RUST_SEL4_VERSION")?;
    Ok(Pins {
        rust_sel4_version: rust_sel4.strip_prefix('v').unwrap_or(&rust_sel4).to_owned(),
        microkit_version: value("MICROKIT_VERSION")?,
        grub_version: value("GRUB_VERSION")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# a comment with an = sign in it
DEBIAN_IMAGE=docker.io/library/debian:13@sha256:abc

MICROKIT_VERSION=2.3.0
RUST_SEL4_VERSION=v5.0.0
GRUB_VERSION=2.14
";

    #[test]
    fn parses_and_strips_the_rust_sel4_tag_prefix() {
        let pins = parse(SAMPLE).unwrap();
        // The tag carries a leading `v`; the on-disk VERSION file does not.
        assert_eq!(pins.rust_sel4_version, "5.0.0");
        assert_eq!(pins.microkit_version, "2.3.0");
        assert_eq!(pins.grub_version, "2.14");
    }

    #[test]
    fn a_missing_key_is_a_named_error() {
        let error = parse("MICROKIT_VERSION=2.3.0\nGRUB_VERSION=2.14\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("RUST_SEL4_VERSION"), "got: {error}");
    }

    #[test]
    fn a_version_without_the_v_prefix_is_taken_verbatim() {
        let pins =
            parse("RUST_SEL4_VERSION=5.0.0\nMICROKIT_VERSION=2.3.0\nGRUB_VERSION=2.14\n").unwrap();
        assert_eq!(pins.rust_sel4_version, "5.0.0");
    }

    #[test]
    fn a_duplicated_key_is_a_named_error() {
        // make and the builder shell take the last assignment; a parser that
        // took the first would pin xtask to a different value than the
        // container was built against. Refuse the file instead.
        let error = parse(&format!("{SAMPLE}GRUB_VERSION=2.15\n"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("GRUB_VERSION"), "got: {error}");
        assert!(error.contains("more than once"), "got: {error}");
    }

    #[test]
    fn the_real_lock_file_parses() {
        // The committed lock file is an input to every build; a malformed or
        // duplicated pin must fail here, not deep inside the toolchain.
        let root = crate::util::workspace_root().unwrap();
        let pins = read(&root).unwrap();
        assert!(!pins.microkit_version.is_empty());
        assert!(!pins.rust_sel4_version.starts_with('v'));
        assert!(!pins.grub_version.is_empty());
    }
}
