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

use std::{fs, path::Path};

/// The pinned versions xtask needs: to gate the builder in
/// [`crate::image`]'s `verify_inputs` and to record provenance in the manifest.
#[derive(Debug)]
pub(crate) struct Pins {
    /// rust-sel4 version, with the source tag's leading `v` stripped: the tag
    /// is `v5.0.0` but the SDK's on-disk `VERSION` file and the manifest carry
    /// the bare `5.0.0`, so this is the form both compare against.
    pub(crate) rust_sel4_version: String,
    pub(crate) microkit_version: String,
    pub(crate) grub_version: String,
}

pub(crate) fn read(root: &Path) -> Result<Pins, String> {
    let path = root.join("third-party/sources.lock");
    let text =
        fs::read_to_string(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    parse(&text)
}

fn parse(text: &str) -> Result<Pins, String> {
    let value = |key: &str| -> Result<String, String> {
        text.lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.starts_with('#') {
                    return None;
                }
                line.split_once('=')
            })
            .find(|(name, _)| name.trim() == key)
            .map(|(_, value)| value.trim().to_owned())
            .ok_or_else(|| format!("sources.lock is missing {key}"))
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
        let error = parse("MICROKIT_VERSION=2.3.0\nGRUB_VERSION=2.14\n").unwrap_err();
        assert!(error.contains("RUST_SEL4_VERSION"), "got: {error}");
    }

    #[test]
    fn a_version_without_the_v_prefix_is_taken_verbatim() {
        let pins =
            parse("RUST_SEL4_VERSION=5.0.0\nMICROKIT_VERSION=2.3.0\nGRUB_VERSION=2.14\n").unwrap();
        assert_eq!(pins.rust_sel4_version, "5.0.0");
    }
}
