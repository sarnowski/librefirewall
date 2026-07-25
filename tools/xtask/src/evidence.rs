//! Release evidence: the manifest, the SPDX SBOM, and the checksums.
//!
//! Every image build emits, alongside the deployable artifacts, the provenance
//! a consumer needs to trust them: a manifest describing the target, boot
//! scheme, and signing trust profile (recording `development` and the dev-key
//! fingerprint so a dev-signed image is never mistaken for production), an SPDX
//! 2.3 SBOM produced by syft, and sha256 checksums over the artifact set.
//!
//! The manifest's artifact list and the checksum file are both derived from
//! [`DIST_ARTIFACTS`] rather than restated here. They are two descriptions of
//! the same set, and a hand-maintained second copy is how a published artifact
//! ends up unlisted or unchecksummed.
//!
//! **SBOM scope — and its known limits.** syft catalogs the workspace *source
//! tree*, with the trees that exist only to build, test, or fuzz the product
//! excluded ([`SBOM_EXCLUDED_TREES`]): `fuzz/` carries its own lockfile whose
//! libFuzzer/ASan/bindgen toolchain never reaches an image, `tools/` is this
//! orchestrator, and `build/`, `dist/`, `target/` are generated. Inventorying
//! any of them describes the build machine rather than the product.
//!
//! Two gaps remain, and a consumer must not read this document as the complete
//! contents of the boot payload. syft's cargo cataloger reads the workspace
//! `Cargo.lock`, which does not distinguish normal from dev dependencies, so
//! host-only test and benchmark crates still appear. And the pinned third-party
//! components that genuinely *do* ship — the seL4 kernel from the Microkit SDK
//! and the GRUB core image — are invisible to a source-tree scan; they are
//! recorded (and version-verified against their pins) as provenance in the
//! manifest instead. Closing both needs a payload-scoped inventory that syft's
//! single-source model does not offer.
//!
//! The SBOM is validated after generation: an unparseable or empty document is
//! a failed build, not a file nobody reads. Validation is done here in Rust
//! rather than by an embedded interpreter script — orchestration belongs in
//! xtask, and an inline `python3 -c` would make a language runtime a
//! build-critical input that appears in no pin file.

use std::{path::Path, process::Command};

use crate::{
    artifacts::{DIST_ARTIFACTS, DIST_CHECKSUMS, DIST_DISK, DIST_MANIFEST, DIST_SBOM},
    image::{BOARD, TARGET},
    pins::Pins,
    util::{Error, capture_stdout, run_command},
};

/// Source subtrees excluded from the SBOM scan: everything that exists only to
/// build, test, or fuzz the product and never enters the boot payload.
const SBOM_EXCLUDED_TREES: &[&str] = &["./build", "./dist", "./target", "./fuzz", "./tools"];

/// The SPDX version the build produces and validates against.
const SPDX_VERSION: &str = "SPDX-2.3";

/// Write the release manifest: what was built, from which pinned inputs, under
/// which boot scheme, and signed by which trust anchor.
pub(crate) fn write_manifest(
    dist: &Path,
    config: &str,
    key_fingerprint: &str,
    pins: &Pins,
) -> Result<(), Error> {
    let artifacts = DIST_ARTIFACTS
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let manifest = format!(
        concat!(
            "{{\n",
            "  \"format\": 3,\n",
            "  \"target\": \"{target}\",\n",
            "  \"microkit\": {{\"version\": \"{microkit}\", \"board\": \"{board}\", \"config\": \"{config}\"}},\n",
            "  \"rust_sel4\": {{\"version\": \"{rust_sel4}\"}},\n",
            "  \"boot\": {{\"manager\": \"grub\", \"grub_version\": \"{grub}\", \"scheme\": \"ab\", \"secure_boot\": false}},\n",
            "  \"signing\": {{\"trust_profile\": \"development\", \"key_fingerprint\": \"{fingerprint}\"}},\n",
            "  \"disk\": {{\"image\": \"{disk}\", \"table\": \"gpt\", \"slots\": [\"SLOTA\", \"SLOTB\"]}},\n",
            "  \"artifacts\": [{artifacts}]\n",
            "}}\n"
        ),
        target = TARGET,
        microkit = pins.microkit_version,
        board = BOARD,
        config = config,
        rust_sel4 = pins.rust_sel4_version,
        grub = pins.grub_version,
        fingerprint = key_fingerprint,
        disk = DIST_DISK,
        artifacts = artifacts,
    );
    let path = dist.join(DIST_MANIFEST);
    std::fs::write(&path, manifest).map_err(|error| Error::io("write", &path, error))
}

/// Generate the SPDX 2.3 SBOM and refuse to publish one that is unparseable,
/// of the wrong SPDX version, or empty of packages.
pub(crate) fn write_sbom(root: &Path, dist: &Path) -> Result<(), Error> {
    let sbom = dist.join(DIST_SBOM);
    let mut syft = Command::new("syft");
    syft.current_dir(root).args(["scan", "dir:."]);
    for tree in SBOM_EXCLUDED_TREES {
        syft.args(["--exclude", tree]);
    }
    run_command(
        syft.args([
            "--source-name",
            "librefirewall",
            "--source-version",
            env!("CARGO_PKG_VERSION"),
            "--output",
        ])
        .arg(format!("spdx-json={}", sbom.display())),
        "generate SPDX SBOM",
    )?;

    let document =
        std::fs::read_to_string(&sbom).map_err(|error| Error::io("read", &sbom, error))?;
    validate_sbom(&document).map_err(|reason| {
        Error::invalid(format!("SBOM at {} is unusable: {reason}", sbom.display()))
    })
}

/// Check that an SPDX document is the version we claim to emit and inventories
/// at least one package. An SBOM nobody can parse, or one describing nothing,
/// is worse than none: it looks like evidence and carries none.
fn validate_sbom(document: &str) -> Result<(), String> {
    let value = json::parse(document)?;
    let version = value
        .get("spdxVersion")
        .and_then(json::Value::as_str)
        .ok_or("no spdxVersion field")?;
    if version != SPDX_VERSION {
        return Err(format!(
            "spdxVersion is {version:?}, expected {SPDX_VERSION:?}"
        ));
    }
    let packages = value
        .get("packages")
        .and_then(json::Value::as_array)
        .ok_or("no packages array")?;
    if packages.is_empty() {
        return Err("the packages array is empty".to_owned());
    }
    Ok(())
}

/// Write SHA-256 sums over every published artifact except the checksum file
/// itself, which cannot cover its own contents.
pub(crate) fn write_checksums(dist: &Path) -> Result<(), Error> {
    let covered: Vec<&str> = DIST_ARTIFACTS
        .iter()
        .copied()
        .filter(|name| *name != DIST_CHECKSUMS)
        .collect();
    let sums = capture_stdout(
        Command::new("sha256sum").current_dir(dist).args(&covered),
        "checksum released artifacts",
    )?;
    let path = dist.join(DIST_CHECKSUMS);
    std::fs::write(&path, sums).map_err(|error| Error::io("write", &path, error))
}

/// A minimal JSON reader for validating the SBOM.
///
/// Only what validation needs: locate a top-level string and a top-level array
/// without mistaking a nested key, an escaped quote, or a number for either.
/// Recursion is depth-bounded — the document comes from an external tool, so
/// its nesting is not something this build controls.
mod json {
    /// Maximum nesting accepted. SPDX documents are shallow; anything deeper is
    /// a malformed or hostile file, not a document to keep descending into.
    const MAX_DEPTH: usize = 64;

    #[derive(Debug, PartialEq)]
    pub(super) enum Value {
        Null,
        Bool(bool),
        /// Kept as written: validation never needs a number's value, and not
        /// parsing one cannot lose or round it.
        Number(String),
        String(String),
        Array(Vec<Value>),
        Object(Vec<(String, Value)>),
    }

    impl Value {
        pub(super) fn get(&self, key: &str) -> Option<&Value> {
            match self {
                Self::Object(entries) => entries
                    .iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value),
                _ => None,
            }
        }

        pub(super) fn as_str(&self) -> Option<&str> {
            match self {
                Self::String(text) => Some(text),
                _ => None,
            }
        }

        pub(super) fn as_array(&self) -> Option<&[Value]> {
            match self {
                Self::Array(items) => Some(items),
                _ => None,
            }
        }
    }

    pub(super) fn parse(text: &str) -> Result<Value, String> {
        let mut reader = Reader {
            bytes: text.as_bytes(),
            at: 0,
        };
        let value = reader.value(0)?;
        reader.skip_whitespace();
        if reader.at == reader.bytes.len() {
            Ok(value)
        } else {
            Err(format!("trailing input at byte {}", reader.at))
        }
    }

    struct Reader<'a> {
        bytes: &'a [u8],
        at: usize,
    }

    impl Reader<'_> {
        fn skip_whitespace(&mut self) {
            while matches!(self.bytes.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
                self.at += 1;
            }
        }

        fn peek(&mut self) -> Result<u8, String> {
            self.skip_whitespace();
            self.bytes
                .get(self.at)
                .copied()
                .ok_or_else(|| "unexpected end of document".to_owned())
        }

        fn expect(&mut self, byte: u8) -> Result<(), String> {
            if self.peek()? == byte {
                self.at += 1;
                Ok(())
            } else {
                Err(format!(
                    "expected {:?} at byte {}",
                    char::from(byte),
                    self.at
                ))
            }
        }

        fn value(&mut self, depth: usize) -> Result<Value, String> {
            if depth > MAX_DEPTH {
                return Err(format!("nesting deeper than {MAX_DEPTH} levels"));
            }
            match self.peek()? {
                b'{' => self.object(depth),
                b'[' => self.array(depth),
                b'"' => self.string().map(Value::String),
                b't' => self.literal("true").map(|()| Value::Bool(true)),
                b'f' => self.literal("false").map(|()| Value::Bool(false)),
                b'n' => self.literal("null").map(|()| Value::Null),
                _ => self.number(),
            }
        }

        fn object(&mut self, depth: usize) -> Result<Value, String> {
            self.expect(b'{')?;
            let mut entries = Vec::new();
            if self.peek()? == b'}' {
                self.at += 1;
                return Ok(Value::Object(entries));
            }
            loop {
                let key = self.string()?;
                self.expect(b':')?;
                entries.push((key, self.value(depth + 1)?));
                match self.peek()? {
                    b',' => self.at += 1,
                    b'}' => {
                        self.at += 1;
                        return Ok(Value::Object(entries));
                    }
                    _ => return Err(format!("expected ',' or '}}' at byte {}", self.at)),
                }
            }
        }

        fn array(&mut self, depth: usize) -> Result<Value, String> {
            self.expect(b'[')?;
            let mut items = Vec::new();
            if self.peek()? == b']' {
                self.at += 1;
                return Ok(Value::Array(items));
            }
            loop {
                items.push(self.value(depth + 1)?);
                match self.peek()? {
                    b',' => self.at += 1,
                    b']' => {
                        self.at += 1;
                        return Ok(Value::Array(items));
                    }
                    _ => return Err(format!("expected ',' or ']' at byte {}", self.at)),
                }
            }
        }

        fn literal(&mut self, word: &str) -> Result<(), String> {
            if self.bytes[self.at..].starts_with(word.as_bytes()) {
                self.at += word.len();
                Ok(())
            } else {
                Err(format!("expected {word} at byte {}", self.at))
            }
        }

        fn number(&mut self) -> Result<Value, String> {
            let start = self.at;
            while matches!(
                self.bytes.get(self.at),
                Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
            ) {
                self.at += 1;
            }
            if self.at == start {
                return Err(format!("not a JSON value at byte {start}"));
            }
            String::from_utf8(self.bytes[start..self.at].to_vec())
                .map(Value::Number)
                .map_err(|error| format!("malformed number at byte {start}: {error}"))
        }

        fn string(&mut self) -> Result<String, String> {
            self.expect(b'"')?;
            let mut text = String::new();
            loop {
                let byte = *self
                    .bytes
                    .get(self.at)
                    .ok_or_else(|| "unterminated string".to_owned())?;
                self.at += 1;
                match byte {
                    b'"' => return Ok(text),
                    b'\\' => text.push(self.escape()?),
                    _ => {
                        // Multi-byte UTF-8 passes through byte by byte; the
                        // input is a `&str`, so the sequence is already valid.
                        let start = self.at - 1;
                        let mut end = self.at;
                        while self.bytes.get(end).is_some_and(|b| b & 0xC0 == 0x80) {
                            end += 1;
                        }
                        text.push_str(
                            std::str::from_utf8(&self.bytes[start..end])
                                .map_err(|error| format!("malformed UTF-8: {error}"))?,
                        );
                        self.at = end;
                    }
                }
            }
        }

        fn escape(&mut self) -> Result<char, String> {
            let byte = *self
                .bytes
                .get(self.at)
                .ok_or_else(|| "unterminated escape".to_owned())?;
            self.at += 1;
            Ok(match byte {
                b'"' => '"',
                b'\\' => '\\',
                b'/' => '/',
                b'b' => '\u{8}',
                b'f' => '\u{c}',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'u' => return self.unicode_escape(),
                other => return Err(format!("unknown escape \\{}", char::from(other))),
            })
        }

        fn unicode_escape(&mut self) -> Result<char, String> {
            let first = self.hex4()?;
            // A code point above the BMP arrives as a surrogate pair; a lone
            // surrogate is not a character and must be rejected, not coerced.
            if (0xD800..0xDC00).contains(&first) {
                if !self.bytes[self.at..].starts_with(br"\u") {
                    return Err("lone high surrogate in \\u escape".to_owned());
                }
                self.at += 2;
                let second = self.hex4()?;
                if !(0xDC00..0xE000).contains(&second) {
                    return Err("high surrogate not followed by a low surrogate".to_owned());
                }
                let combined =
                    0x1_0000 + ((u32::from(first) - 0xD800) << 10) + (u32::from(second) - 0xDC00);
                return char::from_u32(combined).ok_or_else(|| "invalid surrogate pair".to_owned());
            }
            char::from_u32(u32::from(first))
                .ok_or_else(|| format!("\\u{first:04x} is not a character"))
        }

        fn hex4(&mut self) -> Result<u16, String> {
            let digits = self
                .bytes
                .get(self.at..self.at + 4)
                .ok_or_else(|| "truncated \\u escape".to_owned())?;
            let text =
                std::str::from_utf8(digits).map_err(|_| "malformed \\u escape".to_owned())?;
            let value = u16::from_str_radix(text, 16)
                .map_err(|error| format!("bad \\u escape: {error}"))?;
            self.at += 4;
            Ok(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DIST_ARTIFACTS, DIST_CHECKSUMS, DIST_MANIFEST, Pins, json, validate_sbom, write_manifest,
    };

    fn spdx(version: &str, packages: &str) -> String {
        format!(
            "{{\"spdxVersion\": \"{version}\", \"name\": \"librefirewall\", \
             \"packages\": {packages}}}"
        )
    }

    #[test]
    fn a_well_formed_spdx_2_3_document_with_packages_is_accepted() {
        let document = spdx(
            "SPDX-2.3",
            "[{\"name\": \"queue\", \"versionInfo\": \"0.1.0\"}]",
        );
        validate_sbom(&document).unwrap();
    }

    #[test]
    fn a_wrong_spdx_version_is_rejected() {
        let error = validate_sbom(&spdx("SPDX-2.2", "[{\"name\": \"queue\"}]")).unwrap_err();
        assert!(error.contains("SPDX-2.2"), "got: {error}");
    }

    #[test]
    fn an_empty_package_list_is_rejected() {
        let error = validate_sbom(&spdx("SPDX-2.3", "[]")).unwrap_err();
        assert!(error.contains("empty"), "got: {error}");
    }

    #[test]
    fn a_missing_packages_array_is_rejected() {
        let error = validate_sbom("{\"spdxVersion\": \"SPDX-2.3\"}").unwrap_err();
        assert!(error.contains("packages"), "got: {error}");
    }

    #[test]
    fn a_missing_version_is_rejected() {
        let error = validate_sbom("{\"packages\": [1]}").unwrap_err();
        assert!(error.contains("spdxVersion"), "got: {error}");
    }

    #[test]
    fn unparseable_input_is_rejected_rather_than_scanned_for_substrings() {
        for broken in [
            "",
            "{",
            "{\"spdxVersion\": }",
            "{\"spdxVersion\": \"SPDX-2.3\", \"packages\": [1,]}",
            "{\"a\": 1} trailing",
        ] {
            assert!(
                validate_sbom(broken).is_err(),
                "accepted malformed input {broken:?}"
            );
        }
    }

    #[test]
    fn a_nested_key_is_not_mistaken_for_a_top_level_one() {
        // The real defect this parser exists to avoid: a substring search would
        // find the inner `spdxVersion` and pass a document that has none.
        let document = "{\"packages\": [{\"spdxVersion\": \"SPDX-2.3\"}]}";
        let error = validate_sbom(document).unwrap_err();
        assert!(error.contains("spdxVersion"), "got: {error}");
    }

    #[test]
    fn a_version_hidden_in_a_string_escape_is_not_mistaken_for_the_field() {
        let document = "{\"name\": \"\\\"spdxVersion\\\": \\\"SPDX-2.3\\\"\", \"packages\": [1]}";
        assert!(validate_sbom(document).is_err());
    }

    #[test]
    fn strings_decode_escapes_including_surrogate_pairs() {
        let value = json::parse(r#"{"a": "tab\tquote\"slash\/u\u0041pair\uD83D\uDE00"}"#).unwrap();
        assert_eq!(
            value.get("a").and_then(json::Value::as_str),
            Some("tab\tquote\"slash/uApair\u{1F600}")
        );
    }

    #[test]
    fn a_lone_surrogate_is_rejected() {
        assert!(json::parse(r#"{"a": "\uD83D"}"#).is_err());
        assert!(json::parse(r#"{"a": "\uDE00"}"#).is_err());
    }

    #[test]
    fn literals_numbers_and_empty_containers_round_trip() {
        let value = json::parse(
            " {\"n\": null, \"t\": true, \"f\": false, \"x\": -1.5e3, \"o\": {}, \"a\": []} ",
        )
        .unwrap();
        assert_eq!(value.get("n"), Some(&json::Value::Null));
        assert_eq!(value.get("t"), Some(&json::Value::Bool(true)));
        assert_eq!(value.get("f"), Some(&json::Value::Bool(false)));
        assert_eq!(
            value.get("x"),
            Some(&json::Value::Number("-1.5e3".to_owned()))
        );
        assert_eq!(value.get("o").and_then(json::Value::as_array), None);
        assert_eq!(
            value.get("a").and_then(json::Value::as_array),
            Some([].as_slice())
        );
    }

    #[test]
    fn deep_nesting_is_refused_rather_than_recursed_into() {
        let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
        let error = json::parse(&deep).unwrap_err();
        assert!(error.contains("nesting"), "got: {error}");
    }

    #[test]
    fn the_manifest_is_valid_json_listing_exactly_the_published_artifact_set() {
        // The manifest's artifact array and the checksum file are two
        // descriptions of the same set; both are derived from DIST_ARTIFACTS so
        // a published artifact can be neither unlisted nor unchecksummed.
        let dist = std::env::temp_dir().join("librefirewall-manifest-test");
        std::fs::create_dir_all(&dist).unwrap();
        let pins = Pins {
            rust_sel4_version: "5.0.0".to_owned(),
            microkit_version: "2.3.0".to_owned(),
            grub_version: "2.14".to_owned(),
        };
        write_manifest(&dist, "release", "AAAA1111", &pins).unwrap();

        let text = std::fs::read_to_string(dist.join(DIST_MANIFEST)).unwrap();
        let manifest = json::parse(&text).expect("the manifest must be valid JSON");
        let listed: Vec<&str> = manifest
            .get("artifacts")
            .and_then(json::Value::as_array)
            .expect("an artifacts array")
            .iter()
            .map(|value| value.as_str().expect("artifact names are strings"))
            .collect();
        assert_eq!(listed, DIST_ARTIFACTS);
        assert!(
            listed.contains(&DIST_CHECKSUMS),
            "the checksum file is itself a published artifact"
        );
        assert_eq!(
            manifest
                .get("signing")
                .and_then(|signing| signing.get("key_fingerprint"))
                .and_then(json::Value::as_str),
            Some("AAAA1111")
        );
        assert_eq!(
            manifest
                .get("boot")
                .and_then(|boot| boot.get("grub_version"))
                .and_then(json::Value::as_str),
            Some("2.14"),
            "the recorded GRUB provenance is the verified pin"
        );

        std::fs::remove_dir_all(&dist).ok();
    }

    #[test]
    fn non_ascii_content_survives_parsing() {
        let value = json::parse("{\"spdxVersion\": \"SPDX-2.3\", \"n\": \"grüße-日本\"}").unwrap();
        assert_eq!(
            value.get("n").and_then(json::Value::as_str),
            Some("grüße-日本")
        );
    }
}
