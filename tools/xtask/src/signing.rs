//! The development payload-signing trust anchor.
//!
//! GRUB in the boot base enforces detached-signature verification on every file
//! it loads (CONCEPT §14.3), so the build must sign the kernel and system image.
//! Development builds generate a local, throwaway RSA key once per checkout
//! under `build/dev-keys/`: the private key never leaves that directory and is
//! removed by `clean`; only the detached signatures and the exported public key
//! (embedded into the GRUB core image) are consumed downstream. The manifest
//! records `trust_profile: development` and this key's fingerprint so a
//! development-signed image can never be mistaken for a production one.
//!
//! Two invariants make the chain provable rather than assumed:
//!
//! - **Signing is key-explicit.** Every signature is made with `--local-user`
//!   naming the fingerprint that was exported and embedded, never with whatever
//!   secret key the keyring happens to default to. A keyring holding a second
//!   key must therefore be rejected outright ([`parse_fingerprint`]) rather than
//!   silently resolved, or "the exported key" stops being a well-defined thing.
//! - **The build verifies what it just signed** ([`verify_payload_signature`])
//!   against a scratch keyring seeded *only* from the exported public key, and
//!   requires gpg to report `VALIDSIG` for exactly that fingerprint. Signing
//!   without verifying leaves a mis-keyed payload to fail at boot on the
//!   appliance, long after the build exited zero.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    artifacts::{BUILD_DEV_KEY_DIR, DEV_PUBLIC_KEY},
    util::{Error, capture_stdout, recreate_dir, run_command, set_permissions_0700},
};

const DEV_KEY_UID: &str = "librefirewall development signing <dev@librefirewall.invalid>";

/// The development keyring directory (`GNUPGHOME`) for this checkout.
pub(crate) fn dev_key_home(root: &Path) -> PathBuf {
    root.join(BUILD_DEV_KEY_DIR)
}

/// The exported development public key: the single trust anchor embedded into
/// GRUB and used to verify the signatures this build produces.
pub(crate) fn dev_public_key(root: &Path) -> PathBuf {
    dev_key_home(root).join(DEV_PUBLIC_KEY)
}

/// Create (once per checkout) the local development signing key, export its
/// public half to [`dev_public_key`], and return its fingerprint.
///
/// The fingerprint is not decoration: it selects the signing key in
/// [`sign_file`], is the value [`verify_payload_signature`] demands back from
/// gpg, and is recorded in the release manifest. Errors if the keyring holds
/// more than one key, because then "the" key is ambiguous.
pub(crate) fn ensure_dev_key(root: &Path) -> Result<String, Error> {
    let home = dev_key_home(root);
    let pubkey = dev_public_key(root);
    if !pubkey.is_file() {
        fs::create_dir_all(&home).map_err(|error| Error::io("create", &home, error))?;
        set_permissions_0700(&home)?;
        run_command(
            gpg(&home)
                .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
                .args([
                    "--quick-generate-key",
                    DEV_KEY_UID,
                    "rsa3072",
                    "sign",
                    "never",
                ]),
            "generate development signing key",
        )?;
        run_command(
            gpg(&home)
                .args(["--batch", "--yes", "--output"])
                .arg(&pubkey)
                .args(["--export", DEV_KEY_UID]),
            "export development public key",
        )?;
    }
    read_dev_key_fingerprint(&home)
}

/// Read the fingerprint of the development signing key from `home`.
///
/// Errors if the keyring holds no key, or more than one: everything downstream
/// (which key signs, which key GRUB trusts, which key the manifest names) is
/// defined by there being exactly one.
pub(crate) fn read_dev_key_fingerprint(home: &Path) -> Result<String, Error> {
    let output = capture_stdout(
        gpg(home).args(["--batch", "--with-colons", "--fingerprint", DEV_KEY_UID]),
        "read development key fingerprint",
    )?;
    parse_fingerprint(&output)
}

/// Extract the single `fpr:` record from gpg's `--with-colons` output.
///
/// An ambiguous keyring — two keys, e.g. left by an interrupted regeneration —
/// is rejected rather than resolved to the first record: the signing key, the
/// key embedded in GRUB, and the key named in the manifest must all be the same
/// one, and picking a record by position does not establish that.
fn parse_fingerprint(colon_output: &str) -> Result<String, Error> {
    let mut fingerprints = colon_output.lines().filter_map(|line| {
        line.strip_prefix("fpr:")
            .map(|rest| rest.trim_matches(':').to_owned())
    });
    let first = fingerprints
        .next()
        .ok_or_else(|| Error::invalid("no fingerprint in gpg output"))?;
    let extra = fingerprints.count();
    if extra > 0 {
        return Err(Error::invalid(format!(
            "development keyring holds {} keys ({first} and {extra} more); \
             the signing key must be unambiguous — remove {BUILD_DEV_KEY_DIR} and rebuild",
            extra + 1
        )));
    }
    Ok(first)
}

/// Produce a detached signature for `file` at `<file>.sig`, made with exactly
/// the key named by `fingerprint`.
///
/// `--local-user` is what ties the signature to the key GRUB embeds: without
/// it gpg signs with whichever secret key the keyring defaults to, and a
/// mismatch would only surface as a failed verification at boot.
pub(crate) fn sign_file(root: &Path, file: &Path, fingerprint: &str) -> Result<(), Error> {
    let home = dev_key_home(root);
    run_command(
        gpg(&home)
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
            ])
            .args(["--local-user", fingerprint])
            .arg("--detach-sign")
            .arg("--output")
            .arg(signature_path(file))
            .arg(file),
        "sign payload",
    )
}

/// The detached-signature path for a payload: the name GRUB looks for.
pub(crate) fn signature_path(file: &Path) -> PathBuf {
    let mut path = file.as_os_str().to_owned();
    path.push(".sig");
    PathBuf::from(path)
}

/// Prepare a scratch keyring at `home` holding *only* `public_key`.
///
/// Verification must answer "does the key GRUB embeds accept this payload",
/// which the signing keyring — holding the secret key and its owner trust —
/// cannot answer. A keyring seeded from the exported public key alone can.
pub(crate) fn import_verification_key(home: &Path, public_key: &Path) -> Result<(), Error> {
    recreate_dir(home)?;
    set_permissions_0700(home)?;
    run_command(
        gpg(home)
            .args(["--batch", "--yes", "--import"])
            .arg(public_key),
        "import verification public key",
    )
}

/// Verify `<file>.sig` against `file` using the scratch keyring at `home`, and
/// require gpg to attribute the signature to `fingerprint`.
///
/// Reads gpg's machine-readable status stream rather than its exit code alone:
/// the question is not merely "is this signature well-formed" but "was it made
/// by the one key embedded into the boot chain", and only `VALIDSIG` answers
/// that.
pub(crate) fn verify_payload_signature(
    home: &Path,
    file: &Path,
    fingerprint: &str,
) -> Result<(), Error> {
    let signature = signature_path(file);
    let status = capture_stdout(
        gpg(home)
            .args(["--batch", "--status-fd=1", "--verify"])
            .arg(&signature)
            .arg(file),
        "verify payload signature",
    )?;
    if signing_key_matches(&status, fingerprint) {
        Ok(())
    } else {
        Err(Error::invalid(format!(
            "signature {} is not a valid signature over {} by key {fingerprint}; \
             gpg status was:\n{status}",
            signature.display(),
            file.display()
        )))
    }
}

/// True when gpg's status stream reports a `VALIDSIG` attributable to
/// `fingerprint`.
///
/// The `VALIDSIG` record names the *signing* key first and, when the signature
/// came from a subkey, the primary key last. Either identifies our anchor, so
/// both positions are accepted — the record's presence is what proves the
/// signature verified against this keyring.
fn signing_key_matches(status: &str, fingerprint: &str) -> bool {
    status
        .lines()
        .filter_map(|line| line.strip_prefix("[GNUPG:] VALIDSIG "))
        .any(|record| {
            let mut fields = record.split_whitespace();
            let signing_key = fields.next();
            let primary_key = fields.last();
            signing_key == Some(fingerprint) || primary_key == Some(fingerprint)
        })
}

fn gpg(home: &Path) -> Command {
    let mut command = Command::new("gpg");
    command.env("GNUPGHOME", home);
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    // gpg `--with-colons` output: the fingerprint is the tenth colon field of
    // the `fpr:` record (all leading fields empty).
    const FPR: &str = "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333";

    #[test]
    fn extracts_the_fingerprint_from_colon_output() {
        let output = format!(
            "tru::1:1700000000:0:3:1:5\n\
             pub:-:3072:1:0011223344556677:1700000000:::-:::scESC::::::23::0:\n\
             fpr:::::::::{FPR}:\n\
             uid:-::::1700000000::0011::librefirewall development signing::::::::::0:\n"
        );
        assert_eq!(parse_fingerprint(&output).unwrap(), FPR);
    }

    #[test]
    fn absent_fingerprint_is_an_error() {
        let output = "tru::1:1700000000:0:3:1:5\npub:-:3072:1:0011223344556677:\n";
        let error = parse_fingerprint(output).unwrap_err().to_string();
        assert!(error.contains("no fingerprint"), "got: {error}");
    }

    #[test]
    fn an_ambiguous_keyring_is_rejected() {
        // Two keys (e.g. an interrupted regeneration): which one signs, which
        // one GRUB embeds, and which one the manifest names would all be
        // decided by keyring order. Refuse instead of guessing.
        let second = "9999888877776666555544443333222211110000";
        let output = format!("fpr:::::::::{FPR}:\nfpr:::::::::{second}:\n");
        let error = parse_fingerprint(&output).unwrap_err().to_string();
        assert!(error.contains("holds 2 keys"), "got: {error}");
        assert!(error.contains(BUILD_DEV_KEY_DIR), "got: {error}");
    }

    #[test]
    fn a_validsig_for_the_expected_key_is_accepted() {
        let status = format!(
            "[GNUPG:] NEWSIG\n\
             [GNUPG:] GOODSIG 0011223344556677 librefirewall development signing\n\
             [GNUPG:] VALIDSIG {FPR} 2026-01-01 1767225600 0 4 0 1 8 00 {FPR}\n\
             [GNUPG:] TRUST_UNDEFINED 0 pgp\n"
        );
        assert!(signing_key_matches(&status, FPR));
    }

    #[test]
    fn a_validsig_from_a_subkey_is_attributed_to_its_primary_key() {
        let subkey = "1111222233334444555566667777888899990000";
        let status =
            format!("[GNUPG:] VALIDSIG {subkey} 2026-01-01 1767225600 0 4 0 1 8 00 {FPR}\n");
        assert!(signing_key_matches(&status, FPR));
    }

    #[test]
    fn a_validsig_for_a_different_key_is_rejected() {
        let other = "9999888877776666555544443333222211110000";
        let status =
            format!("[GNUPG:] VALIDSIG {other} 2026-01-01 1767225600 0 4 0 1 8 00 {other}");
        assert!(!signing_key_matches(&status, FPR));
    }

    #[test]
    fn a_status_stream_without_validsig_is_rejected() {
        // A signature gpg cannot attribute (unknown key) still leaves GOODSIG
        // absent and VALIDSIG absent; nothing else may be taken as proof.
        let status = "[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG 0011223344556677 1 8 00 1767225600 9\n";
        assert!(!signing_key_matches(status, FPR));
    }

    #[test]
    fn signature_path_appends_the_grub_suffix() {
        assert_eq!(
            signature_path(Path::new("/build/system.img")),
            Path::new("/build/system.img.sig")
        );
    }

    #[test]
    fn key_paths_are_derived_from_the_central_artifact_names() {
        let root = Path::new("/workspace");
        assert_eq!(dev_key_home(root), root.join(BUILD_DEV_KEY_DIR));
        assert_eq!(
            dev_public_key(root),
            root.join(BUILD_DEV_KEY_DIR).join(DEV_PUBLIC_KEY)
        );
    }
}
