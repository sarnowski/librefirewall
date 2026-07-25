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

use std::{fs, path::Path, process::Command};

use crate::util::{run_command, set_permissions_0700};

const DEV_KEY_UID: &str = "librefirewall development signing <dev@librefirewall.invalid>";

/// Create (once per checkout) the local development signing key and return its
/// fingerprint. The private key never leaves `build/dev-keys` and is removed by
/// `clean`; only detached signatures and the exported public key are consumed
/// by the build. This is a development trust anchor, not a release key.
pub(crate) fn ensure_dev_key(root: &Path) -> Result<String, String> {
    let home = root.join("build/dev-keys");
    let pubkey = home.join("librefirewall-dev-pub.gpg");
    if !pubkey.is_file() {
        fs::create_dir_all(&home).map_err(|error| format!("create {}: {error}", home.display()))?;
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
        let export = Command::new("gpg")
            .env("GNUPGHOME", &home)
            .args(["--batch", "--yes", "--output"])
            .arg(&pubkey)
            .args(["--export", DEV_KEY_UID])
            .status()
            .map_err(|error| format!("export public key: {error}"))?;
        if !export.success() {
            return Err(format!("export public key failed with {export}"));
        }
    }
    read_dev_key_fingerprint(&home)
}

pub(crate) fn read_dev_key_fingerprint(home: &Path) -> Result<String, String> {
    let output = gpg(home)
        .args(["--batch", "--with-colons", "--fingerprint", DEV_KEY_UID])
        .output()
        .map_err(|error| format!("read key fingerprint: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "read key fingerprint failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_fingerprint(&text)
}

/// Extract the first `fpr:` field from gpg's `--with-colons` output.
fn parse_fingerprint(colon_output: &str) -> Result<String, String> {
    colon_output
        .lines()
        .find_map(|line| {
            line.strip_prefix("fpr:")
                .map(|rest| rest.trim_matches(':').to_owned())
        })
        .ok_or_else(|| "no fingerprint in gpg output".to_owned())
}

pub(crate) fn sign_file(root: &Path, file: &Path) -> Result<(), String> {
    let home = root.join("build/dev-keys");
    let signature = std::path::PathBuf::from(format!("{}.sig", file.display()));
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
            .arg("--detach-sign")
            .arg("--output")
            .arg(&signature)
            .arg(file),
        "sign payload",
    )
}

fn gpg(home: &Path) -> Command {
    let mut command = Command::new("gpg");
    command.env("GNUPGHOME", home);
    command
}
