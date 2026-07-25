//! The signed GRUB boot base.
//!
//! GRUB is the boot manager (CONCEPT §14.2): a minimal standalone `x86_64-efi`
//! core image built with a curated module allowlist
//! (`third-party/grub/modules.txt`), an immutable embedded configuration
//! (`third-party/grub/grub.cfg`), and the librefirewall public key baked in —
//! which is what makes signature verification on every subsequently loaded file
//! mandatory. This module builds that core image and seeds the initial grubenv
//! that the A/B slot-selection scheme reads.

use std::{fs, path::Path, process::Command};

use crate::util::{Error, capture_stdout, run_command};

const GRUB_MODULES_DIR: &str = "/opt/grub/lib/grub/x86_64-efi";

/// Build the standalone GRUB `x86_64-efi` core image at `output`, embedding
/// `pubkey` as the trust anchor.
///
/// Embedding the key is what makes verification *mandatory*: GRUB refuses to
/// load any file lacking a valid detached signature from a key it was built
/// with, so this image and the payload signatures must come from the same key.
pub(crate) fn build_grub_efi(root: &Path, pubkey: &Path, output: &Path) -> Result<(), Error> {
    let modules_path = root.join("third-party/grub/modules.txt");
    let modules_file = fs::read_to_string(&modules_path)
        .map_err(|error| Error::io("read", &modules_path, error))?;
    // One module per line; `#` comments (the header documenting the allowlist)
    // and blank lines are ignored.
    let modules = modules_file
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ");
    let config = root.join("third-party/grub/grub.cfg");
    run_command(
        Command::new("grub-mkstandalone")
            .current_dir(root)
            .arg(format!("--directory={GRUB_MODULES_DIR}"))
            .arg("--format=x86_64-efi")
            .arg(format!("--modules={modules}"))
            .arg("--pubkey")
            .arg(pubkey)
            .arg("--output")
            .arg(output)
            .arg(format!("boot/grub/grub.cfg={}", config.display())),
        "build standalone grub EFI image",
    )
}

/// Report the version of the GRUB installation the core image is built from.
///
/// The manifest records the pinned GRUB version as provenance, so the build
/// asks the tool that will actually produce the boot base rather than trusting
/// the pin to describe whatever happens to be installed.
pub(crate) fn installed_version(pinned: &str) -> Result<(), Error> {
    let reported = capture_stdout(
        Command::new("grub-mkstandalone").arg("--version"),
        "read grub version",
    )?;
    // `grub-mkstandalone (GRUB) 2.14` — the pin is a substring, not the whole
    // line, and distribution builds append a packaging suffix.
    if reported.contains(pinned) {
        Ok(())
    } else {
        Err(Error::invalid(format!(
            "GRUB at {GRUB_MODULES_DIR} reports {:?}, expected the pinned version {pinned:?}",
            reported.trim()
        )))
    }
}

/// Seed the initial boot-selection env: slot A confirmed, B staged but
/// unconfirmed, A tried first. This is the state the freshly built base image
/// ships with; the A/B harness and (later) the update PD rewrite it.
pub(crate) fn seed_grubenv(grubenv: &Path) -> Result<(), Error> {
    run_command(
        Command::new("grub-editenv").arg(grubenv).arg("create"),
        "create grubenv",
    )?;
    run_command(
        Command::new("grub-editenv")
            .arg(grubenv)
            .arg("set")
            .arg("ORDER=A B")
            .arg("A_OK=1")
            .arg("A_TRY=0")
            .arg("B_OK=0")
            .arg("B_TRY=0"),
        "seed grubenv",
    )
}
