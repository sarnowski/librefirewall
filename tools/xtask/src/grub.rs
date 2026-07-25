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

use crate::util::run_command;

const GRUB_MODULES_DIR: &str = "/opt/grub/lib/grub/x86_64-efi";
pub(crate) const GRUB_VERSION: &str = "2.14";

pub(crate) fn build_grub_efi(root: &Path, pubkey: &Path, output: &Path) -> Result<(), String> {
    let modules = fs::read_to_string(root.join("third-party/grub/modules.txt"))
        .map_err(|error| format!("read grub modules list: {error}"))?
        .split_whitespace()
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

/// Seed the initial boot-selection env: slot A confirmed, B staged but
/// unconfirmed, A tried first. This is the state the freshly built base image
/// ships with; the A/B harness and (later) the update PD rewrite it.
pub(crate) fn seed_grubenv(grubenv: &Path) -> Result<(), String> {
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
