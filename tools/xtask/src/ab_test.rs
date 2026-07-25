//! The A/B boot state-machine system test.
//!
//! GRUB's slot selection follows the `OK`/`TRY`/`ORDER` scheme (CONCEPT §14.2):
//! a confirmed slot (`*_OK`) boots immediately; an unconfirmed slot is tried
//! once (its `*_TRY` is set before hand-off) and, if it never confirms health,
//! the next slot in `ORDER` is used. GRUB's single-attempt model means a slot
//! that fails verification is skipped within the same boot, while a slot that
//! would hang is represented by its persistent aftermath (TRY set, OK unset) —
//! exactly what a watchdog reset leaves behind.
//!
//! Each [`Scenario`] starts from a fresh copy of the pristine release disk, sets
//! the boot-selection state (and, where relevant, breaks a slot) exactly as the
//! real update flow or a failed boot would leave it, then boots through
//! OVMF/GRUB. A healthy boot is proven by the system's real observable
//! contract — frames forwarded between the two NIC ports — with GRUB's
//! slot-selection messages as corroborating slot-choice evidence and, where
//! relevant, the persisted grubenv state.

use std::{fs, path::Path, process::Command};

use crate::{
    artifacts::DIST_DISK,
    disk::disk_at,
    qemu::boot_and_forward,
    util::{copy_file, require_file, run_command},
};

/// One A/B boot scenario: the grubenv the disk is seeded with, any slots whose
/// signature is corrupted before boot, the boot-output needles that must
/// (`expect`) and must not (`reject`) appear, and an optional grubenv entry
/// expected to persist after the boot.
struct Scenario<'a> {
    name: &'a str,
    grubenv: &'a [&'a str],
    corrupt_slots: &'a [&'a str],
    expect: &'a [&'a str],
    reject: &'a [&'a str],
    expect_grubenv_after: Option<&'a str>,
}

/// Exercise the A/B boot state machine end to end across the five scenarios
/// that span the update flow: confirmed A, a first-try of staged B (persisting
/// `B_TRY`), fallback from a signature-broken B, skipping an exhausted B, and a
/// committed (confirmed) B.
pub(crate) fn test_ab(root: &Path) -> Result<(), String> {
    let dist_disk = root.join("dist").join(DIST_DISK);
    require_file(&dist_disk)?;
    let work = root.join("build/image/ab-test.img");

    let scenarios = [
        // 1. Confirmed A boots directly.
        Scenario {
            name: "confirmed-A",
            grubenv: &["ORDER=A B", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=0"],
            corrupt_slots: &[],
            expect: &["librefirewall: booting confirmed slot A"],
            reject: &["slot B"],
            expect_grubenv_after: None,
        },
        // 2. A staged, unconfirmed B is tried once and boots; the attempt is
        //    persisted (B_TRY becomes 1) so a later failure would fall back.
        Scenario {
            name: "try-pending-B",
            grubenv: &["ORDER=B A", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=0"],
            corrupt_slots: &[],
            expect: &["librefirewall: trying slot B"],
            reject: &[],
            expect_grubenv_after: Some("B_TRY=1"),
        },
        // 3. A broken (signature-failing) pending B is skipped and the boot
        //    falls back to confirmed A within the same boot.
        Scenario {
            name: "fallback-from-broken-B",
            grubenv: &["ORDER=B A", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=0"],
            corrupt_slots: &["SLOTB"],
            expect: &[
                "librefirewall: trying slot B",
                "librefirewall: booting confirmed slot A",
            ],
            reject: &[],
            expect_grubenv_after: None,
        },
        // 4. A pending B that was already tried but never confirmed (its
        //    aftermath of a hang + watchdog reset) is skipped in favour of A.
        Scenario {
            name: "skip-exhausted-B",
            grubenv: &["ORDER=B A", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=1"],
            corrupt_slots: &[],
            expect: &["librefirewall: booting confirmed slot A"],
            reject: &["slot B"],
            expect_grubenv_after: None,
        },
        // 5. Once B is confirmed healthy (the update is committed), B boots
        //    directly.
        Scenario {
            name: "confirmed-B",
            grubenv: &["ORDER=B A", "A_OK=0", "A_TRY=0", "B_OK=1", "B_TRY=0"],
            corrupt_slots: &[],
            expect: &["librefirewall: booting confirmed slot B"],
            reject: &[],
            expect_grubenv_after: None,
        },
    ];

    for scenario in &scenarios {
        run_scenario(root, &dist_disk, &work, scenario)?;
    }

    println!("A/B fallback tests passed (5 scenarios)");
    Ok(())
}

fn run_scenario(
    root: &Path,
    dist_disk: &Path,
    work: &Path,
    scenario: &Scenario,
) -> Result<(), String> {
    let name = scenario.name;
    copy_file(dist_disk, work)?;
    set_grubenv(work, scenario.grubenv)?;
    for slot in scenario.corrupt_slots {
        corrupt_slot_signature(root, work, slot)?;
    }

    let output = boot_and_forward(root, work, &format!("ab-{name}.log"))
        .map_err(|error| format!("scenario {name}: {error}"))?;
    let text = String::from_utf8_lossy(&output);

    for needle in scenario.expect {
        if !text.contains(needle) {
            return Err(format!(
                "scenario {name}: expected to see {needle:?} in boot output"
            ));
        }
    }
    for needle in scenario.reject {
        if text.contains(needle) {
            return Err(format!(
                "scenario {name}: unexpectedly saw {needle:?} in boot output"
            ));
        }
    }
    if let Some(entry) = scenario.expect_grubenv_after {
        let env = read_grubenv(work)?;
        if !env.lines().any(|line| line == entry) {
            return Err(format!(
                "scenario {name}: expected grubenv to contain {entry:?} after boot, got:\n{env}"
            ));
        }
    }
    println!("  A/B scenario ok: {name}");
    Ok(())
}

fn set_grubenv(disk: &Path, entries: &[&str]) -> Result<(), String> {
    let local = disk.with_extension("grubenv");
    run_command(
        Command::new("mcopy")
            .arg("-n")
            .arg("-i")
            .arg(disk_at(disk, "STATE"))
            .arg("::/grubenv")
            .arg(&local),
        "extract grubenv",
    )?;
    let mut edit = Command::new("grub-editenv");
    edit.arg(&local).arg("set");
    for entry in entries {
        edit.arg(entry);
    }
    run_command(&mut edit, "edit grubenv")?;
    run_command(
        Command::new("mcopy")
            .arg("-o")
            .arg("-i")
            .arg(disk_at(disk, "STATE"))
            .arg(&local)
            .arg("::/grubenv"),
        "write grubenv",
    )?;
    Ok(())
}

fn read_grubenv(disk: &Path) -> Result<String, String> {
    let local = disk.with_extension("grubenv.read");
    run_command(
        Command::new("mcopy")
            .arg("-n")
            .arg("-i")
            .arg(disk_at(disk, "STATE"))
            .arg("::/grubenv")
            .arg(&local),
        "extract grubenv",
    )?;
    let output = Command::new("grub-editenv")
        .arg(&local)
        .arg("list")
        .output()
        .map_err(|error| format!("list grubenv: {error}"))?;
    if !output.status.success() {
        return Err("grub-editenv list failed".to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Overwrite a slot's kernel signature with garbage so GRUB's enforced
/// verification rejects it, simulating a corrupt or tampered release.
fn corrupt_slot_signature(root: &Path, disk: &Path, label: &str) -> Result<(), String> {
    let garbage = root.join("build/image/garbage.sig");
    fs::write(&garbage, [0xAB_u8; 64]).map_err(|error| format!("write garbage: {error}"))?;
    run_command(
        Command::new("mcopy")
            .arg("-o")
            .arg("-i")
            .arg(disk_at(disk, label))
            .arg(&garbage)
            .arg("::/librefirewall-kernel.elf.sig"),
        "corrupt slot signature",
    )
}
