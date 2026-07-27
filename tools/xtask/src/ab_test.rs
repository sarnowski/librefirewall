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
//! the boot-selection state (and, where relevant, breaks a slot or tears the
//! env block) exactly as the real update flow or a failed boot would leave it,
//! then boots through OVMF/GRUB and asserts two independent things.
//!
//! **Which slot was chosen** is asserted against the boot manager's structured
//! channel: GRUB emits one `LFW-BOOT slot=… state=…` record per selection
//! decision, and each scenario declares the EXACT ORDERED SEQUENCE it must
//! produce. Nothing weaker suffices, for two reasons. Both slots are seeded
//! with the byte-identical signed payload, so no observation downstream of GRUB
//! can name the slot that booted; and a needle test cannot tell "slot B booted"
//! from "slot B was tried, was rejected, and A booted instead", because the
//! record announcing the attempt is present either way. Only the full sequence
//! separates them.
//!
//! **That the chosen slot is healthy** is asserted by the system's real
//! observable contract — a datagram routed between the two NIC ports in each
//! direction — or, for the scenarios where nothing may boot, by its negative:
//! nothing comes back off either port and GRUB's halt record is on the channel.
//! Because a packet can only be routed after seL4 has started, and seL4 only
//! starts after GRUB's last record, the record sequence is always complete by
//! the time it is judged.

use std::{fs, path::Path, process::Command};

use crate::{
    artifacts::DIST_DISK,
    disk::disk_at,
    qemu::{boot_and_forward, boot_and_halt},
    util::{copy_file, require_file, run_command},
};

/// The prefix marking a serial line as a boot-manager record rather than
/// console prose. The grammar is fixed in `third-party/grub/grub.cfg`.
const BOOT_RECORD_PREFIX: &str = "LFW-BOOT ";

/// The record GRUB emits once no slot could be booted, immediately before it
/// halts. It is both an expected record and the marker the halt scenarios wait
/// for on the serial channel.
const HALT_RECORD: &str = "LFW-BOOT slot=none state=halted";

/// How a scenario's boot must end.
enum Outcome {
    /// A slot boots and the appliance routes a datagram in each direction, so
    /// "booted" means the whole stack came up — firmware, boot manager, seL4,
    /// both NIC drivers and the routing stage — not merely that GRUB spoke.
    Routes,
    /// No slot is bootable: GRUB must reach its halt path and no injected
    /// packet may come back.
    Halts,
}

/// The boot-selection state a scenario starts the disk from.
enum GrubenvSeed<'a> {
    /// A well-formed env block carrying exactly these entries.
    Entries(&'a [&'a str]),
    /// A torn env block, as an interrupted write to STATE would leave it:
    /// GRUB can neither read the selection state nor record a new attempt.
    Torn,
}

/// One A/B boot scenario: the boot-selection state the disk is seeded with,
/// any slots whose signature is corrupted before boot, the exact sequence of
/// boot-manager records the boot must emit, how the boot must end, and an
/// optional grubenv entry expected to persist afterwards.
struct Scenario<'a> {
    name: &'a str,
    grubenv: GrubenvSeed<'a>,
    corrupt_slots: &'a [&'a str],
    records: &'a [&'a str],
    outcome: Outcome,
    expect_grubenv_after: Option<&'a str>,
}

/// Exercise the A/B boot state machine end to end: the five scenarios spanning
/// the update flow (confirmed A, a first try of staged B, fallback from a
/// signature-broken B, skipping an exhausted B, a committed B), the recovery of
/// an uninterpretable `ORDER`, and the two ways every slot can become
/// unbootable — a broken payload, and boot state that cannot record an attempt.
pub(crate) fn test_ab(root: &Path) -> Result<(), String> {
    let dist_disk = root.join("dist").join(DIST_DISK);
    require_file(&dist_disk)?;
    let work = root.join("build/image/ab-test.img");

    let scenarios = [
        // 1. Confirmed A boots directly.
        Scenario {
            name: "confirmed-A",
            grubenv: GrubenvSeed::Entries(&["ORDER=A B", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=0"]),
            corrupt_slots: &[],
            records: &["LFW-BOOT slot=A state=confirmed"],
            outcome: Outcome::Routes,
            expect_grubenv_after: None,
        },
        // 2. A staged, unconfirmed B is tried once and boots. The absence of
        //    any further record is what proves B actually booted rather than
        //    falling through to A.
        Scenario {
            name: "try-pending-B",
            grubenv: GrubenvSeed::Entries(&["ORDER=B A", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=0"]),
            corrupt_slots: &[],
            records: &["LFW-BOOT slot=B state=trying"],
            outcome: Outcome::Routes,
            expect_grubenv_after: Some("B_TRY=1"),
        },
        // 3. A broken (signature-failing) pending B is rejected and the boot
        //    falls back to confirmed A within the same boot. The attempt is
        //    still consumed, so a later boot will not retry B.
        Scenario {
            name: "fallback-from-broken-B",
            grubenv: GrubenvSeed::Entries(&["ORDER=B A", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=0"]),
            corrupt_slots: &["SLOTB"],
            records: &[
                "LFW-BOOT slot=B state=trying",
                "LFW-BOOT slot=B state=rejected",
                "LFW-BOOT slot=A state=confirmed",
            ],
            outcome: Outcome::Routes,
            expect_grubenv_after: Some("B_TRY=1"),
        },
        // 4. A pending B that was already tried but never confirmed (the
        //    aftermath of a hang plus watchdog reset) is skipped for A.
        Scenario {
            name: "skip-exhausted-B",
            grubenv: GrubenvSeed::Entries(&["ORDER=B A", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=1"]),
            corrupt_slots: &[],
            records: &[
                "LFW-BOOT slot=B state=exhausted",
                "LFW-BOOT slot=A state=confirmed",
            ],
            outcome: Outcome::Routes,
            expect_grubenv_after: None,
        },
        // 5. Once B is confirmed healthy (the update is committed), B boots
        //    directly.
        Scenario {
            name: "confirmed-B",
            grubenv: GrubenvSeed::Entries(&["ORDER=B A", "A_OK=0", "A_TRY=0", "B_OK=1", "B_TRY=0"]),
            corrupt_slots: &[],
            records: &["LFW-BOOT slot=B state=confirmed"],
            outcome: Outcome::Routes,
            expect_grubenv_after: None,
        },
        // 6. An ORDER naming a slot that does not exist is corrupt state, not
        //    a preference: it must be reported and the built-in A-first order
        //    used, rather than acted on or silently ignored.
        Scenario {
            name: "unknown-order-falls-back-to-default",
            grubenv: GrubenvSeed::Entries(&["ORDER=C D", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=0"]),
            corrupt_slots: &[],
            records: &[
                "LFW-BOOT slot=none state=bad-order",
                "LFW-BOOT slot=A state=confirmed",
            ],
            outcome: Outcome::Routes,
            expect_grubenv_after: None,
        },
        // 7. Both slots carry a broken payload: each is offered, rejected, and
        //    the boot manager halts rather than running anything. B's attempt
        //    is still consumed, so recovery cannot become a retry loop.
        Scenario {
            name: "halt-when-both-slots-are-broken",
            grubenv: GrubenvSeed::Entries(&["ORDER=A B", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=0"]),
            corrupt_slots: &["SLOTA", "SLOTB"],
            records: &[
                "LFW-BOOT slot=A state=confirmed",
                "LFW-BOOT slot=A state=rejected",
                "LFW-BOOT slot=B state=trying",
                "LFW-BOOT slot=B state=rejected",
                HALT_RECORD,
            ],
            outcome: Outcome::Halts,
            expect_grubenv_after: Some("B_TRY=1"),
        },
        // 8. A torn env block leaves both slots unconfirmed AND makes the
        //    attempt unrecordable. Booting anyway would break the
        //    single-attempt guarantee — the same slot would be retried forever
        //    after a hang — so each slot is refused and the boot manager halts.
        //    The env block is unreadable afterwards, so nothing is asserted of
        //    it.
        Scenario {
            name: "halt-when-an-attempt-cannot-persist",
            grubenv: GrubenvSeed::Torn,
            corrupt_slots: &[],
            records: &[
                "LFW-BOOT slot=A state=trying",
                "LFW-BOOT slot=A state=unpersisted",
                "LFW-BOOT slot=B state=trying",
                "LFW-BOOT slot=B state=unpersisted",
                HALT_RECORD,
            ],
            outcome: Outcome::Halts,
            expect_grubenv_after: None,
        },
    ];

    for scenario in &scenarios {
        run_scenario(root, &dist_disk, &work, scenario)?;
    }

    println!("A/B fallback tests passed ({} scenarios)", scenarios.len());
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
    match scenario.grubenv {
        GrubenvSeed::Entries(entries) => set_grubenv(work, entries)?,
        GrubenvSeed::Torn => tear_grubenv(root, work)?,
    }
    for slot in scenario.corrupt_slots {
        corrupt_slot_signature(root, work, slot)?;
    }

    let log_name = format!("ab-{name}.log");
    let booted = match scenario.outcome {
        Outcome::Routes => boot_and_forward(root, work, &log_name),
        Outcome::Halts => boot_and_halt(root, work, &log_name, HALT_RECORD),
    }
    .map_err(|error| format!("scenario {name}: {error}"))?;

    let text = String::from_utf8_lossy(&booted.serial);
    let observed = boot_records(&text);
    if observed.as_slice() != scenario.records {
        return Err(format!(
            "scenario {name}: the boot manager did not make the expected sequence of \
             decisions\n  expected: {:#?}\n  observed: {:#?}\n  full run log: {}",
            scenario.records,
            observed,
            root.join("build/image").join(&log_name).display()
        ));
    }

    if let Some(entry) = scenario.expect_grubenv_after {
        let env = read_grubenv(work)?;
        if !env.lines().any(|line| line == entry) {
            return Err(format!(
                "scenario {name}: expected grubenv to contain {entry:?} after boot, got:\n{env}"
            ));
        }
    }
    // The counts, not the whole traffic table: eight scenarios each printing
    // the same six-line table would bury the one line per scenario that says
    // which of them ran. A halted scenario is a scenario nothing routed
    // through, so counting its traffic would only restate its name.
    let traffic = match scenario.outcome {
        Outcome::Routes => format!(" ({})", booted.traffic.summary()),
        Outcome::Halts => String::new(),
    };
    println!("  A/B scenario ok: {name}{traffic}");
    Ok(())
}

/// Extract the boot manager's records from a serial capture, in emission order.
/// Only lines carrying [`BOOT_RECORD_PREFIX`] participate, so GRUB's prose,
/// seL4's boot chatter and QEMU's own diagnostics can never be mistaken for a
/// selection decision.
fn boot_records(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| line.starts_with(BOOT_RECORD_PREFIX))
        .collect()
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

/// Replace the boot-selection env block with garbage of the right size, as a
/// write interrupted by a power loss would leave it. GRUB's env block opens
/// with a fixed signature, so a block without one is rejected by both
/// `load_env` and `save_env` — which is exactly the state under test.
fn tear_grubenv(root: &Path, disk: &Path) -> Result<(), String> {
    let torn = root.join("build/image/torn.grubenv");
    fs::write(&torn, [0xAB_u8; 1024]).map_err(|error| format!("write torn grubenv: {error}"))?;
    run_command(
        Command::new("mcopy")
            .arg("-o")
            .arg("-i")
            .arg(disk_at(disk, "STATE"))
            .arg(&torn)
            .arg("::/grubenv"),
        "tear grubenv",
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
        return Err(format!(
            "grub-editenv list failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
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
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_extracted_in_order_and_only_from_the_structured_channel() {
        // A realistic capture: GRUB prose, seL4 boot chatter and a QEMU
        // diagnostic around the records, with the CRLF a serial console emits.
        let capture = "SeaBIOS\r\n\
             LFW-BOOT slot=B state=trying\r\n\
             librefirewall: trying slot B\r\n\
             error: bad signature.\r\n\
             LFW-BOOT slot=B state=rejected\r\n\
             LFW-BOOT slot=A state=confirmed\r\n\
             librefirewall: booting confirmed slot A\r\n\
             Bootstrapping kernel\r\n";

        assert_eq!(
            boot_records(capture),
            [
                "LFW-BOOT slot=B state=trying",
                "LFW-BOOT slot=B state=rejected",
                "LFW-BOOT slot=A state=confirmed",
            ]
        );
    }

    #[test]
    fn prose_naming_a_slot_is_never_read_as_a_decision() {
        // The whole point of the structured channel: human text mentioning a
        // slot — including a line that merely quotes a record — contributes
        // nothing to the asserted sequence.
        let capture = "librefirewall: booting confirmed slot A\r\n\
             booting slot B now\r\n\
             see LFW-BOOT slot=A state=confirmed for details\r\n";

        assert!(boot_records(capture).is_empty());
    }

    #[test]
    fn the_halt_record_is_a_well_formed_record() {
        // The halt marker is handed to the QEMU harness as a raw substring to
        // watch for, and is also asserted as the final record; the two uses
        // must not be able to drift apart.
        assert!(HALT_RECORD.starts_with(BOOT_RECORD_PREFIX));
        assert_eq!(boot_records(&format!("{HALT_RECORD}\r\n")), [HALT_RECORD]);
    }
}
