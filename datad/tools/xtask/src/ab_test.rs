//! The A/B boot state-machine system test.
//!
//! GRUB's slot selection follows the `OK`/`TRY`/`ORDER` scheme:
//! a confirmed slot (`*_OK`) boots immediately; an unconfirmed slot is tried
//! once (its `*_TRY` is set before hand-off) and, if it never confirms health,
//! the next slot in `ORDER` is used. GRUB's single-attempt model means a slot
//! that fails verification is skipped within the same boot, while a slot that
//! would hang is represented by its persistent aftermath (TRY set, OK unset) —
//! exactly what a watchdog reset leaves behind.
//!
//! Each [`Scenario`] starts from a fresh copy of a pristine disk built in the
//! RELEASE kernel configuration — the image a release publishes — sets
//! the boot-selection state (and, where relevant, breaks a slot or tears the
//! env block) exactly as the real update flow or a failed boot would leave it,
//! then boots through OVMF/GRUB and asserts two independent things.
//!
//! The kernel configuration is load-bearing for only one of the two. GRUB emits
//! its records before any kernel is entered, so the slot half reads identically
//! under either build; the *health* half is the whole booted stack behind that
//! choice, and reads identically under neither. A scenario that fails is
//! therefore re-run once against the debug kernel by [`crate::diagnose`], whose
//! verdict reports the divergence; that re-run is evidence and never changes
//! the outcome.
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
//! **That the chosen slot is healthy** is asserted the only way this system's
//! health is observable from outside it: a datagram crossing between the two NIC
//! ports in each direction, out of the six probes the system gate's regression
//! set injects. Health for a firewall is carrying traffic, and a slot that came
//! up carrying nothing is not a slot that works — so a dataplane broken by
//! whatever the machinery selected must fail here rather than pass.
//!
//! That needs an appliance somebody owns, a node no management plane has taken
//! refusing every frame before it looks at it. So this run **onboards one of its
//! own first**, and each booting scenario attaches its own copy of the medium
//! that boot leaves — which is what a deployed appliance is: onboarded once, long
//! ago, running ever since. One copy per scenario, so no scenario's writes can
//! reach another's verdict, and the copies come from a boot this run performed
//! rather than from whatever file some other command left, which is what keeps
//! the run standalone. The cost is one boot, and it buys the property the suite
//! exists for.
//!
//! For the scenarios where nothing may boot, the negative — and those keep the
//! factory-fresh medium a disk under an A/B test really carries, an owner
//! deciding nothing on a slot that never ran: nothing comes back off either port,
//! none of the records a running stack produces exists, and GRUB's halt record is
//! on the channel. Because no domain speaks before seL4 has started, and seL4
//! only starts after GRUB's last record, the record sequence is always complete
//! by the time it is judged.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use lfw_log::Ownership;

use crate::{
    artifacts::DIST_DISK,
    diagnose::{self, Run},
    disk::disk_at,
    forward_harness::{ManagementBacking, Traffic},
    image, ownership_contract,
    qemu::{self, boot_and_forward, boot_and_halt},
    topology::Topology,
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
    /// A slot boots and the appliance it brings up **moves a datagram in each
    /// direction**, so "booted" means the whole stack came up and works —
    /// firmware, boot manager, seL4, both NIC drivers and the routing stage — and
    /// not merely that GRUB spoke.
    ///
    /// This is the subject of the suite rather than an extra it happens to
    /// assert. What A/B selection is *for* is that the slot it picked yields a
    /// working firewall; a contract that only asked whether the stack started
    /// would be satisfied by a slot whose dataplane carries nothing, which is the
    /// one failure the machinery under test can actually cause.
    ///
    /// Every scenario taking this attaches its own copy of the medium this run's
    /// onboarding boot left, because an appliance nobody has taken forwards
    /// nothing at all and would refuse all six probes whatever slot it booted
    /// from.
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

/// The pristine disk every scenario is seeded from, for one kind of run.
///
/// A [`Run::Diagnostic`] re-run assembles its own into the build tree; it may
/// not call [`image::image`], which publishes into `dist/` and would overwrite
/// the release artifact the failing run was judging.
fn pristine_disk(root: &Path, run: Run) -> Result<PathBuf, String> {
    match run {
        Run::Shipping => {
            let disk = root.join("dist").join(DIST_DISK);
            require_file(&disk)?;
            Ok(disk)
        }
        Run::Diagnostic => Ok(image::scenario_image(
            root,
            run.config(),
            Path::new(image::CONFIGURATION_DOCUMENT),
            &format!("ab{}", run.name_suffix()),
        )?),
    }
}

/// Exercise the A/B boot state machine end to end: the five scenarios spanning
/// the update flow (confirmed A, a first try of staged B, fallback from a
/// signature-broken B, skipping an exhausted B, a committed B), the recovery of
/// an uninterpretable `ORDER`, and the two ways every slot can become
/// unbootable — a broken payload, and boot state that cannot record an attempt.
///
/// Returns what the run proved.
pub(crate) fn test_ab(root: &Path) -> Result<String, String> {
    // Every scenario boots a disk built from the appliance's own configuration
    // document, so the bench is the one that document describes. Read once:
    // which slot GRUB chose is what varies here, never the addressing behind it.
    let document = root.join(image::CONFIGURATION_DOCUMENT);
    let topology =
        Topology::read(&document).map_err(|error| format!("{}: {error}", document.display()))?;

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
            corrupt_slots: &["SLOT_B"],
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
            corrupt_slots: &["SLOT_A", "SLOT_B"],
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

    let pristine = pristine_disk(root, Run::Shipping)?;
    // This run's own owned appliance, and the first thing it boots. Every
    // scenario below whose subject is that the slot it selected *works* takes a
    // copy of the medium this boot leaves: health for a firewall is carrying
    // traffic, and a node nobody has onboarded carries none. Its own boot rather
    // than a medium some other gate command left, so `test-ab` proves what it
    // proves on its own.
    qemu::boot_the_owned_medium_source(root)?;
    for scenario in &scenarios {
        if let Err(verdict) = run_scenario(root, &pristine, scenario, &topology, Run::Shipping) {
            return Err(diagnose::after_shipping_failure(
                &format!("A/B scenario {}", scenario.name),
                verdict,
                &scenario_log(root, scenario.name, Run::Shipping),
                &scenario_log(root, scenario.name, Run::Diagnostic),
                || {
                    let pristine = pristine_disk(root, Run::Diagnostic)?;
                    run_scenario(root, &pristine, scenario, &topology, Run::Diagnostic)
                },
            ));
        }
    }

    let routed = scenarios
        .iter()
        .filter(|scenario| matches!(scenario.outcome, Outcome::Routes))
        .count();
    Ok(format!(
        "{} A/B scenarios on the {} kernel, {routed} of them holding the slot they selected to \
         moving a datagram in each direction across an appliance this run onboarded first",
        scenarios.len(),
        Run::Shipping.config()
    ))
}

/// Where one scenario's serial capture goes, per run — never the same path for
/// both, so a diagnostic re-run cannot overwrite the failing shipping run's log.
fn scenario_log(root: &Path, name: &str, run: Run) -> PathBuf {
    root.join("build/image")
        .join(format!("ab-{name}{}.log", run.name_suffix()))
}

fn run_scenario(
    root: &Path,
    pristine: &Path,
    scenario: &Scenario,
    topology: &Topology,
    run: Run,
) -> Result<(), String> {
    let name = scenario.name;
    // Per run, for the same reason the log is: the seeded and corrupted disk a
    // shipping scenario failed on is evidence, and a re-run must not eat it.
    let work = root
        .join("build/image")
        .join(format!("ab-test{}.img", run.name_suffix()));
    copy_file(pristine, &work)?;
    match scenario.grubenv {
        GrubenvSeed::Entries(entries) => set_grubenv(&work, entries)?,
        GrubenvSeed::Torn => tear_grubenv(root, &work)?,
    }
    for slot in scenario.corrupt_slots {
        corrupt_slot_signature(root, &work, slot)?;
    }

    let log_name = format!("ab-{name}{}.log", run.name_suffix());
    // What the medium this boot attaches says about ownership, decided here
    // beside the medium itself rather than stated somewhere a later edit could
    // move one without the other. It is the premise the routed contract rests on:
    // an appliance nobody has taken refuses every frame, and a run that let the
    // two drift would report the refusal as a forwarding failure.
    let owner = match scenario.outcome {
        Outcome::Routes => Ownership::Owned,
        Outcome::Halts => Ownership::Unowned,
    };
    let booted = match scenario.outcome {
        Outcome::Routes => {
            boot_and_forward(
                root,
                &work,
                &log_name,
                topology,
                crate::qemu::ForwardBench {
                    management: ManagementBacking::Socket,
                    // The same six frames the system gate's regression set
                    // injects, two of them owed a crossing: what says the slot
                    // this boot selected produced a working appliance is the
                    // appliance working.
                    traffic: Traffic::Routed,
                    // The dial is answered and nothing is required of it: what
                    // these scenarios are about is which slot booted, and the
                    // channel the appliance opens is judged where its own
                    // scenario judges it.
                    dial: crate::qemu::DialContract::Answered,
                    // And nothing at all on the onboarding port, for the same
                    // reason: that port holds one connection, and a session
                    // opened here would sit beside a contract about which slot
                    // booted.
                    onboard: crate::qemu::OnboardContract::Untouched,
                    // This boot's own copy of the medium this run's onboarding
                    // boot left. A copy rather than that file itself, because
                    // these boots make no claim about the medium and write to it;
                    // one copy per scenario means none of them can decide
                    // another's verdict.
                    store: crate::qemu::StoreMedium::CopiedFrom(qemu::OWNED_MEDIUM_SOURCE),
                    // A fresh recorder medium, like every boot but the one whose
                    // subject is the reboot: the witness sector each of these is
                    // judged on is evidence only because no earlier guest wrote
                    // it.
                    data: crate::qemu::DataMedium::Fresh,
                    owner,
                },
            )
        }
        Outcome::Halts => boot_and_halt(root, &work, &log_name, HALT_RECORD, topology),
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
            scenario_log(root, name, run).display()
        ));
    }

    if let Some(entry) = scenario.expect_grubenv_after {
        let env = read_grubenv(&work)?;
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
    //
    // Beside it, on the boots that route, the premise that contract rests on:
    // the forwarding domain's own word for whether this appliance has an owner,
    // held to the medium the harness attached. Without it a copy that failed to
    // carry an owner is reported as a routed contract that timed out, which names
    // the symptom and leaves the cause to be guessed at.
    let traffic = match scenario.outcome {
        Outcome::Routes => {
            let owned =
                ownership_contract::judge(&booted.serial, owner, &scenario_log(root, name, run))
                    .map_err(|error| format!("scenario {name}: {error}"))?;
            format!(" ({}; {owned})", booted.traffic.summary())
        }
        Outcome::Halts => String::new(),
    };
    println!(
        "  A/B scenario ok: {name} on the {} kernel{traffic}",
        run.config()
    );
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
