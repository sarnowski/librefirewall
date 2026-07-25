//! Booting the deployable disk in QEMU.
//!
//! Every QEMU invocation boots through the same firmware → boot-manager → seL4
//! chain the hardware appliance uses: OVMF (UEFI) loads the signed GRUB image
//! from the disk's ESP, which verifies and boots the selected slot. The disk is
//! attached as an explicit `ide-hd,bootindex=0` device so OVMF starts at GRUB
//! rather than at the firmware's own network-boot options for the virtio NICs.
//!
//! Two properties keep a run's result independent of the machine it ran on.
//! The guest CPU model is [`GUEST_CPU`] whether or not KVM is available, so the
//! asserted contract never varies with the runner's host CPU; and the
//! [`Acceleration`] actually chosen — with the reason KVM was rejected — is
//! printed and written into the run log, so an unnoticed degradation to
//! emulation cannot pass for an accelerated run.
//!
//! [`test_system`] is the black-box system gate: it asserts the machine-
//! observable forwarding contract (a frame injected into each NIC port egresses
//! byte-identical on the other), driven by [`crate::forward_harness`].

use std::{fs, path::Path, process::Command};

use crate::{
    artifacts::DIST_DISK,
    forward_harness::{self, BootContract, BootTest},
    util::{copy_file, locate, require_file, run_command},
};

// UEFI firmware for the OVMF boot path; the first existing candidate is used.
const OVMF_CODE_CANDIDATES: &[&str] = &[
    "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
];
const OVMF_VARS_CANDIDATES: &[&str] = &[
    "/usr/share/OVMF/OVMF_VARS_4M.fd",
    "/usr/share/OVMF/OVMF_VARS.fd",
];

const KVM_DEVICE: &str = "/dev/kvm";

/// The guest CPU, pinned to one feature set for BOTH accelerators. seL4's
/// x86_64 kernel needs these features present; naming them explicitly (rather
/// than passing `host` under KVM) is what makes the boot the system test
/// asserts on identical on every runner, accelerated or not. Every feature here
/// has been baseline on x86-64 since well before the hardware this project
/// targets, so pinning them costs no KVM host compatibility.
const GUEST_CPU: &str = "qemu64,+fsgsbase,+pdpe1gb,+xsaveopt,+xsave";

/// How QEMU will execute the guest and, when hardware acceleration was not
/// taken, why. Carrying the reason (rather than a bare flag) is the point: a CI
/// run that silently fell back to emulation must not be indistinguishable from
/// an accelerated one in its log.
enum Acceleration {
    Kvm,
    Tcg { kvm_rejected_because: String },
}

impl Acceleration {
    /// Prefer hardware acceleration, but only when this process can actually
    /// open the KVM device read/write — the access QEMU itself needs.
    /// Existence alone is not enough: a container can expose the device node
    /// without granting the permission to use it.
    fn detect() -> Self {
        // `OpenOptions` opens with `O_CLOEXEC` on Linux and the handle is
        // dropped here, so the probe cannot leak a descriptor into QEMU.
        match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(KVM_DEVICE)
        {
            Ok(_probe) => Self::Kvm,
            Err(error) => Self::Tcg {
                kvm_rejected_because: format!("cannot open {KVM_DEVICE} read-write: {error}"),
            },
        }
    }

    fn qemu_accel(&self) -> &'static str {
        match self {
            Self::Kvm => "kvm",
            Self::Tcg { .. } => "tcg",
        }
    }

    /// One line recording how the guest ran, for the operator's terminal and
    /// for the run log.
    fn describe(&self) -> String {
        match self {
            Self::Kvm => format!("accel=kvm cpu={GUEST_CPU}"),
            Self::Tcg {
                kvm_rejected_because,
            } => format!("accel=tcg cpu={GUEST_CPU} kvm-rejected: {kvm_rejected_because}"),
        }
    }
}

/// A prepared QEMU invocation together with the record of how it will execute.
struct Invocation {
    command: Command,
    acceleration: Acceleration,
}

/// Boot the deployable disk through OVMF/GRUB and prove the complete system
/// behaviour: a frame injected into each NIC port must egress byte-identical
/// on the opposite port.
pub(crate) fn test_system(root: &Path) -> Result<(), String> {
    let disk = root.join("dist").join(DIST_DISK);
    boot_and_forward(root, &disk, "qemu.log")?;
    println!(
        "system test passed; QEMU output is in {}",
        root.join("build/image/qemu.log").display()
    );
    Ok(())
}

/// Boot `disk` through OVMF/GRUB with two socket-backed NICs and assert the
/// bidirectional forwarding contract, returning the captured guest serial
/// output (always also written to `build/image/<log_name>`) for callers that
/// additionally assert on the boot manager's structured records.
pub(crate) fn boot_and_forward(
    root: &Path,
    disk: &Path,
    log_name: &str,
) -> Result<Vec<u8>, String> {
    boot(root, disk, log_name, BootContract::Forwarding)
}

/// Boot `disk` expecting NO slot to be bootable: no injected frame may be
/// forwarded, and the guest must emit `marker` — the boot manager's structured
/// halt record. Returns the captured guest serial output like
/// [`boot_and_forward`].
pub(crate) fn boot_and_halt(
    root: &Path,
    disk: &Path,
    log_name: &str,
    marker: &str,
) -> Result<Vec<u8>, String> {
    boot(root, disk, log_name, BootContract::Halted { marker })
}

fn boot(
    root: &Path,
    disk: &Path,
    log_name: &str,
    contract: BootContract,
) -> Result<Vec<u8>, String> {
    let run_label = log_name.strip_suffix(".log").unwrap_or(log_name);
    let backends = forward_harness::NicBackends::new()?;
    let Invocation {
        mut command,
        acceleration,
    } = qemu_base(root, "stdio", disk, run_label)?;
    command.arg("-monitor").arg("none");
    backends.apply(&mut command)?;

    let description = acceleration.describe();
    println!("  QEMU {run_label}: {description}");
    let log = root.join("build/image").join(log_name);
    let header = format!(
        "# librefirewall QEMU run: {run_label}\n\
         # {description}\n\
         # --- captured guest serial output follows ---\n"
    );
    forward_harness::run_boot_test(
        command,
        backends,
        BootTest {
            contract,
            log_path: &log,
            log_header: &header,
        },
    )
}

pub(crate) fn run_system(root: &Path) -> Result<(), String> {
    let disk = root.join("dist").join(DIST_DISK);
    let Invocation {
        mut command,
        acceleration,
    } = qemu_base(root, "mon:stdio", &disk, "run")?;
    println!("QEMU run: {}", acceleration.describe());
    // Interactive runs have no harness peer to dial into, so back the two NIC
    // ports with QEMU's self-contained user-mode stack instead.
    for port in 0..2 {
        command
            .arg("-netdev")
            .arg(format!("user,id=n{port}"))
            .arg("-device")
            .arg(nic_device(port));
    }
    run_command(&mut command, "run QEMU")?;
    Ok(())
}

/// The virtio-net-pci `-device` argument for dataplane port `port` (0 or 1),
/// pinned to the PCI address the system description assigns (00:02.0, 00:03.0)
/// with the matching per-port MAC and no option ROM (so the firmware gains no
/// PXE payload). This is the single definition of the device contract; the
/// netdev backend (`socket` under the forwarding harness, `user` for
/// interactive runs) is joined separately by the id `n{port}`.
pub(crate) fn nic_device(port: usize) -> String {
    format!(
        "virtio-net-pci,netdev=n{port},disable-legacy=on,disable-modern=off,\
         mac=52:54:00:12:34:5{port},bus=pcie.0,addr=0{}.0,romfile=",
        port + 2
    )
}

/// Build the shared QEMU invocation that boots the deployable disk through
/// OVMF (UEFI) and the signed GRUB image, rather than QEMU's direct multiboot
/// loader. This exercises the same firmware -> boot-manager -> seL4 chain the
/// hardware appliance uses. The disk itself is writable so GRUB can persist
/// boot-selection state.
///
/// Each invocation gets its own writable copy of the OVMF variable store, named
/// after `run_label` and reset from the pristine template every time, so one
/// A/B scenario's UEFI boot-variable writes cannot influence the next. Like the
/// rest of `build/image` — the scenario disk and the run logs included — it
/// assumes one build at a time; the build tree is not a concurrency domain.
fn qemu_base(
    root: &Path,
    serial: &str,
    disk: &Path,
    run_label: &str,
) -> Result<Invocation, String> {
    require_file(disk)?;

    let code = locate(OVMF_CODE_CANDIDATES, "OVMF code firmware")?;
    let vars_template = locate(OVMF_VARS_CANDIDATES, "OVMF variable store")?;
    let vars = root
        .join("build/image")
        .join(format!("OVMF_VARS-{run_label}.fd"));
    if let Some(parent) = vars.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    copy_file(&vars_template, &vars)?;

    let acceleration = Acceleration::detect();

    let mut command = Command::new("qemu-system-x86_64");
    command
        .current_dir(root)
        .args(["-machine", "q35", "-accel", acceleration.qemu_accel()])
        .args(["-cpu", GUEST_CPU])
        .args(["-m", "1G", "-display", "none"])
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            code.display()
        ))
        .arg("-drive")
        .arg(format!("if=pflash,format=raw,file={}", vars.display()))
        // Attach the disk as an explicit device with bootindex=0 so OVMF's
        // boot order starts at GRUB on the disk rather than at the firmware's
        // own network-boot options for the virtio NICs.
        .arg("-drive")
        .arg(format!(
            "if=none,id=boot,format=raw,file={}",
            disk.display()
        ))
        .args(["-device", "ide-hd,drive=boot,bootindex=0"])
        // `-no-reboot` turns a guest reset request into a QEMU exit instead of
        // a boot loop. There is deliberately no `-no-shutdown` beside it:
        // letting a guest power-off exit QEMU is what keeps the harness's fast,
        // specific "QEMU exited" diagnostic reachable — otherwise every
        // guest-initiated exit degrades into the 180 s timeout — and it is what
        // makes the boot manager's halt path observable as an exit at all.
        .args(["-serial", serial, "-no-reboot"]);
    Ok(Invocation {
        command,
        acceleration,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_accelerators_present_the_same_guest_cpu() {
        // The asserted boot contract must not depend on the runner's host CPU,
        // so the CPU model is one pinned string and only `-accel` varies.
        assert_eq!(Acceleration::Kvm.qemu_accel(), "kvm");
        assert_eq!(
            Acceleration::Tcg {
                kvm_rejected_because: "probe failed".to_owned(),
            }
            .qemu_accel(),
            "tcg"
        );
        assert!(
            !GUEST_CPU.contains("host"),
            "the host CPU must never leak in"
        );
    }

    #[test]
    fn a_tcg_fallback_always_carries_the_reason_kvm_was_rejected() {
        let kvm = Acceleration::Kvm.describe();
        assert!(kvm.contains("accel=kvm") && kvm.contains(GUEST_CPU));
        assert!(!kvm.contains("kvm-rejected"));

        let tcg = Acceleration::Tcg {
            kvm_rejected_because: "cannot open /dev/kvm read-write: Permission denied".to_owned(),
        }
        .describe();
        assert!(tcg.contains("accel=tcg") && tcg.contains(GUEST_CPU));
        assert!(
            tcg.contains("Permission denied"),
            "the rejection cause must survive into the log: {tcg}"
        );
    }

    #[test]
    fn detection_reports_a_concrete_reason_when_kvm_is_unusable() {
        // Whatever this machine offers, the decision must be self-describing:
        // either accelerated, or emulated WITH the reason attached.
        match Acceleration::detect() {
            Acceleration::Kvm => assert!(Path::new(KVM_DEVICE).exists()),
            Acceleration::Tcg {
                kvm_rejected_because,
            } => assert!(
                kvm_rejected_because.contains(KVM_DEVICE),
                "the reason must name the device it probed: {kvm_rejected_because}"
            ),
        }
    }

    #[test]
    fn each_port_gets_its_pinned_pci_address_and_mac_with_no_option_rom() {
        assert!(nic_device(0).contains("addr=02.0") && nic_device(0).contains("34:50"));
        assert!(nic_device(1).contains("addr=03.0") && nic_device(1).contains("34:51"));
        for port in 0..2 {
            assert!(
                nic_device(port).ends_with("romfile="),
                "an option ROM would give the firmware a PXE payload"
            );
        }
    }
}
