//! Booting the deployable disk in QEMU.
//!
//! Every QEMU invocation boots through the same firmware → boot-manager → seL4
//! chain the hardware appliance uses: OVMF (UEFI) loads the signed GRUB image
//! from the disk's ESP, which verifies and boots the selected slot. The disk is
//! attached as an explicit `ide-hd,bootindex=0` device so OVMF starts at GRUB
//! rather than at the firmware's own network-boot options for the virtio NICs,
//! and a per-run writable copy of the OVMF variable store keeps runs isolated.
//! Hardware acceleration is used when `/dev/kvm` is usable and a feature-pinned
//! TCG CPU is the deterministic fallback so the boot runs anywhere.
//!
//! [`test_system`] is the black-box system gate: it asserts the machine-
//! observable forwarding contract (a frame injected into each NIC port egresses
//! byte-identical on the other), driven by [`crate::forward_harness`].

use std::{fs, path::Path, process::Command};

use crate::{
    artifacts::DIST_DISK,
    forward_harness,
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
/// bidirectional forwarding contract, returning the captured serial output
/// (always also written to `build/image/<log_name>`) for callers that
/// additionally assert on boot messages.
pub(crate) fn boot_and_forward(
    root: &Path,
    disk: &Path,
    log_name: &str,
) -> Result<Vec<u8>, String> {
    let backends = forward_harness::NicBackends::new()?;
    let mut command = qemu_base(root, "stdio", disk)?;
    command.arg("-monitor").arg("none").arg("-no-shutdown");
    backends.apply(&mut command)?;
    let log = root.join("build/image").join(log_name);
    forward_harness::run_forward_test(command, backends, &log)
}

pub(crate) fn run_system(root: &Path) -> Result<(), String> {
    let disk = root.join("dist").join(DIST_DISK);
    let mut command = qemu_base(root, "mon:stdio", &disk)?;
    // Interactive runs have no harness peer to dial into, so back the two NIC
    // ports with QEMU's self-contained user-mode stack instead.
    for port in 0..2 {
        command
            .arg("-netdev")
            .arg(format!("user,id=n{port}"))
            .arg("-device")
            .arg(nic_device(port));
    }
    run_command(&mut command, "run QEMU")
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
/// hardware appliance uses. A per-run writable copy of the OVMF variable store
/// lives in the build directory; the disk itself is writable so GRUB can
/// persist boot-selection state.
pub(crate) fn qemu_base(root: &Path, serial: &str, disk: &Path) -> Result<Command, String> {
    require_file(disk)?;

    let code = locate(OVMF_CODE_CANDIDATES, "OVMF code firmware")?;
    let vars_template = locate(OVMF_VARS_CANDIDATES, "OVMF variable store")?;
    let vars = root.join("build/image/OVMF_VARS.fd");
    if let Some(parent) = vars.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    copy_file(&vars_template, &vars)?;

    // Prefer hardware acceleration when the KVM device is present and usable,
    // falling back to pure emulation so the test runs anywhere.
    let kvm = Path::new("/dev/kvm");
    let (accel, cpu) = if kvm.exists() && is_writable(kvm) {
        ("kvm", "host")
    } else {
        ("tcg", "qemu64,+fsgsbase,+pdpe1gb,+xsaveopt,+xsave")
    };

    let mut command = Command::new("qemu-system-x86_64");
    command
        .current_dir(root)
        .args(["-machine", "q35", "-accel", accel])
        .args(["-cpu", cpu])
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
        .args(["-serial", serial, "-no-reboot"]);
    Ok(command)
}

/// Linux `O_CLOEXEC`, defined here rather than depending on the `libc` crate so
/// xtask stays zero-dependency. Used only to probe `/dev/kvm`; the flag keeps
/// the probe's file descriptor from leaking into the QEMU child across exec.
const O_CLOEXEC: i32 = 0o2000000;

fn is_writable(path: &Path) -> bool {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(O_CLOEXEC)
        .open(path)
        .is_ok()
}
