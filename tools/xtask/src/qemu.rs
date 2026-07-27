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
//! [`test_system`] is the black-box system gate. It boots three [`Scenario`]s,
//! each of which asserts the machine-observable routed contract — a datagram
//! sent from the host endpoint on each NIC port reaches the endpoint on the
//! other rewritten for its next hop, and the packets the appliance must refuse
//! reach nobody — driven by [`crate::forward_harness`]; two of them
//! additionally judge the `LFW-CFG` console channel through
//! [`crate::config_transcript`].
//!
//! Every address in all of that comes from the configuration document the image
//! under test was built from, read by [`crate::topology`]. Nothing in this
//! module names an address, and the MAC it hands each guest NIC is the MAC an
//! interface in that document claims.

use std::{fs, path::Path, process::Command};

use crate::{
    artifacts::DIST_DISK,
    config_transcript::ConfigContract,
    forward_harness::{self, BootContract, BootTest, Booted},
    image,
    topology::{PORTS, Topology},
    util::{copy_file, locate, require_file, run_command},
};

/// The configuration document the different-configuration scenario builds its
/// own image from — a second bench that shares no address and no MAC with the
/// appliance's own document.
///
/// It is the harness's input rather than the appliance's, so it lives beside
/// the harness. `systems/` holds what the appliance runs, and a second document
/// there would read as a second shippable configuration.
const ALTERNATE_DOCUMENT: &str = "tools/xtask/scenarios/alternate-addressing.xml";

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

/// Which disk a scenario boots.
enum ImageUnderTest {
    /// The disk `dist/` already holds — what `image` published and what an
    /// operator would deploy. `dist/` is left exactly as it is.
    Published,
    /// A disk assembled here from the scenario's own configuration document,
    /// into the build tree. Nothing published changes.
    BuiltForTheScenario,
}

/// Whether a scenario judges the `LFW-CFG` console channel beside the traffic.
enum Transcript {
    Ignored,
    Judged,
}

/// One system scenario: which disk, which configuration document the appliance
/// in it was built from, and what the boot must prove.
struct Scenario {
    name: &'static str,
    /// The document, relative to the workspace root. It is what the endpoints
    /// are derived from *and* what the appliance was compiled around, which is
    /// the whole point: neither side of the contract can hold a stale address
    /// the other does not.
    document: &'static str,
    image: ImageUnderTest,
    transcript: Transcript,
}

/// Boot the deployable disk through OVMF/GRUB and prove the complete system
/// behaviour across three scenarios.
///
/// 1. **routed-forwarding** — the published disk, judged by the routed contract
///    alone. It is the regression guard: exactly the contract that existed
///    before configuration management, now stated between endpoints read out of
///    the document rather than written beside it, so a forwarding failure is
///    reported as a forwarding failure and nothing else.
/// 2. **generation-swap** — the same disk, judged additionally by its
///    configuration transcript: the node comes up fail-closed on generation 0
///    and switches to generation 1, whose change records are the document's own
///    diff. A separate boot, because a transcript that could only be read off a
///    run whose traffic had already passed would be silent in exactly the case
///    it exists for — a node that committed nothing and forwarded nothing.
/// 3. **alternate-configuration** — a disk assembled from a second document
///    that shares no address and no MAC with the first, judged by both. This is
///    what proves the dataplane reads its table from the document: a compiled-in
///    table would satisfy scenarios 1 and 2 and fail every probe here.
pub(crate) fn test_system(root: &Path) -> Result<(), String> {
    let scenarios = [
        Scenario {
            name: "routed-forwarding",
            document: image::CONFIGURATION_DOCUMENT,
            image: ImageUnderTest::Published,
            transcript: Transcript::Ignored,
        },
        Scenario {
            name: "generation-swap",
            document: image::CONFIGURATION_DOCUMENT,
            image: ImageUnderTest::Published,
            transcript: Transcript::Judged,
        },
        Scenario {
            name: "alternate-configuration",
            document: ALTERNATE_DOCUMENT,
            image: ImageUnderTest::BuiltForTheScenario,
            transcript: Transcript::Judged,
        },
    ];

    for scenario in &scenarios {
        run_scenario(root, scenario)?;
    }
    println!("system tests passed ({} scenarios)", scenarios.len());
    Ok(())
}

fn run_scenario(root: &Path, scenario: &Scenario) -> Result<(), String> {
    let name = scenario.name;
    let path = root.join(scenario.document);
    let document = fs::read(&path)
        .map_err(|error| format!("scenario {name}: read {}: {error}", path.display()))?;
    let topology = Topology::from_document(&document)
        .map_err(|error| format!("scenario {name}: {}: {error}", path.display()))?;

    let disk = match scenario.image {
        ImageUnderTest::Published => root.join("dist").join(DIST_DISK),
        ImageUnderTest::BuiltForTheScenario => image::scenario_image(
            root,
            image::DEBUG_CONFIG,
            Path::new(scenario.document),
            name,
        )?,
    };

    let log_name = format!("qemu-{name}.log");
    let booted = boot_and_forward(root, &disk, &log_name, &topology)
        .map_err(|error| format!("scenario {name}: {error}"))?;

    // The table before the verdict: what the two endpoints exchanged and what
    // the appliance refused is the thing a smoke run is run to see, and the
    // verdict is only the count of it. For the alternate scenario it is also
    // where a reader sees the second document's addresses on the wire.
    print!("{}", booted.traffic.render());

    let log = root.join("build/image").join(&log_name);
    let judged = match scenario.transcript {
        Transcript::Ignored => String::new(),
        Transcript::Judged => {
            let contract = ConfigContract::from_document(&document)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            contract
                .judge(&booted.serial, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            format!("; {}", contract.summary())
        }
    };
    println!(
        "  system scenario ok: {name} ({}{judged}); QEMU output is in {}",
        booted.traffic.summary(),
        log.display()
    );
    Ok(())
}

/// Boot `disk` through OVMF/GRUB with two socket-backed NICs and assert the
/// bidirectional routed contract stated between `topology`'s endpoints,
/// returning what the boot was observed to do: the guest's serial output
/// (always also written to `build/image/<log_name>`) for callers that
/// additionally assert on a structured console channel, and the traffic the
/// probes produced.
pub(crate) fn boot_and_forward(
    root: &Path,
    disk: &Path,
    log_name: &str,
    topology: &Topology,
) -> Result<Booted, String> {
    boot(root, disk, log_name, BootContract::Routed, topology)
}

/// Boot `disk` expecting NO slot to be bootable: no injected packet may come
/// back in any form, and the guest must emit `marker` — the boot manager's
/// structured halt record. Returns the same observation as
/// [`boot_and_forward`], whose traffic half records that nothing moved.
pub(crate) fn boot_and_halt(
    root: &Path,
    disk: &Path,
    log_name: &str,
    marker: &str,
    topology: &Topology,
) -> Result<Booted, String> {
    boot(
        root,
        disk,
        log_name,
        BootContract::Halted { marker },
        topology,
    )
}

fn boot(
    root: &Path,
    disk: &Path,
    log_name: &str,
    contract: BootContract,
    topology: &Topology,
) -> Result<Booted, String> {
    let run_label = log_name.strip_suffix(".log").unwrap_or(log_name);
    let backends = forward_harness::NicBackends::new()?;
    let Invocation {
        mut command,
        acceleration,
    } = qemu_base(root, "stdio", disk, run_label)?;
    command.arg("-monitor").arg("none");
    backends.apply(&mut command, topology)?;

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
            topology,
        },
    )
}

pub(crate) fn run_system(root: &Path) -> Result<(), String> {
    let disk = root.join("dist").join(DIST_DISK);
    let path = root.join(image::CONFIGURATION_DOCUMENT);
    let topology = Topology::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let Invocation {
        mut command,
        acceleration,
    } = qemu_base(root, "mon:stdio", &disk, "run")?;
    println!("QEMU run: {}", acceleration.describe());
    // Interactive runs have no harness peer to dial into, so back the two NIC
    // ports with QEMU's self-contained user-mode stack instead.
    for port in 0..PORTS {
        command
            .arg("-netdev")
            .arg(format!("user,id=n{port}"))
            .arg("-device")
            .arg(nic_device(&topology, port)?);
    }
    run_command(&mut command, "run QEMU")?;
    Ok(())
}

/// The virtio-net-pci `-device` argument for dataplane port `port`, pinned to
/// the PCI address the system description assigns (00:02.0, 00:03.0) with the
/// MAC the configuration document's interface on that port claims and no option
/// ROM (so the firmware gains no PXE payload).
///
/// The MAC is the derivation this function exists for. It used to be a literal
/// here that had to equal a literal in the harness and a third in the document,
/// with nothing comparing the three; now a guest NIC can only be given a MAC an
/// interface claims, and the address the routed contract expects the appliance
/// to answer to is that same interface's. The netdev backend (`socket` under
/// the routing harness, `user` for interactive runs) is joined separately by
/// the id `n{port}`.
///
/// # Errors
/// The port has no interface in the document, which the topology names.
pub(crate) fn nic_device(topology: &Topology, port: usize) -> Result<String, String> {
    let [a, b, c, d, e, f] = topology.port_mac(port).map_err(|error| error.to_string())?;
    Ok(format!(
        "virtio-net-pci,netdev=n{port},disable-legacy=on,disable-modern=off,\
         mac={a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x},bus=pcie.0,addr=0{}.0,romfile=",
        port + 2
    ))
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

    /// The shipped bench, so a device argument is checked against the same
    /// document the appliance in the image was built from.
    fn bench() -> Topology {
        Topology::from_document(include_bytes!(
            "../../../systems/qemu-x86_64/configuration.xml"
        ))
        .expect("the shipped document describes the bench")
    }

    #[test]
    fn each_port_gets_its_pinned_pci_address_and_no_option_rom() {
        let topology = bench();
        assert!(nic_device(&topology, 0).unwrap().contains("addr=02.0"));
        assert!(nic_device(&topology, 1).unwrap().contains("addr=03.0"));
        for port in 0..PORTS {
            assert!(
                nic_device(&topology, port).unwrap().ends_with("romfile="),
                "an option ROM would give the firmware a PXE payload"
            );
        }
    }

    /// The cross-artifact fact that used to be a comment saying nothing checked
    /// it: the MAC QEMU puts on a port is the MAC the document's interface on
    /// that port claims, so the appliance answers to the address it was
    /// configured with.
    #[test]
    fn the_mac_a_port_carries_is_the_one_its_interface_claims() {
        let topology = bench();
        for port in 0..PORTS {
            let [a, b, c, d, e, f] = topology.port_mac(port).expect("a claimed port");
            assert!(
                nic_device(&topology, port).unwrap().contains(&format!(
                    "mac={a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}"
                )),
                "port {port}"
            );
        }
        // Two ports must not answer to one address, or a routed frame would be
        // accepted by whichever NIC saw it first. `config` refuses a document
        // that says so; this is the check on the argument that reaches QEMU.
        assert_ne!(topology.port_mac(0), topology.port_mac(1));
    }

    #[test]
    fn a_port_this_build_has_none_of_yields_no_device_argument() {
        let error = nic_device(&bench(), PORTS).expect_err("there is no such port");
        assert!(error.contains(&format!("{PORTS}")), "{error}");
    }

    /// The alternate scenario's document is a different bench, and the device
    /// arguments it produces must differ in every MAC — the property scenario 3
    /// rests on.
    #[test]
    fn the_alternate_document_puts_different_macs_on_the_same_ports() {
        let alternate =
            Topology::from_document(include_bytes!("../scenarios/alternate-addressing.xml"))
                .expect("the alternate document describes a bench");
        let shipped = bench();
        for port in 0..PORTS {
            assert_ne!(
                nic_device(&shipped, port).unwrap(),
                nic_device(&alternate, port).unwrap()
            );
        }
    }
}
