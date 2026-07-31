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
//! Every scenario boots the RELEASE kernel configuration, because that is the
//! image a release publishes (BLD-3). A scenario that fails there is re-run
//! once against the debug kernel by [`crate::diagnose`], whose verdict reports
//! the divergence; that re-run is evidence and never changes the outcome.
//!
//! Every address in all of that comes from the configuration document the image
//! under test was built from, read by [`crate::topology`]. Nothing in this
//! module names an address, and the MAC it hands each guest NIC is the MAC an
//! interface in that document claims.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    artifacts::DIST_DISK,
    clock_contract,
    config_transcript::ConfigContract,
    diagnose::{self, GUEST_OUTPUT_MARKER, Run},
    forward_harness::{self, BootContract, BootTest, Booted},
    image, management_contract,
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

/// Which disk a scenario boots on a [`Run::Shipping`] run.
///
/// It does not decide a [`Run::Diagnostic`] re-run, which always assembles its
/// own disk into the build tree — see [`scenario_disk`].
enum ImageUnderTest {
    /// The disk `dist/` already holds — what `image` published and what an
    /// operator would deploy. `dist/` is left exactly as it is.
    Published,
    /// A disk assembled here from the scenario's own configuration document,
    /// into the build tree. Nothing published changes.
    BuiltForTheScenario,
}

/// Whether a scenario reads the console beside the traffic.
///
/// One flag for every channel rather than one each, because it is one decision:
/// a scenario either judges what the appliance said or is left to report a
/// forwarding failure as a forwarding failure and nothing else. What
/// [`Console::Judged`] covers is the `LFW-CFG` transcript
/// ([`crate::config_transcript`]) and two records on the `LFW-PD` channel — the
/// clock domain's ([`crate::clock_contract`]) and the management port's count
/// ([`crate::management_contract`]).
enum Console {
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
    console: Console,
}

/// Boot the deployable disk through OVMF/GRUB and prove the complete system
/// behaviour across three scenarios, in the kernel configuration a release
/// ships. Returns what the run proved.
///
/// 1. **routed-forwarding** — the published disk, judged by the routed contract
///    alone. It is the regression guard: exactly the contract that existed
///    before configuration management, now stated between endpoints read out of
///    the document rather than written beside it, so a forwarding failure is
///    reported as a forwarding failure and nothing else.
/// 2. **generation-swap** — the same disk, judged additionally by what it said:
///    the node comes up fail-closed on generation 0 and switches to generation
///    1, whose change records are the document's own diff, and its clock domain
///    establishes a time and reports the frequency it measured. A separate boot,
///    because a transcript that could only be read off a run whose traffic had
///    already passed would be silent in exactly the case it exists for — a node
///    that committed nothing and forwarded nothing.
/// 3. **alternate-configuration** — a disk assembled from a second document
///    that shares no address and no MAC with the first, judged by both. This is
///    what proves the dataplane reads its table from the document: a compiled-in
///    table would satisfy scenarios 1 and 2 and fail every probe here.
///
/// Every scenario additionally injects frames into the dedicated management port
/// and holds that port to carrying nothing back, whatever else it judges; the
/// two that read the console also hold the management domain's own count to the
/// frames and bytes injected.
pub(crate) fn test_system(root: &Path) -> Result<String, String> {
    let scenarios = [
        Scenario {
            name: "routed-forwarding",
            document: image::CONFIGURATION_DOCUMENT,
            image: ImageUnderTest::Published,
            console: Console::Ignored,
        },
        Scenario {
            name: "generation-swap",
            document: image::CONFIGURATION_DOCUMENT,
            image: ImageUnderTest::Published,
            console: Console::Judged,
        },
        Scenario {
            name: "alternate-configuration",
            document: ALTERNATE_DOCUMENT,
            image: ImageUnderTest::BuiltForTheScenario,
            console: Console::Judged,
        },
    ];

    let judged = scenarios
        .iter()
        .filter(|scenario| matches!(scenario.console, Console::Judged))
        .count();

    for scenario in &scenarios {
        if let Err(verdict) = run_scenario(root, scenario, Run::Shipping) {
            return Err(diagnose::after_shipping_failure(
                &format!("system scenario {}", scenario.name),
                verdict,
                &scenario_log(root, scenario, Run::Shipping),
                &scenario_log(root, scenario, Run::Diagnostic),
                || run_scenario(root, scenario, Run::Diagnostic),
            ));
        }
    }
    Ok(format!(
        "{} system scenarios on the {} kernel, {judged} of them judged against the \
         configuration transcript, the clock record and the management port's count",
        scenarios.len(),
        Run::Shipping.config(),
    ))
}

/// Where one scenario's serial capture goes, per run. The two runs never share
/// a path, so a diagnostic re-run cannot overwrite the failing shipping run's
/// log — which is the evidence it was called to explain.
fn scenario_log(root: &Path, scenario: &Scenario, run: Run) -> PathBuf {
    root.join("build/image")
        .join(format!("qemu-{}{}.log", scenario.name, run.name_suffix()))
}

/// The disk a scenario boots.
///
/// A [`Run::Diagnostic`] re-run always assembles its own disk into the build
/// tree, `ImageUnderTest::Published` scenarios included. It may not call
/// [`image::image`]: that publishes into `dist/`, which holds the release
/// artifact the failing run was judging, and overwriting it with a debug disk
/// would destroy the thing under assessment (BLD-3).
fn scenario_disk(root: &Path, scenario: &Scenario, run: Run) -> Result<PathBuf, String> {
    let name = scenario.name;
    match (&scenario.image, run) {
        (ImageUnderTest::Published, Run::Shipping) => Ok(root.join("dist").join(DIST_DISK)),
        (ImageUnderTest::BuiltForTheScenario, Run::Shipping) => Ok(image::scenario_image(
            root,
            run.config(),
            Path::new(scenario.document),
            name,
        )?),
        (_, Run::Diagnostic) => Ok(image::scenario_image(
            root,
            run.config(),
            Path::new(scenario.document),
            &format!("{name}{}", run.name_suffix()),
        )?),
    }
}

fn run_scenario(root: &Path, scenario: &Scenario, run: Run) -> Result<(), String> {
    let name = scenario.name;
    let path = root.join(scenario.document);
    let document = fs::read(&path)
        .map_err(|error| format!("scenario {name}: read {}: {error}", path.display()))?;
    let topology = Topology::from_document(&document)
        .map_err(|error| format!("scenario {name}: {}: {error}", path.display()))?;

    let disk = scenario_disk(root, scenario, run)?;

    let log_name = format!("qemu-{name}{}.log", run.name_suffix());
    let booted = boot_and_forward(root, &disk, &log_name, &topology)
        .map_err(|error| format!("scenario {name}: {error}"))?;

    // The table before the verdict: what the two endpoints exchanged and what
    // the appliance refused is the thing a smoke run is run to see, and the
    // verdict is only the count of it. For the alternate scenario it is also
    // where a reader sees the second document's addresses on the wire.
    print!("{}", booted.traffic.render());

    let log = scenario_log(root, scenario, run);
    let judged = match scenario.console {
        Console::Ignored => String::new(),
        Console::Judged => {
            let contract = ConfigContract::from_document(&document)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            contract
                .judge(&booted.serial, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            // The other console channel, and the one record whose content the
            // build cannot predict: what the appliance measured about its own
            // hardware. Judged after the transcript because a node that refused
            // its configuration is the larger finding.
            let clock = clock_contract::judge(&booted.serial, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            // And the record whose content the build knows exactly: the frames
            // the harness put on the management wire, which the appliance must
            // report to the frame and to the byte.
            let management = management_contract::judge(&booted.serial, &log, booted.management)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            format!("; {}; {clock}; {management}", contract.summary())
        }
    };
    println!(
        "  system scenario ok: {name} on the {} kernel ({}{judged}); QEMU output is in {}",
        run.config(),
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
    // The marker closing the header is [`GUEST_OUTPUT_MARKER`] rather than a
    // literal, because `diagnose` splits a run log on it to tell the harness's
    // own words from the guest's — and a release capture with nothing after it
    // is the finding that note exists for.
    let header = format!(
        "# librefirewall QEMU run: {run_label}\n\
         # {description}\n\
         {GUEST_OUTPUT_MARKER}"
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

/// Boot the disk `dist/` holds interactively, on QEMU's own user-mode network.
///
/// The caller assembles that disk in the DEBUG kernel configuration (see
/// `main`'s `run` arm): this is the one command whose output a human reads as
/// it happens, so the kernel's serial diagnostics are worth their cost here
/// exactly as they are not in the gate.
pub(crate) fn run_system(root: &Path) -> Result<(), String> {
    let disk = root.join("dist").join(DIST_DISK);
    let path = root.join(image::CONFIGURATION_DOCUMENT);
    let topology = Topology::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let Invocation {
        mut command,
        acceleration,
    } = qemu_base(root, "mon:stdio", &disk, "run")?;
    println!("QEMU run: {}", acceleration.describe());
    // Interactive runs have no harness peer to dial into, so back every NIC
    // port with QEMU's self-contained user-mode stack instead. The management
    // port is attached like the others: without it the third driver instance
    // finds no device at 00:04.0 and parks on a refusal, which is a boot no
    // shipped image would ever perform.
    for nic in every_guest_nic() {
        command
            .arg("-netdev")
            .arg(format!("user,id={}", nic.netdev_id()))
            .arg("-device")
            .arg(nic_device(&topology, nic)?);
    }
    run_command(&mut command, "run QEMU")?;
    Ok(())
}

/// The MAC the management port's guest NIC carries.
///
/// It is a constant here and not a derivation, because the configuration
/// document has no management interface to derive it from: the port has no
/// address, no ARP and no IP in this increment, so nothing about it is
/// configurable yet (README's port-role-model row). **It moves into the document
/// as that interface's `mac=` the day one exists**, and this constant goes with
/// it — at which point `nic_device` reads it out of the topology like every
/// other port's and `a_managed_port_carries_a_mac_no_dataplane_port_claims`
/// stops being a test about a literal.
///
/// Its value is chosen to sit one past the two the shipped document gives the
/// dataplane ports, so a capture or a `tcpdump` reads in port order; that is
/// convention and nothing depends on it. What *is* depended on is that it
/// belongs to no interface and no station on either bench, which the tests
/// below hold it to: two NICs answering to one address would have a routed
/// frame accepted by whichever saw it first.
pub(crate) const MANAGEMENT_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x52];

/// Which guest NIC a `-device` argument is for.
///
/// A type rather than a port number, because the two are not the same kind of
/// thing: a dataplane port's MAC comes out of the configuration document and the
/// management port's cannot, so a bare `usize` would have to mean "index into
/// the document" and "the one past the end" at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GuestNic {
    /// Dataplane port `n`, whose MAC the document's interface on it claims.
    Dataplane(usize),
    /// The management port, carrying [`MANAGEMENT_MAC`].
    Management,
}

impl GuestNic {
    /// The slot this NIC occupies, which decides both its netdev id and its PCI
    /// address. One derivation for both kinds: the management port sits one past
    /// the dataplane ports, so `addr=0{slot+2}.0` reproduces 00:02.0, 00:03.0
    /// and 00:04.0 — and 00:04.0 is the device whose ECAM page the system
    /// description grants as `ecam2` at PCIEXBAR + (4 << 15).
    const fn slot(self) -> usize {
        match self {
            Self::Dataplane(port) => port,
            Self::Management => PORTS,
        }
    }

    /// The netdev id the backend is joined by, `socket` under the harness and
    /// `user` for interactive runs.
    pub(crate) fn netdev_id(self) -> String {
        format!("n{}", self.slot())
    }
}

/// The virtio-net-pci `-device` argument for one guest NIC, pinned to the PCI
/// address the system description assigns it, with no option ROM (so the
/// firmware gains no PXE payload).
///
/// The MAC is the derivation this function exists for. A dataplane port's used to
/// be a literal here that had to equal a literal in the harness and a third in
/// the document, with nothing comparing the three; now such a NIC can only be
/// given a MAC an interface claims, and the address the routed contract expects
/// the appliance to answer to is that same interface's. The management port has
/// no interface to claim one, so it carries [`MANAGEMENT_MAC`] and the tests hold
/// that constant to belonging to nothing else on the bench.
///
/// # Errors
/// A dataplane port with no interface in the document, which the topology names.
pub(crate) fn nic_device(topology: &Topology, nic: GuestNic) -> Result<String, String> {
    let [a, b, c, d, e, f] = match nic {
        GuestNic::Dataplane(port) => topology.port_mac(port).map_err(|error| error.to_string())?,
        GuestNic::Management => MANAGEMENT_MAC,
    };
    Ok(format!(
        "virtio-net-pci,netdev={},disable-legacy=on,disable-modern=off,\
         mac={a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x},bus=pcie.0,addr=0{}.0,romfile=",
        nic.netdev_id(),
        nic.slot() + 2
    ))
}

/// Every NIC the image expects to find, in slot order: one per dataplane port,
/// then the management port. A shorter list is a boot with a driver instance
/// staring at an absent device.
pub(crate) fn every_guest_nic() -> Vec<GuestNic> {
    (0..PORTS)
        .map(GuestNic::Dataplane)
        .chain([GuestNic::Management])
        .collect()
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
        // `hpet=on` explicitly, and not because QEMU's q35 default is off — it
        // is on. A default is a value QEMU may change between versions, and the
        // clock domain's whole first step is probing a block at 0xFED00000: a
        // machine that stopped presenting one would turn every system scenario
        // into a `hpet-not-present` refusal, reported as this project's defect.
        // The system description grants the region unconditionally, so stating
        // the device here is what keeps the two ends of that grant agreeing.
        .args([
            "-machine",
            "q35,hpet=on",
            "-accel",
            acceleration.qemu_accel(),
        ])
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
        // The three addresses the system description grants an ECAM page for,
        // and the management port is the third: `ecam2` is the page of device 4.
        assert!(
            nic_device(&topology, GuestNic::Dataplane(0))
                .unwrap()
                .contains("addr=02.0")
        );
        assert!(
            nic_device(&topology, GuestNic::Dataplane(1))
                .unwrap()
                .contains("addr=03.0")
        );
        assert!(
            nic_device(&topology, GuestNic::Management)
                .unwrap()
                .contains("addr=04.0")
        );
        for nic in every_guest_nic() {
            assert!(
                nic_device(&topology, nic).unwrap().ends_with("romfile="),
                "an option ROM would give the firmware a PXE payload"
            );
        }
        // Every NIC on its own netdev id and its own slot, or two would share a
        // backend and a PCI function.
        let slots: Vec<usize> = every_guest_nic().iter().map(|nic| nic.slot()).collect();
        assert_eq!(slots, (0..=PORTS).collect::<Vec<_>>());
    }

    /// The management port answers to an address nothing else on either bench
    /// does. Two NICs sharing one would have a routed frame accepted by
    /// whichever saw it first, and the document cannot refuse a collision it
    /// does not know about.
    #[test]
    fn a_managed_port_carries_a_mac_no_dataplane_port_claims() {
        for topology in [bench(), alternate()] {
            assert!(
                !topology.carries_mac(MANAGEMENT_MAC),
                "the management MAC belongs to something on the bench"
            );
            for port in 0..PORTS {
                assert_ne!(topology.port_mac(port), Ok(MANAGEMENT_MAC));
            }
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
                nic_device(&topology, GuestNic::Dataplane(port))
                    .unwrap()
                    .contains(&format!(
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
        let error = nic_device(&bench(), GuestNic::Dataplane(PORTS))
            .expect_err("there is no such dataplane port");
        assert!(error.contains(&format!("{PORTS}")), "{error}");
    }

    /// The alternate scenario's document is a different bench, and the device
    /// arguments it produces must differ in every MAC — the property scenario 3
    /// rests on.
    fn alternate() -> Topology {
        Topology::from_document(include_bytes!("../scenarios/alternate-addressing.xml"))
            .expect("the alternate document describes a bench")
    }

    #[test]
    fn the_alternate_document_puts_different_macs_on_the_same_ports() {
        let shipped = bench();
        let alternate = alternate();
        for port in 0..PORTS {
            let nic = GuestNic::Dataplane(port);
            assert_ne!(
                nic_device(&shipped, nic).unwrap(),
                nic_device(&alternate, nic).unwrap()
            );
        }
        // The management port is the exception, and deliberately: its MAC is not
        // in either document, so both benches present the same one — which is
        // what makes it the one NIC argument the alternate scenario does not
        // re-derive.
        assert_eq!(
            nic_device(&shipped, GuestNic::Management).unwrap(),
            nic_device(&alternate, GuestNic::Management).unwrap()
        );
    }
}
