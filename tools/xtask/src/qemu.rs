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
//! [`test_system`] is the black-box system gate. It boots six [`Scenario`]s,
//! each of which asserts the machine-observable routed contract — a datagram
//! sent from the host endpoint on each NIC port reaches the endpoint on the
//! other rewritten for its next hop, and the packets the appliance must refuse
//! reach nobody — driven by [`crate::forward_harness`]. Two of them
//! additionally judge the `LFW-CFG` console channel through
//! [`crate::config_transcript`], and the three whose management port a real
//! client can reach ([`ManagementRole::Client`]) pull every surface the
//! endpoint serves and hold the three of them to each other
//! ([`crate::surface_contract`]).
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
    data_disk::DataDisk,
    diagnose::{self, GUEST_OUTPUT_MARKER, Run},
    forward_harness::{self, BootContract, BootTest, Booted, ManagementBacking},
    image, management_contract, metrics_contract,
    recording_contract::{self, Download},
    stamp_contract, surface_contract,
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
/// x86_64 kernel needs the first four features present; naming them explicitly
/// (rather than passing `host` under KVM) is what makes the boot the system test
/// asserts on identical on every runner, accelerated or not. Every feature here
/// has been baseline on x86-64 since well before the hardware this project
/// targets, so pinning them costs no KVM host compatibility.
///
/// `rdrand` is the appliance's requirement rather than the kernel's, and it is a
/// *hard* one: the management domain derives its transport's initial sequence
/// numbers from a per-boot secret it draws with `RDRAND` (RFC 6528), and refuses
/// to start at all when `CPUID.01H:ECX[30]` is clear rather than answering a
/// connection with a predictable number. QEMU's `qemu64` model does not expose it
/// — which this gate discovered by the domain refusing on its first boot, exactly
/// as it would on a part that lacked it — so the bench must, and any deployment
/// target must too. It has been present on Intel parts since Ivy Bridge (2012)
/// and on AMD since Excavator, so it costs no host compatibility either.
const GUEST_CPU: &str = "qemu64,+fsgsbase,+pdpe1gb,+xsaveopt,+xsave,+rdrand";

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
    /// The data device this run created and attached, kept so the caller can
    /// read it back once QEMU has exited. Every invocation gets one — including
    /// the interactive `run`, whose guest would otherwise find no device at
    /// 00:05.0 and park the recorder on a refusal, which is a boot no shipped
    /// image would ever perform.
    data: DataDisk,
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

/// What a scenario does with the management port.
///
/// The two are mutually exclusive by construction, which is the point: a
/// harness that plays a station on the wire sees every frame and composes every
/// reply, and a harness that lets a real client in sees none of them. Asserting
/// both in one boot would mean two things on one wire.
enum ManagementRole {
    /// The harness is the station: it injects opaque frames, an ARP request, an
    /// ICMP echo request and a whole TCP exchange, and judges every answer field
    /// by field.
    Station,
    /// The harness is a client. QEMU's user-mode stack carries the port and
    /// `curl` pulls **every surface the endpoint serves** through a host port
    /// forward — `GET /metrics`, `GET /logs.pcapng` and `GET /capture.pcapng` —
    /// and all three are judged, together.
    ///
    /// All three, on every scenario that reaches the endpoint, because judging
    /// one of them is the gap: a recording that silently drops, a metric that
    /// double-counts and a tap that loses a record are each invisible in the
    /// surface they occur in and each a disagreement between two of them
    /// ([`crate::surface_contract`]). Nothing at frame level is asserted on this
    /// wire; what is asserted is the HTTP responses, one metric value against
    /// traffic the harness observed on the *dataplane* ports in the same boot,
    /// every label of the interface info family against the configuration
    /// document this image was built from, the two recordings against each
    /// other and against the bytes the harness injected, and the same two
    /// extents read straight off the disk image after the run — one artifact
    /// reached two ways, neither of them the appliance's own account of itself.
    Client,
}

impl ManagementRole {
    /// Whether QEMU's user-mode stack carries the port, which is what a real
    /// client needs and what a frame-level station forbids.
    const fn user_network(&self) -> bool {
        matches!(self, Self::Client)
    }
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
    management: ManagementRole,
}

/// Boot the deployable disk through OVMF/GRUB and prove the complete system
/// behaviour across six scenarios, in the kernel configuration a release
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
/// 4. **metrics-endpoint**, 5. **metrics-endpoint-alternate** and
///    6. **recording-download** — `curl` pulls every surface the endpoint serves
///    through QEMU's own user-mode stack: `GET /metrics`, `GET /logs.pcapng` and
///    `GET /capture.pcapng`. Scenarios 4 and 6 run against the published disk and
///    5 against a disk built from the second document, and each is judged
///    against *its own* document — which is what makes the interface info family
///    a checked statement about the running configuration, the two documents
///    sharing no identity, so a label the build carried rather than read would
///    pass one and fail the other. The same holds the probes the recordings are
///    compared against: the two benches inject different bytes.
///
///    All three surfaces are judged on all three scenarios, and then against
///    each other ([`crate::surface_contract`]). A scenario that booted a
///    reachable endpoint and judged one of them is the gap that closes: a
///    recording that silently drops, a metric that double-counts and a tap that
///    loses a record are each invisible in the surface they occur in.
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
            management: ManagementRole::Station,
        },
        Scenario {
            name: "generation-swap",
            document: image::CONFIGURATION_DOCUMENT,
            image: ImageUnderTest::Published,
            console: Console::Judged,
            management: ManagementRole::Station,
        },
        Scenario {
            name: "alternate-configuration",
            document: ALTERNATE_DOCUMENT,
            image: ImageUnderTest::BuiltForTheScenario,
            console: Console::Judged,
            management: ManagementRole::Station,
        },
        Scenario {
            name: "metrics-endpoint",
            document: image::CONFIGURATION_DOCUMENT,
            image: ImageUnderTest::Published,
            // The console is not judged here and it is not an omission: this
            // scenario injects no management frame, so the `frames=`/`bytes=`
            // equality the other two hold the console to has nothing to be
            // stated against. What it judges instead is the endpoint's answer.
            console: Console::Ignored,
            management: ManagementRole::Client,
        },
        // The same scrape against a disk built from the second document, and the
        // one thing the scenario above cannot show: that the identity the
        // interface info series carry comes from the document rather than from
        // the build. Both scrapes are judged against the document their own image
        // was assembled from, and the two documents share no id, no address and
        // no MAC — so a label compiled in would satisfy one of the two and fail
        // the other.
        //
        // Its management addressing differs too, which is why this works at all:
        // QEMU's user-mode stack is told the network, the station and the
        // endpoint out of the document (`forward_harness::user_netdev`), so the
        // forward reaches whatever address the document names.
        Scenario {
            name: "metrics-endpoint-alternate",
            document: ALTERNATE_DOCUMENT,
            image: ImageUnderTest::BuiltForTheScenario,
            console: Console::Ignored,
            management: ManagementRole::Client,
        },
        // The recording milestone's own scenario. It is no longer the only one
        // that pulls the recordings — every [`ManagementRole::Client`] scenario
        // does, which is the point of there being one role — and it remains
        // because it is the pairing of the published disk with the recording
        // surfaces, where the two above pair the same surfaces with the two
        // documents. The download proves the whole chain from tap to HTTP; the
        // disk read after it proves what is on the medium independently, so a
        // recorder that composed a plausible body out of nothing would pass one
        // and fail the other.
        Scenario {
            name: "recording-download",
            document: image::CONFIGURATION_DOCUMENT,
            image: ImageUnderTest::Published,
            console: Console::Ignored,
            management: ManagementRole::Client,
        },
    ];

    let judged = scenarios
        .iter()
        .filter(|scenario| matches!(scenario.console, Console::Judged))
        .count();
    let scraped = scenarios
        .iter()
        .filter(|scenario| scenario.management.user_network())
        .count();

    // What each boot chose for its one management connection, kept so the
    // *unpredictability* of it can be judged across boots. RFC 6528 makes that a
    // security property and no single boot can show it: a constant initial
    // sequence number is an off-path injection primitive against exactly the
    // party this port faces (CONCEPT §7.1), and it looks perfectly correct in one
    // scenario.
    let mut sequence_numbers: Vec<(&str, u32)> = Vec::new();
    for scenario in &scenarios {
        match run_scenario(root, scenario, Run::Shipping) {
            Ok(Some(isn)) => sequence_numbers.push((scenario.name, isn)),
            Ok(None) => {}
            Err(verdict) => {
                return Err(diagnose::after_shipping_failure(
                    &format!("system scenario {}", scenario.name),
                    verdict,
                    &scenario_log(root, scenario, Run::Shipping),
                    &scenario_log(root, scenario, Run::Diagnostic),
                    || run_scenario(root, scenario, Run::Diagnostic).map(|_| ()),
                ));
            }
        }
    }
    let distinct = judge_sequence_numbers(&sequence_numbers)?;
    Ok(format!(
        "{} system scenarios on the {} kernel, {judged} of them judged against the \
         configuration transcript, the clock record and the management port's count, and \
         {scraped} scraped with curl against the document each was built from; {distinct}",
        scenarios.len(),
        Run::Shipping.config(),
    ))
}

/// Hold the initial sequence numbers three boots chose to being *different*.
///
/// The two dataplane scenarios boot the same disk, so nothing but the per-boot
/// `RDRAND` secret and the time component separates their numbers (RFC 6528): two
/// equal ones mean one of the two is missing, which is the whole of what makes an
/// initial sequence number unguessable. Every boot must have opened a connection,
/// too — a run that opened none proves nothing and must not read as a pass.
///
/// # Errors
/// The verdict, naming the numbers observed.
pub(crate) fn judge_sequence_numbers(observed: &[(&str, u32)]) -> Result<String, String> {
    if observed.is_empty() {
        return Err(String::from(
            "no scenario opened a TCP connection to the management port, so nothing was judged \
             about the sequence numbers the appliance chooses. Every routed scenario opens one, so \
             this means none of them reached the point where it could",
        ));
    }
    for pair in observed.windows(2) {
        if let [(first, earlier), (second, later)] = pair
            && earlier == later
        {
            return Err(format!(
                "scenarios {first} and {second} were both answered with initial sequence number \
                 {earlier}. Nothing but the per-boot RDRAND secret and a monotonic time component \
                 separates two boots of one disk (RFC 6528), so an equal pair means one of the two \
                 is not reaching the generator — and a predictable initial sequence number lets an \
                 off-path attacker inject into a connection it cannot see"
            ));
        }
    }
    Ok(format!(
        "{} distinct initial sequence numbers across the boots that opened a connection",
        observed.len()
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

fn run_scenario(root: &Path, scenario: &Scenario, run: Run) -> Result<Option<u32>, String> {
    let name = scenario.name;
    let path = root.join(scenario.document);
    let document = fs::read(&path)
        .map_err(|error| format!("scenario {name}: read {}: {error}", path.display()))?;
    let topology = Topology::from_document(&document)
        .map_err(|error| format!("scenario {name}: {}: {error}", path.display()))?;

    let disk = scenario_disk(root, scenario, run)?;

    let log_name = format!("qemu-{name}{}.log", run.name_suffix());
    let backing = if scenario.management.user_network() {
        ManagementBacking::UserNetwork {
            host_port: forward_harness::reserve_host_port()
                .map_err(|error| format!("scenario {name}: {error}"))?,
        }
    } else {
        ManagementBacking::Socket
    };
    let booted = boot_and_forward(root, &disk, &log_name, &topology, backing)
        .map_err(|error| format!("scenario {name}: {error}"))?;

    // The table before the verdict: what the two endpoints exchanged and what
    // the appliance refused is the thing a smoke run is run to see, and the
    // verdict is only the count of it. For the alternate scenario it is also
    // where a reader sees the second document's addresses on the wire.
    print!("{}", booted.traffic.render());
    for answered in &booted.management_replies {
        println!("{answered}");
    }

    let log = scenario_log(root, scenario, run);
    // The scrape before the console, because it is the whole of what this
    // scenario proves and its evidence belongs where a reader looks first.
    let scraped = match &scenario.management {
        ManagementRole::Station => String::new(),
        ManagementRole::Client if booted.scrapes.is_empty() => {
            return Err(format!(
                "scenario {name}: the boot met its routed contract and no scrape was taken, so \
                 nothing was proved about the metrics endpoint\n  full run log: {}",
                log.display()
            ));
        }
        ManagementRole::Client => {
            let judged =
                metrics_contract::judge(&booted.scrapes, booted.dataplane_frames, &topology)
                    .map_err(|error| {
                        format!(
                            "scenario {name}: {error}\n  full run log: {}",
                            log.display()
                        )
                    })?;
            let evidence = metrics_contract::evidence(&booted.scrapes, &judged);
            println!("{evidence}");
            append_evidence(
                &log,
                "the metrics scrape this boot was judged by",
                &evidence,
            )
            .map_err(|error| format!("scenario {name}: {error}"))?;
            let judged = judge_recordings(root, name, &booted, &topology, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            println!("{judged}");
            append_evidence(
                &log,
                "the two recordings this boot was judged by, and their agreement with the \
                 exposition and the wire",
                &judged,
            )
            .map_err(|error| format!("scenario {name}: {error}"))?;
            format!(
                "; {} scrapes and both recordings judged together",
                booted.scrapes.len()
            )
        }
    };
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
            // Last, over every channel at once: the field the other three do
            // not judge, on the records they do not name.
            let stamps = stamp_contract::judge(&booted.serial, &log)
                .map_err(|error| format!("scenario {name}: {error}"))?;
            format!("; {}; {clock}; {management}; {stamps}", contract.summary())
        }
    };
    println!(
        "  system scenario ok: {name} on the {} kernel ({}{judged}{scraped}); QEMU output is in {}",
        run.config(),
        booted.traffic.summary(),
        log.display()
    );
    Ok(booted.management_tcp_isn)
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
    management: ManagementBacking,
) -> Result<Booted, String> {
    boot(
        root,
        disk,
        log_name,
        BootContract::Routed,
        topology,
        management,
    )
}

/// Judge both recordings a boot pulled — each on its own terms, then the two of
/// them against each other, against the exposition the same boot answered, and
/// against the bytes the harness put on the wire.
///
/// The order is the order the findings are worth reading in. A body that is not
/// a pcapng file at all is reported as that and not as a pairing failure; only
/// once both parse is the interesting question reachable, which is whether the
/// three surfaces tell one story ([`crate::surface_contract`]).
///
/// Both bodies are also written into the build tree, so a human can open them
/// in Wireshark or `tcpdump -r` after a run without booting anything again.
///
/// The disk half — read separately by [`crate::data_disk`] — is what makes the
/// download evidence rather than a round trip through the appliance's own
/// memory: a recorder that answered a plausible body out of nothing would
/// satisfy the client and leave the medium empty, and a harness that only asked
/// over HTTP would not notice.
fn judge_recordings(
    root: &Path,
    scenario: &str,
    booted: &Booted,
    topology: &Topology,
    log: &Path,
) -> Result<String, String> {
    let expectations = [
        recording_contract::Expectation {
            target: pd_runtime::LOG_TARGET,
            snap_len: lfw_recorder::deck::LOG_SNAP_LEN as usize,
            // The frames the harness itself put across the appliance, which is
            // the number of observations the router must have decided on. At
            // least, not exactly: the management port's own frames and any
            // re-injection are decided on too.
            least_packets: booted.dataplane_frames as usize,
        },
        recording_contract::Expectation {
            target: pd_runtime::CAPTURE_TARGET,
            snap_len: lfw_recorder::deck::CAPTURE_SNAP_LEN as usize,
            least_packets: booted.dataplane_frames as usize,
        },
    ];
    if booted.recordings.len() != expectations.len() {
        return Err(format!(
            "the boot met its contract and pulled {} recordings rather than {}, so nothing was \
             proved about the download path\n  full run log: {}",
            booted.recordings.len(),
            expectations.len(),
            log.display()
        ));
    }
    let mut evidence = String::from("  both recordings, downloaded and parsed as pcapng:");
    let mut parsed = Vec::new();
    for (download, expected) in booted.recordings.iter().zip(&expectations) {
        let found = recording_contract::judge(download, expected)?;
        evidence.push('\n');
        evidence.push_str(&recording_contract::evidence(
            download,
            &found,
            expected.snap_len,
        ));
        evidence.push('\n');
        evidence.push_str(&keep(root, scenario, download)?);
        parsed.push(found);
    }

    // The second scrape, which is the one `metrics_contract` judges and the one
    // whose counters have advanced past the first connection.
    let exposition = booted.scrapes.last().ok_or(
        "the recordings were pulled and no scrape was taken, so the recorder's own published \
         counts are not available to compare them against",
    )?;
    let [log_parsed, capture_parsed] = parsed.as_slice() else {
        return Err(format!(
            "{} recordings parsed and the contract is stated over two",
            parsed.len()
        ));
    };
    let agreement = surface_contract::judge(
        &surface_contract::Surface {
            target: pd_runtime::LOG_TARGET,
            snap_len: lfw_recorder::deck::LOG_SNAP_LEN,
            parsed: log_parsed,
            published_records: metrics_contract::sink_records(&exposition.body, "log")?,
        },
        &surface_contract::Surface {
            target: pd_runtime::CAPTURE_TARGET,
            snap_len: lfw_recorder::deck::CAPTURE_SNAP_LEN,
            parsed: capture_parsed,
            published_records: metrics_contract::sink_records(&exposition.body, "capture")?,
        },
        &surface_contract::Wire {
            injected: &booted.injected,
            ports: topology.interfaces().len(),
        },
    )
    .map_err(|error| format!("{error}\n  full run log: {}", log.display()))?;
    evidence.push('\n');
    evidence.push_str(&agreement.evidence());
    Ok(evidence)
}

/// Write one downloaded recording into the build tree, answering the line that
/// says where it landed.
///
/// A run that proves something about a file and then discards it leaves a
/// reader with nothing to open: the next question after "the contract held" is
/// always "what was in it", and re-running a ten-minute boot to ask it is the
/// cost this avoids. The name carries the scenario, so two scenarios' captures
/// cannot overwrite each other.
fn keep(root: &Path, scenario: &str, download: &Download) -> Result<String, String> {
    let file = download.target.trim_start_matches('/');
    let path = root
        .join("build/image")
        .join(format!("qemu-{scenario}-{file}"));
    fs::write(&path, &download.body)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok(format!(
        "    kept at {} — open it with `tcpdump -r` or Wireshark",
        path.display()
    ))
}

/// Write one body of evidence into the run log, behind the guest's own output,
/// under a heading that says what it is.
///
/// The log is the artifact a reader opens after a failure, and a proof that
/// exists only in a terminal that has scrolled away is not evidence. The
/// heading is the caller's rather than fixed here: a log carrying three
/// different proofs under one title tells a reader the first thing wrong about
/// the other two. Appended rather than interleaved: the capture above it is the
/// guest's, byte for byte, and nothing this harness writes may land inside it.
fn append_evidence(log: &Path, heading: &str, evidence: &str) -> Result<(), String> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(log)
        .map_err(|error| format!("open {} to append the evidence: {error}", log.display()))?;
    writeln!(file, "\n# {heading}\n{evidence}")
        .map_err(|error| format!("append the evidence to {}: {error}", log.display()))
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
        ManagementBacking::Socket,
    )
}

fn boot(
    root: &Path,
    disk: &Path,
    log_name: &str,
    contract: BootContract,
    topology: &Topology,
    management: ManagementBacking,
) -> Result<Booted, String> {
    let run_label = log_name.strip_suffix(".log").unwrap_or(log_name);
    // Whether this boot reads the recordings back follows from the backing
    // rather than being a second decision beside it: a real client is exactly
    // what a download needs, and there is no scenario that has one and does not
    // use it ([`ManagementRole::Client`]).
    let recordings = !management.is_socket();
    let backends = forward_harness::NicBackends::new(management)?;
    let Invocation {
        mut command,
        acceleration,
        data,
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
    // Which data-disk verdict this boot owes, taken before the contract is
    // handed over: a boot that runs the appliance must leave the witness pattern
    // on the medium, and one with no bootable slot must leave the sector alone.
    let ran_the_appliance = matches!(contract, BootContract::Routed);
    let booted = forward_harness::run_boot_test(
        command,
        backends,
        BootTest {
            contract,
            log_path: &log,
            log_header: &header,
            topology,
        },
    )?;

    // The data disk, judged after the boot contract and never instead of it.
    // Which verdict is owed follows from the contract, and the pair is what
    // makes either one evidence: a boot that ran the appliance must have left
    // the witness pattern on the medium, and a boot with no bootable slot must
    // have left the same sector untouched. A harness asserting only the first
    // would pass on a host that wrote the file itself.
    let verdict = if ran_the_appliance {
        data.judge_written()
    } else {
        data.judge_untouched()
    }
    .map_err(|error| format!("{error}\n  full run log: {}", log.display()))?;
    println!("  data disk {run_label}: {verdict}");
    // And, on every boot that pulled the recordings, the medium itself: the
    // extents the appliance wrote, read by a process the guest cannot reach.
    if recordings {
        let on_disk = data
            .judge_recordings()
            .map_err(|error| format!("{error}\n  full run log: {}", log.display()))?;
        println!("  data disk {run_label}: {on_disk}");
        append_evidence(
            &log,
            "the two recording extents, read off the disk image after shutdown",
            &on_disk,
        )?;
    }
    Ok(booted)
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
        data: _,
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

/// Which guest NIC a `-device` argument is for.
///
/// A type rather than a port number, because the two are not the same kind of
/// thing: a dataplane port is one of the document's `<interface>` elements and
/// is indexed by the `port=` it claims, while the management port is the
/// document's one `<management>` element and has no number at all. A bare
/// `usize` would have to mean "index into the interfaces" and "the one past the
/// end" at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GuestNic {
    /// Dataplane port `n`, whose MAC the document's interface on it claims.
    Dataplane(usize),
    /// The management port, whose MAC the document's `<management>` element
    /// claims.
    Management,
}

impl GuestNic {
    /// The slot this NIC occupies, which decides both its netdev id and its PCI
    /// address. One derivation for both kinds: the management port sits one past
    /// the dataplane ports, so `addr=0{slot+2}.0` reproduces 00:02.0, 00:03.0
    /// and 00:04.0 — and 00:04.0 is the device whose ECAM page the system
    /// description grants as `ecam2` at PCIEXBAR + (4 << 15).
    pub(crate) const fn slot(self) -> usize {
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
/// The MAC is the derivation this function exists for. Every one of them used to
/// be a literal here that had to equal a literal in the harness and a third in
/// the document, with nothing comparing the three; now a NIC can only be given a
/// MAC the document claims — a dataplane port's from the `<interface>` on it, and
/// the management port's from the `<management>` element — so the address a
/// contract expects the appliance to answer to is the address the port carries.
///
/// # Errors
/// A dataplane port with no interface in the document, which the topology names.
pub(crate) fn nic_device(topology: &Topology, nic: GuestNic) -> Result<String, String> {
    let [a, b, c, d, e, f] = match nic {
        GuestNic::Dataplane(port) => topology.port_mac(port).map_err(|error| error.to_string())?,
        GuestNic::Management => topology.management().mac,
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
    let data = DataDisk::create(root, run_label)?;

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
    // The recorder's device, beside the boot disk and before the NICs. It is
    // attached to every invocation rather than to the scenarios that judge it,
    // because a domain staring at an absent device is a different boot from the
    // one the image was assembled for (BLD-3).
    data.attach(&mut command);
    Ok(Invocation {
        command,
        acceleration,
        data,
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

    /// The management port answers to an address no dataplane port on either
    /// bench does. Two NICs sharing one would have a routed frame accepted by
    /// whichever saw it first — and now that both come out of one document, this
    /// is a check on what that document says rather than on a literal.
    #[test]
    fn a_managed_port_carries_a_mac_no_dataplane_port_claims() {
        for topology in [bench(), alternate()] {
            let management = topology.management().mac;
            for port in 0..PORTS {
                assert_ne!(topology.port_mac(port), Ok(management));
            }
            for endpoint in topology.endpoints() {
                assert_ne!(endpoint.mac, management);
            }
            assert!(
                nic_device(&topology, GuestNic::Management)
                    .unwrap()
                    .contains(&mac_argument(management))
            );
        }
    }

    /// The MAC as a `-device` argument renders it, so a test compares the string
    /// QEMU is given rather than a second formatting of the same bytes.
    fn mac_argument([a, b, c, d, e, f]: [u8; 6]) -> String {
        format!("mac={a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
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
    fn the_alternate_document_puts_different_macs_on_every_port() {
        let shipped = bench();
        let alternate = alternate();
        // Every NIC, the management one included: its MAC is in the document
        // now, so scenario 3 re-derives it like the rest and a management
        // endpoint answering there proves it read the second document.
        for nic in every_guest_nic() {
            assert_ne!(
                nic_device(&shipped, nic).unwrap(),
                nic_device(&alternate, nic).unwrap(),
                "{nic:?}"
            );
        }
    }
}
