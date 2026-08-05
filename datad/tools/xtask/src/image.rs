//! seL4/Microkit image assembly — the `image` command.
//!
//! Builds the [`SYSTEM_PDS`] protection-domain ELFs for the seL4 target and
//! the [`SIMD_SYSTEM_PDS`] for the hardfloat SIMD one,
//! assembles them with the Microkit tool into the kernel/system pair, copies
//! that pair into `dist/` as the update input, then hands off to
//! [`crate::disk`] to produce the signed A/B GPT disk and to
//! [`crate::evidence`] for the manifest, SBOM, and checksums.
//!
//! [`verify_inputs`] gates the build on the pinned toolchain *before* anything
//! is compiled, so a mismatched builder fails early and by name rather than deep
//! inside the toolchain — and so the versions the manifest records as provenance
//! are the versions that actually produced the image. Every pinned input the
//! manifest names is checked: an unverified provenance field is a claim, not
//! evidence. [`crate::sysdesc`] and [`check_configuration`] run beside it
//! against the two source-controlled inputs this stage consumes that no
//! compiler judges: the system description, and the configuration document a
//! protection domain is about to be built around.
//!
//! Which document that is, and where the disk it produces goes, are the two
//! things one build varies from another ([`Destination`]). The published build
//! is the appliance's own document into `dist/`; a [`Destination::Scenario`]
//! build goes into the build tree instead, for a QEMU scenario that must not
//! disturb what `dist/` holds. Two kinds of scenario need that: the one proving
//! the dataplane reads its table from the document rather than carrying one
//! compiled in (a second document), and every [`crate::diagnose`] re-run of a
//! failed scenario on the debug kernel (the same document, the other kernel
//! configuration). Both walk the identical pipeline — same pinned-input check,
//! same validator, same protection domains, same signed A/B disk — because a
//! scenario disk assembled by a shorter path would prove something about that
//! path rather than about the appliance.
//!
//! The kernel configuration is the caller's, and the gate's callers all pass
//! `release`: that is the image a release publishes, so that is the image every
//! end-to-end scenario boots. `debug` reaches this module from the
//! `image-debug` opt-in, from `run`, and from a diagnostic re-run.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use config::ConfigError;

use crate::{
    artifacts::{
        BUILD_KERNEL_IMAGE, BUILD_MICROKIT_REPORT, BUILD_SYSTEM_IMAGE, DIST_DISK, DIST_KERNEL,
        DIST_SYSTEM,
    },
    disk, evidence, grub,
    pins::{self, Pins},
    sysdesc, target_spec,
    util::{Error, copy_file, recreate_dir, run_command},
};

pub(crate) const TARGET: &str = "x86_64-sel4-minimal";
/// The hardfloat, SSE-enabled target the [`SIMD_SYSTEM_PDS`] compile with;
/// first-party-authored under `support/targets`, where the minimal one is
/// rust-sel4's own.
pub(crate) const SIMD_TARGET: &str = "x86_64-sel4-simd";
pub(crate) const BOARD: &str = "x86_64_generic";
pub(crate) const DEBUG_CONFIG: &str = "debug";
pub(crate) const RELEASE_CONFIG: &str = "release";
const MICROKIT_SDK: &str = "/opt/microkit";
const RUST_SEL4: &str = "/opt/rust-sel4";

/// The static capability topology, assembled below and cross-checked against
/// the constants the protection domains map it with by [`crate::sysdesc`].
pub(crate) const SYSTEM_DESCRIPTION: &str = "systems/qemu-x86_64/librefirewall.system";
/// The configuration document the appliance runs.
///
/// `pds/config` embeds it verbatim through `include_bytes!(env!(…))`, so the
/// build — and only the build — decides which document ships. Exposed so
/// [`crate::host::lint_protection_domains`] names the same file this stage
/// compiles the domain against: a lint of a domain built from a different
/// document is a lint of a different binary.
pub(crate) const CONFIGURATION_DOCUMENT: &str = "systems/qemu-x86_64/configuration.xml";

/// The document the different-configuration scenarios build their own image
/// from — a second bench that shares no address and no MAC with the appliance's
/// own document.
///
/// It is the harness's input rather than the appliance's, so it lives beside the
/// harness. `systems/` holds what the appliance runs, and a second document there
/// would read as a second shippable configuration.
pub(crate) const ALTERNATE_DOCUMENT: &str = "tools/xtask/scenarios/alternate-addressing.xml";

/// The document the connection-lifecycle scenario builds its own image from: the
/// shipped bench, under rules whose protocol criterion is not UDP-only.
///
/// A connection that closes has to be TCP, and a TCP segment matches neither of
/// the other two documents' rules — so it falls to the default deny and no
/// conversation is ever admitted to have a lifecycle. Beside the harness for
/// [`ALTERNATE_DOCUMENT`]'s reason.
pub(crate) const LIFECYCLE_DOCUMENT: &str = "tools/xtask/scenarios/protocol-agnostic-policy.xml";

/// What the configuration domain says about one document, and so what a build or
/// a scenario may state with it.
///
/// A document a scenario *wants* refused is the awkward case this type exists for.
/// The fast gate holds every document in the tree to `config::load`, which is what
/// keeps a scenario from discovering a typo at its own boot a dozen minutes in —
/// and a fail-closed scenario needs a document that fails exactly that check. So
/// the expectation is declared rather than the check bypassed: a document listed
/// as refused and then accepted fails the gate as loudly as the other way round,
/// which is the whole point. A bypass would have made "the appliance refuses this"
/// an assumption nothing tested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Standing {
    /// Every rule accepts it. An image built around it commits it at boot and
    /// forwards under it.
    Accepted,
    /// The reader accepts it and a **semantic rule** refuses it, so the refusal is
    /// about an object in the document rather than about a byte of it.
    ///
    /// The stage matters to more than the message. A document the *reader* refuses
    /// yields no model at all, so nothing can be read out of it — while one refused
    /// by a rule about the policy still names its interfaces, its neighbours and
    /// its management port, which is what lets a scenario boot it and address the
    /// bench it describes. That is why this variant is the one a fail-closed
    /// scenario uses, and why it is narrower than "refused".
    RefusedByRule,
}

/// Every configuration document in the tree, with what the appliance says about
/// it: the one that ships, and the harness's own, each of which an end-to-end
/// scenario builds a disk from or submits over HTTP.
///
/// The scenarios name these same constants, so a document a scenario boots is one
/// this list holds by construction rather than by somebody remembering. That is
/// what lets the fast gate hold *all* of them to `config::load`: a scenario
/// document is otherwise refused at that scenario's boot, a dozen minutes into the
/// full gate, for a finding that costs milliseconds to read.
///
/// [`standing_of`] is the only reader of the second column, and it refuses a
/// document that is not listed here at all — so registering one is not optional.
pub(crate) const EVERY_CONFIGURATION_DOCUMENT: &[(&str, Standing)] = &[
    (CONFIGURATION_DOCUMENT, Standing::Accepted),
    (ALTERNATE_DOCUMENT, Standing::Accepted),
    (LIFECYCLE_DOCUMENT, Standing::Accepted),
    (SUBMITTED_DOCUMENT, Standing::Accepted),
    (NARROWED_DOCUMENT, Standing::Accepted),
    (RELATED_DOCUMENT, Standing::Accepted),
    (DUPLICATE_RULE_ID_DOCUMENT, Standing::RefusedByRule),
];

/// The one document in the tree the appliance **refuses**, and the only one whose
/// entry above says so.
///
/// It is the shipped document with its two rules given one id, so the reader
/// accepts it and the rule about unique identifiers refuses it. Two scenarios use
/// it, at the two points in a node's life a document can arrive:
///
/// * **built into an image**, where the configuration domain refuses it at boot and
///   the node comes up on the fail-closed generation 0 — forwarding nothing, and
///   saying so on the one channel a node with no address has;
/// * **submitted over HTTP** to a node already running the shipped document, where
///   it must be refused with the *rule's* reason and must leave the running
///   generation and the ruleset exactly as they were.
///
/// One document for both because that is the sharper statement: the same bytes are
/// refused for the same reason whichever way they arrive, and its addressing is the
/// shipped bench's, so the traffic a fail-closed boot refuses to forward is
/// byte-for-byte the traffic the shipped document forwards.
pub(crate) const DUPLICATE_RULE_ID_DOCUMENT: &str = "tools/xtask/scenarios/duplicate-rule-id.xml";

/// What the appliance says about `document`, from the one list that records it.
///
/// # Errors
/// A document this tree does not register. Every document a build or a scenario
/// reaches for is one the fast gate has already judged, and a path that is not in
/// that list is one nothing judged — so it is refused here rather than built from.
pub(crate) fn standing_of(document: &Path) -> Result<Standing, Error> {
    EVERY_CONFIGURATION_DOCUMENT
        .iter()
        .find(|(path, _)| Path::new(path) == document)
        .map(|(_, standing)| *standing)
        .ok_or_else(|| {
            Error::invalid(format!(
                "{} is not one of the {} configuration documents this tree registers, so nothing \
                 has judged what the appliance would say about it. Add it to \
                 EVERY_CONFIGURATION_DOCUMENT with the standing it is meant to have; the fast gate \
                 then holds it to exactly that",
                document.display(),
                EVERY_CONFIGURATION_DOCUMENT.len()
            ))
        })
}

/// The one document in this tree that is never built into an image: it is
/// **submitted over the management API** to a node already running
/// [`CONFIGURATION_DOCUMENT`], and what it proves is that a running appliance
/// changes what it forwards because of it.
///
/// It is in the list above for the same reason the others are — it must be a
/// document this appliance would accept, and a scenario that discovered otherwise a
/// dozen minutes into the full gate would be reporting a finding the fast gate can
/// read in milliseconds.
pub(crate) const SUBMITTED_DOCUMENT: &str = "tools/xtask/scenarios/reconfiguration-swap.xml";

/// The second document that is only ever submitted, and the one a **revocation**
/// scenario hands over: the shipped policy with its accept rule narrowed by one
/// attribute, so a commit ends the conversations it no longer admits and leaves the
/// others running. In the list above for [`SUBMITTED_DOCUMENT`]'s reason.
pub(crate) const NARROWED_DOCUMENT: &str = "tools/xtask/scenarios/revocation-narrow.xml";

/// The third document that is only ever submitted, and the one a **related-traffic**
/// scenario hands over: the shipped policy with one rule added that admits the ICMP
/// errors a live conversation is the reason for. In the list above for
/// [`SUBMITTED_DOCUMENT`]'s reason.
pub(crate) const RELATED_DOCUMENT: &str = "tools/xtask/scenarios/related-icmp.xml";
/// The environment variable that carries [`CONFIGURATION_DOCUMENT`] to
/// `pds/config`.
///
/// Set at every site that compiles a protection domain, and never given a
/// default anywhere: `include_bytes!(env!(…))` fails the compilation when it is
/// absent, which is what keeps "which document did this image ship" a question
/// with one answer rather than a fallback nobody chose.
pub(crate) const CONFIG_PATH_VAR: &str = "LIBREFIREWALL_CONFIG_PATH";
/// Protection-domain binaries the system image is assembled from.
///
/// The single owner of that list: [`crate::host::test_host`] lints exactly these
/// packages for the seL4 target, so a PD added here is linted by the same edit
/// that makes it shippable and cannot slip through unlinted.
pub(crate) const SYSTEM_PDS: &[&str] = &[
    "nic-driver",
    "forwarder",
    "config-pd",
    "console",
    "clock",
    "management",
    "recorder",
];

/// Protection-domain binaries built with the SIMD target rather than
/// [`TARGET`], in a cargo invocation of their own: one target per invocation
/// is cargo's shape, and mixing the two lists would build every domain with
/// the vector units enabled — exactly what the softfloat specification exists
/// to prevent for the dataplane. The same single-owner property as
/// [`SYSTEM_PDS`]: [`crate::host::test_host`] lints exactly these packages for
/// the SIMD target.
pub(crate) const SIMD_SYSTEM_PDS: &[&str] = &["hardware-probe", "crypto"];

/// The pinned SDK's include directory for one seL4 kernel configuration.
///
/// These headers are what `sel4-sys` generates its bindings from and what
/// `sel4-config` derives every `sel4_cfg` flag from, so they — not the Cargo
/// profile — are what makes a protection-domain compilation
/// configuration-specific. Exposed so the PD lint compiles the PDs against the
/// same headers the image build does, rather than restating the SDK's layout.
pub(crate) fn board_include_dir(config: &str) -> PathBuf {
    Path::new(MICROKIT_SDK)
        .join("board")
        .join(BOARD)
        .join(config)
        .join("include")
}

/// Where an assembled image's disk goes, and what is written beside it.
pub(crate) enum Destination<'a> {
    /// `dist/`: the deployable disk together with the manifest, SBOM and
    /// checksums that describe it, plus the loose kernel/system pair published
    /// as the update input. Emptied and rewritten by every build.
    Published,
    /// One QEMU scenario's disk and nothing else, under the build tree.
    ///
    /// No manifest, no SBOM, no checksums: `dist/` holds deployable outputs and
    /// the evidence describing them, and a disk assembled to prove a test is
    /// neither. Writing provenance for an artifact nothing publishes would put
    /// a second manifest in circulation describing a configuration no appliance
    /// runs.
    Scenario { name: &'a str },
}

impl Destination<'_> {
    /// The name of this build's own working directory under `build/image`, kept
    /// apart per destination so a scenario build's protection domains — built
    /// around a different document — cannot overwrite the published ones.
    fn workspace(&self, config: &str) -> String {
        match self {
            Self::Published => config.to_owned(),
            Self::Scenario { name } => format!("{config}-{name}"),
        }
    }
}

/// Build the protection domains, assemble the Microkit image, and package the
/// signed A/B disk and its release evidence into `dist/`.
///
/// `config` selects the *Microkit/seL4 kernel* configuration (`debug` or
/// `release`), not a Cargo profile — see the note on the PD build below.
pub(crate) fn image(root: &Path, config: &str) -> Result<(), Error> {
    assemble(
        root,
        config,
        Path::new(CONFIGURATION_DOCUMENT),
        &Destination::Published,
    )
    .map(|_disk| ())
}

/// Assemble a disk from `document` in kernel configuration `config` for one
/// QEMU scenario, returning its path.
///
/// The published `dist/` is left exactly as it was: a scenario image is
/// evidence for a test and never something to ship, and a gate that overwrote
/// the artifact under test with one built from a different document — or in a
/// different kernel configuration — would prove the wrong disk. That is why a
/// [`crate::diagnose`] re-run of a failed release scenario comes through here
/// and never through [`image`]: the release disk in `dist/` is the thing under
/// judgement, and a debug disk published over it would destroy it.
pub(crate) fn scenario_image(
    root: &Path,
    config: &str,
    document: &Path,
    name: &str,
) -> Result<PathBuf, Error> {
    assemble(root, config, document, &Destination::Scenario { name })
}

/// The one image pipeline, from the pinned-input check to the signed disk.
///
/// `document` is the configuration document the appliance will run, relative to
/// `root`. Returns the disk that was written.
fn assemble(
    root: &Path,
    config: &str,
    document: &Path,
    destination: &Destination,
) -> Result<PathBuf, Error> {
    let pins = pins::read(root)?;
    verify_inputs(config, &pins)?;
    // Before the protection domains are compiled, not merely before the
    // Microkit tool consumes the description: the disagreement this catches is
    // between that file and the constants those binaries are built from, so
    // there is nothing to gain from compiling them first and minutes to lose.
    sysdesc::check(root)?;
    // And the other file the protection domains are built from, for the same
    // reason and at the same point: `pds/config` embeds this document byte for
    // byte, so a document its own validator refuses compiles cleanly into an
    // appliance that comes up on the fail-closed generation 0 and forwards
    // nothing. Read here, that is a build failure naming the byte; read only at
    // boot, it is a console line on a node that otherwise looks healthy.
    check_configuration(root, document)?;

    let build = root.join("build/image").join(destination.workspace(config));
    let dist = match destination {
        Destination::Published => root.join("dist"),
        Destination::Scenario { name } => root.join("build/image").join(format!("{name}-dist")),
    };
    recreate_dir(&build)?;
    recreate_dir(&dist)?;

    let target_root = root.join("target").join(config);
    // Cargo does not fingerprint the JSON specifications the two invocations
    // below name, so each target's artifacts are held to the one now on disk
    // before anything is compiled for either.
    target_spec::reconcile(root, &target_root, TARGET)?;
    target_spec::reconcile(root, &target_root, SIMD_TARGET)?;
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .env("SEL4_INCLUDE_DIRS", board_include_dir(config))
            .env("CARGO_TARGET_DIR", &target_root)
            // Absolute, because `include_bytes!` resolves a relative path
            // against the file that writes it and nothing here knows where in
            // the source tree that file will end up sitting.
            .env(CONFIG_PATH_VAR, root.join(document))
            .args([
                "build",
                "--locked",
                // Always the optimized Cargo profile, in every `config`. The
                // `debug`/`release` distinction here is the seL4 KERNEL
                // configuration (debug serial output and kernel assertions),
                // which is orthogonal to how the PDs are compiled. The PDs are
                // the dataplane and must be optimized in any configuration a
                // forwarding test is meaningful in; they are also `no_std`
                // binaries that depend on this profile's `panic = "abort"`,
                // there being no unwinder under seL4.
                "--release",
                "-Z",
                "build-std=core",
                // The dataplane copies bytes into pool buffers, which lowers to
                // the mem* intrinsics; have compiler-builtins provide them since
                // there is no libc under seL4.
                "-Z",
                "build-std-features=compiler-builtins-mem",
                "--target",
                TARGET,
            ])
            .args(SYSTEM_PDS.iter().flat_map(|pd| ["-p", pd])),
        "build protection domains",
    )?;

    // The SIMD protection domains, in an invocation of their own because a
    // cargo build has one `--target`: same profile, same flags, same
    // environment — only the specification differs.
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .env("SEL4_INCLUDE_DIRS", board_include_dir(config))
            .env("CARGO_TARGET_DIR", &target_root)
            .env(CONFIG_PATH_VAR, root.join(document))
            .args([
                "build",
                "--locked",
                "--release",
                // `alloc` and not only `core`, unlike the invocation above:
                // the cryptography domain carries the appliance's one
                // allocator, because a proven TLS implementation requires one.
                // The dataplane domains keep having none, which is why the two
                // invocations differ here rather than being unified.
                "-Z",
                "build-std=core,alloc",
                "-Z",
                "build-std-features=compiler-builtins-mem",
                "--target",
                SIMD_TARGET,
            ])
            .args(SIMD_SYSTEM_PDS.iter().flat_map(|pd| ["-p", pd])),
        "build SIMD protection domains",
    )?;

    let target_dir = target_root.join(TARGET).join("release");
    for pd in SYSTEM_PDS {
        let elf = format!("{pd}.elf");
        copy_file(&target_dir.join(&elf), &build.join(&elf))?;
    }
    let simd_target_dir = target_root.join(SIMD_TARGET).join("release");
    for pd in SIMD_SYSTEM_PDS {
        let elf = format!("{pd}.elf");
        copy_file(&simd_target_dir.join(&elf), &build.join(&elf))?;
    }
    // The binaries exist for the first time here, which is the only place the
    // acceleration claim can be checked against them: the adopted
    // cryptography crates pick a backend at compile time, so whether the fast
    // one was compiled in is a fact about these bytes and about nothing in the
    // source. The absence half matters more, and it is two absences: a wide
    // vector register in a protection domain is state the pinned kernel does
    // not save, and a VEX- or EVEX-encoded instruction is one the emulator half
    // of the gate will not execute at all while that saved state stays narrow.
    crate::crypto_profile::check_image(&build).map_err(crate::util::Error::Invalid)?;

    run_command(
        Command::new(Path::new(MICROKIT_SDK).join("bin/microkit"))
            .current_dir(root)
            .arg(root.join(SYSTEM_DESCRIPTION))
            .arg("--search-path")
            .arg(&build)
            .args(["--board", BOARD, "--config", config, "-o"])
            .arg(build.join(BUILD_SYSTEM_IMAGE))
            .arg("-r")
            // The capability/memory report is build-internal debugging
            // evidence and a full disclosure of the system's authority
            // topology; it stays out of the published artifact set.
            .arg(build.join(BUILD_MICROKIT_REPORT)),
        "assemble Microkit image",
    )?;

    // Held here rather than beside the other input checks above because it is
    // the assembled image that is judged, and it does not exist until the line
    // above has run. What it rejects is an image GRUB could place below the
    // seL4 kernel; the whole argument is on the function.
    grub::check_boot_module_placement(root, &build.join(BUILD_SYSTEM_IMAGE))?;

    // The loose kernel/system pair is published as the update input; the disk
    // below is the deployable artifact. The 32-bit kernel ELF is the Multiboot2
    // image GRUB boots (its entry is a 32-bit trampoline; the 64-bit sel4.elf
    // shares the same entry but the 32-bit image is what both QEMU and GRUB
    // load). `assemble_disk` reads them out of the build tree either way; this
    // copy is the publication, so it happens only where there is a publication.
    if matches!(destination, Destination::Published) {
        copy_file(&build.join(BUILD_KERNEL_IMAGE), &dist.join(DIST_KERNEL))?;
        copy_file(&build.join(BUILD_SYSTEM_IMAGE), &dist.join(DIST_SYSTEM))?;
    }

    let fingerprint = disk::assemble_disk(root, &build, &dist)?;
    let disk = dist.join(DIST_DISK);

    match destination {
        Destination::Published => {
            evidence::write_manifest(&dist, config, &fingerprint, &pins)?;
            evidence::write_sbom(root, &dist)?;
            evidence::write_checksums(&dist)?;
            println!("packaged boot artifacts in {}", dist.display());
        }
        Destination::Scenario { name } => {
            println!("assembled the {name} scenario disk at {}", disk.display());
        }
    }
    Ok(disk)
}

/// Read the configuration document the protection domains are built from and
/// hold it to `crates/config` — the same [`config::load`] the configuration
/// domain runs at boot, so the build refuses exactly what the appliance would
/// refuse rather than approximating it.
///
/// What "refuses" means is the document's own registered [`Standing`], both
/// directions: a document listed [`Standing::Accepted`] and refused fails, and one
/// listed [`Standing::RefusedByRule`] and *accepted* fails too. The second half is
/// the load-bearing one — a fail-closed scenario boots a document precisely
/// because the appliance will not commit it, and a document that quietly became
/// valid would leave that scenario proving nothing while passing.
pub(crate) fn check_configuration(root: &Path, document: &Path) -> Result<(), Error> {
    let standing = standing_of(document)?;
    let path = root.join(document);
    let bytes = fs::read(&path)
        .map_err(|error| Error::io("read the configuration document", &path, error))?;
    match (standing, config::load(&bytes)) {
        (Standing::Accepted, Ok(model)) => {
            println!(
                "config: {} declares {} interfaces and {} neighbours, every one of which \
                 `config::load` accepts — the same judgement the configuration domain makes at \
                 boot",
                path.display(),
                model.interface_count(),
                model.neighbour_count(),
            );
            Ok(())
        }
        (Standing::Accepted, Err(refusal)) => Err(Error::invalid(format!(
            "{}: the configuration domain would refuse this document — {}. It is embedded \
             verbatim into pds/config and committed in `init`, and a refused document leaves the \
             handover region untouched: the forwarder stays on generation 0, the node boots \
             forwarding nothing, and the only report is a console line. The reason above is the \
             token that line would carry.",
            path.display(),
            located(refusal),
        ))),
        // The document is registered as one the appliance refuses, and it must be
        // refused by a *rule* rather than by the reader: a reader's refusal yields
        // no model, so nothing could read the bench out of it and no scenario could
        // address the appliance it built.
        (Standing::RefusedByRule, Err(ConfigError::Semantic(fault))) => {
            println!(
                "config: {} is registered as a document the appliance refuses, and \
                 `config::load` refuses it — {} at {:?}. A node built around it comes up on the \
                 fail-closed generation 0; submitted to a running node it is answered with that \
                 reason and moves nothing",
                path.display(),
                fault.reason().name(),
                fault.id().as_str(),
            );
            Ok(())
        }
        (Standing::RefusedByRule, Err(ConfigError::Document(fault))) => {
            Err(Error::invalid(format!(
                "{}: this document is registered as one a semantic RULE refuses, and the reader \
             refused it first — {} at byte offset {}. A reader's refusal yields no model, so the \
             bench cannot be read out of it and the scenario that boots it has no addresses to \
             state a contract between. Make the document well formed and wrong about an object.",
                path.display(),
                fault.reason().name(),
                fault.offset,
            )))
        }
        (Standing::RefusedByRule, Ok(model)) => Err(Error::invalid(format!(
            "{}: this document is registered as one the appliance refuses and `config::load` \
             accepts it — {} interfaces and {} neighbours, every rule satisfied. The scenario \
             that boots it exists to show a node coming up on the fail-closed generation 0, so \
             an accepted document would have it prove nothing while passing.",
            path.display(),
            model.interface_count(),
            model.neighbour_count(),
        ))),
    }
}

/// The reason a document was refused, and where.
///
/// Only the document half of `config::load` carries a byte offset; a semantic
/// refusal is about an object and names the id instead. `crates/config` refuses
/// to synthesise the missing one — `ConfigError` deliberately exposes no
/// `offset()` — and so does this, because an offset of zero would point an
/// operator at a byte that has nothing to do with the refusal.
fn located(refusal: ConfigError) -> String {
    match refusal {
        ConfigError::Document(fault) => {
            format!("{} at byte offset {}", fault.reason(), fault.offset)
        }
        ConfigError::Semantic(fault) => format!("{} at {:?}", fault.reason(), fault.id().as_str()),
    }
}

/// Verify, before anything is compiled, that the builder holds the pinned
/// toolchain this build claims to use, and that the SDK pieces the assembly
/// consumes are present.
///
/// This establishes *identity by version*: every pin the manifest goes on to
/// record as provenance is checked against the installed input, so no field in
/// that manifest is an unchecked claim. It does not establish *integrity of
/// content* — the sha256 pins in `sources.lock` are verified when the builder
/// image fetches each archive, and the archives do not survive into the running
/// container for xtask to re-check.
fn verify_inputs(config: &str, pins: &Pins) -> Result<(), Error> {
    verify_version(
        &Path::new(RUST_SEL4).join("VERSION"),
        &pins.rust_sel4_version,
        "rust-sel4",
    )?;
    verify_version(
        &Path::new(MICROKIT_SDK).join("VERSION"),
        &pins.microkit_version,
        "Microkit SDK",
    )?;
    // GRUB is built from source into the builder rather than unpacked, so it
    // carries no VERSION file; ask the tool that will build the boot base. The
    // manifest records this version as provenance, and provenance nothing
    // checks is just a claim.
    grub::installed_version(&pins.grub_version)?;
    crate::util::require_file(&Path::new(MICROKIT_SDK).join("bin/microkit"))?;
    crate::util::require_file(
        &Path::new(MICROKIT_SDK)
            .join("board")
            .join(BOARD)
            .join(config)
            .join("elf")
            .join(BUILD_KERNEL_IMAGE),
    )
}

fn verify_version(path: &Path, expected: &str, name: &str) -> Result<(), Error> {
    let actual = std::fs::read_to_string(path)
        .map_err(|error| Error::io(&format!("read the pinned {name}"), path, error))?;
    if actual.trim() != expected {
        return Err(Error::invalid(format!(
            "{name} at {} has version {:?}, expected {expected:?}",
            path.display(),
            actual.trim()
        )));
    }
    Ok(())
}
