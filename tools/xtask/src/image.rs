//! seL4/Microkit image assembly — the `image` command.
//!
//! Builds the [`SYSTEM_PDS`] protection-domain ELFs for the seL4 target,
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
//! end-to-end scenario boots (BLD-3). `debug` reaches this module from the
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
    sysdesc,
    util::{Error, copy_file, recreate_dir, run_command},
};

pub(crate) const TARGET: &str = "x86_64-sel4-minimal";
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
/// The environment variable that carries [`CONFIGURATION_DOCUMENT`] to
/// `pds/config`.
///
/// Set at every site that compiles a protection domain, and never given a
/// default anywhere: `include_bytes!(env!(…))` fails the compilation when it is
/// absent, which is what keeps "which document did this image ship" a question
/// with one answer rather than a fallback nobody chose (ENG-12).
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
];

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

    let target_dir = target_root.join(TARGET).join("release");
    for pd in SYSTEM_PDS {
        let elf = format!("{pd}.elf");
        copy_file(&target_dir.join(&elf), &build.join(&elf))?;
    }

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
pub(crate) fn check_configuration(root: &Path, document: &Path) -> Result<(), Error> {
    let path = root.join(document);
    let document = fs::read(&path)
        .map_err(|error| Error::io("read the configuration document", &path, error))?;
    let model = config::load(&document).map_err(|refusal| {
        Error::invalid(format!(
            "{}: the configuration domain would refuse this document — {}. It is embedded \
             verbatim into pds/config and committed in `init`, and a refused document leaves the \
             handover region untouched: the forwarder stays on generation 0, the node boots \
             forwarding nothing, and the only report is a console line. The reason above is the \
             token that line would carry.",
            path.display(),
            located(refusal),
        ))
    })?;
    println!(
        "config: {} declares {} interfaces and {} neighbours, every one of which `config::load` \
         accepts — the same judgement the configuration domain makes at boot",
        path.display(),
        model.interface_count(),
        model.neighbour_count(),
    );
    Ok(())
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
