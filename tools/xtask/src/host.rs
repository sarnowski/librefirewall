//! The host-side commands: the fast gate, coverage, benchmarks, fuzzing, clean.
//!
//! These run without booting seL4. [`test_host`] is the fast gate the pre-commit
//! hook and CI share (format, the comment and `unsafe` budgets, the system-description
//! cross-check, host tests, Clippy with warnings denied over *every* workspace
//! member, the `cargo-deny` dependency/license/source policy, and the library
//! coverage floor). [`fuzz`] additionally runs in the full `ci` gate (build
//! every fuzz target and briefly exercise it). [`coverage`] and [`bench`] are
//! measurement/discovery commands deliberately outside any gate.
//!
//! # Why the lint step is two commands, not one
//!
//! A `-D warnings` policy is only worth what it covers, and cargo's package
//! selection makes that easy to get silently wrong here in two independent
//! ways, both of which this module exists to close:
//!
//! * The root `Cargo.toml` sets `default-members = ["tools/xtask"]`, so a bare
//!   `cargo clippy --all-targets -- -D warnings` selects `xtask` alone and
//!   reports clean while never looking at a single library crate. Every lint
//!   invocation below therefore names its packages explicitly, and
//!   [`tests::every_workspace_member_is_linted`] fails the build if a member is
//!   missing from a list rather than leaving that to review.
//! * The protection domains do not build for the host at all, so no host
//!   command can lint them however the packages are selected. They are linted
//!   by [`lint_protection_domains`] for the seL4 target instead.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{budgets, image, reference_contract, sysdesc, util::run_command};

/// Workspace packages that build and test on the host (no seL4 target). The
/// protection-domain binaries are excluded: they need the Microkit target, and
/// [`lint_protection_domains`] lints them there.
const HOST_TEST_PACKAGES: &[&str] = &[
    "wire",
    "queue",
    "packet-buffer",
    "net-headers",
    "routing",
    "pipeline",
    "lfw-ip-endpoint",
    "lfw-tcp",
    "lfw-flow",
    "lfw-http",
    "lfw-log",
    "lfw-metrics",
    "lfw-pcapng",
    "lfw-blk",
    "lfw-capture-ring",
    "lfw-recorder",
    "virtio",
    "pd-runtime",
    "nic-driver-core",
    "uart-16550",
    "config",
    "lfw-clock",
    "lfw-hpet",
    "lfw-rtc",
    "xtask",
];

/// The library crates held to the coverage floor: the portable `no_std` logic
/// the firewall is built from.
///
/// Its exact complement over the workspace is `tests::COVERAGE_EXCLUSIONS`,
/// which records for every remaining member the coverage-exemption reason that
/// admits leaving it out — and, where that reason does not cover the whole of
/// the member, the part it does not. A test in that module holds the two to
/// partitioning the workspace, so a member in neither fails the build rather
/// than going quietly unmeasured.
const LIBRARY_PACKAGES: &[&str] = &[
    "wire",
    "queue",
    "packet-buffer",
    "net-headers",
    "routing",
    "pipeline",
    "lfw-ip-endpoint",
    "lfw-tcp",
    "lfw-flow",
    "lfw-http",
    "lfw-log",
    "lfw-metrics",
    "lfw-pcapng",
    "lfw-blk",
    "lfw-capture-ring",
    "lfw-recorder",
    "virtio",
    "pd-runtime",
    "nic-driver-core",
    "uart-16550",
    "config",
    "lfw-clock",
    "lfw-hpet",
    "lfw-rtc",
];

/// Minimum combined line coverage the [`LIBRARY_PACKAGES`] must hold, enforced
/// by the fast gate so a coverage regression fails locally and in CI. Set well
/// below the measured ~99.3% combined coverage: a real floor that is not
/// flaky. Raise it as coverage rises; never lower it to land a change.
const LIBRARY_COVERAGE_FLOOR_PCT: u32 = 94;

/// Minimum line coverage EACH library crate must hold on its own. The combined
/// floor alone lets one crate regress heavily while the high-coverage crates
/// keep the total above [`LIBRARY_COVERAGE_FLOOR_PCT`]; this per-crate floor
/// closes that gap. Set well below the current per-crate minimum (routing
/// ~98.4%) so it is a real, non-flaky floor; raise it as the weakest crate
/// rises, never lower it to land a change.
const LIBRARY_PER_CRATE_COVERAGE_FLOOR_PCT: u32 = 90;

/// Crates carrying criterion microbenchmarks, run by `bench`. These are the
/// perf-sensitive dataplane substrate crates whose hot operations the 10 Gbit/s
/// budget depends on.
const BENCH_PACKAGES: &[&str] = &["queue", "packet-buffer", "virtio", "pd-runtime"];

/// The seL4 kernel configurations the protection domains are linted in.
///
/// Both, because they are two different compilations of the same source rather
/// than two optimisation levels of one. `sel4-config` derives its `sel4_cfg`
/// flags from the board's generated kernel headers, and the two boards differ:
/// `CONFIG_PRINTING` is set in `debug` and cleared in `release`, so the two
/// build different `sel4_microkit` internals and different kernel bindings
/// under every protection domain. That difference used to be visible in PD
/// source, back when a domain reported through `debug_println!` and the release
/// kernel had no `seL4_DebugPutChar` to answer it — the defect the console
/// domain exists to fix. Now it is not, which makes this second run more
/// load-bearing rather than less: nothing but a compilation shows it.
///
/// # This is now the only thing keeping the `debug` configuration buildable
///
/// Every gate boots the release image: [`crate::ci`] assembles that
/// configuration and the QEMU system and A/B scenarios boot it. The
/// debug kernel survives in exactly three places — this lint, the `image-debug`
/// opt-in, and `run` — and of the three only this one runs in a gate. So a PD
/// change that compiles under the release headers and not under the debug ones
/// is caught here or nowhere, and the debug configuration would otherwise rot
/// undetected until the moment [`crate::diagnose`] tried to build it to explain
/// a release failure. That is the worst possible moment for it to be broken.
///
/// It costs a third of a second, and it is compile-time: nothing about it
/// reaches a booted image.
const SEL4_KERNEL_CONFIGS: &[&str] = &[image::DEBUG_CONFIG, image::RELEASE_CONFIG];

/// The persistent fuzz targets under `fuzz/`, driven by [`fuzz`], ordered from
/// the smallest, most self-contained untrusted-input surface to the deepest
/// composite one, matching the harness list in `fuzz/src/lib.rs`. One defect
/// often reaches several targets, and the narrowest one that reproduces it is
/// the one worth reading, so it runs first.
const FUZZ_TARGETS: &[&str] = &[
    "config_image",
    "log_record",
    "free_list_ownership",
    "route_frame",
    "ip_endpoint",
    "tcp_segments",
    "flow_table",
    "http_request",
    "metrics_render",
    "config_document",
    "spsc_ring_peer",
    "log_ring",
    "virtqueue_poll",
    "blk_requests",
    "pcapng_encode",
    "capture_superblock",
    "recorder_sink",
    "recording_pass",
    "pd_runtime_pipeline",
    "nic_driver_paths",
    "find_virtio_caps",
];

pub(crate) fn test_host(root: &Path) -> Result<(), String> {
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["fmt", "--all", "--check"]),
        "check formatting",
    )?;
    enforce_budgets(root)?;
    // Beside the budgets and for the same reason: it reads two files and
    // compares numbers, so it costs milliseconds against the minutes below it,
    // and a truncated memory region is exactly the finding that is worthless
    // discovered late. Putting it here rather than only in `image` is what
    // makes `make test` catch a divergence with no image build at all — and
    // `ci` and `release` reach it through this function anyway.
    sysdesc::check(root)?;
    // The same argument again, aimed at the other document the code has to stay
    // true to. The reference chapters are the operator's interface definition and
    // nothing in the gate ever read them, so every sentence in them was an
    // untested assertion — a refusal token or a metric family could be added to a
    // shipping domain with the chapter that calls itself complete going stale and
    // every stage of this gate green. It reads two Markdown files and two
    // in-process catalogues, so it costs milliseconds here rather than a boot.
    reference_contract::check(root)?;
    // And for the third time the same argument: the configuration document is
    // a source-controlled input the protection domains are built from, so a
    // document the appliance would refuse is a finding available for the cost
    // of reading one file. Without this the fast gate accepts a document that
    // only fails at `make image`, minutes later and behind a compile.
    image::check_configuration(root, Path::new(image::CONFIGURATION_DOCUMENT))?;
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["test", "--locked"])
            .args(HOST_TEST_PACKAGES.iter().flat_map(|pkg| ["-p", pkg])),
        "run host tests",
    )?;
    // The explicit `-p` list is load-bearing, not verbosity: `default-members`
    // in the root `Cargo.toml` is `["tools/xtask"]`, so dropping it would lint
    // xtask alone and pass while every library crate went unexamined. See this
    // module's header; `tests::every_workspace_member_is_linted` is what keeps
    // the list complete.
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["clippy", "--locked", "--all-targets"])
            .args(HOST_TEST_PACKAGES.iter().flat_map(|pkg| ["-p", pkg]))
            .args(["--", "-D", "warnings"]),
        "run host clippy",
    )?;
    lint_protection_domains(root)?;
    // Enforce the dependency/license/source policy (deny.toml). `advisories`
    // is deliberately not among the three: it must fetch the RustSec database
    // and this gate runs offline (`--network=none`), so adding the flag here
    // would fail rather than scan. It is moved, not skipped —
    // `azure-pipelines.yml` runs `cargo deny check advisories` in the same
    // pinned builder with the network left on, and `deny.toml`'s `[advisories]`
    // section configures it. The consequence to keep straight: a green run here
    // is a dependency-policy pass and not a vulnerability scan; the scan is a
    // CI stage, and only there.
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["deny", "check", "bans", "licenses", "sources"]),
        "check dependency policy",
    )?;
    enforce_coverage(root)
}

/// Lint the protection domains for the seL4 target, in every kernel
/// configuration, with warnings denied.
///
/// # Why this is in the fast gate rather than in `ci`
///
/// The PDs are the two crates that map raw hardware and shared memory, and
/// until this step existed they were the two crates a `-D warnings` policy did
/// not reach: no host command can select them (they do not build for the host),
/// and `image` only ever *compiles* them, which denies nothing. Two binaries
/// exempt from the workspace lint policy is not a workspace lint policy.
///
/// It needs the cross toolchain and the pinned SDK, which sounds like a reason
/// to defer it to `ci`, and is not: `make test` runs inside the pinned builder
/// exactly as `make ci` does (the `Makefile`'s `require_builder` refuses
/// otherwise), so both gates have the SDK and neither has more of it. What the
/// stages really differ in is latency, and a lint is worth nothing discovered
/// late — a PD lint error is detectable here in well under a second warm, or
/// after a QEMU boot and an A/B run if it waits for pre-push. `ci` calls
/// [`test_host`] first, so putting it here puts it in `ci` and `release` too;
/// the reverse would not hold.
///
/// # Two deviations from the host clippy step, both deliberate
///
/// * **No `--all-targets`.** It would add each bin's implicit test target,
///   which needs the `test` crate; the PDs are `no_std` and `build-std=core`
///   supplies `core` alone, so the lint would fail to *compile* rather than
///   report anything. Without it cargo still selects both binaries, which is
///   every target these crates have.
/// * **A lint-only `CARGO_TARGET_DIR`.** `image` points cargo at
///   `target/<config>`, which for `debug` is also where the host dev profile
///   writes; keeping this step in its own tree means it can neither perturb
///   nor be perturbed by an artifact the image build or the coverage run
///   depends on — a cache may accelerate a build, never decide one.
///
/// Everything else mirrors `image`'s PD build exactly — the same `--release`
/// profile (so `debug_assertions` is off here as it is in every booted image),
/// the same `build-std` flags, the same target, and the same headers — because
/// a lint of a different compilation than the one that ships proves nothing
/// about the one that ships. `RUST_TARGET_PATH` is not set here for the same
/// reason `image` does not set it: `.cargo/config.toml` supplies it workspace-
/// wide.
fn lint_protection_domains(root: &Path) -> Result<(), String> {
    for config in SEL4_KERNEL_CONFIGS {
        let include_dir = image::board_include_dir(config);
        // Fail by name rather than as a bindgen error a thousand lines deep:
        // the one way to reach this step without the headers is running xtask
        // outside the pinned builder, and that is what the operator must be
        // told.
        if !include_dir.is_dir() {
            return Err(format!(
                "cannot lint the protection domains: the pinned Microkit SDK's {config} headers \
                 are missing at {}. This step cross-compiles for seL4, so it runs inside the \
                 pinned builder — use `make test`, which enters it.",
                include_dir.display()
            ));
        }
        run_command(
            Command::new("cargo")
                .current_dir(root)
                .env("SEL4_INCLUDE_DIRS", &include_dir)
                .env(
                    "CARGO_TARGET_DIR",
                    root.join("target/lint-sel4").join(config),
                )
                // The configuration domain embeds this document through
                // `include_bytes!(env!(…))`, so without it the lint would not
                // reach a single lint — it would fail to expand. Named here
                // exactly as `image` names it, because a lint of a domain built
                // from a different document is a lint of a different binary.
                .env(
                    image::CONFIG_PATH_VAR,
                    root.join(image::CONFIGURATION_DOCUMENT),
                )
                .args([
                    "clippy",
                    "--locked",
                    "--release",
                    "-Z",
                    "build-std=core",
                    "-Z",
                    "build-std-features=compiler-builtins-mem",
                    "--target",
                    image::TARGET,
                ])
                .args(image::SYSTEM_PDS.iter().flat_map(|pd| ["-p", pd]))
                .args(["--", "-D", "warnings"]),
            &format!("lint protection domains for seL4 ({config} kernel configuration)"),
        )?;
    }
    Ok(())
}

/// Enforce the comment budget and the `unsafe` budget against
/// the recorded baseline in [`budgets::BASELINE`].
///
/// Both are ratchets rather than thresholds: a number may fall and may never
/// rise. [`budgets`] carries the definitions and the reasoning; what belongs
/// here is only where the check sits in the gate.
///
/// # Why it runs before the compiling steps rather than beside the coverage floor
///
/// [`enforce_coverage`] is last because it needs an instrumented test run.
/// This check needs nothing built at all — it reads the `.rs` files and scans
/// them — so it costs milliseconds against the minutes of the steps below it,
/// and it is exactly the kind of finding that is worthless discovered late. A
/// documentation change that pushes a file's ratio up is reported here before
/// the author waits out a full test and Clippy pass to hear it. The same
/// argument [`lint_protection_domains`] makes for itself.
fn enforce_budgets(root: &Path) -> Result<(), String> {
    budgets::enforce(root)
}

/// Enforce the library coverage floors: the combined floor across every
/// [`LIBRARY_PACKAGES`] member AND a per-crate floor on each one, so a regression
/// concentrated in a single crate cannot hide behind the high-coverage crates.
///
/// The library tests are instrumented once with `--no-report`; the combined and
/// per-crate reports then read that one profile, so the extra checks add report
/// generation, not extra test runs. `--fail-under-lines` makes each report exit
/// non-zero below its floor, so a regression fails here and identically in CI.
fn enforce_coverage(root: &Path) -> Result<(), String> {
    // `--no-report` adds to whatever profile data is already in the target
    // directory rather than replacing it, and a report merged from a previous
    // run's `.profraw` describes neither run. Observed both ways in this tree:
    // a crate measured at 54.81% against a clean 94.97%, and — the direction
    // that matters — a stale profile can as easily carry a floor a change no
    // longer meets. A gate that can report a number the tree does not have is
    // not a gate, so the profile is discarded first and every run measures only
    // what it just executed.
    run_command(
        Command::new("cargo").current_dir(root).args([
            "llvm-cov",
            "clean",
            "--workspace",
            "--locked",
        ]),
        "discard stale coverage profile data",
    )?;
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["llvm-cov", "--no-report", "--locked"])
            .args(LIBRARY_PACKAGES.iter().flat_map(|pkg| ["-p", pkg])),
        "instrument library tests for coverage",
    )?;
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["llvm-cov", "report", "--locked", "--summary-only"])
            .arg("--fail-under-lines")
            .arg(LIBRARY_COVERAGE_FLOOR_PCT.to_string())
            .args(LIBRARY_PACKAGES.iter().flat_map(|pkg| ["-p", pkg])),
        "enforce combined library coverage floor",
    )?;
    for pkg in LIBRARY_PACKAGES {
        run_command(
            Command::new("cargo")
                .current_dir(root)
                .args(["llvm-cov", "report", "--locked", "--summary-only"])
                .arg("--fail-under-lines")
                .arg(LIBRARY_PER_CRATE_COVERAGE_FLOOR_PCT.to_string())
                .args(["-p", pkg]),
            &format!("enforce {pkg} per-crate coverage floor"),
        )?;
    }
    Ok(())
}

/// Measure line coverage of the host packages and print the per-crate summary.
/// This mirrors [`HOST_TEST_PACKAGES`] rather than the whole workspace because
/// the protection-domain binaries only build for the seL4 target. The gate's
/// enforced floor is on [`LIBRARY_PACKAGES`] (see [`test_host`]); this command
/// reports every host crate's number so the headroom above the floor is visible.
pub(crate) fn coverage(root: &Path) -> Result<(), String> {
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["llvm-cov", "--locked", "--summary-only"])
            .args(HOST_TEST_PACKAGES.iter().flat_map(|pkg| ["-p", pkg])),
        "measure host coverage",
    )?;
    Ok(())
}

/// Run the criterion microbenchmarks for the perf-sensitive substrate crates.
/// Measurement only: there is deliberately no numeric regression gate here, so
/// `bench` is not part of `ci`. End-to-end throughput and tail-latency gating
/// belongs to QEMU/KVM and physical-hardware runs, not these host micros.
pub(crate) fn bench(root: &Path) -> Result<(), String> {
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["bench", "--locked"])
            .args(BENCH_PACKAGES.iter().flat_map(|pkg| ["-p", pkg])),
        "run microbenchmarks",
    )?;
    Ok(())
}

/// Build every persistent fuzz target and, where this environment permits,
/// run each briefly; always drive the same harness code over the committed
/// seeds. This runs inside the full `ci` gate (bounded per target), unlike
/// `bench`, which stays measurement-only.
///
/// The command distinguishes the two things a non-zero `cargo fuzz run` can
/// mean, because conflating them would make the gate blind to its own subject:
/// the pinned hermetic builder (`--cap-drop=all`, read-only rootfs,
/// `--security-opt=no-new-privileges`) can stop libFuzzer/AddressSanitizer from
/// starting at all, whereas a target that starts and then exits non-zero has
/// found a crash, an OOM, or a timeout. The first is established ONCE by an
/// explicit probe and is tolerated with a loud report; after it passes, every
/// non-zero exit is a finding and fails the gate.
///
/// The seed-corpus smoke tests (`cargo test --lib` in `fuzz/`) run
/// unconditionally and exercise the identical harness functions the fuzz
/// targets call, so the parsers stay covered over valid inputs even where
/// libFuzzer cannot run.
pub(crate) fn fuzz(root: &Path) -> Result<(), String> {
    // Deliberately first: this is the only fuzz-workspace command that accepts
    // `--locked` (see `read_fuzz_lockfile`), so running it before anything else
    // resolves the committed lockfile while it is still untouched, and it fails
    // fast on a stale one.
    run_command(
        Command::new("cargo")
            .current_dir(root.join("fuzz"))
            .args(["test", "--locked", "--lib"]),
        "run fuzz seed smoke tests",
    )?;
    let pinned_lockfile = read_fuzz_lockfile(root)?;

    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["fuzz", "build"]),
        "build fuzz targets",
    )?;
    println!("fuzz: all targets built with AddressSanitizer instrumentation");

    let mut targets = Vec::new();
    for target in FUZZ_TARGETS {
        targets.push((*target, scratch_corpus(target)?));
    }
    let (probe_target, probe_scratch) = targets
        .first()
        .ok_or_else(|| "no fuzz targets are declared, so `fuzz` would prove nothing".to_owned())?;
    let blocked = probe_fuzz_execution(root, probe_target, probe_scratch)?;

    match &blocked {
        Some(reason) => eprintln!(
            "fuzz: this environment cannot EXECUTE an instrumented target ({reason}); the \
             hermetic builder (cap-drop=all, read-only rootfs, no-new-privileges) can stop \
             libFuzzer/ASan before main. Building targets and running the seed smoke tests only."
        ),
        None => {
            for (target, scratch) in &targets {
                let seeds = root.join("fuzz").join("corpus").join(target);
                // The probe proved an instrumented target can start here, so a
                // non-zero exit now is libFuzzer reporting a crash, OOM or
                // timeout. That is a finding, and it must fail the gate.
                run_command(
                    Command::new("cargo")
                        .current_dir(root)
                        .args(["fuzz", "run", target])
                        .arg(scratch)
                        .arg(&seeds)
                        .args(["--", "-runs=20000", "-max_total_time=15"]),
                    &format!("fuzz {target}"),
                )?;
                println!("fuzz: ran {target} (-runs=20000 -max_total_time=15)");
            }
        }
    }

    if read_fuzz_lockfile(root)? != pinned_lockfile {
        return Err(LOCKFILE_REWRITTEN.to_owned());
    }

    match blocked {
        None => println!("fuzz: targets built AND ran; seed smoke tests passed"),
        Some(_) => println!(
            "fuzz: targets BUILD and the seed smoke tests pass, but libFuzzer execution was \
             blocked by this environment (see above) — build + seed coverage only, no live \
             fuzzing here"
        ),
    }
    Ok(())
}

/// What to tell the operator when the fuzz build re-resolved the committed
/// lockfile — the failure `--locked` would report if `cargo-fuzz` accepted it.
const LOCKFILE_REWRITTEN: &str = "fuzz/Cargo.lock was rewritten by the fuzz build; the committed lockfile is authoritative. \
     Re-resolve it deliberately in fuzz/ and commit the result, or fix the dependency edit that \
     forced the re-resolve.";

/// The committed lockfile of the standalone `fuzz/` workspace, read so it can
/// be compared before and after the fuzz build.
///
/// `cargo-fuzz` 0.13.2 takes no `--locked`: its clap parser rejects the flag
/// outright, so it cannot be passed to `cargo fuzz build`/`run` the way the
/// rest of the build passes it to cargo. The guarantee is reconstructed from
/// outside instead — the `--locked` seed smoke test resolves the committed
/// lockfile first, and this comparison proves the fuzz build did not then
/// rewrite it.
fn read_fuzz_lockfile(root: &Path) -> Result<Vec<u8>, String> {
    let lockfile = root.join("fuzz").join("Cargo.lock");
    fs::read(&lockfile).map_err(|error| format!("read {}: {error}", lockfile.display()))
}

/// A throwaway corpus directory under the tmpfs for one target.
///
/// libFuzzer writes coverage-increasing inputs into the FIRST corpus directory
/// it is given, so this one goes first and the committed corpus follows as a
/// read-only seed source. That keeps the bounded smoke run — which `ci`
/// performs on every commit — from growing or dirtying the tracked
/// `fuzz/corpus/` tree; curated regression seeds are added there deliberately.
fn scratch_corpus(target: &str) -> Result<PathBuf, String> {
    let scratch = std::env::temp_dir()
        .join("librefirewall-fuzz-corpus")
        .join(target);
    fs::create_dir_all(&scratch)
        .map_err(|error| format!("create fuzz scratch corpus {}: {error}", scratch.display()))?;
    Ok(scratch)
}

/// Establish once whether this environment can execute an instrumented fuzz
/// binary at all, returning `None` when it can and the reason when it cannot.
///
/// `-help=1` makes libFuzzer print its options and exit successfully without
/// running a single input, yet still exercises the entire instrumented startup
/// — AddressSanitizer establishes its shadow mapping before `main`, which is
/// exactly what a locked-down sandbox refuses. The probe therefore cannot
/// report a fuzz finding, which is what licenses treating every later non-zero
/// exit as one.
fn probe_fuzz_execution(
    root: &Path,
    target: &str,
    scratch: &Path,
) -> Result<Option<String>, String> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["fuzz", "run", target])
        .arg(scratch)
        .args(["--", "-help=1"])
        .output()
        .map_err(|error| format!("spawn fuzz execution probe for {target}: {error}"))?;
    if output.status.success() {
        return Ok(None);
    }
    Ok(Some(format!(
        "{target} exited {} — {}",
        output.status,
        tail(&output.stderr, 5)
    )))
}

/// The last `count` non-blank lines of a captured stderr, joined for a
/// single-line diagnostic: enough of the tool's own words to act on, without
/// pasting a whole build log into an error message.
fn tail(stderr: &[u8], count: usize) -> String {
    let text = String::from_utf8_lossy(stderr);
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    lines[lines.len().saturating_sub(count)..].join(" | ")
}

/// Remove every generated directory, leaving only source-controlled inputs
/// (`build/` keeps `build/container`; only its generated `image`/`dev-keys`
/// subtrees go). This is the single owner of the clean list; `make clean`
/// delegates here so the two never diverge.
pub(crate) fn clean(root: &Path) -> Result<(), String> {
    for path in [
        root.join("build/image"),
        root.join("build/dev-keys"),
        root.join("dist"),
        root.join("target"),
    ] {
        if path.exists() {
            fs::remove_dir_all(&path)
                .map_err(|error| format!("remove {}: {error}", path.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Why a workspace member is outside the [`LIBRARY_PACKAGES`] coverage
    /// floor.
    ///
    /// The set of admissible reasons is closed — only-observable-under-seL4,
    /// build orchestration, or a test-or-benchmark harness — so the reason is
    /// this enum rather than free prose: an exclusion that cannot name one of
    /// these variants is not an exclusion, and the check below refuses it.
    /// Only the two reasons this workspace uses are declared — the third owns
    /// no member here; the criterion benches live inside floored crates.
    enum CoverageExclusion {
        /// Only observable under seL4: a protection-domain adapter, which no
        /// host command can measure because it does not build for the host.
        ///
        /// This reason holds only when the exclusion "names the QEMU test that
        /// covers it instead", so that clause is a field and not a sentence
        /// someone may forget to write. `qemu_evidence` names the covering
        /// command and what it asserts; `residue` names the adapter code that
        /// evidence does NOT reach. `None` claims the evidence covers the
        /// whole adapter — a claim made deliberately, never by omission.
        OnlyObservableUnderSel4 {
            qemu_evidence: &'static str,
            residue: Option<&'static str>,
        },
        /// Build orchestration. None of it runs on a
        /// deployed appliance, so it is host-tested to keep the build honest
        /// rather than held to a number defending the product.
        BuildOrchestration,
    }

    /// The xtask commands an only-under-seL4 exclusion may cite: the two that
    /// boot a real image and judge it by a machine-observable contract.
    /// Requiring the evidence to name one is what separates it from "the QEMU
    /// gate covers it", which names nothing and can be written about anything.
    const QEMU_TESTS: &[&str] = &["test-system", "test-ab"];

    /// Every workspace member outside the coverage floor, with the recorded
    /// reason admitting it — the exact complement of [`LIBRARY_PACKAGES`].
    ///
    /// The pair is what makes "excluded" a decision someone recorded rather
    /// than a consequence of the directory a crate happens to sit in.
    const COVERAGE_EXCLUSIONS: &[(&str, CoverageExclusion)] = &[
        (
            "nic-driver",
            CoverageExclusion::OnlyObservableUnderSel4 {
                qemu_evidence: "`xtask test-system` boots the deployable disk and asserts the \
                                forwarding contract — a frame injected into each virtio port \
                                must egress on the other, rewritten for its next hop and with \
                                its payload intact — which no frame can satisfy unless this \
                                domain's whole bring-up ran against the device (identify, \
                                place_bar, map, acknowledge, negotiate_features, \
                                configure_queues, go_live) and then primed and polled. `xtask \
                                test-ab` re-asserts the same contract on the slot it selected \
                                in six of its eight scenarios.",
                residue: Some(
                    "`PoolDmaBase::new`'s rejecting branches and the `StartupError` console \
                     path are reached by no QEMU test: every scenario boots the one correct \
                     system description, so the patched `rx_pool_paddr`/`tx_pool_paddr` are \
                     always valid and only the accepting branch runs. That is the \
                     layering defect the crate header already records — first-party decision \
                     logic sitting in a PD, where neither the host floor nor the QEMU gate can \
                     reach it — and not a covered path. Closing it means moving the newtype \
                     into `pd_runtime`, beside the `MAPPING_ALIGN` and `POOL_REGION_SIZE` it \
                     checks against, and having `NicPort::attach` take it, which puts the \
                     check under the host coverage floor.",
                ),
            },
        ),
        (
            "forwarder",
            CoverageExclusion::OnlyObservableUnderSel4 {
                qemu_evidence: "`xtask test-system` boots the deployable disk and asserts the \
                                forwarding contract in both directions at once, and this domain \
                                cannot satisfy it by accident: it starts on the fail-closed \
                                generation 0, whose empty table forwards nothing at all. A frame \
                                egressing on the opposite port, rewritten for its next hop, \
                                therefore proves `init` attached both `ForwardRings` regions, \
                                both pools and both configuration regions, and that `notified` \
                                took the offered image, acknowledged it, switched to it at a \
                                poll boundary and then drove both `RouteStage`s under it. The \
                                `alternate-configuration` scenario boots a second disk whose \
                                document shares no address and no MAC with the first, so the \
                                table those frames were decided by is the one that crossed the \
                                handover rather than one this binary could have held. `xtask \
                                test-ab` re-asserts the contract on the slot it selected in six \
                                of its eight scenarios.",
                residue: Some(
                    "The refusal arm of the handover — rendering the offer's \
                     `Event::ConfigRejected` to the console, and withholding the signal that \
                     tells the publisher a generation was staged — is reached by no QEMU test. \
                     `xtask image` validates the document every scenario is built from, so \
                     `image_from` can only produce an image `ConfigImage::check` accepts under \
                     this build's port count, and `take_offer` answers `Offer::Staged` on every \
                     boot. Refusing an offered configuration rather than forwarding under one \
                     nobody checked is the fail-closed property itself; the decision behind it is \
                     floored in `pd_runtime`, but this domain's reaction to it is first-party \
                     logic sitting in a PD where neither the host floor nor the QEMU gate reaches \
                     it — a layering defect, since first-party logic belongs in a host-testable \
                     crate. Closing it means moving that reaction \
                     beside `take_offer`: one call taking this domain's `Sink`, emitting whatever \
                     the offer has to say, and returning whether the publisher must be signalled, \
                     which leaves the domain a call and a `notify` and puts the arm under the \
                     host coverage floor.",
                ),
            },
        ),
        (
            "config-pd",
            CoverageExclusion::OnlyObservableUnderSel4 {
                qemu_evidence: "`xtask test-system` boots the deployable disk and asserts the \
                                forwarding contract, which this domain is on the critical path \
                                of: the forwarder comes up fail-closed on generation 0 and \
                                forwards nothing, so a frame egressing at all proves this domain \
                                read the document compiled into it, committed it, wrote the \
                                handover image, published the offer, and released the commit once \
                                the consumer had acknowledged it — `init` and `notified` \
                                together, which is every statement it has. `xtask test-ab` \
                                re-asserts the same contract on the slot it selected in six of \
                                its eight scenarios.",
                residue: Some(
                    "The refusal branch — announcing `DomainState::Refused` and leaving the \
                     handover region untouched — is reached by no QEMU test: `xtask image` \
                     validates the one document every scenario boots, so only the accepting \
                     branch ever runs. Choosing to publish nothing rather than something weaker \
                     is the fail-closed property itself, and it is first-party decision logic \
                     sitting in a PD where neither the host floor nor the QEMU gate reaches it — \
                     a layering defect. Closing it means moving the \
                     commit-or-refuse decision into `crates/config` beside \
                     `commit_and_report`, returning whether anything was offered and leaving the \
                     domain with the publish call alone, which puts the branch under the host \
                     coverage floor.",
                ),
            },
        ),
        (
            "console",
            CoverageExclusion::OnlyObservableUnderSel4 {
                qemu_evidence: "`xtask test-system` boots the deployable disk and \
                                `config_transcript.rs` scans its serial output for the `LFW-` \
                                records the configuration handover produces. Those records now \
                                reach that output only through this domain: every other domain \
                                writes a typed record into a log ring and nothing else in the \
                                system touches the serial port, so a transcript containing a \
                                single `LFW-` line proves this domain proved its `<ioport>` \
                                capability through `Com1::claim` and drove it by invocation \
                                (`seL4_X86_IOPort_In8`/`Out8` — an `in`/`out` instruction would \
                                fault the domain instead), programmed the controller through \
                                `Uart::initialise`, took a reader on the peer's region, decoded \
                                a record and wrote the rendered bytes — `init` and the drain \
                                loop, which is every statement it has. `xtask test-ab` boots the \
                                slot it selected through the same path.",
                residue: Some(
                    "Both REFUSED branches — `Com1::claim` answering `Err` because the \
                     capability is not what `BASE_IOPORT_SLOT` and the `<ioport>` element say, \
                     and `Uart::initialise` answering `Err`, each followed by this domain's \
                     decision to park rather than retry — are reached by no QEMU test: every \
                     scenario boots the one correct system description against QEMU's q35, \
                     which always presents a conforming 16550A at 0x3F8, so only the accepting \
                     branch ever runs, and the six ways a controller can refuse are \
                     distinguished by `uart_16550` (whose own host tests cover all six) and \
                     then discarded here, a console with no controller having nowhere to report \
                     that it has no console. The capability refusal is the one of the two that \
                     does reach an operator, and only in the `debug` kernel configuration, \
                     through the `debug_println!` the release build compiles away. What to do \
                     about a refused device is first-party \
                     decision logic sitting in a PD, where neither the host floor nor the QEMU \
                     gate reaches it — a layering defect — and not a covered \
                     path. Closing it needs both halves: a reporting channel that does not \
                     depend on the console (the specified `GET /logs` ring, or \
                     the management-plane metrics endpoint), and the park-or-retry decision moved \
                     beside `Uart::initialise` so a host test can drive it. The same second \
                     channel is what would expose `ConsolePrinter`'s malformed, unknown, \
                     unrenderable and write_failed counters, which are floored in `crates/log` \
                     but unobservable from here, so no QEMU assertion today can tell a console \
                     that printed everything from one that silently refused half of it.",
                ),
            },
        ),
        (
            "clock",
            CoverageExclusion::OnlyObservableUnderSel4 {
                qemu_evidence: "`xtask test-system` boots the deployable disk and \
                                `clock_contract.rs` judges the `LFW-PD domain=clock` record its \
                                serial output carries: `state=ready`, a `tsc-hz=` inside the band \
                                `lfw_clock::calibrate` admits, and a `utc=` whose year is inside \
                                the band `lfw_rtc` admits. No boot can produce that record \
                                without this domain having mapped the HPET page and driven it \
                                through `Hpet::probe`, sized a window with `ticks_for`, measured \
                                the timestamp counter across `wait_ticks`, derived a frequency, \
                                proved its `<ioport>` capability through `Cmos::claim` and driven \
                                it by invocation (`seL4_X86_IOPort_In8`/`Out8` — an `in`/`out` \
                                instruction would fault the domain instead), read the part \
                                through `read_unix_seconds`, and anchored a `Calibration` it then \
                                converted back to an instant — `init` and `establish`, which is \
                                every statement it has that is not a refusal. `xtask test-ab` \
                                boots the slot it selected through the same path.",
                residue: Some(
                    "The whole refusal tree — every arm of `StartupError::refusal` and the four \
                     `?` sites that reach it — is reached by no QEMU test: every scenario boots \
                     the one correct system description against QEMU's q35, which presents a \
                     conforming HPET at 0xFED00000 and a conforming MC146818 at 0x70, so only \
                     the accepting path ever runs. The refusals the three library crates \
                     distinguish are covered by their own host tests, floored at 90% each; what \
                     is unreached is this domain's translation of them into console tokens, and \
                     `EpochOutOfRange`, which no reading `lfw_rtc` admits can produce. That is \
                     first-party logic sitting in a PD where neither the host floor nor the QEMU \
                     gate can measure it — a layering defect — and not a covered \
                     path. Closing it means the same move the other three PDs' residues \
                     describe: a refusal type owning its own console mapping, which cannot live \
                     in `lfw-clock` (the dependency would cycle through `lfw-log`) and so needs \
                     a crate of its own the day a second consumer of these three exists.",
                ),
            },
        ),
        (
            "management",
            CoverageExclusion::OnlyObservableUnderSel4 {
                qemu_evidence: "`xtask test-system` boots the deployable disk, injects frames of \
                                four different lengths into the management port, and \
                                `management_contract.rs` judges the `LFW-PD domain=management` \
                                record its serial output carries: the frame count must be exactly \
                                what was injected and the byte total exactly their summed lengths. \
                                No boot can produce that record without this domain having \
                                attached both pipeline regions, been woken on its channel, drained \
                                the ring `nic_driver2` published into, counted each descriptor and \
                                published a record of its own — `init` and `notified`, which is \
                                every statement it has. The same scenario asserts that no frame \
                                ever comes back on that port, which is the isolation half: this \
                                domain cannot transmit and the forwarder cannot reach the port. \
                                `xtask test-ab` boots the slot it selected through the same path.",
                residue: Some(
                    "One branch is reached by no QEMU test: the wakeup that moved no frame, where \
                     this domain decides to say nothing. Whether it happens at all is the \
                     scheduler's — the driver signals once per batch and a drain may take the \
                     whole batch, so a second signal for the same frames may or may not arrive — \
                     which is precisely a decision that cannot be asserted from outside. It is \
                     first-party logic sitting in a PD, where neither the host floor nor the QEMU \
                     gate reaches it, and that is a layering defect rather than a \
                     covered path. Closing it means moving the report-or-stay-silent decision \
                     beside `TerminalStage::poll`, answering the totals to report or nothing, \
                     which leaves the domain a call and an `announce` and puts the branch under \
                     the host coverage floor. What no arrangement of this domain closes is \
                     `TerminalCounters::malformed_descriptor` and `return_ring_full`: no scenario \
                     has a byzantine driver to raise either and no surface exposes them \
                     (the counts reach the console only as the frames/bytes \
                     pair), which needs the management-plane metrics endpoint.",
                ),
            },
        ),
        (
            "recorder",
            CoverageExclusion::OnlyObservableUnderSel4 {
                qemu_evidence: "`xtask test-system` boots the deployable disk with a second raw \
                                disk attached at 00:05.0, and afterwards reads the sector \
                                `lfw_blk::smoke::WITNESS_SECTOR` names out of that file and \
                                compares its 512 bytes against `lfw_blk::smoke::witness_pattern` \
                                — the appliance's own definition, so the two sides cannot drift. \
                                Nothing but this domain can put those bytes there: the harness \
                                zero-fills the image and writes a different, recognisable pattern \
                                into sector 0 before boot, so a witness sector that matches proves \
                                the whole chain ran against the real device — identify, place_bar, \
                                map, acknowledge, negotiate_features, configure_queue, go_live, and \
                                then a submitted chain, a rung doorbell and a polled completion \
                                through the mapped staging window at the physical address the \
                                system description patched in. The same run asserts the negative \
                                on the halt scenarios, where no slot boots and the sector must \
                                still be zero.",
                residue: Some(
                    "Every refusal path is reached by no QEMU test: each scenario attaches one \
                     conforming virtio-blk device at the pinned address, so `bring_up`'s \
                     `StartupError` arm, the `IoRegionUnusable` branch and the `state=refused` \
                     record are never taken. The decisions behind them are not in this domain — \
                     `lfw_blk::bringup`, `lfw_blk::io` and `lfw_blk::smoke` hold every one and \
                     are exercised exhaustively against hostile stand-in devices under the host \
                     floor — so what stays uncovered here is the adapter's own wiring: which \
                     region is attached to which symbol, and the conversion of a `lfw_blk::Refusal` \
                     into the console's. That conversion is the layering defect this entry records: \
                     it is first-party logic in a PD, and closing it means moving the \
                     `lfw_blk::Refusal`-to-`lfw_log::Refusal` conversion into `pd_runtime`, beside \
                     the `log_sample` that already lives there, which would put it under the host \
                     coverage floor.",
                ),
            },
        ),
        ("xtask", CoverageExclusion::BuildOrchestration),
    ];

    /// The recorded reason `package` sits outside the coverage floor, or
    /// `None` when no exclusion names it.
    fn coverage_exclusion(package: &str) -> Option<&'static CoverageExclusion> {
        COVERAGE_EXCLUSIONS
            .iter()
            .find(|(name, _)| *name == package)
            .map(|(_, reason)| reason)
    }

    /// The `(package name, directory)` of every member the root workspace
    /// manifest declares. The name is read from the member's own manifest
    /// rather than taken from its directory, because the package lists in this
    /// module are package names and the two are free to differ.
    fn workspace_members(root: &Path) -> Vec<(String, String)> {
        let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("the root manifest");
        let members = manifest
            .split_once("members = [")
            .expect("the root manifest declares workspace members")
            .1
            .split_once(']')
            .expect("the members list is terminated")
            .0;
        // Odd fields of a split on the quote character are the quoted strings.
        members
            .split('"')
            .skip(1)
            .step_by(2)
            .map(|directory| {
                let path = root.join(directory).join("Cargo.toml");
                let member = fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
                let name = member
                    .split_once("name = \"")
                    .unwrap_or_else(|| panic!("{directory} declares no package name"))
                    .1
                    .split_once('"')
                    .expect("the package name is terminated")
                    .0
                    .to_owned();
                (name, directory.to_owned())
            })
            .collect()
    }

    /// Guard against a manifest parse that silently produced almost nothing:
    /// every check below is a loop over the members, so an empty or truncated
    /// parse would pass them all while examining nothing.
    fn members_of_the_whole_workspace(root: &Path) -> Vec<(String, String)> {
        let members = workspace_members(root);
        assert!(
            members.len() >= 3,
            "the manifest parse produced {members:?}, which cannot be the whole workspace"
        );
        members
    }

    #[test]
    fn every_member_is_built_for_exactly_one_of_the_host_and_sel4() {
        // What this closes: the gate's build and lint coverage is exactly
        // these two lists, because `default-members` makes an unqualified
        // cargo invocation see almost nothing (see the module header). A
        // member in neither list is never compiled by any gate command while
        // the gate stays green.
        //
        // Membership of the lists — not the member's directory — is what
        // decides which side it belongs to, so the classification is total
        // over the workspace by construction: there is no directory to add a
        // crate under that would place it outside both questions.
        let root = crate::util::workspace_root().expect("the workspace root");
        for (name, directory) in members_of_the_whole_workspace(&root) {
            let package = name.as_str();
            match (
                HOST_TEST_PACKAGES.contains(&package),
                image::SYSTEM_PDS.contains(&package),
            ) {
                (true, false) | (false, true) => {}
                (false, false) => panic!(
                    "{directory} ({package}) is a workspace member that no build list names. \
                     HOST_TEST_PACKAGES does not, so no host command builds, tests or lints it; \
                     SYSTEM_PDS does not, so it is neither assembled into the image nor linted \
                     for the seL4 target. Add it to HOST_TEST_PACKAGES, or — if it is a \
                     protection domain, which does not build for the host — to SYSTEM_PDS."
                ),
                (true, true) => panic!(
                    "{directory} ({package}) is in both HOST_TEST_PACKAGES and SYSTEM_PDS. A \
                     protection domain does not build for the host, so the two are exclusive: \
                     remove it from whichever describes it wrongly."
                ),
            }
        }
    }

    #[test]
    fn every_member_is_coverage_floored_or_excluded_for_a_stated_reason() {
        // What this closes: an exclusion is admitted only for a reason on
        // the closed list, so every member is either inside the floor or named
        // by an exclusion carrying one.
        //
        // Both questions are answered from the lists and never from the
        // member's directory, because a directory-keyed partition cannot be
        // total: it matches the directories someone thought of and needs a
        // fallback for the rest, and whatever that fallback does not demand is
        // an exclusion no one states. A library crate outside `crates/` is
        // then linted and host-tested with no coverage floor and no recorded
        // reason — green, and exempt. Keyed off the lists there is no such
        // fallback, and no directory to add that reaches one.
        let root = crate::util::workspace_root().expect("the workspace root");
        for (name, directory) in members_of_the_whole_workspace(&root) {
            let package = name.as_str();
            match (
                LIBRARY_PACKAGES.contains(&package),
                coverage_exclusion(package),
            ) {
                (true, None) => {}
                (false, Some(reason)) => assert_reason_is_stated(package, reason),
                (false, None) => panic!(
                    "{directory} ({package}) is a workspace member no coverage decision names: \
                     absent from LIBRARY_PACKAGES, and absent from COVERAGE_EXCLUSIONS. It is \
                     therefore built and linted while no coverage floor defends it and no \
                     reason is recorded for that — exactly the unstated exclusion the coverage \
                     policy forbids. Either add it to LIBRARY_PACKAGES, or give it a \
                     COVERAGE_EXCLUSIONS entry naming its reason from the closed list."
                ),
                (true, Some(_)) => panic!(
                    "{directory} ({package}) is in LIBRARY_PACKAGES and is also excluded by \
                     COVERAGE_EXCLUSIONS. It cannot be both held to the floor and outside it: \
                     drop whichever of the two is wrong."
                ),
            }
        }
    }

    /// Hold a recorded exclusion to actually stating its reason, rather than
    /// merely selecting a variant. The only-under-seL4 reason is satisfied when
    /// the exclusion names the QEMU test covering the member instead, so an
    /// evidence string that names neither QEMU command is the same defect as
    /// no evidence at all.
    fn assert_reason_is_stated(package: &str, reason: &CoverageExclusion) {
        let CoverageExclusion::OnlyObservableUnderSel4 {
            qemu_evidence,
            residue,
        } = reason
        else {
            // Build orchestration is complete in the variant: nothing runs on a
            // deployed appliance, so there is no covering test to name.
            return;
        };
        assert!(
            QEMU_TESTS.iter().any(|test| qemu_evidence.contains(test)),
            "{package} is excluded as only observable under seL4, which holds only when the exclusion \
             names the QEMU test that covers it instead, but its evidence names none of \
             {QEMU_TESTS:?}: {qemu_evidence:?}"
        );
        if let Some(residue) = residue {
            assert!(
                residue.contains("layering defect"),
                "{package} admits adapter code its QEMU evidence does not reach. That is \
                 first-party logic in a PD that neither the host floor nor the QEMU gate can \
                 measure — a layering defect — and the admission must say so \
                 rather than read as an accepted exclusion: {residue:?}"
            );
        }
    }

    #[test]
    fn a_crate_with_benchmarks_is_benched_and_a_benched_crate_has_them() {
        // BENCH_PACKAGES was the one package list nothing validated: a crate
        // that grew a `benches/` and was left off it is never benched, and the
        // expected performance measurement silently does not happen. Both
        // directions are one comparison, because the directory on disk is the
        // whole truth about whether a crate has benchmarks.
        let root = crate::util::workspace_root().expect("the workspace root");
        for (name, directory) in members_of_the_whole_workspace(&root) {
            let package = name.as_str();
            match (
                root.join(&directory).join("benches").is_dir(),
                BENCH_PACKAGES.contains(&package),
            ) {
                (true, true) | (false, false) => {}
                (true, false) => panic!(
                    "{directory} has a benches/ directory but {package} is not in \
                     BENCH_PACKAGES, so `xtask bench` never runs those benchmarks and a \
                     regression in them is invisible. Add it, or delete the \
                     benchmarks nothing runs."
                ),
                (false, true) => panic!(
                    "{package} is in BENCH_PACKAGES but {directory}/benches does not exist, so \
                     `cargo bench -p {package}` measures nothing and the list overstates what \
                     the command covers."
                ),
            }
        }
    }

    #[test]
    fn no_package_list_names_a_non_member() {
        // The reverse direction, so a package removed from the workspace but
        // left in a list fails here rather than as a confusing cargo error in
        // the middle of the gate. Every list this module drives a command or a
        // decision from participates, COVERAGE_EXCLUSIONS included: an
        // exclusion for a package that no longer exists is a reason defending
        // nothing.
        let root = crate::util::workspace_root().expect("the workspace root");
        let members = members_of_the_whole_workspace(&root);
        let declared: Vec<&str> = members.iter().map(|(name, _)| name.as_str()).collect();
        for package in HOST_TEST_PACKAGES
            .iter()
            .chain(LIBRARY_PACKAGES)
            .chain(image::SYSTEM_PDS)
            .chain(BENCH_PACKAGES)
            .chain(COVERAGE_EXCLUSIONS.iter().map(|(name, _)| name))
        {
            assert!(
                declared.contains(package),
                "{package} is listed in this module but is not a workspace member"
            );
        }
    }

    #[test]
    fn the_default_members_trap_the_lint_lists_exist_for_is_still_real() {
        // The module header and the lint step both justify their explicit `-p`
        // lists by this one line in the root manifest. If it ever goes away the
        // justification is stale, and a stale justification is how the next
        // reader concludes the lists are redundant and deletes them.
        let root = crate::util::workspace_root().expect("the workspace root");
        let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("the root manifest");
        assert!(
            manifest.contains("default-members = [\"tools/xtask\"]"),
            "the root manifest no longer narrows default-members to xtask; the explanation on \
             the lint steps in this module now describes something that is not true"
        );
    }

    #[test]
    fn a_diagnostic_keeps_the_tools_last_words_and_survives_empty_output() {
        // A tool's actionable line is at the END of its output, so the tail is
        // what a probe failure must carry.
        let stderr = b"configuring\n\nlinking\nASan: failed to map shadow\naborted\n";
        assert_eq!(tail(stderr, 2), "ASan: failed to map shadow | aborted");

        // Fewer lines than asked for, and none at all, must not panic: a tool
        // that dies before writing anything is exactly the case being reported.
        assert_eq!(tail(b"only one\n", 5), "only one");
        assert_eq!(tail(b"", 5), "");
        assert_eq!(tail(b"\n  \n\n", 3), "");
    }

    #[test]
    fn every_fuzz_target_has_its_own_scratch_corpus_outside_the_tracked_tree() {
        // libFuzzer writes into the first corpus dir it is given, so the
        // scratch dirs must be distinct AND must not be under fuzz/corpus.
        let first = scratch_corpus(FUZZ_TARGETS[0]).unwrap();
        let second = scratch_corpus(FUZZ_TARGETS[1]).unwrap();
        assert_ne!(first, second);
        for scratch in [&first, &second] {
            assert!(scratch.is_dir());
            assert!(
                !scratch.to_string_lossy().contains("fuzz/corpus"),
                "the tracked corpus must never be the writable one: {}",
                scratch.display()
            );
        }
    }
}
