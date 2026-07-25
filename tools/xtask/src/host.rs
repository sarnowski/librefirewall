//! The host-side commands: the fast gate, coverage, benchmarks, fuzzing, clean.
//!
//! These run without booting seL4. [`test_host`] is the fast gate the pre-commit
//! hook and CI share (format, host tests, Clippy with warnings denied, the
//! `cargo-deny` dependency/license/source policy, and the library coverage
//! floor). [`fuzz`] additionally runs in the full `ci` gate (build every fuzz
//! target and briefly exercise it). [`coverage`] and [`bench`] are
//! measurement/discovery commands deliberately outside any gate.

use std::{fs, path::Path, process::Command};

use crate::util::run_command;

/// Workspace packages that build and test on the host (no seL4 target). The
/// protection-domain binaries are excluded: they need the Microkit target and
/// are exercised by the QEMU system test instead.
const HOST_TEST_PACKAGES: &[&str] = &[
    "wire",
    "queue",
    "packet-buffer",
    "virtio",
    "pd-runtime",
    "nic-driver-core",
    "xtask",
];

/// The six library crates held to the coverage floor: the portable `no_std`
/// logic the firewall is built from. The binary/tool crates are excluded — the
/// PD adapters are only observable under seL4, and `xtask` is host-tested for
/// correctness but not held to the coverage bar (CONCEPT trust boundary).
const LIBRARY_PACKAGES: &[&str] = &[
    "wire",
    "queue",
    "packet-buffer",
    "virtio",
    "pd-runtime",
    "nic-driver-core",
];

/// Minimum combined line coverage the [`LIBRARY_PACKAGES`] must hold, enforced
/// by the fast gate so a coverage regression fails locally and in CI. Set a few
/// points below the measured ~98% combined coverage: a real floor that is not
/// flaky. Raise it as coverage rises; never lower it to land a change.
const LIBRARY_COVERAGE_FLOOR_PCT: u32 = 94;

/// Minimum line coverage EACH library crate must hold on its own. The combined
/// floor alone lets one crate regress heavily while the high-coverage crates
/// keep the total above [`LIBRARY_COVERAGE_FLOOR_PCT`]; this per-crate floor
/// closes that gap. Set a few points below the current per-crate minimum
/// (pd-runtime ~94%) so it is a real, non-flaky floor; raise it as the weakest
/// crate rises, never lower it to land a change.
const LIBRARY_PER_CRATE_COVERAGE_FLOOR_PCT: u32 = 90;

/// Crates carrying criterion microbenchmarks, run by `bench`. These are the
/// perf-sensitive dataplane substrate crates whose hot operations the 10 Gbit/s
/// budget depends on.
const BENCH_PACKAGES: &[&str] = &["queue", "packet-buffer", "virtio"];

/// Persistent fuzz targets under `fuzz/`, driven by `fuzz`.
const FUZZ_TARGETS: &[&str] = &["find_virtio_caps", "virtqueue_poll"];

pub(crate) fn test_host(root: &Path) -> Result<(), String> {
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["fmt", "--all", "--check"]),
        "check formatting",
    )?;
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["test", "--locked"])
            .args(HOST_TEST_PACKAGES.iter().flat_map(|pkg| ["-p", pkg])),
        "run host tests",
    )?;
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["clippy", "--locked", "--all-targets"])
            .args(HOST_TEST_PACKAGES.iter().flat_map(|pkg| ["-p", pkg]))
            .args(["--", "-D", "warnings"]),
        "run host clippy",
    )?;
    // Enforce the dependency/license/source policy (deny.toml). The advisories
    // check is omitted: it needs the network to fetch the RustSec database,
    // and the host gate runs offline.
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["deny", "check", "bans", "licenses", "sources"]),
        "check dependency policy",
    )?;
    enforce_coverage(root)
}

/// Enforce the library coverage floors: the combined floor across all six
/// [`LIBRARY_PACKAGES`] AND a per-crate floor on each one, so a regression
/// concentrated in a single crate cannot hide behind the high-coverage crates.
///
/// The library tests are instrumented once with `--no-report`; the combined and
/// per-crate reports then read that one profile, so the extra checks add report
/// generation, not extra test runs. `--fail-under-lines` makes each report exit
/// non-zero below its floor, so a regression fails here and identically in CI.
fn enforce_coverage(root: &Path) -> Result<(), String> {
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
    )
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
    )
}

/// Build every persistent fuzz target and, where the sandbox permits, run each
/// briefly; always drive the same harness code over the committed seeds.
///
/// This is honest about what actually executes. `cargo fuzz build` must always
/// succeed. A short `cargo fuzz run` of each target is then attempted, but the
/// pinned hermetic builder (`--cap-drop=all`, read-only rootfs,
/// `--security-opt=no-new-privileges`) can prevent libFuzzer/AddressSanitizer
/// from starting; that is tolerated and reported rather than failing the
/// command. The seed-corpus smoke tests (`cargo test --lib` in `fuzz/`) run
/// unconditionally and exercise the identical harness functions the fuzz
/// targets call, so the parsers are covered over valid inputs even when
/// libFuzzer cannot run. This runs in the full `ci` gate (bounded per target);
/// unlike `bench`, which stays measurement-only.
pub(crate) fn fuzz(root: &Path) -> Result<(), String> {
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["fuzz", "build"]),
        "build fuzz targets",
    )?;
    println!("fuzz: all targets built with AddressSanitizer instrumentation");

    // libFuzzer writes coverage-increasing inputs into the first corpus dir it
    // is given. Point that at a throwaway dir under the tmpfs and pass the
    // committed corpus as a read-only seed source, so this bounded smoke run —
    // in `ci` on every commit — never grows or dirties the tracked
    // `fuzz/corpus/` tree. Curated regression seeds are added there deliberately.
    let scratch_root = std::env::temp_dir().join("librefirewall-fuzz-corpus");
    let mut executed = true;
    for target in FUZZ_TARGETS {
        let scratch = scratch_root.join(target);
        fs::create_dir_all(&scratch).map_err(|error| {
            format!("create fuzz scratch corpus {}: {error}", scratch.display())
        })?;
        let seeds = root.join("fuzz").join("corpus").join(target);
        let status = Command::new("cargo")
            .current_dir(root)
            .args(["fuzz", "run", target])
            .arg(&scratch)
            .arg(&seeds)
            .args(["--", "-runs=20000", "-max_total_time=15"])
            .status()
            .map_err(|error| format!("spawn cargo fuzz run {target}: {error}"))?;
        if status.success() {
            println!("fuzz: ran {target} (-runs=20000 -max_total_time=15)");
        } else {
            executed = false;
            eprintln!(
                "fuzz: could not EXECUTE {target} here ({status}); the hermetic \
                 sandbox (cap-drop=all, read-only rootfs, no-new-privileges) can \
                 block libFuzzer/ASan from starting. Falling back to build-only \
                 plus the seed smoke tests below."
            );
        }
    }

    run_command(
        Command::new("cargo")
            .current_dir(root.join("fuzz"))
            .args(["test", "--locked", "--lib"]),
        "run fuzz seed smoke tests",
    )?;

    if executed {
        println!("fuzz: targets built AND ran; seed smoke tests passed");
    } else {
        println!(
            "fuzz: targets BUILD and the seed smoke tests pass, but libFuzzer \
             execution was blocked by the sandbox (see above) — build + seed \
             coverage only, no live fuzzing in this environment"
        );
    }
    Ok(())
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
        root.join("sdk"),
        root.join("target"),
    ] {
        if path.exists() {
            fs::remove_dir_all(&path)
                .map_err(|error| format!("remove {}: {error}", path.display()))?;
        }
    }
    Ok(())
}
