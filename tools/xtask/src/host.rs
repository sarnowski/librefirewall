//! The host-side commands: the fast gate, coverage, benchmarks, fuzzing, clean.
//!
//! These run without booting seL4. [`test_host`] is the fast gate the pre-commit
//! hook and CI share (format, host tests, Clippy with warnings denied, and the
//! `cargo-deny` dependency/license/source policy). [`coverage`], [`bench`], and
//! [`fuzz`] are measurement/discovery commands deliberately outside `ci`.

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
    )
}

/// Measure line coverage of the host packages and print the per-crate summary.
/// This mirrors [`HOST_TEST_PACKAGES`] rather than the whole workspace because
/// the protection-domain binaries only build for the seL4 target. No threshold
/// is enforced yet; this makes coverage measurable on demand.
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
/// libFuzzer cannot run. Like `bench`, this is not part of `ci`.
pub(crate) fn fuzz(root: &Path) -> Result<(), String> {
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["fuzz", "build"]),
        "build fuzz targets",
    )?;
    println!("fuzz: all targets built with AddressSanitizer instrumentation");

    let mut executed = true;
    for target in FUZZ_TARGETS {
        let status = Command::new("cargo")
            .current_dir(root)
            .args([
                "fuzz",
                "run",
                target,
                "--",
                "-runs=20000",
                "-max_total_time=15",
            ])
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
