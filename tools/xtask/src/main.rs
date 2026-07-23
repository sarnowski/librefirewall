use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const TARGET: &str = "x86_64-sel4-minimal";
const BOARD: &str = "x86_64_generic";
const DEBUG_CONFIG: &str = "debug";
const RELEASE_CONFIG: &str = "release";
const MICROKIT_SDK: &str = "/opt/microkit";
const RUST_SEL4: &str = "/opt/rust-sel4";
const RUST_SEL4_VERSION: &str = "5.0.0";
const MICROKIT_VERSION: &str = "2.3.0";
const DIST_KERNEL: &str = "librefirewall-kernel.elf";
const DIST_SYSTEM: &str = "librefirewall-system.img";
const DIST_REPORT: &str = "librefirewall-microkit-report.txt";
const DIST_MANIFEST: &str = "librefirewall-manifest.json";
const DIST_SBOM: &str = "librefirewall-sbom.spdx.json";
const DIST_CHECKSUMS: &str = "librefirewall-checksums.sha256";
const PASS_MARKER: &str =
    "LIBREFIREWALL_BOOTSTRAP_PASS:initiator-responder-notification-round-trip";
const QEMU_TIMEOUT: Duration = Duration::from_secs(20);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let command = env::args().nth(1).ok_or_else(usage)?;
    if env::args().nth(2).is_some() {
        return Err(usage());
    }

    let root = workspace_root()?;
    match command.as_str() {
        "image" => image(&root, DEBUG_CONFIG),
        "run" => {
            image(&root, DEBUG_CONFIG)?;
            run_system(&root)
        }
        "test" => test_host(&root),
        "test-host" => test_host(&root),
        "test-system" => {
            image(&root, DEBUG_CONFIG)?;
            test_system(&root)
        }
        "ci" => {
            test_host(&root)?;
            image(&root, DEBUG_CONFIG)?;
            test_system(&root)
        }
        "release" => {
            test_host(&root)?;
            image(&root, DEBUG_CONFIG)?;
            test_system(&root)?;
            image(&root, RELEASE_CONFIG)
        }
        "clean" => clean(&root),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: cargo xtask <image|run|test|test-host|test-system|ci|release|clean>".to_owned()
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot determine workspace root".to_owned())
}

fn image(root: &Path, config: &str) -> Result<(), String> {
    verify_inputs(config)?;

    let build = root.join("build/bootstrap").join(config);
    let dist = root.join("dist");
    recreate_dir(&build)?;
    recreate_dir(&dist)?;

    let board_dir = Path::new(MICROKIT_SDK)
        .join("board")
        .join(BOARD)
        .join(config);
    let target_root = root.join("target").join(config);
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .env("SEL4_INCLUDE_DIRS", board_dir.join("include"))
            .env("CARGO_TARGET_DIR", &target_root)
            .args([
                "build",
                "--locked",
                "--release",
                "-Z",
                "build-std=core",
                "--target",
                TARGET,
                "-p",
                "bootstrap-initiator",
                "-p",
                "bootstrap-responder",
            ]),
        "build protection domains",
    )?;

    let target_dir = target_root.join(TARGET).join("release");
    for pd in ["bootstrap-initiator.elf", "bootstrap-responder.elf"] {
        copy_file(&target_dir.join(pd), &build.join(pd))?;
    }

    run_command(
        Command::new(Path::new(MICROKIT_SDK).join("bin/microkit"))
            .current_dir(root)
            .arg(root.join("systems/qemu-x86_64/bootstrap.system"))
            .arg("--search-path")
            .arg(&build)
            .args(["--board", BOARD, "--config", config, "-o"])
            .arg(build.join("loader.img"))
            .arg("-r")
            .arg(build.join("report.txt")),
        "assemble Microkit image",
    )?;

    copy_file(&build.join("sel4_32.elf"), &dist.join(DIST_KERNEL))?;
    copy_file(&build.join("loader.img"), &dist.join(DIST_SYSTEM))?;
    copy_file(&build.join("report.txt"), &dist.join(DIST_REPORT))?;
    write_manifest(&dist, config)?;
    write_sbom(root, &dist)?;
    write_checksums(&dist)?;
    println!("packaged boot artifacts in {}", dist.display());
    Ok(())
}

fn verify_inputs(config: &str) -> Result<(), String> {
    verify_version(
        Path::new(RUST_SEL4).join("VERSION"),
        RUST_SEL4_VERSION,
        "rust-sel4",
    )?;
    verify_version(
        Path::new(MICROKIT_SDK).join("VERSION"),
        MICROKIT_VERSION,
        "Microkit SDK",
    )?;
    require_file(&Path::new(MICROKIT_SDK).join("bin/microkit"))?;
    require_file(
        &Path::new(MICROKIT_SDK)
            .join("board")
            .join(BOARD)
            .join(config)
            .join("elf/sel4_32.elf"),
    )
}

fn verify_version(path: PathBuf, expected: &str, name: &str) -> Result<(), String> {
    let actual = fs::read_to_string(&path)
        .map_err(|error| format!("required {name} input {}: {error}", path.display()))?;
    if actual.trim() != expected {
        return Err(format!(
            "{name} at {} has version {:?}, expected {expected:?}",
            path.display(),
            actual.trim()
        ));
    }
    Ok(())
}

fn test_host(root: &Path) -> Result<(), String> {
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["fmt", "--all", "--check"]),
        "check formatting",
    )?;
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["test", "--locked", "-p", "xtask"]),
        "run host tests",
    )?;
    run_command(
        Command::new("cargo")
            .current_dir(root)
            .args(["clippy", "--locked", "-p", "xtask", "--", "-D", "warnings"]),
        "run host clippy",
    )
}

fn test_system(root: &Path) -> Result<(), String> {
    let dist = root.join("dist");
    require_file(&dist.join(DIST_KERNEL))?;
    require_file(&dist.join(DIST_SYSTEM))?;

    let mut child = Command::new("qemu-system-x86_64")
        .current_dir(root)
        .args([
            "-accel",
            "tcg",
            "-cpu",
            "qemu64,+fsgsbase,+pdpe1gb,+xsaveopt,+xsave",
            "-m",
            "1G",
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            "stdio",
            "-no-reboot",
            "-no-shutdown",
            "-kernel",
        ])
        .arg(dist.join(DIST_KERNEL))
        .arg("-initrd")
        .arg(dist.join(DIST_SYSTEM))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start QEMU: {error}"))?;

    let (sender, receiver) = mpsc::channel();
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate(&mut child, "stdout capture failure")?;
            return Err("capture QEMU stdout".to_owned());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            terminate(&mut child, "stderr capture failure")?;
            return Err("capture QEMU stderr".to_owned());
        }
    };
    let stdout_reader = spawn_reader(stdout, sender.clone());
    let stderr_reader = spawn_reader(stderr, sender);

    let start = Instant::now();
    let mut output = Vec::new();
    let mut observed_pass = false;
    let result = loop {
        while let Ok(chunk) = receiver.try_recv() {
            output.extend_from_slice(&chunk);
        }

        if count_occurrences(&output, PASS_MARKER.as_bytes()) > 0 {
            observed_pass = true;
            break terminate(&mut child, "pass marker observed");
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break Err(format!("QEMU exited before the pass marker with {status}"));
            }
            Ok(None) => {}
            Err(error) => {
                break terminate(&mut child, "poll failure")
                    .and_then(|()| Err(format!("poll QEMU: {error}")));
            }
        }
        if start.elapsed() >= QEMU_TIMEOUT {
            break terminate(&mut child, "hard timeout").and_then(|()| {
                Err(format!(
                    "QEMU timed out after {} seconds",
                    QEMU_TIMEOUT.as_secs()
                ))
            });
        }
        thread::sleep(Duration::from_millis(25));
    };

    stdout_reader
        .join()
        .map_err(|_| "QEMU stdout reader panicked".to_owned())?
        .map_err(|error| format!("read QEMU stdout: {error}"))?;
    stderr_reader
        .join()
        .map_err(|_| "QEMU stderr reader panicked".to_owned())?
        .map_err(|error| format!("read QEMU stderr: {error}"))?;
    while let Ok(chunk) = receiver.try_recv() {
        output.extend_from_slice(&chunk);
    }

    let log = root.join("build/bootstrap/qemu.log");
    if let Some(parent) = log.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    fs::write(&log, &output).map_err(|error| format!("write {}: {error}", log.display()))?;
    result?;

    let pass_count = count_occurrences(&output, PASS_MARKER.as_bytes());
    if !observed_pass || pass_count != 1 {
        return Err(format!(
            "expected exactly one pass marker, observed {pass_count}; output is in {}",
            log.display()
        ));
    }
    println!("system test passed; QEMU output is in {}", log.display());
    Ok(())
}

fn run_system(root: &Path) -> Result<(), String> {
    let dist = root.join("dist");
    require_file(&dist.join(DIST_KERNEL))?;
    require_file(&dist.join(DIST_SYSTEM))?;

    run_command(
        Command::new("qemu-system-x86_64")
            .current_dir(root)
            .args([
                "-accel",
                "tcg",
                "-cpu",
                "qemu64,+fsgsbase,+pdpe1gb,+xsaveopt,+xsave",
                "-m",
                "1G",
                "-display",
                "none",
                "-serial",
                "mon:stdio",
                "-kernel",
            ])
            .arg(dist.join(DIST_KERNEL))
            .arg("-initrd")
            .arg(dist.join(DIST_SYSTEM)),
        "run QEMU",
    )
}

fn spawn_reader<R>(
    mut reader: R,
    sender: mpsc::Sender<Vec<u8>>,
) -> thread::JoinHandle<io::Result<()>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                return Ok(());
            }
            if sender.send(buffer[..count].to_vec()).is_err() {
                return Ok(());
            }
        }
    })
}

fn terminate(child: &mut Child, reason: &str) -> Result<(), String> {
    match child.kill() {
        Ok(()) => {}
        Err(_error) if child.try_wait().ok().flatten().is_some() => {}
        Err(error) => return Err(format!("kill QEMU after {reason}: {error}")),
    }
    child
        .wait()
        .map_err(|error| format!("reap QEMU after {reason}: {error}"))?;
    Ok(())
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn write_manifest(dist: &Path, config: &str) -> Result<(), String> {
    let manifest = format!(
        concat!(
            "{{\n",
            "  \"format\": 1,\n",
            "  \"target\": \"{}\",\n",
            "  \"microkit\": {{\"version\": \"{}\", \"board\": \"{}\", \"config\": \"{}\"}},\n",
            "  \"rust_sel4\": {{\"version\": \"{}\"}},\n",
            "  \"artifacts\": [\"{}\", \"{}\", \"{}\", \"{}\"]\n",
            "}}\n"
        ),
        TARGET,
        MICROKIT_VERSION,
        BOARD,
        config,
        RUST_SEL4_VERSION,
        DIST_KERNEL,
        DIST_SYSTEM,
        DIST_REPORT,
        DIST_SBOM
    );
    fs::write(dist.join(DIST_MANIFEST), manifest)
        .map_err(|error| format!("write manifest: {error}"))
}

fn write_sbom(root: &Path, dist: &Path) -> Result<(), String> {
    let sbom = dist.join(DIST_SBOM);
    run_command(
        Command::new("syft")
            .current_dir(root)
            .args([
                "scan",
                "dir:.",
                "--exclude",
                "./build",
                "--exclude",
                "./dist",
                "--exclude",
                "./target",
                "--source-name",
                "librefirewall",
                "--source-version",
                env!("CARGO_PKG_VERSION"),
                "--output",
            ])
            .arg(format!("spdx-json={}", sbom.display())),
        "generate SPDX SBOM",
    )?;

    run_command(
        Command::new("python3")
            .arg("-c")
            .arg(concat!(
                "import json,sys; ",
                "document=json.load(open(sys.argv[1], encoding='utf-8')); ",
                "assert document['spdxVersion']=='SPDX-2.3'; ",
                "assert document['packages']"
            ))
            .arg(&sbom),
        "validate SPDX 2.3 SBOM",
    )
}

fn write_checksums(dist: &Path) -> Result<(), String> {
    let artifacts = [
        DIST_KERNEL,
        DIST_SYSTEM,
        DIST_MANIFEST,
        DIST_REPORT,
        DIST_SBOM,
    ];
    let output = Command::new("sha256sum")
        .current_dir(dist)
        .args(artifacts)
        .output()
        .map_err(|error| format!("run sha256sum: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "sha256sum failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    fs::write(dist.join(DIST_CHECKSUMS), output.stdout)
        .map_err(|error| format!("write {DIST_CHECKSUMS}: {error}"))
}

fn clean(root: &Path) -> Result<(), String> {
    for path in [
        root.join("build/bootstrap"),
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

fn recreate_dir(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_dir_all(path).map_err(|error| format!("remove {}: {error}", path.display()))?;
    }
    fs::create_dir_all(path).map_err(|error| format!("create {}: {error}", path.display()))
}

fn copy_file(source: &Path, destination: &Path) -> Result<(), String> {
    require_file(source)?;
    fs::copy(source, destination).map_err(|error| {
        format!(
            "copy {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn require_file(path: &Path) -> Result<(), String> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("required file is missing: {}", path.display()))
    }
}

fn run_command(command: &mut Command, description: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|error| format!("{description}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{description} failed with {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_count_requires_an_exact_unique_marker() {
        let output = format!("prefix{PASS_MARKER}middle{PASS_MARKER}suffix");
        assert_eq!(
            count_occurrences(output.as_bytes(), PASS_MARKER.as_bytes()),
            2
        );
        assert_eq!(
            count_occurrences(PASS_MARKER.as_bytes(), PASS_MARKER.as_bytes()),
            1
        );
        assert_eq!(count_occurrences(b"unrelated", PASS_MARKER.as_bytes()), 0);
    }
}
