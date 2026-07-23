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
const DIST_DISK: &str = "librefirewall-qemu-x86_64.img";
const PASS_MARKER: &str = "LIBREFIREWALL_DATAPLANE_PASS:spsc-zero-copy-descriptor-round-trip";

/// Workspace packages that build and test on the host (no seL4 target). The
/// protection-domain binaries are excluded: they need the Microkit target and
/// are exercised by the QEMU system test instead.
const HOST_TEST_PACKAGES: &[&str] = &["wire", "queue", "packet-buffer", "pd-runtime", "xtask"];
const QEMU_TIMEOUT: Duration = Duration::from_secs(40);

const GRUB_MODULES_DIR: &str = "/opt/grub/lib/grub/x86_64-efi";
const GRUB_VERSION: &str = "2.14";
const DEV_KEY_UID: &str = "librefirewall development signing <dev@librefirewall.invalid>";

// UEFI firmware for the OVMF boot path; the first existing candidate is used.
const OVMF_CODE_CANDIDATES: &[&str] = &[
    "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
];
const OVMF_VARS_CANDIDATES: &[&str] = &[
    "/usr/share/OVMF/OVMF_VARS_4M.fd",
    "/usr/share/OVMF/OVMF_VARS.fd",
];

const SECTORS_PER_MIB: u64 = 2048;
const DISK_SIZE_MIB: u64 = 128;

/// The GPT layout of the deployable disk. `SLOT_A` and `SLOT_B` are the two
/// software slots; `STATE` carries the mutable boot-selection env; `DATA` is
/// reserved for configuration and secrets and is left unformatted for now.
struct Partition {
    number: usize,
    label: &'static str,
    gpt_type: &'static str,
    start_mib: u64,
    size_mib: u64,
}

const PARTITIONS: &[Partition] = &[
    Partition {
        number: 1,
        label: "ESP",
        gpt_type: "ef00",
        start_mib: 1,
        size_mib: 48,
    },
    Partition {
        number: 2,
        label: "STATE",
        gpt_type: "8300",
        start_mib: 49,
        size_mib: 8,
    },
    Partition {
        number: 3,
        label: "SLOTA",
        gpt_type: "8300",
        start_mib: 57,
        size_mib: 16,
    },
    Partition {
        number: 4,
        label: "SLOTB",
        gpt_type: "8300",
        start_mib: 73,
        size_mib: 16,
    },
    Partition {
        number: 5,
        label: "DATA",
        gpt_type: "8300",
        start_mib: 89,
        size_mib: 16,
    },
];

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
        "test-ab" => {
            image(&root, DEBUG_CONFIG)?;
            test_ab(&root)
        }
        "ci" => {
            test_host(&root)?;
            image(&root, DEBUG_CONFIG)?;
            test_system(&root)?;
            test_ab(&root)
        }
        "release" => {
            test_host(&root)?;
            image(&root, DEBUG_CONFIG)?;
            test_system(&root)?;
            test_ab(&root)?;
            image(&root, RELEASE_CONFIG)
        }
        "clean" => clean(&root),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: cargo xtask <image|run|test|test-host|test-system|test-ab|ci|release|clean>".to_owned()
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
                // The dataplane copies bytes into pool buffers, which lowers to
                // the mem* intrinsics; have compiler-builtins provide them since
                // there is no libc under seL4.
                "-Z",
                "build-std-features=compiler-builtins-mem",
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

    // The loose kernel/system pair stays in dist as the update input and as
    // debugging evidence; the disk below is the deployable artifact. The 32-bit
    // kernel ELF is the Multiboot2 image GRUB boots (its entry is a 32-bit
    // trampoline; the 64-bit sel4.elf shares the same entry but the 32-bit image
    // is what both QEMU and GRUB load).
    copy_file(&build.join("sel4_32.elf"), &dist.join(DIST_KERNEL))?;
    copy_file(&build.join("loader.img"), &dist.join(DIST_SYSTEM))?;
    copy_file(&build.join("report.txt"), &dist.join(DIST_REPORT))?;

    let fingerprint = assemble_disk(root, &build, &dist)?;

    write_manifest(&dist, config, &fingerprint)?;
    write_sbom(root, &dist)?;
    write_checksums(&dist)?;
    println!("packaged boot artifacts in {}", dist.display());
    Ok(())
}

/// Build the signed GPT A/B disk from the kernel and system image already in
/// `build`, returning the development signing key's fingerprint for the
/// manifest. Both slots are seeded with the same signed release and A is
/// marked confirmed, so the base image boots A while B stands ready as a
/// fallback and update target.
fn assemble_disk(root: &Path, build: &Path, dist: &Path) -> Result<String, String> {
    let kernel = build.join("sel4_32.elf");
    let system = build.join("loader.img");

    let fingerprint = ensure_dev_key(root)?;
    let pubkey = root.join("build/dev-keys/librefirewall-dev-pub.gpg");
    sign_file(root, &kernel)?;
    sign_file(root, &system)?;

    let efi = build.join("BOOTX64.EFI");
    build_grub_efi(root, &pubkey, &efi)?;

    let parts = build.join("parts");
    recreate_dir(&parts)?;

    let esp = parts.join("esp.img");
    make_fat(&esp, part("ESP").size_mib, Some(32), "ESP")?;
    mmd(&esp, "::/EFI")?;
    mmd(&esp, "::/EFI/BOOT")?;
    mcopy(&esp, &efi, "::/EFI/BOOT/BOOTX64.EFI")?;

    let state = parts.join("state.img");
    make_fat(&state, part("STATE").size_mib, None, "STATE")?;
    let grubenv = build.join("grubenv");
    seed_grubenv(root, &grubenv)?;
    mcopy(&state, &grubenv, "::/grubenv")?;

    let kernel_sig = build.join("sel4_32.elf.sig");
    let system_sig = build.join("loader.img.sig");
    let slot_files = [
        (kernel.as_path(), "::/librefirewall-kernel.elf"),
        (kernel_sig.as_path(), "::/librefirewall-kernel.elf.sig"),
        (system.as_path(), "::/librefirewall-system.img"),
        (system_sig.as_path(), "::/librefirewall-system.img.sig"),
    ];
    for label in ["SLOTA", "SLOTB"] {
        let image = parts.join(format!("{}.img", label.to_lowercase()));
        make_fat(&image, part(label).size_mib, Some(16), label)?;
        for (source, destination) in &slot_files {
            mcopy(&image, source, destination)?;
        }
    }

    let data = parts.join("data.img");
    make_fat(&data, part("DATA").size_mib, None, "DATA")?;

    let disk = dist.join(DIST_DISK);
    write_disk(&disk, &parts)?;
    Ok(fingerprint)
}

fn part(label: &str) -> &'static Partition {
    PARTITIONS
        .iter()
        .find(|partition| partition.label == label)
        .expect("known partition label")
}

/// Create (once per checkout) the local development signing key and return its
/// fingerprint. The private key never leaves `build/dev-keys` and is removed by
/// `clean`; only detached signatures and the exported public key are consumed
/// by the build. This is a development trust anchor, not a release key.
fn ensure_dev_key(root: &Path) -> Result<String, String> {
    let home = root.join("build/dev-keys");
    let pubkey = home.join("librefirewall-dev-pub.gpg");
    if !pubkey.is_file() {
        fs::create_dir_all(&home).map_err(|error| format!("create {}: {error}", home.display()))?;
        set_permissions_0700(&home)?;
        run_command(
            gpg(&home)
                .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
                .args([
                    "--quick-generate-key",
                    DEV_KEY_UID,
                    "rsa3072",
                    "sign",
                    "never",
                ]),
            "generate development signing key",
        )?;
        let export = Command::new("gpg")
            .env("GNUPGHOME", &home)
            .args(["--batch", "--yes", "--output"])
            .arg(&pubkey)
            .args(["--export", DEV_KEY_UID])
            .status()
            .map_err(|error| format!("export public key: {error}"))?;
        if !export.success() {
            return Err(format!("export public key failed with {export}"));
        }
    }
    read_dev_key_fingerprint(&home)
}

fn read_dev_key_fingerprint(home: &Path) -> Result<String, String> {
    let output = gpg(home)
        .args(["--batch", "--with-colons", "--fingerprint", DEV_KEY_UID])
        .output()
        .map_err(|error| format!("read key fingerprint: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "read key fingerprint failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find_map(|line| {
            line.strip_prefix("fpr:")
                .map(|rest| rest.trim_matches(':').to_owned())
        })
        .ok_or_else(|| "no fingerprint in gpg output".to_owned())
}

fn sign_file(root: &Path, file: &Path) -> Result<(), String> {
    let home = root.join("build/dev-keys");
    let signature = PathBuf::from(format!("{}.sig", file.display()));
    run_command(
        gpg(&home)
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
            ])
            .arg("--detach-sign")
            .arg("--output")
            .arg(&signature)
            .arg(file),
        "sign payload",
    )
}

fn build_grub_efi(root: &Path, pubkey: &Path, output: &Path) -> Result<(), String> {
    let modules = fs::read_to_string(root.join("third-party/grub/modules.txt"))
        .map_err(|error| format!("read grub modules list: {error}"))?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let config = root.join("third-party/grub/grub.cfg");
    run_command(
        Command::new("grub-mkstandalone")
            .current_dir(root)
            .arg(format!("--directory={GRUB_MODULES_DIR}"))
            .arg("--format=x86_64-efi")
            .arg(format!("--modules={modules}"))
            .arg("--pubkey")
            .arg(pubkey)
            .arg("--output")
            .arg(output)
            .arg(format!("boot/grub/grub.cfg={}", config.display())),
        "build standalone grub EFI image",
    )
}

fn seed_grubenv(root: &Path, grubenv: &Path) -> Result<(), String> {
    run_command(
        Command::new("grub-editenv").arg(grubenv).arg("create"),
        "create grubenv",
    )?;
    run_command(
        Command::new("grub-editenv")
            .arg(grubenv)
            .arg("set")
            .arg("ORDER=A B")
            .arg("A_OK=1")
            .arg("A_TRY=0")
            .arg("B_OK=0")
            .arg("B_TRY=0"),
        "seed grubenv",
    )?;
    let _ = root;
    Ok(())
}

fn make_fat(image: &Path, size_mib: u64, fat: Option<u32>, label: &str) -> Result<(), String> {
    let blocks = size_mib * 1024;
    let mut command = Command::new("mkfs.vfat");
    command.args(["-C", "-n", label]);
    if let Some(bits) = fat {
        command.args(["-F", &bits.to_string()]);
    }
    command.arg(image).arg(blocks.to_string());
    run_command(&mut command, "create FAT filesystem")
}

fn mmd(image: &Path, path: &str) -> Result<(), String> {
    run_command(Command::new("mmd").arg("-i").arg(image).arg(path), "mmd")
}

fn mcopy(image: &Path, source: &Path, destination: &str) -> Result<(), String> {
    require_file(source)?;
    run_command(
        Command::new("mcopy")
            .args(["-i"])
            .arg(image)
            .arg(source)
            .arg(destination),
        "mcopy",
    )
}

/// Preallocate the raw disk, lay down a GPT with the fixed layout, and copy
/// each partition image into place. All offsets are fixed and 1 MiB aligned so
/// the on-disk positions match the sector ranges handed to sgdisk exactly.
fn write_disk(disk: &Path, parts: &Path) -> Result<(), String> {
    run_command(
        Command::new("truncate")
            .arg("-s")
            .arg(format!("{}M", DISK_SIZE_MIB))
            .arg(disk),
        "allocate disk image",
    )?;
    run_command(Command::new("sgdisk").arg("-Z").arg(disk), "zap disk")?;

    let mut sgdisk = Command::new("sgdisk");
    sgdisk.args(["-a", &SECTORS_PER_MIB.to_string()]);
    for partition in PARTITIONS {
        let start = partition.start_mib * SECTORS_PER_MIB;
        let end = start + partition.size_mib * SECTORS_PER_MIB - 1;
        sgdisk
            .arg("-n")
            .arg(format!("{}:{start}:{end}", partition.number))
            .arg("-t")
            .arg(format!("{}:{}", partition.number, partition.gpt_type))
            .arg("-c")
            .arg(format!("{}:{}", partition.number, partition.label));
    }
    sgdisk.arg(disk);
    run_command(&mut sgdisk, "write GPT")?;

    for partition in PARTITIONS {
        if partition.label == "DATA" {
            continue;
        }
        let image = parts.join(format!("{}.img", partition.label.to_lowercase()));
        run_command(
            Command::new("dd")
                .arg(format!("if={}", image.display()))
                .arg(format!("of={}", disk.display()))
                .arg("bs=512")
                .arg(format!("seek={}", partition.start_mib * SECTORS_PER_MIB))
                .arg("conv=notrunc")
                .arg("status=none"),
            "write partition into disk",
        )?;
    }
    Ok(())
}

fn gpg(home: &Path) -> Command {
    let mut command = Command::new("gpg");
    command.env("GNUPGHOME", home);
    command
}

fn set_permissions_0700(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("chmod 0700 {}: {error}", path.display()))
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
    )
}

fn test_system(root: &Path) -> Result<(), String> {
    let disk = root.join("dist").join(DIST_DISK);
    let (output, observed_pass) = boot_for_marker(root, &disk, "qemu.log")?;
    let log = root.join("build/bootstrap/qemu.log");
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

/// Boot `disk` through OVMF/GRUB and capture serial output until the pass
/// marker appears or the timeout elapses. Returns the captured output and
/// whether the marker was seen. Reaching the timeout without the marker is a
/// valid outcome for callers that assert on the absence of a boot (it is not an
/// error here); a QEMU launch/exit failure is.
fn boot_for_marker(root: &Path, disk: &Path, log_name: &str) -> Result<(Vec<u8>, bool), String> {
    let mut command = qemu_base(root, "stdio", disk)?;
    command.arg("-monitor").arg("none").arg("-no-shutdown");
    let mut child = command
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
            Ok(Some(_status)) => {
                // GRUB or seL4 may reset/exit without the marker; that is a
                // legitimate no-boot outcome, so drain and stop without erroring.
                break Ok(());
            }
            Ok(None) => {}
            Err(error) => {
                break terminate(&mut child, "poll failure")
                    .and_then(|()| Err(format!("poll QEMU: {error}")));
            }
        }
        if start.elapsed() >= QEMU_TIMEOUT {
            break terminate(&mut child, "hard timeout");
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

    let log = root.join("build/bootstrap").join(log_name);
    if let Some(parent) = log.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    fs::write(&log, &output).map_err(|error| format!("write {}: {error}", log.display()))?;
    result?;
    Ok((output, observed_pass))
}

fn run_system(root: &Path) -> Result<(), String> {
    let disk = root.join("dist").join(DIST_DISK);
    let mut command = qemu_base(root, "mon:stdio", &disk)?;
    run_command(&mut command, "run QEMU")
}

/// Exercise the A/B boot state machine end to end. Each scenario starts from a
/// fresh copy of the pristine release disk, sets the boot-selection state (and,
/// where relevant, breaks a slot) exactly as the real update flow or a failed
/// boot would leave it, then boots through OVMF/GRUB and asserts on both GRUB's
/// slot-selection messages and seL4's completion marker. GRUB's single-attempt
/// model means a slot that fails verification is skipped within the same boot,
/// while a slot that would hang is represented by its persistent aftermath
/// (TRY set, OK unset) — exactly what a watchdog reset leaves behind.
fn test_ab(root: &Path) -> Result<(), String> {
    let dist_disk = root.join("dist").join(DIST_DISK);
    require_file(&dist_disk)?;
    let work = root.join("build/bootstrap/ab-test.img");

    // 1. Confirmed A boots directly.
    ab_scenario(
        root,
        &dist_disk,
        &work,
        "confirmed-A",
        &["ORDER=A B", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=0"],
        &[],
        &["librefirewall: booting confirmed slot A"],
        &["slot B"],
        true,
        None,
    )?;

    // 2. A staged, unconfirmed B is tried once and boots; the attempt is
    //    persisted (B_TRY becomes 1) so a later failure would fall back.
    ab_scenario(
        root,
        &dist_disk,
        &work,
        "try-pending-B",
        &["ORDER=B A", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=0"],
        &[],
        &["librefirewall: trying slot B"],
        &[],
        true,
        Some("B_TRY=1"),
    )?;

    // 3. A broken (signature-failing) pending B is skipped and the boot falls
    //    back to confirmed A within the same boot.
    ab_scenario(
        root,
        &dist_disk,
        &work,
        "fallback-from-broken-B",
        &["ORDER=B A", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=0"],
        &["SLOTB"],
        &[
            "librefirewall: trying slot B",
            "librefirewall: booting confirmed slot A",
        ],
        &[],
        true,
        None,
    )?;

    // 4. A pending B that was already tried but never confirmed (its aftermath
    //    of a hang + watchdog reset) is skipped in favour of A.
    ab_scenario(
        root,
        &dist_disk,
        &work,
        "skip-exhausted-B",
        &["ORDER=B A", "A_OK=1", "A_TRY=0", "B_OK=0", "B_TRY=1"],
        &[],
        &["librefirewall: booting confirmed slot A"],
        &["slot B"],
        true,
        None,
    )?;

    // 5. Once B is confirmed healthy (the update is committed), B boots directly.
    ab_scenario(
        root,
        &dist_disk,
        &work,
        "confirmed-B",
        &["ORDER=B A", "A_OK=0", "A_TRY=0", "B_OK=1", "B_TRY=0"],
        &[],
        &["librefirewall: booting confirmed slot B"],
        &[],
        true,
        None,
    )?;

    println!("A/B fallback tests passed (5 scenarios)");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn ab_scenario(
    root: &Path,
    dist_disk: &Path,
    work: &Path,
    name: &str,
    grubenv: &[&str],
    corrupt_slots: &[&str],
    expect: &[&str],
    reject: &[&str],
    expect_marker: bool,
    expect_grubenv_after: Option<&str>,
) -> Result<(), String> {
    copy_file(dist_disk, work)?;
    set_grubenv(work, grubenv)?;
    for slot in corrupt_slots {
        corrupt_slot_signature(root, work, slot)?;
    }

    let (output, observed_pass) = boot_for_marker(root, work, &format!("ab-{name}.log"))?;
    let text = String::from_utf8_lossy(&output);

    for needle in expect {
        if !text.contains(needle) {
            return Err(format!(
                "scenario {name}: expected to see {needle:?} in boot output"
            ));
        }
    }
    for needle in reject {
        if text.contains(needle) {
            return Err(format!(
                "scenario {name}: unexpectedly saw {needle:?} in boot output"
            ));
        }
    }
    if observed_pass != expect_marker {
        return Err(format!(
            "scenario {name}: pass marker observed={observed_pass}, expected={expect_marker}"
        ));
    }
    if let Some(entry) = expect_grubenv_after {
        let env = read_grubenv(work)?;
        if !env.lines().any(|line| line == entry) {
            return Err(format!(
                "scenario {name}: expected grubenv to contain {entry:?} after boot, got:\n{env}"
            ));
        }
    }
    println!("  A/B scenario ok: {name}");
    Ok(())
}

fn disk_at(disk: &Path, label: &str) -> String {
    // mtools addresses a partition by byte offset into the image.
    let bytes = part(label).start_mib * 1024 * 1024;
    format!("{}@@{}", disk.display(), bytes)
}

fn set_grubenv(disk: &Path, entries: &[&str]) -> Result<(), String> {
    let local = disk.with_extension("grubenv");
    run_command(
        Command::new("mcopy")
            .arg("-n")
            .arg("-i")
            .arg(disk_at(disk, "STATE"))
            .arg("::/grubenv")
            .arg(&local),
        "extract grubenv",
    )?;
    let mut edit = Command::new("grub-editenv");
    edit.arg(&local).arg("set");
    for entry in entries {
        edit.arg(entry);
    }
    run_command(&mut edit, "edit grubenv")?;
    run_command(
        Command::new("mcopy")
            .arg("-o")
            .arg("-i")
            .arg(disk_at(disk, "STATE"))
            .arg(&local)
            .arg("::/grubenv"),
        "write grubenv",
    )?;
    Ok(())
}

fn read_grubenv(disk: &Path) -> Result<String, String> {
    let local = disk.with_extension("grubenv.read");
    run_command(
        Command::new("mcopy")
            .arg("-n")
            .arg("-i")
            .arg(disk_at(disk, "STATE"))
            .arg("::/grubenv")
            .arg(&local),
        "extract grubenv",
    )?;
    let output = Command::new("grub-editenv")
        .arg(&local)
        .arg("list")
        .output()
        .map_err(|error| format!("list grubenv: {error}"))?;
    if !output.status.success() {
        return Err("grub-editenv list failed".to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Overwrite a slot's kernel signature with garbage so GRUB's enforced
/// verification rejects it, simulating a corrupt or tampered release.
fn corrupt_slot_signature(root: &Path, disk: &Path, label: &str) -> Result<(), String> {
    let garbage = root.join("build/bootstrap/garbage.sig");
    fs::write(&garbage, [0xAB_u8; 64]).map_err(|error| format!("write garbage: {error}"))?;
    run_command(
        Command::new("mcopy")
            .arg("-o")
            .arg("-i")
            .arg(disk_at(disk, label))
            .arg(&garbage)
            .arg("::/librefirewall-kernel.elf.sig"),
        "corrupt slot signature",
    )
}

/// Build the shared QEMU invocation that boots the deployable disk through
/// OVMF (UEFI) and the signed GRUB image, rather than QEMU's direct multiboot
/// loader. This exercises the same firmware -> boot-manager -> seL4 chain the
/// hardware appliance uses. A per-run writable copy of the OVMF variable store
/// lives in the build directory; the disk itself is writable so GRUB can
/// persist boot-selection state.
fn qemu_base(root: &Path, serial: &str, disk: &Path) -> Result<Command, String> {
    require_file(disk)?;

    let code = locate(OVMF_CODE_CANDIDATES, "OVMF code firmware")?;
    let vars_template = locate(OVMF_VARS_CANDIDATES, "OVMF variable store")?;
    let vars = root.join("build/bootstrap/OVMF_VARS.fd");
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
        .arg("-drive")
        .arg(format!("format=raw,file={}", disk.display()))
        .args(["-serial", serial, "-no-reboot"]);
    Ok(command)
}

fn is_writable(path: &Path) -> bool {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc_o_cloexec())
        .open(path)
        .is_ok()
}

fn libc_o_cloexec() -> i32 {
    0o2000000
}

fn locate(candidates: &[&str], description: &str) -> Result<PathBuf, String> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| format!("{description} not found in {candidates:?}"))
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

fn write_manifest(dist: &Path, config: &str, key_fingerprint: &str) -> Result<(), String> {
    let manifest = format!(
        concat!(
            "{{\n",
            "  \"format\": 2,\n",
            "  \"target\": \"{}\",\n",
            "  \"microkit\": {{\"version\": \"{}\", \"board\": \"{}\", \"config\": \"{}\"}},\n",
            "  \"rust_sel4\": {{\"version\": \"{}\"}},\n",
            "  \"boot\": {{\"manager\": \"grub\", \"grub_version\": \"{}\", \"scheme\": \"ab\", \"secure_boot\": false}},\n",
            "  \"signing\": {{\"trust_profile\": \"development\", \"key_fingerprint\": \"{}\"}},\n",
            "  \"disk\": {{\"image\": \"{}\", \"table\": \"gpt\", \"slots\": [\"SLOTA\", \"SLOTB\"]}},\n",
            "  \"artifacts\": [\"{}\", \"{}\", \"{}\", \"{}\", \"{}\"]\n",
            "}}\n"
        ),
        TARGET,
        MICROKIT_VERSION,
        BOARD,
        config,
        RUST_SEL4_VERSION,
        GRUB_VERSION,
        key_fingerprint,
        DIST_DISK,
        DIST_DISK,
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
        DIST_DISK,
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
