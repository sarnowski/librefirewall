//! The signed A/B GPT disk: on-disk layout and assembly.
//!
//! The deployable artifact is a fixed-layout GPT image (see CONCEPT §14.1). The
//! partitions are placed at fixed, 1 MiB-aligned offsets so the byte offsets the
//! `dd` writes seek to match the sector ranges handed to `sgdisk` exactly — the
//! layout is const data, not discovered at runtime, which is what lets mtools
//! address a partition purely by its start offset ([`disk_at`]).
//!
//! Both software slots are seeded with the same signed release and slot A is
//! marked confirmed, so the base image boots A while B stands ready as a
//! fallback and update target. Signing is delegated to [`crate::signing`] and
//! the embedded-key GRUB image to [`crate::grub`]; this module owns only the
//! partition geometry and the FAT/GPT assembly.

use std::{path::Path, process::Command};

use crate::{
    artifacts::DIST_DISK,
    grub, signing,
    util::{recreate_dir, require_file, run_command},
};

const SECTORS_PER_MIB: u64 = 2048;
const DISK_SIZE_MIB: u64 = 128;

/// The GPT layout of the deployable disk. `SLOTA` and `SLOTB` are the two
/// software slots; `STATE` carries the mutable boot-selection env; `DATA` is
/// reserved for configuration and secrets (CONCEPT §14.1) and is deliberately
/// left as a bare GPT partition with no filesystem — no in-system component
/// maps it yet, so [`write_disk`] lays down its partition entry but writes no
/// image into it.
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

/// Build the signed GPT A/B disk from the kernel and system image already in
/// `build`, returning the development signing key's fingerprint for the
/// manifest. Both slots are seeded with the same signed release and A is
/// marked confirmed, so the base image boots A while B stands ready as a
/// fallback and update target.
pub(crate) fn assemble_disk(root: &Path, build: &Path, dist: &Path) -> Result<String, String> {
    let kernel = build.join("sel4_32.elf");
    let system = build.join("loader.img");

    let fingerprint = signing::ensure_dev_key(root)?;
    let pubkey = root.join("build/dev-keys/librefirewall-dev-pub.gpg");
    signing::sign_file(root, &kernel)?;
    signing::sign_file(root, &system)?;

    let efi = build.join("BOOTX64.EFI");
    grub::build_grub_efi(root, &pubkey, &efi)?;

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
    grub::seed_grubenv(&grubenv)?;
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

    // DATA gets a GPT entry (in write_disk) but no filesystem: it is reserved
    // and stays unformatted until an in-system consumer owns it.

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
        // DATA is reserved and unformatted: it has a GPT entry but no image.
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

/// mtools addresses a partition by byte offset into the whole-disk image; this
/// renders the `image@@offset` form for the partition with `label`.
pub(crate) fn disk_at(disk: &Path, label: &str) -> String {
    let bytes = part(label).start_mib * 1024 * 1024;
    format!("{}@@{}", disk.display(), bytes)
}
