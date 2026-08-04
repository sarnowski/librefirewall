//! The signed A/B GPT disk: on-disk layout and assembly.
//!
//! The deployable artifact is a fixed-layout GPT image. The
//! partitions are placed at fixed, 1 MiB-aligned offsets so the byte offsets the
//! partition writes seek to match the sector ranges handed to `sgdisk` exactly —
//! the layout is const data, not discovered at runtime, which is what lets
//! mtools address a partition purely by its start offset ([`disk_at`]).
//!
//! Both software slots are seeded with the same signed release and slot A is
//! marked confirmed, so the base image boots A while B stands ready as a
//! fallback and update target. Signing is delegated to [`crate::signing`] and
//! the embedded-key GRUB image to [`crate::grub`]; this module owns only the
//! partition geometry and the FAT/GPT assembly.
//!
//! Two properties are enforced here rather than assumed, because both fail
//! silently otherwise and both produce a disk that is wrong in a way no later
//! stage looks at:
//!
//! - **Every signature this build produces is verified before it is copied into
//!   a slot**, against a scratch keyring holding nothing but the public key
//!   embedded into GRUB. An unverifiable or wrongly-keyed payload would
//!   otherwise reach *both* slots — leaving no fallback — and only surface as a
//!   boot failure on the appliance.
//! - **Every partition image is checked to fit its partition before it is
//!   written.** The raw writes are positional; an oversized image would run on
//!   into the next partition. The const layout assertions below constrain the
//!   *layout*, which is a different thing from the size of what goes into it.

use std::{
    fs::{File, OpenOptions},
    io::{self, Seek, SeekFrom},
    path::Path,
    process::Command,
};

use crate::{
    artifacts::{BUILD_KERNEL_IMAGE, BUILD_SYSTEM_IMAGE, DIST_DISK, DIST_KERNEL, DIST_SYSTEM},
    grub, signing,
    util::{Error, recreate_dir, require_file, run_command},
};

const BYTES_PER_MIB: u64 = 1024 * 1024;
const SECTORS_PER_MIB: u64 = 2048;
const DISK_SIZE_MIB: u64 = 128;

/// The GPT layout of the deployable disk. `SLOT_A` and `SLOT_B` are the two
/// software slots; `STATE` carries the mutable boot-selection env; `DATA` is
/// reserved for configuration and secrets and is deliberately
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

impl Partition {
    fn start_bytes(&self) -> u64 {
        self.start_mib * BYTES_PER_MIB
    }

    fn size_bytes(&self) -> u64 {
        self.size_mib * BYTES_PER_MIB
    }
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
        label: "SLOT_A",
        gpt_type: "8300",
        start_mib: 57,
        size_mib: 16,
    },
    Partition {
        number: 4,
        label: "SLOT_B",
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

// Compile-time layout invariants the positional writes in `write_disk` rely on:
// partition numbers run 1..N in order, no two partitions overlap, and the whole
// layout fits within the disk. A mis-edit that broke any of these would produce
// overlapping writes, so it must fail the build rather than corrupt a disk.
const _: () = {
    let mut index = 0;
    let mut cursor = 0;
    while index < PARTITIONS.len() {
        assert!(
            PARTITIONS[index].number == index + 1,
            "partition numbers must run 1..N in slice order"
        );
        assert!(
            PARTITIONS[index].start_mib >= cursor,
            "partitions must not overlap"
        );
        cursor = PARTITIONS[index].start_mib + PARTITIONS[index].size_mib;
        index += 1;
    }
    assert!(
        cursor <= DISK_SIZE_MIB,
        "partitions must fit within the disk"
    );
};

/// The payload each slot carries: the kernel and system image with their
/// detached signatures, under the names GRUB's configuration loads.
const SLOT_PAYLOAD: &[(&str, &str)] = &[
    (BUILD_KERNEL_IMAGE, DIST_KERNEL),
    (BUILD_SYSTEM_IMAGE, DIST_SYSTEM),
];

/// Build the signed GPT A/B disk from the kernel and system image already in
/// `build`, returning the development signing key's fingerprint for the
/// manifest. Both slots are seeded with the same signed release and A is
/// marked confirmed, so the base image boots A while B stands ready as a
/// fallback and update target.
pub(crate) fn assemble_disk(root: &Path, build: &Path, dist: &Path) -> Result<String, Error> {
    let fingerprint = signing::ensure_dev_key(root)?;
    let pubkey = signing::dev_public_key(root);

    let payload: Vec<_> = SLOT_PAYLOAD
        .iter()
        .map(|(source, _)| build.join(source))
        .collect();
    for file in &payload {
        signing::sign_file(root, file, &fingerprint)?;
    }

    // Prove the chain before anything is committed to a slot: the key that
    // verifies here is the same file that is embedded into GRUB below, so a
    // pass means the boot manager will accept exactly these payloads.
    let verification_keyring = build.join("verify-keyring");
    signing::import_verification_key(&verification_keyring, &pubkey)?;
    for file in &payload {
        signing::verify_payload_signature(&verification_keyring, file, &fingerprint)?;
    }

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

    for label in ["SLOT_A", "SLOT_B"] {
        let image = parts.join(format!("{}.img", label.to_lowercase()));
        make_fat(&image, part(label).size_mib, Some(16), label)?;
        for (source, slot_name) in SLOT_PAYLOAD {
            let file = build.join(source);
            mcopy(&image, &file, &format!("::/{slot_name}"))?;
            mcopy(
                &image,
                &signing::signature_path(&file),
                &format!("::/{slot_name}.sig"),
            )?;
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

fn make_fat(image: &Path, size_mib: u64, fat: Option<u32>, label: &str) -> Result<(), Error> {
    let blocks = size_mib * 1024;
    let mut command = Command::new("mkfs.vfat");
    command.args(["-C", "-n", label]);
    if let Some(bits) = fat {
        command.args(["-F", &bits.to_string()]);
    }
    command.arg(image).arg(blocks.to_string());
    run_command(&mut command, "create FAT filesystem")
}

fn mmd(image: &Path, path: &str) -> Result<(), Error> {
    run_command(Command::new("mmd").arg("-i").arg(image).arg(path), "mmd")
}

fn mcopy(image: &Path, source: &Path, destination: &str) -> Result<(), Error> {
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
///
/// Preallocation and the partition writes are done directly rather than through
/// `truncate`/`dd`: those add two more external tools to the path that produces
/// the deployable disk, and `dd`'s positional write has no idea how large the
/// partition it is landing in is.
fn write_disk(disk: &Path, parts: &Path) -> Result<(), Error> {
    let file = File::create(disk).map_err(|error| Error::io("create", disk, error))?;
    file.set_len(DISK_SIZE_MIB * BYTES_PER_MIB)
        .map_err(|error| Error::io("preallocate", disk, error))?;
    drop(file);

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
        write_partition(disk, partition, &image)?;
    }
    Ok(())
}

/// Copy one partition image into its slot in the raw disk, refusing an image
/// that does not fit.
///
/// The write is positional and does not truncate the disk, so an image larger
/// than its partition would silently overwrite the start of the next one — for
/// SLOT_A that means corrupting the fallback slot SLOT_B, destroying the very
/// redundancy the A/B scheme exists for.
fn write_partition(disk: &Path, partition: &Partition, image: &Path) -> Result<(), Error> {
    let length = image
        .metadata()
        .map_err(|error| Error::io("stat", image, error))?
        .len();
    let capacity = partition.size_bytes();
    if length > capacity {
        return Err(Error::invalid(format!(
            "partition image {} is {length} bytes but partition {} holds only {capacity}; \
             writing it would overrun into the next partition",
            image.display(),
            partition.label
        )));
    }

    let mut source = File::open(image).map_err(|error| Error::io("open", image, error))?;
    let mut target = OpenOptions::new()
        .write(true)
        .open(disk)
        .map_err(|error| Error::io("open for writing", disk, error))?;
    target
        .seek(SeekFrom::Start(partition.start_bytes()))
        .map_err(|error| Error::io("seek in", disk, error))?;
    io::copy(&mut source, &mut target).map_err(|error| Error::io("write into", disk, error))?;
    Ok(())
}

/// mtools addresses a partition by byte offset into the whole-disk image; this
/// renders the `image@@offset` form for the partition with `label`.
pub(crate) fn disk_at(disk: &Path, label: &str) -> String {
    format!("{}@@{}", disk.display(), part(label).start_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partitions_are_ordered_non_overlapping_and_fit_the_disk() {
        let mut cursor = 0;
        for (index, partition) in PARTITIONS.iter().enumerate() {
            assert_eq!(partition.number, index + 1, "numbers run 1..N in order");
            assert!(
                partition.start_mib >= cursor,
                "{} overlaps the previous partition",
                partition.label
            );
            cursor = partition.start_mib + partition.size_mib;
        }
        assert!(cursor <= DISK_SIZE_MIB, "layout exceeds the disk size");
    }

    #[test]
    fn part_resolves_every_declared_label() {
        for partition in PARTITIONS {
            assert_eq!(part(partition.label).number, partition.number);
        }
    }

    #[test]
    fn disk_at_renders_the_partition_byte_offset() {
        let rendered = disk_at(Path::new("/tmp/disk.img"), "SLOT_B");
        assert_eq!(
            rendered,
            format!("/tmp/disk.img@@{}", 73 * 1024 * 1024_u64),
            "mtools addresses SLOT_B by its 1 MiB-aligned byte offset"
        );
    }

    /// A scratch disk with the layout's real geometry but no GPT: enough to
    /// prove the positional-write guard, which is what stands between an
    /// oversized image and a silently corrupted neighbouring partition.
    fn scratch_disk(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("librefirewall-disk-test-{name}"));
        let file = File::create(&path).unwrap();
        file.set_len(DISK_SIZE_MIB * BYTES_PER_MIB).unwrap();
        path
    }

    /// Read one window out of the scratch disk. The disk is 128 MiB, so the
    /// assertions read the bytes they care about rather than the whole image.
    fn window(disk: &Path, offset: u64, length: usize) -> Vec<u8> {
        use std::io::Read;
        let mut file = File::open(disk).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut buffer = vec![0_u8; length];
        file.read_exact(&mut buffer).unwrap();
        buffer
    }

    fn cleanup(disk: &Path, image: &Path) {
        std::fs::remove_file(disk).ok();
        std::fs::remove_file(image).ok();
    }

    #[test]
    fn an_oversized_partition_image_is_refused() {
        let disk = scratch_disk("oversized");
        let image = disk.with_extension("part");
        let slot_a = part("SLOT_A");
        std::fs::write(&image, vec![0xAB_u8; (slot_a.size_bytes() + 1) as usize]).unwrap();

        let error = write_partition(&disk, slot_a, &image)
            .unwrap_err()
            .to_string();
        assert!(error.contains("SLOT_A"), "got: {error}");
        assert!(error.contains("overrun"), "got: {error}");

        // Nothing was written, so the fallback slot the whole A/B scheme rests
        // on is still intact.
        assert!(
            window(&disk, part("SLOT_B").start_bytes(), 512)
                .iter()
                .all(|byte| *byte == 0),
            "a refused write must not have touched SLOT_B"
        );
        cleanup(&disk, &image);
    }

    #[test]
    fn a_fitting_partition_image_lands_at_its_offset_and_leaves_neighbours_alone() {
        let disk = scratch_disk("fitting");
        let image = disk.with_extension("part");
        let slot_a = part("SLOT_A");
        let content = vec![0xCD_u8; 4096];
        std::fs::write(&image, &content).unwrap();

        write_partition(&disk, slot_a, &image).unwrap();

        assert_eq!(window(&disk, slot_a.start_bytes(), content.len()), content);
        assert!(
            window(&disk, slot_a.start_bytes() - 512, 512)
                .iter()
                .all(|byte| *byte == 0),
            "the write must not reach back before its partition"
        );
        assert!(
            window(&disk, part("SLOT_B").start_bytes(), 512)
                .iter()
                .all(|byte| *byte == 0),
            "the write must not reach into SLOT_B"
        );
        assert_eq!(
            disk.metadata().unwrap().len(),
            DISK_SIZE_MIB * BYTES_PER_MIB,
            "the positional write must not truncate the disk"
        );
        cleanup(&disk, &image);
    }

    #[test]
    fn an_exactly_full_partition_image_is_accepted() {
        let disk = scratch_disk("exact");
        let image = disk.with_extension("part");
        let state = part("STATE");
        std::fs::write(&image, vec![0x5A_u8; state.size_bytes() as usize]).unwrap();

        write_partition(&disk, state, &image).unwrap();

        assert_eq!(
            window(&disk, state.start_bytes() + state.size_bytes() - 1, 1),
            vec![0x5A],
            "the last byte of an exactly-sized image is written"
        );
        assert!(
            window(&disk, part("SLOT_A").start_bytes(), 512)
                .iter()
                .all(|byte| *byte == 0),
            "an exactly-sized image must stop at the partition boundary"
        );
        cleanup(&disk, &image);
    }
}
