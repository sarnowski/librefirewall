use std::env;

use super::*;

/// A scratch directory of this test's own, removed when it drops, so two tests
/// running at once cannot judge each other's image.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = env::temp_dir().join(format!("lfw-data-disk-{name}-{}", std::process::id()));
        std::fs::create_dir_all(root.join("build/image")).expect("a scratch tree");
        Self { root }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Play the guest: write `sector` where the appliance would.
fn guest_writes(disk: &DataDisk, sector: [u8; SECTOR_SIZE]) {
    let mut file = OpenOptions::new()
        .write(true)
        .open(&disk.path)
        .expect("the image is writable");
    file.seek(SeekFrom::Start(WITNESS_SECTOR * SECTOR_SIZE as u64))
        .expect("seek");
    file.write_all(&sector).expect("write");
    file.sync_all().expect("flush");
}

#[test]
fn a_fresh_image_is_the_right_size_seeded_at_sector_zero_and_zero_at_the_witness() {
    let scratch = Scratch::new("fresh");
    let disk = DataDisk::create(&scratch.root, "fresh").expect("created");
    let metadata = std::fs::metadata(&disk.path).expect("stat");
    assert_eq!(metadata.len(), DATA_DISK_BYTES);

    let mut file = File::open(&disk.path).expect("open");
    let mut first = [0u8; SECTOR_SIZE];
    file.read_exact(&mut first).expect("read sector 0");
    assert_eq!(first, seed_pattern());
    assert_eq!(
        disk.witness().expect("read the witness"),
        [0u8; SECTOR_SIZE]
    );
}

/// The seed and the witness must not be confusable, or a guest that copied the
/// sector it read into the sector it was meant to compose would pass.
#[test]
fn the_seed_and_the_witness_patterns_are_different() {
    assert_ne!(seed_pattern(), witness_pattern());
    assert_ne!(seed_pattern(), [0u8; SECTOR_SIZE]);
    assert_ne!(witness_pattern(), [0u8; SECTOR_SIZE]);
}

/// The witness sector must be inside the image, or the read-back would fail as
/// an I/O error rather than as a verdict.
#[test]
fn the_witness_sector_lies_inside_the_image() {
    assert!((WITNESS_SECTOR + 1) * SECTOR_SIZE as u64 <= DATA_DISK_BYTES);
}

#[test]
fn the_written_verdict_passes_only_on_the_appliances_own_pattern() {
    let scratch = Scratch::new("written");
    let disk = DataDisk::create(&scratch.root, "written").expect("created");

    // Before the guest runs, the positive assertion must fail — this is the
    // demonstration that it is load-bearing and not decorative.
    let untouched = disk.judge_written().expect_err("nothing has been written");
    assert!(untouched.contains("still zeroes"), "{untouched}");
    disk.judge_untouched().expect("and the negative passes");

    guest_writes(&disk, witness_pattern());
    let verdict = disk.judge_written().expect("the pattern is there");
    assert!(verdict.contains("witness pattern"), "{verdict}");
    let now_written = disk
        .judge_untouched()
        .expect_err("and the negative now fails");
    assert!(
        now_written.contains("reached no protection domain"),
        "{now_written}"
    );
}

#[test]
fn a_copied_seed_sector_is_refused_and_named_as_one() {
    let scratch = Scratch::new("copied");
    let disk = DataDisk::create(&scratch.root, "copied").expect("created");
    guest_writes(&disk, seed_pattern());
    let error = disk.judge_written().expect_err("a copy is not a compose");
    assert!(error.contains("copied a sector"), "{error}");
}

#[test]
fn a_pattern_off_by_one_byte_is_refused() {
    let scratch = Scratch::new("nearly");
    let disk = DataDisk::create(&scratch.root, "nearly").expect("created");
    let mut nearly = witness_pattern();
    let last = nearly.len() - 1;
    nearly[last] ^= 0x01;
    guest_writes(&disk, nearly);
    let error = disk.judge_written().expect_err("nearly is not the pattern");
    assert!(error.contains("does not recognise"), "{error}");
}

#[test]
fn the_device_argument_pins_the_slot_the_ecam_grant_names() {
    let scratch = Scratch::new("attach");
    let disk = DataDisk::create(&scratch.root, "attach").expect("created");
    let mut command = Command::new("qemu-system-x86_64");
    disk.attach(&mut command);
    let rendered: Vec<String> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let joined = rendered.join(" ");
    assert!(joined.contains("addr=05.0"), "{joined}");
    assert!(joined.contains("disable-legacy=on"), "{joined}");
    assert!(joined.contains("disable-modern=off"), "{joined}");
    assert!(joined.contains("format=raw"), "{joined}");
    assert!(
        joined.contains(&disk.path.display().to_string()),
        "{joined}"
    );
}

/// Two runs must not share an image, so a scenario cannot pass on a sector some
/// earlier scenario's guest wrote.
#[test]
fn each_run_label_gets_its_own_image() {
    let scratch = Scratch::new("labels");
    let first = DataDisk::create(&scratch.root, "one").expect("created");
    let second = DataDisk::create(&scratch.root, "two").expect("created");
    assert_ne!(first.path, second.path);
    guest_writes(&first, witness_pattern());
    first.judge_written().expect("the first was written");
    second.judge_untouched().expect("the second was not");
}

/// Re-creating a label's image resets it, so a re-run never inherits the
/// previous run's verdict.
#[test]
fn recreating_an_image_resets_the_witness_sector() {
    let scratch = Scratch::new("reset");
    let disk = DataDisk::create(&scratch.root, "reset").expect("created");
    guest_writes(&disk, witness_pattern());
    disk.judge_written().expect("written");
    let again = DataDisk::create(&scratch.root, "reset").expect("recreated");
    again.judge_untouched().expect("and it is zeroes again");
}
