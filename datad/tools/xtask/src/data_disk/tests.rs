use std::env;

use lfw_capture_ring::{Copies, Cursor, Geometry, RingState, encode_superblock};

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

/// Play the guest for one recording extent: a superblock stating `writer`, and
/// `payload` laid into the extent's first payload segment.
///
/// The superblock is composed with the appliance's own encoder rather than by
/// hand, so a test that passes here is a test against the bytes the recorder
/// writes and not against this module's idea of them.
fn guest_records(disk: &DataDisk, extent: usize, writer: Cursor, payload: &[u8]) {
    let (start_sector, sectors) = Deck::extents()[extent];
    let geometry = Geometry::new(
        start_sector,
        sectors,
        SEGMENT_BYTES,
        DATA_DISK_BYTES / SECTOR_SIZE as u64,
    )
    .expect("the deck's own extent is a ring");
    let state = RingState::new(geometry, 7, writer, &[]).expect("a cursor inside the segment");
    let mut region = [0u8; SUPERBLOCK_BYTES];
    encode_superblock(&mut region, &state, Copies::Both);

    let mut file = OpenOptions::new()
        .write(true)
        .open(&disk.path)
        .expect("the image is writable");
    file.seek(SeekFrom::Start(start_sector * SECTOR_SIZE as u64))
        .expect("seek to the superblock");
    file.write_all(&region).expect("write the superblock");
    let segment_sectors = (SEGMENT_BYTES / SECTOR_SIZE) as u64;
    file.seek(SeekFrom::Start(
        (start_sector + segment_sectors) * SECTOR_SIZE as u64,
    ))
    .expect("seek to the payload");
    file.write_all(payload).expect("write the payload");
    file.sync_all().expect("flush");
}

/// Where each recording sits in [`Deck::extents`], named rather than indexed: the
/// two extents owe different things on a boot that carried nothing, so a test
/// about that difference must not turn on which of them `0` is.
const HISTORY_EXTENT: usize = 0;
const CAPTURE_EXTENT: usize = 1;

// Which position each of them occupies is the deck's, so the two names above are
// held to it rather than to this module's memory of it.
const _: () = {
    assert!(Deck::extents()[HISTORY_EXTENT].0 == lfw_recorder::deck::LOG_START_SECTOR);
    assert!(Deck::extents()[CAPTURE_EXTENT].0 == lfw_recorder::deck::CAPTURE_START_SECTOR);
};

/// Both extents recorded the same way, which is what `judge_recordings` walks.
fn both_extents_record(disk: &DataDisk, writer: Cursor, payload: &[u8]) {
    for extent in 0..Deck::extents().len() {
        guest_records(disk, extent, writer, payload);
    }
}

#[test]
fn a_recording_walked_to_the_superblocks_durable_end_passes() {
    let scratch = Scratch::new("recordings");
    let disk = DataDisk::create(&scratch.root, "recordings").expect("created");
    let payload = crate::recording_contract::tests::recording(3, 64);
    both_extents_record(
        &disk,
        Cursor {
            sequence: 0,
            offset: payload.len(),
        },
        &payload,
    );
    let verdict = disk
        .judge_recordings(true)
        .map(|held| held.evidence)
        .expect("both extents are recordings");
    assert!(verdict.contains("durable end at payload byte"), "{verdict}");
    assert!(verdict.contains("generation 7"), "{verdict}");
}

/// The defect this bound closes: one valid segment and then rubbish. The walk
/// necessarily stops where the ring stops being walkable, so without the
/// superblock's own cursor to reach for, the stop reads as the end of a
/// well-formed recording.
#[test]
fn a_recording_the_walk_stops_short_of_the_durable_end_is_a_finding() {
    let scratch = Scratch::new("short-walk");
    let disk = DataDisk::create(&scratch.root, "short-walk").expect("created");
    let good = crate::recording_contract::tests::recording(3, 64);
    let mut payload = good.clone();
    // What a recorder that lost its place writes: a block whose trailing length
    // disagrees with its head, which is exactly where a reader gives up.
    payload.extend_from_slice(&crate::recording_contract::tests::enhanced_packet(32));
    let at = payload.len() - 4;
    payload[at] ^= 0xFF;
    both_extents_record(
        &disk,
        Cursor {
            sequence: 0,
            offset: payload.len(),
        },
        &payload,
    );
    let error = disk
        .judge_recordings(true)
        .map(|held| held.evidence)
        .expect_err("the walk stopped before the superblock's end");
    assert!(error.contains("durable end at payload byte"), "{error}");
    assert!(
        error.contains("followed the extent's own lengths"),
        "{error}"
    );
}

/// The other direction is not a finding, and that is the barrier's doing: a
/// checkpoint goes out behind a device flush, so between a payload write
/// completing and its superblock landing the written prefix is ahead of the
/// durable cursor. An extent that understates sends no reader anywhere wrong, so
/// the lag is reported rather than refused.
#[test]
fn a_superblock_one_flush_behind_the_written_prefix_is_reported_and_not_refused() {
    let scratch = Scratch::new("lagging");
    let disk = DataDisk::create(&scratch.root, "lagging").expect("created");
    let payload = crate::recording_contract::tests::recording(3, 64);
    let behind = payload.len() - crate::recording_contract::tests::enhanced_packet(64).len();
    both_extents_record(
        &disk,
        Cursor {
            sequence: 0,
            offset: behind,
        },
        &payload,
    );
    let verdict = disk
        .judge_recordings(true)
        .map(|held| held.evidence)
        .expect("a checkpoint behind the payload is the ordinary state");
    assert!(
        verdict.contains(&format!("durable end at payload byte {behind}")),
        "{verdict}"
    );
    assert!(verdict.contains("awaiting a checkpoint"), "{verdict}");
}

/// What the equality used to close and the zero tail closes now: one walkable
/// recording followed by bytes that are not part of it. The walk stops where the
/// stream stops being walkable, so without this the stop reads as a clean end.
#[test]
fn bytes_past_the_written_prefix_are_a_finding() {
    let scratch = Scratch::new("trailing-rubbish");
    let disk = DataDisk::create(&scratch.root, "trailing-rubbish").expect("created");
    let good = crate::recording_contract::tests::recording(3, 64);
    let mut payload = good.clone();
    // A block whose trailing length disagrees with its head: the walk gives up
    // at it, and the bytes are on the medium all the same.
    payload.extend_from_slice(&crate::recording_contract::tests::enhanced_packet(32));
    let at = payload.len() - 4;
    payload[at] ^= 0xFF;
    both_extents_record(
        &disk,
        Cursor {
            sequence: 0,
            offset: good.len(),
        },
        &payload,
    );
    let error = disk
        .judge_recordings(true)
        .map(|held| held.evidence)
        .expect_err("bytes past the walkable prefix are not the recording");
    assert!(
        error.contains("holds a non-zero byte at payload offset"),
        "{error}"
    );
}

#[test]
fn a_superblock_claiming_nothing_durable_is_a_finding() {
    let scratch = Scratch::new("nothing-durable");
    let disk = DataDisk::create(&scratch.root, "nothing-durable").expect("created");
    let payload = crate::recording_contract::tests::recording(3, 64);
    both_extents_record(
        &disk,
        Cursor {
            sequence: 0,
            offset: 0,
        },
        &payload,
    );
    let error = disk
        .judge_recordings(true)
        .map(|held| held.evidence)
        .expect_err("a cursor at zero says nothing reached the medium");
    assert!(
        error.contains("no byte of the recording is durable"),
        "{error}"
    );
}

/// **A boot that carried nothing wrote no conversation history, and that is not a
/// finding.** An appliance no management plane has taken forwards nothing, so it
/// opens no flow — and requiring a record in the history extent would turn the
/// correct behaviour of an unowned node into a failed gate. The capture extent
/// still owes its records on such a boot, because a refusal is a decision.
#[test]
fn an_empty_history_is_allowed_only_where_no_conversation_was_carried() {
    let scratch = Scratch::new("no-conversations");
    let disk = DataDisk::create(&scratch.root, "no-conversations").expect("created");
    // The history extent holds a recording with no packet block and the capture
    // extent holds one with three, which is exactly the shape an unowned boot
    // leaves: every frame was decided and none opened a conversation.
    let carried = crate::recording_contract::tests::recording(3, 64);
    let empty = crate::recording_contract::tests::recording(0, 64);
    guest_records(
        &disk,
        HISTORY_EXTENT,
        Cursor {
            sequence: 0,
            offset: empty.len(),
        },
        &empty,
    );
    guest_records(
        &disk,
        CAPTURE_EXTENT,
        Cursor {
            sequence: 0,
            offset: carried.len(),
        },
        &carried,
    );

    let error = disk
        .judge_recordings(true)
        .map(|held| held.evidence)
        .expect_err("a boot that carried traffic owes a history");
    assert!(error.contains("holds no packet block"), "{error}");

    let verdict = disk
        .judge_recordings(false)
        .map(|held| held.evidence)
        .expect("a boot that carried nothing owes no history");
    assert!(verdict.contains("packet block(s)"), "{verdict}");
}

#[test]
fn an_extent_with_no_superblock_at_all_is_a_finding() {
    let scratch = Scratch::new("no-superblock");
    let disk = DataDisk::create(&scratch.root, "no-superblock").expect("created");
    let error = disk
        .judge_recordings(true)
        .map(|held| held.evidence)
        .expect_err("a zeroed extent carries no superblock");
    assert!(error.contains("no decodable superblock"), "{error}");
}

/// **The join two boots leave in one extent is walked, not stepped over.** A
/// resumed recording continues at the byte its predecessor stopped on and opens
/// a pcapng section there, so an extent several boots wrote is one stream from
/// payload byte zero — and this walk begins there whatever segment the writer
/// has reached. Written past a segment boundary deliberately: a walk that began
/// at the writer's own segment would pass this and read none of the join.
#[test]
fn an_extent_two_boots_wrote_is_walked_whole_across_the_join() {
    let scratch = Scratch::new("resume-join");
    let disk = DataDisk::create(&scratch.root, "resume-join").expect("created");
    // One boot's worth, twice: each opens a section of its own, which is the
    // shape a resume leaves, and two of them run past a segment.
    let boot = crate::recording_contract::tests::recording(1200, 400);
    let mut payload = boot.clone();
    let mut sections = 1;
    while payload.len() <= SEGMENT_BYTES {
        payload.extend_from_slice(&boot);
        sections += 1;
    }
    let writer = Cursor {
        sequence: 1,
        offset: payload.len() - SEGMENT_BYTES,
    };
    both_extents_record(&disk, writer, &payload);

    let verdict = disk
        .judge_recordings(true)
        .map(|held| held.evidence)
        .expect("both extents are one recording across the join");
    assert!(
        verdict.contains(&format!("durable end at payload byte {}", payload.len())),
        "{verdict}"
    );
    assert!(
        verdict.contains(&format!("{sections} section header(s)")),
        "a walk that began at the writer's segment would have read one, saw: {verdict}"
    );
}

/// A wrapped ring is named as out of this walk's reach rather than waved
/// through: the payload is read in device order, which stops being write order
/// at the first wrap.
#[test]
fn a_wrapped_ring_is_refused_as_beyond_this_walks_reach() {
    let (start_sector, sectors) = Deck::extents()[0];
    let geometry = Geometry::new(
        start_sector,
        sectors,
        SEGMENT_BYTES,
        DATA_DISK_BYTES / SECTOR_SIZE as u64,
    )
    .expect("a ring");
    let wrapped = RingState::new(
        geometry,
        1,
        Cursor {
            sequence: geometry.segments(),
            offset: 0,
        },
        &[],
    )
    .expect("a legal cursor one wrap along");
    assert_eq!(durable_payload_bytes(&wrapped), None);

    let last_before_wrap = RingState::new(
        geometry,
        1,
        Cursor {
            sequence: geometry.segments() - 1,
            offset: 64,
        },
        &[],
    )
    .expect("a legal cursor in the last segment");
    assert_eq!(
        durable_payload_bytes(&last_before_wrap),
        Some((geometry.segments() as usize - 1) * SEGMENT_BYTES + 64)
    );
}
