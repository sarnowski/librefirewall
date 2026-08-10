//! The boot-time read judged against a device that answers, refuses, fails,
//! lies about how much it moved, replays its used ring and says nothing at all —
//! and against a medium holding a superblock nobody this decoder recognises
//! wrote.

use super::*;

use std::{vec, vec::Vec};

use lfw_capture_ring::{
    Copies, Cursor, Geometry, RingState, SECTOR_SIZE, SUPERBLOCK_COPY_BYTES, encode_superblock,
};

use crate::deck::{Refused, SEGMENT_BYTES, STAGING_END};

/// The device the QEMU harness attaches, so the extents this crate compiles in
/// fit exactly as they do on a booted node.
const CAPACITY_SECTORS: u64 = 64 * 1024 * 1024 / SECTOR_SIZE as u64;

/// How the stand-in device answers the read it is handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Conduct {
    /// Transfer the sectors and report the count that was asked for.
    Conforming,
    /// Take nothing: no free slot, no room in the queue.
    Refuses,
    /// Answer, and say no.
    Fails,
    /// Answer `Ok` having moved one sector less, leaving the tail of the
    /// staging area holding whatever was in it.
    Short,
    /// Answer a job nothing submitted.
    Misattributes,
    /// Say nothing at all.
    Silent,
    /// Replay `count` used-ring entries this side can attribute to no job, and
    /// then answer properly.
    Replays(u32),
    /// Answer properly, but hand out a staging area shorter than the region.
    Unstages,
}

struct Device {
    disk: Vec<u8>,
    window: Vec<u8>,
    conduct: Conduct,
    ready: Option<Polled>,
    replays_left: u32,
    /// Every job submitted, in order, so a read's attribution is checked
    /// against what was asked for rather than against what came back.
    submitted: Vec<Job>,
}

impl Device {
    fn new(conduct: Conduct) -> Self {
        Self {
            disk: vec![0u8; CAPACITY_SECTORS as usize * SECTOR_SIZE],
            window: vec![0u8; STAGING_END],
            conduct,
            ready: None,
            replays_left: match conduct {
                Conduct::Replays(count) => count,
                _ => 0,
            },
            submitted: Vec::new(),
        }
    }

    /// Put a superblock for `state` on the medium at `sector`, as a previous
    /// boot's checkpoint left it.
    fn seed(&mut self, sector: u64, state: &RingState) {
        let mut region = [0u8; SUPERBLOCK_BYTES];
        encode_superblock(&mut region, state, Copies::Both);
        let at = sector as usize * SECTOR_SIZE;
        self.disk[at..at + SUPERBLOCK_BYTES].copy_from_slice(&region);
    }

    /// Put bytes on the medium that no writer of this layout produced.
    fn seed_bytes(&mut self, sector: u64, byte: u8) {
        let at = sector as usize * SECTOR_SIZE;
        self.disk[at..at + SUPERBLOCK_BYTES].fill(byte);
    }
}

impl Medium for Device {
    fn staging(&mut self, area: Area) -> &mut [u8] {
        let (offset, len) = area.extent();
        let len = if self.conduct == Conduct::Unstages && area == Area::Superblock {
            len - SECTOR_SIZE
        } else {
            len
        };
        self.window
            .get_mut(offset..offset + len)
            .expect("the window holds every area")
    }

    fn orders_writes(&self) -> bool {
        true
    }

    fn barrier(&mut self, _job: Job) -> Result<(), Refused> {
        unreachable!("the boot-time read orders nothing")
    }

    fn submit(&mut self, job: Job, transfer: Transfer) -> Result<(), Refused> {
        if self.conduct == Conduct::Refuses {
            return Err(Refused);
        }
        self.submitted.push(job);
        assert!(!transfer.write, "the boot-time read writes nothing");
        assert!(
            transfer.len.is_multiple_of(SECTOR_SIZE),
            "a block transfer is whole sectors"
        );
        let (base, area_len) = transfer.area.extent();
        assert!(
            transfer.at + transfer.len <= area_len,
            "a transfer stays inside its area"
        );
        let at = transfer.sector as usize * SECTOR_SIZE;
        assert!(
            at + transfer.len <= self.disk.len(),
            "a transfer stays inside the device"
        );
        if self.conduct == Conduct::Silent {
            return Ok(());
        }
        let moved = if self.conduct == Conduct::Short {
            transfer.len - SECTOR_SIZE
        } else {
            transfer.len
        };
        for byte in 0..moved {
            self.window[base + transfer.at + byte] = self.disk[at + byte];
        }
        let answered = if self.conduct == Conduct::Misattributes {
            Job::Fetch
        } else {
            job
        };
        self.ready = Some(Polled::Settled(Completion {
            job: answered,
            ended: if self.conduct == Conduct::Fails {
                Ended::Failed
            } else {
                Ended::Ok { delivered: moved }
            },
        }));
        Ok(())
    }

    fn poll(&mut self) -> Option<Polled> {
        if self.replays_left > 0 {
            self.replays_left -= 1;
            return Some(Polled::Unattributed);
        }
        self.ready.take()
    }
}

/// The state a previous boot of `which`'s own ring would have checkpointed.
fn stored(which: Which, generation: u64, cursor: Cursor) -> RingState {
    let (start_sector, sectors) = which.extent();
    let geometry = Geometry::new(start_sector, sectors, SEGMENT_BYTES, start_sector + sectors)
        .expect("the compiled-in extent is a ring");
    RingState::new(geometry, generation, cursor, &[]).expect("a cursor inside the geometry")
}

#[test]
fn an_unwritten_medium_reads_as_no_superblock_at_all_and_is_not_an_error() {
    let mut device = Device::new(Conduct::Conforming);
    let stored = read_superblocks(CAPACITY_SECTORS, &mut device).expect("a zeroed disk answers");
    assert_eq!(stored, [None, None]);
    // Both extents, in the order the recordings are brought up, and each read
    // exactly once.
    assert_eq!(
        device.submitted,
        vec![Job::Preload(Which::Log), Job::Preload(Which::Capture)]
    );
}

#[test]
fn each_extents_own_superblock_comes_back_whole_and_under_its_own_geometry() {
    let mut device = Device::new(Conduct::Conforming);
    for (index, which) in Which::ALL.into_iter().enumerate() {
        device.seed(
            which.extent().0,
            &stored(
                which,
                7 + index as u64,
                Cursor {
                    sequence: 3 + index as u64,
                    offset: 512 * (index as u64 + 1) as usize,
                },
            ),
        );
    }
    let read = read_superblocks(CAPACITY_SECTORS, &mut device).expect("a written disk answers");
    for (index, (slot, which)) in read.into_iter().zip(Which::ALL).enumerate() {
        let state = slot.expect("the extent carries a superblock");
        assert_eq!(state.write_generation(), 7 + index as u64);
        assert_eq!(state.writer().sequence, 3 + index as u64);
        assert_eq!(state.writer().offset, 512 * (index + 1));
        assert_eq!(state.geometry().start_sector(), which.extent().0);
        // And it is this extent's, so a `check` against the same geometry the
        // deck builds accepts it.
        assert!(
            state
                .check(
                    &which
                        .geometry(CAPACITY_SECTORS)
                        .expect("the compiled-in extent is a ring")
                )
                .is_ok()
        );
    }
}

#[test]
fn one_written_extent_leaves_the_other_reading_as_fresh() {
    let mut device = Device::new(Conduct::Conforming);
    device.seed(
        Which::Capture.extent().0,
        &stored(
            Which::Capture,
            1,
            Cursor {
                sequence: 0,
                offset: 0,
            },
        ),
    );
    let read = read_superblocks(CAPACITY_SECTORS, &mut device).expect("the disk answers");
    assert!(read[0].is_none(), "the log extent was never written");
    assert!(read[1].is_some(), "the capture extent was");
}

#[test]
fn bytes_no_writer_of_this_layout_produced_read_as_a_fresh_medium() {
    // Not an error and not half-believed: a medium whose superblock is beyond
    // use is what a first boot over somebody else's disk finds, and the caller
    // holding the policy is the one that decides to write over it.
    for byte in [0x5a, 0xff, 0x01] {
        let mut device = Device::new(Conduct::Conforming);
        for which in Which::ALL {
            device.seed_bytes(which.extent().0, byte);
        }
        let read = read_superblocks(CAPACITY_SECTORS, &mut device).expect("the disk answers");
        assert_eq!(read, [None, None], "byte {byte:#04x}");
    }
}

#[test]
fn a_superblock_naming_another_extent_decodes_and_is_refused_by_the_geometry() {
    // The whole defence against a rebound medium, and the reason a decoded
    // superblock is a `RingState` rather than something a ring may resume from:
    // it decodes here, and only the comparison against a geometry this side
    // built refuses it.
    let mut device = Device::new(Conduct::Conforming);
    let (start_sector, sectors) = Which::Log.extent();
    let elsewhere = Geometry::new(
        start_sector + (SEGMENT_BYTES / SECTOR_SIZE) as u64,
        sectors,
        SEGMENT_BYTES,
        CAPACITY_SECTORS,
    )
    .expect("a legal geometry that is not this extent's");
    let state = RingState::new(
        elsewhere,
        9,
        Cursor {
            sequence: 2,
            offset: 0,
        },
        &[],
    )
    .expect("a cursor inside the geometry");
    let mut region = [0u8; SUPERBLOCK_BYTES];
    encode_superblock(&mut region, &state, Copies::Both);
    let at = start_sector as usize * SECTOR_SIZE;
    device.disk[at..at + SUPERBLOCK_BYTES].copy_from_slice(&region);

    let read = read_superblocks(CAPACITY_SECTORS, &mut device).expect("the disk answers");
    let decoded = read[0].expect("the bytes decode");
    assert!(
        decoded
            .check(
                &Which::Log
                    .geometry(CAPACITY_SECTORS)
                    .expect("the compiled-in extent is a ring")
            )
            .is_err()
    );
}

#[test]
fn only_the_newer_copy_needs_to_survive() {
    // The torn-write defence, reached through the read rather than through the
    // decoder alone: one copy destroyed and the extent still says what it is.
    let mut device = Device::new(Conduct::Conforming);
    let which = Which::Log;
    device.seed(
        which.extent().0,
        &stored(
            which,
            4,
            Cursor {
                sequence: 1,
                offset: 0,
            },
        ),
    );
    let at = which.extent().0 as usize * SECTOR_SIZE;
    device.disk[at + SUPERBLOCK_COPY_BYTES..at + SUPERBLOCK_BYTES].fill(0xaa);
    let read = read_superblocks(CAPACITY_SECTORS, &mut device).expect("the disk answers");
    assert_eq!(
        read[0]
            .expect("the surviving copy decodes")
            .write_generation(),
        4
    );
}

#[test]
fn a_device_that_will_not_take_the_read_is_refused_rather_than_assumed_fresh() {
    let mut device = Device::new(Conduct::Refuses);
    assert_eq!(
        read_superblocks(CAPACITY_SECTORS, &mut device),
        Err(PreloadError::Refused { which: Which::Log })
    );
}

#[test]
fn a_device_error_on_the_read_is_reported_as_one() {
    let mut device = Device::new(Conduct::Fails);
    assert_eq!(
        read_superblocks(CAPACITY_SECTORS, &mut device),
        Err(PreloadError::Failed { which: Which::Log })
    );
}

#[test]
fn a_read_that_moved_less_than_the_region_is_a_failure_however_it_reports_itself() {
    // The case the check exists for: the shortfall still holds this side's own
    // leftovers, so decoding it would be decoding the staging window rather
    // than the medium.
    let mut device = Device::new(Conduct::Short);
    assert_eq!(
        read_superblocks(CAPACITY_SECTORS, &mut device),
        Err(PreloadError::Short {
            which: Which::Log,
            delivered: SUPERBLOCK_BYTES - SECTOR_SIZE,
        })
    );
}

#[test]
fn a_completion_answering_a_job_this_read_never_submitted_is_its_own_refusal() {
    let mut device = Device::new(Conduct::Misattributes);
    assert_eq!(
        read_superblocks(CAPACITY_SECTORS, &mut device),
        Err(PreloadError::Misattributed { which: Which::Log })
    );
}

#[test]
fn a_staging_area_shorter_than_the_region_is_refused_rather_than_decoded() {
    let mut device = Device::new(Conduct::Unstages);
    assert_eq!(
        read_superblocks(CAPACITY_SECTORS, &mut device),
        Err(PreloadError::Unstaged {
            which: Which::Log,
            len: SUPERBLOCK_BYTES - SECTOR_SIZE,
        })
    );
}

#[test]
fn a_device_that_never_answers_parks_the_read_and_not_the_domain() {
    // The budget is what bounds this, and it is a constant of this crate's: the
    // device says nothing at all, so the loop must end by itself.
    let mut device = Device::new(Conduct::Silent);
    assert_eq!(
        read_superblocks(CAPACITY_SECTORS, &mut device),
        Err(PreloadError::Silent { which: Which::Log })
    );
}

#[test]
fn a_device_replaying_its_used_ring_neither_ends_the_wait_nor_extends_it_past_the_budget() {
    let mut device = Device::new(Conduct::Replays(3));
    let read = read_superblocks(CAPACITY_SECTORS, &mut device).expect("the read still lands");
    assert_eq!(read, [None, None]);
}

#[test]
fn an_extent_that_is_not_a_ring_on_this_device_is_named_before_a_sector_is_read() {
    // A device too small for the capture extent: the log's read still happens,
    // and the capture's is refused with the geometry that made it one.
    let (capture_start, _) = Which::Capture.extent();
    let mut device = Device::new(Conduct::Conforming);
    let error = read_superblocks(capture_start + 8, &mut device)
        .expect_err("the capture extent does not fit");
    assert!(matches!(
        error,
        PreloadError::Extent {
            which: Which::Capture,
            ..
        }
    ));
    assert_eq!(error.which(), Which::Capture);
    assert_eq!(device.submitted, vec![Job::Preload(Which::Log)]);
}

#[test]
fn every_refusal_names_the_recording_it_is_about() {
    // The console renders the extent's own first sector from this, so a variant
    // that lost the recording would render the wrong extent rather than fail.
    for which in Which::ALL {
        for error in [
            PreloadError::Refused { which },
            PreloadError::Silent { which },
            PreloadError::Misattributed { which },
            PreloadError::Failed { which },
            PreloadError::Short {
                which,
                delivered: 0,
            },
            PreloadError::Unstaged { which, len: 0 },
        ] {
            assert_eq!(error.which(), which, "{error:?}");
        }
    }
}
