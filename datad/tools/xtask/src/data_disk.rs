//! The second disk every QEMU run attaches, and the machine-observable contract
//! the recorder domain is judged against on it.
//!
//! # What this proves that a console line cannot
//!
//! A boot transcript saying `domain=recorder state=ready` is the appliance's own
//! account of itself. It is worth printing and it is not evidence: the record is
//! emitted by the very code whose conduct is in question, and a bring-up that
//! negotiated features with a device and never moved a byte through it would
//! produce the identical line. What settles the question is a file on the host
//! side of the emulation, written by the guest and read back by a process the
//! guest cannot reach.
//!
//! So the contract is a byte comparison against
//! [`lfw_blk::smoke::witness_pattern`] — the appliance's own definition of what
//! it writes, reached for rather than restated, so the two sides cannot come to
//! disagree about the pattern the way two copies of a constant do.
//!
//! # Why the image is seeded and then judged at a different sector
//!
//! The file is zero-filled and then a recognisable, *different* pattern is
//! written into sector 0 — the sector the appliance reads. That does two things.
//! It gives the probe something to find that is not zeroes, so a device that
//! answered every read out of the driver's own untouched staging window would be
//! reporting a leading word of zero rather than the seed. And it makes the
//! judged sector's content unambiguous: it is zeroes before the run and the
//! witness pattern after it, and nothing on the host wrote either.
//!
//! # No adversary
//!
//! This is build orchestration on the host side of an emulator; no threat-model
//! adversary is named for it. The guest composes every byte read back here —
//! that is the point — and two of the three judgements do parse what it wrote:
//! a superblock through the appliance's own decoder, and the payload as pcapng
//! by the lengths the payload itself states. So they are written the way a
//! reader of hostile bytes would write them, and for the reason stated for this
//! crate as a whole: a malformed extent is the case a failing gate exists to
//! report, and a harness that aborted on it would lose the report. The witness
//! sector alone is the comparison of 512 bytes against a constant.

use std::{
    fs::{File, OpenOptions},
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
    process::Command,
};

use lfw_blk::{
    SECTOR_SIZE,
    smoke::{WITNESS_SECTOR, witness_pattern},
};
use lfw_capture_ring::{SUPERBLOCK_BYTES, decode_superblock};
use lfw_recorder::deck::{Deck, SEGMENT_BYTES};

use crate::recording_contract;

/// How large the data device is, in bytes.
///
/// 64 MiB: far more than the two sectors this milestone touches, and enough for
/// the recording milestone to exercise a segmented ring with a wrap in it
/// without the file becoming something a build tree should not be creating.
const DATA_DISK_BYTES: u64 = 64 * 1024 * 1024;

/// The pattern seeded into sector 0 before boot.
///
/// Deliberately unlike [`witness_pattern`] in both its magic and its filler, so
/// a judged sector holding this one would be a finding rather than a pass — a
/// guest that copied the sector it read into the sector it was meant to compose
/// is exactly the confusion a single shared pattern would hide.
fn seed_pattern() -> [u8; SECTOR_SIZE] {
    let mut sector = [0u8; SECTOR_SIZE];
    for (at, byte) in sector.iter_mut().enumerate() {
        *byte = match at {
            0..8 => b"LFW-SEED"[at],
            _ => (at as u8).wrapping_mul(3).wrapping_add(1),
        };
    }
    sector
}

/// One run's data device: a raw image created fresh, attached to QEMU, and read
/// back afterwards.
///
/// One per run rather than one shared file, on the same terms as the run log and
/// the OVMF variable store beside it: a scenario must not be able to pass on a
/// sector some earlier scenario's guest wrote.
pub(crate) struct DataDisk {
    path: PathBuf,
}

impl DataDisk {
    /// Create the image for `run_label`, zero-filled with the seed pattern in
    /// sector 0, replacing any file left by an earlier run of the same label.
    ///
    /// # Errors
    /// Anything that stops the file being created at exactly its size.
    pub(crate) fn create(root: &Path, run_label: &str) -> Result<Self, String> {
        let path = root
            .join("build/image")
            .join(format!("data-{run_label}.img"));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let mut file =
            File::create(&path).map_err(|error| format!("create {}: {error}", path.display()))?;
        // `set_len` on a fresh file gives a sparse, zero-reading image, which is
        // what the judged sector must start as.
        file.set_len(DATA_DISK_BYTES)
            .map_err(|error| format!("size {}: {error}", path.display()))?;
        file.write_all(&seed_pattern())
            .map_err(|error| format!("seed {}: {error}", path.display()))?;
        file.sync_all()
            .map_err(|error| format!("flush {}: {error}", path.display()))?;
        Ok(Self { path })
    }

    /// Attach this image to a QEMU invocation as the modern virtio-blk device at
    /// 00:05.0.
    ///
    /// The PCI address is the whole of what joins this to the appliance: the
    /// system description grants `ecam3` at PCIEXBAR + (5 << 15), which is the
    /// configuration page of exactly this function, and the recorder domain
    /// holds that page and no other. `disable-legacy=on,disable-modern=off`
    /// because `lfw_blk` speaks virtio 1.0 and refuses a transitional device's
    /// legacy interface.
    pub(crate) fn attach(&self, command: &mut Command) {
        command
            .arg("-drive")
            .arg(format!(
                "if=none,id=data,format=raw,file={}",
                self.path.display()
            ))
            .args([
                "-device",
                "virtio-blk-pci,drive=data,bus=pcie.0,addr=05.0,\
                 disable-legacy=on,disable-modern=off",
            ]);
    }

    /// The sector the appliance is expected to have written.
    fn witness(&self) -> Result<[u8; SECTOR_SIZE], String> {
        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|error| format!("open {}: {error}", self.path.display()))?;
        let offset = WITNESS_SECTOR * SECTOR_SIZE as u64;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| format!("seek {} to {offset}: {error}", self.path.display()))?;
        let mut sector = [0u8; SECTOR_SIZE];
        file.read_exact(&mut sector)
            .map_err(|error| format!("read {} at {offset}: {error}", self.path.display()))?;
        Ok(sector)
    }

    /// Assert that the appliance committed its witness pattern, answering the
    /// evidence line for the run's summary.
    ///
    /// # Errors
    /// The sector holding anything else, named by what it holds instead: all
    /// zeroes is a guest that never wrote (the device was absent, the domain
    /// refused, or the write never left the staging window), the seed pattern is
    /// a guest that wrote back what it read, and anything else is a guest that
    /// wrote something this build does not recognise.
    pub(crate) fn judge_written(&self) -> Result<String, String> {
        let sector = self.witness()?;
        let expected = witness_pattern();
        if sector == expected {
            return Ok(format!(
                "the recorder's witness pattern is on the data disk at sector {WITNESS_SECTOR} \
                 ({SECTOR_SIZE} bytes, byte for byte)"
            ));
        }
        Err(format!(
            "the data disk's sector {WITNESS_SECTOR} does not hold the recorder's witness \
             pattern, so no byte is proved to have reached the medium: {}\n  \
             expected the first bytes {:02x?}\n  \
             found the first bytes    {:02x?}\n  \
             image: {}",
            diagnose(&sector),
            &expected[..16],
            &sector[..16],
            self.path.display()
        ))
    }

    /// Assert the opposite: that nothing wrote the sector at all.
    ///
    /// This is what turns the positive assertion above from a check into
    /// evidence. A halt scenario boots a disk with no bootable slot, so no
    /// protection domain runs — and the same file, attached the same way, must
    /// come back untouched. A harness whose positive assertion passed here too
    /// would be asserting something about the host and not about the guest.
    ///
    /// # Errors
    /// The sector holding anything at all.
    pub(crate) fn judge_untouched(&self) -> Result<String, String> {
        let sector = self.witness()?;
        if sector == [0u8; SECTOR_SIZE] {
            return Ok(format!(
                "the data disk's sector {WITNESS_SECTOR} is untouched, as a boot with no \
                 bootable slot owes"
            ));
        }
        Err(format!(
            "the data disk's sector {WITNESS_SECTOR} was written by a boot that reached no \
             protection domain: {}\n  image: {}",
            diagnose(&sector),
            self.path.display()
        ))
    }
}

impl DataDisk {
    /// Read the two recording extents straight off the image and assert that
    /// each identifies itself and parses as pcapng.
    ///
    /// This is the half of the recording contract the download path cannot
    /// give: a recorder that answered a plausible body out of its own memory
    /// would satisfy every HTTP client and leave the medium empty, and the only
    /// thing that notices is a process on the host side reading the file the
    /// guest wrote.
    ///
    /// # Errors
    /// A superblock that does not decode, one that claims nothing durable, an
    /// extent whose payload segments hold no walkable pcapng, or one the walk
    /// did not follow to exactly the byte the superblock's durable cursor
    /// names.
    pub(crate) fn judge_recordings(&self) -> Result<String, String> {
        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|error| format!("open {}: {error}", self.path.display()))?;
        let mut lines = Vec::new();
        for (start_sector, sectors) in Deck::extents() {
            let mut superblock = [0u8; SUPERBLOCK_BYTES];
            read_at(
                &mut file,
                start_sector * SECTOR_SIZE as u64,
                &mut superblock,
            )
            .map_err(|error| format!("read the superblock at sector {start_sector}: {error}"))?;
            let state = decode_superblock(&superblock).ok_or_else(|| {
                format!(
                    "the extent at sector {start_sector} carries no decodable superblock, so \
                     nothing on the disk says what the bytes after it are\n  image: {}",
                    self.path.display()
                )
            })?;
            if state.geometry().start_sector() != start_sector {
                return Err(format!(
                    "the superblock at sector {start_sector} describes an extent starting at {}",
                    state.geometry().start_sector()
                ));
            }
            // How far the walk must reach, off the disk rather than assumed.
            // The superblock records the *durable* cursor — where the recording
            // ends to anything holding the medium — so the payload's written
            // prefix is that cursor's segments plus its offset, exactly. Without
            // this bound the walk stops wherever the ring becomes unwritten and
            // reports a pass, so a recorder that wrote one valid segment and
            // then garbage would satisfy every other assertion here.
            let durable = durable_payload_bytes(&state).ok_or_else(|| {
                format!(
                    "the superblock at sector {start_sector} places its durable cursor at \
                     segment {} of {}, past the first wrap. This walk reads the payload in \
                     device order, which is write order only until the ring wraps, so it cannot \
                     state where the recording ends — extend it before a run gets this far\n  \
                     image: {}",
                    state.writer().sequence,
                    state.geometry().segments(),
                    self.path.display()
                )
            })?;
            if durable == 0 {
                return Err(format!(
                    "the superblock at sector {start_sector} says no byte of the recording is \
                     durable, so nothing the appliance composed reached the medium\n  image: {}",
                    self.path.display()
                ));
            }
            // Past segment 0, which holds the superblock and no record.
            let segment_sectors = (SEGMENT_BYTES / SECTOR_SIZE) as u64;
            let payload_sectors = sectors.saturating_sub(segment_sectors);
            let mut payload = vec![0u8; payload_sectors as usize * SECTOR_SIZE];
            read_at(
                &mut file,
                (start_sector + segment_sectors) * SECTOR_SIZE as u64,
                &mut payload,
            )
            .map_err(|error| format!("read the extent at sector {start_sector}: {error}"))?;
            let parsed = recording_contract::parse(&payload).map_err(|error| {
                format!(
                    "the extent at sector {start_sector} is not a pcapng recording: {error}\n  \
                     image: {}",
                    self.path.display()
                )
            })?;
            // The superblock must never claim more than is there, and it may
            // claim less: a checkpoint sits behind a device barrier, so between
            // a payload write completing and its superblock going out the
            // written prefix is legitimately ahead of the durable cursor. An
            // extent that overstated would send a reader into bytes that were
            // never written, which is the direction the barrier exists to make
            // impossible; understating costs a reader the last staging buffer.
            if durable > parsed.consumed {
                return Err(format!(
                    "the superblock at sector {start_sector} claims a durable end at payload byte \
                     {durable} and the block walk followed the extent's own lengths only to byte \
                     {}, so the superblock names bytes that never reached the medium\n  image: {}",
                    parsed.consumed,
                    self.path.display()
                ));
            }
            // And the walk's end must be the end of what was written, not
            // wherever parsing gave up. Nothing seeded this image past the
            // superblock, so every byte beyond the written prefix is zero — a
            // recorder that wrote one valid segment and then garbage stops the
            // walk at the segment and is caught here rather than passing.
            if let Some(tail) = payload.get(parsed.consumed..)
                && let Some(at) = tail.iter().position(|byte| *byte != 0)
            {
                return Err(format!(
                    "the extent at sector {start_sector} holds a non-zero byte at payload offset \
                     {} — past the byte {} the block walk reached — so what is on the medium is \
                     not one walkable recording\n  image: {}",
                    parsed.consumed + at,
                    parsed.consumed,
                    self.path.display()
                ));
            }
            if parsed.packets.is_empty() {
                return Err(format!(
                    "the extent at sector {start_sector} parses and holds no packet block, so \
                     nothing was recorded on the medium\n  image: {}",
                    self.path.display()
                ));
            }
            lines.push(format!(
                "  sector {start_sector}: superblock generation {}, {} section header(s), {} \
                 packet block(s); durable end at payload byte {durable}, written prefix ending at \
                 {} ({} byte(s) awaiting a checkpoint), nothing written beyond it",
                state.write_generation(),
                parsed.sections,
                parsed.packets.len(),
                parsed.consumed,
                parsed.consumed - durable,
            ));
        }
        Ok(format!(
            "both recording extents, read off the disk image after shutdown:\n{}",
            lines.join("\n")
        ))
    }
}

/// How many bytes of the payload area the superblock's durable cursor accounts
/// for, or `None` where the ring has wrapped and the answer is not a prefix.
///
/// The payload area is read as one contiguous run of segments in device order,
/// and payload segment `sequence % segments` is where sequence `sequence` sits —
/// so until the first wrap the durable bytes are the prefix
/// `sequence * segment_bytes + offset`, and after it they are not a prefix of
/// anything: the segments ahead of the open one still hold the previous wrap.
/// `None` rather than a weaker bound, because a bound that admits stale bytes is
/// the hole this function exists to close.
fn durable_payload_bytes(state: &lfw_capture_ring::RingState) -> Option<usize> {
    let geometry = state.geometry();
    let cursor = state.writer();
    if cursor.sequence >= geometry.segments() {
        return None;
    }
    let segments = usize::try_from(cursor.sequence).ok()?;
    segments
        .checked_mul(geometry.segment_bytes())?
        .checked_add(cursor.offset)
}

/// Read exactly `into.len()` bytes at `offset`.
fn read_at(file: &mut File, offset: u64, into: &mut [u8]) -> Result<(), String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| format!("seek to {offset}: {error}"))?;
    file.read_exact(into)
        .map_err(|error| format!("read {} bytes at {offset}: {error}", into.len()))
}

/// What a sector that is not the witness pattern is, in the three shapes worth
/// naming apart.
fn diagnose(sector: &[u8; SECTOR_SIZE]) -> &'static str {
    if *sector == [0u8; SECTOR_SIZE] {
        "it is still zeroes, so nothing wrote it"
    } else if *sector == seed_pattern() {
        "it holds the seed pattern this harness put in sector 0, so something copied a sector \
         rather than composing one"
    } else {
        "it holds bytes this build does not recognise"
    }
}

#[cfg(test)]
mod tests;
