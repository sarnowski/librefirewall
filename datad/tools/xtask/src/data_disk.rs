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
use lfw_recorder::deck::{Deck, LOG_START_SECTOR, SEGMENT_BYTES};

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

/// What one recording extent held **before** a boot that inherits the medium.
///
/// Captured on the host side, from the file, so the claim the boot after it is
/// held to is about the disk and not about anything the guest said.
struct Inherited {
    start_sector: u64,
    state: lfw_capture_ring::RingState,
    /// The payload bytes the superblock's durable cursor accounted for, which is
    /// exactly the prefix a reader holding this disk would have been promised.
    /// It is what a boot that started the ring over would have written on.
    durable: Vec<u8>,
}

/// One run's data device: a raw image created fresh — or the one an earlier
/// boot left — attached to QEMU, and read back afterwards.
///
/// Fresh per run by default, on the same terms as the run log and the OVMF
/// variable store beside it: a scenario must not be able to pass on a sector some
/// earlier scenario's guest wrote. The exception is the boot whose whole subject
/// **is** the medium: a recording that did not survive a reboot is not a
/// recording, so the only way to judge one is to boot the same file twice and
/// hold the second boot's answer to what the first left — which means one file
/// outliving one invocation, deliberately, and a scenario saying so
/// ([`DataMedium`]).
///
/// [`DataMedium`]: crate::qemu::DataMedium
pub(crate) struct DataDisk {
    path: PathBuf,
    /// What each extent held going into this boot, on a boot that inherits the
    /// medium; empty on every boot that made its own.
    inherited: Vec<Inherited>,
}

impl DataDisk {
    /// Create the image for `run_label`, zero-filled with the seed pattern in
    /// sector 0, replacing any file left by an earlier run of the same label.
    ///
    /// # Errors
    /// Anything that stops the file being created at exactly its size.
    pub(crate) fn create(root: &Path, run_label: &str) -> Result<Self, String> {
        let path = Self::path_for(root, run_label);
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
        Ok(Self {
            path,
            inherited: Vec::new(),
        })
    }

    fn path_for(root: &Path, label: &str) -> PathBuf {
        root.join("build/image").join(format!("data-{label}.img"))
    }

    /// The medium an earlier boot left behind — the file itself, not a copy —
    /// for the scenario whose whole subject is that a recording survives a
    /// reboot.
    ///
    /// A copy would prove nothing: the claim is about one medium read twice, and
    /// the second reading has to be of the bytes the first left. What each extent
    /// held is captured here, before the boot, because afterwards there is
    /// nothing to compare against — a boot that started the rings over leaves a
    /// medium that is internally consistent and has lost the evidence.
    ///
    /// # Errors
    /// The file not being there, which names the boot that was supposed to leave
    /// it; and an extent that carries no decodable superblock, which would make
    /// the resumption this boot is judged on vacuously true.
    pub(crate) fn carried(root: &Path, source_label: &str) -> Result<Self, String> {
        let path = Self::path_for(root, source_label);
        if !path.exists() {
            return Err(format!(
                "the data medium {} is not there, and this boot's whole subject is resuming the \
                 recordings the {source_label} boot left on it. On a full run that means the two \
                 scenarios are out of order — the boot that writes the medium must precede the \
                 one that resumes it. On a diagnostic re-run of this scenario alone it is \
                 expected: the writing boot is a different scenario and was not re-run, so run \
                 the pair",
                path.display()
            ));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|error| format!("open {}: {error}", path.display()))?;
        let mut inherited = Vec::new();
        for (start_sector, _) in Deck::extents() {
            let mut superblock = [0u8; SUPERBLOCK_BYTES];
            read_at(
                &mut file,
                start_sector * SECTOR_SIZE as u64,
                &mut superblock,
            )
            .map_err(|error| format!("read the superblock at sector {start_sector}: {error}"))?;
            let state = decode_superblock(&superblock).ok_or_else(|| {
                format!(
                    "the extent at sector {start_sector} of {} carries no decodable superblock, \
                     so this boot would have nothing to resume and the claim it is judged on \
                     would be vacuously true",
                    path.display()
                )
            })?;
            let durable = durable_payload_bytes(&state).ok_or_else(|| {
                format!(
                    "the extent at sector {start_sector} places its durable cursor past the \
                     first wrap, and this comparison reads the payload in device order — extend \
                     it before a run gets this far"
                )
            })?;
            if durable == 0 {
                return Err(format!(
                    "the extent at sector {start_sector} of {} says no byte of its recording is \
                     durable, so there is nothing for the boot after it to preserve and the \
                     comparison would hold whatever that boot did",
                    path.display()
                ));
            }
            let mut payload = vec![0u8; durable];
            let segment_sectors = (SEGMENT_BYTES / SECTOR_SIZE) as u64;
            read_at(
                &mut file,
                (start_sector + segment_sectors) * SECTOR_SIZE as u64,
                &mut payload,
            )
            .map_err(|error| format!("read the extent at sector {start_sector}: {error}"))?;
            inherited.push(Inherited {
                start_sector,
                state,
                durable: payload,
            });
        }
        Ok(Self { path, inherited })
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
    /// **The walk begins at payload byte zero on every medium**, carried or not.
    /// A boot that resumed picked the recording up at the byte its predecessor
    /// stopped on — a block boundary, because what the device takes always ends
    /// on one — and opened a pcapng section there, so the whole extent is one
    /// walkable stream across every boot that ever wrote it. Starting anywhere
    /// later would be this harness declining to read the join it exists to
    /// judge.
    ///
    /// `conversations` says whether this boot opened one, which decides what the
    /// **history** extent owes and nothing else. A conversation is opened by a
    /// packet the appliance decided to carry, so a boot that carried none wrote
    /// no history — and requiring a record there would turn the correct behaviour
    /// of an appliance nobody has onboarded into a failure. The capture extent
    /// owes its records either way: a refusal is a decision, and a boot that
    /// refused everything decided as many times as one that forwarded.
    ///
    /// # Errors
    /// A superblock that does not decode, one that claims nothing durable, an
    /// extent whose payload segments hold no walkable pcapng, one the walk did
    /// not follow to exactly the byte the superblock's durable cursor names, or
    /// an extent that holds no packet block where this boot owed one.
    pub(crate) fn judge_recordings(&self, conversations: bool) -> Result<String, String> {
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
            // Past segment 0, which holds the superblock and no record, and no
            // further: every boot that ever wrote this extent appended to the
            // one stream that starts here, so the walk below crosses each
            // resume join rather than beginning after it.
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
            let Some(awaiting_checkpoint) = parsed.consumed.checked_sub(durable) else {
                return Err(format!(
                    "the superblock at sector {start_sector} claims a durable end at payload byte \
                     {durable} and the block walk followed the extent's own lengths only to byte \
                     {}, so the superblock names bytes that never reached the medium\n  image: {}",
                    parsed.consumed,
                    self.path.display()
                ));
            };
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
            // The history extent alone may be legitimately empty, and only on a
            // boot that carried nothing: its records are conversations, and an
            // appliance that forwarded no packet opened none. Every other extent,
            // and this one on every boot that did carry traffic, must hold a
            // record — an empty extent is otherwise a recorder that never reached
            // the medium, which looks exactly like a healthy node from here.
            let may_be_empty = !conversations && start_sector == LOG_START_SECTOR;
            if parsed.packets.is_empty() && !may_be_empty {
                return Err(format!(
                    "the extent at sector {start_sector} parses and holds no packet block, so \
                     nothing was recorded on the medium\n  image: {}",
                    self.path.display()
                ));
            }
            lines.push(format!(
                "  sector {start_sector}: superblock generation {}, {} section header(s), {} \
                 packet block(s); durable end at payload byte {durable}, written prefix ending \
                 at {} ({awaiting_checkpoint} byte(s) awaiting a checkpoint), nothing written \
                 beyond it",
                state.write_generation(),
                parsed.sections,
                parsed.packets.len(),
                parsed.consumed,
            ));
        }
        Ok(format!(
            "both recording extents, read off the disk image after shutdown:\n{}",
            lines.join("\n")
        ))
    }

    /// What each extent already held **going into** this boot, parsed — in
    /// [`Deck::extents`]'s order, which is the connection history and then the
    /// capture. Empty on a boot that made its own medium.
    ///
    /// A recording outlives the node, so a download taken during a boot that
    /// resumed one answers earlier boots' records as well as this boot's, while
    /// every counter the appliance publishes is this boot's alone. What tells
    /// the two apart is this: the durable prefix read off the file before QEMU
    /// was started is exactly the part of the download that is not this boot's
    /// doing, so a contract holding the recordings to the exposition can
    /// subtract it and stay exact instead of standing down on a carried medium.
    ///
    /// # Errors
    /// An inherited prefix that does not parse as pcapng, which would leave
    /// whatever is subtracted from it meaningless.
    pub(crate) fn carried_recordings(&self) -> Result<Vec<recording_contract::Parsed>, String> {
        let mut carried = Vec::new();
        for held in &self.inherited {
            let start_sector = held.start_sector;
            let parsed = recording_contract::parse(&held.durable).map_err(|error| {
                format!(
                    "the {} inherited byte(s) at sector {start_sector} are not a pcapng \
                     recording: {error}\n  image: {}",
                    held.durable.len(),
                    self.path.display()
                )
            })?;
            if parsed.consumed != held.durable.len() {
                return Err(format!(
                    "the extent at sector {start_sector} went into this boot with {} durable \
                     byte(s) of which the block walk followed the extent's own lengths only to \
                     {}, so what this boot inherited is not a whole number of blocks and nothing \
                     can be counted out of it\n  image: {}",
                    held.durable.len(),
                    parsed.consumed,
                    self.path.display()
                ));
            }
            carried.push(parsed);
        }
        Ok(carried)
    }
}

impl DataDisk {
    /// Assert that a boot which inherited this medium **continued** each
    /// recording instead of starting it over, and said so on the console.
    ///
    /// `Ok(None)` on every boot that made its own medium, which is every boot
    /// but the one whose subject is the reboot.
    ///
    /// # Two halves, and neither is the other
    ///
    /// The disk half is the one that cannot be faked from inside the guest: the
    /// bytes the previous boot made durable are compared byte for byte against
    /// what is there now, and the superblock's generation and writer sequence
    /// must both have advanced past what they were. A recorder that started the
    /// ring over satisfies every console assertion — it comes up, it records, it
    /// checkpoints — and fails here on the first segment, which is exactly where
    /// it would have written.
    ///
    /// The console half is the one the disk cannot give: an operator with no
    /// shell learns whether a reboot kept the evidence only from what the node
    /// said, so the record has to be there and its numbers have to be the ones
    /// this harness read off the medium before the boot. A node that resumed
    /// silently would leave a deployment unable to tell this case from the
    /// defect.
    ///
    /// # Errors
    /// A recording that did not resume, one whose console record is missing or
    /// carries numbers the medium does not bear out, a generation or write
    /// position that did not advance, or any byte of the inherited prefix that
    /// moved.
    pub(crate) fn judge_resumed(&self, serial: &[u8]) -> Result<Option<String>, String> {
        if self.inherited.is_empty() {
            return Ok(None);
        }
        let transcript = String::from_utf8_lossy(serial);
        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|error| format!("open {}: {error}", self.path.display()))?;
        let mut lines = Vec::new();
        for held in &self.inherited {
            let start_sector = held.start_sector;
            let before = &held.state;

            // What the node said, before what the disk shows: a resumption
            // nobody can read off the console is one a deployment cannot act on.
            let record = format!(
                " recording-start={start_sector} recording=resumed recording-generation={} \
                 recording-sequence={} recording-offset={}",
                before.write_generation(),
                before.writer().sequence,
                before.writer().offset,
            );
            if !transcript.contains(&record) {
                return Err(format!(
                    "the console does not carry \"{}\" for the extent at sector {start_sector}. \
                     The medium held generation {} at writer sequence {} going into this boot, so \
                     that is what a resuming node owes an operator — and a node with no shell has \
                     no other way to say it{}",
                    record.trim(),
                    before.write_generation(),
                    before.writer().sequence,
                    fresh_hint(&transcript, start_sector),
                ));
            }

            let mut superblock = [0u8; SUPERBLOCK_BYTES];
            read_at(
                &mut file,
                start_sector * SECTOR_SIZE as u64,
                &mut superblock,
            )
            .map_err(|error| format!("read the superblock at sector {start_sector}: {error}"))?;
            let after = decode_superblock(&superblock).ok_or_else(|| {
                format!("the extent at sector {start_sector} lost its superblock over this boot")
            })?;
            if after.write_generation() <= before.write_generation() {
                return Err(format!(
                    "the extent at sector {start_sector} came out of this boot at generation {} \
                     and went into it at {}. A resumed ring checkpoints past the generation it \
                     adopted, so one that did not is a ring that was written afresh",
                    after.write_generation(),
                    before.write_generation()
                ));
            }
            let went_in = position_of(before.writer());
            let came_out = position_of(after.writer());
            if came_out <= went_in {
                return Err(format!(
                    "the extent at sector {start_sector} came out of this boot writing position \
                     {came_out} and went into it at {went_in}. A resumed recording picks up at the \
                     byte the medium named and appends past it, so a position that did not advance \
                     is a boot that wrote nothing of its own"
                ));
            }

            // And the bytes themselves: the prefix the previous boot made
            // durable, still where it put them.
            let mut payload = vec![0u8; held.durable.len()];
            let segment_sectors = (SEGMENT_BYTES / SECTOR_SIZE) as u64;
            read_at(
                &mut file,
                (start_sector + segment_sectors) * SECTOR_SIZE as u64,
                &mut payload,
            )
            .map_err(|error| format!("read the extent at sector {start_sector}: {error}"))?;
            if let Some(at) = payload
                .iter()
                .zip(&held.durable)
                .position(|(now, before)| now != before)
            {
                return Err(format!(
                    "the extent at sector {start_sector} lost the recording it carried: payload \
                     byte {at} of the {} the previous boot had made durable was overwritten by \
                     this one. That is the defect a resumed ring exists to prevent — a reboot \
                     that starts a fresh ring over a customer's evidence\n  image: {}",
                    held.durable.len(),
                    self.path.display()
                ));
            }
            lines.push(format!(
                "  sector {start_sector}: resumed at generation {} position {went_in}, now at \
                 generation {} position {came_out}; the {} byte(s) the previous boot made durable \
                 are byte for byte where it left them",
                before.write_generation(),
                after.write_generation(),
                held.durable.len(),
            ));
        }
        Ok(Some(format!(
            "both recordings survived the reboot, as the console said and the disk shows:\n{}",
            lines.join("\n")
        )))
    }
}

/// A writer cursor as one number in the ring's own append space, which is what
/// a boot advances along whether or not it crosses a segment.
fn position_of(cursor: lfw_capture_ring::Cursor) -> u64 {
    cursor
        .sequence
        .saturating_mul(SEGMENT_BYTES as u64)
        .saturating_add(cursor.offset as u64)
}

/// What to add to a missing-resumption message when the node said the opposite,
/// which is the whole defect this pair of boots exists to catch.
fn fresh_hint(transcript: &str, start_sector: u64) -> String {
    let fresh = format!(" recording-start={start_sector} recording=fresh");
    if transcript.contains(&fresh) {
        return format!(
            ". The console says \"{}\" instead, so this boot started the recording over rather \
             than continuing it",
            fresh.trim()
        );
    }
    String::new()
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

/// How large the store device is, in bytes.
///
/// One mebibyte, which is the medium `lfw_store`'s layout is sized against: the
/// state record, the reset-request sector and the eight configuration slots come
/// to [`lfw_store::STORE_SECTORS`], and everything past that is deliberately
/// unused. Made exactly one mebibyte rather than exactly the layout, so a sector
/// the appliance is *not* meant to touch exists to be found untouched.
const STORE_DISK_BYTES: u64 = 1024 * 1024;

/// One run's store device: the medium the appliance's own identity lives on.
///
/// # Why this is not a second [`DataDisk`]
///
/// The recorder's disk is created fresh for every invocation, and it must be: a
/// scenario must not be able to pass on a witness sector some earlier guest
/// wrote. The store's is the opposite kind of object. An identity that did not
/// survive a reboot is not an identity, so the only way to judge one is to boot
/// the *same medium* twice and hold the second boot's answer to the first's —
/// which means one file outliving one invocation, deliberately, and a scenario
/// saying so ([`StoreMedium`]).
///
/// # What the host may say about the contents, and what it may not
///
/// Almost nothing is read, and that is deliberate: the medium carries the
/// appliance's private scalar in plaintext, and a harness that parsed it would be
/// a second place that had to be trusted not to print one. What the gate compares
/// is the console records the boots produced — the public name and the public-key
/// fingerprint — which is exactly what an administrator compares.
///
/// The one exception is a **factory reset**, and it is an exception because no
/// console record can stand in for it. A boot that reported a reset and left the
/// old key on the medium produces the identical transcript, and the changed state
/// record proves nothing either — re-minting changes it whatever the reset did. So
/// the erasure is proved the only way it can be: the scalar's window is captured
/// off the medium *before* the reset boot, and afterwards the whole medium is
/// required to hold **zero** occurrences of it. That needle is a private key. It
/// is held in memory for the length of one scenario, is never written anywhere,
/// and is never rendered: a surviving occurrence is reported as an **offset**, and
/// the failure message that names it carries no byte of it.
///
/// [`StoreMedium`]: crate::qemu::StoreMedium
pub(crate) struct StoreDisk {
    path: PathBuf,
    /// The private scalar this medium held before a factory-reset boot, which that
    /// boot must leave nowhere on it. `None` on every other boot, which is every
    /// boot that is not proving an erasure.
    ///
    /// **Never printed, never written, never derived from.** It exists to be
    /// searched for and to be absent.
    erased_secret: Option<[u8; lfw_store::SECRET_LEN]>,
    /// The scalar the medium holds going *into* this boot, on a boot that is
    /// meant to keep it and use it.
    ///
    /// [`Self::erased_secret`]'s opposite question, and its own field for that
    /// reason: one boot must destroy this key and one must sign with it, so a
    /// single field would have one verdict standing in for two claims. What this
    /// one is scanned against is not the medium — the key belongs there — but the
    /// **console**, which is the one surface the domain that borrows it writes.
    live_secret: Option<[u8; lfw_store::SECRET_LEN]>,
}

impl StoreDisk {
    /// Create a fresh medium for `run_label`, replacing any file an earlier run
    /// of the same label left.
    ///
    /// Zero-filled and nothing else — no seed pattern, unlike the recorder's
    /// disk. A zeroed medium is what `lfw_store::decode_state` reads as "no
    /// record", so this is the state a first boot must mint from, and putting a
    /// recognisable pattern in sector 0 would put it inside the state record's
    /// first copy and make the medium a *malformed* record rather than an absent
    /// one. Those are two different boots.
    ///
    /// # Errors
    /// Anything that stops the file being created at exactly its size.
    pub(crate) fn create(root: &Path, run_label: &str) -> Result<Self, String> {
        let path = Self::path_for(root, run_label);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let file =
            File::create(&path).map_err(|error| format!("create {}: {error}", path.display()))?;
        file.set_len(STORE_DISK_BYTES)
            .map_err(|error| format!("size {}: {error}", path.display()))?;
        file.sync_all()
            .map_err(|error| format!("flush {}: {error}", path.display()))?;
        Ok(Self {
            path,
            erased_secret: None,
            live_secret: None,
        })
    }

    /// The medium an earlier boot left behind, for a scenario whose whole subject
    /// is that an identity survives a reboot.
    ///
    /// # Errors
    /// The file not being there, which names the boot that was supposed to leave
    /// it. On a full run that is a scenario ordering defect; on a diagnostic
    /// re-run of this scenario alone it is expected, because the boot that mints
    /// the medium is a different scenario and was not re-run — so the message
    /// says both.
    pub(crate) fn carried(root: &Path, source_label: &str) -> Result<Self, String> {
        let path = Self::path_for(root, source_label);
        if !path.exists() {
            return Err(format!(
                "the store medium {} is not there, and this boot's whole subject is reloading the \
                 identity the {source_label} boot minted on it. On a full run that means the two \
                 scenarios are out of order — the boot that mints the medium must precede the one \
                 that reloads it. On a diagnostic re-run of this scenario alone it is expected: \
                 the minting boot is a different scenario and was not re-run, so run the pair",
                path.display()
            ));
        }
        // The key this boot will reload and sign with, captured for the console
        // scan below. A medium whose window is all zeroes is not refused here,
        // unlike the reset path's: this boot's subject is the reload, and the scan
        // reports having proved nothing rather than failing a boot for it.
        let live = Self::secret_window(&path)
            .ok()
            .filter(|secret| *secret != [0u8; lfw_store::SECRET_LEN]);
        Ok(Self {
            path,
            erased_secret: None,
            live_secret: live,
        })
    }

    /// A **copy** of the medium an earlier boot left, made for `run_label` alone,
    /// for a scenario that needs an appliance somebody already owns rather than a
    /// claim about the medium itself.
    ///
    /// # Why this is not [`Self::carried`]
    ///
    /// That one hands the boot the source's own file, because its whole subject is
    /// one medium read twice and a copy would prove nothing about persistence.
    /// This one exists for the opposite reason: an appliance in service was
    /// onboarded once and has been running ever since, so nearly every scenario
    /// wants to boot an owned node without its subject being ownership at all. Nine
    /// teen boots taking the source's own file would be nineteen boots writing to
    /// it, and a scenario could then pass on state a later one reads — the defect
    /// the recorder's disk is created fresh to avoid. A copy per boot gives each
    /// the same starting medium and lets none of them see another's writes.
    ///
    /// Nothing is read out of the bytes here, unlike the two above: neither claim
    /// this medium supports is about its contents. That the copy really did carry
    /// an owner is stated where an operator would state it — the forwarding
    /// domain's own console record, which every boot is held to.
    ///
    /// # Errors
    /// The source not being there, on [`Self::carried`]'s terms, and anything that
    /// stops the copy being written.
    pub(crate) fn copied(root: &Path, source_label: &str, run_label: &str) -> Result<Self, String> {
        let from = Self::path_for(root, source_label);
        if !from.exists() {
            return Err(format!(
                "the store medium {} is not there, and this boot needs the appliance the \
                 {source_label} boot left owned. On a full run that means the two scenarios are \
                 out of order — the boot that takes an owner must precede every boot that copies \
                 it. On a diagnostic re-run of this scenario alone it is expected: the boot that \
                 was onboarded is a different scenario and was not re-run, so run the pair",
                from.display()
            ));
        }
        let path = Self::path_for(root, run_label);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        // Refused rather than silently made a no-op: a scenario copying from
        // itself would boot whatever its own previous run left, which is the one
        // way this call can hand a boot a medium no source decided.
        if path == from {
            return Err(format!(
                "the store medium {} is both the source and the destination of a copy, so this \
                 boot would attach whatever its own previous run left rather than the medium \
                 {source_label} left",
                path.display()
            ));
        }
        std::fs::copy(&from, &path)
            .map_err(|error| format!("copy {} to {}: {error}", from.display(), path.display()))?;
        Ok(Self {
            path,
            erased_secret: None,
            // Not scanned for: this boot signs with the key it inherits like any
            // owned appliance, and the console scan the reload path performs is
            // that scenario's claim rather than a property of every boot that
            // happens to carry a key.
            live_secret: None,
        })
    }

    /// The 32-byte private-scalar window of the first copy of the state record.
    ///
    /// Positional rather than decoded, on `lfw_store::stored_secret_window`'s
    /// terms: it must work on a medium whose record this build would refuse, since
    /// that is one of the states a proof about the bytes has to cover.
    fn secret_window(path: &Path) -> Result<[u8; lfw_store::SECRET_LEN], String> {
        let mut file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|error| format!("open {}: {error}", path.display()))?;
        let mut region = [0u8; 2 * lfw_store::STATE_COPY_BYTES];
        read_at(&mut file, 0, &mut region)
            .map_err(|error| format!("read the state record: {error}"))?;
        Ok(lfw_store::stored_secret_window(&region))
    }

    /// The medium an earlier boot left behind, with a **factory-reset request**
    /// written onto it, for the one scenario whose subject is the appliance giving
    /// up its owner.
    ///
    /// This is the whole of how a reset is asked for: there is no channel
    /// operation, no configuration document and no console input that can invoke
    /// one, because a reset revokes a management plane's ownership and must not be
    /// reachable by one. What is left is possession of the medium, which for a
    /// harness means a write to one sector of a file — and the request written is
    /// `lfw_store::reset_token`, the appliance's own definition of it, so the two
    /// sides cannot come to disagree about the pattern the way two copies of a
    /// constant do.
    ///
    /// The scalar the medium currently holds is captured here, before the boot
    /// that must destroy it. See the type's own header for why that capture is
    /// necessary and what is done to keep it harmless.
    ///
    /// # Errors
    /// The file not being there, on [`Self::carried`]'s terms; anything that stops
    /// the sector being written; and a medium whose scalar window is all zeroes,
    /// which would make the erasure proof vacuously true.
    pub(crate) fn reset_requested(root: &Path, source_label: &str) -> Result<Self, String> {
        let carried = Self::carried(root, source_label)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&carried.path)
            .map_err(|error| format!("open {}: {error}", carried.path.display()))?;

        let mut region = [0u8; 2 * lfw_store::STATE_COPY_BYTES];
        read_at(&mut file, 0, &mut region)
            .map_err(|error| format!("read the state record: {error}"))?;
        let secret = lfw_store::stored_secret_window(&region);
        if secret == [0u8; lfw_store::SECRET_LEN] {
            return Err(format!(
                "the store medium {} carries no scalar in its first copy of the state record, so                  requiring a reset to erase it would prove nothing — every byte of the window is                  already zero. Either the boot that was to mint on this medium did not, or the                  record's layout moved and this window is no longer the one that holds the key",
                carried.path.display()
            ));
        }

        let offset = lfw_store::RESET_REQUEST_SECTOR * SECTOR_SIZE as u64;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| format!("seek {} to {offset}: {error}", carried.path.display()))?;
        file.write_all(&lfw_store::reset_token())
            .map_err(|error| format!("request a reset on {}: {error}", carried.path.display()))?;
        file.sync_all()
            .map_err(|error| format!("flush {}: {error}", carried.path.display()))?;
        Ok(Self {
            erased_secret: Some(secret),
            // Not both: this boot destroys the key rather than signing with it, so
            // the console scan below has no live key to be asked about.
            live_secret: None,
            ..carried
        })
    }

    fn path_for(root: &Path, label: &str) -> PathBuf {
        root.join("build/image").join(format!("store-{label}.img"))
    }

    /// Attach this image to a QEMU invocation as the modern virtio-blk device at
    /// 00:06.0.
    ///
    /// The PCI address is the whole of what joins this to the appliance: the
    /// system description grants `ecam4` at PCIEXBAR + (6 << 15), which is the
    /// configuration page of exactly this function, and the store domain holds
    /// that page and no other. One slot past the recorder's `05.0`, so the two
    /// block devices are two authorities rather than two views of one.
    pub(crate) fn attach(&self, command: &mut Command) {
        command
            .arg("-drive")
            .arg(format!(
                "if=none,id=store,format=raw,file={}",
                self.path.display()
            ))
            .args([
                "-device",
                "virtio-blk-pci,drive=store,bus=pcie.0,addr=06.0,\
                 disable-legacy=on,disable-modern=off",
            ]);
    }

    /// Assert the medium is no longer the zeroes it was made as — the one thing
    /// about it the host may say without reading what it holds.
    ///
    /// This is the counterpart of the recorder's witness assertion and it is
    /// deliberately weaker: the recorder writes a *published constant* and the
    /// store writes an identity, so there is nothing here to compare against.
    /// What it establishes is the half a console record cannot: bytes reached the
    /// medium at all, so a domain that composed a record and never got it past
    /// the staging window is caught rather than believed. The record's *content*
    /// is judged where an administrator judges it — on the console, across two
    /// boots.
    ///
    /// It reads the first sixteen bytes: the magic and the version, which are the
    /// only fields of this medium that are not the appliance's secret or derived
    /// from it. On a boot proving a factory reset the whole medium is read as well,
    /// and [`Self::judge_secret_erased`] is where that happens and why.
    ///
    /// # Errors
    /// The leading bytes being zero, which is a medium nothing wrote.
    pub(crate) fn judge_written(&self) -> Result<String, String> {
        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|error| format!("open {}: {error}", self.path.display()))?;
        let mut leading = [0u8; 16];
        file.read_exact(&mut leading)
            .map_err(|error| format!("read {}: {error}", self.path.display()))?;
        let magic = lfw_store::STATE_MAGIC.to_le_bytes();
        if leading[..8] != magic {
            return Err(format!(
                "the store medium's first sector does not open with the state record's magic, so \
                 nothing the store domain composed reached the medium\n  \
                 expected the first bytes {:02x?}\n  \
                 found the first bytes    {:02x?}\n  image: {}",
                magic,
                &leading[..8],
                self.path.display()
            ));
        }
        let version = u32::from_le_bytes([leading[8], leading[9], leading[10], leading[11]]);
        if version != lfw_store::STATE_VERSION {
            return Err(format!(
                "the store medium carries record version {version} and this build writes {}\n  \
                 image: {}",
                lfw_store::STATE_VERSION,
                self.path.display()
            ));
        }
        Ok(format!(
            "the store medium's first sector opens with the state record's magic and version \
             {version}, so the identity reached the medium ({})",
            self.path.display()
        ))
    }

    /// Assert that the scalar this boot **signs with** occurs nowhere in what it
    /// said.
    ///
    /// `Ok(None)` on every boot that captured no live key, which is every boot but
    /// the one that reloads a medium an earlier boot minted.
    ///
    /// # What this proves and what it deliberately does not
    ///
    /// The appliance's private key is held by one protection domain and *borrowed*
    /// by another: the domain that authenticates asks for a signature over two
    /// shared regions rather than holding the scalar. Two things establish that the
    /// scalar cannot cross — the ABI has no field it fits in, and the reply region
    /// has exactly one writer — and both are compile-time and build-time facts
    /// rather than observations. Neither is checkable from here, because those
    /// regions are guest RAM: nothing writes them to a file this harness can read,
    /// and QEMU is not asked to dump memory. So the region argument stands on the
    /// grants (`xtask::sysdesc`) and the types (`wire::signing`), and is not
    /// restated here.
    ///
    /// **What is checkable is the surface**, and it is worth checking on exactly
    /// this boot: the key is live, the delegation runs, and the borrowing domain
    /// signs with it twice — once for its own proof and once inside a handshake —
    /// and then writes records about having done so. If any of that leaked the
    /// scalar to an operator-visible place, this is the boot and the console is the
    /// place. Zero occurrences over the whole capture is the whole answer.
    ///
    /// # Errors
    /// Any occurrence, reported by **offset**: the needle is a private key and
    /// reaches no message this function writes.
    pub(crate) fn judge_secret_off_the_console(
        &self,
        serial: &[u8],
    ) -> Result<Option<String>, String> {
        let Some(needle) = self.live_secret else {
            return Ok(None);
        };
        let found: Vec<usize> = serial
            .windows(needle.len())
            .enumerate()
            .filter(|(_, window)| *window == needle)
            .map(|(at, _)| at)
            .collect();
        if !found.is_empty() {
            return Err(format!(
                "the {}-byte private scalar this appliance signs with occurs in its own serial \
                 capture, at offset(s) {found:?} of {} bytes. The key is borrowed by a second \
                 protection domain over a channel whose ABI has no field for one, so a copy on the \
                 console is a leak by some other route entirely — and the console is the surface an \
                 operator reads",
                needle.len(),
                serial.len()
            ));
        }
        Ok(Some(format!(
            "the {}-byte private scalar this boot signed with twice — once for the delegation's own \
             proof and once inside a TLS handshake — occurs at no offset of the {} bytes it wrote to \
             the console, so borrowing the key put none of it on the one surface an operator reads",
            needle.len(),
            serial.len()
        )))
    }

    /// Assert that the scalar this medium held before a factory-reset boot occurs
    /// **nowhere on it** afterwards.
    ///
    /// `Ok(None)` on every boot that armed no capture, which is every boot that is
    /// not proving an erasure.
    ///
    /// # Why a needle scan and not a comparison of the record
    ///
    /// Because the record proves nothing. A reset ends in a fresh mint, so the
    /// state record is different whatever the reset did to the bytes before it —
    /// and a domain that wrote a new record over the old one *without* overwriting
    /// the copy the layout does not reach on that write, or the slot array behind
    /// it, would satisfy every comparison of the record and leave the old key
    /// readable a few sectors away. What is asked here is the only question worth
    /// asking of the medium: is this key still on it, anywhere. Zero occurrences
    /// is the whole answer, so the scan covers every byte of the file rather than
    /// the sectors the layout claims — a copy left outside them is exactly the
    /// defect that would otherwise pass.
    ///
    /// # Errors
    /// Any occurrence, reported by **offset**: the needle is a private key, and it
    /// reaches no message this function writes. Also anything that stops the file
    /// being read whole.
    pub(crate) fn judge_secret_erased(&self) -> Result<Option<String>, String> {
        let Some(needle) = self.erased_secret else {
            return Ok(None);
        };
        let medium = std::fs::read(&self.path)
            .map_err(|error| format!("read {}: {error}", self.path.display()))?;
        let found: Vec<usize> = medium
            .windows(needle.len())
            .enumerate()
            .filter(|(_, window)| *window == needle)
            .map(|(at, _)| at)
            .collect();
        if found.is_empty() {
            return Ok(Some(format!(
                "the {}-byte private scalar the store medium held before this boot occurs at no \
                 offset of it — {} bytes searched, zero matches — so the factory reset overwrote \
                 the key rather than releasing the sectors that held it ({})",
                needle.len(),
                medium.len(),
                self.path.display()
            )));
        }
        Err(format!(
            "the store medium still holds the private scalar it carried before this boot, at {} \
             offset(s): {:?}. The appliance reported a factory reset and the key it was supposed \
             to destroy is readable to anyone holding the medium, which is the one failure a \
             reset must not have — a released sector is a kept secret\n  image: {}",
            found.len(),
            found,
            self.path.display()
        ))
    }

    /// Assert the opposite: that nothing wrote the medium at all.
    ///
    /// What turns the assertion above from a check into evidence, on
    /// [`DataDisk::judge_untouched`]'s terms: a halt scenario boots a disk with
    /// no bootable slot, so no protection domain runs, and the same file attached
    /// the same way must come back as the zeroes it was made as.
    ///
    /// # Errors
    /// Any non-zero byte in the leading sector.
    pub(crate) fn judge_untouched(&self) -> Result<String, String> {
        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|error| format!("open {}: {error}", self.path.display()))?;
        let mut sector = [0u8; SECTOR_SIZE];
        file.read_exact(&mut sector)
            .map_err(|error| format!("read {}: {error}", self.path.display()))?;
        if sector == [0u8; SECTOR_SIZE] {
            return Ok(
                "the store medium is untouched, as a boot with no bootable slot owes".to_owned(),
            );
        }
        Err(format!(
            "the store medium's first sector was written by a boot that reached no protection \
             domain\n  found the first bytes {:02x?}\n  image: {}",
            &sector[..16],
            self.path.display()
        ))
    }
}
