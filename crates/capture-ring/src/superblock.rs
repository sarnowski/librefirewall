//! The ring's identity and delivery state as it sits on the medium, so a node
//! that restarts — or falls back to its other slot (CONCEPT §14.2) — resumes
//! every cursor from the same device that holds the data (CONCEPT §15.4).
//!
//! Faces a hostile or malfunctioning device (CONCEPT §7.1). Everything decoded
//! here arrived as bytes off a disk: a sector the device mis-addressed, a
//! superblock the other image wrote, or an extent an offline attacker composed
//! at leisure. A copy is a superblock only if it carries the magic, the
//! version, a CRC over itself, a geometry that is a geometry, and cursors
//! inside it — and even then only [`RingState::check`], against the geometry
//! this deployment was configured with, turns it into something a ring may
//! resume from.
//!
//! # Two copies, because a whole sector write is a promise
//!
//! A device is expected to make a sector write atomic and is not trusted to.
//! The region is therefore two sector-sized copies, each with its own
//! generation and CRC, and a writer rewrites the one its generation's parity
//! selects — so the copy the medium is currently relying on is never the copy
//! being overwritten. A torn, lost or misdirected write costs the newer copy
//! and the older one still decodes; both failing is a fresh or unusable ring,
//! which [`decode_superblock`] reports as `None` rather than as an error,
//! because an unwritten medium is the ordinary first boot.
//!
//! Two copies within one sector would defend against nothing: the tear this
//! guards against is the sector, so independence requires two of them.
//!
//! # Canonical bytes, so a forgery has nowhere to hide
//!
//! Every byte of a copy is defined. The fields are little-endian at fixed
//! offsets, the CRC is the last four bytes and covers everything before it, and
//! every byte the layout does not name — the unused reader slots and the
//! reserved tail — is written zero and refused non-zero. A copy carrying
//! meaning in a byte this writer zeroes is not a copy this writer produced, and
//! deciding that now is cheaper than deciding later what it meant.
//! [`SUPERBLOCK_VERSION`] is how the layout changes; there is no compatibility
//! path (ENG-6).

use crate::{Cursor, Geometry, SECTOR_SIZE};

#[cfg(test)]
mod tests;

/// `LFWCAPRG` in ASCII, so the first eight bytes of the extent identify it in a
/// hex dump without a decoder.
pub const SUPERBLOCK_MAGIC: u64 = u64::from_le_bytes(*b"LFWCAPRG");

pub const SUPERBLOCK_VERSION: u32 = 1;

/// Independent cursors one ring records. The pcapng download, the
/// OpenTelemetry exporter and a live console stream are three (CONCEPT §15.4);
/// the fourth is the headroom that keeps adding one from being a layout change.
pub const MAX_READERS: usize = 4;

/// One copy is one sector, because the sector is the unit the device promises
/// to write whole.
pub const SUPERBLOCK_COPY_BYTES: usize = SECTOR_SIZE;

pub const SUPERBLOCK_COPIES: usize = 2;

/// The region a caller reads and writes: both copies, back to back, at
/// [`Geometry::superblock_sector`].
pub const SUPERBLOCK_BYTES: usize = SUPERBLOCK_COPY_BYTES * SUPERBLOCK_COPIES;

const MAGIC_AT: usize = 0;
const VERSION_AT: usize = 8;
const READER_COUNT_AT: usize = 12;
const GENERATION_AT: usize = 16;
const START_SECTOR_AT: usize = 24;
const SECTORS_AT: usize = 32;
const SEGMENT_BYTES_AT: usize = 40;
const WRITER_SEQUENCE_AT: usize = 48;
const WRITER_OFFSET_AT: usize = 56;
const READERS_AT: usize = 64;

const READER_BYTES: usize = 24;
const READER_ID_AT: usize = 0;
const READER_SEQUENCE_AT: usize = 8;
const READER_OFFSET_AT: usize = 16;

/// The CRC is last so that the range it covers is the single contiguous prefix
/// before it — magic and version included, which a CRC placed among the fields
/// would have had to skip around.
const CRC_AT: usize = SUPERBLOCK_COPY_BYTES - 4;

// The on-disk ABI of an appliance that must still read its own recordings after
// a rebuild: a field moving or growing has to be a compile error here, not a
// ring that decodes to plausible nonsense (TEST-5).
const _: () = {
    assert!(SUPERBLOCK_BYTES == 1024);
    assert!(SUPERBLOCK_COPY_BYTES == 512);
    assert!(READER_BYTES == 24);
    assert!(READER_OFFSET_AT + 8 == READER_BYTES);
    assert!(READERS_AT == WRITER_OFFSET_AT + 8);
    assert!(READERS_AT + MAX_READERS * READER_BYTES <= CRC_AT);
    assert!(CRC_AT + 4 == SUPERBLOCK_COPY_BYTES);
    // Segment 0 is the superblock's, so the smallest legal segment must hold
    // the whole region.
    assert!(crate::MIN_SEGMENT_BYTES >= SUPERBLOCK_BYTES);
    // Copy selection is generation parity, which needs exactly two copies.
    assert!(SUPERBLOCK_COPIES == 2);
};

/// One reader's position, and the identifier that keeps it that reader's across
/// a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderCursor {
    pub id: u32,
    pub cursor: Cursor,
}

/// A ring's identity and every cursor into it, valid against its own geometry.
///
/// Only [`RingState::new`] and [`decode_superblock`] mint one, and both refuse
/// a cursor the geometry cannot hold — so [`encode_superblock`] has nothing
/// left to reject and needs no error of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingState {
    geometry: Geometry,
    write_generation: u64,
    writer: Cursor,
    /// A leading run of `Some`, as `new` and `decode_superblock` build it.
    readers: [Option<ReaderCursor>; MAX_READERS],
}

/// A [`RingState`] checked against the geometry this deployment configured, and
/// therefore the only thing [`crate::Ring::resume`] accepts.
///
/// The distinction is the whole defence against a medium that describes some
/// other ring: a `RingState` is internally consistent, which a forger can also
/// arrange, while a `CheckedState` additionally agrees with a number that came
/// from the domain owning the device rather than from the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedState {
    geometry: Geometry,
    write_generation: u64,
    writer: Cursor,
    readers: [Option<ReaderCursor>; MAX_READERS],
}

/// Why a superblock is not this ring's, or not a ring's at all. Each variant
/// carries the values that disagreed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RingStateError {
    TooManyReaders {
        count: usize,
    },
    /// Two cursors under one identifier: "resume reader 3" would have no
    /// answer, and picking one silently loses the other's place.
    DuplicateReaderId {
        id: u32,
    },
    WriterOffsetOutsideSegment {
        offset: usize,
        segment_bytes: usize,
    },
    ReaderOffsetOutsideSegment {
        id: u32,
        offset: usize,
        segment_bytes: usize,
    },
    /// A reader past the newest segment the writer ever started, which no run
    /// of this ring produced. A reader merely ahead of the write cursor
    /// *within* the open segment is not refused: it has been overtaken by
    /// nothing and has nothing to read, which [`crate::Located::Unwritten`]
    /// already says exactly.
    ReaderAheadOfWriter {
        id: u32,
        sequence: u64,
        writer_sequence: u64,
    },
    StartSectorMismatch {
        stored: u64,
        configured: u64,
    },
    SectorsMismatch {
        stored: u64,
        configured: u64,
    },
    SegmentBytesMismatch {
        stored: usize,
        configured: usize,
    },
}

impl RingState {
    /// # Errors
    /// [`RingStateError`] for a cursor the geometry cannot hold or a reader set
    /// it cannot describe.
    pub fn new(
        geometry: Geometry,
        write_generation: u64,
        writer: Cursor,
        readers: &[ReaderCursor],
    ) -> Result<Self, RingStateError> {
        let segment_bytes = geometry.segment_bytes();
        if writer.offset > segment_bytes {
            return Err(RingStateError::WriterOffsetOutsideSegment {
                offset: writer.offset,
                segment_bytes,
            });
        }
        if readers.len() > MAX_READERS {
            return Err(RingStateError::TooManyReaders {
                count: readers.len(),
            });
        }

        let mut slots = [None; MAX_READERS];
        // Bounded by the array rather than by `readers.len()`: the zip stops at
        // whichever is shorter, and the length check above is what makes that
        // the caller's slice.
        for (index, (slot, reader)) in slots.iter_mut().zip(readers).enumerate() {
            if reader.cursor.offset > segment_bytes {
                return Err(RingStateError::ReaderOffsetOutsideSegment {
                    id: reader.id,
                    offset: reader.cursor.offset,
                    segment_bytes,
                });
            }
            if reader.cursor.sequence > writer.sequence {
                return Err(RingStateError::ReaderAheadOfWriter {
                    id: reader.id,
                    sequence: reader.cursor.sequence,
                    writer_sequence: writer.sequence,
                });
            }
            // Against the entries already accepted, so `MAX_READERS` squared is
            // the whole cost and the first repeat names itself.
            if readers[..index].iter().any(|seen| seen.id == reader.id) {
                return Err(RingStateError::DuplicateReaderId { id: reader.id });
            }
            *slot = Some(*reader);
        }

        Ok(Self {
            geometry,
            write_generation,
            writer,
            readers: slots,
        })
    }

    #[must_use]
    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    #[must_use]
    pub const fn write_generation(&self) -> u64 {
        self.write_generation
    }

    #[must_use]
    pub const fn writer(&self) -> Cursor {
        self.writer
    }

    #[must_use]
    pub const fn readers(&self) -> &[Option<ReaderCursor>; MAX_READERS] {
        &self.readers
    }

    /// Accept the stored state as describing the ring this deployment
    /// configured.
    ///
    /// Comparing start, extent and segment size is comparing the whole
    /// geometry: every other field of a [`Geometry`] is derived from those
    /// three by [`Geometry::new`].
    ///
    /// # Errors
    /// [`RingStateError`], naming the field that disagreed and both values. A
    /// mismatch is a ring the medium is holding for somebody else — the extent
    /// was rebound (CONCEPT §15.5) or the device is not the one it was — and
    /// adopting it would place writes over another object's bytes.
    pub const fn check(&self, configured: &Geometry) -> Result<CheckedState, RingStateError> {
        if self.geometry.start_sector() != configured.start_sector() {
            return Err(RingStateError::StartSectorMismatch {
                stored: self.geometry.start_sector(),
                configured: configured.start_sector(),
            });
        }
        if self.geometry.sectors() != configured.sectors() {
            return Err(RingStateError::SectorsMismatch {
                stored: self.geometry.sectors(),
                configured: configured.sectors(),
            });
        }
        if self.geometry.segment_bytes() != configured.segment_bytes() {
            return Err(RingStateError::SegmentBytesMismatch {
                stored: self.geometry.segment_bytes(),
                configured: configured.segment_bytes(),
            });
        }
        Ok(CheckedState {
            geometry: *configured,
            write_generation: self.write_generation,
            writer: self.writer,
            readers: self.readers,
        })
    }
}

impl CheckedState {
    #[must_use]
    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    #[must_use]
    pub const fn write_generation(&self) -> u64 {
        self.write_generation
    }

    #[must_use]
    pub const fn writer(&self) -> Cursor {
        self.writer
    }

    #[must_use]
    pub const fn readers(&self) -> &[Option<ReaderCursor>; MAX_READERS] {
        &self.readers
    }
}

/// Write `state` into the copy its generation's parity selects, leaving the
/// other copy — the one the medium is currently relying on — untouched.
///
/// Returns the byte offset within `out` of the copy it rewrote; the copy is
/// [`SUPERBLOCK_COPY_BYTES`] long, and that one sector is what the caller
/// flushes. `out` is the whole region and nothing else, which is why this
/// cannot fail: the short-buffer case is not a rejection here but a type the
/// caller cannot construct.
pub fn encode_superblock(out: &mut [u8; SUPERBLOCK_BYTES], state: &RingState) -> usize {
    let mut image = [0u8; SUPERBLOCK_COPY_BYTES];

    write_u64(&mut image, MAGIC_AT, SUPERBLOCK_MAGIC);
    write_u32(&mut image, VERSION_AT, SUPERBLOCK_VERSION);
    write_u32(
        &mut image,
        READER_COUNT_AT,
        state.readers.iter().flatten().count() as u32,
    );
    write_u64(&mut image, GENERATION_AT, state.write_generation);
    write_u64(&mut image, START_SECTOR_AT, state.geometry.start_sector());
    write_u64(&mut image, SECTORS_AT, state.geometry.sectors());
    write_u64(
        &mut image,
        SEGMENT_BYTES_AT,
        state.geometry.segment_bytes() as u64,
    );
    write_u64(&mut image, WRITER_SEQUENCE_AT, state.writer.sequence);
    write_u64(&mut image, WRITER_OFFSET_AT, state.writer.offset as u64);

    for (index, reader) in state.readers.iter().flatten().enumerate() {
        // `index < MAX_READERS`, so the last byte touched is the one the
        // `READERS_AT + MAX_READERS * READER_BYTES <= CRC_AT` assertion pins
        // inside the image.
        let at = READERS_AT + index * READER_BYTES;
        write_u32(&mut image, at + READER_ID_AT, reader.id);
        write_u64(&mut image, at + READER_SEQUENCE_AT, reader.cursor.sequence);
        write_u64(
            &mut image,
            at + READER_OFFSET_AT,
            reader.cursor.offset as u64,
        );
    }

    let crc = crc32(&image[..CRC_AT]);
    write_u32(&mut image, CRC_AT, crc);

    let copy = (state.write_generation % SUPERBLOCK_COPIES as u64) as usize;
    let (first, second) = out.split_at_mut(SUPERBLOCK_COPY_BYTES);
    if copy == 0 {
        first.copy_from_slice(&image);
    } else {
        second.copy_from_slice(&image);
    }
    copy * SUPERBLOCK_COPY_BYTES
}

/// Decode the newer of the two valid copies.
///
/// `None` where neither is valid — a fresh medium, or one whose superblock is
/// beyond use. That is not an error: a first boot writes a new ring, and the
/// caller that would rather refuse than overwrite is the one holding the
/// policy, not this function.
///
/// A tie in generation is resolved to the first copy. Two valid copies at one
/// generation are two writes of the same state and are byte-identical, so the
/// rule exists to make the choice total rather than because the outcome differs
/// — except for a forgery that arranged the tie, where a fixed answer is the
/// point.
#[must_use]
pub fn decode_superblock(bytes: &[u8; SUPERBLOCK_BYTES]) -> Option<RingState> {
    let (first, second) = bytes.split_at(SUPERBLOCK_COPY_BYTES);
    match (decode_copy(first), decode_copy(second)) {
        (Some(first), Some(second)) => Some(if second.write_generation > first.write_generation {
            second
        } else {
            first
        }),
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    }
}

/// One copy, or `None` for anything this writer would not have produced.
///
/// `copy` is exactly [`SUPERBLOCK_COPY_BYTES`] long, from
/// [`decode_superblock`]'s split of the region, and every offset read is a
/// constant the assertions above pin inside it.
fn decode_copy(copy: &[u8]) -> Option<RingState> {
    if read_u64(copy, MAGIC_AT) != SUPERBLOCK_MAGIC {
        return None;
    }
    if read_u32(copy, VERSION_AT) != SUPERBLOCK_VERSION {
        return None;
    }
    if read_u32(copy, CRC_AT) != crc32(&copy[..CRC_AT]) {
        return None;
    }

    let reader_count = read_u32(copy, READER_COUNT_AT) as usize;
    if reader_count > MAX_READERS {
        return None;
    }
    // Everything the layout does not name for this reader count, in one span:
    // the unused reader slots and the reserved tail.
    let named_end = READERS_AT + reader_count * READER_BYTES;
    if copy[named_end..CRC_AT].iter().any(|byte| *byte != 0) {
        return None;
    }

    let geometry = stored_geometry(copy)?;
    let writer = Cursor {
        sequence: read_u64(copy, WRITER_SEQUENCE_AT),
        offset: read_u64(copy, WRITER_OFFSET_AT) as usize,
    };

    let mut readers = [ReaderCursor {
        id: 0,
        cursor: Cursor::default(),
    }; MAX_READERS];
    for (index, reader) in readers.iter_mut().enumerate().take(reader_count) {
        let at = READERS_AT + index * READER_BYTES;
        // The four bytes between the identifier and the sequence are this
        // writer's padding and are covered by the CRC, so a value in them is
        // another writer's meaning.
        if read_u32(copy, at + READER_ID_AT + 4) != 0 {
            return None;
        }
        *reader = ReaderCursor {
            id: read_u32(copy, at + READER_ID_AT),
            cursor: Cursor {
                sequence: read_u64(copy, at + READER_SEQUENCE_AT),
                offset: read_u64(copy, at + READER_OFFSET_AT) as usize,
            },
        };
    }

    RingState::new(
        geometry,
        read_u64(copy, GENERATION_AT),
        writer,
        &readers[..reader_count],
    )
    .ok()
}

/// The geometry the copy claims, validated as a geometry in its own right.
///
/// Its own extent is the capacity it is checked against, because the medium
/// does not carry the device's size and would not be believed about it if it
/// did: whether the extent fits *this* device is what [`RingState::check`]
/// settles, against a geometry the domain owning the device built.
fn stored_geometry(copy: &[u8]) -> Option<Geometry> {
    let start_sector = read_u64(copy, START_SECTOR_AT);
    let sectors = read_u64(copy, SECTORS_AT);
    let segment_bytes = read_u64(copy, SEGMENT_BYTES_AT) as usize;
    Geometry::new(
        start_sector,
        sectors,
        segment_bytes,
        start_sector.checked_add(sectors)?,
    )
    .ok()
}

fn write_u32(image: &mut [u8; SUPERBLOCK_COPY_BYTES], at: usize, value: u32) {
    image[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(image: &mut [u8; SUPERBLOCK_COPY_BYTES], at: usize, value: u64) {
    image[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(copy: &[u8], at: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&copy[at..at + 4]);
    u32::from_le_bytes(bytes)
}

fn read_u64(copy: &[u8], at: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&copy[at..at + 8]);
    u64::from_le_bytes(bytes)
}

/// The reflected IEEE polynomial, which is CRC-32 as zlib and pcapng use it.
const CRC32_POLYNOMIAL: u32 = 0xEDB8_8320;

/// The byte-at-a-time table, built at compile time so the crate carries the
/// eight shifts per entry once rather than a kilobyte of literals nobody can
/// check by eye.
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut remainder = index as u32;
        let mut bit = 0;
        while bit < 8 {
            remainder = if remainder & 1 == 0 {
                remainder >> 1
            } else {
                (remainder >> 1) ^ CRC32_POLYNOMIAL
            };
            bit += 1;
        }
        table[index] = remainder;
        index += 1;
    }
    table
};

/// CRC-32 (IEEE), detecting the bit rot and the torn write a superblock is
/// exposed to. Not a signature: it says a copy is intact, never that the party
/// who wrote it was entitled to — which is why a copy that passes it is still
/// only a [`RingState`] and not yet a [`CheckedState`].
const fn crc32(bytes: &[u8]) -> u32 {
    let mut remainder = u32::MAX;
    let mut index = 0;
    while index < bytes.len() {
        let slot = ((remainder ^ bytes[index] as u32) & 0xFF) as usize;
        remainder = (remainder >> 8) ^ CRC32_TABLE[slot];
        index += 1;
    }
    remainder ^ u32::MAX
}
