//! The geometry and on-disk metadata of a segmented recording ring on a block
//! device: where a record's bytes belong on the medium, and
//! what the superblock beside them says about the ring's identity and every
//! cursor into it.
//!
//! Faces a hostile or malfunctioning device and the byzantine peer protection
//! domain. Two of the inputs are adversarial and neither looks
//! it. A record length is a captured frame's own size, so whoever sent the
//! frame chose it, and it reaches the segment arithmetic, the wrap decision and
//! the caller's write bound at once. A superblock is whatever bytes the medium
//! hands back — a device returning a neighbouring sector, a slot the other
//! A/B image wrote, or an extent composed offline by someone who
//! had the disk. Nothing here panics, indexes past a bound or wraps an
//! arithmetic operation on either, and a superblock that does not describe
//! *this* ring is refused by name rather than adopted.
//!
//! # No I/O, and why that is the design rather than an omission
//!
//! This crate moves no bytes. It decides where they belong; the protection
//! domain holding the device's capability moves them. That split is what makes
//! a wrap, an eviction and a torn superblock testable at all: every interesting
//! state of a recording ring is hours of traffic away on real hardware and one
//! call away here.
//!
//! # A reservation, not a placement and a promise to commit
//!
//! [`Ring::append`] hands back a [`Reservation`] borrowing the ring mutably,
//! and publishes the record only when [`Reservation::commit`] consumes it.
//! Three mistakes are unrepresentable rather than checked: committing
//! twice, because `commit` takes `self`; committing a placement the ring has
//! since moved past, because the reservation's `&mut Ring` is the only handle
//! to the ring while it lives, so nothing can append or roll underneath it; and
//! committing a placement this ring never made, because [`Placement`] has no
//! public constructor and a reservation carries the ring that minted it.
//!
//! Rust has no linear type, so *forgetting* to commit cannot be made
//! impossible. It is made loud and harmless instead: `#[must_use]` on
//! [`Append`] fails the build on an accidental drop, and a dropped reservation
//! leaves the cursor exactly where it stood, so the record is simply never
//! published and the identical append can be made again.
//!
//! That direction is the point. The alternative — advancing the cursor inside
//! `append` and trusting the caller to write afterwards — publishes bytes the
//! medium may never receive, and a reader is then handed that hole as live
//! history. A capture that silently omits is worse than one that states what it
//! omitted, as the recording design holds; this is the same choice one layer down.
//!
//! # One decision, reached two ways
//!
//! [`Ring::fit`] is the whole decision and takes no claim on the ring;
//! [`Ring::append`] is that decision with `Fits` upgraded to a reservation. A
//! writer sizing a batch asks `fit` what is left of the open segment without
//! reserving any of it, and the two cannot disagree about what fits because
//! there is only one of them.
//!
//! # What a placement addresses, and what it does not claim
//!
//! A [`Placement`] names a segment's first sector and a byte offset within that
//! segment rather than a device sector and an offset inside it: the segment is
//! the unit a wrap replaces whole and the unit a reader resynchronises on, so
//! it is the frame the other numbers are stated in.
//!
//! The ring records where bytes go, never which of them the caller's framing
//! considers current. [`Ring::roll`] leaves the tail of the segment it closes
//! unwritten and those bytes still hold the previous wrap's; [`Ring::slack`] is
//! how many, so a writer can pad before rolling. [`Ring::locate`] reports a
//! closed segment readable to its end on that basis, and the open one only as
//! far as the write cursor.
//!
//! # Refusal is a value, never a repair
//!
//! Every rejection here names what was refused and why: a [`GeometryError`]
//! per rule, a [`Fit::Oversized`] carrying both the record and the segment
//! payload it could not fit, a [`Located::Overrun`] carrying the number of
//! segments a reader was overtaken by — the gap that must be a measured number
//! rather than a suspicion — and a [`RingStateError`] per superblock field. No
//! path clamps a cursor into range, substitutes a default geometry or silently
//! restarts a ring whose superblock it could not use.
//!
//! The one saturation is [`Cursor::sequence`], and it is not a fallback: at one
//! [`MIN_SEGMENT_BYTES`] segment per roll and the targeted 10 Gbit/s, a
//! `u64` runs out after some ten million years, and saturating rather than
//! wrapping is chosen so that the unreachable case stalls visibly — a
//! [`RingCounters::segments_rolled`] still climbing against a frozen sequence —
//! instead of silently reordering history.
//!
//! # Deliberate narrowness
//!
//! * **One extent, one writer.** A [`Ring`] is one party's view of one extent.
//!   Nothing here coordinates two writers, and a reader is a `(sequence,
//!   offset)` pair this ring answers questions about rather than a thing it
//!   holds.
//! * **No dependency and no allocator.** Every bound is a constant or a field
//!   of a validated [`Geometry`], so the crate compiles into a protection
//!   domain unchanged from what the host tests exercise.
//! * **The medium's format is not this crate's.** A segment begins with a
//!   caller-supplied prologue of a known length and continues with appendable
//!   payload; that the prologue is a pcapng Section Header Block and its
//!   interface set is the encoder's business and is nowhere
//!   assumed here.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod superblock;

#[cfg(test)]
mod tests;

pub use superblock::{
    CheckedState, MAX_READERS, ReaderCursor, RingState, RingStateError, SUPERBLOCK_BYTES,
    SUPERBLOCK_COPIES, SUPERBLOCK_COPY_BYTES, SUPERBLOCK_MAGIC, SUPERBLOCK_VERSION,
    decode_superblock, encode_superblock,
};

/// The unit a block device addresses and the granularity at which it promises
/// a write is whole. Every extent, segment and superblock copy here is a
/// multiple of it.
pub const SECTOR_SIZE: usize = 512;

/// The smallest segment a [`Geometry`] accepts.
///
/// Two bounds meet here and the larger wins. A segment must hold the
/// superblock, because segment 0 is where it lives, and it must be worth a
/// block write on its own — a segment is what a wrap replaces and what a reader
/// resynchronises on, so a ring of tiny segments spends its device on prologues
/// and its readers' time on boundaries.
pub const MIN_SEGMENT_BYTES: usize = 4096;

/// The fewest payload segments a ring may have.
///
/// With one, every roll evicts the whole history and [`Ring::readable`] spans a
/// single segment that is also the one being written; a ring that cannot hold
/// anything it is not currently overwriting is not a ring.
pub const MIN_PAYLOAD_SEGMENTS: u64 = 2;

// The conversions between `u64` and `usize` in this crate are written as `as`
// rather than a fallible `try_from` whose error arm no target could reach.
// x86_64 is the only target this project accommodates, and this is the check
// that makes the casts lossless in both directions rather than a comment
// claiming they are.
const _: () = assert!(usize::BITS == 64);

/// A ring's fixed geometry over a contiguous extent of one block device,
/// validated once by [`Geometry::new`] and total thereafter.
///
/// The derived fields are stored rather than recomputed so that every accessor
/// is a field read; they are functions of the three the constructor takes, so
/// two geometries agreeing on start, extent and segment size are equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    start_sector: u64,
    sectors: u64,
    segment_bytes: usize,
    segment_sectors: u64,
    segments: u64,
}

/// Why an extent is not a ring. Each variant carries the values that made it
/// one, so a refusal is attributable to a number rather than to a category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GeometryError {
    SegmentNotSectorMultiple {
        bytes: usize,
    },
    /// Smaller than [`MIN_SEGMENT_BYTES`], zero included.
    SegmentTooSmall {
        bytes: usize,
    },
    ExtentNotSegmentMultiple {
        sectors: u64,
        segment_sectors: u64,
    },
    /// Fewer than `MIN_PAYLOAD_SEGMENTS + 1` in total; `segments` is the total,
    /// the superblock's included.
    TooFewSegments {
        segments: u64,
    },
    ExtentOutsideDevice {
        start: u64,
        sectors: u64,
        capacity: u64,
    },
    /// The extent's last byte does not fit a `u64` byte address. No device is
    /// that large, but `capacity_sectors` is configuration rather than a
    /// measurement, and refusing here is what makes [`Geometry::payload_bytes`]
    /// total instead of an operation that can wrap.
    ExtentExceedsByteAddressing {
        sectors: u64,
    },
}

impl Geometry {
    /// Validate an extent as a ring.
    ///
    /// `capacity_sectors` is the device's size as the domain that owns the
    /// device knows it — never a number read back off the medium, which is
    /// what a superblock's own extent would be.
    ///
    /// # Errors
    /// [`GeometryError`], naming the rule and the value that broke it.
    pub const fn new(
        start_sector: u64,
        sectors: u64,
        segment_bytes: usize,
        capacity_sectors: u64,
    ) -> Result<Self, GeometryError> {
        if !segment_bytes.is_multiple_of(SECTOR_SIZE) {
            return Err(GeometryError::SegmentNotSectorMultiple {
                bytes: segment_bytes,
            });
        }
        // Also what keeps `segment_sectors` non-zero, so the divisions below
        // and the modulus in `segment_sector` have no zero divisor to reach.
        if segment_bytes < MIN_SEGMENT_BYTES {
            return Err(GeometryError::SegmentTooSmall {
                bytes: segment_bytes,
            });
        }
        let segment_sectors = (segment_bytes / SECTOR_SIZE) as u64;
        if !sectors.is_multiple_of(segment_sectors) {
            return Err(GeometryError::ExtentNotSegmentMultiple {
                sectors,
                segment_sectors,
            });
        }
        let total = sectors / segment_sectors;
        if total < MIN_PAYLOAD_SEGMENTS + 1 {
            return Err(GeometryError::TooFewSegments { segments: total });
        }
        let end = match start_sector.checked_add(sectors) {
            Some(end) => end,
            None => {
                return Err(GeometryError::ExtentOutsideDevice {
                    start: start_sector,
                    sectors,
                    capacity: capacity_sectors,
                });
            }
        };
        if end > capacity_sectors {
            return Err(GeometryError::ExtentOutsideDevice {
                start: start_sector,
                sectors,
                capacity: capacity_sectors,
            });
        }
        if sectors.checked_mul(SECTOR_SIZE as u64).is_none() {
            return Err(GeometryError::ExtentExceedsByteAddressing { sectors });
        }
        Ok(Self {
            start_sector,
            sectors,
            segment_bytes,
            segment_sectors,
            // `total >= 3` above, so the payload count is at least
            // `MIN_PAYLOAD_SEGMENTS` and never zero.
            segments: total - 1,
        })
    }

    #[must_use]
    pub const fn start_sector(&self) -> u64 {
        self.start_sector
    }

    #[must_use]
    pub const fn sectors(&self) -> u64 {
        self.sectors
    }

    /// Payload segments, the superblock's excluded.
    #[must_use]
    pub const fn segments(&self) -> u64 {
        self.segments
    }

    #[must_use]
    pub const fn segment_bytes(&self) -> usize {
        self.segment_bytes
    }

    #[must_use]
    pub const fn segment_sectors(&self) -> u64 {
        self.segment_sectors
    }

    /// Every byte of every payload segment, one wrap's worth.
    ///
    /// Gross rather than net: the prologue each segment opens with belongs to
    /// the [`Ring`] and not to the extent, so [`Ring::segment_payload`] is what
    /// says how much of a segment a caller may append into.
    #[must_use]
    pub const fn payload_bytes(&self) -> u64 {
        // `segments * segment_bytes` is `(sectors - segment_sectors) *
        // SECTOR_SIZE`, and `new` refused an extent whose `sectors *
        // SECTOR_SIZE` does not fit a `u64`.
        self.segments * self.segment_bytes as u64
    }

    /// The first device sector of payload segment `index`, which is the segment
    /// a cursor's sequence names once it has wrapped as many times as it has.
    ///
    /// Total: `index` is reduced modulo the payload segment count, so a
    /// sequence far past a wrap addresses the segment now holding it.
    #[must_use]
    pub const fn segment_sector(&self, index: u64) -> u64 {
        // Bounded by `start_sector + sectors - segment_sectors`, which `new`
        // proved is inside the device: the largest factor is `segments`, and
        // `segments * segment_sectors == sectors - segment_sectors`.
        self.start_sector + (index % self.segments + 1) * self.segment_sectors
    }

    /// Where the superblock lives: the first sector of the extent, which is
    /// segment 0 and the one segment no append ever reaches.
    #[must_use]
    pub const fn superblock_sector(&self) -> u64 {
        self.start_sector
    }
}

/// The append position: the segment being written, how far into it, and — in
/// `sequence` — how many segments the ring has ever started.
///
/// `sequence` is monotone across wraps and is what lets a reader tell that the
/// segment it was reading has been replaced underneath it: the segment index is
/// `sequence % segments`, so two sequences one wrap apart share a segment and
/// only the older one is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Cursor {
    pub sequence: u64,
    pub offset: usize,
}

/// A span of one segment on the medium: the segment's first sector, the byte
/// offset within that segment, and how many bytes the span covers.
///
/// The fields are private and no constructor is public, so every placement a
/// caller holds was computed by this crate against a validated [`Geometry`] —
/// a span outside the extent is not something a caller can express.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    sector: u64,
    byte_offset: usize,
    len: usize,
}

impl Placement {
    /// The first device sector of the segment the span lies in.
    #[must_use]
    pub const fn sector(&self) -> u64 {
        self.sector
    }

    /// The offset of the span's first byte within that segment, not within the
    /// sector: `sector * SECTOR_SIZE + byte_offset` is the device byte the
    /// caller writes at.
    #[must_use]
    pub const fn byte_offset(&self) -> usize {
        self.byte_offset
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// What an append would do, holding no claim on the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fit {
    /// The record fits the open segment, here.
    Fits(Placement),
    /// Not in what is left of the open segment, but in an empty one: close
    /// this segment, [`Ring::roll`] to the next, write the prologue, retry.
    SegmentFull,
    /// Larger than a whole segment's payload, so no roll will ever help.
    Oversized {
        needed: usize,
        segment_payload: usize,
    },
}

/// [`Fit`] with its `Fits` upgraded to a reservation on the ring.
///
/// Dropping a `Placed` abandons the reservation and leaves the ring exactly as
/// it was — see the crate header on why that is the safe direction and why
/// `#[must_use]` rather than a linear type is what catches the accident.
#[must_use = "a reservation publishes nothing until it is committed, and dropping one abandons the record"]
#[derive(Debug)]
pub enum Append<'ring> {
    Placed(Reservation<'ring>),
    SegmentFull,
    Oversized {
        needed: usize,
        segment_payload: usize,
    },
}

impl Append<'_> {
    /// Where a `Placed` would put the record, for a caller that wants the span
    /// without giving up the reservation. `None` for the two refusals.
    #[must_use]
    pub const fn placement(&self) -> Option<Placement> {
        match self {
            Self::Placed(reservation) => Some(reservation.placement()),
            Self::SegmentFull | Self::Oversized { .. } => None,
        }
    }
}

/// Space held open in the ring's current segment, and the sole way to advance
/// the append cursor over it.
///
/// Holds the ring mutably for its whole life, which is what makes the placement
/// it carries impossible to stale: no append, roll or commit can happen while
/// one exists.
#[derive(Debug)]
pub struct Reservation<'ring> {
    ring: &'ring mut Ring,
    placement: Placement,
}

impl Reservation<'_> {
    /// Where the caller writes the record's bytes.
    #[must_use]
    pub const fn placement(&self) -> Placement {
        self.placement
    }

    /// Publish the record, advancing the append cursor over it, and return the
    /// cursor as it now stands — which is what the next superblock checkpoint
    /// records.
    ///
    /// Call it once the bytes are on the medium, never before: until it is
    /// called the span is not part of [`Ring::readable`] history and no
    /// [`Ring::locate`] will hand it to a reader.
    pub fn commit(self) -> Cursor {
        let Self { ring, placement } = self;
        // `offset + len <= segment_bytes`. A `Reservation` is built in
        // `Ring::append` out of a `Fit::Fits`, and `Ring::fit` returns that
        // only for `len <= Ring::slack()`, which is `segment_bytes - offset`.
        // The cursor cannot have moved since, this reservation having held the
        // ring's only handle. Enforcement is standing rather than argued:
        // `crates/capture-ring/src/tests.rs` property
        // `the_cursor_never_leaves_its_segment` fails on any sequence of
        // appends and rolls that walks the offset past its segment.
        ring.cursor.offset += placement.len;
        ring.counters.records_appended = ring.counters.records_appended.saturating_add(1);
        ring.counters.bytes_appended = ring
            .counters
            .bytes_appended
            .saturating_add(placement.len as u64);
        ring.cursor
    }
}

/// Where a reader's `(sequence, offset)` points now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Located {
    /// Still on the medium. The placement's length is how far the reader may
    /// read contiguously without leaving the segment: to the write cursor in
    /// the open segment, to the segment's end in a closed one.
    Live(Placement),
    /// Overtaken. The writer has wrapped past this sequence, `gap` segments
    /// ago, and `oldest` is the first sequence still on the medium — the
    /// resynchronisation point, and the measured loss a reader is owed.
    Overrun { gap: u64, oldest: u64 },
    /// A position this ring has not written: ahead of the write cursor, or past
    /// the end of a segment. Not loss — a cursor no writer here produced, which
    /// is what a corrupt or forged reader position looks like.
    Unwritten,
}

/// Saturating, monotone counts backing the exposed ring metrics.
///
/// One [`Ring`] is one party's view of an extent, so a writer's ring leaves
/// [`Self::reader_overruns`] at zero and a reader's leaves the append counts
/// there; neither is a whole-system total.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RingCounters {
    /// Reservations committed.
    pub records_appended: u64,
    /// Bytes those reservations covered, prologues excluded.
    pub bytes_appended: u64,
    /// Segments closed and reopened by [`Ring::roll`].
    pub segments_rolled: u64,
    /// Rolls that returned to the extent's first payload segment.
    pub wraps: u64,
    /// Records refused by [`Ring::append`] as larger than a segment's payload.
    /// [`Ring::fit`] asks the same question and counts nothing.
    pub records_oversized: u64,
    /// Reader positions [`Ring::locate`] found overtaken, one per observation
    /// rather than per reader.
    pub reader_overruns: u64,
}

/// One party's view of a segmented ring: its geometry, its prologue length, and
/// where the append cursor stands.
#[derive(Debug)]
pub struct Ring {
    geometry: Geometry,
    prologue_len: usize,
    cursor: Cursor,
    write_generation: u64,
    counters: RingCounters,
}

impl Ring {
    /// A ring over a fresh extent, its first segment open and its prologue
    /// space already accounted for — so the caller's first act is to write the
    /// prologue at [`Ring::prologue`], exactly as it does after every
    /// [`Ring::roll`].
    ///
    /// `prologue_len` at or beyond a segment leaves no payload. That is not
    /// refused, because it needs no fallible constructor to be visible: every
    /// non-empty append then returns [`Fit::Oversized`] carrying
    /// `segment_payload: 0`, which names the misconfiguration at the point it
    /// bites and counts it.
    #[must_use]
    pub const fn new(geometry: Geometry, prologue_len: usize) -> Self {
        Self {
            geometry,
            prologue_len,
            cursor: Cursor {
                sequence: 0,
                offset: opening_offset(&geometry, prologue_len),
            },
            write_generation: 0,
            counters: RingCounters {
                records_appended: 0,
                bytes_appended: 0,
                segments_rolled: 0,
                wraps: 0,
                records_oversized: 0,
                reader_overruns: 0,
            },
        }
    }

    /// A ring resuming the cursor and generation a superblock carried.
    ///
    /// Takes a [`CheckedState`] rather than a [`RingState`], so a superblock
    /// that was never checked against this deployment's geometry cannot reach a
    /// ring at all: [`RingState::check`] is the only way to obtain one.
    ///
    /// A stored cursor sitting below `prologue_len` — a ring resumed under a
    /// longer prologue than it was written with — leaves the open segment more
    /// room than a fresh one has. [`Ring::fit`] stays conservative there and
    /// still refuses anything a fresh segment could not hold, so the ring never
    /// starts a record it could not repeat after a roll.
    #[must_use]
    pub const fn resume(checked: CheckedState, prologue_len: usize) -> Self {
        Self {
            geometry: checked.geometry(),
            prologue_len,
            cursor: checked.writer(),
            write_generation: checked.write_generation(),
            counters: RingCounters {
                records_appended: 0,
                bytes_appended: 0,
                segments_rolled: 0,
                wraps: 0,
                records_oversized: 0,
                reader_overruns: 0,
            },
        }
    }

    #[must_use]
    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    #[must_use]
    pub const fn cursor(&self) -> Cursor {
        self.cursor
    }

    #[must_use]
    pub const fn counters(&self) -> RingCounters {
        self.counters
    }

    /// The generation the last [`Ring::checkpoint`] wrote, and the one a
    /// [`Ring::resume`] carried in.
    #[must_use]
    pub const fn write_generation(&self) -> u64 {
        self.write_generation
    }

    #[must_use]
    pub const fn prologue_len(&self) -> usize {
        self.prologue_len
    }

    /// What a caller may append into one segment, the prologue deducted.
    #[must_use]
    pub const fn segment_payload(&self) -> usize {
        self.geometry.segment_bytes - opening_offset(&self.geometry, self.prologue_len)
    }

    /// What is left of the open segment: the tail a [`Ring::roll`] would leave
    /// unwritten, and so the padding a writer emits to keep a closed segment
    /// free of the previous wrap's bytes.
    #[must_use]
    pub const fn slack(&self) -> usize {
        // `cursor.offset <= segment_bytes`, established by the three places
        // that set it: `Ring::new` and `Ring::roll` take it from
        // `opening_offset`, which caps at the segment; `Reservation::commit`
        // adds a length `Ring::fit` bounded by this very value; and
        // `Ring::resume` takes it from a `CheckedState`, which `RingState::new`
        // refuses unless the offset is within the segment. The property
        // `the_cursor_never_leaves_its_segment` in
        // `crates/capture-ring/src/tests.rs` is what keeps that true.
        self.geometry.segment_bytes - self.cursor.offset
    }

    /// Where the open segment's prologue goes — the span [`Ring::roll`] returns
    /// for every segment after the first, and the only way to learn it for the
    /// first, which no roll opened.
    #[must_use]
    pub const fn prologue(&self) -> Placement {
        Placement {
            sector: self.geometry.segment_sector(self.cursor.sequence),
            byte_offset: 0,
            len: opening_offset(&self.geometry, self.prologue_len),
        }
    }

    /// The oldest and newest sequences on the medium, inclusive.
    ///
    /// The oldest is the resynchronisation point for a reader that has been
    /// overtaken; before the first wrap it is sequence 0, because nothing has
    /// been evicted yet.
    #[must_use]
    pub const fn readable(&self) -> (u64, u64) {
        let newest = self.cursor.sequence;
        // `Geometry::new` refuses fewer than `MIN_PAYLOAD_SEGMENTS`, so there
        // is a segment to subtract and the count cannot underflow.
        (newest.saturating_sub(self.geometry.segments - 1), newest)
    }

    /// Whether a record of `len` bytes fits, and where — the whole decision,
    /// taking nothing and counting nothing.
    ///
    /// A record larger than a *fresh* segment's payload is [`Fit::Oversized`]
    /// even where the open segment happens to have room for it (which only a
    /// [`Ring::resume`] under a longer prologue can arrange). The rule is
    /// stated against the segment rather than against the moment, so a record
    /// accepted here is one a roll could accept again.
    #[must_use]
    pub const fn fit(&self, len: usize) -> Fit {
        let segment_payload = self.segment_payload();
        if len > segment_payload {
            return Fit::Oversized {
                needed: len,
                segment_payload,
            };
        }
        if len > self.slack() {
            return Fit::SegmentFull;
        }
        Fit::Fits(Placement {
            sector: self.geometry.segment_sector(self.cursor.sequence),
            byte_offset: self.cursor.offset,
            len,
        })
    }

    /// [`Ring::fit`], reserving the span it found and counting the refusal it
    /// did not.
    ///
    /// The reservation publishes nothing: [`Reservation::commit`] does, once
    /// the bytes are on the medium.
    pub fn append(&mut self, len: usize) -> Append<'_> {
        match self.fit(len) {
            Fit::Fits(placement) => Append::Placed(Reservation {
                ring: self,
                placement,
            }),
            Fit::SegmentFull => Append::SegmentFull,
            Fit::Oversized {
                needed,
                segment_payload,
            } => {
                self.counters.records_oversized = self.counters.records_oversized.saturating_add(1);
                Append::Oversized {
                    needed,
                    segment_payload,
                }
            }
        }
    }

    /// Close the open segment and open the next, returning where its prologue
    /// goes. Where a wrap happens, and where a segment is replaced whole.
    ///
    /// The tail this leaves behind in the closed segment is whatever
    /// [`Ring::slack`] last reported; pad it first if the caller's framing
    /// needs a closed segment to hold none of the previous wrap.
    pub fn roll(&mut self) -> Placement {
        self.cursor.sequence = self.cursor.sequence.saturating_add(1);
        self.cursor.offset = opening_offset(&self.geometry, self.prologue_len);
        self.counters.segments_rolled = self.counters.segments_rolled.saturating_add(1);
        if self.cursor.sequence.is_multiple_of(self.geometry.segments) {
            self.counters.wraps = self.counters.wraps.saturating_add(1);
        }
        self.prologue()
    }

    /// Where a reader's `(sequence, offset)` points, and how much it may read
    /// from there without leaving the segment.
    ///
    /// Takes `&mut self` because an overrun is only knowable here — the gap is
    /// the difference between the reader's sequence and the oldest one still on
    /// the medium, and no later caller can recover it from an
    /// [`Located::Overrun`] it forgot to count. Leaving the count to the caller
    /// would make measured loss depend on the caller remembering, which is the
    /// silent omission a recording must never make.
    pub fn locate(&mut self, sequence: u64, offset: usize) -> Located {
        let (oldest, newest) = self.readable();
        if sequence < oldest {
            self.counters.reader_overruns = self.counters.reader_overruns.saturating_add(1);
            return Located::Overrun {
                gap: oldest - sequence,
                oldest,
            };
        }
        if sequence > newest {
            return Located::Unwritten;
        }
        // The open segment is written only as far as the cursor; a closed one
        // is written to its end, the unpadded tail included — see the crate
        // header on what the ring does not claim about content.
        let run_end = if sequence == newest {
            self.cursor.offset
        } else {
            self.geometry.segment_bytes
        };
        if offset >= run_end {
            return Located::Unwritten;
        }
        Located::Live(Placement {
            sector: self.geometry.segment_sector(sequence),
            byte_offset: offset,
            len: run_end - offset,
        })
    }

    /// The next superblock: this ring's geometry and cursor plus the reader
    /// positions the caller collected, under a generation one past the last.
    ///
    /// The bump is what selects the copy [`encode_superblock`] rewrites, so a
    /// checkpoint that is never written leaves a generation unused rather than
    /// rewriting the copy the medium is currently relying on.
    ///
    /// # Errors
    /// [`RingStateError`] for a reader set this ring cannot describe — too
    /// many, a repeated identifier, or a position outside the extent. The ring
    /// is left untouched, generation included.
    pub fn checkpoint(&mut self, readers: &[ReaderCursor]) -> Result<RingState, RingStateError> {
        let generation = self.write_generation.saturating_add(1);
        let state = RingState::new(self.geometry, generation, self.cursor, readers)?;
        self.write_generation = generation;
        Ok(state)
    }
}

/// Where a segment's payload starts, which is its prologue's length — or the
/// whole segment where the prologue does not fit in one, so that the cursor
/// stays inside its segment however the caller configured it.
const fn opening_offset(geometry: &Geometry, prologue_len: usize) -> usize {
    if prologue_len > geometry.segment_bytes {
        geometry.segment_bytes
    } else {
        prologue_len
    }
}
