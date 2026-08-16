//! One recording sink: pcapng encoding onto a segmented ring, and the placement
//! of whole sectors for the protection domain that owns the block device.
//!
//! The appliance keeps two of these and they differ in **what they record**: a
//! connection history of the observations that carried a lifecycle or policy
//! event, and a capture of every observation with its verdict. The selection is
//! the caller's ([`crate::deck::Which::records`]); what this type carries of it is
//! the extent, the snap length, and the annotation naming the event.
//!
//! # The adversary
//!
//! A **byzantine neighbour protection domain**: the tap annotations arrive from the
//! forwarding domain through shared memory, already checked by `wire::tap` into
//! a [`CheckedTap`], and the frame bytes they describe are the network's. A
//! frame length is therefore never allowed to steer a write, and every record
//! is measured before a byte of it is placed.
//!
//! # Constraints that shaped it
//!
//! Nothing here touches a device. It decides *where* bytes belong and *what*
//! they are; the protection domain moves them. That is what makes a recording's
//! whole correctness — its framing, its sector alignment, its wrap, its
//! download addressing — reachable by a host test with a `Vec<u8>` for a disk.
//!
//! Two rules govern the placement, and between them they are why a download is
//! a byte range rather than a transformation. **Every device write is a whole
//! number of sectors and no sector is ever written twice**: the slack at the
//! end of a sector is filled with a pcapng Custom Block, which every reader
//! skips, rather than left for a later write to complete. And **a closed
//! segment is always exactly `segment_bytes` long**, padded out at the roll, so
//! the byte offset of a segment within a recording is a multiplication rather
//! than a running total nothing could recover after a wrap.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use lfw_capture_ring::{
    Append, Copies, Cursor, Fit, Geometry, Located, ReaderCursor, Ring, RingState, RingStateError,
    SECTOR_SIZE, SUPERBLOCK_BYTES, SuperblockWrite, encode_superblock,
};
use lfw_pcapng::{
    CustomBinary, EncodeError, EnhancedPacket, InterfaceDescription, LinkType,
    MIN_CUSTOM_BLOCK_LEN, SectionHeader, TimestampResolution, Verdict, VerdictKind,
    enhanced_packet_len, interface_description_len, section_header_len, write_enhanced_packet,
    write_interface_description, write_padding_block, write_section_header,
};
use wire::{CheckedTap, TapDirection, TapOutcome};

/// Interfaces one recording may describe, matching `wire::MAX_INTERFACES`.
pub const MAX_INTERFACES: usize = 8;

/// The longest interface identifier the configuration schema admits.
pub const MAX_INTERFACE_NAME: usize = 16;

/// Bytes held back at the end of every segment so a seal always has room for
/// its padding block.
///
/// A seal pads at most `SECTOR_SIZE - 4` bytes, plus a further `SECTOR_SIZE`
/// where that slack is too small to encode a Custom Block in. Two sectors cover
/// both, so "the padding always fits" is a property of the reservation rather
/// than a case a caller handles.
pub const TAIL_RESERVE: usize = 2 * SECTOR_SIZE;

/// The version byte leading [`ANNOTATION_LEN`]'s layout.
///
/// A reader keys on this rather than on the length it happens to see, which is
/// what lets the layout grow: version 1 carried the verdict, its reason and the
/// configuration generation, version 2 added the flow the observation is about,
/// what the packet did to it, and the rule that decided it, and version 3 widens
/// two of its vocabularies — a third verdict for the record that is about a flow
/// and about no frame, and the event that goes with it.
pub const ANNOTATION_VERSION: u8 = 3;

/// Bytes of firewall annotation carried in each record's Custom Option.
pub const ANNOTATION_LEN: usize = 24;

const ANNOTATION_VERDICT_FORWARDED: u8 = 0;
const ANNOTATION_VERDICT_DROPPED: u8 = 1;
/// Neither: the record is about a flow the appliance ended and about no frame.
/// Its packet block therefore carries no bytes and states a wire length of zero,
/// which is what says there was no packet rather than that a packet was empty.
const ANNOTATION_VERDICT_REVOKED: u8 = 2;

/// Where each field of the annotation begins: the offsets a reader outside this
/// workspace navigates by, so a shifted one is a field read as another.
const ANNOTATION_AT_VERSION: usize = 0;
const ANNOTATION_AT_VERDICT: usize = 1;
const ANNOTATION_AT_DROP_REASON: usize = 2;
const ANNOTATION_AT_INTERFACE: usize = 3;
const ANNOTATION_AT_DIRECTION: usize = 4;
const ANNOTATION_AT_CLASSIFICATION: usize = 5;
const ANNOTATION_AT_EVENT: usize = 6;
const ANNOTATION_AT_FLOW_STATE: usize = 7;
const ANNOTATION_AT_GENERATION: usize = 8;
const ANNOTATION_AT_FLOW_SLOT: usize = 12;
const ANNOTATION_AT_FLOW_GENERATION: usize = 16;
const ANNOTATION_AT_RULE: usize = 20;

/// pcapng `epb_flags`: bits 0-1 are the direction, 1 inbound and 2 outbound.
const FLAGS_INBOUND: u32 = 1;
const FLAGS_OUTBOUND: u32 = 2;

/// The verdict type octet of `epb_verdict`. The registered kinds name hardware
/// and two Linux eBPF hooks; a firewall's own verdict is none of those, so it
/// travels as the vendor-defined kind the annotation's version byte identifies.
const VERDICT_KIND: VerdictKind = VerdictKind(0xFF);

const _: () = {
    assert!(TAIL_RESERVE >= 2 * SECTOR_SIZE);
    assert!(TAIL_RESERVE > SECTOR_SIZE + MIN_CUSTOM_BLOCK_LEN);
    assert!(ANNOTATION_LEN.is_multiple_of(4));
    // The rule is the last field and takes two octets, so the layout ends
    // exactly where the length says it does.
    assert!(ANNOTATION_AT_RULE + 2 <= ANNOTATION_LEN);
    // Every value the annotation narrows to one octet must fit one, which the
    // tap ABI's own bounds already guarantee — restated here because this is
    // where the narrowing happens.
    assert!(wire::TAP_DROP_REASON_COUNT <= u8::MAX as u32);
    assert!(wire::TAP_CLASSIFICATION_COUNT <= u8::MAX as u32);
    assert!(wire::TAP_FLOW_STATE_COUNT <= u8::MAX as u32);
    assert!(wire::TAP_EVENT_COUNT <= u8::MAX as u32);
    // And the rule position, which takes two.
    assert!(wire::TAP_RULE_COUNT <= u16::MAX as u32);
};

/// One interface a recording describes, as one pcapng Interface Description
/// Block in every segment's prologue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceName {
    bytes: [u8; MAX_INTERFACE_NAME],
    len: u8,
}

impl InterfaceName {
    /// Truncates rather than refuses: a recording that would not start over a
    /// long identifier would trade the evidence for the label.
    #[must_use]
    pub fn new(name: &str) -> Self {
        let mut bytes = [0u8; MAX_INTERFACE_NAME];
        let source = name.as_bytes();
        let len = if source.len() < MAX_INTERFACE_NAME {
            source.len()
        } else {
            MAX_INTERFACE_NAME
        };
        let mut index = 0;
        while index < len {
            if let (Some(slot), Some(byte)) = (bytes.get_mut(index), source.get(index)) {
                *slot = *byte;
            }
            index += 1;
        }
        Self {
            bytes,
            len: len as u8,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        let len = self.len as usize;
        self.bytes
            .get(..len)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }
}

/// What a recording is: its extent, how much of each frame it keeps, and the
/// interfaces its prologue names.
#[derive(Clone, Copy, Debug)]
pub struct SinkConfig {
    pub geometry: Geometry,
    /// Bytes of each frame recorded — a consequence of what a recording is for
    /// rather than what distinguishes the two.
    pub snap_len: u32,
    pub interfaces: [InterfaceName; MAX_INTERFACES],
    pub interface_count: usize,
}

/// Why a sink could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SinkError {
    /// More interfaces than a prologue can describe.
    TooManyInterfaces { count: usize },
    /// The prologue does not fit a segment, so no record ever could.
    PrologueTooLong { prologue: usize, segment: usize },
    /// The encoder refused to measure the prologue.
    Encode(EncodeError),
    /// The stored superblock does not describe this deployment.
    State(RingStateError),
}

/// The outcome of offering one observation to a sink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recorded {
    /// Placed; `bytes` of the staging buffer now hold it.
    Placed { bytes: usize },
    /// No room left in the open segment: close it and retry.
    SegmentFull,
    /// No segment could ever hold it. Counted and dropped.
    Oversized { needed: usize },
    /// No room left in the staging buffer: flush and retry.
    StagingFull { needed: usize, free: usize },
    /// The encoder refused the record. Counted and dropped.
    Refused(EncodeError),
}

/// Whole sectors of the staging buffer the caller must put on the device.
///
/// Not `Copy`: [`Sink::acknowledge`] consumes it, so a flush cannot be
/// acknowledged twice or acknowledged without having been issued.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a flush names bytes the device has not been given yet"]
pub struct Flush {
    sector: u64,
    len: usize,
}

impl Flush {
    /// The first device sector the bytes go to.
    #[must_use]
    pub const fn sector(&self) -> u64 {
        self.sector
    }

    /// Bytes from the front of staging, always a whole number of sectors.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Where a byte of a recording lives on the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    sector: u64,
    skip: usize,
    len: usize,
}

impl Span {
    /// The first sector to read.
    #[must_use]
    pub const fn sector(&self) -> u64 {
        self.sector
    }

    /// Bytes to discard from the front of that sector.
    #[must_use]
    pub const fn skip(&self) -> usize {
        self.skip
    }

    /// Bytes of body available from there without leaving the segment.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Sectors a caller must read to cover the span.
    #[must_use]
    pub const fn sectors(&self) -> u64 {
        ((self.skip + self.len).div_ceil(SECTOR_SIZE)) as u64
    }
}

/// What a reader's position resolves to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Locate {
    Live(Span),
    /// Past the last byte the reader may have: the end of what the medium took.
    /// Nothing there **yet**.
    PastEnd,
    /// The ring wrapped over these bytes, so the caller must abandon what it was
    /// reading rather than continue from a byte it did not ask for.
    Overrun,
}

/// Saturating, monotone counts for the operator-facing metrics contract.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SinkCounters {
    pub records: u64,
    pub record_bytes: u64,
    pub dropped_oversized: u64,
    /// Records refused for want of staging room. **Not a drop** — the record is
    /// still the caller's, and [`crate::deck::Deck`] re-offers it after a flush.
    pub staging_deferrals: u64,
    pub dropped_refused: u64,
    pub segments_closed: u64,
    pub wraps: u64,
    pub sectors_written: u64,
    pub padding_bytes: u64,
}

/// Which reader the **management channel's** cursor is in the superblock's
/// reader table. The identifier is what makes a cursor survive a restart *as
/// that reader's*; one and not zero, so a slot is legible in a hex dump.
pub const CHANNEL_READER_ID: u32 = 1;

/// One recording sink.
#[derive(Debug)]
pub struct Sink {
    ring: Ring,
    snap_len: u32,
    interfaces: [InterfaceName; MAX_INTERFACES],
    interface_count: usize,
    /// The segment the staging buffer's bytes belong to. Held separately from
    /// the ring's cursor because a roll advances the cursor while the closed
    /// segment's last sectors are still in the buffer, and a flush addressed
    /// with the new sequence would write them over the next segment.
    staged_sequence: u64,
    /// Segment byte offset the staging buffer's first byte holds. Always a
    /// multiple of `SECTOR_SIZE`, which `Sink::resume` refuses a state without.
    staged_from: usize,
    /// Bytes of staging currently holding appended, unflushed record data.
    staged_len: usize,
    /// Everything the device has acknowledged.
    durable: Cursor,
    reader: Option<Cursor>,
    /// Whether the superblock region may still hold another ring's — so until a
    /// checkpoint of this one reached the device, and never for a resumed sink.
    superblock_stale: bool,
    /// True while a [`Flush`] is outstanding.
    flushing: bool,
    /// Tap-ring drops to attribute to the next record, so the file states its
    /// own loss in-band.
    pending_drops: u64,
    counters: SinkCounters,
}

impl Sink {
    /// Build a sink over a fresh extent, composing its opening prologue into
    /// `staging` rather than leaving a call for the caller to remember: records
    /// staged over an absent prologue put the staging offset out of step with
    /// the ring cursor, and every later flush is addressed short of its bytes.
    ///
    /// # Errors
    /// [`SinkError`] when the interfaces do not fit a prologue, it does not fit a
    /// segment, or the staging buffer cannot hold it.
    pub fn new(config: SinkConfig, staging: &mut [u8]) -> Result<Self, SinkError> {
        let prologue = prologue_len(&config)?;
        if !payload_fits(prologue, config.geometry.segment_bytes()) {
            return Err(SinkError::PrologueTooLong {
                prologue,
                segment: config.geometry.segment_bytes(),
            });
        }
        let mut sink = Self {
            ring: Ring::new(config.geometry, prologue),
            snap_len: config.snap_len,
            interfaces: config.interfaces,
            interface_count: config.interface_count,
            staged_sequence: 0,
            staged_from: 0,
            staged_len: 0,
            durable: Cursor {
                sequence: 0,
                offset: 0,
            },
            reader: None,
            superblock_stale: true,
            flushing: false,
            pending_drops: 0,
            counters: SinkCounters::default(),
        };
        sink.write_prologue(staging).map_err(SinkError::Encode)?;
        Ok(sink)
    }

    /// Resume from a superblock a previous boot left, continuing in the segment
    /// its writer cursor names at the offset it names, a pcapng section opened
    /// there — so the predecessor's unpadded tail lies beyond this boot's own
    /// write cursor rather than inside a segment it has closed.
    ///
    /// # Errors
    /// As [`Sink::new`], plus [`SinkError::State`] for a stored state that is
    /// not this deployment's geometry or names a position no run of this left.
    pub fn resume(
        config: SinkConfig,
        state: &RingState,
        staging: &mut [u8],
    ) -> Result<Self, SinkError> {
        let checked = state.check(&config.geometry).map_err(SinkError::State)?;
        // A flush addresses the staging buffer's first byte by the sector, so a
        // position between two is one this ring never wrote and one a resumed
        // write would land short of.
        if !checked.writer().offset.is_multiple_of(SECTOR_SIZE) {
            return Err(SinkError::State(
                RingStateError::WriterOffsetNotSectorMultiple {
                    offset: checked.writer().offset,
                },
            ));
        }
        let mut sink = Self::new(config, staging)?;
        let prologue = sink.ring.prologue_len();
        sink.ring = Ring::resume(checked, prologue);
        let at = sink.ring.cursor();
        sink.staged_sequence = at.sequence;
        sink.staged_from = at.offset;
        sink.staged_len = 0;
        sink.durable = at;
        // Carried across the restart, and republished until one moves it.
        sink.reader = checked
            .readers()
            .iter()
            .flatten()
            .find(|reader| reader.id == CHANNEL_READER_ID)
            .map(|reader| reader.cursor);
        sink.superblock_stale = false;
        // Through `fit`, which counts nothing: a header is not an oversized record.
        match sink.ring.fit(prologue) {
            Fit::Fits(_) => {
                if let Append::Placed(reservation) = sink.ring.append(prologue) {
                    reservation.commit();
                    sink.write_prologue(staging).map_err(SinkError::Encode)?;
                }
            }
            Fit::SegmentFull | Fit::Oversized { .. } => {
                sink.close_segment(staging).map_err(SinkError::Encode)?;
            }
        }
        Ok(sink)
    }

    #[must_use]
    pub const fn counters(&self) -> SinkCounters {
        self.counters
    }

    #[must_use]
    pub const fn snap_len(&self) -> u32 {
        self.snap_len
    }

    /// Bytes of the staging buffer currently holding unflushed records.
    #[must_use]
    pub const fn staged(&self) -> usize {
        self.staged_len
    }

    #[must_use]
    pub const fn cursor(&self) -> Cursor {
        self.ring.cursor()
    }

    /// The most one segment can ever hold, a block too large reported against it.
    #[must_use]
    pub const fn segment_payload(&self) -> usize {
        self.ring.segment_payload()
    }

    /// Where this recording's superblock goes: the first sector of its extent,
    /// which no record ever reaches.
    #[must_use]
    pub const fn superblock_sector(&self) -> u64 {
        self.ring.geometry().superblock_sector()
    }

    /// The segment the staging buffer's bytes belong to, which a flush is
    /// addressed against and which trails the ring's cursor across a roll.
    #[must_use]
    pub const fn staged_sequence(&self) -> u64 {
        self.staged_sequence
    }

    /// Note tap-ring drops observed since the last record, for the next
    /// record's `epb_dropcount`.
    pub fn note_drops(&mut self, drops: u64) {
        self.pending_drops = self.pending_drops.saturating_add(drops);
    }

    /// Encode one observation into the staging buffer.
    pub fn record(&mut self, tap: &CheckedTap, frame: &[u8], staging: &mut [u8]) -> Recorded {
        let captured_len = frame.len().min(self.snap_len as usize);
        // `captured_len` is a minimum with `frame.len()`, so the slice is the
        // whole frame or a prefix of it; the fallback is unreachable and says
        // so by recording more rather than by branching on the impossible.
        let captured = frame.get(..captured_len).unwrap_or(frame);
        let annotation = self.annotation(tap);
        let verdict_data = [annotation_verdict(tap)];
        let epb = EnhancedPacket {
            interface_id: u32::from(tap.interface_id),
            timestamp: tap.timestamp,
            captured,
            original_len: tap.original_len,
            // Absent on a record about no frame: `epb_flags`' direction bits
            // describe a packet on a wire, and there was none.
            flags: tap.direction.map(|direction| match direction {
                TapDirection::Inbound => FLAGS_INBOUND,
                TapDirection::Outbound => FLAGS_OUTBOUND,
            }),
            drop_count: Some(self.pending_drops),
            packet_id: Some(tap.packet_id),
            queue: None,
            verdict: Some(Verdict {
                kind: VERDICT_KIND,
                data: &verdict_data,
            }),
            custom: Some(CustomBinary {
                pen: lfw_pcapng::UNREGISTERED_PEN,
                data: &annotation,
            }),
            comment: None,
        };
        let needed = match enhanced_packet_len(&epb) {
            Ok(needed) => needed,
            Err(error) => {
                self.counters.dropped_refused = self.counters.dropped_refused.saturating_add(1);
                return Recorded::Refused(error);
            }
        };
        // A record is only accepted with the tail reserve still to spare, so a
        // seal's padding block always has room — see `TAIL_RESERVE`. Saturating
        // rather than checked: a sum at `usize::MAX` exceeds every segment, so
        // the refusal below is already the right answer for it.
        let claim = needed.saturating_add(TAIL_RESERVE);
        if claim > self.ring.segment_payload() {
            self.counters.dropped_oversized = self.counters.dropped_oversized.saturating_add(1);
            return Recorded::Oversized { needed };
        }
        if claim > self.ring.slack() {
            return Recorded::SegmentFull;
        }
        let out = self.free(staging);
        let written = match write_enhanced_packet(out, &epb) {
            Ok(written) => written,
            Err(EncodeError::OutOfSpace { needed, capacity }) => {
                self.counters.staging_deferrals = self.counters.staging_deferrals.saturating_add(1);
                return Recorded::StagingFull {
                    needed,
                    free: capacity,
                };
            }
            Err(error) => {
                self.counters.dropped_refused = self.counters.dropped_refused.saturating_add(1);
                return Recorded::Refused(error);
            }
        };
        match self.ring.append(written) {
            Append::Placed(reservation) => {
                reservation.commit();
            }
            Append::SegmentFull => return Recorded::SegmentFull,
            Append::Oversized { .. } => {
                self.counters.dropped_oversized = self.counters.dropped_oversized.saturating_add(1);
                return Recorded::Oversized { needed: written };
            }
        }
        self.staged_len = self.staged_len.saturating_add(written);
        self.pending_drops = 0;
        self.counters.records = self.counters.records.saturating_add(1);
        self.counters.record_bytes = self.counters.record_bytes.saturating_add(written as u64);
        Recorded::Placed { bytes: written }
    }

    /// Encode one PEN-tagged Custom Block carrying `data` into the staging
    /// buffer.
    ///
    /// The same eight steps [`Sink::record`] takes and in the same order —
    /// measure, claim the tail reserve, refuse what no segment could hold, refuse
    /// what this one cannot, write into staging, re-offer rather than drop when
    /// staging is full, place, commit — because a block that skipped any of them
    /// could leave a segment without room for its seal. `data` is opaque, save
    /// that one leading with a zero byte, or with none, reads as the padding
    /// below. **It touches none of this sink's counters**:
    /// `records` and `record_bytes` are the account of *observations*, held by
    /// the gate to the packet blocks in the file and the frames put on the wire.
    pub fn block(&mut self, data: &[u8], staging: &mut [u8]) -> Recorded {
        let body = CustomBinary {
            pen: lfw_pcapng::UNREGISTERED_PEN,
            data,
        };
        let needed = match lfw_pcapng::custom_block_len(&body) {
            Ok(needed) => needed,
            Err(error) => return Recorded::Refused(error),
        };
        let claim = needed.saturating_add(TAIL_RESERVE);
        if claim > self.ring.segment_payload() {
            return Recorded::Oversized { needed };
        }
        if claim > self.ring.slack() {
            return Recorded::SegmentFull;
        }
        let out = self.free(staging);
        let written = match lfw_pcapng::write_custom_block(out, &body) {
            Ok(written) => written,
            Err(EncodeError::OutOfSpace { needed, capacity }) => {
                return Recorded::StagingFull {
                    needed,
                    free: capacity,
                };
            }
            Err(error) => return Recorded::Refused(error),
        };
        match self.ring.append(written) {
            Append::Placed(reservation) => {
                reservation.commit();
            }
            Append::SegmentFull => return Recorded::SegmentFull,
            Append::Oversized { .. } => return Recorded::Oversized { needed: written },
        }
        self.staged_len = self.staged_len.saturating_add(written);
        Recorded::Placed { bytes: written }
    }

    /// Complete the open sector with a padding block, so what is on the device
    /// is a whole file. Call before serving a download.
    ///
    /// # Errors
    /// [`EncodeError`] when the staging buffer cannot hold the padding.
    pub fn seal(&mut self, staging: &mut [u8]) -> Result<usize, EncodeError> {
        let offset = self.ring.cursor().offset;
        let remainder = offset % SECTOR_SIZE;
        if remainder == 0 {
            return Ok(0);
        }
        let mut pad = SECTOR_SIZE - remainder;
        if pad < MIN_CUSTOM_BLOCK_LEN {
            pad += SECTOR_SIZE;
        }
        self.pad(pad, staging)
    }

    /// Fill the rest of the open segment with padding, so a closed segment is
    /// exactly `segment_bytes` long and holds none of the previous wrap. It
    /// does **not** roll: the bytes it just placed are still in the staging
    /// buffer and are addressed against this segment.
    ///
    /// # Errors
    /// [`EncodeError`] when the staging buffer cannot hold the padding.
    pub fn close_segment(&mut self, staging: &mut [u8]) -> Result<usize, EncodeError> {
        let pad = self.ring.slack();
        let padded = if pad == 0 { 0 } else { self.pad(pad, staging)? };
        self.counters.segments_closed = self.counters.segments_closed.saturating_add(1);
        Ok(padded)
    }

    /// Roll to the next segment and write its prologue. Call only once the
    /// closed segment's bytes are on the device: staging is reused, so calling
    /// it early makes [`Sink::snapshot`] promise bytes the device never took and
    /// [`Sink::take_flush`] address a write outside its own segment. Enforced by
    /// [`crate::deck::Deck::advance`], which reopens only while rolling with no
    /// flush held and nothing staged, and proved by its
    /// `a_segment_reopens_only_once_its_predecessor_is_durable`.
    ///
    /// # Errors
    /// [`EncodeError`] when the staging buffer cannot hold a prologue.
    pub fn begin_segment(&mut self, staging: &mut [u8]) -> Result<usize, EncodeError> {
        let before = self.ring.counters().wraps;
        self.ring.roll();
        self.counters.wraps = self
            .counters
            .wraps
            .saturating_add(self.ring.counters().wraps.saturating_sub(before));
        self.staged_sequence = self.ring.cursor().sequence;
        self.staged_from = 0;
        self.staged_len = 0;
        self.write_prologue(staging)
    }

    /// Whole sectors of the staging buffer ready for the device, or `None` when
    /// there are none, one is outstanding, or the seal below cannot be composed.
    ///
    /// The open sector is completed first, so what the device takes ends on a
    /// **block** boundary: the position the superblock then names is where the
    /// next boot writes, and a truncated head there would derail every walk.
    pub fn take_flush(&mut self, staging: &mut [u8]) -> Option<Flush> {
        if self.flushing {
            return None;
        }
        self.seal(staging).ok()?;
        let whole = (self.staged_len / SECTOR_SIZE) * SECTOR_SIZE;
        if whole == 0 {
            return None;
        }
        let sector = self
            .ring
            .geometry()
            .segment_sector(self.staged_sequence)
            .saturating_add((self.staged_from / SECTOR_SIZE) as u64);
        self.flushing = true;
        Some(Flush { sector, len: whole })
    }

    /// Record that the device has taken a flush's bytes, shifting the staging
    /// buffer down over them and advancing what a download may see.
    pub fn acknowledge(&mut self, flush: Flush, staging: &mut [u8]) {
        let Flush { len, .. } = flush;
        self.flushing = false;
        let tail = self.staged_len.saturating_sub(len);
        if let Some(bytes) = staging.get_mut(..self.staged_len) {
            bytes.copy_within(len.min(self.staged_len).., 0);
        }
        self.staged_from = self.staged_from.saturating_add(len);
        self.staged_len = tail;
        // A segment written to its end is durable as a whole, and is stated as
        // the next segment at offset zero so a snapshot's arithmetic is one
        // multiplication rather than a special case per segment.
        self.durable = if self.staged_from >= self.ring.geometry().segment_bytes() {
            Cursor {
                sequence: self.staged_sequence.saturating_add(1),
                offset: 0,
            }
        } else {
            Cursor {
                sequence: self.staged_sequence,
                offset: self.staged_from,
            }
        };
        self.counters.sectors_written = self
            .counters
            .sectors_written
            .saturating_add((len / SECTOR_SIZE) as u64);
    }

    /// Compose this recording's next superblock into `image`, answering which part
    /// of the region the caller must put on the medium.
    ///
    /// It records the **durable** cursor: a superblock states where the recording
    /// ends to anything holding the disk, and the append cursor runs ahead of it
    /// by everything still staged.
    ///
    /// # Errors
    /// [`RingStateError`] when the cursor cannot be represented.
    pub fn superblock(
        &mut self,
        image: &mut [u8; SUPERBLOCK_BYTES],
    ) -> Result<SuperblockWrite, RingStateError> {
        let readers = self.reader.map(|cursor| ReaderCursor {
            id: CHANNEL_READER_ID,
            cursor,
        });
        let state = self.ring.checkpoint(self.durable, readers.as_slice())?;
        let copies = if self.superblock_stale {
            Copies::Both
        } else {
            Copies::Parity
        };
        Ok(encode_superblock(image, &state, copies))
    }

    pub fn acknowledge_checkpoint(&mut self) {
        self.superblock_stale = false;
    }

    /// Take a management server's word for how far it has durably ingested this
    /// recording, and answer whether that moved the reader cursor. `position`
    /// came off the wire and is clamped three ways. **Never past the writer**: a
    /// ring refuses a cursor ahead of its writer, so a claim past the end would
    /// stop this appliance making *any* of it durable. **Never behind the oldest
    /// byte the medium holds**, and **never backward**.
    pub fn acknowledge_reader(&mut self, position: u64) -> bool {
        let segment = self.ring.geometry().segment_bytes() as u64;
        if segment == 0 {
            // Unreachable, and answered rather than divided by, on `find`'s terms.
            return false;
        }
        let bounded = position
            .max(self.first_position())
            .min(self.durable_position());
        let sequence = bounded / segment;
        // Not redundant: a durable cursor at a segment's end puts
        // `durable_position` one sequence past the writer.
        let cursor = if sequence > self.durable.sequence {
            self.durable
        } else {
            Cursor {
                sequence,
                offset: (bounded % segment) as usize,
            }
        };
        let held = self.reader;
        if held.is_some_and(|held| (cursor.sequence, cursor.offset) <= (held.sequence, held.offset))
        {
            return false;
        }
        self.reader = Some(cursor);
        true
    }

    #[must_use]
    pub const fn reader(&self) -> Option<Cursor> {
        self.reader
    }

    /// One past the last byte of this ring the medium has taken, as an absolute
    /// position in its own append space. The append cursor runs ahead by
    /// everything staged, which a reader must not cross: the sectors under those
    /// bytes still hold the previous wrap.
    #[must_use]
    pub const fn durable_position(&self) -> u64 {
        let segment = self.ring.geometry().segment_bytes() as u64;
        self.durable
            .sequence
            .saturating_mul(segment)
            .saturating_add(self.durable.offset as u64)
    }

    /// The oldest position still on the medium, in [`Self::durable_position`]'s append space.
    #[must_use]
    pub fn first_position(&self) -> u64 {
        let (oldest, _) = self.ring.readable();
        let segment = self.ring.geometry().segment_bytes() as u64;
        oldest.saturating_mul(segment)
    }

    /// Where absolute ring position `position` lives on the device. The
    /// coordinate is `sequence * segment_bytes + offset`, which a restart
    /// preserves — which is why it is the only one this sink resolves.
    pub fn find(&mut self, position: u64) -> Locate {
        let durable = self.durable_position();
        if position >= durable {
            return Locate::PastEnd;
        }
        let segment = self.ring.geometry().segment_bytes() as u64;
        // `Geometry::new` refuses a segment of no bytes; answered rather than
        // divided by, no fault being admissible here.
        if segment == 0 {
            return Locate::PastEnd;
        }
        if position < self.first_position() {
            return Locate::Overrun;
        }
        let sequence = position / segment;
        let within = (position % segment) as usize;
        match self.ring.locate(sequence, within) {
            Located::Live(placement) => Locate::Live(Span {
                sector: placement
                    .sector()
                    .saturating_add((within / SECTOR_SIZE) as u64),
                skip: within % SECTOR_SIZE,
                len: (placement.len() as u64).min(durable.saturating_sub(position)) as usize,
            }),
            Located::Overrun { .. } => Locate::Overrun,
            Located::Unwritten => Locate::PastEnd,
        }
    }

    /// The firewall state pcapng has no standard field for, as the bytes the
    /// record's Custom Option carries.
    ///
    /// Every narrowing here is of a value the tap ABI already bounded, so none can
    /// truncate; the assertion block states the bounds it relies on. A zero names
    /// *absent* rather than a member, as it does in that ABI.
    fn annotation(&self, tap: &CheckedTap) -> [u8; ANNOTATION_LEN] {
        let mut annotation = [0u8; ANNOTATION_LEN];
        let drop_reason = match tap.outcome {
            TapOutcome::Forwarded | TapOutcome::Revoked => 0,
            TapOutcome::Dropped(reason) => reason.to_bits() as u8,
        };
        let octets = [
            (ANNOTATION_AT_VERSION, ANNOTATION_VERSION),
            (ANNOTATION_AT_VERDICT, annotation_verdict(tap)),
            (ANNOTATION_AT_DROP_REASON, drop_reason),
            (ANNOTATION_AT_INTERFACE, tap.interface_id),
            (
                ANNOTATION_AT_DIRECTION,
                // Zero also names inbound, which is what a record with no
                // direction shares with one that came in: the verdict octet is
                // what tells them apart, and it is checked before this is read.
                match tap.direction {
                    Some(TapDirection::Inbound) | None => 0,
                    Some(TapDirection::Outbound) => 1,
                },
            ),
            (
                ANNOTATION_AT_CLASSIFICATION,
                match tap.flow.and_then(|flow| flow.classification) {
                    Some(classification) => classification.to_bits() as u8,
                    None => 0,
                },
            ),
            (
                ANNOTATION_AT_EVENT,
                match tap.event {
                    Some(event) => event.to_bits() as u8,
                    None => 0,
                },
            ),
            (
                ANNOTATION_AT_FLOW_STATE,
                match tap.flow {
                    Some(flow) => flow.state.to_bits() as u8,
                    None => 0,
                },
            ),
        ];
        for (at, value) in octets {
            if let Some(slot) = annotation.get_mut(at) {
                *slot = value;
            }
        }
        let words = [
            (ANNOTATION_AT_GENERATION, tap.generation),
            (
                ANNOTATION_AT_FLOW_SLOT,
                tap.flow.map_or(0, |flow| flow.slot),
            ),
            (
                ANNOTATION_AT_FLOW_GENERATION,
                tap.flow.map_or(0, |flow| flow.generation),
            ),
        ];
        for (at, value) in words {
            if let Some(target) = annotation.get_mut(at..at.saturating_add(4)) {
                target.copy_from_slice(&value.to_le_bytes());
            }
        }
        // One higher than the position, so zero names *no rule matched* rather
        // than the first rule of the generation.
        let rule = tap.rule.map_or(0, |rule| rule.position().saturating_add(1));
        if let Some(target) =
            annotation.get_mut(ANNOTATION_AT_RULE..ANNOTATION_AT_RULE.saturating_add(2))
        {
            target.copy_from_slice(&rule.to_le_bytes());
        }
        annotation
    }

    /// The staging a record may use: what is unwritten, less a seal's room.
    fn free<'a>(&self, staging: &'a mut [u8]) -> &'a mut [u8] {
        let end = staging.len().saturating_sub(TAIL_RESERVE);
        staging.get_mut(self.staged_len..end).unwrap_or_default()
    }

    fn pad(&mut self, pad: usize, staging: &mut [u8]) -> Result<usize, EncodeError> {
        if pad < MIN_CUSTOM_BLOCK_LEN {
            return Err(EncodeError::BlockTooShort { len: pad });
        }
        let out: &mut [u8] = staging.get_mut(self.staged_len..).unwrap_or_default();
        let written = write_padding_block(out, pad)?;
        match self.ring.append(written) {
            Append::Placed(reservation) => {
                reservation.commit();
            }
            Append::SegmentFull | Append::Oversized { .. } => {
                return Err(EncodeError::OutOfSpace {
                    needed: written,
                    capacity: self.ring.slack(),
                });
            }
        }
        self.staged_len = self.staged_len.saturating_add(written);
        self.counters.padding_bytes = self.counters.padding_bytes.saturating_add(written as u64);
        Ok(written)
    }

    fn write_prologue(&mut self, staging: &mut [u8]) -> Result<usize, EncodeError> {
        // From the staged tail, as `record` and `pad` do, rather than from zero,
        // which is correct only while every caller empties the buffer first.
        let at = self.staged_len;
        let mut written = 0usize;
        let header = SectionHeader {
            hardware: None,
            os: Some("librefirewall"),
            application: Some("librefirewall recorder"),
            schema: Some(CustomBinary {
                pen: lfw_pcapng::UNREGISTERED_PEN,
                data: &[ANNOTATION_VERSION, 0, 0, 0],
            }),
        };
        let out: &mut [u8] = staging
            .get_mut(at.saturating_add(written)..)
            .unwrap_or_default();
        written += write_section_header(out, &header)?;
        for index in 0..self.interface_count {
            let name = self.interfaces.get(index).copied().unwrap_or(EMPTY_NAME);
            let idb = self.interface_description(&name);
            let out: &mut [u8] = staging
                .get_mut(at.saturating_add(written)..)
                .unwrap_or_default();
            written += write_interface_description(out, &idb)?;
        }
        self.staged_len = self.staged_len.saturating_add(written);
        Ok(written)
    }

    fn interface_description<'a>(&self, name: &'a InterfaceName) -> InterfaceDescription<'a> {
        InterfaceDescription {
            link_type: LinkType::ETHERNET,
            snap_len: self.snap_len,
            name: Some(name.as_str()),
            description: None,
            speed: None,
            timestamp_resolution: TimestampResolution::MICROSECONDS,
        }
    }
}

const EMPTY_NAME: InterfaceName = InterfaceName {
    bytes: [0; MAX_INTERFACE_NAME],
    len: 0,
};

/// Whether a segment has room for a record once its prologue and the tail
/// reserve are deducted. Extracted so the refusal can be judged on its own
/// numbers: the schema's eight interfaces produce a prologue far below the
/// smallest legal segment, so no configuration this build accepts reaches it.
const fn payload_fits(prologue: usize, segment_bytes: usize) -> bool {
    match prologue.checked_add(TAIL_RESERVE) {
        Some(claim) => claim < segment_bytes,
        None => false,
    }
}

const fn annotation_verdict(tap: &CheckedTap) -> u8 {
    match tap.outcome {
        TapOutcome::Forwarded => ANNOTATION_VERDICT_FORWARDED,
        TapOutcome::Dropped(_) => ANNOTATION_VERDICT_DROPPED,
        TapOutcome::Revoked => ANNOTATION_VERDICT_REVOKED,
    }
}

/// The bytes a segment prologue occupies, measured with the same calls that
/// write it so the ring's reservation and the encoder cannot disagree.
///
/// # Errors
/// [`SinkError`] when there are more interfaces than a recording may describe,
/// or the encoder refuses to measure one.
pub fn prologue_len(config: &SinkConfig) -> Result<usize, SinkError> {
    if config.interface_count > MAX_INTERFACES {
        return Err(SinkError::TooManyInterfaces {
            count: config.interface_count,
        });
    }
    let header = SectionHeader {
        hardware: None,
        os: Some("librefirewall"),
        application: Some("librefirewall recorder"),
        schema: Some(CustomBinary {
            pen: lfw_pcapng::UNREGISTERED_PEN,
            data: &[ANNOTATION_VERSION, 0, 0, 0],
        }),
    };
    let mut total = section_header_len(&header).map_err(SinkError::Encode)?;
    for index in 0..config.interface_count {
        let name = config.interfaces.get(index).copied().unwrap_or(EMPTY_NAME);
        let idb = InterfaceDescription {
            link_type: LinkType::ETHERNET,
            snap_len: config.snap_len,
            name: Some(name.as_str()),
            description: None,
            speed: None,
            timestamp_resolution: TimestampResolution::MICROSECONDS,
        };
        total = total
            .checked_add(interface_description_len(&idb).map_err(SinkError::Encode)?)
            .ok_or(SinkError::PrologueTooLong {
                prologue: usize::MAX,
                segment: config.geometry.segment_bytes(),
            })?;
    }
    Ok(total)
}

pub mod deck;
pub mod preload;

pub use deck::{
    Area, COMPLETION_BUDGET, Completion, Deck, DeckError, Ended, Job, Medium, Opened, Polled,
    RecorderCounters, Refused, Served, TAP_BUDGET, Transfer, Which,
};
pub use preload::{POLL_BUDGET, PreloadError, read_superblocks};

#[cfg(test)]
mod tests;
