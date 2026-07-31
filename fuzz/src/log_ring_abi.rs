//! The byzantine peer's reach into the two regions a `wire` log ring is laid
//! across.
//!
//! # Why this exists
//!
//! `LogRecords`'s cursor, drop count and slot array and `LogConsume`'s cursor
//! are **private fields with no accessor**, and that is correct: the crate's
//! own header gives the reason — a caller that could reach a field could choose
//! its own `Ordering`, and which ordering each word carries is a property of
//! the transport rather than a convention its users are asked to keep (DOC-9).
//!
//! A peer protection domain is under no such constraint. It maps the very same
//! pages, and which of the two it maps read-write is the whole of the
//! asymmetry: a writing domain owns the records region and reads the consume
//! cursor, the console domain owns the consume region and reads the records.
//! Every word on the side a domain owns is a plain address it may store to at
//! any moment. A harness that could not write them would be modelling a
//! *polite* peer and would exclude the entire adversarial region — the TEST-8
//! failure this workspace exists to correct.
//!
//! So the peer is reproduced the way the peer really works: through the
//! regions' `#[repr(C)]` ABI, with atomic stores of the widths the ABI
//! declares. That is not a back door into private state; it is the
//! shared-memory image, and it is an ABI precisely so a second address space
//! can address it.
//!
//! # The layout this rests on, and who guarantees it
//!
//! Guaranteed by two `const _` blocks that fail the build if any of it moves —
//! `crates/wire/src/log_ring.rs` for the regions and
//! `crates/wire/src/log_slot.rs` for the slot:
//!
//! * `offset_of!(LogRecords, tail) == 0` and `dropped == 4`, both `AtomicU32`;
//! * `offset_of!(LogRecords, slots) == 8`, and
//!   `size_of::<LogRecords>() == 8 + LOG_RING_SLOTS * size_of::<LogRecord>()`,
//!   so the slots are `LOG_RING_SLOTS` consecutive [`RECORD_BYTES`]-byte images;
//! * `align_of::<LogRecords>() == align_of::<AtomicU64>()`, which is what makes
//!   every quadword location below naturally aligned;
//! * `offset_of!(LogConsume, head) == 0`, `AtomicU32`, and the region is 4 bytes;
//! * every field of `LogSlot` sits at its `LogRecord` counterpart's offset and
//!   is the atomic of that field's own width, which is what [`SEGMENTS`]
//!   restates.
//!
//! Every offset below is computed from those constants alone — never from a
//! value read out of a region — and every slot index is reduced modulo
//! `LOG_RING_SLOTS` before use, so no input can drive an access outside a
//! region.
//!
//! # Why the peer stores one location at a time
//!
//! A slot is 147 separate atomics and `LogSlot::load` reads them as 147
//! separate relaxed loads, so the peer's real granularity is **one atomic**,
//! not one record. That distinction is the whole of the torn-read hazard
//! `log_ring`'s own header names ("per-field atomics mean a write concurrent
//! with a read can yield a record whose fields come from different writes"),
//! and a view that could only store whole records would have excluded it —
//! TEST-8, because a *conforming* writer publishes whole records and only a
//! byzantine one leaves a slot half-rewritten.
//!
//! [`store_location`](LogRingPeer::store_location) is therefore the primitive
//! and [`store_record`](LogRingPeer::store_record) is 147 of it. Single-location
//! coherence makes that sufficient rather than merely convenient: each atomic's
//! `load` returns *some* value stored to it at or before the load, so the
//! records a torn read can produce are exactly the location-wise mixtures, and
//! a harness that can set each location independently between operations
//! reaches all of them without a second thread — whose unsynchronised writes
//! into the same words would be a data race this harness manufactured itself.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use wire::{LOG_RING_SLOTS, LogConsume, LogRecord, LogRecords};

use crate::log_record::RECORD_BYTES;

/// Byte offset of the records region's published producer cursor.
const TAIL_OFFSET: usize = 0;
/// Byte offset of the writer's published drop count.
const DROPPED_OFFSET: usize = 4;
/// Byte offset at which the slot array starts.
const SLOTS_OFFSET: usize = 8;
/// Byte offset of the consume region's published consumer cursor.
const HEAD_OFFSET: usize = 0;

/// The width of one atomic location within a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Width {
    Byte,
    Word,
    Quad,
}

impl Width {
    /// Bytes this width occupies, which is also the alignment the ABI gives it.
    const fn bytes(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 4,
            Self::Quad => 8,
        }
    }
}

/// One run of consecutive same-width atomics within a slot: the location index
/// the run starts at, the byte offset it starts at, how many there are, and
/// their width.
///
/// This is the slot's atomic layout restated from the ABI contract rather than
/// derived from `LogSlot`, whose fields are private — and restating it is what
/// makes it checkable: [`tests::the_segments_partition_the_whole_record`] holds
/// the runs to covering all [`RECORD_BYTES`] exactly once, contiguously, each
/// location naturally aligned. A field that moved without this moving would
/// fail there rather than silently putting a peer store in the wrong place.
///
/// The runs, in order: `features`, the two `operands`, the two quads a measured
/// clock carries and the two a terminal endpoint's counts do; the six `u32`
/// counters from `kind` to `receive_posted`; the ten vocabulary bytes, the six
/// pad bytes and the whole of `cause` and `key`; `from.number`; the rest of
/// `from`; `to.number`; the rest of `to`.
const SEGMENTS: &[(usize, usize, usize, Width)] = &[
    (0, 0, 7, Width::Quad),
    (7, 56, 6, Width::Word),
    (13, 80, 80, Width::Byte),
    (93, 160, 1, Width::Word),
    (94, 164, 28, Width::Byte),
    (122, 192, 1, Width::Word),
    (123, 196, 28, Width::Byte),
];

/// How many separately writable atomics one slot holds.
pub const LOCATION_COUNT: usize = 151;

/// Which atomic of a slot a peer store lands in.
///
/// A type with a private field rather than a bare index, so no caller can name
/// a location the slot does not have: the bound the accesses below rest on is
/// carried by the type instead of by a check every call site is trusted to have
/// made (DOC-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Location(usize);

impl Location {
    /// Pick a location from an arbitrary word, so the fuzzer chooses which
    /// atomic a peer store lands in.
    #[must_use]
    pub const fn from_selector(selector: u32) -> Self {
        Self(selector as usize % LOCATION_COUNT)
    }

    /// Every location of a slot, in offset order.
    pub fn all() -> impl Iterator<Item = Self> {
        (0..LOCATION_COUNT).map(Self)
    }

    /// This location's index, so a caller can index its own per-location shadow
    /// of a slot by the same number.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }

    /// Where this location sits within a slot, and how wide it is.
    ///
    /// Total by construction: `Location` is only ever built from a value
    /// reduced modulo [`LOCATION_COUNT`], and [`SEGMENTS`] covers `0..147`
    /// without a gap — which [`tests::the_segments_partition_the_whole_record`]
    /// is what proves. The fallback is the last run rather than a panic
    /// because a branch safe Rust cannot delete is not a failure to surface.
    fn placement(self) -> (usize, Width) {
        let mut last = (0, Width::Byte);
        for &(first, offset, count, width) in SEGMENTS {
            last = (offset, width);
            if self.0 >= first && self.0 - first < count {
                return (offset + (self.0 - first) * width.bytes(), width);
            }
        }
        last
    }
}

/// A byzantine peer's view of a log ring: the records region's cursor, drop
/// count and every slot, and the consume region's cursor.
///
/// Holds both region borrows, so the words it addresses are live for as long as
/// the view is. Constructing one asserts nothing about the peer's behaviour —
/// the point is that it has no obligations at all.
///
/// One view over both regions rather than two, because a harness must be able
/// to drive them *together*: the two are separately granted and independently
/// hostile, and the interesting inputs are the ones where a forged consume
/// cursor and a rewritten slot arrive in the same run.
pub struct LogRingPeer<'ring> {
    records: *const u8,
    consume: *const u8,
    regions: PhantomData<(&'ring LogRecords, &'ring LogConsume)>,
}

impl<'ring> LogRingPeer<'ring> {
    /// Map a peer's view over both regions of one ring.
    #[must_use]
    pub fn new(records: &'ring LogRecords, consume: &'ring LogConsume) -> Self {
        Self {
            records: std::ptr::from_ref(records).cast::<u8>(),
            consume: std::ptr::from_ref(consume).cast::<u8>(),
            regions: PhantomData,
        }
    }

    /// Borrow one `u32` of a region by byte offset.
    ///
    /// # Safety
    /// `offset` must be within the region `base` points at, 4-aligned, and the
    /// start of a declared `AtomicU32` field of it. Every caller below passes a
    /// constant offset the ABI pins to an `AtomicU32`, or one derived from
    /// [`Location::placement`] for a [`Width::Word`] location.
    unsafe fn word_at(base: *const u8, offset: usize) -> &'ring AtomicU32 {
        // SAFETY: the caller guarantees `offset` names a 4-aligned `AtomicU32`
        // inside the region, and the pinned `#[repr(C)]` layout (this module's
        // header, enforced by the `const _` blocks in `crates/wire/src/log_ring.rs`
        // and `crates/wire/src/log_slot.rs`) is what makes that offset the one
        // the two domains agree on.
        unsafe { &*base.add(offset).cast::<AtomicU32>() }
    }

    /// Borrow one `u64` of the records region by byte offset.
    ///
    /// # Safety
    /// As [`word_at`](Self::word_at), for an 8-aligned `AtomicU64` field.
    unsafe fn quad_at(&self, offset: usize) -> &'ring AtomicU64 {
        // SAFETY: as `word_at`; `align_of::<LogRecords>() == align_of::<AtomicU64>()`
        // is asserted by the `const _` block in `crates/wire/src/log_ring.rs`,
        // so an 8-aligned offset from the region base is 8-aligned absolutely.
        unsafe { &*self.records.add(offset).cast::<AtomicU64>() }
    }

    /// Borrow one `u8` of the records region by byte offset.
    ///
    /// # Safety
    /// As [`word_at`](Self::word_at), for an `AtomicU8` field. Alignment is
    /// trivial; the offset must still be inside the region.
    unsafe fn byte_at(&self, offset: usize) -> &'ring AtomicU8 {
        // SAFETY: as `word_at`. Every byte offset below is `SLOTS_OFFSET` plus a
        // slot index already reduced modulo `LOG_RING_SLOTS`, plus a location
        // offset below `RECORD_BYTES`.
        unsafe { &*self.records.add(offset).cast::<AtomicU8>() }
    }

    /// Forge the writer's published cursor: the lever that presents the console
    /// with slots that were never published.
    pub fn set_tail(&self, value: u32) {
        // SAFETY: `TAIL_OFFSET` is 0, the region's own `AtomicU32` tail.
        unsafe { Self::word_at(self.records, TAIL_OFFSET) }.store(value, Ordering::Relaxed);
    }

    /// Read the writer's published cursor, so a harness can predict what the
    /// reader under test will decide.
    #[must_use]
    pub fn tail(&self) -> u32 {
        // SAFETY: as `set_tail`.
        unsafe { Self::word_at(self.records, TAIL_OFFSET) }.load(Ordering::Relaxed)
    }

    /// Forge the writer's published drop count — the one number the console
    /// exposes about its peer that the peer itself supplies.
    pub fn set_dropped(&self, value: u32) {
        // SAFETY: `DROPPED_OFFSET` is 4, the region's own `AtomicU32` count.
        unsafe { Self::word_at(self.records, DROPPED_OFFSET) }.store(value, Ordering::Relaxed);
    }

    /// Read it back; see [`set_dropped`](Self::set_dropped).
    #[must_use]
    pub fn dropped(&self) -> u32 {
        // SAFETY: as `set_dropped`.
        unsafe { Self::word_at(self.records, DROPPED_OFFSET) }.load(Ordering::Relaxed)
    }

    /// Forge the console's published cursor: the lever that stalls a writing
    /// domain, or invites it to overwrite a record the console never rendered.
    pub fn set_head(&self, value: u32) {
        // SAFETY: `HEAD_OFFSET` is 0, the consume region's whole content.
        unsafe { Self::word_at(self.consume, HEAD_OFFSET) }.store(value, Ordering::Relaxed);
    }

    /// Read it back; see [`set_head`](Self::set_head).
    #[must_use]
    pub fn head(&self) -> u32 {
        // SAFETY: as `set_head`.
        unsafe { Self::word_at(self.consume, HEAD_OFFSET) }.load(Ordering::Relaxed)
    }

    /// Byte offset of slot `slot % LOG_RING_SLOTS` within the records region.
    const fn slot_offset(slot: usize) -> usize {
        SLOTS_OFFSET + RECORD_BYTES * (slot % LOG_RING_SLOTS)
    }

    /// Store one atomic of slot `slot % LOG_RING_SLOTS` — the peer's real
    /// granularity, and the primitive every other slot write here is built
    /// from. `value` is truncated to the location's own width.
    ///
    /// Leaving the other 146 alone is what a torn record *is*: the next
    /// `LogSlot::load` mixes this value with whatever the untouched locations
    /// still hold, which is exactly what a peer store landing between two of
    /// that function's relaxed loads produces.
    pub fn store_location(&self, slot: usize, location: Location, value: u64) {
        let (within, width) = location.placement();
        let offset = Self::slot_offset(slot) + within;
        match width {
            // SAFETY: `slot % LOG_RING_SLOTS < LOG_RING_SLOTS` and `within` is a
            // `Width::Byte` location below `RECORD_BYTES`, so `offset` names an
            // `AtomicU8` field inside the slot array.
            Width::Byte => unsafe { self.byte_at(offset) }.store(value as u8, Ordering::Relaxed),
            // SAFETY: as above; a `Width::Word` location is 4-aligned within the
            // slot and the slot base is 8-aligned, so `offset` is 4-aligned and
            // names an `AtomicU32` field.
            Width::Word => unsafe { Self::word_at(self.records, offset) }
                .store(value as u32, Ordering::Relaxed),
            // SAFETY: as above; a `Width::Quad` location is 8-aligned within the
            // slot and the slot base is 8-aligned.
            Width::Quad => unsafe { self.quad_at(offset) }.store(value, Ordering::Relaxed),
        }
    }

    /// Read one atomic back, widened to a `u64`.
    #[must_use]
    pub fn load_location(&self, slot: usize, location: Location) -> u64 {
        let (within, width) = location.placement();
        let offset = Self::slot_offset(slot) + within;
        match width {
            // SAFETY: as `store_location`.
            Width::Byte => u64::from(unsafe { self.byte_at(offset) }.load(Ordering::Relaxed)),
            Width::Word => {
                // SAFETY: as `store_location`.
                let word = unsafe { Self::word_at(self.records, offset) };
                u64::from(word.load(Ordering::Relaxed))
            }
            // SAFETY: as `store_location`.
            Width::Quad => unsafe { self.quad_at(offset) }.load(Ordering::Relaxed),
        }
    }

    /// Overwrite every atomic of slot `slot % LOG_RING_SLOTS`, as a writing
    /// domain publishing a whole record into the mapped image does — but at any
    /// slot it likes rather than the one its own cursor names.
    ///
    /// [`LOCATION_COUNT`] [`store_location`](Self::store_location) calls and
    /// nothing more: a peer has no wider store, and expressing it any other way
    /// would let this convenience drift from the granularity it stands for.
    pub fn store_record(&self, slot: usize, record: &LogRecord) {
        let bytes = record_bytes(record);
        for location in Location::all() {
            let (within, width) = location.placement();
            let mut value = [0u8; 8];
            value[..width.bytes()].copy_from_slice(&bytes[within..within + width.bytes()]);
            self.store_location(slot, location, u64::from_le_bytes(value));
        }
    }

    /// Read slot `slot % LOG_RING_SLOTS` back, so a harness can assert that what
    /// the reader under test decoded is what that slot actually held.
    #[must_use]
    pub fn load_record(&self, slot: usize) -> LogRecord {
        let mut bytes = [0u8; RECORD_BYTES];
        for location in Location::all() {
            let (within, width) = location.placement();
            let value = self.load_location(slot, location).to_le_bytes();
            bytes[within..within + width.bytes()].copy_from_slice(&value[..width.bytes()]);
        }
        record_from_bytes(bytes)
    }
}

/// One record as the [`RECORD_BYTES`] bytes it occupies in a region.
///
/// Sound because `LogRecord` is `#[repr(C)]` with **no implicit padding**: the
/// `const _` block at the foot of `crates/wire/src/log_record.rs` asserts that
/// its fields sum to `size_of::<LogRecord>()`, so every byte of the value
/// belongs to a declared integer field and is initialised. The `transmute` also
/// fails to compile unless [`RECORD_BYTES`] is that size, which is the
/// cross-artifact half of the same claim.
#[must_use]
fn record_bytes(record: &LogRecord) -> [u8; RECORD_BYTES] {
    // SAFETY: `LogRecord` is `#[repr(C)]`, `Copy`, and every one of its fields
    // is an integer or an array of integers with no implicit padding between
    // them — guaranteed by the `const _` block in `crates/wire/src/log_record.rs`
    // that asserts the field widths sum to the whole size. Every byte of the
    // value is therefore initialised, which is `transmute`'s only requirement
    // here beyond the size equality the compiler checks.
    unsafe { std::mem::transmute::<LogRecord, [u8; RECORD_BYTES]>(*record) }
}

/// The inverse of [`record_bytes`].
#[must_use]
fn record_from_bytes(bytes: [u8; RECORD_BYTES]) -> LogRecord {
    // SAFETY: as `record_bytes`, in the other direction. Every field of
    // `LogRecord` is an integer or an array of integers, none of which has an
    // invalid bit pattern, so any 192 initialised bytes are a valid value —
    // which is precisely why a peer may write whatever it likes into a slot and
    // the result is untrusted input rather than undefined behaviour.
    unsafe { std::mem::transmute::<[u8; RECORD_BYTES], LogRecord>(bytes) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wire::LogRecordError;

    /// The runs cover the whole record exactly once, contiguously, with every
    /// location naturally aligned and every index in `0..LOCATION_COUNT` named
    /// by exactly one of them.
    ///
    /// This is the assertion the whole peer view rests on: a wrong run would
    /// put a store in the wrong field, or overlap two atomics of different
    /// widths, and every harness resting on the view would quietly stop testing
    /// the thing it names.
    #[test]
    fn the_segments_partition_the_whole_record() {
        let mut next_index = 0usize;
        let mut next_offset = 0usize;
        for &(first, offset, count, width) in SEGMENTS {
            assert_eq!(first, next_index, "a run does not follow the previous one");
            assert_eq!(offset, next_offset, "a run leaves a gap in the record");
            assert!(count > 0);
            assert!(
                offset.is_multiple_of(width.bytes()),
                "a {width:?} run starts unaligned at {offset}"
            );
            next_index = first + count;
            next_offset = offset + count * width.bytes();
        }
        assert_eq!(next_index, LOCATION_COUNT);
        assert_eq!(next_offset, RECORD_BYTES);

        // And every location resolves back into the run it came from.
        let mut expected_offset = 0usize;
        for location in Location::all() {
            let (offset, width) = location.placement();
            assert_eq!(
                offset, expected_offset,
                "location {location:?} is misplaced"
            );
            expected_offset += width.bytes();
        }
        assert_eq!(expected_offset, RECORD_BYTES);
    }

    /// Every selector reaches a location, and each of the first
    /// [`LOCATION_COUNT`] selectors reaches a different one — so a harness
    /// counting torn deliveries is not silently writing one atomic twice.
    #[test]
    fn every_selector_reaches_exactly_one_location() {
        let mut seen = vec![false; LOCATION_COUNT];
        for selector in 0..LOCATION_COUNT as u32 {
            let location = Location::from_selector(selector);
            assert_eq!(location.index(), selector as usize);
            assert!(!seen[location.index()], "selector {selector} collided");
            seen[location.index()] = true;
        }
        assert!(seen.into_iter().all(|hit| hit));
        // And a selector past the end wraps rather than leaving the slot.
        assert_eq!(
            Location::from_selector(u32::MAX).index(),
            u32::MAX as usize % LOCATION_COUNT
        );
    }

    /// A record survives the byte image the peer writes it through.
    #[test]
    fn a_record_round_trips_through_its_own_bytes() {
        let record = LogRecord {
            features: 0x0102_0304_0506_0708,
            operands: [u64::MAX, 1],
            kind: 1,
            generation: 0xDEAD_BEEF,
            reason: 29,
            _pad: [0xAB; 6],
            ..LogRecord::ZERO
        };
        assert_eq!(record_from_bytes(record_bytes(&record)), record);
        assert_eq!(
            record_from_bytes([0xFF; RECORD_BYTES]).check(),
            Err(LogRecordError::KindUnknown { kind: u32::MAX }),
            "the all-bytes-set image is not the record the ABI says it is"
        );
    }

    /// The peer view addresses the words the ring really uses.
    ///
    /// If the pinned layout ever moved, this would read a cursor as a slot and
    /// every claim the ring harness makes would quietly become vacuous.
    #[test]
    fn the_peer_view_addresses_the_words_the_ring_really_uses() {
        let records = LogRecords::zero();
        let consume = LogConsume::zero();
        let peer = LogRingPeer::new(&records, &consume);

        peer.set_tail(0x1234);
        peer.set_dropped(0x5678);
        peer.set_head(0x9abc);
        assert_eq!(peer.tail(), 0x1234);
        assert_eq!(peer.dropped(), 0x5678);
        assert_eq!(peer.head(), 0x9abc);
        assert_ne!(peer.tail(), peer.dropped(), "two cursors share one word");

        // Restore an empty ring, publish through the writer, and read the slot
        // back through the peer's view: the writer writes slot 0 first.
        peer.set_tail(0);
        peer.set_dropped(0);
        peer.set_head(0);
        let mut writer = records.writer(&consume);
        let published = LogRecord {
            kind: 2,
            generation: 9,
            changes: 4,
            ..LogRecord::ZERO
        };
        writer.write(&published).expect("the ring is empty");
        assert_eq!(peer.load_record(0), published);
        assert_eq!(peer.tail(), 1, "the writer publishes its new position");

        // And a peer store lands where the console will read it.
        let forged = LogRecord {
            kind: 3,
            generation: 7,
            reason: 2,
            ..LogRecord::ZERO
        };
        peer.store_record(1, &forged);
        peer.set_tail(2);
        let mut reader = consume.reader(&records);
        assert_eq!(reader.read(), Some(published.check()));
        assert_eq!(reader.read(), Some(forged.check()));
        assert_eq!(peer.head(), 2, "the reader publishes its consume position");
    }

    /// A slot index past the array wraps rather than leaving the region.
    #[test]
    fn slot_indices_wrap_rather_than_leaving_the_region() {
        let records = LogRecords::zero();
        let consume = LogConsume::zero();
        let peer = LogRingPeer::new(&records, &consume);
        let forged = LogRecord {
            kind: 2,
            generation: 5,
            ..LogRecord::ZERO
        };
        peer.store_record(usize::MAX, &forged);
        assert_eq!(peer.load_record(usize::MAX % LOG_RING_SLOTS), forged);
        assert_eq!(peer.load_record(usize::MAX), forged);
    }

    /// One location store leaves the other 146 alone, which is what makes a
    /// torn record expressible at all.
    #[test]
    fn a_single_location_store_leaves_every_other_location_alone() {
        let records = LogRecords::zero();
        let consume = LogConsume::zero();
        let peer = LogRingPeer::new(&records, &consume);
        let whole = LogRecord {
            features: 0x1111_1111_1111_1111,
            kind: 1,
            generation: 0x2222_2222,
            domain: 3,
            ..LogRecord::ZERO
        };
        peer.store_record(0, &whole);
        for location in Location::all() {
            let before: Vec<u64> = Location::all()
                .map(|other| peer.load_location(0, other))
                .collect();
            peer.store_location(0, location, 0x5A5A_5A5A_5A5A_5A5A);
            for other in Location::all() {
                if other == location {
                    continue;
                }
                assert_eq!(
                    peer.load_location(0, other),
                    before[other.index()],
                    "storing {location:?} disturbed {other:?}"
                );
            }
            // Put it back so each iteration starts from the same image.
            peer.store_location(0, location, before[location.index()]);
        }
        assert_eq!(peer.load_record(0), whole, "the image did not survive");
    }

    /// A store is truncated to its location's own width rather than spilling
    /// into the next one.
    #[test]
    fn a_store_is_truncated_to_its_locations_width() {
        let records = LogRecords::zero();
        let consume = LogConsume::zero();
        let peer = LogRingPeer::new(&records, &consume);
        for location in Location::all() {
            let (_, width) = location.placement();
            peer.store_location(0, location, u64::MAX);
            let expected = match width {
                Width::Byte => u64::from(u8::MAX),
                Width::Word => u64::from(u32::MAX),
                Width::Quad => u64::MAX,
            };
            assert_eq!(peer.load_location(0, location), expected);
            peer.store_location(0, location, 0);
        }
        assert_eq!(peer.load_record(0), LogRecord::ZERO);
    }
}
