//! A bounded single-producer/single-consumer ring of [`LogRecord`]s, laid out
//! across the two regions its two directions are granted in.
//!
//! Faces the byzantine neighbour protection domain from both sides at
//! once: a writing domain owns [`LogRecords`] and the console domain owns
//! [`LogConsume`], each reads the other's, and neither may assume the other
//! wrote anything a correct implementation would.
//!
//! # Two regions, because a region is the unit of grant
//!
//! [`LogRecords`] holds the slots, the producer cursor and the writer's drop
//! count; [`LogConsume`] holds the consumer cursor alone. The writing domain
//! maps the first read-write and the second read-only, and the console domain
//! maps them the other way round — the split `cfg`/`cfgack` already makes for
//! the configuration handover, for the same reason: only two regions can give
//! each domain write access to exactly the direction it speaks in.
//!
//! One region could not. [`LogReader::read`] publishes its consume position,
//! which is the writer's only flow control, so a console mapping a single
//! region read-only would fault on the first record it took; and a console
//! mapping it read-write could store into any slot, forging a line attributed
//! to a domain that never emitted it. Split, the console cannot write a record
//! into a domain's ring and a writer cannot write the cursor that says how much
//! of its ring has been read.
//!
//! The handles carry that asymmetry rather than restating it: [`LogWriter`]
//! holds a `&LogRecords` and reaches the consume cursor only through
//! [`PeerConsume`], which has no store on it, and [`LogReader`] is the mirror
//! image. Neither can name the method that would write the peer's
//! region. What the types do not close is a domain holding both references
//! minting the *other* side's handle — the console could ask a records region
//! for a writer — and that is where the mapping is the enforcement rather than
//! the reminder: the store faults on a read-only page. The types keep the call
//! from being written; the grant is what makes writing it useless.
//!
//! # The protocol is `queue`'s, and is repeated rather than shared
//!
//! Each side's position lives in domain-private memory and the shared cursor is
//! a *publication* of it for the peer's flow control, never a value this side
//! reads back. Re-reading it would hand the peer the two failures a private
//! position removes: a rewound reader cursor redelivers a record, and a rewound
//! writer cursor overwrites a record the reader never saw.
//!
//! `queue::SpscRing` carries the identical protocol over [`crate::Descriptor`],
//! and this is not that type instantiated over another payload: `queue` depends
//! on `wire`, so a ring declared there could not be a field of a region this
//! crate lays out. The two also part on what refusing an item means. A refused
//! descriptor is handed back, because it names a packet buffer whose ownership
//! the caller has to keep; a refused record names nothing and has no owner to
//! return it to, so it is counted instead, and the count is a field of the
//! records region rather than a value the writer alone would know.
//!
//! # A full ring refuses the newest record
//!
//! A ring that dropped the *oldest* would have the writer advance the reader's
//! cursor — a write the split has now made impossible in any case, and which
//! the private-position rule above forbade before it: the writer would be
//! overwriting the slot the reader is reading, so a record could be assembled
//! out of two different writes and rendered as a third that was never emitted.
//! Refusing the newest keeps the writer inside the slots the reader has
//! released, and that is what makes a record either whole or absent.
//!
//! And it is what this ring is for: it carries the boot transcript, and when a
//! domain parks the earliest records are the ones that say why.
//!
//! This is the opposite bias from the `GET /logs` retention buffer the operator
//! contract specifies, which drops the oldest because it answers "what is this node
//! doing *right now*": recent history and first history are different
//! questions, and each buffer counts what it dropped.
//!
//! # What each side still achieves against the other
//!
//! * **Flow control is advisory in both directions.** A forged `tail` can
//!   present the reader with up to [`LogRecords::capacity`] slots that were
//!   never published; a forged `head` can stall the writer or let it overwrite
//!   an unread slot. Those slots are stale or zero — in bounds, never out of
//!   it. The second costs the console its own records and nobody else's, which
//!   is the shape a consumer harming itself should have.
//! * **A record is untrusted input.** Per-field atomics mean a write concurrent
//!   with a read can yield a record whose fields come from different writes. The
//!   guarantee is exactly this and no more: every field is always a well-formed
//!   value and never undefined behaviour. [`LogRecord::check`] refuses a *shape*
//!   — a length, a token, a discriminant the ABI cannot carry — and provenance is
//!   not a shape, so a record whose domain came from one write and whose state
//!   came from the next passes and renders as a console line no domain emitted.
//!   That is the accepted residue of a per-field publish: the alternative is a
//!   sequence word per slot on the path of every record, against an outcome that
//!   is a wrong line and never a fault.
//! * **The drop count is the writer's own claim about itself** and bounds
//!   nothing here. It restarts at zero when the writing domain does — the one
//!   discontinuity the exposed counter semantics admit.

use core::{
    mem::size_of,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};

use crate::MAPPING_ALIGN;
use crate::log_record::{CheckedRecord, LogRecord, LogRecordError};
use crate::log_slot::LogSlot;

/// Slots one records region holds, of which [`LogRecords::capacity`] are usable.
///
/// ABI rather than a tuning knob: it sizes the region the system description
/// reserves, so moving it rebuilds every domain that maps one. Sized for the
/// boot transcript, which is the case where nothing is draining: a domain's
/// lifecycle records plus a first configuration generation's whole diff must
/// fit before the console domain has started, or the records that explain a
/// failed bring-up are the ones refused.
///
/// It is what a wider record is spent against, and it wins: the shipped
/// document's first generation alone is 16 change records. At 264 bytes a
/// record, 64 of them plus the cursor and the drop count are 16 904 bytes, so
/// the region rounds to five pages rather than four — the count is what the
/// width is spent against and the page is what the width costs.
pub const LOG_RING_SLOTS: usize = 64;

/// Bytes the system description reserves for one records region, derived rather
/// than chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const LOG_RECORDS_REGION_SIZE: usize = size_of::<LogRecords>().next_multiple_of(MAPPING_ALIGN);

/// As [`LOG_RECORDS_REGION_SIZE`]. A page for one word is what a region costs
/// when a region is the unit of grant, and `cfgack` spends one for that reason.
pub const LOG_CONSUME_REGION_SIZE: usize = size_of::<LogConsume>().next_multiple_of(MAPPING_ALIGN);

/// The mask that bounds every cursor, and what makes an out-of-range one an
/// in-range index rather than a fault.
const MASK: u32 = (LOG_RING_SLOTS - 1) as u32;

/// The records half of the ring: the slots, the cursor that publishes them and
/// the writer's count of what it refused. The writing domain maps this
/// read-write and the console domain read-only.
///
/// Every field is private and no accessor reaches one, so the ordering each
/// word carries is a property of this type rather than a convention its users
/// are asked to keep.
#[repr(C)]
pub struct LogRecords {
    tail: AtomicU32,
    dropped: AtomicU32,
    slots: [LogSlot; LOG_RING_SLOTS],
}

impl LogRecords {
    /// A function rather than a `const`: a `const` holding an atomic is copied
    /// at each mention, so a store through one is read back by nobody.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            tail: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
            slots: [const { LogSlot::zero() }; LOG_RING_SLOTS],
        }
    }

    /// How many records the ring holds at once. One slot is always left unused,
    /// which tells a full ring from an empty one without a flag.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        MASK as usize
    }

    /// Take the writing side's handle: this region to write, the console's
    /// cursor to read.
    ///
    /// Take it **once** per ring and keep it: a second restarts at position
    /// zero and overwrites slots the first published. No type stops it, for the
    /// reason `queue`'s header gives — the flag that would close it could only
    /// live in a region a peer writes.
    #[must_use]
    pub const fn writer<'ring>(&'ring self, consume: &'ring LogConsume) -> LogWriter<'ring> {
        LogWriter {
            records: self,
            consume: PeerConsume::new(consume),
            tail: 0,
            dropped: 0,
        }
    }

    /// The slot a cursor names. Total by construction: `MASK` is one below
    /// `LOG_RING_SLOTS`, which the assertion block below holds to a power of
    /// two, so the masked value indexes the array for every `u32` there is.
    fn slot(&self, at: u32) -> &LogSlot {
        &self.slots[(at & MASK) as usize]
    }
}

impl Default for LogRecords {
    fn default() -> Self {
        Self::zero()
    }
}

/// The consume half of the ring: how far the console has read, and nothing
/// else. The console domain maps this read-write and the writing domain
/// read-only.
///
/// Its own region rather than a field of [`LogRecords`], which is what denies
/// the writing domain the one write that would matter here — forging the cursor
/// that decides which of its slots it may reuse, and so overwriting a record
/// the console has not rendered while telling it nothing was lost. Private for
/// the reason [`LogRecords`]'s fields are.
#[repr(C)]
pub struct LogConsume {
    head: AtomicU32,
}

impl LogConsume {
    /// As [`LogRecords::zero`].
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            head: AtomicU32::new(0),
        }
    }

    /// Take the draining side's handle: this region to write, the writer's
    /// records to read. On [`LogRecords::writer`]'s terms.
    #[must_use]
    pub const fn reader<'ring>(&'ring self, records: &'ring LogRecords) -> LogReader<'ring> {
        LogReader {
            consume: self,
            records: PeerRecords::new(records),
            head: 0,
        }
    }
}

impl Default for LogConsume {
    fn default() -> Self {
        Self::zero()
    }
}

/// Each side's view of the region it reads and may not write.
///
/// A module of their own, and that is the whole mechanism: the borrow each view
/// wraps is private to it, so nothing outside — including the two handles
/// below, which sit in the parent — can reach past a view to the region behind
/// it. "Neither side writes the other's region" is thereby a fact about the
/// types rather than about care taken at each call site. A child module
/// still reads its parent's private items, which is what lets these reach the
/// cursors and slots they load.
mod peer {
    use core::sync::atomic::Ordering;

    use super::{LogConsume, LogRecords, MASK};
    use crate::log_record::LogRecord;

    /// The records region as the console holds it: loads only.
    pub(super) struct PeerRecords<'ring>(&'ring LogRecords);

    impl<'ring> PeerRecords<'ring> {
        pub(super) const fn new(records: &'ring LogRecords) -> Self {
            Self(records)
        }

        pub(super) const fn capacity(&self) -> usize {
            self.0.capacity()
        }

        /// Masked into range because it is attacker-controlled. Acquire so the
        /// writer's slot writes are visible before this side reads them.
        pub(super) fn tail(&self) -> u32 {
            self.0.tail.load(Ordering::Acquire) & MASK
        }

        pub(super) fn dropped(&self) -> u32 {
            self.0.dropped.load(Ordering::Acquire)
        }

        pub(super) fn record(&self, at: u32) -> LogRecord {
            self.0.slot(at).load()
        }
    }

    /// The consume region as a writing domain holds it, on [`PeerRecords`]'s
    /// terms.
    pub(super) struct PeerConsume<'ring>(&'ring LogConsume);

    impl<'ring> PeerConsume<'ring> {
        pub(super) const fn new(consume: &'ring LogConsume) -> Self {
            Self(consume)
        }

        /// On [`PeerRecords::tail`]'s terms, for the cursor going the other way.
        pub(super) fn head(&self) -> u32 {
            self.0.head.load(Ordering::Acquire) & MASK
        }
    }
}

use peer::{PeerConsume, PeerRecords};

/// A record the ring had no slot for. Carries the writer's running total so a
/// caller that only ever sees refusals still has the number to expose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogRingFull {
    /// Records this writer has refused, saturating at [`u32::MAX`] rather than
    /// wrapping: a wrap would turn a sustained flood back into a small number.
    pub dropped: u32,
}

/// The writing side, holding this domain's publish position and its own drop
/// count in private memory.
pub struct LogWriter<'ring> {
    records: &'ring LogRecords,
    consume: PeerConsume<'ring>,
    tail: u32,
    /// The authoritative count, published to the records region but never read
    /// back from it: a count this side reads out of shared memory could be
    /// walked backwards by the domain it accuses.
    dropped: u32,
}

impl LogWriter<'_> {
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.records.capacity()
    }

    /// Write one record, publishing it to the console domain.
    ///
    /// # Errors
    /// [`LogRingFull`] when the ring *appears* full, having counted the drop.
    /// "Appears" is deliberate: fullness is judged against the console's
    /// published cursor, which that domain may forge either way.
    pub fn write(&mut self, record: &LogRecord) -> Result<(), LogRingFull> {
        let next = self.tail.wrapping_add(1) & MASK;
        if next == self.consume.head() {
            self.dropped = self.dropped.saturating_add(1);
            self.records.dropped.store(self.dropped, Ordering::Release);
            return Err(LogRingFull {
                dropped: self.dropped,
            });
        }
        self.records.slot(self.tail).store(record);
        self.tail = next;
        self.records.tail.store(next, Ordering::Release);
        Ok(())
    }

    /// Records this writer has refused for want of a slot.
    #[must_use]
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    /// A best-effort instantaneous estimate of how many records are queued.
    ///
    /// One operand is the console's published cursor, so under a hostile
    /// console this is an arbitrary number in `0..=capacity()`. Never size a
    /// following batch from it; drive writes from [`write`](Self::write)'s
    /// `Result`.
    #[must_use]
    pub fn len(&self) -> usize {
        (self.tail.wrapping_sub(self.consume.head()) & MASK) as usize
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The draining side, holding this domain's consume position in private memory.
pub struct LogReader<'ring> {
    consume: &'ring LogConsume,
    records: PeerRecords<'ring>,
    head: u32,
}

impl<'ring> LogReader<'ring> {
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.records.capacity()
    }

    /// Read one record and decode it.
    ///
    /// The outer `None` means only that nothing is queued *at this instant*,
    /// judged against the writer's published cursor; a later call may return
    /// `Some`. The inner `Err` is a record the writer's bytes cannot be, which is
    /// a fact about the peer rather than a reason to stop draining — and the
    /// caller's to count, one refusal being no more this side's business than the
    /// line it would otherwise have rendered.
    pub fn read(&mut self) -> Option<Result<CheckedRecord, LogRecordError>> {
        if self.head == self.records.tail() {
            return None;
        }
        let record = self.records.record(self.head);
        self.head = self.head.wrapping_add(1) & MASK;
        self.consume.head.store(self.head, Ordering::Release);
        Some(record.check())
    }

    /// Read at most `limit` records, and never more than
    /// [`capacity`](Self::capacity) however large `limit` is.
    ///
    /// Both bounds matter and neither is the peer's. `limit` is the caller's
    /// budget per scheduling round, which only the caller knows; the capacity
    /// clamp is what makes a single drain finite for *any* caller, including
    /// one that passed [`usize::MAX`]. A peer that keeps advancing its published
    /// cursor keeps [`read`](Self::read) returning `Some`, so an unbounded loop
    /// over it never returns and the console stops progressing on anything
    /// else. [`len`](Self::len) must not supply either bound, being
    /// peer-influenced.
    #[must_use = "a drain iterator reads nothing until it is consumed"]
    pub fn drain(&mut self, limit: usize) -> LogDrain<'_, 'ring> {
        let remaining = if limit < self.capacity() {
            limit
        } else {
            self.capacity()
        };
        LogDrain {
            reader: self,
            remaining,
        }
    }

    /// What the writer says it refused for want of a slot. The writer's claim
    /// about itself, so it is a number to expose and never one to decide under.
    #[must_use]
    pub fn dropped_by_writer(&self) -> u32 {
        self.records.dropped()
    }

    /// As best-effort as [`LogWriter::len`], and bounded the same way.
    #[must_use]
    pub fn len(&self) -> usize {
        (self.records.tail().wrapping_sub(self.head) & MASK) as usize
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The bounded read iterator from [`LogReader::drain`]. Dropping it early
/// leaves the remaining records queued.
pub struct LogDrain<'reader, 'ring> {
    reader: &'reader mut LogReader<'ring>,
    remaining: usize,
}

impl Iterator for LogDrain<'_, '_> {
    type Item = Result<CheckedRecord, LogRecordError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let decoded = self.reader.read()?;
        self.remaining -= 1;
        Some(decoded)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // The upper bound is the whole guarantee: iteration is finite whatever
        // the peer does.
        (0, Some(self.remaining))
    }
}

// Two cross-PD shared-memory ABIs: pin both layouts so a field reorder or a size
// change is a compile error rather than a silently corrupted mapping.
const _: () = {
    use core::mem::{align_of, offset_of};

    assert!(
        LOG_RING_SLOTS.is_power_of_two(),
        "the cursor mask needs one"
    );
    assert!(LOG_RING_SLOTS >= 2, "a ring of one slot holds nothing");
    assert!(LOG_RING_SLOTS - 1 <= u32::MAX as usize, "cursors are u32");

    assert!(offset_of!(LogRecords, tail) == 0);
    assert!(offset_of!(LogRecords, dropped) == 4);
    assert!(offset_of!(LogRecords, slots) == 8);
    assert!(align_of::<LogRecords>() == align_of::<AtomicU64>());
    assert!(size_of::<LogRecords>() == 8 + LOG_RING_SLOTS * size_of::<LogRecord>());

    assert!(offset_of!(LogConsume, head) == 0);
    assert!(align_of::<LogConsume>() == align_of::<AtomicU32>());
    assert!(size_of::<LogConsume>() == 4);

    // Each region must hold its type and be mappable.
    assert!(LOG_RECORDS_REGION_SIZE >= size_of::<LogRecords>());
    assert!(LOG_RECORDS_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(LOG_CONSUME_REGION_SIZE >= size_of::<LogConsume>());
    assert!(LOG_CONSUME_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
};

#[cfg(test)]
mod tests;
